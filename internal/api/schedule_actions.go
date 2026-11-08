package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/services"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/storage"
	"github.com/morcheh/backend/internal/terminal"
)

// Cron job actions other than a file sync. Each is checked when saved with
// the same rules as doing it by hand, and again when it runs, as the person
// who saved it last.

// ---- Types ----

// ScheduleTask holds what the action needs; only the action's own field is
// set. sync, archive and fetch use the schedule's source and destinations.
type ScheduleTask struct {
	Script  *ScheduleScript  `json:"script,omitempty" doc:"action script"`
	Ansible *ScheduleAnsible `json:"ansible,omitempty" doc:"action ansible"`
	Service *ScheduleService `json:"service,omitempty" doc:"action service"`
	Reboot  *ScheduleReboot  `json:"reboot,omitempty" doc:"action reboot"`
	Fetch   *ScheduleFetch   `json:"fetch,omitempty" doc:"action fetch: what to download into the destination folders"`
	Verify  *ScheduleVerify  `json:"verify,omitempty" doc:"action verify-backup"`
}

// ScheduleScript is a saved script or a command, as when starting a run.
type ScheduleScript startScriptRunBody

type ScheduleAnsible struct {
	PlaybookID string           `json:"playbook_id" format:"uuid" doc:"A saved playbook; its text is read at each run"`
	Selection  AnsibleSelection `json:"selection" doc:"Read at each run: servers tagged later are included"`
	Options    AnsibleOptions   `json:"options,omitempty"`
}

type ScheduleService struct {
	ServerIDs []string `json:"server_ids" minItems:"1" maxItems:"200" format:"uuid"`
	Unit      string   `json:"unit" minLength:"1" maxLength:"256" example:"nginx.service"`
	Action    string   `json:"action" enum:"start,stop,restart,reload"`
	Force     bool     `json:"force,omitempty" doc:"Stop a protected service (sshd, dbus, journald…) anyway. Needs Engineer"`
}

type ScheduleReboot struct {
	ServerIDs      []string `json:"server_ids" minItems:"1" maxItems:"50" format:"uuid" doc:"Rebooted one at a time; the next waits until the last is back"`
	OnlyIfRequired bool     `json:"only_if_required,omitempty" doc:"Skip a server that isn't asking for a reboot (updated kernel or packages)"`
	SkipIfLoggedIn bool     `json:"skip_if_logged_in,omitempty" doc:"Skip a server someone is logged in to"`
	Message        string   `json:"message,omitempty" maxLength:"200" doc:"Shown to logged-in users first (wall)"`
}

type ScheduleFetch struct {
	URL       string `json:"url" minLength:"1" maxLength:"4096" example:"https://example.com/list.txt"`
	Name      string `json:"name,omitempty" maxLength:"255" doc:"File name to save as; default the address's last part"`
	Overwrite bool   `json:"overwrite,omitempty" doc:"Replace the file each time; without it a run fails where the file is already there"`
}

type ScheduleVerify struct {
	DatabaseID string  `json:"database_id" format:"uuid"`
	PlanID     *string `json:"plan_id,omitempty" format:"uuid" doc:"Only this plan's backups; default every plan's"`
}

// ScheduleRef is something a task names, with what it's called now.
type ScheduleRef struct {
	ID      string `json:"id" format:"uuid"`
	Kind    string `json:"kind" enum:"server,storage,script,playbook,database"`
	Name    string `json:"name" doc:"Empty when it was deleted"`
	Missing bool   `json:"missing"`
}

// usesSource says whether an action reads from the schedule's source.
func usesSource(action string) bool { return action == "sync" || action == "archive" }

// taskRefs lists what a task names, servers first.
func taskRefs(action string, t ScheduleTask) []ScheduleRef {
	refs := []ScheduleRef{}
	add := func(kind string, ids ...string) {
		for _, id := range ids {
			if _, err := uuid.Parse(id); err == nil {
				refs = append(refs, ScheduleRef{ID: id, Kind: kind})
			}
		}
	}
	switch {
	case action == "script" && t.Script != nil:
		add("server", t.Script.ServerIDs...)
		if t.Script.ScriptID != nil {
			add("script", *t.Script.ScriptID)
		}
	case action == "ansible" && t.Ansible != nil:
		add("server", t.Ansible.Selection.ServerIDs...)
		add("playbook", t.Ansible.PlaybookID)
	case action == "service" && t.Service != nil:
		add("server", t.Service.ServerIDs...)
	case action == "reboot" && t.Reboot != nil:
		add("server", t.Reboot.ServerIDs...)
	case action == "verify-backup" && t.Verify != nil:
		add("database", t.Verify.DatabaseID)
	}
	return refs
}

func refIDs(refs []ScheduleRef) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(refs))
	for _, r := range refs {
		out = append(out, uuid.MustParse(r.ID))
	}
	return out
}

func parseID(raw string) uuid.UUID {
	id, _ := uuid.Parse(raw)
	return id
}

// refViews turns a kind of ref into ends (servers a run goes through).
func refViews(refs []ScheduleRef, kind string) []ScheduleEndView {
	out := []ScheduleEndView{}
	for _, r := range refs {
		if r.Kind == kind {
			id := r.ID
			out = append(out, ScheduleEndView{ScheduleEnd: ScheduleEnd{ServerID: &id, Path: "/"}, Name: r.Name, Missing: r.Missing})
		}
	}
	return out
}

func decodePlan(raw []byte) schedulePlan {
	var p schedulePlan
	decodeInto(raw, &p)
	if p.Action == "" {
		p.Action = "sync" // runs from before there were other actions
	}
	return p
}

// within moves an error's body field locations under prefix, for a check
// borrowed from another endpoint (body.server_ids → body.task.script.server_ids).
func within(prefix string, err error) error {
	var em *huma.ErrorModel
	if !errors.As(err, &em) {
		return err
	}
	for _, d := range em.Errors {
		if d != nil && strings.HasPrefix(d.Location, "body.") {
			d.Location = prefix + "." + strings.TrimPrefix(d.Location, "body.")
		}
	}
	return err
}

// ---- Checking ----

type scheduleChecker struct {
	h                       *scheduleHandler
	ctx                     context.Context
	ws                      uuid.UUID
	c                       *checkedSchedule
	seenServer, seenStorage map[uuid.UUID]bool
}

func (k *scheduleChecker) addServer(id uuid.UUID) {
	if !k.seenServer[id] {
		k.seenServer[id] = true
		k.c.serverIDs = append(k.c.serverIDs, id)
	}
}

func (k *scheduleChecker) addStorage(id uuid.UUID) {
	if !k.seenStorage[id] {
		k.seenStorage[id] = true
		k.c.storageIDs = append(k.c.storageIDs, id)
	}
}

// end checks one source or destination: in the workspace, with need.
func (k *scheduleChecker) end(loc string, e ScheduleEnd, need auth.Level, dest, serverOnly bool) (ScheduleEnd, error) {
	server, store := parseOptionalID(e.ServerID), parseOptionalID(e.StorageID)
	if serverOnly && store != nil {
		return e, fieldError(loc, "Choose a server.", nil)
	}
	if (server == nil) == (store == nil) {
		return e, fieldError(loc, "Choose a server or a storage.", nil)
	}
	p := strings.TrimSpace(e.Path)
	if !strings.HasPrefix(p, "/") || strings.ContainsRune(p, 0) {
		return e, fieldError(loc+".path", "Use a full path, starting with /.", e.Path)
	}
	out := ScheduleEnd{Path: storage.Clean(p)}
	acc := principalOf(k.ctx).Access
	var level auth.Level
	if server != nil {
		s, err := k.h.q.GetServer(k.ctx, *server)
		if isNotFound(err) || (err == nil && s.WorkspaceID != k.ws) {
			return e, fieldError(loc+".server_id", "This server isn't in this workspace.", *e.ServerID)
		}
		if err != nil {
			return e, internalError(err)
		}
		level = acc.ServerLevel(k.ws, s.ID)
		id := s.ID.String()
		out.ServerID = &id
		k.addServer(s.ID)
	} else {
		s, err := k.h.q.GetStorage(k.ctx, *store)
		if isNotFound(err) || (err == nil && s.WorkspaceID != k.ws) {
			return e, fieldError(loc+".storage_id", "This storage isn't in this workspace.", *e.StorageID)
		}
		if err != nil {
			return e, internalError(err)
		}
		if dest && s.ReadOnly {
			return e, fieldError(loc+".storage_id", s.Name+" is read-only in Morcheh, so nothing can be written to it.", *e.StorageID)
		}
		level = acc.StorageLevel(k.ws, s.ID)
		id := s.ID.String()
		out.StorageID = &id
		k.addStorage(s.ID)
	}
	if level == auth.None {
		return e, fieldError(loc, "Not found.", nil)
	}
	if level < need {
		return e, forbidden(need)
	}
	return out, nil
}

// servers checks a list of server ids: all in the workspace, with need.
func (k *scheduleChecker) servers(loc string, raw []string, need auth.Level) ([]string, error) {
	var ids []uuid.UUID
	for _, r := range raw {
		id, err := uuid.Parse(r)
		if err != nil {
			return nil, fieldError(loc, "Not a server id.", r)
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, fieldError(loc, "Choose at least one server.", nil)
	}
	where, err := k.h.authz.requireServers(k.ctx, ids, need)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(ids))
	for i, id := range ids {
		if w, ok := where[id]; !ok || w != k.ws {
			return nil, fieldError(loc, "This server isn't in this workspace.", id.String())
		}
		k.addServer(id)
		out[i] = id.String()
	}
	return out, nil
}

func cleanExcludes(in []string) ([]string, error) {
	var out []string
	for _, p := range in {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if _, err := storage.NewMatcher(out); err != nil {
		return nil, fieldError("body.options.excludes", "Not a valid pattern: "+err.Error(), out)
	}
	return out, nil
}

func (k *scheduleChecker) sync(b ScheduleBody) error {
	c := k.c
	c.options = b.Options
	if c.options.Mode == "" {
		c.options.Mode = storage.SyncUpdate
	}
	excludes, err := cleanExcludes(c.options.Excludes)
	if err != nil {
		return err
	}
	c.options.Excludes = excludes
	if c.options.Mode != storage.SyncSnapshot {
		c.options.Keep = 0
	}
	if b.Source == nil {
		return fieldError("body.source", "Choose what to copy.", nil)
	}
	if len(b.Destinations) == 0 {
		return fieldError("body.destinations", "Choose at least one destination.", nil)
	}
	src, err := k.end("body.source", *b.Source, auth.Operator, false, false)
	if err != nil {
		return err
	}
	c.source = &src
	for i, d := range b.Destinations {
		loc := fmt.Sprintf("body.destinations[%d]", i)
		out, err := k.end(loc, d, auth.Engineer, true, false)
		if err != nil {
			return err
		}
		if out.id() == src.id() && (storage.Within(out.Path, src.Path) || storage.Within(src.Path, out.Path)) {
			return fieldError(loc+".path", "A destination can't be the source folder, or inside it or around it.", d.Path)
		}
		if c.options.Mode == storage.SyncMirror && out.Path == "/" {
			return fieldError(loc+".path", "A mirror deletes what the source doesn't have, so it can't go into the top folder. Choose a folder.", d.Path)
		}
		for j, other := range c.dests {
			if other.id() == out.id() && (storage.Within(out.Path, other.Path) || storage.Within(other.Path, out.Path)) {
				return fieldError(loc+".path", fmt.Sprintf("Overlaps destination %d.", j+1), d.Path)
			}
		}
		c.dests = append(c.dests, out)
	}
	return nil
}

// archive packs a server folder into <name>-<time>.tar.gz and sends it to
// servers and storages, keeping the newest options.keep there.
func (k *scheduleChecker) archive(b ScheduleBody) error {
	c := k.c
	excludes, err := cleanExcludes(b.Options.Excludes)
	if err != nil {
		return err
	}
	for _, p := range excludes {
		if strings.ContainsAny(p, "\n\r") {
			return fieldError("body.options.excludes", "A pattern can't contain a line break.", p)
		}
	}
	c.options = ScheduleOptions{Excludes: excludes, Keep: b.Options.Keep}
	if b.Source == nil {
		return fieldError("body.source", "Choose the folder to pack.", nil)
	}
	if len(b.Destinations) == 0 {
		return fieldError("body.destinations", "Choose at least one place to send it.", nil)
	}
	src, err := k.end("body.source", *b.Source, auth.Engineer, false, true)
	if err != nil {
		return err
	}
	if src.Path == "/" {
		return fieldError("body.source.path", "Choose a folder, not the whole disk.", b.Source.Path)
	}
	c.source = &src
	for i, d := range b.Destinations {
		loc := fmt.Sprintf("body.destinations[%d]", i)
		out, err := k.end(loc, d, auth.Engineer, true, false)
		if err != nil {
			return err
		}
		if out.id() == src.id() && storage.Within(out.Path, src.Path) {
			return fieldError(loc+".path", "The archives can't go inside the folder being packed: each would hold the ones before.", d.Path)
		}
		for j, other := range c.dests {
			if other.id() == out.id() && other.Path == out.Path {
				return fieldError(loc+".path", fmt.Sprintf("The same as destination %d.", j+1), d.Path)
			}
		}
		c.dests = append(c.dests, out)
	}
	return nil
}

// fetch downloads a URL into a folder on each destination server.
func (k *scheduleChecker) fetch(b ScheduleBody) error {
	c := k.c
	t := b.Task.Fetch
	if t == nil {
		return fieldError("body.task.fetch", "Say what to download.", nil)
	}
	u, err := url.Parse(strings.TrimSpace(t.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fieldError("body.task.fetch.url", "Enter a full http:// or https:// address.", t.URL)
	}
	if u.User != nil {
		return fieldError("body.task.fetch.url", "Leave the user name and password out of the address.", nil)
	}
	name := strings.TrimSpace(t.Name)
	if name == "" {
		name = urlName(u)
	}
	if name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return fieldError("body.task.fetch.name", "Not a valid file name.", name)
	}
	if len(b.Destinations) == 0 {
		return fieldError("body.destinations", "Choose at least one server folder.", nil)
	}
	for i, d := range b.Destinations {
		loc := fmt.Sprintf("body.destinations[%d]", i)
		out, err := k.end(loc, d, auth.Engineer, true, true)
		if err != nil {
			return err
		}
		for j, other := range c.dests {
			if other.id() == out.id() && other.Path == out.Path {
				return fieldError(loc+".path", fmt.Sprintf("The same as destination %d.", j+1), d.Path)
			}
		}
		c.dests = append(c.dests, out)
	}
	c.task.Fetch = &ScheduleFetch{URL: u.String(), Name: name, Overwrite: t.Overwrite}
	return nil
}

func (k *scheduleChecker) script(b ScheduleBody) error {
	t := b.Task.Script
	if t == nil {
		return fieldError("body.task.script", "Choose a script or write a command.", nil)
	}
	plan, err := k.h.scripts.plan(k.ctx, startScriptRunBody(*t), k.ws)
	if err != nil {
		return within("body.task.script", err)
	}
	out := ScheduleScript{Env: t.Env}
	for _, id := range plan.ids {
		out.ServerIDs = append(out.ServerIDs, id.String())
		k.addServer(id)
	}
	if plan.scriptID != nil {
		// A saved script is read again at each run, so edits to it count.
		id := plan.scriptID.String()
		out.ScriptID = &id
	} else {
		out.Name, out.Interpreter, out.Content = plan.src.Name, plan.src.Interpreter, plan.src.Content
		out.RunAs, out.TimeoutSeconds = plan.src.RunAs, plan.src.TimeoutSeconds
	}
	k.c.task.Script = &out
	return nil
}

func (k *scheduleChecker) playbook(b ScheduleBody) error {
	t := b.Task.Ansible
	if t == nil || t.PlaybookID == "" {
		return fieldError("body.task.ansible.playbook_id", "Choose a playbook.", nil)
	}
	id := t.PlaybookID
	plan, err := k.h.ansible.plan(k.ctx, k.ws, startRunBody{PlaybookID: &id, Selection: t.Selection, Options: t.Options})
	if err != nil {
		return within("body.task.ansible", err)
	}
	for _, id := range plan.ids {
		k.addServer(id)
	}
	k.c.task.Ansible = &ScheduleAnsible{PlaybookID: id, Selection: t.Selection, Options: t.Options}
	return nil
}

// serviceName is a unit as systemd names it, for the protected list.
func serviceName(unit string) string {
	if !strings.Contains(unit, ".") {
		return unit + ".service"
	}
	return unit
}

func (k *scheduleChecker) service(b ScheduleBody) error {
	t := b.Task.Service
	if t == nil {
		return fieldError("body.task.service", "Choose a service.", nil)
	}
	unit := strings.TrimSpace(t.Unit)
	if !unitRe.MatchString(unit) {
		return fieldError("body.task.service.unit", "Not a service name.", t.Unit)
	}
	// Operators keep services running, as by hand; forcing is for Engineers.
	need := auth.Operator
	if t.Force {
		need = auth.Engineer
	}
	if t.Action == "stop" && !t.Force && services.Protected(serviceName(unit)) {
		return fieldError("body.task.service.force", serviceName(unit)+" is protected: Morcheh or the system needs it. Tick Force to stop it anyway.", false)
	}
	ids, err := k.servers("body.task.service.server_ids", t.ServerIDs, need)
	if err != nil {
		return err
	}
	k.c.task.Service = &ScheduleService{ServerIDs: ids, Unit: unit, Action: t.Action, Force: t.Force}
	return nil
}

func (k *scheduleChecker) reboot(b ScheduleBody) error {
	t := b.Task.Reboot
	if t == nil {
		return fieldError("body.task.reboot", "Choose the servers.", nil)
	}
	ids, err := k.servers("body.task.reboot.server_ids", t.ServerIDs, auth.Operator)
	if err != nil {
		return err
	}
	k.c.task.Reboot = &ScheduleReboot{
		ServerIDs: ids, OnlyIfRequired: t.OnlyIfRequired, SkipIfLoggedIn: t.SkipIfLoggedIn,
		Message: strings.Join(strings.Fields(t.Message), " "),
	}
	return nil
}

func (k *scheduleChecker) verify(b ScheduleBody) error {
	t := b.Task.Verify
	if t == nil {
		return fieldError("body.task.verify.database_id", "Choose a database.", nil)
	}
	id, err := uuid.Parse(t.DatabaseID)
	if err != nil {
		return fieldError("body.task.verify.database_id", "Choose a database.", t.DatabaseID)
	}
	d, err := k.h.q.GetDatabase(k.ctx, id)
	if isNotFound(err) || (err == nil && d.WorkspaceID != k.ws) {
		return fieldError("body.task.verify.database_id", "This database isn't in this workspace.", t.DatabaseID)
	}
	if err != nil {
		return internalError(err)
	}
	switch l := databaseLevelOf(principalOf(k.ctx).Access, d); {
	case l == auth.None:
		return fieldError("body.task.verify.database_id", "Not found.", t.DatabaseID)
	case l < auth.Operator:
		return forbidden(auth.Operator)
	}
	out := &ScheduleVerify{DatabaseID: d.ID.String()}
	if pid := parseOptionalID(t.PlanID); pid != nil {
		plan, err := k.h.q.GetBackupPlan(k.ctx, *pid)
		if isNotFound(err) || (err == nil && plan.DatabaseID != d.ID) {
			return fieldError("body.task.verify.plan_id", "This plan isn't this database's.", *t.PlanID)
		}
		if err != nil {
			return internalError(err)
		}
		s := plan.ID.String()
		out.PlanID = &s
	}
	k.c.task.Verify = out
	return nil
}

// ---- Running ----

// taskRun is one run of a non-sync action, with its per-row results.
type taskRun struct {
	h       *scheduleHandler
	t       *jobs.Task
	id      uuid.UUID
	ws      uuid.UUID
	who     string
	acc     *auth.Access
	plan    schedulePlan
	loc     *time.Location
	results []ScheduleRunDest
	files   int
	bytes   int64
}

func (h *scheduleHandler) runTask(ctx context.Context, t *jobs.Task) (any, error) {
	var params scheduleRunParams
	if err := t.Decode(&params); err != nil {
		return nil, err
	}
	bg := context.WithoutCancel(ctx)
	run, err := h.q.GetScheduleRun(ctx, params.RunID)
	if isNotFound(err) {
		return nil, errors.New("The cron job was deleted before this run started.")
	}
	if err != nil {
		return nil, err
	}
	if !jobs.Active(run.State) {
		return nil, nil
	}
	fail := func(err error) (any, error) {
		_ = h.q.EndScheduleRun(bg, sqlc.EndScheduleRunParams{ID: run.ID, State: jobs.Failed, Error: problemText(err)})
		return nil, err
	}
	s, err := h.q.GetSchedule(ctx, run.ScheduleID)
	if err != nil {
		return fail(errors.New("The cron job was deleted before this run started."))
	}
	if err := h.q.StartScheduleRun(ctx, run.ID); err != nil {
		return nil, err
	}
	u, who, acc, err := h.runUser(ctx, s)
	if err != nil {
		return fail(err)
	}
	// Everything below acts as that person, checked as when done by hand.
	ctx = context.WithValue(ctx, principalKey{}, &principal{User: u, Access: acc})
	r := &taskRun{
		h: h, t: t, id: run.ID, ws: s.WorkspaceID, who: who, acc: acc,
		plan: decodePlan(run.Plan), loc: scheduleLoc(s.Timezone), results: []ScheduleRunDest{},
	}
	switch r.plan.Action {
	case "script":
		return r.script(ctx)
	case "ansible":
		return r.playbook(ctx)
	case "service":
		return r.service(ctx)
	case "reboot":
		return r.reboot(ctx)
	case "fetch":
		return r.fetch(ctx)
	case "archive":
		return r.archive(ctx)
	case "verify-backup":
		return r.verify(ctx)
	}
	return fail(fmt.Errorf("Unknown action %q.", r.plan.Action))
}

func (r *taskRun) save() {
	raw, _ := json.Marshal(r.results)
	if err := r.h.q.SaveScheduleRunResults(context.Background(), sqlc.SaveScheduleRunResultsParams{
		ID: r.id, Results: raw, Files: int32(r.files), Bytes: r.bytes,
	}); err != nil {
		slog.Warn("save a cron job run", "run", r.id, "error", err)
	}
}

// rows starts one pending row per end.
func (r *taskRun) rows(ends []ScheduleEndView) {
	r.results = make([]ScheduleRunDest, len(ends))
	for i, e := range ends {
		r.results[i] = ScheduleRunDest{ScheduleEndView: e, State: "pending"}
	}
	r.save()
}

func (r *taskRun) begin(i int, phase string) {
	now := time.Now()
	r.results[i].State, r.results[i].StartedAt = "running", &now
	r.save()
	label := fmt.Sprintf("%s (%d of %d)", r.results[i].Name, i+1, len(r.results))
	r.t.Update(func(p *jobs.Progress) {
		p.Phase, p.Current, p.Items, p.ItemsTotal = phase+" "+label, "", i, len(r.results)
	})
}

// end records how row i went; note says what happened when it worked.
func (r *taskRun) end(ctx context.Context, i int, err error, note string) {
	row := &r.results[i]
	now := time.Now()
	row.FinishedAt = &now
	switch {
	case err != nil && ctx.Err() != nil:
		row.State = "canceled"
	case err != nil:
		row.State, row.Error = "failed", problemText(jobError(err))
		r.t.Logf("%s: %s", row.Name, row.Error)
	default:
		row.State, row.Note = "succeeded", note
		if note != "" {
			r.t.Logf("%s: %s", row.Name, note)
		} else {
			r.t.Logf("%s: done", row.Name)
		}
	}
	r.save()
}

func (r *taskRun) skip(i int, note string) {
	now := time.Now()
	r.results[i].State, r.results[i].Note, r.results[i].FinishedAt = "skipped", note, &now
	r.t.Logf("%s: skipped, %s", r.results[i].Name, strings.ToLower(note[:1])+note[1:])
	r.save()
}

func (r *taskRun) link(kind string, id uuid.UUID) {
	raw, _ := json.Marshal(ScheduleRunLink{Kind: kind, ID: id.String()})
	if err := r.h.q.SetScheduleRunLink(context.Background(), sqlc.SetScheduleRunLinkParams{ID: r.id, Link: raw}); err != nil {
		slog.Warn("link a cron job run", "run", r.id, "error", err)
	}
}

func (r *taskRun) finish(ctx context.Context, failMsg string) (any, error) {
	return r.h.endRun(ctx, r.t, r.id, r.results, r.files, r.bytes, failMsg)
}

// asWho words a refusal checked as the person the job runs as.
func (r *taskRun) asWho(err error) string {
	return fmt.Sprintf("Checked as %s: %s", r.who, problemText(jobError(err)))
}

// ended closes a run that handed its work to a script or Ansible run.
func (r *taskRun) ended(ctx context.Context, state, msg string, execErr error) (any, error) {
	switch {
	case ctx.Err() != nil && r.t.Canceled():
		state = jobs.Canceled
	case ctx.Err() != nil:
		state, msg = jobs.Interrupted, "Morcheh stopped before it finished."
	case state == jobs.Succeeded:
		msg = ""
	case jobs.Active(state) || state == "":
		state = jobs.Failed
		fallthrough
	default:
		if msg == "" && execErr != nil {
			msg = problemText(jobError(execErr))
		}
		msg = cmpOr(msg, "It failed.")
	}
	return r.h.closeRun(ctx, r.id, state, msg, r.results, r.files, r.bytes)
}

func (r *taskRun) script(ctx context.Context) (any, error) {
	t := r.plan.Task.Script
	if t == nil {
		return r.finish(ctx, "It has nothing to run.")
	}
	plan, err := r.h.scripts.plan(ctx, startScriptRunBody(*t), r.ws)
	if err != nil {
		return r.finish(ctx, r.asWho(err))
	}
	run, err := r.h.scripts.create(ctx, plan)
	if err != nil {
		return r.finish(ctx, problemText(err))
	}
	jobID := r.t.ID
	if err := r.h.q.SetScriptRunJob(ctx, sqlc.SetScriptRunJobParams{JobID: &jobID, ID: run.ID}); err != nil {
		slog.Warn("link a script run to its job", "run", run.ID, "error", err)
	}
	r.link("script-run", run.ID)
	r.t.Logf("Running %s on %d server(s)", plan.src.Name, len(plan.ids))
	_, execErr := r.h.scripts.execute(ctx, r.t, run.ID)
	done, err := r.h.q.GetScriptRun(context.WithoutCancel(ctx), run.ID)
	if err != nil {
		return r.ended(ctx, jobs.Failed, "", execErr)
	}
	return r.ended(ctx, done.State, done.Error, execErr)
}

func (r *taskRun) playbook(ctx context.Context) (any, error) {
	t := r.plan.Task.Ansible
	if t == nil {
		return r.finish(ctx, "It has no playbook.")
	}
	id := t.PlaybookID
	plan, err := r.h.ansible.plan(ctx, r.ws, startRunBody{PlaybookID: &id, Selection: t.Selection, Options: t.Options})
	if err != nil {
		return r.finish(ctx, r.asWho(err))
	}
	run, err := r.h.ansible.create(ctx, plan)
	if err != nil {
		return r.finish(ctx, problemText(err))
	}
	jobID := r.t.ID
	if err := r.h.q.SetAnsibleRunJob(ctx, sqlc.SetAnsibleRunJobParams{JobID: &jobID, ID: run.ID}); err != nil {
		slog.Warn("link an Ansible run to its job", "run", run.ID, "error", err)
	}
	r.link("ansible-run", run.ID)
	r.t.Logf("Running %s on %d server(s)", plan.name, len(plan.ids))
	_, execErr := r.h.ansible.execute(ctx, r.t, ansibleRunParams{RunID: run.ID, AllowNoSandbox: r.acc.Admin})
	done, err := r.h.q.GetAnsibleRun(context.WithoutCancel(ctx), run.ID)
	if err != nil {
		return r.ended(ctx, jobs.Failed, "", execErr)
	}
	return r.ended(ctx, done.State, done.Error, execErr)
}

func (r *taskRun) service(ctx context.Context) (any, error) {
	t := r.plan.Task.Service
	if t == nil {
		return r.finish(ctx, "It has no service.")
	}
	r.rows(r.plan.Destinations)
	need := auth.Operator
	if t.Force {
		need = auth.Engineer
	}
	done := map[string]string{"start": "Started", "stop": "Stopped", "restart": "Restarted", "reload": "Reloaded"}[t.Action]
	srv := r.h.st.servers
	for i, d := range r.plan.Destinations {
		if ctx.Err() != nil {
			break
		}
		r.begin(i, map[string]string{"start": "Starting", "stop": "Stopping", "restart": "Restarting", "reload": "Reloading"}[t.Action]+" "+t.Unit+" on")
		err := mayUse(r.acc, r.ws, d, need, r.who)
		note := ""
		if err == nil {
			err = srv.withService(ctx, &ServicePath{ID: *d.ServerID, Unit: t.Unit}, true, func(sh *rootShell, init, unit string) error {
				if t.Action == "stop" && !t.Force && services.Protected(unit) {
					return errors.New(unit + " is protected, so it wasn't stopped. Edit the cron job and tick Force to stop it anyway.")
				}
				script, err := actionScript(init, unit, ServiceActionBody{Action: t.Action, Force: t.Force})
				if err != nil {
					return err
				}
				note = done + " " + unit + "."
				return runChange(ctx, sh, script)
			})
		}
		r.end(ctx, i, err, note)
	}
	return r.finish(ctx, "")
}

func (r *taskRun) reboot(ctx context.Context) (any, error) {
	t := r.plan.Task.Reboot
	if t == nil {
		return r.finish(ctx, "It has no servers.")
	}
	r.rows(r.plan.Destinations)
	for i, d := range r.plan.Destinations {
		if ctx.Err() != nil {
			break
		}
		r.begin(i, "Rebooting")
		skip, note, sent, err := r.rebootOne(ctx, d, t)
		if skip {
			r.skip(i, note)
			continue
		}
		r.end(ctx, i, err, note)
		if err != nil && sent && ctx.Err() == nil {
			// One didn't come back: don't take the next ones down too.
			for j := i + 1; j < len(r.results); j++ {
				r.results[j].State, r.results[j].Note = "canceled", "Not rebooted: "+d.Name+" didn't come back."
			}
			r.save()
			break
		}
	}
	return r.finish(ctx, "")
}

const bootTimeCmd = `awk '/^btime/{print $2}' /proc/stat`

// rebootOne reboots a server and waits until it is back (a later boot time).
// sent = the reboot command went out.
func (r *taskRun) rebootOne(ctx context.Context, d ScheduleEndView, t *ScheduleReboot) (skip bool, note string, sent bool, err error) {
	if err = mayUse(r.acc, r.ws, d, auth.Operator, r.who); err != nil {
		return
	}
	id := *d.ServerID
	srv := r.h.st.servers
	var before time.Time
	err = srv.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := srv.powerRoot(ctx, id, c)
		if err != nil {
			return err
		}
		facts, err := sh.run(ctx, powerScript)
		if err != nil {
			return err
		}
		o := parsePower(facts)
		switch {
		case t.OnlyIfRequired && !o.RebootRequired:
			skip, note = true, "It doesn't need a reboot."
			return nil
		case t.SkipIfLoggedIn && o.Sessions > 0:
			skip, note = true, fmt.Sprintf("%d login session(s) open.", o.Sessions)
			return nil
		case o.BootTime.IsZero():
			return errors.New("Couldn't read when it last started, so it wasn't rebooted (its return couldn't be told).")
		}
		before = o.BootTime
		if _, err := sh.run(ctx, powerCommand("reboot", 0, t.Message)); err != nil {
			return err
		}
		sent = true
		return nil
	})
	if err != nil || skip {
		return
	}
	r.t.Logf("%s: rebooting", d.Name)
	started := time.Now()
	r.t.Update(func(p *jobs.Progress) { p.Phase = "Waiting for " + d.Name + " to come back" })
	// The command runs a couple of seconds after the session ends.
	if err = sleepCtx(ctx, 5*time.Second); err != nil {
		return
	}
	srv.pool.Drop(id)
	deadline := started.Add(15 * time.Minute)
	for {
		if err = sleepCtx(ctx, 10*time.Second); err != nil {
			return
		}
		actx, cancel := context.WithTimeout(ctx, 20*time.Second)
		var out string
		e := srv.withConn(actx, id, func(c *sshpool.Conn) error {
			var err error
			out, err = run(actx, c, bootTimeCmd)
			return err
		})
		cancel()
		if e == nil {
			if n, perr := strconv.ParseInt(strings.TrimSpace(out), 10, 64); perr == nil && time.Unix(n, 0).After(before) {
				note = "Back after " + time.Since(started).Round(time.Second).String() + "."
				return
			}
		} else {
			srv.pool.Drop(id)
		}
		if time.Now().After(deadline) {
			err = errors.New("It didn't come back within 15 minutes.")
			return
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

func (r *taskRun) fetch(ctx context.Context) (any, error) {
	t := r.plan.Task.Fetch
	if t == nil {
		return r.finish(ctx, "It has nothing to download.")
	}
	r.rows(r.plan.Destinations)
	srv := r.h.st.servers
	for i, d := range r.plan.Destinations {
		if ctx.Err() != nil {
			break
		}
		r.begin(i, "Downloading to")
		err := mayUse(r.acc, r.ws, d, auth.Engineer, r.who)
		note := ""
		if err == nil {
			var fe FileEntry
			fe, err = srv.fetch(ctx, r.t, fetchParams{ServerID: *d.ServerID, URL: t.URL, Dir: d.Path, Name: t.Name, Overwrite: t.Overwrite, MakeDir: true})
			if err == nil {
				r.results[i].Copied, r.results[i].Bytes = 1, fe.Size
				r.files, r.bytes = r.files+1, r.bytes+fe.Size
				note = fmt.Sprintf("Saved %s (%s).", path.Join(d.Path, t.Name), humanBytes(fe.Size))
			}
		}
		r.end(ctx, i, err, note)
	}
	return r.finish(ctx, "")
}

// archiveSuffix ends every archive the action makes; with the time before it
// that's how old ones are told apart from other files when pruning.
const archiveSuffix = ".tar.gz"

func (r *taskRun) archive(ctx context.Context) (any, error) {
	src := r.plan.Source
	if src == nil || src.ServerID == nil {
		return r.finish(ctx, "It has no folder to pack.")
	}
	if err := mayUse(r.acc, r.ws, *src, auth.Engineer, r.who); err != nil {
		return r.finish(ctx, "Source: "+problemText(err))
	}
	r.rows(r.plan.Destinations)
	srv := r.h.st.servers
	srcID := *src.ServerID
	base := path.Base(src.Path)
	name := base + "-" + time.Now().In(r.loc).Format(storage.SnapshotLayout) + archiveSuffix

	// Packed into a temporary folder on the source, removed afterwards.
	var tmp string
	err := srv.withConn(ctx, srcID, func(c *sshpool.Conn) error {
		out, err := run(ctx, c, "mktemp -d /var/tmp/morcheh-archive.XXXXXX")
		tmp = strings.TrimSpace(out)
		return err
	})
	if err == nil && !strings.HasPrefix(tmp, "/var/tmp/morcheh-archive.") {
		err = errors.New("Couldn't make a temporary folder in /var/tmp.")
	}
	if err != nil {
		return r.finish(ctx, "Source "+src.Name+": "+problemText(jobError(err)))
	}
	defer func() {
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		if err := srv.withConn(bg, srcID, func(c *sshpool.Conn) error {
			_, err := run(bg, c, "rm -rf -- "+terminal.ShellQuote(tmp))
			return err
		}); err != nil {
			slog.Warn("remove a cron job's temporary archive", "server", srcID, "path", tmp, "error", err)
		}
	}()
	r.t.Update(func(p *jobs.Progress) { p.Phase, p.Current = "Packing "+src.Path, "" })
	archive := path.Join(tmp, name)
	fe, err := srv.compress(ctx, r.t, compressParams{
		ServerID: srcID, Dir: path.Dir(src.Path), Names: []string{base}, Dest: archive, Format: "tar.gz",
		Excludes: r.plan.Options.Excludes,
	})
	if err != nil {
		return r.finish(ctx, "Packing "+src.Name+":"+src.Path+": "+problemText(jobError(err)))
	}
	r.t.Logf("Packed %s (%s)", name, humanBytes(fe.Size))

	srcErr := r.h.st.with(ctx, StorageTransferEnd{ServerID: &srcID}, func(sp place) error {
		for i, d := range r.plan.Destinations {
			if ctx.Err() != nil {
				break
			}
			r.begin(i, "Sending to")
			err := mayUse(r.acc, r.ws, d, auth.Engineer, r.who)
			var res storage.SyncResult
			if err == nil {
				err = r.h.st.with(ctx, d.transferEnd(), func(dp place) error {
					if dp.readOnly {
						return errors.New(dp.name + " is read-only in Morcheh.")
					}
					r.t.Update(func(p *jobs.Progress) { p.Done, p.Total = 0, fe.Size })
					var prog storage.Progress
					prog.OnBytes = r.t.Add
					var err error
					res, err = storage.Sync(ctx, sp.fs, archive, dp.fs, d.Path, storage.SyncOptions{
						Mode: storage.SyncUpdate, Now: time.Now().In(r.loc),
					}, &prog)
					if err != nil {
						return err
					}
					if res.Failed > 0 {
						return errors.New("The archive couldn't be copied.")
					}
					if keep := r.plan.Options.Keep; keep > 0 {
						n, err := pruneArchives(ctx, dp.fs, d.Path, base, keep)
						res.Deleted += n
						if err != nil {
							r.t.Logf("%s: couldn't remove an old archive: %s", d.Name, problemText(err))
						}
					}
					return nil
				})
			}
			r.results[i].SyncResult = res
			r.files, r.bytes = r.files+res.Copied, r.bytes+res.Bytes
			note := "Saved " + path.Join(d.Path, name) + "."
			if res.Deleted > 0 {
				note += fmt.Sprintf(" Removed %d older.", res.Deleted)
			}
			r.end(ctx, i, err, note)
		}
		return nil
	})
	failMsg := ""
	if srcErr != nil {
		failMsg = "Source " + src.Name + ": " + problemText(srcErr)
	}
	return r.finish(ctx, failMsg)
}

// pruneArchives removes all but the newest keep archives of base in dir:
// files named <base>-<time>.tar.gz, the time as the action writes it.
func pruneArchives(ctx context.Context, f storage.FS, dir, base string, keep int) (int, error) {
	entries, err := f.List(ctx, dir, 100000)
	if err != nil {
		return 0, err
	}
	type found struct {
		name string
		at   time.Time
	}
	var all []found
	prefix := base + "-"
	for _, e := range entries {
		if e.Dir || !strings.HasPrefix(e.Name, prefix) || !strings.HasSuffix(e.Name, archiveSuffix) {
			continue
		}
		stamp := strings.TrimSuffix(strings.TrimPrefix(e.Name, prefix), archiveSuffix)
		at, err := time.Parse(storage.SnapshotLayout, stamp)
		if err != nil {
			continue
		}
		all = append(all, found{e.Name, at})
	}
	if len(all) <= keep {
		return 0, nil
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.After(all[j].at) })
	n := 0
	for _, old := range all[keep:] {
		if err := f.Remove(ctx, path.Join(dir, old.name)); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (r *taskRun) verify(ctx context.Context) (any, error) {
	t := r.plan.Task.Verify
	if t == nil {
		return r.finish(ctx, "It has no database.")
	}
	d, err := r.h.q.GetDatabase(ctx, parseID(t.DatabaseID))
	if isNotFound(err) || (err == nil && d.WorkspaceID != r.ws) {
		return r.finish(ctx, "The database was deleted.")
	}
	if err != nil {
		return r.finish(ctx, problemText(err))
	}
	if databaseLevelOf(r.acc, d) < auth.Operator {
		return r.finish(ctx, fmt.Sprintf("%s no longer has Operator access to %s.", r.who, d.Name))
	}
	r.link("database", d.ID)
	backups, err := r.h.q.LatestGoodBackups(ctx, sqlc.LatestGoodBackupsParams{DatabaseID: d.ID, PlanID: parseOptionalID(t.PlanID)})
	if err != nil {
		return r.finish(ctx, problemText(err))
	}
	if len(backups) == 0 {
		return r.finish(ctx, "There's no finished backup to check yet.")
	}
	ends := make([]ScheduleEndView, len(backups))
	for i, b := range backups {
		ends[i] = ScheduleEndView{
			ScheduleEnd: ScheduleEnd{Path: b.Path},
			Name:        cmpOr(b.Target, d.Name) + " · " + b.CreatedAt.In(r.loc).Format("2006-01-02 15:04"),
		}
	}
	r.rows(ends)
	for i, b := range backups {
		if ctx.Err() != nil {
			break
		}
		r.begin(i, "Checking")
		_, err := r.h.backups.verify(ctx, r.t, b)
		note := ""
		if err == nil {
			note = "Every copy reads back intact (" + humanBytes(b.Bytes) + ")."
			r.files, r.bytes = r.files+1, r.bytes+b.Bytes
		}
		r.end(ctx, i, err, note)
	}
	return r.finish(ctx, "")
}
