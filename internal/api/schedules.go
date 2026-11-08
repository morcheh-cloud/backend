package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	_ "time/tzdata" // schedules name IANA zones; the host may have none

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/robfig/cron/v3"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/storage"
)

// Schedules are cron jobs Morcheh runs itself (the panel calls them "Cron
// jobs"; "cron" in this package is a server's crontab). An action says what
// one does: sync copies files from a server or storage to servers and
// storages (job kind schedule-sync); every other action runs as schedule-run
// (schedule_actions.go).

const (
	scheduleSyncKind = "schedule-sync"
	scheduleRunKind  = "schedule-run"
	// Runs kept per schedule; older ones are deleted as new ones start.
	scheduleRunsKept = 200
	maxDestinations  = 20
)

// ---- Types ----

type ScheduleEnd struct {
	ServerID  *string `json:"server_id,omitempty" format:"uuid" doc:"Exactly one of server_id and storage_id"`
	StorageID *string `json:"storage_id,omitempty" format:"uuid"`
	Path      string  `json:"path" minLength:"1" maxLength:"4096" doc:"Absolute path. The source may be a file or a folder; a destination is a folder" example:"/var/www"`
}

func (e ScheduleEnd) id() uuid.UUID {
	if id := parseOptionalID(e.ServerID); id != nil {
		return *id
	}
	if id := parseOptionalID(e.StorageID); id != nil {
		return *id
	}
	return uuid.Nil
}

func (e ScheduleEnd) transferEnd() StorageTransferEnd {
	return StorageTransferEnd{ServerID: e.ServerID, StorageID: e.StorageID}
}

// ScheduleEndView is an end with what it points at.
type ScheduleEndView struct {
	ScheduleEnd
	Name    string `json:"name" doc:"The server's or storage's name; empty when it was deleted"`
	Missing bool   `json:"missing" doc:"The server or storage was deleted"`
}

type ScheduleOptions struct {
	Mode     string   `json:"mode" enum:"update,mirror,snapshot" doc:"update: copy new and changed files. mirror: also delete what the source no longer has. snapshot: a full copy in a new dated folder each run" default:"update"`
	Excludes []string `json:"excludes,omitempty" maxItems:"100" doc:"Glob patterns to leave out; without a slash they match a name at any depth" example:"[\"*.log\",\"node_modules\"]"`
	Keep     int      `json:"keep,omitempty" minimum:"0" maximum:"1000" doc:"Snapshots to keep (snapshot mode), or archives (archive action); 0 = all"`
}

type ScheduleRunBrief struct {
	ID         string     `json:"id" format:"uuid"`
	State      string     `json:"state" enum:"queued,running,succeeded,partial,failed,canceled,interrupted"`
	At         time.Time  `json:"at"`
	FinishedAt *time.Time `json:"finished_at"`
	Error      string     `json:"error"`
}

type Schedule struct {
	ID           string            `json:"id" format:"uuid"`
	WorkspaceID  string            `json:"workspace_id" format:"uuid"`
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	Action       string            `json:"action" enum:"sync,script,ansible,service,reboot,fetch,archive,verify-backup"`
	Cron         string            `json:"cron" example:"0 3 * * *"`
	Timezone     string            `json:"timezone" example:"Asia/Tehran"`
	Enabled      bool              `json:"enabled"`
	Source       *ScheduleEndView  `json:"source,omitempty" doc:"sync and archive"`
	Destinations []ScheduleEndView `json:"destinations" doc:"sync, archive and fetch"`
	Options      ScheduleOptions   `json:"options"`
	Task         ScheduleTask      `json:"task"`
	Refs         []ScheduleRef     `json:"refs" doc:"What the task names (servers, script, playbook, database), with names"`
	NextRunAt    *time.Time        `json:"next_run_at" doc:"null while paused"`
	LastRun      *ScheduleRunBrief `json:"last_run"`
	RunAsID      *string           `json:"run_as_id" format:"uuid" doc:"Runs use this person's access: whoever saved it last"`
	RunAsName    string            `json:"run_as_name"`
	// Why it can't run as it is, checked when listing: the person is gone or
	// blocked, or a server or storage was deleted.
	Problem   string    `json:"problem"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ScheduleBody struct {
	Name         string          `json:"name" minLength:"1" maxLength:"100"`
	Description  string          `json:"description,omitempty" maxLength:"2000"`
	Cron         string          `json:"cron" minLength:"1" maxLength:"200" doc:"Five fields (minute hour day month weekday), or @hourly, @daily, @weekly, @monthly, @every 2h" example:"0 3 * * *"`
	Timezone     string          `json:"timezone,omitempty" maxLength:"64" doc:"IANA zone the times are read in; default UTC" example:"Asia/Tehran"`
	Enabled      *bool           `json:"enabled,omitempty" doc:"Default true"`
	Action       string          `json:"action,omitempty" enum:"sync,script,ansible,service,reboot,fetch,archive,verify-backup" default:"sync" doc:"What it does. sync and archive use source and destinations, fetch only destinations (server folders); the rest use task"`
	Source       *ScheduleEnd    `json:"source,omitempty"`
	Destinations []ScheduleEnd   `json:"destinations,omitempty" maxItems:"20"`
	Options      ScheduleOptions `json:"options,omitempty"`
	Task         ScheduleTask    `json:"task,omitempty"`
}

type ScheduleUpdate struct {
	ScheduleBody
	Revision *time.Time `json:"revision,omitempty" doc:"updated_at when you loaded it; 409 when it changed since"`
}

type ScheduleOutput struct{ Body Schedule }

// ScheduleRunDest is what a run did at one destination.
type ScheduleRunDest struct {
	ScheduleEndView
	State string `json:"state" enum:"pending,running,succeeded,partial,failed,canceled,skipped" doc:"partial: some files couldn't be copied. skipped: nothing to do there (a reboot that wasn't needed)"`
	Error string `json:"error"`
	Note  string `json:"note,omitempty" doc:"What happened, when it isn't an error"`
	storage.SyncResult
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

// schedulePlan is what a run was started with. Destinations are also the
// servers a service action or reboot goes through.
type schedulePlan struct {
	Action       string            `json:"action"`
	Source       *ScheduleEndView  `json:"source"`
	Destinations []ScheduleEndView `json:"destinations"`
	Options      ScheduleOptions   `json:"options"`
	Task         ScheduleTask      `json:"task"`
	Name         string            `json:"name"`
}

// ScheduleRunLink is the record a run made elsewhere: a script run, an
// Ansible run, or the database whose backups it checked.
type ScheduleRunLink struct {
	Kind string `json:"kind" enum:"script-run,ansible-run,database"`
	ID   string `json:"id" format:"uuid"`
}

type ScheduleRun struct {
	ID            string            `json:"id" format:"uuid"`
	ScheduleID    string            `json:"schedule_id" format:"uuid"`
	Trigger       string            `json:"trigger" enum:"schedule,manual"`
	DryRun        bool              `json:"dry_run" doc:"A test run: counted, nothing changed"`
	State         string            `json:"state" enum:"queued,running,succeeded,partial,failed,canceled,interrupted,skipped"`
	Error         string            `json:"error"`
	Action        string            `json:"action" enum:"sync,script,ansible,service,reboot,fetch,archive,verify-backup"`
	Source        *ScheduleEndView  `json:"source,omitempty"`
	Options       ScheduleOptions   `json:"options"`
	Results       []ScheduleRunDest `json:"results" doc:"One row per destination, server or backup checked"`
	Link          *ScheduleRunLink  `json:"link,omitempty"`
	Files         int               `json:"files" doc:"Files copied in all"`
	Bytes         int64             `json:"bytes"`
	JobID         *string           `json:"job_id" format:"uuid"`
	Progress      *jobs.Progress    `json:"progress" doc:"While it runs"`
	CreatedByName string            `json:"created_by_name" doc:"Who pressed Run now; empty for a run on time"`
	CreatedAt     time.Time         `json:"created_at"`
	StartedAt     *time.Time        `json:"started_at"`
	FinishedAt    *time.Time        `json:"finished_at"`
}

// ---- Handler ----

type scheduleHandler struct {
	q       *sqlc.Queries
	st      *storageHandler
	authz   *authz
	runner  *jobs.Runner
	scripts *scriptHandler
	ansible *ansibleHandler
	backups *backupHandler
}

func newScheduleHandler(st *storageHandler, a *authz, scripts *scriptHandler, playbooks *ansibleHandler, backups *backupHandler) *scheduleHandler {
	return &scheduleHandler{
		q: st.q, st: st, authz: a, runner: st.servers.jobs,
		scripts: scripts, ansible: playbooks, backups: backups,
	}
}

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// parseCron reads an expression in a zone.
func parseCron(expr, tz string) (cron.Schedule, *time.Location, error) {
	expr = strings.TrimSpace(expr)
	loc, err := time.LoadLocation(cmpOr(strings.TrimSpace(tz), "UTC"))
	if err != nil {
		return nil, nil, fieldError("body.timezone", "Unknown time zone.", tz)
	}
	if strings.HasPrefix(expr, "CRON_TZ=") || strings.HasPrefix(expr, "TZ=") {
		return nil, nil, fieldError("body.cron", "Set the time zone in its own field.", expr)
	}
	s, err := cronParser.Parse(expr)
	if err != nil {
		return nil, nil, fieldError("body.cron", "Not a valid schedule: "+err.Error(), expr)
	}
	if every, ok := s.(cron.ConstantDelaySchedule); ok && every.Delay < time.Minute {
		return nil, nil, fieldError("body.cron", "Runs can't be less than a minute apart.", expr)
	}
	if s.Next(time.Now().In(loc)).IsZero() {
		return nil, nil, fieldError("body.cron", "This schedule never comes round.", expr)
	}
	return s, loc, nil
}

// nextRun is the first time after `after` the schedule fires.
func nextRun(expr, tz string, after time.Time) *time.Time {
	s, loc, err := parseCron(expr, tz)
	if err != nil {
		return nil
	}
	t := s.Next(after.In(loc))
	if t.IsZero() {
		return nil
	}
	return &t
}

// ---- Reading ----

// names looks up what ends and people point at.
type scheduleNames struct {
	ends  map[uuid.UUID]sqlc.ListScheduleEndNamesRow
	users map[uuid.UUID]sqlc.ListUserNamesRow
}

func (h *scheduleHandler) names(ctx context.Context, ends []uuid.UUID, users []uuid.UUID) (scheduleNames, error) {
	n := scheduleNames{ends: map[uuid.UUID]sqlc.ListScheduleEndNamesRow{}, users: map[uuid.UUID]sqlc.ListUserNamesRow{}}
	if len(ends) > 0 {
		rows, err := h.q.ListScheduleEndNames(ctx, ends)
		if err != nil {
			return n, err
		}
		for _, r := range rows {
			n.ends[r.ID] = r
		}
	}
	if len(users) > 0 {
		rows, err := h.q.ListUserNames(ctx, users)
		if err != nil {
			return n, err
		}
		for _, r := range rows {
			n.users[r.ID] = r
		}
	}
	return n, nil
}

func (n scheduleNames) view(e ScheduleEnd) ScheduleEndView {
	r, ok := n.ends[e.id()]
	return ScheduleEndView{ScheduleEnd: e, Name: r.Name, Missing: !ok}
}

func decodeEnds(raw []byte) []ScheduleEnd {
	var out []ScheduleEnd
	decodeInto(raw, &out)
	return out
}

// scheduleEndIDs is everything a schedule points at, for the names lookup
// and the job's refs.
func scheduleEndIDs(s sqlc.Schedule) []uuid.UUID {
	var task ScheduleTask
	decodeInto(s.Task, &task)
	return append(append(append([]uuid.UUID{}, s.ServerIds...), s.StorageIds...), refIDs(taskRefs(s.Action, task))...)
}

func (h *scheduleHandler) toSchedule(s sqlc.Schedule, n scheduleNames, last *ScheduleRunBrief) Schedule {
	var opts ScheduleOptions
	decodeInto(s.Options, &opts)
	out := Schedule{
		ID: s.ID.String(), WorkspaceID: s.WorkspaceID.String(), Name: s.Name, Description: s.Description,
		Action: s.Action, Cron: s.Cron, Timezone: s.Timezone, Enabled: s.Enabled,
		Options: opts, NextRunAt: s.NextRunAt, LastRun: last,
		RunAsID: optionalIDString(s.UpdatedBy), CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
	decodeInto(s.Task, &out.Task)
	if opts.Mode == "" && s.Action == "sync" {
		out.Options.Mode = storage.SyncUpdate
	}
	missing := false
	if usesSource(s.Action) {
		var src ScheduleEnd
		decodeInto(s.Source, &src)
		v := n.view(src)
		out.Source, missing = &v, v.Missing
	}
	out.Refs = taskRefs(s.Action, out.Task)
	for i, r := range out.Refs {
		row, ok := n.ends[parseID(r.ID)]
		out.Refs[i].Name, out.Refs[i].Missing = row.Name, !ok
		missing = missing || !ok
	}
	for _, d := range decodeEnds(s.Destinations) {
		v := n.view(d)
		missing = missing || v.Missing
		out.Destinations = append(out.Destinations, v)
	}
	if out.Destinations == nil {
		out.Destinations = []ScheduleEndView{}
	}
	if s.UpdatedBy != nil {
		if u, ok := n.users[*s.UpdatedBy]; ok {
			out.RunAsName = cmpOr(u.FullName, u.Username)
			if u.Status != "active" {
				out.Problem = out.RunAsName + "'s account isn't active, so this can't run. Someone with access should open it and save it."
			}
		}
	}
	switch {
	case s.UpdatedBy == nil || out.RunAsName == "":
		out.Problem = "The person who saved it was removed, so this can't run. Someone with access should open it and save it."
	case missing:
		out.Problem = "Something it uses (a server, storage, script, playbook or database) was deleted. Edit it to choose another."
	}
	return out
}

func (h *scheduleHandler) one(ctx context.Context, s sqlc.Schedule) (Schedule, error) {
	var users []uuid.UUID
	if s.UpdatedBy != nil {
		users = append(users, *s.UpdatedBy)
	}
	n, err := h.names(ctx, scheduleEndIDs(s), users)
	if err != nil {
		return Schedule{}, internalError(err)
	}
	rows, err := h.q.ListScheduleRuns(ctx, sqlc.ListScheduleRunsParams{ScheduleID: s.ID, Lim: 5})
	if err != nil {
		return Schedule{}, internalError(err)
	}
	var last *ScheduleRunBrief
	for _, r := range rows {
		if r.State == "skipped" {
			continue
		}
		if h.syncRun(ctx, r) {
			if r, err = h.q.GetScheduleRun(ctx, r.ID); err != nil {
				return Schedule{}, internalError(err)
			}
		}
		last = &ScheduleRunBrief{ID: r.ID.String(), State: r.State, At: r.CreatedAt, FinishedAt: r.FinishedAt, Error: r.Error}
		break
	}
	return h.toSchedule(s, n, last), nil
}

func (h *scheduleHandler) load(ctx context.Context, rawID string) (sqlc.Schedule, error) {
	s, err := h.q.GetSchedule(ctx, uuid.MustParse(rawID))
	if isNotFound(err) {
		return s, huma.Error404NotFound("cron job not found")
	}
	if err != nil {
		return s, internalError(err)
	}
	return s, nil
}

// ---- Checking what's saved ----

type checkedSchedule struct {
	action                string
	cron, tz              string
	source                *ScheduleEnd
	dests                 []ScheduleEnd
	options               ScheduleOptions
	task                  ScheduleTask
	serverIDs, storageIDs []uuid.UUID
	sourceJSON, destsJSON []byte
	optionsJSON, taskJSON []byte
}

// check validates a body for workspace ws with the caller's access, the same
// rules as doing it by hand: for a sync, Operator on the source (reading it)
// and Engineer on every destination (writing, and deleting in mirror mode).
// The other actions are checked in schedule_actions.go.
func (h *scheduleHandler) check(ctx context.Context, ws uuid.UUID, b ScheduleBody) (checkedSchedule, error) {
	c := checkedSchedule{cron: strings.TrimSpace(b.Cron), tz: cmpOr(strings.TrimSpace(b.Timezone), "UTC"), action: cmpOr(b.Action, "sync")}
	if _, _, err := parseCron(c.cron, c.tz); err != nil {
		return c, err
	}
	k := &scheduleChecker{h: h, ctx: ctx, ws: ws, c: &c, seenServer: map[uuid.UUID]bool{}, seenStorage: map[uuid.UUID]bool{}}
	var err error
	switch c.action {
	case "sync":
		err = k.sync(b)
	case "archive":
		err = k.archive(b)
	case "fetch":
		err = k.fetch(b)
	case "script":
		err = k.script(b)
	case "ansible":
		err = k.playbook(b)
	case "service":
		err = k.service(b)
	case "reboot":
		err = k.reboot(b)
	case "verify-backup":
		err = k.verify(b)
	default:
		err = fieldError("body.action", "Unknown action.", b.Action)
	}
	if err != nil {
		return c, err
	}
	if c.serverIDs == nil {
		c.serverIDs = []uuid.UUID{}
	}
	if c.storageIDs == nil {
		c.storageIDs = []uuid.UUID{}
	}
	if c.dests == nil {
		c.dests = []ScheduleEnd{}
	}
	c.sourceJSON = []byte("{}")
	if c.source != nil {
		c.sourceJSON, _ = json.Marshal(c.source)
	}
	c.destsJSON, _ = json.Marshal(c.dests)
	c.optionsJSON, _ = json.Marshal(c.options)
	c.taskJSON, _ = json.Marshal(c.task)
	return c, nil
}

// ---- Runs ----

func (h *scheduleHandler) toRun(r sqlc.ScheduleRun) ScheduleRun {
	plan := decodePlan(r.Plan)
	out := ScheduleRun{
		ID: r.ID.String(), ScheduleID: r.ScheduleID.String(), Trigger: r.Trigger, DryRun: r.DryRun,
		State: r.State, Error: r.Error, Action: plan.Action, Source: plan.Source, Options: plan.Options,
		Files: int(r.Files), Bytes: r.Bytes, JobID: optionalIDString(r.JobID),
		CreatedByName: r.CreatedByName, CreatedAt: r.CreatedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
	}
	var link ScheduleRunLink
	if decodeInto(r.Link, &link); link.Kind != "" {
		out.Link = &link
	}
	decodeInto(r.Results, &out.Results)
	if out.Results == nil {
		// Not started: one pending row per destination.
		out.Results = make([]ScheduleRunDest, len(plan.Destinations))
		for i, d := range plan.Destinations {
			out.Results[i] = ScheduleRunDest{ScheduleEndView: d, State: "pending"}
			if !jobs.Active(r.State) {
				out.Results[i].State = "canceled"
			}
		}
	}
	return out
}

// live adds a running run's progress.
func (h *scheduleHandler) live(ctx context.Context, r *ScheduleRun) {
	if !jobs.Active(r.State) || r.JobID == nil {
		return
	}
	j, err := h.runner.Get(ctx, uuid.MustParse(*r.JobID))
	if err != nil || !jobs.Active(j.State) {
		return
	}
	p := toJob(j, false).Progress
	r.Progress = &p
}

// syncRun ends a stored run whose job ended without it: canceled while
// queued, or Morcheh restarted. It says whether it changed anything.
func (h *scheduleHandler) syncRun(ctx context.Context, r sqlc.ScheduleRun) bool {
	if !jobs.Active(r.State) {
		return false
	}
	end := func(state, msg string) bool {
		if err := h.q.EndScheduleRun(ctx, sqlc.EndScheduleRunParams{ID: r.ID, State: state, Error: msg}); err != nil {
			slog.Warn("end a cron job run", "run", r.ID, "error", err)
			return false
		}
		return true
	}
	const lost = "Morcheh restarted before it finished."
	if r.JobID == nil {
		if time.Since(r.CreatedAt) < time.Minute {
			return false
		}
		return end(jobs.Interrupted, lost)
	}
	j, err := h.runner.Get(ctx, *r.JobID)
	switch {
	case errors.Is(err, jobs.ErrNotFound):
		return end(jobs.Interrupted, lost)
	case err != nil, jobs.Active(j.State):
		return false
	case j.State == jobs.Canceled:
		return end(jobs.Canceled, "")
	case j.State == jobs.Failed:
		return end(jobs.Failed, j.Error)
	}
	return end(jobs.Interrupted, cmpOr(j.Error, lost))
}

// busy says a run of the schedule is still queued or running.
func (h *scheduleHandler) busy(ctx context.Context, id uuid.UUID) (bool, error) {
	rows, err := h.q.ListActiveScheduleRuns(ctx, &id)
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		if !h.syncRun(ctx, r) {
			return true, nil
		}
	}
	return false, nil
}

type scheduleRunParams struct {
	RunID uuid.UUID `json:"run_id"`
}

// start queues a run. by is nil for a run on time. A run on time while the
// last one is still going is recorded as skipped.
func (h *scheduleHandler) start(ctx context.Context, s sqlc.Schedule, by *principal, dryRun bool) (sqlc.ScheduleRun, *Job, error) {
	busy, err := h.busy(ctx, s.ID)
	if err != nil {
		return sqlc.ScheduleRun{}, nil, internalError(err)
	}
	trigger, byName := "schedule", ""
	var byID *uuid.UUID
	if by != nil {
		trigger, byID, byName = "manual", by.ID(), cmpOr(by.User.FullName, by.User.Username)
	}
	if busy && by != nil {
		return sqlc.ScheduleRun{}, nil, huma.Error409Conflict("It's running now. Wait for it to finish, or stop it first.")
	}
	if dryRun && s.Action != "sync" {
		return sqlc.ScheduleRun{}, nil, huma.Error422UnprocessableEntity("Only a file sync has a test run.")
	}
	sched, err := h.one(ctx, s)
	if err != nil {
		return sqlc.ScheduleRun{}, nil, err
	}
	dests := sched.Destinations
	if s.Action == "service" || s.Action == "reboot" {
		dests = refViews(sched.Refs, "server")
	}
	plan, _ := json.Marshal(schedulePlan{
		Action: s.Action, Source: sched.Source, Destinations: dests, Options: sched.Options, Task: sched.Task, Name: s.Name,
	})
	params := sqlc.CreateScheduleRunParams{
		ScheduleID: s.ID, WorkspaceID: s.WorkspaceID, Trigger: trigger, DryRun: dryRun, Plan: plan,
		State: jobs.Queued, CreatedBy: byID, CreatedByName: byName,
	}
	if busy {
		now := time.Now()
		params.State, params.Error, params.FinishedAt = "skipped", "The run before was still going.", &now
	}
	run, err := h.q.CreateScheduleRun(ctx, params)
	if err != nil {
		return run, nil, internalError(err)
	}
	if err := h.q.PruneScheduleRuns(ctx, sqlc.PruneScheduleRunsParams{ScheduleID: s.ID, Keep: scheduleRunsKept}); err != nil {
		slog.Warn("prune cron job runs", "schedule", s.ID, "error", err)
	}
	if busy {
		return run, nil, nil
	}
	kind, title := scheduleRunKind, "Run "+s.Name
	switch {
	case dryRun:
		kind, title = scheduleSyncKind, "Test "+s.Name
	case s.Action == "sync":
		kind, title = scheduleSyncKind, "Sync "+s.Name
	}
	refs := scheduleEndIDs(s)
	j, err := h.runner.Submit(ctx, jobs.Spec{
		Kind: kind, Title: title, Params: scheduleRunParams{RunID: run.ID}, Refs: refs,
		Target:    JobPlace{ScheduleID: s.ID.String(), RunID: run.ID.String(), Name: s.Name},
		CreatedBy: byID,
	})
	if err != nil {
		_ = h.q.EndScheduleRun(context.WithoutCancel(ctx), sqlc.EndScheduleRunParams{ID: run.ID, State: jobs.Failed, Error: "It couldn't be queued."})
		return run, nil, internalError(err)
	}
	if err := h.q.SetScheduleRunJob(ctx, sqlc.SetScheduleRunJobParams{ID: run.ID, JobID: &j.ID}); err != nil {
		return run, nil, internalError(err)
	}
	run.JobID = &j.ID
	job := toJob(j, false)
	return run, &job, nil
}

// runner is the person a schedule acts as, with their access now.
func (h *scheduleHandler) runAs(ctx context.Context, s sqlc.Schedule) (string, *auth.Access, error) {
	_, name, acc, err := h.runUser(ctx, s)
	return name, acc, err
}

// runUser is runAs with the person too, to act as them.
func (h *scheduleHandler) runUser(ctx context.Context, s sqlc.Schedule) (sqlc.User, string, *auth.Access, error) {
	gone := errors.New("The person who saved this cron job was removed. Someone with access should open it and save it again.")
	if s.UpdatedBy == nil {
		return sqlc.User{}, "", nil, gone
	}
	u, err := h.q.GetUser(ctx, *s.UpdatedBy)
	if isNotFound(err) {
		return u, "", nil, gone
	}
	if err != nil {
		return u, "", nil, err
	}
	name := cmpOr(u.FullName, u.Username)
	if u.Status != "active" {
		return u, name, nil, fmt.Errorf("%s's account isn't active, so their cron jobs don't run. Someone with access should open it and save it again.", name)
	}
	acc, err := h.authz.accessOf(ctx, u)
	return u, name, acc, err
}

// mayUse checks the schedule's person still has the level on an end.
func mayUse(acc *auth.Access, ws uuid.UUID, e ScheduleEndView, need auth.Level, who string) error {
	if e.Missing {
		return errors.New("It was deleted.")
	}
	var level auth.Level
	if id := parseOptionalID(e.ServerID); id != nil {
		level = acc.ServerLevel(ws, *id)
	} else if id := parseOptionalID(e.StorageID); id != nil {
		level = acc.StorageLevel(ws, *id)
	}
	if level < need {
		return fmt.Errorf("%s no longer has %s access to %s.", who, need, e.Name)
	}
	return nil
}

// problemText is an error as one line for a run's record.
func problemText(err error) string {
	var se huma.StatusError
	if errors.As(err, &se) {
		return err.Error()
	}
	switch {
	case errors.Is(err, storage.ErrEmptySource):
		return "The source folder is empty, so nothing was deleted from this destination (a mirror would have emptied it). Check that the source is there."
	case errors.Is(err, context.DeadlineExceeded):
		return "It took too long."
	}
	var ce *storage.ConnError
	if errors.As(err, &ce) {
		return ce.Message
	}
	msg := storage.Message(err)
	if msg == "Not found" {
		return "Not found: " + err.Error()
	}
	return msg
}

func (h *scheduleHandler) runJob(ctx context.Context, t *jobs.Task) (any, error) {
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
	plan := decodePlan(run.Plan)
	if plan.Source == nil {
		return fail(errors.New("It has no source."))
	}
	who, acc, err := h.runAs(ctx, s)
	if err != nil {
		return fail(err)
	}
	if err := mayUse(acc, s.WorkspaceID, *plan.Source, auth.Operator, who); err != nil {
		return fail(fmt.Errorf("Source: %w", err))
	}

	results := make([]ScheduleRunDest, len(plan.Destinations))
	for i, d := range plan.Destinations {
		results[i] = ScheduleRunDest{ScheduleEndView: d, State: "pending"}
	}
	var files int
	var bytes int64
	save := func() {
		raw, _ := json.Marshal(results)
		if err := h.q.SaveScheduleRunResults(bg, sqlc.SaveScheduleRunResultsParams{ID: run.ID, Results: raw, Files: int32(files), Bytes: bytes}); err != nil {
			slog.Warn("save a cron job run", "run", run.ID, "error", err)
		}
	}
	save()
	verb := "Syncing"
	if run.DryRun {
		verb = "Checking"
	}
	t.Logf("%s %s:%s to %d destination(s), mode %s", verb, plan.Source.Name, plan.Source.Path, len(plan.Destinations), plan.Options.Mode)

	// The source stays open while each destination is synced in turn.
	srcErr := h.st.with(ctx, plan.Source.transferEnd(), func(src place) error {
		for i, d := range plan.Destinations {
			if ctx.Err() != nil {
				break
			}
			r := &results[i]
			now := time.Now()
			r.State, r.StartedAt = "running", &now
			save()
			label := fmt.Sprintf("%s (%d of %d)", d.Name, i+1, len(plan.Destinations))
			t.Update(func(p *jobs.Progress) { p.Phase, p.Current = "Comparing with "+label, "" })
			err := mayUse(acc, s.WorkspaceID, d, auth.Engineer, who)
			if err == nil {
				err = h.st.with(ctx, d.transferEnd(), func(dst place) error {
					if dst.readOnly {
						return errors.New(dst.name + " is read-only in Morcheh.")
					}
					var prog storage.Progress
					prog.OnBytes = t.Add
					prog.OnFile = func(f string) {
						done := prog.Files
						t.Update(func(p *jobs.Progress) {
							p.Current = strings.TrimPrefix(strings.TrimPrefix(f, plan.Source.Path), "/")
							p.Items = done
						})
					}
					res, err := storage.Sync(ctx, src.fs, plan.Source.Path, dst.fs, d.Path, storage.SyncOptions{
						Mode: plan.Options.Mode, Excludes: plan.Options.Excludes, Keep: plan.Options.Keep,
						Now: time.Now().In(scheduleLoc(s.Timezone)), DryRun: run.DryRun,
						Plan: func(n int, size int64) {
							t.Update(func(p *jobs.Progress) {
								p.Phase, p.Done, p.Total, p.Items, p.ItemsTotal = verb+" to "+label, 0, size, 0, n
							})
						},
					}, &prog)
					r.SyncResult = res
					return err
				})
			}
			end := time.Now()
			r.FinishedAt = &end
			files, bytes = files+r.Copied, bytes+r.Bytes
			switch {
			case err != nil && ctx.Err() != nil:
				r.State = "canceled"
			case err != nil:
				r.State, r.Error = "failed", problemText(err)
				t.Logf("%s: %s", d.Name, r.Error)
			case r.Failed > 0:
				r.State = "partial"
				t.Logf("%s: %d copied, %d couldn't be", d.Name, r.Copied, r.Failed)
			default:
				r.State = "succeeded"
				t.Logf("%s:%s: %d copied (%s), %d up to date, %d deleted", d.Name, d.Path, r.Copied, humanBytes(r.Bytes), r.Skipped, r.Deleted)
			}
			save()
		}
		return nil
	})

	failMsg := ""
	if srcErr != nil {
		failMsg = "Source " + plan.Source.Name + ": " + problemText(srcErr)
	}
	return h.endRun(ctx, t, run.ID, results, files, bytes, failMsg)
}

// endRun works out how a run with per-destination results ended and stores
// it. failMsg fails it whatever the results say.
func (h *scheduleHandler) endRun(ctx context.Context, t *jobs.Task, runID uuid.UUID, results []ScheduleRunDest, files int, bytes int64, failMsg string) (any, error) {
	state, msg := jobs.Succeeded, ""
	var ok, bad int
	for i := range results {
		switch results[i].State {
		case "succeeded", "skipped":
			ok++
		case "pending", "running":
			results[i].State = "canceled"
		case "partial", "failed":
			bad++
		}
	}
	switch {
	case ctx.Err() != nil && t.Canceled():
		state = jobs.Canceled
	case ctx.Err() != nil:
		state, msg = jobs.Interrupted, "Morcheh stopped before it finished."
	case failMsg != "":
		state, msg = jobs.Failed, failMsg
	case bad > 0 && ok == 0 && !anyPartial(results):
		state, msg = jobs.Failed, failedText(results)
	case bad > 0:
		state, msg = "partial", failedText(results)
	}
	return h.closeRun(ctx, runID, state, msg, results, files, bytes)
}

// closeRun stores how a run ended and answers its job the same way.
func (h *scheduleHandler) closeRun(ctx context.Context, runID uuid.UUID, state, msg string, results []ScheduleRunDest, files int, bytes int64) (any, error) {
	if results == nil {
		results = []ScheduleRunDest{}
	}
	raw, _ := json.Marshal(results)
	if err := h.q.FinishScheduleRun(context.WithoutCancel(ctx), sqlc.FinishScheduleRunParams{
		ID: runID, State: state, Error: msg, Results: raw, Files: int32(files), Bytes: bytes,
	}); err != nil {
		slog.Warn("finish a cron job run", "run", runID, "error", err)
	}
	switch state {
	case jobs.Canceled, jobs.Interrupted:
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New(cmpOr(msg, "It was stopped."))
	case jobs.Failed, "partial":
		return nil, errors.New(msg)
	}
	return struct {
		Files int   `json:"files"`
		Bytes int64 `json:"bytes"`
	}{files, bytes}, nil
}

func anyPartial(rs []ScheduleRunDest) bool {
	for _, r := range rs {
		if r.State == "partial" {
			return true
		}
	}
	return false
}

func failedText(rs []ScheduleRunDest) string {
	var parts []string
	for _, r := range rs {
		switch r.State {
		case "failed":
			parts = append(parts, r.Name+": "+r.Error)
		case "partial":
			noun := "files"
			if r.Failed == 1 {
				noun = "file"
			}
			parts = append(parts, fmt.Sprintf("%s: %d %s couldn't be copied", r.Name, r.Failed, noun))
		}
	}
	return strings.Join(parts, "; ")
}

func scheduleLoc(tz string) *time.Location {
	if loc, err := time.LoadLocation(tz); err == nil {
		return loc
	}
	return time.UTC
}

// ---- The clock ----

// startScheduler fires schedules that are due, checking every `every`. A
// run missed while Morcheh was down happens once when it's back.
func startScheduler(h *scheduleHandler, every time.Duration) {
	if every <= 0 {
		return
	}
	go func() {
		ctx := context.Background()
		h.fixNext(ctx)
		for range time.Tick(every) {
			h.fire(ctx)
		}
	}()
}

// fixNext gives a next run to enabled schedules that lack one.
func (h *scheduleHandler) fixNext(ctx context.Context) {
	rows, err := h.q.ListEnabledSchedulesWithoutNext(ctx)
	if err != nil {
		slog.Warn("cron jobs without a next run", "error", err)
		return
	}
	for _, s := range rows {
		_ = h.q.SetScheduleNext(ctx, sqlc.SetScheduleNextParams{ID: s.ID, NextRunAt: nextRun(s.Cron, s.Timezone, time.Now())})
	}
}

func (h *scheduleHandler) fire(ctx context.Context) {
	now := time.Now()
	due, err := h.q.ListDueSchedules(ctx, &now)
	if err != nil {
		slog.Warn("list due cron jobs", "error", err)
		return
	}
	for _, s := range due {
		n, err := h.q.ClaimSchedule(ctx, sqlc.ClaimScheduleParams{ID: s.ID, Due: s.NextRunAt, NextRunAt: nextRun(s.Cron, s.Timezone, now)})
		if err != nil || n == 0 {
			continue
		}
		if _, _, err := h.start(ctx, s, nil, false); err != nil {
			slog.Warn("start a cron job", "schedule", s.ID, "error", err)
		}
	}
}

// ---- Routes ----

// SchedulePath is exported (and not declared inside registerSchedules) so
// Huma reads its field when it's embedded in a request.
type SchedulePath struct {
	ID string `path:"id" format:"uuid"`
}

func registerSchedules(api huma.API, h *scheduleHandler) {
	tags := []string{"Cron jobs"}
	h.runner.Handle(scheduleSyncKind, h.runJob)
	h.runner.Handle(scheduleRunKind, h.runTask)

	type scheduleList struct {
		Body struct {
			Items []Schedule `json:"items"`
		}
	}

	huma.Register(api, huma.Operation{
		OperationID: "list-schedules",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/schedules",
		Summary:     "List a workspace's cron jobs",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		ServerID  string `query:"server_id" format:"uuid" doc:"Only those using this server"`
		StorageID string `query:"storage_id" format:"uuid" doc:"Only those using this storage"`
	}) (*scheduleList, error) {
		params := sqlc.ListSchedulesParams{WorkspaceID: uuid.MustParse(in.ID)}
		if in.ServerID != "" {
			id := uuid.MustParse(in.ServerID)
			params.ServerID = &id
		}
		if in.StorageID != "" {
			id := uuid.MustParse(in.StorageID)
			params.StorageID = &id
		}
		rows, err := h.q.ListSchedules(ctx, params)
		if err != nil {
			return nil, internalError(err)
		}
		var ends, users []uuid.UUID
		scheds := make([]sqlc.Schedule, len(rows))
		for i, r := range rows {
			scheds[i] = sqlc.Schedule{
				ID: r.ID, WorkspaceID: r.WorkspaceID, Name: r.Name, Description: r.Description, Action: r.Action,
				Cron: r.Cron, Timezone: r.Timezone, Enabled: r.Enabled, Source: r.Source, Destinations: r.Destinations,
				Options: r.Options, Task: r.Task, ServerIds: r.ServerIds, StorageIds: r.StorageIds, NextRunAt: r.NextRunAt,
				CreatedBy: r.CreatedBy, UpdatedBy: r.UpdatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
			}
			ends = append(ends, scheduleEndIDs(scheds[i])...)
			if r.UpdatedBy != nil {
				users = append(users, *r.UpdatedBy)
			}
		}
		n, err := h.names(ctx, ends, users)
		if err != nil {
			return nil, internalError(err)
		}
		out := &scheduleList{}
		out.Body.Items = make([]Schedule, len(rows))
		for i, r := range rows {
			s := scheds[i]
			var last *ScheduleRunBrief
			if r.LastRunID != nil {
				last = &ScheduleRunBrief{
					ID: r.LastRunID.String(), State: deref(r.LastRunState), At: *r.LastRunAt,
					FinishedAt: r.LastRunFinishedAt, Error: deref(r.LastRunError),
				}
				// A run left behind by a restart reads as what it is.
				if jobs.Active(last.State) {
					if run, err := h.q.GetScheduleRun(ctx, *r.LastRunID); err == nil && h.syncRun(ctx, run) {
						if run, err = h.q.GetScheduleRun(ctx, run.ID); err == nil {
							last.State, last.Error, last.FinishedAt = run.State, run.Error, run.FinishedAt
						}
					}
				}
			}
			out.Body.Items[i] = h.toSchedule(s, n, last)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "preview-schedule",
		Method:      http.MethodPost,
		Path:        "/schedules/preview",
		Summary:     "Check a cron expression and see when it would run",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		Body struct {
			Cron     string `json:"cron" minLength:"1" maxLength:"200"`
			Timezone string `json:"timezone,omitempty" maxLength:"64"`
			Count    int    `json:"count,omitempty" minimum:"1" maximum:"20" default:"5"`
		}
	}) (*struct {
		Body struct {
			Next []time.Time `json:"next"`
		}
	}, error) {
		s, loc, err := parseCron(in.Body.Cron, in.Body.Timezone)
		if err != nil {
			return nil, err
		}
		out := &struct {
			Body struct {
				Next []time.Time `json:"next"`
			}
		}{}
		out.Body.Next = []time.Time{}
		t := time.Now().In(loc)
		for range max(in.Body.Count, 1) {
			if t = s.Next(t); t.IsZero() {
				break
			}
			out.Body.Next = append(out.Body.Next, t)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-schedule",
		Method:        http.MethodPost,
		Path:          "/workspaces/{id}/schedules",
		Summary:       "Create a cron job",
		Description:   "You need Engineer on the workspace, plus what the action needs done by hand: a sync needs Operator on the source and Engineer on every destination; a script Engineer on its servers; a playbook Owner on them; a service action or reboot Operator; fetch and archive Engineer; checking backups Operator on the database. Runs act with your access, checked each time.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body ScheduleBody
	}) (*ScheduleOutput, error) {
		ws := uuid.MustParse(in.ID)
		c, err := h.check(ctx, ws, in.Body)
		if err != nil {
			return nil, err
		}
		enabled := in.Body.Enabled == nil || *in.Body.Enabled
		var next *time.Time
		if enabled {
			next = nextRun(c.cron, c.tz, time.Now())
		}
		s, err := h.q.CreateSchedule(ctx, sqlc.CreateScheduleParams{
			WorkspaceID: ws, Name: strings.TrimSpace(in.Body.Name), Description: strings.TrimSpace(in.Body.Description),
			Action: c.action, Cron: c.cron, Timezone: c.tz, Enabled: enabled, Source: c.sourceJSON,
			Destinations: c.destsJSON, Options: c.optionsJSON, Task: c.taskJSON, ServerIds: c.serverIDs, StorageIds: c.storageIDs,
			NextRunAt: next, CreatedBy: principalOf(ctx).ID(),
		})
		if isUniqueViolation(err) {
			return nil, fieldError("body.name", "A cron job with this name already exists.", in.Body.Name)
		}
		if err != nil {
			return nil, internalError(err)
		}
		out, err := h.one(ctx, s)
		if err != nil {
			return nil, err
		}
		return &ScheduleOutput{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-schedule",
		Method:      http.MethodGet,
		Path:        "/schedules/{id}",
		Summary:     "Get a cron job",
		Tags:        tags,
	}, func(ctx context.Context, in *SchedulePath) (*ScheduleOutput, error) {
		s, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		out, err := h.one(ctx, s)
		if err != nil {
			return nil, err
		}
		return &ScheduleOutput{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-schedule",
		Method:      http.MethodPatch,
		Path:        "/schedules/{id}",
		Summary:     "Save changes to a cron job",
		Description: "The whole job is sent. From now on it runs with your access. With revision, answers 409 when someone else saved in between.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		SchedulePath
		Body ScheduleUpdate
	}) (*ScheduleOutput, error) {
		old, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if in.Body.Revision != nil && !in.Body.Revision.Equal(old.UpdatedAt) {
			return nil, huma.Error409Conflict("Someone else saved this cron job after you opened it.")
		}
		c, err := h.check(ctx, old.WorkspaceID, in.Body.ScheduleBody)
		if err != nil {
			return nil, err
		}
		enabled := old.Enabled
		if in.Body.Enabled != nil {
			enabled = *in.Body.Enabled
		}
		var next *time.Time
		if enabled {
			next = nextRun(c.cron, c.tz, time.Now())
		}
		s, err := h.q.UpdateSchedule(ctx, sqlc.UpdateScheduleParams{
			ID: old.ID, Name: strings.TrimSpace(in.Body.Name), Description: strings.TrimSpace(in.Body.Description),
			Action: c.action, Task: c.taskJSON,
			Cron: c.cron, Timezone: c.tz, Enabled: enabled, Source: c.sourceJSON, Destinations: c.destsJSON,
			Options: c.optionsJSON, ServerIds: c.serverIDs, StorageIds: c.storageIDs, NextRunAt: next,
			UpdatedBy: principalOf(ctx).ID(),
		})
		if isUniqueViolation(err) {
			return nil, fieldError("body.name", "A cron job with this name already exists.", in.Body.Name)
		}
		if err != nil {
			return nil, internalError(err)
		}
		out, err := h.one(ctx, s)
		if err != nil {
			return nil, err
		}
		return &ScheduleOutput{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-schedule-enabled",
		Method:      http.MethodPost,
		Path:        "/schedules/{id}/enabled",
		Summary:     "Pause or resume a cron job",
		Description: "A run already going isn't stopped. Resuming doesn't make up for runs missed while paused.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		SchedulePath
		Body struct {
			Enabled bool `json:"enabled"`
		}
	}) (*ScheduleOutput, error) {
		old, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		var next *time.Time
		if in.Body.Enabled {
			next = nextRun(old.Cron, old.Timezone, time.Now())
		}
		s, err := h.q.SetScheduleEnabled(ctx, sqlc.SetScheduleEnabledParams{ID: old.ID, Enabled: in.Body.Enabled, NextRunAt: next})
		if err != nil {
			return nil, internalError(err)
		}
		out, err := h.one(ctx, s)
		if err != nil {
			return nil, err
		}
		return &ScheduleOutput{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-schedule",
		Method:        http.MethodDelete,
		Path:          "/schedules/{id}",
		Summary:       "Delete a cron job and its runs",
		Description:   "A run going now is stopped. Files it already copied stay.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *SchedulePath) (*struct{}, error) {
		id := uuid.MustParse(in.ID)
		if active, err := h.q.ListActiveScheduleRuns(ctx, &id); err == nil {
			for _, r := range active {
				if r.JobID != nil {
					_, _ = h.runner.Cancel(ctx, *r.JobID)
				}
			}
		}
		if _, err := h.q.DeleteSchedule(ctx, id); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})

	type runOutput struct {
		Body struct {
			Run ScheduleRun `json:"run"`
			Job *Job        `json:"job" doc:"The background job; null when the run was skipped"`
		}
	}

	huma.Register(api, huma.Operation{
		OperationID:   "run-schedule",
		Method:        http.MethodPost,
		Path:          "/schedules/{id}/run",
		Summary:       "Run a cron job now",
		Description:   "Queues a background job, with the access of the person who saved the job. dry_run counts what would change and changes nothing. 409 while a run is going.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		SchedulePath
		Body struct {
			DryRun bool `json:"dry_run,omitempty" doc:"Only count what would be copied and deleted"`
		}
	}) (*runOutput, error) {
		s, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		run, job, err := h.start(ctx, s, principalOf(ctx), in.Body.DryRun)
		if err != nil {
			return nil, err
		}
		out := &runOutput{}
		out.Body.Run = h.toRun(run)
		out.Body.Job = job
		return out, nil
	})

	type runList struct {
		Body struct {
			Items []ScheduleRun `json:"items"`
			Total int64         `json:"total"`
		}
	}

	huma.Register(api, huma.Operation{
		OperationID: "list-schedule-runs",
		Method:      http.MethodGet,
		Path:        "/schedules/{id}/runs",
		Summary:     "List a cron job's runs, newest first",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		SchedulePath
		State  string `query:"state" enum:"queued,running,succeeded,partial,failed,canceled,interrupted,skipped"`
		Limit  int32  `query:"limit" minimum:"1" maximum:"200" default:"50"`
		Offset int32  `query:"offset" minimum:"0"`
	}) (*runList, error) {
		id := uuid.MustParse(in.ID)
		params := sqlc.ListScheduleRunsParams{ScheduleID: id, Lim: in.Limit, Off: in.Offset}
		count := sqlc.CountScheduleRunsParams{ScheduleID: id}
		if in.State != "" {
			params.State, count.State = &in.State, &in.State
		}
		rows, err := h.q.ListScheduleRuns(ctx, params)
		if err != nil {
			return nil, internalError(err)
		}
		changed := false
		for _, r := range rows {
			changed = h.syncRun(ctx, r) || changed
		}
		if changed {
			if rows, err = h.q.ListScheduleRuns(ctx, params); err != nil {
				return nil, internalError(err)
			}
		}
		total, err := h.q.CountScheduleRuns(ctx, count)
		if err != nil {
			return nil, internalError(err)
		}
		out := &runList{}
		out.Body.Total = total
		out.Body.Items = make([]ScheduleRun, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = h.toRun(r)
			h.live(ctx, &out.Body.Items[i])
		}
		return out, nil
	})

	type runPath struct {
		ID string `path:"id" format:"uuid"`
	}
	type oneRun struct{ Body ScheduleRun }
	loadRun := func(ctx context.Context, raw string) (ScheduleRun, sqlc.ScheduleRun, error) {
		r, err := h.q.GetScheduleRun(ctx, uuid.MustParse(raw))
		if isNotFound(err) {
			return ScheduleRun{}, r, huma.Error404NotFound("run not found")
		}
		if err != nil {
			return ScheduleRun{}, r, internalError(err)
		}
		if h.syncRun(ctx, r) {
			if r, err = h.q.GetScheduleRun(ctx, r.ID); err != nil {
				return ScheduleRun{}, r, internalError(err)
			}
		}
		out := h.toRun(r)
		h.live(ctx, &out)
		return out, r, nil
	}

	huma.Register(api, huma.Operation{
		OperationID: "get-schedule-run",
		Method:      http.MethodGet,
		Path:        "/schedule-runs/{id}",
		Summary:     "Get a run, with each destination's result",
		Tags:        tags,
	}, func(ctx context.Context, in *runPath) (*oneRun, error) {
		out, _, err := loadRun(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &oneRun{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "cancel-schedule-run",
		Method:      http.MethodPost,
		Path:        "/schedule-runs/{id}/cancel",
		Summary:     "Stop a run",
		Description: "Files already copied stay. 409 when it has finished.",
		Tags:        tags,
	}, func(ctx context.Context, in *runPath) (*oneRun, error) {
		_, r, err := loadRun(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if !jobs.Active(r.State) || r.JobID == nil {
			return nil, huma.Error409Conflict("The run has already finished.")
		}
		if _, err := h.runner.Cancel(ctx, *r.JobID); err != nil {
			return nil, jobProblem(err)
		}
		out, _, err := loadRun(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &oneRun{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-schedule-run",
		Method:        http.MethodDelete,
		Path:          "/schedule-runs/{id}",
		Summary:       "Delete a finished run's record",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *runPath) (*struct{}, error) {
		n, err := h.q.DeleteScheduleRun(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		if n == 0 {
			return nil, huma.Error409Conflict("It's still running. Stop it first.")
		}
		return nil, nil
	})
}
