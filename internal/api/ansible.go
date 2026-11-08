package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/sse"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/morcheh/backend/internal/ansible"
	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
)

const ansibleRunKind = "ansible-run"

// ---- API shapes ----

// AnsibleStatus says whether playbooks can run on this Morcheh.
type AnsibleStatus struct {
	Installed bool   `json:"installed"`
	Version   string `json:"version" doc:"ansible-core version" example:"2.22.0"`
	Sandbox   bool   `json:"sandbox" doc:"Playbooks run in a bubblewrap sandbox on the Morcheh host"`
	CanRun    bool   `json:"can_run" doc:"This person can start a run here (they still need Owner on every server)"`
	Problem   string `json:"problem" doc:"Why they can't"`
}

// Playbook is one playbook in a list.
type Playbook struct {
	ID           string     `json:"id" format:"uuid"`
	WorkspaceID  string     `json:"workspace_id" format:"uuid"`
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	Size         int32      `json:"size" doc:"Length of the YAML"`
	LastRunID    *string    `json:"last_run_id,omitempty" format:"uuid"`
	LastRunState *string    `json:"last_run_state,omitempty"`
	LastRunAt    *time.Time `json:"last_run_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at" doc:"Send it back as revision when saving"`
}

// PlaybookDetail is a playbook with its text.
type PlaybookDetail struct {
	ID          string    `json:"id" format:"uuid"`
	WorkspaceID string    `json:"workspace_id" format:"uuid"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Content     string    `json:"content" doc:"The playbook (YAML)"`
	Variables   string    `json:"variables" doc:"Extra variables offered when running it (YAML)"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type PlaybookOutput struct{ Body PlaybookDetail }

func toPlaybookDetail(p sqlc.AnsiblePlaybook) PlaybookDetail {
	return PlaybookDetail{
		ID: p.ID.String(), WorkspaceID: p.WorkspaceID.String(), Name: p.Name,
		Description: p.Description, Content: p.Content, Variables: p.Variables,
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
}

// AnsibleSelection is which servers a run goes to; the parts add up.
type AnsibleSelection struct {
	ServerIDs []string `json:"server_ids,omitempty" format:"uuid"`
	Tags      []string `json:"tags,omitempty" doc:"Servers with any of these tags"`
	FolderIDs []string `json:"folder_ids,omitempty" doc:"Servers in these folders and their subfolders"`
	All       bool     `json:"all,omitempty" doc:"Every server in the workspace"`
}

// AnsibleOptions are ansible-playbook's options for a run.
type AnsibleOptions struct {
	Check     bool     `json:"check,omitempty" doc:"Dry run: report what would change"`
	Diff      bool     `json:"diff,omitempty" doc:"Show the changes made to files"`
	Verbosity int      `json:"verbosity,omitempty" minimum:"0" maximum:"4"`
	Tags      []string `json:"tags,omitempty" doc:"Only tasks with these tags"`
	SkipTags  []string `json:"skip_tags,omitempty"`
	Limit     string   `json:"limit,omitempty" maxLength:"500" doc:"Narrow the hosts further (Ansible host pattern)"`
	Forks     int      `json:"forks,omitempty" minimum:"1" maximum:"100" doc:"Hosts worked on at once (default 5)"`
	ExtraVars string   `json:"extra_vars,omitempty" maxLength:"262144" doc:"Extra variables (YAML mapping). Kept with the run and shown to whoever can read it"`
}

// AnsibleHost is a server in a run.
type AnsibleHost struct {
	ServerID      string `json:"server_id" format:"uuid"`
	Name          string `json:"name"`
	Host          string `json:"host"`
	InventoryName string `json:"inventory_name" doc:"What it's called in the playbook's output"`
}

// AnsibleRun is one run of a playbook, without its logs.
type AnsibleRun struct {
	ID            string                       `json:"id" format:"uuid"`
	WorkspaceID   string                       `json:"workspace_id" format:"uuid"`
	PlaybookID    *string                      `json:"playbook_id,omitempty" format:"uuid"`
	PlaybookName  string                       `json:"playbook_name"`
	Hosts         []AnsibleHost                `json:"hosts"`
	Options       AnsibleOptions               `json:"options"`
	State         string                       `json:"state" enum:"queued,running,succeeded,failed,canceled,interrupted"`
	Error         string                       `json:"error"`
	ExitCode      *int32                       `json:"exit_code,omitempty"`
	Recap         map[string]ansible.HostStats `json:"recap" doc:"By inventory host name"`
	JobID         *string                      `json:"job_id,omitempty" format:"uuid"`
	CreatedByName string                       `json:"created_by_name"`
	CreatedAt     time.Time                    `json:"created_at"`
	StartedAt     *time.Time                   `json:"started_at,omitempty"`
	FinishedAt    *time.Time                   `json:"finished_at,omitempty"`
}

// AnsibleRunDetail is a run with what it printed and did.
type AnsibleRunDetail struct {
	AnsibleRun
	Content         string             `json:"content" doc:"The playbook as it ran"`
	Selection       AnsibleSelection   `json:"selection"`
	Output          string             `json:"output" doc:"What ansible-playbook printed, ANSI colors included"`
	OutputTruncated bool               `json:"output_truncated" doc:"The middle was too long and was dropped"`
	OutputOffset    int64              `json:"output_offset" doc:"Bytes printed so far; output events continue from here"`
	Plays           []*ansible.RunPlay `json:"plays"`
}

// AnsibleOutputChunk is new text from a running playbook.
type AnsibleOutputChunk struct {
	Offset int64  `json:"offset" doc:"Bytes printed before it"`
	Text   string `json:"text"`
}

func decodeInto[T any](raw []byte, into *T) {
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, into); err != nil {
			slog.Warn("read a stored ansible run", "error", err)
		}
	}
}

func toAnsibleRunRow(r sqlc.ListAnsibleRunsRow) AnsibleRun {
	out := AnsibleRun{
		ID: r.ID.String(), WorkspaceID: r.WorkspaceID.String(),
		PlaybookID: optionalIDString(r.PlaybookID), PlaybookName: r.PlaybookName,
		Hosts: []AnsibleHost{}, Recap: map[string]ansible.HostStats{},
		State: r.State, Error: r.Error, ExitCode: r.ExitCode,
		JobID: optionalIDString(r.JobID), CreatedByName: r.CreatedByName,
		CreatedAt: r.CreatedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
	}
	decodeInto(r.Hosts, &out.Hosts)
	decodeInto(r.Options, &out.Options)
	decodeInto(r.Recap, &out.Recap)
	return out
}

func toAnsibleRunDetail(r sqlc.AnsibleRun) AnsibleRunDetail {
	out := AnsibleRunDetail{
		AnsibleRun: toAnsibleRunRow(sqlc.ListAnsibleRunsRow{
			ID: r.ID, WorkspaceID: r.WorkspaceID, PlaybookID: r.PlaybookID, PlaybookName: r.PlaybookName,
			Hosts: r.Hosts, Options: r.Options, State: r.State, Error: r.Error, ExitCode: r.ExitCode,
			Recap: r.Recap, JobID: r.JobID, CreatedByName: r.CreatedByName,
			CreatedAt: r.CreatedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
		}),
		Content: r.Content, Output: r.Output, OutputTruncated: r.OutputTruncated,
		OutputOffset: int64(len(r.Output)), Plays: []*ansible.RunPlay{},
	}
	decodeInto(r.Selection, &out.Selection)
	decodeInto(r.Plays, &out.Plays)
	return out
}

// ---- Runs in progress ----

// ansibleLive is a running playbook's output, in memory and shared with
// everyone following it. The database gets a copy every few seconds.
type ansibleLive struct {
	mu    sync.Mutex
	out   ansible.Output
	log   *ansible.Log
	dirty bool
	subs  map[*ansibleSub]struct{}
}

type ansibleSub struct {
	ch   chan any
	gone chan struct{} // the run ended, or this follower fell too far behind
}

func (l *ansibleLive) publish(msg any) {
	for s := range l.subs {
		select {
		case s.ch <- msg:
		default:
			delete(l.subs, s)
			close(s.gone)
		}
	}
}

// follow returns a run's state so far and everything after it, with no gap.
func (l *ansibleLive) follow(base sqlc.AnsibleRun) (AnsibleRunDetail, *ansibleSub) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := &ansibleSub{ch: make(chan any, 512), gone: make(chan struct{})}
	l.subs[s] = struct{}{}
	return l.overlay(base), s
}

func (l *ansibleLive) leave(s *ansibleSub) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.subs[s]; ok {
		delete(l.subs, s)
		close(s.gone)
	}
}

func (l *ansibleLive) end() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for s := range l.subs {
		delete(l.subs, s)
		close(s.gone)
	}
}

// overlay puts the live output over a stored run. Call with l.mu held.
func (l *ansibleLive) overlay(base sqlc.AnsibleRun) AnsibleRunDetail {
	d := toAnsibleRunDetail(base)
	d.Output, d.OutputTruncated, d.OutputOffset = l.out.String(), l.out.Truncated(), l.out.Total()
	// A deep copy, so it can be read after the lock is released.
	if raw, err := json.Marshal(l.log.Plays); err == nil {
		d.Plays = []*ansible.RunPlay{}
		_ = json.Unmarshal(raw, &d.Plays)
	}
	if l.log.Recap != nil {
		d.Recap = l.log.Recap
	}
	return d
}

type ansibleHandler struct {
	q       *sqlc.Queries
	servers *serverHandler
	authz   *authz
	runner  *jobs.Runner
	cfg     ansible.Config
	catalog ansible.Catalog

	mu       sync.Mutex
	live     map[uuid.UUID]*ansibleLive
	status   ansible.Status
	statusAt time.Time
}

func newAnsibleHandler(servers *serverHandler, a *authz) *ansibleHandler {
	h := &ansibleHandler{
		q: servers.q, servers: servers, authz: a, runner: servers.jobs,
		cfg: ansible.Config{
			Playbook: a.cfg.AnsiblePlaybook,
			Sandbox:  a.cfg.AnsibleSandbox,
			Timeout:  a.cfg.AnsibleRunTimeout,
		},
		live: map[uuid.UUID]*ansibleLive{},
	}
	go ansible.CleanStale(a.cfg.AnsibleRunTimeout + 10*time.Minute)
	return h
}

func (h *ansibleHandler) liveRun(id uuid.UUID) *ansibleLive {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.live[id]
}

// hostStatus is what the host offers, looked up at most once a minute: it
// starts ansible-playbook twice.
func (h *ansibleHandler) hostStatus() ansible.Status {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.statusAt.IsZero() || time.Since(h.statusAt) > time.Minute {
		h.status, h.statusAt = ansible.Detect(context.Background(), h.cfg), time.Now()
	}
	return h.status
}

// noSandbox is why someone can't run a playbook on this host. Without a sandbox
// a playbook's local tasks run as Morcheh itself, able to read its secrets.
func noSandboxProblem(st ansible.Status, admin bool) string {
	switch {
	case st.Problem != "":
		return st.Problem
	case st.Sandbox == "" && !admin:
		return "This Morcheh runs playbooks without a sandbox, so only a system admin can start them. Install bubblewrap on its host to allow Owners too."
	}
	return ""
}

// ---- Choosing servers ----

type ansibleTarget struct {
	server sqlc.Server
	name   string // inventory name
}

// resolveTargets turns a selection into servers, in a stable order, with
// their inventory names. Servers they can't reach at all aren't included.
func (h *ansibleHandler) resolveTargets(ctx context.Context, ws uuid.UUID, sel AnsibleSelection) ([]ansibleTarget, error) {
	all, err := h.q.ListAnsibleServers(ctx, ws)
	if err != nil {
		return nil, internalError(err)
	}
	acc := principalOf(ctx).Access
	known := make(map[string]bool, len(all))
	for _, s := range all {
		if acc.ServerLevel(ws, s.ID) != auth.None {
			known[s.ID.String()] = true
		}
	}
	for _, id := range sel.ServerIDs {
		if !known[id] {
			return nil, fieldError("body.selection.server_ids", "A chosen server isn't in this workspace.", id)
		}
	}
	folders, err := h.q.ListAnsibleFolders(ctx, ws)
	if err != nil {
		return nil, internalError(err)
	}
	inFolder := map[uuid.UUID]bool{}
	for _, raw := range sel.FolderIDs {
		id, err := uuid.Parse(raw)
		if err != nil || !slices.ContainsFunc(folders, func(f sqlc.ListAnsibleFoldersRow) bool { return f.ID == id }) {
			return nil, fieldError("body.selection.folder_ids", "A chosen folder isn't in this workspace.", raw)
		}
		inFolder[id] = true
	}
	// Subfolders: repeat until nothing new is added.
	for grew := len(inFolder) > 0; grew; {
		grew = false
		for _, f := range folders {
			if f.ParentID != nil && inFolder[*f.ParentID] && !inFolder[f.ID] {
				inFolder[f.ID] = true
				grew = true
			}
		}
	}
	var picked []sqlc.Server
	for _, s := range all {
		if !known[s.ID.String()] {
			continue
		}
		if sel.All || slices.Contains(sel.ServerIDs, s.ID.String()) ||
			(s.FolderID != nil && inFolder[*s.FolderID]) ||
			slices.ContainsFunc(s.Tags, func(t string) bool { return slices.Contains(sel.Tags, t) }) {
			picked = append(picked, s)
		}
	}
	names := make([]string, len(picked))
	for i, s := range picked {
		names[i] = s.Name
	}
	names = ansible.Names(names)
	out := make([]ansibleTarget, len(picked))
	for i, s := range picked {
		out[i] = ansibleTarget{s, names[i]}
	}
	return out, nil
}

// serverGroups are the Ansible groups a server is in: its tags, and its OS.
func serverGroups(s sqlc.Server) []string {
	groups := []string{}
	for _, t := range s.Tags {
		if g := ansible.GroupName(t); g != "" && !slices.Contains(groups, g) {
			groups = append(groups, g)
		}
	}
	if s.OsID != "" {
		if g := ansible.GroupName("os_" + s.OsID); g != "" && !slices.Contains(groups, g) {
			groups = append(groups, g)
		}
	}
	return groups
}

// targetProblem is why a server can't be in this person's run.
func targetProblem(acc *auth.Access, s sqlc.Server) string {
	switch {
	case acc.ServerLevel(s.WorkspaceID, s.ID) < auth.Owner:
		return "You need Owner access on this server to run a playbook on it."
	case s.HostKey == "":
		return "It hasn't been reached yet, so its host key isn't known. Check it first."
	}
	return ""
}

// ---- Validation ----

// checkPlaybookYAML catches what ansible-playbook would refuse outright, and
// answers at the field rather than as a failed run.
func checkPlaybookYAML(content string) error {
	var doc any
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return fieldError("body.content", "This isn't valid YAML: "+strings.TrimPrefix(err.Error(), "yaml: "), nil)
	}
	plays, ok := doc.([]any)
	if !ok || len(plays) == 0 {
		return fieldError("body.content", "A playbook is a list of plays: start with \"- hosts: all\".", nil)
	}
	return nil
}

func checkExtraVars(s string) error {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var doc any
	if err := yaml.Unmarshal([]byte(s), &doc); err != nil {
		return fieldError("body.options.extra_vars", "This isn't valid YAML: "+strings.TrimPrefix(err.Error(), "yaml: "), nil)
	}
	if _, ok := doc.(map[string]any); !ok {
		return fieldError("body.options.extra_vars", "Extra variables are a mapping, like \"version: 1.2\".", nil)
	}
	return nil
}

var ansibleTagRe = regexp.MustCompile(`^[^\s,@-][^\s,]*$`)

func checkAnsibleOptions(o AnsibleOptions) error {
	for _, t := range append(slices.Clone(o.Tags), o.SkipTags...) {
		if !ansibleTagRe.MatchString(t) {
			return fieldError("body.options.tags", "A tag is one word, not starting with - or @.", t)
		}
	}
	// @file would read a file on the Morcheh host.
	if l := strings.TrimSpace(o.Limit); l != "" && (l[0] == '-' || strings.Contains(l, "@")) {
		return fieldError("body.options.limit", "A limit can't start with - or contain @.", o.Limit)
	}
	return checkExtraVars(o.ExtraVars)
}

// ---- Keeping stored runs honest ----

// syncRun ends a stored run whose job ended without it: canceled while queued,
// or Morcheh restarted. It says whether it changed anything.
func (h *ansibleHandler) syncRun(ctx context.Context, id uuid.UUID, state string, job *uuid.UUID, created time.Time) bool {
	if !jobs.Active(state) || h.liveRun(id) != nil {
		return false
	}
	end := func(state, msg string) bool {
		if err := h.q.EndAnsibleRun(ctx, sqlc.EndAnsibleRunParams{ID: id, State: state, Error: msg}); err != nil {
			slog.Warn("end an ansible run", "run", id, "error", err)
			return false
		}
		return true
	}
	const lost = "Morcheh restarted before it finished."
	if job == nil {
		// Its job is being submitted right now.
		if time.Since(created) < time.Minute {
			return false
		}
		return end(jobs.Interrupted, lost)
	}
	j, err := h.runner.Get(ctx, *job)
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

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// loadRun reads a run, with the live output over it while it runs.
func (h *ansibleHandler) loadRun(ctx context.Context, id uuid.UUID) (sqlc.AnsibleRun, *ansibleLive, error) {
	r, err := h.q.GetAnsibleRun(ctx, id)
	if isNotFound(err) {
		return r, nil, huma.Error404NotFound("run not found")
	}
	if err != nil {
		return r, nil, internalError(err)
	}
	if h.syncRun(ctx, r.ID, r.State, r.JobID, r.CreatedAt) {
		if r, err = h.q.GetAnsibleRun(ctx, id); err != nil {
			return r, nil, internalError(err)
		}
	}
	return r, h.liveRun(id), nil
}

func (h *ansibleHandler) detail(ctx context.Context, id uuid.UUID) (AnsibleRunDetail, error) {
	r, live, err := h.loadRun(ctx, id)
	if err != nil {
		return AnsibleRunDetail{}, err
	}
	if live != nil {
		live.mu.Lock()
		defer live.mu.Unlock()
		return live.overlay(r), nil
	}
	return toAnsibleRunDetail(r), nil
}

// ---- Running ----

// ansibleRunPlan is a checked request to run a playbook.
type ansibleRunPlan struct {
	ws         uuid.UUID
	playbookID *uuid.UUID
	content    string
	name       string
	hosts      []AnsibleHost
	ids        []uuid.UUID
	body       startRunBody
}

// plan checks a run request as the person in ctx: a sandbox (or a system
// admin), a valid playbook and Owner on every chosen server. Cron jobs check
// theirs with it too.
func (h *ansibleHandler) plan(ctx context.Context, ws uuid.UUID, body startRunBody) (ansibleRunPlan, error) {
	p := principalOf(ctx)
	if msg := noSandboxProblem(h.hostStatus(), p.Access.Admin); msg != "" {
		return ansibleRunPlan{}, huma.Error409Conflict(msg)
	}
	var playbookID *uuid.UUID
	content, name := "", strings.TrimSpace(body.Name)
	if body.PlaybookID != nil && *body.PlaybookID != "" {
		id, err := uuid.Parse(*body.PlaybookID)
		if err != nil {
			return ansibleRunPlan{}, fieldError("body.playbook_id", "Not a playbook id.", *body.PlaybookID)
		}
		saved, err := h.q.GetPlaybook(ctx, id)
		if isNotFound(err) || (err == nil && saved.WorkspaceID != ws) {
			return ansibleRunPlan{}, fieldError("body.playbook_id", "This playbook isn't in this workspace.", *body.PlaybookID)
		}
		if err != nil {
			return ansibleRunPlan{}, internalError(err)
		}
		playbookID, content, name = &saved.ID, saved.Content, saved.Name
	}
	if body.Content != nil {
		content = *body.Content
	}
	if name == "" {
		name = "Untitled playbook"
	}
	if err := checkPlaybookYAML(content); err != nil {
		return ansibleRunPlan{}, err
	}
	if err := checkAnsibleOptions(body.Options); err != nil {
		return ansibleRunPlan{}, err
	}
	targets, err := h.resolveTargets(ctx, ws, body.Selection)
	if err != nil {
		return ansibleRunPlan{}, err
	}
	if len(targets) == 0 {
		return ansibleRunPlan{}, fieldError("body.selection", "Choose at least one server.", nil)
	}
	ids := make([]uuid.UUID, len(targets))
	hosts := make([]AnsibleHost, len(targets))
	for i, t := range targets {
		if msg := targetProblem(p.Access, t.server); msg != "" {
			if p.Access.ServerLevel(ws, t.server.ID) < auth.Owner {
				return ansibleRunPlan{}, forbidden(auth.Owner)
			}
			return ansibleRunPlan{}, fieldError("body.selection", t.server.Name+": "+msg, t.server.ID.String())
		}
		ids[i] = t.server.ID
		hosts[i] = AnsibleHost{ServerID: t.server.ID.String(), Name: t.server.Name, Host: t.server.Host, InventoryName: t.name}
	}
	if _, err := h.authz.requireServers(ctx, ids, auth.Owner); err != nil {
		return ansibleRunPlan{}, err
	}
	return ansibleRunPlan{ws: ws, playbookID: playbookID, content: content, name: name, hosts: hosts, ids: ids, body: body}, nil
}

// create stores a planned run, not yet started.
func (h *ansibleHandler) create(ctx context.Context, plan ansibleRunPlan) (sqlc.AnsibleRun, error) {
	p := principalOf(ctx)
	selection, _ := json.Marshal(plan.body.Selection)
	hostsJSON, _ := json.Marshal(plan.hosts)
	options, _ := json.Marshal(plan.body.Options)
	run, err := h.q.CreateAnsibleRun(ctx, sqlc.CreateAnsibleRunParams{
		WorkspaceID: plan.ws, PlaybookID: plan.playbookID, PlaybookName: plan.name, Content: plan.content,
		Selection: selection, Hosts: hostsJSON, ServerIds: plan.ids, Options: options,
		CreatedBy: p.ID(), CreatedByName: cmpOr(p.User.FullName, p.User.Username),
	})
	if err != nil {
		return run, internalError(err)
	}
	return run, nil
}

type ansibleRunParams struct {
	RunID uuid.UUID `json:"run_id"`
	// The person who started it is a system admin. Checked again when it runs:
	// the sandbox could be gone by then.
	AllowNoSandbox bool `json:"allow_no_sandbox"`
}

func (h *ansibleHandler) runJob(ctx context.Context, t *jobs.Task) (any, error) {
	var params ansibleRunParams
	if err := t.Decode(&params); err != nil {
		return nil, err
	}
	return h.execute(ctx, t, params)
}

// execute runs a stored run in the job t (its own, or a cron job's).
func (h *ansibleHandler) execute(ctx context.Context, t *jobs.Task, params ansibleRunParams) (any, error) {
	bg := context.WithoutCancel(ctx)
	run, err := h.q.GetAnsibleRun(ctx, params.RunID)
	if isNotFound(err) {
		return nil, errors.New("The run was deleted before it started.")
	}
	if err != nil {
		return nil, err
	}
	if !jobs.Active(run.State) {
		return nil, nil
	}
	fail := func(err error) (any, error) {
		_ = h.q.EndAnsibleRun(bg, sqlc.EndAnsibleRunParams{ID: run.ID, State: jobs.Failed, Error: err.Error()})
		return nil, err
	}

	st := ansible.Detect(ctx, h.cfg)
	if msg := noSandboxProblem(st, params.AllowNoSandbox); msg != "" {
		return fail(errors.New(msg))
	}
	var spec ansible.Spec
	var options AnsibleOptions
	decodeInto(run.Options, &options)
	spec = ansible.Spec{
		Playbook: run.Content, Check: options.Check, Diff: options.Diff, Verbosity: options.Verbosity,
		Tags: options.Tags, SkipTags: options.SkipTags, Limit: options.Limit, Forks: options.Forks,
		ExtraVars: options.ExtraVars,
	}
	if spec.Hosts, err = h.inventoryHosts(ctx, run); err != nil {
		return fail(err)
	}

	live := &ansibleLive{log: ansible.NewLog(), subs: map[*ansibleSub]struct{}{}}
	if err := h.q.StartAnsibleRun(ctx, run.ID); err != nil {
		return fail(err)
	}
	h.mu.Lock()
	h.live[run.ID] = live
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.live, run.ID)
		h.mu.Unlock()
		live.end()
	}()

	t.Update(func(p *jobs.Progress) {
		p.Phase, p.ItemsTotal = "Starting", 0
	})

	// Copies to the database, so a restart loses a few seconds at most.
	saveDone := make(chan struct{})
	saveStop := make(chan struct{})
	go func() {
		defer close(saveDone)
		tick := time.NewTicker(3 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-saveStop:
				return
			case <-tick.C:
				live.mu.Lock()
				if !live.dirty {
					live.mu.Unlock()
					continue
				}
				live.dirty = false
				output, truncated := live.out.String(), live.out.Truncated()
				plays, err := json.Marshal(live.log.Plays)
				live.mu.Unlock()
				if err != nil {
					continue
				}
				if err := h.q.SaveAnsibleRunProgress(bg, sqlc.SaveAnsibleRunProgressParams{
					ID: run.ID, Output: output, OutputTruncated: truncated, Plays: plays,
				}); err != nil {
					slog.Warn("save an ansible run's progress", "run", run.ID, "error", err)
				}
			}
		}
	}()

	code, runErr := ansible.Run(ctx, h.cfg, st, spec, ansible.Hook{
		Output: func(text string) {
			live.mu.Lock()
			defer live.mu.Unlock()
			offset := live.out.Add(text)
			live.dirty = true
			live.publish(AnsibleOutputChunk{Offset: offset, Text: text})
		},
		Event: func(ev ansible.RunEvent) {
			live.mu.Lock()
			task := live.log.Apply(ev)
			live.dirty = true
			live.publish(ev)
			live.mu.Unlock()
			if ev.E == "task" && task != nil {
				t.Update(func(p *jobs.Progress) { p.Phase, p.Current = "Running", task.Name })
			}
		},
	})
	close(saveStop)
	<-saveDone

	state, msg := ansibleOutcome(ctx, t, code, runErr, live)
	live.mu.Lock()
	live.log.Close()
	output, truncated := live.out.String(), live.out.Truncated()
	plays, _ := json.Marshal(live.log.Plays)
	recap, _ := json.Marshal(live.log.Recap)
	live.mu.Unlock()
	var exit *int32
	if code >= 0 {
		c := int32(code)
		exit = &c
	}
	finish := sqlc.FinishAnsibleRunParams{
		ID: run.ID, State: state, Error: msg, ExitCode: exit,
		Output: output, OutputTruncated: truncated, Plays: plays, Recap: recap,
	}
	if err := h.q.FinishAnsibleRun(bg, finish); err != nil {
		// Whatever the results held that PostgreSQL refused, the run must end.
		slog.Warn("store an ansible run's results", "run", run.ID, "error", err)
		finish.Plays = []byte("[]")
		if err := h.q.FinishAnsibleRun(bg, finish); err != nil {
			slog.Error("finish an ansible run", "run", run.ID, "error", err)
		}
	}

	switch state {
	case jobs.Succeeded:
		return map[string]any{"run_id": run.ID.String()}, nil
	case jobs.Failed:
		return nil, errors.New(msg)
	}
	return nil, cmpErr(ctx.Err(), runErr)
}

func cmpErr(a, b error) error {
	if a != nil {
		return a
	}
	return b
}

// ansibleOutcome turns how ansible-playbook ended into the run's state.
func ansibleOutcome(ctx context.Context, t *jobs.Task, code int, err error, live *ansibleLive) (state, msg string) {
	if ctx.Err() != nil {
		if t.Canceled() {
			return jobs.Canceled, ""
		}
		return jobs.Interrupted, "Morcheh restarted before it finished."
	}
	if err != nil {
		return jobs.Failed, err.Error()
	}
	if code == 0 {
		return jobs.Succeeded, ""
	}
	live.mu.Lock()
	defer live.mu.Unlock()
	failed, unreachable := 0, 0
	for _, s := range live.log.Recap {
		if s.Failed > 0 {
			failed++
		}
		if s.Unreachable > 0 {
			unreachable++
		}
	}
	switch {
	case failed > 0 && unreachable > 0:
		return jobs.Failed, fmt.Sprintf("%s failed, %s unreachable", countHosts(failed), countHosts(unreachable))
	case failed > 0:
		return jobs.Failed, countHosts(failed) + " failed"
	case unreachable > 0:
		return jobs.Failed, countHosts(unreachable) + " unreachable"
	}
	return jobs.Failed, fmt.Sprintf("ansible-playbook stopped with exit code %d. See the output.", code)
}

func countHosts(n int) string {
	if n == 1 {
		return "1 host"
	}
	return fmt.Sprintf("%d hosts", n)
}

// inventoryHosts opens the credentials of a run's servers, under the names the
// run was created with. Servers deleted since are left out.
func (h *ansibleHandler) inventoryHosts(ctx context.Context, run sqlc.AnsibleRun) ([]ansible.Host, error) {
	var stored []AnsibleHost
	decodeInto(run.Hosts, &stored)
	all, err := h.q.ListAnsibleServers(ctx, run.WorkspaceID)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]sqlc.Server, len(all))
	for _, s := range all {
		byID[s.ID.String()] = s
	}
	hosts := make([]ansible.Host, 0, len(stored))
	for _, want := range stored {
		s, ok := byID[want.ServerID]
		if !ok {
			continue
		}
		target, err := h.servers.target(s)
		if err != nil {
			return nil, fmt.Errorf("%s: its login can't be read: %w", s.Name, err)
		}
		hosts = append(hosts, ansible.Host{
			ServerID: want.ServerID, Name: want.InventoryName, ServerName: s.Name,
			Address: s.Host, Port: int(s.Port), User: s.Username,
			Password: target.Password, PrivateKey: target.PrivateKey, Passphrase: target.Passphrase,
			HostKey: s.HostKey, Groups: serverGroups(s),
		})
	}
	if len(hosts) == 0 {
		return nil, errors.New("None of its servers exist anymore.")
	}
	return hosts, nil
}

// ---- Endpoints ----

type playbookBody struct {
	Name        string `json:"name" minLength:"1" maxLength:"100"`
	Description string `json:"description,omitempty" maxLength:"2000"`
	Content     string `json:"content" maxLength:"1048576" doc:"The playbook (YAML). Saved even if it isn't valid yet; checked when it runs"`
	Variables   string `json:"variables,omitempty" maxLength:"262144"`
}

// playbookUpdate repeats playbookBody's fields: Huma doesn't flatten an
// embedded unexported struct into the schema, and would refuse them.
type playbookUpdate struct {
	Name        string     `json:"name" minLength:"1" maxLength:"100"`
	Description string     `json:"description,omitempty" maxLength:"2000"`
	Content     string     `json:"content" maxLength:"1048576"`
	Variables   string     `json:"variables,omitempty" maxLength:"262144"`
	Revision    *time.Time `json:"revision,omitempty" doc:"Its updated_at when loaded; a different one answers 409"`
}

type startRunBody struct {
	PlaybookID *string          `json:"playbook_id,omitempty" format:"uuid" doc:"A saved playbook"`
	Content    *string          `json:"content,omitempty" maxLength:"1048576" doc:"Run this text instead of the saved one, or without saving at all"`
	Name       string           `json:"name,omitempty" maxLength:"100" doc:"What to call it when it isn't saved"`
	Selection  AnsibleSelection `json:"selection"`
	Options    AnsibleOptions   `json:"options,omitempty"`
}

type previewHost struct {
	AnsibleHost
	Groups  []string `json:"groups" doc:"The Ansible groups it's in: its tags and os_<id>"`
	Status  string   `json:"status" doc:"Its status at the last check"`
	Problem string   `json:"problem" doc:"Why it can't be in the run"`
}

type startRunOutput struct {
	Body struct {
		Run AnsibleRun `json:"run"`
		Job Job        `json:"job"`
	}
}

func registerAnsible(api huma.API, h *ansibleHandler) {
	tags := []string{"Ansible"}
	h.runner.Handle(ansibleRunKind, h.runJob)

	huma.Register(api, huma.Operation{
		OperationID: "get-ansible-status",
		Method:      http.MethodGet,
		Path:        "/ansible/status",
		Summary:     "Can playbooks run on this Morcheh?",
		Tags:        tags,
	}, func(ctx context.Context, _ *struct{}) (*struct{ Body AnsibleStatus }, error) {
		st := h.hostStatus()
		problem := noSandboxProblem(st, principalOf(ctx).Access.Admin)
		return &struct{ Body AnsibleStatus }{AnsibleStatus{
			Installed: st.Installed, Version: st.Version, Sandbox: st.Sandbox != "",
			CanRun: problem == "", Problem: problem,
		}}, nil
	})

	// ---- Modules (what a task can use) ----

	huma.Register(api, huma.Operation{
		OperationID: "list-ansible-modules",
		Method:      http.MethodGet,
		Path:        "/ansible/modules",
		Summary:     "List the modules installed with Ansible",
		Description: "Read from ansible-doc and kept until Ansible is upgraded.",
		Tags:        tags,
	}, func(ctx context.Context, _ *struct{}) (*struct {
		Body struct {
			Version string           `json:"version" doc:"ansible-core version"`
			Items   []ansible.Module `json:"items"`
		}
	}, error) {
		st := h.hostStatus()
		if !st.Installed {
			return nil, huma.Error503ServiceUnavailable(st.Problem)
		}
		list, err := h.catalog.Modules(ctx, st)
		if err != nil {
			return nil, huma.Error503ServiceUnavailable(err.Error())
		}
		out := &struct {
			Body struct {
				Version string           `json:"version" doc:"ansible-core version"`
				Items   []ansible.Module `json:"items"`
			}
		}{}
		out.Body.Version, out.Body.Items = st.Version, list
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-ansible-module",
		Method:      http.MethodGet,
		Path:        "/ansible/modules/{name}",
		Summary:     "Describe a module: its options and examples",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		Name string `path:"name" maxLength:"200" doc:"Fully qualified (ansible.builtin.apt) or short (apt)"`
	}) (*struct{ Body ansible.ModuleDoc }, error) {
		st := h.hostStatus()
		if !st.Installed {
			return nil, huma.Error503ServiceUnavailable(st.Problem)
		}
		d, err := h.catalog.Doc(ctx, st, in.Name)
		if errors.Is(err, ansible.ErrNoModule) {
			return nil, huma.Error404NotFound("There's no module called " + in.Name + " on this Morcheh.")
		}
		if err != nil {
			return nil, huma.Error503ServiceUnavailable(err.Error())
		}
		return &struct{ Body ansible.ModuleDoc }{*d}, nil
	})

	// ---- Playbooks ----

	huma.Register(api, huma.Operation{
		OperationID: "list-playbooks",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/ansible/playbooks",
		Summary:     "List a workspace's playbooks",
		Tags:        tags,
	}, func(ctx context.Context, in *WorkspacePath) (*struct {
		Body struct {
			Items []Playbook `json:"items"`
		}
	}, error) {
		rows, err := h.q.ListPlaybooks(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []Playbook `json:"items"`
			}
		}{}
		out.Body.Items = make([]Playbook, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = Playbook{
				ID: r.ID.String(), WorkspaceID: r.WorkspaceID.String(), Name: r.Name, Description: r.Description,
				Size: r.Size, LastRunID: optionalIDString(r.LastRunID), LastRunState: r.LastRunState, LastRunAt: r.LastRunAt,
				CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
			}
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-playbook",
		Method:        http.MethodPost,
		Path:          "/workspaces/{id}/ansible/playbooks",
		Summary:       "Save a new playbook",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body playbookBody
	}) (*PlaybookOutput, error) {
		p, err := h.q.CreatePlaybook(ctx, sqlc.CreatePlaybookParams{
			WorkspaceID: uuid.MustParse(in.ID), Name: strings.TrimSpace(in.Body.Name),
			Description: in.Body.Description, Content: in.Body.Content, Variables: in.Body.Variables,
			CreatedBy: principalOf(ctx).ID(),
		})
		if isUniqueViolation(err) {
			return nil, fieldError("body.name", "A playbook with this name already exists.", in.Body.Name)
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &PlaybookOutput{toPlaybookDetail(p)}, nil
	})

	type playbookPath struct {
		ID string `path:"id" format:"uuid"`
	}

	huma.Register(api, huma.Operation{
		OperationID: "get-playbook",
		Method:      http.MethodGet,
		Path:        "/ansible/playbooks/{id}",
		Summary:     "Get a playbook",
		Tags:        tags,
	}, func(ctx context.Context, in *playbookPath) (*PlaybookOutput, error) {
		p, err := h.q.GetPlaybook(ctx, uuid.MustParse(in.ID))
		if isNotFound(err) {
			return nil, huma.Error404NotFound("playbook not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &PlaybookOutput{toPlaybookDetail(p)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-playbook",
		Method:      http.MethodPatch,
		Path:        "/ansible/playbooks/{id}",
		Summary:     "Save changes to a playbook",
		Description: "With revision (its updated_at when you loaded it), answers 409 when someone else saved in between.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		playbookPath
		Body playbookUpdate
	}) (*PlaybookOutput, error) {
		id := uuid.MustParse(in.ID)
		old, err := h.q.GetPlaybook(ctx, id)
		if isNotFound(err) {
			return nil, huma.Error404NotFound("playbook not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if in.Body.Revision != nil && !in.Body.Revision.Equal(old.UpdatedAt) {
			return nil, huma.Error409Conflict("Someone else saved this playbook after you opened it.")
		}
		p, err := h.q.UpdatePlaybook(ctx, sqlc.UpdatePlaybookParams{
			ID: id, Name: strings.TrimSpace(in.Body.Name), Description: in.Body.Description,
			Content: in.Body.Content, Variables: in.Body.Variables, UpdatedBy: principalOf(ctx).ID(),
		})
		if isUniqueViolation(err) {
			return nil, fieldError("body.name", "A playbook with this name already exists.", in.Body.Name)
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &PlaybookOutput{toPlaybookDetail(p)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-playbook",
		Method:        http.MethodDelete,
		Path:          "/ansible/playbooks/{id}",
		Summary:       "Delete a playbook",
		Description:   "Its past runs stay, with the text they ran.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *playbookPath) (*struct{}, error) {
		if _, err := h.q.DeletePlaybook(ctx, uuid.MustParse(in.ID)); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})

	// ---- Targets ----

	huma.Register(api, huma.Operation{
		OperationID: "preview-ansible-targets",
		Method:      http.MethodPost,
		Path:        "/workspaces/{id}/ansible/preview",
		Summary:     "See which servers a selection means",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body struct {
			Selection AnsibleSelection `json:"selection"`
		}
	}) (*struct {
		Body struct {
			Hosts []previewHost `json:"hosts"`
		}
	}, error) {
		targets, err := h.resolveTargets(ctx, uuid.MustParse(in.ID), in.Body.Selection)
		if err != nil {
			return nil, err
		}
		acc := principalOf(ctx).Access
		out := &struct {
			Body struct {
				Hosts []previewHost `json:"hosts"`
			}
		}{}
		out.Body.Hosts = make([]previewHost, len(targets))
		for i, t := range targets {
			out.Body.Hosts[i] = previewHost{
				AnsibleHost: AnsibleHost{ServerID: t.server.ID.String(), Name: t.server.Name, Host: t.server.Host, InventoryName: t.name},
				Groups:      serverGroups(t.server), Status: t.server.Status, Problem: targetProblem(acc, t.server),
			}
		}
		return out, nil
	})

	// ---- Runs ----

	huma.Register(api, huma.Operation{
		OperationID:   "start-ansible-run",
		Method:        http.MethodPost,
		Path:          "/workspaces/{id}/ansible/runs",
		Summary:       "Run a playbook",
		Description:   "Queues a background job. You need Owner on every chosen server: a playbook can do anything there, including reading its login.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body startRunBody
	}) (*startRunOutput, error) {
		p := principalOf(ctx)
		plan, err := h.plan(ctx, uuid.MustParse(in.ID), in.Body)
		if err != nil {
			return nil, err
		}
		run, err := h.create(ctx, plan)
		if err != nil {
			return nil, err
		}
		name, targets, ids := plan.name, plan.hosts, plan.ids
		runID := run.ID.String()
		j, err := submit(ctx, h.runner, jobs.Spec{
			Kind:   ansibleRunKind,
			Title:  fmt.Sprintf("Run %s on %s", name, countServers(len(targets))),
			Params: ansibleRunParams{RunID: run.ID, AllowNoSandbox: p.Access.Admin},
			Refs:   ids,
			Target: JobPlace{RunID: runID, Name: name},
		})
		if err != nil {
			_ = h.q.EndAnsibleRun(context.WithoutCancel(ctx), sqlc.EndAnsibleRunParams{ID: run.ID, State: jobs.Failed, Error: "It couldn't be queued."})
			return nil, err
		}
		jobID := uuid.MustParse(j.Body.ID)
		if err := h.q.SetAnsibleRunJob(ctx, sqlc.SetAnsibleRunJobParams{ID: run.ID, JobID: &jobID}); err != nil {
			return nil, internalError(err)
		}
		run.JobID = &jobID
		out := &startRunOutput{}
		out.Body.Run = toAnsibleRunDetail(run).AnsibleRun
		out.Body.Job = j.Body
		return out, nil
	})

	type runList struct {
		Body struct {
			Items []AnsibleRun `json:"items"`
			Total int64        `json:"total"`
		}
	}

	huma.Register(api, huma.Operation{
		OperationID: "list-ansible-runs",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/ansible/runs",
		Summary:     "List runs, newest first",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		PlaybookID string `query:"playbook_id" format:"uuid"`
		ServerID   string `query:"server_id" format:"uuid"`
		State      string `query:"state" enum:"queued,running,succeeded,failed,canceled,interrupted"`
		Q          string `query:"q" doc:"In the playbook's name or who ran it"`
		Limit      int32  `query:"limit" minimum:"1" maximum:"200" default:"50"`
		Offset     int32  `query:"offset" minimum:"0"`
	}) (*runList, error) {
		params := sqlc.ListAnsibleRunsParams{WorkspaceID: uuid.MustParse(in.ID), Lim: in.Limit, Off: in.Offset}
		count := sqlc.CountAnsibleRunsParams{WorkspaceID: params.WorkspaceID}
		if in.PlaybookID != "" {
			id := uuid.MustParse(in.PlaybookID)
			params.PlaybookID, count.PlaybookID = &id, &id
		}
		if in.ServerID != "" {
			id := uuid.MustParse(in.ServerID)
			params.ServerID, count.ServerID = &id, &id
		}
		if in.State != "" {
			params.State, count.State = &in.State, &in.State
		}
		if q := strings.TrimSpace(in.Q); q != "" {
			params.Q, count.Q = &q, &q
		}
		rows, err := h.q.ListAnsibleRuns(ctx, params)
		if err != nil {
			return nil, internalError(err)
		}
		changed := false
		for _, r := range rows {
			if h.syncRun(ctx, r.ID, r.State, r.JobID, r.CreatedAt) {
				changed = true
			}
		}
		if changed {
			if rows, err = h.q.ListAnsibleRuns(ctx, params); err != nil {
				return nil, internalError(err)
			}
		}
		total, err := h.q.CountAnsibleRuns(ctx, count)
		if err != nil {
			return nil, internalError(err)
		}
		out := &runList{}
		out.Body.Total = total
		out.Body.Items = make([]AnsibleRun, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = toAnsibleRunRow(r)
		}
		return out, nil
	})

	type runPath struct {
		ID string `path:"id" format:"uuid"`
	}
	type runOutput struct{ Body AnsibleRunDetail }

	huma.Register(api, huma.Operation{
		OperationID: "get-ansible-run",
		Method:      http.MethodGet,
		Path:        "/ansible/runs/{id}",
		Summary:     "Get a run with its output and results",
		Tags:        tags,
	}, func(ctx context.Context, in *runPath) (*runOutput, error) {
		d, err := h.detail(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, err
		}
		return &runOutput{d}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "cancel-ansible-run",
		Method:      http.MethodPost,
		Path:        "/ansible/runs/{id}/cancel",
		Summary:     "Stop a run",
		Description: "A queued run is dropped; a running one stops soon. What it already did on the servers stays done.",
		Tags:        tags,
	}, func(ctx context.Context, in *runPath) (*runOutput, error) {
		id := uuid.MustParse(in.ID)
		r, _, err := h.loadRun(ctx, id)
		if err != nil {
			return nil, err
		}
		if !jobs.Active(r.State) || r.JobID == nil {
			return nil, huma.Error409Conflict("The run has already finished.")
		}
		if _, err := h.runner.Cancel(ctx, *r.JobID); err != nil {
			return nil, jobProblem(err)
		}
		d, err := h.detail(ctx, id)
		if err != nil {
			return nil, err
		}
		return &runOutput{d}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-ansible-run",
		Method:        http.MethodDelete,
		Path:          "/ansible/runs/{id}",
		Summary:       "Delete a finished run",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *runPath) (*struct{}, error) {
		id := uuid.MustParse(in.ID)
		if _, _, err := h.loadRun(ctx, id); err != nil {
			return nil, err
		}
		n, err := h.q.DeleteAnsibleRun(ctx, id)
		if err != nil {
			return nil, internalError(err)
		}
		if n == 0 {
			return nil, huma.Error409Conflict("Stop the run before deleting it.")
		}
		return nil, nil
	})

	sse.Register(api, huma.Operation{
		OperationID: "stream-ansible-run",
		Method:      http.MethodGet,
		Path:        "/ansible/runs/{id}/stream",
		Summary:     "Follow a run",
		Description: "Server-sent events. `snapshot` is the whole run: on connecting, and last when it ends (state is then final, and the stream closes). " +
			"In between `output` carries new text and `event` what the callback reported: apply it to plays and recap as GET returns them.",
		Tags: tags,
	}, map[string]any{"snapshot": AnsibleRunDetail{}, "output": AnsibleOutputChunk{}, "event": ansible.RunEvent{}},
		func(ctx context.Context, in *runPath, send sse.Sender) {
			h.stream(ctx, uuid.MustParse(in.ID), send)
		})
}

func countServers(n int) string {
	if n == 1 {
		return "1 server"
	}
	return fmt.Sprintf("%d servers", n)
}

// stream follows a run until it ends. A follower that falls too far behind
// starts over from a fresh snapshot.
func (h *ansibleHandler) stream(ctx context.Context, id uuid.UUID, send sse.Sender) {
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	poll := time.NewTicker(time.Second)
	defer poll.Stop()
	sent := false
	for ctx.Err() == nil {
		r, live, err := h.loadRun(ctx, id)
		if err != nil {
			return
		}
		if live != nil {
			d, sub := live.follow(r)
			if send.Data(d) != nil {
				live.leave(sub)
				return
			}
			sent = true
			following := true
			for following {
				var err error
				select {
				case <-ctx.Done():
					live.leave(sub)
					return
				case <-sub.gone:
					following = false
				case msg := <-sub.ch:
					err = send.Data(msg)
				case <-ping.C:
					err = send(sse.Message{Comment: "ping"})
				}
				if err != nil {
					live.leave(sub)
					return
				}
			}
			continue
		}
		if !jobs.Active(r.State) {
			_ = send.Data(toAnsibleRunDetail(r))
			return
		}
		// Waiting for its turn, or about to start.
		if !sent {
			if send.Data(toAnsibleRunDetail(r)) != nil {
				return
			}
			sent = true
		}
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
		case <-ping.C:
			if send(sse.Message{Comment: "ping"}) != nil {
				return
			}
		}
	}
}
