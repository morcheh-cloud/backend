package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/events"
	"github.com/morche/backend/internal/jobs"
	"github.com/morche/backend/internal/secrets"
)

// Automations: when an event happens in a workspace (or an automation's
// incoming URL is called, or someone presses Run), do up to 10 steps in
// order. A run is a job (automationRunKind) acting as whoever saved the
// automation last, with their access re-checked when it runs.

const (
	automationRunKind     = "automation-run"
	maxAutomationActions  = 10
	automationStepOutput  = 16 << 10
	automationKeepDays    = 90
	automationKeepRuns    = 500
	automationHookPerMin  = 30
	automationHookBody    = 64 << 10
	automationHookPrefix  = "/automation-hooks/"
	automationDefaultCool = 300
	automationDefaultHour = 20
)

// ---- Shapes ----

// AutomationFilter narrows which events of the chosen types start it; every
// filter given must match.
type AutomationFilter struct {
	Servers  []string `json:"servers,omitempty" maxItems:"200" doc:"Only events on these servers (server_id)"`
	Tags     []string `json:"tags,omitempty" maxItems:"50" doc:"Only events on a server with one of these tags"`
	Severity []string `json:"severity,omitempty" maxItems:"3" doc:"Only these severities: info, warning, critical"`
	Subjects []string `json:"subjects,omitempty" maxItems:"200" doc:"Only events about these subjects (subject.id: a monitor, database, cron job…)"`
	Match    string   `json:"match,omitempty" maxLength:"200" doc:"Only events whose title contains this text (any case)"`
}

// AutomationTrigger is what starts an automation.
type AutomationTrigger struct {
	Kind         string           `json:"kind" enum:"event,webhook,manual" doc:"event = events of the chosen types; webhook = its incoming URL is called; manual = only Run now"`
	Events       []string         `json:"events,omitempty" maxItems:"50" doc:"event: the event types (GET /events/catalog; not internal ones)"`
	Filter       AutomationFilter `json:"filter" required:"false"`
	IncludeMuted bool             `json:"include_muted,omitempty" doc:"Also react to alert events published while a mute covers them (data.muted = true)"`
}

// AutomationAction is one step. Only the fields of its kind count.
type AutomationAction struct {
	ID              string `json:"id,omitempty" maxLength:"64" doc:"The step's own id, kept across edits (made when empty)"`
	Kind            string `json:"kind" enum:"notify,webhook,script,service,cronjob,check,wait"`
	Label           string `json:"label,omitempty" maxLength:"100" doc:"A name for the step in runs; blank = said from the kind"`
	ContinueOnError bool   `json:"continue_on_error,omitempty" doc:"Go on with the next steps when this one fails"`

	// notify
	ChannelIDs []string `json:"channel_ids,omitempty" maxItems:"20" doc:"notify: notification channels of the workspace"`
	Title      string   `json:"title,omitempty" maxLength:"500" doc:"notify: the message's title (templates; blank = {{event.title}})"`
	Text       string   `json:"text,omitempty" maxLength:"4000" doc:"notify: the message (templates; blank = {{event.text}})"`

	// webhook
	URL           string            `json:"url,omitempty" maxLength:"2000" doc:"webhook: http(s) address (never templated)"`
	Method        string            `json:"method,omitempty" enum:"POST,PUT,GET," doc:"webhook: default POST"`
	Headers       map[string]string `json:"headers,omitempty" doc:"webhook: extra headers, values may use templates. Answers carry the names with blank values (they're sealed); on save a blank value keeps the saved one"`
	Body          string            `json:"body,omitempty" maxLength:"65536" doc:"webhook: the body (templates); blank = the event as JSON"`
	AllowInternal bool              `json:"allow_internal,omitempty" doc:"webhook: allow a private or loopback address. System admins only"`

	// script, service, check
	On        string   `json:"on,omitempty" enum:"event,servers," doc:"script/service/check: event = the server the event happened on (default); servers = server_ids"`
	ServerIDs []string `json:"server_ids,omitempty" maxItems:"200" doc:"script/service/check with on = servers"`

	// script
	ScriptID       string `json:"script_id,omitempty" maxLength:"36" doc:"script: a saved script of the workspace; else command"`
	Command        string `json:"command,omitempty" maxLength:"262144" doc:"script: what to run when no script_id. The event reaches it as env vars MORCHE_EVENT_TYPE, MORCHE_EVENT_TITLE, MORCHE_SUBJECT_NAME… (never spliced into the text)"`
	Interpreter    string `json:"interpreter,omitempty" enum:"bash,sh,python3," doc:"script: for command; default bash"`
	AsRoot         bool   `json:"as_root,omitempty" doc:"script: run command as root (sudo -n)"`
	TimeoutSeconds int32  `json:"timeout_seconds,omitempty" minimum:"0" maximum:"86400" doc:"script: for command; 0 = 600"`

	// service
	Unit   string `json:"unit,omitempty" maxLength:"256" doc:"service: the unit (templates allowed, e.g. {{data.detail}}; must come out a unit name)"`
	Action string `json:"action,omitempty" enum:"start,stop,restart,reload," doc:"service: what to do"`

	// cronjob
	ScheduleID string `json:"schedule_id,omitempty" maxLength:"36" doc:"cronjob: the cron job to run now; the step waits for it"`

	// wait
	Seconds int32 `json:"seconds,omitempty" minimum:"0" maximum:"3600" doc:"wait: 1–3600"`
}

// storedAction is a step as saved: the webhook header values sealed apart.
type storedAction struct {
	AutomationAction
	HeadersEnc []byte `json:"headers_enc,omitempty"`
}

// AutomationRunBrief is one of the latest runs, for a list's strip.
type AutomationRunBrief struct {
	ID          string    `json:"id" format:"uuid"`
	Status      string    `json:"status"`
	TriggerKind string    `json:"trigger_kind"`
	CreatedAt   time.Time `json:"created_at"`
}

type Automation struct {
	ID              string               `json:"id" format:"uuid"`
	WorkspaceID     string               `json:"workspace_id" format:"uuid"`
	Name            string               `json:"name"`
	Description     string               `json:"description"`
	Enabled         bool                 `json:"enabled"`
	Trigger         AutomationTrigger    `json:"trigger"`
	Actions         []AutomationAction   `json:"actions"`
	CooldownSeconds int32                `json:"cooldown_seconds" doc:"After a run for a subject, events about the same subject are skipped this long"`
	MaxRunsPerHour  int32                `json:"max_runs_per_hour" doc:"0 = no limit"`
	HasHook         bool                 `json:"has_hook" doc:"An incoming URL is set (its token is only shown when made)"`
	RunAsID         *string              `json:"run_as_id" format:"uuid" doc:"Whoever saved it last: it runs with their access"`
	RunAsName       string               `json:"run_as_name"`
	CreatedAt       time.Time            `json:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at"`
	LastRunAt       *time.Time           `json:"last_run_at"`
	LastStatus      string               `json:"last_status" doc:"How its last run (not a skipped one) ended: succeeded, failed, canceled; '' = never ran"`
	Problem         string               `json:"problem" doc:"Why it can't run (lost access, a removed person…); '' = fine"`
	Recent          []AutomationRunBrief `json:"recent" doc:"Its last 10 runs, newest first"`
}

type AutomationBody struct {
	Name            string             `json:"name" minLength:"1" maxLength:"100"`
	Description     string             `json:"description,omitempty" maxLength:"2000"`
	Enabled         *bool              `json:"enabled,omitempty" doc:"Default true"`
	Trigger         AutomationTrigger  `json:"trigger"`
	Actions         []AutomationAction `json:"actions" minItems:"1" maxItems:"10"`
	CooldownSeconds *int32             `json:"cooldown_seconds,omitempty" minimum:"0" maximum:"86400" doc:"Default 300"`
	MaxRunsPerHour  *int32             `json:"max_runs_per_hour,omitempty" minimum:"0" maximum:"1000" doc:"Default 20; 0 = no limit"`
}

type AutomationStepLink struct {
	Kind     string `json:"kind" doc:"script-run, schedule-run (parent_id = the cron job), monitor, server"`
	ID       string `json:"id"`
	ParentID string `json:"parent_id,omitempty"`
}

// AutomationStepTarget is how a step went on one server or channel.
type AutomationStepTarget struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status" doc:"succeeded, failed, skipped, canceled, running, pending"`
	ExitCode *int32 `json:"exit_code,omitempty"`
	Output   string `json:"output,omitempty"`
	Error    string `json:"error,omitempty"`
}

// AutomationStep is how one step of a run went.
type AutomationStep struct {
	Index      int                    `json:"index"`
	ActionID   string                 `json:"action_id"`
	Kind       string                 `json:"kind"`
	Label      string                 `json:"label"`
	Status     string                 `json:"status" enum:"pending,running,succeeded,failed,skipped,canceled"`
	StartedAt  *time.Time             `json:"started_at"`
	FinishedAt *time.Time             `json:"finished_at"`
	Output     string                 `json:"output" doc:"≤16 KB. Blank for script and service steps below Operator"`
	Error      string                 `json:"error"`
	Link       *AutomationStepLink    `json:"link"`
	Targets    []AutomationStepTarget `json:"targets"`
}

type AutomationRun struct {
	ID             string           `json:"id" format:"uuid"`
	AutomationID   string           `json:"automation_id" format:"uuid"`
	AutomationName string           `json:"automation_name"`
	WorkspaceID    string           `json:"workspace_id" format:"uuid"`
	TriggerKind    string           `json:"trigger_kind" enum:"event,webhook,manual,test"`
	Event          PanelEvent       `json:"event"`
	Status         string           `json:"status" enum:"queued,running,succeeded,failed,skipped,canceled"`
	Steps          []AutomationStep `json:"steps"`
	Reason         string           `json:"reason" doc:"Why it was skipped or failed"`
	JobID          *string          `json:"job_id" format:"uuid"`
	CreatedAt      time.Time        `json:"created_at"`
	StartedAt      *time.Time       `json:"started_at"`
	FinishedAt     *time.Time       `json:"finished_at"`
	StartedByName  string           `json:"started_by_name" doc:"Who pressed Run or Test; '' for event and webhook runs"`
}

// AutomationEventInput is an event given to Run or Test (all optional): the
// workspace, id and time are always set by Morche.
type AutomationEventInput struct {
	Type     string          `json:"type,omitempty" maxLength:"100" doc:"Default: the trigger's first event type (with its sample's values)"`
	Severity string          `json:"severity,omitempty" enum:"info,warning,critical,"`
	Title    string          `json:"title,omitempty" maxLength:"500"`
	Text     string          `json:"text,omitempty" maxLength:"4000"`
	URL      string          `json:"url,omitempty" maxLength:"2000"`
	Subject  *events.Subject `json:"subject,omitempty" required:"false"`
	ServerID string          `json:"server_id,omitempty" maxLength:"36" doc:"The server it happened on (steps with on = event act there)"`
	Data     map[string]any  `json:"data,omitempty"`
}

type AutomationRunBody struct {
	Event *AutomationEventInput `json:"event,omitempty" required:"false" doc:"The event to run for; none = a manual run without one (steps with on = event then fail)"`
}

type AutomationTestBody struct {
	DryRun bool                  `json:"dry_run,omitempty" doc:"Say what each step would do, without doing it (no run is recorded)"`
	Event  *AutomationEventInput `json:"event,omitempty" required:"false" doc:"Default: the sample event of its first event type"`
}

type AutomationPreviewBody struct {
	Automation AutomationBody        `json:"automation"`
	Event      *AutomationEventInput `json:"event,omitempty" required:"false"`
}

// AutomationDryStep is what a step would do.
type AutomationDryStep struct {
	Index   int      `json:"index"`
	Kind    string   `json:"kind"`
	Label   string   `json:"label"`
	Summary string   `json:"summary" doc:"In plain words"`
	Servers []string `json:"servers" doc:"The servers (names) it would act on"`
	// Rendered templates.
	Title   string            `json:"title,omitempty"`
	Text    string            `json:"text,omitempty"`
	Body    string            `json:"body,omitempty"`
	Unit    string            `json:"unit,omitempty"`
	Env     map[string]string `json:"env,omitempty" doc:"script: the MORCHE_* variables it would get"`
	Problem string            `json:"problem" doc:"Why it would fail; '' = fine"`
}

type AutomationDryRun struct {
	Event   PanelEvent          `json:"event"`
	Matches bool                `json:"matches" doc:"The trigger would start it for this event"`
	Gate    string              `json:"gate" doc:"Why it wouldn't start now even though it matches (cooldown, runs per hour); '' = it would"`
	Problem string              `json:"problem" doc:"Why it couldn't run at all (lost access…)"`
	Steps   []AutomationDryStep `json:"steps"`
}

type AutomationTestResult struct {
	DryRun *AutomationDryRun `json:"dry_run" doc:"With dry_run"`
	Run    *AutomationRun    `json:"run" doc:"Without dry_run: the run started"`
	Job    *Job              `json:"job"`
}

type AutomationRunStarted struct {
	Run AutomationRun `json:"run"`
	Job *Job          `json:"job" doc:"null when it was skipped"`
}

type AutomationHook struct {
	Token string `json:"token" doc:"Shown only now"`
	Path  string `json:"path" doc:"POST JSON here (≤64 KB, it becomes event.data): the API's address + this path"`
}

type AutomationPath struct {
	ID string `path:"id" format:"uuid"`
}

type AutomationRunPath struct {
	ID string `path:"id" format:"uuid"`
}

type automationOutput struct{ Body Automation }

type automationListBody struct {
	Items []Automation `json:"items"`
}

type automationRunListBody struct {
	Items []AutomationRun `json:"items"`
	Total int64           `json:"total"`
}

type automationRunOutput struct{ Body AutomationRun }

// ---- Handler ----

type automationHandler struct {
	q         *sqlc.Queries
	box       *secrets.Box
	authz     *authz
	runner    *jobs.Runner
	servers   *serverHandler
	scripts   *scriptHandler
	schedules *scheduleHandler
	up        *uptimeHandler
	limiter   *hookLimiter
	// client makes the HTTP client for a webhook step (tests may swap it).
	client func(allowInternal bool) *http.Client

	mu     sync.Mutex
	pruned time.Time
}

func newAutomationHandler(q *sqlc.Queries, box *secrets.Box, a *authz, servers *serverHandler, scripts *scriptHandler, schedules *scheduleHandler, up *uptimeHandler) *automationHandler {
	h := &automationHandler{
		q: q, box: box, authz: a, runner: servers.jobs, servers: servers, scripts: scripts,
		schedules: schedules, up: up, limiter: newHookLimiter(automationHookPerMin), client: webhookClient,
	}
	// Runs left going when Morche stopped (before the runner picks their jobs up).
	if err := q.InterruptAutomationRuns(context.Background()); err != nil {
		slog.Warn("automations: end runs left running", "error", err)
	}
	return h
}

func decodeTrigger(raw []byte) AutomationTrigger {
	var t AutomationTrigger
	_ = json.Unmarshal(raw, &t)
	return t
}

func decodeActions(raw []byte) []storedAction {
	out := []storedAction{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func (h *automationHandler) toAutomation(ctx context.Context, a sqlc.Automation, recent []AutomationRunBrief) Automation {
	t := decodeTrigger(a.Trigger)
	if t.Events == nil {
		t.Events = []string{}
	}
	stored := decodeActions(a.Actions)
	acts := make([]AutomationAction, len(stored))
	for i, s := range stored {
		acts[i] = s.AutomationAction
	}
	if recent == nil {
		recent = []AutomationRunBrief{}
	}
	out := Automation{
		ID: a.ID.String(), WorkspaceID: a.WorkspaceID.String(), Name: a.Name, Description: a.Description,
		Enabled: a.Enabled, Trigger: t, Actions: acts, CooldownSeconds: a.CooldownSeconds,
		MaxRunsPerHour: a.MaxRunsPerHour, HasHook: a.HookTokenHash != nil, RunAsID: optionalIDString(a.UpdatedBy),
		CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt, LastRunAt: a.LastRunAt, LastStatus: a.LastStatus,
		Problem: a.Problem, Recent: recent,
	}
	// Whose access it runs with, and whether that person can still act.
	if a.UpdatedBy == nil {
		out.Problem = cmpOr(out.Problem, "The person who saved it was removed, so it can't run. Someone with access should open it and save it.")
	} else if u, err := h.q.GetUser(ctx, *a.UpdatedBy); err == nil {
		out.RunAsName = cmpOr(u.FullName, u.Username)
		if u.Status != "active" && out.Problem == "" {
			out.Problem = out.RunAsName + "'s account isn't active, so it can't run. Someone with access should open it and save it."
		}
	} else if isNotFound(err) {
		out.Problem = cmpOr(out.Problem, "The person who saved it was removed, so it can't run. Someone with access should open it and save it.")
	}
	return out
}

func (h *automationHandler) recent(ctx context.Context, ws uuid.UUID) map[uuid.UUID][]AutomationRunBrief {
	rows, err := h.q.RecentAutomationRuns(ctx, ws)
	out := map[uuid.UUID][]AutomationRunBrief{}
	if err != nil {
		return out
	}
	for _, r := range rows {
		out[r.AutomationID] = append(out[r.AutomationID], AutomationRunBrief{
			ID: r.ID.String(), Status: r.Status, TriggerKind: r.TriggerKind, CreatedAt: r.CreatedAt,
		})
	}
	return out
}

func (h *automationHandler) one(ctx context.Context, a sqlc.Automation) Automation {
	return h.toAutomation(ctx, a, h.recent(ctx, a.WorkspaceID)[a.ID])
}

// toRun shapes a run; script and service output stays hidden below Operator.
func toAutomationRun(r sqlc.AutomationRun, name string, level auth.Level) AutomationRun {
	var ev PanelEvent
	_ = json.Unmarshal(r.Event, &ev)
	steps := []AutomationStep{}
	_ = json.Unmarshal(r.Steps, &steps)
	for i := range steps {
		if steps[i].Targets == nil {
			steps[i].Targets = []AutomationStepTarget{}
		}
		if level < auth.Operator && (steps[i].Kind == "script" || steps[i].Kind == "service") {
			steps[i].Output = ""
			for j := range steps[i].Targets {
				steps[i].Targets[j].Output = ""
			}
		}
	}
	return AutomationRun{
		ID: r.ID.String(), AutomationID: r.AutomationID.String(), AutomationName: name,
		WorkspaceID: r.WorkspaceID.String(), TriggerKind: r.TriggerKind, Event: ev, Status: r.Status,
		Steps: steps, Reason: r.Reason, JobID: optionalIDString(r.JobID), CreatedAt: r.CreatedAt,
		StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, StartedByName: r.StartedByName,
	}
}

// ---- Checks ----

var automationSeverities = []string{events.Info, events.Warning, events.Critical}

// clean checks a body as the person saving it (p) and answers the steps to
// store. prev = the steps saved before (for kept header values and
// allow_internal).
func (h *automationHandler) clean(ctx context.Context, ws uuid.UUID, b *AutomationBody, prev []storedAction, p *principal) ([]storedAction, error) {
	b.Name = strings.TrimSpace(b.Name)
	b.Description = strings.TrimSpace(b.Description)
	if b.Name == "" {
		return nil, fieldError("body.name", "Give it a name.", b.Name)
	}
	t := &b.Trigger
	switch t.Kind {
	case "event":
		seen := map[string]bool{}
		evs := []string{}
		for i, e := range t.Events {
			e = strings.TrimSpace(e)
			typ, ok := events.Lookup(e)
			if !ok || typ.Internal {
				return nil, fieldError("body.trigger.events["+strconv.Itoa(i)+"]", "Not an event type an automation can react to.", e)
			}
			if !seen[e] {
				seen[e] = true
				evs = append(evs, e)
			}
		}
		if len(evs) == 0 {
			return nil, fieldError("body.trigger.events", "Choose at least one event.", nil)
		}
		t.Events = evs
	case "webhook", "manual":
		t.Events, t.Filter, t.IncludeMuted = []string{}, AutomationFilter{}, false
	default:
		return nil, fieldError("body.trigger.kind", "Choose what starts it.", t.Kind)
	}
	f := &t.Filter
	for i, s := range f.Servers {
		if _, err := uuid.Parse(s); err != nil {
			return nil, fieldError("body.trigger.filter.servers["+strconv.Itoa(i)+"]", "Not a server id.", s)
		}
	}
	f.Tags = trimAll(f.Tags)
	for i, s := range f.Severity {
		if !slices.Contains(automationSeverities, s) {
			return nil, fieldError("body.trigger.filter.severity["+strconv.Itoa(i)+"]", "info, warning or critical.", s)
		}
	}
	f.Subjects = trimAll(f.Subjects)
	f.Match = strings.TrimSpace(f.Match)

	if b.CooldownSeconds == nil {
		v := int32(automationDefaultCool)
		b.CooldownSeconds = &v
	}
	if b.MaxRunsPerHour == nil {
		v := int32(automationDefaultHour)
		b.MaxRunsPerHour = &v
	}
	if len(b.Actions) == 0 || len(b.Actions) > maxAutomationActions {
		return nil, fieldError("body.actions", fmt.Sprintf("Give it 1 to %d steps.", maxAutomationActions), len(b.Actions))
	}
	out := make([]storedAction, len(b.Actions))
	ids := map[string]bool{}
	for i := range b.Actions {
		a := b.Actions[i]
		loc := fmt.Sprintf("body.actions[%d]", i)
		a.ID = strings.TrimSpace(a.ID)
		if a.ID == "" || ids[a.ID] {
			a.ID = uuid.NewString()
		}
		ids[a.ID] = true
		a.Label = strings.TrimSpace(a.Label)
		var old *storedAction
		for j := range prev {
			if prev[j].ID == a.ID && prev[j].Kind == a.Kind {
				old = &prev[j]
			}
		}
		// Whoever holds an incoming URL writes the event's data: it must not
		// pick which service gets stopped or restarted.
		if b.Trigger.Kind == "webhook" && a.Kind == "service" && strings.Contains(a.Unit, "{{data.") {
			return nil, fieldError(loc+".unit", "With an incoming URL, the service can't come from the request's data: name it here.", a.Unit)
		}
		s, err := h.cleanAction(ctx, ws, loc, a, old, p)
		if err != nil {
			return nil, err
		}
		out[i] = s
	}
	return out, nil
}

func (h *automationHandler) cleanAction(ctx context.Context, ws uuid.UUID, loc string, a AutomationAction, old *storedAction, p *principal) (storedAction, error) {
	// Only the kind's fields are kept.
	keep := AutomationAction{ID: a.ID, Kind: a.Kind, Label: a.Label, ContinueOnError: a.ContinueOnError}
	out := storedAction{}
	switch a.Kind {
	case "notify":
		if len(a.ChannelIDs) == 0 {
			return out, fieldError(loc+".channel_ids", "Choose at least one channel.", nil)
		}
		seen := map[uuid.UUID]bool{}
		for i, raw := range a.ChannelIDs {
			id, err := uuid.Parse(raw)
			cl := fmt.Sprintf("%s.channel_ids[%d]", loc, i)
			if err != nil {
				return out, fieldError(cl, "Not a channel id.", raw)
			}
			c, err := h.q.GetNotificationChannel(ctx, id)
			if err != nil || c.WorkspaceID != ws {
				return out, fieldError(cl, "This channel isn't in the workspace.", raw)
			}
			if !seen[id] {
				seen[id] = true
				keep.ChannelIDs = append(keep.ChannelIDs, id.String())
			}
		}
		keep.Title, keep.Text = strings.TrimSpace(a.Title), strings.TrimSpace(a.Text)
	case "webhook":
		u, err := url.Parse(strings.TrimSpace(a.URL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return out, fieldError(loc+".url", "Enter an http:// or https:// address.", a.URL)
		}
		if u.User != nil {
			return out, fieldError(loc+".url", "Put credentials in a header, not in the address.", a.URL)
		}
		if templateHas(a.URL) {
			return out, fieldError(loc+".url", "The address can't use {{…}}: put values in the body or a header.", a.URL)
		}
		keep.URL = u.String()
		keep.Method = cmpOr(a.Method, http.MethodPost)
		keep.Body = a.Body
		// Keeping an admin's allow_internal is fine, pointing it elsewhere isn't.
		if a.AllowInternal && !p.Access.Admin && (old == nil || !old.AllowInternal || old.URL != keep.URL) {
			return out, fieldError(loc+".allow_internal", "Only a system admin can allow private addresses.", true)
		}
		keep.AllowInternal = a.AllowInternal
		// Saved header values only stay with the address they were for.
		saved := map[string]string{}
		if old != nil && old.URL == keep.URL {
			saved = h.headersOf(*old)
		}
		hs, err := cleanHookHeaders(loc+".headers", a.Headers, saved, []string{"Content-Length", "Host", "Transfer-Encoding", "Connection"})
		if err != nil {
			return out, err
		}
		if len(hs) > 0 {
			keep.Headers = map[string]string{}
			for k := range hs {
				keep.Headers[k] = ""
			}
			raw, _ := json.Marshal(hs)
			out.HeadersEnc = h.box.Seal(string(raw))
		}
	case "script":
		keep.On, keep.ServerIDs = a.On, nil
		if a.ScriptID != "" {
			id, err := uuid.Parse(a.ScriptID)
			if err != nil {
				return out, fieldError(loc+".script_id", "Not a script id.", a.ScriptID)
			}
			s, err := h.q.GetScript(ctx, id)
			if err != nil || s.WorkspaceID != ws {
				return out, fieldError(loc+".script_id", "This script isn't in the workspace.", a.ScriptID)
			}
			// Steps can't give parameter values: the defaults must do.
			if _, err := runEnv(scriptParams(s.Params), true, nil); err != nil {
				return out, fieldError(loc+".script_id", "This script has a required parameter without a default, which an automation can't fill.", a.ScriptID)
			}
			keep.ScriptID = id.String()
		} else {
			if strings.TrimSpace(a.Command) == "" {
				return out, fieldError(loc+".command", "Choose a script or write a command.", nil)
			}
			if strings.ContainsRune(a.Command, 0) {
				return out, fieldError(loc+".command", "The command contains a NUL byte.", nil)
			}
			keep.Command, keep.Interpreter, keep.AsRoot, keep.TimeoutSeconds = a.Command, cmpOr(a.Interpreter, "bash"), a.AsRoot, a.TimeoutSeconds
		}
		if err := h.cleanOn(ctx, ws, loc, a, &keep, p, auth.Engineer); err != nil {
			return out, err
		}
	case "service":
		keep.Unit = strings.TrimSpace(a.Unit)
		if keep.Unit == "" {
			return out, fieldError(loc+".unit", "Name the service.", nil)
		}
		if !templateHas(keep.Unit) && !unitRe.MatchString(keep.Unit) {
			return out, fieldError(loc+".unit", "Not a service name.", keep.Unit)
		}
		switch a.Action {
		case "start", "stop", "restart", "reload":
			keep.Action = a.Action
		default:
			return out, fieldError(loc+".action", "Choose start, stop, restart or reload.", a.Action)
		}
		if err := h.cleanOn(ctx, ws, loc, a, &keep, p, auth.Engineer); err != nil {
			return out, err
		}
	case "cronjob":
		id, err := uuid.Parse(a.ScheduleID)
		if err != nil {
			return out, fieldError(loc+".schedule_id", "Choose a cron job.", a.ScheduleID)
		}
		s, err := h.q.GetSchedule(ctx, id)
		if err != nil || s.WorkspaceID != ws {
			return out, fieldError(loc+".schedule_id", "This cron job isn't in the workspace.", a.ScheduleID)
		}
		keep.ScheduleID = id.String()
	case "check":
		if err := h.cleanOn(ctx, ws, loc, a, &keep, p, auth.Operator); err != nil {
			return out, err
		}
	case "wait":
		if a.Seconds < 1 || a.Seconds > 3600 {
			return out, fieldError(loc+".seconds", "Wait 1 to 3600 seconds.", a.Seconds)
		}
		keep.Seconds = a.Seconds
	default:
		return out, fieldError(loc+".kind", "Unknown kind of step.", a.Kind)
	}
	out.AutomationAction = keep
	return out, nil
}

// cleanOn checks where a script/service/check step acts: the person saving
// needs need on every chosen server.
func (h *automationHandler) cleanOn(ctx context.Context, ws uuid.UUID, loc string, a AutomationAction, keep *AutomationAction, p *principal, need auth.Level) error {
	keep.On = cmpOr(a.On, "event")
	if keep.On != "servers" {
		return nil
	}
	ids := []uuid.UUID{}
	for i, raw := range a.ServerIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			return fieldError(fmt.Sprintf("%s.server_ids[%d]", loc, i), "Not a server id.", raw)
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return fieldError(loc+".server_ids", "Choose at least one server.", nil)
	}
	rows, err := h.q.ListServerWorkspaces(ctx, ids)
	if err != nil {
		return internalError(err)
	}
	where := map[uuid.UUID]uuid.UUID{}
	for _, r := range rows {
		where[r.ID] = r.WorkspaceID
	}
	for i, id := range ids {
		w, ok := where[id]
		if !ok || w != ws {
			return fieldError(fmt.Sprintf("%s.server_ids[%d]", loc, i), "This server isn't in the workspace.", id.String())
		}
		if p.Access.ServerLevel(ws, id) < need {
			return fieldError(fmt.Sprintf("%s.server_ids[%d]", loc, i), "You need "+need.String()+" access to this server for this step.", id.String())
		}
		keep.ServerIDs = append(keep.ServerIDs, id.String())
	}
	return nil
}

func (h *automationHandler) headersOf(a storedAction) map[string]string {
	out := map[string]string{}
	if len(a.HeadersEnc) == 0 {
		return out
	}
	raw, err := h.box.Open(a.HeadersEnc)
	if err != nil || raw == "" {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

// eventFor builds the event a Run or Test goes with: given values over the
// sample of the trigger's first type (sample) or a bare manual event. The
// workspace, id and time are Morche's; an Origin is never taken.
func (h *automationHandler) eventFor(a sqlc.Automation, in *AutomationEventInput, sample bool) (events.Event, error) {
	t := decodeTrigger(a.Trigger)
	e := events.Event{
		Type: "manual", Severity: events.Info, Title: a.Name + " was run by hand",
		Subject: events.Subject{Kind: events.SubjectAutomation, ID: a.ID.String(), Name: a.Name},
	}
	typ := ""
	if in != nil {
		typ = strings.TrimSpace(in.Type)
	}
	if typ == "" && (sample || in != nil) && len(t.Events) > 0 {
		typ = t.Events[0]
	}
	if typ == "" && t.Kind == "webhook" && sample {
		typ = events.WebhookReceived
	}
	if typ != "" {
		ct, ok := events.Lookup(typ)
		if !ok {
			return e, fieldError("body.event.type", "Unknown event type.", typ)
		}
		e = ct.Sample
		e.Data = maps.Clone(e.Data)
		// The sample's server isn't a real one.
		e.ServerID = nil
		if typ == events.WebhookReceived {
			e.Subject = events.Subject{Kind: events.SubjectAutomation, ID: a.ID.String(), Name: a.Name}
		}
	}
	if in != nil {
		if in.Severity != "" {
			e.Severity = in.Severity
		}
		if in.Title != "" {
			e.Title = in.Title
		}
		if in.Text != "" {
			e.Text = in.Text
		}
		if in.URL != "" {
			e.URL = in.URL
		}
		if in.Subject != nil {
			e.Subject = *in.Subject
		}
		if in.Data != nil {
			e.Data = in.Data
		}
		if in.ServerID != "" {
			id, err := uuid.Parse(in.ServerID)
			if err != nil {
				return e, fieldError("body.event.server_id", "Not a server id.", in.ServerID)
			}
			e.ServerID = &id
		}
	}
	e.ID, e.WorkspaceID, e.At, e.Origin = uuid.New(), a.WorkspaceID, time.Now().UTC(), ""
	return e, nil
}

// mayAimAt checks that whoever gives an event with a server may act on that
// server at each step's level (else an Operator could point an Engineer's
// command anywhere).
func mayAimAt(ctx context.Context, q *sqlc.Queries, ws uuid.UUID, acts []storedAction, e events.Event) error {
	if e.ServerID != nil {
		sws, err := q.GetServerWorkspace(ctx, *e.ServerID)
		if err != nil || sws != ws {
			return fieldError("body.event.server_id", "This server isn't in the automation's workspace.", e.ServerID.String())
		}
	}
	acc := principalOf(ctx).Access
	for _, a := range acts {
		need := stepNeed(a.Kind)
		// The event's data could pick which unit a fixed server restarts.
		if a.Kind == "service" && a.On == "servers" && templateHas(a.Unit) {
			for _, raw := range a.ServerIDs {
				if id, err := uuid.Parse(raw); err == nil && acc.ServerLevel(ws, id) < auth.Engineer {
					return huma.Error403Forbidden("You need Engineer access to its servers to run this with an event: the event names the service.")
				}
			}
		}
		if need == auth.None || a.On == "servers" || e.ServerID == nil {
			continue
		}
		if acc.ServerLevel(ws, *e.ServerID) < need {
			return huma.Error403Forbidden("You need " + need.String() + " access to that server to run this with it.")
		}
	}
	return nil
}

// stepNeed is the level a step needs on the server it acts on.
func stepNeed(kind string) auth.Level {
	switch kind {
	case "script", "service":
		return auth.Engineer
	case "check":
		return auth.Operator
	}
	return auth.None
}

// ---- API ----

func registerAutomations(api huma.API, h *automationHandler) {
	tags := []string{"Automations"}

	huma.Register(api, huma.Operation{
		OperationID: "list-automations", Method: http.MethodGet, Path: "/workspaces/{id}/automations",
		Summary: "List a workspace's automations", Tags: tags,
	}, func(ctx context.Context, in *WorkspacePath) (*struct{ Body automationListBody }, error) {
		ws := uuid.MustParse(in.ID)
		rows, err := h.q.ListAutomations(ctx, ws)
		if err != nil {
			return nil, internalError(err)
		}
		recent := h.recent(ctx, ws)
		out := &struct{ Body automationListBody }{}
		out.Body.Items = make([]Automation, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = h.toAutomation(ctx, r, recent[r.ID])
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-automation", Method: http.MethodPost, Path: "/workspaces/{id}/automations",
		Summary: "Add an automation", Tags: tags, DefaultStatus: http.StatusCreated,
		Description: "It runs with the access of whoever saves it last.",
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body AutomationBody
	}) (*automationOutput, error) {
		p := principalOf(ctx)
		ws := uuid.MustParse(in.ID)
		b := in.Body
		acts, err := h.clean(ctx, ws, &b, nil, p)
		if err != nil {
			return nil, err
		}
		trig, _ := json.Marshal(b.Trigger)
		raw, _ := json.Marshal(acts)
		a, err := h.q.CreateAutomation(ctx, sqlc.CreateAutomationParams{
			WorkspaceID: ws, Name: b.Name, Description: b.Description, Enabled: b.Enabled == nil || *b.Enabled,
			Trigger: trig, Actions: raw, CooldownSeconds: *b.CooldownSeconds, MaxRunsPerHour: *b.MaxRunsPerHour,
			CreatedBy: p.ID(),
		})
		if err != nil {
			return nil, internalError(err)
		}
		return &automationOutput{h.one(ctx, a)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "preview-automation", Method: http.MethodPost, Path: "/workspaces/{id}/automations/preview",
		Summary: "Dry-run an unsaved automation", Tags: tags,
		Description: "Checks the body like a save would (422 with field errors) and says what each step would do for the event, as you. Nothing runs.",
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body AutomationPreviewBody
	}) (*struct{ Body AutomationDryRun }, error) {
		p := principalOf(ctx)
		ws := uuid.MustParse(in.ID)
		b := in.Body.Automation
		acts, err := h.clean(ctx, ws, &b, nil, p)
		if err != nil {
			return nil, err
		}
		trig, _ := json.Marshal(b.Trigger)
		a := sqlc.Automation{ID: uuid.Nil, WorkspaceID: ws, Name: b.Name, Trigger: trig, CooldownSeconds: *b.CooldownSeconds, MaxRunsPerHour: *b.MaxRunsPerHour}
		e, err := h.eventFor(a, in.Body.Event, true)
		if err != nil {
			return nil, err
		}
		out := &struct{ Body AutomationDryRun }{}
		out.Body = h.dryRun(ctx, a, acts, e, p.Access, "")
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-automation", Method: http.MethodGet, Path: "/automations/{id}",
		Summary: "An automation", Tags: tags,
	}, func(ctx context.Context, in *AutomationPath) (*automationOutput, error) {
		a, err := h.q.GetAutomation(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, notFoundOr(err, "automation not found")
		}
		return &automationOutput{h.one(ctx, a)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-automation", Method: http.MethodPut, Path: "/automations/{id}",
		Summary: "Change an automation", Tags: tags,
		Description: "Also turns it on or off (enabled). From now on it runs with your access; its problem is cleared.",
	}, func(ctx context.Context, in *struct {
		AutomationPath
		Body AutomationBody
	}) (*automationOutput, error) {
		p := principalOf(ctx)
		prev, err := h.q.GetAutomation(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, notFoundOr(err, "automation not found")
		}
		b := in.Body
		acts, err := h.clean(ctx, prev.WorkspaceID, &b, decodeActions(prev.Actions), p)
		if err != nil {
			return nil, err
		}
		trig, _ := json.Marshal(b.Trigger)
		raw, _ := json.Marshal(acts)
		a, err := h.q.UpdateAutomation(ctx, sqlc.UpdateAutomationParams{
			ID: prev.ID, Name: b.Name, Description: b.Description, Enabled: b.Enabled == nil || *b.Enabled,
			Trigger: trig, Actions: raw, CooldownSeconds: *b.CooldownSeconds, MaxRunsPerHour: *b.MaxRunsPerHour,
			UpdatedBy: p.ID(),
		})
		if err != nil {
			return nil, internalError(err)
		}
		return &automationOutput{h.one(ctx, a)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-automation", Method: http.MethodDelete, Path: "/automations/{id}",
		Summary: "Remove an automation", Tags: tags, DefaultStatus: http.StatusNoContent,
		Description: "Its runs go with it; a run going now is stopped.",
	}, func(ctx context.Context, in *AutomationPath) (*struct{}, error) {
		id := uuid.MustParse(in.ID)
		if rows, err := h.q.ListAutomationRuns(ctx, sqlc.ListAutomationRunsParams{
			WorkspaceID: mustWorkspaceOf(ctx, h.q, id), AutomationID: &id, Lim: 20,
		}); err == nil {
			for _, r := range rows {
				if r.JobID != nil && (r.Status == jobs.Queued || r.Status == jobs.Running) {
					_, _ = h.runner.Cancel(ctx, *r.JobID)
				}
			}
		}
		if err := h.q.DeleteAutomation(ctx, id); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "run-automation", Method: http.MethodPost, Path: "/automations/{id}/run",
		Summary: "Run an automation now", Tags: tags, DefaultStatus: http.StatusAccepted,
		Description: "With an event (optional) its steps can use; it runs even when turned off, past the cooldown. 409 while a run of it is going.",
	}, func(ctx context.Context, in *struct {
		AutomationPath
		Body AutomationRunBody
	}) (*struct{ Body AutomationRunStarted }, error) {
		a, err := h.q.GetAutomation(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, notFoundOr(err, "automation not found")
		}
		e, err := h.eventFor(a, in.Body.Event, false)
		if err != nil {
			return nil, err
		}
		if err := mayAimAt(ctx, h.q, a.WorkspaceID, decodeActions(a.Actions), e); err != nil {
			return nil, err
		}
		run, job, err := h.fire(ctx, a, e, "manual", principalOf(ctx))
		if err != nil {
			return nil, err
		}
		out := &struct{ Body AutomationRunStarted }{}
		out.Body = AutomationRunStarted{Run: toAutomationRun(run, a.Name, principalOf(ctx).Level), Job: job}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "test-automation", Method: http.MethodPost, Path: "/automations/{id}/test",
		Summary: "Test an automation", Tags: tags,
		Description: "With the sample event of its first event type (or the event given). dry_run: say what each step would do, as the person it runs as, without doing it or recording a run; else run it for real (a run with trigger_kind test).",
	}, func(ctx context.Context, in *struct {
		AutomationPath
		Body AutomationTestBody
	}) (*struct{ Body AutomationTestResult }, error) {
		a, err := h.q.GetAutomation(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, notFoundOr(err, "automation not found")
		}
		e, err := h.eventFor(a, in.Body.Event, true)
		if err != nil {
			return nil, err
		}
		acts := decodeActions(a.Actions)
		if err := mayAimAt(ctx, h.q, a.WorkspaceID, acts, e); err != nil {
			return nil, err
		}
		out := &struct{ Body AutomationTestResult }{}
		if in.Body.DryRun {
			problem := ""
			_, _, acc, err := runAsUser(ctx, h.q, h.authz, a.UpdatedBy, "automation")
			if err != nil {
				problem, acc = problemText(err), principalOf(ctx).Access
			}
			d := h.dryRun(ctx, a, acts, e, acc, problem)
			out.Body.DryRun = &d
			return out, nil
		}
		run, job, err := h.fire(ctx, a, e, "test", principalOf(ctx))
		if err != nil {
			return nil, err
		}
		r := toAutomationRun(run, a.Name, principalOf(ctx).Level)
		out.Body.Run, out.Body.Job = &r, job
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-automation-hook", Method: http.MethodPost, Path: "/automations/{id}/hook",
		Summary: "Make a new incoming URL", Tags: tags,
		Description: "For an automation started by its incoming URL (trigger webhook). The old URL stops at once. Answers the URL once.",
	}, func(ctx context.Context, in *AutomationPath) (*struct{ Body AutomationHook }, error) {
		token, _, err := newAPIToken()
		if err != nil {
			return nil, internalError(err)
		}
		token = "mah_" + strings.TrimPrefix(token, tokenPrefix)
		hash := hookHash(token)
		if _, err := h.q.SetAutomationHook(ctx, sqlc.SetAutomationHookParams{ID: uuid.MustParse(in.ID), Hash: &hash}); err != nil {
			return nil, notFoundOr(err, "automation not found")
		}
		out := &struct{ Body AutomationHook }{}
		out.Body = AutomationHook{Token: token, Path: automationHookPrefix + token}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-automation-hook", Method: http.MethodDelete, Path: "/automations/{id}/hook",
		Summary: "Remove the incoming URL", Tags: tags, DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *AutomationPath) (*struct{}, error) {
		if _, err := h.q.SetAutomationHook(ctx, sqlc.SetAutomationHookParams{ID: uuid.MustParse(in.ID)}); err != nil {
			return nil, notFoundOr(err, "automation not found")
		}
		return nil, nil
	})

	listRuns := func(ctx context.Context, ws uuid.UUID, automation *uuid.UUID, status string, limit, offset int32) (*struct{ Body automationRunListBody }, error) {
		params := sqlc.ListAutomationRunsParams{WorkspaceID: ws, AutomationID: automation, Lim: limit, Off: offset}
		count := sqlc.CountAutomationRunsParams{WorkspaceID: ws, AutomationID: automation}
		if status != "" {
			params.Status, count.Status = &status, &status
		}
		rows, err := h.q.ListAutomationRuns(ctx, params)
		if err != nil {
			return nil, internalError(err)
		}
		total, err := h.q.CountAutomationRuns(ctx, count)
		if err != nil {
			return nil, internalError(err)
		}
		level := principalOf(ctx).Level
		out := &struct{ Body automationRunListBody }{}
		out.Body.Total = total
		out.Body.Items = make([]AutomationRun, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = toAutomationRun(automationRunOf(r), r.AutomationName, level)
		}
		return out, nil
	}

	huma.Register(api, huma.Operation{
		OperationID: "list-automation-runs", Method: http.MethodGet, Path: "/automations/{id}/runs",
		Summary: "An automation's runs, newest first", Tags: tags,
	}, func(ctx context.Context, in *struct {
		AutomationPath
		Status string `query:"status" enum:"queued,running,succeeded,failed,skipped,canceled,"`
		Limit  int32  `query:"limit" minimum:"1" maximum:"200" default:"50"`
		Offset int32  `query:"offset" minimum:"0"`
	}) (*struct{ Body automationRunListBody }, error) {
		id := uuid.MustParse(in.ID)
		ws, err := h.q.GetAutomationWorkspace(ctx, id)
		if err != nil {
			return nil, notFoundOr(err, "automation not found")
		}
		return listRuns(ctx, ws, &id, in.Status, in.Limit, in.Offset)
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-workspace-automation-runs", Method: http.MethodGet, Path: "/workspaces/{id}/automation-runs",
		Summary: "Every automation's runs in a workspace, newest first", Tags: tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		AutomationID string `query:"automation_id" format:"uuid"`
		Status       string `query:"status" enum:"queued,running,succeeded,failed,skipped,canceled,"`
		Limit        int32  `query:"limit" minimum:"1" maximum:"200" default:"50"`
		Offset       int32  `query:"offset" minimum:"0"`
	}) (*struct{ Body automationRunListBody }, error) {
		var auto *uuid.UUID
		if in.AutomationID != "" {
			id := uuid.MustParse(in.AutomationID)
			auto = &id
		}
		return listRuns(ctx, uuid.MustParse(in.ID), auto, in.Status, in.Limit, in.Offset)
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-automation-run", Method: http.MethodGet, Path: "/automation-runs/{id}",
		Summary: "An automation run", Tags: tags,
		Description: "Steps are saved as they go: poll it while status is queued or running.",
	}, func(ctx context.Context, in *AutomationRunPath) (*automationRunOutput, error) {
		r, name, err := h.loadRun(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &automationRunOutput{toAutomationRun(r, name, principalOf(ctx).Level)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "cancel-automation-run", Method: http.MethodPost, Path: "/automation-runs/{id}/cancel",
		Summary: "Stop a run", Tags: tags,
		Description: "The step going now is stopped (a cron job it started too); later steps don't run. 409 when it has finished.",
	}, func(ctx context.Context, in *AutomationRunPath) (*automationRunOutput, error) {
		r, name, err := h.loadRun(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if (r.Status != "queued" && r.Status != "running") || r.JobID == nil {
			return nil, huma.Error409Conflict("The run has already finished.")
		}
		if _, err := h.runner.Cancel(ctx, *r.JobID); err != nil {
			return nil, jobProblem(err)
		}
		r, name, err = h.loadRun(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &automationRunOutput{toAutomationRun(r, name, principalOf(ctx).Level)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "automation-hook", Method: http.MethodPost, Path: "/automation-hooks/{token}",
		Summary:      "Start an automation (incoming URL)",
		Description:  "No sign-in; the token is the secret. A JSON body (≤64 KB) becomes event.data (a title or severity in it are used for the event). 30 calls a minute at most (429 past that).",
		Tags:         tags,
		MaxBodyBytes: automationHookBody,
	}, h.hook)
	if op := api.OpenAPI().Paths["/automation-hooks/{token}"]; op != nil && op.Post != nil && op.Post.RequestBody != nil {
		op.Post.RequestBody.Required = false
	}

	h.runner.Handle(automationRunKind, h.runJob)
}

func mustWorkspaceOf(ctx context.Context, q *sqlc.Queries, id uuid.UUID) uuid.UUID {
	ws, _ := q.GetAutomationWorkspace(ctx, id)
	return ws
}

func automationRunOf(r sqlc.ListAutomationRunsRow) sqlc.AutomationRun {
	return sqlc.AutomationRun{
		ID: r.ID, AutomationID: r.AutomationID, WorkspaceID: r.WorkspaceID, TriggerKind: r.TriggerKind,
		Event: r.Event, SubjectID: r.SubjectID, Status: r.Status, Steps: r.Steps, Reason: r.Reason,
		JobID: r.JobID, CreatedAt: r.CreatedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
		StartedBy: r.StartedBy, StartedByName: r.StartedByName,
	}
}

func (h *automationHandler) loadRun(ctx context.Context, raw string) (sqlc.AutomationRun, string, error) {
	r, err := h.q.GetAutomationRun(ctx, uuid.MustParse(raw))
	if err != nil {
		return r, "", notFoundOr(err, "run not found")
	}
	name := ""
	if a, err := h.q.GetAutomation(ctx, r.AutomationID); err == nil {
		name = a.Name
	}
	return r, name, nil
}

// ---- Incoming hook ----

type AutomationHookInput struct {
	Token   string `path:"token" maxLength:"100"`
	RawBody []byte `required:"false"`
}

type AutomationHookOutput struct {
	Status int
	Body   struct {
		OK      bool    `json:"ok"`
		RunID   *string `json:"run_id,omitempty"`
		Status  string  `json:"status,omitempty" doc:"queued, or skipped (see message)"`
		Message string  `json:"message"`
	}
}

func (h *automationHandler) hook(ctx context.Context, in *AutomationHookInput) (*AutomationHookOutput, error) {
	a, err := h.q.GetAutomationByHook(ctx, new(hookHash(in.Token)))
	if isNotFound(err) {
		return nil, huma.Error404NotFound("No automation has this address")
	}
	if err != nil {
		return nil, internalError(err)
	}
	if !h.limiter.allow(a.ID, time.Now()) {
		return nil, huma.NewError(http.StatusTooManyRequests, fmt.Sprintf("At most %d calls a minute", automationHookPerMin))
	}
	out := &AutomationHookOutput{Status: http.StatusOK}
	if !a.Enabled {
		out.Body.Message = "Ignored: the automation is turned off"
		return out, nil
	}
	if decodeTrigger(a.Trigger).Kind != "webhook" {
		out.Body.Message = "Ignored: the automation isn't started by its incoming URL"
		return out, nil
	}
	data := map[string]any{}
	if body := strings.TrimSpace(string(in.RawBody)); body != "" {
		var v any
		if err := json.Unmarshal(in.RawBody, &v); err != nil {
			data["body"] = strings.ToValidUTF8(body, "")
		} else if m, ok := v.(map[string]any); ok {
			data = m
		} else {
			data["body"] = v
		}
	}
	e := events.Event{
		ID: uuid.New(), Type: events.WebhookReceived, WorkspaceID: a.WorkspaceID, At: time.Now().UTC(),
		Severity: events.Info, Title: a.Name + " was called",
		Subject: events.Subject{Kind: events.SubjectAutomation, ID: a.ID.String(), Name: a.Name},
		Data:    data,
	}
	if t, ok := data["title"].(string); ok && strings.TrimSpace(t) != "" {
		e.Title = strings.ToValidUTF8(truncate(strings.TrimSpace(t), 500), "")
	}
	if t, ok := data["text"].(string); ok {
		e.Text = strings.ToValidUTF8(truncate(t, 4000), "")
	}
	if s, ok := data["severity"].(string); ok && slices.Contains(automationSeverities, s) {
		e.Severity = s
	}
	run, _, err := h.fire(context.WithoutCancel(ctx), a, e, "webhook", nil)
	if err != nil {
		return nil, err
	}
	out.Body.OK, out.Body.Status = true, run.Status
	if run.ID != uuid.Nil {
		id := run.ID.String()
		out.Body.RunID = &id
	}
	if run.Status == "skipped" {
		out.Body.Message = "Skipped: " + run.Reason
	} else {
		out.Status, out.Body.Message = http.StatusAccepted, "Running"
	}
	return out, nil
}
