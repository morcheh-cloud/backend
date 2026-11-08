package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/terminal"
)

const (
	scriptRunKind = "script-run"
	// Output kept per server; the rest is dropped (and the run says so).
	scriptOutputCap = 1 << 20
	// Servers worked on at once in one run.
	scriptParallel = 5
	// How long a stopped script gets to exit on SIGTERM before its session
	// is closed.
	scriptGrace  = 5 * time.Second
	maxScriptEnv = 30
)

// ScriptParam is a value asked for when the script runs, passed to it as an
// environment variable.
type ScriptParam struct {
	Name     string `json:"name" minLength:"1" maxLength:"64" pattern:"^[A-Za-z_][A-Za-z0-9_]*$" doc:"The environment variable" example:"VERSION"`
	Label    string `json:"label,omitempty" maxLength:"100" doc:"What the run form asks"`
	Default  string `json:"default,omitempty" maxLength:"4096"`
	Required bool   `json:"required,omitempty" doc:"A run must give it a value"`
}

// ScriptInput is what a script is made of.
type ScriptInput struct {
	Name           string        `json:"name" minLength:"1" maxLength:"100"`
	Description    string        `json:"description,omitempty" maxLength:"2000"`
	Interpreter    string        `json:"interpreter" enum:"sh,bash,python3"`
	Content        string        `json:"content" maxLength:"262144"`
	RunAs          string        `json:"run_as" enum:"user,root" doc:"user = the server's login user; root = through sudo when it isn't root"`
	TimeoutSeconds int32         `json:"timeout_seconds" minimum:"1" maximum:"86400"`
	Params         []ScriptParam `json:"params" maxItems:"30"`
}

// ScriptUpdate is a script's new version.
type ScriptUpdate struct {
	ScriptInput
	Revision *time.Time `json:"revision,omitempty" doc:"Its updated_at when you loaded it: 409 if someone saved in between"`
}

// ScriptLastRun is a script's newest run (on one server, in a server's list).
type ScriptLastRun struct {
	RunID    string    `json:"run_id" format:"uuid"`
	State    string    `json:"state"`
	At       time.Time `json:"at"`
	ExitCode *int32    `json:"exit_code,omitempty"`
}

// Script is a saved script.
type Script struct {
	ID             string         `json:"id" format:"uuid"`
	WorkspaceID    string         `json:"workspace_id" format:"uuid"`
	Name           string         `json:"name"`
	Description    string         `json:"description"`
	Interpreter    string         `json:"interpreter" enum:"sh,bash,python3"`
	Content        string         `json:"content"`
	RunAs          string         `json:"run_as" enum:"user,root"`
	TimeoutSeconds int32          `json:"timeout_seconds"`
	Params         []ScriptParam  `json:"params"`
	CreatedByName  string         `json:"created_by_name"`
	UpdatedByName  string         `json:"updated_by_name"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	LastRun        *ScriptLastRun `json:"last_run,omitempty"`
}

// ScriptRun is one run on one or more servers, without its output.
type ScriptRun struct {
	ID            string     `json:"id" format:"uuid"`
	WorkspaceID   string     `json:"workspace_id" format:"uuid"`
	ScriptID      *string    `json:"script_id,omitempty" format:"uuid" doc:"Unset for a command run without saving, or a script deleted since"`
	Name          string     `json:"name"`
	Interpreter   string     `json:"interpreter"`
	RunAs         string     `json:"run_as"`
	State         string     `json:"state" enum:"queued,running,succeeded,failed,canceled,interrupted"`
	Error         string     `json:"error,omitempty"`
	JobID         *string    `json:"job_id,omitempty" format:"uuid"`
	CreatedByName string     `json:"created_by_name"`
	CreatedAt     time.Time  `json:"created_at"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	Servers       int32      `json:"servers"`
	Succeeded     int32      `json:"succeeded"`
	Failed        int32      `json:"failed"`
	ServerNames   []string   `json:"server_names"`
}

// ScriptRunTarget is what a run did on one server.
type ScriptRunTarget struct {
	ServerID   *string    `json:"server_id,omitempty" format:"uuid" doc:"Unset once the server is deleted"`
	ServerName string     `json:"server_name"`
	Position   int32      `json:"position"`
	State      string     `json:"state" enum:"queued,running,succeeded,failed,canceled,interrupted"`
	ExitCode   *int32     `json:"exit_code,omitempty"`
	TimedOut   bool       `json:"timed_out"`
	Error      string     `json:"error,omitempty" doc:"Why it couldn't run at all"`
	Output     string     `json:"output" doc:"stdout and stderr together"`
	Truncated  bool       `json:"truncated" doc:"Output past 1 MiB was dropped"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// ScriptRunDetail is a run with what it ran and its output on each server.
type ScriptRunDetail struct {
	ScriptRun
	Content        string            `json:"content"`
	TimeoutSeconds int32             `json:"timeout_seconds"`
	Env            map[string]string `json:"env" doc:"The values it ran with"`
	Targets        []ScriptRunTarget `json:"targets"`
}

// ServerScriptRun is a run as seen from one server.
type ServerScriptRun struct {
	RunID         string     `json:"run_id" format:"uuid"`
	ScriptID      *string    `json:"script_id,omitempty" format:"uuid"`
	Name          string     `json:"name"`
	Interpreter   string     `json:"interpreter"`
	RunAs         string     `json:"run_as"`
	RunState      string     `json:"run_state"`
	CreatedByName string     `json:"created_by_name"`
	CreatedAt     time.Time  `json:"created_at"`
	State         string     `json:"state" doc:"How it went on this server"`
	ExitCode      *int32     `json:"exit_code,omitempty"`
	TimedOut      bool       `json:"timed_out"`
	Error         string     `json:"error,omitempty"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	Servers       int32      `json:"servers" doc:"Servers in the whole run"`
}

type startScriptRunBody struct {
	ServerIDs      []string          `json:"server_ids" minItems:"1" maxItems:"200" format:"uuid"`
	ScriptID       *string           `json:"script_id,omitempty" format:"uuid" doc:"A saved script; the fields below are then ignored"`
	Name           string            `json:"name,omitempty" maxLength:"100" doc:"For a command run without saving"`
	Interpreter    string            `json:"interpreter,omitempty" enum:"sh,bash,python3"`
	Content        string            `json:"content,omitempty" maxLength:"262144"`
	RunAs          string            `json:"run_as,omitempty" enum:"user,root"`
	TimeoutSeconds int32             `json:"timeout_seconds,omitempty" minimum:"0" maximum:"86400"`
	Env            map[string]string `json:"env,omitempty" doc:"Values for the script's parameters (or any variables, without a saved script). Kept with the run and shown to whoever can read it"`
}

type scriptHandler struct {
	q       *sqlc.Queries
	servers *serverHandler
	authz   *authz
	runner  *jobs.Runner
}

func newScriptHandler(servers *serverHandler, a *authz) *scriptHandler {
	h := &scriptHandler{q: servers.q, servers: servers, authz: a, runner: servers.jobs}
	ctx := context.Background()
	if err := h.q.InterruptScriptRuns(ctx); err != nil {
		slog.Warn("end script runs left running", "error", err)
	}
	go func() {
		for {
			if err := h.q.DeleteOldScriptRuns(ctx); err != nil {
				slog.Warn("delete old script runs", "error", err)
			}
			time.Sleep(6 * time.Hour)
		}
	}()
	return h
}

// ---- Validation ----

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Variables that would change how the shell or the interpreter itself
// behaves, rather than reach the script.
func reservedEnv(name string) bool {
	u := strings.ToUpper(name)
	switch u {
	case "PATH", "IFS", "ENV", "BASH_ENV", "SHELLOPTS", "BASHOPTS", "PS4", "HOME", "SHELL", "USER", "LOGNAME", "SUDO_ASKPASS":
		return true
	}
	return strings.HasPrefix(u, "LD_") || strings.HasPrefix(u, "BASH_FUNC") || strings.HasPrefix(u, "PYTHON")
}

func checkEnvName(location, name string) error {
	switch {
	case !envNameRe.MatchString(name) || len(name) > 64:
		return fieldError(location, "A variable name is letters, digits and _, not starting with a digit.", name)
	case reservedEnv(name):
		return fieldError(location, name+" is used by the shell itself; pick another name.", name)
	}
	return nil
}

func checkScript(in ScriptInput) error {
	if strings.TrimSpace(in.Name) == "" {
		return fieldError("body.name", "Give it a name.", in.Name)
	}
	if strings.TrimSpace(in.Content) == "" {
		return fieldError("body.content", "The script is empty.", nil)
	}
	if strings.ContainsRune(in.Content, 0) {
		return fieldError("body.content", "The script contains a NUL byte.", nil)
	}
	seen := map[string]bool{}
	for i, p := range in.Params {
		loc := fmt.Sprintf("body.params[%d].name", i)
		if err := checkEnvName(loc, p.Name); err != nil {
			return err
		}
		if seen[p.Name] {
			return fieldError(loc, "Two parameters are called "+p.Name+".", p.Name)
		}
		seen[p.Name] = true
		if strings.ContainsRune(p.Default, 0) {
			return fieldError(fmt.Sprintf("body.params[%d].default", i), "A value can't contain a NUL byte.", nil)
		}
	}
	return nil
}

func normalizeScript(in ScriptInput) ScriptInput {
	in.Name = strings.TrimSpace(in.Name)
	in.Description = strings.TrimSpace(in.Description)
	if in.Params == nil {
		in.Params = []ScriptParam{}
	}
	for i := range in.Params {
		in.Params[i].Label = strings.TrimSpace(in.Params[i].Label)
	}
	return in
}

// runEnv is the environment a run gets: a saved script's parameters (its
// defaults filled in, required ones checked), or any variables for an
// unsaved one.
func runEnv(params []ScriptParam, saved bool, given map[string]string) (map[string]string, error) {
	if len(given) > maxScriptEnv {
		return nil, fieldError("body.env", fmt.Sprintf("At most %d variables.", maxScriptEnv), nil)
	}
	env := map[string]string{}
	for name, v := range given {
		loc := "body.env." + name
		if saved && !slices.ContainsFunc(params, func(p ScriptParam) bool { return p.Name == name }) {
			return nil, fieldError(loc, "The script has no parameter called "+name+".", name)
		}
		if err := checkEnvName(loc, name); err != nil {
			return nil, err
		}
		if len(v) > 4096 || strings.ContainsRune(v, 0) {
			return nil, fieldError(loc, "A value is at most 4096 characters, with no NUL byte.", nil)
		}
		env[name] = v
	}
	for _, p := range params {
		if _, ok := env[p.Name]; !ok {
			env[p.Name] = p.Default
		}
		if p.Required && strings.TrimSpace(env[p.Name]) == "" {
			return nil, fieldError("body.env."+p.Name, cmpOr(p.Label, p.Name)+" needs a value.", nil)
		}
	}
	return env, nil
}

// ---- Shapes ----

func scriptParams(raw []byte) []ScriptParam {
	out := []ScriptParam{}
	decodeInto(raw, &out)
	return out
}

func toScript(s sqlc.Script) Script {
	return Script{
		ID: s.ID.String(), WorkspaceID: s.WorkspaceID.String(), Name: s.Name, Description: s.Description,
		Interpreter: s.Interpreter, Content: s.Content, RunAs: s.RunAs, TimeoutSeconds: s.TimeoutSeconds,
		Params: scriptParams(s.Params), CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
}

func toScriptRow(r sqlc.ListScriptsRow) Script {
	s := toScript(sqlc.Script{
		ID: r.ID, WorkspaceID: r.WorkspaceID, Name: r.Name, Description: r.Description, Interpreter: r.Interpreter,
		Content: r.Content, RunAs: r.RunAs, TimeoutSeconds: r.TimeoutSeconds, Params: r.Params,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})
	s.CreatedByName, s.UpdatedByName = r.CreatedByName, r.UpdatedByName
	if r.LastRunID != nil && r.LastRunState != nil && r.LastRunAt != nil {
		s.LastRun = &ScriptLastRun{RunID: r.LastRunID.String(), State: *r.LastRunState, At: *r.LastRunAt}
	}
	return s
}

func toScriptRunRow(r sqlc.ListScriptRunsRow) ScriptRun {
	return ScriptRun{
		ID: r.ID.String(), WorkspaceID: r.WorkspaceID.String(), ScriptID: optionalIDString(r.ScriptID), Name: r.Name,
		Interpreter: r.Interpreter, RunAs: r.RunAs, State: r.State, Error: r.Error, JobID: optionalIDString(r.JobID),
		CreatedByName: r.CreatedByName, CreatedAt: r.CreatedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
		Servers: r.Servers, Succeeded: r.Succeeded, Failed: r.Failed, ServerNames: r.ServerNames,
	}
}

func toScriptRunDetail(r sqlc.ScriptRun, targets []sqlc.ScriptRunTarget) ScriptRunDetail {
	d := ScriptRunDetail{
		ScriptRun: ScriptRun{
			ID: r.ID.String(), WorkspaceID: r.WorkspaceID.String(), ScriptID: optionalIDString(r.ScriptID), Name: r.Name,
			Interpreter: r.Interpreter, RunAs: r.RunAs, State: r.State, Error: r.Error, JobID: optionalIDString(r.JobID),
			CreatedByName: r.CreatedByName, CreatedAt: r.CreatedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
			Servers: int32(len(targets)), ServerNames: make([]string, len(targets)),
		},
		Content: r.Content, TimeoutSeconds: r.TimeoutSeconds, Env: map[string]string{},
		Targets: make([]ScriptRunTarget, len(targets)),
	}
	decodeInto(r.Env, &d.Env)
	for i, t := range targets {
		d.ServerNames[i] = t.ServerName
		switch t.State {
		case jobs.Succeeded:
			d.Succeeded++
		case jobs.Failed, jobs.Interrupted:
			d.Failed++
		}
		d.Targets[i] = ScriptRunTarget{
			ServerID: optionalIDString(t.ServerID), ServerName: t.ServerName, Position: t.Position, State: t.State,
			ExitCode: t.ExitCode, TimedOut: t.TimedOut, Error: t.Error, Output: t.Output, Truncated: t.Truncated,
			StartedAt: t.StartedAt, FinishedAt: t.FinishedAt,
		}
	}
	return d
}

// ---- Access to a run ----

// runLevel is the caller's level on a run: the lowest they have on its
// servers (so a run is visible to whoever may see every server it touched),
// or on its workspace once they are all gone.
func runLevel(acc *auth.Access, r sqlc.ScriptRun, targets []sqlc.ScriptRunTarget) auth.Level {
	level := auth.Owner + 1
	for _, t := range targets {
		if t.ServerID != nil {
			level = min(level, acc.ServerLevel(r.WorkspaceID, *t.ServerID))
		}
	}
	if level > auth.Owner {
		return acc.WorkspaceLevel(r.WorkspaceID)
	}
	return max(level, acc.WorkspaceLevel(r.WorkspaceID))
}

// loadRun reads a run the caller may act on with need, ended first when its
// job is gone.
func (h *scriptHandler) loadRun(ctx context.Context, rawID string, need auth.Level) (sqlc.ScriptRun, []sqlc.ScriptRunTarget, error) {
	id, err := uuid.Parse(rawID)
	if err != nil {
		return sqlc.ScriptRun{}, nil, huma.Error404NotFound("run not found")
	}
	r, err := h.q.GetScriptRun(ctx, id)
	if isNotFound(err) {
		return r, nil, huma.Error404NotFound("run not found")
	}
	if err != nil {
		return r, nil, internalError(err)
	}
	targets, err := h.q.ListScriptRunTargets(ctx, id)
	if err != nil {
		return r, nil, internalError(err)
	}
	switch level := runLevel(principalOf(ctx).Access, r, targets); {
	case level == auth.None:
		return r, nil, huma.Error404NotFound("run not found")
	case level < need:
		return r, nil, forbidden(need)
	}
	if h.syncRun(ctx, r.ID, r.State, r.JobID, r.CreatedAt) {
		if r, err = h.q.GetScriptRun(ctx, id); err != nil {
			return r, nil, internalError(err)
		}
		if targets, err = h.q.ListScriptRunTargets(ctx, id); err != nil {
			return r, nil, internalError(err)
		}
	}
	return r, targets, nil
}

// syncRun ends a stored run whose job ended without it: canceled while
// queued, or Morcheh restarted. It says whether it changed anything.
func (h *scriptHandler) syncRun(ctx context.Context, id uuid.UUID, state string, job *uuid.UUID, created time.Time) bool {
	if !jobs.Active(state) {
		return false
	}
	end := func(state, msg string) bool {
		if err := h.q.EndScriptRun(ctx, sqlc.EndScriptRunParams{ID: id, State: state, Error: msg}); err != nil {
			slog.Warn("end a script run", "run", id, "error", err)
			return false
		}
		return true
	}
	const lost = "Morcheh restarted before it finished."
	if job == nil {
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

// ---- Routes ----

func registerScripts(api huma.API, h *scriptHandler) {
	h.runner.Handle(scriptRunKind, h.runJob)
	tags := []string{"Scripts"}

	type scriptList struct {
		Body struct {
			Items []Script `json:"items"`
		}
	}
	type scriptOutput struct{ Body Script }
	type scriptPath struct {
		ID string `path:"id" format:"uuid"`
	}

	huma.Register(api, huma.Operation{
		OperationID: "list-scripts",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/scripts",
		Summary:     "List a workspace's saved scripts",
		Description: "By name, each with its newest run.",
		Tags:        tags,
	}, func(ctx context.Context, in *WorkspacePath) (*scriptList, error) {
		rows, err := h.q.ListScripts(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		out := &scriptList{}
		out.Body.Items = make([]Script, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = toScriptRow(r)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-server-scripts",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/scripts",
		Summary:     "Scripts that can run on a server",
		Description: "Its workspace's saved scripts, each with its newest run on this server.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*scriptList, error) {
		s, err := h.servers.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		rows, err := h.q.ListScripts(ctx, s.WorkspaceID)
		if err != nil {
			return nil, internalError(err)
		}
		last, err := h.q.LastScriptRuns(ctx, &s.ID)
		if err != nil {
			return nil, internalError(err)
		}
		here := map[uuid.UUID]sqlc.LastScriptRunsRow{}
		for _, l := range last {
			if l.ScriptID != nil {
				here[*l.ScriptID] = l
			}
		}
		out := &scriptList{}
		out.Body.Items = make([]Script, len(rows))
		for i, r := range rows {
			sc := toScriptRow(r)
			sc.LastRun = nil
			if l, ok := here[r.ID]; ok {
				sc.LastRun = &ScriptLastRun{RunID: l.RunID.String(), State: l.State, At: l.CreatedAt, ExitCode: l.ExitCode}
			}
			out.Body.Items[i] = sc
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-script",
		Method:        http.MethodPost,
		Path:          "/workspaces/{id}/scripts",
		Summary:       "Save a new script",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body ScriptInput
	}) (*scriptOutput, error) {
		b := normalizeScript(in.Body)
		if err := checkScript(b); err != nil {
			return nil, err
		}
		params, _ := json.Marshal(b.Params)
		p := principalOf(ctx)
		s, err := h.q.CreateScript(ctx, sqlc.CreateScriptParams{
			WorkspaceID: uuid.MustParse(in.ID), Name: b.Name, Description: b.Description, Interpreter: b.Interpreter,
			Content: b.Content, RunAs: b.RunAs, TimeoutSeconds: b.TimeoutSeconds, Params: params, CreatedBy: p.ID(),
		})
		if isUniqueViolation(err) {
			return nil, fieldError("body.name", "A script with this name already exists.", b.Name)
		}
		if err != nil {
			return nil, internalError(err)
		}
		out := toScript(s)
		out.CreatedByName = cmpOr(p.User.FullName, p.User.Username)
		out.UpdatedByName = out.CreatedByName
		return &scriptOutput{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-script",
		Method:      http.MethodGet,
		Path:        "/scripts/{id}",
		Summary:     "Get a saved script",
		Tags:        tags,
	}, func(ctx context.Context, in *scriptPath) (*scriptOutput, error) {
		id := uuid.MustParse(in.ID)
		s, err := h.q.GetScript(ctx, id)
		if isNotFound(err) {
			return nil, huma.Error404NotFound("script not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		rows, err := h.q.ListScripts(ctx, s.WorkspaceID)
		if err != nil {
			return nil, internalError(err)
		}
		for _, r := range rows {
			if r.ID == id {
				return &scriptOutput{toScriptRow(r)}, nil
			}
		}
		return &scriptOutput{toScript(s)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-script",
		Method:      http.MethodPatch,
		Path:        "/scripts/{id}",
		Summary:     "Save changes to a script",
		Description: "With revision (its updated_at when you loaded it), answers 409 when someone else saved in between. Past runs keep the text they ran.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		scriptPath
		Body ScriptUpdate
	}) (*scriptOutput, error) {
		id := uuid.MustParse(in.ID)
		old, err := h.q.GetScript(ctx, id)
		if isNotFound(err) {
			return nil, huma.Error404NotFound("script not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if in.Body.Revision != nil && !in.Body.Revision.Equal(old.UpdatedAt) {
			return nil, huma.Error409Conflict("Someone else saved this script after you opened it.")
		}
		b := normalizeScript(in.Body.ScriptInput)
		if err := checkScript(b); err != nil {
			return nil, err
		}
		params, _ := json.Marshal(b.Params)
		p := principalOf(ctx)
		s, err := h.q.UpdateScript(ctx, sqlc.UpdateScriptParams{
			ID: id, Name: b.Name, Description: b.Description, Interpreter: b.Interpreter, Content: b.Content,
			RunAs: b.RunAs, TimeoutSeconds: b.TimeoutSeconds, Params: params, UpdatedBy: p.ID(),
		})
		if isUniqueViolation(err) {
			return nil, fieldError("body.name", "A script with this name already exists.", b.Name)
		}
		if err != nil {
			return nil, internalError(err)
		}
		out := toScript(s)
		out.UpdatedByName = cmpOr(p.User.FullName, p.User.Username)
		return &scriptOutput{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-script",
		Method:        http.MethodDelete,
		Path:          "/scripts/{id}",
		Summary:       "Delete a saved script",
		Description:   "Its past runs stay, with the text they ran.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *scriptPath) (*struct{}, error) {
		if err := h.q.DeleteScript(ctx, uuid.MustParse(in.ID)); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})

	// ---- Runs ----

	type runOutput struct{ Body ScriptRunDetail }

	huma.Register(api, huma.Operation{
		OperationID:   "start-script-run",
		Method:        http.MethodPost,
		Path:          "/script-runs",
		Summary:       "Run a script on servers",
		Description:   "A saved script (script_id) or one written for this run. Queues a background job. You need Engineer on every server, as for its terminal. All servers must be in one workspace.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct{ Body startScriptRunBody }) (*struct {
		Body struct {
			Run ScriptRunDetail `json:"run"`
			Job Job             `json:"job"`
		}
	}, error) {
		plan, err := h.plan(ctx, in.Body, uuid.Nil)
		if err != nil {
			return nil, err
		}
		run, err := h.create(ctx, plan)
		if err != nil {
			return nil, err
		}
		bg := context.WithoutCancel(ctx)
		src, servers, ids := plan.src, plan.servers, plan.ids
		title := fmt.Sprintf("Run %s on %s", src.Name, countServers(len(servers)))
		if len(servers) == 1 {
			title = fmt.Sprintf("Run %s on %s", src.Name, servers[0].Name)
		}
		j, err := submit(ctx, h.runner, jobs.Spec{
			Kind: scriptRunKind, Title: title,
			Params: scriptRunParams{RunID: run.ID}, Refs: ids,
			Target: JobPlace{RunID: run.ID.String(), Name: src.Name},
		})
		if err != nil {
			_ = h.q.EndScriptRun(bg, sqlc.EndScriptRunParams{ID: run.ID, State: jobs.Failed, Error: "It couldn't be queued."})
			return nil, err
		}
		jobID := uuid.MustParse(j.Body.ID)
		if err := h.q.SetScriptRunJob(ctx, sqlc.SetScriptRunJobParams{ID: run.ID, JobID: &jobID}); err != nil {
			return nil, internalError(err)
		}
		run.JobID = &jobID
		targets, err := h.q.ListScriptRunTargets(ctx, run.ID)
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Run ScriptRunDetail `json:"run"`
				Job Job             `json:"job"`
			}
		}{}
		out.Body.Run, out.Body.Job = toScriptRunDetail(run, targets), j.Body
		return out, nil
	})

	type scriptRunList struct {
		Body struct {
			Items []ScriptRun `json:"items"`
			Total int64       `json:"total"`
		}
	}

	huma.Register(api, huma.Operation{
		OperationID: "list-script-runs",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/script-runs",
		Summary:     "List a workspace's script runs, newest first",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		ScriptID string `query:"script_id" format:"uuid"`
		State    string `query:"state" enum:"queued,running,succeeded,failed,canceled,interrupted"`
		Q        string `query:"q" doc:"In the run's name or who ran it"`
		Limit    int32  `query:"limit" minimum:"1" maximum:"200" default:"50"`
		Offset   int32  `query:"offset" minimum:"0"`
	}) (*scriptRunList, error) {
		params := sqlc.ListScriptRunsParams{WorkspaceID: uuid.MustParse(in.ID), Lim: in.Limit, Off: in.Offset}
		count := sqlc.CountScriptRunsParams{WorkspaceID: params.WorkspaceID}
		if in.ScriptID != "" {
			id := uuid.MustParse(in.ScriptID)
			params.ScriptID, count.ScriptID = &id, &id
		}
		if in.State != "" {
			params.State, count.State = &in.State, &in.State
		}
		if q := strings.TrimSpace(in.Q); q != "" {
			params.Q, count.Q = &q, &q
		}
		rows, err := h.q.ListScriptRuns(ctx, params)
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
			if rows, err = h.q.ListScriptRuns(ctx, params); err != nil {
				return nil, internalError(err)
			}
		}
		total, err := h.q.CountScriptRuns(ctx, count)
		if err != nil {
			return nil, internalError(err)
		}
		out := &scriptRunList{}
		out.Body.Total = total
		out.Body.Items = make([]ScriptRun, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = toScriptRunRow(r)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-server-script-runs",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/script-runs",
		Summary:     "Script runs on a server, newest first",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		ScriptID string `query:"script_id" format:"uuid"`
		Limit    int32  `query:"limit" minimum:"1" maximum:"200" default:"50"`
		Offset   int32  `query:"offset" minimum:"0"`
	}) (*struct {
		Body struct {
			Items []ServerScriptRun `json:"items"`
			Total int64             `json:"total"`
		}
	}, error) {
		sid := uuid.MustParse(in.ID)
		params := sqlc.ListServerScriptRunsParams{ServerID: &sid, Lim: in.Limit, Off: in.Offset}
		count := sqlc.CountServerScriptRunsParams{ServerID: &sid}
		if in.ScriptID != "" {
			id := uuid.MustParse(in.ScriptID)
			params.ScriptID, count.ScriptID = &id, &id
		}
		rows, err := h.q.ListServerScriptRuns(ctx, params)
		if err != nil {
			return nil, internalError(err)
		}
		changed := false
		for _, r := range rows {
			if h.syncRun(ctx, r.ID, r.RunState, r.JobID, r.CreatedAt) {
				changed = true
			}
		}
		if changed {
			if rows, err = h.q.ListServerScriptRuns(ctx, params); err != nil {
				return nil, internalError(err)
			}
		}
		total, err := h.q.CountServerScriptRuns(ctx, count)
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []ServerScriptRun `json:"items"`
				Total int64             `json:"total"`
			}
		}{}
		out.Body.Total = total
		out.Body.Items = make([]ServerScriptRun, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = ServerScriptRun{
				RunID: r.ID.String(), ScriptID: optionalIDString(r.ScriptID), Name: r.Name, Interpreter: r.Interpreter,
				RunAs: r.RunAs, RunState: r.RunState, CreatedByName: r.CreatedByName, CreatedAt: r.CreatedAt,
				State: r.State, ExitCode: r.ExitCode, TimedOut: r.TimedOut, Error: r.Error,
				StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, Servers: r.Servers,
			}
		}
		return out, nil
	})

	type runPath struct {
		ID string `path:"id" format:"uuid"`
	}

	huma.Register(api, huma.Operation{
		OperationID: "get-script-run",
		Method:      http.MethodGet,
		Path:        "/script-runs/{id}",
		Summary:     "Get a script run with its output on each server",
		Description: "Needs Operator on every server it touched. While it runs, the output is saved about every second: poll this.",
		Tags:        tags,
	}, func(ctx context.Context, in *runPath) (*runOutput, error) {
		r, targets, err := h.loadRun(ctx, in.ID, auth.Operator)
		if err != nil {
			return nil, err
		}
		return &runOutput{toScriptRunDetail(r, targets)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "cancel-script-run",
		Method:      http.MethodPost,
		Path:        "/script-runs/{id}/cancel",
		Summary:     "Stop a script run",
		Description: "Servers not started yet are skipped; a running script gets SIGTERM, then its session is closed. Needs Engineer on every server it touched.",
		Tags:        tags,
	}, func(ctx context.Context, in *runPath) (*runOutput, error) {
		r, _, err := h.loadRun(ctx, in.ID, auth.Engineer)
		if err != nil {
			return nil, err
		}
		if !jobs.Active(r.State) || r.JobID == nil {
			return nil, huma.Error409Conflict("The run has already finished.")
		}
		if _, err := h.runner.Cancel(ctx, *r.JobID); err != nil {
			return nil, jobProblem(err)
		}
		r, targets, err := h.loadRun(ctx, in.ID, auth.Engineer)
		if err != nil {
			return nil, err
		}
		return &runOutput{toScriptRunDetail(r, targets)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-script-run",
		Method:        http.MethodDelete,
		Path:          "/script-runs/{id}",
		Summary:       "Delete a finished script run",
		Description:   "Needs Engineer on every server it touched.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *runPath) (*struct{}, error) {
		r, _, err := h.loadRun(ctx, in.ID, auth.Engineer)
		if err != nil {
			return nil, err
		}
		n, err := h.q.DeleteScriptRun(ctx, r.ID)
		if err != nil {
			return nil, internalError(err)
		}
		if n == 0 {
			return nil, huma.Error409Conflict("Stop the run before deleting it.")
		}
		return nil, nil
	})
}

// scriptRunPlan is a checked request to run a script.
type scriptRunPlan struct {
	ws       uuid.UUID
	ids      []uuid.UUID
	servers  []sqlc.Server
	scriptID *uuid.UUID
	src      ScriptInput
	env      map[string]string
}

// plan checks a run request as the person in ctx: Engineer on every server,
// all in one workspace (ws, when not Nil). Cron jobs check theirs with it too.
func (h *scriptHandler) plan(ctx context.Context, b startScriptRunBody, ws uuid.UUID) (scriptRunPlan, error) {
	var plan scriptRunPlan
	ids := make([]uuid.UUID, 0, len(b.ServerIDs))
	for _, raw := range b.ServerIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			return plan, fieldError("body.server_ids", "Not a server id.", raw)
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return plan, fieldError("body.server_ids", "Choose at least one server.", nil)
	}
	where, err := h.authz.requireServers(ctx, ids, auth.Engineer)
	if err != nil {
		return plan, err
	}
	servers := make([]sqlc.Server, 0, len(ids))
	for _, id := range ids {
		w, ok := where[id]
		if !ok {
			return plan, fieldError("body.server_ids", "A chosen server doesn't exist.", id.String())
		}
		if ws == uuid.Nil {
			ws = w
		} else if w != ws {
			return plan, fieldError("body.server_ids", "The servers must all be in one workspace.", id.String())
		}
		s, err := h.servers.get(ctx, id.String())
		if err != nil {
			return plan, err
		}
		servers = append(servers, s)
	}
	sort.SliceStable(servers, func(i, j int) bool { return strings.ToLower(servers[i].Name) < strings.ToLower(servers[j].Name) })

	var scriptID *uuid.UUID
	var src ScriptInput
	if b.ScriptID != nil && *b.ScriptID != "" {
		id, err := uuid.Parse(*b.ScriptID)
		if err != nil {
			return plan, fieldError("body.script_id", "Not a script id.", *b.ScriptID)
		}
		s, err := h.q.GetScript(ctx, id)
		if isNotFound(err) || (err == nil && s.WorkspaceID != ws) {
			return plan, fieldError("body.script_id", "This script isn't in the servers' workspace.", *b.ScriptID)
		}
		if err != nil {
			return plan, internalError(err)
		}
		scriptID = &s.ID
		src = ScriptInput{Name: s.Name, Interpreter: s.Interpreter, Content: s.Content, RunAs: s.RunAs, TimeoutSeconds: s.TimeoutSeconds, Params: scriptParams(s.Params)}
	} else {
		src = ScriptInput{
			Name: cmpOr(strings.TrimSpace(b.Name), "Command"), Interpreter: cmpOr(b.Interpreter, "bash"),
			Content: b.Content, RunAs: cmpOr(b.RunAs, "user"), TimeoutSeconds: b.TimeoutSeconds,
		}
		if src.TimeoutSeconds == 0 {
			src.TimeoutSeconds = 600
		}
		if strings.TrimSpace(src.Content) == "" {
			return plan, fieldError("body.content", "Write something to run.", nil)
		}
		if strings.ContainsRune(src.Content, 0) {
			return plan, fieldError("body.content", "The script contains a NUL byte.", nil)
		}
	}
	env, err := runEnv(src.Params, scriptID != nil, b.Env)
	if err != nil {
		return plan, err
	}
	return scriptRunPlan{ws: ws, ids: ids, servers: servers, scriptID: scriptID, src: src, env: env}, nil
}

// create stores a planned run with its servers, not yet started.
func (h *scriptHandler) create(ctx context.Context, plan scriptRunPlan) (sqlc.ScriptRun, error) {
	p := principalOf(ctx)
	src := plan.src
	envJSON, _ := json.Marshal(plan.env)
	run, err := h.q.CreateScriptRun(ctx, sqlc.CreateScriptRunParams{
		WorkspaceID: plan.ws, ScriptID: plan.scriptID, Name: src.Name, Interpreter: src.Interpreter, Content: src.Content,
		RunAs: src.RunAs, TimeoutSeconds: src.TimeoutSeconds, Env: envJSON, CreatedBy: p.ID(),
		CreatedByName: cmpOr(p.User.FullName, p.User.Username),
	})
	if err != nil {
		return run, internalError(err)
	}
	bg := context.WithoutCancel(ctx)
	for i, s := range plan.servers {
		if err := h.q.CreateScriptRunTarget(ctx, sqlc.CreateScriptRunTargetParams{
			RunID: run.ID, ServerID: &s.ID, ServerName: s.Name, Position: int32(i),
		}); err != nil {
			_ = h.q.EndScriptRun(bg, sqlc.EndScriptRunParams{ID: run.ID, State: jobs.Failed, Error: "It couldn't be saved."})
			return run, internalError(err)
		}
	}
	return run, nil
}

// ---- Running ----

type scriptRunParams struct {
	RunID uuid.UUID `json:"run_id"`
}

func (h *scriptHandler) runJob(ctx context.Context, t *jobs.Task) (any, error) {
	var params scriptRunParams
	if err := t.Decode(&params); err != nil {
		return nil, err
	}
	return h.execute(ctx, t, params.RunID)
}

// execute runs a stored run in the job t (its own, or a cron job's).
func (h *scriptHandler) execute(ctx context.Context, t *jobs.Task, runID uuid.UUID) (any, error) {
	bg := context.WithoutCancel(ctx)
	run, err := h.q.GetScriptRun(ctx, runID)
	if isNotFound(err) {
		return nil, errors.New("The run was deleted before it started.")
	}
	if err != nil {
		return nil, err
	}
	if !jobs.Active(run.State) {
		return nil, nil
	}
	targets, err := h.q.ListScriptRunTargets(ctx, run.ID)
	if err != nil {
		return nil, err
	}
	env := map[string]string{}
	decodeInto(run.Env, &env)
	script, err := wrapScript(run.Interpreter, run.Content, env)
	if err != nil {
		_ = h.q.EndScriptRun(bg, sqlc.EndScriptRunParams{ID: run.ID, State: jobs.Failed, Error: err.Error()})
		return nil, err
	}
	if err := h.q.StartScriptRun(ctx, run.ID); err != nil {
		return nil, err
	}

	var mu sync.Mutex
	running := []string{}
	done, failed := 0, 0
	report := func() {
		t.Update(func(p *jobs.Progress) {
			p.Phase, p.Items, p.ItemsTotal = "Running", done, len(targets)
			p.Current = strings.Join(running, ", ")
		})
	}
	report()

	sem := make(chan struct{}, scriptParallel)
	var wg sync.WaitGroup
	for _, tg := range targets {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			mu.Lock()
			running = append(running, tg.ServerName)
			report()
			mu.Unlock()

			state := h.runTarget(ctx, t, run, tg, script)

			mu.Lock()
			running = slices.DeleteFunc(running, func(n string) bool { return n == tg.ServerName })
			done++
			if state != jobs.Succeeded {
				failed++
			}
			report()
			mu.Unlock()
			t.Logf("%s: %s", tg.ServerName, state)
		}()
	}
	wg.Wait()

	state, msg := jobs.Succeeded, ""
	switch {
	case ctx.Err() != nil && t.Canceled():
		state = jobs.Canceled
	case ctx.Err() != nil:
		state, msg = jobs.Interrupted, "Morcheh stopped before it finished."
	case failed > 0:
		state, msg = jobs.Failed, fmt.Sprintf("It failed on %d of %s.", failed, countServers(len(targets)))
		if len(targets) == 1 {
			msg = "It failed on " + targets[0].ServerName + "."
		}
	}
	// Servers it never got to.
	if state == jobs.Canceled || state == jobs.Interrupted {
		_ = h.q.EndScriptRun(bg, sqlc.EndScriptRunParams{ID: run.ID, State: state, Error: msg})
	} else if err := h.q.FinishScriptRun(bg, sqlc.FinishScriptRunParams{ID: run.ID, State: state, Error: msg}); err != nil {
		slog.Error("finish a script run", "run", run.ID, "error", err)
	}
	switch state {
	case jobs.Succeeded:
		return map[string]any{"run_id": run.ID.String()}, nil
	case jobs.Failed:
		return nil, errors.New(msg)
	}
	return nil, ctx.Err()
}

// runTarget runs the script on one server and stores what happened there.
func (h *scriptHandler) runTarget(ctx context.Context, t *jobs.Task, run sqlc.ScriptRun, tg sqlc.ScriptRunTarget, script string) string {
	bg := context.WithoutCancel(ctx)
	key := sqlc.FinishScriptTargetParams{RunID: run.ID, Position: tg.Position}
	finish := func(p sqlc.FinishScriptTargetParams) string {
		p.RunID, p.Position = run.ID, tg.Position
		p.Output = cleanOutput(p.Output)
		if err := h.q.FinishScriptTarget(bg, p); err != nil {
			slog.Error("finish a script run's server", "run", run.ID, "server", tg.ServerName, "error", err)
		}
		return p.State
	}
	stopped := func() string {
		if t.Canceled() {
			return jobs.Canceled
		}
		return jobs.Interrupted
	}
	if ctx.Err() != nil {
		return finish(sqlc.FinishScriptTargetParams{State: stopped()})
	}
	if tg.ServerID == nil {
		return finish(sqlc.FinishScriptTargetParams{State: jobs.Failed, Error: "The server was deleted."})
	}
	if err := h.q.StartScriptTarget(ctx, sqlc.StartScriptTargetParams{RunID: key.RunID, Position: key.Position}); err != nil {
		return finish(sqlc.FinishScriptTargetParams{State: jobs.Failed, Error: err.Error()})
	}

	out := &liveOutput{limit: scriptOutputCap}
	saveStop := make(chan struct{})
	saveDone := make(chan struct{})
	go func() {
		defer close(saveDone)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		seen := 0
		for {
			select {
			case <-saveStop:
				return
			case <-tick.C:
				text, truncated, version := out.snapshot()
				if version == seen {
					continue
				}
				seen = version
				if err := h.q.SaveScriptTargetOutput(bg, sqlc.SaveScriptTargetOutputParams{
					RunID: run.ID, Position: tg.Position, Output: cleanOutput(text), Truncated: truncated,
				}); err != nil {
					slog.Warn("save a script's output", "run", run.ID, "error", err)
				}
			}
		}
	}()
	res, err := h.execOn(ctx, tg.ServerID.String(), run.RunAs, script, time.Duration(run.TimeoutSeconds)*time.Second, out)
	close(saveStop)
	<-saveDone

	text, truncated, _ := out.snapshot()
	p := sqlc.FinishScriptTargetParams{Output: text, Truncated: truncated}
	switch {
	case err != nil && ctx.Err() != nil:
		p.State = stopped()
	case err != nil:
		p.State, p.Error = jobs.Failed, err.Error()
	case res.stopped && ctx.Err() != nil:
		p.State = stopped()
	case res.stopped:
		p.State, p.TimedOut = jobs.Failed, true
		p.Error = fmt.Sprintf("It ran past its time limit (%s) and was stopped.", time.Duration(run.TimeoutSeconds)*time.Second)
	default:
		p.ExitCode = res.code
		p.State = jobs.Succeeded
		if res.code == nil || *res.code != 0 {
			p.State = jobs.Failed
		}
	}
	if p.ExitCode == nil && res != nil {
		p.ExitCode = res.code
	}
	return finish(p)
}

type scriptResult struct {
	code    *int32
	stopped bool // canceled or timed out, then signaled
}

// execOn runs a wrapped script on a server as its login user or as root.
// A lost connection is retried once, but only before the script started.
func (h *scriptHandler) execOn(ctx context.Context, serverID, runAs, script string, timeout time.Duration, w *liveOutput) (*scriptResult, error) {
	for attempt := 0; ; attempt++ {
		c, err := h.servers.conn(ctx, serverID)
		if err != nil {
			return nil, err
		}
		var res *scriptResult
		started := false
		err = hold(c, func() error {
			sh := &rootShell{c: c, priv: privUser}
			if runAs == "root" {
				if sh, err = h.servers.rootShell(ctx, serverID, c); err != nil {
					return err
				}
				if sh.priv == privUser {
					return errors.New("Its login user can't become root (no sudo, and the stored password didn't work). Run it as the login user, or give that user sudo.")
				}
			}
			res, started, err = execScript(ctx, sh, script, timeout, w)
			return err
		})
		if err != nil && !started && attempt == 0 && sshpool.Lost(err) {
			h.servers.pool.Drop(serverID)
			continue
		}
		return res, err
	}
}

// execScript starts the script in its own session and waits for it. When ctx
// ends or the time limit passes it sends SIGTERM (relayed by sudo and by the
// wrapper to the script's process group), and closes the session if the
// script hasn't exited within scriptGrace.
func execScript(ctx context.Context, sh *rootShell, script string, timeout time.Duration, w *liveOutput) (*scriptResult, bool, error) {
	// The wrapper goes in on stdin, not the command line: one argument is
	// limited to 128 KiB on Linux. sudo -S reads its password a byte at a
	// time, so the rest of stdin reaches sh.
	cmd, stdin := "sh -s", script
	switch sh.priv {
	case privSudo:
		cmd = "sudo -n sh -s"
	case privSudoPassword:
		cmd, stdin = "sudo -S -p '' sh -s", sh.password+"\n"+script
	}
	sess, err := sh.c.Client.NewSession()
	if err != nil {
		return nil, false, err
	}
	defer sess.Close()
	sess.Stdout, sess.Stderr = w, w
	sess.Stdin = strings.NewReader(stdin)
	if err := sess.Start(cmd); err != nil {
		return nil, false, err
	}
	wait := make(chan error, 1)
	go func() { wait <- sess.Wait() }()

	limit, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res := &scriptResult{}
	select {
	case err = <-wait:
	case <-limit.Done():
		res.stopped = true
		_ = sess.Signal(ssh.SIGTERM)
		select {
		case err = <-wait:
		case <-time.After(scriptGrace):
			_ = sess.Close()
			err = <-wait
		}
	}
	var exit *ssh.ExitError
	switch {
	case err == nil:
		zero := int32(0)
		res.code = &zero
	case errors.As(err, &exit) && exit.Signal() == "":
		code := int32(exit.ExitStatus())
		res.code = &code
	case res.stopped:
	case errors.As(err, &exit):
		return nil, true, errors.New("The script was killed by signal " + exit.Signal() + ".")
	default:
		var missing *ssh.ExitMissingError
		if errors.As(err, &missing) {
			return nil, true, errors.New("The connection closed before the script finished.")
		}
		return nil, true, err
	}
	return res, true, nil
}

// wrapScript is the POSIX sh that runs content with its interpreter: written
// to a temporary file (so the script can read stdin from nowhere and its
// line numbers are right), the variables exported, stopped as a group on
// SIGTERM, cleaned up after.
func wrapScript(interpreter, content string, env map[string]string) (string, error) {
	switch interpreter {
	case "sh", "bash", "python3":
	default:
		return "", errors.New("Unknown interpreter " + interpreter + ".")
	}
	var delim string
	for {
		b := make([]byte, 12)
		_, _ = rand.Read(b)
		delim = "MORCHEH_" + strings.ToUpper(hex.EncodeToString(b))
		if !strings.Contains(content, delim) {
			break
		}
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	names := make([]string, 0, len(env))
	for n := range env {
		names = append(names, n)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("f=$(mktemp 2>/dev/null || mktemp -t morcheh.XXXXXX) || { echo 'Could not create a temporary file.' >&2; exit 1; }\n")
	b.WriteString("cat > \"$f\" <<'" + delim + "'\n")
	b.WriteString(content)
	b.WriteString(delim + "\n")
	for _, n := range names {
		if !envNameRe.MatchString(n) || reservedEnv(n) {
			return "", errors.New("Bad variable name " + n + ".")
		}
		b.WriteString("export " + n + "=" + terminal.ShellQuote(env[n]) + "\n")
	}
	fmt.Fprintf(&b, "if ! command -v %s >/dev/null 2>&1; then echo '%s is not installed on this server.' >&2; rm -f \"$f\"; exit 127; fi\n", interpreter, interpreter)
	b.WriteString("set -m 2>/dev/null\n")
	fmt.Fprintf(&b, "%s \"$f\" </dev/null &\n", interpreter)
	b.WriteString("pid=$!\n")
	b.WriteString("trap 'kill -TERM -\"$pid\" 2>/dev/null || kill -TERM \"$pid\" 2>/dev/null; wait \"$pid\" 2>/dev/null; rm -f \"$f\"; exit 143' TERM HUP INT\n")
	b.WriteString("wait \"$pid\"; code=$?\n")
	b.WriteString("rm -f \"$f\"\n")
	b.WriteString("exit $code\n")
	return b.String(), nil
}

// liveOutput keeps the first limit bytes of a script's stdout and stderr,
// from both goroutines, with a version that changes on every write.
type liveOutput struct {
	mu        sync.Mutex
	buf       []byte
	limit     int
	truncated bool
	version   int
}

func (o *liveOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	room := o.limit - len(o.buf)
	if room < len(p) {
		o.truncated = true
	}
	if room > 0 {
		o.buf = append(o.buf, p[:min(room, len(p))]...)
		o.version++
	}
	return len(p), nil
}

func (o *liveOutput) snapshot() (string, bool, int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return string(o.buf), o.truncated, o.version
}

// cleanOutput is output PostgreSQL will store as text: valid UTF-8, no NUL.
func cleanOutput(s string) string {
	return strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", ""), "�")
}
