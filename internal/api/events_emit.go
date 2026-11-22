package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/events"
	"github.com/morche/backend/internal/jobs"
	"github.com/morche/backend/internal/sshprobe"
	"github.com/morche/backend/internal/uptime"
)

// Where panel events (internal/events) are published, and the catalog
// endpoint. Every emit point is a state transition; none sits in a
// notification send function (those also carry reminders and are skipped
// while muted).

// PanelEvent is one event as the API shows it (webhook bodies, catalog
// samples). Named so the generated TypeScript doesn't shadow the DOM's Event.
type PanelEvent events.Event

// EventType describes one event type.
type EventType struct {
	Name         string     `json:"name"`
	Group        string     `json:"group"`
	Label        string     `json:"label"`
	Description  string     `json:"description"`
	Severity     string     `json:"severity"`
	SubjectKind  string     `json:"subject_kind"`
	ServerScoped bool       `json:"server_scoped"`
	Internal     bool       `json:"internal" doc:"Never triggers automations (test.ping, automation.failed)"`
	Sample       PanelEvent `json:"sample"`
}

func registerEvents(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "get-event-catalog", Method: http.MethodGet, Path: "/events/catalog",
		Summary: "Event types", Tags: []string{"Events"},
		Description: "Every event type webhooks and automations can react to, with a sample event each.",
	}, func(ctx context.Context, _ *struct{}) (*struct {
		Body struct {
			Items []EventType `json:"items"`
		}
	}, error) {
		out := &struct {
			Body struct {
				Items []EventType `json:"items"`
			}
		}{}
		out.Body.Items = make([]EventType, len(events.Catalog))
		for i, t := range events.Catalog {
			out.Body.Items[i] = EventType{
				Name: t.Name, Group: t.Group, Label: t.Label, Description: t.Description,
				Severity: t.Severity, SubjectKind: t.SubjectKind, ServerScoped: t.ServerScoped,
				Internal: t.Internal, Sample: PanelEvent(t.Sample),
			}
		}
		return out, nil
	})
}

// publish sends e to the bus (never blocks; nil-safe).
func (a *authz) publish(e events.Event) {
	if a == nil {
		return
	}
	a.events.Publish(e)
}

// originKey carries the Origin of work an automation does, so the events
// that work causes are marked (and never start automations again).
type originKey struct{}

func withOrigin(ctx context.Context, origin string) context.Context {
	return context.WithValue(ctx, originKey{}, origin)
}

func originOf(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	o, _ := ctx.Value(originKey{}).(string)
	return o
}

// cronOrigins: schedule run id → the Origin of the automation that started
// it, for publishCronRun (the run ends in another job, without our context).
var cronOrigins sync.Map

// link is a panel address, or "" when the panel's address isn't known.
func (a *authz) link(path string) string {
	if a == nil || a.panelURL == "" {
		return ""
	}
	return a.panelURL + path
}

// ---- Alerts ----

// publishAlert is called by alertEngine.event, i.e. only when a rule fires or
// resolves on a target (reminders and "the mute is over" sends aren't
// events). Muted ones are published too, with data.muted.
func (e *alertEngine) publishAlert(r sqlc.AlertRule, t alertTarget, kind string, v float64, detail string, lasted time.Duration, muted bool, at time.Time) {
	if e.up == nil || e.up.authz == nil {
		return
	}
	msg := e.alertMessage(r, t, kind, v, detail, lasted, at)
	typ, sev := events.AlertFired, r.Severity
	if kind == "resolved" {
		typ, sev = events.AlertResolved, events.Info
	}
	if sev != events.Critical && sev != events.Warning && sev != events.Info {
		sev = events.Warning
	}
	data := msg.Data
	data["muted"] = muted
	if lasted > 0 {
		data["lasted_seconds"] = int64(lasted / time.Second)
	}
	subj := events.Subject{Kind: t.kind, ID: t.id.String(), Name: t.name}
	var server *uuid.UUID
	switch t.kind {
	case "pve":
		subj.Kind = events.SubjectCluster
	case "database":
	default:
		subj.Kind = events.SubjectServer
		id := t.id
		server = &id
	}
	e.up.authz.publish(events.Event{
		Type: typ, WorkspaceID: r.WorkspaceID, At: at, Severity: sev,
		Title: msg.Title, Text: msg.Text, URL: msg.URL, Subject: subj, ServerID: server, Data: data,
	})
}

// ---- Uptime monitors ----

// publishMonitor is called by alertChange on every status change of a
// monitor, whether or not the change is notified.
func (h *uptimeHandler) publishMonitor(ctx context.Context, m sqlc.Monitor, prev, next string, r uptime.CheckResult, at time.Time) {
	var typ, sev, title string
	switch next {
	case uptime.Down:
		typ, sev, title = events.MonitorDown, events.Critical, m.Name+" is down"
	case uptime.Degraded:
		typ, sev, title = events.MonitorDegraded, events.Warning, m.Name+" is degraded"
		if prev == uptime.Down {
			typ, sev, title = events.MonitorUp, events.Info, m.Name+" is back up, but degraded"
		}
	case uptime.Up:
		// A new monitor's first answer isn't news.
		if prev != uptime.Down && prev != uptime.Degraded {
			return
		}
		typ, sev, title = events.MonitorUp, events.Info, m.Name+" is back up"
		if prev == uptime.Degraded {
			title = m.Name + " is back to normal"
		}
	default:
		return
	}
	cfg := monitorConfig(m)
	data := map[string]any{
		"kind": m.Kind, "target": monitorTarget(m.Kind, cfg), "status": next, "previous": prev,
		"code": r.Code, "message": r.Message, "latency_ms": r.LatencyMs,
	}
	if typ == events.MonitorUp && !m.StatusSince.IsZero() {
		data["lasted_seconds"] = int64(at.Sub(m.StatusSince) / time.Second)
	}
	if len(r.Locations) > 1 {
		data["locations"] = r.Locations
	}
	h.authz.publish(events.Event{
		Type: typ, WorkspaceID: m.WorkspaceID, At: at, Severity: sev, Title: title, Text: r.Message,
		URL:      h.authz.link("/monitoring/" + m.ID.String()),
		Subject:  events.Subject{Kind: events.SubjectMonitor, ID: m.ID.String(), Name: m.Name},
		ServerID: m.ServerID, Data: data, Origin: originOf(ctx),
	})
}

// ---- Servers ----

// publishServerStatus is called from recordCheckHistory when a checked
// server's status changed: only a flip between online and not online is an
// event (unreachable → auth failed isn't).
func (h *serverHandler) publishServerStatus(ctx context.Context, prev sqlc.Server, res sshprobe.Result) {
	wasOnline, isOnline := prev.Status == sshprobe.StatusOnline, res.Status == sshprobe.StatusOnline
	var typ, sev, title, text string
	switch {
	case wasOnline && !isOnline:
		typ, sev, title, text = events.ServerOffline, events.Critical, prev.Name+" is offline", cmpOr(res.Message, statusText(res.Status))
	case isOnline && !wasOnline && prev.Status != "unknown" && prev.Status != "":
		typ, sev, title = events.ServerOnline, events.Info, prev.Name+" is online again"
	default:
		return
	}
	id := prev.ID
	data := map[string]any{"status": res.Status, "previous": prev.Status, "host": prev.Host}
	if isOnline {
		data["latency_ms"] = res.LatencyMs
	}
	h.authz.publish(events.Event{
		Type: typ, WorkspaceID: prev.WorkspaceID, Severity: sev, Title: title, Text: text,
		URL:      h.authz.link("/servers/" + id.String()),
		Subject:  events.Subject{Kind: events.SubjectServer, ID: id.String(), Name: prev.Name},
		ServerID: &id, Data: data, Origin: originOf(ctx),
	})
}

// ---- Cron jobs ----

// publishCronRun is called by closeRun once a run's end is stored. Dry runs,
// canceled and interrupted ones aren't events; partial counts as failed.
func (h *scheduleHandler) publishCronRun(ctx context.Context, runID uuid.UUID, state, msg string, files int, bytes int64) {
	if state != jobs.Succeeded && state != jobs.Failed && state != "partial" {
		return
	}
	run, err := h.q.GetScheduleRun(ctx, runID)
	if err != nil || run.DryRun {
		return
	}
	s, err := h.q.GetSchedule(ctx, run.ScheduleID)
	if err != nil {
		return
	}
	data := map[string]any{
		"run_id": run.ID.String(), "action": s.Action, "trigger": run.Trigger, "state": state,
		"partial": state == "partial", "files": files, "bytes": bytes,
	}
	e := events.Event{
		Type: events.CronjobSucceeded, WorkspaceID: s.WorkspaceID, Severity: events.Info,
		Title:   s.Name + " finished",
		URL:     h.authz.link("/cronjobs/" + s.ID.String() + "?run=" + run.ID.String()),
		Subject: events.Subject{Kind: events.SubjectCronjob, ID: s.ID.String(), Name: s.Name},
		Data:    data,
	}
	if state != jobs.Succeeded {
		e.Type, e.Severity, e.Text = events.CronjobFailed, events.Warning, msg
		e.Title = s.Name + " failed"
		if state == "partial" {
			e.Title = s.Name + " partly failed"
		}
		data["error"] = msg
	}
	if len(s.ServerIds) == 1 {
		e.ServerID = &s.ServerIds[0]
	}
	if o, ok := cronOrigins.LoadAndDelete(run.ID); ok {
		e.Origin, _ = o.(string)
	}
	h.authz.publish(e)
}

// ---- Job ends: database backups and compose deploys ----

// registerJobEvents publishes events when backup and deploy jobs end. Call it
// once, after the handlers are registered.
func registerJobEvents(runner *jobs.Runner, servers *serverHandler) {
	runner.OnEnd(backupKind, func(j sqlc.Job) { publishBackupEnd(servers, j) })
	runner.OnEnd(dockerComposeKind, func(j sqlc.Job) { publishDeployEnd(servers, j, false) })
	runner.OnEnd(dockerGitDeployKind, func(j sqlc.Job) { publishDeployEnd(servers, j, true) })
}

func publishBackupEnd(h *serverHandler, j sqlc.Job) {
	if j.State != jobs.Succeeded && j.State != jobs.Failed {
		return
	}
	var p backupParams
	if json.Unmarshal(j.Params, &p) != nil {
		return
	}
	ids := p.Backups
	if len(ids) == 0 && p.Backup != "" {
		ids = []string{p.Backup}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var rows []sqlc.DatabaseBackup
	for _, raw := range ids {
		id, err := uuid.Parse(raw)
		if err != nil {
			continue
		}
		if b, err := h.q.GetBackup(ctx, id); err == nil {
			rows = append(rows, b)
		}
	}
	if len(rows) == 0 {
		return
	}
	d, err := h.q.GetDatabase(ctx, rows[0].DatabaseID)
	if err != nil {
		return
	}
	failed, canceled := 0, 0
	var total int64
	var targets, problems []string
	for _, b := range rows {
		targets = append(targets, cmpOr(b.Target, d.Name))
		switch b.State {
		case jobs.Succeeded:
			total += b.Bytes
		case jobs.Canceled, jobs.Interrupted:
			canceled++
		default:
			failed++
			if b.Error != "" {
				problems = append(problems, cmpOr(b.Target, d.Name)+": "+b.Error)
			}
		}
	}
	if canceled == len(rows) {
		return
	}
	b := rows[0]
	data := map[string]any{
		"plan_name": b.PlanName, "trigger": b.Trigger, "backups": len(rows), "failed": failed,
		"bytes": total, "targets": targets, "job_id": j.ID.String(), "engine": d.Engine,
	}
	if b.PlanID != nil {
		data["plan_id"] = b.PlanID.String()
	}
	e := events.Event{
		Type: events.BackupSucceeded, WorkspaceID: d.WorkspaceID, Severity: events.Info,
		Title:    "Backup of " + d.Name + " finished",
		URL:      h.authz.link("/databases/" + d.ID.String() + "?tab=backups"),
		Subject:  events.Subject{Kind: events.SubjectDatabase, ID: d.ID.String(), Name: d.Name},
		ServerID: d.ServerID, Data: data,
	}
	if failed > 0 || j.State == jobs.Failed {
		msg := cmpOr(j.Error, strings.Join(problems, "; "))
		e.Type, e.Severity, e.Text = events.BackupFailed, events.Critical, msg
		e.Title = "Backup of " + d.Name + " failed"
		data["error"] = msg
	}
	h.authz.publish(e)
}

// deployActions are the compose actions that count as a deploy.
var deployActions = map[string]bool{"up": true, "redeploy": true}

func publishDeployEnd(h *serverHandler, j sqlc.Job, git bool) {
	if j.State != jobs.Succeeded && j.State != jobs.Failed {
		return
	}
	var p struct {
		ServerID string `json:"server_id"`
		Project  string `json:"project"`
		Action   string `json:"action"`
		Trigger  string `json:"trigger"`
	}
	if json.Unmarshal(j.Params, &p) != nil {
		return
	}
	action := p.Action
	data := map[string]any{"project": p.Project, "job_id": j.ID.String()}
	if git {
		action = "git"
		data["trigger"] = p.Trigger
		if j.State == jobs.Succeeded {
			var res struct {
				Commit   string `json:"commit"`
				Deployed bool   `json:"deployed"`
			}
			// An up-to-date repository deployed nothing.
			if json.Unmarshal(j.Result, &res) != nil || !res.Deployed {
				return
			}
			data["commit"] = res.Commit
		}
	} else if !deployActions[action] {
		return
	}
	data["action"] = action
	sid, err := uuid.Parse(p.ServerID)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := h.q.GetServer(ctx, sid)
	if err != nil {
		slog.Warn("events: deploy's server", "server", sid, "error", err)
		return
	}
	e := events.Event{
		Type: events.DeploySucceeded, WorkspaceID: s.WorkspaceID, Severity: events.Info,
		Title:    p.Project + " deployed on " + s.Name,
		URL:      h.authz.link("/containers/projects/" + p.Project + "?env=" + sid.String()),
		Subject:  events.Subject{Kind: events.SubjectProject, ID: sid.String() + "/" + p.Project, Name: p.Project},
		ServerID: &sid, Data: data,
	}
	if j.State == jobs.Failed {
		e.Type, e.Severity, e.Text = events.DeployFailed, events.Critical, j.Error
		e.Title = "Deploy of " + p.Project + " on " + s.Name + " failed"
		data["error"] = j.Error
	}
	h.authz.publish(e)
}
