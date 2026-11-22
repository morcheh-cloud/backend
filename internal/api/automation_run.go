package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/dbmon"
	"github.com/morche/backend/internal/events"
	"github.com/morche/backend/internal/jobs"
	"github.com/morche/backend/internal/notify"
	"github.com/morche/backend/internal/sshprobe"
	"github.com/morche/backend/internal/uptime"
)

// How automations run: the bus subscriber picks the automations an event
// starts and queues a run for each (after the cooldown and runs-per-hour
// gates); the run is a light job (it takes no runner slot, so a cron job it
// waits for can start) that does the steps one by one as the person who saved
// the automation, saving each step's state as it goes.

const automationCronWait = 6 * time.Hour

// testAutomationHook, when set (tests), is given the handler once wired.
var testAutomationHook func(*automationHandler)

// start subscribes to the bus.
func (h *automationHandler) start(bus *events.Bus) {
	if testAutomationHook != nil {
		testAutomationHook(h)
	}
	ch, _ := bus.Subscribe("automations", 1000)
	go func() {
		for e := range ch {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			h.handle(ctx, e)
			cancel()
		}
	}()
	go func() {
		for range time.Tick(time.Hour) {
			h.prune(context.Background())
		}
	}()
}

// handle starts every automation of the event's workspace it matches.
func (h *automationHandler) handle(ctx context.Context, e events.Event) {
	if e.ByAutomation() {
		return
	}
	if t, ok := events.Lookup(e.Type); !ok || t.Internal {
		return
	}
	autos, err := h.q.ListEventAutomations(ctx, e.WorkspaceID)
	if err != nil {
		slog.Warn("automations: list", "workspace", e.WorkspaceID, "error", err)
		return
	}
	var tags []string
	looked := false
	serverTags := func() []string {
		if !looked && e.ServerID != nil {
			looked = true
			if s, err := h.q.GetServer(ctx, *e.ServerID); err == nil {
				tags = s.Tags
			}
		}
		return tags
	}
	for _, a := range autos {
		if !automationMatches(decodeTrigger(a.Trigger), e, serverTags) {
			continue
		}
		if _, _, err := h.fire(ctx, a, e, "event", nil); err != nil {
			slog.Warn("automations: start a run", "automation", a.ID, "error", err)
		}
	}
}

type automationRunParams struct {
	RunID uuid.UUID `json:"run_id"`
}

// gate says why an event-started run must be skipped now, or "".
func (h *automationHandler) gate(ctx context.Context, a sqlc.Automation, subject string) (string, error) {
	active, err := h.q.CountActiveAutomationRunsFor(ctx, sqlc.CountActiveAutomationRunsForParams{AutomationID: a.ID, SubjectID: subject})
	if err != nil {
		return "", err
	}
	last, err := h.q.LastAutomationRunFor(ctx, sqlc.LastAutomationRunForParams{AutomationID: a.ID, SubjectID: subject})
	if err != nil {
		return "", err
	}
	hour, err := h.q.CountAutomationRunsSince(ctx, sqlc.CountAutomationRunsSinceParams{AutomationID: a.ID, Since: time.Now().Add(-time.Hour)})
	if err != nil {
		return "", err
	}
	return automationGate(a.CooldownSeconds, a.MaxRunsPerHour, last, hour, active, time.Now()), nil
}

// fire records a run of a for e and queues it. Event and webhook runs go
// through the gates (a skipped run is recorded, at most one a minute); a
// manual or test run only waits for none to be going (409).
func (h *automationHandler) fire(ctx context.Context, a sqlc.Automation, e events.Event, kind string, by *principal) (sqlc.AutomationRun, *Job, error) {
	evRaw, _ := json.Marshal(PanelEvent(e))
	steps := make([]AutomationStep, 0)
	for i, act := range decodeActions(a.Actions) {
		steps = append(steps, AutomationStep{
			Index: i, ActionID: act.ID, Kind: act.Kind, Label: stepLabel(act.AutomationAction), Status: "pending",
			Targets: []AutomationStepTarget{},
		})
	}
	stepsRaw, _ := json.Marshal(steps)
	params := sqlc.CreateAutomationRunParams{
		AutomationID: a.ID, WorkspaceID: a.WorkspaceID, TriggerKind: kind, Event: evRaw,
		SubjectID: e.Subject.ID, Status: jobs.Queued, Steps: stepsRaw,
	}
	if kind == "webhook" {
		params.SubjectID = ""
	}
	if by != nil {
		params.StartedBy, params.StartedByName = by.ID(), cmpOr(by.User.FullName, by.User.Username)
	}
	if kind == "event" || kind == "webhook" {
		reason, err := h.gate(ctx, a, params.SubjectID)
		if err != nil {
			return sqlc.AutomationRun{}, nil, internalError(err)
		}
		if reason != "" {
			// Keep skipped rows, but not a flood of them.
			last, err := h.q.LastSkippedAutomationRun(ctx, a.ID)
			if err == nil && time.Since(last) < time.Minute {
				return sqlc.AutomationRun{Status: "skipped", Reason: reason}, nil, nil
			}
			now := time.Now()
			params.Status, params.Reason, params.FinishedAt = "skipped", reason, &now
			run, err := h.q.CreateAutomationRun(ctx, params)
			if err != nil {
				return run, nil, internalError(err)
			}
			return run, nil, nil
		}
	} else {
		active, err := h.q.CountActiveAutomationRuns(ctx, a.ID)
		if err != nil {
			return sqlc.AutomationRun{}, nil, internalError(err)
		}
		if active > 0 {
			return sqlc.AutomationRun{}, nil, huma.Error409Conflict("It's running now. Wait for it to finish, or stop it first.")
		}
	}
	run, err := h.q.CreateAutomationRun(ctx, params)
	if err != nil {
		return run, nil, internalError(err)
	}
	var byID *uuid.UUID
	if by != nil {
		byID = by.ID()
	}
	j, err := h.runner.Submit(ctx, jobs.Spec{
		Kind: automationRunKind, Title: "Run " + a.Name, Params: automationRunParams{RunID: run.ID},
		Target: JobPlace{Automation: a.ID.String(), RunID: run.ID.String(), Name: a.Name},
		Light:  true, CreatedBy: byID,
	})
	if err != nil {
		_ = h.q.EndAutomationRun(context.WithoutCancel(ctx), sqlc.EndAutomationRunParams{ID: run.ID, Status: jobs.Failed, Reason: "It couldn't be queued."})
		return run, nil, internalError(err)
	}
	if err := h.q.SetAutomationRunJob(ctx, sqlc.SetAutomationRunJobParams{ID: run.ID, JobID: &j.ID}); err != nil {
		return run, nil, internalError(err)
	}
	run.JobID = &j.ID
	job := toJob(j, false)
	return run, &job, nil
}

func stepLabel(a AutomationAction) string {
	if a.Label != "" {
		return a.Label
	}
	switch a.Kind {
	case "notify":
		return "Send a notification"
	case "webhook":
		return "Call " + urlHost(a.URL)
	case "script":
		if a.ScriptID != "" {
			return "Run a script"
		}
		return "Run a command"
	case "service":
		return strings.ToUpper(a.Action[:1]) + a.Action[1:] + " " + a.Unit
	case "cronjob":
		return "Run a cron job"
	case "check":
		return "Check again"
	case "wait":
		return fmt.Sprintf("Wait %s", fmtSeconds(int64(a.Seconds)))
	}
	return a.Kind
}

func urlHost(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

// ---- Running ----

type automationRun struct {
	h     *automationHandler
	t     *jobs.Task
	auto  sqlc.Automation
	run   sqlc.AutomationRun
	acc   *auth.Access
	who   string
	vars  automationVars
	steps []AutomationStep
	mu    sync.Mutex
}

func (r *automationRun) save() {
	r.mu.Lock()
	raw, _ := json.Marshal(r.steps)
	r.mu.Unlock()
	if err := r.h.q.SaveAutomationRunSteps(context.Background(), sqlc.SaveAutomationRunStepsParams{ID: r.run.ID, Steps: raw}); err != nil {
		slog.Warn("automations: save a run's steps", "run", r.run.ID, "error", err)
	}
}

func (h *automationHandler) runJob(ctx context.Context, t *jobs.Task) (any, error) {
	var params automationRunParams
	if err := t.Decode(&params); err != nil {
		return nil, err
	}
	bg := context.WithoutCancel(ctx)
	run, err := h.q.GetAutomationRun(ctx, params.RunID)
	if isNotFound(err) {
		return nil, errors.New("The automation was deleted before this run started.")
	}
	if err != nil {
		return nil, err
	}
	if run.Status != jobs.Queued && run.Status != jobs.Running {
		return nil, nil
	}
	a, err := h.q.GetAutomation(ctx, run.AutomationID)
	if err != nil {
		return nil, errors.New("The automation was deleted before this run started.")
	}
	if err := h.q.StartAutomationRun(ctx, run.ID); err != nil {
		return nil, err
	}
	r := &automationRun{h: h, t: t, auto: a, run: run}
	_ = json.Unmarshal(run.Steps, &r.steps)
	acts := decodeActions(a.Actions)
	// The steps saved when it was queued; the automation may have changed since.
	if len(r.steps) != len(acts) {
		r.steps = r.steps[:0]
		for i, act := range acts {
			r.steps = append(r.steps, AutomationStep{Index: i, ActionID: act.ID, Kind: act.Kind, Label: stepLabel(act.AutomationAction), Status: "pending", Targets: []AutomationStepTarget{}})
		}
	}
	var ev PanelEvent
	_ = json.Unmarshal(run.Event, &ev)

	u, who, acc, err := runAsUser(ctx, h.q, h.authz, a.UpdatedBy, "automation")
	if err != nil {
		return r.fail(bg, problemText(err), true)
	}
	r.acc, r.who = acc, who
	// Everything below acts as that person, checked as when done by hand, and
	// what it causes is marked as caused by this automation.
	ctx = context.WithValue(ctx, principalKey{}, &principal{User: u, Access: acc, Level: acc.WorkspaceLevel(a.WorkspaceID)})
	ctx = withOrigin(ctx, events.FromAutomation(a.ID))
	if err := h.mayRun(ctx, a, acts, acc, who); err != nil {
		return r.fail(bg, err.Error(), true)
	}
	if a.Problem != "" {
		_ = h.q.SetAutomationProblem(bg, sqlc.SetAutomationProblemParams{ID: a.ID, Problem: ""})
	}

	r.vars = automationVars{
		Event: events.Event(ev), Automation: a.Name, AutoID: a.ID, RunID: run.ID,
		RunURL: h.authz.link("/automations/" + a.ID.String() + "?run=" + run.ID.String()),
	}
	if ev.ServerID != nil {
		if s, err := h.q.GetServer(ctx, *ev.ServerID); err == nil && s.WorkspaceID == a.WorkspaceID {
			r.vars.ServerName, r.vars.ServerHost = s.Name, s.Host
		}
	}
	t.Logf("Running as %s", who)

	failed := ""
	for i, act := range acts {
		if ctx.Err() != nil {
			break
		}
		r.begin(i)
		t.Update(func(p *jobs.Progress) {
			p.Phase, p.Items, p.ItemsTotal, p.Current = r.steps[i].Label, i, len(acts), ""
		})
		err := r.step(ctx, i, act)
		r.end(ctx, i, err)
		if err != nil && ctx.Err() == nil && !act.ContinueOnError {
			failed = fmt.Sprintf("Step %d (%s): %s", i+1, r.steps[i].Label, r.steps[i].Error)
			for j := i + 1; j < len(r.steps); j++ {
				r.steps[j].Status, r.steps[j].Error = "skipped", "Not run: step "+fmt.Sprint(i+1)+" failed."
			}
			r.save()
			break
		}
		if err != nil && failed == "" && act.ContinueOnError {
			// It went on, but the run still counts as failed.
			failed = fmt.Sprintf("Step %d (%s): %s", i+1, r.steps[i].Label, r.steps[i].Error)
		}
	}
	switch {
	case ctx.Err() != nil:
		for j := range r.steps {
			if r.steps[j].Status == "pending" || r.steps[j].Status == "running" {
				r.steps[j].Status = "canceled"
			}
		}
		r.save()
		status, reason := "canceled", ""
		if !t.Canceled() {
			status, reason = jobs.Failed, "Morche stopped before it finished."
		}
		r.close(bg, status, reason)
		return nil, ctx.Err()
	case failed != "":
		r.close(bg, jobs.Failed, failed)
		return nil, errors.New(failed)
	}
	r.close(bg, jobs.Succeeded, "")
	return nil, nil
}

// fail ends a run before any step ran. problem: also note it on the
// automation (its person lost access…), so the list shows it.
func (r *automationRun) fail(ctx context.Context, reason string, problem bool) (any, error) {
	if problem {
		_ = r.h.q.SetAutomationProblem(ctx, sqlc.SetAutomationProblemParams{ID: r.auto.ID, Problem: reason})
	}
	for j := range r.steps {
		r.steps[j].Status = "skipped"
	}
	r.save()
	r.close(ctx, jobs.Failed, reason)
	return nil, errors.New(reason)
}

func (r *automationRun) close(ctx context.Context, status, reason string) {
	if err := r.h.q.EndAutomationRun(ctx, sqlc.EndAutomationRunParams{ID: r.run.ID, Status: status, Reason: reason}); err != nil {
		slog.Warn("automations: end a run", "run", r.run.ID, "error", err)
	}
	if err := r.h.q.NoteAutomationRun(ctx, sqlc.NoteAutomationRunParams{ID: r.auto.ID, Status: status}); err != nil {
		slog.Warn("automations: note a run", "automation", r.auto.ID, "error", err)
	}
	if status == jobs.Failed {
		a := r.auto
		r.h.authz.publish(events.Event{
			Type: events.AutomationFailed, WorkspaceID: a.WorkspaceID, Severity: events.Warning,
			Title: "Automation " + a.Name + " failed", Text: reason,
			URL:     r.h.authz.link("/automations/" + a.ID.String() + "?run=" + r.run.ID.String()),
			Subject: events.Subject{Kind: events.SubjectAutomation, ID: a.ID.String(), Name: a.Name},
			Data:    map[string]any{"run_id": r.run.ID.String(), "trigger": r.run.TriggerKind, "error": reason},
			Origin:  events.FromAutomation(a.ID),
		})
	}
}

func (r *automationRun) begin(i int) {
	r.mu.Lock()
	now := time.Now()
	r.steps[i].Status, r.steps[i].StartedAt = "running", &now
	r.mu.Unlock()
	r.save()
}

func (r *automationRun) end(ctx context.Context, i int, err error) {
	r.mu.Lock()
	now := time.Now()
	s := &r.steps[i]
	s.FinishedAt = &now
	switch {
	case err != nil && ctx.Err() != nil:
		s.Status = "canceled"
	case err != nil:
		s.Status, s.Error = "failed", problemText(jobError(err))
		r.t.Logf("Step %d (%s): %s", i+1, s.Label, s.Error)
	default:
		s.Status = "succeeded"
		r.t.Logf("Step %d (%s): done", i+1, s.Label)
	}
	s.Output = capText(s.Output, automationStepOutput)
	r.mu.Unlock()
	r.save()
}

func (r *automationRun) setOutput(i int, out string) {
	r.mu.Lock()
	r.steps[i].Output = capText(out, automationStepOutput)
	r.mu.Unlock()
}

func (r *automationRun) setTargets(i int, ts []AutomationStepTarget) {
	r.mu.Lock()
	r.steps[i].Targets = ts
	r.mu.Unlock()
	r.save()
}

func (r *automationRun) setLink(i int, l AutomationStepLink) {
	r.mu.Lock()
	r.steps[i].Link = &l
	r.mu.Unlock()
	r.save()
}

func capText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "\n… (cut)"
}

// mayRun re-checks, as the person it runs as, everything its steps use that
// is known before the event: chosen servers, the script, the cron job, the
// channels. A failure is a problem with the automation: nothing runs.
func (h *automationHandler) mayRun(ctx context.Context, a sqlc.Automation, acts []storedAction, acc *auth.Access, who string) error {
	ws := a.WorkspaceID
	for i, act := range acts {
		step := fmt.Sprintf("Step %d: ", i+1)
		if act.On == "servers" {
			need := stepNeed(act.Kind)
			for _, raw := range act.ServerIDs {
				id, _ := uuid.Parse(raw)
				sws, err := h.q.GetServerWorkspace(ctx, id)
				if err != nil || sws != ws {
					return errors.New(step + "a server it acts on was deleted or moved. Edit the automation to choose another.")
				}
				if acc.ServerLevel(ws, id) < need {
					name := raw
					if s, err := h.q.GetServer(ctx, id); err == nil {
						name = s.Name
					}
					return fmt.Errorf("%s%s no longer has %s access to %s. Someone with access should open the automation and save it.", step, who, need, name)
				}
			}
		}
		switch act.Kind {
		case "script":
			if act.ScriptID != "" {
				s, err := h.q.GetScript(ctx, uuid.MustParse(act.ScriptID))
				if err != nil || s.WorkspaceID != ws {
					return errors.New(step + "its script was deleted. Edit the automation to choose another.")
				}
			}
		case "cronjob":
			s, err := h.q.GetSchedule(ctx, uuid.MustParse(act.ScheduleID))
			if err != nil || s.WorkspaceID != ws {
				return errors.New(step + "its cron job was deleted. Edit the automation to choose another.")
			}
			if acc.WorkspaceLevel(ws) < auth.Engineer {
				return fmt.Errorf("%s%s no longer has Engineer access to the workspace, which running a cron job from an automation needs.", step, who)
			}
		case "notify":
			for _, raw := range act.ChannelIDs {
				c, err := h.q.GetNotificationChannel(ctx, uuid.MustParse(raw))
				if err != nil || c.WorkspaceID != ws {
					return errors.New(step + "a channel it sends to was deleted. Edit the automation to choose another.")
				}
			}
		}
	}
	if acc.WorkspaceLevel(ws) < auth.Viewer {
		return fmt.Errorf("%s no longer has access to the workspace.", who)
	}
	return nil
}

// ---- Steps ----

func (r *automationRun) step(ctx context.Context, i int, act storedAction) error {
	switch act.Kind {
	case "notify":
		return r.notify(ctx, i, act)
	case "webhook":
		return r.webhook(ctx, i, act)
	case "script":
		return r.script(ctx, i, act)
	case "service":
		return r.service(ctx, i, act)
	case "cronjob":
		return r.cronjob(ctx, i, act)
	case "check":
		return r.check(ctx, i, act)
	case "wait":
		select {
		case <-time.After(time.Duration(act.Seconds) * time.Second):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return fmt.Errorf("Unknown kind of step %q.", act.Kind)
}

var errNoServer = errors.New("This event didn't happen on a server.")

// servers is where a script/service/check step acts, as (id, name) pairs.
func (h *automationHandler) stepServers(ctx context.Context, ws uuid.UUID, act storedAction, e events.Event) ([]sqlc.Server, error) {
	var ids []uuid.UUID
	if act.On == "servers" {
		for _, raw := range act.ServerIDs {
			id, err := uuid.Parse(raw)
			if err == nil {
				ids = append(ids, id)
			}
		}
	} else {
		if e.ServerID == nil {
			return nil, errNoServer
		}
		ids = []uuid.UUID{*e.ServerID}
	}
	out := make([]sqlc.Server, 0, len(ids))
	for _, id := range ids {
		s, err := h.q.GetServer(ctx, id)
		if err != nil || s.WorkspaceID != ws {
			return nil, errors.New("A server it acts on was deleted or isn't in the automation's workspace.")
		}
		out = append(out, s)
	}
	return out, nil
}

func severityEvent(sev string) string {
	switch sev {
	case events.Critical:
		return notify.EventDown
	case events.Warning:
		return notify.EventDegraded
	}
	return ""
}

func (r *automationRun) notify(ctx context.Context, i int, act storedAction) error {
	if r.h.up == nil {
		return errors.New("Notifications aren't set up.")
	}
	msg := notify.Message{
		Event: severityEvent(r.vars.Event.Severity),
		Title: renderTemplate(cmpOr(act.Title, "{{event.title}}"), r.vars),
		Text:  renderTemplate(cmpOr(act.Text, "{{event.text}}"), r.vars),
		URL:   cmpOr(r.vars.Event.URL, r.vars.RunURL), At: time.Now(),
		Data: map[string]any{
			"automation_id": r.auto.ID.String(), "automation_name": r.auto.Name, "run_id": r.run.ID.String(),
			"event": PanelEvent(r.vars.Event),
		},
	}
	targets := []AutomationStepTarget{}
	failed := []string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, raw := range act.ChannelIDs {
		c, err := r.h.q.GetNotificationChannel(ctx, uuid.MustParse(raw))
		if err != nil || c.WorkspaceID != r.auto.WorkspaceID {
			mu.Lock()
			targets = append(targets, AutomationStepTarget{ID: raw, Name: raw, Status: "failed", Error: "The channel was deleted."})
			failed = append(failed, raw)
			mu.Unlock()
			continue
		}
		if !c.Enabled {
			mu.Lock()
			targets = append(targets, AutomationStepTarget{ID: raw, Name: c.Name, Status: "skipped", Error: "The channel is turned off."})
			mu.Unlock()
			continue
		}
		wg.Go(func() {
			ch, err := r.h.up.sendable(c)
			if err == nil {
				sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				err = notify.Send(sctx, ch, msg)
				cancel()
			}
			tg := AutomationStepTarget{ID: c.ID.String(), Name: c.Name, Status: "succeeded"}
			if err != nil {
				tg.Status, tg.Error = "failed", err.Error()
			}
			mu.Lock()
			targets = append(targets, tg)
			if err != nil {
				failed = append(failed, c.Name)
			}
			mu.Unlock()
		})
	}
	wg.Wait()
	r.setOutput(i, msg.Title+"\n"+msg.Text)
	r.setTargets(i, targets)
	if len(failed) > 0 {
		return fmt.Errorf("Couldn't send to %s.", strings.Join(failed, ", "))
	}
	return nil
}

func (r *automationRun) webhook(ctx context.Context, i int, act storedAction) error {
	body := ""
	if act.Method != http.MethodGet {
		if strings.TrimSpace(act.Body) == "" {
			body = r.vars.eventJSON()
		} else {
			body = renderTemplate(act.Body, r.vars)
		}
	}
	ctx2, cancel := context.WithTimeout(ctx, webhookTimeout)
	defer cancel()
	var rd io.Reader
	if body != "" {
		rd = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequestWithContext(ctx2, cmpOr(act.Method, http.MethodPost), act.URL, rd)
	if err != nil {
		return err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", webhookUserAgent)
	for k, v := range r.h.headersOf(act) {
		req.Header.Set(k, renderTemplate(v, r.vars))
	}
	req.Header.Set("X-Morche-Event", r.vars.Event.Type)
	req.Header.Set("X-Morche-Automation", r.auto.ID.String())
	req.Header.Set("X-Morche-Run", r.run.ID.String())
	resp, err := r.h.client(act.AllowInternal).Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		var blocked *dbmon.BlockedError
		if errors.As(err, &blocked) {
			err = errors.New(blocked.Error() + " (a system admin can allow private addresses)")
		}
		return err
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, webhookResponseCap))
	r.setOutput(i, fmt.Sprintf("HTTP %d\n%s", resp.StatusCode, strings.ToValidUTF8(string(answer), "�")))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("The address answered HTTP %d.", resp.StatusCode)
	}
	return nil
}

func (r *automationRun) script(ctx context.Context, i int, act storedAction) error {
	h := r.h
	servers, err := h.stepServers(ctx, r.auto.WorkspaceID, act, r.vars.Event)
	if err != nil {
		return err
	}
	b := startScriptRunBody{}
	for _, s := range servers {
		b.ServerIDs = append(b.ServerIDs, s.ID.String())
	}
	if act.ScriptID != "" {
		id := act.ScriptID
		b.ScriptID = &id
	} else {
		b.Name = cmpOr(act.Label, "Automation "+r.auto.Name)
		b.Interpreter, b.Content, b.TimeoutSeconds = act.Interpreter, act.Command, act.TimeoutSeconds
		b.RunAs = "user"
		if act.AsRoot {
			b.RunAs = "root"
		}
	}
	plan, err := h.scripts.plan(ctx, b, r.auto.WorkspaceID)
	if err != nil {
		return fmt.Errorf("Checked as %s: %s", r.who, problemText(jobError(err)))
	}
	// The event goes in as env vars, never into the text.
	if plan.env == nil {
		plan.env = map[string]string{}
	}
	for k, v := range automationEnv(r.vars) {
		plan.env[k] = v
	}
	run, err := h.scripts.create(ctx, plan)
	if err != nil {
		return err
	}
	jobID := r.t.ID
	if err := h.q.SetScriptRunJob(ctx, sqlc.SetScriptRunJobParams{JobID: &jobID, ID: run.ID}); err != nil {
		slog.Warn("automations: link a script run to its job", "run", run.ID, "error", err)
	}
	r.setLink(i, AutomationStepLink{Kind: "script-run", ID: run.ID.String()})
	_, execErr := h.scripts.execute(ctx, r.t, run.ID)
	bg := context.WithoutCancel(ctx)
	targets, _ := h.q.ListScriptRunTargets(bg, run.ID)
	ts := make([]AutomationStepTarget, 0, len(targets))
	per := automationStepOutput / max(1, len(targets))
	var out strings.Builder
	bad := 0
	for _, tg := range targets {
		t := AutomationStepTarget{
			ID: optionalString(tg.ServerID), Name: tg.ServerName, Status: tg.State, ExitCode: tg.ExitCode,
			Output: capText(tg.Output, per), Error: tg.Error,
		}
		if tg.State != jobs.Succeeded {
			bad++
		}
		ts = append(ts, t)
		if len(targets) > 1 {
			fmt.Fprintf(&out, "== %s ==\n", tg.ServerName)
		}
		out.WriteString(capText(tg.Output, per))
		if !strings.HasSuffix(tg.Output, "\n") {
			out.WriteString("\n")
		}
	}
	r.setOutput(i, out.String())
	r.setTargets(i, ts)
	done, err := h.q.GetScriptRun(bg, run.ID)
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case err == nil && done.State == jobs.Succeeded:
		return nil
	case bad > 0:
		return fmt.Errorf("It failed on %d of %d server(s).", bad, len(targets))
	case err == nil && done.Error != "":
		return errors.New(done.Error)
	case execErr != nil:
		return execErr
	}
	return errors.New("It failed.")
}

func optionalString(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func (r *automationRun) service(ctx context.Context, i int, act storedAction) error {
	servers, err := r.h.stepServers(ctx, r.auto.WorkspaceID, act, r.vars.Event)
	if err != nil {
		return err
	}
	unit := renderTemplate(act.Unit, r.vars)
	if !unitRe.MatchString(unit) {
		return fmt.Errorf("%q isn't a service name.", unit)
	}
	ts := make([]AutomationStepTarget, len(servers))
	for j, s := range servers {
		ts[j] = AutomationStepTarget{ID: s.ID.String(), Name: s.Name, Status: "pending"}
	}
	r.setTargets(i, ts)
	bad := 0
	var out strings.Builder
	for j, s := range servers {
		if ctx.Err() != nil {
			ts[j].Status = "canceled"
			continue
		}
		var note string
		var err error
		if r.acc.ServerLevel(r.auto.WorkspaceID, s.ID) < auth.Engineer {
			err = fmt.Errorf("%s doesn't have Engineer access to %s.", r.who, s.Name)
		} else {
			note, err = r.h.servers.serviceAction(ctx, s.ID.String(), unit, act.Action, false, "Automations don't stop protected services.")
		}
		if err != nil {
			bad++
			ts[j].Status, ts[j].Error = "failed", problemText(jobError(err))
			fmt.Fprintf(&out, "%s: %s\n", s.Name, ts[j].Error)
		} else {
			ts[j].Status, ts[j].Output = "succeeded", note
			fmt.Fprintf(&out, "%s: %s\n", s.Name, note)
		}
		r.setTargets(i, ts)
	}
	r.setOutput(i, out.String())
	if bad > 0 {
		if len(servers) == 1 {
			return errors.New(ts[0].Error)
		}
		return fmt.Errorf("It failed on %d of %d servers.", bad, len(servers))
	}
	return nil
}

func (r *automationRun) cronjob(ctx context.Context, i int, act storedAction) error {
	h := r.h
	s, err := h.q.GetSchedule(ctx, uuid.MustParse(act.ScheduleID))
	if err != nil || s.WorkspaceID != r.auto.WorkspaceID {
		return errors.New("The cron job was deleted.")
	}
	if h.schedules == nil {
		return errors.New("Cron jobs aren't set up.")
	}
	run, _, err := h.schedules.start(ctx, s, principalOf(ctx), false)
	if err != nil {
		return err
	}
	r.setLink(i, AutomationStepLink{Kind: "schedule-run", ID: run.ID.String(), ParentID: s.ID.String()})
	if run.State == "skipped" || run.JobID == nil {
		return errors.New("The cron job was still running from before, so it wasn't started again.")
	}
	deadline := time.After(automationCronWait)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	bg := context.WithoutCancel(ctx)
	for {
		select {
		case <-ctx.Done():
			_, _ = h.runner.Cancel(bg, *run.JobID)
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("The cron job ran longer than %s; it goes on without the automation.", automationCronWait)
		case <-tick.C:
		}
		cur, err := h.q.GetScheduleRun(bg, run.ID)
		if err != nil {
			return errors.New("The cron job's run was deleted.")
		}
		if jobs.Active(cur.State) {
			continue
		}
		r.setOutput(i, s.Name+": "+cur.State)
		switch cur.State {
		case jobs.Succeeded:
			return nil
		case "partial":
			return errors.New(cmpOr(cur.Error, "It only partly worked."))
		}
		return errors.New(cmpOr(cur.Error, "It "+cur.State+"."))
	}
}

func (r *automationRun) check(ctx context.Context, i int, act storedAction) error {
	h := r.h
	e := r.vars.Event
	ws := r.auto.WorkspaceID
	if act.On != "servers" && e.ServerID == nil && e.Subject.Kind == events.SubjectMonitor {
		return r.checkMonitor(ctx, i, e.Subject.ID)
	}
	servers, err := h.stepServers(ctx, ws, act, e)
	if errors.Is(err, errNoServer) {
		return errors.New("This event didn't happen on a server or monitor.")
	}
	if err != nil {
		return err
	}
	ts := make([]AutomationStepTarget, len(servers))
	var out strings.Builder
	bad := 0
	for j, s := range servers {
		ts[j] = AutomationStepTarget{ID: s.ID.String(), Name: s.Name}
		if r.acc.ServerLevel(ws, s.ID) < auth.Operator {
			ts[j].Status, ts[j].Error = "failed", fmt.Sprintf("%s doesn't have Operator access to %s.", r.who, s.Name)
			bad++
			continue
		}
		checked, err := h.servers.check(ctx, s)
		if err != nil {
			ts[j].Status, ts[j].Error = "failed", problemText(err)
			bad++
			continue
		}
		said := "online"
		if checked.Status != sshprobe.StatusOnline {
			said = strings.ToLower(statusText(checked.Status))
			if checked.StatusMessage != "" {
				said += " (" + checked.StatusMessage + ")"
			}
		}
		ts[j].Status, ts[j].Output = "succeeded", said
		fmt.Fprintf(&out, "%s: %s\n", s.Name, said)
	}
	r.setOutput(i, out.String())
	r.setTargets(i, ts)
	if bad > 0 {
		return errors.New(ts[slices.IndexFunc(ts, func(t AutomationStepTarget) bool { return t.Status == "failed" })].Error)
	}
	return nil
}

func (r *automationRun) checkMonitor(ctx context.Context, i int, raw string) error {
	up := r.h.up
	id, err := uuid.Parse(raw)
	if err != nil || up == nil {
		return errors.New("This event's monitor can't be checked.")
	}
	m, err := r.h.q.GetMonitor(ctx, id)
	if err != nil || m.WorkspaceID != r.auto.WorkspaceID {
		return errors.New("The monitor was deleted.")
	}
	if r.acc.WorkspaceLevel(m.WorkspaceID) < auth.Operator {
		return fmt.Errorf("%s doesn't have Operator access to the monitor.", r.who)
	}
	if m.Kind == uptime.Push {
		return errors.New("A push monitor is checked by its heartbeats.")
	}
	if !up.claim(m.ID) {
		return errors.New("A check of this monitor is already running.")
	}
	defer up.unclaim(m.ID)
	res := up.checkMonitor(ctx, m)
	saved := up.apply(context.WithoutCancel(ctx), m, res, time.Now())
	r.setLink(i, AutomationStepLink{Kind: "monitor", ID: m.ID.String()})
	r.setOutput(i, fmt.Sprintf("%s: %s %s", m.Name, saved.Status, res.Message))
	return nil
}

// ---- Dry run ----

// dryRun says what each step would do for e, checked with acc; nothing runs.
func (h *automationHandler) dryRun(ctx context.Context, a sqlc.Automation, acts []storedAction, e events.Event, acc *auth.Access, problem string) AutomationDryRun {
	t := decodeTrigger(a.Trigger)
	out := AutomationDryRun{Event: PanelEvent(e), Problem: problem, Steps: []AutomationDryStep{}}
	switch t.Kind {
	case "event":
		out.Matches = automationMatches(t, e, func() []string {
			if e.ServerID != nil {
				if s, err := h.q.GetServer(ctx, *e.ServerID); err == nil {
					return s.Tags
				}
			}
			return nil
		})
	case "webhook":
		out.Matches = e.Type == events.WebhookReceived
	}
	if out.Matches && a.ID != uuid.Nil {
		if reason, err := h.gate(ctx, a, e.Subject.ID); err == nil {
			out.Gate = reason
		}
	}
	if problem == "" && a.ID != uuid.Nil {
		if err := h.mayRun(ctx, a, acts, acc, "The person it runs as"); err != nil {
			out.Problem = err.Error()
		}
	}
	v := automationVars{Event: e, Automation: a.Name, AutoID: a.ID}
	if e.ServerID != nil {
		if s, err := h.q.GetServer(ctx, *e.ServerID); err == nil && s.WorkspaceID == a.WorkspaceID {
			v.ServerName, v.ServerHost = s.Name, s.Host
		}
	}
	for i, act := range acts {
		d := AutomationDryStep{Index: i, Kind: act.Kind, Label: stepLabel(act.AutomationAction), Servers: []string{}}
		var servers []sqlc.Server
		if act.Kind == "script" || act.Kind == "service" || act.Kind == "check" {
			var err error
			servers, err = h.stepServers(ctx, a.WorkspaceID, act, e)
			if errors.Is(err, errNoServer) && act.Kind == "check" && e.Subject.Kind == events.SubjectMonitor {
				err = nil
			}
			if err != nil {
				d.Problem = err.Error()
			}
			for _, s := range servers {
				d.Servers = append(d.Servers, s.Name)
				if need := stepNeed(act.Kind); acc.ServerLevel(a.WorkspaceID, s.ID) < need && d.Problem == "" {
					d.Problem = "No " + need.String() + " access to " + s.Name + "."
				}
			}
		}
		on := strings.Join(d.Servers, ", ")
		switch act.Kind {
		case "notify":
			d.Title = renderTemplate(cmpOr(act.Title, "{{event.title}}"), v)
			d.Text = renderTemplate(cmpOr(act.Text, "{{event.text}}"), v)
			names := []string{}
			for _, raw := range act.ChannelIDs {
				if c, err := h.q.GetNotificationChannel(ctx, uuid.MustParse(raw)); err == nil {
					names = append(names, c.Name)
				}
			}
			d.Summary = "Send “" + d.Title + "” to " + strings.Join(names, ", ") + "."
		case "webhook":
			if act.Method != http.MethodGet {
				d.Body = renderTemplate(act.Body, v)
				if strings.TrimSpace(act.Body) == "" {
					d.Body = v.eventJSON()
				}
			}
			d.Summary = cmpOr(act.Method, "POST") + " " + act.URL + "."
		case "script":
			d.Env = automationEnv(v)
			what := "the command"
			if act.ScriptID != "" {
				what = "the script"
				if s, err := h.q.GetScript(ctx, uuid.MustParse(act.ScriptID)); err == nil {
					what = s.Name
				}
			}
			d.Summary = "Run " + what + " on " + cmpOr(on, "the event's server") + "."
		case "service":
			d.Unit = renderTemplate(act.Unit, v)
			if !unitRe.MatchString(d.Unit) && d.Problem == "" {
				d.Problem = fmt.Sprintf("%q isn't a service name.", d.Unit)
			}
			d.Summary = strings.ToUpper(act.Action[:1]) + act.Action[1:] + " " + d.Unit + " on " + cmpOr(on, "the event's server") + "."
		case "cronjob":
			name := "the cron job"
			if s, err := h.q.GetSchedule(ctx, uuid.MustParse(act.ScheduleID)); err == nil {
				name = s.Name
			}
			d.Summary = "Run " + name + " now and wait for it."
		case "check":
			if len(servers) == 0 && e.Subject.Kind == events.SubjectMonitor {
				d.Summary = "Check the monitor " + e.Subject.Name + " again."
			} else {
				d.Summary = "Check " + cmpOr(on, "the event's server") + " again."
			}
		case "wait":
			d.Summary = "Wait " + fmtSeconds(int64(act.Seconds)) + "."
		}
		out.Steps = append(out.Steps, d)
	}
	return out
}

// prune keeps 90 days and 500 runs per automation.
func (h *automationHandler) prune(ctx context.Context) {
	h.mu.Lock()
	if time.Since(h.pruned) < time.Hour {
		h.mu.Unlock()
		return
	}
	h.pruned = time.Now()
	h.mu.Unlock()
	if _, err := h.q.PruneAutomationRuns(ctx, sqlc.PruneAutomationRunsParams{
		Before: time.Now().AddDate(0, 0, -automationKeepDays), Keep: automationKeepRuns,
	}); err != nil {
		slog.Warn("automations: prune runs", "error", err)
	}
}
