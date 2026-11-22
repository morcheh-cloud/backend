package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/morche/backend/internal/cache"
	"github.com/morche/backend/internal/config"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/events"
	"github.com/morche/backend/internal/jobs"
	"github.com/morche/backend/internal/secrets"
	"github.com/morche/backend/internal/sshprobe"
)

// autoEnv is env with a running job runner and the automation handler (to
// publish on its bus).
func newAutoEnv(t *testing.T) (*env, *automationHandler) {
	t.Helper()
	url := os.Getenv("MORCHE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("MORCHE_TEST_DATABASE_URL not set; run make test-integration")
	}
	db, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	box, err := secrets.New(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	var h *automationHandler
	testAutomationHook = func(x *automationHandler) { h = x }
	defer func() { testAutomationHook = nil }()
	runner := jobs.New(sqlc.New(db))
	cfg := &config.Config{Env: "test", CORSOrigins: []string{"http://localhost:3200"}}
	r, _ := build(cfg, db, &cache.Cache{}, box, runner)
	if err := runner.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		runner.Close(ctx)
	})
	return &env{db: db, q: sqlc.New(db), box: box, h: r}, h
}

// catcher is an HTTP server that keeps what it was sent.
type catcher struct {
	*httptest.Server
	mu   sync.Mutex
	got  []caught
	code int
}

type caught struct {
	method, path, body string
	header             http.Header
}

func newCatcher(t *testing.T) *catcher {
	c := &catcher{code: http.StatusOK}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.got = append(c.got, caught{r.Method, r.URL.Path, string(b), r.Header.Clone()})
		code := c.code
		c.mu.Unlock()
		w.WriteHeader(code)
		_, _ = w.Write([]byte("thanks"))
	}))
	t.Cleanup(c.Close)
	return c
}

func (c *catcher) all() []caught {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]caught(nil), c.got...)
}

// waitRun waits until the automation has n runs and the newest has ended.
func waitRuns(t *testing.T, c *tclient, auto string, n int) []AutomationRun {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		var list automationRunListBody
		expect(t, c.do(t, http.MethodGet, "/automations/"+auto+"/runs", nil, nil), http.StatusOK, &list)
		if len(list.Items) >= n {
			done := true
			for _, r := range list.Items {
				if r.Status == "queued" || r.Status == "running" {
					done = false
				}
			}
			if done {
				return list.Items
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited for %d runs: %+v", n, list.Items)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestIntegrationAutomationEvent(t *testing.T) {
	e, h := newAutoEnv(t)
	ctx := context.Background()
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	srv := newCatcher(t)

	cfg, _ := json.Marshal(map[string]any{"url": srv.URL + "/notify"})
	ch, err := e.q.CreateNotificationChannel(ctx, sqlc.CreateNotificationChannelParams{
		WorkspaceID: ws, Name: "Ops hook", Kind: "webhook", Config: cfg, Enabled: true, AllowInternal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := e.q.CreateServer(ctx, sqlc.CreateServerParams{
		WorkspaceID: ws, Name: "web-" + suffix(), Host: "10.0.0.5", Port: 22, Username: "ant", AuthMethod: "password", Tags: []string{"prod"},
	})
	if err != nil {
		t.Fatal(err)
	}

	var a Automation
	expect(t, admin.do(t, http.MethodPost, "/workspaces/"+ws.String()+"/automations", map[string]any{
		"name": "Tell ops",
		"trigger": map[string]any{
			"kind": "event", "events": []string{events.AlertFired},
			"filter": map[string]any{"tags": []string{"prod"}, "match": "cpu"},
		},
		"actions": []map[string]any{
			{"kind": "webhook", "url": srv.URL + "/hook", "allow_internal": true,
				"headers": map[string]string{"Authorization": "Bearer {{subject.name}}"},
				"body":    `{"say":"{{event.title}} on {{server.name}}","v":{{data.value}}}`},
			{"kind": "notify", "channel_ids": []string{ch.ID.String()}, "title": "Fired: {{event.title}}"},
		},
	}, nil), http.StatusCreated, &a)
	if a.Actions[0].Headers["Authorization"] != "" || a.Actions[0].ID == "" || a.CooldownSeconds != 300 {
		t.Fatalf("created %+v", a)
	}

	fire := func(mut func(*events.Event)) {
		sid := server.ID
		ev := events.Event{
			Type: events.AlertFired, WorkspaceID: ws, Severity: events.Warning, Title: "High CPU on " + server.Name,
			Subject: events.Subject{Kind: events.SubjectServer, ID: server.ID.String(), Name: server.Name}, ServerID: &sid,
			Data: map[string]any{"value": 93.5, "muted": false},
		}
		if mut != nil {
			mut(&ev)
		}
		h.authz.publish(ev)
	}
	fire(nil)
	runs := waitRuns(t, admin, a.ID, 1)
	r := runs[0]
	if r.Status != "succeeded" || r.TriggerKind != "event" || len(r.Steps) != 2 || r.Steps[0].Status != "succeeded" || r.Steps[1].Status != "succeeded" {
		t.Fatalf("run %+v", r)
	}
	if !strings.HasPrefix(r.Steps[0].Output, "HTTP 200") || len(r.Steps[1].Targets) != 1 || r.Steps[1].Targets[0].Status != "succeeded" {
		t.Fatalf("steps %+v", r.Steps)
	}
	got := srv.all()
	if len(got) != 2 {
		t.Fatalf("sent %d: %+v", len(got), got)
	}
	var hook caught
	var note caught
	for _, g := range got {
		if g.path == "/hook" {
			hook = g
		} else {
			note = g
		}
	}
	if hook.body != `{"say":"High CPU on `+server.Name+` on `+server.Name+`","v":93.5}` ||
		hook.header.Get("Authorization") != "Bearer "+server.Name || hook.header.Get("X-Morche-Automation") != a.ID {
		t.Fatalf("hook got %+v", hook)
	}
	if !strings.Contains(note.body, "Fired: High CPU") {
		t.Fatalf("notify got %s", note.body)
	}

	// Again within the cooldown: a skipped run, nothing sent.
	fire(nil)
	runs = waitRuns(t, admin, a.ID, 2)
	if runs[0].Status != "skipped" || !strings.Contains(runs[0].Reason, "Cooling down") || len(srv.all()) != 2 {
		t.Fatalf("second %+v", runs[0])
	}
	// More within the minute: no more skipped rows.
	fire(nil)
	time.Sleep(300 * time.Millisecond)
	if n := len(waitRuns(t, admin, a.ID, 2)); n != 2 {
		t.Fatalf("%d runs", n)
	}

	// Filters: another tag, another title, muted, caused by an automation:
	// none start it (cooldown aside: a new subject).
	other := uuid.New()
	for _, mut := range []func(*events.Event){
		func(ev *events.Event) { ev.Title = "Disk full"; ev.Subject.ID = other.String() },
		func(ev *events.Event) { ev.Data["muted"] = true; ev.Subject.ID = other.String() },
		func(ev *events.Event) { ev.Origin = events.FromAutomation(uuid.New()); ev.Subject.ID = other.String() },
		func(ev *events.Event) { ev.ServerID = nil; ev.Subject.ID = other.String() },
	} {
		fire(mut)
	}
	time.Sleep(500 * time.Millisecond)
	if n := len(waitRuns(t, admin, a.ID, 2)); n != 2 {
		t.Fatalf("filtered events ran: %d runs", n)
	}

	// The loop guard holds for events an automation's own work causes: a
	// server check done in a step marks the status change it publishes.
	ch2, stop := h.authz.events.Subscribe("test", 10)
	defer stop()
	prev := server
	prev.Status = sshprobe.StatusOnline
	h.servers.publishServerStatus(withOrigin(ctx, events.FromAutomation(uuid.MustParse(a.ID))), prev, sshprobe.Result{Status: sshprobe.StatusUnreachable})
	select {
	case ev := <-ch2:
		if ev.Type != events.ServerOffline || !ev.ByAutomation() {
			t.Fatalf("caused event %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
	}

	// Lists carry the recent runs.
	var list automationListBody
	expect(t, admin.do(t, http.MethodGet, "/workspaces/"+ws.String()+"/automations", nil, nil), http.StatusOK, &list)
	if len(list.Items) != 1 || len(list.Items[0].Recent) != 2 || list.Items[0].LastStatus != "succeeded" || list.Items[0].RunAsName == "" {
		t.Fatalf("list %+v", list.Items)
	}

	// A failing step stops the run and publishes automation.failed (which
	// never starts an automation itself).
	srv.mu.Lock()
	srv.code = http.StatusInternalServerError
	srv.mu.Unlock()
	fails, stopF := h.authz.events.Subscribe("test-fail", 10)
	defer stopF()
	var started AutomationRunStarted
	expect(t, admin.do(t, http.MethodPost, "/automations/"+a.ID+"/run", map[string]any{}, nil), http.StatusAccepted, &started)
	if started.Job == nil || started.Run.TriggerKind != "manual" {
		t.Fatalf("started %+v", started)
	}
	runs = waitRuns(t, admin, a.ID, 3)
	if runs[0].Status != "failed" || runs[0].Steps[0].Status != "failed" || runs[0].Steps[1].Status != "skipped" || !strings.Contains(runs[0].Reason, "HTTP 500") {
		t.Fatalf("failed run %+v", runs[0])
	}
	deadline := time.After(3 * time.Second)
	for found := false; !found; {
		select {
		case ev := <-fails:
			found = ev.Type == events.AutomationFailed && ev.ByAutomation()
		case <-deadline:
			t.Fatal("no automation.failed")
		}
	}
	var one AutomationRun
	expect(t, admin.do(t, http.MethodGet, "/automation-runs/"+runs[0].ID, nil, nil), http.StatusOK, &one)
	if one.ID != runs[0].ID || one.AutomationName != "Tell ops" {
		t.Fatalf("get run %+v", one)
	}
}

func TestIntegrationAutomationAccess(t *testing.T) {
	e, _ := newAutoEnv(t)
	ctx := context.Background()
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	viewer, op := e.user(t, "member"), e.user(t, "member")
	e.grant(t, viewer, "viewer", grantTarget{Workspace: &ws})
	e.grant(t, op, "operator", grantTarget{Workspace: &ws})
	server, err := e.q.CreateServer(ctx, sqlc.CreateServerParams{
		WorkspaceID: ws, Name: "db-" + suffix(), Host: "10.0.0.6", Port: 22, Username: "ant", AuthMethod: "password", Tags: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"name":    "Restart it",
		"trigger": map[string]any{"kind": "event", "events": []string{events.ServerOffline}},
		"actions": []map[string]any{
			{"kind": "service", "unit": "{{data.unit}}", "action": "restart"},
			{"kind": "webhook", "url": "https://example.com/x", "headers": map[string]string{"X-Key": "s3cret"}},
		},
	}
	expect(t, viewer.do(t, http.MethodPost, "/workspaces/"+ws.String()+"/automations", body, nil), http.StatusForbidden, nil)
	expect(t, op.do(t, http.MethodPost, "/workspaces/"+ws.String()+"/automations", body, nil), http.StatusForbidden, nil)
	var a Automation
	expect(t, admin.do(t, http.MethodPost, "/workspaces/"+ws.String()+"/automations", body, nil), http.StatusCreated, &a)

	// A Viewer reads it, without the header's value.
	w := viewer.do(t, http.MethodGet, "/automations/"+a.ID, nil, nil)
	expect(t, w, http.StatusOK, nil)
	if strings.Contains(w.Body.String(), "s3cret") {
		t.Fatal("header value shown")
	}
	expect(t, viewer.do(t, http.MethodPost, "/automations/"+a.ID+"/run", map[string]any{}, nil), http.StatusForbidden, nil)
	// An Operator may run it, but not aim its Engineer step at a server.
	expect(t, op.do(t, http.MethodPost, "/automations/"+a.ID+"/run", map[string]any{
		"event": map[string]any{"server_id": server.ID.String()},
	}, nil), http.StatusForbidden, nil)

	// Saving keeps a blank header value; private addresses are admin-only.
	body["actions"] = []map[string]any{
		{"id": a.Actions[1].ID, "kind": "webhook", "url": "https://example.com/x", "headers": map[string]string{"X-Key": ""}},
	}
	expect(t, admin.do(t, http.MethodPut, "/automations/"+a.ID, body, nil), http.StatusOK, nil)
	stored, _ := e.q.GetAutomation(ctx, uuid.MustParse(a.ID))
	h := &automationHandler{box: e.box}
	if got := h.headersOf(decodeActions(stored.Actions)[0]); got["X-Key"] != "s3cret" {
		t.Fatalf("kept headers %v", got)
	}
	// Pointed elsewhere, a blank value keeps nothing (the secret stays home).
	body["actions"] = []map[string]any{
		{"id": a.Actions[1].ID, "kind": "webhook", "url": "https://evil.example.com/x", "headers": map[string]string{"X-Key": ""}},
	}
	expect(t, admin.do(t, http.MethodPut, "/automations/"+a.ID, body, nil), http.StatusUnprocessableEntity, nil)
	eng := e.user(t, "member")
	e.grant(t, eng, "engineer", grantTarget{Workspace: &ws})
	body["actions"] = []map[string]any{{"kind": "webhook", "url": "http://127.0.0.1:9/x", "allow_internal": true}}
	expect(t, eng.do(t, http.MethodPut, "/automations/"+a.ID, body, nil), http.StatusUnprocessableEntity, nil)
	// Internal event types can't start one.
	body["trigger"] = map[string]any{"kind": "event", "events": []string{events.AutomationFailed}}
	body["actions"] = []map[string]any{{"kind": "wait", "seconds": 1}}
	expect(t, eng.do(t, http.MethodPut, "/automations/"+a.ID, body, nil), http.StatusUnprocessableEntity, nil)
}

func TestIntegrationAutomationDryRunAndHook(t *testing.T) {
	e, _ := newAutoEnv(t)
	ctx := context.Background()
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	server, err := e.q.CreateServer(ctx, sqlc.CreateServerParams{
		WorkspaceID: ws, Name: "app-" + suffix(), Host: "10.0.0.7", Port: 22, Username: "ant", AuthMethod: "password", Tags: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	var a Automation
	expect(t, admin.do(t, http.MethodPost, "/workspaces/"+ws.String()+"/automations", map[string]any{
		"name":    "Fix nginx",
		"trigger": map[string]any{"kind": "event", "events": []string{events.ServerOffline}},
		"actions": []map[string]any{
			{"kind": "script", "command": "echo \"$MORCHE_EVENT_TITLE\""},
			{"kind": "service", "unit": "nginx", "action": "restart", "on": "servers", "server_ids": []string{server.ID.String()}},
			{"kind": "wait", "seconds": 5},
		},
	}, nil), http.StatusCreated, &a)

	var res AutomationTestResult
	expect(t, admin.do(t, http.MethodPost, "/automations/"+a.ID+"/test", map[string]any{
		"dry_run": true, "event": map[string]any{"server_id": server.ID.String(), "title": "app is offline"},
	}, nil), http.StatusOK, &res)
	d := res.DryRun
	if d == nil || res.Run != nil || !d.Matches || d.Problem != "" || len(d.Steps) != 3 {
		t.Fatalf("dry run %+v", res)
	}
	if d.Steps[0].Env["MORCHE_EVENT_TITLE"] != "app is offline" || d.Steps[0].Servers[0] != server.Name ||
		d.Steps[1].Unit != "nginx" || d.Steps[1].Servers[0] != server.Name || d.Steps[2].Summary != "Wait 5 s." {
		t.Fatalf("steps %+v", d.Steps)
	}
	// Without a server, the event's-server step says so.
	expect(t, admin.do(t, http.MethodPost, "/automations/"+a.ID+"/test", map[string]any{"dry_run": true}, nil), http.StatusOK, &res)
	if res.DryRun.Steps[0].Problem != errNoServer.Error() {
		t.Fatalf("no server %+v", res.DryRun.Steps[0])
	}
	var list automationRunListBody
	expect(t, admin.do(t, http.MethodGet, "/automations/"+a.ID+"/runs", nil, nil), http.StatusOK, &list)
	if list.Total != 0 {
		t.Fatalf("a dry run made a run: %+v", list)
	}
	// The editor's preview checks an unsaved body.
	expect(t, admin.do(t, http.MethodPost, "/workspaces/"+ws.String()+"/automations/preview", map[string]any{
		"automation": map[string]any{"name": "x", "trigger": map[string]any{"kind": "manual"}, "actions": []map[string]any{{"kind": "wait"}}},
	}, nil), http.StatusUnprocessableEntity, nil)

	// Incoming hook.
	var hk Automation
	expect(t, admin.do(t, http.MethodPost, "/workspaces/"+ws.String()+"/automations", map[string]any{
		"name": "From CI", "trigger": map[string]any{"kind": "webhook"}, "cooldown_seconds": 0,
		"actions": []map[string]any{{"kind": "wait", "seconds": 1}},
	}, nil), http.StatusCreated, &hk)
	var made AutomationHook
	expect(t, admin.do(t, http.MethodPost, "/automations/"+hk.ID+"/hook", nil, nil), http.StatusOK, &made)
	if !strings.HasPrefix(made.Path, automationHookPrefix+"mah_") {
		t.Fatalf("hook %+v", made)
	}
	anon := &tclient{e: e}
	w := anon.raw(t, http.MethodPost, made.Path, "application/json", []byte(`{"title":"Deployed","branch":"main"}`), nil)
	expect(t, w, http.StatusAccepted, nil)
	runs := waitRuns(t, admin, hk.ID, 1)
	if runs[0].TriggerKind != "webhook" || runs[0].Event.Type != events.WebhookReceived || runs[0].Event.Title != "Deployed" ||
		runs[0].Event.Data["branch"] != "main" || runs[0].Status != "succeeded" {
		t.Fatalf("hook run %+v", runs[0])
	}
	expect(t, anon.raw(t, http.MethodPost, automationHookPrefix+"mah_nope", "application/json", nil, nil), http.StatusNotFound, nil)
	// A new URL ends the old one.
	expect(t, admin.do(t, http.MethodDelete, "/automations/"+hk.ID+"/hook", nil, nil), http.StatusNoContent, nil)
	expect(t, anon.raw(t, http.MethodPost, made.Path, "application/json", nil, nil), http.StatusNotFound, nil)
}

// Events about different subjects each get their run, even while one goes.
func TestIntegrationAutomationSubjects(t *testing.T) {
	e, h := newAutoEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	var a Automation
	expect(t, admin.do(t, http.MethodPost, "/workspaces/"+ws.String()+"/automations", map[string]any{
		"name":    "Slow",
		"trigger": map[string]any{"kind": "event", "events": []string{events.MonitorDown}},
		"actions": []map[string]any{{"kind": "wait", "seconds": 2}},
	}, nil), http.StatusCreated, &a)
	for _, s := range []string{"m1", "m2", "m1"} {
		h.authz.publish(events.Event{
			Type: events.MonitorDown, WorkspaceID: ws, Severity: events.Critical, Title: s + " is down",
			Subject: events.Subject{Kind: events.SubjectMonitor, ID: s, Name: s},
		})
		time.Sleep(200 * time.Millisecond)
	}
	runs := waitRuns(t, admin, a.ID, 3)
	got := map[string]int{}
	for _, r := range runs {
		got[r.Event.Subject.ID+"/"+r.Status]++
	}
	if got["m1/succeeded"] != 1 || got["m2/succeeded"] != 1 || got["m1/skipped"] != 1 {
		t.Fatalf("runs %v", got)
	}
	// While it runs, Run now waits its turn.
	var started AutomationRunStarted
	expect(t, admin.do(t, http.MethodPost, "/automations/"+a.ID+"/run", map[string]any{}, nil), http.StatusAccepted, &started)
	expect(t, admin.do(t, http.MethodPost, "/automations/"+a.ID+"/run", map[string]any{}, nil), http.StatusConflict, nil)
	waitRuns(t, admin, a.ID, 4)
}
