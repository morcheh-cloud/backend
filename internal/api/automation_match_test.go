package api

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/morche/backend/internal/events"
)

func sampleEvent(t *testing.T, typ string) events.Event {
	t.Helper()
	ct, ok := events.Lookup(typ)
	if !ok {
		t.Fatalf("no %s", typ)
	}
	return ct.Sample
}

func TestRenderTemplate(t *testing.T) {
	e := sampleEvent(t, events.AlertFired)
	e.Data = map[string]any{"value": 93.4, "rule_name": "High CPU", "nested": map[string]any{"a": []any{"x", 2.0}}, "ok": true}
	v := automationVars{Event: e, ServerName: "web-1", ServerHost: "10.0.0.5", Automation: "Fix it"}
	cases := map[string]string{
		"{{event.title}}":                   e.Title,
		"{{ event.type }}/{{severity}}":     events.AlertFired + "/",
		"{{data.value}}%":                   "93.4%",
		"{{data.nested.a.1}}":               "2",
		"{{data.nested.a}}":                 `["x",2]`,
		"{{data.ok}} {{data.missing}}":      "true ",
		"{{server.name}} @ {{server.host}}": "web-1 @ 10.0.0.5",
		"{{subject.name}}":                  "web-1",
		"{{automation.name}}":               "Fix it",
		"no placeholders":                   "no placeholders",
		"{{unknown.thing}}x":                "x",
	}
	for in, want := range cases {
		if got := renderTemplate(in, v); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
	if got := renderTemplate("{{event.json}}", v); !strings.Contains(got, `"type":"alert.fired"`) {
		t.Errorf("event.json = %s", got)
	}
	// Values are substituted once, never evaluated again.
	v.Event.Title = "{{server.name}}"
	if got := renderTemplate("{{event.title}}", v); got != "{{server.name}}" {
		t.Errorf("re-rendered: %q", got)
	}
}

func TestAutomationEnv(t *testing.T) {
	e := sampleEvent(t, events.ServerOffline)
	e.Title = "it's `rm -rf /` $(boom)"
	env := automationEnv(automationVars{Event: e, ServerName: "web-1"})
	if env["MORCHE_EVENT_TITLE"] != e.Title || env["MORCHE_SERVER_NAME"] != "web-1" || env["MORCHE_EVENT_TYPE"] != events.ServerOffline {
		t.Fatalf("%v", env)
	}
	if !strings.Contains(env["MORCHE_EVENT_JSON"], `"type":"server.offline"`) {
		t.Fatal(env["MORCHE_EVENT_JSON"])
	}
	for k := range env {
		if err := checkEnvName("x", k); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
}

func TestAutomationMatches(t *testing.T) {
	server := uuid.New()
	base := func() events.Event {
		e := sampleEvent(t, events.AlertFired)
		e.ServerID = &server
		e.Data = map[string]any{"muted": false}
		return e
	}
	tags := func() []string { return []string{"Prod", "web"} }
	trig := AutomationTrigger{Kind: "event", Events: []string{events.AlertFired}}

	if !automationMatches(trig, base(), tags) {
		t.Fatal("plain match")
	}
	other := base()
	other.Type = events.AlertResolved
	if automationMatches(trig, other, tags) {
		t.Error("other type matched")
	}
	// Loop guard: an event an automation caused never starts one.
	caused := base()
	caused.Origin = events.FromAutomation(uuid.New())
	if automationMatches(trig, caused, tags) {
		t.Error("automation-caused event matched")
	}
	// Muted alerts only with include_muted.
	muted := base()
	muted.Data["muted"] = true
	if automationMatches(trig, muted, tags) {
		t.Error("muted matched")
	}
	withMuted := trig
	withMuted.IncludeMuted = true
	if !automationMatches(withMuted, muted, tags) {
		t.Error("include_muted didn't match")
	}
	// Internal types never.
	internal := AutomationTrigger{Kind: "event", Events: []string{events.AutomationFailed}}
	if automationMatches(internal, sampleEvent(t, events.AutomationFailed), tags) {
		t.Error("internal type matched")
	}
	// Webhook/manual triggers aren't started by events.
	if automationMatches(AutomationTrigger{Kind: "manual", Events: trig.Events}, base(), tags) {
		t.Error("manual matched")
	}

	filtered := func(f AutomationFilter) bool {
		tr := trig
		tr.Filter = f
		return automationMatches(tr, base(), tags)
	}
	for name, c := range map[string]struct {
		f    AutomationFilter
		want bool
	}{
		"server in":      {AutomationFilter{Servers: []string{server.String()}}, true},
		"server out":     {AutomationFilter{Servers: []string{uuid.NewString()}}, false},
		"tag any case":   {AutomationFilter{Tags: []string{"prod"}}, true},
		"tag missing":    {AutomationFilter{Tags: []string{"db"}}, false},
		"severity in":    {AutomationFilter{Severity: []string{"warning", "critical"}}, true},
		"severity out":   {AutomationFilter{Severity: []string{"critical"}}, false},
		"subject in":     {AutomationFilter{Subjects: []string{base().Subject.ID}}, true},
		"subject out":    {AutomationFilter{Subjects: []string{"x"}}, false},
		"match in title": {AutomationFilter{Match: "high cpu"}, true},
		"match not":      {AutomationFilter{Match: "disk"}, false},
		"all together":   {AutomationFilter{Servers: []string{server.String()}, Tags: []string{"web"}, Match: "CPU"}, true},
	} {
		if got := filtered(c.f); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	// A tag filter on an event without a server never matches.
	noServer := base()
	noServer.ServerID = nil
	tr := trig
	tr.Filter.Tags = []string{"web"}
	if automationMatches(tr, noServer, tags) {
		t.Error("tag filter without a server matched")
	}
}

func TestAutomationGate(t *testing.T) {
	now := time.Now()
	long := time.Unix(0, 0)
	if r := automationGate(300, 20, long, 0, 0, now); r != "" {
		t.Errorf("free: %q", r)
	}
	if r := automationGate(300, 20, long, 0, 1, now); !strings.Contains(r, "still going") {
		t.Errorf("active: %q", r)
	}
	if r := automationGate(300, 20, now.Add(-time.Minute), 1, 0, now); !strings.Contains(r, "Cooling down") {
		t.Errorf("cooldown: %q", r)
	}
	if r := automationGate(300, 20, now.Add(-6*time.Minute), 1, 0, now); r != "" {
		t.Errorf("after cooldown: %q", r)
	}
	if r := automationGate(0, 20, now, 1, 0, now); r != "" {
		t.Errorf("no cooldown: %q", r)
	}
	if r := automationGate(0, 3, long, 3, 0, now); !strings.Contains(r, "3 times") {
		t.Errorf("per hour: %q", r)
	}
	if r := automationGate(0, 0, long, 999, 0, now); r != "" {
		t.Errorf("no limit: %q", r)
	}
}

func TestHookLimiter(t *testing.T) {
	l := newHookLimiter(3)
	id, other := uuid.New(), uuid.New()
	now := time.Now()
	for i := range 3 {
		if !l.allow(id, now.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("call %d refused", i)
		}
	}
	if l.allow(id, now.Add(5*time.Second)) {
		t.Fatal("4th call in a minute allowed")
	}
	if !l.allow(other, now) {
		t.Fatal("another automation refused")
	}
	if !l.allow(id, now.Add(61*time.Second)) {
		t.Fatal("not allowed again after a minute")
	}
}
