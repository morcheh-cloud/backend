package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/events"
)

func TestSignWebhook(t *testing.T) {
	body := []byte(`{"id":"x"}`)
	mac := hmac.New(sha256.New, []byte("whsec_k"))
	mac.Write([]byte("1700000000." + string(body)))
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if got := signWebhook("whsec_k", "1700000000", body); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestWebhookWants(t *testing.T) {
	all := sqlc.Webhook{Enabled: true}
	some := sqlc.Webhook{Enabled: true, Events: []string{events.MonitorDown}}
	off := sqlc.Webhook{Events: []string{}}
	down := events.Event{Type: events.MonitorDown}
	muted := events.Event{Type: events.AlertFired, Data: map[string]any{"muted": true}}
	switch {
	case !webhookWants(all, down), !webhookWants(some, down):
		t.Error("should take monitor.down")
	case webhookWants(some, events.Event{Type: events.MonitorUp}):
		t.Error("took a type it didn't pick")
	case webhookWants(off, down):
		t.Error("a hook that's off took it")
	case webhookWants(all, muted):
		t.Error("took a muted alert")
	case !webhookWants(sqlc.Webhook{Enabled: true, IncludeMuted: true}, muted):
		t.Error("include_muted didn't take it")
	case webhookWants(all, events.Event{Type: events.TestPing}):
		t.Error("a test ping went through the bus")
	}
}

func TestWebhookPayload(t *testing.T) {
	s := uuid.New()
	raw, err := webhookPayload(events.Event{ID: uuid.New(), Type: events.ServerOffline, WorkspaceID: uuid.New(), ServerID: &s, Origin: "automation:x"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(raw), &m)
	for _, k := range []string{"id", "type", "at", "workspace_id", "severity", "title", "text", "url", "subject", "server_id", "data"} {
		if _, ok := m[k]; !ok {
			t.Errorf("no %s in %s", k, raw)
		}
	}
	if _, ok := m["origin"]; ok {
		t.Error("origin is internal")
	}
}

func TestWebhookBodyClean(t *testing.T) {
	b := WebhookBody{Name: " Ops ", URL: "https://example.com/hook", Events: []string{events.MonitorDown, events.MonitorDown},
		Headers: map[string]string{"x-token": "", "authorization": "Bearer 1"}}
	hs, err := b.clean(map[string]string{"X-Token": "saved"})
	if err != nil {
		t.Fatal(err)
	}
	if b.Name != "Ops" || len(b.Events) != 1 || hs["X-Token"] != "saved" || hs["Authorization"] != "Bearer 1" {
		t.Fatalf("%+v %v", b, hs)
	}
	for _, bad := range []WebhookBody{
		{Name: "a", URL: "ftp://x"},
		{Name: "a", URL: "https://u:p@x"},
		{Name: "a", URL: "https://x", Events: []string{"nope"}},
		{Name: "a", URL: "https://x", Events: []string{events.TestPing}},
		{Name: "a", URL: "https://x", Headers: map[string]string{"X-Morche-Signature": "1"}},
		{Name: "a", URL: "https://x", Headers: map[string]string{"Host": "1"}},
		{Name: "a", URL: "https://x", Headers: map[string]string{"X-New": ""}},
	} {
		if _, err := bad.clean(nil); err == nil {
			t.Errorf("%+v passed", bad)
		}
	}
	keep := WebhookBody{Name: "a", URL: "https://x"}
	if hs, _ := keep.clean(map[string]string{"A": "1"}); hs["A"] != "1" {
		t.Error("nil headers didn't keep the saved ones")
	}
}
