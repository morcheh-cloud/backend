package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/events"
)

// bearer sends a request with an API token instead of a session cookie.
func (e *env) bearer(t *testing.T, token, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func makeToken(t *testing.T, c *tclient, body map[string]any) ApiTokenCreated {
	t.Helper()
	var out ApiTokenCreated
	expect(t, c.do(t, http.MethodPost, "/auth/tokens", body, nil), http.StatusCreated, &out)
	if !strings.HasPrefix(out.Secret, "morche_") || out.Token.Prefix != out.Secret[7:15] {
		t.Fatalf("token %+v", out)
	}
	return out
}

func TestIntegrationAPITokens(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	c := e.user(t, "member")
	e.grant(t, c, "viewer", grantTarget{Workspace: &ws})

	tok := makeToken(t, c, map[string]any{"name": "ci"})
	var me PanelUser
	expect(t, e.bearer(t, tok.Secret, http.MethodGet, "/auth/me", nil), http.StatusOK, &me)
	if me.ID != c.user.ID.String() {
		t.Fatalf("me = %+v", me)
	}
	expect(t, e.bearer(t, tok.Secret, http.MethodGet, "/servers", nil), http.StatusOK, nil)
	expect(t, e.bearer(t, tok.Secret, http.MethodGet, "/workspaces/"+ws.String()+"/schedules", nil), http.StatusOK, nil)
	// A token can't make tokens, nor touch the account or sessions.
	for _, r := range []struct{ method, path string }{
		{http.MethodPost, "/auth/tokens"}, {http.MethodGet, "/auth/tokens"},
		{http.MethodGet, "/auth/sessions"}, {http.MethodPost, "/auth/logout"},
	} {
		w := e.bearer(t, tok.Secret, r.method, r.path, map[string]any{"name": "x"})
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), tokenRefusal) {
			t.Errorf("%s %s = %d %s", r.method, r.path, w.Code, w.Body.String())
		}
	}

	// Read only: GETs work, anything else doesn't.
	ro := makeToken(t, c, map[string]any{"name": "read", "read_only": true, "expires_in_days": 30})
	if ro.Token.ExpiresAt == nil || !ro.Token.ReadOnly {
		t.Fatalf("read-only token %+v", ro.Token)
	}
	expect(t, e.bearer(t, ro.Secret, http.MethodGet, "/servers", nil), http.StatusOK, nil)
	w := e.bearer(t, ro.Secret, http.MethodPost, "/servers/test-connection", map[string]any{})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), readOnlyRefuse) {
		t.Fatalf("read-only POST = %d %s", w.Code, w.Body.String())
	}

	// The list shows them, never the secret; last use is noted.
	var list ApiTokenList
	w = c.do(t, http.MethodGet, "/auth/tokens", nil, nil)
	expect(t, w, http.StatusOK, &list.Body)
	if len(list.Body.Items) != 2 || strings.Contains(w.Body.String(), tok.Secret) {
		t.Fatalf("list %s", w.Body.String())
	}
	for _, it := range list.Body.Items {
		if it.ID == tok.Token.ID && it.LastUsedAt == nil {
			t.Error("last use not noted")
		}
	}

	// Someone else can't revoke it.
	other := e.user(t, "member")
	expect(t, other.do(t, http.MethodDelete, "/auth/tokens/"+tok.Token.ID, nil, nil), http.StatusNotFound, nil)

	// A cookie wins over a token: a bad token next to a good session is fine.
	r := httptest.NewRequest(http.MethodGet, "/servers", nil)
	r.Header.Set("Authorization", "Bearer morche_"+strings.Repeat("A", 40))
	expect(t, c.send(t, r, nil), http.StatusOK, nil)
	// Something that isn't a Morche token is never looked up.
	expect(t, e.bearer(t, "not-a-token", http.MethodGet, "/servers", nil), http.StatusUnauthorized, nil)

	// Revoked: 401.
	expect(t, c.do(t, http.MethodDelete, "/auth/tokens/"+tok.Token.ID, nil, nil), http.StatusNoContent, nil)
	expect(t, e.bearer(t, tok.Secret, http.MethodGet, "/servers", nil), http.StatusUnauthorized, nil)

	// Expired: 401.
	secret, hash, _ := newAPIToken()
	past := time.Now().Add(-time.Hour)
	if _, err := e.q.CreateApiToken(context.Background(), sqlc.CreateApiTokenParams{
		UserID: c.user.ID, Name: "old", Prefix: tokenShown(secret), TokenHash: hash, ExpiresAt: &past,
	}); err != nil {
		t.Fatal(err)
	}
	expect(t, e.bearer(t, secret, http.MethodGet, "/servers", nil), http.StatusUnauthorized, nil)

	// A blocked user's tokens stop.
	if _, err := e.db.Exec(context.Background(), `UPDATE users SET status = 'blocked' WHERE id = $1`, c.user.ID); err != nil {
		t.Fatal(err)
	}
	expect(t, e.bearer(t, ro.Secret, http.MethodGet, "/servers", nil), http.StatusUnauthorized, nil)
}

func TestIntegrationAPITokenAdmin(t *testing.T) {
	e := newEnv(t)
	admin, c := e.user(t, "admin"), e.user(t, "member")
	tok := makeToken(t, c, map[string]any{"name": "ci"})
	var list ApiTokenList
	expect(t, admin.do(t, http.MethodGet, "/admin/users/"+c.user.ID.String()+"/tokens", nil, nil), http.StatusOK, &list.Body)
	if len(list.Body.Items) != 1 {
		t.Fatalf("%+v", list.Body)
	}
	// An admin's token can do admin things, but not revoke tokens.
	at := makeToken(t, admin, map[string]any{"name": "admin"})
	expect(t, e.bearer(t, at.Secret, http.MethodGet, "/admin/users", nil), http.StatusOK, nil)
	expect(t, e.bearer(t, at.Secret, http.MethodDelete, "/admin/tokens/"+tok.Token.ID, nil), http.StatusForbidden, nil)
	expect(t, admin.do(t, http.MethodDelete, "/admin/tokens/"+tok.Token.ID, nil, nil), http.StatusNoContent, nil)
	expect(t, e.bearer(t, tok.Secret, http.MethodGet, "/auth/me", nil), http.StatusUnauthorized, nil)
}

// hookServer records what it's sent and answers status.
type hookServer struct {
	*httptest.Server
	mu     sync.Mutex
	got    []*http.Request
	bodies [][]byte
	status int
}

func newHookServer(t *testing.T, status int) *hookServer {
	h := &hookServer{status: status}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.got, h.bodies = append(h.got, r), append(h.bodies, b)
		h.mu.Unlock()
		w.WriteHeader(h.status)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(h.Close)
	return h
}

func TestIntegrationWebhookSignedDelivery(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin, owner := e.user(t, "admin"), e.user(t, "member")
	e.grant(t, owner, "owner", grantTarget{Workspace: &ws})
	srv := newHookServer(t, http.StatusOK)
	body := map[string]any{"name": "ops", "url": srv.URL + "/in", "allow_internal": true, "headers": map[string]string{"X-Token": "t1"}}

	// Only an admin may point it at a private address.
	expect422At(t, owner, http.MethodPost, "/workspaces/"+ws.String()+"/webhooks", body, ws, "body.allow_internal")
	var made WebhookWithSecret
	expect(t, admin.do(t, http.MethodPost, "/workspaces/"+ws.String()+"/webhooks", body, &ws), http.StatusCreated, &made)
	if !strings.HasPrefix(made.Secret, "whsec_") || !made.Webhook.HasSecret || len(made.Webhook.HeaderNames) != 1 {
		t.Fatalf("made %+v", made)
	}
	// The Owner can keep it as it is, but not point it elsewhere.
	keep := map[string]any{"name": "ops 2", "url": srv.URL + "/in", "allow_internal": true}
	expect(t, owner.do(t, http.MethodPut, "/webhooks/"+made.Webhook.ID, keep, &ws), http.StatusOK, nil)
	keep["url"] = srv.URL + "/other"
	expect422At(t, owner, http.MethodPut, "/webhooks/"+made.Webhook.ID, keep, ws, "body.allow_internal")
	// A viewer doesn't see it.
	viewer := e.user(t, "member")
	e.grant(t, viewer, "viewer", grantTarget{Workspace: &ws})
	expect(t, viewer.do(t, http.MethodGet, "/webhooks/"+made.Webhook.ID, nil, &ws), http.StatusForbidden, nil)

	var del WebhookDelivery
	expect(t, owner.do(t, http.MethodPost, "/webhooks/"+made.Webhook.ID+"/test", nil, &ws), http.StatusOK, &del)
	if del.Status != "delivered" || del.Attempt != 1 || del.HTTPStatus == nil || *del.HTTPStatus != 200 {
		t.Fatalf("delivery %+v", del)
	}
	srv.mu.Lock()
	r, raw := srv.got[0], srv.bodies[0]
	srv.mu.Unlock()
	ts := r.Header.Get("X-Morche-Timestamp")
	if r.Header.Get("X-Morche-Signature") != signWebhook(made.Secret, ts, raw) {
		t.Fatal("signature doesn't match")
	}
	if r.Header.Get("X-Morche-Event") != events.TestPing || r.Header.Get("X-Morche-Delivery") != del.ID ||
		r.Header.Get("User-Agent") != webhookUserAgent || r.Header.Get("X-Token") != "t1" || r.URL.Path != "/in" {
		t.Fatalf("headers %v", r.Header)
	}
	var got map[string]any
	_ = json.Unmarshal(raw, &got)
	if got["type"] != events.TestPing || got["workspace_id"] != ws.String() {
		t.Fatalf("body %s", raw)
	}

	// Rotate: the old secret no longer signs.
	var rot WebhookWithSecret
	expect(t, owner.do(t, http.MethodPost, "/webhooks/"+made.Webhook.ID+"/secret", nil, &ws), http.StatusOK, &rot)
	if rot.Secret == made.Secret {
		t.Fatal("same secret")
	}
	var again WebhookDelivery
	expect(t, owner.do(t, http.MethodPost, "/webhook-deliveries/"+del.ID+"/redeliver", nil, &ws), http.StatusOK, &again)
	if again.RedeliveryOf != del.ID || again.Status != "delivered" {
		t.Fatalf("redelivery %+v", again)
	}
	srv.mu.Lock()
	r2, raw2 := srv.got[1], srv.bodies[1]
	srv.mu.Unlock()
	if r2.Header.Get("X-Morche-Signature") != signWebhook(rot.Secret, r2.Header.Get("X-Morche-Timestamp"), raw2) || !bytes.Equal(raw, raw2) {
		t.Fatal("redelivery not signed with the new secret, or a different body")
	}

	var list struct {
		Items []WebhookDelivery `json:"items"`
		Total int64             `json:"total"`
	}
	expect(t, owner.do(t, http.MethodGet, "/webhooks/"+made.Webhook.ID+"/deliveries", nil, &ws), http.StatusOK, &list)
	if list.Total != 2 {
		t.Fatalf("deliveries %+v", list)
	}
	// Without allow_internal the same address is refused when sending.
	expect(t, admin.do(t, http.MethodPut, "/webhooks/"+made.Webhook.ID, map[string]any{"name": "ops", "url": srv.URL + "/in"}, &ws), http.StatusOK, nil)
	expect(t, owner.do(t, http.MethodPost, "/webhooks/"+made.Webhook.ID+"/test", nil, &ws), http.StatusOK, &del)
	if del.Status != "failed" || !strings.Contains(del.Error, "admin") {
		t.Fatalf("private address went through: %+v", del)
	}
}

func TestIntegrationWebhookRetries(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	srv := newHookServer(t, http.StatusInternalServerError)
	var made WebhookWithSecret
	expect(t, admin.do(t, http.MethodPost, "/workspaces/"+ws.String()+"/webhooks",
		map[string]any{"name": "down", "url": srv.URL, "allow_internal": true, "events": []string{events.MonitorDown}}, &ws),
		http.StatusCreated, &made)
	hook := uuid.MustParse(made.Webhook.ID)
	ctx := context.Background()
	d := newWebhookDispatcher(e.q, e.box)

	// Only the types it picked, never muted alerts.
	if n := d.enqueue(ctx, events.Event{ID: uuid.New(), Type: events.MonitorUp, WorkspaceID: ws}); n != 0 {
		t.Fatalf("queued %d for a type it didn't pick", n)
	}
	if n := d.enqueue(ctx, events.Event{ID: uuid.New(), Type: events.MonitorDown, WorkspaceID: ws, At: time.Now()}); n != 1 {
		t.Fatalf("queued %d", n)
	}
	rows, err := e.q.ListWebhookDeliveries(ctx, sqlc.ListWebhookDeliveriesParams{WebhookID: hook, Limit: 10})
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	id := rows[0].ID

	// step makes the delivery due and waits for one more attempt (by this
	// dispatcher or the router's own loop).
	step := func(want int32) sqlc.WebhookDelivery {
		t.Helper()
		if _, err := e.db.Exec(ctx, `UPDATE webhook_deliveries SET next_try_at = now() - interval '1 second' WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(15 * time.Second)
		for {
			d.deliverDue(ctx)
			got, err := e.q.GetWebhookDelivery(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if got.Attempt == want {
				return got
			}
			if time.Now().After(deadline) {
				t.Fatalf("attempt %d, want %d", got.Attempt, want)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	for i, wait := range webhookRetryAfter {
		got := step(int32(i + 1))
		if got.Status != "pending" || got.NextTryAt == nil {
			t.Fatalf("attempt %d: %+v", i+1, got)
		}
		if left := time.Until(*got.NextTryAt); left < wait-5*time.Second || left > wait+5*time.Second {
			t.Fatalf("attempt %d: next try in %s, want %s", i+1, left, wait)
		}
		if got.HttpStatus == nil || *got.HttpStatus != 500 || !strings.Contains(got.Error, "500") {
			t.Fatalf("attempt %d: %+v", i+1, got)
		}
	}
	last := step(webhookMaxAttempts)
	if last.Status != "failed" || last.NextTryAt != nil {
		t.Fatalf("last: %+v", last)
	}
	w, err := e.q.GetWebhook(ctx, hook)
	if err != nil || w.LastStatus != "failed" || w.FailingSince == nil {
		t.Fatalf("webhook %+v %v", w, err)
	}
	if srv.got == nil || len(srv.got) != webhookMaxAttempts {
		t.Fatalf("sent %d times", len(srv.got))
	}
}

