package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/textproto"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/dbmon"
	"github.com/morche/backend/internal/events"
	"github.com/morche/backend/internal/secrets"
)

// Outgoing webhooks: a workspace's events POSTed as JSON to a URL, signed like
// notification webhooks (X-Morche-Signature: sha256=HMAC(secret, ts + "." +
// body)). The bus subscriber only writes a pending delivery row; one loop
// sends every delivery (claimed with a lease, so a restart or a second loop
// never sends one twice) and retries a failed one after 30 s, 5 min and
// 30 min.

const (
	webhookTimeout     = 10 * time.Second
	webhookLease       = 2 * time.Minute
	webhookTick        = 10 * time.Second
	webhookBatch       = 20
	webhookParallel    = 8
	webhookMaxAttempts = 4
	webhookKeepDays    = 30
	webhookKeepPerHook = 1000
	webhookResponseCap = 4 << 10
	webhookUserAgent   = "Morche-Webhooks/1"
	webhookSecretLen   = 40
	maxWebhookHeaders  = 20
)

// webhookRetryAfter is the wait after the nth failed attempt (n from 1).
var webhookRetryAfter = []time.Duration{30 * time.Second, 5 * time.Minute, 30 * time.Minute}

// webhookBody is what a delivery POSTs.
type webhookBody struct {
	ID          uuid.UUID      `json:"id"`
	Type        string         `json:"type"`
	At          time.Time      `json:"at"`
	WorkspaceID uuid.UUID      `json:"workspace_id"`
	Severity    string         `json:"severity"`
	Title       string         `json:"title"`
	Text        string         `json:"text"`
	URL         string         `json:"url"`
	Subject     events.Subject `json:"subject"`
	ServerID    *uuid.UUID     `json:"server_id"`
	Data        map[string]any `json:"data"`
}

func webhookPayload(e events.Event) (string, error) {
	data := e.Data
	if data == nil {
		data = map[string]any{}
	}
	raw, err := json.Marshal(webhookBody{
		ID: e.ID, Type: e.Type, At: e.At.UTC(), WorkspaceID: e.WorkspaceID, Severity: e.Severity,
		Title: e.Title, Text: e.Text, URL: e.URL, Subject: e.Subject, ServerID: e.ServerID, Data: data,
	})
	return string(raw), err
}

// signWebhook is the X-Morche-Signature value for a body sent at ts.
func signWebhook(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// webhookWants says whether a hook takes an event.
func webhookWants(w sqlc.Webhook, e events.Event) bool {
	if !w.Enabled || e.Type == events.TestPing || e.Type == events.WebhookReceived {
		return false
	}
	if e.Muted() && !w.IncludeMuted {
		return false
	}
	return len(w.Events) == 0 || slices.Contains(w.Events, e.Type)
}

// ---- Dispatcher ----

type webhookDispatcher struct {
	q    *sqlc.Queries
	box  *secrets.Box
	poke chan struct{}
	// client makes the HTTP client for a hook (tests may swap it).
	client func(allowInternal bool) *http.Client

	mu     sync.Mutex
	pruned time.Time
}

func newWebhookDispatcher(q *sqlc.Queries, box *secrets.Box) *webhookDispatcher {
	return &webhookDispatcher{q: q, box: box, poke: make(chan struct{}, 1), client: webhookClient}
}

func webhookClient(allowInternal bool) *http.Client {
	return &http.Client{
		Timeout: webhookTimeout,
		Transport: &http.Transport{
			Proxy: nil, DialContext: dbmon.DirectDialer(allowInternal),
			TLSHandshakeTimeout: webhookTimeout, ForceAttemptHTTP2: true,
		},
		// A redirect is an answer like any other (a 3xx isn't delivered):
		// following it would turn the POST into a GET somewhere else.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// start subscribes to the bus and runs the send loop.
func (d *webhookDispatcher) start(bus *events.Bus) {
	ch, _ := bus.Subscribe("webhooks", 1000)
	go func() {
		for e := range ch {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if d.enqueue(ctx, e) > 0 {
				d.wake()
			}
			cancel()
		}
	}()
	go func() {
		t := time.NewTicker(webhookTick)
		defer t.Stop()
		for {
			select {
			case <-t.C:
			case <-d.poke:
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			for d.deliverDue(ctx) == webhookBatch && ctx.Err() == nil {
			}
			d.prune(ctx)
			cancel()
		}
	}()
}

func (d *webhookDispatcher) wake() {
	select {
	case d.poke <- struct{}{}:
	default:
	}
}

// enqueue writes a pending delivery for every hook that takes e; it answers
// how many.
func (d *webhookDispatcher) enqueue(ctx context.Context, e events.Event) int {
	hooks, err := d.q.ListEnabledWebhooks(ctx, e.WorkspaceID)
	if err != nil {
		slog.Warn("webhooks: list", "workspace", e.WorkspaceID, "error", err)
		return 0
	}
	body := ""
	n := 0
	now := time.Now()
	for _, w := range hooks {
		if !webhookWants(w, e) {
			continue
		}
		if body == "" {
			if body, err = webhookPayload(e); err != nil {
				slog.Warn("webhooks: body", "type", e.Type, "error", err)
				return 0
			}
		}
		if _, err := d.q.InsertWebhookDelivery(ctx, sqlc.InsertWebhookDeliveryParams{
			WebhookID: w.ID, EventID: e.ID, EventType: e.Type, Body: body, NextTryAt: &now,
		}); err != nil {
			slog.Warn("webhooks: queue a delivery", "webhook", w.ID, "error", err)
			continue
		}
		n++
	}
	return n
}

// deliverDue sends the deliveries that are due (up to a batch) and answers
// how many it took.
func (d *webhookDispatcher) deliverDue(ctx context.Context) int {
	due, err := d.q.ClaimDueWebhookDeliveries(ctx, sqlc.ClaimDueWebhookDeliveriesParams{
		LeaseUntil: time.Now().Add(webhookLease), MaxRows: webhookBatch,
	})
	if err != nil {
		slog.Warn("webhooks: claim deliveries", "error", err)
		return 0
	}
	sem := make(chan struct{}, webhookParallel)
	var wg sync.WaitGroup
	for _, del := range due {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			if _, err := d.attempt(ctx, del, true); err != nil {
				slog.Warn("webhooks: deliver", "delivery", del.ID, "error", err)
			}
		})
	}
	wg.Wait()
	return len(due)
}

func (d *webhookDispatcher) prune(ctx context.Context) {
	d.mu.Lock()
	if time.Since(d.pruned) < time.Hour {
		d.mu.Unlock()
		return
	}
	d.pruned = time.Now()
	d.mu.Unlock()
	if _, err := d.q.PruneWebhookDeliveries(ctx, sqlc.PruneWebhookDeliveriesParams{
		Before: time.Now().AddDate(0, 0, -webhookKeepDays), Keep: webhookKeepPerHook,
	}); err != nil {
		slog.Warn("webhooks: prune deliveries", "error", err)
	}
}

// attempt sends one delivery once and stores how it went. With retry, a
// failure with tries left stays pending for the next wait; without (a test,
// a redelivery), it is final.
func (d *webhookDispatcher) attempt(ctx context.Context, del sqlc.WebhookDelivery, retry bool) (sqlc.WebhookDelivery, error) {
	w, err := d.q.GetWebhook(ctx, del.WebhookID)
	if err != nil {
		return del, err // deleted: its deliveries went with it
	}
	res := sqlc.FinishWebhookAttemptParams{ID: del.ID, Attempt: del.Attempt + 1}
	if retry && !w.Enabled {
		res.Status, res.Error = "failed", "The webhook was turned off before this was sent."
		return d.q.FinishWebhookAttempt(ctx, res)
	}
	status, answer, dur, sendErr := d.send(ctx, w, del)
	res.DurationMs, res.Response = int32(dur/time.Millisecond), answer
	if status > 0 {
		s := int32(status)
		res.HttpStatus = &s
	}
	switch {
	case sendErr == nil && status >= 200 && status < 300:
		res.Status = "delivered"
	default:
		res.Status = "failed"
		if sendErr != nil {
			res.Error = sendErr.Error()
		} else {
			res.Error = "The address answered " + strconv.Itoa(status) + " " + http.StatusText(status) + "."
		}
		if retry && int(res.Attempt) < webhookMaxAttempts {
			next := time.Now().Add(webhookRetryAfter[res.Attempt-1])
			res.Status, res.NextTryAt = "pending", &next
		}
	}
	out, err := d.q.FinishWebhookAttempt(ctx, res)
	if err != nil {
		return del, err
	}
	note := "delivered"
	if res.Status != "delivered" {
		note = "failed"
	}
	if err := d.q.NoteWebhookAttempt(ctx, sqlc.NoteWebhookAttemptParams{ID: w.ID, Status: note}); err != nil {
		slog.Warn("webhooks: note attempt", "webhook", w.ID, "error", err)
	}
	return out, nil
}

// send POSTs a delivery's body: the answer's status (0 = none), the start of
// its body and how long it took.
func (d *webhookDispatcher) send(ctx context.Context, w sqlc.Webhook, del sqlc.WebhookDelivery) (int, string, time.Duration, error) {
	secret, err := d.box.Open(w.SecretEnc)
	if err != nil {
		return 0, "", 0, errors.New("The webhook's secret can't be read (was SECRETS_KEY changed?)")
	}
	headers, err := d.headers(w)
	if err != nil {
		return 0, "", 0, errors.New("The webhook's headers can't be read (was SECRETS_KEY changed?)")
	}
	body := []byte(del.Body)
	ctx, cancel := context.WithTimeout(ctx, webhookTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.Url, bytes.NewReader(body))
	if err != nil {
		return 0, "", 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", webhookUserAgent)
	req.Header.Set("X-Morche-Event", del.EventType)
	req.Header.Set("X-Morche-Delivery", del.ID.String())
	req.Header.Set("X-Morche-Timestamp", ts)
	if secret != "" {
		req.Header.Set("X-Morche-Signature", signWebhook(secret, ts, body))
	}
	start := time.Now()
	resp, err := d.client(w.AllowInternal).Do(req)
	dur := time.Since(start)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		var blocked *dbmon.BlockedError
		if errors.As(err, &blocked) {
			err = errors.New(blocked.Error() + " (a system admin can allow private addresses)")
		}
		return 0, "", dur, err
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, webhookResponseCap))
	return resp.StatusCode, strings.ToValidUTF8(string(answer), "�"), dur, nil
}

func (d *webhookDispatcher) headers(w sqlc.Webhook) (map[string]string, error) {
	raw, err := d.box.Open(w.HeadersEnc)
	if err != nil || raw == "" {
		return map[string]string{}, err
	}
	h := map[string]string{}
	return h, json.Unmarshal([]byte(raw), &h)
}

// ---- API ----

// OutgoingWebhook is a webhook (never its secret or header values).
type OutgoingWebhook struct {
	ID             string     `json:"id" format:"uuid"`
	WorkspaceID    string     `json:"workspace_id" format:"uuid"`
	Name           string     `json:"name"`
	URL            string     `json:"url"`
	Events         []string   `json:"events" doc:"Event types it sends; empty = all"`
	Enabled        bool       `json:"enabled"`
	IncludeMuted   bool       `json:"include_muted" doc:"Also send alert events published while muted (data.muted = true)"`
	AllowInternal  bool       `json:"allow_internal"`
	HasSecret      bool       `json:"has_secret"`
	HeaderNames    []string   `json:"header_names" doc:"Names of the extra headers (values are never shown)"`
	CreatedByName  string     `json:"created_by_name"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	LastStatus     string     `json:"last_status" doc:"delivered or failed: the last attempt; empty = never sent"`
	LastDeliveryAt *time.Time `json:"last_delivery_at,omitempty"`
	FailingSince   *time.Time `json:"failing_since,omitempty" doc:"Every attempt since then failed"`
}

// WebhookDelivery is one event sent (or to be sent) to one webhook.
type WebhookDelivery struct {
	ID           string     `json:"id" format:"uuid"`
	WebhookID    string     `json:"webhook_id" format:"uuid"`
	EventID      string     `json:"event_id" format:"uuid"`
	EventType    string     `json:"event_type"`
	Attempt      int32      `json:"attempt" doc:"Attempts made so far"`
	Status       string     `json:"status" enum:"pending,delivered,failed"`
	HTTPStatus   *int32     `json:"http_status,omitempty"`
	Response     string     `json:"response" doc:"The start of the answer (up to 4 KB)"`
	DurationMs   int32      `json:"duration_ms"`
	Error        string     `json:"error"`
	NextTryAt    *time.Time `json:"next_try_at,omitempty" doc:"When a pending one is tried again"`
	RequestBody  string     `json:"request_body" doc:"The JSON that was sent"`
	RedeliveryOf string     `json:"redelivery_of,omitempty" format:"uuid"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

func toWebhookDelivery(d sqlc.WebhookDelivery) WebhookDelivery {
	out := WebhookDelivery{
		ID: d.ID.String(), WebhookID: d.WebhookID.String(), EventID: d.EventID.String(), EventType: d.EventType,
		Attempt: d.Attempt, Status: d.Status, HTTPStatus: d.HttpStatus, Response: d.Response,
		DurationMs: d.DurationMs, Error: d.Error, RequestBody: d.Body, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
	}
	if d.Status == "pending" {
		out.NextTryAt = d.NextTryAt
	}
	if d.RedeliveryOf != nil {
		out.RedeliveryOf = d.RedeliveryOf.String()
	}
	return out
}

type webhookHandler struct {
	q     *sqlc.Queries
	box   *secrets.Box
	authz *authz
	d     *webhookDispatcher
}

func (h *webhookHandler) toWebhook(w sqlc.Webhook) OutgoingWebhook {
	names := []string{}
	if hs, err := h.d.headers(w); err == nil {
		for k := range hs {
			names = append(names, k)
		}
		slices.Sort(names)
	}
	events := w.Events
	if events == nil {
		events = []string{}
	}
	return OutgoingWebhook{
		ID: w.ID.String(), WorkspaceID: w.WorkspaceID.String(), Name: w.Name, URL: w.Url, Events: events,
		Enabled: w.Enabled, IncludeMuted: w.IncludeMuted, AllowInternal: w.AllowInternal,
		HasSecret: len(w.SecretEnc) > 0, HeaderNames: names, CreatedByName: w.CreatedByName,
		CreatedAt: w.CreatedAt, UpdatedAt: w.UpdatedAt, LastStatus: w.LastStatus,
		LastDeliveryAt: w.LastDeliveryAt, FailingSince: w.FailingSince,
	}
}

type WebhookBody struct {
	Name          string   `json:"name" minLength:"1" maxLength:"100"`
	URL           string   `json:"url" minLength:"1" maxLength:"2000" doc:"http(s) address the events are POSTed to"`
	Events        []string `json:"events,omitempty" maxItems:"50" doc:"Event types (GET /events/catalog); empty = all"`
	Enabled       *bool    `json:"enabled,omitempty" doc:"Default true"`
	IncludeMuted  bool     `json:"include_muted,omitempty"`
	AllowInternal bool     `json:"allow_internal,omitempty" doc:"Send to a private or loopback address. System admins only."`
	// Headers: nil = keep the saved ones; given = the new set, where a blank
	// value keeps that header's saved value.
	Headers map[string]string `json:"headers,omitempty" doc:"Extra headers sent with every delivery (sealed). On update: absent = keep all; given = the new set, a blank value keeps that header's saved value."`
}

var reservedWebhookHeaders = []string{"Content-Type", "Content-Length", "Host", "User-Agent", "Transfer-Encoding", "Connection"}

// clean checks a body and answers the headers to store.
func (b *WebhookBody) clean(saved map[string]string) (map[string]string, error) {
	b.Name = strings.TrimSpace(b.Name)
	b.URL = strings.TrimSpace(b.URL)
	if b.Name == "" {
		return nil, fieldError("body.name", "Give the webhook a name", b.Name)
	}
	u, err := url.Parse(b.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fieldError("body.url", "Enter an http:// or https:// address", b.URL)
	}
	if u.User != nil {
		return nil, fieldError("body.url", "Put credentials in a header, not in the address", b.URL)
	}
	seen := map[string]bool{}
	evs := []string{}
	for i, e := range b.Events {
		e = strings.TrimSpace(e)
		t, ok := events.Lookup(e)
		if !ok || t.Name == events.TestPing || t.Name == events.WebhookReceived {
			return nil, fieldError("body.events["+strconv.Itoa(i)+"]", "Unknown event type", e)
		}
		if !seen[e] {
			seen[e] = true
			evs = append(evs, e)
		}
	}
	b.Events = evs
	if b.Headers == nil {
		return saved, nil
	}
	return cleanHookHeaders("body.headers", b.Headers, saved, reservedWebhookHeaders)
}

// cleanHookHeaders checks extra headers for an outgoing request (webhooks,
// automation webhook steps): a blank value keeps that header's saved value.
func cleanHookHeaders(loc string, given, saved map[string]string, reserved []string) (map[string]string, error) {
	if len(given) > maxWebhookHeaders {
		return nil, fieldError(loc, "At most 20 headers", len(given))
	}
	out := map[string]string{}
	for k, v := range given {
		name := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(k))
		if name == "" || strings.ContainsAny(name, " :\r\n") || len(name) > 100 {
			return nil, fieldError(loc, "Not a valid header name: "+k, k)
		}
		if slices.Contains(reserved, name) || strings.HasPrefix(name, "X-Morche-") {
			return nil, fieldError(loc, name+" is set by Morche", k)
		}
		if strings.ContainsAny(v, "\r\n") || len(v) > 4000 {
			return nil, fieldError(loc, "Not a valid value for "+name, nil)
		}
		if v == "" {
			for sk, sv := range saved {
				if textproto.CanonicalMIMEHeaderKey(sk) == name {
					v = sv
				}
			}
			if v == "" {
				return nil, fieldError(loc, "Give "+name+" a value", nil)
			}
		}
		out[name] = v
	}
	return out, nil
}

func (h *webhookHandler) sealHeaders(hs map[string]string) []byte {
	if len(hs) == 0 {
		return nil
	}
	raw, _ := json.Marshal(hs)
	return h.box.Seal(string(raw))
}

type WebhookPath struct {
	ID string `path:"id" format:"uuid"`
}

type webhookOutput struct{ Body OutgoingWebhook }

// WebhookWithSecret is a webhook with its signing secret, shown only when it
// is made or rotated.
type WebhookWithSecret struct {
	Webhook OutgoingWebhook `json:"webhook"`
	Secret  string          `json:"secret" doc:"Signs every body: X-Morche-Signature = sha256=HMAC-SHA256(secret, X-Morche-Timestamp + \".\" + body). Shown only now."`
}

func newWebhookSecret() (string, error) {
	t, _, err := newAPIToken()
	if err != nil {
		return "", err
	}
	return "whsec_" + strings.TrimPrefix(t, tokenPrefix)[:webhookSecretLen], nil
}

func registerWebhooks(api huma.API, h *webhookHandler) {
	tags := []string{"Webhooks"}

	huma.Register(api, huma.Operation{
		OperationID: "list-webhooks", Method: http.MethodGet, Path: "/workspaces/{id}/webhooks",
		Summary: "List a workspace's outgoing webhooks", Tags: tags,
	}, func(ctx context.Context, in *WorkspacePath) (*struct {
		Body struct {
			Items []OutgoingWebhook `json:"items"`
		}
	}, error) {
		rows, err := h.q.ListWebhooks(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []OutgoingWebhook `json:"items"`
			}
		}{}
		out.Body.Items = make([]OutgoingWebhook, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = h.toWebhook(r)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-webhook", Method: http.MethodPost, Path: "/workspaces/{id}/webhooks",
		Summary: "Add an outgoing webhook", Tags: tags, DefaultStatus: http.StatusCreated,
		Description: "Answers the signing secret once.",
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body WebhookBody
	}) (*struct{ Body WebhookWithSecret }, error) {
		p := principalOf(ctx)
		b := in.Body
		if b.AllowInternal && !p.Access.Admin {
			return nil, fieldError("body.allow_internal", "Only a system admin can allow private addresses", true)
		}
		hs, err := b.clean(nil)
		if err != nil {
			return nil, err
		}
		secret, err := newWebhookSecret()
		if err != nil {
			return nil, internalError(err)
		}
		w, err := h.q.CreateWebhook(ctx, sqlc.CreateWebhookParams{
			WorkspaceID: uuid.MustParse(in.ID), Name: b.Name, Url: b.URL, Events: b.Events,
			SecretEnc: h.box.Seal(secret), HeadersEnc: h.sealHeaders(hs),
			Enabled: b.Enabled == nil || *b.Enabled, IncludeMuted: b.IncludeMuted, AllowInternal: b.AllowInternal,
			CreatedBy: p.ID(), CreatedByName: cmpOr(p.User.FullName, p.User.Username),
		})
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct{ Body WebhookWithSecret }{}
		out.Body = WebhookWithSecret{Webhook: h.toWebhook(w), Secret: secret}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-webhook", Method: http.MethodGet, Path: "/webhooks/{id}",
		Summary: "An outgoing webhook", Tags: tags,
	}, func(ctx context.Context, in *WebhookPath) (*webhookOutput, error) {
		w, err := h.q.GetWebhook(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, notFoundOr(err, "webhook not found")
		}
		return &webhookOutput{Body: h.toWebhook(w)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-webhook", Method: http.MethodPut, Path: "/webhooks/{id}",
		Summary: "Change an outgoing webhook", Tags: tags,
	}, func(ctx context.Context, in *struct {
		WebhookPath
		Body WebhookBody
	}) (*webhookOutput, error) {
		p := principalOf(ctx)
		prev, err := h.q.GetWebhook(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, notFoundOr(err, "webhook not found")
		}
		b := in.Body
		// Keeping an admin's allow_internal is fine, pointing it elsewhere isn't.
		if b.AllowInternal && !p.Access.Admin && (!prev.AllowInternal || strings.TrimSpace(b.URL) != prev.Url) {
			return nil, fieldError("body.allow_internal", "Only a system admin can allow private addresses", true)
		}
		saved, err := h.d.headers(prev)
		if err != nil {
			return nil, internalError(err)
		}
		hs, err := b.clean(saved)
		if err != nil {
			return nil, err
		}
		w, err := h.q.UpdateWebhook(ctx, sqlc.UpdateWebhookParams{
			ID: prev.ID, Name: b.Name, Url: b.URL, Events: b.Events, HeadersEnc: h.sealHeaders(hs),
			Enabled: b.Enabled == nil || *b.Enabled, IncludeMuted: b.IncludeMuted, AllowInternal: b.AllowInternal,
		})
		if err != nil {
			return nil, internalError(err)
		}
		return &webhookOutput{Body: h.toWebhook(w)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-webhook", Method: http.MethodDelete, Path: "/webhooks/{id}",
		Summary: "Remove an outgoing webhook", Tags: tags, DefaultStatus: http.StatusNoContent,
		Description: "Its deliveries, including pending retries, go with it.",
	}, func(ctx context.Context, in *WebhookPath) (*struct{}, error) {
		if err := h.q.DeleteWebhook(ctx, uuid.MustParse(in.ID)); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "rotate-webhook-secret", Method: http.MethodPost, Path: "/webhooks/{id}/secret",
		Summary: "Make a new signing secret", Tags: tags,
		Description: "The old one stops at once. Answers the new one once.",
	}, func(ctx context.Context, in *WebhookPath) (*struct{ Body WebhookWithSecret }, error) {
		secret, err := newWebhookSecret()
		if err != nil {
			return nil, internalError(err)
		}
		w, err := h.q.SetWebhookSecret(ctx, sqlc.SetWebhookSecretParams{ID: uuid.MustParse(in.ID), SecretEnc: h.box.Seal(secret)})
		if err != nil {
			return nil, notFoundOr(err, "webhook not found")
		}
		out := &struct{ Body WebhookWithSecret }{}
		out.Body = WebhookWithSecret{Webhook: h.toWebhook(w), Secret: secret}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "test-webhook", Method: http.MethodPost, Path: "/webhooks/{id}/test",
		Summary: "Send a test event", Tags: tags,
		Description: "Sends a test.ping now (even when the webhook is off) and answers how it went. Not retried.",
	}, func(ctx context.Context, in *WebhookPath) (*webhookDeliveryOutput, error) {
		w, err := h.q.GetWebhook(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, notFoundOr(err, "webhook not found")
		}
		e := events.Event{
			ID: uuid.New(), Type: events.TestPing, WorkspaceID: w.WorkspaceID, At: time.Now().UTC(), Severity: events.Info,
			Title: "Test from Morche", Text: "If you can read this, the webhook works.",
			Subject: events.Subject{Kind: events.SubjectWebhook, ID: w.ID.String(), Name: w.Name},
			Data:    map[string]any{"sent_by": cmpOr(principalOf(ctx).User.FullName, principalOf(ctx).User.Username)},
		}
		body, err := webhookPayload(e)
		if err != nil {
			return nil, internalError(err)
		}
		return h.sendNow(ctx, w.ID, e.ID, e.Type, body, nil)
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-webhook-deliveries", Method: http.MethodGet, Path: "/webhooks/{id}/deliveries",
		Summary: "A webhook's deliveries, newest first", Tags: tags,
		Description: "Kept 30 days, at most 1000 per webhook.",
	}, func(ctx context.Context, in *struct {
		WebhookPath
		Status string `query:"status" enum:"pending,delivered,failed," doc:"Only these"`
		Limit  int32  `query:"limit" minimum:"1" maximum:"200" default:"50"`
		Offset int32  `query:"offset" minimum:"0"`
	}) (*struct {
		Body struct {
			Items []WebhookDelivery `json:"items"`
			Total int64             `json:"total"`
		}
	}, error) {
		id := uuid.MustParse(in.ID)
		var status *string
		if in.Status != "" {
			status = &in.Status
		}
		rows, err := h.q.ListWebhookDeliveries(ctx, sqlc.ListWebhookDeliveriesParams{WebhookID: id, Status: status, Limit: in.Limit, Offset: in.Offset})
		if err != nil {
			return nil, internalError(err)
		}
		total, err := h.q.CountWebhookDeliveries(ctx, sqlc.CountWebhookDeliveriesParams{WebhookID: id, Status: status})
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []WebhookDelivery `json:"items"`
				Total int64             `json:"total"`
			}
		}{}
		out.Body.Items = make([]WebhookDelivery, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = toWebhookDelivery(r)
		}
		out.Body.Total = total
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-webhook-delivery", Method: http.MethodGet, Path: "/webhook-deliveries/{id}",
		Summary: "One webhook delivery", Tags: tags,
	}, func(ctx context.Context, in *WebhookPath) (*webhookDeliveryOutput, error) {
		d, err := h.q.GetWebhookDelivery(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, notFoundOr(err, "delivery not found")
		}
		return &webhookDeliveryOutput{Body: toWebhookDelivery(d)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "redeliver-webhook-delivery", Method: http.MethodPost, Path: "/webhook-deliveries/{id}/redeliver",
		Summary: "Send a delivery again", Tags: tags,
		Description: "Sends the same body now as a new delivery and answers how it went. Not retried.",
	}, func(ctx context.Context, in *WebhookPath) (*webhookDeliveryOutput, error) {
		d, err := h.q.GetWebhookDelivery(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, notFoundOr(err, "delivery not found")
		}
		return h.sendNow(ctx, d.WebhookID, d.EventID, d.EventType, d.Body, &d.ID)
	})
}

// sendNow writes a delivery, sends it at once (the loop leaves it alone: it
// is leased) and answers it.
type webhookDeliveryOutput struct{ Body WebhookDelivery }

func (h *webhookHandler) sendNow(ctx context.Context, hook, event uuid.UUID, typ, body string, of *uuid.UUID) (*webhookDeliveryOutput, error) {
	lease := time.Now().Add(webhookLease)
	del, err := h.q.InsertWebhookDelivery(ctx, sqlc.InsertWebhookDeliveryParams{
		WebhookID: hook, EventID: event, EventType: typ, Body: body, NextTryAt: &lease, RedeliveryOf: of,
	})
	if err != nil {
		return nil, internalError(err)
	}
	del, err = h.d.attempt(context.WithoutCancel(ctx), del, false)
	if err != nil {
		return nil, internalError(err)
	}
	return &webhookDeliveryOutput{Body: toWebhookDelivery(del)}, nil
}

func notFoundOr(err error, msg string) error {
	if isNotFound(err) {
		return huma.Error404NotFound(msg)
	}
	return internalError(err)
}
