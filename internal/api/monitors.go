package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/secrets"
	"github.com/morcheh/backend/internal/uptime"
)

// Uptime monitors: something to check on a schedule (a web address, a
// socket, a database, a queue, a container on a server…), its history,
// incidents and the alerts it sends.

type uptimeHandler struct {
	q        *sqlc.Queries
	box      *secrets.Box
	authz    *authz
	servers  *serverHandler
	panelURL string
	history  time.Duration

	mu      sync.Mutex
	running map[uuid.UUID]bool
}

func newUptimeHandler(q *sqlc.Queries, box *secrets.Box, a *authz, servers *serverHandler, panelURL string, history time.Duration) *uptimeHandler {
	return &uptimeHandler{
		q: q, box: box, authz: a, servers: servers,
		panelURL: strings.TrimRight(panelURL, "/"), history: history,
		running: map[uuid.UUID]bool{},
	}
}

// claim marks a monitor as being checked, so two checks never overlap.
func (h *uptimeHandler) claim(id uuid.UUID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.running[id] {
		return false
	}
	h.running[id] = true
	return true
}

func (h *uptimeHandler) unclaim(id uuid.UUID) {
	h.mu.Lock()
	delete(h.running, id)
	h.mu.Unlock()
}

type MonitorIDPath struct {
	ID string `path:"id" format:"uuid"`
}

// Beat is one check, for the bars.
type Beat struct {
	At        time.Time `json:"at"`
	Status    string    `json:"status"`
	LatencyMs *int32    `json:"latency_ms,omitempty"`
	Message   string    `json:"message"`
}

// UptimeMonitor is a monitor. Its secrets never leave the backend: only their
// names come back.
type UptimeMonitor struct {
	ID              string               `json:"id" format:"uuid"`
	WorkspaceID     string               `json:"workspace_id" format:"uuid"`
	Name            string               `json:"name"`
	Kind            string               `json:"kind"`
	Description     string               `json:"description"`
	Tags            []string             `json:"tags"`
	Config          uptime.MonitorConfig `json:"config"`
	Secrets         []string             `json:"secrets" doc:"Which secrets are saved"`
	Locations       []MonitorLocation    `json:"locations" doc:"Where it's checked from"`
	Rule            LocationRule         `json:"rule" doc:"How the locations' answers make one status"`
	ServerID        *string              `json:"server_id,omitempty" format:"uuid"`
	IntervalSeconds int32                `json:"interval_seconds"`
	RetrySeconds    int32                `json:"retry_seconds"`
	TimeoutSeconds  int32                `json:"timeout_seconds"`
	Retries         int32                `json:"retries"`
	ResendEvery     int32                `json:"resend_every"`
	NotifyDegraded  bool                 `json:"notify_degraded"`
	AllowInternal   bool                 `json:"allow_internal"`
	Paused          bool                 `json:"paused"`
	PushToken       string               `json:"push_token,omitempty" doc:"push: the secret in the heartbeat address (Engineer and up)"`
	Status          string               `json:"status" enum:"pending,up,degraded,down"`
	StatusMessage   string               `json:"status_message"`
	StatusSince     time.Time            `json:"status_since"`
	FailCount       int32                `json:"fail_count" doc:"Failed checks in a row; above 0 while still up = retrying"`
	LastLatencyMs   *int32               `json:"last_latency_ms,omitempty"`
	LastCheckedAt   *time.Time           `json:"last_checked_at,omitempty"`
	NextCheckAt     time.Time            `json:"next_check_at"`
	CertExpiresAt   *time.Time           `json:"cert_expires_at,omitempty"`
	ChannelIDs      []string             `json:"channel_ids"`
	Recent          []Beat               `json:"recent" doc:"The newest checks, oldest first"`
	Uptime24h       *float64             `json:"uptime_24h,omitempty" doc:"Percent of checks up or degraded"`
	Uptime30d       *float64             `json:"uptime_30d,omitempty"`
	CreatedByName   string               `json:"created_by_name"`
	UpdatedByName   string               `json:"updated_by_name"`
	CreatedAt       time.Time            `json:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at"`
}

// LocationRule turns the answers of several locations into one status.
// Locations that couldn't check at all (their server was unreachable) don't
// vote; counts above the number that answered mean all of them.
type LocationRule struct {
	Down          string `json:"down" enum:"any,majority,all,count" doc:"Down when any, a majority, all or at least down_count locations fail"`
	DownCount     int32  `json:"down_count" minimum:"1" maximum:"50"`
	Degraded      string `json:"degraded" enum:"any,majority,count,never" doc:"Below that, degraded when any, a majority or at least degraded_count locations have trouble; never = stays up"`
	DegradedCount int32  `json:"degraded_count" minimum:"1" maximum:"50"`
}

func ruleOf(m sqlc.Monitor) uptime.Rule {
	return uptime.Rule{Down: m.RuleDown, DownCount: int(m.RuleDownCount), Degraded: m.RuleDegraded, DegradedCount: int(m.RuleDegradedCount)}
}

func toLocationRule(r uptime.Rule) LocationRule {
	return LocationRule{Down: r.Down, DownCount: int32(r.DownCount), Degraded: r.Degraded, DegradedCount: int32(r.DegradedCount)}
}

// MonitorLocation is one place a monitor is checked from, with its own
// latest answer.
type MonitorLocation struct {
	Location      string     `json:"location" doc:"morcheh, or the server's id"`
	ServerID      *string    `json:"server_id,omitempty" format:"uuid"`
	Name          string     `json:"name"`
	Status        string     `json:"status" enum:"pending,up,degraded,down,unknown" doc:"unknown = it couldn't check (its server was unreachable)"`
	StatusMessage string     `json:"status_message"`
	StatusSince   time.Time  `json:"status_since"`
	LatencyMs     *int32     `json:"latency_ms,omitempty"`
	Code          string     `json:"code"`
	CheckedAt     *time.Time `json:"checked_at,omitempty"`
}

func locKey(server *uuid.UUID) string {
	if server == nil {
		return uptime.Morcheh
	}
	return server.String()
}

func locName(server *uuid.UUID, name string) string {
	if server == nil {
		return "Morcheh"
	}
	return cmpOr(name, "A removed server")
}

func toMonitorLocation(l sqlc.ListMonitorLocationsRow) MonitorLocation {
	return MonitorLocation{
		Location: locKey(l.ServerID), ServerID: optionalIDString(l.ServerID), Name: locName(l.ServerID, l.ServerName),
		Status: l.Status, StatusMessage: l.StatusMessage, StatusSince: l.StatusSince, LatencyMs: l.LatencyMs,
		Code: l.Code, CheckedAt: l.CheckedAt,
	}
}

type UptimeMonitorOutput struct {
	Body UptimeMonitor
}

const monitorKinds = "http,tcp,udp,ping,dns,tls,websocket,socketio,smtp,database,rabbitmq,kafka,nats,mqtt,memcached,elasticsearch,docker,systemd,command,push"

type MonitorBody struct {
	Name            string                `json:"name" minLength:"1" maxLength:"100"`
	Kind            string                `json:"kind" enum:"http,tcp,udp,ping,dns,tls,websocket,socketio,smtp,database,rabbitmq,kafka,nats,mqtt,memcached,elasticsearch,docker,systemd,command,push" doc:"Can't change after it's created"`
	Description     string                `json:"description,omitempty" maxLength:"2000"`
	Tags            []string              `json:"tags,omitempty" maxItems:"20"`
	Config          uptime.MonitorConfig  `json:"config"`
	Secrets         uptime.MonitorSecrets `json:"secrets" doc:"A blank secret keeps the saved one"`
	Locations       []string              `json:"locations,omitempty" maxItems:"20" doc:"Where to check from: morcheh and/or server ids (over SSH). docker, systemd and command take one server. Left out: Morcheh on create, unchanged on update"`
	Rule            *LocationRule         `json:"rule,omitempty" doc:"With several locations: when they make it down or degraded. Left out: majority down, any degraded on create, unchanged on update"`
	ServerID        *string               `json:"server_id,omitempty" format:"uuid" doc:"The server it belongs to, shown on that server's page"`
	IntervalSeconds int32                 `json:"interval_seconds,omitempty" minimum:"10" maximum:"86400" default:"60"`
	RetrySeconds    int32                 `json:"retry_seconds,omitempty" minimum:"5" maximum:"86400" default:"20" doc:"How soon to check again after a failure"`
	TimeoutSeconds  int32                 `json:"timeout_seconds,omitempty" minimum:"1" maximum:"120" default:"10"`
	Retries         int32                 `json:"retries" minimum:"0" maximum:"20" default:"1" doc:"Failures in a row before it counts as down"`
	ResendEvery     int32                 `json:"resend_every,omitempty" minimum:"0" maximum:"10000" doc:"While down, remind every this many checks; 0 = never"`
	NotifyDegraded  *bool                 `json:"notify_degraded,omitempty" doc:"Also alert when it turns slow or degraded (default false)"`
	AllowInternal   bool                  `json:"allow_internal,omitempty" doc:"Check a private or loopback address from Morcheh. System admins only."`
	Paused          bool                  `json:"paused,omitempty" doc:"Create it paused (ignored on update)"`
	ChannelIDs      []string              `json:"channel_ids,omitempty" doc:"Where alerts go; left out on create = the workspace's default channels, on update = unchanged"`
	ResetPushToken  bool                  `json:"reset_push_token,omitempty" doc:"push: make a new heartbeat address (the old one stops working)"`
}

func (h *uptimeHandler) monitorSecrets(m sqlc.Monitor) (uptime.MonitorSecrets, error) {
	var s uptime.MonitorSecrets
	plain, err := h.box.Open(m.SecretsEnc)
	if err != nil || plain == "" {
		return s, err
	}
	err = json.Unmarshal([]byte(plain), &s)
	return s, err
}

func monitorConfig(m sqlc.Monitor) uptime.MonitorConfig {
	var c uptime.MonitorConfig
	_ = json.Unmarshal(m.Config, &c)
	return c
}

func percent(good, all int64) *float64 {
	if all == 0 {
		return nil
	}
	v := float64(good) * 100 / float64(all)
	return &v
}

func toUptimeMonitor(m sqlc.Monitor, s uptime.MonitorSecrets, showToken bool) UptimeMonitor {
	out := UptimeMonitor{
		ID: m.ID.String(), WorkspaceID: m.WorkspaceID.String(), Name: m.Name, Kind: m.Kind,
		Description: m.Description, Tags: m.Tags, Config: monitorConfig(m), Secrets: s.Names(),
		Locations: []MonitorLocation{}, Rule: toLocationRule(ruleOf(m)), ServerID: optionalIDString(m.ServerID),
		IntervalSeconds: m.IntervalSeconds, RetrySeconds: m.RetrySeconds, TimeoutSeconds: m.TimeoutSeconds,
		Retries: m.Retries, ResendEvery: m.ResendEvery, NotifyDegraded: m.NotifyDegraded,
		AllowInternal: m.AllowInternal, Paused: m.Paused, Status: m.Status, StatusMessage: m.StatusMessage,
		StatusSince: m.StatusSince, FailCount: m.FailCount, LastLatencyMs: m.LastLatencyMs,
		LastCheckedAt: m.LastCheckedAt, NextCheckAt: m.NextCheckAt, CertExpiresAt: m.CertExpiresAt,
		ChannelIDs: []string{}, Recent: []Beat{}, CreatedByName: m.CreatedByName,
		UpdatedByName: m.UpdatedByName, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt,
	}
	if out.Tags == nil {
		out.Tags = []string{}
	}
	if showToken && m.PushToken != nil {
		out.PushToken = *m.PushToken
	}
	return out
}

const recentBeats = 40

// enrich adds the bars, uptime and channels to monitors, in a few queries.
func (h *uptimeHandler) enrich(ctx context.Context, items []UptimeMonitor) {
	if len(items) == 0 {
		return
	}
	ids := make([]uuid.UUID, len(items))
	at := map[uuid.UUID]int{}
	for i, it := range items {
		ids[i] = uuid.MustParse(it.ID)
		at[ids[i]] = i
	}
	if rows, err := h.q.RecentMonitorChecks(ctx, sqlc.RecentMonitorChecksParams{Per: recentBeats, Ids: ids}); err == nil {
		for _, r := range rows {
			i := at[r.MonitorID]
			items[i].Recent = append(items[i].Recent, Beat{At: r.At, Status: r.Status, LatencyMs: r.LatencyMs, Message: r.Message})
		}
		for i := range items {
			slices.Reverse(items[i].Recent)
		}
	}
	now := time.Now()
	if rows, err := h.q.MonitorUptimeSince(ctx, sqlc.MonitorUptimeSinceParams{Ids: ids, Since: now.Add(-24 * time.Hour)}); err == nil {
		for _, r := range rows {
			items[at[r.MonitorID]].Uptime24h = percent(int64(r.Up+r.Degraded), int64(r.Checks))
		}
	}
	since := pgtype.Date{Time: now.UTC().AddDate(0, 0, -29).Truncate(24 * time.Hour), Valid: true}
	if rows, err := h.q.MonitorDaysSince(ctx, sqlc.MonitorDaysSinceParams{Ids: ids, Since: since}); err == nil {
		up := map[uuid.UUID][2]int64{}
		for _, d := range rows {
			v := up[d.MonitorID]
			v[0] += int64(d.Up + d.Degraded)
			v[1] += int64(d.Checks)
			up[d.MonitorID] = v
		}
		for id, v := range up {
			items[at[id]].Uptime30d = percent(v[0], v[1])
		}
	}
	if rows, err := h.q.ListMonitorLocationsFor(ctx, ids); err == nil {
		for _, r := range rows {
			i := at[r.MonitorID]
			items[i].Locations = append(items[i].Locations, toMonitorLocation(sqlc.ListMonitorLocationsRow(r)))
		}
	}
	if rows, err := h.q.ListMonitorChannelsFor(ctx, ids); err == nil {
		for _, r := range rows {
			i := at[r.MonitorID]
			items[i].ChannelIDs = append(items[i].ChannelIDs, r.ChannelID.String())
		}
	}
}

func (h *uptimeHandler) monitorOut(ctx context.Context, m sqlc.Monitor, showToken bool) (*UptimeMonitorOutput, error) {
	s, err := h.monitorSecrets(m)
	if err != nil {
		return nil, internalError(err)
	}
	items := []UptimeMonitor{toUptimeMonitor(m, s, showToken)}
	h.enrich(ctx, items)
	return &UptimeMonitorOutput{Body: items[0]}, nil
}

func (h *uptimeHandler) getMonitor(ctx context.Context, rawID string) (sqlc.Monitor, error) {
	id, err := uuid.Parse(rawID)
	if err != nil {
		return sqlc.Monitor{}, huma.Error404NotFound("Monitor not found")
	}
	m, err := h.q.GetMonitor(ctx, id)
	if isNotFound(err) {
		return m, huma.Error404NotFound("Monitor not found")
	}
	if err != nil {
		return m, internalError(err)
	}
	return m, nil
}

func pushToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// monitorTarget is what a monitor checks, to tell whether a saved
// allow_internal still covers it, and to name it in alerts.
func monitorTarget(kind string, c uptime.MonitorConfig) string {
	switch kind {
	case uptime.HTTP, uptime.WebSocket, uptime.SocketIO, uptime.Elasticsearch:
		return c.URL
	case uptime.Ping:
		return c.Host
	case uptime.DNS:
		t := c.Name
		if c.RecordType != "" {
			t += " " + c.RecordType
		}
		if c.Resolver != "" {
			t += " @" + c.Resolver
		}
		return t
	case uptime.Docker:
		return "container " + c.Container
	case uptime.Systemd:
		return "unit " + c.Unit
	case uptime.Command:
		return "a command"
	case uptime.Push:
		return "heartbeats"
	}
	if c.Port > 0 {
		return joinHost(c.Host, c.Port)
	}
	return c.Host
}

func joinHost(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + itoa(port)
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func cleanTags(tags []string) []string {
	out := []string{}
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t != "" && len(t) <= 40 && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// monitorPlan is a checked body, ready to save.
type monitorPlan struct {
	ws       uuid.UUID
	locs     []planLoc
	rule     uptime.Rule
	server   *uuid.UUID
	channels []uuid.UUID
	setCh    bool
	secrets  uptime.MonitorSecrets
	// hadMorcheh: the saved monitor was checked from Morcheh.
	hadMorcheh bool
}

// planLocations checks where the monitor is checked from and its rule. A
// server needs Engineer access to check from, unless it already was one.
func (h *uptimeHandler) planLocations(ctx context.Context, p *principal, kind string, b *MonitorBody, prev *sqlc.Monitor, pl *monitorPlan) error {
	var saved []sqlc.ListMonitorLocationsRow
	pl.rule = uptime.DefaultRule
	if prev != nil {
		rows, err := h.q.ListMonitorLocations(ctx, prev.ID)
		if err != nil {
			return internalError(err)
		}
		saved = rows
		pl.rule = ruleOf(*prev)
		pl.hadMorcheh = hasMorcheh(planLocs(rows))
	}
	if b.Rule != nil {
		pl.rule = uptime.Rule{
			Down: b.Rule.Down, DownCount: int(b.Rule.DownCount),
			Degraded: b.Rule.Degraded, DegradedCount: int(b.Rule.DegradedCount),
		}
	}
	if kind == uptime.Push {
		return nil
	}
	raw := b.Locations
	if raw == nil {
		if prev != nil {
			for _, l := range saved {
				raw = append(raw, locKey(l.ServerID))
			}
		} else if !uptime.OnServer(kind) {
			raw = []string{uptime.Morcheh}
		}
	}
	had := func(id uuid.UUID) (planLoc, bool) {
		for _, l := range planLocs(saved) {
			if l.server != nil && *l.server == id {
				return l, true
			}
		}
		return planLoc{}, false
	}
	for _, r := range raw {
		r = strings.TrimSpace(r)
		if r == uptime.Morcheh {
			if !hasMorcheh(pl.locs) {
				pl.locs = append(pl.locs, planLoc{key: r, name: "Morcheh"})
			}
			continue
		}
		id, err := uuid.Parse(r)
		if err != nil {
			return fieldError("body.locations", "Server not found", r)
		}
		if slices.ContainsFunc(pl.locs, func(l planLoc) bool { return l.key == id.String() }) {
			continue
		}
		if l, ok := had(id); ok {
			// Already a location: it stays, whoever saves.
			pl.locs = append(pl.locs, l)
			continue
		}
		srv, err := h.q.GetServer(ctx, id)
		if isNotFound(err) || (err == nil && p.Access.ServerLevel(srv.WorkspaceID, id) == auth.None) {
			return fieldError("body.locations", "Server not found", r)
		}
		if err != nil {
			return internalError(err)
		}
		if p.Access.ServerLevel(srv.WorkspaceID, id) < auth.Engineer {
			return fieldError("body.locations", "You need Engineer access to "+srv.Name+" to check from it", r)
		}
		pl.locs = append(pl.locs, planLoc{key: id.String(), server: &id, name: srv.Name})
	}
	switch {
	case uptime.OnServer(kind) && len(pl.locs) > 1:
		return fieldError("body.locations", "It runs on one server: pick just that one", b.Locations)
	case uptime.OnServer(kind) && len(pl.locs) == 1 && pl.locs[0].server == nil:
		return fieldError("body.locations", "Pick the server it runs on", b.Locations)
	case len(pl.locs) == 0 && !uptime.OnServer(kind):
		return fieldError("body.locations", "Pick at least one place to check from", b.Locations)
	}
	return nil
}

// setLocations makes the saved locations match the plan. Ones that stay keep
// their latest answer.
func (h *uptimeHandler) setLocations(ctx context.Context, monitor uuid.UUID, locs []planLoc) error {
	keep := make([]string, len(locs))
	for i, l := range locs {
		keep[i] = l.key
	}
	if err := h.q.KeepMonitorLocations(ctx, sqlc.KeepMonitorLocationsParams{MonitorID: monitor, Keep: keep}); err != nil {
		return err
	}
	for _, l := range locs {
		if err := h.q.AddMonitorLocation(ctx, sqlc.AddMonitorLocationParams{MonitorID: monitor, ServerID: l.server}); err != nil {
			return err
		}
	}
	return nil
}

// planLoc is a place to check from: server nil = Morcheh.
type planLoc struct {
	key    string
	server *uuid.UUID
	name   string
}

func planLocs(rows []sqlc.ListMonitorLocationsRow) []planLoc {
	out := make([]planLoc, len(rows))
	for i, l := range rows {
		out[i] = planLoc{key: locKey(l.ServerID), server: l.ServerID, name: locName(l.ServerID, l.ServerName)}
	}
	return out
}

func hasMorcheh(locs []planLoc) bool {
	return slices.ContainsFunc(locs, func(l planLoc) bool { return l.server == nil })
}

// planMonitor checks a body for workspace ws: settings, servers, channels and
// the private-address switch. prev is the saved monitor when editing.
func (h *uptimeHandler) planMonitor(ctx context.Context, p *principal, ws uuid.UUID, kind string, b *MonitorBody, prev *sqlc.Monitor) (monitorPlan, error) {
	pl := monitorPlan{ws: ws, secrets: b.Secrets}
	var savedCfg uptime.MonitorConfig
	if prev != nil {
		saved, err := h.monitorSecrets(*prev)
		if err != nil {
			return pl, internalError(err)
		}
		pl.secrets = b.Secrets.Merge(saved)
		savedCfg = monitorConfig(*prev)
	}
	b.Config.URL = strings.TrimSpace(b.Config.URL)
	b.Config.Host = strings.TrimSpace(b.Config.Host)
	b.Config.Name = strings.TrimSpace(b.Config.Name)
	b.Config.Resolver = strings.TrimSpace(b.Config.Resolver)
	b.Config.Container = strings.TrimSpace(b.Config.Container)
	b.Config.Unit = strings.TrimSpace(b.Config.Unit)
	b.Tags = cleanTags(b.Tags)
	if b.TimeoutSeconds > b.IntervalSeconds {
		return pl, fieldError("body.timeout_seconds", "The time limit can't be longer than the interval", b.TimeoutSeconds)
	}

	if err := h.planLocations(ctx, p, kind, b, prev, &pl); err != nil {
		return pl, err
	}
	fromServer := slices.ContainsFunc(pl.locs, func(l planLoc) bool { return l.server != nil })
	if e := uptime.Validate(kind, b.Config, fromServer); e != nil {
		return pl, fieldError("body."+e.Field, e.Message, nil)
	}

	pl.server = parseOptionalID(b.ServerID)
	if pl.server == nil && uptime.OnServer(kind) && len(pl.locs) == 1 {
		pl.server = pl.locs[0].server
	}
	if pl.server != nil && !slices.ContainsFunc(pl.locs, func(l planLoc) bool { return l.server != nil && *l.server == *pl.server }) {
		sws, err := h.q.GetServerWorkspace(ctx, *pl.server)
		if isNotFound(err) || (err == nil && p.Access.ServerLevel(sws, *pl.server) == auth.None) {
			return pl, fieldError("body.server_id", "Server not found", b.ServerID)
		}
		if err != nil {
			return pl, internalError(err)
		}
	}

	if b.AllowInternal && hasMorcheh(pl.locs) && !p.Access.Admin {
		kept := prev != nil && prev.AllowInternal && pl.hadMorcheh &&
			monitorTarget(kind, savedCfg) == monitorTarget(kind, b.Config) && savedCfg.Resolver == b.Config.Resolver
		if !kept {
			return pl, fieldError("body.allow_internal", "Only a system admin can allow private addresses", true)
		}
	}

	if b.ChannelIDs != nil {
		pl.setCh = true
		for _, raw := range b.ChannelIDs {
			id, err := uuid.Parse(raw)
			if err != nil {
				return pl, fieldError("body.channel_ids", "Channel not found", raw)
			}
			cws, err := h.q.GetNotificationChannelWorkspace(ctx, id)
			if isNotFound(err) || (err == nil && cws != ws) {
				return pl, fieldError("body.channel_ids", "That channel isn't in this monitor's workspace", raw)
			}
			if err != nil {
				return pl, internalError(err)
			}
			if !slices.Contains(pl.channels, id) {
				pl.channels = append(pl.channels, id)
			}
		}
	}
	return pl, nil
}

func (h *uptimeHandler) setChannels(ctx context.Context, monitor uuid.UUID, ids []uuid.UUID) error {
	if err := h.q.ClearMonitorChannels(ctx, monitor); err != nil {
		return err
	}
	for _, id := range ids {
		if err := h.q.AddMonitorChannel(ctx, sqlc.AddMonitorChannelParams{MonitorID: monitor, ChannelID: id}); err != nil {
			return err
		}
	}
	return nil
}

func (h *uptimeHandler) createMonitor(ctx context.Context, in *struct{ Body MonitorBody }) (*UptimeMonitorOutput, error) {
	p := principalOf(ctx)
	b := in.Body
	ws, err := h.authz.createTarget(ctx, p)
	if err != nil {
		return nil, err
	}
	if p.Access.WorkspaceLevel(ws) < auth.Engineer {
		return nil, huma.Error403Forbidden("You need Engineer access to the workspace to add a monitor.")
	}
	pl, err := h.planMonitor(ctx, p, ws, b.Kind, &b, nil)
	if err != nil {
		return nil, err
	}
	if !pl.setCh {
		pl.channels, _ = h.q.DefaultChannels(ctx, ws)
	}
	var token *string
	if b.Kind == uptime.Push {
		t := pushToken()
		token = &t
	}
	cfg, _ := json.Marshal(b.Config)
	m, err := h.q.CreateMonitor(ctx, sqlc.CreateMonitorParams{
		WorkspaceID: ws, Name: strings.TrimSpace(b.Name), Kind: b.Kind, Config: cfg,
		SecretsEnc:  h.sealJSON(pl.secrets, len(pl.secrets.Names()) == 0),
		Description: strings.TrimSpace(b.Description), Tags: b.Tags, ServerID: pl.server,
		RuleDown: pl.rule.Down, RuleDownCount: int32(pl.rule.DownCount),
		RuleDegraded: pl.rule.Degraded, RuleDegradedCount: int32(pl.rule.DegradedCount),
		IntervalSeconds: b.IntervalSeconds, RetrySeconds: b.RetrySeconds, TimeoutSeconds: b.TimeoutSeconds,
		Retries: b.Retries, ResendEvery: b.ResendEvery, NotifyDegraded: b.NotifyDegraded != nil && *b.NotifyDegraded,
		AllowInternal: b.AllowInternal, Paused: b.Paused, PushToken: token,
		CreatedByName: cmpOr(p.User.FullName, p.User.Username),
	})
	if isUniqueViolation(err) {
		return nil, fieldError("body.name", "A monitor with this name already exists", b.Name)
	}
	if err != nil {
		return nil, internalError(err)
	}
	if err := h.setChannels(ctx, m.ID, pl.channels); err != nil {
		return nil, internalError(err)
	}
	if err := h.setLocations(ctx, m.ID, pl.locs); err != nil {
		return nil, internalError(err)
	}
	return h.monitorOut(ctx, m, true)
}

func (h *uptimeHandler) updateMonitor(ctx context.Context, in *struct {
	MonitorIDPath
	Body MonitorBody
}) (*UptimeMonitorOutput, error) {
	p := principalOf(ctx)
	b := in.Body
	prev, err := h.getMonitor(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	if b.Kind != "" && b.Kind != prev.Kind {
		return nil, fieldError("body.kind", "The kind of a monitor can't change; add a new one", b.Kind)
	}
	pl, err := h.planMonitor(ctx, p, prev.WorkspaceID, prev.Kind, &b, &prev)
	if err != nil {
		return nil, err
	}
	token := prev.PushToken
	if prev.Kind == uptime.Push && (token == nil || b.ResetPushToken) {
		t := pushToken()
		token = &t
	}
	cfg, _ := json.Marshal(b.Config)
	m, err := h.q.UpdateMonitor(ctx, sqlc.UpdateMonitorParams{
		ID: prev.ID, Name: strings.TrimSpace(b.Name), Config: cfg,
		SecretsEnc:  h.sealJSON(pl.secrets, len(pl.secrets.Names()) == 0),
		Description: strings.TrimSpace(b.Description), Tags: b.Tags, ServerID: pl.server,
		RuleDown: pl.rule.Down, RuleDownCount: int32(pl.rule.DownCount),
		RuleDegraded: pl.rule.Degraded, RuleDegradedCount: int32(pl.rule.DegradedCount),
		IntervalSeconds: b.IntervalSeconds, RetrySeconds: b.RetrySeconds, TimeoutSeconds: b.TimeoutSeconds,
		Retries: b.Retries, ResendEvery: b.ResendEvery, NotifyDegraded: b.NotifyDegraded != nil && *b.NotifyDegraded,
		AllowInternal: b.AllowInternal, PushToken: token,
		UpdatedByName: cmpOr(p.User.FullName, p.User.Username),
	})
	if isUniqueViolation(err) {
		return nil, fieldError("body.name", "A monitor with this name already exists", b.Name)
	}
	if err != nil {
		return nil, internalError(err)
	}
	if pl.setCh {
		if err := h.setChannels(ctx, m.ID, pl.channels); err != nil {
			return nil, internalError(err)
		}
	}
	if err := h.setLocations(ctx, m.ID, pl.locs); err != nil {
		return nil, internalError(err)
	}
	return h.monitorOut(ctx, m, true)
}

type MonitorTestBody struct {
	MonitorBody
	MonitorID *string `json:"monitor_id,omitempty" format:"uuid" doc:"When editing: the saved monitor, whose secrets blank ones stand for"`
}

type MonitorTestOutput struct {
	Body uptime.CheckResult
}

// testMonitor runs a check with settings that aren't saved yet.
func (h *uptimeHandler) testMonitor(ctx context.Context, in *struct{ Body MonitorTestBody }) (*MonitorTestOutput, error) {
	p := principalOf(ctx)
	b := in.Body
	kind := b.Kind
	var prev *sqlc.Monitor
	var ws uuid.UUID
	if id := parseOptionalID(b.MonitorID); id != nil {
		m, err := h.q.GetMonitor(ctx, *id)
		if isNotFound(err) || (err == nil && p.Access.WorkspaceLevel(m.WorkspaceID) == auth.None) {
			return nil, huma.Error404NotFound("Monitor not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if p.Access.WorkspaceLevel(m.WorkspaceID) < auth.Engineer {
			return nil, huma.Error403Forbidden("You need Engineer access to the workspace to test this monitor.")
		}
		prev, ws, kind = &m, m.WorkspaceID, m.Kind
	} else {
		var err error
		if ws, err = h.authz.createTarget(ctx, p); err != nil {
			return nil, err
		}
		if p.Access.WorkspaceLevel(ws) < auth.Engineer {
			return nil, huma.Error403Forbidden("You need Engineer access to the workspace to add a monitor.")
		}
	}
	if kind == uptime.Push {
		return nil, huma.Error422UnprocessableEntity("A push monitor is checked by its heartbeats; there's nothing to test from here.")
	}
	b.ChannelIDs = nil
	pl, err := h.planMonitor(ctx, p, ws, kind, &b.MonitorBody, prev)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(max(b.TimeoutSeconds, 1)) * time.Second
	probes := h.runAll(ctx, kind, b.Config, pl.secrets, pl.locs, b.AllowInternal, timeout)
	return &MonitorTestOutput{Body: uptime.Combine(pl.rule, probes)}, nil
}

// ---- report ----

type ReportBucket struct {
	At         time.Time `json:"at"`
	Checks     int32     `json:"checks"`
	Up         int32     `json:"up"`
	Degraded   int32     `json:"degraded"`
	Down       int32     `json:"down"`
	LatencyAvg *float64  `json:"latency_avg,omitempty"`
	LatencyMax *int32    `json:"latency_max,omitempty"`
	LatencyP95 *float64  `json:"latency_p95,omitempty"`
}

type ReportWindow struct {
	Range  string   `json:"range"`
	Checks int64    `json:"checks"`
	Uptime *float64 `json:"uptime,omitempty"`
}

type ReportDay struct {
	Day      string `json:"day" doc:"YYYY-MM-DD, UTC"`
	Checks   int32  `json:"checks"`
	Up       int32  `json:"up"`
	Degraded int32  `json:"degraded"`
	Down     int32  `json:"down"`
}

type UptimeIncident struct {
	ID                 string     `json:"id" format:"uuid"`
	MonitorID          string     `json:"monitor_id" format:"uuid"`
	MonitorName        string     `json:"monitor_name,omitempty"`
	MonitorKind        string     `json:"monitor_kind,omitempty"`
	WorkspaceID        string     `json:"workspace_id,omitempty"`
	StartedAt          time.Time  `json:"started_at"`
	ResolvedAt         *time.Time `json:"resolved_at,omitempty"`
	Seconds            float64    `json:"seconds" doc:"How long it lasted (so far, when open)"`
	Cause              string     `json:"cause"`
	AcknowledgedAt     *time.Time `json:"acknowledged_at,omitempty"`
	AcknowledgedByName string     `json:"acknowledged_by_name"`
	Note               string     `json:"note"`
}

func toIncident(i sqlc.MonitorIncident) UptimeIncident {
	end := time.Now()
	if i.ResolvedAt != nil {
		end = *i.ResolvedAt
	}
	return UptimeIncident{
		ID: i.ID.String(), MonitorID: i.MonitorID.String(), StartedAt: i.StartedAt,
		ResolvedAt: i.ResolvedAt, Seconds: end.Sub(i.StartedAt).Seconds(), Cause: i.Cause,
		AcknowledgedAt: i.AcknowledgedAt, AcknowledgedByName: i.AcknowledgedByName, Note: i.Note,
	}
}

type MonitorReport struct {
	Range    string         `json:"range"`
	Step     int            `json:"step" doc:"Seconds per bucket"`
	Since    time.Time      `json:"since"`
	Buckets  []ReportBucket `json:"buckets"`
	Checks   int64          `json:"checks"`
	Up       int64          `json:"up"`
	Degraded int64          `json:"degraded"`
	Down     int64          `json:"down"`
	Uptime   *float64       `json:"uptime,omitempty"`
	// Latency over the range.
	LatencyAvg *float64 `json:"latency_avg,omitempty"`
	LatencyMax *int32   `json:"latency_max,omitempty"`
	// Downtime from incidents in the range.
	Incidents       int32            `json:"incidents"`
	DowntimeSeconds float64          `json:"downtime_seconds"`
	IncidentList    []UptimeIncident `json:"incident_list"`
	Windows         []ReportWindow   `json:"windows" doc:"Uptime over 24h, 7d, 30d and 365d"`
	Days            []ReportDay      `json:"days" doc:"The last 90 days, oldest first"`
	// Locations: each place's own answers, for a monitor checked from
	// several. Counted from the kept checks, so a long range may start later
	// (locations_since).
	Locations      []ReportLocation `json:"locations"`
	LocationsSince *time.Time       `json:"locations_since,omitempty"`
}

type ReportLocation struct {
	Location   string   `json:"location" doc:"morcheh, or the server's id"`
	Name       string   `json:"name"`
	Checks     int32    `json:"checks"`
	Up         int32    `json:"up"`
	Degraded   int32    `json:"degraded"`
	Down       int32    `json:"down"`
	Unknown    int32    `json:"unknown" doc:"Rounds it couldn't check in"`
	Uptime     *float64 `json:"uptime,omitempty" doc:"Of the rounds it could check in"`
	LatencyAvg *float64 `json:"latency_avg,omitempty"`
	LatencyP95 *float64 `json:"latency_p95,omitempty"`
	// Buckets line up with the report's (ranges up to 7d).
	Buckets []LocationBucket `json:"buckets"`
}

type LocationBucket struct {
	At         time.Time `json:"at"`
	Checks     int32     `json:"checks"`
	Down       int32     `json:"down"`
	LatencyAvg *float64  `json:"latency_avg,omitempty"`
}

// reportLocations fills each location's numbers, when there are several.
func (h *uptimeHandler) reportLocations(ctx context.Context, m sqlc.Monitor, out *MonitorReport, now time.Time) error {
	locs, err := h.q.ListMonitorLocations(ctx, m.ID)
	if err != nil {
		return err
	}
	if len(locs) < 2 {
		return nil
	}
	since := out.Since
	if h.history > 0 && since.Before(now.Add(-h.history)) {
		since = now.Add(-h.history)
		out.LocationsSince = &since
	}
	stats, err := h.q.MonitorLocationStats(ctx, sqlc.MonitorLocationStatsParams{MonitorID: m.ID, Since: since})
	if err != nil {
		return err
	}
	byLoc := map[string]sqlc.MonitorLocationStatsRow{}
	for _, s := range stats {
		byLoc[s.Loc] = s
	}
	buckets := map[string]map[int64]sqlc.MonitorLocationBucketsRow{}
	if out.Step > 0 && out.Step < 86400 {
		rows, err := h.q.MonitorLocationBuckets(ctx, sqlc.MonitorLocationBucketsParams{Step: int32(out.Step), Origin: out.Since, MonitorID: m.ID})
		if err != nil {
			return err
		}
		for _, r := range rows {
			if buckets[r.Loc] == nil {
				buckets[r.Loc] = map[int64]sqlc.MonitorLocationBucketsRow{}
			}
			buckets[r.Loc][r.Bucket.Unix()] = r
		}
	}
	for _, l := range locs {
		key := locKey(l.ServerID)
		s := byLoc[key]
		rl := ReportLocation{
			Location: key, Name: locName(l.ServerID, l.ServerName), Checks: s.Checks, Up: s.Up,
			Degraded: s.Degraded, Down: s.Down, Unknown: s.Unknown, Buckets: []LocationBucket{},
			Uptime: percent(int64(s.Up+s.Degraded), int64(s.Checks-s.Unknown)),
		}
		if s.LatencyAvg > 0 {
			avg, p95 := s.LatencyAvg, s.LatencyP95
			rl.LatencyAvg, rl.LatencyP95 = &avg, &p95
		}
		if got := buckets[key]; out.Step < 86400 {
			for _, b := range out.Buckets {
				lb := LocationBucket{At: b.At}
				if r, ok := got[b.At.Unix()]; ok {
					lb.Checks, lb.Down = r.Checks, r.Down
					if r.LatencyAvg > 0 {
						v := r.LatencyAvg
						lb.LatencyAvg = &v
					}
				}
				rl.Buckets = append(rl.Buckets, lb)
			}
		}
		out.Locations = append(out.Locations, rl)
	}
	return nil
}

var reportRanges = map[string]time.Duration{
	"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour,
	"90d": 90 * 24 * time.Hour, "365d": 365 * 24 * time.Hour,
}

func dayOf(t time.Time) pgtype.Date {
	t = t.UTC()
	return pgtype.Date{Time: time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC), Valid: true}
}

func (h *uptimeHandler) report(ctx context.Context, m sqlc.Monitor, rng string) (*MonitorReport, error) {
	span := reportRanges[rng]
	now := time.Now()
	out := &MonitorReport{Range: rng, Buckets: []ReportBucket{}, IncidentList: []UptimeIncident{}, Locations: []ReportLocation{}}
	ids := []uuid.UUID{m.ID}

	// Daily rows for the last 365 days serve the long ranges and windows.
	days, err := h.q.MonitorDaysSince(ctx, sqlc.MonitorDaysSinceParams{Ids: ids, Since: dayOf(now.AddDate(0, 0, -364))})
	if err != nil {
		return nil, internalError(err)
	}
	byDay := map[string]sqlc.MonitorDay{}
	for _, d := range days {
		byDay[d.Day.Time.Format(time.DateOnly)] = d
	}
	daysUptime := func(n int) ReportWindow {
		var good, all int64
		for i := range n {
			if d, ok := byDay[now.UTC().AddDate(0, 0, -i).Format(time.DateOnly)]; ok {
				good += int64(d.Up + d.Degraded)
				all += int64(d.Checks)
			}
		}
		return ReportWindow{Checks: all, Uptime: percent(good, all)}
	}

	if span <= 7*24*time.Hour {
		step := 15 * time.Minute
		if span > 24*time.Hour {
			step = 2 * time.Hour
		}
		origin := now.Add(-span).Truncate(step)
		out.Step, out.Since = int(step.Seconds()), origin
		rows, err := h.q.MonitorBuckets(ctx, sqlc.MonitorBucketsParams{Step: int32(step.Seconds()), Origin: origin, MonitorID: m.ID})
		if err != nil {
			return nil, internalError(err)
		}
		got := map[int64]sqlc.MonitorBucketsRow{}
		for _, r := range rows {
			got[r.Bucket.Unix()] = r
		}
		var latSum float64
		var latN int64
		for t := origin; !t.After(now); t = t.Add(step) {
			b := ReportBucket{At: t}
			if r, ok := got[t.Unix()]; ok {
				b.Checks, b.Up, b.Degraded, b.Down = r.Checks, r.Up, r.Degraded, r.Down
				avg, mx, p95 := r.LatencyAvg, r.LatencyMax, r.LatencyP95
				if mx > 0 || avg > 0 {
					b.LatencyAvg, b.LatencyMax, b.LatencyP95 = &avg, &mx, &p95
					latSum += avg * float64(r.Checks)
					latN += int64(r.Checks)
					if out.LatencyMax == nil || mx > *out.LatencyMax {
						v := mx
						out.LatencyMax = &v
					}
				}
			}
			out.Checks += int64(b.Checks)
			out.Up += int64(b.Up)
			out.Degraded += int64(b.Degraded)
			out.Down += int64(b.Down)
			out.Buckets = append(out.Buckets, b)
		}
		if latN > 0 {
			v := latSum / float64(latN)
			out.LatencyAvg = &v
		}
	} else {
		n := int(span / (24 * time.Hour))
		start := dayOf(now.AddDate(0, 0, -(n - 1))).Time
		out.Step, out.Since = 86400, start
		var latSum, latN int64
		for i := range n {
			t := start.AddDate(0, 0, i)
			b := ReportBucket{At: t}
			if d, ok := byDay[t.Format(time.DateOnly)]; ok {
				b.Checks, b.Up, b.Degraded, b.Down = d.Checks, d.Up, d.Degraded, d.Down
				if d.LatencyCount > 0 {
					avg := float64(d.LatencySum) / float64(d.LatencyCount)
					mx := d.LatencyMax
					b.LatencyAvg, b.LatencyMax = &avg, &mx
					latSum += d.LatencySum
					latN += int64(d.LatencyCount)
					if out.LatencyMax == nil || mx > *out.LatencyMax {
						v := mx
						out.LatencyMax = &v
					}
				}
			}
			out.Checks += int64(b.Checks)
			out.Up += int64(b.Up)
			out.Degraded += int64(b.Degraded)
			out.Down += int64(b.Down)
			out.Buckets = append(out.Buckets, b)
		}
		if latN > 0 {
			v := float64(latSum) / float64(latN)
			out.LatencyAvg = &v
		}
	}
	out.Uptime = percent(out.Up+out.Degraded, out.Checks)

	if rows, err := h.q.MonitorDowntimeSince(ctx, sqlc.MonitorDowntimeSinceParams{Since: out.Since, Ids: ids}); err == nil && len(rows) > 0 {
		out.Incidents, out.DowntimeSeconds = rows[0].Incidents, rows[0].Seconds
	}
	if rows, err := h.q.ListMonitorIncidents(ctx, sqlc.ListMonitorIncidentsParams{MonitorID: m.ID, Lim: 200}); err == nil {
		for _, i := range rows {
			if i.ResolvedAt == nil || i.ResolvedAt.After(out.Since) {
				out.IncidentList = append(out.IncidentList, toIncident(i))
			}
		}
	}

	// Windows: the short ones from the checks, the long ones from the days.
	out.Windows = []ReportWindow{}
	for _, w := range []struct {
		name string
		span time.Duration
	}{{"24h", 24 * time.Hour}, {"7d", 7 * 24 * time.Hour}} {
		win := ReportWindow{Range: w.name}
		if rows, err := h.q.MonitorUptimeSince(ctx, sqlc.MonitorUptimeSinceParams{Ids: ids, Since: now.Add(-w.span)}); err == nil && len(rows) > 0 {
			win.Checks = int64(rows[0].Checks)
			win.Uptime = percent(int64(rows[0].Up+rows[0].Degraded), win.Checks)
		}
		out.Windows = append(out.Windows, win)
	}
	for _, w := range []struct {
		name string
		days int
	}{{"30d", 30}, {"365d", 365}} {
		win := daysUptime(w.days)
		win.Range = w.name
		out.Windows = append(out.Windows, win)
	}

	out.Days = make([]ReportDay, 0, 90)
	for i := 89; i >= 0; i-- {
		key := now.UTC().AddDate(0, 0, -i).Format(time.DateOnly)
		d := byDay[key]
		out.Days = append(out.Days, ReportDay{Day: key, Checks: d.Checks, Up: d.Up, Degraded: d.Degraded, Down: d.Down})
	}
	if err := h.reportLocations(ctx, m, out, now); err != nil {
		return nil, internalError(err)
	}
	return out, nil
}

// MonitorCheck is one round of checks; locations lists each place's answer
// when it was checked from several.
type MonitorCheck struct {
	At        time.Time               `json:"at"`
	Status    string                  `json:"status"`
	LatencyMs *int32                  `json:"latency_ms,omitempty"`
	Code      string                  `json:"code"`
	Message   string                  `json:"message"`
	Locations []uptime.LocationResult `json:"locations"`
}

func toMonitorCheck(r sqlc.MonitorChecksBetweenRow, names map[string]string) MonitorCheck {
	c := MonitorCheck{At: r.At, Status: r.Status, LatencyMs: r.LatencyMs, Code: r.Code, Message: r.Message, Locations: []uptime.LocationResult{}}
	var res []checkResult
	if json.Unmarshal(r.Results, &res) == nil {
		for _, x := range res {
			name := names[x.Loc]
			if name == "" {
				name = "A removed server"
			}
			c.Locations = append(c.Locations, uptime.LocationResult{
				Location: x.Loc, Name: name, Status: x.Status, LatencyMs: x.LatencyMs, Code: x.Code, Message: x.Message,
			})
		}
	}
	return c
}

// ---- push ----

type PushInput struct {
	Token  string `path:"token" maxLength:"100"`
	Status string `query:"status" enum:"up,degraded,down," doc:"Default up"`
	Msg    string `query:"msg" maxLength:"1000"`
	Ping   int    `query:"ping" minimum:"0" maximum:"86400000" doc:"A latency to record, in milliseconds"`
}

type PushOutput struct {
	Body struct {
		OK bool `json:"ok"`
	}
}

func (h *uptimeHandler) push(ctx context.Context, in *PushInput) (*PushOutput, error) {
	token := in.Token
	m, err := h.q.GetMonitorByPushToken(ctx, &token)
	if isNotFound(err) || (err == nil && m.Kind != uptime.Push) {
		return nil, huma.Error404NotFound("No monitor has this address")
	}
	if err != nil {
		return nil, internalError(err)
	}
	out := &PushOutput{}
	out.Body.OK = true
	if m.Paused {
		return out, nil
	}
	r := uptime.CheckResult{Status: cmpOr(in.Status, uptime.Up), Message: strings.TrimSpace(in.Msg)}
	if r.Message == "" {
		r.Message = "Heartbeat"
	}
	if in.Ping > 0 {
		ms := in.Ping
		r.LatencyMs = &ms
	}
	// Wait out a check of the same monitor that's running (a missed-heartbeat
	// check takes no time).
	for i := 0; !h.claim(m.ID); i++ {
		if i > 50 {
			return nil, huma.Error503ServiceUnavailable("Busy, try again")
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer h.unclaim(m.ID)
	if m, err = h.q.GetMonitor(ctx, m.ID); err != nil {
		return nil, internalError(err)
	}
	h.apply(context.WithoutCancel(ctx), m, r, time.Now())
	return out, nil
}

// ---- routes ----

func registerMonitors(api huma.API, h *uptimeHandler) {
	tags := []string{"Uptime"}

	type listOut struct {
		Body struct {
			Items []UptimeMonitor `json:"items"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "list-monitors", Method: http.MethodGet, Path: "/monitors",
		Summary: "List uptime monitors", Tags: tags,
	}, func(ctx context.Context, in *struct {
		ServerID string `query:"server_id" doc:"Only monitors that belong to or check from this server"`
	}) (*listOut, error) {
		p := principalOf(ctx)
		sc := p.scope()
		params := sqlc.ListMonitorsParams{SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, WorkspaceID: sc.current}
		if in.ServerID != "" {
			id, err := uuid.Parse(in.ServerID)
			if err != nil {
				return nil, fieldError("server_id", "Not a server id", in.ServerID)
			}
			params.ServerID = &id
			params.WorkspaceID = nil
		}
		rows, err := h.q.ListMonitors(ctx, params)
		if err != nil {
			return nil, internalError(err)
		}
		out := &listOut{}
		out.Body.Items = make([]UptimeMonitor, 0, len(rows))
		for _, m := range rows {
			s, _ := h.monitorSecrets(m)
			out.Body.Items = append(out.Body.Items, toUptimeMonitor(m, s, p.Access.WorkspaceLevel(m.WorkspaceID) >= auth.Engineer))
		}
		h.enrich(ctx, out.Body.Items)
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-monitor", Method: http.MethodPost, Path: "/monitors",
		Summary: "Add an uptime monitor", Tags: tags, DefaultStatus: http.StatusCreated,
	}, h.createMonitor)

	huma.Register(api, huma.Operation{
		OperationID: "test-monitor-settings", Method: http.MethodPost, Path: "/monitors/test",
		Summary:     "Run a check with unsaved settings",
		Description: "Runs one check with the given settings and returns what it found, without saving anything.", Tags: tags,
	}, h.testMonitor)

	huma.Register(api, huma.Operation{
		OperationID: "get-monitor", Method: http.MethodGet, Path: "/monitors/{id}",
		Summary: "Get an uptime monitor", Tags: tags,
	}, func(ctx context.Context, in *MonitorIDPath) (*UptimeMonitorOutput, error) {
		m, err := h.getMonitor(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return h.monitorOut(ctx, m, principalOf(ctx).Level >= auth.Engineer)
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-monitor", Method: http.MethodPut, Path: "/monitors/{id}",
		Summary: "Update an uptime monitor", Tags: tags,
	}, h.updateMonitor)

	huma.Register(api, huma.Operation{
		OperationID: "delete-monitor", Method: http.MethodDelete, Path: "/monitors/{id}",
		Summary: "Remove an uptime monitor", Description: "Its history and incidents go with it.", Tags: tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *MonitorIDPath) (*struct{}, error) {
		m, err := h.getMonitor(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if err := h.q.DeleteMonitor(ctx, m.ID); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})

	type checkOut struct {
		Body struct {
			Result  uptime.CheckResult `json:"result"`
			Monitor UptimeMonitor      `json:"monitor"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "check-monitor", Method: http.MethodPost, Path: "/monitors/{id}/check",
		Summary: "Check now", Description: "Runs a check now and records it like a scheduled one.", Tags: tags,
	}, func(ctx context.Context, in *MonitorIDPath) (*checkOut, error) {
		m, err := h.getMonitor(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if m.Kind == uptime.Push {
			return nil, huma.Error422UnprocessableEntity("A push monitor is checked by its heartbeats.")
		}
		if !h.claim(m.ID) {
			return nil, huma.Error409Conflict("A check is already running")
		}
		defer h.unclaim(m.ID)
		r := h.checkMonitor(ctx, m)
		saved := h.apply(context.WithoutCancel(ctx), m, r, time.Now())
		o, err := h.monitorOut(ctx, saved, principalOf(ctx).Level >= auth.Engineer)
		if err != nil {
			return nil, err
		}
		out := &checkOut{}
		out.Body.Result, out.Body.Monitor = r, o.Body
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "pause-monitor", Method: http.MethodPost, Path: "/monitors/{id}/pause",
		Summary: "Pause or resume a monitor", Description: "Resuming starts over: pending until the next check.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		MonitorIDPath
		Body struct {
			Paused bool `json:"paused"`
		}
	}) (*UptimeMonitorOutput, error) {
		m, err := h.getMonitor(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if in.Body.Paused {
			// A paused monitor can't stay in an incident.
			now := time.Now()
			_ = h.q.ResolveMonitorIncident(ctx, sqlc.ResolveMonitorIncidentParams{MonitorID: m.ID, ResolvedAt: &now})
		}
		m, err = h.q.SetMonitorPaused(ctx, sqlc.SetMonitorPausedParams{ID: m.ID, Paused: in.Body.Paused})
		if err != nil {
			return nil, internalError(err)
		}
		if !in.Body.Paused {
			_ = h.q.ResetMonitorLocations(ctx, m.ID)
		}
		return h.monitorOut(ctx, m, principalOf(ctx).Level >= auth.Engineer)
	})

	type reportOut struct {
		Body *MonitorReport
	}
	huma.Register(api, huma.Operation{
		OperationID: "get-monitor-report", Method: http.MethodGet, Path: "/monitors/{id}/report",
		Summary: "A monitor's report", Description: "Uptime, response times and incidents over a range.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		MonitorIDPath
		Range string `query:"range" enum:"24h,7d,30d,90d,365d" default:"24h"`
	}) (*reportOut, error) {
		m, err := h.getMonitor(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		r, err := h.report(ctx, m, cmpOr(in.Range, "24h"))
		if err != nil {
			return nil, err
		}
		return &reportOut{Body: r}, nil
	})

	type checksOut struct {
		Body struct {
			Items []MonitorCheck `json:"items"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "list-monitor-checks", Method: http.MethodGet, Path: "/monitors/{id}/checks",
		Summary: "A monitor's checks", Description: "Newest first. Old checks are pruned (MONITOR_HISTORY).", Tags: tags,
	}, func(ctx context.Context, in *struct {
		MonitorIDPath
		Since  time.Time `query:"since" doc:"Default: the start"`
		Until  time.Time `query:"until" doc:"Default: now"`
		Status string    `query:"status" enum:"up,degraded,down," doc:"Only checks with this result"`
		Limit  int32     `query:"limit" minimum:"1" maximum:"2000" default:"200"`
	}) (*checksOut, error) {
		m, err := h.getMonitor(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		until := in.Until
		if until.IsZero() {
			until = time.Now().Add(time.Minute)
		}
		lim := in.Limit
		if in.Status != "" {
			lim = 5000
		}
		rows, err := h.q.MonitorChecksBetween(ctx, sqlc.MonitorChecksBetweenParams{MonitorID: m.ID, Since: in.Since, Until: until, Lim: lim})
		if err != nil {
			return nil, internalError(err)
		}
		out := &checksOut{}
		names := map[string]string{}
		if locs, err := h.q.ListMonitorLocations(ctx, m.ID); err == nil {
			for _, l := range locs {
				names[locKey(l.ServerID)] = locName(l.ServerID, l.ServerName)
			}
		}
		out.Body.Items = make([]MonitorCheck, 0, len(rows))
		for _, r := range rows {
			if in.Status == "" || r.Status == in.Status {
				out.Body.Items = append(out.Body.Items, toMonitorCheck(r, names))
			}
			if int32(len(out.Body.Items)) >= in.Limit {
				break
			}
		}
		return out, nil
	})

	type eventsOut struct {
		Body struct {
			Items []sqlc.MonitorEvent `json:"items"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "list-monitor-events", Method: http.MethodGet, Path: "/monitors/{id}/events",
		Summary: "A monitor's status changes", Description: "Newest first.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		MonitorIDPath
		Limit int32 `query:"limit" minimum:"1" maximum:"1000" default:"100"`
	}) (*eventsOut, error) {
		m, err := h.getMonitor(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		rows, err := h.q.ListMonitorEvents(ctx, sqlc.ListMonitorEventsParams{MonitorID: m.ID, Lim: in.Limit})
		if err != nil {
			return nil, internalError(err)
		}
		out := &eventsOut{}
		out.Body.Items = rows
		return out, nil
	})

	type incidentsOut struct {
		Body struct {
			Items []UptimeIncident `json:"items"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "list-monitor-incidents", Method: http.MethodGet, Path: "/monitors/{id}/incidents",
		Summary: "A monitor's incidents", Description: "Newest first.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		MonitorIDPath
		Limit int32 `query:"limit" minimum:"1" maximum:"1000" default:"100"`
	}) (*incidentsOut, error) {
		m, err := h.getMonitor(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		rows, err := h.q.ListMonitorIncidents(ctx, sqlc.ListMonitorIncidentsParams{MonitorID: m.ID, Lim: in.Limit})
		if err != nil {
			return nil, internalError(err)
		}
		out := &incidentsOut{}
		out.Body.Items = make([]UptimeIncident, 0, len(rows))
		for _, r := range rows {
			i := toIncident(r)
			i.MonitorName, i.MonitorKind, i.WorkspaceID = m.Name, m.Kind, m.WorkspaceID.String()
			out.Body.Items = append(out.Body.Items, i)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-incidents", Method: http.MethodGet, Path: "/monitor-incidents",
		Summary: "Incidents across monitors", Description: "Newest first, in the workspaces you can see.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		Open  bool  `query:"open" doc:"Only the ones still going on"`
		Limit int32 `query:"limit" minimum:"1" maximum:"1000" default:"200"`
	}) (*incidentsOut, error) {
		sc := principalOf(ctx).scope()
		rows, err := h.q.ListWorkspaceIncidents(ctx, sqlc.ListWorkspaceIncidentsParams{
			SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, WorkspaceID: sc.current, OpenOnly: in.Open, Lim: in.Limit,
		})
		if err != nil {
			return nil, internalError(err)
		}
		out := &incidentsOut{}
		out.Body.Items = make([]UptimeIncident, 0, len(rows))
		for _, r := range rows {
			i := toIncident(sqlc.MonitorIncident{
				ID: r.ID, MonitorID: r.MonitorID, StartedAt: r.StartedAt, ResolvedAt: r.ResolvedAt, Cause: r.Cause,
				AcknowledgedAt: r.AcknowledgedAt, AcknowledgedByName: r.AcknowledgedByName, Note: r.Note,
			})
			i.MonitorName, i.MonitorKind, i.WorkspaceID = r.MonitorName, r.MonitorKind, r.WorkspaceID.String()
			out.Body.Items = append(out.Body.Items, i)
		}
		return out, nil
	})

	type incidentOut struct {
		Body UptimeIncident
	}
	huma.Register(api, huma.Operation{
		OperationID: "acknowledge-monitor-incident", Method: http.MethodPost, Path: "/monitor-incidents/{id}/acknowledge",
		Summary: "Acknowledge an incident", Description: "Says someone is on it, with an optional note.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		ID   string `path:"id" format:"uuid"`
		Body struct {
			Note string `json:"note,omitempty" maxLength:"2000"`
		}
	}) (*incidentOut, error) {
		p := principalOf(ctx)
		id, _ := uuid.Parse(in.ID)
		i, err := h.q.AcknowledgeMonitorIncident(ctx, sqlc.AcknowledgeMonitorIncidentParams{
			ID: id, Name: cmpOr(p.User.FullName, p.User.Username), Note: strings.TrimSpace(in.Body.Note),
		})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("incident not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &incidentOut{Body: toIncident(i)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "push-heartbeat", Method: http.MethodGet, Path: "/push/{token}",
		Summary:     "Send a heartbeat",
		Description: "For push monitors: call it from a cron job or an app. No sign-in; the token is the secret.",
		Tags:        tags,
	}, h.push)
	huma.Register(api, huma.Operation{
		OperationID: "push-heartbeat-post", Method: http.MethodPost, Path: "/push/{token}",
		Summary: "Send a heartbeat (POST)", Description: "Same as the GET.", Tags: tags,
	}, h.push)
}
