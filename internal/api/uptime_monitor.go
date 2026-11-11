package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/notify"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/uptime"
)

// The uptime scheduler: every second it picks the monitors that are due,
// checks them (a few at a time), records the result, opens and closes
// incidents and sends the alerts.

const uptimeWorkers = 32

func startUptimeMonitor(h *uptimeHandler) {
	go func() {
		sem := make(chan struct{}, uptimeWorkers)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		var pruned time.Time
		for range tick.C {
			ctx := context.Background()
			if time.Since(pruned) > time.Hour {
				pruned = time.Now()
				if n, err := h.q.PruneMonitorChecks(ctx, time.Now().Add(-h.history)); err != nil {
					slog.Warn("uptime: prune checks", "err", err)
				} else if n > 0 {
					slog.Debug("uptime: pruned checks", "rows", n)
				}
			}
			due, err := h.q.ListDueMonitors(ctx, 100)
			if err != nil {
				slog.Warn("uptime: list due monitors", "err", err)
				continue
			}
			for _, m := range due {
				if !h.claim(m.ID) {
					continue
				}
				select {
				case sem <- struct{}{}:
				default:
					// Every worker is busy: it stays due for the next tick.
					h.unclaim(m.ID)
					continue
				}
				go func(id uuid.UUID) {
					defer func() { <-sem }()
					defer h.unclaim(id)
					h.runDue(id)
				}(m.ID)
			}
		}
	}()
}

// runDue checks one due monitor. The caller holds its claim.
func (h *uptimeHandler) runDue(id uuid.UUID) {
	ctx := context.Background()
	m, err := h.q.GetMonitor(ctx, id)
	if err != nil || m.Paused {
		return
	}
	now := time.Now()
	if m.Kind == uptime.Push {
		h.missedBeat(ctx, m, now)
		return
	}
	r := h.checkMonitor(ctx, m)
	h.apply(ctx, m, r, time.Now())
}

// missedBeat runs when a push monitor's time is up: no heartbeat came in.
func (h *uptimeHandler) missedBeat(ctx context.Context, m sqlc.Monitor, now time.Time) {
	interval := time.Duration(m.IntervalSeconds) * time.Second
	if m.FailCount == 0 && m.Status != uptime.Down {
		last := m.CreatedAt
		for _, t := range []time.Time{m.StatusSince, m.UpdatedAt} {
			if t.After(last) {
				last = t
			}
		}
		if m.LastCheckedAt != nil && m.LastCheckedAt.After(last) {
			last = *m.LastCheckedAt
		}
		if deadline := last.Add(interval); deadline.After(now) {
			_ = h.q.DelayMonitor(ctx, sqlc.DelayMonitorParams{ID: m.ID, NextCheckAt: deadline})
			return
		}
	}
	h.apply(ctx, m, uptime.CheckResult{Status: uptime.Down, Message: "No heartbeat in " + humanDuration(interval)}, now)
}

func (h *uptimeHandler) checkMonitor(ctx context.Context, m sqlc.Monitor) uptime.CheckResult {
	s, err := h.monitorSecrets(m)
	if err != nil {
		return uptime.CheckResult{Status: uptime.Down, Message: "Couldn't read the saved secrets"}
	}
	timeout := time.Duration(max(m.TimeoutSeconds, 1)) * time.Second
	rows, err := h.q.ListMonitorLocations(ctx, m.ID)
	if err != nil {
		return uptime.CheckResult{Status: uptime.Down, Message: "Couldn't read where to check from"}
	}
	probes := h.runAll(ctx, m.Kind, monitorConfig(m), s, planLocs(rows), m.AllowInternal, timeout)
	return uptime.Combine(ruleOf(m), probes)
}

// runAll checks from every location at once. A location whose server can't
// be reached is marked unreachable: it doesn't vote.
func (h *uptimeHandler) runAll(ctx context.Context, kind string, c uptime.MonitorConfig, s uptime.MonitorSecrets, locs []planLoc, allowInternal bool, timeout time.Duration) []uptime.Probe {
	probes := make([]uptime.Probe, len(locs))
	var wg sync.WaitGroup
	for i, l := range locs {
		wg.Go(func() {
			r := h.runCheck(ctx, kind, c, s, l.server, allowInternal, timeout)
			probes[i] = uptime.Probe{Location: l.key, Name: l.name, Result: r, Unreachable: l.server != nil && r.Code == "via"}
		})
	}
	wg.Wait()
	return probes
}

// checkResult is one location's answer as kept in a check row.
type checkResult struct {
	Loc       string `json:"loc"`
	Status    string `json:"status"`
	LatencyMs *int   `json:"latency_ms,omitempty"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message"`
}

func checkResults(locs []uptime.LocationResult) []byte {
	if len(locs) < 2 {
		return []byte("[]")
	}
	out := make([]checkResult, len(locs))
	for i, l := range locs {
		out[i] = checkResult{Loc: l.Location, Status: l.Status, LatencyMs: l.LatencyMs, Code: clipText(l.Code, 100), Message: clipText(l.Message, 300)}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return []byte("[]")
	}
	return b
}

// saveLocations keeps each location's own latest answer.
func (h *uptimeHandler) saveLocations(ctx context.Context, m sqlc.Monitor, locs []uptime.LocationResult, at time.Time) {
	if len(locs) == 0 {
		return
	}
	rows, err := h.q.ListMonitorLocations(ctx, m.ID)
	if err != nil {
		return
	}
	for _, row := range rows {
		key := locKey(row.ServerID)
		for _, l := range locs {
			if l.Location != key {
				continue
			}
			_ = h.q.SaveMonitorLocation(ctx, sqlc.SaveMonitorLocationParams{
				ID: row.ID, Status: l.Status, StatusMessage: clipText(l.Message, 1000),
				LatencyMs: int32p(l.LatencyMs), Code: clipText(l.Code, 100), CheckedAt: &at,
			})
		}
	}
}

// locationsLine says how each location answered: "Morcheh: up · vm1: down".
func locationsLine(locs []uptime.LocationResult) string {
	parts := make([]string, len(locs))
	for i, l := range locs {
		st := l.Status
		if st == uptime.Unknown {
			st = "couldn't check"
		}
		parts[i] = l.Name + ": " + st
	}
	return strings.Join(parts, " · ")
}

// runCheck runs one check, from Morcheh or through a server over SSH.
func (h *uptimeHandler) runCheck(ctx context.Context, kind string, c uptime.MonitorConfig, s uptime.MonitorSecrets, via *uuid.UUID, allowInternal bool, timeout time.Duration) uptime.CheckResult {
	env := uptime.Env{AllowInternal: allowInternal, Timeout: timeout}
	if via != nil {
		cctx, cancel := context.WithTimeout(ctx, timeout+20*time.Second)
		defer cancel()
		conn, err := h.servers.conn(cctx, via.String())
		if err != nil {
			return uptime.CheckResult{Status: uptime.Down, Code: "via", Message: "Can't reach the server it runs from: " + errDetail(err)}
		}
		conn.Acquire()
		defer conn.Release()
		env.Dial, env.Run, env.Tunneled = conn.Client.DialContext, sshRunner(conn), true
	}
	return uptime.Check(ctx, kind, c, s, env)
}

// capWriter keeps the first max bytes written to it, from several goroutines.
type capWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (w *capWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if room := w.max - w.buf.Len(); room > 0 {
		w.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (w *capWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// sshRunner runs argv on the server. It returns ctx.Err() when the time
// limit cut it off, and an error only when the command couldn't run.
func sshRunner(c *sshpool.Conn) uptime.Runner {
	return func(ctx context.Context, argv []string) (string, int, error) {
		sess, err := c.Client.NewSession()
		if err != nil {
			return "", 0, err
		}
		defer sess.Close()
		out := &capWriter{max: 64 << 10}
		sess.Stdout, sess.Stderr = out, out
		stop := context.AfterFunc(ctx, func() { _ = sess.Close() })
		defer stop()
		err = sess.Run(quoteAll(argv))
		if ctx.Err() != nil {
			return out.String(), 0, ctx.Err()
		}
		var exit *ssh.ExitError
		if errors.As(err, &exit) {
			return out.String(), exit.ExitStatus(), nil
		}
		if err != nil {
			return out.String(), 0, err
		}
		return out.String(), 0, nil
	}
}

func int32p(v *int) *int32 {
	if v == nil {
		return nil
	}
	n := int32(min(*v, 1<<31-1))
	return &n
}

// apply records a check's result and moves the monitor's state on: retries,
// status changes, incidents and alerts. The caller holds the claim.
func (h *uptimeHandler) apply(ctx context.Context, m sqlc.Monitor, r uptime.CheckResult, at time.Time) sqlc.Monitor {
	if r.Status != uptime.Up && r.Status != uptime.Degraded {
		r.Status = uptime.Down
	}
	lat := int32p(r.LatencyMs)
	if err := h.q.InsertMonitorCheck(ctx, sqlc.InsertMonitorCheckParams{
		MonitorID: m.ID, At: at, Status: r.Status, LatencyMs: lat, Code: clipText(r.Code, 100), Message: clipText(r.Message, 1000),
		Results: checkResults(r.Locations),
	}); err != nil {
		slog.Warn("uptime: save check", "monitor", m.ID, "err", err)
	}
	h.saveLocations(ctx, m, r.Locations, at)
	_ = h.q.AddMonitorDay(ctx, sqlc.AddMonitorDayParams{MonitorID: m.ID, Day: dayOf(at), Status: r.Status, LatencyMs: lat})

	st := sqlc.SaveMonitorStateParams{
		ID: m.ID, Status: m.Status, StatusMessage: m.StatusMessage, StatusSince: m.StatusSince,
		FailCount: m.FailCount, DownChecks: m.DownChecks, LastLatencyMs: lat, LastCheckedAt: &at,
		NextCheckAt: at.Add(time.Duration(m.IntervalSeconds) * time.Second), CertExpiresAt: r.CertExpires,
	}
	next := r.Status
	if r.Status == uptime.Down {
		st.FailCount++
		if m.Status != uptime.Down && st.FailCount <= m.Retries {
			// Not sure yet: keep the status and look again soon.
			next = m.Status
			st.NextCheckAt = at.Add(time.Duration(m.RetrySeconds) * time.Second)
		}
	} else {
		st.FailCount = 0
	}
	if next == r.Status {
		st.StatusMessage = clipText(r.Message, 1000)
	}

	prev := m.Status
	if next != prev {
		st.Status, st.StatusSince = next, at
		_ = h.q.InsertMonitorEvent(ctx, sqlc.InsertMonitorEventParams{
			MonitorID: m.ID, At: at, FromStatus: prev, ToStatus: next, Message: clipText(r.Message, 1000),
		})
		if next == uptime.Down {
			st.DownChecks = 1
			_ = h.q.OpenMonitorIncident(ctx, sqlc.OpenMonitorIncidentParams{MonitorID: m.ID, StartedAt: at, Cause: clipText(r.Message, 1000)})
		} else {
			st.DownChecks = 0
		}
		if prev == uptime.Down {
			_ = h.q.ResolveMonitorIncident(ctx, sqlc.ResolveMonitorIncidentParams{MonitorID: m.ID, ResolvedAt: &at})
		}
		h.alertChange(m, prev, next, r, at)
	} else if next == uptime.Down {
		st.DownChecks++
		if m.ResendEvery > 0 && st.DownChecks > 1 && (st.DownChecks-1)%m.ResendEvery == 0 {
			h.alert(m, notify.EventReminder, m.Name+" is still down", r, at, at.Sub(m.StatusSince))
		}
	}

	saved, err := h.q.SaveMonitorState(ctx, st)
	if err != nil {
		slog.Warn("uptime: save state", "monitor", m.ID, "err", err)
		return m
	}
	return saved
}

// alertChange sends the alert for a status change, if it deserves one.
func (h *uptimeHandler) alertChange(m sqlc.Monitor, prev, next string, r uptime.CheckResult, at time.Time) {
	lasted := at.Sub(m.StatusSince)
	switch {
	case next == uptime.Down:
		h.alert(m, notify.EventDown, m.Name+" is down", r, at, 0)
	case prev == uptime.Down && next == uptime.Up:
		h.alert(m, notify.EventUp, m.Name+" is back up", r, at, lasted)
	case prev == uptime.Down && next == uptime.Degraded:
		h.alert(m, notify.EventUp, m.Name+" is back up, but degraded", r, at, lasted)
	case !m.NotifyDegraded:
	case next == uptime.Degraded:
		h.alert(m, notify.EventDegraded, m.Name+" is degraded", r, at, 0)
	case prev == uptime.Degraded && next == uptime.Up:
		h.alert(m, notify.EventUp, m.Name+" is back to normal", r, at, lasted)
	}
}

// alert sends a message to the monitor's channels, in the background.
func (h *uptimeHandler) alert(m sqlc.Monitor, event, title string, r uptime.CheckResult, at time.Time, lasted time.Duration) {
	cfg := monitorConfig(m)
	fields := []notify.Field{{Name: "Check", Value: kindLabel(m.Kind)}}
	if t := monitorTarget(m.Kind, cfg); t != "" {
		fields = append(fields, notify.Field{Name: "Target", Value: t})
	}
	if lasted > 0 {
		name := "Down for"
		if event != notify.EventReminder {
			name = "Was down for"
			if event == notify.EventUp && m.Status == uptime.Degraded {
				name = "Was degraded for"
			}
		}
		fields = append(fields, notify.Field{Name: name, Value: humanDuration(lasted)})
	}
	if r.LatencyMs != nil {
		fields = append(fields, notify.Field{Name: "Response", Value: uptime.Ms(*r.LatencyMs)})
	}
	if r.Code != "" {
		fields = append(fields, notify.Field{Name: "Code", Value: r.Code})
	}
	if len(r.Locations) > 1 {
		fields = append(fields, notify.Field{Name: "Locations", Value: locationsLine(r.Locations)})
	}
	url := ""
	if h.panelURL != "" {
		url = h.panelURL + "/uptime/" + m.ID.String()
	}
	msg := notify.Message{
		Event: event, Title: title, Text: r.Message, URL: url, Fields: fields, At: at,
		Data: map[string]any{
			"monitor_id": m.ID.String(), "monitor_name": m.Name, "kind": m.Kind,
			"status": r.Status, "message": r.Message, "code": r.Code, "latency_ms": r.LatencyMs,
		},
	}
	if len(r.Locations) > 1 {
		msg.Data["locations"] = r.Locations
	}
	go func() {
		ctx := context.Background()
		chans, err := h.q.ChannelsToNotify(ctx, m.ID)
		if err != nil {
			slog.Warn("uptime: channels to notify", "monitor", m.ID, "err", err)
			return
		}
		for _, c := range chans {
			go func(c sqlc.NotificationChannel) {
				ch, err := h.sendable(c)
				if err == nil {
					sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
					err = notify.Send(sctx, ch, msg)
					cancel()
				}
				h.recordSend(ctx, c.ID, &m.ID, title, err)
			}(c)
		}
	}()
}

var kindLabels = map[string]string{
	uptime.HTTP: "HTTP(S)", uptime.TCP: "TCP port", uptime.UDP: "UDP port", uptime.Ping: "Ping",
	uptime.DNS: "DNS", uptime.TLS: "TLS certificate", uptime.WebSocket: "WebSocket", uptime.SocketIO: "Socket.IO",
	uptime.SMTP: "Mail server", uptime.Database: "Database", uptime.RabbitMQ: "RabbitMQ", uptime.Kafka: "Kafka",
	uptime.NATS: "NATS", uptime.MQTT: "MQTT", uptime.Memcached: "Memcached", uptime.Elasticsearch: "Elasticsearch",
	uptime.Docker: "Docker container", uptime.Systemd: "systemd unit", uptime.Command: "Command", uptime.Push: "Push",
}

func kindLabel(kind string) string {
	if l, ok := kindLabels[kind]; ok {
		return l
	}
	return kind
}

// humanDuration says a duration the short way: 45 s, 12 min, 3 h 5 min, 2 d 4 h.
func humanDuration(d time.Duration) string {
	s := int64(d.Round(time.Second) / time.Second)
	switch {
	case s < 60:
		return fmt.Sprintf("%d s", s)
	case s < 3600:
		return fmt.Sprintf("%d min", s/60)
	case s < 86400:
		if m := s % 3600 / 60; m > 0 {
			return fmt.Sprintf("%d h %d min", s/3600, m)
		}
		return fmt.Sprintf("%d h", s/3600)
	default:
		if h := s % 86400 / 3600; h > 0 {
			return fmt.Sprintf("%d d %d h", s/86400, h)
		}
		return fmt.Sprintf("%d d", s/86400)
	}
}
