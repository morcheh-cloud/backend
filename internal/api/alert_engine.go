package api

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/notify"
	"github.com/morcheh/backend/internal/sshprobe"
)

// Alert rules on server metrics are checked here: against every resource
// sample (cpu, memory, disk…) and, for "offline", every connection check. A
// rule fires on a server once its condition has held for for_minutes, sends to
// its channels, reminds every repeat_minutes, and resolves when it clears.

const (
	metricCPU     = "cpu"
	metricIOWait  = "iowait"
	metricLoad    = "load"
	metricMemory  = "memory"
	metricSwap    = "swap"
	metricDisk    = "disk"
	metricNetRx   = "net_rx"
	metricNetTx   = "net_tx"
	metricOffline = "offline"
)

var metricLabels = map[string]string{
	metricCPU: "CPU", metricIOWait: "I/O wait", metricLoad: "Load per core",
	metricMemory: "Memory", metricSwap: "Swap", metricDisk: "Disk",
	metricNetRx: "Download", metricNetTx: "Upload", metricOffline: "Unreachable",
}

// percentMetric says whether a metric's threshold is a percent (0–100).
func percentMetric(m string) bool {
	switch m {
	case metricCPU, metricIOWait, metricMemory, metricSwap, metricDisk:
		return true
	}
	return false
}

// formatMetric writes a value the way people read it.
func formatMetric(metric string, v float64) string {
	switch {
	case percentMetric(metric):
		return fmt.Sprintf("%.1f%%", v)
	case metric == metricLoad:
		return fmt.Sprintf("%.2f per core", v)
	case metric == metricNetRx, metric == metricNetTx:
		return fmt.Sprintf("%.1f Mbit/s", v*8/1e6)
	}
	return fmt.Sprintf("%g", v)
}

// ruleCondition is "above 90%", or "unreachable".
func ruleCondition(r sqlc.AlertRule) string {
	if r.Metric == metricOffline {
		return "unreachable"
	}
	return r.Op + " " + formatMetric(r.Metric, r.Threshold)
}

// metricSample is what one resource sample says, in the units rules use.
type metricSample struct {
	at     time.Time
	cpu    float64
	iowait float64
	load   float64 // per core
	mem    float64
	swap   float64 // -1 without swap
	disks  []diskUse
	rx, tx float64 // bytes per second
}

type diskUse struct {
	mount   string
	percent float64
}

// value is the rule's metric in this sample; ok = false when it has none (no
// swap, the mount isn't there).
func (s metricSample) value(r sqlc.AlertRule) (v float64, detail string, ok bool) {
	switch r.Metric {
	case metricCPU:
		return s.cpu, "", true
	case metricIOWait:
		return s.iowait, "", true
	case metricLoad:
		return s.load, "", true
	case metricMemory:
		return s.mem, "", true
	case metricSwap:
		return s.swap, "", s.swap >= 0
	case metricNetRx:
		return s.rx, "", true
	case metricNetTx:
		return s.tx, "", true
	case metricDisk:
		found := false
		for _, d := range s.disks {
			if r.Mount != "" {
				if d.mount == r.Mount {
					return d.percent, d.mount, true
				}
				continue
			}
			if !found || d.percent > v {
				v, detail, found = d.percent, d.mount, true
			}
		}
		return v, detail, found
	}
	return 0, "", false
}

func breached(r sqlc.AlertRule, v float64) bool {
	if r.Op == "below" {
		return v < r.Threshold
	}
	return v > r.Threshold
}

type alertEngine struct {
	q  *sqlc.Queries
	up *uptimeHandler
	// A state not updated for this long is stale (no samples came: the server
	// was off, or sampling stopped): its breach starts over.
	stale time.Duration
	mu    sync.Mutex
}

func newAlertEngine(q *sqlc.Queries, up *uptimeHandler, sampleEvery time.Duration) *alertEngine {
	return &alertEngine{q: q, up: up, stale: max(3*sampleEvery, 10*time.Minute)}
}

func serverTags(s sqlc.Server) []string {
	if s.Tags == nil {
		return []string{}
	}
	return s.Tags
}

// onSample checks a server's metric rules against a new sample.
func (e *alertEngine) onSample(ctx context.Context, srv sqlc.Server, s metricSample) {
	rules, err := e.q.AlertRulesForServer(ctx, sqlc.AlertRulesForServerParams{
		WorkspaceID: srv.WorkspaceID, ServerID: srv.ID, Tags: serverTags(srv),
	})
	if err != nil {
		slog.Warn("alerts: rules for server", "server", srv.ID, "error", err)
		return
	}
	for _, r := range rules {
		if r.Metric == metricOffline {
			continue
		}
		v, detail, ok := s.value(r)
		if !ok {
			continue
		}
		e.step(ctx, r, srv, breached(r, v), v, detail, s.at)
	}
}

// onStatus checks a server's "offline" rules against a connection check.
func (e *alertEngine) onStatus(ctx context.Context, srv sqlc.Server, res sshprobe.Result) {
	rules, err := e.q.AlertRulesForServer(ctx, sqlc.AlertRulesForServerParams{
		WorkspaceID: srv.WorkspaceID, ServerID: srv.ID, Tags: serverTags(srv),
	})
	if err != nil {
		slog.Warn("alerts: rules for server", "server", srv.ID, "error", err)
		return
	}
	down := res.Status != sshprobe.StatusOnline
	v, detail := 0.0, ""
	if down {
		v, detail = 1, cmpOr(res.Message, statusText(res.Status))
	}
	for _, r := range rules {
		if r.Metric == metricOffline {
			e.step(ctx, r, srv, down, v, detail, time.Now().UTC())
		}
	}
}

func statusText(status string) string {
	switch status {
	case sshprobe.StatusUnreachable:
		return "Can't be reached"
	case sshprobe.StatusAuthFailed:
		return "Sign-in refused"
	case sshprobe.StatusHostKeyMismatch:
		return "Host key changed"
	}
	return "Check failed"
}

// step moves a rule's state on a server along by one reading.
func (e *alertEngine) step(ctx context.Context, r sqlc.AlertRule, srv sqlc.Server, met bool, v float64, detail string, at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st, err := e.q.GetAlertState(ctx, sqlc.GetAlertStateParams{RuleID: r.ID, ServerID: srv.ID})
	found := err == nil
	if err != nil && !isNotFound(err) {
		slog.Warn("alerts: get state", "rule", r.ID, "server", srv.ID, "error", err)
		return
	}
	if !met && (!found || (st.BreachSince == nil && st.FiringSince == nil)) {
		return // nothing going on, nothing to write
	}
	next := sqlc.UpsertAlertStateParams{
		RuleID: r.ID, ServerID: srv.ID, BreachSince: st.BreachSince, FiringSince: st.FiringSince,
		LastSentAt: st.LastSentAt, Value: v, Detail: detail,
	}
	if met {
		if next.BreachSince != nil && next.FiringSince == nil && at.Sub(st.UpdatedAt) > e.stale {
			next.BreachSince = nil
		}
		if next.BreachSince == nil {
			next.BreachSince = &at
		}
		switch {
		case next.FiringSince == nil:
			if at.Sub(*next.BreachSince) >= time.Duration(r.ForMinutes)*time.Minute {
				next.FiringSince, next.LastSentAt = &at, &at
				e.event(ctx, r, srv, "fired", v, detail, 0, at)
				e.send(r, srv, "fired", v, detail, at.Sub(*next.BreachSince), at)
			}
		case r.RepeatMinutes > 0 && (next.LastSentAt == nil ||
			at.Sub(*next.LastSentAt) >= time.Duration(r.RepeatMinutes)*time.Minute):
			next.LastSentAt = &at
			e.send(r, srv, "reminder", v, detail, at.Sub(*next.BreachSince), at)
		}
	} else {
		if next.FiringSince != nil {
			since := *next.FiringSince
			if next.BreachSince != nil {
				since = *next.BreachSince
			}
			lasted := at.Sub(since)
			e.event(ctx, r, srv, "resolved", v, detail, lasted, at)
			if r.NotifyResolved {
				e.send(r, srv, "resolved", v, detail, lasted, at)
			}
		}
		next.BreachSince, next.FiringSince, next.LastSentAt = nil, nil, nil
	}
	if err := e.q.UpsertAlertState(ctx, next); err != nil {
		slog.Warn("alerts: save state", "rule", r.ID, "server", srv.ID, "error", err)
	}
}

func (e *alertEngine) event(ctx context.Context, r sqlc.AlertRule, srv sqlc.Server, kind string, v float64, detail string, lasted time.Duration, at time.Time) {
	rid, sid := r.ID, srv.ID
	if err := e.q.InsertAlertEvent(ctx, sqlc.InsertAlertEventParams{
		WorkspaceID: r.WorkspaceID, RuleID: &rid, ServerID: &sid, RuleName: r.Name, ServerName: srv.Name,
		Metric: r.Metric, Severity: r.Severity, Kind: kind, Value: v, Threshold: r.Threshold,
		Detail: detail, LastedSecs: int64(lasted / time.Second), At: at,
	}); err != nil {
		slog.Warn("alerts: record event", "rule", r.ID, "server", srv.ID, "error", err)
	}
}

// alertMessage builds what a rule sends: kind is fired, reminder or resolved.
func (e *alertEngine) alertMessage(r sqlc.AlertRule, srv sqlc.Server, kind string, v float64, detail string, lasted time.Duration, at time.Time) notify.Message {
	label := metricLabels[r.Metric]
	what := label
	if r.Metric == metricDisk && detail != "" {
		what = "Disk " + detail
	}
	var event, title, text string
	switch kind {
	case "resolved":
		event, title = notify.EventUp, "Resolved: "+r.Name+" on "+srv.Name
		if r.Metric == metricOffline {
			text = srv.Name + " can be reached again."
		} else {
			text = what + " is back to " + formatMetric(r.Metric, v) + "."
		}
	default:
		event = notify.EventDegraded
		if r.Severity == "critical" {
			event = notify.EventDown
		}
		title = r.Name + " on " + srv.Name
		if kind == "reminder" {
			event, title = notify.EventReminder, "Still firing: "+title
		}
		if r.Metric == metricOffline {
			text = srv.Name + " can't be reached: " + detail
		} else {
			text = fmt.Sprintf("%s is %s (%s).", what, formatMetric(r.Metric, v), ruleCondition(r))
		}
	}
	fields := []notify.Field{{Name: "Server", Value: srv.Name + " (" + srv.Host + ")"}}
	if r.Metric != metricOffline {
		fields = append(fields, notify.Field{Name: label, Value: formatMetric(r.Metric, v)},
			notify.Field{Name: "Alert when", Value: ruleCondition(r)})
	}
	if lasted > 0 {
		name := "For"
		if kind == "resolved" {
			name = "Lasted"
		}
		fields = append(fields, notify.Field{Name: name, Value: humanDuration(lasted)})
	}
	fields = append(fields, notify.Field{Name: "Severity", Value: strings.ToUpper(r.Severity[:1]) + r.Severity[1:]})
	url := ""
	if e.up.panelURL != "" {
		url = e.up.panelURL + "/servers/" + srv.ID.String()
		if r.Metric != metricOffline {
			url += "/metrics"
		}
	}
	return notify.Message{
		Event: event, Title: title, Text: text, URL: url, Fields: fields, At: at,
		Data: map[string]any{
			"rule_id": r.ID.String(), "rule_name": r.Name, "server_id": srv.ID.String(),
			"server_name": srv.Name, "metric": r.Metric, "severity": r.Severity, "state": kind,
			"value": v, "threshold": r.Threshold, "op": r.Op, "detail": detail,
		},
	}
}

// send delivers to the rule's channels, in the background.
func (e *alertEngine) send(r sqlc.AlertRule, srv sqlc.Server, kind string, v float64, detail string, lasted time.Duration, at time.Time) {
	msg := e.alertMessage(r, srv, kind, v, detail, lasted, at)
	go func() {
		ctx := context.Background()
		chans, err := e.q.AlertRuleChannelsToNotify(ctx, r.ID)
		if err != nil {
			slog.Warn("alerts: channels to notify", "rule", r.ID, "error", err)
			return
		}
		for _, c := range chans {
			go func(c sqlc.NotificationChannel) {
				ch, err := e.up.sendable(c)
				if err == nil {
					sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
					err = notify.Send(sctx, ch, msg)
					cancel()
				}
				e.up.recordRuleSend(ctx, c.ID, r.ID, msg.Title, err)
			}(c)
		}
	}()
}

// forget drops what a rule knew, after it's edited or paused: it starts over.
func (e *alertEngine) forget(ctx context.Context, rule uuid.UUID) {
	e.mu.Lock()
	defer e.mu.Unlock()
	_ = e.q.DeleteAlertStates(ctx, rule)
}
