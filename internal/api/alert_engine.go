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

// Alert rules are checked here: server metrics against every resource sample
// (cpu, memory, disk, failed services…), "offline" against every connection
// check, and the database ones against every database check. A rule fires on
// a target (server or database) once its condition has held for for_minutes,
// sends to its channels, reminds every repeat_minutes, and resolves when it
// clears. While a mute covers it (alert_mutes), it's recorded but not sent;
// what fired during a mute is sent when the mute ends, if it still holds.

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
	metricService = "service"
	// Databases.
	metricDBDown   = "db_down"
	metricDBHealth = "db_health"
)

// databaseMetric says whether a rule watches databases (not servers).
func databaseMetric(m string) bool { return m == metricDBDown || m == metricDBHealth }

// stateMetric says whether a metric is a yes/no state, without a threshold.
func stateMetric(m string) bool {
	return m == metricOffline || m == metricService || databaseMetric(m)
}

var metricLabels = map[string]string{
	metricCPU: "CPU", metricIOWait: "I/O wait", metricLoad: "Load per core",
	metricMemory: "Memory", metricSwap: "Swap", metricDisk: "Disk",
	metricNetRx: "Download", metricNetTx: "Upload", metricOffline: "Unreachable",
	metricService: "Service", metricDBDown: "Database unreachable", metricDBHealth: "Database health",
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
	switch r.Metric {
	case metricOffline, metricDBDown:
		return "unreachable"
	case metricDBHealth:
		return "health critical"
	case metricService:
		if r.Unit != "" {
			return r.Unit + " not running"
		}
		return "a service failed"
	}
	return r.Op + " " + formatMetric(r.Metric, r.Threshold)
}

// alertTarget is what a rule fires on: a server or a database.
type alertTarget struct {
	id          uuid.UUID
	kind        string // server or database
	name, where string // where = host, for messages
}

func serverTarget(s sqlc.Server) alertTarget {
	return alertTarget{id: s.ID, kind: "server", name: s.Name, where: s.Host}
}

func databaseTarget(d sqlc.Database) alertTarget {
	return alertTarget{id: d.ID, kind: "database", name: d.Name, where: d.Host}
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
	// services lists the failed services (unit = "": every failed one; else
	// that unit when it isn't running). Nil when it can't be asked.
	services func(ctx context.Context, unit string) ([]string, error)
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
	t := serverTarget(srv)
	// One question per unit, however many rules ask it.
	type answer struct {
		names []string
		err   error
	}
	asked := map[string]answer{}
	for _, r := range rules {
		switch r.Metric {
		case metricOffline:
			continue
		case metricService:
			if s.services == nil {
				continue
			}
			a, ok := asked[r.Unit]
			if !ok {
				a.names, a.err = s.services(ctx, r.Unit)
				asked[r.Unit] = a
			}
			if a.err != nil {
				continue
			}
			v := float64(len(a.names))
			e.step(ctx, r, t, v > 0, v, strings.Join(a.names, ", "), s.at)
			continue
		}
		v, detail, ok := s.value(r)
		if !ok {
			continue
		}
		e.step(ctx, r, t, breached(r, v), v, detail, s.at)
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
			e.step(ctx, r, serverTarget(srv), down, v, detail, time.Now().UTC())
		}
	}
}

// onDatabase checks a database's rules against a finished check: status is
// how it answered, health the worst check, problems the critical checks.
func (e *alertEngine) onDatabase(ctx context.Context, d sqlc.Database, status, message, health string, problems []string) {
	rules, err := e.q.AlertRulesForDatabase(ctx, sqlc.AlertRulesForDatabaseParams{
		WorkspaceID: d.WorkspaceID, DatabaseID: d.ID,
	})
	if err != nil {
		slog.Warn("alerts: rules for database", "database", d.ID, "error", err)
		return
	}
	now := time.Now().UTC()
	for _, r := range rules {
		met, detail := false, ""
		switch r.Metric {
		case metricDBDown:
			met = status != "online" && status != "unknown"
			if met {
				detail = cmpOr(message, strings.ReplaceAll(status, "_", " "))
			}
		case metricDBHealth:
			met = health == "critical"
			if met {
				detail = strings.Join(problems, ", ")
			}
		}
		v := 0.0
		if met {
			v = 1
		}
		e.step(ctx, r, databaseTarget(d), met, v, detail, now)
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

// muted says whether a mute covers a rule on a target right now.
func (e *alertEngine) muted(ctx context.Context, r sqlc.AlertRule, t alertTarget) bool {
	rid, tid := r.ID, t.id
	m, err := e.q.AlertMuted(ctx, sqlc.AlertMutedParams{WorkspaceID: r.WorkspaceID, RuleID: &rid, TargetID: &tid})
	if err != nil {
		slog.Warn("alerts: muted", "rule", r.ID, "error", err)
		return false
	}
	return m
}

// step moves a rule's state on a target along by one reading.
func (e *alertEngine) step(ctx context.Context, r sqlc.AlertRule, t alertTarget, met bool, v float64, detail string, at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st, err := e.q.GetAlertState(ctx, sqlc.GetAlertStateParams{RuleID: r.ID, TargetID: t.id})
	found := err == nil
	if err != nil && !isNotFound(err) {
		slog.Warn("alerts: get state", "rule", r.ID, "target", t.id, "error", err)
		return
	}
	if !met && (!found || (st.BreachSince == nil && st.FiringSince == nil)) {
		return // nothing going on, nothing to write
	}
	next := sqlc.UpsertAlertStateParams{
		RuleID: r.ID, TargetID: t.id, TargetKind: t.kind, BreachSince: st.BreachSince,
		FiringSince: st.FiringSince, LastSentAt: st.LastSentAt, Value: v, Detail: detail,
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
				quiet := e.muted(ctx, r, t)
				next.FiringSince = &at
				e.event(ctx, r, t, "fired", v, detail, 0, quiet, at)
				if !quiet {
					next.LastSentAt = &at
					e.send(r, t, "fired", v, detail, at.Sub(*next.BreachSince), at)
				}
			}
		case next.LastSentAt == nil:
			// It fired during a mute: tell now that the mute is over.
			if !e.muted(ctx, r, t) {
				next.LastSentAt = &at
				e.send(r, t, "fired", v, detail, at.Sub(*next.BreachSince), at)
			}
		case r.RepeatMinutes > 0 && at.Sub(*next.LastSentAt) >= time.Duration(r.RepeatMinutes)*time.Minute:
			if !e.muted(ctx, r, t) {
				next.LastSentAt = &at
				e.send(r, t, "reminder", v, detail, at.Sub(*next.BreachSince), at)
			}
		}
	} else {
		if next.FiringSince != nil {
			since := *next.FiringSince
			if next.BreachSince != nil {
				since = *next.BreachSince
			}
			lasted := at.Sub(since)
			// Nobody heard it fire (muted all along): nothing to take back.
			quiet := next.LastSentAt == nil || e.muted(ctx, r, t)
			e.event(ctx, r, t, "resolved", v, detail, lasted, quiet, at)
			if r.NotifyResolved && !quiet {
				e.send(r, t, "resolved", v, detail, lasted, at)
			}
		}
		next.BreachSince, next.FiringSince, next.LastSentAt = nil, nil, nil
	}
	if err := e.q.UpsertAlertState(ctx, next); err != nil {
		slog.Warn("alerts: save state", "rule", r.ID, "target", t.id, "error", err)
	}
}

func (e *alertEngine) event(ctx context.Context, r sqlc.AlertRule, t alertTarget, kind string, v float64, detail string, lasted time.Duration, muted bool, at time.Time) {
	rid, tid := r.ID, t.id
	p := sqlc.InsertAlertEventParams{
		WorkspaceID: r.WorkspaceID, RuleID: &rid, RuleName: r.Name, ServerName: t.name,
		Metric: r.Metric, Severity: r.Severity, Kind: kind, Value: v, Threshold: r.Threshold,
		Detail: detail, LastedSecs: int64(lasted / time.Second), Muted: muted, At: at,
	}
	if t.kind == "database" {
		p.DatabaseID = &tid
	} else {
		p.ServerID = &tid
	}
	if err := e.q.InsertAlertEvent(ctx, p); err != nil {
		slog.Warn("alerts: record event", "rule", r.ID, "target", t.id, "error", err)
	}
}

// alertText says what's wrong (or right again) in a sentence.
func alertText(r sqlc.AlertRule, t alertTarget, kind string, v float64, detail string) string {
	resolved := kind == "resolved"
	switch r.Metric {
	case metricOffline, metricDBDown:
		if resolved {
			return t.name + " can be reached again."
		}
		return t.name + " can't be reached: " + detail
	case metricDBHealth:
		if resolved {
			return t.name + " is healthy again (no critical checks)."
		}
		return t.name + " has critical checks: " + detail
	case metricService:
		switch {
		case resolved && r.Unit != "":
			return r.Unit + " is running again."
		case resolved:
			return "No failed services left."
		case r.Unit != "":
			return r.Unit + " isn't running (" + detail + ")."
		case v == 1:
			return "A service failed: " + detail
		}
		return fmt.Sprintf("%g services failed: %s", v, detail)
	}
	what := metricLabels[r.Metric]
	if r.Metric == metricDisk && detail != "" {
		what = "Disk " + detail
	}
	if resolved {
		return what + " is back to " + formatMetric(r.Metric, v) + "."
	}
	return fmt.Sprintf("%s is %s (%s).", what, formatMetric(r.Metric, v), ruleCondition(r))
}

// alertMessage builds what a rule sends: kind is fired, reminder or resolved.
func (e *alertEngine) alertMessage(r sqlc.AlertRule, t alertTarget, kind string, v float64, detail string, lasted time.Duration, at time.Time) notify.Message {
	var event, title string
	switch kind {
	case "resolved":
		event, title = notify.EventUp, "Resolved: "+r.Name+" on "+t.name
	default:
		event = notify.EventDegraded
		if r.Severity == "critical" {
			event = notify.EventDown
		}
		title = r.Name + " on " + t.name
		if kind == "reminder" {
			event, title = notify.EventReminder, "Still firing: "+title
		}
	}
	noun := "Server"
	if t.kind == "database" {
		noun = "Database"
	}
	fields := []notify.Field{{Name: noun, Value: t.name + " (" + t.where + ")"}}
	if !stateMetric(r.Metric) {
		fields = append(fields, notify.Field{Name: metricLabels[r.Metric], Value: formatMetric(r.Metric, v)},
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
		switch {
		case t.kind == "database":
			url = e.up.panelURL + "/databases/" + t.id.String()
		case r.Metric == metricService:
			url = e.up.panelURL + "/servers/" + t.id.String() + "/services"
		case r.Metric == metricOffline:
			url = e.up.panelURL + "/servers/" + t.id.String()
		default:
			url = e.up.panelURL + "/servers/" + t.id.String() + "/metrics"
		}
	}
	data := map[string]any{
		"rule_id": r.ID.String(), "rule_name": r.Name, "target_kind": t.kind,
		"metric": r.Metric, "severity": r.Severity, "state": kind,
		"value": v, "threshold": r.Threshold, "op": r.Op, "detail": detail,
	}
	if t.kind == "database" {
		data["database_id"], data["database_name"] = t.id.String(), t.name
	} else {
		data["server_id"], data["server_name"] = t.id.String(), t.name
	}
	return notify.Message{
		Event: event, Title: title, Text: alertText(r, t, kind, v, detail), URL: url, Fields: fields,
		At: at, Data: data,
	}
}

// send delivers to the rule's channels, in the background.
func (e *alertEngine) send(r sqlc.AlertRule, t alertTarget, kind string, v float64, detail string, lasted time.Duration, at time.Time) {
	msg := e.alertMessage(r, t, kind, v, detail, lasted, at)
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
