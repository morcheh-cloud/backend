package api

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/sshprobe"
)

// Alert rules: which server metrics to watch, when to alert and where to send
// it (the workspace's notification channels). Viewers read them, Engineers
// edit them. The engine that runs them is in alert_engine.go.

type alertRuleHandler struct {
	q      *sqlc.Queries
	authz  *authz
	engine *alertEngine
}

type AlertRuleIDPath struct {
	ID string `path:"id" format:"uuid"`
}

type AlertRuleState struct {
	TargetID    string     `json:"target_id" format:"uuid" doc:"The server or database"`
	TargetKind  string     `json:"target_kind" enum:"server,database"`
	TargetName  string     `json:"target_name"`
	State       string     `json:"state" enum:"pending,firing" doc:"pending = the condition holds, not yet for long enough"`
	BreachSince *time.Time `json:"breach_since,omitempty"`
	FiringSince *time.Time `json:"firing_since,omitempty"`
	Value       float64    `json:"value"`
	Detail      string     `json:"detail" doc:"The disk's mount point, the failed services, or why it can't be reached"`
	UpdatedAt   time.Time  `json:"updated_at"`
	Notified    bool       `json:"notified" doc:"firing: it was sent (false = it fired during a mute)"`
}

type AlertRule struct {
	ID             string           `json:"id" format:"uuid"`
	WorkspaceID    string           `json:"workspace_id" format:"uuid"`
	Name           string           `json:"name"`
	Enabled        bool             `json:"enabled"`
	Metric         string           `json:"metric"`
	Op             string           `json:"op"`
	Threshold      float64          `json:"threshold"`
	Mount          string           `json:"mount"`
	Unit           string           `json:"unit"`
	ForMinutes     int32            `json:"for_minutes"`
	Severity       string           `json:"severity"`
	Scope          string           `json:"scope"`
	ServerIDs      []string         `json:"server_ids"`
	DatabaseIDs    []string         `json:"database_ids"`
	Tags           []string         `json:"tags"`
	RepeatMinutes  int32            `json:"repeat_minutes"`
	NotifyResolved bool             `json:"notify_resolved"`
	ChannelIDs     []string         `json:"channel_ids"`
	States         []AlertRuleState `json:"states" doc:"Servers or databases where it's pending or firing, firing first"`
	CreatedByName  string           `json:"created_by_name"`
	UpdatedByName  string           `json:"updated_by_name"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
}

type AlertRuleOutput struct {
	Body AlertRule
}

type AlertRuleBody struct {
	Name           string   `json:"name" minLength:"1" maxLength:"100"`
	Enabled        *bool    `json:"enabled,omitempty" doc:"Default true"`
	Metric         string   `json:"metric" enum:"cpu,iowait,load,memory,swap,disk,net_rx,net_tx,offline,service,db_down,db_health"`
	Op             string   `json:"op,omitempty" enum:"above,below" default:"above"`
	Threshold      float64  `json:"threshold" doc:"Percent for cpu, iowait, memory, swap and disk; load per core; bytes per second for net_rx/net_tx; ignored for offline, service, db_down and db_health"`
	Mount          string   `json:"mount,omitempty" maxLength:"255" doc:"disk only: one mount point; empty = the fullest"`
	Unit           string   `json:"unit,omitempty" maxLength:"255" doc:"service only: one systemd unit that must keep running; empty = any service that failed"`
	ForMinutes     int32    `json:"for_minutes" minimum:"0" maximum:"1440" doc:"How long it must hold before alerting; 0 = at once"`
	Severity       string   `json:"severity,omitempty" enum:"warning,critical" default:"warning"`
	Scope          string   `json:"scope,omitempty" enum:"all,servers,tags,databases" default:"all" doc:"databases = for db_down/db_health, which take all or databases"`
	ServerIDs      []string `json:"server_ids,omitempty" doc:"scope servers"`
	DatabaseIDs    []string `json:"database_ids,omitempty" doc:"scope databases"`
	Tags           []string `json:"tags,omitempty" doc:"scope tags: servers with any of them"`
	RepeatMinutes  int32    `json:"repeat_minutes,omitempty" minimum:"0" maximum:"10080" doc:"Remind while it fires; 0 = once"`
	NotifyResolved *bool    `json:"notify_resolved,omitempty" doc:"Send when it clears; default true"`
	ChannelIDs     []string `json:"channel_ids,omitempty" doc:"Notification channels of the same workspace"`
}

func toAlertRule(r sqlc.AlertRule, channels []string, states []AlertRuleState) AlertRule {
	ids := idStrings(r.ServerIds)
	if channels == nil {
		channels = []string{}
	}
	if states == nil {
		states = []AlertRuleState{}
	}
	tags := r.Tags
	if tags == nil {
		tags = []string{}
	}
	return AlertRule{
		ID: r.ID.String(), WorkspaceID: r.WorkspaceID.String(), Name: r.Name, Enabled: r.Enabled,
		Metric: r.Metric, Op: r.Op, Threshold: r.Threshold, Mount: r.Mount, Unit: r.Unit,
		ForMinutes: r.ForMinutes, Severity: r.Severity, Scope: r.Scope, ServerIDs: ids,
		DatabaseIDs: idStrings(r.DatabaseIds), Tags: tags,
		RepeatMinutes: r.RepeatMinutes, NotifyResolved: r.NotifyResolved, ChannelIDs: channels,
		States: states, CreatedByName: r.CreatedByName, UpdatedByName: r.UpdatedByName,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

// expand adds each rule's channels and states.
func (h *alertRuleHandler) expand(ctx context.Context, rules []sqlc.AlertRule) ([]AlertRule, error) {
	ids := make([]uuid.UUID, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	chans := map[uuid.UUID][]string{}
	rows, err := h.q.ListAlertRuleChannels(ctx, ids)
	if err != nil {
		return nil, internalError(err)
	}
	for _, c := range rows {
		chans[c.RuleID] = append(chans[c.RuleID], c.ChannelID.String())
	}
	states := map[uuid.UUID][]AlertRuleState{}
	sts, err := h.q.ListAlertStates(ctx, ids)
	if err != nil {
		return nil, internalError(err)
	}
	for _, s := range sts {
		if s.BreachSince == nil && s.FiringSince == nil {
			continue
		}
		state := "pending"
		if s.FiringSince != nil {
			state = "firing"
		}
		states[s.RuleID] = append(states[s.RuleID], AlertRuleState{
			TargetID: s.TargetID.String(), TargetKind: s.TargetKind, TargetName: s.TargetName,
			State: state, BreachSince: s.BreachSince, FiringSince: s.FiringSince, Value: s.Value,
			Detail: s.Detail, UpdatedAt: s.UpdatedAt, Notified: s.LastSentAt != nil,
		})
	}
	out := make([]AlertRule, len(rules))
	for i, r := range rules {
		out[i] = toAlertRule(r, chans[r.ID], states[r.ID])
	}
	return out, nil
}

func (h *alertRuleHandler) ruleOut(ctx context.Context, r sqlc.AlertRule) (*AlertRuleOutput, error) {
	list, err := h.expand(ctx, []sqlc.AlertRule{r})
	if err != nil {
		return nil, err
	}
	return &AlertRuleOutput{Body: list[0]}, nil
}

// database finds a database this person can see.
func (h *alertRuleHandler) database(ctx context.Context, p *principal, raw string) (sqlc.Database, error) {
	id, err := uuid.Parse(raw)
	if err != nil {
		return sqlc.Database{}, huma.Error404NotFound("Database not found")
	}
	d, err := h.q.GetDatabase(ctx, id)
	if isNotFound(err) || (err == nil && databaseLevelOf(p.Access, d) == auth.None) {
		return d, huma.Error404NotFound("Database not found")
	}
	if err != nil {
		return d, internalError(err)
	}
	return d, nil
}

func (h *alertRuleHandler) getRule(ctx context.Context, raw string) (sqlc.AlertRule, error) {
	id, err := uuid.Parse(raw)
	if err != nil {
		return sqlc.AlertRule{}, huma.Error404NotFound("Alert rule not found")
	}
	r, err := h.q.GetAlertRule(ctx, id)
	if isNotFound(err) {
		return r, huma.Error404NotFound("Alert rule not found")
	}
	if err != nil {
		return r, internalError(err)
	}
	return r, nil
}

// cleanedRule is a checked body, ready to save.
type cleanedRule struct {
	name, op, mount, unit, severity, scope string
	servers, databases                     []uuid.UUID
	tags                                   []string
	channels                               []uuid.UUID
	enabled, resolved                      bool
}

// clean checks a body against the rules of the workspace ws.
func (h *alertRuleHandler) clean(ctx context.Context, ws uuid.UUID, b *AlertRuleBody) (cleanedRule, error) {
	c := cleanedRule{
		name: strings.TrimSpace(b.Name), op: cmpOr(b.Op, "above"), mount: strings.TrimSpace(b.Mount),
		severity: cmpOr(b.Severity, "warning"), scope: cmpOr(b.Scope, "all"),
		unit:    strings.TrimSpace(b.Unit),
		servers: []uuid.UUID{}, databases: []uuid.UUID{}, tags: []string{}, channels: []uuid.UUID{},
		enabled: b.Enabled == nil || *b.Enabled, resolved: b.NotifyResolved == nil || *b.NotifyResolved,
	}
	if c.name == "" {
		return c, fieldError("body.name", "Give the rule a name", b.Name)
	}
	switch {
	case stateMetric(b.Metric):
		b.Threshold, c.op = 0, "above"
	case percentMetric(b.Metric) && (b.Threshold < 0 || b.Threshold > 100):
		return c, fieldError("body.threshold", "Use a percent from 0 to 100", b.Threshold)
	case b.Threshold < 0:
		return c, fieldError("body.threshold", "Can't be below 0", b.Threshold)
	}
	if b.Metric != metricDisk {
		c.mount = ""
	} else if c.mount != "" && !strings.HasPrefix(c.mount, "/") {
		return c, fieldError("body.mount", "A mount point starts with /, like /var", b.Mount)
	}
	if b.Metric != metricService {
		c.unit = ""
	} else if c.unit != "" && !unitRe.MatchString(c.unit) {
		return c, fieldError("body.unit", "Use a unit name like nginx or nginx.service", b.Unit)
	}
	if databaseMetric(b.Metric) != (c.scope == "databases") && c.scope != "all" {
		if databaseMetric(b.Metric) {
			return c, fieldError("body.scope", "A database rule covers every database or the ones you pick", b.Scope)
		}
		return c, fieldError("body.scope", "Pick servers or tags for a server rule", b.Scope)
	}
	switch c.scope {
	case "databases":
		if len(b.DatabaseIDs) == 0 {
			return c, fieldError("body.database_ids", "Pick at least one database", b.DatabaseIDs)
		}
		for _, raw := range b.DatabaseIDs {
			id, err := uuid.Parse(raw)
			if err != nil {
				return c, fieldError("body.database_ids", "Unknown database", raw)
			}
			d, err := h.q.GetDatabase(ctx, id)
			if isNotFound(err) || (err == nil && d.WorkspaceID != ws) {
				return c, fieldError("body.database_ids", "That database isn't in this workspace", raw)
			}
			if err != nil {
				return c, internalError(err)
			}
			if !slices.Contains(c.databases, id) {
				c.databases = append(c.databases, id)
			}
		}
	case "servers":
		if len(b.ServerIDs) == 0 {
			return c, fieldError("body.server_ids", "Pick at least one server", b.ServerIDs)
		}
		for _, raw := range b.ServerIDs {
			id, err := uuid.Parse(raw)
			if err != nil {
				return c, fieldError("body.server_ids", "Unknown server", raw)
			}
			s, err := h.q.GetServer(ctx, id)
			if isNotFound(err) || (err == nil && s.WorkspaceID != ws) {
				return c, fieldError("body.server_ids", "That server isn't in this workspace", raw)
			}
			if err != nil {
				return c, internalError(err)
			}
			if !slices.Contains(c.servers, id) {
				c.servers = append(c.servers, id)
			}
		}
	case "tags":
		tags, err := normalizeTags(b.Tags)
		if err != nil {
			return c, err
		}
		if len(tags) == 0 {
			return c, fieldError("body.tags", "Pick at least one tag", b.Tags)
		}
		c.tags = tags
	}
	for _, raw := range b.ChannelIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			return c, fieldError("body.channel_ids", "Unknown channel", raw)
		}
		ch, err := h.q.GetNotificationChannel(ctx, id)
		if isNotFound(err) || (err == nil && ch.WorkspaceID != ws) {
			return c, fieldError("body.channel_ids", "That channel isn't in this workspace", raw)
		}
		if err != nil {
			return c, internalError(err)
		}
		if !slices.Contains(c.channels, id) {
			c.channels = append(c.channels, id)
		}
	}
	return c, nil
}

func (h *alertRuleHandler) setChannels(ctx context.Context, rule uuid.UUID, channels []uuid.UUID) error {
	if err := h.q.ClearAlertRuleChannels(ctx, rule); err != nil {
		return err
	}
	for _, c := range channels {
		if err := h.q.AddAlertRuleChannel(ctx, sqlc.AddAlertRuleChannelParams{RuleID: rule, ChannelID: c}); err != nil {
			return err
		}
	}
	return nil
}

func (h *alertRuleHandler) create(ctx context.Context, in *struct{ Body AlertRuleBody }) (*AlertRuleOutput, error) {
	p := principalOf(ctx)
	ws, err := h.authz.createTarget(ctx, p)
	if err != nil {
		return nil, err
	}
	if p.Access.WorkspaceLevel(ws) < auth.Engineer {
		return nil, huma.Error403Forbidden("You need Engineer access to the workspace to add an alert rule.")
	}
	b := in.Body
	c, err := h.clean(ctx, ws, &b)
	if err != nil {
		return nil, err
	}
	r, err := h.q.CreateAlertRule(ctx, sqlc.CreateAlertRuleParams{
		WorkspaceID: ws, Name: c.name, Enabled: c.enabled, Metric: b.Metric, Op: c.op,
		Threshold: b.Threshold, Mount: c.mount, Unit: c.unit, ForMinutes: b.ForMinutes, Severity: c.severity,
		Scope: c.scope, ServerIds: c.servers, DatabaseIds: c.databases, Tags: c.tags, RepeatMinutes: b.RepeatMinutes,
		NotifyResolved: c.resolved, CreatedByName: cmpOr(p.User.FullName, p.User.Username),
	})
	if err != nil {
		return nil, internalError(err)
	}
	if err := h.setChannels(ctx, r.ID, c.channels); err != nil {
		return nil, internalError(err)
	}
	return h.ruleOut(ctx, r)
}

func (h *alertRuleHandler) update(ctx context.Context, in *struct {
	AlertRuleIDPath
	Body AlertRuleBody
}) (*AlertRuleOutput, error) {
	p := principalOf(ctx)
	prev, err := h.getRule(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	b := in.Body
	c, err := h.clean(ctx, prev.WorkspaceID, &b)
	if err != nil {
		return nil, err
	}
	r, err := h.q.UpdateAlertRule(ctx, sqlc.UpdateAlertRuleParams{
		ID: prev.ID, Name: c.name, Enabled: c.enabled, Metric: b.Metric, Op: c.op,
		Threshold: b.Threshold, Mount: c.mount, Unit: c.unit, ForMinutes: b.ForMinutes, Severity: c.severity,
		Scope: c.scope, ServerIds: c.servers, DatabaseIds: c.databases, Tags: c.tags, RepeatMinutes: b.RepeatMinutes,
		NotifyResolved: c.resolved, UpdatedByName: cmpOr(p.User.FullName, p.User.Username),
	})
	if err != nil {
		return nil, internalError(err)
	}
	if err := h.setChannels(ctx, r.ID, c.channels); err != nil {
		return nil, internalError(err)
	}
	h.engine.forget(ctx, r.ID)
	return h.ruleOut(ctx, r)
}

// ---- Preview ----

type AlertPreviewItem struct {
	TargetID   string     `json:"target_id" format:"uuid"`
	TargetKind string     `json:"target_kind" enum:"server,database"`
	TargetName string     `json:"target_name"`
	Status     string     `json:"status"`
	At         *time.Time `json:"at,omitempty" doc:"The sample it was read from; missing = no data"`
	Value      *float64   `json:"value,omitempty"`
	Detail     string     `json:"detail"`
	Met        bool       `json:"met" doc:"The condition holds now"`
}

type AlertPreviewOutput struct {
	Body struct {
		Items []AlertPreviewItem `json:"items" doc:"Every server or database the rule covers, those that meet it first"`
	}
}

// preview says what an unsaved rule would see right now.
func (h *alertRuleHandler) preview(ctx context.Context, in *struct {
	Body AlertRuleBody
}) (*AlertPreviewOutput, error) {
	p := principalOf(ctx)
	ws, err := h.authz.createTarget(ctx, p)
	if err != nil {
		return nil, err
	}
	b := in.Body
	if b.Name == "" {
		b.Name = "Preview"
	}
	c, err := h.clean(ctx, ws, &b)
	if err != nil {
		return nil, err
	}
	rule := sqlc.AlertRule{
		Metric: b.Metric, Op: c.op, Threshold: b.Threshold, Mount: c.mount, Scope: c.scope,
		ServerIds: c.servers, DatabaseIds: c.databases, Tags: c.tags, Unit: c.unit,
	}
	sc := p.scope()
	if databaseMetric(rule.Metric) {
		return h.previewDatabases(ctx, p, ws, rule)
	}
	rows, err := h.q.ListServers(ctx, sqlc.ListServersParams{
		SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, ServerIds: sc.servers, WorkspaceID: &ws,
		OsIds: []string{}, Statuses: []string{}, Tags: []string{}, AuthMethods: []string{},
		Sort: "name", Lim: 10000,
	})
	if err != nil {
		return nil, internalError(err)
	}
	var covered []sqlc.Server
	for _, r := range rows {
		if ruleCovers(rule, r.Server) {
			covered = append(covered, r.Server)
		}
	}
	ids := make([]uuid.UUID, len(covered))
	for i, s := range covered {
		ids[i] = s.ID
	}
	latest := map[uuid.UUID]sqlc.ServerSample{}
	if len(ids) > 0 {
		ls, err := h.q.LatestServerSamples(ctx, ids)
		if err != nil {
			return nil, internalError(err)
		}
		for _, l := range ls {
			latest[l.ServerID] = l
		}
	}
	out := &AlertPreviewOutput{}
	out.Body.Items = []AlertPreviewItem{}
	for _, s := range covered {
		it := AlertPreviewItem{TargetID: s.ID.String(), TargetKind: "server", TargetName: s.Name, Status: s.Status}
		if rule.Metric == metricService {
			// Read on the next sample; nothing kept to show now.
		} else if rule.Metric == metricOffline {
			if s.LastCheckedAt != nil {
				v := 0.0
				it.Met = s.Status != sshprobe.StatusOnline
				if it.Met {
					v, it.Detail = 1, cmpOr(s.StatusMessage, statusText(s.Status))
				}
				it.At, it.Value = s.LastCheckedAt, &v
			}
		} else if l, ok := latest[s.ID]; ok {
			if v, detail, ok := metricSampleOf(l).value(rule); ok {
				at := l.At
				it.At, it.Value, it.Detail, it.Met = &at, &v, detail, breached(rule, v)
			}
		}
		out.Body.Items = append(out.Body.Items, it)
	}
	metFirst(out.Body.Items)
	return out, nil
}

func metFirst(items []AlertPreviewItem) {
	slices.SortStableFunc(items, func(a, b AlertPreviewItem) int {
		switch {
		case a.Met == b.Met:
			return 0
		case a.Met:
			return -1
		}
		return 1
	})
}

// previewDatabases checks a database rule against each covered database's
// last look.
func (h *alertRuleHandler) previewDatabases(ctx context.Context, p *principal, ws uuid.UUID, rule sqlc.AlertRule) (*AlertPreviewOutput, error) {
	sc := p.scope()
	rows, err := h.q.ListDatabases(ctx, sqlc.ListDatabasesParams{
		SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, ServerIds: sc.servers, WorkspaceID: &ws,
	})
	if err != nil {
		return nil, internalError(err)
	}
	out := &AlertPreviewOutput{}
	out.Body.Items = []AlertPreviewItem{}
	for _, d := range rows {
		if !databaseCovered(rule, d) || databaseLevelOf(p.Access, d) == auth.None {
			continue
		}
		it := AlertPreviewItem{TargetID: d.ID.String(), TargetKind: "database", TargetName: d.Name, Status: d.Status}
		if d.LastCheckedAt != nil && !d.Paused {
			v := 0.0
			switch rule.Metric {
			case metricDBDown:
				it.Met = d.Status != "online" && d.Status != "unknown"
				if it.Met {
					v, it.Detail = 1, cmpOr(d.StatusMessage, d.Status)
				}
			case metricDBHealth:
				it.Met = d.Health == "critical"
				if it.Met {
					v, it.Detail = 1, "Health is critical"
				}
			}
			it.At, it.Value = d.LastCheckedAt, &v
		}
		out.Body.Items = append(out.Body.Items, it)
	}
	metFirst(out.Body.Items)
	return out, nil
}

// databaseCovered says whether a database rule takes in a database.
func databaseCovered(r sqlc.AlertRule, d sqlc.Database) bool {
	if !databaseMetric(r.Metric) {
		return false
	}
	return r.Scope != "databases" || slices.Contains(r.DatabaseIds, d.ID)
}

// ruleCovers says whether a rule's scope takes in a server.
func ruleCovers(r sqlc.AlertRule, s sqlc.Server) bool {
	if databaseMetric(r.Metric) {
		return false
	}
	switch r.Scope {
	case "servers":
		return slices.Contains(r.ServerIds, s.ID)
	case "tags":
		for _, t := range s.Tags {
			if slices.Contains(r.Tags, t) {
				return true
			}
		}
		return false
	}
	return true
}

// ---- Events ----

type AlertEvent struct {
	ID         int64     `json:"id"`
	RuleID     *string   `json:"rule_id,omitempty" format:"uuid"`
	ServerID   *string   `json:"server_id,omitempty" format:"uuid"`
	DatabaseID *string   `json:"database_id,omitempty" format:"uuid"`
	RuleName   string    `json:"rule_name"`
	ServerName string    `json:"server_name" doc:"The server's or the database's name"`
	Metric     string    `json:"metric"`
	Severity   string    `json:"severity"`
	Kind       string    `json:"kind" enum:"fired,resolved"`
	Value      float64   `json:"value"`
	Threshold  float64   `json:"threshold"`
	Detail     string    `json:"detail"`
	LastedSecs int64     `json:"lasted_secs" doc:"resolved: how long it lasted"`
	Muted      bool      `json:"muted" doc:"It happened during a mute: recorded, not sent"`
	At         time.Time `json:"at"`
}

func registerAlertRules(api huma.API, h *alertRuleHandler) {
	tags := []string{"Alerts"}

	type listOut struct {
		Body struct {
			Items []AlertRule `json:"items"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "list-alert-rules", Method: http.MethodGet, Path: "/alert-rules",
		Summary: "List alert rules", Tags: tags,
		Description: "The rules of the workspaces this person can see (in the selected one). With server_id or database_id, only the rules that cover it.",
	}, func(ctx context.Context, in *struct {
		ServerID   string `query:"server_id" doc:"Only rules covering this server"`
		DatabaseID string `query:"database_id" doc:"Only rules covering this database"`
	}) (*listOut, error) {
		p := principalOf(ctx)
		sc := p.scope()
		params := sqlc.ListAlertRulesParams{SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, WorkspaceID: sc.current}
		var srv *sqlc.Server
		if in.ServerID != "" {
			id, err := uuid.Parse(in.ServerID)
			if err != nil {
				return nil, huma.Error404NotFound("Server not found")
			}
			s, err := h.q.GetServer(ctx, id)
			if isNotFound(err) || (err == nil && p.Access.ServerLevel(s.WorkspaceID, s.ID) == auth.None) {
				return nil, huma.Error404NotFound("Server not found")
			}
			if err != nil {
				return nil, internalError(err)
			}
			// Someone with access to just this server still sees its rules.
			srv, params.SeeAll, params.WorkspaceID = &s, true, &s.WorkspaceID
		}
		var dbase *sqlc.Database
		if in.DatabaseID != "" && srv == nil {
			d, err := h.database(ctx, p, in.DatabaseID)
			if err != nil {
				return nil, err
			}
			dbase, params.SeeAll, params.WorkspaceID = &d, true, &d.WorkspaceID
		}
		rows, err := h.q.ListAlertRules(ctx, params)
		if err != nil {
			return nil, internalError(err)
		}
		if srv != nil || dbase != nil {
			kept := rows[:0]
			for _, r := range rows {
				if (srv != nil && ruleCovers(r, *srv)) || (dbase != nil && databaseCovered(r, *dbase)) {
					kept = append(kept, r)
				}
			}
			rows = kept
		}
		items, err := h.expand(ctx, rows)
		if err != nil {
			return nil, err
		}
		if srv != nil || dbase != nil {
			// Only this one's states.
			only := ""
			if srv != nil {
				only = srv.ID.String()
			} else {
				only = dbase.ID.String()
			}
			for i := range items {
				st := items[i].States[:0]
				for _, s := range items[i].States {
					if s.TargetID == only {
						st = append(st, s)
					}
				}
				items[i].States = st
			}
		}
		out := &listOut{}
		out.Body.Items = items
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-alert-rule", Method: http.MethodPost, Path: "/alert-rules",
		Summary: "Add an alert rule", Tags: tags, DefaultStatus: http.StatusCreated,
	}, h.create)

	huma.Register(api, huma.Operation{
		OperationID: "preview-alert-rule", Method: http.MethodPost, Path: "/alert-rules/preview",
		Summary:     "What a rule would see now",
		Description: "Checks unsaved settings against each covered server's latest sample, without saving anything.",
		Tags:        tags,
	}, h.preview)

	huma.Register(api, huma.Operation{
		OperationID: "get-alert-rule", Method: http.MethodGet, Path: "/alert-rules/{id}",
		Summary: "Get an alert rule", Tags: tags,
	}, func(ctx context.Context, in *AlertRuleIDPath) (*AlertRuleOutput, error) {
		r, err := h.getRule(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return h.ruleOut(ctx, r)
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-alert-rule", Method: http.MethodPut, Path: "/alert-rules/{id}",
		Summary: "Update an alert rule", Tags: tags,
		Description: "Saving starts the rule over: what was pending or firing is forgotten (without a resolved message).",
	}, h.update)

	huma.Register(api, huma.Operation{
		OperationID: "set-alert-rule-enabled", Method: http.MethodPut, Path: "/alert-rules/{id}/enabled",
		Summary: "Turn an alert rule on or off", Tags: tags,
	}, func(ctx context.Context, in *struct {
		AlertRuleIDPath
		Body struct {
			Enabled bool `json:"enabled"`
		}
	}) (*AlertRuleOutput, error) {
		p := principalOf(ctx)
		prev, err := h.getRule(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		r, err := h.q.SetAlertRuleEnabled(ctx, sqlc.SetAlertRuleEnabledParams{
			ID: prev.ID, Enabled: in.Body.Enabled, UpdatedByName: cmpOr(p.User.FullName, p.User.Username),
		})
		if err != nil {
			return nil, internalError(err)
		}
		h.engine.forget(ctx, r.ID)
		return h.ruleOut(ctx, r)
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-alert-rule", Method: http.MethodDelete, Path: "/alert-rules/{id}",
		Summary: "Remove an alert rule", Tags: tags, DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *AlertRuleIDPath) (*struct{}, error) {
		r, err := h.getRule(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if err := h.q.DeleteAlertRule(ctx, r.ID); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})

	type eventsOut struct {
		Body struct {
			Items []AlertEvent `json:"items"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "list-alert-events", Method: http.MethodGet, Path: "/alert-events",
		Summary: "When rules fired and resolved", Description: "Newest first.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		ServerID   string `query:"server_id" doc:"Only this server"`
		DatabaseID string `query:"database_id" doc:"Only this database"`
		RuleID     string `query:"rule_id" doc:"Only this rule"`
		Limit      int32  `query:"limit" minimum:"1" maximum:"500" default:"100"`
	}) (*eventsOut, error) {
		p := principalOf(ctx)
		sc := p.scope()
		params := sqlc.ListAlertEventsParams{
			SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, WorkspaceID: sc.current, Lim: in.Limit,
		}
		if in.ServerID != "" {
			id, err := uuid.Parse(in.ServerID)
			if err != nil {
				return nil, huma.Error404NotFound("Server not found")
			}
			s, err := h.q.GetServer(ctx, id)
			if isNotFound(err) || (err == nil && p.Access.ServerLevel(s.WorkspaceID, s.ID) == auth.None) {
				return nil, huma.Error404NotFound("Server not found")
			}
			if err != nil {
				return nil, internalError(err)
			}
			params.ServerID, params.SeeAll, params.WorkspaceID = &id, true, &s.WorkspaceID
		}
		if in.DatabaseID != "" {
			d, err := h.database(ctx, p, in.DatabaseID)
			if err != nil {
				return nil, err
			}
			params.DatabaseID, params.SeeAll, params.WorkspaceID = &d.ID, true, &d.WorkspaceID
		}
		if in.RuleID != "" {
			id, err := uuid.Parse(in.RuleID)
			if err != nil {
				return nil, huma.Error404NotFound("Alert rule not found")
			}
			params.RuleID = &id
		}
		rows, err := h.q.ListAlertEvents(ctx, params)
		if err != nil {
			return nil, internalError(err)
		}
		out := &eventsOut{}
		out.Body.Items = make([]AlertEvent, 0, len(rows))
		for _, e := range rows {
			out.Body.Items = append(out.Body.Items, AlertEvent{
				ID: e.ID, RuleID: optionalIDString(e.RuleID), ServerID: optionalIDString(e.ServerID),
				DatabaseID: optionalIDString(e.DatabaseID),
				RuleName:   e.RuleName, ServerName: e.ServerName, Metric: e.Metric, Severity: e.Severity,
				Kind: e.Kind, Value: e.Value, Threshold: e.Threshold, Detail: e.Detail,
				LastedSecs: e.LastedSecs, Muted: e.Muted, At: e.At,
			})
		}
		return out, nil
	})
}
