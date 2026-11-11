package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/dbmon"
	"github.com/morcheh/backend/internal/notify"
)

// Notification channels are where alerts go (email, Telegram, Bale, chat
// webhooks…). They belong to a workspace; each monitor picks its own.

type ChannelIDPath struct {
	ID string `path:"id" format:"uuid"`
}

// NotifyChannel is a channel. Its secrets never leave the backend: only their
// names come back.
type NotifyChannel struct {
	ID            string               `json:"id" format:"uuid"`
	WorkspaceID   string               `json:"workspace_id" format:"uuid"`
	Name          string               `json:"name"`
	Kind          string               `json:"kind"`
	Config        notify.ChannelConfig `json:"config"`
	Secrets       []string             `json:"secrets" doc:"Which secrets are saved"`
	Enabled       bool                 `json:"enabled"`
	IsDefault     bool                 `json:"is_default" doc:"Added to every new monitor in the workspace"`
	AllowInternal bool                 `json:"allow_internal"`
	Monitors      int32                `json:"monitors" doc:"How many monitors use it"`
	Rules         int32                `json:"rules" doc:"How many alert rules use it"`
	LastSentAt    *time.Time           `json:"last_sent_at,omitempty"`
	LastError     string               `json:"last_error"`
	LastErrorAt   *time.Time           `json:"last_error_at,omitempty"`
	CreatedByName string               `json:"created_by_name"`
	UpdatedByName string               `json:"updated_by_name"`
	CreatedAt     time.Time            `json:"created_at"`
	UpdatedAt     time.Time            `json:"updated_at"`
}

type NotifyChannelOutput struct {
	Body NotifyChannel
}

type NotifyChannelBody struct {
	Name          string                `json:"name" minLength:"1" maxLength:"100"`
	Kind          string                `json:"kind" enum:"email,telegram,bale,webhook,slack,discord,mattermost,teams,ntfy,gotify,pushover" doc:"Can't change after it's created"`
	Config        notify.ChannelConfig  `json:"config"`
	Secrets       notify.ChannelSecrets `json:"secrets" doc:"A blank secret keeps the saved one"`
	Enabled       *bool                 `json:"enabled,omitempty" doc:"Default true"`
	IsDefault     bool                  `json:"is_default,omitempty"`
	AllowInternal bool                  `json:"allow_internal,omitempty" doc:"Send to a private or loopback address. System admins only."`
	AttachAll     bool                  `json:"attach_all,omitempty" doc:"Also add it to every monitor the workspace already has"`
}

func (h *uptimeHandler) channelSecrets(c sqlc.NotificationChannel) (notify.ChannelSecrets, error) {
	var s notify.ChannelSecrets
	plain, err := h.box.Open(c.SecretsEnc)
	if err != nil || plain == "" {
		return s, err
	}
	err = json.Unmarshal([]byte(plain), &s)
	return s, err
}

func (h *uptimeHandler) sealJSON(v any, empty bool) []byte {
	if empty {
		return nil
	}
	b, _ := json.Marshal(v)
	return h.box.Seal(string(b))
}

func toNotifyChannel(c sqlc.NotificationChannel, s notify.ChannelSecrets, monitors, rules int32) NotifyChannel {
	var cfg notify.ChannelConfig
	_ = json.Unmarshal(c.Config, &cfg)
	return NotifyChannel{
		ID: c.ID.String(), WorkspaceID: c.WorkspaceID.String(), Name: c.Name, Kind: c.Kind,
		Config: cfg, Secrets: s.Names(), Enabled: c.Enabled, IsDefault: c.IsDefault,
		AllowInternal: c.AllowInternal, Monitors: monitors, Rules: rules, LastSentAt: c.LastSentAt,
		LastError: c.LastError, LastErrorAt: c.LastErrorAt, CreatedByName: c.CreatedByName,
		UpdatedByName: c.UpdatedByName, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
}

func (h *uptimeHandler) channelOut(ctx context.Context, c sqlc.NotificationChannel) (*NotifyChannelOutput, error) {
	s, err := h.channelSecrets(c)
	if err != nil {
		return nil, internalError(err)
	}
	var n, rules int32
	if rows, err := h.q.CountChannelMonitors(ctx, []uuid.UUID{c.ID}); err == nil && len(rows) > 0 {
		n = rows[0].Monitors
	}
	if rows, err := h.q.CountChannelRules(ctx, []uuid.UUID{c.ID}); err == nil && len(rows) > 0 {
		rules = rows[0].Rules
	}
	return &NotifyChannelOutput{Body: toNotifyChannel(c, s, n, rules)}, nil
}

func (h *uptimeHandler) getChannel(ctx context.Context, rawID string) (sqlc.NotificationChannel, error) {
	id, err := uuid.Parse(rawID)
	if err != nil {
		return sqlc.NotificationChannel{}, huma.Error404NotFound("Channel not found")
	}
	c, err := h.q.GetNotificationChannel(ctx, id)
	if isNotFound(err) {
		return c, huma.Error404NotFound("Channel not found")
	}
	if err != nil {
		return c, internalError(err)
	}
	return c, nil
}

// channelTarget is where a channel sends, to tell whether a saved
// allow_internal still covers it.
func channelTarget(c notify.ChannelConfig, s notify.ChannelSecrets) string {
	return strings.Join([]string{c.Host, c.URL, c.APIURL, s.WebhookURL}, "|")
}

// cleanChannel trims the settings and checks what the kind needs.
func cleanChannel(kind string, b *NotifyChannelBody, s notify.ChannelSecrets) error {
	b.Config.Host = strings.TrimSpace(b.Config.Host)
	b.Config.URL = strings.TrimSpace(b.Config.URL)
	b.Config.APIURL = strings.TrimRight(strings.TrimSpace(b.Config.APIURL), "/")
	b.Config.ChatID = strings.TrimSpace(b.Config.ChatID)
	b.Config.Topic = strings.TrimSpace(b.Config.Topic)
	to := b.Config.To[:0]
	for _, t := range b.Config.To {
		if t = strings.TrimSpace(t); t != "" {
			to = append(to, t)
		}
	}
	b.Config.To = to
	if e := notify.Check(kind, b.Config, s); e != nil {
		return fieldError("body."+e.Field, e.Message, nil)
	}
	return nil
}

func (h *uptimeHandler) sendable(c sqlc.NotificationChannel) (notify.Channel, error) {
	var cfg notify.ChannelConfig
	if err := json.Unmarshal(c.Config, &cfg); err != nil {
		return notify.Channel{}, err
	}
	s, err := h.channelSecrets(c)
	if err != nil {
		return notify.Channel{}, err
	}
	return notify.Channel{
		Kind: c.Kind, Config: cfg, Secrets: s,
		Dial: notify.Dialer(dbmon.DirectDialer(c.AllowInternal)),
	}, nil
}

func testMessage(name string) notify.Message {
	return notify.Message{
		Event: notify.EventTest,
		Title: "Test from Morcheh",
		Text:  "If you can read this, " + name + " works: alerts from Morcheh will arrive here.",
		At:    time.Now(),
	}
}

func (h *uptimeHandler) createChannel(ctx context.Context, in *struct{ Body NotifyChannelBody }) (*NotifyChannelOutput, error) {
	p := principalOf(ctx)
	b := in.Body
	ws, err := h.authz.createTarget(ctx, p)
	if err != nil {
		return nil, err
	}
	if p.Access.WorkspaceLevel(ws) < auth.Owner {
		return nil, huma.Error403Forbidden("You need Owner access to the workspace to add a notification channel.")
	}
	if b.AllowInternal && !p.Access.Admin {
		return nil, fieldError("body.allow_internal", "Only a system admin can allow private addresses", true)
	}
	// Merging with nothing tidies the headers (trimmed names, blanks dropped).
	b.Secrets = b.Secrets.Merge(notify.ChannelSecrets{})
	if err := cleanChannel(b.Kind, &b, b.Secrets); err != nil {
		return nil, err
	}
	cfg, _ := json.Marshal(b.Config)
	c, err := h.q.CreateNotificationChannel(ctx, sqlc.CreateNotificationChannelParams{
		WorkspaceID: ws, Name: strings.TrimSpace(b.Name), Kind: b.Kind, Config: cfg,
		SecretsEnc: h.sealJSON(b.Secrets, len(b.Secrets.Names()) == 0),
		Enabled:    b.Enabled == nil || *b.Enabled, IsDefault: b.IsDefault,
		AllowInternal: b.AllowInternal, CreatedByName: cmpOr(p.User.FullName, p.User.Username),
	})
	if isUniqueViolation(err) {
		return nil, fieldError("body.name", "A channel with this name already exists", b.Name)
	}
	if err != nil {
		return nil, internalError(err)
	}
	if b.AttachAll {
		h.attachEverywhere(ctx, c)
	}
	return h.channelOut(ctx, c)
}

// attachEverywhere adds a channel to every monitor of its workspace.
func (h *uptimeHandler) attachEverywhere(ctx context.Context, c sqlc.NotificationChannel) {
	ms, err := h.q.ListMonitors(ctx, sqlc.ListMonitorsParams{SeeAll: true, WorkspaceID: &c.WorkspaceID})
	if err != nil {
		return
	}
	for _, m := range ms {
		_ = h.q.AddMonitorChannel(ctx, sqlc.AddMonitorChannelParams{MonitorID: m.ID, ChannelID: c.ID})
	}
}

func (h *uptimeHandler) updateChannel(ctx context.Context, in *struct {
	ChannelIDPath
	Body NotifyChannelBody
}) (*NotifyChannelOutput, error) {
	p := principalOf(ctx)
	b := in.Body
	prev, err := h.getChannel(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	saved, err := h.channelSecrets(prev)
	if err != nil {
		return nil, internalError(err)
	}
	var prevCfg notify.ChannelConfig
	_ = json.Unmarshal(prev.Config, &prevCfg)
	merged := b.Secrets.Merge(saved)
	if b.AllowInternal && !p.Access.Admin &&
		(!prev.AllowInternal || channelTarget(prevCfg, saved) != channelTarget(b.Config, merged)) {
		return nil, fieldError("body.allow_internal", "Only a system admin can allow private addresses", true)
	}
	if err := cleanChannel(prev.Kind, &b, merged); err != nil {
		return nil, err
	}
	cfg, _ := json.Marshal(b.Config)
	c, err := h.q.UpdateNotificationChannel(ctx, sqlc.UpdateNotificationChannelParams{
		ID: prev.ID, Name: strings.TrimSpace(b.Name), Config: cfg,
		SecretsEnc: h.sealJSON(merged, len(merged.Names()) == 0),
		Enabled:    b.Enabled == nil || *b.Enabled, IsDefault: b.IsDefault,
		AllowInternal: b.AllowInternal, UpdatedByName: cmpOr(p.User.FullName, p.User.Username),
	})
	if isUniqueViolation(err) {
		return nil, fieldError("body.name", "A channel with this name already exists", b.Name)
	}
	if err != nil {
		return nil, internalError(err)
	}
	if b.AttachAll {
		h.attachEverywhere(ctx, c)
	}
	return h.channelOut(ctx, c)
}

type ChannelTestBody struct {
	NotifyChannelBody
	ChannelID *string `json:"channel_id,omitempty" format:"uuid" doc:"When editing: the saved channel, whose secrets blank ones stand for"`
}

type ChannelTestOutput struct {
	Body struct {
		OK      bool   `json:"ok"`
		Message string `json:"message"`
	}
}

func testResult(err error) *ChannelTestOutput {
	out := &ChannelTestOutput{}
	out.Body.OK = err == nil
	out.Body.Message = "Sent. Check that it arrived."
	if err != nil {
		out.Body.Message = clipText(err.Error(), 500)
	}
	return out
}

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// testUnsaved sends a test with settings that aren't saved yet.
func (h *uptimeHandler) testUnsaved(ctx context.Context, in *struct{ Body ChannelTestBody }) (*ChannelTestOutput, error) {
	p := principalOf(ctx)
	b := in.Body
	kind := b.Kind
	secrets := b.Secrets
	allowed := false
	if id := parseOptionalID(b.ChannelID); id != nil {
		prev, err := h.q.GetNotificationChannel(ctx, *id)
		if isNotFound(err) || (err == nil && p.Access.WorkspaceLevel(prev.WorkspaceID) == auth.None) {
			return nil, huma.Error404NotFound("Channel not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if p.Access.WorkspaceLevel(prev.WorkspaceID) < auth.Owner {
			return nil, huma.Error403Forbidden("You need Owner access to the workspace to test this channel.")
		}
		saved, err := h.channelSecrets(prev)
		if err != nil {
			return nil, internalError(err)
		}
		var prevCfg notify.ChannelConfig
		_ = json.Unmarshal(prev.Config, &prevCfg)
		secrets = secrets.Merge(saved)
		kind = prev.Kind
		allowed = prev.AllowInternal && channelTarget(prevCfg, saved) == channelTarget(b.Config, secrets)
	} else {
		ws, err := h.authz.createTarget(ctx, p)
		if err != nil {
			return nil, err
		}
		if p.Access.WorkspaceLevel(ws) < auth.Owner {
			return nil, huma.Error403Forbidden("You need Owner access to the workspace to add a notification channel.")
		}
	}
	if b.AllowInternal && !p.Access.Admin && !allowed {
		return nil, fieldError("body.allow_internal", "Only a system admin can allow private addresses", true)
	}
	if err := cleanChannel(kind, &b.NotifyChannelBody, secrets); err != nil {
		return nil, err
	}
	ch := notify.Channel{
		Kind: kind, Config: b.Config, Secrets: secrets,
		Dial: notify.Dialer(dbmon.DirectDialer(b.AllowInternal)),
	}
	return testResult(notify.Send(ctx, ch, testMessage(strings.TrimSpace(b.Name)))), nil
}

type NotificationLogEntry struct {
	ID          int64     `json:"id"`
	At          time.Time `json:"at"`
	Title       string    `json:"title"`
	OK          bool      `json:"ok"`
	Error       string    `json:"error"`
	MonitorID   *string   `json:"monitor_id,omitempty" format:"uuid"`
	MonitorName string    `json:"monitor_name"`
	RuleID      *string   `json:"rule_id,omitempty" format:"uuid"`
	RuleName    string    `json:"rule_name"`
}

func registerNotifications(api huma.API, h *uptimeHandler) {
	tags := []string{"Notifications"}

	type listOut struct {
		Body struct {
			Items []NotifyChannel `json:"items"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "list-notification-channels", Method: http.MethodGet, Path: "/notification-channels",
		Summary: "List notification channels", Tags: tags,
	}, func(ctx context.Context, _ *struct{}) (*listOut, error) {
		sc := principalOf(ctx).scope()
		rows, err := h.q.ListNotificationChannels(ctx, sqlc.ListNotificationChannelsParams{
			SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, WorkspaceID: sc.current,
		})
		if err != nil {
			return nil, internalError(err)
		}
		ids := make([]uuid.UUID, len(rows))
		for i, r := range rows {
			ids[i] = r.ID
		}
		counts := map[uuid.UUID]int32{}
		if cs, err := h.q.CountChannelMonitors(ctx, ids); err == nil {
			for _, c := range cs {
				counts[c.ChannelID] = c.Monitors
			}
		}
		rules := map[uuid.UUID]int32{}
		if cs, err := h.q.CountChannelRules(ctx, ids); err == nil {
			for _, c := range cs {
				rules[c.ChannelID] = c.Rules
			}
		}
		out := &listOut{}
		out.Body.Items = make([]NotifyChannel, 0, len(rows))
		for _, r := range rows {
			s, _ := h.channelSecrets(r)
			out.Body.Items = append(out.Body.Items, toNotifyChannel(r, s, counts[r.ID], rules[r.ID]))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-notification-channel", Method: http.MethodPost, Path: "/notification-channels",
		Summary: "Add a notification channel", Tags: tags, DefaultStatus: http.StatusCreated,
	}, h.createChannel)

	huma.Register(api, huma.Operation{
		OperationID: "test-notification-settings", Method: http.MethodPost, Path: "/notification-channels/test",
		Summary:     "Send a test with unsaved settings",
		Description: "Sends a test message with the given settings without saving anything.", Tags: tags,
	}, h.testUnsaved)

	huma.Register(api, huma.Operation{
		OperationID: "get-notification-channel", Method: http.MethodGet, Path: "/notification-channels/{id}",
		Summary: "Get a notification channel", Tags: tags,
	}, func(ctx context.Context, in *ChannelIDPath) (*NotifyChannelOutput, error) {
		c, err := h.getChannel(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return h.channelOut(ctx, c)
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-notification-channel", Method: http.MethodPut, Path: "/notification-channels/{id}",
		Summary: "Update a notification channel", Tags: tags,
	}, h.updateChannel)

	huma.Register(api, huma.Operation{
		OperationID: "delete-notification-channel", Method: http.MethodDelete, Path: "/notification-channels/{id}",
		Summary: "Remove a notification channel", Tags: tags, DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *ChannelIDPath) (*struct{}, error) {
		c, err := h.getChannel(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if err := h.q.DeleteNotificationChannel(ctx, c.ID); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "test-notification-channel", Method: http.MethodPost, Path: "/notification-channels/{id}/test",
		Summary: "Send a test message", Tags: tags,
	}, func(ctx context.Context, in *ChannelIDPath) (*ChannelTestOutput, error) {
		c, err := h.getChannel(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		ch, err := h.sendable(c)
		if err != nil {
			return nil, internalError(err)
		}
		sendErr := notify.Send(ctx, ch, testMessage(c.Name))
		h.recordSend(ctx, c.ID, nil, "Test", sendErr)
		return testResult(sendErr), nil
	})

	type logOut struct {
		Body struct {
			Items []NotificationLogEntry `json:"items"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "list-notification-log", Method: http.MethodGet, Path: "/notification-channels/{id}/log",
		Summary: "What a channel sent", Description: "Newest first.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		ChannelIDPath
		Limit int32 `query:"limit" minimum:"1" maximum:"500" default:"100"`
	}) (*logOut, error) {
		c, err := h.getChannel(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		rows, err := h.q.ListNotificationLog(ctx, sqlc.ListNotificationLogParams{ChannelID: c.ID, Lim: in.Limit})
		if err != nil {
			return nil, internalError(err)
		}
		out := &logOut{}
		out.Body.Items = make([]NotificationLogEntry, 0, len(rows))
		for _, r := range rows {
			out.Body.Items = append(out.Body.Items, NotificationLogEntry{
				ID: r.ID, At: r.At, Title: r.Title, OK: r.Ok, Error: r.Error,
				MonitorID: optionalIDString(r.MonitorID), MonitorName: r.MonitorName,
				RuleID: optionalIDString(r.RuleID), RuleName: r.RuleName,
			})
		}
		return out, nil
	})
}

// recordSend notes a delivery on the channel and in its log.
func (h *uptimeHandler) recordSend(ctx context.Context, channel uuid.UUID, monitor *uuid.UUID, title string, err error) {
	msg := ""
	if err != nil {
		msg = clipText(err.Error(), 1000)
	}
	_ = h.q.RecordChannelSend(ctx, sqlc.RecordChannelSendParams{ID: channel, Ok: err == nil, Error: msg})
	_ = h.q.LogNotification(ctx, sqlc.LogNotificationParams{
		ChannelID: channel, MonitorID: monitor, Title: title, Ok: err == nil, Error: msg,
	})
}

// recordRuleSend is recordSend for an alert rule's message.
func (h *uptimeHandler) recordRuleSend(ctx context.Context, channel, rule uuid.UUID, title string, err error) {
	msg := ""
	if err != nil {
		msg = clipText(err.Error(), 1000)
	}
	_ = h.q.RecordChannelSend(ctx, sqlc.RecordChannelSendParams{ID: channel, Ok: err == nil, Error: msg})
	_ = h.q.LogNotification(ctx, sqlc.LogNotificationParams{
		ChannelID: channel, RuleID: &rule, Title: title, Ok: err == nil, Error: msg,
	})
}
