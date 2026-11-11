package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	sqlc "github.com/morcheh/backend/internal/database/sqlc"
)

// Mutes are quiet times (maintenance): while one is on, the alerts it matches
// are recorded but not sent. One can be planned ahead (starts_at later).

type AlertMute struct {
	ID            string    `json:"id" format:"uuid"`
	WorkspaceID   string    `json:"workspace_id" format:"uuid"`
	RuleID        *string   `json:"rule_id,omitempty" format:"uuid" doc:"Missing = every rule"`
	RuleName      string    `json:"rule_name"`
	TargetKind    string    `json:"target_kind" enum:",server,database" doc:"Empty = everywhere"`
	TargetID      *string   `json:"target_id,omitempty" format:"uuid"`
	TargetName    string    `json:"target_name"`
	StartsAt      time.Time `json:"starts_at"`
	Until         time.Time `json:"until"`
	Active        bool      `json:"active" doc:"On now (false = planned for later)"`
	Note          string    `json:"note"`
	CreatedByName string    `json:"created_by_name"`
	CreatedAt     time.Time `json:"created_at"`
}

type AlertMuteBody struct {
	RuleID     string     `json:"rule_id,omitempty" doc:"One rule; empty = every rule"`
	TargetKind string     `json:"target_kind,omitempty" enum:"server,database" doc:"With target_id: one server or database; empty = everywhere"`
	TargetID   string     `json:"target_id,omitempty"`
	StartsAt   *time.Time `json:"starts_at,omitempty" doc:"Empty = now"`
	Minutes    int32      `json:"minutes,omitempty" minimum:"0" maximum:"129600" doc:"How long; or give until"`
	Until      *time.Time `json:"until,omitempty"`
	Note       string     `json:"note,omitempty" maxLength:"500"`
}

func toAlertMute(m sqlc.AlertMute, ruleName string, now time.Time) AlertMute {
	return AlertMute{
		ID: m.ID.String(), WorkspaceID: m.WorkspaceID.String(), RuleID: optionalIDString(m.RuleID),
		RuleName: ruleName, TargetKind: m.TargetKind, TargetID: optionalIDString(m.TargetID),
		TargetName: m.TargetName, StartsAt: m.StartsAt, Until: m.Until,
		Active: !m.StartsAt.After(now), Note: m.Note, CreatedByName: m.CreatedByName,
		CreatedAt: m.CreatedAt,
	}
}

// muteLevel is what this person has on what a mute covers.
func (h *alertRuleHandler) muteLevel(ctx context.Context, p *principal, m sqlc.AlertMute) auth.Level {
	if m.TargetID != nil {
		switch m.TargetKind {
		case "server":
			return p.Access.ServerLevel(m.WorkspaceID, *m.TargetID)
		case "database":
			if d, err := h.q.GetDatabase(ctx, *m.TargetID); err == nil {
				return databaseLevelOf(p.Access, d)
			}
		}
	}
	return p.Access.WorkspaceLevel(m.WorkspaceID)
}

func (h *alertRuleHandler) createMute(ctx context.Context, in *struct {
	Body AlertMuteBody
}) (*struct{ Body AlertMute }, error) {
	p := principalOf(ctx)
	b := in.Body
	now := time.Now()
	m := sqlc.CreateAlertMuteParams{
		Note: strings.TrimSpace(b.Note), CreatedByName: cmpOr(p.User.FullName, p.User.Username),
	}
	var ws *uuid.UUID
	ruleName := ""
	if b.RuleID != "" {
		r, err := h.getRule(ctx, b.RuleID)
		if err != nil {
			return nil, err
		}
		m.RuleID, ws, ruleName = &r.ID, &r.WorkspaceID, r.Name
	}
	level := auth.None
	switch {
	case b.TargetID == "" && b.TargetKind == "":
	case b.TargetKind == "server":
		id, err := uuid.Parse(b.TargetID)
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
		m.TargetID, m.TargetName = &s.ID, s.Name
		level = p.Access.ServerLevel(s.WorkspaceID, s.ID)
		if ws != nil && *ws != s.WorkspaceID {
			return nil, fieldError("body.target_id", "That server isn't in the rule's workspace", b.TargetID)
		}
		ws = &s.WorkspaceID
	case b.TargetKind == "database":
		d, err := h.database(ctx, p, b.TargetID)
		if err != nil {
			return nil, err
		}
		m.TargetID, m.TargetName = &d.ID, d.Name
		level = databaseLevelOf(p.Access, d)
		if ws != nil && *ws != d.WorkspaceID {
			return nil, fieldError("body.target_id", "That database isn't in the rule's workspace", b.TargetID)
		}
		ws = &d.WorkspaceID
	default:
		return nil, fieldError("body.target_kind", "Say whether it's a server or a database", b.TargetKind)
	}
	if ws == nil {
		w, err := h.authz.createTarget(ctx, p)
		if err != nil {
			return nil, err
		}
		ws = &w
	}
	if m.TargetID == nil {
		level = p.Access.WorkspaceLevel(*ws)
		m.TargetKind = ""
	} else {
		m.TargetKind = b.TargetKind
	}
	if level < auth.Operator {
		return nil, huma.Error403Forbidden("You need Operator access to mute alerts")
	}
	m.WorkspaceID = *ws

	m.StartsAt = now
	if b.StartsAt != nil && b.StartsAt.After(now) {
		m.StartsAt = *b.StartsAt
	}
	switch {
	case b.Until != nil:
		m.Until = *b.Until
	case b.Minutes > 0:
		m.Until = m.StartsAt.Add(time.Duration(b.Minutes) * time.Minute)
	default:
		return nil, fieldError("body.minutes", "Say how long", b.Minutes)
	}
	if !m.Until.After(m.StartsAt) || !m.Until.After(now) {
		return nil, fieldError("body.until", "The end must be after the start", b.Until)
	}
	if m.Until.Sub(m.StartsAt) > 90*24*time.Hour {
		return nil, fieldError("body.until", "A mute lasts 90 days at most", b.Until)
	}
	if m.StartsAt.Sub(now) > 365*24*time.Hour {
		return nil, fieldError("body.starts_at", "Plan it within a year", b.StartsAt)
	}
	row, err := h.q.CreateAlertMute(ctx, m)
	if err != nil {
		return nil, internalError(err)
	}
	return &struct{ Body AlertMute }{toAlertMute(row, ruleName, now)}, nil
}

func registerAlertMutes(api huma.API, h *alertRuleHandler) {
	tags := []string{"Alerts"}

	type listOut struct {
		Body struct {
			Items []AlertMute `json:"items"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "list-alert-mutes", Method: http.MethodGet, Path: "/alert-mutes",
		Summary: "List alert mutes", Tags: tags,
		Description: "Mutes that are on now or planned, soonest first. With server_id or database_id, only those that cover it.",
	}, func(ctx context.Context, in *struct {
		ServerID   string `query:"server_id"`
		DatabaseID string `query:"database_id"`
	}) (*listOut, error) {
		p := principalOf(ctx)
		sc := p.scope()
		params := sqlc.ListAlertMutesParams{SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, WorkspaceID: sc.current}
		var only *uuid.UUID
		switch {
		case in.ServerID != "":
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
			only, params.SeeAll, params.WorkspaceID = &s.ID, true, &s.WorkspaceID
		case in.DatabaseID != "":
			d, err := h.database(ctx, p, in.DatabaseID)
			if err != nil {
				return nil, err
			}
			only, params.SeeAll, params.WorkspaceID = &d.ID, true, &d.WorkspaceID
		}
		rows, err := h.q.ListAlertMutes(ctx, params)
		if err != nil {
			return nil, internalError(err)
		}
		now := time.Now()
		out := &listOut{}
		out.Body.Items = []AlertMute{}
		for _, r := range rows {
			if only != nil && r.TargetID != nil && *r.TargetID != *only {
				continue
			}
			m := sqlc.AlertMute{
				ID: r.ID, WorkspaceID: r.WorkspaceID, RuleID: r.RuleID, TargetID: r.TargetID,
				TargetKind: r.TargetKind, TargetName: r.TargetName, StartsAt: r.StartsAt, Until: r.Until,
				Note: r.Note, CreatedByName: r.CreatedByName, CreatedAt: r.CreatedAt,
			}
			if only == nil && h.muteLevel(ctx, p, m) == auth.None {
				continue
			}
			out.Body.Items = append(out.Body.Items, toAlertMute(m, r.RuleName, now))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-alert-mute", Method: http.MethodPost, Path: "/alert-mutes",
		Summary: "Mute alerts for a while", Tags: tags, DefaultStatus: http.StatusCreated,
		Description: "One rule or all, on one server or database or everywhere, now or later. Alerts that fire meanwhile are recorded, not sent; one still firing when the mute ends is sent then. Needs Operator on what it covers.",
	}, h.createMute)

	huma.Register(api, huma.Operation{
		OperationID: "delete-alert-mute", Method: http.MethodDelete, Path: "/alert-mutes/{id}",
		Summary: "End a mute", Tags: tags, DefaultStatus: http.StatusNoContent,
		Description: "Ends it now; a planned one is dropped.",
	}, func(ctx context.Context, in *AlertRuleIDPath) (*struct{}, error) {
		p := principalOf(ctx)
		id, err := uuid.Parse(in.ID)
		if err != nil {
			return nil, huma.Error404NotFound("Mute not found")
		}
		m, err := h.q.GetAlertMute(ctx, id)
		level := auth.None
		if err == nil {
			level = h.muteLevel(ctx, p, m)
		}
		if isNotFound(err) || (err == nil && level == auth.None) {
			return nil, huma.Error404NotFound("Mute not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if level < auth.Operator {
			return nil, huma.Error403Forbidden("You need Operator access to end a mute")
		}
		if m.StartsAt.After(time.Now()) {
			err = h.q.DeleteAlertMute(ctx, m.ID)
		} else {
			_, err = h.q.EndAlertMute(ctx, m.ID)
		}
		if err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})
}
