package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/notify"
)

// signInKeepDays is how long the sign-in log is kept.
const signInKeepDays = 180

// Failed sign-ins that send an alert: the count on one account reaching these
// (from one address, or from anywhere) within the rate-limit window.
const (
	alertPairFailures = 5
	alertNameFailures = 30
)

// ---- Recording ----

// logSignIn writes one row of the sign-in log. A failure is logged, never
// returned: signing in must not break because the log couldn't be written.
func (a *authz) logSignIn(ctx context.Context, q *sqlc.Queries, row sqlc.RecordSignInParams) {
	row.Username = truncate(row.Username, 64)
	if _, err := q.RecordSignIn(ctx, row); err != nil {
		slog.Warn("record a sign-in", "kind", row.Kind, "error", err)
	}
}

// clientRow fills where the request came from.
func clientRow(ctx context.Context, row sqlc.RecordSignInParams) sqlc.RecordSignInParams {
	cl := clientOf(ctx)
	row.Ip, row.Network, row.UserAgent = cl.ip, networkOf(cl.ip), cl.userAgent
	return row
}

// byRow says who ended a session, for the log.
func byRow(p *principal, row sqlc.RecordSignInParams) sqlc.RecordSignInParams {
	if p != nil {
		row.ByUserID = &p.User.ID
		row.ByName = cmpOr(p.User.FullName, p.User.Username)
	}
	return row
}

// sessionRow is a log row about an existing session: its device, not the
// caller's.
func sessionRow(u sqlc.User, s sqlc.Session, kind, reason string) sqlc.RecordSignInParams {
	return sqlc.RecordSignInParams{
		UserID: &u.ID, Username: u.Username, Ip: s.Ip, Network: networkOf(s.Ip),
		UserAgent: s.UserAgent, Kind: kind, Reason: reason, SessionID: &s.ID,
	}
}

// isNewAddress says whether u signing in from ip should be called out: they
// have signed in before (or have a session open) and never from this network.
// The very first sign-in of an account isn't news.
func (a *authz) isNewAddress(ctx context.Context, u uuid.UUID, ip string) bool {
	network := networkOf(ip)
	sessions, err := a.q.ListUserSessions(ctx, u)
	if err != nil {
		return false
	}
	for _, s := range sessions {
		if networkOf(s.Ip) == network {
			return false
		}
	}
	known, err := a.q.KnownNetwork(ctx, sqlc.KnownNetworkParams{UserID: &u, Network: network})
	if err != nil || known {
		return false
	}
	if len(sessions) > 0 {
		return true
	}
	before, err := a.q.HasSignedIn(ctx, &u)
	return err == nil && before
}

// ---- Alerts ----

// securityAlert sends msg to the channels picked in the security settings,
// if that kind of alert is on. It runs in the background.
func (a *authz) securityAlert(kind string, msg notify.Message) {
	if a.up == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		st, err := a.q.GetSettings(ctx)
		if err != nil {
			slog.Warn("security alert: settings", "error", err)
			return
		}
		if (kind == "new_address" && !st.AlertNewAddress) || (kind == "failed" && !st.AlertFailedSignIns) {
			return
		}
		if a.up.panelURL != "" {
			msg.URL = a.up.panelURL + "/recordings?tab=sign-ins"
		}
		for _, id := range st.SignInChannels {
			c, err := a.q.GetNotificationChannel(ctx, id)
			if err != nil || !c.Enabled {
				continue
			}
			ch, err := a.up.sendable(c)
			if err == nil {
				sctx, scancel := context.WithTimeout(ctx, 30*time.Second)
				err = notify.Send(sctx, ch, msg)
				scancel()
			}
			a.up.recordSend(ctx, c.ID, nil, msg.Title, err)
		}
	}()
}

func signInFields(u, ip, ua string, at time.Time) []notify.Field {
	f := []notify.Field{{Name: "Account", Value: u}, {Name: "Address", Value: ip}}
	if d := deviceOf(ua).name; d != "" {
		f = append(f, notify.Field{Name: "Device", Value: d})
	}
	return append(f, notify.Field{Name: "Time", Value: at.UTC().Format("2006-01-02 15:04 UTC")})
}

func (a *authz) alertNewAddress(u sqlc.User, ip, ua string) {
	at := time.Now()
	name := cmpOr(u.FullName, u.Username)
	a.securityAlert("new_address", notify.Message{
		Event: notify.EventSecurity,
		Title: "Sign-in from a new address: " + u.Username,
		Text: fmt.Sprintf("%s signed in to Morche from %s, an address they haven't used before. "+
			"If it wasn't them, end that session and change the password.", name, ip),
		Fields: signInFields(u.Username, ip, ua, at), At: at,
		Data: map[string]any{"type": "sign_in_new_address", "user_id": u.ID.String(), "username": u.Username, "ip": ip},
	})
}

func (a *authz) alertFailures(u sqlc.User, ip, ua string, count int64, fromOne bool) {
	at := time.Now()
	text := fmt.Sprintf("%d wrong passwords for %s from %s in the last 15 minutes.", count, u.Username, ip)
	if !fromOne {
		text = fmt.Sprintf("%d wrong passwords for %s in the last 15 minutes, from several addresses (the last from %s).", count, u.Username, ip)
	}
	a.securityAlert("failed", notify.Message{
		Event:  notify.EventSecurity,
		Title:  "Failed sign-ins: " + u.Username,
		Text:   text + " Further tries are refused for a while.",
		Fields: signInFields(u.Username, ip, ua, at), At: at,
		Data: map[string]any{"type": "sign_in_failed", "user_id": u.ID.String(), "username": u.Username, "ip": ip, "count": count},
	})
}

// ---- Devices ----

type device struct{ name, kind string }

// deviceOf names the browser and system in a User-Agent, like "Chrome on
// Windows". kind is desktop, phone, tablet or other.
func deviceOf(ua string) device {
	if ua == "" {
		return device{"", "other"}
	}
	has := func(s string) bool { return strings.Contains(ua, s) }
	browser := ""
	switch {
	case has("Edg/") || has("EdgA/") || has("EdgiOS/"):
		browser = "Edge"
	case has("OPR/") || has("Opera"):
		browser = "Opera"
	case has("SamsungBrowser/"):
		browser = "Samsung Internet"
	case has("Firefox/") || has("FxiOS/"):
		browser = "Firefox"
	case has("YaBrowser/"):
		browser = "Yandex"
	case has("CriOS/") || has("Chrome/"):
		browser = "Chrome"
	case has("Safari/") && has("Version/"):
		browser = "Safari"
	case has("curl/"):
		browser = "curl"
	}
	system, kind := "", "desktop"
	switch {
	case has("iPad"):
		system, kind = "iPad", "tablet"
	case has("iPhone"):
		system, kind = "iPhone", "phone"
	case has("Android"):
		system, kind = "Android", "phone"
		if !has("Mobile") {
			kind = "tablet"
		}
	case has("Windows"):
		system = "Windows"
	case has("CrOS"):
		system = "ChromeOS"
	case has("Mac OS X") || has("Macintosh"):
		system = "macOS"
	case has("Linux"):
		system = "Linux"
	default:
		kind = "other"
	}
	switch {
	case browser != "" && system != "":
		return device{browser + " on " + system, kind}
	case browser != "":
		return device{browser, kind}
	case system != "":
		return device{system, kind}
	}
	return device{truncate(ua, 40), "other"}
}

// ---- API shapes ----

type PanelSession struct {
	ID         string    `json:"id" format:"uuid"`
	Current    bool      `json:"current" doc:"The session making this request."`
	Remember   bool      `json:"remember"`
	Device     string    `json:"device" doc:"Browser and system, like Chrome on Windows."`
	DeviceKind string    `json:"device_kind" enum:"desktop,phone,tablet,other"`
	UserAgent  string    `json:"user_agent"`
	IP         string    `json:"ip"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func toPanelSession(s sqlc.Session, current uuid.UUID) PanelSession {
	d := deviceOf(s.UserAgent)
	return PanelSession{
		ID: s.ID.String(), Current: s.ID == current, Remember: s.Remember,
		Device: d.name, DeviceKind: d.kind, UserAgent: s.UserAgent, IP: s.Ip,
		CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt, ExpiresAt: s.ExpiresAt,
	}
}

type PanelSessionsOutput struct {
	Body struct {
		Items []PanelSession `json:"items"`
	}
}

type SignInEntry struct {
	ID          string     `json:"id" format:"uuid"`
	At          time.Time  `json:"at"`
	UserID      string     `json:"user_id,omitempty" doc:"Empty when the name typed isn't an account."`
	Username    string     `json:"username" doc:"The account, or what was typed."`
	IP          string     `json:"ip"`
	UserAgent   string     `json:"user_agent"`
	Device      string     `json:"device"`
	DeviceKind  string     `json:"device_kind" enum:"desktop,phone,tablet,other"`
	Kind        string     `json:"kind" enum:"signed_in,failed,signed_out,ended"`
	Reason      string     `json:"reason" doc:"failed: unknown_user, wrong_password, blocked_account, address_not_allowed. signed_out: everywhere. ended: by_self, by_admin, by_admin_everywhere, not_me, password_changed."`
	NewAddress  bool       `json:"new_address" doc:"A sign-in from a network this account hadn't used."`
	SessionID   string     `json:"session_id,omitempty"`
	SessionOpen bool       `json:"session_open" doc:"The session it started is still signed in."`
	Current     bool       `json:"current" doc:"It started the session making this request."`
	ByName      string     `json:"by_name,omitempty" doc:"Who ended the session, when someone did."`
	Answer      string     `json:"answer" enum:",me,not_me" doc:"What the person said about a new-address alert."`
	AnsweredAt  *time.Time `json:"answered_at,omitempty"`
}

func toSignInEntry(l sqlc.SignIn, open bool, current uuid.UUID) SignInEntry {
	d := deviceOf(l.UserAgent)
	e := SignInEntry{
		ID: l.ID.String(), At: l.At, Username: l.Username, IP: l.Ip, UserAgent: l.UserAgent,
		Device: d.name, DeviceKind: d.kind, Kind: l.Kind, Reason: l.Reason,
		NewAddress: l.NewAddress, SessionOpen: open, ByName: l.ByName,
		Answer: l.Answer, AnsweredAt: l.AnsweredAt,
	}
	if l.UserID != nil {
		e.UserID = l.UserID.String()
	}
	if l.SessionID != nil {
		e.SessionID = l.SessionID.String()
		e.Current = *l.SessionID == current
	}
	return e
}

type SignInsInput struct {
	User    string `query:"user" doc:"One account (admins only; others always see their own)."`
	Kind    string `query:"kind" enum:"all,signed_in,failed,signed_out,ended" default:"all"`
	Q       string `query:"q" maxLength:"100" doc:"Account name or the start of an address."`
	NewOnly bool   `query:"new_only" doc:"Only sign-ins from a new address."`
	Since   string `query:"since" enum:"all,24h,7d,30d" default:"all"`
	Before  string `query:"before" maxLength:"100" doc:"The next cursor of the previous page."`
	Limit   int32  `query:"limit" minimum:"1" maximum:"200" default:"50"`
}

type SignInsOutput struct {
	Body struct {
		Items []SignInEntry `json:"items"`
		Next  string        `json:"next,omitempty" doc:"Pass as before for the next page."`
	}
}

type SignInAlertsOutput struct {
	Body struct {
		Items []SignInEntry `json:"items"`
	}
}

type AnswerSignInInput struct {
	ID   string `path:"alert" format:"uuid"`
	Body struct {
		Answer string `json:"answer" enum:"me,not_me"`
	}
}

type SessionPath struct {
	ID string `path:"session" format:"uuid"`
}

type UserSessionPath struct {
	ID      string `path:"id" format:"uuid"`
	Session string `path:"session" format:"uuid"`
}

type SecurityChannel struct {
	ID            string `json:"id" format:"uuid"`
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Enabled       bool   `json:"enabled"`
	WorkspaceID   string `json:"workspace_id" format:"uuid"`
	WorkspaceName string `json:"workspace_name"`
}

type SecuritySettingsBody struct {
	AllowlistEnabled   bool         `json:"allowlist_enabled" doc:"Only the addresses below reach the panel."`
	Allowlist          []AllowEntry `json:"allowlist" maxItems:"200"`
	SignInChannels     []string     `json:"sign_in_channels" maxItems:"20" doc:"Notification channels that get sign-in alerts."`
	AlertNewAddress    bool         `json:"alert_new_address"`
	AlertFailedSignIns bool         `json:"alert_failed_sign_ins"`
}

type SecuritySettings struct {
	SecuritySettingsBody
	YourAddress        string            `json:"your_address" doc:"The address the panel sees for this request."`
	YourAddressAllowed bool              `json:"your_address_allowed" doc:"Whether it's in the saved list."`
	YourAddressPrivate bool              `json:"your_address_private" doc:"A private address: the panel probably sees a proxy, not you."`
	TrustProxy         bool              `json:"trust_proxy" doc:"The backend reads the client address from X-Forwarded-For (TRUST_PROXY)."`
	Channels           []SecurityChannel `json:"channels" doc:"Every notification channel there is, to pick from."`
}

type SecuritySettingsOutput struct{ Body SecuritySettings }

// ---- Endpoints ----

func registerSignIns(api huma.API, a *authz) {
	tags := []string{"Auth"}

	huma.Register(api, huma.Operation{
		OperationID: "list-my-sessions", Method: http.MethodGet, Path: "/auth/sessions",
		Summary: "Your open sessions", Tags: tags,
	}, func(ctx context.Context, _ *struct{}) (*PanelSessionsOutput, error) {
		p := principalOf(ctx)
		return a.sessionsOf(ctx, p.User.ID, p.SessionID)
	})

	huma.Register(api, huma.Operation{
		OperationID: "end-my-session", Method: http.MethodDelete, Path: "/auth/sessions/{session}",
		Summary: "End one of your sessions", Tags: tags,
		Description: "Signs that device out. To end this one, sign out.", DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *SessionPath) (*struct{}, error) {
		p := principalOf(ctx)
		id, _ := uuid.Parse(in.ID)
		if id == p.SessionID {
			return nil, huma.Error422UnprocessableEntity("That's this session. Sign out instead.")
		}
		return nil, a.endSession(ctx, p.User, id, "by_self")
	})

	huma.Register(api, huma.Operation{
		OperationID: "end-my-other-sessions", Method: http.MethodPost, Path: "/auth/sessions/end-others",
		Summary: "Sign out your other devices", Tags: tags,
		Description: "Ends every session but this one. Your terminals stay open.", DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, _ *struct{}) (*struct{}, error) {
		p := principalOf(ctx)
		sessions, err := a.q.ListUserSessions(ctx, p.User.ID)
		if err != nil {
			return nil, internalError(err)
		}
		for _, s := range sessions {
			if s.ID == p.SessionID {
				continue
			}
			if err := a.q.DeleteSession(ctx, s.ID); err != nil {
				return nil, internalError(err)
			}
			a.logSignIn(ctx, a.q, byRow(p, sessionRow(p.User, s, "ended", "by_self")))
		}
		a.invalidate()
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-sign-in-alerts", Method: http.MethodGet, Path: "/auth/sign-in-alerts",
		Summary: "Sign-ins from a new address you haven't answered", Tags: tags,
		Description: "Only sign-ins of other sessions, from the last 14 days.",
	}, func(ctx context.Context, _ *struct{}) (*SignInAlertsOutput, error) {
		p := principalOf(ctx)
		rows, err := a.q.PendingSignInAlerts(ctx, sqlc.PendingSignInAlertsParams{UserID: &p.User.ID, Current: &p.SessionID})
		if err != nil {
			return nil, internalError(err)
		}
		out := &SignInAlertsOutput{}
		out.Body.Items = make([]SignInEntry, 0, len(rows))
		for _, r := range rows {
			out.Body.Items = append(out.Body.Items, toSignInEntry(r.SignIn, r.SessionOpen, p.SessionID))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "answer-sign-in-alert", Method: http.MethodPost, Path: "/auth/sign-in-alerts/{alert}/answer",
		Summary: "Say whether a new-address sign-in was you", Tags: tags,
		Description:   "not_me ends that session and closes your terminals; change your password next.",
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *AnswerSignInInput) (*struct{}, error) {
		p := principalOf(ctx)
		id, _ := uuid.Parse(in.ID)
		row, err := a.q.AnswerSignIn(ctx, sqlc.AnswerSignInParams{Answer: in.Body.Answer, ID: id, UserID: &p.User.ID})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("sign-in not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if in.Body.Answer != "not_me" {
			return nil, nil
		}
		if row.SessionID != nil && *row.SessionID != p.SessionID {
			if err := a.endSession(ctx, p.User, *row.SessionID, "not_me"); err != nil && !isHumaNotFound(err) {
				return nil, err
			}
		}
		// Whatever they started may still be running on a server.
		a.terms.KillOwner(p.User.ID.String())
		a.invalidate()
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-sign-ins", Method: http.MethodGet, Path: "/sign-ins",
		Summary: "The sign-in log", Tags: []string{"Audit log"},
		Description: "Successful and failed sign-ins, sign-outs and ended sessions, newest first. Admins see everyone; others only their own account.",
	}, func(ctx context.Context, in *SignInsInput) (*SignInsOutput, error) {
		p := principalOf(ctx)
		params := sqlc.ListSignInsParams{Kinds: []string{}, NewOnly: in.NewOnly, Q: strings.TrimSpace(in.Q), Lim: in.Limit + 1}
		switch {
		case !p.Access.Admin:
			params.UserID = &p.User.ID
		case in.User != "":
			id, err := uuid.Parse(in.User)
			if err != nil {
				return nil, fieldError("query.user", "Not a user id.", in.User)
			}
			params.UserID = &id
		}
		if in.Kind != "" && in.Kind != "all" {
			params.Kinds = []string{in.Kind}
		}
		if d := map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}[in.Since]; d > 0 {
			t := time.Now().Add(-d)
			params.Since = &t
		}
		if in.Before != "" {
			at, id, ok := readCursor(in.Before)
			if !ok {
				return nil, fieldError("query.before", "Not a cursor from this list.", in.Before)
			}
			params.BeforeAt, params.BeforeID = &at, &id
		}
		rows, err := a.q.ListSignIns(ctx, params)
		if err != nil {
			return nil, internalError(err)
		}
		out := &SignInsOutput{}
		if len(rows) > int(in.Limit) {
			rows = rows[:in.Limit]
			last := rows[len(rows)-1].SignIn
			out.Body.Next = strconv.FormatInt(last.At.UnixMicro(), 10) + "_" + last.ID.String()
		}
		out.Body.Items = make([]SignInEntry, 0, len(rows))
		for _, r := range rows {
			out.Body.Items = append(out.Body.Items, toSignInEntry(r.SignIn, r.SessionOpen, p.SessionID))
		}
		return out, nil
	})

	// ---- Admin ----

	admin := []string{"Admin"}

	huma.Register(api, huma.Operation{
		OperationID: "admin-list-user-sessions", Method: http.MethodGet, Path: "/admin/users/{id}/sessions",
		Summary: "Someone's open sessions", Tags: admin,
	}, func(ctx context.Context, in *PanelUserPath) (*PanelSessionsOutput, error) {
		u, err := lookupUser(ctx, a.q, in.ID)
		if err != nil {
			return nil, err
		}
		return a.sessionsOf(ctx, u.ID, principalOf(ctx).SessionID)
	})

	huma.Register(api, huma.Operation{
		OperationID: "admin-end-user-session", Method: http.MethodDelete, Path: "/admin/users/{id}/sessions/{session}",
		Summary: "End one of someone's sessions", Tags: admin, DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *UserSessionPath) (*struct{}, error) {
		u, err := lookupUser(ctx, a.q, in.ID)
		if err != nil {
			return nil, err
		}
		id, err := uuid.Parse(in.Session)
		if err != nil {
			return nil, huma.Error404NotFound("session not found")
		}
		if id == principalOf(ctx).SessionID {
			return nil, huma.Error422UnprocessableEntity("That's this session. Sign out instead.")
		}
		return nil, a.endSession(ctx, u, id, "by_admin")
	})

	huma.Register(api, huma.Operation{
		OperationID: "admin-get-security", Method: http.MethodGet, Path: "/admin/security",
		Summary: "Panel security settings", Tags: admin,
		Description: "Allowed addresses and sign-in alerts.",
	}, func(ctx context.Context, _ *struct{}) (*SecuritySettingsOutput, error) {
		st, err := a.q.GetSettings(ctx)
		if err != nil {
			return nil, internalError(err)
		}
		return a.securityOut(ctx, st)
	})

	huma.Register(api, huma.Operation{
		OperationID: "admin-update-security", Method: http.MethodPut, Path: "/admin/security",
		Summary: "Save panel security settings", Tags: admin,
		Description: "Turning the allowlist on is refused unless your own address is in it, so you can't lock yourself out.",
	}, func(ctx context.Context, in *struct{ Body SecuritySettingsBody }) (*SecuritySettingsOutput, error) {
		b := in.Body
		entries, err := cleanAllowlist(b.Allowlist)
		if err != nil {
			return nil, err
		}
		ip := clientOf(ctx).ip
		if b.AllowlistEnabled {
			if len(entries) == 0 {
				return nil, fieldError("body.allowlist", "Add at least one address before turning the allowlist on.", nil)
			}
			if !(&allowlist{on: true, prefixes: prefixesOf(entries)}).allows(ip) {
				return nil, fieldError("body.allowlist", fmt.Sprintf("Your own address (%s) isn't in the list: saving would lock you out. Add it first.", ip), nil)
			}
		}
		channels := make([]uuid.UUID, 0, len(b.SignInChannels))
		for i, raw := range b.SignInChannels {
			id, err := uuid.Parse(raw)
			if err == nil {
				_, err = a.q.GetNotificationChannel(ctx, id)
			}
			if err != nil {
				return nil, fieldError(fmt.Sprintf("body.sign_in_channels[%d]", i), "That channel doesn't exist any more.", raw)
			}
			if !slices.Contains(channels, id) {
				channels = append(channels, id)
			}
		}
		list, _ := json.Marshal(entries)
		st, err := a.q.SetSecuritySettings(ctx, sqlc.SetSecuritySettingsParams{
			IpAllowlistEnabled: b.AllowlistEnabled, IpAllowlist: list, SignInChannels: channels,
			AlertNewAddress: b.AlertNewAddress, AlertFailedSignIns: b.AlertFailedSignIns,
		})
		if err != nil {
			return nil, internalError(err)
		}
		a.allow.Store(toAllowlist(st))
		a.invalidate()
		return a.securityOut(ctx, st)
	})
}

func isHumaNotFound(err error) bool {
	var se huma.StatusError
	return errors.As(err, &se) && se.GetStatus() == http.StatusNotFound
}

func (a *authz) sessionsOf(ctx context.Context, user, current uuid.UUID) (*PanelSessionsOutput, error) {
	rows, err := a.q.ListUserSessions(ctx, user)
	if err != nil {
		return nil, internalError(err)
	}
	out := &PanelSessionsOutput{}
	out.Body.Items = make([]PanelSession, 0, len(rows))
	for _, s := range rows {
		out.Body.Items = append(out.Body.Items, toPanelSession(s, current))
	}
	return out, nil
}

// endSession signs one of u's sessions out and logs who did it and why.
func (a *authz) endSession(ctx context.Context, u sqlc.User, id uuid.UUID, reason string) error {
	s, err := a.q.GetUserSession(ctx, sqlc.GetUserSessionParams{ID: id, UserID: u.ID})
	if isNotFound(err) {
		return huma.Error404NotFound("That session has already ended.")
	}
	if err != nil {
		return internalError(err)
	}
	if err := a.q.DeleteSession(ctx, s.ID); err != nil {
		return internalError(err)
	}
	a.logSignIn(ctx, a.q, byRow(principalOf(ctx), sessionRow(u, s, "ended", reason)))
	a.invalidate()
	return nil
}

func readCursor(s string) (time.Time, uuid.UUID, bool) {
	at, rawID, ok := strings.Cut(s, "_")
	if !ok {
		return time.Time{}, uuid.Nil, false
	}
	micros, err := strconv.ParseInt(at, 10, 64)
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	id, err := uuid.Parse(rawID)
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	return time.UnixMicro(micros), id, true
}

// cleanAllowlist checks every entry and writes each the same way, dropping
// repeats. Errors point at the row.
func cleanAllowlist(in []AllowEntry) ([]AllowEntry, error) {
	out := make([]AllowEntry, 0, len(in))
	seen := map[string]bool{}
	for i, e := range in {
		loc := fmt.Sprintf("body.allowlist[%d].address", i)
		if strings.TrimSpace(e.Address) == "" {
			return nil, fieldError(loc, "Enter an address or a range.", e.Address)
		}
		p, err := parseAllowEntry(e.Address)
		if err != nil {
			return nil, fieldError(loc, "Not an address or range, e.g. 203.0.113.7 or 203.0.113.0/24.", e.Address)
		}
		if p.Bits() == 0 {
			return nil, fieldError(loc, "That range is every address: it would allow everyone.", e.Address)
		}
		text := prefixText(p)
		if seen[text] {
			continue
		}
		seen[text] = true
		out = append(out, AllowEntry{Address: text, Note: strings.TrimSpace(e.Note)})
	}
	return out, nil
}

func prefixesOf(entries []AllowEntry) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(entries))
	for _, e := range entries {
		if p, err := parseAllowEntry(e.Address); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func (a *authz) securityOut(ctx context.Context, st sqlc.AppSetting) (*SecuritySettingsOutput, error) {
	ip := clientOf(ctx).ip
	saved := toAllowlist(st)
	out := &SecuritySettingsOutput{}
	out.Body.AllowlistEnabled = st.IpAllowlistEnabled
	out.Body.Allowlist = readAllowEntries(st.IpAllowlist)
	out.Body.SignInChannels = make([]string, 0, len(st.SignInChannels))
	for _, id := range st.SignInChannels {
		out.Body.SignInChannels = append(out.Body.SignInChannels, id.String())
	}
	out.Body.AlertNewAddress = st.AlertNewAddress
	out.Body.AlertFailedSignIns = st.AlertFailedSignIns
	out.Body.YourAddress = ip
	out.Body.YourAddressAllowed = (&allowlist{on: true, prefixes: saved.prefixes}).allows(ip)
	out.Body.YourAddressPrivate = privateAddress(ip)
	out.Body.TrustProxy = a.cfg.TrustProxy

	workspaces, err := a.q.ListWorkspaces(ctx)
	if err != nil {
		return nil, internalError(err)
	}
	names := map[uuid.UUID]string{}
	for _, w := range workspaces {
		names[w.ID] = w.Name
	}
	chans, err := a.q.ListNotificationChannels(ctx, sqlc.ListNotificationChannelsParams{SeeAll: true, WorkspaceIds: []uuid.UUID{}})
	if err != nil {
		return nil, internalError(err)
	}
	out.Body.Channels = make([]SecurityChannel, 0, len(chans))
	for _, c := range chans {
		out.Body.Channels = append(out.Body.Channels, SecurityChannel{
			ID: c.ID.String(), Name: c.Name, Kind: c.Kind, Enabled: c.Enabled,
			WorkspaceID: c.WorkspaceID.String(), WorkspaceName: names[c.WorkspaceID],
		})
	}
	return out, nil
}
