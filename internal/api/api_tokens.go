package api

import (
	"context"
	"crypto/rand"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/database/sqlc"
)

// API tokens (personal access tokens): for scripts, the CLI and other tools.
// A request with `Authorization: Bearer morche_…` and no session cookie acts as
// the token's user, with the same grants and the same blocking/approval rules.
// What a token may never do is in tokenRefused; a read-only one only reads.

const (
	tokenPrefix    = "morche_"
	tokenBodyLen   = 40
	tokenShownLen  = 8
	maxUserTokens  = 50
	tokenTouchGap  = time.Minute
	tokenRefusal   = "API tokens can't do that."
	readOnlyRefuse = "This token can only read."
)

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// tokenRefused are the operations a token can never call, whatever its user
// may do: signing in and out, the account itself, sessions and sign-in
// security, and tokens (a token can't make more tokens). Every session-level
// operation is here except get-me, which only says who the token belongs to
// (the CLI's whoami). TestTokenRefusedOperationsExist keeps the ids real.
var tokenRefused = map[string]bool{
	"auth-logout":     true,
	"auth-logout-all": true,
	"change-password": true,
	"update-me":       true,
	// Sessions and sign-in security.
	"list-my-sessions":         true,
	"end-my-session":           true,
	"end-my-other-sessions":    true,
	"list-sign-in-alerts":      true,
	"answer-sign-in-alert":     true,
	"list-sign-ins":            true,
	"admin-list-user-sessions": true,
	"admin-end-user-session":   true,
	"admin-revoke-sessions":    true,
	"admin-get-security":       true,
	"admin-update-security":    true,
	// Tokens.
	"list-api-tokens":        true,
	"create-api-token":       true,
	"delete-api-token":       true,
	"admin-list-user-tokens": true,
	"admin-delete-api-token": true,
}

// tokenAllowedSessionOps are session-level operations a token may still call.
var tokenAllowedSessionOps = map[string]bool{"get-me": true}

// newAPIToken makes a token and the hash to store.
func newAPIToken() (token string, hash []byte, err error) {
	var b strings.Builder
	b.WriteString(tokenPrefix)
	n := big.NewInt(int64(len(base62)))
	for range tokenBodyLen {
		i, err := rand.Int(rand.Reader, n)
		if err != nil {
			return "", nil, err
		}
		b.WriteByte(base62[i.Int64()])
	}
	token = b.String()
	return token, auth.HashToken(token), nil
}

// validAPIToken says whether s looks like one of our tokens.
func validAPIToken(s string) bool {
	body, ok := strings.CutPrefix(s, tokenPrefix)
	if !ok || len(body) != tokenBodyLen {
		return false
	}
	for i := range len(body) {
		if !strings.ContainsRune(base62, rune(body[i])) {
			return false
		}
	}
	return true
}

// bearerToken reads an API token from an Authorization header. Anything that
// isn't a well-formed Morche token gives "", so it's never looked up.
func bearerToken(header string) string {
	scheme, value, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	value = strings.TrimSpace(value)
	if !validAPIToken(value) {
		return ""
	}
	return value
}

func tokenShown(token string) string {
	return strings.TrimPrefix(token, tokenPrefix)[:tokenShownLen]
}

// authorizeToken is authorize for an API token: op and method are the
// operation's, for tokenRefused and read-only tokens.
func (a *authz) authorizeToken(ctx context.Context, token, op, method string, pol policy, rawID, workspace string) (*principal, *denied) {
	row, err := a.q.GetApiTokenByHash(ctx, auth.HashToken(token))
	if isNotFound(err) {
		return nil, &denied{http.StatusUnauthorized, "This API token isn't valid (revoked or expired)."}
	}
	if err != nil {
		slog.Error("load api token", "error", err)
		return nil, &denied{http.StatusInternalServerError, "internal error"}
	}
	t, u := row.ApiToken, row.User
	if u.Status == "blocked" {
		return nil, errUnauthenticated()
	}
	// Visitors share the demo account: a token would outlive their visit.
	if a.cfg.DemoMode && u.Role != "admin" {
		return nil, &denied{http.StatusForbidden, demoRefusal}
	}
	if tokenRefused[op] || (pol.kind == kindSession && !tokenAllowedSessionOps[op]) {
		return nil, &denied{http.StatusForbidden, tokenRefusal}
	}
	if t.ReadOnly && method != http.MethodGet && method != http.MethodHead {
		return nil, &denied{http.StatusForbidden, readOnlyRefuse}
	}
	if t.LastUsedAt == nil || time.Since(*t.LastUsedAt) > tokenTouchGap {
		if err := a.q.TouchApiToken(ctx, sqlc.TouchApiTokenParams{ID: t.ID, LastUsedIp: clientOf(ctx).ip}); err != nil {
			slog.Warn("touch api token", "error", err)
		}
	}
	// Unlike a session, a token never works for an account that isn't ready.
	if u.Status != "active" {
		return nil, &denied{http.StatusForbidden, "Your account is waiting for approval."}
	}
	if u.MustChangePassword {
		return nil, &denied{http.StatusForbidden, "Change your password to continue."}
	}
	p := &principal{User: u, TokenID: t.ID, TokenName: t.Name}
	if id, err := uuid.Parse(workspace); err == nil {
		p.Workspace = &id
	}
	return a.authorizeAs(ctx, p, pol, rawID)
}

// ---- API ----

// ApiToken is one personal access token (never the token itself).
type ApiToken struct {
	ID         string     `json:"id" format:"uuid"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix" doc:"The first characters after morche_, to tell tokens apart"`
	ReadOnly   bool       `json:"read_only"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Expired    bool       `json:"expired"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP string     `json:"last_used_ip,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

func toApiToken(t sqlc.ApiToken) ApiToken {
	return ApiToken{
		ID: t.ID.String(), Name: t.Name, Prefix: t.Prefix, ReadOnly: t.ReadOnly, ExpiresAt: t.ExpiresAt,
		Expired:    t.ExpiresAt != nil && !t.ExpiresAt.After(time.Now()),
		LastUsedAt: t.LastUsedAt, LastUsedIP: t.LastUsedIp, CreatedAt: t.CreatedAt,
	}
}

type ApiTokenList struct {
	Body struct {
		Items []ApiToken `json:"items"`
	}
}

type ApiTokenCreateBody struct {
	Name          string `json:"name" minLength:"1" maxLength:"100"`
	ReadOnly      bool   `json:"read_only,omitempty" doc:"Only GET requests"`
	ExpiresInDays int    `json:"expires_in_days,omitempty" minimum:"0" maximum:"3650" doc:"0 = never expires"`
}

// ApiTokenCreated carries the token itself, the only time it is shown.
type ApiTokenCreated struct {
	Token  ApiToken `json:"token"`
	Secret string   `json:"secret" doc:"The token (morche_…). Shown only now; send it as Authorization: Bearer <secret>."`
}

type ApiTokenPath struct {
	ID string `path:"id" format:"uuid"`
}

func (a *authz) listTokens(ctx context.Context, user uuid.UUID) (*ApiTokenList, error) {
	rows, err := a.q.ListUserApiTokens(ctx, user)
	if err != nil {
		return nil, internalError(err)
	}
	out := &ApiTokenList{}
	out.Body.Items = make([]ApiToken, len(rows))
	for i, r := range rows {
		out.Body.Items[i] = toApiToken(r)
	}
	return out, nil
}

func registerAPITokens(api huma.API, a *authz) {
	tags := []string{"Auth"}

	huma.Register(api, huma.Operation{
		OperationID: "list-api-tokens", Method: http.MethodGet, Path: "/auth/tokens",
		Summary: "Your API tokens", Tags: tags,
	}, func(ctx context.Context, _ *struct{}) (*ApiTokenList, error) {
		return a.listTokens(ctx, principalOf(ctx).User.ID)
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-api-token", Method: http.MethodPost, Path: "/auth/tokens",
		Summary: "Make an API token", Tags: tags, DefaultStatus: http.StatusCreated,
		Description: "The token acts as you (your access, nothing more). It is shown once. At most 50 per person.",
	}, func(ctx context.Context, in *struct{ Body ApiTokenCreateBody }) (*struct{ Body ApiTokenCreated }, error) {
		p := principalOf(ctx)
		name := strings.TrimSpace(in.Body.Name)
		if name == "" {
			return nil, fieldError("body.name", "Give the token a name", in.Body.Name)
		}
		n, err := a.q.CountUserApiTokens(ctx, p.User.ID)
		if err != nil {
			return nil, internalError(err)
		}
		if n >= maxUserTokens {
			return nil, huma.Error409Conflict("You have 50 tokens already. Revoke one first.")
		}
		token, hash, err := newAPIToken()
		if err != nil {
			return nil, internalError(err)
		}
		var expires *time.Time
		if d := in.Body.ExpiresInDays; d > 0 {
			t := time.Now().UTC().Add(time.Duration(d) * 24 * time.Hour)
			expires = &t
		}
		row, err := a.q.CreateApiToken(ctx, sqlc.CreateApiTokenParams{
			UserID: p.User.ID, Name: name, Prefix: tokenShown(token), TokenHash: hash,
			ReadOnly: in.Body.ReadOnly, ExpiresAt: expires,
		})
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct{ Body ApiTokenCreated }{}
		out.Body = ApiTokenCreated{Token: toApiToken(row), Secret: token}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-api-token", Method: http.MethodDelete, Path: "/auth/tokens/{id}",
		Summary: "Revoke one of your API tokens", Tags: tags, DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *ApiTokenPath) (*struct{}, error) {
		n, err := a.q.DeleteUserApiToken(ctx, sqlc.DeleteUserApiTokenParams{ID: uuid.MustParse(in.ID), UserID: principalOf(ctx).User.ID})
		if err != nil {
			return nil, internalError(err)
		}
		if n == 0 {
			return nil, huma.Error404NotFound("token not found")
		}
		a.invalidate()
		return nil, nil
	})

	admin := []string{"Admin"}
	huma.Register(api, huma.Operation{
		OperationID: "admin-list-user-tokens", Method: http.MethodGet, Path: "/admin/users/{id}/tokens",
		Summary: "Someone's API tokens", Tags: admin,
	}, func(ctx context.Context, in *PanelUserPath) (*ApiTokenList, error) {
		u, err := lookupUser(ctx, a.q, in.ID)
		if err != nil {
			return nil, err
		}
		return a.listTokens(ctx, u.ID)
	})

	huma.Register(api, huma.Operation{
		OperationID: "admin-delete-api-token", Method: http.MethodDelete, Path: "/admin/tokens/{id}",
		Summary: "Revoke someone's API token", Tags: admin, DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *ApiTokenPath) (*struct{}, error) {
		n, err := a.q.DeleteApiToken(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		if n == 0 {
			return nil, huma.Error404NotFound("token not found")
		}
		a.invalidate()
		return nil, nil
	})
}
