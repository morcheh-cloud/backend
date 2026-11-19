package api

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morche/backend/internal/database/sqlc"
)

// The public demo (DEMO_MODE): every visitor shares one account, so what one
// of them could use to spoil the others' visit is refused for it. The rest
// stays open on purpose: the demo's servers are throwaway containers on a
// network with no way out, and the data is put back every reset.
var demoRefused = map[string]bool{
	// Nobody signs up on the demo. (First-run setup stays: the demo's seed
	// uses it, behind SETUP_TOKEN.)
	"auth-register": true,
	// The shared account itself: its password, profile and sessions.
	"change-password":       true,
	"update-me":             true,
	"auth-logout-all":       true,
	"end-my-session":        true,
	"end-my-other-sessions": true,
	"answer-sign-in-alert":  true,
	// They'd show every visitor's address to the others.
	"list-my-sessions": true,
	"list-sign-ins":    true,
	// Who can reach what.
	"set-grant":    true,
	"delete-grant": true,
	// Playbooks run on Morche's own machine; never for a stranger.
	"start-ansible-run": true,
}

const demoRefusal = "That isn't available in the demo."

// DemoState tells the panel it's the public demo.
type DemoState struct {
	ResetAt         time.Time `json:"reset_at" doc:"When the demo's data is next put back."`
	IntervalSeconds int64     `json:"interval_seconds"`
}

func (a *authz) demoState() *DemoState {
	if !a.cfg.DemoMode {
		return nil
	}
	return &DemoState{
		ResetAt:         a.cfg.NextDemoReset(time.Now()),
		IntervalSeconds: int64(a.cfg.DemoResetInterval / time.Second),
	}
}

// demoRefuses says whether this operation is closed to p in the demo. Admins
// (whoever runs the demo) keep everything.
func (a *authz) demoRefuses(op string, p *principal) bool {
	if !a.cfg.DemoMode || !demoRefused[op] {
		return false
	}
	return p == nil || p.User.Role != "admin"
}

func registerDemo(api huma.API, a *authz) {
	huma.Register(api, huma.Operation{
		OperationID: "auth-demo", Method: http.MethodPost, Path: "/auth/demo",
		Summary: "Enter the public demo", Tags: []string{"Auth"},
		Description: "Signs in as the shared demo account. Only on a panel started with DEMO_MODE.",
	}, func(ctx context.Context, _ *struct{}) (*SignedInOutput, error) {
		if !a.cfg.DemoMode {
			return nil, huma.Error404NotFound("This panel isn't a demo.")
		}
		key := "demo:" + clientOf(ctx).ip
		if a.over(ctx, key, 30) {
			return nil, errTooMany()
		}
		a.hit(ctx, key, time.Hour)
		u, err := a.q.GetUserByUsername(ctx, a.cfg.DemoUser)
		if isNotFound(err) {
			return nil, huma.Error503ServiceUnavailable("The demo is being set up. Try again in a minute.")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if u.Status != "active" || u.Role == "admin" {
			return nil, huma.Error503ServiceUnavailable("The demo account isn't ready.")
		}
		// Made by an admin, so it starts with "change your password"; nobody
		// knows that password and visitors can't change it, so drop the ask.
		if u.MustChangePassword {
			if u, err = a.q.SetUserPassword(ctx, sqlc.SetUserPasswordParams{
				ID: u.ID, PasswordHash: u.PasswordHash,
			}); err != nil {
				return nil, internalError(err)
			}
		}
		out := &SignedInOutput{Body: toPanelUser(u)}
		if out.SetCookie, err = a.signedIn(ctx, a.q, u, false, false); err != nil {
			return nil, internalError(err)
		}
		return out, nil
	})
}

// termOwner is who a web terminal belongs to: the user, or on the demo each
// visitor's own session, since they all share one account.
func (a *authz) termOwner(p *principal) string {
	if a.cfg.DemoMode && p.User.Role != "admin" {
		return p.User.ID.String() + "/" + p.SessionID.String()
	}
	return p.User.ID.String()
}

// loggedIP is the address the command log keeps. On the demo visitors share
// one account, so one's address would show to all the others: none is kept.
func (a *authz) loggedIP(p *principal, ip string) string {
	if a.cfg.DemoMode && p.User.Role != "admin" {
		return ""
	}
	return ip
}
