package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
)

// PanelUser is someone who can log in to the panel. (The users on a server are
// in users.go.)
type PanelUser struct {
	ID                 string     `json:"id" format:"uuid"`
	Username           string     `json:"username"`
	Email              string     `json:"email"`
	FirstName          string     `json:"first_name"`
	FullName           string     `json:"full_name"`
	Role               string     `json:"role" enum:"admin,member"`
	Status             string     `json:"status" enum:"pending,active,blocked"`
	MustChangePassword bool       `json:"must_change_password"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	// Only in the admin screens.
	GroupIDs []string `json:"group_ids,omitempty"`
}

func toPanelUser(u sqlc.User) PanelUser {
	return PanelUser{
		ID: u.ID.String(), Username: u.Username, Email: u.Email,
		FirstName: u.FirstName, FullName: u.FullName,
		Role: u.Role, Status: u.Status, MustChangePassword: u.MustChangePassword,
		LastLoginAt: u.LastLoginAt, CreatedAt: u.CreatedAt,
	}
}

type PanelProfile struct {
	Email     string `json:"email" maxLength:"254"`
	FirstName string `json:"first_name" maxLength:"64"`
	FullName  string `json:"full_name" maxLength:"128"`
}

// clean trims the profile and reports the first bad field.
func (b *PanelProfile) clean() error {
	b.Email = strings.TrimSpace(b.Email)
	b.FirstName = strings.TrimSpace(b.FirstName)
	b.FullName = strings.TrimSpace(b.FullName)
	if a, err := mail.ParseAddress(b.Email); err != nil || a.Address != b.Email {
		return fieldError("body.email", "Enter a valid email address.", nil)
	}
	if b.FirstName == "" {
		return fieldError("body.first_name", "Enter a first name.", nil)
	}
	if b.FullName == "" {
		return fieldError("body.full_name", "Enter a full name.", nil)
	}
	if utf8.RuneCountInString(b.FirstName) > 64 {
		return fieldError("body.first_name", "That name is too long.", nil)
	}
	if utf8.RuneCountInString(b.FullName) > 128 {
		return fieldError("body.full_name", "That name is too long.", nil)
	}
	return nil
}

// PanelSignup is what creating an account takes.
type PanelSignup struct {
	Username string `json:"username" maxLength:"32"`
	PanelProfile
	Password string `json:"password" maxLength:"1024"`
}

func (b *PanelSignup) clean() error {
	b.Username = strings.TrimSpace(b.Username)
	if !auth.ValidUsername(b.Username) {
		return fieldError("body.username", auth.UsernameRule, nil)
	}
	if err := b.PanelProfile.clean(); err != nil {
		return err
	}
	if err := auth.CheckPassword(b.Password, b.Username); err != nil {
		return fieldError("body.password", err.Error(), nil)
	}
	return nil
}

// userConflict turns a taken username or email into an error on that field.
func userConflict(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		if pg.ConstraintName == "users_email_key" {
			return fieldError("body.email", "That email is already in use.", nil)
		}
		return fieldError("body.username", "That username is taken.", nil)
	}
	return internalError(err)
}

// inTx runs fn in a transaction. fn returns errors ready for the client.
func (a *authz) inTx(ctx context.Context, fn func(q *sqlc.Queries) error) error {
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return internalError(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := fn(a.q.WithTx(tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return internalError(err)
	}
	return nil
}

// ---- Cookies ----

func (a *authz) cookie(value string) http.Cookie {
	return http.Cookie{
		Name: sessionCookie, Value: value, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   !a.cfg.Development() && !a.cfg.CookieInsecure,
	}
}

func (a *authz) clearCookie() http.Cookie {
	c := a.cookie("")
	c.MaxAge = -1
	return c
}

// startSession opens a session. Without "remember" the cookie dies with the
// browser, and the row after sessionTTL either way.
func (a *authz) startSession(ctx context.Context, q *sqlc.Queries, userID uuid.UUID, remember bool) (http.Cookie, error) {
	token, hash, err := auth.NewToken()
	if err != nil {
		return http.Cookie{}, err
	}
	ttl := sessionTTL
	if remember {
		ttl = rememberTTL
	}
	cl := clientOf(ctx)
	if _, err := q.CreateSession(ctx, sqlc.CreateSessionParams{
		UserID: userID, TokenHash: hash, Remember: remember,
		UserAgent: cl.userAgent, Ip: cl.ip, ExpiresAt: time.Now().Add(ttl),
	}); err != nil {
		return http.Cookie{}, err
	}
	c := a.cookie(token)
	if remember {
		c.MaxAge = int(ttl.Seconds())
	}
	return c, nil
}

func sameToken(a, b string) bool {
	x, y := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(x[:], y[:]) == 1
}

// ---- Endpoints ----

type AuthState struct {
	NeedsSetup         bool `json:"needs_setup" doc:"No user exists yet: show the first-run form."`
	SetupTokenRequired bool `json:"setup_token_required"`
	RegistrationOpen   bool `json:"registration_open"`
}

type AuthStateOutput struct{ Body AuthState }

type AuthSetupBody struct {
	PanelSignup
	SetupToken string `json:"setup_token,omitempty" maxLength:"256"`
}

type AuthSetupInput struct{ Body AuthSetupBody }

type AuthRegisterInput struct{ Body PanelSignup }

type AuthLoginBody struct {
	Username string `json:"username" maxLength:"64"`
	Password string `json:"password" maxLength:"1024"`
	Remember bool   `json:"remember,omitempty"`
}

type AuthLoginInput struct{ Body AuthLoginBody }

// SignedInOutput carries the session cookie.
type SignedInOutput struct {
	SetCookie http.Cookie `header:"Set-Cookie"`
	Body      PanelUser
}

type SignedOutOutput struct {
	SetCookie http.Cookie `header:"Set-Cookie"`
}

type MeOutput struct{ Body PanelUser }

type UpdateMeInput struct{ Body PanelProfile }

type ChangePasswordBody struct {
	CurrentPassword string `json:"current_password" maxLength:"1024"`
	NewPassword     string `json:"new_password" maxLength:"1024"`
}

type ChangePasswordInput struct{ Body ChangePasswordBody }

type WorkspaceAccess struct {
	ID        string `json:"id" format:"uuid"`
	Level     string `json:"level"`
	CanCreate bool   `json:"can_create"`
}

type ResourceAccess struct {
	ID    string `json:"id" format:"uuid"`
	Level string `json:"level"`
}

// MyAccess is what the panel uses to hide what would be refused anyway. On a
// server, someone has the higher of its workspace's level and its own entry.
type MyAccess struct {
	Admin      bool              `json:"admin"`
	CanCreate  bool              `json:"can_create" doc:"Can add servers and storages somewhere."`
	Workspaces []WorkspaceAccess `json:"workspaces"`
	Servers    []ResourceAccess  `json:"servers"`
	Storages   []ResourceAccess  `json:"storages"`
	Apps       []ResourceAccess  `json:"apps" doc:"Services on the Services page."`
}

type MyAccessOutput struct{ Body MyAccess }

func registerAuth(api huma.API, a *authz) {
	tags := []string{"Auth"}

	huma.Register(api, huma.Operation{
		OperationID: "get-auth-state", Method: http.MethodGet, Path: "/auth/state",
		Summary: "What the sign-in page should offer", Tags: tags,
	}, func(ctx context.Context, _ *struct{}) (*AuthStateOutput, error) {
		n, err := a.q.CountUsers(ctx)
		if err != nil {
			return nil, internalError(err)
		}
		st, err := a.q.GetSettings(ctx)
		if err != nil {
			return nil, internalError(err)
		}
		out := &AuthStateOutput{}
		out.Body.NeedsSetup = n == 0
		out.Body.SetupTokenRequired = n == 0 && a.cfg.SetupToken != ""
		out.Body.RegistrationOpen = st.RegistrationOpen && n > 0
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "auth-setup", Method: http.MethodPost, Path: "/auth/setup",
		Summary: "Create the first admin", Tags: tags,
		Description: "Works only while no user exists.",
	}, func(ctx context.Context, in *AuthSetupInput) (*SignedInOutput, error) {
		key := "setup:" + clientOf(ctx).ip
		if a.over(ctx, key, 10) {
			return nil, errTooMany()
		}
		a.hit(ctx, key, time.Hour)

		setupDone := huma.Error409Conflict("This panel is already set up.")
		n, err := a.q.CountUsers(ctx)
		if err != nil {
			return nil, internalError(err)
		}
		if n > 0 {
			return nil, setupDone
		}
		if a.cfg.SetupToken != "" && !sameToken(a.cfg.SetupToken, in.Body.SetupToken) {
			return nil, fieldError("body.setup_token", "That setup token is wrong.", nil)
		}
		if err := in.Body.clean(); err != nil {
			return nil, err
		}
		hash, err := auth.HashPassword(in.Body.Password)
		if err != nil {
			return nil, internalError(err)
		}
		out := &SignedInOutput{}
		err = a.inTx(ctx, func(q *sqlc.Queries) error {
			// Two people submitting at once: the second finds a user here.
			if err := q.LockAuth(ctx); err != nil {
				return internalError(err)
			}
			n, err := q.CountUsers(ctx)
			if err != nil {
				return internalError(err)
			}
			if n > 0 {
				return setupDone
			}
			u, err := q.CreateUser(ctx, sqlc.CreateUserParams{
				Username: in.Body.Username, Email: in.Body.Email,
				FirstName: in.Body.FirstName, FullName: in.Body.FullName,
				PasswordHash: hash, Role: "admin", Status: "active",
			})
			if err != nil {
				return userConflict(err)
			}
			if out.SetCookie, err = a.startSession(ctx, q, u.ID, false); err != nil {
				return internalError(err)
			}
			out.Body = toPanelUser(u)
			return nil
		})
		if err != nil {
			return nil, err
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "auth-register", Method: http.MethodPost, Path: "/auth/register",
		Summary: "Sign up", Tags: tags,
		Description: "Only while an admin has registration open. The account can do nothing until approved.",
	}, func(ctx context.Context, in *AuthRegisterInput) (*SignedInOutput, error) {
		key := "register:" + clientOf(ctx).ip
		if a.over(ctx, key, 10) {
			return nil, errTooMany()
		}
		a.hit(ctx, key, time.Hour)

		st, err := a.q.GetSettings(ctx)
		if err != nil {
			return nil, internalError(err)
		}
		n, err := a.q.CountUsers(ctx)
		if err != nil {
			return nil, internalError(err)
		}
		if !st.RegistrationOpen || n == 0 {
			return nil, huma.Error403Forbidden("Registration is closed.")
		}
		if err := in.Body.clean(); err != nil {
			return nil, err
		}
		hash, err := auth.HashPassword(in.Body.Password)
		if err != nil {
			return nil, internalError(err)
		}
		out := &SignedInOutput{}
		err = a.inTx(ctx, func(q *sqlc.Queries) error {
			u, err := q.CreateUser(ctx, sqlc.CreateUserParams{
				Username: in.Body.Username, Email: in.Body.Email,
				FirstName: in.Body.FirstName, FullName: in.Body.FullName,
				PasswordHash: hash, Role: "member", Status: "pending",
			})
			if err != nil {
				return userConflict(err)
			}
			if out.SetCookie, err = a.startSession(ctx, q, u.ID, false); err != nil {
				return internalError(err)
			}
			out.Body = toPanelUser(u)
			return nil
		})
		if err != nil {
			return nil, err
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "auth-login", Method: http.MethodPost, Path: "/auth/login",
		Summary: "Sign in", Tags: tags,
	}, func(ctx context.Context, in *AuthLoginInput) (*SignedInOutput, error) {
		name := strings.ToLower(strings.TrimSpace(in.Body.Username))
		ip := clientOf(ctx).ip
		pair, byIP, byName := "login:pair:"+name+":"+ip, "login:ip:"+ip, "login:name:"+name
		if a.over(ctx, pair, 5) || a.over(ctx, byIP, 30) || a.over(ctx, byName, 30) {
			return nil, errTooMany()
		}
		// The same answer for an unknown name and a wrong password, after the
		// same amount of work, so a guess can't tell which it was.
		wrong := func() error {
			for _, k := range []string{pair, byIP, byName} {
				a.hit(ctx, k, 15*time.Minute)
			}
			return huma.Error401Unauthorized("Wrong username or password.")
		}
		u, err := a.q.GetUserByUsername(ctx, name)
		if isNotFound(err) {
			auth.BurnPassword(in.Body.Password)
			return nil, wrong()
		}
		if err != nil {
			return nil, internalError(err)
		}
		if !auth.VerifyPassword(u.PasswordHash, in.Body.Password) {
			return nil, wrong()
		}
		// Only someone who knows the password learns the account is blocked.
		if u.Status == "blocked" {
			return nil, huma.Error403Forbidden("This account is blocked. Ask an admin.")
		}
		a.forget(ctx, pair)
		if err := a.q.DeleteExpiredSessions(ctx); err != nil {
			slog.Warn("delete expired sessions", "error", err)
		}
		if err := a.q.TouchUserLogin(ctx, u.ID); err != nil {
			slog.Warn("touch login", "error", err)
		}
		out := &SignedInOutput{Body: toPanelUser(u)}
		if out.SetCookie, err = a.startSession(ctx, a.q, u.ID, in.Body.Remember); err != nil {
			return nil, internalError(err)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "auth-logout", Method: http.MethodPost, Path: "/auth/logout",
		Summary: "Sign out", Tags: tags,
	}, func(ctx context.Context, _ *struct{}) (*SignedOutOutput, error) {
		if err := a.q.DeleteSession(ctx, principalOf(ctx).SessionID); err != nil {
			return nil, internalError(err)
		}
		a.invalidate()
		return &SignedOutOutput{SetCookie: a.clearCookie()}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "auth-logout-all", Method: http.MethodPost, Path: "/auth/logout-all",
		Summary: "Sign out everywhere", Tags: tags,
		Description: "Ends every session of this user and closes their terminals.",
	}, func(ctx context.Context, _ *struct{}) (*SignedOutOutput, error) {
		p := principalOf(ctx)
		if err := a.q.DeleteUserSessions(ctx, p.User.ID); err != nil {
			return nil, internalError(err)
		}
		a.terms.KillOwner(p.User.ID.String())
		a.invalidate()
		return &SignedOutOutput{SetCookie: a.clearCookie()}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-me", Method: http.MethodGet, Path: "/auth/me",
		Summary: "The signed-in user", Tags: tags,
	}, func(ctx context.Context, _ *struct{}) (*MeOutput, error) {
		return &MeOutput{Body: toPanelUser(principalOf(ctx).User)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-me", Method: http.MethodPatch, Path: "/auth/me",
		Summary: "Edit your profile", Tags: tags,
	}, func(ctx context.Context, in *UpdateMeInput) (*MeOutput, error) {
		if err := in.Body.clean(); err != nil {
			return nil, err
		}
		u, err := a.q.UpdateUserProfile(ctx, sqlc.UpdateUserProfileParams{
			ID: principalOf(ctx).User.ID, Email: in.Body.Email,
			FirstName: in.Body.FirstName, FullName: in.Body.FullName,
		})
		if err != nil {
			return nil, userConflict(err)
		}
		return &MeOutput{Body: toPanelUser(u)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "change-password", Method: http.MethodPost, Path: "/auth/password",
		Summary: "Change your password", Tags: tags,
		Description: "Ends your other sessions and closes your terminals: if the old password leaked, whoever had it is out.",
	}, func(ctx context.Context, in *ChangePasswordInput) (*MeOutput, error) {
		p := principalOf(ctx)
		key := "password:" + p.User.ID.String()
		if a.over(ctx, key, 5) {
			return nil, errTooMany()
		}
		if !auth.VerifyPassword(p.User.PasswordHash, in.Body.CurrentPassword) {
			a.hit(ctx, key, 15*time.Minute)
			return nil, fieldError("body.current_password", "That isn't your current password.", nil)
		}
		if err := auth.CheckPassword(in.Body.NewPassword, p.User.Username); err != nil {
			return nil, fieldError("body.new_password", err.Error(), nil)
		}
		if in.Body.NewPassword == in.Body.CurrentPassword {
			return nil, fieldError("body.new_password", "Choose a different password.", nil)
		}
		hash, err := auth.HashPassword(in.Body.NewPassword)
		if err != nil {
			return nil, internalError(err)
		}
		var u sqlc.User
		err = a.inTx(ctx, func(q *sqlc.Queries) error {
			var err error
			u, err = q.SetUserPassword(ctx, sqlc.SetUserPasswordParams{ID: p.User.ID, PasswordHash: hash})
			if err != nil {
				return internalError(err)
			}
			if err := q.DeleteOtherUserSessions(ctx, sqlc.DeleteOtherUserSessionsParams{UserID: p.User.ID, Keep: p.SessionID}); err != nil {
				return internalError(err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		a.forget(ctx, key)
		a.terms.KillOwner(p.User.ID.String())
		a.invalidate()
		return &MeOutput{Body: toPanelUser(u)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-my-access", Method: http.MethodGet, Path: "/auth/access",
		Summary: "What the signed-in user can reach", Tags: tags,
	}, func(ctx context.Context, _ *struct{}) (*MyAccessOutput, error) {
		acc := principalOf(ctx).Access
		out := &MyAccessOutput{}
		out.Body = MyAccess{
			Admin: acc.Admin, CanCreate: acc.CanCreateAnywhere(),
			Workspaces: []WorkspaceAccess{}, Servers: []ResourceAccess{}, Storages: []ResourceAccess{}, Apps: []ResourceAccess{},
		}
		for id, w := range acc.Workspaces {
			out.Body.Workspaces = append(out.Body.Workspaces, WorkspaceAccess{ID: id.String(), Level: w.Level.String(), CanCreate: w.CanCreate})
		}
		for id, l := range acc.Servers {
			out.Body.Servers = append(out.Body.Servers, ResourceAccess{ID: id.String(), Level: l.String()})
		}
		for id, l := range acc.Storages {
			out.Body.Storages = append(out.Body.Storages, ResourceAccess{ID: id.String(), Level: l.String()})
		}
		for id, l := range acc.Apps {
			out.Body.Apps = append(out.Body.Apps, ResourceAccess{ID: id.String(), Level: l.String()})
		}
		return out, nil
	})
}
