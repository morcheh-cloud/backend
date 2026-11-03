package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/cache"
	"github.com/morcheh/backend/internal/config"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/secrets"
)

// env is the real router over a real database, for tests named Integration*
// (`make test-integration`). Each test makes its own workspaces and people
// with random names and cleans nothing up.
type env struct {
	db  *pgxpool.Pool
	q   *sqlc.Queries
	box *secrets.Box
	h   http.Handler
}

func newEnv(t *testing.T) *env {
	t.Helper()
	url := os.Getenv("MORCHEH_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("MORCHEH_TEST_DATABASE_URL not set; run make test-integration")
	}
	db, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	box, err := secrets.New(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Env: "test", CORSOrigins: []string{"http://localhost:3200"}}
	r, _ := build(cfg, db, &cache.Cache{}, box, jobs.New(sqlc.New(db)))
	return &env{db: db, q: sqlc.New(db), box: box, h: r}
}

func suffix() string { return uuid.NewString()[:8] }

// tclient is one signed-in person. (client is taken by the request origin.)
type tclient struct {
	e     *env
	user  sqlc.User
	token string
}

// user makes an active person with a session; role is "admin" or "member".
func (e *env) user(t *testing.T, role string) *tclient {
	t.Helper()
	ctx := context.Background()
	s := suffix()
	u, err := e.q.CreateUser(ctx, sqlc.CreateUserParams{
		Username: "u" + s, Email: s + "@test.local", FirstName: "Test", FullName: "Test " + s,
		PasswordHash: "unused", Role: role, Status: "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	token, hash, err := auth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.q.CreateSession(ctx, sqlc.CreateSessionParams{
		UserID: u.ID, TokenHash: hash, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return &tclient{e: e, user: u, token: token}
}

func (e *env) workspace(t *testing.T) uuid.UUID {
	t.Helper()
	w, err := e.q.CreateWorkspace(context.Background(), sqlc.CreateWorkspaceParams{Name: "ws-" + suffix()})
	if err != nil {
		t.Fatal(err)
	}
	return w.ID
}

// grantTarget is what a grant is on: one of them.
type grantTarget struct {
	Workspace, App *uuid.UUID
	// CanCreate lets them add services to the workspace.
	CanCreate bool
}

func (e *env) grant(t *testing.T, c *tclient, level string, target grantTarget) {
	t.Helper()
	if _, err := e.q.UpsertGrant(context.Background(), sqlc.UpsertGrantParams{
		UserID: &c.user.ID, WorkspaceID: target.Workspace, AppID: target.App,
		Level: level, CanCreate: target.CanCreate,
	}); err != nil {
		t.Fatal(err)
	}
}

// do sends one request as this person, in the given open workspace (or none).
func (c *tclient) do(t *testing.T, method, path string, body any, workspace *uuid.UUID) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = httptest.NewRequest(method, path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	return c.send(t, r, workspace)
}

// raw sends bytes as they are, with the given Content-Type.
func (c *tclient) raw(t *testing.T, method, path, contentType string, data []byte, workspace *uuid.UUID) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewReader(data))
	r.Header.Set("Content-Type", contentType)
	return c.send(t, r, workspace)
}

func (c *tclient) send(t *testing.T, r *http.Request, workspace *uuid.UUID) *httptest.ResponseRecorder {
	t.Helper()
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.token})
	if workspace != nil {
		r.Header.Set(workspaceHeader, workspace.String())
	}
	w := httptest.NewRecorder()
	c.e.h.ServeHTTP(w, r)
	return w
}

// expect fails unless the response has the status, and decodes the body into
// out when given.
func expect(t *testing.T, w *httptest.ResponseRecorder, status int, out any) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status %d, want %d: %s", w.Code, status, w.Body.String())
	}
	if out != nil {
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			t.Fatalf("decode %s: %v", w.Body.String(), err)
		}
	}
}
