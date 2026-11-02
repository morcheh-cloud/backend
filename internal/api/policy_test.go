package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/cache"
	"github.com/morcheh/backend/internal/config"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
)

// testRouter builds the real router. The pool connects lazily and nothing here
// gets as far as the database, so no services are needed.
func testRouter(t *testing.T, env string) (*chi.Mux, huma.API) {
	t.Helper()
	db, err := pgxpool.New(context.Background(), "postgres://nobody@127.0.0.1:1/none")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	cfg := &config.Config{Env: env, CORSOrigins: []string{"http://localhost:3200"}}
	return build(cfg, db, &cache.Cache{}, nil, jobs.New(sqlc.New(db)))
}

type operation struct{ id, method, path string }

func operations(api huma.API) []operation {
	var out []operation
	for path, item := range api.OpenAPI().Paths {
		for method, op := range map[string]*huma.Operation{
			http.MethodGet: item.Get, http.MethodPost: item.Post, http.MethodPut: item.Put,
			http.MethodPatch: item.Patch, http.MethodDelete: item.Delete,
		} {
			if op != nil {
				out = append(out, operation{op.OperationID, method, path})
			}
		}
	}
	return out
}

// Handlers of these check the id themselves, against things other than a server,
// storage or workspace.
var checkedInside = []string{
	"get-job", "cancel-job", "retry-job", "delete-job",
	"update-folder", "delete-folder",
	"delete-grant",
}

func TestEveryOperationHasAPolicy(t *testing.T) {
	_, api := testRouter(t, "development")
	seen := map[string]bool{}
	for _, op := range operations(api) {
		seen[op.id] = true
		pol, ok := policies[op.id]
		if !ok {
			t.Errorf("%s %s (%s) has no policy", op.method, op.path, op.id)
			continue
		}
		hasID := strings.Contains(op.path, "{id}")
		switch pol.kind {
		case kindServer, kindStorage, kindWorkspace, kindDatabase:
			if !hasID {
				t.Errorf("%s checks the path's {id}, but %s has none", op.id, op.path)
			}
			if pol.level == auth.None {
				t.Errorf("%s has no level", op.id)
			}
		case kindActive, kindSession, kindPublic:
			if hasID && !slices.Contains(checkedInside, op.id) {
				t.Errorf("%s takes an {id} that nothing checks: give it a server, storage or workspace policy", op.id)
			}
		}
	}
	for id := range policies {
		if !seen[id] {
			t.Errorf("policy for %s, which doesn't exist", id)
		}
	}
}

// The only routes outside the API, and so outside its middleware.
func TestOnlyKnownRoutesSkipTheMiddleware(t *testing.T) {
	r, api := testRouter(t, "development")
	known := map[string]bool{}
	for _, op := range operations(api) {
		known[op.method+" "+op.path] = true
	}
	err := chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		switch {
		case known[method+" "+route],
			route == "/servers/{id}/terminals/connect",
			route == "/docs",
			strings.HasPrefix(route, "/openapi"),
			strings.HasPrefix(route, "/schemas/"):
			return nil
		}
		t.Errorf("%s %s isn't in the API, so nothing guards it", method, route)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignedOutRequestsAreRefused(t *testing.T) {
	r, api := testRouter(t, "development")
	id := uuid.NewString()
	for _, op := range operations(api) {
		if policies[op.id].kind == kindPublic {
			continue
		}
		path := strings.NewReplacer("{id}", id, "{session}", "x", "{unit}", "x", "{jail}", "x", "{name}", "x").Replace(op.path)
		req := httptest.NewRequest(op.method, path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s answered %d without a session", op.method, op.path, rec.Code)
		}
	}
}

func TestProductionHidesTheDocs(t *testing.T) {
	r, _ := testRouter(t, "production")
	for _, path := range []string{"/docs", "/openapi.json", "/openapi.yaml", "/schemas/Server.json"} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s answered %d in production", path, rec.Code)
		}
	}
}

func TestOriginGuard(t *testing.T) {
	h := originGuard([]string{"https://panel.example.com"})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for _, c := range []struct {
		method, origin string
		want           int
	}{
		{http.MethodPost, "https://panel.example.com", http.StatusOK},
		{http.MethodPost, "https://evil.example.com", http.StatusForbidden},
		{http.MethodDelete, "https://evil.example.com", http.StatusForbidden},
		{http.MethodPost, "", http.StatusOK},
		{http.MethodGet, "https://evil.example.com", http.StatusOK},
		// Same origin, wherever the panel is served from.
		{http.MethodPost, "http://api.test", http.StatusOK},
	} {
		req := httptest.NewRequest(c.method, "http://api.test/x", nil)
		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s from %q: %d, want %d", c.method, c.origin, rec.Code, c.want)
		}
	}
}

func TestPruneFolders(t *testing.T) {
	full, partial := uuid.New(), uuid.New()
	root, leaf, empty, own := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	rows := []sqlc.ListFoldersRow{
		{ID: root, WorkspaceID: partial, Name: "root"},
		{ID: leaf, WorkspaceID: partial, ParentID: &root, Name: "leaf", ServerCount: 1},
		{ID: empty, WorkspaceID: partial, ParentID: &root, Name: "empty"},
		{ID: own, WorkspaceID: full, Name: "own"},
	}
	acc := &auth.Access{Workspaces: map[uuid.UUID]auth.WorkspaceGrant{full: {Level: auth.Viewer}}}
	var got []string
	for _, r := range pruneFolders(acc, rows) {
		got = append(got, r.Name)
	}
	if want := []string{"root", "leaf", "own"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if n := len(pruneFolders(&auth.Access{Admin: true}, rows)); n != 4 {
		t.Errorf("an admin sees %d folders", n)
	}
}
