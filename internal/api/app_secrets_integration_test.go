package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

type revealed struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type activityRow struct {
	ID           string    `json:"id"`
	AccountLabel string    `json:"account_label"`
	UserName     string    `json:"user_name"`
	IP           string    `json:"ip"`
	CreatedAt    time.Time `json:"created_at"`
}

type activityList struct {
	Items []activityRow `json:"items"`
}

func revealPath(app App, account string) string {
	return "/apps/" + app.ID + "/accounts/" + account + "/reveal"
}

// secretApp adds a service with one account that has a password and one
// that doesn't.
func secretApp(t *testing.T, c *tclient, ws uuid.UUID) App {
	t.Helper()
	return addApp(t, c, ws, map[string]any{"name": "Vault", "address": "vault.local", "accounts": []map[string]any{
		{"label": "Admin", "username": "root", "password": "s3cret"},
		{"label": "", "username": "guest"},
	}})
}

func activity(t *testing.T, c *tclient, app App, ws uuid.UUID) []activityRow {
	t.Helper()
	var out activityList
	expect(t, c.do(t, http.MethodGet, "/apps/"+app.ID+"/activity", nil, &ws), http.StatusOK, &out)
	return out.Items
}

func TestIntegrationRevealByLevel(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin, viewer, stranger, operator := e.user(t, "admin"), e.user(t, "member"), e.user(t, "member"), e.user(t, "member")
	a := secretApp(t, admin, ws)
	id := uuid.MustParse(a.ID)
	e.grant(t, viewer, "viewer", grantTarget{App: &id})
	e.grant(t, operator, "operator", grantTarget{App: &id})

	path := revealPath(a, a.Accounts[0].ID)
	expect(t, viewer.do(t, http.MethodPost, path, nil, &ws), http.StatusForbidden, nil)
	expect(t, stranger.do(t, http.MethodPost, path, nil, &ws), http.StatusNotFound, nil)
	var got revealed
	expect(t, operator.do(t, http.MethodPost, path, nil, &ws), http.StatusOK, &got)
	if got.Username != "root" || got.Password != "s3cret" {
		t.Fatalf("got %+v", got)
	}
}

func TestIntegrationRevealNoStore(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	a := secretApp(t, admin, ws)
	w := admin.do(t, http.MethodPost, revealPath(a, a.Accounts[0].ID), nil, &ws)
	expect(t, w, http.StatusOK, nil)
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}
}

func TestIntegrationRevealLogsEveryCall(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	a := secretApp(t, admin, ws)
	for range 2 {
		expect(t, admin.do(t, http.MethodPost, revealPath(a, a.Accounts[0].ID), nil, &ws), http.StatusOK, nil)
	}
	rows := activity(t, admin, a, ws)
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	for _, r := range rows {
		if r.UserName != admin.user.FullName || r.AccountLabel != "Admin" || r.IP == "" || r.ID == "" {
			t.Fatalf("row = %+v", r)
		}
	}
}

func TestIntegrationRevealRefusedLeavesNoLog(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin, viewer := e.user(t, "admin"), e.user(t, "member")
	a := secretApp(t, admin, ws)
	id := uuid.MustParse(a.ID)
	e.grant(t, viewer, "viewer", grantTarget{App: &id})
	expect(t, viewer.do(t, http.MethodPost, revealPath(a, a.Accounts[0].ID), nil, &ws), http.StatusForbidden, nil)
	if rows := activity(t, admin, a, ws); len(rows) != 0 {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestIntegrationRevealCrossAppAccount404(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	a, b := secretApp(t, admin, ws), secretApp(t, admin, ws)
	expect(t, admin.do(t, http.MethodPost, revealPath(a, b.Accounts[0].ID), nil, &ws), http.StatusNotFound, nil)
	for _, app := range []App{a, b} {
		if rows := activity(t, admin, app, ws); len(rows) != 0 {
			t.Fatalf("rows = %+v", rows)
		}
	}
}

func TestIntegrationRevealNoPassword422(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	a := secretApp(t, admin, ws)
	expect(t, admin.do(t, http.MethodPost, revealPath(a, a.Accounts[1].ID), nil, &ws), http.StatusUnprocessableEntity, nil)
	if rows := activity(t, admin, a, ws); len(rows) != 0 {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestIntegrationRevealActivityOwnerOnly(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin, engineer, owner := e.user(t, "admin"), e.user(t, "member"), e.user(t, "member")
	a := secretApp(t, admin, ws)
	id := uuid.MustParse(a.ID)
	e.grant(t, engineer, "engineer", grantTarget{App: &id})
	e.grant(t, owner, "owner", grantTarget{App: &id})
	expect(t, engineer.do(t, http.MethodGet, "/apps/"+a.ID+"/activity", nil, &ws), http.StatusForbidden, nil)
	activity(t, owner, a, ws)
}

func TestIntegrationRevealSnapshotSurvivesAccountRemoval(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	a := secretApp(t, admin, ws)
	// The unlabelled account is logged under its username.
	expect(t, admin.do(t, http.MethodPatch, "/apps/"+a.ID, map[string]any{"accounts": []map[string]any{
		{"id": a.Accounts[1].ID, "label": "", "username": "guest", "password": "pw"},
	}}, &ws), http.StatusOK, nil)
	expect(t, admin.do(t, http.MethodPost, revealPath(a, a.Accounts[1].ID), nil, &ws), http.StatusOK, nil)
	expect(t, admin.do(t, http.MethodPatch, "/apps/"+a.ID, map[string]any{"accounts": []any{}}, &ws), http.StatusOK, nil)
	rows := activity(t, admin, a, ws)
	if len(rows) != 1 || rows[0].AccountLabel != "guest" {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestIntegrationRevealDeletedWithService(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	a := secretApp(t, admin, ws)
	expect(t, admin.do(t, http.MethodPost, revealPath(a, a.Accounts[0].ID), nil, &ws), http.StatusOK, nil)
	expect(t, admin.do(t, http.MethodDelete, "/apps/"+a.ID, nil, &ws), http.StatusNoContent, nil)
	var n int
	if err := e.db.QueryRow(context.Background(), "SELECT count(*) FROM app_secret_views WHERE app_id = $1", uuid.MustParse(a.ID)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d rows left", n)
	}
}
