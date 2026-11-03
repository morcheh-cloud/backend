package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type appList struct {
	Items      []App         `json:"items"`
	Categories []AppCategory `json:"categories"`
}

type problemBody struct {
	Errors []struct {
		Location string `json:"location"`
	} `json:"errors"`
}

// addApp creates a service as c in ws and answers it.
func addApp(t *testing.T, c *tclient, ws uuid.UUID, body map[string]any) App {
	t.Helper()
	var a App
	expect(t, c.do(t, http.MethodPost, "/apps", body, &ws), http.StatusCreated, &a)
	return a
}

// addCategory puts a category straight in the database (its API is another
// task's).
func addCategory(t *testing.T, e *env, ws uuid.UUID, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := e.db.QueryRow(t.Context(),
		`INSERT INTO app_categories (workspace_id, name, color) VALUES ($1, $2, 'blue') RETURNING id`,
		ws, name).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func listApps(t *testing.T, c *tclient, ws uuid.UUID, q string) (appList, string) {
	t.Helper()
	w := c.do(t, http.MethodGet, "/apps?q="+url.QueryEscape(q), nil, &ws)
	var out appList
	expect(t, w, http.StatusOK, &out)
	return out, w.Body.String()
}

func expect422At(t *testing.T, c *tclient, method, path string, body any, ws uuid.UUID, location string) {
	t.Helper()
	var p problemBody
	expect(t, c.do(t, method, path, body, &ws), http.StatusUnprocessableEntity, &p)
	for _, e := range p.Errors {
		if e.Location == location {
			return
		}
	}
	t.Fatalf("422 without %s: %+v", location, p)
}

func TestIntegrationAppsViewerSeesNoCredentials(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin, viewer := e.user(t, "admin"), e.user(t, "member")
	e.grant(t, viewer, "viewer", grantTarget{Workspace: &ws})
	addApp(t, admin, ws, map[string]any{
		"name": "Portainer", "address": "portainer.acme.ir",
		"accounts": []map[string]any{{"username": "ops-root-user", "password": "s3cret-pass"}},
	})
	got, raw := listApps(t, viewer, ws, "")
	if len(got.Items) != 1 || got.Items[0].Address != "https://portainer.acme.ir" {
		t.Fatalf("items = %+v", got.Items)
	}
	if len(got.Items[0].Accounts) != 0 || strings.Contains(raw, "ops-root-user") {
		t.Fatalf("viewer sees accounts: %s", raw)
	}
}

func TestIntegrationAppsQDoesNotMatchUsername(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin, viewer := e.user(t, "admin"), e.user(t, "member")
	e.grant(t, viewer, "viewer", grantTarget{Workspace: &ws})
	addApp(t, admin, ws, map[string]any{
		"name": "Grafana", "address": "grafana.local",
		"accounts": []map[string]any{{"username": "hiddenname"}},
	})
	if got, _ := listApps(t, viewer, ws, "hiddenname"); len(got.Items) != 0 {
		t.Fatalf("q matched a username: %+v", got.Items)
	}
	if got, _ := listApps(t, viewer, ws, "graf"); len(got.Items) != 1 {
		t.Fatalf("q by name = %d items", len(got.Items))
	}
}

func TestIntegrationAppsListNeverHasPassword(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	a := addApp(t, admin, ws, map[string]any{
		"name": "MinIO", "address": "minio.acme.ir",
		"accounts": []map[string]any{{"username": "minio", "password": "very-secret-123"}},
	})
	_, raw := listApps(t, admin, ws, "")
	w := admin.do(t, http.MethodGet, "/apps/"+a.ID, nil, &ws)
	expect(t, w, http.StatusOK, nil)
	for _, body := range []string{raw, w.Body.String()} {
		if strings.Contains(body, "very-secret-123") || !strings.Contains(body, `"has_password":true`) {
			t.Fatalf("body = %s", body)
		}
	}
}

func TestIntegrationAppsPerServiceVisibility(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin, viewer := e.user(t, "admin"), e.user(t, "member")
	c1, c2 := addCategory(t, e, ws, "One"), addCategory(t, e, ws, "Two")
	app1 := addApp(t, admin, ws, map[string]any{"name": "First", "address": "first.local", "category_id": c1.String()})
	app2 := addApp(t, admin, ws, map[string]any{"name": "Second", "address": "second.local", "category_id": c2.String()})
	id1 := uuid.MustParse(app1.ID)
	e.grant(t, viewer, "viewer", grantTarget{App: &id1})

	got, _ := listApps(t, viewer, ws, "")
	if len(got.Items) != 1 || got.Items[0].ID != app1.ID {
		t.Fatalf("items = %+v", got.Items)
	}
	if len(got.Categories) != 1 || got.Categories[0].ID != c1.String() {
		t.Fatalf("categories = %+v", got.Categories)
	}
	expect(t, viewer.do(t, http.MethodGet, "/apps/"+app2.ID, nil, &ws), http.StatusNotFound, nil)
}

func TestIntegrationAppsCreateMakesOwner(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	maker, viewer := e.user(t, "member"), e.user(t, "member")
	e.grant(t, maker, "viewer", grantTarget{Workspace: &ws, CanCreate: true})
	e.grant(t, viewer, "viewer", grantTarget{Workspace: &ws})

	a := addApp(t, maker, ws, map[string]any{"name": "Mine", "address": "mine.local"})
	expect(t, maker.do(t, http.MethodDelete, "/apps/"+a.ID, nil, &ws), http.StatusNoContent, nil)
	body := map[string]any{"name": "Nope", "address": "nope.local"}
	expect(t, viewer.do(t, http.MethodPost, "/apps", body, &ws), http.StatusForbidden, nil)
}

func TestIntegrationAppsLevelsEnforced(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	a := addApp(t, admin, ws, map[string]any{"name": "Svc", "address": "svc.local"})
	people := map[string]*tclient{}
	for _, l := range []string{"operator", "engineer", "owner"} {
		people[l] = e.user(t, "member")
		e.grant(t, people[l], l, grantTarget{Workspace: &ws})
	}
	patch := map[string]any{"note": "changed"}
	expect(t, people["operator"].do(t, http.MethodPatch, "/apps/"+a.ID, patch, &ws), http.StatusForbidden, nil)
	expect(t, people["engineer"].do(t, http.MethodPatch, "/apps/"+a.ID, patch, &ws), http.StatusOK, nil)
	expect(t, people["engineer"].do(t, http.MethodDelete, "/apps/"+a.ID, nil, &ws), http.StatusForbidden, nil)
	expect(t, people["owner"].do(t, http.MethodDelete, "/apps/"+a.ID, nil, &ws), http.StatusNoContent, nil)
}

func TestIntegrationAppsRejectsBadAddress(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	bad := map[string]any{"name": "Evil", "address": "javascript:alert(1)"}
	expect422At(t, admin, http.MethodPost, "/apps", bad, ws, "body.address")
	a := addApp(t, admin, ws, map[string]any{"name": "Good", "address": "good.local"})
	expect422At(t, admin, http.MethodPatch, "/apps/"+a.ID, map[string]any{"address": "javascript:alert(1)"}, ws, "body.address")
}

func TestIntegrationAppsAccountsReplace(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	a := addApp(t, admin, ws, map[string]any{
		"name": "Svc", "address": "svc.local",
		"accounts": []map[string]any{
			{"label": "keep", "username": "kept", "password": "kept-pass"},
			{"label": "drop", "username": "dropped"},
		},
	})
	keep := a.Accounts[0].ID

	var got App
	expect(t, admin.do(t, http.MethodPatch, "/apps/"+a.ID, map[string]any{"accounts": []map[string]any{
		{"id": keep, "label": "x", "username": "kept"},
		{"username": "new", "password": "p"},
	}}, &ws), http.StatusOK, &got)
	if len(got.Accounts) != 2 {
		t.Fatalf("accounts = %+v", got.Accounts)
	}
	if first := got.Accounts[0]; first.ID != keep || first.Label != "x" || !first.HasPassword {
		t.Fatalf("kept account = %+v", first)
	}
	if second := got.Accounts[1]; second.Username != "new" || !second.HasPassword {
		t.Fatalf("new account = %+v", second)
	}

	unknown := map[string]any{"accounts": []map[string]any{{"id": uuid.NewString(), "username": "x"}}}
	expect422At(t, admin, http.MethodPatch, "/apps/"+a.ID, unknown, ws, "body.accounts[0].id")
	empty := map[string]any{"accounts": []map[string]any{{"label": ""}}}
	expect(t, admin.do(t, http.MethodPatch, "/apps/"+a.ID, empty, &ws), http.StatusUnprocessableEntity, nil)

	expect(t, admin.do(t, http.MethodPatch, "/apps/"+a.ID, map[string]any{"accounts": []map[string]any{
		{"id": keep, "label": "x", "username": "kept", "remove_password": true},
	}}, &ws), http.StatusOK, &got)
	if len(got.Accounts) != 1 || got.Accounts[0].HasPassword {
		t.Fatalf("after remove_password = %+v", got.Accounts)
	}
}

func TestIntegrationAppsCategoryMustBeInWorkspace(t *testing.T) {
	e := newEnv(t)
	ws, other := e.workspace(t), e.workspace(t)
	admin := e.user(t, "admin")
	foreign := addCategory(t, e, other, "Elsewhere")
	mine := addCategory(t, e, ws, "Mine")
	body := map[string]any{"name": "Svc", "address": "svc.local", "category_id": foreign.String()}
	expect422At(t, admin, http.MethodPost, "/apps", body, ws, "body.category_id")

	first := addApp(t, admin, ws, map[string]any{"name": "A", "address": "a.local", "category_id": mine.String()})
	second := addApp(t, admin, ws, map[string]any{"name": "B", "address": "b.local"})
	var got App
	expect(t, admin.do(t, http.MethodPatch, "/apps/"+second.ID, map[string]any{"category_id": mine.String()}, &ws), http.StatusOK, &got)
	if got.CategoryID == nil || *got.CategoryID != mine.String() || got.Position <= first.Position {
		t.Fatalf("moved = %+v (first at %d)", got, first.Position)
	}
	got = App{}
	expect(t, admin.do(t, http.MethodPatch, "/apps/"+second.ID, map[string]any{"category_id": ""}, &ws), http.StatusOK, &got)
	if got.CategoryID != nil {
		t.Fatalf("still in %s", *got.CategoryID)
	}
	expect422At(t, admin, http.MethodPatch, "/apps/"+second.ID, map[string]any{"category_id": foreign.String()}, ws, "body.category_id")
}

func TestIntegrationAppsWorkspaceDeleteAndMove(t *testing.T) {
	e := newEnv(t)
	ws, dest := e.workspace(t), e.workspace(t)
	admin := e.user(t, "admin")
	cat := addCategory(t, e, ws, "Cat")
	a := addApp(t, admin, ws, map[string]any{"name": "Svc", "address": "svc.local", "category_id": cat.String()})

	expect(t, admin.do(t, http.MethodDelete, "/workspaces/"+ws.String(), nil, nil), http.StatusConflict, nil)
	expect(t, admin.do(t, http.MethodPost, fmt.Sprintf("/workspaces/%s/assign", dest), map[string]any{"app_ids": []string{a.ID}}, nil), http.StatusNoContent, nil)
	var got App
	expect(t, admin.do(t, http.MethodGet, "/apps/"+a.ID, nil, &dest), http.StatusOK, &got)
	if got.WorkspaceID != dest.String() || got.CategoryID != nil {
		t.Fatalf("after move = %+v", got)
	}
	expect(t, admin.do(t, http.MethodDelete, "/workspaces/"+ws.String(), nil, nil), http.StatusNoContent, nil)
}
