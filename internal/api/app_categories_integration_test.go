package api

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func catPath(ws uuid.UUID) string { return "/workspaces/" + ws.String() + "/app-categories" }

func layoutPath(ws uuid.UUID) string { return "/workspaces/" + ws.String() + "/apps/layout" }

func addCategoryAPI(t *testing.T, c *tclient, ws uuid.UUID, name string) AppCategory {
	t.Helper()
	var cat AppCategory
	expect(t, c.do(t, http.MethodPost, catPath(ws), map[string]any{"name": name, "color": "teal"}, &ws), http.StatusCreated, &cat)
	return cat
}

type layoutGroup struct {
	CategoryID *string  `json:"category_id"`
	AppIDs     []string `json:"app_ids"`
}

func TestIntegrationAppLayoutNeedsWholeWorkspaceEngineer(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin, someone := e.user(t, "admin"), e.user(t, "member")
	a := addApp(t, admin, ws, map[string]any{"name": "Svc", "address": "svc.local"})
	id := uuid.MustParse(a.ID)
	e.grant(t, someone, "viewer", grantTarget{Workspace: &ws})
	e.grant(t, someone, "engineer", grantTarget{App: &id})

	expect(t, someone.do(t, http.MethodPost, catPath(ws), map[string]any{"name": "X", "color": "red"}, &ws), http.StatusForbidden, nil)
	layout := map[string]any{"categories": []string{}, "groups": []layoutGroup{{AppIDs: []string{a.ID}}}}
	expect(t, someone.do(t, http.MethodPut, layoutPath(ws), layout, &ws), http.StatusForbidden, nil)
}

func TestIntegrationAppLayoutCategoryNameUnique(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	addCategoryAPI(t, admin, ws, "Monitoring")
	expect422At(t, admin, http.MethodPost, catPath(ws), map[string]any{"name": "monitoring", "color": "red"}, ws, "body.name")

	other := addCategoryAPI(t, admin, ws, "Storage")
	expect422At(t, admin, http.MethodPatch, catPath(ws)+"/"+other.ID, map[string]any{"name": "MONITORING"}, ws, "body.name")
	var renamed AppCategory
	expect(t, admin.do(t, http.MethodPatch, catPath(ws)+"/"+other.ID, map[string]any{"name": "Files", "color": "amber"}, &ws), http.StatusOK, &renamed)
	if renamed.Name != "Files" || renamed.Color != "amber" {
		t.Fatalf("renamed = %+v", renamed)
	}
}

func TestIntegrationAppLayoutDeleteKeepsServices(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	cat := addCategoryAPI(t, admin, ws, "Gone")
	a := addApp(t, admin, ws, map[string]any{"name": "Svc", "address": "svc.local", "category_id": cat.ID})
	expect(t, admin.do(t, http.MethodDelete, catPath(ws)+"/"+cat.ID, nil, &ws), http.StatusNoContent, nil)
	var got App
	expect(t, admin.do(t, http.MethodGet, "/apps/"+a.ID, nil, &ws), http.StatusOK, &got)
	if got.CategoryID != nil {
		t.Fatalf("still in %s", *got.CategoryID)
	}
}

func TestIntegrationAppLayoutReorders(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	c1, c2 := addCategoryAPI(t, admin, ws, "One"), addCategoryAPI(t, admin, ws, "Two")
	a := addApp(t, admin, ws, map[string]any{"name": "A", "address": "a.local", "category_id": c1.ID})
	b := addApp(t, admin, ws, map[string]any{"name": "B", "address": "b.local", "category_id": c1.ID})
	c := addApp(t, admin, ws, map[string]any{"name": "C", "address": "c.local"})

	// Two first; B then C in it; A uncategorized.
	layout := map[string]any{
		"categories": []string{c2.ID, c1.ID},
		"groups": []layoutGroup{
			{CategoryID: &c2.ID, AppIDs: []string{b.ID, c.ID}},
			{CategoryID: nil, AppIDs: []string{a.ID}},
		},
	}
	var answer appList
	expect(t, admin.do(t, http.MethodPut, layoutPath(ws), layout, &ws), http.StatusOK, &answer)
	listed, _ := listApps(t, admin, ws, "")
	for _, got := range []appList{answer, listed} {
		if len(got.Categories) != 2 || got.Categories[0].ID != c2.ID || got.Categories[1].ID != c1.ID {
			t.Fatalf("categories = %+v", got.Categories)
		}
		order := []string{}
		for _, it := range got.Items {
			order = append(order, it.Name)
		}
		if len(order) != 3 || order[0] != "B" || order[1] != "C" || order[2] != "A" {
			t.Fatalf("order = %v", order)
		}
		if got.Items[2].CategoryID != nil || got.Items[0].CategoryID == nil || *got.Items[0].CategoryID != c2.ID {
			t.Fatalf("items = %+v", got.Items)
		}
	}
}

func TestIntegrationAppLayoutCannotTouchOtherWorkspace(t *testing.T) {
	e := newEnv(t)
	ws, other := e.workspace(t), e.workspace(t)
	admin := e.user(t, "admin")
	mine := addCategoryAPI(t, admin, ws, "Mine")
	foreignCat := addCategoryAPI(t, admin, other, "Theirs")
	foreignApp := addApp(t, admin, other, map[string]any{"name": "Theirs", "address": "t.local", "category_id": foreignCat.ID})
	local := addApp(t, admin, ws, map[string]any{"name": "Local", "address": "l.local"})

	layout := map[string]any{"categories": []string{mine.ID}, "groups": []layoutGroup{{CategoryID: &mine.ID, AppIDs: []string{foreignApp.ID, local.ID}}}}
	expect(t, admin.do(t, http.MethodPut, layoutPath(ws), layout, &ws), http.StatusOK, nil)
	var got App
	expect(t, admin.do(t, http.MethodGet, "/apps/"+foreignApp.ID, nil, &other), http.StatusOK, &got)
	if got.WorkspaceID != other.String() || got.CategoryID == nil || *got.CategoryID != foreignCat.ID {
		t.Fatalf("foreign app changed: %+v", got)
	}

	bad := map[string]any{"categories": []string{}, "groups": []layoutGroup{
		{CategoryID: nil, AppIDs: []string{local.ID}},
		{CategoryID: &foreignCat.ID, AppIDs: []string{}},
	}}
	expect422At(t, admin, http.MethodPut, layoutPath(ws), bad, ws, "body.groups[1].category_id")
	got = App{}
	expect(t, admin.do(t, http.MethodGet, "/apps/"+local.ID, nil, &ws), http.StatusOK, &got)
	if got.CategoryID == nil || *got.CategoryID != mine.ID {
		t.Fatalf("not rolled back: %+v", got)
	}
	foreignOrder := map[string]any{"categories": []string{foreignCat.ID}, "groups": []layoutGroup{}}
	expect422At(t, admin, http.MethodPut, layoutPath(ws), foreignOrder, ws, "body.categories[0]")
}

func TestIntegrationAppLayoutIgnoresDeleted(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	a := addApp(t, admin, ws, map[string]any{"name": "Gone", "address": "g.local"})
	b := addApp(t, admin, ws, map[string]any{"name": "Kept", "address": "k.local"})
	expect(t, admin.do(t, http.MethodDelete, "/apps/"+a.ID, nil, &ws), http.StatusNoContent, nil)
	layout := map[string]any{"categories": []string{}, "groups": []layoutGroup{{AppIDs: []string{b.ID, a.ID}}}}
	var answer appList
	expect(t, admin.do(t, http.MethodPut, layoutPath(ws), layout, &ws), http.StatusOK, &answer)
	if len(answer.Items) != 1 || answer.Items[0].ID != b.ID {
		t.Fatalf("items = %+v", answer.Items)
	}
}

func TestIntegrationAppLayoutCategoryPathChecksWorkspace(t *testing.T) {
	e := newEnv(t)
	w1, w2 := e.workspace(t), e.workspace(t)
	admin := e.user(t, "admin")
	cat := addCategoryAPI(t, admin, w2, "Elsewhere")
	expect(t, admin.do(t, http.MethodPatch, catPath(w1)+"/"+cat.ID, map[string]any{"name": "Hijack"}, &w1), http.StatusNotFound, nil)
	expect(t, admin.do(t, http.MethodDelete, catPath(w1)+"/"+cat.ID, nil, &w1), http.StatusNotFound, nil)
}
