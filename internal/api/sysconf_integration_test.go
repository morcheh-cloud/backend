package api

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/morche/backend/internal/database/sqlc"
)

func TestIntegrationConfigChangeHistory(t *testing.T) {
	e := newEnv(t)
	admin := e.user(t, "admin")
	outsider := e.user(t, "member")
	ws := e.workspace(t)
	var server uuid.UUID
	if err := e.db.QueryRow(t.Context(),
		`INSERT INTO servers (name, host, username, auth_method, workspace_id) VALUES ($1, '10.9.9.9', 'root', 'password', $2) RETURNING id`,
		"cfg-"+suffix(), ws).Scan(&server); err != nil {
		t.Fatal(err)
	}
	files := []byte(`[{"path":"/etc/hosts","before":"a\n","after":"b\n","existed":true,"exists":true,"cut":false}]`)
	id, err := e.q.AddConfigChange(t.Context(), sqlc.AddConfigChangeParams{
		ServerID: server, UserName: "Ann", Area: "network", Summary: "MTU 1450 on eth0", Status: "pending", Files: files,
	})
	if err != nil {
		t.Fatal(err)
	}
	base := "/servers/" + server.String() + "/config-changes"

	var list ConfigChanges
	expect(t, admin.do(t, http.MethodGet, base+"?area=network", nil, &ws), http.StatusOK, &list)
	if len(list.Items) != 1 || list.Items[0].Status != "pending" || list.Items[0].Files[0] != "/etc/hosts" || list.Items[0].User != "Ann" {
		t.Fatalf("%+v", list)
	}
	expect(t, admin.do(t, http.MethodGet, base+"?area=hosts", nil, &ws), http.StatusOK, &list)
	if len(list.Items) != 0 {
		t.Fatalf("other area leaked: %+v", list)
	}

	var detail ConfigChangeDetail
	expect(t, admin.do(t, http.MethodGet, base+"/"+id.String(), nil, &ws), http.StatusOK, &detail)
	if len(detail.Files) != 1 || detail.Files[0].Before != "a\n" || detail.Files[0].After != "b\n" {
		t.Fatalf("%+v", detail)
	}
	if w := outsider.do(t, http.MethodGet, base, nil, &ws); w.Code != http.StatusNotFound && w.Code != http.StatusForbidden {
		t.Fatalf("someone without access read the history: %d", w.Code)
	}

	if err := e.q.SettleConfigChanges(t.Context(), sqlc.SettleConfigChangesParams{ServerID: server, Area: "network", Status: "applied"}); err != nil {
		t.Fatal(err)
	}
	expect(t, admin.do(t, http.MethodGet, base, nil, &ws), http.StatusOK, &list)
	if list.Items[0].Status != "applied" {
		t.Fatalf("not settled: %+v", list.Items[0])
	}
}
