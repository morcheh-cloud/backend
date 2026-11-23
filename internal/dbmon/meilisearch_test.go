package dbmon

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestMeiliSearches(t *testing.T) {
	raw := []byte(`# HELP meilisearch_http_requests_total x
meilisearch_http_requests_total{method="POST",path="/indexes/{index_uid}/search",status="200"} 12
meilisearch_http_requests_total{method="POST",path="/multi-search",status="200"} 3
meilisearch_http_requests_total{method="GET",path="/stats",status="200"} 99
meilisearch_db_size_bytes 1234
`)
	n, ok := meiliSearches(raw)
	if !ok || n != 15 {
		t.Fatalf("got %d %v, want 15", n, ok)
	}
	if _, ok := meiliSearches([]byte("nothing here")); ok {
		t.Fatal("found searches in nothing")
	}
}

func TestMeiliTaskText(t *testing.T) {
	idx := "movies"
	got := meiliTaskText(meiliTask{IndexUID: &idx, Type: "documentAdditionOrUpdate", Details: json.RawMessage(`{"receivedDocuments":1200,"indexedDocuments":null}`)})
	if got != "documentAdditionOrUpdate (1,200 documents received)" {
		t.Fatalf("got %q", got)
	}
	if got := meiliTaskText(meiliTask{Type: "dumpCreation"}); got != "dumpCreation" {
		t.Fatalf("got %q", got)
	}
}

// meiliLive is the compose service test-meilisearch, or a skip.
func meiliLive(t *testing.T) Config {
	t.Helper()
	c := http.Client{Timeout: 2 * time.Second}
	res, err := c.Get("http://127.0.0.1:7701/health")
	if err != nil {
		t.Skip("test-meilisearch isn't running (make up in the backend)")
	}
	res.Body.Close()
	return Config{Engine: Meili, Host: "127.0.0.1", Port: 7701, Password: "colony-master-key-2026", TLS: TLSDisable, Dial: DirectDialer(true)}
}

func TestMeiliLiveCollect(t *testing.T) {
	cfg := meiliLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// A wrong key is a refused login.
	bad := cfg
	bad.Password = "nope"
	if _, err := Open(ctx, bad); err == nil || !engineAuthError(err) {
		t.Fatalf("a wrong key should be refused as a login: %v", err)
	}

	c, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := c.Collect(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if s.Flavor != "Meilisearch" || s.Version == "" || s.Role != "standalone" {
		t.Errorf("flavor/version/role: %q %q %q", s.Flavor, s.Version, s.Role)
	}
	if s.Search == nil || s.Search.Status != "green" || s.Search.Documents == nil {
		t.Fatalf("search: %+v", s.Search)
	}
	if s.SizeBytes == nil || *s.SizeBytes == 0 {
		t.Error("no database size")
	}
	if len(s.Databases) == 0 || len(s.Tables) == 0 || s.Tables[0].Kind != "index" {
		t.Errorf("databases %v tables %v", s.Databases, s.Tables)
	}
	if len(s.Users) == 0 || s.Security.Admins == nil {
		t.Errorf("users: %v notes %v", s.Users, s.Notes)
	}
	raw, _ := json.Marshal(s)
	if strings.Contains(string(raw), cfg.Password) {
		t.Fatal("the key ended up in the snapshot")
	}
	if s.Security.AuthDisabled || s.Security.Encrypted == nil || *s.Security.Encrypted {
		t.Errorf("security: %+v", s.Security)
	}
	if len(s.Settings) == 0 {
		t.Errorf("no settings: %v", s.Notes)
	}
	// The second look has rates.
	s2, err := c.Collect(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Rates == nil || s2.Rates.Transactions == nil {
		t.Errorf("rates: %+v", s2.Rates)
	}
	checks := Evaluate(EvalInput{Engine: Meili, Snapshot: s2, Status: StatusOnline})
	var found int
	for _, ch := range checks {
		if ch.ID == "task_queue" || ch.ID == "failed_tasks" {
			found++
		}
	}
	if found != 2 {
		t.Errorf("checks: %+v", checks)
	}
	if err := c.Kill(ctx, "999999999", false); err == nil {
		t.Error("killing a task that doesn't exist should fail")
	}
	if _, err := c.Explain(ctx, "", "x"); err != ErrUnsupported {
		t.Errorf("explain: %v", err)
	}
	t.Logf("%s %s: %d indexes, %d documents, %d keys, notes %v", s.Flavor, s.Version, s.Search.Indexes, *s.Search.Documents, len(s.Users), s.Notes)
}
