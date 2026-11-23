package dbmon

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestElasticWatermarkRatio(t *testing.T) {
	cases := map[string]*float64{
		"90%":   f64(0.9),
		"95.5%": f64(0.955),
		"0.85":  f64(0.85),
		"10gb":  nil,
		"500mb": nil,
		"":      nil,
		"150%":  nil,
	}
	for in, want := range cases {
		got := WatermarkRatio(in)
		switch {
		case want == nil && got != nil:
			t.Errorf("%q: got %v, want nil", in, *got)
		case want != nil && (got == nil || *got-*want > 1e-9 || *want-*got > 1e-9):
			t.Errorf("%q: got %v, want %v", in, got, *want)
		}
	}
}

func TestElasticQueryBody(t *testing.T) {
	b, err := ElasticQueryBody(`{"match": {"name": "apple"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b["query"].(map[string]any)["match"]; !ok {
		t.Errorf("bare query not wrapped: %v", b)
	}
	b, _ = ElasticQueryBody(`{"query": {"term": {"a": 1}}, "size": 0}`)
	if b["size"] == nil {
		t.Errorf("whole body changed: %v", b)
	}
	b, _ = ElasticQueryBody(`{"aggs": {"x": {"terms": {"field": "a"}}}}`)
	if _, ok := b["query"]; ok {
		t.Errorf("a body without query got one: %v", b)
	}
	b, _ = ElasticQueryBody(`status:active AND price:>10`)
	if qs := b["query"].(map[string]any)["query_string"]; qs == nil {
		t.Errorf("text not a query_string: %v", b)
	}
	if _, err := ElasticQueryBody(`{"broken"`); err == nil {
		t.Error("bad JSON accepted")
	}
}

func TestElasticSessions(t *testing.T) {
	tasks := []elasticTask{
		{Node: "n1", ID: 1, Action: "indices:data/read/search", Description: "indices[shop], search_type[QUERY_THEN_FETCH]", RunningNs: 3e9},
		{Node: "n1", ID: 2, Action: "indices:data/read/search[phase/query]", RunningNs: 2e9, Parent: "n1:1"},
		{Node: "n2", ID: 7, Action: "indices:data/write/reindex", Description: "reindex from [a] to [b]", RunningNs: 9e9},
	}
	s := elasticSessions(tasks)
	if len(s) != 2 {
		t.Fatalf("want 2 sessions (child left out), got %d", len(s))
	}
	if s[0].ID != "n2:7" || *s[0].Seconds != 9 {
		t.Errorf("longest first: %+v", s[0])
	}
}

func TestElasticIndexName(t *testing.T) {
	for _, ok := range []string{"shop", "shop-2026.11", "logs_a+b"} {
		if err := CheckElasticIndexName(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", ".", "..", "Shop", "-x", "_x", "+x", "a b", "a/b", "a*", "a,b", "a#b", "a:b", string(make([]byte, 256))} {
		if CheckElasticIndexName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCleanElasticSettings(t *testing.T) {
	s := map[string]any{
		"uuid": "x", "creation_date": "1", "provided_name": "a", "number_of_shards": "1",
		"version":  map[string]any{"created": "8"},
		"routing":  map[string]any{"allocation": map[string]any{"initial_recovery": map[string]any{"_id": "x"}, "include": map[string]any{"_tier_preference": "data_content"}}},
		"resize":   map[string]any{"source": map[string]any{"name": "b"}},
		"analysis": map[string]any{"analyzer": map[string]any{}},
	}
	CleanElasticSettings(s)
	for _, k := range []string{"uuid", "creation_date", "provided_name", "version", "resize"} {
		if _, ok := s[k]; ok {
			t.Errorf("%s kept", k)
		}
	}
	r := s["routing"].(map[string]any)["allocation"].(map[string]any)
	if _, ok := r["initial_recovery"]; ok {
		t.Error("initial_recovery kept")
	}
	if _, ok := r["include"]; !ok || s["number_of_shards"] != "1" || s["analysis"] == nil {
		t.Errorf("too much dropped: %v", s)
	}
}

// liveElastic is the compose service test-elasticsearch; tests using it skip
// when it isn't running.
func liveElastic(t *testing.T) Config {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:9201", time.Second)
	if err != nil {
		t.Skip("test-elasticsearch isn't running (make up)")
	}
	c.Close()
	return Config{Engine: Elastic, Host: "127.0.0.1", Port: 9201, Username: "elastic", Password: "colony", TLS: TLSDisable, Dial: DirectDialer(true)}
}

func TestElasticLive(t *testing.T) {
	cfg := liveElastic(t)
	ctx := context.Background()
	c, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := c.Collect(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if s.Flavor != "Elasticsearch" || s.Version == "" {
		t.Errorf("flavor/version: %q %q", s.Flavor, s.Version)
	}
	x := s.Search
	if x == nil || x.Status == "" || x.Nodes < 1 || x.HeapRatio == nil || x.DiskRatio == nil {
		t.Fatalf("search part: %+v", x)
	}
	if x.Documents == nil || x.Indexes == 0 {
		t.Errorf("documents/indexes missing on the first look: %+v", x)
	}
	if s.Memory == nil || s.Disk == nil || s.StartedAt == nil || s.Connections.Total < 1 {
		t.Errorf("memory %v disk %v started %v connections %d", s.Memory, s.Disk, s.StartedAt, s.Connections.Total)
	}
	for _, d := range s.Databases {
		if ElasticSystemIndex(d.Name) {
			t.Errorf("system index listed: %s", d.Name)
		}
	}
	if len(s.Databases) == 0 || len(s.Tables) == 0 || len(s.Settings) == 0 || len(s.Users) == 0 {
		t.Errorf("heavy parts: dbs %d tables %d settings %d users %d notes %v", len(s.Databases), len(s.Tables), len(s.Settings), len(s.Users), s.Notes)
	}
	admin := false
	for _, u := range s.Users {
		admin = admin || (u.Name == "elastic" && u.Admin)
	}
	if !admin {
		t.Errorf("elastic isn't an admin: %+v", s.Users)
	}
	if s.Role != "standalone" {
		t.Errorf("role %q", s.Role)
	}
	for _, n := range s.Notes {
		t.Logf("note: %s: %s", n.Area, n.Message)
	}
	s2, err := c.Collect(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Rates == nil || s2.Rates.Queries == nil {
		t.Errorf("rates: %+v", s2.Rates)
	}
	if s2.Search.Documents == nil {
		t.Error("light look lost the documents")
	}
	checks := Evaluate(EvalInput{Engine: Elastic, Snapshot: s2, Status: StatusOnline})
	found := map[string]bool{}
	for _, ch := range checks {
		found[ch.ID] = true
	}
	for _, id := range []string{"cluster_health", "shards", "heap", "watermark"} {
		if !found[id] {
			t.Errorf("check %s missing", id)
		}
	}
	plan, err := c.Explain(ctx, "shop-products", `{"query": {"wildcard": {"sku": "*01"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Plan == "" {
		t.Error("empty plan")
	}
	t.Logf("plan: %s %v", plan.Plan, plan.Warnings)
	if _, err := c.Explain(ctx, "shop-products", `name:apple AND stock:>3`); err != nil {
		t.Error(err)
	}
	if err := c.Kill(ctx, "nosuchnode:1", false); err == nil {
		t.Error("killing a missing task worked")
	}
}
