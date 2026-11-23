package dbbackup

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/morche/backend/internal/dbmon"
)

func TestElasticLoadChecksFirst(t *testing.T) {
	ctx := context.Background()
	// A bad name or someone else's file is refused before any request (the
	// client is nil here).
	if err := elasticLoad(ctx, nil, "Bad Name", RestoreOptions{Format: ElasticNDJSON}, strings.NewReader("")); err == nil {
		t.Error("bad name accepted")
	}
	var buf bytes.Buffer
	w, _ := NewNativeWriter(&buf, NativeHeader{Morche: MeiliNDJSON, Engine: dbmon.Meili})
	_ = w.Close()
	if err := elasticLoad(ctx, nil, "ok", RestoreOptions{Format: ElasticNDJSON}, &buf); err == nil || !strings.Contains(err.Error(), "isn't an Elasticsearch export") {
		t.Errorf("meili file: %v", err)
	}
	if err := elasticLoad(ctx, nil, "ok", RestoreOptions{Format: ElasticNDJSON}, strings.NewReader("not json")); err == nil {
		t.Error("garbage accepted")
	}
}

func liveElastic(t *testing.T) (dbmon.Config, *dbmon.HTTPDB) {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:9201", time.Second)
	if err != nil {
		t.Skip("test-elasticsearch isn't running (make up)")
	}
	c.Close()
	cfg := dbmon.Config{Engine: dbmon.Elastic, Host: "127.0.0.1", Port: 9201, Username: "elastic", Password: "colony", TLS: dbmon.TLSDisable, Dial: dbmon.DirectDialer(true)}
	h, err := dbmon.OpenHTTP(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, h
}

// Dump an index (with routing, an alias, nested and object fields) and load
// it back under other names, both ways, comparing documents.
func TestElasticLiveRoundTrip(t *testing.T) {
	cfg, h := liveElastic(t)
	defer h.Close()
	ctx := context.Background()
	const src, copyName, other = "backup-es-test", "backup-es-test-copy", "backup-es-test-two"
	drop := func() {
		for _, n := range []string{src, copyName, other} {
			_ = h.JSON(ctx, http.MethodDelete, dbmon.Path(n), nil, nil)
		}
	}
	drop()
	defer drop()
	must := func(method, path string, body any) {
		t.Helper()
		if err := h.JSON(ctx, method, path, body, nil); err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
	}
	must(http.MethodPut, "/"+src, map[string]any{
		"settings": map[string]any{"number_of_shards": 2, "number_of_replicas": 0, "analysis": map[string]any{"analyzer": map[string]any{"low": map[string]any{"type": "custom", "tokenizer": "standard", "filter": []string{"lowercase"}}}}},
		"mappings": map[string]any{"properties": map[string]any{
			"name": map[string]any{"type": "text", "analyzer": "low"},
			"n":    map[string]any{"type": "long"},
			"v":    map[string]any{"type": "nested", "properties": map[string]any{"c": map[string]any{"type": "keyword"}}},
		}},
		"aliases": map[string]any{"backup-es-alias": map[string]any{}},
	})
	var bulk strings.Builder
	const docs = 2500 // more than two pages
	for i := range docs {
		routing := ""
		if i%10 == 0 {
			routing = fmt.Sprintf(`,"routing":"r%d"`, i%3)
		}
		fmt.Fprintf(&bulk, "{\"index\":{\"_id\":\"d%d\"%s}}\n{\"name\":\"Doc %d\\nline\",\"n\":%d,\"v\":[{\"c\":\"x%d\"}],\"o\":{\"deep\":{\"k\":%d}}}\n", i, routing, i, i, i%4, i)
	}
	res, err := h.Do(ctx, http.MethodPost, dbmon.Path(src, "_bulk")+"?refresh=true", bulk.String(), "application/x-ndjson")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	var file bytes.Buffer
	if err := Dump(ctx, cfg, Target{Engine: dbmon.Elastic, Name: src, Username: cfg.Username, Password: cfg.Password}, &file); err != nil {
		t.Fatal(err)
	}
	s := sniffNative(file.Bytes()[:min(file.Len(), 64<<10)])
	if s.Format != ElasticNDJSON || len(s.Databases) != 1 || s.Databases[0] != src {
		t.Errorf("sniff: %+v", s)
	}
	if !nativeEnds(file.Bytes()[max(0, file.Len()-200):]) {
		t.Error("no trailer")
	}
	if strings.Contains(file.String(), `"uuid"`) || strings.Contains(file.String(), "creation_date") {
		t.Error("cluster-made settings in the file")
	}

	// The scroll fallback (OpenSearch) reads the same documents.
	var scrolled bytes.Buffer
	sw, _ := NewNativeWriter(&scrolled, NativeHeader{Morche: ElasticNDJSON})
	if err := esDumpScroll(ctx, h, src, sw); err != nil {
		t.Fatal(err)
	}
	_ = sw.Close()
	if n := strings.Count(scrolled.String(), `{"doc":`); n != docs {
		t.Errorf("scroll read %d documents", n)
	}

	count := func(name string) int64 {
		var c struct {
			Count int64 `json:"count"`
		}
		if err := h.JSON(ctx, http.MethodGet, dbmon.Path(name, "_count"), nil, &c); err != nil {
			t.Fatal(err)
		}
		return c.Count
	}
	load := func(name string, o RestoreOptions, data []byte) error {
		o.Format = ElasticNDJSON
		return Load(ctx, cfg, Target{Engine: dbmon.Elastic, Name: name, Username: cfg.Username, Password: cfg.Password}, o, bytes.NewReader(data))
	}
	if err := load(copyName, RestoreOptions{}, file.Bytes()); err != nil {
		t.Fatal(err)
	}
	if n := count(copyName); n != docs {
		t.Errorf("copy has %d documents, want %d", n, docs)
	}
	// Routing and the source came back as they were.
	var doc struct {
		Routing string         `json:"_routing"`
		Source  map[string]any `json:"_source"`
	}
	if err := h.JSON(ctx, http.MethodGet, dbmon.Path(copyName, "_doc", "d20")+"?routing=r2", nil, &doc); err != nil || doc.Routing != "r2" || doc.Source["name"] != "Doc 20\nline" {
		t.Errorf("routed document: %+v %v", doc, err)
	}
	// The alias stays with the source (another name), settings came over.
	var def map[string]struct {
		Aliases  map[string]any `json:"aliases"`
		Settings struct {
			Index struct {
				Shards   string         `json:"number_of_shards"`
				Analysis map[string]any `json:"analysis"`
			} `json:"index"`
		} `json:"settings"`
	}
	must(http.MethodGet, dbmon.Path(copyName), nil)
	_ = h.JSON(ctx, http.MethodGet, dbmon.Path(copyName), nil, &def)
	if d := def[copyName]; len(d.Aliases) != 0 || d.Settings.Index.Shards != "2" || d.Settings.Index.Analysis == nil {
		t.Errorf("copy's definition: %+v", d)
	}

	// Again without Replace: refused; with Replace: done.
	if err := load(copyName, RestoreOptions{}, file.Bytes()); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("second load: %v", err)
	}
	must(http.MethodDelete, dbmon.Path(copyName, "_doc", "d1"), nil)
	if err := load(copyName, RestoreOptions{Replace: true}, file.Bytes()); err != nil {
		t.Fatal(err)
	}
	if n := count(copyName); n != docs {
		t.Errorf("replaced copy has %d documents", n)
	}

	// Into an alias's name: refused.
	if err := load("backup-es-alias", RestoreOptions{Replace: true}, file.Bytes()); err == nil {
		t.Error("load into an alias worked")
	}
	// Dumping an alias is refused with the index named.
	if err := Dump(ctx, cfg, Target{Engine: dbmon.Elastic, Name: "backup-es-alias", Username: cfg.Username, Password: cfg.Password}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), src) {
		t.Errorf("alias dump: %v", err)
	}

	// A file of every index: one picked by Source; none picked is refused.
	must(http.MethodPut, "/"+other, map[string]any{"settings": map[string]any{"number_of_replicas": 0}})
	must(http.MethodPut, dbmon.Path(other, "_doc", "1")+"?refresh=true", map[string]any{"a": 1})
	var all bytes.Buffer
	if err := Dump(ctx, cfg, Target{Engine: dbmon.Elastic, Username: cfg.Username, Password: cfg.Password}, &all); err != nil {
		t.Fatal(err)
	}
	names := nativeIndexes(all.Bytes())
	if len(names) < 3 {
		t.Errorf("every index: %v", names)
	}
	for _, d := range names {
		if strings.HasPrefix(d, ".") {
			t.Errorf("system index dumped: %s", d)
		}
	}
	must(http.MethodDelete, dbmon.Path(copyName), nil)
	if err := load(copyName, RestoreOptions{}, all.Bytes()); err == nil || !strings.Contains(err.Error(), "several") {
		t.Errorf("several without a pick: %v", err)
	}
	var exists bool
	if _, err := h.Raw(ctx, http.MethodHead, dbmon.Path(copyName), nil, 0); err == nil {
		exists = true
	}
	if exists {
		t.Error("the half-loaded index was left behind")
	}
	if err := load(copyName, RestoreOptions{Source: src}, all.Bytes()); err != nil {
		t.Fatal(err)
	}
	if n := count(copyName); n != docs {
		t.Errorf("picked copy has %d documents", n)
	}
	if err := load(other+"-x", RestoreOptions{Source: "nope"}, all.Bytes()); err == nil {
		t.Error("a missing source worked")
	}
}
