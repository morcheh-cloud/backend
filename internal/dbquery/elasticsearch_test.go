package dbquery

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/morche/backend/internal/dbmon"
)

func TestElasticParseConsole(t *testing.T) {
	text := `# the health
GET _cluster/health

// a search
POST /shop/_search
{
  "query": {"match": {"name": "apple"}},
  "size": 2
}

POST _bulk
{"index": {"_index": "shop", "_id": "1"}}
{"name": "x"}
{"delete": {"_index": "shop", "_id": "2"}}

PUT /shop/_doc/3
{"text": """line one
line "two" """}
`
	reqs, err := ParseConsole(text, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 4 {
		t.Fatalf("want 4 requests, got %d: %+v", len(reqs), reqs)
	}
	if reqs[0].Method != "GET" || reqs[0].Path != "/_cluster/health" || reqs[0].Body != "" {
		t.Errorf("first: %+v", reqs[0])
	}
	if reqs[1].Body != `{"query":{"match":{"name":"apple"}},"size":2}` || reqs[1].NDJSON {
		t.Errorf("search body: %q", reqs[1].Body)
	}
	if !reqs[2].NDJSON || strings.Count(reqs[2].Body, "\n") != 3 || !strings.HasSuffix(reqs[2].Body, "\n") {
		t.Errorf("bulk body: %q", reqs[2].Body)
	}
	var doc map[string]string
	if err := json.Unmarshal([]byte(reqs[3].Body), &doc); err != nil || doc["text"] != "line one\nline \"two\" " {
		t.Errorf("triple quotes: %q %v", reqs[3].Body, err)
	}

	// A bare body is a search on the open index.
	reqs, err = ParseConsole(`{"query": {"match_all": {}}}`, "shop")
	if err != nil || len(reqs) != 1 || reqs[0].Path != "/shop/_search" || reqs[0].Method != "POST" {
		t.Errorf("bare body: %+v %v", reqs, err)
	}
	// A single-line _bulk is still NDJSON.
	reqs, _ = ParseConsole("POST /shop/_bulk\n{\"delete\":{\"_id\":\"1\"}}", "")
	if !reqs[0].NDJSON {
		t.Error("single-line bulk not NDJSON")
	}
	for _, bad := range []string{"", "hello", "GET /x\n{broken"} {
		if _, err := ParseConsole(bad, ""); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestElasticCheckRead(t *testing.T) {
	ok := [][2]string{
		{"GET", "/shop/_doc/1"}, {"HEAD", "/shop"}, {"GET", "/_cat/indices?v"},
		{"POST", "/shop/_search"}, {"POST", "/_search/template"}, {"POST", "/shop/_count"},
		{"POST", "/shop/_validate/query?explain"}, {"POST", "/shop/_explain/1"},
		{"POST", "/_msearch"}, {"POST", "/shop/_mget"}, {"POST", "/_sql?format=json"},
		{"POST", "/shop/_field_caps"}, {"POST", "/_analyze"}, {"POST", "/shop/_pit?keep_alive=1m"},
		{"POST", "/_search/scroll"}, {"POST", "/_query"},
	}
	for _, c := range ok {
		if err := CheckReadElastic(c[0], c[1]); err != nil {
			t.Errorf("%s %s refused: %v", c[0], c[1], err)
		}
	}
	bad := [][2]string{
		{"PUT", "/shop"}, {"DELETE", "/shop"}, {"POST", "/shop/_doc"}, {"PUT", "/shop/_doc/1"},
		{"POST", "/_bulk"}, {"POST", "/shop/_update/1"}, {"POST", "/shop/_delete_by_query"},
		{"POST", "/_reindex"}, {"POST", "/_snapshot/repo/snap/_restore"}, {"PUT", "/_cluster/settings"},
		{"POST", "/shop/_close"}, {"DELETE", "/_pit"}, {"POST", "/_security/user/x"},
		{"PATCH", "/shop"}, {"POST", "/shop/_forcemerge"}, {"POST", "/searchy/_doc"},
	}
	for _, c := range bad {
		err := CheckReadElastic(c[0], c[1])
		var rf *ErrRefused
		if !errors.As(err, &rf) {
			t.Errorf("%s %s allowed", c[0], c[1])
		}
	}
}

func testMapping() *esMapping {
	m := newMapping()
	var props map[string]esProp
	_ = json.Unmarshal([]byte(`{
		"name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
		"body": {"type": "text"},
		"sku": {"type": "keyword"},
		"price": {"type": "double"},
		"dims": {"properties": {"w": {"type": "integer"}}},
		"loc": {"type": "geo_point"},
		"variants": {"type": "nested", "properties": {"color": {"type": "keyword"}}}
	}`), &props)
	m.add("", props)
	return m
}

func TestElasticMapping(t *testing.T) {
	m := testMapping()
	var paths []string
	for _, f := range m.fields {
		paths = append(paths, f.Path+":"+f.Type)
	}
	want := "body:text dims.w:integer loc:geo_point name:text price:double sku:keyword variants:nested"
	if got := strings.Join(paths, " "); got != want {
		t.Errorf("fields: %s", got)
	}
	if m.byPath["name"].Keyword != "name.keyword" {
		t.Errorf("keyword sub-field: %+v", m.byPath["name"])
	}
}

func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestElasticFilters(t *testing.T) {
	m := testMapping()
	cases := []struct {
		f    RowFilter
		want string
	}{
		{RowFilter{Column: "sku", Op: "eq", Value: "A1"}, `{"term":{"sku":"A1"}}`},
		{RowFilter{Column: "body", Op: "eq", Value: "hi there"}, `{"match":{"body":{"operator":"and","query":"hi there"}}}`},
		{RowFilter{Column: "name", Op: "contains", Value: "a*b"}, `{"wildcard":{"name.keyword":{"case_insensitive":true,"value":"*a\\*b*"}}}`},
		{RowFilter{Column: "price", Op: "gte", Value: "10"}, `{"range":{"price":{"gte":"10"}}}`},
		{RowFilter{Column: "sku", Op: "in", Values: []string{"a", "b"}}, `{"terms":{"sku":["a","b"]}}`},
		{RowFilter{Column: "sku", Op: "null"}, `{"bool":{"must_not":[{"exists":{"field":"sku"}}]}}`},
		{RowFilter{Column: "sku", Op: "not_null"}, `{"exists":{"field":"sku"}}`},
		{RowFilter{Column: "sku", Op: "starts", Value: "SK"}, `{"prefix":{"sku":{"case_insensitive":true,"value":"SK"}}}`},
		{RowFilter{Column: "sku", Op: "ends", Value: "01"}, `{"wildcard":{"sku":{"case_insensitive":true,"value":"*01"}}}`},
		{RowFilter{Column: "sku", Op: "ne", Value: "x"}, `{"bool":{"must_not":[{"term":{"sku":"x"}}]}}`},
		{RowFilter{Column: "_id", Op: "eq", Value: "p1"}, `{"ids":{"values":["p1"]}}`},
	}
	for _, c := range cases {
		q, err := esFilter(m, c.f)
		if err != nil {
			t.Errorf("%+v: %v", c.f, err)
			continue
		}
		if got := jsonOf(q); got != c.want {
			t.Errorf("%+v:\n got %s\nwant %s", c.f, got, c.want)
		}
	}
	if _, err := esFilter(m, RowFilter{Column: "_id", Op: "contains", Value: "x"}); err == nil {
		t.Error("_id contains accepted")
	}

	q, err := esRowsQuery(m, RowsRequest{Filters: []RowFilter{{Column: "sku", Op: "eq", Value: "a"}, {Column: "price", Op: "lt", Value: "3"}}, Match: "any", Where: "stock:>3"})
	if err != nil {
		t.Fatal(err)
	}
	got := jsonOf(q)
	if !strings.Contains(got, `"should":[{"term"`) || !strings.Contains(got, `"minimum_should_match":1`) || !strings.Contains(got, `"query_string":{"query":"stock:\u003e3"}`) {
		t.Errorf("rows query: %s", got)
	}
	q, _ = esRowsQuery(m, RowsRequest{})
	if jsonOf(q) != `{"match_all":{}}` {
		t.Errorf("empty: %s", jsonOf(q))
	}
	q, _ = esRowsQuery(m, RowsRequest{Where: `{"query": {"term": {"sku": "x"}}, "size": 3}`})
	if !strings.Contains(jsonOf(q), `"must":[{"term":{"sku":"x"}}]`) {
		t.Errorf("where body: %s", jsonOf(q))
	}
	if _, err := esRowsQuery(m, RowsRequest{Where: `{"bad"`}); err == nil {
		t.Error("bad where accepted")
	}
}

func TestElasticSort(t *testing.T) {
	m := testMapping()
	s, err := esSort(m, []RowSort{{Column: "name", Desc: true}, {Column: "_id"}, {Column: "price"}})
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"name.keyword":{"order":"desc","unmapped_type":"keyword"}},{"_doc":{"order":"asc"}},{"price":{"order":"asc","unmapped_type":"double"}}]`
	if got := jsonOf(s); got != want {
		t.Errorf("sort:\n got %s\nwant %s", got, want)
	}
	for _, bad := range []string{"body", "loc", "nope"} {
		if _, err := esSort(m, []RowSort{{Column: bad}}); err == nil {
			t.Errorf("sort on %s accepted", bad)
		}
	}
}

func TestElasticHitsResult(t *testing.T) {
	m := testMapping()
	hits := []esHit{
		{Index: "a", ID: "1", Source: json.RawMessage(`{"sku":"X","extra":true,"dims":{"w":3},"loc":{"lat":1,"lon":2},"name":"Apple\npie","variants":[{"color":"red"}]}`)},
		{Index: "a", ID: "2", Source: json.RawMessage(`{"price":2.5,"sku":null}`)},
	}
	r := esHitsResult(hits, m, false)
	var cols []string
	for _, c := range r.Columns {
		cols = append(cols, c.Name)
	}
	if got := strings.Join(cols, ","); got != "_id,dims.w,loc,name,price,sku,variants,extra" {
		t.Errorf("columns: %s", got)
	}
	cell := func(row int, col string) *string {
		for i, c := range r.Columns {
			if c.Name == col {
				return r.Rows[row][i]
			}
		}
		return nil
	}
	if v := cell(0, "loc"); v == nil || *v != `{"lat":1,"lon":2}` {
		t.Errorf("geo point: %v", v)
	}
	if v := cell(0, "dims.w"); v == nil || *v != "3" {
		t.Errorf("object field: %v", v)
	}
	if v := cell(1, "sku"); v != nil {
		t.Errorf("null: %v", *v)
	}
	if r.Documents[0] != `{"sku":"X","extra":true,"dims":{"w":3},"loc":{"lat":1,"lon":2},"name":"Apple\npie","variants":[{"color":"red"}]}` {
		t.Errorf("document: %s", r.Documents[0])
	}
}

func TestElasticAnswer(t *testing.T) {
	search := `{"took":3,"hits":{"total":{"value":12,"relation":"eq"},"hits":[{"_index":"a","_id":"1","_source":{"x":1}}]},"aggregations":{"by":{"buckets":[]}}}`
	rs := esAnswer("POST /a/_search", []byte(search), false, 100)
	if len(rs) != 2 || rs[0].Columns[0].Name != "_index" || rs[1].Columns[0].Name != "aggregations" || !strings.Contains(rs[0].Message, "12 match") {
		t.Errorf("search + aggs: %+v", rs)
	}
	rs = esAnswer("x", []byte(`{"took":1,"hits":{"total":{"value":0,"relation":"eq"},"hits":[]},"aggregations":{"n":{"value":3}}}`), false, 100)
	if len(rs) != 1 || rs[0].Columns[0].Name != "aggregations" {
		t.Errorf("aggs only: %+v", rs)
	}
	rs = esAnswer("x", []byte(`{"columns":[{"name":"a","type":"long"},{"name":"b","type":"text"}],"rows":[[1,"x"],[2,null]]}`), false, 100)
	if len(rs[0].Rows) != 2 || *rs[0].Rows[0][1] != "x" || rs[0].Rows[1][1] != nil {
		t.Errorf("sql: %+v", rs)
	}
	rs = esAnswer("x", []byte(`{"took":1,"errors":true,"items":[{"index":{"status":201}},{"index":{"status":400,"error":{"type":"mapper_parsing_exception","reason":"bad"}}}]}`), false, 100)
	if rs[0].Affected == nil || *rs[0].Affected != 1 || !strings.Contains(rs[0].Message, "1 failed") {
		t.Errorf("bulk: %+v %s", rs[0].Affected, rs[0].Message)
	}
	rs = esAnswer("x", []byte(`{"_index":"a","_id":"1","result":"created"}`), false, 100)
	if rs[0].Affected == nil || *rs[0].Affected != 1 {
		t.Errorf("doc write: %+v", rs[0])
	}
	rs = esAnswer("x", []byte("health status index\ngreen open a\n"), false, 100)
	if rs[0].Columns[0].Name != "response" || !strings.Contains(*rs[0].Rows[0][0], "green") {
		t.Errorf("text: %+v", rs[0])
	}
	rs = esAnswer("x", []byte(`{"responses":[{"hits":{"hits":[]}},{"hits":{"hits":[{"_id":"1","_source":{}}]}}]}`), false, 100)
	if len(rs) != 2 {
		t.Errorf("msearch: %d results", len(rs))
	}
}

func TestElasticDocument(t *testing.T) {
	doc, id, err := esDocument(`{"_id": "k1", "name": "x", "n": 12345678901234567890}`, 1)
	if err != nil || id != "k1" || doc != `{"n":12345678901234567890,"name":"x"}` {
		t.Errorf("got %q %q %v", doc, id, err)
	}
	for _, bad := range []string{"", "[1]", "null", `{"_index": "x"}`, `{"_id": {"a": 1}}`, "{"} {
		if _, _, err := esDocument(bad, 1); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestElasticRisks(t *testing.T) {
	r := elasticRisks("DELETE /shop\nPOST /shop/_delete_by_query\n{\"query\":{\"match_all\":{}}}\nGET /shop/_search")
	if len(r) != 2 {
		t.Errorf("risks: %v", r)
	}
	if r := elasticRisks("PUT /shop/_doc/1\n{}"); len(r) != 0 {
		t.Errorf("a doc write is risky: %v", r)
	}
}

// liveElastic is the compose service test-elasticsearch with shop-products
// (and its alias products) in it; tests using it skip when it isn't running.
func liveElastic(t *testing.T) dbmon.Config {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:9201", time.Second)
	if err != nil {
		t.Skip("test-elasticsearch isn't running (make up)")
	}
	c.Close()
	return dbmon.Config{Engine: dbmon.Elastic, Host: "127.0.0.1", Port: 9201, Username: "elastic", Password: "colony", TLS: dbmon.TLSDisable, Dial: dbmon.DirectDialer(true)}
}

func TestElasticLive(t *testing.T) {
	cfg := liveElastic(t)
	ctx := context.Background()
	c, err := Open(ctx, cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	es := c.(*esClient)
	const idx = "explore-test"
	setup := `DELETE /` + idx + `
PUT /` + idx + `
{"settings": {"number_of_shards": 1, "number_of_replicas": 0},
 "mappings": {"properties": {"name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}}, "n": {"type": "integer"}, "tag": {"type": "keyword"}, "at": {"type": "date"}, "o": {"properties": {"x": {"type": "integer"}}}}},
 "aliases": {"explore-alias": {}}}
POST /` + idx + `/_bulk?refresh=true
{"index": {"_id": "a"}}
{"name": "Green apple", "n": 1, "tag": "fruit", "at": "2026-01-01", "o": {"x": 5}}
{"index": {"_id": "b"}}
{"name": "Pear", "n": 2, "tag": "fruit"}
{"index": {"_id": "c"}}
{"name": "Carrot cake", "n": 3, "tag": "cake"}
`
	// The setup's DELETE fails when the index isn't there yet; run it alone.
	_, _ = c.Run(ctx, "", "DELETE /"+idx, RunOptions{Change: true, Timeout: 30 * time.Second})
	if _, err := c.Run(ctx, "", strings.SplitN(setup, "\n", 2)[1], RunOptions{Change: true, Timeout: 30 * time.Second}); err != nil {
		t.Fatal(err)
	}
	defer c.Run(context.Background(), "", "DELETE /"+idx, RunOptions{Change: true, Timeout: 30 * time.Second})

	o, err := c.Overview(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, x := range o.Objects {
		kinds[x.Name] = x.Kind
		if strings.HasPrefix(x.Name, ".") {
			t.Errorf("system index listed: %s", x.Name)
		}
	}
	if kinds[idx] != "index" || kinds["explore-alias"] != "alias" {
		t.Errorf("overview: %v", kinds)
	}
	if kinds["logs-app-default"] != "data_stream" {
		t.Logf("no data stream logs-app-default in the test cluster: %v", kinds)
	}

	info, err := c.Describe(ctx, "", "", idx)
	if err != nil {
		t.Fatal(err)
	}
	if info.Columns[0].Name != "_id" || info.ReadOnly != "" || !strings.Contains(info.Definition, `"mappings"`) || strings.Contains(info.Definition, "uuid") {
		t.Errorf("describe: %+v", info)
	}
	if len(info.Facts) == 0 {
		t.Error("no facts")
	}
	if _, err := c.Describe(ctx, "", "", "no-such-index"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing index: %v", err)
	}
	if kinds["logs-app-default"] == "data_stream" {
		ds, err := c.Describe(ctx, "", "", "logs-app-default")
		if err != nil || ds.Kind != "data_stream" || ds.ReadOnly == "" {
			t.Errorf("data stream: %+v %v", ds, err)
		}
	}

	page, err := c.Rows(ctx, RowsRequest{Table: idx, Count: true, Sort: []RowSort{{Column: "n", Desc: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total == nil || *page.Total != 3 || len(page.Rows) != 3 || *page.Rows[0][0] != "c" || len(page.Documents) != 3 {
		t.Errorf("rows: total %v rows %v", page.Total, page.Rows)
	}
	page, err = c.Rows(ctx, RowsRequest{Table: idx, Filters: []RowFilter{{Column: "name", Op: "contains", Value: "APPLE"}}, Count: true})
	if err != nil || page.Total == nil || *page.Total != 1 {
		t.Errorf("contains: %v %v", page, err)
	}
	page, err = c.Rows(ctx, RowsRequest{Table: idx, Filters: []RowFilter{{Column: "tag", Op: "eq", Value: "fruit"}, {Column: "n", Op: "gte", Value: "2"}}, Count: true})
	if err != nil || *page.Total != 1 || *page.Rows[0][0] != "b" {
		t.Errorf("eq + gte: %v %v", page, err)
	}
	page, err = c.Rows(ctx, RowsRequest{Table: idx, Search: "carrot", Count: true})
	if err != nil || *page.Total != 1 {
		t.Errorf("search: %v %v", page, err)
	}
	page, err = c.Rows(ctx, RowsRequest{Table: idx, Where: "tag:cake OR n:1", Count: true, Limit: 1})
	if err != nil || *page.Total != 2 || !page.Truncated {
		t.Errorf("where + limit: %v %v", page, err)
	}
	page, err = c.Rows(ctx, RowsRequest{Table: "explore-alias", Filters: []RowFilter{{Column: "o.x", Op: "not_null"}}})
	if err != nil || len(page.Rows) != 1 || page.Columns[0].Name != "_index" {
		t.Errorf("alias + object field: %v %v", page, err)
	}
	if _, err := c.Rows(ctx, RowsRequest{Table: idx, Offset: 20000}); err == nil {
		t.Error("offset past the window accepted")
	}

	// Read mode refuses writes before running anything.
	_, err = c.Run(ctx, "", "GET /"+idx+"/_search\nDELETE /"+idx, RunOptions{Timeout: 10 * time.Second})
	var rf *ErrRefused
	if !errors.As(err, &rf) {
		t.Fatalf("delete in read mode: %v", err)
	}
	res, err := c.Run(ctx, idx, `GET /`+idx+`/_search
{"query": {"match_all": {}}, "aggs": {"tags": {"terms": {"field": "tag"}}}}

POST /_sql?format=json
{"query": "SELECT tag, COUNT(*) AS n FROM \"`+idx+`\" GROUP BY tag ORDER BY tag"}

GET /_cat/indices/`+idx+`?v`, RunOptions{Timeout: 10 * time.Second, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 4 || len(res[0].Rows) != 3 || res[1].Columns[0].Name != "aggregations" || len(res[2].Rows) != 2 || res[3].Columns[0].Name != "response" {
		for _, r := range res {
			t.Logf("%s: %v %d rows %s", r.Statement, r.Columns, len(r.Rows), r.Message)
		}
		t.Errorf("read run: %d results", len(res))
	}

	// Edit: insert, update, delete.
	ed := c.(Editor)
	pv, err := ed.Edit(ctx, EditRequest{Table: idx, Preview: true, Changes: []RowChange{{Op: "insert", Document: `{"_id": "d", "name": "Date", "n": 4}`}}})
	if err != nil || pv.Ran || !strings.HasPrefix(pv.Statements[0], "PUT /"+idx+"/_create/d") {
		t.Fatalf("preview: %+v %v", pv, err)
	}
	keyB, keyC, keyX := "b", "c", "zzz"
	out, err := ed.Edit(ctx, EditRequest{Table: idx, Changes: []RowChange{
		{Op: "insert", Document: `{"_id": "d", "name": "Date", "n": 4}`},
		{Op: "insert", Document: `{"name": "No id", "n": 5}`},
		{Op: "update", Key: map[string]*string{"_id": &keyB}, Document: `{"name": "Pear", "n": 20, "tag": "fruit"}`},
		{Op: "delete", Key: map[string]*string{"_id": &keyC}},
	}})
	if err != nil || !out.Ran || out.Affected != 4 {
		t.Fatalf("edit: %+v %v", out, err)
	}
	page, _ = c.Rows(ctx, RowsRequest{Table: idx, Count: true, Filters: []RowFilter{{Column: "n", Op: "gte", Value: "4"}}})
	if *page.Total != 3 {
		t.Errorf("after the edit, n >= 4: %d", *page.Total)
	}
	// A missing key: nothing is sent.
	_, err = ed.Edit(ctx, EditRequest{Table: idx, Changes: []RowChange{
		{Op: "delete", Key: map[string]*string{"_id": &keyB}},
		{Op: "delete", Key: map[string]*string{"_id": &keyX}},
	}})
	if !errors.As(err, &rf) {
		t.Errorf("missing key: %v", err)
	}
	if _, err := es.existing(ctx, idx, []string{"b"}); err != nil {
		t.Error(err)
	}
	page, _ = c.Rows(ctx, RowsRequest{Table: idx, Filters: []RowFilter{{Column: "_id", Op: "eq", Value: "b"}}})
	if len(page.Rows) != 1 {
		t.Error("b was removed although the change was refused")
	}
	// Inserting an id that is there fails.
	if _, err := ed.Edit(ctx, EditRequest{Table: idx, Changes: []RowChange{{Op: "insert", Document: `{"_id": "a", "n": 9}`}}}); err == nil {
		t.Error("duplicate insert worked")
	}
}
