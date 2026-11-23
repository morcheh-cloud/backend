package dbquery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/morche/backend/internal/dbmon"
)

func TestMeiliParse(t *testing.T) {
	reqs, err := meiliParse(`# find batman
POST /indexes/movies/search
{
  "q": "batman",

  "limit": 5
}
get indexes?limit=3
// stats
GET http://localhost:7700/stats

POST /indexes/movies/documents
{"id": 1}
{"id": 2}
DELETE /indexes/movies`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"POST /indexes/movies/search", "GET /indexes?limit=3", "GET /stats", "POST /indexes/movies/documents", "DELETE /indexes/movies"}
	if len(reqs) != len(want) {
		t.Fatalf("got %d requests: %+v", len(reqs), reqs)
	}
	for i, w := range want {
		if reqs[i].String() != w {
			t.Errorf("request %d = %q, want %q", i, reqs[i], w)
		}
	}
	var body map[string]any
	if json.Unmarshal(reqs[0].Body, &body) != nil || body["q"] != "batman" {
		t.Errorf("body: %s", reqs[0].Body)
	}
	if !reqs[3].NDJSON || reqs[1].Body != nil {
		t.Errorf("ndjson %v, body of a GET %q", reqs[3].NDJSON, reqs[1].Body)
	}
	for _, bad := range []string{
		"",
		"# only a comment",
		`{"q": "x"}`,
		"POST /indexes/movies/search\n{\"q\": ",
		"GET /indexes/../keys",
	} {
		var rf *ErrRefused
		if _, err := meiliParse(bad); !errors.As(err, &rf) {
			t.Errorf("%q: want a refusal, got %v", bad, err)
		}
	}
}

func TestMeiliCheckRead(t *testing.T) {
	ok := []string{
		"GET /indexes", "GET /tasks?statuses=failed", "GET /indexes/movies/settings",
		"POST /indexes/movies/search", "POST /multi-search", "POST /indexes/movies/documents/fetch",
		"POST /indexes/movies/facet-search", "POST /indexes/movies/similar",
	}
	no := []string{
		"GET /keys", "GET /keys/abc", "GET /webhooks", "GET /chats/x/settings",
		"POST /indexes/movies/documents", "DELETE /indexes/movies", "PATCH /indexes/movies/settings",
		"POST /tasks/cancel?uids=1", "POST /dumps", "PUT /indexes/movies/documents", "POST /indexes",
		"POST /indexes/movies/search/x",
	}
	for _, s := range ok {
		m, p, _ := strings.Cut(s, " ")
		if err := meiliCheckRead(meiliRequest{Method: m, Path: p}); err != nil {
			t.Errorf("%s refused: %v", s, err)
		}
	}
	for _, s := range no {
		m, p, _ := strings.Cut(s, " ")
		if err := meiliCheckRead(meiliRequest{Method: m, Path: p}); err == nil {
			t.Errorf("%s allowed in read mode", s)
		}
	}
}

func TestMeiliFilter(t *testing.T) {
	got, err := meiliFilter([]RowFilter{
		{Column: "genre", Op: "eq", Value: `dr"ama`},
		{Column: "year", Op: "gte", Value: "2000"},
		{Column: "release date", Op: "in", Values: []string{"a", "b"}},
		{Column: "note", Op: "null"},
	}, "any", "rating > 5")
	if err != nil {
		t.Fatal(err)
	}
	want := `(rating > 5) AND ((genre = "dr\"ama") OR (year >= "2000") OR ("release date" IN ["a", "b"]) OR ((note IS NULL OR note NOT EXISTS)))`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if got, _ := meiliFilter([]RowFilter{{Column: "a", Op: "starts", Value: "x"}}, "", ""); got != `a STARTS WITH "x"` {
		t.Errorf("starts: %s", got)
	}
	if _, err := meiliFilter([]RowFilter{{Column: "a", Op: "ends", Value: "x"}}, "", ""); err == nil {
		t.Error("ends should be refused")
	}
	if _, err := meiliFilter([]RowFilter{{Column: "a", Op: "in"}}, "", ""); err == nil {
		t.Error("an empty in should be refused")
	}
}

func TestMeiliMatches(t *testing.T) {
	p := []string{"genre", "meta", "price_*", "*_at"}
	for f, want := range map[string]bool{
		"genre": true, "meta.lang": true, "price_eur": true, "created_at": true,
		"genres": false, "title": false, "metadata": false,
	} {
		if got := meiliMatches(p, f); got != want {
			t.Errorf("%s: got %v", f, got)
		}
	}
	if !meiliMatches([]string{"*"}, "x") {
		t.Error("* matches everything")
	}
}

func TestMeiliDocs(t *testing.T) {
	r := meiliDocs([]json.RawMessage{
		json.RawMessage(`{"title":"A","id":7,"tags":["x", "y"],"n":null}`),
		json.RawMessage(`{"id":"b","extra":{"k":1}}`),
	}, "id")
	var names []string
	for _, c := range r.Columns {
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "id,title,tags,n,extra" {
		t.Fatalf("columns %v", names)
	}
	if *r.Rows[0][0] != "7" || *r.Rows[0][2] != `["x","y"]` || r.Rows[0][3] != nil || *r.Rows[1][4] != `{"k":1}` {
		t.Errorf("rows: %v", r.Rows)
	}
	if r.Documents[0] != `{"title":"A","id":7,"tags":["x","y"],"n":null}` {
		t.Errorf("document %s", r.Documents[0])
	}
}

// meiliLive is the compose service test-meilisearch, or a skip.
func meiliLive(t *testing.T) *meiliClient {
	t.Helper()
	hc := http.Client{Timeout: 2 * time.Second}
	res, err := hc.Get("http://127.0.0.1:7701/health")
	if err != nil {
		t.Skip("test-meilisearch isn't running (make up in the backend)")
	}
	res.Body.Close()
	cfg := dbmon.Config{Engine: dbmon.Meili, Host: "127.0.0.1", Port: 7701, Password: "colony-master-key-2026", TLS: dbmon.TLSDisable, Dial: dbmon.DirectDialer(true)}
	c, err := Open(context.Background(), cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c.(*meiliClient)
}

func TestMeiliLiveExplorer(t *testing.T) {
	c := meiliLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	change := RunOptions{Change: true, Limit: 100, Timeout: time.Minute}
	read := RunOptions{Limit: 100, Timeout: time.Minute}

	// A fresh index of 50 documents.
	var docs []string
	for i := 1; i <= 50; i++ {
		docs = append(docs, fmt.Sprintf(`{"id": %d, "title": "Film %d %s", "genre": "%s", "year": %d, "meta": {"n": %d}}`,
			i, i, []string{"Batman", "Star", "Night"}[i%3], []string{"drama", "comedy"}[i%2], 1990+i, i))
	}
	script := "DELETE /indexes/explore_test\n\n" +
		"POST /indexes\n{\"uid\": \"explore_test\", \"primaryKey\": \"id\"}\n" +
		"PATCH /indexes/explore_test/settings\n{\"filterableAttributes\": [\"genre\", \"year\", \"id\"], \"sortableAttributes\": [\"year\"]}\n" +
		"POST /indexes/explore_test/documents\n[" + strings.Join(docs, ",\n") + "]"
	res, err := c.Run(ctx, "", script, change)
	if err != nil && !strings.Contains(err.Error(), "request 1") {
		t.Fatal(err)
	}
	if err != nil { // the index wasn't there yet
		res, err = c.Run(ctx, "", strings.SplitN(script, "\n\n", 2)[1], change)
		if err != nil {
			t.Fatal(err)
		}
	}
	last := res[len(res)-1]
	if last.Affected == nil || *last.Affected != 50 || !strings.Contains(last.Message, "succeeded") {
		t.Fatalf("adding documents: %+v", last)
	}
	t.Cleanup(func() {
		_, _ = c.Run(context.Background(), "", "DELETE /indexes/explore_test", change)
	})

	o, err := c.Overview(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, ob := range o.Objects {
		if ob.Name == "explore_test" && ob.Kind == "index" && ob.Rows != nil && *ob.Rows == 50 {
			found = true
		}
	}
	if !found {
		t.Fatalf("overview: %+v", o.Objects)
	}

	info, err := c.Describe(ctx, "", "", "explore_test")
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Key) != 1 || info.Key[0] != "id" || info.Columns[0].Name != "id" || !info.Columns[0].Key || info.ReadOnly != "" {
		t.Fatalf("describe: %+v", info)
	}
	if !strings.Contains(info.Definition, "filterableAttributes") {
		t.Errorf("definition: %s", info.Definition)
	}

	// Plain paging, filters, search, sort.
	page, err := c.Rows(ctx, RowsRequest{Table: "explore_test", Limit: 10, Offset: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 10 || page.Total == nil || *page.Total != 50 || !page.Truncated || page.Columns[0].Name != "id" {
		t.Fatalf("page: %+v", page)
	}
	page, err = c.Rows(ctx, RowsRequest{Table: "explore_test", Filters: []RowFilter{{Column: "genre", Op: "eq", Value: "drama"}, {Column: "year", Op: "gt", Value: "2030"}}})
	if err != nil {
		t.Fatal(err)
	}
	if *page.Total != 5 { // even ids 42..50 → years 2032..2040
		t.Errorf("filtered total %d", *page.Total)
	}
	page, err = c.Rows(ctx, RowsRequest{Table: "explore_test", Search: "batman", Sort: []RowSort{{Column: "year", Desc: true}}, Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) == 0 || page.Total == nil || page.Estimated {
		t.Fatalf("search: %+v", page)
	}
	if !strings.Contains(*page.Rows[0][1], "Batman") {
		t.Errorf("search hit: %v", page.Rows[0])
	}
	if _, err := c.Rows(ctx, RowsRequest{Table: "explore_test", Sort: []RowSort{{Column: "title"}}}); err == nil || !strings.Contains(err.Error(), "sortableAttributes") {
		t.Errorf("sorting by a non-sortable field: %v", err)
	}
	if _, err := c.Rows(ctx, RowsRequest{Table: "explore_test", Filters: []RowFilter{{Column: "title", Op: "eq", Value: "x"}}}); err == nil || !strings.Contains(err.Error(), "filterableAttributes") {
		t.Errorf("filtering a non-filterable field: %v", err)
	}
	if _, err := c.Rows(ctx, RowsRequest{Table: "explore_test", Filters: []RowFilter{{Column: "genre", Op: "contains", Value: "dra"}}}); err == nil || !strings.Contains(err.Error(), "containsFilter") {
		t.Errorf("contains without the feature: %v", err)
	}

	// The console in read mode.
	res, err = c.Run(ctx, "", "POST /indexes/explore_test/search\n{\"q\": \"star\", \"facets\": [\"genre\"]}\nGET /indexes/explore_test/stats", read)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 || len(res[0].Rows) == 0 || len(res[0].Documents) == 0 || !strings.Contains(res[0].Message, "hits") ||
		res[1].Columns[0].Name != "attribute" || res[2].Columns[0].Name != "response" {
		t.Fatalf("read run: %+v", res)
	}
	for _, q := range []string{"POST /indexes/explore_test/documents\n[{\"id\": 99}]", "GET /keys", "DELETE /indexes/explore_test"} {
		var rf *ErrRefused
		if _, err := c.Run(ctx, "", q, read); !errors.As(err, &rf) {
			t.Errorf("%q in read mode: %v", q, err)
		}
	}

	// Editing by primary key.
	ed := Editor(c)
	p, err := ed.Edit(ctx, EditRequest{Table: "explore_test", Preview: true, Changes: []RowChange{
		{Op: "insert", Document: `{"id": 100, "title": "New"}`},
		{Op: "delete", Key: map[string]*string{"id": ptr("3")}},
	}})
	if err != nil || len(p.Statements) != 2 || p.Ran {
		t.Fatalf("preview: %+v %v", p, err)
	}
	if _, err := ed.Edit(ctx, EditRequest{Table: "explore_test", Changes: []RowChange{{Op: "insert", Document: `{"id": 5, "title": "Twin"}`}}}); err == nil {
		t.Error("inserting an id that exists should be refused")
	}
	if _, err := ed.Edit(ctx, EditRequest{Table: "explore_test", Changes: []RowChange{{Op: "update", Key: map[string]*string{"id": ptr("6")}, Document: `{"id": 7}`}}}); err == nil {
		t.Error("an update that changes the key should be refused")
	}
	if _, err := ed.Edit(ctx, EditRequest{Table: "explore_test", Changes: []RowChange{{Op: "delete", Key: map[string]*string{"id": ptr("9999")}}}}); err == nil {
		t.Error("deleting a missing document should be refused")
	}
	r, err := ed.Edit(ctx, EditRequest{Table: "explore_test", Changes: []RowChange{
		{Op: "insert", Document: `{"id": 100, "title": "New one", "genre": "drama"}`},
		{Op: "update", Key: map[string]*string{"id": ptr("2")}, Document: `{"id": 2, "title": "Changed", "genre": "comedy"}`},
		{Op: "delete", Key: map[string]*string{"id": ptr("3")}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Ran || r.Affected != 3 {
		t.Errorf("edit: %+v", r)
	}
	page, err = c.Rows(ctx, RowsRequest{Table: "explore_test", Filters: []RowFilter{{Column: "id", Op: "in", Values: []string{"2", "3", "100"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if *page.Total != 2 {
		t.Fatalf("after the edit: %+v", page.Rows)
	}
	for i, row := range page.Rows {
		if *row[0] == "2" && !strings.Contains(page.Documents[i], "Changed") || strings.Contains(page.Documents[i], "Film 2 ") {
			t.Errorf("document 2 wasn't replaced: %s", page.Documents[i])
		}
	}
}
