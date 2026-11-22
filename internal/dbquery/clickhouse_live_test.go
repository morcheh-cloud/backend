//go:build dbquerylive

package dbquery

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/morche/backend/internal/dbmon"
)

// Runs against the compose service test-clickhouse:
// go test -tags dbquerylive -run ClickHouse ./internal/dbquery
func TestClickHouseLive(t *testing.T) {
	setup := `DROP DATABASE IF EXISTS explore_test;
CREATE DATABASE explore_test;
CREATE TABLE explore_test.items (
  id UInt64, name String, price Decimal(10, 2), at DateTime64(3), tags Array(String),
  attrs Map(String, UInt8), pair Tuple(String, Int32), kind LowCardinality(String), note Nullable(String),
  uid UUID, ip IPv4, state Enum8('new' = 1, 'old' = 2), doc JSON, big UInt256,
  total Float64 MATERIALIZED price * 2,
  INDEX name_idx name TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree PARTITION BY toYYYYMM(at) ORDER BY id TTL toDateTime(at) + INTERVAL 10 YEAR COMMENT 'things';
INSERT INTO explore_test.items (id, name, price, at, tags, attrs, pair, kind, note, uid, ip, state, doc, big) VALUES
 (1, 'apple', 1.50, '2024-01-02 03:04:05.123', ['red','sweet'], {'a':1}, ('x', -1), 'fruit', NULL, '6d1b1b1e-8f2b-4f53-9a3e-0e6c4b1d7a10', '10.0.0.1', 'new', '{"a":{"b":1}}', 123456789012345678901234567890),
 (2, 'pear', 2.25, '2024-02-02 00:00:00', ['green'], {}, ('y', 2), 'fruit', 'it\'s ripe', '6d1b1b1e-8f2b-4f53-9a3e-0e6c4b1d7a11', '10.0.0.2', 'old', '{}', 2),
 (3, 'leek', 0.75, '2024-02-03 00:00:00', [], {}, ('z', 3), 'veg', NULL, '6d1b1b1e-8f2b-4f53-9a3e-0e6c4b1d7a12', '10.0.0.3', 'new', '{}', 3),
 (3, 'leek twin', 0.75, '2024-02-03 00:00:00', [], {}, ('z', 3), 'veg', NULL, '6d1b1b1e-8f2b-4f53-9a3e-0e6c4b1d7a12', '10.0.0.3', 'new', '{}', 3);
CREATE TABLE explore_test.log (a UInt8) ENGINE = Log;
CREATE VIEW explore_test.cheap AS SELECT id, name FROM explore_test.items WHERE price < 2;`
	cmd := exec.Command("docker", "exec", "-i", "morche-test-clickhouse-1", "clickhouse-client", "-u", "ant", "--password", "colony", "-n")
	cmd.Stdin = strings.NewReader(setup)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("setup: %v %s", err, b)
	}
	ctx := context.Background()
	cfg := dbmon.Config{Engine: dbmon.ClickHouse, Host: "127.0.0.1", Port: 9002, Username: "ant", Password: "colony", Database: "shop", Dial: dbmon.DirectDialer(true)}
	c, err := Open(ctx, cfg, "explore_test")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	o, err := c.Overview(ctx, "explore_test")
	if err != nil {
		t.Fatal(err)
	}
	if o.Database != "explore_test" || len(o.Objects) != 3 {
		t.Fatalf("overview: %+v", o)
	}
	if last := o.Databases[len(o.Databases)-1]; !chSystem[last] {
		t.Errorf("system databases should come last: %v", o.Databases)
	}
	kinds := map[string]string{}
	for _, ob := range o.Objects {
		kinds[ob.Name] = ob.Kind
	}
	if kinds["items"] != "table" || kinds["cheap"] != "view" {
		t.Errorf("kinds: %v", kinds)
	}

	info, err := c.Describe(ctx, "explore_test", "", "items")
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Key) != 1 || info.Key[0] != "id" || info.ReadOnly != "" || !strings.Contains(info.Definition, "CREATE TABLE") {
		t.Fatalf("describe: key %v ro %q", info.Key, info.ReadOnly)
	}
	facts := map[string]string{}
	for _, f := range info.Facts {
		facts[f.Label] = f.Value
	}
	if facts["Engine"] != "MergeTree" || facts["Partition key"] == "" || facts["TTL"] == "" || facts["Rows"] != "4" {
		t.Errorf("facts: %v", facts)
	}
	for _, col := range info.Columns {
		if col.Name == "note" && !col.Nullable || col.Name == "total" && col.Extra != "materialized" {
			t.Errorf("column %+v", col)
		}
	}
	if len(info.Indexes) != 2 {
		t.Errorf("indexes: %+v", info.Indexes)
	}
	if li, err := c.Describe(ctx, "explore_test", "", "log"); err != nil || li.ReadOnly == "" {
		t.Errorf("log table should be read only: %+v %v", li, err)
	}

	page, err := c.Rows(ctx, RowsRequest{Database: "explore_test", Table: "items",
		Filters: []RowFilter{{Column: "kind", Op: "eq", Value: "fruit"}, {Column: "at", Op: "gte", Value: "2024-01-01 00:00:00"}},
		Sort:    []RowSort{{Column: "id", Desc: true}}, Count: true, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 1 || !page.Truncated || page.Total == nil || *page.Total != 2 {
		t.Fatalf("rows: %+v", page)
	}
	row := map[string]*string{}
	for i, col := range page.Columns {
		row[col.Name] = page.Rows[0][i]
	}
	if *row["id"] != "2" || *row["note"] != "it's ripe" || *row["tags"] != "['green']" || *row["price"] != "2.25" {
		t.Errorf("row: id %s note %s tags %s price %s", *row["id"], *row["note"], *row["tags"], *row["price"])
	}
	if search, err := c.Rows(ctx, RowsRequest{Database: "explore_test", Table: "items", Search: "SWEET", Count: true}); err != nil || len(search.Rows) != 1 {
		t.Errorf("search: %+v %v", search, err)
	}
	if _, err := c.Rows(ctx, RowsRequest{Database: "explore_test", Table: "items", Where: "id IN (SELECT a FROM file('x', CSV, 'a UInt8'))"}); err == nil {
		t.Errorf("file() in a condition should be refused")
	}

	ro := RunOptions{Limit: 100, Timeout: 20 * time.Second}
	res, err := c.Run(ctx, "explore_test", "SELECT * FROM items ORDER BY id; # comment\nSELECT `name` FROM items WHERE name = 'it\\'s; not' -- ;", ro)
	if err != nil || len(res) != 2 || len(res[0].Rows) != 4 {
		t.Fatalf("read: %v %+v", err, res)
	}
	var rf *ErrRefused
	if _, err := c.Run(ctx, "explore_test", "INSERT INTO items (id, name) VALUES (9, 'x')", ro); !errors.As(err, &rf) {
		t.Errorf("insert in read mode: %v", err)
	}
	if _, err := c.Run(ctx, "explore_test", "SELECT * FROM items SETTINGS readonly = 0", ro); err == nil {
		t.Errorf("readonly = 0 should be refused")
	}
	ro.Change = true
	res, err = c.Run(ctx, "explore_test", "INSERT INTO items (id, name, at) VALUES (9, 'nine', now()); SELECT count() FROM items", ro)
	if err != nil || len(res) != 2 || *res[1].Rows[0][0] != "5" {
		t.Fatalf("change: %v %+v", err, res)
	}

	// Stop: the context ends, the server stops the query.
	sctx, stop := context.WithTimeout(ctx, 500*time.Millisecond)
	_, err = c.Run(sctx, "explore_test", "SELECT count() FROM numbers(1000000000000) WHERE sipHash64(number) = 1", RunOptions{Limit: 10, Timeout: time.Minute})
	stop()
	if err == nil {
		t.Fatal("a stopped query should fail")
	}
	time.Sleep(time.Second)
	left, err := c.Run(ctx, "explore_test", "SELECT count() FROM system.processes WHERE query LIKE '%sipHash64(number) = 1%' AND query NOT LIKE '%system.processes%'", RunOptions{Limit: 10, Timeout: 10 * time.Second})
	if err != nil || *left[0].Rows[0][0] != "0" {
		t.Errorf("the stopped query still runs: %v %+v", err, left)
	}

	e := c.(Editor)
	prev, err := e.Edit(ctx, EditRequest{Database: "explore_test", Table: "items", Preview: true, Changes: []RowChange{
		{Op: "update", Key: map[string]*string{"id": ptr("1")}, Values: map[string]*string{"name": ptr("apple's"), "tags": ptr("['a','b']")}},
	}})
	if err != nil || len(prev.Statements) != 1 || !strings.HasPrefix(prev.Statements[0], "ALTER TABLE `explore_test`.`items` UPDATE") || prev.Ran {
		t.Fatalf("preview: %v %+v", err, prev)
	}
	if _, err := e.Edit(ctx, EditRequest{Database: "explore_test", Table: "items", Changes: []RowChange{
		{Op: "update", Key: map[string]*string{"id": ptr("3")}, Values: map[string]*string{"name": ptr("x")}},
	}}); !errors.As(err, &rf) || !strings.Contains(err.Error(), "share its key") {
		t.Errorf("duplicate key: %v", err)
	}
	if _, err := e.Edit(ctx, EditRequest{Database: "explore_test", Table: "items", Changes: []RowChange{
		{Op: "update", Key: map[string]*string{"id": ptr("1")}, Values: map[string]*string{"id": ptr("7")}},
	}}); !errors.As(err, &rf) {
		t.Errorf("updating the sorting key: %v", err)
	}
	if _, err := e.Edit(ctx, EditRequest{Database: "explore_test", Table: "log", Changes: []RowChange{{Op: "insert", Values: map[string]*string{"a": ptr("1")}}}}); !errors.As(err, &rf) {
		t.Errorf("log table edit: %v", err)
	}
	done, err := e.Edit(ctx, EditRequest{Database: "explore_test", Table: "items", Changes: []RowChange{
		{Op: "insert", Values: map[string]*string{"id": ptr("10"), "name": ptr("fig"), "tags": ptr("['x','y\\'z']"), "note": nil, "at": ptr("2024-03-01 10:00:00.5")}},
		{Op: "update", Key: map[string]*string{"id": ptr("1")}, Values: map[string]*string{"name": ptr("apple's"), "tags": ptr("['a','b']"), "note": ptr("n")}},
		{Op: "delete", Key: map[string]*string{"id": ptr("2")}},
	}})
	if err != nil || !done.Ran || done.Affected != 3 {
		t.Fatalf("edit: %v %+v", err, done)
	}
	check, err := c.Run(ctx, "explore_test", "SELECT name, tags, note FROM items WHERE id IN (1, 2, 10) ORDER BY id", RunOptions{Limit: 10, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	got := check[0].Rows
	if len(got) != 2 || *got[0][0] != "apple's" || *got[0][1] != `["a","b"]` || *got[1][0] != "fig" || *got[1][1] != `["x","y'z"]` || got[1][2] != nil {
		for _, r := range got {
			for _, v := range r {
				if v != nil {
					t.Logf("%s", *v)
				}
			}
		}
		t.Fatalf("after edit: %d rows", len(got))
	}
}
