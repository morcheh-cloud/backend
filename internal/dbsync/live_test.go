package dbsync

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"

	"github.com/morche/backend/internal/dbmon"
)

// Runs against the dev compose's test databases: DBSYNC_LIVE=1 go test ./internal/dbsync
func open(t *testing.T, engine string, port int, db string) Side {
	user := "ant"
	if engine == dbmon.MySQL {
		user = "root"
	}
	h, err := dbmon.OpenSQL(context.Background(), dbmon.Config{Engine: engine, Host: "127.0.0.1", Port: port, Username: user, Password: "colony", Dial: dbmon.DirectDialer(true)}, db, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	d := Postgres
	switch engine {
	case dbmon.MySQL:
		d = MySQL
	case dbmon.ClickHouse:
		d = ClickHouse
	}
	return Side{DB: h, Dialect: d, Database: db}
}

func show(t *testing.T, res []TableResult, err error) {
	t.Helper()
	for _, r := range res {
		r.Samples = r.Samples[:min(len(r.Samples), 3)]
		b, _ := json.Marshal(r)
		t.Logf("%s", b)
	}
	if err != nil {
		t.Logf("ERR %v", err)
	}
}

func TestLivePostgres(t *testing.T) {
	if os.Getenv("DBSYNC_LIVE") == "" {
		t.Skip()
	}
	ctx := context.Background()
	src, dst := open(t, dbmon.Postgres, 5434, "sync_a"), open(t, dbmon.Postgres, 5434, "sync_b")
	tables, err := Tables(ctx, src.DB, Postgres, "")
	if err != nil {
		t.Fatal(err)
	}
	var pairs []Pair
	for _, tb := range tables {
		t.Logf("%s key=%v from=%s rows=%d cols=%d", tb.Ref, tb.Key, tb.KeyFrom, tb.Rows, len(tb.Columns))
		pairs = append(pairs, Pair{From: tb.Ref, To: tb.Ref})
	}
	rules := Rules{Insert: true, Delete: true, Conflict: Overwrite, OnError: SkipRow, Create: true, NoKey: "reload", PauseChecks: true, Batch: 200}
	r := &Run{Src: src, Dst: dst, Rules: rules, DryRun: true}
	func() { res, err := r.Do(ctx, pairs); show(t, res, err) }()
	r = &Run{Src: src, Dst: dst, Rules: rules}
	func() { res, err := r.Do(ctx, pairs); show(t, res, err) }()
	t.Log("notes", r.Notes())
	r = &Run{Src: src, Dst: dst, Rules: rules, DryRun: true}
	res, err := r.Do(ctx, pairs)
	show(t, res, err)
	for _, x := range res {
		if x.Written() != 0 && !x.Reloaded {
			t.Errorf("%s still differs: %+v", x.From, x.Samples)
		}
	}
	// Incremental.
	src.DB.ExecContext(ctx, "UPDATE customers SET name = 'changed', updated_at = now() WHERE id IN (3, 4)")
	r = &Run{Src: src, Dst: dst, Rules: rules, Incremental: true, Marks: map[string]Mark{}}
	res, err = r.Do(ctx, []Pair{{From: Ref{"public", "customers"}, To: Ref{"public", "customers"}, Track: "updated_at"}})
	show(t, res, err)
	marks := map[string]Mark{"public.customers": *res[0].Mark}
	src.DB.ExecContext(ctx, "UPDATE customers SET name = 'again', updated_at = now() WHERE id = 7")
	r = &Run{Src: src, Dst: dst, Rules: rules, Incremental: true, Marks: marks}
	func() {
		res, err := r.Do(ctx, []Pair{{From: Ref{"public", "customers"}, To: Ref{"public", "customers"}, Track: "updated_at"}})
		show(t, res, err)
	}()
}

func TestLiveMySQL(t *testing.T) {
	if os.Getenv("DBSYNC_LIVE") == "" {
		t.Skip()
	}
	ctx := context.Background()
	for _, port := range []int{3307, 3308} {
		src, dst := open(t, dbmon.MySQL, port, "sync_a"), open(t, dbmon.MySQL, port, "sync_b")
		tables, err := Tables(ctx, src.DB, MySQL, "sync_a")
		if err != nil {
			t.Fatal(err)
		}
		var pairs []Pair
		for _, tb := range tables {
			t.Logf("%s key=%v rows=%d cols=%+v", tb.Ref, tb.Key, tb.Rows, tb.Columns)
			pairs = append(pairs, Pair{From: tb.Ref, To: tb.Ref})
		}
		rules := Rules{Insert: true, Delete: true, Conflict: Overwrite, OnError: SkipRow, Create: true, PauseChecks: true, Batch: 300}
		r := &Run{Src: src, Dst: dst, Rules: rules}
		func() { res, err := r.Do(ctx, pairs); show(t, res, err) }()
		r = &Run{Src: src, Dst: dst, Rules: rules, DryRun: true}
		res, err := r.Do(ctx, pairs)
		show(t, res, err)
		for _, x := range res {
			if x.Written() != 0 {
				t.Errorf("%d %s still differs: %+v", port, x.From, x.Samples)
			}
		}
	}
}

// ---- ClickHouse (test-clickhouse on :9002, test-postgres on :5434) ----

func mustExec(t *testing.T, db *sql.DB, stmts ...string) {
	t.Helper()
	for _, q := range stmts {
		if _, err := db.ExecContext(context.Background(), q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func count(t *testing.T, db *sql.DB, q string) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRowContext(context.Background(), q).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// same runs a Compare and fails when anything still differs.
func same(t *testing.T, src, dst Side, rules Rules, pairs []Pair) {
	t.Helper()
	r := &Run{Src: src, Dst: dst, Rules: rules, DryRun: true}
	res, err := r.Do(context.Background(), pairs)
	show(t, res, err)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range res {
		if x.State != "done" || (x.Written() != 0 && !x.Reloaded) {
			t.Errorf("%s still differs (%s %s): %+v", x.From, x.State, x.Error, x.Samples)
		}
	}
}

func run(t *testing.T, r *Run, pairs []Pair) []TableResult {
	t.Helper()
	res, err := r.Do(context.Background(), pairs)
	show(t, res, err)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range res {
		if x.State != "done" || x.Failed > 0 {
			t.Errorf("%s: %s %s %+v", x.From, x.State, x.Error, x.Failures)
		}
	}
	return res
}

func pairsOf(tables []Table) []Pair {
	var out []Pair
	for _, tb := range tables {
		out = append(out, Pair{From: tb.Ref, To: tb.Ref})
	}
	return out
}

func TestLiveClickHouse(t *testing.T) {
	if os.Getenv("DBSYNC_LIVE") == "" {
		t.Skip()
	}
	ctx := context.Background()
	admin := open(t, dbmon.ClickHouse, 9002, "default")
	mustExec(t, admin.DB,
		"DROP DATABASE IF EXISTS sync_src SYNC", "DROP DATABASE IF EXISTS sync_dst SYNC",
		"CREATE DATABASE sync_src", "CREATE DATABASE sync_dst",
		`CREATE TABLE sync_src.events (id UInt64, name String, amount Decimal(10, 2), at DateTime64(6, 'UTC'),
			flag Bool, uid UUID, note Nullable(String), tags Array(String), big Int128)
			ENGINE = ReplacingMergeTree ORDER BY id`,
		`INSERT INTO sync_src.events SELECT number, concat('e', toString(number)), number / 4, toDateTime64('2026-01-01 00:00:00', 6, 'UTC') + number,
			number % 2 = 0, generateUUIDv4(), if(number % 3 = 0, NULL, 'n'), ['a'], number * 1000000000000 FROM numbers(12000)`,
		`CREATE TABLE sync_src.logs (msg String, n Int32) ENGINE = MergeTree ORDER BY tuple()`,
		`INSERT INTO sync_src.logs SELECT toString(number), number FROM numbers(300)`,
	)
	src, dst := open(t, dbmon.ClickHouse, 9002, "sync_src"), open(t, dbmon.ClickHouse, 9002, "sync_dst")
	tables, err := Tables(ctx, src.DB, ClickHouse, "sync_src")
	if err != nil {
		t.Fatal(err)
	}
	for _, tb := range tables {
		t.Logf("%s engine=%s key=%v from=%s sorting=%v rows=%d cols=%+v", tb.Ref, tb.Engine, tb.Key, tb.KeyFrom, tb.Sorting, tb.Rows, tb.Columns)
	}
	pairs := pairsOf(tables)
	rules := Rules{Insert: true, Delete: true, Conflict: Overwrite, OnError: SkipRow, Create: true, NoKey: "reload"}

	r := &Run{Src: src, Dst: dst, Rules: rules, DryRun: true}
	func() { res, err := r.Do(ctx, pairs); show(t, res, err) }()
	run(t, &Run{Src: src, Dst: dst, Rules: rules}, pairs)
	if n := count(t, dst.DB, "SELECT toInt64(count()) FROM events"); n != 12000 {
		t.Fatalf("events: %d rows", n)
	}
	same(t, src, dst, rules, pairs)

	// Changes on the source: one new, one changed, one gone.
	mustExec(t, src.DB,
		`INSERT INTO events (id, name, amount, at, flag, uid, tags, big) VALUES (20000, 'new', 1.5, '2026-02-01 00:00:00', true, generateUUIDv4(), ['x'], 1)`,
		`INSERT INTO events SELECT id, 'changed', amount, at, flag, uid, note, tags, big FROM events FINAL WHERE id = 5`,
		`DELETE FROM events WHERE id = 7`,
		`INSERT INTO logs VALUES ('more', 1)`,
	)
	res := run(t, &Run{Src: src, Dst: dst, Rules: rules}, pairs)
	if e := res[0]; e.Inserted != 1 || e.Updated != 1 || e.Deleted != 1 {
		t.Errorf("events: %+v", e)
	}
	same(t, src, dst, rules, pairs)
	var name string
	dst.DB.QueryRowContext(ctx, "SELECT name FROM events FINAL WHERE id = 5").Scan(&name)
	if name != "changed" {
		t.Errorf("id 5 = %q", name)
	}

	// Incremental by the time column.
	inc := []Pair{{From: Ref{Name: "events"}, To: Ref{Name: "events"}, Track: "at"}}
	r = &Run{Src: src, Dst: dst, Rules: rules, Incremental: true, Marks: map[string]Mark{}}
	res = run(t, r, inc)
	marks := map[string]Mark{"events": *res[0].Mark}
	mustExec(t, src.DB, `INSERT INTO events SELECT id, 'later', amount, toDateTime64('2026-03-01 00:00:00', 6, 'UTC'), flag, uid, note, tags, big FROM events FINAL WHERE id IN (1, 2)`)
	res = run(t, &Run{Src: src, Dst: dst, Rules: rules, Incremental: true, Marks: marks}, inc)
	if res[0].Read != 2 || res[0].Updated != 2 {
		t.Errorf("incremental: %+v", res[0])
	}
	same(t, src, dst, rules, pairs)
}

func TestLivePostgresToClickHouse(t *testing.T) {
	if os.Getenv("DBSYNC_LIVE") == "" {
		t.Skip()
	}
	ctx := context.Background()
	pg := open(t, dbmon.Postgres, 5434, "postgres")
	mustExec(t, pg.DB, "DROP DATABASE IF EXISTS sync_ch_src WITH (FORCE)", "CREATE DATABASE sync_ch_src")
	admin := open(t, dbmon.ClickHouse, 9002, "default")
	mustExec(t, admin.DB, "DROP DATABASE IF EXISTS sync_dst_pg SYNC", "CREATE DATABASE sync_dst_pg")
	src := open(t, dbmon.Postgres, 5434, "sync_ch_src")
	mustExec(t, src.DB,
		`CREATE TABLE customers (id serial PRIMARY KEY, name text NOT NULL, balance numeric(12, 2), active boolean,
			created timestamptz, born date, uid uuid, data jsonb, raw bytea, score double precision, small smallint,
			updated_at timestamptz NOT NULL DEFAULT now(), tags text[])`,
		`INSERT INTO customers (name, balance, active, created, born, uid, data, raw, score, small, updated_at, tags)
			SELECT 'c' || g, g * 1.10, g % 2 = 0, '2026-01-01 10:00:00.123456+03:30'::timestamptz + g * interval '1 minute', date '2000-01-01' + g,
				md5(g::text)::uuid, jsonb_build_object('g', g), decode(lpad(to_hex(g), 4, '0'), 'hex'), g / 3.0, g % 100,
				'2026-01-01'::timestamptz + g * interval '1 second', ARRAY['a', 'b']
			FROM generate_series(1, 7000) g`,
		`CREATE TABLE notes (body text, n int)`,
		`INSERT INTO notes SELECT 'n' || g, g FROM generate_series(1, 50) g`,
	)
	dst := open(t, dbmon.ClickHouse, 9002, "sync_dst_pg")
	tables, err := Tables(ctx, src.DB, Postgres, "")
	if err != nil {
		t.Fatal(err)
	}
	pairs := pairsOf(tables)
	rules := Rules{Insert: true, Delete: true, Conflict: Overwrite, OnError: SkipRow, Create: true, NoKey: "reload"}
	r := &Run{Src: src, Dst: dst, Rules: rules, DryRun: true}
	func() { res, err := r.Do(ctx, pairs); show(t, res, err) }()
	run(t, &Run{Src: src, Dst: dst, Rules: rules}, pairs)
	var create string
	dst.DB.QueryRowContext(ctx, "SHOW CREATE TABLE customers").Scan(&create)
	t.Log(create)
	if n := count(t, dst.DB, "SELECT toInt64(count()) FROM customers"); n != 7000 {
		t.Fatalf("customers: %d rows", n)
	}
	same(t, src, dst, rules, pairs)

	mustExec(t, src.DB,
		`UPDATE customers SET name = 'changed', balance = 99.90, updated_at = now() WHERE id IN (3, 4)`,
		`DELETE FROM customers WHERE id = 10`,
		`INSERT INTO customers (name, updated_at) VALUES ('fresh', now())`,
	)
	res := run(t, &Run{Src: src, Dst: dst, Rules: rules}, pairs)
	if c := res[0]; c.Inserted != 1 || c.Updated != 2 || c.Deleted != 1 {
		t.Errorf("customers: %+v", c)
	}
	same(t, src, dst, rules, pairs)

	inc := []Pair{{From: Ref{"public", "customers"}, To: Ref{Name: "customers"}, Track: "updated_at"}}
	incRules := rules
	incRules.Lookback = 0
	res = run(t, &Run{Src: src, Dst: dst, Rules: incRules, Incremental: true, Marks: map[string]Mark{}}, inc)
	marks := map[string]Mark{"public.customers": *res[0].Mark}
	mustExec(t, src.DB, `UPDATE customers SET name = 'again', updated_at = now() + interval '1 hour' WHERE id = 7`)
	res = run(t, &Run{Src: src, Dst: dst, Rules: incRules, Incremental: true, Marks: marks}, inc)
	if res[0].Read != 1 || res[0].Updated != 1 {
		t.Errorf("incremental: %+v", res[0])
	}
	same(t, src, dst, rules, pairs)
}

func TestLiveMySQLToClickHouse(t *testing.T) {
	if os.Getenv("DBSYNC_LIVE") == "" {
		t.Skip()
	}
	my := open(t, dbmon.MySQL, 3307, "mysql")
	mustExec(t, my.DB, "DROP DATABASE IF EXISTS sync_ch_my", "CREATE DATABASE sync_ch_my")
	admin := open(t, dbmon.ClickHouse, 9002, "default")
	mustExec(t, admin.DB, "DROP DATABASE IF EXISTS sync_dst_my SYNC", "CREATE DATABASE sync_dst_my")
	src := open(t, dbmon.MySQL, 3307, "sync_ch_my")
	mustExec(t, src.DB,
		`CREATE TABLE orders (id bigint unsigned AUTO_INCREMENT PRIMARY KEY, code varchar(20) NOT NULL, paid tinyint(1),
			total decimal(10, 2), at datetime(6), day date, kind enum('a', 'b'), bin varbinary(8), ratio float, yr year)`,
		`INSERT INTO orders (code, paid, total, at, day, kind, bin, ratio, yr) VALUES
			('x1', 1, 10.50, '2026-01-01 10:00:00.5', '2026-01-01', 'a', x'00ff', 0.5, 2026),
			('x2', 0, 3.00, NULL, NULL, 'b', NULL, 1.25, NULL)`,
	)
	dst := open(t, dbmon.ClickHouse, 9002, "sync_dst_my")
	pairs := []Pair{{From: Ref{Name: "orders"}, To: Ref{Name: "orders"}}}
	rules := Rules{Insert: true, Delete: true, Conflict: Overwrite, OnError: SkipRow, Create: true}
	run(t, &Run{Src: src, Dst: dst, Rules: rules}, pairs)
	same(t, src, dst, rules, pairs)
	mustExec(t, src.DB, `UPDATE orders SET total = 11.00 WHERE id = 1`, `DELETE FROM orders WHERE id = 2`)
	res := run(t, &Run{Src: src, Dst: dst, Rules: rules}, pairs)
	if res[0].Updated != 1 || res[0].Deleted != 1 {
		t.Errorf("orders: %+v", res[0])
	}
	same(t, src, dst, rules, pairs)
}
