package dbsync

import (
	"context"
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
	if engine == dbmon.MySQL {
		d = MySQL
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
	func() { res, err := r.Do(ctx, []Pair{{From: Ref{"public", "customers"}, To: Ref{"public", "customers"}, Track: "updated_at"}}); show(t, res, err) }()
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
