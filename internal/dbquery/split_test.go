package dbquery

import (
	"encoding/json"
	"testing"

	"github.com/morche/backend/internal/dbmon"
)

func TestSplit(t *testing.T) {
	cases := []struct {
		engine, in string
		want       int
	}{
		{dbmon.Postgres, "select 1; select 2;", 2},
		{dbmon.Postgres, "select ';'; -- a ; comment\nselect 2", 2},
		{dbmon.Postgres, "create function f() returns int as $$ select 1; $$ language sql; select 2", 2},
		{dbmon.Postgres, "select $1::int; /* x; /* nested; */ y; */ select 2", 2},
		{dbmon.MySQL, "select 'it\\'s; ok'; select `a;b` from t # c;\n", 2},
		{dbmon.MSSQL, "select 1\nGO\nselect [a;b] from t\n go \n", 2},
		{dbmon.Postgres, "-- only a comment", 0},
	}
	for _, c := range cases {
		if got := Split(c.engine, c.in); len(got) != c.want {
			t.Errorf("%s %q: got %d %q, want %d", c.engine, c.in, len(got), got, c.want)
		}
	}
}

func TestCheckRead(t *testing.T) {
	ok := []struct{ engine, q string }{
		{dbmon.Postgres, "select * from users where name = 'drop table'"},
		{dbmon.Postgres, "with x as (select 1) select * from x"},
		{dbmon.MySQL, "show tables"},
		{dbmon.MSSQL, "select [update] from t"},
		{dbmon.Postgres, "/* hi */ explain select 1"},
	}
	for _, c := range ok {
		if err := checkRead(c.engine, c.q); err != nil {
			t.Errorf("%s %q refused: %v", c.engine, c.q, err)
		}
	}
	bad := []struct{ engine, q string }{
		{dbmon.Postgres, "delete from users"},
		{dbmon.Postgres, "set role admin"},
		{dbmon.MySQL, "select * from t into outfile '/tmp/x'"},
		{dbmon.MySQL, "drop table t"},
		{dbmon.MSSQL, "select 1 drop table t"},
		{dbmon.MSSQL, "select * into copy from t"},
		{dbmon.MSSQL, "exec xp_cmdshell 'dir'"},
	}
	for _, c := range bad {
		if err := checkRead(c.engine, c.q); err == nil {
			t.Errorf("%s %q allowed", c.engine, c.q)
		}
	}
}

func TestRisks(t *testing.T) {
	if r := Risks(dbmon.Postgres, "delete from users"); len(r) != 1 {
		t.Errorf("delete without where: %v", r)
	}
	if r := Risks(dbmon.Postgres, "delete from users where id = 1; update t set a = 1 where b = 2"); len(r) != 0 {
		t.Errorf("safe script: %v", r)
	}
	if r := Risks(dbmon.MySQL, "DROP TABLE x"); len(r) != 1 {
		t.Errorf("drop: %v", r)
	}
	if r := Risks(dbmon.Redis, "set a 1\nflushdb"); len(r) != 1 {
		t.Errorf("redis: %v", r)
	}
	if r := Risks(dbmon.Mongo, `db.users.deleteMany({})`); len(r) != 1 {
		t.Errorf("mongo: %v", r)
	}
}

func TestShellCall(t *testing.T) {
	j, err := shellCall(`db.users.find({age: {$gt: 30}, name: 'Ann', _id: ObjectId("507f1f77bcf86cd799439011")}).sort({age: -1}).limit(5)`)
	if err != nil {
		t.Fatal(err)
	}
	var q mongoQuery
	if err := json.Unmarshal([]byte(j), &q); err != nil {
		t.Fatalf("%s: %v", j, err)
	}
	if q.Collection != "users" || q.Limit != 5 || q.kind() != "find" || q.Sort == nil {
		t.Errorf("got %+v from %s", q, j)
	}
	if _, err := readMongoQuery(`db.getCollection("a.b").aggregate([{$match: {x: 1}}])`); err != nil {
		t.Error(err)
	}
	if q, err := readMongoQuery(`{"collection": "c", "count": {}}`); err != nil || q.kind() != "count" {
		t.Error(q, err)
	}
}

func TestRedisLines(t *testing.T) {
	got := redisLines("SET \"a b\" 'c d'\n# note\nGET x")
	if len(got) != 2 || got[0][1] != "a b" || got[0][2] != "c d" {
		t.Errorf("%q", got)
	}
}

func TestClickHouseSplitAndRead(t *testing.T) {
	if got := Split(dbmon.ClickHouse, "select 'a\\';b'; select `x;y`, \"p;q\" from t # c;\n/* a /* b; */ c; */ select 3; select 4"); len(got) != 3 {
		t.Errorf("split: %q", got)
	}
	for _, q := range []string{"select * from t", "exists table t", "explain select 1", "select `file` from t", "select 'from url(' from t"} {
		if err := checkRead(dbmon.ClickHouse, q); err != nil {
			t.Errorf("%q refused: %v", q, err)
		}
	}
	for _, q := range []string{"insert into t values (1)", "optimize table t", "select * from url('http://x', CSV)", "select 1 from t, /**/ remote('h', db.t)", "select 1 into outfile 'x'", "set readonly = 0"} {
		if err := checkRead(dbmon.ClickHouse, q); err == nil {
			t.Errorf("%q allowed", q)
		}
	}
}
