package dbbackup

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/morche/backend/internal/dbmon"
)

func gz(s []byte) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(s)
	w.Close()
	return b.Bytes()
}

const pgDump = "--\n-- PostgreSQL database dump\n--\n\\restrict abc\nSET statement_timeout = 0;\nSET transaction_timeout = 0;\nCREATE TABLE public.t (a text);\nALTER TABLE public.t OWNER TO bob;\nCOPY public.t (a) FROM stdin;\n\\restrict inside\nALTER TABLE x OWNER TO y;\n\\.\nGRANT ALL ON TABLE public.t TO bob;\n\\unrestrict abc\n--\n-- PostgreSQL database dump complete\n--\n"

func TestSniff(t *testing.T) {
	mysql := "-- MySQL dump 10.13\n-- Host: x\nCREATE DATABASE `shop`;\nUSE `shop`;\nINSERT INTO a VALUES (1);\n-- Dump completed on 2026\n"
	cases := []struct {
		name, engine string
		data         []byte
		format       string
		gzip         bool
		problem      bool
		dbs          []string
	}{
		{"pg custom", dbmon.Postgres, []byte("PGDMP\x01\x0e"), PgCustom, false, false, nil},
		{"pg sql gz", dbmon.Postgres, gz([]byte(pgDump)), PgSQL, true, false, nil},
		{"pg create", dbmon.Postgres, []byte("-- PostgreSQL database dump\nCREATE DATABASE x;\n\\connect x\n"), PgSQL, false, true, nil},
		{"pg all", dbmon.Postgres, []byte("--\n-- PostgreSQL database cluster dump\n--\n"), PgAll, false, true, nil},
		{"mysql use", dbmon.MySQL, []byte(mysql), MySQLSQL, false, false, []string{"shop"}},
		{"mysql plain", dbmon.MySQL, []byte("CREATE TABLE a (b int);\n"), MySQLDB, false, false, nil},
		{"mysql two", dbmon.MySQL, []byte("USE `a`;\nUSE `b`;\n"), MySQLSQL, false, true, []string{"a", "b"}},
		{"bak", dbmon.MSSQL, []byte("TAPE\x00\x00"), MSSQLBak, false, false, nil},
		{"rdb", dbmon.Redis, []byte("REDIS0011"), RedisRDB, false, true, nil},
		{"binary", dbmon.Postgres, []byte{0, 1, 2, 3}, "", false, true, nil},
		{"empty", dbmon.Postgres, nil, "", false, true, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := Sniff(bytes.NewReader(c.data), c.engine)
			if err != nil {
				t.Fatal(err)
			}
			if s.Format != c.format || s.Gzip != c.gzip || (s.Problem != "") != c.problem || strings.Join(s.Databases, ",") != strings.Join(c.dbs, ",") {
				t.Fatalf("got %+v", s)
			}
		})
	}
}

func mongoArchive(t *testing.T, gzipped bool) []byte {
	doc := func(v any) []byte {
		b, err := bson.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	end := binary.LittleEndian.AppendUint32(nil, 0xffffffff)
	var b bytes.Buffer
	b.Write(mongoMagic)
	b.Write(doc(bson.M{"concurrent_collections": 4, "version": "0.1"}))
	b.Write(doc(bson.M{"db": "shop", "collection": "orders", "metadata": "{}"}))
	b.Write(doc(bson.M{"db": "app", "collection": "users", "metadata": "{}"}))
	b.Write(end)
	b.Write(doc(bson.M{"db": "shop", "collection": "orders"}))
	if gzipped {
		b.Write(gz(doc(bson.M{"a": 1})))
	} else {
		b.Write(doc(bson.M{"a": 1}))
	}
	return b.Bytes()
}

func TestSniffMongo(t *testing.T) {
	for _, zipped := range []bool{true, false} {
		s, err := Sniff(bytes.NewReader(gz(mongoArchive(t, zipped))), dbmon.Mongo)
		if err != nil {
			t.Fatal(err)
		}
		if s.Format != MongoArchive || !s.Gzip || s.MongoGzip != zipped || strings.Join(s.Databases, ",") != "app,shop" {
			t.Fatalf("zipped=%v: %+v", zipped, s)
		}
	}
}

func TestCheckFile(t *testing.T) {
	c, err := CheckFile(bytes.NewReader(gz([]byte(pgDump))), dbmon.Postgres)
	if err != nil || c.Problem != "" || c.Format != PgSQL || c.Bytes == 0 || c.SHA256 == "" {
		t.Fatalf("%+v %v", c, err)
	}
	cut := pgDump[:len(pgDump)-30]
	if c, _ := CheckFile(strings.NewReader(cut), dbmon.Postgres); c.Problem == "" {
		t.Fatal("cut dump passed")
	}
	broken := gz([]byte(pgDump))
	broken = broken[:len(broken)-6]
	if c, err := CheckFile(bytes.NewReader(broken), dbmon.Postgres); err != nil || c.Problem == "" {
		t.Fatalf("broken gzip: %+v %v", c, err)
	}
	// A database named only past the head still counts.
	big := "-- MySQL dump\nUSE `a`;\n" + strings.Repeat("INSERT INTO t VALUES ('x');\n", 50000) + "USE `b`;\n-- Dump completed\n"
	if c, _ := CheckFile(strings.NewReader(big), dbmon.MySQL); c.Problem == "" || len(c.Databases) != 2 {
		t.Fatalf("late USE: %+v", c.Sniffed)
	}
	if s := (Sniffed{Engine: dbmon.MySQL}).ForEngine(dbmon.Postgres); s == "" {
		t.Fatal("engine mismatch passed")
	}
}

func TestPlainSQL(t *testing.T) {
	out, err := io.ReadAll(PlainSQL(strings.NewReader(pgDump), "KEY"))
	if err != nil {
		t.Fatal(err)
	}
	want := "\\restrict KEY\n--\n-- PostgreSQL database dump\n--\nSET statement_timeout = 0;\nCREATE TABLE public.t (a text);\nCOPY public.t (a) FROM stdin;\n\\restrict inside\nALTER TABLE x OWNER TO y;\n\\.\n--\n-- PostgreSQL database dump complete\n--\n"
	if string(out) != want {
		t.Fatalf("got:\n%s", out)
	}
	// A line longer than the reader's buffer passes whole.
	long := "INSERT INTO t VALUES ('" + strings.Repeat("y", 200_000) + "');\n"
	out, _ = io.ReadAll(PlainSQL(strings.NewReader(long), "K"))
	if string(out) != "\\restrict K\n"+long {
		t.Fatal("long line changed")
	}
}

func TestPgSQLRestoreScript(t *testing.T) {
	tg := Target{Engine: dbmon.Postgres, Username: "u", Name: "shop", ID: "0193a1b2-c3d4-7e5f"}
	s, err := BuildRestore(tg, RestoreOptions{Format: PgSQL, Source: "shop", Replace: true, First: true, Last: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"morche_restore_0193a1b2", "RENAME TO \"morche_old_0193a1b2\"", "--single-transaction", "WITH (FORCE)"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in\n%s", want, s)
		}
	}
	s, _ = BuildRestore(tg, RestoreOptions{Format: MongoArchive, Source: "shop", MongoPlain: true})
	_ = s
	tg.Engine = dbmon.Mongo
	s, _ = BuildRestore(tg, RestoreOptions{Format: MongoArchive, Source: "shop", MongoPlain: true})
	if strings.Contains(s, "--gzip") {
		t.Fatal("plain archive asks for gzip")
	}
}
