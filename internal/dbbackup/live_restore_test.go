//go:build dbbackuplive

package dbbackup

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"
)

// Round trips through the compose test containers: back up, change, restore,
// count rows. go test -tags dbbackuplive ./internal/dbbackup -run TestLiveRestore -v

// feed runs a script the way the API does: script first, then the file.
func feed(t *testing.T, container, script string, data []byte) ([]byte, string) {
	t.Helper()
	shell := fmt.Sprintf(`s=$(dd bs=1 count=%d 2>/dev/null) && eval "$s"`, len(script))
	cmd := exec.Command("docker", "exec", "-i", container, "sh", "-c", shell)
	cmd.Stdin = bytes.NewReader(append([]byte(script), data...))
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v: %.800s", err, errb.String())
	}
	return out.Bytes(), errb.String()
}

func sh(t *testing.T, container string, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", append([]string{"exec", container}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func markIn(stderr string) string {
	for _, l := range strings.Split(stderr, "\n") {
		if p, ok := strings.CutPrefix(l, PositionMark); ok {
			return strings.TrimSpace(p)
		}
	}
	return ""
}

func restore(t *testing.T, container string, tg Target, o RestoreOptions, file []byte) {
	t.Helper()
	s, err := BuildRestore(tg, o)
	if err != nil {
		t.Fatal(err)
	}
	feed(t, container, s, file)
}

// packed compresses a dump the way the API does when Spec.Pack asks.
func packed(t *testing.T, spec Spec, file []byte) []byte {
	t.Helper()
	if !spec.Pack {
		return file
	}
	method, level, _ := strings.Cut(spec.Compression, ":")
	var z bytes.Buffer
	w, err := Pack(&z, method, level)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(file)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return z.Bytes()
}

// unpacked undoes it on the way back.
func unpacked(t *testing.T, format, compression string, file []byte) []byte {
	t.Helper()
	r, err := Unpack(bytes.NewReader(file), Packed(format, compression))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLiveRestorePostgres(t *testing.T) {
	const c = "morche-test-postgres-1"
	psql := func(db, sql string) string {
		return sh(t, c, "env", "PGPASSWORD=colony", "psql", "-U", "ant", "-h", "127.0.0.1", "-d", db, "-tAc", sql)
	}
	for _, v := range []struct {
		compression, level string
		workers            int
		format             string
	}{
		{Gzip, LevelBalanced, 1, PgCustom},
		{Zstd, LevelFast, 1, PgCustom},
		{Zstd, LevelBalanced, 4, PgDir},
		{Gzip, LevelSmall, 3, PgDir},
	} {
		t.Run(fmt.Sprintf("%s-%s-%d", v.compression, v.level, v.workers), func(t *testing.T) {
			psql("postgres", "DROP DATABASE IF EXISTS rt_src")
			psql("postgres", "DROP DATABASE IF EXISTS rt_new")
			psql("postgres", "CREATE DATABASE rt_src")
			defer psql("postgres", "DROP DATABASE IF EXISTS rt_src")
			defer psql("postgres", "DROP DATABASE IF EXISTS rt_new")
			psql("rt_src", "CREATE TABLE t (n int); INSERT INTO t SELECT generate_series(1, 2000); CREATE TABLE u (s text); INSERT INTO u SELECT md5(i::text) FROM generate_series(1, 5000) i; SELECT lo_from_bytea(0, 'blob')")

			login := Target{Engine: "postgres", Username: "ant", Password: "colony", Local: true}
			src := login
			src.Name, src.Compression, src.Level, src.Workers = "rt_src", v.compression, v.level, v.workers
			spec, err := Build(src)
			if err != nil {
				t.Fatal(err)
			}
			if spec.Format != v.format || spec.Workers != v.workers {
				t.Fatalf("format %s workers %d", spec.Format, spec.Workers)
			}
			file, stderr := feed(t, c, spec.Script, nil)
			if strings.Contains(stderr, CompressionMark) {
				t.Fatalf("fell back: %s", stderr)
			}
			if _, err := Verify(spec.Format, bytes.NewReader(file)); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if s, err := Sniff(bytes.NewReader(file), "postgres"); err != nil || s.Format != v.format {
				t.Fatalf("sniff: %+v %v", s, err)
			}
			if fc, err := CheckFile(bytes.NewReader(file), "postgres"); err != nil || fc.Problem != "" {
				t.Fatalf("check: %+v %v", fc, err)
			}
			if v.workers > 1 {
				// Cut short, it's found out.
				if _, err := Verify(spec.Format, bytes.NewReader(file[:len(file)/2])); err == nil {
					t.Fatal("a cut archive passed")
				}
			}
			t.Logf("%s: %d bytes", spec.Compression, len(file))

			into := login
			into.Name = "rt_new"
			o := RestoreOptions{Format: spec.Format, Source: "rt_src", First: true, Last: true, Workers: v.workers}
			restore(t, c, into, o, file)
			if n := psql("rt_new", "SELECT count(*) FROM t"); n != "2000" {
				t.Fatalf("new: %s rows", n)
			}
			psql("rt_new", "INSERT INTO t VALUES (3); CREATE TABLE extra (x int)")
			o.Replace = true
			restore(t, c, into, o, file)
			if n := psql("rt_new", "SELECT count(*) FROM t"); n != "2000" {
				t.Fatalf("replace: %s rows", n)
			}
			if n := psql("rt_new", "SELECT count(*) FROM u"); n != "5000" {
				t.Fatalf("replace u: %s rows", n)
			}
		})
	}
}

func TestLiveRestoreMySQLIncremental(t *testing.T) {
	// The mysql image has no mysqlbinlog; the mariadb one has its own.
	const c = "morche-test-mariadb-1"
	my := func(sql string) string {
		return sh(t, c, "mariadb", "-uroot", "-pcolony", "-N", "-e", sql)
	}
	my("DROP DATABASE IF EXISTS rt_src; CREATE DATABASE rt_src; CREATE TABLE rt_src.t (n int); INSERT INTO rt_src.t VALUES (1)")
	defer my("DROP DATABASE IF EXISTS rt_src")

	tg := Target{Engine: "mysql", Username: "root", Password: "colony", Name: "rt_src", Local: true, Chain: true}
	full, err := Build(tg)
	if err != nil {
		t.Fatal(err)
	}
	fullFile, stderr := feed(t, c, full.Script, nil)
	pos := markIn(stderr)
	if pos == "" && full.HeadPosition {
		pos = PositionIn(fullFile[:min(len(fullFile), 4096)])
	}
	if pos == "" {
		t.Fatalf("no position after the full backup: %s", stderr)
	}

	my("INSERT INTO rt_src.t VALUES (2), (3)")
	tg.Chain, tg.Incremental, tg.Position = false, true, pos
	inc, err := Build(tg)
	if err != nil {
		t.Fatal(err)
	}
	incFile, stderr := feed(t, c, inc.Script, nil)
	if markIn(stderr) == "" {
		t.Fatalf("no position after the incremental: %s", stderr)
	}

	my("INSERT INTO rt_src.t VALUES (99)")
	tg.Incremental, tg.Position = false, ""
	restore(t, c, tg, RestoreOptions{Format: full.Format, Source: "rt_src", Replace: true, First: true}, fullFile)
	if n := my("SELECT count(*) FROM rt_src.t"); n != "1" {
		t.Fatalf("after the full one: %s rows", n)
	}
	restore(t, c, tg, RestoreOptions{Format: inc.Format, Source: "rt_src", Replace: true, Last: true}, incFile)
	if n := my("SELECT count(*) FROM rt_src.t"); n != "3" {
		t.Fatalf("after the incremental: %s rows", n)
	}
	t.Log("mysql full + binlog ok")
}

func TestLiveRestoreMongo(t *testing.T) {
	const c = "morche-test-mongo-1"
	mongo := func(js string) string {
		return sh(t, c, "mongosh", "--quiet", "-u", "ant", "-p", "colony", "--authenticationDatabase", "admin", "--eval", js)
	}
	for _, method := range []string{Gzip, Zstd} {
		t.Run(method, func(t *testing.T) {
			mongo(`db.getSiblingDB("rt_src").dropDatabase(); db.getSiblingDB("rt_new").dropDatabase(); db.getSiblingDB("rt_src").t.insertMany([{n:1},{n:2}])`)
			defer mongo(`db.getSiblingDB("rt_src").dropDatabase(); db.getSiblingDB("rt_new").dropDatabase()`)

			tg := Target{Engine: "mongodb", Username: "ant", Password: "colony", AuthDatabase: "admin", Name: "rt_src", Local: true, Compression: method, Workers: 2}
			spec, err := Build(tg)
			if err != nil {
				t.Fatal(err)
			}
			out, _ := feed(t, c, spec.Script, nil)
			file := packed(t, spec, out)
			if _, err := Verify(spec.Format, bytes.NewReader(file)); err != nil {
				t.Fatalf("verify: %v", err)
			}
			tg.Name = "rt_new"
			restore(t, c, tg, RestoreOptions{
				Format: spec.Format, Source: "rt_src", First: true, Last: true,
				MongoPlain: Packed(spec.Format, spec.Compression) == Zstd,
			}, unpacked(t, spec.Format, spec.Compression, file))
			if n := mongo(`db.getSiblingDB("rt_new").t.countDocuments()`); n != "2" {
				t.Fatalf("new: %s docs", n)
			}
		})
	}
}

func TestLiveRestoreMSSQLDifferential(t *testing.T) {
	const c = "morche-test-mssql-1"
	q := func(sql string) string {
		return sh(t, c, "/opt/mssql-tools18/bin/sqlcmd", "-C", "-S", "127.0.0.1", "-U", "sa", "-P", "Colony-2026!", "-h-1", "-W", "-Q", "SET NOCOUNT ON; "+sql)
	}
	q("IF DB_ID('rt_src') IS NOT NULL DROP DATABASE rt_src; IF DB_ID('rt_new') IS NOT NULL DROP DATABASE rt_new; CREATE DATABASE rt_src")
	defer q("IF DB_ID('rt_src') IS NOT NULL DROP DATABASE rt_src; IF DB_ID('rt_new') IS NOT NULL DROP DATABASE rt_new")
	q("CREATE TABLE rt_src.dbo.t (n int); INSERT INTO rt_src.dbo.t VALUES (1)")

	tg := Target{Engine: "mssql", Username: "sa", Password: "Colony-2026!", Name: "rt_src", Local: true, ID: "rt-full", Chain: true}
	full, err := Build(tg)
	if err != nil {
		t.Fatal(err)
	}
	fullFile, stderr := feed(t, c, full.Script, nil)
	base := markIn(stderr)
	if base == "" {
		t.Fatalf("no base: %s", stderr)
	}
	q("INSERT INTO rt_src.dbo.t VALUES (2), (3)")
	tg.Chain, tg.Incremental, tg.Position, tg.ID = false, true, base, "rt-diff"
	diff, err := Build(tg)
	if err != nil {
		t.Fatal(err)
	}
	diffFile, _ := feed(t, c, diff.Script, nil)

	into := Target{Engine: "mssql", Username: "sa", Password: "Colony-2026!", Name: "rt_new", Local: true, ID: "rt-restore"}
	restore(t, c, into, RestoreOptions{Format: full.Format, Source: "rt_src", First: true}, fullFile)
	restore(t, c, into, RestoreOptions{Format: diff.Format, Source: "rt_src", Last: true}, diffFile)
	if n := q("SELECT count(*) FROM rt_new.dbo.t"); n != "3" {
		t.Fatalf("new: %s rows", n)
	}
	t.Log("mssql full + differential into a new name ok")
}

// A plain pg_dump from elsewhere: sniffed, checked, filtered, then loaded new
// and swapped in over a database still in use.
func TestLiveRestorePostgresPlain(t *testing.T) {
	const c = "morche-test-postgres-1"
	psql := func(db, sql string) string {
		return sh(t, c, "env", "PGPASSWORD=colony", "psql", "-U", "ant", "-h", "127.0.0.1", "-d", db, "-tAc", sql)
	}
	for _, db := range []string{"rt_src", "rt_new"} {
		psql("postgres", "DROP DATABASE IF EXISTS "+db+" WITH (FORCE)")
		defer psql("postgres", "DROP DATABASE IF EXISTS "+db+" WITH (FORCE)")
	}
	psql("postgres", "CREATE DATABASE rt_src")
	psql("rt_src", "CREATE TABLE t (n int, s text); INSERT INTO t VALUES (1, E'a\\\\b'), (2, '\\restrict x'); ALTER TABLE t OWNER TO ant")
	dump := []byte(sh(t, c, "env", "PGPASSWORD=colony", "pg_dump", "-U", "ant", "-h", "127.0.0.1", "rt_src") + "\n")

	check, err := CheckFile(bytes.NewReader(dump), "postgres")
	if err != nil || check.Format != PgSQL || check.Problem != "" {
		t.Fatalf("%+v %v", check, err)
	}
	load := func(tg Target, replace bool) {
		s, err := BuildRestore(tg, RestoreOptions{Format: PgSQL, Source: "rt_src", Replace: replace, First: true, Last: true})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(PlainSQL(bytes.NewReader(dump), "k3y"))
		feed(t, c, s, body)
	}
	tg := Target{Engine: "postgres", Username: "ant", Password: "colony", Local: true, Name: "rt_new", ID: "0193a1b2-0000-7000"}
	load(tg, false)
	if n := psql("rt_new", "SELECT count(*) FROM t"); n != "2" {
		t.Fatalf("new: %s rows", n)
	}
	// Replace while someone is connected.
	psql("rt_src", "DELETE FROM t")
	hold := exec.Command("docker", "exec", c, "env", "PGPASSWORD=colony", "psql", "-U", "ant", "-h", "127.0.0.1", "-d", "rt_src", "-c", "SELECT pg_sleep(30)")
	hold.Start()
	defer hold.Process.Kill()
	tg.Name, tg.ID = "rt_src", "0193a1b2-1111-7000"
	load(tg, true)
	if n := psql("rt_src", "SELECT count(*) FROM t WHERE s = '\\restrict x'"); n != "1" {
		t.Fatalf("replace: %s rows", n)
	}
	if left := psql("postgres", "SELECT count(*) FROM pg_database WHERE datname LIKE 'morche_%'"); left != "0" {
		t.Fatalf("%s leftovers", left)
	}
}

// mongodump --archive without --gzip.
func TestLiveRestoreMongoPlain(t *testing.T) {
	const c = "morche-test-mongo-1"
	mongo := func(js string) string {
		return sh(t, c, "mongosh", "--quiet", "-u", "ant", "-p", "colony", "--authenticationDatabase", "admin", "--eval", js)
	}
	mongo(`db.getSiblingDB("rt_src").dropDatabase(); db.getSiblingDB("rt_new").dropDatabase(); db.getSiblingDB("rt_src").t.insertMany([{n:1},{n:2}])`)
	defer mongo(`db.getSiblingDB("rt_src").dropDatabase(); db.getSiblingDB("rt_new").dropDatabase()`)
	file, _ := feed(t, c, "mongodump --quiet --archive -u ant -p colony --authenticationDatabase admin --db rt_src", nil)
	s, err := Sniff(bytes.NewReader(file), "mongodb")
	if err != nil || s.MongoGzip || s.Format != MongoArchive || strings.Join(s.Databases, ",") != "rt_src" {
		t.Fatalf("%+v %v", s, err)
	}
	tg := Target{Engine: "mongodb", Username: "ant", Password: "colony", AuthDatabase: "admin", Name: "rt_new", Local: true}
	restore(t, c, tg, RestoreOptions{Format: MongoArchive, Source: "rt_src", First: true, Last: true, MongoPlain: true}, file)
	if n := mongo(`db.getSiblingDB("rt_new").t.countDocuments()`); n != "2" {
		t.Fatalf("new: %s docs", n)
	}
}
