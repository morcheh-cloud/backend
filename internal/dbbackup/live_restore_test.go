//go:build dbbackuplive

package dbbackup

import (
	"bytes"
	"fmt"
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

func TestLiveRestorePostgres(t *testing.T) {
	const c = "morcheh-test-postgres-1"
	psql := func(db, sql string) string {
		return sh(t, c, "env", "PGPASSWORD=colony", "psql", "-U", "ant", "-h", "127.0.0.1", "-d", db, "-tAc", sql)
	}
	psql("postgres", "DROP DATABASE IF EXISTS rt_src")
	psql("postgres", "DROP DATABASE IF EXISTS rt_new")
	psql("postgres", "CREATE DATABASE rt_src")
	defer psql("postgres", "DROP DATABASE IF EXISTS rt_src")
	defer psql("postgres", "DROP DATABASE IF EXISTS rt_new")
	psql("rt_src", "CREATE TABLE t (n int); INSERT INTO t VALUES (1), (2)")

	login := Target{Engine: "postgres", Username: "ant", Password: "colony", Local: true}
	src := login
	src.Name = "rt_src"
	spec, err := Build(src)
	if err != nil {
		t.Fatal(err)
	}
	file, _ := feed(t, c, spec.Script, nil)

	into := login
	into.Name = "rt_new"
	restore(t, c, into, RestoreOptions{Format: spec.Format, Source: "rt_src", First: true, Last: true}, file)
	if n := psql("rt_new", "SELECT count(*) FROM t"); n != "2" {
		t.Fatalf("new: %s rows", n)
	}
	psql("rt_new", "INSERT INTO t VALUES (3); CREATE TABLE extra (x int)")
	restore(t, c, into, RestoreOptions{Format: spec.Format, Source: "rt_src", Replace: true, First: true, Last: true}, file)
	if n := psql("rt_new", "SELECT count(*) FROM t"); n != "2" {
		t.Fatalf("replace: %s rows", n)
	}
	t.Log("postgres new + replace ok")
}

func TestLiveRestoreMySQLIncremental(t *testing.T) {
	// The mysql image has no mysqlbinlog; the mariadb one has its own.
	const c = "morcheh-test-mariadb-1"
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
	const c = "morcheh-test-mongo-1"
	mongo := func(js string) string {
		return sh(t, c, "mongosh", "--quiet", "-u", "ant", "-p", "colony", "--authenticationDatabase", "admin", "--eval", js)
	}
	mongo(`db.getSiblingDB("rt_src").dropDatabase(); db.getSiblingDB("rt_new").dropDatabase(); db.getSiblingDB("rt_src").t.insertMany([{n:1},{n:2}])`)
	defer mongo(`db.getSiblingDB("rt_src").dropDatabase(); db.getSiblingDB("rt_new").dropDatabase()`)

	tg := Target{Engine: "mongodb", Username: "ant", Password: "colony", AuthDatabase: "admin", Name: "rt_src", Local: true}
	spec, err := Build(tg)
	if err != nil {
		t.Fatal(err)
	}
	file, _ := feed(t, c, spec.Script, nil)
	tg.Name = "rt_new"
	restore(t, c, tg, RestoreOptions{Format: spec.Format, Source: "rt_src", First: true, Last: true}, file)
	if n := mongo(`db.getSiblingDB("rt_new").t.countDocuments()`); n != "2" {
		t.Fatalf("new: %s docs", n)
	}
	t.Log("mongo new ok")
}

func TestLiveRestoreMSSQLDifferential(t *testing.T) {
	const c = "morcheh-test-mssql-1"
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
