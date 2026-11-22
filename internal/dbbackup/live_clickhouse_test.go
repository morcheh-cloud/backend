//go:build dbbackuplive

package dbbackup

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// ClickHouse round trip in the compose test container: dump backup_test,
// check the file, restore it as backup_test_copy (both ways the restore can
// read the tar), then replace the copy, and compare every table's rows.
// go test -tags dbbackuplive ./internal/dbbackup -run TestLiveClickHouse -v
func TestLiveClickHouse(t *testing.T) {
	const c = "morche-test-clickhouse-1"
	q := func(sql string) string {
		return sh(t, c, "clickhouse-client", "--user", "ant", "--password", "colony", "--max_partitions_per_insert_block=0", "-n", "-q", sql)
	}
	q("DROP DATABASE IF EXISTS backup_test SYNC; DROP DATABASE IF EXISTS backup_test_copy SYNC; CREATE DATABASE backup_test")
	defer q("DROP DATABASE IF EXISTS backup_test SYNC; DROP DATABASE IF EXISTS backup_test_copy SYNC")
	q("CREATE TABLE backup_test.events (id UInt64, d Date, s String, m UInt64 MATERIALIZED id * 2) ENGINE = MergeTree PARTITION BY d ORDER BY id;" +
		"INSERT INTO backup_test.events (id, d, s) SELECT number, toDate('2024-01-01') + (number % 150), toString(number) FROM numbers(20000);" +
		"CREATE TABLE backup_test.`odd name'x` (x Int32) ENGINE = Log; INSERT INTO backup_test.`odd name'x` VALUES (1), (2), (3);" +
		"CREATE TABLE backup_test.empty (x Int32) ENGINE = MergeTree ORDER BY x;" +
		"CREATE TABLE backup_test.agg (d Date, c UInt64) ENGINE = SummingMergeTree ORDER BY d;" +
		"CREATE MATERIALIZED VIEW backup_test.mv_to TO backup_test.agg AS SELECT d, count() AS c FROM backup_test.events GROUP BY d;" +
		"CREATE MATERIALIZED VIEW backup_test.mv_inner ENGINE = MergeTree ORDER BY d AS SELECT d, sum(id) AS t FROM backup_test.events GROUP BY d;" +
		"INSERT INTO backup_test.events (id, d, s) SELECT number, toDate('2024-01-01'), 'x' FROM numbers(100);" +
		"CREATE VIEW backup_test.v AS SELECT s FROM backup_test.events WHERE id < 10;" +
		"CREATE VIEW backup_test.vv AS SELECT * FROM backup_test.v;" +
		"CREATE DICTIONARY backup_test.dict (d Date, c UInt64) PRIMARY KEY d SOURCE(CLICKHOUSE(TABLE 'agg' DB 'backup_test')) LIFETIME(0) LAYOUT(HASHED())")
	counts := func(db string) string {
		return q("SELECT name, engine FROM system.tables WHERE database = '" + db + "' AND NOT startsWith(name, '.inner') ORDER BY name FORMAT TSV")
	}
	rows := func(db string) string {
		return q("SELECT (SELECT count() FROM " + db + ".events), (SELECT sum(m) FROM " + db + ".events), (SELECT count() FROM " + db + ".`odd name'x`)," +
			" (SELECT sum(c) FROM " + db + ".agg), (SELECT sum(t) FROM " + db + ".mv_inner), (SELECT count() FROM " + db + ".vv), (SELECT count() FROM " + db + ".empty)")
	}
	want := rows("backup_test")
	t.Logf("source: %s\n%s", want, counts("backup_test"))

	for _, zstd := range []bool{false, true} {
		target := Target{Engine: "clickhouse", Username: "ant", Password: "colony", Name: "backup_test", Local: true}
		if zstd {
			target.Compression = Zstd
		}
		spec, err := Build(target)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("docker", "exec", "-i", c, "sh", "-s")
		cmd.Stdin = strings.NewReader(spec.Script)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			t.Fatalf("dump: %v: %s", err, errb.String())
		}
		t.Logf("dump %d bytes, stderr: %.300s", out.Len(), errb.String())
		file := packed(t, spec, out.Bytes())
		if _, err := Verify(spec.Format, bytes.NewReader(file)); err != nil {
			t.Fatalf("verify: %v", err)
		}
		s, err := Sniff(bytes.NewReader(file), "clickhouse")
		if err != nil || s.Format != ClickHouseTar || s.Problem != "" || strings.Join(s.Databases, ",") != "backup_test" {
			t.Fatalf("sniff: %+v %v", s, err)
		}
		fc, err := CheckFile(bytes.NewReader(file), "clickhouse")
		if err != nil || fc.Problem != "" {
			t.Fatalf("check: %+v %v", fc, err)
		}
		// Cut short: the check must say so.
		if _, err := Verify(spec.Format, bytes.NewReader(packed(t, spec, out.Bytes()[:out.Len()/2]))); err == nil {
			t.Fatal("a file cut in half verified")
		}
		plain := unpacked(t, spec.Format, spec.Compression, file)

		for _, mode := range []string{"stream", "unpacked"} {
			t.Run(fmt.Sprintf("zstd=%v/%s", zstd, mode), func(t *testing.T) {
				into := Target{Engine: "clickhouse", Username: "ant", Password: "colony", Name: "backup_test_copy", Local: true}
				env := []string{}
				if mode == "unpacked" {
					// A tar without --to-command unpacks first.
					sh(t, c, "sh", "-c", `mkdir -p /tmp/oldtar && printf '#!/bin/sh\n[ "$1" = --help ] && exit 0\nexec /usr/bin/tar "$@"\n' > /tmp/oldtar/tar && chmod +x /tmp/oldtar/tar`)
					env = []string{"-e", "PATH=/tmp/oldtar:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
				}
				q("DROP DATABASE IF EXISTS backup_test_copy SYNC")
				for _, replace := range []bool{false, true} {
					script, err := BuildRestore(into, RestoreOptions{Format: ClickHouseTar, Source: "backup_test", Replace: replace, First: true, Last: true})
					if err != nil {
						t.Fatal(err)
					}
					_, stderr := feedEnv(t, c, env, script, plain)
					if got := rows("backup_test_copy"); got != want {
						t.Fatalf("replace=%v: rows %s, want %s (stderr %s)", replace, got, want, stderr)
					}
				}
				if got, w := counts("backup_test_copy"), counts("backup_test"); got != w {
					t.Fatalf("tables:\n%s\nwant\n%s", got, w)
				}
				// The view in the copy reads the copy.
				if ddl := q("SELECT create_table_query FROM system.tables WHERE database = 'backup_test_copy' AND name = 'mv_to'"); !strings.Contains(ddl, "backup_test_copy.events") || !strings.Contains(ddl, "TO backup_test_copy.agg") {
					t.Fatalf("mv_to: %s", ddl)
				}
			})
		}
	}

	// A database the file doesn't hold: the new database goes again.
	spec, _ := Build(Target{Engine: "clickhouse", Username: "ant", Password: "colony", Name: "backup_test", Local: true})
	dump, _ := exec.Command("docker", "exec", "-i", c, "sh", "-c", spec.Script).Output()
	script, _ := BuildRestore(Target{Engine: "clickhouse", Username: "ant", Password: "colony", Name: "backup_test_copy2", Local: true},
		RestoreOptions{Format: ClickHouseTar, Source: "nope", First: true, Last: true})
	shell := fmt.Sprintf(`s=$(dd bs=1 count=%d 2>/dev/null) && eval "$s"`, len(script))
	cmd := exec.Command("docker", "exec", "-i", c, "sh", "-c", shell)
	cmd.Stdin = bytes.NewReader(append([]byte(script), dump...))
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if cmd.Run() == nil || !strings.Contains(errb.String(), "no database called nope") {
		t.Fatalf("restore of a missing source: %s", errb.String())
	}
	if n := q("SELECT count() FROM system.databases WHERE name = 'backup_test_copy2'"); n != "0" {
		t.Fatal("the failed restore left its database")
	}
}

func feedEnv(t *testing.T, container string, env []string, script string, data []byte) ([]byte, string) {
	t.Helper()
	shell := fmt.Sprintf(`s=$(dd bs=1 count=%d 2>/dev/null) && eval "$s"`, len(script))
	args := append([]string{"exec", "-i"}, env...)
	cmd := exec.Command("docker", append(args, container, "sh", "-c", shell)...)
	cmd.Stdin = bytes.NewReader(append([]byte(script), data...))
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v: %.2000s", err, errb.String())
	}
	return out.Bytes(), errb.String()
}
