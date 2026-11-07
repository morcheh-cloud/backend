package api

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/dbmon"
)

func TestBackupPath(t *testing.T) {
	at := time.Date(2026, 11, 7, 3, 0, 5, 0, time.UTC)
	id := uuid.MustParse("01a1b549-14aa-7d2c-b33c-ec514df15c6e")
	cases := []struct{ folder, db, target, want string }{
		{"/backups", "Shop Primary!", "", "/backups/shop-primary/all_2026-11-07_03-00-05_f15c6e.sql.gz"},
		{"/", "فروشگاه", "orders", "/database/orders_2026-11-07_03-00-05_f15c6e.sql.gz"},
		{"/a/../b/", "db_1", "My_DB", "/b/db-1/my-db_2026-11-07_03-00-05_f15c6e.sql.gz"},
	}
	for _, c := range cases {
		if got := backupPath(c.folder, c.db, c.target, at, id, "sql.gz"); got != c.want {
			t.Errorf("backupPath(%q, %q, %q) = %q, want %q", c.folder, c.db, c.target, got, c.want)
		}
	}
}

func TestDumpCommand(t *testing.T) {
	cases := []struct {
		name      string
		priv      privilege
		container string
		cmd       string
		stdin     string
	}{
		{"plain", privUser, "", "sh -s", "SCRIPT"},
		{"container", privUser, "pg 1", "docker exec -i -- 'pg 1' sh -s", "SCRIPT"},
		{"sudo", privSudo, "pg", "sudo -n docker exec -i -- 'pg' sh -s", "SCRIPT"},
		{"sudo password", privSudoPassword, "", "sudo -S -p '' sh -s", "pw\nSCRIPT"},
	}
	for _, c := range cases {
		cmd, stdin := dumpCommand(c.priv, "pw", c.container, "SCRIPT")
		if strings.ReplaceAll(cmd, "'", "") != strings.ReplaceAll(c.cmd, "'", "") || stdin != c.stdin {
			t.Errorf("%s: got %q / %q", c.name, cmd, stdin)
		}
	}
	// The password never reaches a command line.
	if cmd, _ := dumpCommand(privSudoPassword, "hunter2", "pg", "SCRIPT"); strings.Contains(cmd, "hunter2") {
		t.Errorf("password in the command: %q", cmd)
	}
}

func TestScrubAndTail(t *testing.T) {
	if got := scrub(" login failed for s3cret\n", "s3cret", ""); got != "login failed for •••" {
		t.Errorf("scrub = %q", got)
	}
	var w tailWriter
	for range 3 {
		if _, err := w.Write([]byte(strings.Repeat("x", backupStderrTail))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Write([]byte("end")); err != nil {
		t.Fatal(err)
	}
	if len(w.b) != backupStderrTail || !strings.HasSuffix(string(w.b), "end") {
		t.Errorf("tail is %d bytes", len(w.b))
	}
}

func TestBackupTarget(t *testing.T) {
	inside := sqlc.Database{Engine: dbmon.Postgres, Mode: "server", Container: "pg", Port: 5432, Tls: dbmon.TLSVerify}
	got := backupTarget(inside, "u", "p", "shop", "id")
	if got.Host != "127.0.0.1" || got.Port != 5432 || !got.Local || got.TLS != dbmon.TLSDisable {
		t.Errorf("container: %+v", got)
	}
	// A set host means the port is the published one, not the one inside.
	published := inside
	published.Host, published.Port = "10.0.0.1", 15432
	if got := backupTarget(published, "u", "p", "", "id"); got.Port != 0 || got.Host != "127.0.0.1" {
		t.Errorf("published: %+v", got)
	}
	direct := sqlc.Database{Engine: dbmon.MySQL, Mode: "direct", Host: "db.example.com", Port: 3306, Tls: dbmon.TLSRequire}
	if got := backupTarget(direct, "u", "p", "", "id"); got.Host != "db.example.com" || got.Local || got.TLS != dbmon.TLSRequire {
		t.Errorf("direct: %+v", got)
	}
}

func TestBackupSelectionProblem(t *testing.T) {
	onServer := sqlc.Database{Engine: dbmon.MSSQL, Mode: "server", Container: "sql"}
	remote := sqlc.Database{Engine: dbmon.MSSQL, Mode: "direct", Host: "sql.example.com"}
	redis := sqlc.Database{Engine: dbmon.Redis, Mode: "server"}
	pg := sqlc.Database{Engine: dbmon.Postgres, Mode: "direct"}
	cases := []struct {
		d         sqlc.Database
		selection string
		targets   []string
		pattern   string
		field     string
	}{
		{onServer, "selected", []string{"shop"}, "", ""},
		{onServer, "all", nil, "", ""},
		{remote, "all", nil, "", "selection"},
		{redis, "all", nil, "", ""},
		{redis, "selected", []string{"0"}, "", "selection"},
		{pg, "selected", nil, "", "targets"},
		{pg, "selected", []string{"shop", "shop; drop"}, "", ""}, // quoted in the script
		{pg, "selected", []string{"-x"}, "", "targets"},
		{pg, "pattern", nil, "", "pattern"},
		{pg, "pattern", nil, "^shop_(", "pattern"},
		{pg, "pattern", nil, "^shop_", ""},
	}
	for _, c := range cases {
		if field, msg := backupSelectionProblem(c.d, c.selection, c.targets, c.pattern); field != c.field {
			t.Errorf("%s %s %v %q: %q %q", c.d.Engine, c.selection, c.targets, c.pattern, field, msg)
		}
	}
}

func TestBackupFolder(t *testing.T) {
	at := time.Date(2026, 11, 7, 23, 0, 0, 0, time.UTC)
	if got := backupFolder("/db/{year}-{month}-{day}", at); got != "/db/2026-11-07" {
		t.Errorf("backupFolder = %q", got)
	}
}

func TestReadMarks(t *testing.T) {
	m, rest := readMarks("warning: x\n MORCHEH_POSITION=binlog.000004:157\nMORCHEH_CHAIN_BROKEN\nend")
	if m.position != "binlog.000004:157" || !m.broken || rest != "warning: x\nend" {
		t.Errorf("readMarks = %+v %q", m, rest)
	}
}

func TestFeedCommand(t *testing.T) {
	cmd, prefix := wrapCommand(privSudoPassword, "pw", "db", feedCommand(42))
	if prefix != "pw\n" || !strings.Contains(cmd, "count=42") || !strings.HasPrefix(cmd, "sudo -S -p '' docker exec -i -- ") {
		t.Errorf("got %q / %q", cmd, prefix)
	}
}

func TestKeepSet(t *testing.T) {
	loc := time.UTC
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, loc)
	id := func(n int) uuid.UUID { return uuid.MustParse(fmt.Sprintf("00000000-0000-0000-0000-%012d", n)) }
	// One backup a day for 60 days, newest first, two databases.
	var rows []sqlc.DatabaseBackup
	for day := range 60 {
		for i, target := range []string{"a", "b"} {
			rows = append(rows, sqlc.DatabaseBackup{
				ID: id(day*2 + i + 1), Target: target, Kind: "full", CreatedAt: now.AddDate(0, 0, -day).Add(-time.Hour),
			})
		}
	}
	count := func(keep map[uuid.UUID]bool, target string) int {
		n := 0
		for _, b := range rows {
			if keep[b.ID] && b.Target == target {
				n++
			}
		}
		return n
	}

	days := keepSet(rows, sqlc.DatabaseBackupPlan{Retention: "days", KeepDays: 7}, loc, now)
	if count(days, "a") != 7 || count(days, "b") != 7 {
		t.Errorf("days: %d / %d", count(days, "a"), count(days, "b"))
	}
	// The newest stays even when it's older than the window.
	old := []sqlc.DatabaseBackup{{ID: id(999), Target: "a", CreatedAt: now.AddDate(0, 0, -30)}}
	if !keepSet(old, sqlc.DatabaseBackupPlan{Retention: "days", KeepDays: 7}, loc, now)[id(999)] {
		t.Error("days: the newest was dropped")
	}

	gfs := keepSet(rows, sqlc.DatabaseBackupPlan{Retention: "gfs", GfsDaily: 3, GfsWeekly: 4, GfsMonthly: 3}, loc, now)
	// 3 days; weeks: this week's newest is a daily already, then 3 more
	// Sundays; months: November's newest is daily, then October's and
	// September's newest. Some overlap: count between 7 and 10.
	if n := count(gfs, "a"); n < 7 || n > 10 {
		t.Errorf("gfs kept %d", n)
	}
	off := keepSet(rows, sqlc.DatabaseBackupPlan{Retention: "gfs"}, loc, now)
	if count(off, "a") != 1 {
		t.Errorf("gfs with every tier off kept %d, want the newest", count(off, "a"))
	}
	if all := keepSet(rows, sqlc.DatabaseBackupPlan{Retention: "forever"}, loc, now); len(all) != len(rows) {
		t.Errorf("forever kept %d of %d", len(all), len(rows))
	}

	// A kept incremental keeps what it builds on.
	full, mid, last := id(1001), id(1002), id(1003)
	chain := []sqlc.DatabaseBackup{
		{ID: last, Target: "a", Kind: "incremental", ParentID: &mid, CreatedAt: now},
		{ID: mid, Target: "a", Kind: "incremental", ParentID: &full, CreatedAt: now.AddDate(0, 0, -20)},
		{ID: full, Target: "a", Kind: "full", CreatedAt: now.AddDate(0, 0, -21)},
	}
	keep := keepSet(chain, sqlc.DatabaseBackupPlan{Retention: "days", KeepDays: 1}, loc, now)
	if !keep[full] || !keep[mid] || !keep[last] {
		t.Errorf("chain: %v", keep)
	}
}
