//go:build pitrlive

package pitr

import (
	"bytes"
	"encoding/base64"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The whole cycle against the compose test-pitr + test-minio-tls containers:
//
//	docker compose up -d --build test-pitr test-minio-tls
//	go test -tags pitrlive ./internal/pitr -run TestLive -v -count=1
const box = "morche-test-pitr-1"

func run(t *testing.T, script string) string {
	t.Helper()
	cmd := exec.Command("docker", "exec", "-i", box, "sh", "-s")
	cmd.Stdin = strings.NewReader(script)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	t.Logf("stderr: %s", strings.TrimSpace(errb.String()))
	if err != nil {
		t.Fatalf("%v\nstdout: %s", err, out.String())
	}
	return out.String()
}

func psql(t *testing.T, port, db, query string) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", box, "runuser", "-u", "postgres", "--", "psql", "-X", "-At", "-p", port, "-d", db, "-c", query).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v %s", query, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestLive(t *testing.T) {
	if out, err := exec.Command("docker", "exec", "morche-test-minio-tls-1", "sh", "-c",
		"mc alias set l https://127.0.0.1:9000 morche morche-secret --insecure >/dev/null && mc mb -p --insecure l/pitr-live").CombinedOutput(); err != nil {
		t.Fatalf("bucket: %v %s", err, out)
	}
	c, err := ParseDetect(run(t, DetectScript(5432)), 5432)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("cluster %+v", c)
	s := Settings{
		Repo: Repo{Type: "s3", Path: "/live-" + time.Now().Format("150405"), Endpoint: "127.0.0.1", Port: 9120,
			Bucket: "pitr-live", Region: "us-east-1", Key: "morche", Secret: "morche-secret", PathStyle: true},
		RetentionFull: 2, CompressLevel: 3, ProcessMax: 2, ArchiveTimeout: 10, CipherPass: "live-test-pass",
	}
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	m := Marks(run(t, SetupScript(c, s, false)))
	if m["RESTART"] == "1" {
		m = Marks(run(t, RestartScript(c)))
	}
	if m["READY"] != "1" {
		t.Fatalf("not ready: %v", m)
	}
	run(t, BackupScript(c, Full))

	marker := "before the mark " + time.Now().Format(time.RFC3339Nano)
	psql(t, "5432", "shop", "insert into orders (item) values ('"+marker+"')")
	time.Sleep(2 * time.Second)
	var mark time.Time
	if mark, err = time.Parse(time.RFC3339Nano, psql(t, "5432", "shop", `select to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	want := psql(t, "5432", "shop", "select count(*) from orders")
	psql(t, "5432", "shop", "insert into orders (item) values ('the mistake')") // always a commit after the mark
	run(t, CheckScript(c))                                                      // its WAL in the repository

	// pg_stat_archiver catches up a moment after the WAL is in the repository.
	var info Info
	var from, to time.Time
	for range 20 {
		if info, err = ParseInfo(run(t, InfoScript(c))); err != nil {
			t.Fatal(err)
		}
		if from, to = info.Window(); !to.Before(mark) {
			break
		}
		time.Sleep(time.Second)
	}
	t.Logf("window %v → %v, %d backups, archiver %+v", from, to, len(info.Backups), info.Archiver)
	if len(info.Backups) != 1 || to.Before(mark) {
		t.Fatalf("info %+v", info)
	}

	stamp := time.Now().Format("20060102-150405")
	out := run(t, RestoreNewScript(c, mark, stamp, 15432, info.Backups[0].Size))
	dir := Marks(out)["RESTORED"]
	if dir == "" {
		t.Fatalf("no folder: %s", out)
	}
	defer run(t, TeardownScript(c, dir))
	if got := psql(t, "15432", "shop", "select count(*) from orders"); got != want {
		t.Errorf("the copy has %s orders, want %s (before the delete)", got, want)
	}
	if psql(t, "15432", "shop", "select count(*) from orders where item = '"+marker+"'") != "1" {
		t.Error("the row written before the mark is missing")
	}
	run(t, TeardownScript(c, dir))

	// A time after the last commit: PostgreSQL can't find where to stop, so
	// the script restores to the newest point, which is the same data.
	time.Sleep(2 * time.Second)
	idle := time.Now().Add(-time.Second)
	dir = Marks(run(t, RestoreNewScript(c, idle, stamp+"b", 15432, info.Backups[0].Size)))["RESTORED"]
	if dir == "" {
		t.Fatal("no folder for the idle time")
	}
	all := psql(t, "5432", "shop", "select count(*) from orders")
	if got := psql(t, "15432", "shop", "select count(*) from orders"); got != all {
		t.Errorf("idle time: the copy has %s orders, want %s", got, all)
	}
	run(t, TeardownScript(c, dir))
	run(t, RemoveScript(c, true))
}

// Replace brings the server itself back to a point in time.
func TestLiveReplace(t *testing.T) {
	c, err := ParseDetect(run(t, DetectScript(5432)), 5432)
	if err != nil {
		t.Fatal(err)
	}
	s := Settings{
		Repo: Repo{Type: "s3", Path: "/replace-" + time.Now().Format("150405"), Endpoint: "127.0.0.1", Port: 9120,
			Bucket: "pitr-live", Region: "us-east-1", Key: "morche", Secret: "morche-secret", PathStyle: true},
		RetentionFull: 1, CompressLevel: 3, ProcessMax: 2, ArchiveTimeout: 10,
	}
	if m := Marks(run(t, SetupScript(c, s, false))); m["RESTART"] == "1" {
		run(t, RestartScript(c))
	}
	run(t, BackupScript(c, Full))
	keep := "keep " + time.Now().Format(time.RFC3339Nano)
	psql(t, "5432", "shop", "insert into orders (item) values ('"+keep+"')")
	time.Sleep(2 * time.Second)
	mark := time.Now()
	time.Sleep(2 * time.Second)
	psql(t, "5432", "shop", "create table dropped_by_mistake as select 1 as x")

	out := run(t, ReplaceScript(c, mark))
	if Marks(out)["READY"] != "1" {
		t.Fatalf("not ready: %s", out)
	}
	if psql(t, "5432", "shop", "select count(*) from orders where item = '"+keep+"'") != "1" {
		t.Error("the row from before the mark is gone")
	}
	if psql(t, "5432", "shop", "select to_regclass('dropped_by_mistake') is null") != "t" {
		t.Error("the table made after the mark is still there")
	}
	// Archiving goes on after it, on the new timeline.
	run(t, CheckScript(c))
	run(t, RemoveScript(c, true))
}

// An SFTP repository: this server's own sshd, a key made for the test.
func TestLiveSFTP(t *testing.T) {
	repo := sftpRepo(t)
	c, err := ParseDetect(run(t, DetectScript(5432)), 5432)
	if err != nil {
		t.Fatal(err)
	}
	s := Settings{
		Repo:          repo,
		RetentionFull: 1, CompressLevel: 3, ProcessMax: 2, ArchiveTimeout: 10,
	}
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	if m := Marks(run(t, SetupScript(c, s, true))); m["RESTART"] == "1" {
		run(t, RestartScript(c))
	}
	run(t, BackupScript(c, Full))
	info, err := ParseInfo(run(t, InfoScript(c)))
	if err != nil || len(info.Backups) != 1 {
		t.Fatalf("info %+v %v", info, err)
	}
	run(t, RemoveScript(c, true))
}

// Replace with PostgreSQL already down (the usual reason to restore): it
// comes back, at the newest point.
func TestLiveReplaceDown(t *testing.T) {
	c, err := ParseDetect(run(t, DetectScript(5432)), 5432)
	if err != nil {
		t.Fatal(err)
	}
	s := Settings{
		// SFTP: MinIO refuses writes when the dev machine's disk is nearly full.
		Repo:          sftpRepo(t),
		RetentionFull: 1, CompressLevel: 3, ProcessMax: 2, ArchiveTimeout: 10,
	}
	if m := Marks(run(t, SetupScript(c, s, true))); m["RESTART"] == "1" {
		run(t, RestartScript(c))
	}
	run(t, BackupScript(c, Full))
	last := "last " + time.Now().Format(time.RFC3339Nano)
	psql(t, "5432", "shop", "insert into orders (item) values ('"+last+"')")
	run(t, CheckScript(c))
	if out, err := exec.Command("docker", "exec", box, "pg_ctlcluster", "17", "main", "stop").CombinedOutput(); err != nil {
		t.Fatalf("stop: %v %s", err, out)
	}
	out := run(t, ReplaceScript(c, time.Time{}))
	if Marks(out)["READY"] != "1" {
		t.Fatalf("not ready: %s", out)
	}
	if psql(t, "5432", "shop", "select count(*) from orders where item = '"+last+"'") != "1" {
		t.Error("the last archived row is missing")
	}
	run(t, RemoveScript(c, true))
}

// sftpRepo makes a key for ops on this server's own sshd and returns an
// SFTP repository there.
func sftpRepo(t *testing.T) Repo {
	t.Helper()
	keys := run(t, `set -e
rm -f /tmp/morche-sftp-test /tmp/morche-sftp-test.pub
ssh-keygen -q -t ed25519 -N '' -f /tmp/morche-sftp-test >/dev/null
install -d -o ops -g ops -m 700 /home/ops/.ssh /home/ops/pitr-repo
cat /tmp/morche-sftp-test.pub >> /home/ops/.ssh/authorized_keys
chown ops:ops /home/ops/.ssh/authorized_keys; chmod 600 /home/ops/.ssh/authorized_keys
echo "MORCHE_hostkey=$(awk '{print $1 " " $2}' /etc/ssh/ssh_host_ed25519_key.pub)"
printf 'MORCHE_key='; base64 -w0 /tmp/morche-sftp-test; echo
`)
	m := Marks(keys)
	key, err := base64.StdEncoding.DecodeString(m["key"])
	if err != nil {
		t.Fatal(err)
	}
	return Repo{Type: "sftp", Path: "/home/ops/pitr-repo/" + time.Now().Format("150405.000"), Host: "127.0.0.1", Port: 22,
		User: "ops", PrivateKey: string(key), HostKey: m["hostkey"]}
}
