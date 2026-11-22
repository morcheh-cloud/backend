package pitr

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

var cluster = PitrCluster{
	Version: 17, DataDir: "/var/lib/postgresql/17/main", ConfigFile: "/etc/postgresql/17/main/postgresql.conf",
	HbaFile: "/etc/postgresql/17/main/pg_hba.conf", IdentFile: "/etc/postgresql/17/main/pg_ident.conf",
	Port: 5432, Socket: "/var/run/postgresql", BinDir: "/usr/lib/postgresql/17/bin",
	ArchiveMode: "off", WalLevel: "replica", PgCluster: "17 main",
}

var settings = Settings{
	Repo: Repo{
		Type: "s3", Path: "/pgbackrest/abc", Endpoint: "s3.example.com", Port: 9000, Bucket: "backups",
		Region: "eu", Key: "AKIA", Secret: "s3cr'et$(x)", PathStyle: true,
	},
	RetentionFull: 2, CompressLevel: 3, ProcessMax: 2, ArchiveTimeout: 60, CipherPass: "pass'word",
}

// Every script must at least parse.
func TestScriptsParse(t *testing.T) {
	sftp := settings
	sftp.Repo = Repo{Type: "sftp", Path: "/backups", Host: "files", User: "u", PrivateKey: "-----BEGIN KEY-----\nabc\n-----END KEY-----\n", HostKey: "ssh-ed25519 AAAAC3Nza"}
	at := time.Date(2026, 11, 22, 10, 30, 0, 0, time.UTC)
	scripts := map[string]string{
		"detect":      DetectScript(5432),
		"setup":       SetupScript(cluster, settings, false),
		"setup sftp":  SetupScript(cluster, sftp, true),
		"restart":     RestartScript(cluster),
		"check":       CheckScript(cluster),
		"backup":      BackupScript(cluster, Diff),
		"info":        InfoScript(cluster),
		"restore new": RestoreNewScript(cluster, at, "20261122-103000", 15432, 1<<30),
		"latest":      RestoreNewScript(cluster, time.Time{}, "x", 15432, 0),
		"teardown":    TeardownScript(cluster, "/var/lib/postgresql/17/morche-restore-x"),
		"replace":     ReplaceScript(cluster, at),
		"remove":      RemoveScript(cluster, true),
	}
	for name, s := range scripts {
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(s)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: %v %s\n%s", name, err, out, s)
		}
	}
}

// Secrets go in the config through a quoted here-document, never on a
// command line.
func TestSecretsStayOffCommandLines(t *testing.T) {
	s := SetupScript(cluster, settings, false)
	in := false
	for line := range strings.SplitSeq(s, "\n") {
		switch {
		case strings.HasPrefix(line, "cat > ") && strings.Contains(line, "<<'MORCHE_"):
			in = true
			continue
		case strings.HasPrefix(line, "MORCHE_CONF_EOF"), strings.HasPrefix(line, "MORCHE_KEY_EOF"):
			in = false
			continue
		}
		if !in && (strings.Contains(line, "s3cr") || strings.Contains(line, "pass'word")) {
			t.Errorf("secret outside the config: %q", line)
		}
	}
	if !strings.Contains(s, "repo1-s3-key-secret=s3cr'et$(x)\n") || !strings.Contains(s, "repo1-storage-port=9000\n") {
		t.Errorf("config:\n%s", s)
	}
}

func TestSettingsCheck(t *testing.T) {
	if err := settings.Check(); err != nil {
		t.Fatal(err)
	}
	bad := settings
	bad.Repo.Secret = "a\nrepo1-path=/elsewhere"
	if bad.Check() == nil {
		t.Error("a newline in a value was let through")
	}
	ftp := settings
	ftp.Repo.Type = "ftp"
	if ftp.Check() == nil {
		t.Error("ftp was accepted")
	}
}

func TestRefusesForeignArchiveCommand(t *testing.T) {
	c := cluster
	c.ArchiveCommand = "cp %p /mnt/wal/%f"
	if !strings.Contains(SetupScript(c, settings, false), "unless you ask it to") {
		t.Error("someone else's archive_command would be replaced")
	}
	if strings.Contains(SetupScript(c, settings, true), "unless you ask it to") {
		t.Error("replace was asked for")
	}
}

func TestParseInfo(t *testing.T) {
	out := `noise
MORCHE_info=[{"archive":[{"database":{"id":1,"repo-key":1},"id":"17-1","max":"000000010000000000000009","min":"000000010000000000000001"}],"backup":[{"archive":{"start":"000000010000000000000003","stop":"000000010000000000000003"},"database":{"id":1,"repo-key":1},"error":false,"info":{"delta":31000000,"repository":{"delta":4000000,"size":4000000},"size":31000000},"label":"20261122-100000F","lsn":{"start":"0/3000028","stop":"0/3000100"},"prior":null,"timestamp":{"start":1795341600,"stop":1795341660},"type":"full"},{"archive":{"start":"000000010000000000000006","stop":"000000010000000000000006"},"database":{"id":1,"repo-key":1},"error":false,"info":{"delta":800000,"repository":{"delta":90000,"size":4000000},"size":31800000},"label":"20261122-100000F_20261122-110000D","lsn":{"start":"0/6000028","stop":"0/6000100"},"prior":"20261122-100000F","timestamp":{"start":1795345200,"stop":1795345230},"type":"diff"}],"cipher":"aes-256-cbc","db":[{"id":1,"repo-key":1,"system-id":7,"version":"17"}],"name":"morche","repo":[{"cipher":"aes-256-cbc","key":1,"status":{"code":0,"message":"ok"}}],"status":{"code":0,"lock":{"backup":{"held":false}},"message":"ok"}}]
MORCHE_archiver={"archived_count":9,"last_archived_wal":"000000010000000000000009","last_archived_time":"2026-11-22T11:30:00.5+00:00","failed_count":1,"last_failed_wal":"000000010000000000000004","last_failed_time":"2026-11-22T10:20:00+00:00","stats_reset":"2026-11-22T09:00:00+00:00"}
MORCHE_now=2026-11-22T11:31:00.000000Z
`
	info, err := ParseInfo(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Status != "ok" || len(info.Backups) != 2 || info.Backups[1].Prior != "20261122-100000F" || info.Backups[0].PGVersion != "17" {
		t.Fatalf("%+v", info)
	}
	from, to := info.Window()
	if !from.Equal(time.Unix(1795341660, 0)) || !to.Equal(time.Date(2026, 11, 22, 11, 30, 0, 5e8, time.UTC)) {
		t.Errorf("window %v → %v", from, to)
	}
	if info.Archiver.Failing() {
		t.Error("the archiver recovered after its failure")
	}
	if l := info.Latest(Full); l == nil || l.Label != "20261122-100000F" {
		t.Errorf("latest full %+v", l)
	}
	if info.RepoSize() != 4090000 {
		t.Errorf("repo size %d", info.RepoSize())
	}
}

func TestParseDetect(t *testing.T) {
	out := "MORCHE_version=170006\nMORCHE_data_directory=/var/lib/postgresql/17/main\nMORCHE_bindir=/usr/lib/postgresql/17/bin\nMORCHE_archive_mode=off\nMORCHE_archive_command=(disabled)\nMORCHE_pg_cluster=17 main\nMORCHE_free=1073741824\n"
	c, err := ParseDetect(out, 5432)
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != 17 || c.PgCluster != "17 main" || !c.Ours() || !c.NeedsRestart() || c.FreeBytes != 1<<30 {
		t.Errorf("%+v", c)
	}
}
