package api

import (
	"slices"
	"strings"
	"testing"

	"github.com/morche/backend/internal/sysconf"
)

func TestHostsSummary(t *testing.T) {
	old := sysconf.ParseHosts("127.0.0.1 localhost\n10.0.0.5 db\n10.0.0.6 cache\n")
	add := append(slices.Clone(old), sysconf.HostEntry{Address: "10.0.0.7", Names: []string{"queue"}, Enabled: true})
	if got := hostsSummary(old, add); got != "Add 10.0.0.7 queue" {
		t.Fatal(got)
	}
	if got := hostsSummary(old, old[:2]); got != "Remove 10.0.0.6 cache" {
		t.Fatal(got)
	}
	ch := slices.Clone(old)
	ch[1] = sysconf.HostEntry{Line: 2, Address: "10.0.0.9", Names: []string{"db"}, Enabled: true}
	if got := hostsSummary(old, ch); got != "Change 10.0.0.9 db" {
		t.Fatal(got)
	}
	if got := hostsSummary(old, append(ch[:2], sysconf.HostEntry{Address: "1.2.3.4", Names: []string{"x"}, Enabled: true})); got != "Change 3 entries in /etc/hosts" {
		t.Fatal(got)
	}
}

func TestParseGetent(t *testing.T) {
	got := parseGetent("10.0.0.5      STREAM db\n10.0.0.5      DGRAM  \n10.0.0.5      RAW    \nfd00::5   STREAM db\n")
	if !slices.Equal(got, []string{"10.0.0.5", "fd00::5"}) {
		t.Fatal(got)
	}
}

func TestParseResolvectl(t *testing.T) {
	links := parseResolvectl("Global: 1.1.1.1\nLink 2 (eth0): 192.168.56.1 fe80::1\nLink 3 (docker0):\n",
		"Global:\nLink 2 (eth0): lan ~.\nLink 3 (docker0):\n")
	if len(links) != 2 || links[0].Name != "Global" || links[1].Name != "eth0" ||
		!slices.Equal(links[1].Servers, []string{"192.168.56.1", "fe80::1"}) || !slices.Equal(links[1].Search, []string{"lan", "~."}) {
		t.Fatalf("%+v", links)
	}
}

func TestParseChronyOffset(t *testing.T) {
	if ms, ok := parseClockOffset("Reference ID    : C0A80101\nSystem time     : 0.001234567 seconds slow of NTP time\n"); !ok || ms > -1.2 || ms < -1.3 {
		t.Fatal(ms, ok)
	}
	if ms, ok := parseClockOffset("       Server: 10.0.0.1 (ntp.lan)\n       Offset: -12.345ms\n"); !ok || ms != -12.345 {
		t.Fatal(ms, ok)
	}
	if ms, ok := parseClockOffset("       Offset: +1.5s\n"); !ok || ms != 1500 {
		t.Fatal(ms, ok)
	}
	if _, ok := parseClockOffset("nothing"); ok {
		t.Fatal("no offset")
	}
}

func TestValidTimezone(t *testing.T) {
	for _, z := range []string{"Asia/Tehran", "UTC", "America/Argentina/Buenos_Aires", "Etc/GMT+3"} {
		if !validTimezone(z) {
			t.Error(z)
		}
	}
	for _, z := range []string{"", "../etc/passwd", "Asia/Tehran; rm", "/UTC", "a b"} {
		if validTimezone(z) {
			t.Error(z)
		}
	}
}

func TestKeptFileHidesSecrets(t *testing.T) {
	got, cut := keptFile("[wifi-security]\nkey-mgmt=wpa-psk\npsk=hunter22\n[802-1x]\npassword=s3cret\n")
	if !cut || strings.Contains(got, "hunter22") || strings.Contains(got, "s3cret") || !strings.Contains(got, "psk=<hidden>") {
		t.Fatalf("%v %q", cut, got)
	}
	if got, cut := keptFile("127.0.0.1 localhost\n"); cut || got != "127.0.0.1 localhost\n" {
		t.Fatal(got)
	}
}

func TestConfigScriptKeepsMode(t *testing.T) {
	s := configScript(configPlan{Area: "hosts", Read: []string{"/etc/hosts"}, Writes: []configWrite{{Path: "/etc/hosts", Text: "x\n"}}}, "tok")
	if !strings.Contains(s, `stat -c %a '/etc/hosts'`) {
		t.Fatalf("an existing file's mode must be kept:\n%s", s)
	}
	s = configScript(configPlan{Area: "network", Writes: []configWrite{{Path: "/etc/netplan/a.yaml", Text: "x\n", Mode: "0600"}}}, "tok")
	if !strings.Contains(s, "chmod 0600") {
		t.Fatal(s)
	}
}

func TestCheckRepoAdd(t *testing.T) {
	ok := RepoAddBody{Name: "docker", URIs: []string{"https://download.docker.com/linux/ubuntu"}, Suites: []string{"noble"}, Components: []string{"stable"}, SignedBy: "/etc/apt/keyrings/docker.asc"}
	if err := checkRepoAdd(ok, "apt"); err != nil {
		t.Fatal(err)
	}
	bad := []RepoAddBody{
		{Name: "Docker", URIs: ok.URIs, Suites: ok.Suites},
		{Name: "x", URIs: []string{"ftp://x"}, Suites: ok.Suites},
		{Name: "x", URIs: []string{"https://x/a\nURIs: https://evil"}, Suites: ok.Suites},
		{Name: "x", URIs: ok.URIs, Suites: []string{"noble\nComponents: x"}},
		{Name: "x", URIs: ok.URIs},
		{Name: "x", URIs: ok.URIs, Suites: ok.Suites, SignedBy: "keys/rel"},
	}
	for _, b := range bad {
		if checkRepoAdd(b, "apt") == nil {
			t.Errorf("should refuse %+v", b)
		}
	}
	if checkRepoAdd(RepoAddBody{Name: "x", URIs: ok.URIs, Title: "A\nB"}, "dnf") == nil {
		t.Error("title with a newline")
	}
}

func TestOsRelease(t *testing.T) {
	id, code := osRelease("NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_CODENAME=noble\n")
	if id != "ubuntu" || code != "noble" {
		t.Fatal(id, code)
	}
}

func TestRevisionIgnoresMissingFiles(t *testing.T) {
	a := revisionOf([]configFile{{Path: "/etc/hosts", Text: "x", Exists: true}})
	b := revisionOf([]configFile{{Path: "/etc/hosts", Text: "x", Exists: true}, {Path: "/etc/new.conf"}})
	if a != b {
		t.Fatal("a file that isn't there must not move the revision")
	}
	if c := revisionOf([]configFile{{Path: "/etc/hosts", Text: "x", Exists: true}, {Path: "/etc/new.conf", Exists: true}}); c == a {
		t.Fatal("a file that appeared must move it")
	}
}
