package software

import (
	"os/exec"
	"strings"
	"testing"
)

func TestBuiltinsLoad(t *testing.T) {
	if len(Builtins()) < 15 {
		t.Fatalf("only %d built-in recipes", len(Builtins()))
	}
	for _, r := range Builtins() {
		if r.Kind != KindPackage && r.Kind != KindScript {
			t.Errorf("%s: kind %q", r.ID, r.Kind)
		}
		for _, s := range []string{InstallScript(r), UpdateScript(r), UninstallScript(r)} {
			if !strings.Contains(s, "need_root") {
				t.Errorf("%s: script without need_root", r.ID)
			}
		}
	}
}

func TestValues(t *testing.T) {
	r, _ := Find(Builtins(), "swap")
	v, _, err := r.Values(map[string]string{"SIZE": "4"})
	if err != nil {
		t.Fatal(err)
	}
	if v["SIZE"] != "4" || v["SWAPPINESS"] != "10" {
		t.Fatalf("values %v", v)
	}
	if _, _, err := r.Values(map[string]string{"SIZE": "lots"}); err == nil {
		t.Fatal("a word accepted as a number")
	}
	if _, _, err := r.Values(map[string]string{"NOPE": "1"}); err == nil {
		t.Fatal("unknown param accepted")
	}
}

func TestDockerKindRefused(t *testing.T) {
	r := Recipe{ID: "x", Name: "X", Kind: "docker"}
	if err := r.Check(); err == nil {
		t.Fatal("a docker recipe passed the check")
	}
}

func TestPrettyVersion(t *testing.T) {
	for in, want := range map[string]string{
		"5:27.3.1-1~ubuntu.24.04~noble": "27.3.1",
		"1:2.43.0-1ubuntu7.1":           "2.43.0",
		"3.12.3-0ubuntu2":               "3.12.3",
		"2.43.0":                        "2.43.0",
	} {
		if got := prettyVersion(in); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}

func TestParseScan(t *testing.T) {
	out := strings.Join([]string{
		"@@ host", "pm=apt", "root=1", "docker=27.3.1", "compose=2.29.7", "reboot=1",
		"@@ packages",
		"Listing...",
		"openssl/noble-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3.1]",
		"git/noble-updates 1:2.43.0-1ubuntu7.2 amd64 [upgradable from: 1:2.43.0-1ubuntu7.1]",
		"@@ recipe:git", "pkg=1:2.43.0-1ubuntu7.1", "latest=1:2.43.0-1ubuntu7.2", "version=2.43.0",
		"@@ recipe:htop",
	}, "\n")
	s := ParseScan(out, Builtins())
	if s.Host.PM != "apt" || !s.Host.RebootRequired || s.Host.Upgradable != 2 || s.Host.Security != 1 {
		t.Fatalf("host %+v", s.Host)
	}
	got := map[string]Found{}
	for _, f := range s.Software {
		got[f.RecipeID] = f
	}
	if g := got["git"]; !g.UpdateAvailable || g.Version != "2.43.0" {
		t.Errorf("git %+v", g)
	}
	if _, ok := got["htop"]; ok {
		t.Error("htop found")
	}
}

func TestScriptsParse(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	scripts := map[string]string{
		"scan":   ScanScript(Builtins(), ScanOptions{Full: true}),
		"scan1":  ScanScript(Builtins()[:2], ScanOptions{}),
		"system": SystemUpgradeScript(SystemOptions{}),
		"sec":    SystemUpgradeScript(SystemOptions{SecurityOnly: true}),
		"full":   SystemUpgradeScript(SystemOptions{Full: true}),
	}
	for _, r := range Builtins() {
		scripts["install-"+r.ID] = InstallScript(r)
		scripts["update-"+r.ID] = UpdateScript(r)
		scripts["remove-"+r.ID] = UninstallScript(r)
		scripts["pre-"+r.ID] = PreflightScript(r, []int{80})
	}
	for name, s := range scripts {
		cmd := exec.Command(sh, "-n")
		cmd.Stdin = strings.NewReader(s)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: %v %s", name, err, out)
		}
	}
}
