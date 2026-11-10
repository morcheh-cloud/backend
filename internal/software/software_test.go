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
		if r.Kind == KindDocker && len(r.Images()) == 0 {
			t.Errorf("%s: no images", r.ID)
		}
		for _, s := range []string{InstallScript(r, map[string]string{}, InstallOptions{}), UpdateScript(r), UninstallScript(r, UninstallOptions{})} {
			if !strings.Contains(s, "need_root") {
				t.Errorf("%s: script without need_root", r.ID)
			}
		}
	}
}

func TestValues(t *testing.T) {
	r, _ := Find(Builtins(), "grafana")
	v, gen, err := r.Values(map[string]string{"PORT": "3100"})
	if err != nil {
		t.Fatal(err)
	}
	if v["PORT"] != "3100" || len(v["ADMIN_PASSWORD"]) != 24 || len(gen) != 1 {
		t.Fatalf("values %v generated %v", v, gen)
	}
	if _, _, err := r.Values(map[string]string{"PORT": "70000"}); err == nil {
		t.Fatal("port 70000 accepted")
	}
	if _, _, err := r.Values(map[string]string{"NOPE": "1"}); err == nil {
		t.Fatal("unknown param accepted")
	}
	if _, _, err := r.Values(map[string]string{"ADMIN_PASSWORD": "a'b"}); err == nil {
		t.Fatal("quote accepted in a docker value")
	}
}

func TestSplit(t *testing.T) {
	cases := map[string][3]string{
		"redis:8":                      {"registry-1.docker.io", "library/redis", "8"},
		"grafana/grafana":              {"registry-1.docker.io", "grafana/grafana", "latest"},
		"ghcr.io/org/app:1.2":          {"ghcr.io", "org/app", "1.2"},
		"localhost:5000/x/y":           {"localhost:5000", "x/y", "latest"},
		"docker.io/library/nginx:1.27": {"registry-1.docker.io", "library/nginx", "1.27"},
	}
	for ref, want := range cases {
		h, r, tag := Split(ref)
		if [3]string{h, r, tag} != want {
			t.Errorf("%s: got %s %s %s", ref, h, r, tag)
		}
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
		"@@ app:grafana", "rollback=1", "services=grafana ",
		"c\tsha256:abc\tgrafana\tgrafana/grafana:latest\trunning\tgrafana/grafana@sha256:111\t11.3.0",
		"@@ containers",
		"f00\tlouislam/uptime-kuma:2\trunning\tkuma\tkuma\t/srv/kuma\tlouislam/uptime-kuma@sha256:222\t",
		"f01\tnginx:latest\trunning\t\t\t\t\t",
	}, "\n")
	s := ParseScan(out, Builtins(), ScanOptions{Full: true})
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
	if g := got["grafana"]; g.State != "running" || g.Version != "11.3.0" || !g.CanRollback || g.Origin != "morcheh" ||
		len(g.Images) != 1 || g.Images[0].Digests[0] != "sha256:111" {
		t.Errorf("grafana %+v", g)
	}
	if k := got["uptime-kuma"]; k.Origin != "found" || k.Project != "kuma" || k.Dir != "/srv/kuma" || k.Version != "2" {
		t.Errorf("kuma %+v", k)
	}
}

func TestScriptsParse(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	scripts := map[string]string{
		"scan":    ScanScript(Builtins(), ScanOptions{Full: true}),
		"scan1":   ScanScript(Builtins()[:2], ScanOptions{Apps: []string{"grafana"}}),
		"system":  SystemUpgradeScript(SystemOptions{}),
		"sec":     SystemUpgradeScript(SystemOptions{SecurityOnly: true}),
		"full":    SystemUpgradeScript(SystemOptions{Full: true}),
		"compose": SaveComposeScript("grafana", "services: {}\n"),
		"logs":    ComposeScript("grafana", "logs --tail 10"),
	}
	for _, r := range Builtins() {
		scripts["install-"+r.ID] = InstallScript(r, map[string]string{"X": "y"}, InstallOptions{Fresh: true})
		scripts["update-"+r.ID] = UpdateScript(r)
		scripts["remove-"+r.ID] = UninstallScript(r, UninstallOptions{RemoveData: true})
		scripts["keep-"+r.ID] = UninstallScript(r, UninstallOptions{})
		scripts["pre-"+r.ID] = PreflightScript(r, []int{80})
		if r.Kind == KindDocker {
			scripts["rollback-"+r.ID] = RollbackScript(r)
		}
	}
	for name, s := range scripts {
		cmd := exec.Command(sh, "-n")
		cmd.Stdin = strings.NewReader(s)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: %v %s", name, err, out)
		}
	}
}
