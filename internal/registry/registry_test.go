package registry

import (
	"os"
	"strings"
	"testing"
)

func TestHarborYML(t *testing.T) {
	c := HarborConfig{Dir: "/opt/morche/projects/harbor", Hostname: "reg.example.com", ExternalURL: "https://reg.example.com",
		Port: 8480, AdminPassword: `a"b\c`, DBPassword: "db-pw", Scanner: true}
	y := HarborYML(c)
	for _, want := range []string{`hostname: "reg.example.com"`, "  port: 8480", `external_url: "https://reg.example.com"`,
		`harbor_admin_password: "a\"b\\c"`, "data_volume: /opt/morche/projects/harbor/data", "trivy:"} {
		if !strings.Contains(y, want) {
			t.Errorf("harbor.yml lacks %q", want)
		}
	}
	if strings.Contains(y, "https:") && !strings.Contains(y, "external_url") {
		t.Error("harbor.yml must not have an https section")
	}
	if got := HarborDBPassword(y); got != "db-pw" {
		t.Errorf("db password = %q", got)
	}
	if out := os.Getenv("MORCHE_HARBOR_YML"); out != "" {
		_ = os.WriteFile(out, []byte(y), 0o600)
	}
}

func TestHtpasswd(t *testing.T) {
	a, _ := HtpasswdLine("admin", "secret")
	b, _ := HtpasswdLine("ci", "x")
	text := SetHtpasswd("", "admin", a)
	text = SetHtpasswd(text, "ci", b)
	if got := HtpasswdUsers(text); strings.Join(got, ",") != "admin,ci" {
		t.Fatalf("users = %v", got)
	}
	text = SetHtpasswd(text, "ci", "")
	if got := HtpasswdUsers(text); strings.Join(got, ",") != "admin" {
		t.Fatalf("after remove = %v", got)
	}
	if !strings.HasPrefix(strings.SplitN(a, ":", 2)[1], "$2a$") {
		t.Error("not bcrypt")
	}
}

func TestVerdaccioYAML(t *testing.T) {
	s := RegistrySettings{Mirror: true, Scopes: []string{"Company", "@x"}}
	if p := s.Clean(Verdaccio); len(p) > 0 {
		t.Fatal(p)
	}
	y := VerdaccioYAML(VerdaccioConfig{Name: "npm", Settings: s})
	for _, want := range []string{`"@company/*":`, `"@x/*":`, "proxy: npmjs", `access: "$authenticated"`, "max_users: -1", `url: "https://registry.npmjs.org/"`} {
		if !strings.Contains(y, want) {
			t.Errorf("config.yaml lacks %q:\n%s", want, y)
		}
	}
	// A private scope is never fetched from the mirror.
	i := strings.Index(y, `"@company/*":`)
	j := strings.Index(y, `"@*/*":`)
	if strings.Contains(y[i:j], "proxy:") {
		t.Error("private scope goes through the mirror")
	}
}

func TestPassword(t *testing.T) {
	for range 50 {
		p := Password(16)
		if len(p) != 16 || !strings.ContainsAny(p, "ABCDEFGHJKLMNPQRSTUVWXYZ") || !strings.ContainsAny(p, "abcdefghijkmnopqrstuvwxyz") || !strings.ContainsAny(p, "23456789") {
			t.Fatal(p)
		}
	}
}

func TestValidPackage(t *testing.T) {
	for _, n := range []string{"react", "@types/node", "lodash.merge"} {
		if !ValidPackage(n) {
			t.Error(n)
		}
	}
	for _, n := range []string{"../etc", "@a/../b", "a b", "", "@/x"} {
		if ValidPackage(n) {
			t.Error(n)
		}
	}
}
