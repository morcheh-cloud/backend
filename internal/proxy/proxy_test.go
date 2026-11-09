package proxy

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	ok := Normalize(HostConfig{Domains: []string{" Example.com. ", "*.example.com", "example.com", "10.0.0.1"}, Type: TypeProxy, Upstream: "http://app:3000"})
	if len(ok.Domains) != 3 {
		t.Errorf("domains = %q", ok.Domains)
	}
	if p := Validate(ok); len(p) > 0 {
		t.Errorf("unexpected problems: %v", p)
	}
	bad := Normalize(HostConfig{
		Domains: []string{"bad domain", "a..b"}, Type: TypeProxy, Upstream: "http://x;rm -rf /",
		TLS:      HostTLS{Enabled: true, Certificate: "relative.pem", Key: "/etc/../x"},
		Allow:    []string{"nope"},
		Headers:  []HeaderRule{{To: "response", Name: "X Bad", Value: `a"b`}},
		Paths:    []PathRule{{Path: "/", Upstream: "ftp://x"}, {Path: "/a b", Upstream: "http://x"}},
		Advanced: "}\nserver {",
	})
	got := map[string]bool{}
	for _, p := range Validate(bad) {
		got[p.Field] = true
	}
	for _, f := range []string{"domains[0]", "domains[1]", "upstream", "tls.certificate", "tls.key", "allow[0]", "headers[0].name", "headers[0].value", "paths[0].path", "paths[0].upstream", "paths[1].path", "advanced"} {
		if !got[f] {
			t.Errorf("no problem reported for %s (got %v)", f, got)
		}
	}
	r := Validate(Normalize(HostConfig{Domains: []string{"a.com"}, Type: TypeRedirect, RedirectTo: "https://b.com"}))
	if len(r) > 0 {
		t.Errorf("redirect: %v", r)
	}
	if p := Validate(Normalize(HostConfig{Domains: []string{"a.com"}, Type: TypeStatic, Root: "/var/www/../etc"})); len(p) != 1 || p[0].Field != "root" {
		t.Errorf("static root: %v", p)
	}
}

func TestCheckAdvanced(t *testing.T) {
	for s, ok := range map[string]bool{
		"":                                  true,
		"location /a { return 200; }":       true,
		"# } in a comment\nadd_header X 1;": true,
		`set $x "}";`:                       true,
		"location /a {":                     false,
		"} server {":                        false,
		`set $x "a;`:                        false,
	} {
		if (checkAdvanced(s) == "") != ok {
			t.Errorf("checkAdvanced(%q) = %q", s, checkAdvanced(s))
		}
	}
	_ = strings.TrimSpace
}

func TestCustom(t *testing.T) {
	h := Normalize(HostConfig{Type: TypeProxy, Domains: []string{"a.test"}, Upstream: "http://127.0.0.1:1", Custom: "server {\r\n  listen 80;\r\n}\r\n"})
	if h.Custom != "server {\n  listen 80;\n}" {
		t.Fatalf("custom not tidied: %q", h.Custom)
	}
	if p := Validate(h); len(p) != 0 {
		t.Fatalf("unexpected problems: %v", p)
	}
	for _, bad := range []string{"server {", "}", "MORCHEH_HOST_x", "# @@morcheh-file:x"} {
		h.Custom = bad
		if p := Validate(h); len(p) == 0 || p[0].Field != "custom" {
			t.Errorf("%q: want a custom problem, got %v", bad, p)
		}
	}
}
