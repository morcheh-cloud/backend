package nginx

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/morcheh/backend/internal/proxy"
)

func redirectHost() proxy.HostConfig {
	return proxy.Normalize(proxy.HostConfig{
		Type: proxy.TypeProxy, Domains: []string{"example.com", "*.example.org"},
		Upstream: "http://127.0.0.1:3000",
		TLS:      proxy.HostTLS{Enabled: true, Certificate: "/etc/ssl/c.pem", Key: "/etc/ssl/c.key", ForceHTTPS: true},
		Redirects: proxy.Redirects{Rules: []proxy.RedirectRule{
			{From: "https://example.com/old-page/", To: "/new-page"},
			{From: "/caf%C3%A9", To: "https://other.com/cafe", Code: 302, KeepQuery: true},
			{From: "/shop?id=5", To: "/products/5"},
			{From: "/blog/", Match: proxy.MatchPrefix, To: "https://blog.example.com", Code: 308},
			{From: `^/item/(\d+)\.html$`, Match: proxy.MatchRegex, To: "/items/$1?ref=old", KeepQuery: true},
			{From: "/gone", Code: 410, To: "/ignored"},
			{From: "/a-very-long-address-that-will-not-fit-in-a-hash-bucket-at-all", To: "/short"},
			{From: "/paused", To: "/x", Off: true},
		}},
	})
}

func TestRenderRedirects(t *testing.T) {
	h := redirectHost()
	if p := proxy.Validate(h); len(p) > 0 {
		t.Fatalf("problems: %+v", p)
	}
	if got := h.Redirects.Rules[0].From; got != "/old-page/" {
		t.Errorf("site address not reduced to its path: %q", got)
	}
	if got := h.Redirects.Rules[1].From; got != "/café" {
		t.Errorf("path not decoded: %q", got)
	}
	out := Driver{}.Render("abc-123", h, proxy.Env{Version: "1.26.0"})
	if f := os.Getenv("NGINX_DUMP"); f != "" {
		os.WriteFile(f, []byte(out), 0o644)
	}
	for _, want := range []string{
		`map $uri $morcheh_abc123_rd {`,
		`"/old-page/" "301:/new-page";`,
		`"/old-page" "301:/new-page";`,
		`"/café" "302:https://other.com/cafe$is_args$args";`,
		`"~^/\\.well-known/acme-challenge/" "";`,
		`"~*^/a-very-long-address-that-will-not-fit-in-a-hash-bucket-at-all$" "301:/short";`,
		`"~*^/blog(?:/(.*))?$" "308:https://blog.example.com/$1";`,
		`"~^/item/(\\d+)\\.html$" "301:/items/$1?ref=old$morcheh_abc123_rdargs";`,
		`default "&$args";`,
		`"/gone" "410:";`,
		`map $request_uri $morcheh_abc123_rdq {`,
		`default $morcheh_abc123_rd;`,
		`"/shop?id=5" "301:/products/5";`,
		`if ($morcheh_abc123_rdq ~ "^301:(/.*)$")`,
		`return 301 https://$host$1;`,
		`if ($morcheh_abc123_rdq ~ "^308:(.+)$")`,
		`if ($morcheh_abc123_rdq = "410:")`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(out, "/paused") {
		t.Error("a rule that is off was written")
	}
}

func TestValidateRedirects(t *testing.T) {
	bad := proxy.Normalize(proxy.HostConfig{
		Type: proxy.TypeProxy, Domains: []string{"example.com"}, Upstream: "http://127.0.0.1:3000",
		Redirects: proxy.Redirects{Rules: []proxy.RedirectRule{
			{From: "/a", To: "/a/"},
			{From: "/b", To: "/x"},
			{From: "/B/", To: "/y"},
			{From: "https://elsewhere.com/c", To: "/z"},
			{From: "/d", To: "/x$1"},
			{From: "/e", Match: proxy.MatchPrefix, To: "/x?y=1"},
			{From: "(", Match: proxy.MatchRegex, To: "/x"},
			{From: "/.well-known/acme-challenge/x", To: "/x"},
			{From: "/f", To: "ftp://x"},
			{From: "/g"},
		}},
	})
	got := map[string]bool{}
	for _, p := range proxy.Validate(bad) {
		got[p.Field] = true
	}
	for _, f := range []string{
		"redirects.rules[0].to", "redirects.rules[2].from", "redirects.rules[3].from",
		"redirects.rules[4].to", "redirects.rules[5].to", "redirects.rules[6].from",
		"redirects.rules[7].from", "redirects.rules[8].to", "redirects.rules[9].to",
	} {
		if !got[f] {
			t.Errorf("no problem on %s", f)
		}
	}
	if got["redirects.rules[1].from"] {
		t.Error("the first of two equal rules was refused")
	}
}

func TestRenderConditionalRedirects(t *testing.T) {
	h := proxy.Normalize(proxy.HostConfig{
		Type: proxy.TypeProxy, Domains: []string{"example.com"}, Upstream: "http://127.0.0.1:3000",
		Redirects: proxy.Redirects{Rules: []proxy.RedirectRule{
			{From: "/shop", To: "/fa/shop", When: &proxy.RedirectWhen{Countries: []string{"ir"}, Languages: []string{"FA"}}},
			{From: "/app", Match: proxy.MatchPrefix, To: "/m", When: &proxy.RedirectWhen{Devices: []string{"phone", "tablet"}}},
			{From: `^/sale/(\d+)$`, Match: proxy.MatchRegex, To: "/offer/$1", Code: 302, When: &proxy.RedirectWhen{From: "2026-11-25T00:00", Until: "2026-12-01T00:00"}},
			{From: "/shop", To: "/en/shop"},
			{From: "/x", To: "/y", When: &proxy.RedirectWhen{}},
		}},
	})
	if p := proxy.Validate(h); len(p) > 0 {
		t.Fatalf("problems: %+v", p)
	}
	if h.Redirects.Rules[4].When != nil {
		t.Errorf("empty conditions kept")
	}
	if !h.Redirects.UsesCountries() {
		t.Errorf("countries not seen")
	}
	out := Driver{}.Render("abc-123", h, proxy.Env{Version: "1.26.0"})
	if f := os.Getenv("NGINX_DUMP"); f != "" {
		os.WriteFile(f, []byte(out), 0o644)
	}
	for _, want := range []string{
		`map $http_user_agent $morcheh_abc123_rddev {`,
		`map $http_accept_language $morcheh_abc123_rdlang {`,
		`map "$time_iso8601|$morcheh_country|$morcheh_abc123_rddev|$morcheh_abc123_rdlang|$uri" $morcheh_abc123_rdc {`,
		`default $morcheh_abc123_rd;`,
		`"~^[^|]*\\|[^|]*\\|[^|]*\\|[^|]*\\|/\\.well-known/acme-challenge/" "";`,
		`"~^[^|]*\\|(?:IR)\\|[^|]*\\|(?i:fa)\\|(?i:/shop)/?$" "301:/fa/shop";`,
		`"~^[^|]*\\|[^|]*\\|(?:phone|tablet)\\|[^|]*\\|(?i:/app)(?:/(.*))?$" "301:/m/$1";`,
		`"/shop" "301:/en/shop";`,
		`if ($morcheh_abc123_rdc ~ "^302:(.+)$")`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s", want)
		}
	}
	if !strings.Contains(out, `(?=(?:2026-11-25T00:00|`) || !strings.Contains(out, `(?:/sale/(\\d+)$)`) {
		t.Errorf("time window or pattern missing:\n%s", out)
	}
	bad := h
	bad.Redirects.Rules = []proxy.RedirectRule{{From: "/a?b=1", To: "/c", Code: 301, Match: "exact", When: &proxy.RedirectWhen{Devices: []string{"phone"}, From: "2026-12-01T00:00", Until: "2026-11-01T00:00"}}}
	if p := proxy.Validate(bad); len(p) != 2 {
		t.Errorf("want 2 problems, got %+v", p)
	}
}

func TestTimeWindow(t *testing.T) {
	ge, lt := regexp.MustCompile("^"+timeAtLeast("2026-11-25T09:30")), regexp.MustCompile("^"+timeBelow("2026-12-01T00:00"))
	for s, want := range map[string][2]bool{
		"2026-11-25T09:30:00+03:30": {true, true},
		"2026-11-25T09:29:59+03:30": {false, true},
		"2026-11-30T23:59:59+00:00": {true, true},
		"2026-12-01T00:00:00+00:00": {true, false},
		"2027-01-01T00:00:00+00:00": {true, false},
		"2025-12-31T23:59:00+00:00": {false, true},
	} {
		if ge.MatchString(s) != want[0] || lt.MatchString(s) != want[1] {
			t.Errorf("%s: got %v %v, want %v", s, ge.MatchString(s), lt.MatchString(s), want)
		}
	}
}
