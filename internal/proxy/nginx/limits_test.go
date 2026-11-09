package nginx

import (
	"strings"
	"testing"

	"github.com/morcheh/backend/internal/proxy"
)

func render(t *testing.T, h proxy.HostConfig, version string) string {
	t.Helper()
	h = proxy.Normalize(h)
	if p := proxy.Validate(h); len(p) > 0 {
		t.Fatalf("invalid host: %+v", p)
	}
	return Driver{}.Render("01AB-cd", h, proxy.Env{Version: version})
}

func has(t *testing.T, got string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("render lacks %q:\n%s", w, got)
		}
	}
}

func before(t *testing.T, got, a, b string) {
	t.Helper()
	i, j := strings.Index(got, a), strings.Index(got, b)
	if i < 0 || j < 0 || i > j {
		t.Errorf("%q should come before %q:\n%s", a, b, got)
	}
}

func TestAccessLists(t *testing.T) {
	got := render(t, proxy.HostConfig{
		Domains: []string{"a.test"}, Type: proxy.TypeProxy, Upstream: "http://127.0.0.1:1",
		Allow: []string{"10.0.0.0/8"}, Deny: []string{"10.1.2.3", "10.1.0.0/16"},
	}, "1.24.0")
	// Narrowest first, then deny all (allow has entries: default deny).
	before(t, got, "deny 10.1.2.3;", "deny 10.1.0.0/16;")
	before(t, got, "deny 10.1.0.0/16;", "allow 10.0.0.0/8;")
	before(t, got, "allow 10.0.0.0/8;", "deny all;")

	open := render(t, proxy.HostConfig{
		Domains: []string{"a.test"}, Type: proxy.TypeProxy, Upstream: "http://127.0.0.1:1",
		Deny: []string{"1.2.3.4"},
	}, "1.24.0")
	if strings.Contains(open, "deny all;") {
		t.Errorf("a block list only shouldn't deny all:\n%s", open)
	}
}

func TestCountries(t *testing.T) {
	got := render(t, proxy.HostConfig{
		Domains: []string{"a.test"}, Type: proxy.TypeProxy, Upstream: "http://127.0.0.1:1",
		Allow: []string{"1.2.3.4"}, Countries: []string{"de", "FR"}, CountryMode: "allow", DefaultAccess: "allow",
	}, "1.24.0")
	has(t, got,
		"geo $morcheh_01abcd_ip {", "1.2.3.4 a;",
		"map $morcheh_country $morcheh_01abcd_cc {", "default d;", `"" a;`, "DE a;", "FR a;",
		"map $uri $morcheh_01abcd_acme {", `~^/\.well-known/acme-challenge/ 1;`,
		`map "$morcheh_01abcd_acme:$morcheh_01abcd_ip:$morcheh_01abcd_cc" $morcheh_01abcd_block {`,
		`"0:n:d" 1;`, "if ($morcheh_01abcd_block) {", "return 403;",
	)
	if strings.Contains(got, "allow 1.2.3.4;") {
		t.Errorf("with countries, addresses go through the geo block:\n%s", got)
	}

	deny := render(t, proxy.HostConfig{
		Domains: []string{"a.test"}, Type: proxy.TypeProxy, Upstream: "http://127.0.0.1:1",
		Countries: []string{"CN"}, CountryMode: "deny",
	}, "1.24.0")
	has(t, deny, "default a;", "CN d;", `map "$morcheh_01abcd_acme:$morcheh_01abcd_cc" $morcheh_01abcd_block {`, `"0:d" 1;`)
}

func TestRateLimits(t *testing.T) {
	got := render(t, proxy.HostConfig{
		Domains: []string{"a.test"}, Type: proxy.TypeProxy, Upstream: "http://127.0.0.1:1",
		Paths: []proxy.PathRule{{Path: "/api/", Upstream: "http://127.0.0.1:2"}},
		RateLimit: proxy.RateLimit{
			Rules: []proxy.RateRule{
				{Rate: 10, Burst: 20},
				{Path: "/login", Rate: 5, Per: "minute", Methods: []string{"post"}},
				{Path: "/api/", Rate: 100, Burst: 50, Mode: "delay", Delay: 10},
			},
			ConnPerIP: 20, DownloadKBs: 500, FullSpeedMB: 10, Exempt: []string{"10.0.0.0/8"}, DryRun: true,
		},
	}, "1.24.0")
	has(t, got,
		"geo $morcheh_01abcd_free_ip {", "10.0.0.0/8 1;",
		`map "$morcheh_01abcd_free_ip:$uri" $morcheh_01abcd_free {`,
		`~^0:/\.well-known/acme-challenge/ 1;`,
		"limit_req_zone $morcheh_01abcd_key_", "rate=10r/s;", "rate=5r/m;",
		"limit_req_status 429;", "limit_req_dry_run on;",
		"burst=20 nodelay;", "burst=50 delay=10;",
		"limit_conn_status 429;", "limit_conn_dry_run on;",
		"limit_rate 500k;", "limit_rate_after 10m;",
		"location /login {",
		`"0:POST" $binary_remote_addr;`,
	)
	// /api/ has its own limit and repeats the site's.
	api := got[strings.Index(got, "location /api/"):]
	api = api[:strings.Index(api, "}")]
	if strings.Count(api, "limit_req zone=") != 2 {
		t.Errorf("/api/ should carry 2 limits:\n%s", api)
	}

	old := render(t, proxy.HostConfig{
		Domains: []string{"a.test"}, Type: proxy.TypeProxy, Upstream: "http://127.0.0.1:1",
		RateLimit: proxy.RateLimit{Rules: []proxy.RateRule{{Rate: 1}}, DryRun: true},
	}, "1.16.0")
	if strings.Contains(old, "dry_run") {
		t.Errorf("nginx 1.16 has no dry run:\n%s", old)
	}
	// Without exempt addresses, ACME challenges still aren't counted.
	has(t, old, "map $uri $morcheh_01abcd_free {", `~^/\.well-known/acme-challenge/ 1;`,
		"limit_req_zone $morcheh_01abcd_key_")
}

func TestStreamLimits(t *testing.T) {
	got := render(t, proxy.HostConfig{
		Type: proxy.TypeStream, ListenPort: 2222, StreamTo: "127.0.0.1:22",
		Allow: []string{"10.0.0.0/8"},
		RateLimit: proxy.RateLimit{
			Rules:     []proxy.RateRule{{Rate: 10}},
			ConnPerIP: 3, ConnTotal: 100, DownloadKBs: 100, UploadKBs: 50, FullSpeedMB: 5,
		},
	}, "1.24.0")
	has(t, got, "limit_conn_zone $binary_remote_addr", "limit_conn_zone $server_port",
		"proxy_download_rate 100k;", "proxy_upload_rate 50k;", "allow 10.0.0.0/8;", "deny all;")
	for _, no := range []string{"limit_req", "limit_rate", "limit_conn_status"} {
		if strings.Contains(got, no) {
			t.Errorf("stream has %q:\n%s", no, got)
		}
	}
}
