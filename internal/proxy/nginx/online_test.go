package nginx

import (
	"strings"
	"testing"

	"github.com/morcheh/backend/internal/proxy"
)

func onlineHost(c proxy.Cache) proxy.HostConfig {
	return proxy.Normalize(proxy.HostConfig{
		Domains: []string{"app.example.com"}, Type: "proxy", Upstream: "http://127.0.0.1:3000",
		Cache: c,
	})
}

func TestAlwaysOnlineBackupOnly(t *testing.T) {
	h := onlineHost(proxy.Cache{
		Online:      proxy.AlwaysOnline{Mode: "backup", KeepDays: 3, Statuses: []int{429, 502, 503}},
		SkipCookies: []string{"sessionid"}, Minutes: 60, VaryDevice: true,
	})
	if p := proxy.Validate(h); len(p) > 0 {
		t.Fatalf("problems: %v", p)
	}
	if h.Cache.Minutes != 0 || h.Cache.VaryDevice || len(h.Cache.SkipCookies) != 1 {
		t.Errorf("cache off: only the Never keep lists stay, got %+v", h.Cache)
	}
	got := Driver{}.Render("h1", h, proxy.Env{Version: "1.24.0"})
	for _, want := range []string{
		"keys_zone=morcheh_h1_cache:10m max_size=1024m inactive=4320m",
		"map $upstream_http_cache_control $morcheh_h1_private",
		"proxy_cache_valid 200 301 302 1s;",
		"proxy_cache_revalidate on;",
		"proxy_no_cache $http_authorization $http_upgrade $morcheh_h1_skip_cookie $morcheh_h1_private;",
		"proxy_cache_use_stale error timeout http_502 http_503 http_429;",
		"proxy_ignore_headers Cache-Control Expires;",
		"proxy_connect_timeout 5s;",
		"proxy_pass http://127.0.0.1:3000;",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	for _, bad := range []string{"updating", "background_update", "proxy_cache_valid 404", "X-Cache-Status"} {
		if strings.Contains(got, bad) {
			t.Errorf("unexpected %q in\n%s", bad, got)
		}
	}
}

func TestAlwaysOnlineWithCache(t *testing.T) {
	h := onlineHost(proxy.Cache{
		Enabled: true, Minutes: 60,
		Online: proxy.AlwaysOnline{Mode: "fast", KeepDays: 30, WaitSeconds: 3, KeepPrivate: true},
	})
	h.ConnectTimeout = 10
	got := Driver{}.Render("h1", h, proxy.Env{Version: "1.24.0"})
	for _, want := range []string{
		"inactive=43200m",
		"proxy_cache_valid 200 301 302 60m;",
		"proxy_cache_use_stale error timeout updating;",
		"proxy_cache_background_update on;",
		"proxy_connect_timeout 3s;",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "_private") || strings.Contains(got, "proxy_ignore_headers") {
		t.Errorf("with the cache on, the app's headers decide:\n%s", got)
	}
}

func TestAlwaysOnlineCopiesOnly(t *testing.T) {
	h := onlineHost(proxy.Cache{Online: proxy.AlwaysOnline{Mode: "copies"}})
	got := Driver{}.Render("h1", h, proxy.Env{Version: "1.24.0"})
	if !strings.Contains(got, "proxy_pass "+offlineUpstream+";") || strings.Contains(got, "127.0.0.1:3000") {
		t.Errorf("copies only never asks the app:\n%s", got)
	}
}

func TestServeStaleBecomesAlwaysOnline(t *testing.T) {
	h := onlineHost(proxy.Cache{Enabled: true, ServeStale: true})
	if h.Cache.ServeStale || h.Cache.Online.Mode != "fast" || len(h.Cache.Online.Statuses) != 4 {
		t.Fatalf("got %+v", h.Cache)
	}
	got := Driver{}.Render("h1", h, proxy.Env{Version: "1.24.0"})
	if !strings.Contains(got, "proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;") {
		t.Errorf("old serve_stale lost:\n%s", got)
	}
	if off := onlineHost(proxy.Cache{}); off.Cache.Keeps() {
		t.Errorf("nothing on keeps nothing: %+v", off.Cache)
	}
	bad := onlineHost(proxy.Cache{Online: proxy.AlwaysOnline{Mode: "backup", Statuses: []int{404}}})
	if p := proxy.Validate(bad); len(p) == 0 {
		t.Error("404 should be refused")
	}
}

func TestParseKeptPages(t *testing.T) {
	out := "MORCHEH_PAGES\t3\t20\t1000\n" +
		"P\t990\t2048\tHTTP/1.1 200 OK\tKEY: httpsapp.example.com/blog?page=2\n" +
		"P\t400\t1024\tHTTP/1.1 301 Moved Permanently\tKEY: mobile,android|httpshop.com/\n" +
		"P\t100\t512\t\tKEY: httpsother.org/x\n"
	r, ok := proxy.ParseKeptPages(out, []string{"app.example.com", "shop.com"})
	if !ok || r.Total != 3 || r.Bytes != 20*1024 || len(r.Pages) != 3 {
		t.Fatalf("got %+v %v", r, ok)
	}
	if p := r.Pages[0]; p.URL != "https://app.example.com/blog?page=2" || p.Path != "/blog?page=2" || p.Status != 200 || p.AgeSeconds != 10 || p.Bytes != 2048 {
		t.Errorf("page 0: %+v", p)
	}
	if p := r.Pages[1]; p.URL != "http://shop.com/" || p.Variant != "mobile,android" || p.Status != 301 {
		t.Errorf("page 1: %+v", p)
	}
	if p := r.Pages[2]; p.URL != "https://other.org/x" || p.Status != 0 {
		t.Errorf("page 2: %+v", p)
	}
	if _, ok := proxy.ParseKeptPages("oops", nil); ok {
		t.Error("no summary line should fail")
	}
}

func TestAlwaysOnlineSlowPages(t *testing.T) {
	h := onlineHost(proxy.Cache{
		Online:      proxy.AlwaysOnline{Mode: "backup", SlowSeconds: 15, KeepDays: 365},
		SkipPaths:   []string{"/admin"},
		SkipCookies: []string{"sessionid"},
	})
	h.TimeoutSeconds = 120
	h.WebSockets = true
	h.ErrorPages = []proxy.ErrorPage{{Codes: []int{502}, Title: "Down", Message: "Back soon"}}
	if p := proxy.Validate(h); len(p) > 0 {
		t.Fatalf("problems: %v", p)
	}
	got := Driver{}.Render("h1", h, proxy.Env{Version: "1.24.0"})
	for _, want := range []string{
		"inactive=525600m",
		`map "$request_method:$http_upgrade$http_authorization:$morcheh_h1_skip_path$morcheh_h1_skip_cookie" $morcheh_h1_pass`,
		`"~^(?:GET|HEAD)::0*$" 0;`,
		"error_page 418 = @morcheh_h1_pass;",
		"if ($morcheh_h1_pass) {",
		"proxy_read_timeout 15s;",
		"proxy_send_timeout 120s;",
		"location @morcheh_h1_pass {",
		"proxy_read_timeout 120s;",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	// The site's error pages are repeated in location / (its own error_page
	// drops the server's), and the twin keeps no copies.
	loc := got[strings.Index(got, "location / {"):]
	if !strings.Contains(loc[:strings.Index(loc, "proxy_pass")], "error_page 502") {
		t.Errorf("error pages not repeated in location /:\n%s", loc)
	}
	twin := got[strings.Index(got, "location @morcheh_h1_pass {"):]
	twin = twin[:strings.Index(twin, "\n    }")]
	if strings.Contains(twin, "proxy_cache") || !strings.Contains(twin, "proxy_connect_timeout 5s;") {
		t.Errorf("twin location:\n%s", twin)
	}
}

func TestAlwaysOnlineSlowNotUsed(t *testing.T) {
	for name, c := range map[string]struct {
		mode    string
		timeout int
	}{
		"copies":          {"copies", 0},
		"shorter timeout": {"backup", 10},
	} {
		h := onlineHost(proxy.Cache{Online: proxy.AlwaysOnline{Mode: c.mode, SlowSeconds: 15}})
		h.TimeoutSeconds = c.timeout
		got := Driver{}.Render("h1", h, proxy.Env{Version: "1.24.0"})
		if strings.Contains(got, "morcheh_h1_pass") || strings.Contains(got, "418") {
			t.Errorf("%s: unexpected slow route in\n%s", name, got)
		}
	}
}
