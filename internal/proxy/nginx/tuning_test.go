package nginx

import (
	"strings"
	"testing"

	"github.com/morcheh/backend/internal/proxy"
)

func TestTuning(t *testing.T) {
	h := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"app.example.com"}, Type: "proxy", Upstream: "http://127.0.0.1:3000",
		Gzip: true, ConnectTimeout: 5, HideVersion: true,
		RealIP: proxy.RealIP{From: []string{"173.245.48.0/20", " "}, Header: "CF-Connecting-IP"},
		Paths:  []proxy.PathRule{{Path: "/api/", Upstream: "http://127.0.0.1:4000"}},
	})
	if p := proxy.Validate(h); len(p) > 0 {
		t.Fatalf("problems: %v", p)
	}
	got := Driver{}.Render("h1", h, proxy.Env{Version: "1.24.0"})
	for _, want := range []string{
		"set_real_ip_from 173.245.48.0/20;",
		"real_ip_header CF-Connecting-IP;",
		"server_tokens off;",
		"gzip on;",
		"gzip_types text/plain",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Count(got, "proxy_connect_timeout 5s;") != 2 {
		t.Errorf("connect timeout should go with both proxy_pass:\n%s", got)
	}
	if strings.Contains(got, "real_ip_recursive") || strings.Contains(got, "proxy_buffering") {
		t.Errorf("unexpected lines:\n%s", got)
	}

	s := proxy.Normalize(proxy.HostConfig{
		Type: "stream", ListenPort: 2222, Protocol: "tcp", StreamTo: "10.0.0.2:22",
		ProxyProtocol: true, ConnectTimeout: 3, Gzip: true, HideVersion: true,
	})
	if s.Gzip || s.HideVersion {
		t.Errorf("stream kept site options: %+v", s)
	}
	got = Driver{}.Render("s1", s, proxy.Env{})
	if !strings.Contains(got, "proxy_protocol on;") || !strings.Contains(got, "proxy_connect_timeout 3s;") {
		t.Errorf("stream:\n%s", got)
	}
}

func TestCache(t *testing.T) {
	h := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"app.example.com"}, Type: "proxy", Upstream: "http://127.0.0.1:3000",
		Cache: proxy.Cache{
			AssetDays: 30, PagesFresh: true, Enabled: true, Minutes: 5, ServeStale: true,
			IgnoreUpstream: true, StatusHeader: true,
			SkipPaths: []string{"/admin", "/wp-json/", "/admin"}, SkipCookies: []string{"wordpress_logged_in", "session.id"},
		},
	})
	if p := proxy.Validate(h); len(p) > 0 {
		t.Fatalf("problems: %v", p)
	}
	got := Driver{}.Render("h1", h, proxy.Env{Version: "1.24.0"})
	for _, want := range []string{
		"proxy_cache_path " + CacheDir + "/morcheh_h1 levels=1:2 keys_zone=morcheh_h1_cache:10m max_size=1024m inactive=1440m use_temp_path=off;",
		"map $sent_http_content_type $morcheh_h1_expires {",
		"~^text/html -1;",
		`"~^text/css" 30d;`,
		`"~^/admin(?:/|$)" 1;`,
		`"~^/wp-json/" 1;`,
		`"~(?:^|;)\s*(?:wordpress_logged_in|session\.id)" 1;`,
		"expires $morcheh_h1_expires;",
		"add_header X-Cache-Status $upstream_cache_status always;",
		"proxy_cache morcheh_h1_cache;",
		"proxy_cache_valid 200 301 302 5m;",
		"proxy_cache_bypass $http_authorization $http_upgrade $morcheh_h1_skip_path $morcheh_h1_skip_cookie;",
		"proxy_cache_use_stale error timeout updating",
		"proxy_ignore_headers Cache-Control Expires;",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Count(got, `"~^/admin(?:/|$)" 1;`) != 1 {
		t.Errorf("skip paths aren't tidied:\n%s", got)
	}

	// A static site keeps only the browser part; buffering off can't cache.
	st := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"a.example.com"}, Type: "static", Root: "/var/www/a",
		Cache: proxy.Cache{AssetDays: 7, Enabled: true, SkipPaths: []string{"/x"}},
	})
	if st.Cache.Enabled || len(st.Cache.SkipPaths) > 0 || st.Cache.AssetDays != 7 {
		t.Errorf("static cache = %+v", st.Cache)
	}
	if got := (Driver{}).Render("s", st, proxy.Env{}); strings.Contains(got, "proxy_cache") || !strings.Contains(got, "expires $morcheh_s_expires;") {
		t.Errorf("static:\n%s", got)
	}
	bad := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"a.example.com"}, Type: "proxy", Upstream: "http://127.0.0.1:1", NoBuffering: true,
		Cache: proxy.Cache{Enabled: true, SkipPaths: []string{"no slash"}, SkipCookies: []string{"a b"}},
	})
	fields := map[string]bool{}
	for _, p := range proxy.Validate(bad) {
		fields[p.Field] = true
	}
	for _, f := range []string{"cache.enabled", "cache.skip_paths[0]", "cache.skip_cookies[0]"} {
		if !fields[f] {
			t.Errorf("no problem for %s: %v", f, fields)
		}
	}

	if s := (Driver{}).PurgeCacheScript("01A-b"); !strings.Contains(s, "d="+CacheDir+"/morcheh_01ab\n") {
		t.Errorf("purge script:\n%s", s)
	}
}
