package nginx

import (
	"regexp"
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
		"proxy_cache_path " + CacheDir + "/morcheh_h1 levels=1:2 keys_zone=morcheh_h1_cache:10m max_size=1024m inactive=10080m use_temp_path=off;",
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

	if s := (Driver{}).PurgeCacheScript("01A-b", proxy.PurgeFilter{}, false); !strings.Contains(s, "d="+CacheDir+"/morcheh_01ab\n") || strings.Contains(s, "grep -l") {
		t.Errorf("purge script:\n%s", s)
	}
}

func TestCacheKey(t *testing.T) {
	for q, want := range map[string]string{
		"":     "proxy_cache_key $scheme$host$request_uri;",
		"none": "proxy_cache_key $scheme$host$uri;",
		"only": "proxy_cache_key $scheme$host$uri?page=$arg_page&lang=$arg_lang;",
	} {
		h := proxy.Normalize(proxy.HostConfig{
			Domains: []string{"a.example.com"}, Type: "proxy", Upstream: "http://127.0.0.1:1",
			Cache: proxy.Cache{Enabled: true, Query: q, QueryParams: []string{"page", "lang", "page"}},
		})
		if p := proxy.Validate(h); len(p) > 0 {
			t.Fatalf("%q: %v", q, p)
		}
		if got := (Driver{}).Render("k", h, proxy.Env{}); !strings.Contains(got, want) {
			t.Errorf("%q: missing %q in\n%s", q, want, got)
		}
	}
	bad := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"a.example.com"}, Type: "proxy", Upstream: "http://127.0.0.1:1",
		Cache: proxy.Cache{Enabled: true, Query: "only", Groups: []proxy.CacheGroup{
			{Name: "Blog", Paths: []string{"/blog/", "has space"}},
			{Name: "blog", Header: "Bad Header"},
			{Name: " "},
			{Name: "Tags", Value: "x"},
		}},
	})
	fields := map[string]bool{}
	for _, p := range proxy.Validate(bad) {
		fields[p.Field] = true
	}
	for _, f := range []string{
		"cache.query_params", "cache.groups[0].paths[1]", "cache.groups[1].name",
		"cache.groups[1].header", "cache.groups[2].name", "cache.groups[2].paths", "cache.groups[3].header",
	} {
		if !fields[f] {
			t.Errorf("no problem for %s: %v", f, fields)
		}
	}
}

func TestCacheVary(t *testing.T) {
	h := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"a.example.com"}, Type: "proxy", Upstream: "http://127.0.0.1:1",
		Cache: proxy.Cache{
			Enabled: true, StatusHeader: true, VaryDevice: true, VaryOS: true, VaryLanguage: true,
			VaryHeaders: []string{"X-Country:"}, VaryCookies: []string{"currency"},
		},
	})
	if p := proxy.Validate(h); len(p) > 0 {
		t.Fatal(p)
	}
	got := (Driver{}).Render("k", h, proxy.Env{})
	for _, want := range []string{
		`proxy_cache_key "$morcheh_k_device,$morcheh_k_os,$morcheh_k_lang,$morcheh_k_vh0,$morcheh_k_vc0|$scheme$host$request_uri";`,
		"map $http_user_agent $morcheh_k_device", "map $http_user_agent $morcheh_k_os",
		"map $http_accept_language $morcheh_k_lang", "map $http_x_country $morcheh_k_vh0",
		"map $cookie_currency $morcheh_k_vc0", `add_header X-Cache-Variant`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	bad := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"a.example.com"}, Type: "proxy", Upstream: "http://127.0.0.1:1",
		Cache: proxy.Cache{Enabled: true, VaryHeaders: []string{"User-Agent", "Bad Name"}, VaryCookies: []string{"a-b"}},
	})
	fields := map[string]bool{}
	for _, p := range proxy.Validate(bad) {
		fields[p.Field] = true
	}
	for _, f := range []string{"cache.vary_headers[0]", "cache.vary_headers[1]", "cache.vary_cookies[0]"} {
		if !fields[f] {
			t.Errorf("no problem for %s: %v", f, fields)
		}
	}
}

func TestCacheRules(t *testing.T) {
	h := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"a.example.com"}, Type: "proxy", Upstream: "http://127.0.0.1:1",
		Cache: proxy.Cache{Enabled: true, Query: "none", Groups: []proxy.CacheGroup{
			{Name: "API", Paths: []string{"/api/"}, Never: true},
			{Name: "Images\nevil", Paths: []string{"*.png", "/img"}, Minutes: 600},
			{Name: "Tags", Header: "Cache-Tag"},
		}},
	})
	if p := proxy.Validate(h); len(p) > 0 {
		t.Fatal(p)
	}
	got := (Driver{}).Render("k", h, proxy.Env{})
	for _, want := range []string{
		`location ~ "^(?:/api/)"`, "proxy_no_cache 1;",
		`location ~ "^(?:/.*\.png(?:/|$)|/img(?:/|$))"`, "proxy_cache_valid 200 301 302 600m;",
		"# Cache rule: Images evil", "inactive=1440m",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Count(got, "proxy_pass http://127.0.0.1:1;") != 3 {
		t.Errorf("want proxy_pass in / and both rules:\n%s", got)
	}
	for re, cases := range map[string]map[string]bool{
		"/blog":  {"/blog": true, "/blog/x": true, "/blogs": false},
		"/blog/": {"/blog/x": true, "/blog": false},
		"*.css":  {"/a.css": true, "/x/y.css": true, "/a.js": false},
		"/img/*": {"/img/a/b": true, "/im": false},
	} {
		r := regexp.MustCompile("^(?:" + rulePathRegexp(re) + ")")
		for path, ok := range cases {
			if r.MatchString(path) != ok {
				t.Errorf("%s on %s: want %v", re, path, ok)
			}
		}
	}

	based := h
	based.Upstream = "http://127.0.0.1:1/base/"
	got = (Driver{}).Render("k", based, proxy.Env{})
	for _, want := range []string{
		"set $morcheh_k_asked $uri;", "rewrite ^/(.*)$ /base/$1 break;",
		"proxy_cache_key $scheme$host$morcheh_k_asked;",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}

	bad := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"a.example.com"}, Type: "proxy", Upstream: "http://127.0.0.1:1",
		Cache: proxy.Cache{Enabled: true, Groups: []proxy.CacheGroup{
			{Name: "A", Paths: []string{"shop.example.com/x"}, Minutes: 5},
			{Name: "B", Paths: []string{"/x"}, Minutes: 5, Never: true},
			{Name: "C", Header: "Cache-Tag", Minutes: 5},
		}},
	})
	fields := map[string]bool{}
	for _, p := range proxy.Validate(bad) {
		fields[p.Field] = true
	}
	for _, f := range []string{"cache.groups[0].paths[0]", "cache.groups[1].minutes", "cache.groups[2].header"} {
		if !fields[f] {
			t.Errorf("no problem for %s: %v", f, fields)
		}
	}
}

// The patterns are POSIX EREs; the ones written here are also valid RE2.
func TestPurgeRegexps(t *testing.T) {
	keys := map[string][]string{
		"/blog":                 {"httpsa.com/blog", "httpa.com/blog?x=1", "httpsb.com/blog/post"},
		"/blog/":                {"httpsa.com/blog/", "httpsa.com/blog/a/b?c"},
		"/img/*.png":            {"httpsa.com/img/a.png", "httpsa.com/img/x/y.png?v=2"},
		"/search?q=*":           {"httpsa.com/search?q=cats"},
		"shop.example.com/cart": {"httpsshop.example.com/cart", "httpshop.example.com/cart/1"},
		"*.example.com/":        {"httpsshop.example.com/", "httpsx.example.com/a"},
		"https://a.com:8443/x":  {"httpsa.com/x"},
		"blog/post":             {"httpsa.com/blog/post"},
		"*.css":                 {"httpsa.com/x/a.css", "httpsa.com/a.css?v=3"},
		"/news":                 {"phone,android,en|httpsa.com/news", "desktop,none|httpa.com/news/1?x"},
	}
	not := map[string][]string{
		"/blog":                 {"httpsa.com/blogs", "httpsa.com/", "httpsa.com/x/blog"},
		"/img/*.png":            {"httpsa.com/img/a.jpg"},
		"/search?q=*":           {"httpsa.com/search", "httpsa.com/search?page=2"},
		"shop.example.com/cart": {"httpsother.com/cart", "httpsshop.example.com/carts"},
		"https://a.com:8443/x":  {"httpa.com/x"},
		"*.css":                 {"httpsa.com/a.js", "httpsa.css/x"},
	}
	for p, ks := range keys {
		if msg := proxy.CheckPurgePath(p); msg != "" {
			t.Errorf("%s refused: %s", p, msg)
		}
		re := regexp.MustCompile(keyRegexp(p))
		for _, k := range ks {
			if !re.MatchString("KEY: " + k) {
				t.Errorf("%s (%s) should match %s", p, re, k)
			}
		}
		for _, k := range not[p] {
			if re.MatchString("KEY: " + k) {
				t.Errorf("%s (%s) shouldn't match %s", p, re, k)
			}
		}
	}
	for _, p := range []string{"", "*", "/a b", "/a'b", `/a"b`} {
		if proxy.CheckPurgePath(p) == "" {
			t.Errorf("%q accepted", p)
		}
	}
	h := regexp.MustCompile(headerRegexp("Cache-Tag", "product-1*"))
	for _, l := range []string{"Cache-Tag: product-12\r", "cache-tag: a, product-1, b\r", "CACHE-TAG:x,product-1"} {
		if !h.MatchString(l) {
			t.Errorf("%s should match %q", h, l)
		}
	}
	for _, l := range []string{"Cache-Tag: xproduct-1\r", "X-Cache-Tag: product-1\r", "Cache-Tag: a-product-1"} {
		if h.MatchString(l) {
			t.Errorf("%s shouldn't match %q", h, l)
		}
	}
	if !regexp.MustCompile(headerRegexp("Content-Type", "image/*")).MatchString("Content-Type: image/png\r") {
		t.Error("content type")
	}
	s := (Driver{}).PurgeCacheScript("h", proxy.PurgeFilter{Paths: []string{"/a"}, Header: "Cache-Tag", Value: "x"}, true)
	if strings.Count(s, "grep -l") != 2 || strings.Contains(s, "xargs -r rm -f") {
		t.Errorf("dry run script:\n%s", s)
	}
	if n, kb, ok := proxy.ParsePurge("noise\nMORCHEH_PURGE 12 340\n"); !ok || n != 12 || kb != 340 {
		t.Errorf("parse = %d %d %v", n, kb, ok)
	}
}
