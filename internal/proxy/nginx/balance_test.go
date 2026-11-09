package nginx

import (
	"strings"
	"testing"

	"github.com/morcheh/backend/internal/proxy"
)

func TestBalance(t *testing.T) {
	h := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"app.example.com"}, Type: "proxy", Upstream: "https://app.internal/base",
		Paths: []proxy.PathRule{
			{Path: "/api/", StripPrefix: true},
			{Path: "/other/", Upstream: "http://10.9.9.9:80"},
		},
		Balance: proxy.Balance{
			Method: "hash", HashKey: "cookie", HashName: "sid", Consistent: true,
			Main: proxy.UpstreamServer{Weight: 3},
			Servers: []proxy.UpstreamServer{
				{Address: " 10.0.0.6:443 ", MaxConns: 50, Note: "second box"},
				{Address: "10.0.0.7:443", Down: true},
				{Address: ""},
			},
			Keepalive: 16, MaxFails: 3, FailTimeout: 30,
			RetryOn: []string{"error", "timeout", "http_502"}, Tries: 2,
		},
	})
	if p := proxy.Validate(h); len(p) > 0 {
		t.Fatalf("problems: %v", p)
	}
	if len(h.Balance.Servers) != 2 {
		t.Fatalf("servers = %v", h.Balance.Servers)
	}
	got := Driver{}.Render("h1", h, proxy.Env{Version: "1.24.0"})
	for _, want := range []string{
		"upstream morcheh_h1_pool {",
		"zone morcheh_h1_pool 64k;",
		"hash $cookie_sid consistent;",
		"server app.internal:443 weight=3 max_fails=3 fail_timeout=30s;",
		"# second box",
		"server 10.0.0.6:443 max_fails=3 fail_timeout=30s max_conns=50;",
		"server 10.0.0.7:443 max_fails=3 fail_timeout=30s down;",
		"keepalive 16;",
		"proxy_pass https://morcheh_h1_pool/base;",
		"proxy_pass https://morcheh_h1_pool;",
		"proxy_set_header Host app.internal;",
		"proxy_ssl_name app.internal;",
		"proxy_next_upstream error timeout http_502;",
		"proxy_next_upstream_tries 2;",
		"proxy_pass http://10.9.9.9:80;",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Index(got, "upstream morcheh_h1_pool") > strings.Index(got, "server {") {
		t.Errorf("upstream must come before the server block:\n%s", got)
	}

	s := proxy.Normalize(proxy.HostConfig{
		Type: "stream", ListenPort: 5432, StreamTo: "10.0.0.2:5432",
		Balance: proxy.Balance{
			Method: "least_conn", Keepalive: 8, RetryOn: []string{"http_502"},
			Servers: []proxy.UpstreamServer{{Address: "10.0.0.3:5432", Backup: true}},
			Tries:   2,
		},
	})
	if p := proxy.Validate(s); len(p) > 0 {
		t.Fatalf("stream problems: %v", p)
	}
	got = Driver{}.Render("s1", s, proxy.Env{})
	for _, want := range []string{
		"least_conn;",
		"server 10.0.0.2:5432;",
		"server 10.0.0.3:5432 backup;",
		"proxy_pass morcheh_s1_pool;",
		"proxy_next_upstream_tries 2;",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("stream: missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "keepalive") || strings.Contains(got, "http_502") {
		t.Errorf("stream got site-only lines:\n%s", got)
	}

	// No other servers = no pool at all.
	plain := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"a.com"}, Type: "proxy", Upstream: "http://127.0.0.1:3000",
		Balance: proxy.Balance{Method: "least_conn"},
	})
	if got := (Driver{}).Render("p", plain, proxy.Env{}); strings.Contains(got, "upstream ") {
		t.Errorf("pool without servers:\n%s", got)
	}
}

func TestBalanceProblems(t *testing.T) {
	h := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"a.com"}, Type: "proxy", Upstream: "http://10.0.0.1:3000",
		Balance: proxy.Balance{
			Method: "ip_hash",
			Main:   proxy.UpstreamServer{Down: true},
			Servers: []proxy.UpstreamServer{
				{Address: "10.0.0.1:3000"},
				{Address: "nope"},
				{Address: "10.0.0.2:3000", Backup: true},
				{Address: "10.0.0.2:3000", Down: true},
			},
			RetryOn: []string{"bogus"},
		},
	})
	got := map[string]bool{}
	for _, p := range proxy.Validate(h) {
		got[p.Field] = true
	}
	for _, f := range []string{
		"balance.servers[0].address", "balance.servers[1].address",
		"balance.servers[2].backup", "balance.servers[3].address", "balance.retry_on[0]",
	} {
		if !got[f] {
			t.Errorf("no problem for %s (got %v)", f, got)
		}
	}
	s := proxy.Normalize(proxy.HostConfig{
		Type: "stream", ListenPort: 5432, StreamTo: "10.0.0.2:5432",
		Balance: proxy.Balance{Method: "ip_hash", Servers: []proxy.UpstreamServer{{Address: "10.0.0.3:5432", Down: true}}},
	})
	got = map[string]bool{}
	for _, p := range proxy.Validate(s) {
		got[p.Field] = true
	}
	if !got["balance.method"] {
		t.Errorf("stream ip_hash allowed: %v", got)
	}
	c := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"a.com"}, Type: "proxy", Upstream: "http://10.0.0.1:3000",
		Balance: proxy.Balance{
			Method: "hash", HashKey: "cookie", HashName: "bad-name",
			Main:    proxy.UpstreamServer{Down: true},
			Servers: []proxy.UpstreamServer{{Address: "10.0.0.2:3000", Backup: true}},
		},
	})
	got = map[string]bool{}
	for _, p := range proxy.Validate(c) {
		got[p.Field] = true
	}
	for _, f := range []string{"balance.hash_name", "balance.servers", "balance.servers[0].backup"} {
		if !got[f] {
			t.Errorf("no problem for %s (got %v)", f, got)
		}
	}
}
