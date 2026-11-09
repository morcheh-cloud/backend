package nginx

import (
	"os"
	"strings"
	"testing"

	"github.com/morcheh/backend/internal/proxy"
)

// fullHost turns on every feature a proxy site can have.
func fullHost() proxy.HostConfig {
	h := proxy.HostConfig{
		Type: proxy.TypeProxy, Domains: []string{"app.example.com"},
		Upstream: "https://10.0.0.5:8443", PreserveHost: true,
		Allow: []string{"10.0.0.0/8"},
		Auth: proxy.Auth{
			Mode: "basic", Realm: "Team only", SkipForAllowed: true,
			Users: []proxy.AuthUser{{Name: "ali", Hash: "$6$salt$hash"}},
		},
		UpstreamTLS: proxy.UpstreamTLS{Verify: true, Name: "internal.example.com", Certificate: "/etc/ssl/c.pem", Key: "/etc/ssl/c.key"},
		Maintenance: proxy.Maintenance{Enabled: true, Allow: []string{"10.1.2.3"}, Title: `Back "soon"`, Message: "Costs $5\nline two", RetryMinutes: 10},
		ErrorPages:  []proxy.ErrorPage{{Codes: []int{502, 504}, Title: "Down"}, {Codes: []int{404}}},
		Hardening:   proxy.Hardening{Dotfiles: true, Backups: true, Scanners: true, AICrawlers: true, Probes: true, Methods: []string{"GET", "POST"}, Status: 444},
		RequestID:   true, Brotli: true, InterceptErrors: true,
		Headers: []proxy.HeaderRule{{To: "hide", Name: "X-Powered-By"}},
		Paths: []proxy.PathRule{
			{Path: "/api/", Upstream: "http://127.0.0.1:9000/v1", StripPrefix: true},
			{Path: "/old", Match: proxy.MatchExact, Action: proxy.ActionRedirect, RedirectTo: "/new"},
			{Path: `\.(png|jpg)$`, Match: proxy.MatchRegex, Action: proxy.ActionStatic, Root: "/srv/img"},
			{Path: "/health", Match: proxy.MatchExact, Action: proxy.ActionReturn, Body: `ok "yes"`, Public: true},
			{Path: "/admin/", Action: proxy.ActionDeny, Status: 404},
		},
	}
	h = proxy.Normalize(h)
	return h
}

func TestRenderFeatures(t *testing.T) {
	h := fullHost()
	if p := proxy.Validate(h); len(p) > 0 {
		t.Fatalf("problems: %+v", p)
	}
	out := Driver{}.Render("abc-123", h, proxy.Env{Version: "1.24.0", Brotli: true, CABundle: "/etc/ca.pem"})
	if os.Getenv("NGINX_DUMP") != "" {
		os.WriteFile(os.Getenv("NGINX_DUMP"), []byte(out), 0o644)
	}
	for _, want := range []string{
		`geo $morcheh_abc123_realm`,
		`default "Team only";`,
		`auth_basic $morcheh_abc123_realm;`,
		`auth_basic_user_file ` + AuthFile("abc-123") + `;`,
		`error_page 503 /__morcheh/maintenance.html;`,
		`if ($morcheh_abc123_maint)`,
		`add_header Retry-After 600 always;`,
		`error_page 502 504 /__morcheh/error-0.html;`,
		`error_page 404 /__morcheh/error-1.html;`,
		`if ($morcheh_abc123_harden)`,
		`return 444;`,
		`if ($morcheh_abc123_h_method)`,
		`HEAD 0;`,
		`add_header X-Request-ID $request_id always;`,
		`proxy_set_header X-Request-ID $request_id;`,
		`brotli on;`,
		`proxy_hide_header X-Powered-By;`,
		`proxy_intercept_errors on;`,
		`proxy_ssl_verify on;`,
		`proxy_ssl_trusted_certificate /etc/ca.pem;`,
		`proxy_ssl_name internal.example.com;`,
		`proxy_ssl_certificate_key /etc/ssl/c.key;`,
		`rewrite "^/api/?(.*)$" "/v1/$1" break;`,
		`proxy_pass http://127.0.0.1:9000;`,
		`location = /old`,
		`return 302 /new;`,
		`location ~ "\.(png|jpg)$"`,
		`root /srv/img;`,
		`return 200 "ok \"yes\"";`,
		`return 404;`,
		`location ^~ /__morcheh/`,
		`&#34;soon&#34;`,
		`&#36;5<br>line two`,
		`volatile;`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// The public path skips the sign-in.
	i := strings.Index(out, "location = /health")
	if i < 0 || !strings.Contains(out[i:i+80], "auth_basic off;") {
		t.Errorf("public path keeps the sign-in")
	}
	if got := htpasswd(h.Auth); got != "ali:$6$salt$hash\n" {
		t.Errorf("htpasswd = %q", got)
	}
}

func TestRenderForwardAuth(t *testing.T) {
	h := proxy.HostConfig{
		Type: proxy.TypeProxy, Domains: []string{"a.example.com"}, Upstream: "http://127.0.0.1:3000",
		Auth: proxy.Auth{Mode: "forward", Forward: proxy.ForwardAuth{
			URL: "http://127.0.0.1:9091/api/verify", SigninURL: "https://auth.example.com/?x=1",
			Headers: []string{"Remote-User"}, PassPath: "/oauth2/",
		}},
	}
	h = proxy.Normalize(h)
	if p := proxy.Validate(h); len(p) > 0 {
		t.Fatalf("problems: %+v", p)
	}
	out := Driver{}.Render("f", h, proxy.Env{})
	for _, want := range []string{
		"auth_request /__morcheh/auth;",
		"auth_request_set $morcheh_f_auth_0 $upstream_http_remote_user;",
		"proxy_set_header Remote-User $morcheh_f_auth_0;",
		"error_page 401 =302 https://auth.example.com/?x=1&rd=$scheme://$http_host$request_uri;",
		"location = /__morcheh/auth",
		"proxy_pass http://127.0.0.1:9091/api/verify;",
		"location ^~ /oauth2/",
		"proxy_pass http://127.0.0.1:9091;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderCatchAll(t *testing.T) {
	h := proxy.HostConfig{Type: proxy.TypeNotFound, CatchAll: true, NotFoundCode: 444}
	h = proxy.Normalize(h)
	if p := proxy.Validate(h); len(p) > 0 {
		t.Fatalf("problems: %+v", p)
	}
	out := Driver{}.Render("c", h, proxy.Env{Version: "1.24.0", IPv6: true})
	for _, want := range []string{
		"listen 80 default_server;", "listen [::]:80 default_server;",
		"listen 443 ssl default_server;", "ssl_reject_handshake on;",
		"server_name _;", "return 444;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestPathAccessAndLogin(t *testing.T) {
	h := proxy.Normalize(proxy.HostConfig{
		Type: proxy.TypeProxy, Domains: []string{"app.example.com"},
		Upstream: "http://10.0.0.5:8080",
		Allow:    []string{"10.0.0.0/8"}, DefaultAccess: "deny",
		Auth: proxy.Auth{
			Mode: "forward", OnlyPaths: true,
			Forward: proxy.ForwardAuth{URL: "http://127.0.0.1:9091/auth", SigninURL: "https://sso.example.com/"},
		},
		ErrorPages: []proxy.ErrorPage{{Codes: []int{502}}},
		Paths: []proxy.PathRule{
			{Path: "/admin/", Access: "only", Addresses: []string{" 192.168.1.0/24 ", "192.168.1.0/24"}, Login: true},
			{Path: "/hooks/", Access: "everyone", Addresses: []string{"1.2.3.4"}},
			{Path: "/api/", Access: "except", Addresses: []string{"5.6.7.8"}},
			{Path: "/old", Action: proxy.ActionRedirect, RedirectTo: "/new", Access: "only", Addresses: []string{"1.1.1.1"}, Login: true},
		},
	})
	if p := proxy.Validate(h); len(p) > 0 {
		t.Fatalf("problems: %+v", p)
	}
	if got := h.Paths[0].Addresses; len(got) != 1 || got[0] != "192.168.1.0/24" {
		t.Fatalf("addresses not tidied: %v", got)
	}
	if h.Paths[1].Addresses != nil || h.Paths[3].Access != "" || h.Paths[3].Login {
		t.Fatalf("leftovers kept: %+v", h.Paths)
	}
	out := Driver{}.Render("abc-123", h, proxy.Env{Version: "1.24.0"})
	server := out[strings.Index(out, "server_name"):]
	if strings.Contains(server[:strings.Index(server, "location")], "auth_request /__morcheh/auth;") {
		t.Error("the whole site asks to sign in")
	}
	admin := server[strings.Index(server, "location /admin/"):]
	admin = admin[:strings.Index(admin, "}")]
	for _, want := range []string{
		"allow 192.168.1.0/24;", "deny all;", "auth_request /__morcheh/auth;",
		"error_page 502 /__morcheh/error-0.html;", "error_page 401 =302 https://sso.example.com/?rd=",
	} {
		if !strings.Contains(admin, want) {
			t.Errorf("/admin/ is missing %q:\n%s", want, admin)
		}
	}
	for _, want := range []string{"location /hooks/ {\n        allow all;", "deny 5.6.7.8;\n        allow all;"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}

	h.Paths[0].Login = false
	if p := proxy.Validate(h); len(p) != 1 || p[0].Field != "auth.only_paths" {
		t.Errorf("want auth.only_paths, got %+v", p)
	}
	h.Paths[2].Addresses = []string{"nope"}
	if p := proxy.Validate(h); len(p) != 2 || p[0].Field != "paths[2].addresses[0]" {
		t.Errorf("want paths[2].addresses[0], got %+v", p)
	}
}
