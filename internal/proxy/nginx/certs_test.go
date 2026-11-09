package nginx

import (
	"strings"
	"testing"

	"github.com/morcheh/backend/internal/proxy"
)

func TestRenderTLSOptions(t *testing.T) {
	h := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"app.example.com"}, Type: "proxy", Upstream: "http://127.0.0.1:3000",
		TLS: proxy.HostTLS{
			Enabled: true, Certificate: "/etc/letsencrypt/live/app.example.com/fullchain.pem",
			Key: "/etc/letsencrypt/live/app.example.com/privkey.pem", ForceHTTPS: true, ForceCode: 308,
			HTTP3: true, HSTS: true, HSTSSub: true, HSTSPreload: true, Profile: "modern",
			OCSP: true, SessionCache: true, ClientCA: "/etc/ssl/ca.pem", VerifyClient: "optional",
		},
	})
	if p := proxy.Validate(h); len(p) > 0 {
		t.Fatalf("validate: %+v", p)
	}
	out := Driver{}.Render("h1", h, proxy.Env{Version: "1.25.3", QUICReuseport: true})
	for _, want := range []string{
		"return 308 https://$host$request_uri;",
		"location ^~ /.well-known/acme-challenge/",
		"listen 443 quic reuseport;",
		"ssl_protocols TLSv1.3;",
		"ssl_session_cache shared:morcheh_tls:10m;",
		"ssl_stapling on;",
		"ssl_verify_client optional;",
		`Alt-Svc 'h3=":443"; ma=86400'`,
		`Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	// The ACME location sits only in the port-80 server, once.
	if n := strings.Count(out, "acme-challenge"); n != 1 {
		t.Errorf("acme location %d times", n)
	}

	plain := Driver{}.Render("h2", proxy.Normalize(proxy.HostConfig{Domains: []string{"a.com"}, Type: "proxy", Upstream: "http://127.0.0.1:1"}), proxy.Env{})
	if !strings.Contains(plain, "acme-challenge") {
		t.Errorf("a plain http site should answer ACME checks:\n%s", plain)
	}
}

func TestHostTLSRules(t *testing.T) {
	h := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"a.com"}, Type: "proxy", Upstream: "http://127.0.0.1:1",
		TLS: proxy.HostTLS{Enabled: true, Certificate: "/c.pem", Key: "/k.pem", HSTS: true, HSTSPreload: true, HSTSMaxAge: 600},
	})
	if !hasField(proxy.Validate(h), "tls.hsts_preload") {
		t.Errorf("preload without subdomains and a year should be refused: %+v", proxy.Validate(h))
	}
	off := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"a.com"}, Type: "proxy", Upstream: "http://127.0.0.1:1",
		TLS: proxy.HostTLS{Enabled: true, Certificate: "/c.pem", Key: "/k.pem", ForceCode: 308},
	})
	if off.TLS.ForceCode != 0 {
		t.Errorf("force code kept without force https: %d", off.TLS.ForceCode)
	}
}

func hasField(ps []proxy.Problem, f string) bool {
	for _, p := range ps {
		if p.Field == f {
			return true
		}
	}
	return false
}

func TestCertificateScript(t *testing.T) {
	r := proxy.CertRequest{Source: proxy.CertACME, Domains: []string{"App.example.com", "www.example.com"}, CA: "zerossl", EABKid: "kid", EABHMAC: "secret", Email: "a@b.co"}
	r.Normalize()
	if p := r.Validate(); len(p) > 0 {
		t.Fatalf("validate: %+v", p)
	}
	s := Driver{}.CertificateScript(r, proxy.Setup{Install: func(...string) string { return "apt-get install -y certbot" }})
	for _, want := range []string{"--cert-name 'app.example.com'", "https://acme.zerossl.com/v2/DV90", "-d 'www.example.com'", "--keep-until-expiring", "zz-acme-"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(s, "'secret'") && !strings.Contains(s, "eab-hmac-key") {
		t.Errorf("hmac outside the config file")
	}

	bad := proxy.CertRequest{Source: proxy.CertACME, Domains: []string{"*.example.com", "10.0.0.1"}, CA: "google"}
	bad.Normalize()
	got := bad.Validate()
	for _, f := range []string{"domains[0]", "domains[1]", "eab_kid", "eab_hmac"} {
		if !hasField(got, f) {
			t.Errorf("want a problem on %s: %+v", f, got)
		}
	}
}
