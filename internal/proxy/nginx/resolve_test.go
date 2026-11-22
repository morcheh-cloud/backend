package nginx

import (
	"strings"
	"testing"

	"github.com/morche/backend/internal/proxy"
)

func TestResolveInContainer(t *testing.T) {
	box := proxy.Env{Version: "1.29.0", Resolver: "127.0.0.11", HostsNames: []string{"host.docker.internal"}}
	site := func(up string) proxy.HostConfig {
		return proxy.Normalize(proxy.HostConfig{Domains: []string{"app.example.com"}, Type: "proxy", Upstream: up})
	}

	got := Driver{}.Render("h1", site("http://frontend:3000/base"), box)
	for _, want := range []string{
		"upstream morche_h1_pool {",
		"zone morche_h1_pool 64k;",
		"resolver 127.0.0.11 valid=10s ipv6=off;",
		"server frontend:3000 resolve;",
		"proxy_pass http://morche_h1_pool/base;",
		"proxy_set_header Host frontend:3000;",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}

	// Addresses, localhost, /etc/hosts names, an old nginx and nginx on the
	// server itself stay as they were.
	for _, c := range []struct {
		up  string
		env proxy.Env
	}{
		{"http://172.18.0.5:3000", box},
		{"http://localhost:3000", box},
		{"http://host.docker.internal:3000", box},
		{"http://frontend:3000", proxy.Env{Version: "1.25.0", Resolver: "127.0.0.11"}},
		{"http://frontend:3000", proxy.Env{Version: "1.29.0"}},
	} {
		got := Driver{}.Render("h1", site(c.up), c.env)
		if strings.Contains(got, "upstream ") || strings.Contains(got, "resolve") {
			t.Errorf("%s %+v: no upstream block expected\n%s", c.up, c.env, got)
		}
	}

	// A balanced site: resolve only on the named servers.
	h := site("http://frontend:3000")
	h.Balance.Servers = []proxy.UpstreamServer{{Address: "10.0.0.6:3000"}, {Address: "frontend-2:3000"}}
	got = Driver{}.Render("h1", proxy.Normalize(h), box)
	for _, want := range []string{
		"resolver 127.0.0.11 valid=10s ipv6=off;",
		"server frontend:3000 resolve;",
		"server 10.0.0.6:3000;",
		"server frontend-2:3000 resolve;",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}

	// A port forward, and an IPv6 resolver (Podman).
	fwd := proxy.Normalize(proxy.HostConfig{Type: "stream", ListenPort: 5432, StreamTo: "db:5432", Protocol: "tcp"})
	got = Driver{}.Render("s1", fwd, proxy.Env{Version: "1.29.0", Resolver: "fd00::1"})
	for _, want := range []string{
		"resolver [fd00::1] valid=10s ipv6=off;",
		"server db:5432 resolve;",
		"proxy_pass morche_s1_pool;",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}

func TestHostsNames(t *testing.T) {
	got := hostsNames("127.0.0.1\tlocalhost\n# x\n172.17.0.1 Host.Docker.Internal gw # note\n\n")
	if strings.Join(got, ",") != "localhost,host.docker.internal,gw" {
		t.Fatalf("got %v", got)
	}
}
