package nginx

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/morcheh/backend/internal/proxy"
)

func TestParseSites(t *testing.T) {
	dump, err := os.ReadFile("testdata/dump.txt")
	if err != nil {
		t.Fatal(err)
	}
	sites := ParseSites(string(dump))
	if len(sites) != 3 {
		t.Fatalf("got %d sites, want 3 (stream servers are skipped): %+v", len(sites), sites)
	}
	def := sites[0]
	if def.File != "/etc/nginx/sites-enabled/default" || def.Line != 1 || len(def.Domains) != 0 || def.Root != "/var/www/html" || def.TLS {
		t.Errorf("default site = %+v", def)
	}
	if len(def.Listen) != 2 || def.Listen[0] != "80 default_server" {
		t.Errorf("listen = %q", def.Listen)
	}
	if !strings.HasPrefix(def.Text, "server {\n\tlisten 80") || !strings.HasSuffix(def.Text, "}") {
		t.Errorf("text = %q", def.Text)
	}
	shop := sites[1]
	if strings.Join(shop.Domains, ",") != "shop.example.com,www.shop.example.com" || !shop.TLS || shop.Upstream != "http://127.0.0.1:8080/" || shop.Redirect != "https://new.example.com/$1" {
		t.Errorf("shop = %+v", shop)
	}
	if shop.Managed || !sites[2].Managed {
		t.Errorf("managed flags = %v %v", shop.Managed, sites[2].Managed)
	}
}

func TestParseInspect(t *testing.T) {
	dump, _ := os.ReadFile("testdata/dump.txt")
	out := "\n" + sectionMark + "facts@@\ninit systemd\nipv6\nversion 1.24.0\nrunning\nenabled\n" +
		"\n" + sectionMark + "test@@\nnginx: [warn] conflicting server name\nnginx: configuration file /etc/nginx/nginx.conf test is successful\nexit 0\n" +
		"\n" + sectionMark + "dump@@\n" + string(dump) +
		"\n" + sectionMark + "files@@\n" +
		"\n" + fileMark + "abc@@\nserver {\n}\n" +
		"\n" + fileMark + "def@@\nx\n" +
		"\n" + sectionMark + "certs@@\ncert shop.example.com\nnotAfter=Feb  3 10:00:00 2027 GMT\nX509v3 Subject Alternative Name: \n    DNS:shop.example.com, DNS:www.shop.example.com\n" +
		"\n" + sectionMark + "end@@\n"
	in := Driver{}.ParseInspect(out)
	if !in.Installed || in.Version != "1.24.0" || !in.Running || !in.Enabled || !in.IPv6 || in.Init != "systemd" || !in.ConfigOK || !in.SetUp {
		t.Errorf("status = %+v", in.Status)
	}
	if in.Files["abc"] != "server {\n}\n" || in.Files["def"] != "x\n" {
		t.Errorf("files = %q", in.Files)
	}
	if len(in.Certificates) != 1 || len(in.Certificates[0].Domains) != 2 || in.Certificates[0].Expires == nil || in.Certificates[0].Expires.Year() != 2027 {
		t.Errorf("certs = %+v", in.Certificates)
	}

	bad := Driver{}.ParseInspect("\n" + sectionMark + "facts@@\nversion 1.18.0\n\n" + sectionMark + "test@@\nnginx: [emerg] unknown directive \"foo\" in /etc/nginx/x:1\nnginx: configuration file test failed\nexit 1\n")
	if bad.ConfigOK || bad.ConfigError != `nginx: [emerg] unknown directive "foo" in /etc/nginx/x:1` {
		t.Errorf("bad = %+v", bad.Status)
	}
	if none := (Driver{}).ParseInspect("\n" + sectionMark + "facts@@\ninit none\nmissing\n"); none.Installed {
		t.Error("missing nginx reads as installed")
	}
}

func TestRender(t *testing.T) {
	h := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"App.Example.com", "www.app.example.com"}, Type: "proxy",
		Upstream: "http://127.0.0.1:3000", WebSockets: true, PreserveHost: true,
		TLS:   proxy.HostTLS{Enabled: true, Certificate: "/etc/ssl/a.pem", Key: "/etc/ssl/a.key", ForceHTTPS: true, HTTP2: true, HSTS: true},
		Allow: []string{"10.0.0.0/8"}, MaxBodyMB: 50,
		Headers:  []proxy.HeaderRule{{To: "response", Name: "X-Frame-Options", Value: "DENY"}, {To: "request", Name: "X-Env", Value: "prod"}},
		Paths:    []proxy.PathRule{{Path: "/api/", Upstream: "https://10.0.0.2:8443/"}},
		Advanced: "location /health {\n    return 200;\n}",
	})
	if p := proxy.Validate(h); len(p) > 0 {
		t.Fatalf("problems: %v", p)
	}
	got := Driver{}.Render("h1", h, proxy.Env{Version: "1.24.0", IPv6: true})
	for _, want := range []string{
		"server_name app.example.com www.app.example.com;",
		"return 301 https://$host$request_uri;",
		"listen 443 ssl http2;",
		"listen [::]:443 ssl http2;",
		"ssl_certificate_key /etc/ssl/a.key;",
		`add_header Strict-Transport-Security "max-age=31536000" always;`,
		"allow 10.0.0.0/8;\n    deny all;",
		"client_max_body_size 50m;",
		`add_header X-Frame-Options "DENY" always;`,
		"location /api/ {\n        proxy_pass https://10.0.0.2:8443/;",
		"proxy_ssl_server_name on;",
		"proxy_set_header Connection $morcheh_connection;",
		`proxy_set_header X-Env "prod";`,
		"proxy_set_header Host $host;",
		"access_log /var/log/nginx/morcheh-h1.access.log morcheh_access;",
		"    # Advanced\n    location /health {\n        return 200;\n    }\n}\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("render lacks %q:\n%s", want, got)
		}
	}
	if strings.Count(got, "listen 80;") != 1 {
		t.Errorf("plain http should only redirect:\n%s", got)
	}
	// Rendered text parses back to the same names.
	sites := ParseSites("# configuration file " + HostsDir + "/h1.conf:\n" + got)
	if len(sites) != 2 || !sites[1].TLS || sites[1].Upstream != "https://10.0.0.2:8443/" {
		t.Errorf("round trip = %+v", sites)
	}

	newer := Driver{}.Render("h1", h, proxy.Env{Version: "1.25.3"})
	if !strings.Contains(newer, "http2 on;") || strings.Contains(newer, "[::]") {
		t.Errorf("1.25 render:\n%s", newer)
	}

	redirect := Driver{}.Render("r", proxy.Normalize(proxy.HostConfig{Domains: []string{"old.com"}, Type: "redirect", RedirectTo: "https://new.com/", KeepPath: true}), proxy.Env{})
	if !strings.Contains(redirect, "return 301 https://new.com$request_uri;") {
		t.Errorf("redirect:\n%s", redirect)
	}
	static := Driver{}.Render("s", proxy.Normalize(proxy.HostConfig{Domains: []string{"s.com"}, Type: "static", Root: "/var/www/s", SPA: true}), proxy.Env{})
	if !strings.Contains(static, "root /var/www/s;") || !strings.Contains(static, "try_files $uri $uri/ /index.html;") {
		t.Errorf("static:\n%s", static)
	}
}

func TestApplyScript(t *testing.T) {
	stream := proxy.Normalize(proxy.HostConfig{Type: "stream", ListenPort: 5432, StreamTo: "10.0.0.5:5432"})
	s := Driver{}.ApplyScript([]proxy.File{{ID: "b-1", Text: "B\n"}, {ID: "a-2", Text: "A\n"}, {ID: "c-3", Config: stream, Text: "C\n"}}, proxy.Takeover{})
	if strings.Index(s, "a-2.conf") > strings.Index(s, "b-1.conf") {
		t.Error("files should be written in a stable order")
	}
	if !strings.Contains(s, "<<'MORCHEH_HOST_a2'\nA\nMORCHEH_HOST_a2\n") {
		t.Errorf("heredoc:\n%s", s)
	}
	if !strings.Contains(s, `"$n/streams/c-3.conf"`) || !strings.Contains(s, "taken_by t 5432") {
		t.Errorf("stream file:\n%s", s)
	}
	if strings.Contains(Driver{}.ApplyScript(nil, proxy.Takeover{}), "stream_state)") {
		t.Error("no streams: the module isn't needed")
	}
}

func TestRenderStreamAndNotFound(t *testing.T) {
	st := proxy.Normalize(proxy.HostConfig{Type: "stream", ListenPort: 53, Protocol: "udp", StreamTo: "10.0.0.5:53", TimeoutSeconds: 30, Allow: []string{"10.0.0.0/8"}})
	if p := proxy.Validate(st); len(p) > 0 {
		t.Fatalf("stream problems: %v", p)
	}
	out := Driver{}.Render("s1", st, proxy.Env{IPv6: true})
	for _, want := range []string{"listen 53 udp;", "listen [::]:53 udp;", "proxy_pass 10.0.0.5:53;", "proxy_timeout 30s;", "allow 10.0.0.0/8;", "morcheh_stream;"} {
		if !strings.Contains(out, want) {
			t.Errorf("stream render lacks %q:\n%s", want, out)
		}
	}
	nf := Driver{}.Render("n1", proxy.Normalize(proxy.HostConfig{Domains: []string{"x.com"}, Type: "notfound"}), proxy.Env{})
	if !strings.Contains(nf, "return 404;") || strings.Contains(nf, "proxy_pass") {
		t.Errorf("404 render:\n%s", nf)
	}
	bad := proxy.Normalize(proxy.HostConfig{Type: "stream", ListenPort: 443, StreamTo: "x"})
	if len(proxy.Validate(bad)) < 2 {
		t.Errorf("tcp 443 and a target without a port should be refused: %v", proxy.Validate(bad))
	}
}

func TestTraffic(t *testing.T) {
	s := Driver{}.TrafficScript([]string{"h1", "bad id;"}, map[string]proxy.LogMark{"h1": {Inode: "12", Size: 40}})
	if !strings.Contains(s, "count h1 12 40\n") || strings.Contains(s, "bad id") {
		t.Errorf("script:\n%s", s)
	}
	hits, marks := Driver{}.ParseTraffic("@@host h1 13 900\n08/Nov/2026:10:15 +0330 2 14 5120\n08/Nov/2026:10:15 +0330 5 1 0\n@@host h2 - 0\n")
	if marks["h1"] != (proxy.LogMark{Inode: "13", Size: 900}) || len(marks) != 2 {
		t.Errorf("marks = %v", marks)
	}
	if len(hits) != 2 || hits[0].Requests != 14 || hits[0].Bytes != 5120 || hits[1].Class != 5 || hits[0].Minute.Hour() != 6 || hits[0].Minute.Minute() != 45 {
		t.Errorf("hits = %+v", hits)
	}
}

func TestAtLeast(t *testing.T) {
	for v, want := range map[string]bool{"1.25.1": true, "1.25.0": false, "1.26": true, "1.9.15": false, "2.0.0": true, "": false} {
		if atLeast(v, 1, 25, 1) != want {
			t.Errorf("atLeast(%q) != %v", v, want)
		}
	}
}

func TestDefaultHolders(t *testing.T) {
	sites := []proxy.Site{
		{File: "/etc/nginx/sites-enabled/default", Listen: []string{"80 default_server", "[::]:80 default_server"}},
		{File: "/etc/nginx/conf.d/alt.conf", Listen: []string{"8080 default_server"}},
		{File: "/etc/nginx/conf.d/tls.conf", Listen: []string{"443 ssl default_server"}},
		{File: "/etc/nginx/morcheh/hosts/x.conf", Listen: []string{"80 default_server"}, Managed: true},
		{File: "/etc/nginx/conf.d/plain.conf", Listen: []string{"80"}},
	}
	got := proxy.DefaultHolders(sites)
	want := []string{"/etc/nginx/sites-enabled/default", "/etc/nginx/conf.d/tls.conf"}
	if !slices.Equal(got, want) {
		t.Errorf("holders = %v, want %v", got, want)
	}
}

// The takeover's shell functions, run for real on a scratch file.
func TestTakeAndGiveBack(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "default")
	orig := "server {\n  listen 80 default_server;\n  listen [::]:80 default_server;\n  # listen 443 ssl default_server;\n  listen 8080 default_server;\n  server_name _;\n}\n"
	if err := os.WriteFile(conf, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "enabled")
	if err := os.Symlink(conf, link); err != nil {
		t.Fatal(err)
	}
	fns := strings.Replace(defaultFns, "R="+ReleasedDir, "R="+filepath.Join(dir, "released"), 1)
	run := func(s string) string {
		out, err := exec.Command("sh", "-c", fns+s).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", s, err, out)
		}
		return string(out)
	}

	run("take " + shellQuote(link))
	got, _ := os.ReadFile(conf)
	want := "server {\n  listen 80;\n  listen [::]:80;\n  # listen 443 ssl default_server;\n  listen 8080 default_server;\n  server_name _;\n}\n"
	if string(got) != want {
		t.Errorf("after take:\n%s", got)
	}
	if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink should stay a symlink")
	}
	if p := run(`cat "$R"/*.path`); p != link {
		t.Errorf("recorded path = %q", p)
	}

	run("give_back")
	if got, _ := os.ReadFile(conf); string(got) != orig {
		t.Errorf("after give_back:\n%s", got)
	}

	// Edited after the takeover: left alone, with a note.
	run("take " + shellQuote(link))
	os.WriteFile(conf, []byte("server { listen 80; }\n"), 0o644)
	if out := run("give_back"); !strings.Contains(out, "changed after") {
		t.Errorf("give_back note: %q", out)
	}
	if got, _ := os.ReadFile(conf); string(got) != "server { listen 80; }\n" {
		t.Errorf("an edited file should be left alone:\n%s", got)
	}
	if out := run(`ls "$R"`); out != "" {
		t.Errorf("records should be gone: %q", out)
	}
}
