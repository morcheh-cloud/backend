package nginx

import (
	"strings"
	"testing"

	"github.com/morcheh/backend/internal/proxy"
)

func TestStorageSite(t *testing.T) {
	h := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"files.example.com"}, Type: proxy.TypeStorage,
		Storage: proxy.StorageSite{StorageID: "x", Bucket: "site", Folder: "/www/", Endpoint: "https://s3.example.com:9000", PathStyle: true},
		Upstream: "http://ignored", Gzip: true,
	})
	if probs := proxy.Validate(h); len(probs) > 0 {
		t.Fatalf("problems = %v", probs)
	}
	if h.Upstream != "" || h.Storage.Folder != "/www" || !h.Gzip {
		t.Fatalf("normalized = %+v", h)
	}
	out := Driver{}.Render("01a1bb40-b9e8-74d3-ac12-f55f7660205d", h, proxy.Env{})
	for _, want := range []string{
		`rewrite "^/(.*)$" "/site/www/$1?" break;`,
		"proxy_pass https://s3.example.com:9000;",
		`proxy_set_header Authorization "";`,
		"proxy_hide_header x-amz-request-id;",
		"proxy_ssl_server_name on;",
		"proxy_intercept_errors on;",
		"error_page 403 404 =404 @",
		"return 405;",
		"gzip on;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}

	h.SPA = true
	h.Storage.PathStyle = false
	out = Driver{}.Render("01a1bb40-b9e8-74d3-ac12-f55f7660205d", h, proxy.Env{})
	if !strings.Contains(out, `rewrite ^ "/www/index.html" break;`) || !strings.Contains(out, "error_page 403 404 = @") {
		t.Errorf("spa:\n%s", out)
	}

	bad := proxy.Validate(proxy.Normalize(proxy.HostConfig{Domains: []string{"a.example.com"}, Type: proxy.TypeStorage,
		Storage: proxy.StorageSite{Bucket: "Bad_Name"}}))
	fields := ""
	for _, p := range bad {
		fields += p.Field + " "
	}
	if !strings.Contains(fields, "storage.storage_id") || !strings.Contains(fields, "storage.bucket") {
		t.Errorf("problems = %v", bad)
	}
}

func TestMirror(t *testing.T) {
	h := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"app.example.com"}, Type: proxy.TypeProxy, Upstream: "http://127.0.0.1:3000",
		Mirror: proxy.Mirror{To: "https://test.internal", SkipBody: true, Percent: 25},
	})
	if probs := proxy.Validate(h); len(probs) > 0 {
		t.Fatalf("problems = %v", probs)
	}
	id := "01a1bb40-b9e8-74d3-ac12-f55f7660205d"
	tg := tag(id)
	out := Driver{}.Render(id, h, proxy.Env{})
	for _, want := range []string{
		"upstream " + tg + "_mirror {",
		"server test.internal:443;",
		`split_clients "$request_id" $` + tg + "_mirror_skip {",
		`25% "";`,
		"mirror " + mirrorLocation + ";",
		"mirror_request_body off;",
		"location = " + mirrorLocation + " {",
		"proxy_pass https://" + tg + "_mirror$request_uri;",
		"proxy_ssl_name test.internal;",
		"proxy_pass_request_body off;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if n := len(tg + "_mirror_skip"); n > 46 {
		t.Errorf("variable name is %d characters", n)
	}

	// Other types drop it; a path is refused.
	if c := proxy.Normalize(proxy.HostConfig{Type: proxy.TypeStatic, Mirror: h.Mirror}); c.Mirror.On() {
		t.Error("static kept the mirror")
	}
	h.Mirror.To = "http://test.internal/api"
	if probs := proxy.Validate(h); len(probs) != 1 || probs[0].Field != "mirror.to" {
		t.Errorf("problems = %v", probs)
	}
}
