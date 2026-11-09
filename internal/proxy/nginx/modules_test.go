package nginx

import (
	"strings"
	"testing"

	"github.com/morcheh/backend/internal/proxy"
)

func TestWAF(t *testing.T) {
	h := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"a.test"}, Type: proxy.TypeProxy, Upstream: "http://127.0.0.1:1",
		WAF: proxy.WAF{Mode: "detect", SkipPaths: []string{"/upload", "/upload"}, SkipRules: []int{942100, 920350}},
	})
	if p := proxy.Validate(h); len(p) > 0 {
		t.Fatalf("problems: %+v", p)
	}
	if h.WAF.Paranoia != 1 || h.WAF.Threshold != 5 || len(h.WAF.SkipPaths) != 1 {
		t.Fatalf("normalized = %+v", h.WAF)
	}
	got := render(t, h, "1.24.0")
	has(t, got,
		"modsecurity on;",
		`modsecurity_transaction_id "$request_id";`,
		"setvar:tx.paranoia_level=1",
		"setvar:tx.inbound_anomaly_score_threshold=5",
		`"@beginsWith /upload" "id:10100,`,
		"modsecurity_rules_file "+WAFConf+";",
		"SecRuleEngine DetectionOnly",
		"SecRuleRemoveById 920350 942100",
	)
	if strings.Index(got, "paranoia_level") > strings.Index(got, WAFConf) {
		t.Errorf("the paranoia level must come before the rule set:\n%s", got)
	}

	bad := proxy.Validate(proxy.Normalize(proxy.HostConfig{
		Domains: []string{"a.test"}, Type: proxy.TypeProxy, Upstream: "http://127.0.0.1:1",
		WAF: proxy.WAF{Mode: "block", Paranoia: 5, SkipPaths: []string{"no slash", `/a"b`}, SkipRules: []int{949110}},
	}))
	fields := map[string]bool{}
	for _, p := range bad {
		fields[p.Field] = true
	}
	for _, f := range []string{"waf.paranoia", "waf.skip_paths[0]", "waf.skip_paths[1]", "waf.skip_rules[0]"} {
		if !fields[f] {
			t.Errorf("no problem for %s: %+v", f, bad)
		}
	}

	stream := proxy.Normalize(proxy.HostConfig{
		Type: proxy.TypeStream, ListenPort: 2222, StreamTo: "127.0.0.1:22",
		WAF: proxy.WAF{Mode: "block"}, Images: proxy.Images{Enabled: true},
	})
	if stream.WAF.On() || stream.Images.Enabled {
		t.Errorf("a stream can't have the firewall or images: %+v", stream)
	}
}

func TestImages(t *testing.T) {
	h := proxy.Normalize(proxy.HostConfig{
		Domains: []string{"a.test"}, Type: proxy.TypeProxy, Upstream: "http://127.0.0.1:1",
		Images: proxy.Images{Enabled: true, Sizes: []int{640, 320, 640}, Quality: 70},
	})
	if p := proxy.Validate(h); len(p) > 0 {
		t.Fatalf("problems: %+v", p)
	}
	got := render(t, h, "1.24.0")
	has(t, got,
		"map $arg_w $morcheh_01abcd_iw {", "default -;", "320 320;", "640 640;",
		`map "$morcheh_01abcd_iw$morcheh_01abcd_ih:$uri" $morcheh_01abcd_img {`,
		"if ($morcheh_01abcd_img) {", "rewrite ^ /__morcheh/img$uri last;",
		"location ^~ /__morcheh/img/ {", "internal;",
		"image_filter resize $morcheh_01abcd_iw $morcheh_01abcd_ih;",
		"image_filter_jpeg_quality 70;", "image_filter_buffer 10M;",
	)
	if strings.Contains(got, "1920 1920;") {
		t.Errorf("chosen sizes replace the default ones:\n%s", got)
	}
	static := render(t, proxy.Normalize(proxy.HostConfig{
		Domains: []string{"a.test"}, Type: proxy.TypeStatic, Root: "/srv/www",
		Images: proxy.Images{Enabled: true, Mode: "crop"},
	}), "1.24.0")
	has(t, static, "1920 1920;", "image_filter crop", "try_files $uri =404;")
}

func TestStreamCountries(t *testing.T) {
	h := proxy.Normalize(proxy.HostConfig{
		Type: proxy.TypeStream, ListenPort: 2222, StreamTo: "127.0.0.1:22",
		Allow: []string{"10.0.0.0/8"}, Countries: []string{"ir"}, CountryMode: "allow",
	})
	if len(h.Countries) != 1 {
		t.Fatalf("a stream keeps its countries: %+v", h)
	}
	got := render(t, h, "1.24.0")
	has(t, got,
		"upstream morcheh_01abcd_main {", "server 127.0.0.1:22;",
		"upstream morcheh_01abcd_refuse {", "server 127.0.0.1:1 down;",
		"geo $morcheh_01abcd_ip {", "10.0.0.0/8 a;",
		"IR a;",
		`map "$morcheh_01abcd_ip:$morcheh_01abcd_cc" $morcheh_01abcd_to {`,
		"proxy_pass $morcheh_01abcd_to;",
	)
	if strings.Contains(got, "allow 10.0.0.0/8;") {
		t.Errorf("with countries, addresses go through the geo block:\n%s", got)
	}
}

func TestParseWAFEvents(t *testing.T) {
	out := `{"transaction":{"client_ip":"1.2.3.4","time_stamp":"Mon Nov  9 10:00:00 2026","unique_id":"abc","producer":{"secrules_engine":"Enabled"},"request":{"method":"GET","uri":"/?id=1' or 1=1"},"response":{"http_code":403},"messages":[{"message":"SQL Injection Attack","details":{"ruleId":"942100","data":"Matched Data: 1' or 1=1","severity":"2"}},{"message":"Inbound Anomaly Score Exceeded","details":{"ruleId":"949110"}}]}}
not json
{"transaction":{"client_ip":"5.6.7.8","unique_id":"def","producer":{"secrules_engine":"DetectionOnly"},"request":{"method":"POST","uri":"/login"},"response":{"http_code":200},"messages":[{"message":"XSS","details":{"ruleId":"941100"}},{"message":"Inbound Anomaly Score Exceeded","details":{"ruleId":"949110"}}]}}
{"transaction":{"client_ip":"5.6.7.8","unique_id":"ghi","request":{"method":"GET","uri":"/"},"response":{"http_code":502},"messages":[]}}
`
	ev := Driver{}.ParseWAFEvents(out)
	if len(ev) != 2 || ev[0].ID != "def" || ev[1].IP != "1.2.3.4" || ev[1].Status != 403 {
		t.Fatalf("events = %+v", ev)
	}
	if !ev[1].Blocked || ev[0].Blocked {
		t.Fatalf("blocked = %v, %v; want the Enabled one only", ev[1].Blocked, ev[0].Blocked)
	}
	if len(ev[1].Rules) != 2 || ev[1].Rules[0].ID != "942100" || ev[1].Rules[0].Message != "SQL Injection Attack" {
		t.Fatalf("rules = %+v", ev[1].Rules)
	}
}
