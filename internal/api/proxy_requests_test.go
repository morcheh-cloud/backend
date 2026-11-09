package api

import (
	"testing"
	"time"

	"github.com/morcheh/backend/internal/proxy"
)

func TestClassifyAgent(t *testing.T) {
	cases := map[string]agentKind{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36": {"Chrome", "Windows", "Desktop"},
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1": {"Safari", "iOS", "Phone"},
		"Mozilla/5.0 (Linux; Android 14; SM-X200) AppleWebKit/537.36 Chrome/130.0 Safari/537.36":                        {"Chrome", "Android", "Tablet"},
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)":                                         {"Googlebot", "", "Bot"},
		"curl/8.5.0": {"curl", "", "Tool"},
		"":           {"No user agent", "", "Tool"},
	}
	for ua, want := range cases {
		if got := classifyAgent(ua); got != want {
			t.Errorf("%q: got %+v want %+v", ua, got, want)
		}
	}
}

func TestBuildHostReport(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 7, 0, 0, time.UTC)
	start, end, bucket := reportWindow("1h", now, time.UTC)
	if end.Sub(start) != time.Hour || bucket != time.Minute {
		t.Fatal(start, end)
	}
	at := func(m int) time.Time { return end.Add(-time.Duration(m) * time.Minute) }
	es := []proxy.AccessEntry{
		{Time: at(90), IP: "1.1.1.1", Status: 200, Method: "GET", Path: "/", Duration: .1},
		{Time: at(30), IP: "1.1.1.1", Status: 200, Method: "GET", Path: "/a?x=1", Duration: .1, Detailed: true, Referer: "https://google.com/q", Domain: "ex.com"},
		{Time: at(20), IP: "2.2.2.2", Status: 404, Method: "GET", Path: "/missing", Duration: .3, Detailed: true, Referer: "https://ex.com/"},
		{Time: at(1), IP: "2.2.2.2", Status: 502, Method: "POST", Path: "/a", Duration: 2, Detailed: true},
	}
	r := buildHostReport(es, start, end, bucket, time.UTC, []string{"ex.com"})
	if r.Totals.Requests != 3 || r.Totals.Visitors != 2 || r.Totals.ClientErrors != 1 || r.Totals.ServerErrors != 1 {
		t.Fatalf("totals %+v", r.Totals)
	}
	if r.Previous == nil || r.Previous.Requests != 1 {
		t.Fatalf("previous %+v", r.Previous)
	}
	if len(r.Paths) != 2 || r.Paths[0].Path != "/a" || r.Paths[0].Requests != 2 {
		t.Fatalf("paths %+v", r.Paths)
	}
	if len(r.Referrers) != 1 || r.Referrers[0].Name != "google.com" {
		t.Fatalf("refs %+v", r.Referrers)
	}
	if len(r.NotFound) != 1 || len(r.Failing) != 1 || *r.Totals.P50Ms != 300 {
		t.Fatalf("errors %+v %+v %v", r.NotFound, r.Failing, *r.Totals.P50Ms)
	}
	if len(r.Series.Ok) != 60 || r.Series.ServerErrors[59] != 1 {
		t.Fatalf("series %+v", r.Series.ServerErrors)
	}
}
