package api

import (
	"testing"

	"github.com/morcheh/backend/internal/proxy"
)

func TestWAFIndexFind(t *testing.T) {
	x := newWAFIndex([]proxy.WAFEvent{
		{ID: "rid1", IP: "1.2.3.4", Method: "GET", URI: "/a", Time: "Mon Nov  9 14:29:24 2026", Blocked: true},
		{ID: "17312345.123", IP: "5.6.7.8", Method: "GET", URI: "/b?x=1", Time: "Mon Nov  9 14:30:01 2026"},
	})
	if ev := x.find(proxy.AccessEntry{RequestID: "rid1"}, ""); ev == nil || !ev.Blocked {
		t.Fatalf("by id = %+v", ev)
	}
	line := `5.6.7.8 - - [09/Nov/2026:14:30:01 +0000] "GET /b?x=1 HTTP/1.1" 200 0`
	ev := x.find(proxy.AccessEntry{RequestID: "other", IP: "5.6.7.8", Method: "GET", Path: "/b?x=1"}, line)
	if ev == nil || ev.Blocked {
		t.Fatalf("by key = %+v", ev)
	}
	if ev := x.find(proxy.AccessEntry{IP: "5.6.7.8", Method: "POST", Path: "/b?x=1"}, line); ev != nil {
		t.Fatalf("other method matched: %+v", ev)
	}
	if !firewallMatch("", nil) || firewallMatch("any", nil) || firewallMatch("flagged", &proxy.WAFEvent{Blocked: true}) {
		t.Fatal("firewallMatch")
	}
}
