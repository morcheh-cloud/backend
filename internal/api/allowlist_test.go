package api

import "testing"

func TestAllowlist(t *testing.T) {
	entries, err := cleanAllowlist([]AllowEntry{
		{Address: " 203.0.113.7 "}, {Address: "198.51.100.9/24", Note: "Office"},
		{Address: "2001:db8::/48"}, {Address: "203.0.113.7/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[0].Address != "203.0.113.7" || entries[1].Address != "198.51.100.0/24" {
		t.Fatalf("entries = %+v", entries)
	}
	l := &allowlist{on: true, prefixes: prefixesOf(entries)}
	for ip, want := range map[string]bool{
		"203.0.113.7": true, "::ffff:203.0.113.7": true, "203.0.113.8": false,
		"198.51.100.200": true, "2001:db8:0:1::5": true, "2001:db9::1": false,
		"": false, "junk": false,
	} {
		if got := l.allows(ip); got != want {
			t.Errorf("allows(%q) = %v, want %v", ip, got, want)
		}
	}
	if !(&allowlist{}).allows("junk") {
		t.Error("an allowlist that's off lets everyone in")
	}
	for _, bad := range []string{"", "0.0.0.0/0", "::/0", "300.1.1.1", "example.com"} {
		if _, err := cleanAllowlist([]AllowEntry{{Address: bad}}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNetworkOf(t *testing.T) {
	for ip, want := range map[string]string{
		"203.0.113.7": "203.0.113.0/24", "::ffff:203.0.113.7": "203.0.113.0/24",
		"2001:db8:1:2:3::4": "2001:db8:1:2::/64", "x": "x",
	} {
		if got := networkOf(ip); got != want {
			t.Errorf("networkOf(%q) = %q, want %q", ip, got, want)
		}
	}
}

func TestDeviceOf(t *testing.T) {
	for ua, want := range map[string]device{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36":                             {"Chrome on Windows", "desktop"},
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1": {"Safari on iPhone", "phone"},
		"Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0":                                                                  {"Firefox on Linux", "desktop"},
		"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36 EdgA/130.0":                     {"Edge on Android", "phone"},
		"curl/8.5.0": {"curl", "other"},
		"":           {"", "other"},
	} {
		if got := deviceOf(ua); got != want {
			t.Errorf("deviceOf(%q) = %+v, want %+v", ua, got, want)
		}
	}
}
