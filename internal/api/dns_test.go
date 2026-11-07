package api

import (
	"testing"

	"github.com/morcheh/backend/internal/technitium"
)

func TestCleanDNSURL(t *testing.T) {
	good := map[string]string{
		"https://ns1.example.com:53443/":  "https://ns1.example.com:53443",
		" http://10.0.0.1:5380 ":          "http://10.0.0.1:5380",
		"https://example.com/dns/console": "https://example.com/dns/console",
	}
	for in, want := range good {
		got, err := cleanDNSURL(in)
		if err != nil || got != want {
			t.Errorf("cleanDNSURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"ns1.example.com", "ftp://x", "https://u:p@x", "https://x/?a=1", "https://x/#f"} {
		if _, err := cleanDNSURL(in); err == nil {
			t.Errorf("cleanDNSURL(%q) should fail", in)
		}
	}
}

func TestRecordNameMustBeInZone(t *testing.T) {
	bad := DNSRecordBody{Name: "evil.com", Type: "A", Value: "1.2.3.4"}
	if err := bad.normalize("example.com", "body"); err == nil {
		t.Error("a name outside the zone passed")
	}
	// A suffix of the text alone isn't enough.
	lookalike := DNSRecordBody{Name: "notexample.com", Type: "A", Value: "1.2.3.4"}
	if err := lookalike.normalize("example.com", "body"); err == nil {
		t.Error("a look-alike name passed")
	}
	ok := DNSRecordBody{Name: "www.Example.com.", Type: "A", Value: "1.2.3.4"}
	if err := ok.normalize("example.com", "body"); err != nil {
		t.Error(err)
	}
	if ok.TTL != 3600 {
		t.Errorf("default TTL = %d", ok.TTL)
	}
}

func TestRecordValueChecks(t *testing.T) {
	for _, r := range []DNSRecordBody{
		{Name: "a.x.io", Type: "A", Value: "::1"},
		{Name: "a.x.io", Type: "AAAA", Value: "1.2.3.4"},
		{Name: "a.x.io", Type: "A", Value: "request-ip-address"},
		{Name: "a.x.io", Type: "MX", Value: "mail.x.io"},
		{Name: "a.x.io", Type: "SRV", Value: "t.x.io"},
		{Name: "a.x.io", Type: "CAA", Value: "letsencrypt.org"},
		{Name: "a.x.io", Type: "CNAME", Value: "not a host"},
	} {
		if err := r.normalize("x.io", "body"); err == nil {
			t.Errorf("%+v passed", r)
		}
	}
}

func TestUpdateFormSendsCurrentAndNew(t *testing.T) {
	five, ten := 5, 10
	cur := DNSRecordBody{Name: "x.io", Type: "MX", TTL: 60, Value: "a.x.io", Priority: &five}
	next := DNSRecordBody{Name: "m.x.io", Type: "MX", TTL: 90, Value: "b.x.io", Priority: &ten, Disabled: true}
	f := updateForm("x.io", &cur, &next)
	want := map[string]string{
		"domain": "x.io", "zone": "x.io", "type": "MX", "exchange": "a.x.io", "preference": "5",
		"newExchange": "b.x.io", "newPreference": "10", "newDomain": "m.x.io", "ttl": "90", "disable": "true",
	}
	for k, v := range want {
		if f.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, f.Get(k), v)
		}
	}
}

func TestToDNSRecord(t *testing.T) {
	r := toDNSRecord(technitium.RawRecord{Name: "_s._tcp.x.io", Type: "SRV", TTL: 60, RData: map[string]any{
		"priority": 1.0, "weight": 2.0, "port": 443.0, "target": "t.x.io",
	}})
	if r.Value != "t.x.io" || *r.Priority != 1 || *r.Weight != 2 || *r.Port != 443 || !r.Editable {
		t.Errorf("%+v", r)
	}
	soa := toDNSRecord(technitium.RawRecord{Name: "x.io", Type: "SOA", RData: map[string]any{"serial": 3.0, "primaryNameServer": "ns"}})
	if soa.Editable || soa.Value != "primaryNameServer: ns  serial: 3" {
		t.Errorf("%+v", soa)
	}
}

func TestGroupZones(t *testing.T) {
	zone := func(server, kind string, serial uint32) DNSZoneCopy {
		return DNSZoneCopy{ServerName: server, DNSZone: DNSZone{Name: "x.io", Type: kind, SOASerial: serial}}
	}
	got := groupZones([]DNSZoneCopy{zone("b", "Secondary", 5), zone("a", "Secondary", 7), zone("c", "Primary", 7)})
	if len(got) != 1 || got[0].Copies[0].ServerName != "c" || !got[0].OutOfSync {
		t.Errorf("%+v", got)
	}
	// Independent primaries may differ.
	got = groupZones([]DNSZoneCopy{zone("a", "Primary", 1), zone("b", "Primary", 2)})
	if got[0].OutOfSync {
		t.Error("two primaries flagged out of sync")
	}
	// In step.
	got = groupZones([]DNSZoneCopy{zone("a", "Primary", 3), zone("b", "Secondary", 3)})
	if got[0].OutOfSync {
		t.Error("matching serials flagged out of sync")
	}
}

func TestZoneOptionsForm(t *testing.T) {
	b := DNSZoneOptionsBody{
		ZoneTransfer:        "UseSpecifiedNetworkACL",
		ZoneTransferAllowed: []string{" 10.0.0.0/24 ", "!10.0.0.5", ""},
		Notify:              "None",
	}
	form, err := b.form()
	if err != nil {
		t.Fatal(err)
	}
	if got := form.Get("zoneTransferNetworkACL"); got != "10.0.0.0/24,!10.0.0.5" {
		t.Errorf("acl = %q", got)
	}
	if got := form.Get("notifyNameServers"); got != "false" {
		t.Errorf("an empty list must clear it, got %q", got)
	}
	if form.Has("primaryNameServerAddresses") {
		t.Error("primaries sent for a Primary zone")
	}

	for _, bad := range []DNSZoneOptionsBody{
		{ZoneTransfer: "Allow", Notify: "None", ZoneTransferAllowed: []string{"not-an-ip"}},
		{ZoneTransfer: "UseSpecifiedNetworkACL", Notify: "None"},
		{ZoneTransfer: "Allow", Notify: "SpecifiedNameServers"},
		{ZoneTransfer: "Allow", Notify: "SpecifiedNameServers", NotifyServers: []string{"10.0.0.0/8"}},
		{ZoneTransfer: "Allow", Notify: "None", PrimaryAddresses: []string{"a b"}},
	} {
		if _, err := bad.form(); err == nil {
			t.Errorf("%+v: want an error", bad)
		}
	}
}
