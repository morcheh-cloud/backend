package firewall

import (
	"strings"
	"testing"
	"time"
)

const v4Rules = `*filter
### RULES ###

### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment=535348206b656570
-A ufw-user-input -p tcp --dport 22 -j ACCEPT
### tuple ### deny any any 0.0.0.0/0 any 1.2.3.4 in
### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in
### tuple ### allow any 8080 0.0.0.0/0 any 0.0.0.0/0 in_eth0
### tuple ### route:allow tcp 80 10.0.0.0/8 any 0.0.0.0/0 in_eth0!out_eth1
### tuple ### deny udp 53 8.8.8.8 any 0.0.0.0/0 out_eth0
### tuple ### allow_log udp 5000:5010 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow_log-all tcp 7101 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow udp 5353 0.0.0.0/0 53 0.0.0.0/0 in
### END RULES ###
`

const v6Rules = `### tuple ### allow tcp 22 ::/0 any ::/0 in comment=535348206b656570
### tuple ### deny any any ::/0 any 2001:db8::1 in
### tuple ### allow any 8080 ::/0 any ::/0 in_eth0
`

func TestParseUFW(t *testing.T) {
	rules := ParseUFW(v4Rules, v6Rules)
	if len(rules) != 10 {
		t.Fatalf("got %d rules: %+v", len(rules), rules)
	}
	ssh := rules[0]
	if ssh.Action != "allow" || ssh.Port != "22" || ssh.Protocol != "tcp" || ssh.Family != "both" || ssh.Comment != "SSH keep" || ssh.Position() != 1 {
		t.Errorf("ssh rule = %+v", ssh)
	}
	if !ssh.Lets(22, "") || !ssh.Lets(22, "198.51.100.1") || ssh.Lets(80, "") {
		t.Errorf("Lets is wrong for %+v", ssh)
	}
	if b := rules[1]; b.Action != "block" || b.From != "1.2.3.4" || b.Port != "" || b.Family != "v4" {
		t.Errorf("block = %+v", b)
	}
	if a := rules[2]; a.Service != "OpenSSH" || a.Port != "22" {
		t.Errorf("app = %+v", a)
	}
	if i := rules[3]; i.Interface != "eth0" || i.Family != "both" {
		t.Errorf("interface = %+v", i)
	}
	if r := rules[4]; r.Direction != "routed" || r.Interface != "eth0" || r.OutInterface != "eth1" || r.To != "10.0.0.0/8" {
		t.Errorf("route = %+v", r)
	}
	if o := rules[5]; o.Direction != "out" || o.Interface != "eth0" || o.To != "8.8.8.8" {
		t.Errorf("out = %+v", o)
	}
	if l := rules[6]; !l.Log || !l.Editable || l.Port != "5000:5010" {
		t.Errorf("log = %+v", l)
	}
	if l := rules[7]; !l.logAll || l.Editable {
		t.Errorf("log-all = %+v", l)
	}
	if v := rules[9]; v.Family != "v6" || v.From != "2001:db8::1" {
		t.Errorf("v6 = %+v", v)
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.ID] {
			t.Errorf("duplicate id for %+v", r)
		}
		seen[r.ID] = true
	}
}

func TestUFWDeleteSpellsTheRule(t *testing.T) {
	want := []string{
		"ufw delete allow proto tcp from any to any port 22",
		"ufw delete deny from 1.2.3.4 to any",
		"ufw delete allow from any to any app OpenSSH",
		"ufw delete allow in on eth0 from any to any port 8080",
		"ufw route delete allow in on eth0 out on eth1 proto tcp from any to 10.0.0.0/8 port 80",
		"ufw delete deny out on eth0 proto udp from any to 8.8.8.8 port 53",
		"ufw delete allow log proto udp from any to any port 5000:5010",
		"ufw delete allow log-all proto tcp from any to any port 7101",
		"ufw delete allow proto udp from any port 53 to any port 5353",
	}
	rules := ParseUFW(v4Rules, v6Rules)
	for i, w := range want {
		if got := UFWDelete(rules[i]); got != w {
			t.Errorf("delete %d:\n got %s\nwant %s", i, got, w)
		}
	}
}

func TestUFWAdd(t *testing.T) {
	check := func(in Input, pos int, want ...string) {
		t.Helper()
		if err := in.Normalize(); err != nil {
			t.Fatal(err)
		}
		got := UFWAdd(in, pos)
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	check(Input{Action: "allow", Port: "443", Protocol: "tcp", Comment: "Web"}, 0,
		"ufw allow proto tcp from any to any port 443 comment Web")
	check(Input{Action: "block", From: "203.0.113.9"}, 0, "ufw prepend deny from 203.0.113.9 to any")
	check(Input{Action: "allow", Port: "80,443"}, 0,
		"ufw allow proto tcp from any to any port 80,443", "ufw allow proto udp from any to any port 80,443")
	check(Input{Action: "allow", Port: "5000-5010", Protocol: "udp"}, 3,
		"ufw insert 3 allow proto udp from any to any port 5000:5010")
	check(Input{Action: "block", From: "2001:db8::1"}, 3, "ufw prepend deny from 2001:db8::1 to any")
	check(Input{Action: "allow", Comment: "it's; rm -rf /", Port: "1"}, 0,
		`ufw allow from any to any port 1 comment 'it’s; rm -rf /'`)
}

func TestNormalizeRefusesBadInput(t *testing.T) {
	for _, in := range []Input{
		{Action: "allow", Port: "22; reboot"},
		{Action: "allow", Port: "70000"},
		{Action: "allow", Port: "9-1"},
		{Action: "allow", From: "1.2.3.4; reboot"},
		{Action: "allow", To: "$(reboot)"},
		{Action: "allow", Interface: "eth0;x"},
		{Action: "allow", Service: "a'b"},
		{Action: "allow", Zone: "a b"},
		{Action: "allow", Service: "ssh", Port: "22"},
		{Action: "limit", Port: "22"},
		{Action: "allow", From: "1.2.3.4", To: "2001:db8::1"},
	} {
		if err := in.Normalize(); err == nil {
			t.Errorf("accepted %+v", in)
		}
	}
	in := Input{Action: "allow", From: "any", To: "::/0", Comment: "two\n lines"}
	if err := in.Normalize(); err != nil || in.From != "" || in.To != "" || in.Comment != "two lines" {
		t.Errorf("normalized to %+v (%v)", in, err)
	}
}

func TestStops(t *testing.T) {
	const me = "198.51.100.7"
	for _, c := range []struct {
		in   Input
		want bool
	}{
		{Input{Action: "block", From: "203.0.113.9"}, false},
		{Input{Action: "block", From: me}, true},
		{Input{Action: "block", From: "198.51.100.0/24"}, true},
		{Input{Action: "block", From: me, Port: "80"}, false},
		{Input{Action: "block", Port: "22"}, true},
		{Input{Action: "block", Port: "20:30", Protocol: "tcp"}, true},
		{Input{Action: "block", Port: "22", Protocol: "udp"}, false},
		{Input{Action: "reject"}, true},
		{Input{Action: "allow", Port: "22"}, false},
		{Input{Action: "block", Direction: "out"}, true},
		{Input{Action: "block", Direction: "out", Port: "25"}, false},
	} {
		if c.in.Direction == "" {
			c.in.Direction = "in"
		}
		if c.in.Protocol == "" {
			c.in.Protocol = "any"
		}
		if got := c.in.Stops(22, me, ""); got != c.want {
			t.Errorf("%+v: got %v", c.in, got)
		}
	}
}

func TestUFWDefaultsAndConf(t *testing.T) {
	in, out, routed := UFWDefaults("IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\nDEFAULT_FORWARD_POLICY=\"REJECT\"\n")
	if in != "deny" || out != "allow" || routed != "reject" {
		t.Errorf("%s %s %s", in, out, routed)
	}
	on, level := UFWConf("# c\nENABLED=yes\nLOGLEVEL=medium\n")
	if !on || level != "medium" {
		t.Errorf("%v %s", on, level)
	}
}

const zones = `block
  target: %%REJECT%%
  interfaces: 
  sources: 
  services: 
  ports: 
  rich rules: 

public (default)
  target: default
  ingress-priority: 0
  icmp-block-inversion: no
  interfaces: eth0
  sources: 
  services: dhcpv6-client ssh
  ports: 8080/tcp 5000-5010/udp
  protocols: gre
  forward: yes
  masquerade: no
  forward-ports: 
	port=80:proto=tcp:toport=8080:toaddr=
  source-ports: 
  icmp-blocks: 
  rich rules: 
	rule family="ipv4" source address="1.2.3.4" drop
	rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" accept
	rule family="ipv4" source not address="10.0.0.1" log prefix="x" reject
	rule service name="ssh" accept limit value="12/m"

trusted
  target: ACCEPT
  sources: 192.168.1.0/24
  services: http
`

func TestFirewalldRules(t *testing.T) {
	z := ParseZones(zones)
	if len(z) != 3 || !z[1].Default || !z[1].Active || z[0].Active || !z[2].Active {
		t.Fatalf("zones = %+v", z)
	}
	if ParseActiveZones("public (default)\n  interfaces: eth0\ntrusted\n  sources: 10.0.0.1\n")[1] != "trusted" {
		t.Error("active zones")
	}
	services := ParseServicePorts(`/usr/lib/firewalld/services/ssh.xml:  <port protocol="tcp" port="22"/>
/usr/lib/firewalld/services/http.xml:  <port port="80" protocol="tcp"/>
/usr/lib/firewalld/services/dns.xml:  <port protocol="tcp" port="53"/>
/usr/lib/firewalld/services/dns.xml:  <port protocol="udp" port="53"/>
`)
	rules := FirewalldRules(z, services)
	byRaw := map[string]FilterRule{}
	for _, r := range rules {
		byRaw[r.Raw] = r
	}
	if r := byRaw["service ssh"]; r.Port != "22" || r.Protocol != "tcp" || !r.Lets(22, "") {
		t.Errorf("ssh = %+v", r)
	}
	if r := byRaw["port 5000-5010/udp"]; r.Port != "5000:5010" || r.Protocol != "udp" {
		t.Errorf("port = %+v", r)
	}
	if r := byRaw[`rule family="ipv4" source address="1.2.3.4" drop`]; r.Action != "block" || r.From != "1.2.3.4" || !r.Editable || r.Family != "v4" {
		t.Errorf("drop = %+v", r)
	}
	if r := byRaw[`rule family="ipv4" source not address="10.0.0.1" log prefix="x" reject`]; r.Editable || !r.Deletable || r.Action != "reject" {
		t.Errorf("complex = %+v", r)
	}
	if r := byRaw[`rule service name="ssh" accept limit value="12/m"`]; r.Action != "limit" || r.Service != "ssh" {
		t.Errorf("limit = %+v", r)
	}
	if _, ok := byRaw["forward-port port=80:proto=tcp:toport=8080:toaddr="]; ok {
		t.Error("a forward isn't a filter rule")
	}
	if f := FirewalldForwards(z); len(f) != 1 || f[0].Port != "80" || f[0].ToPort != "8080" || f[0].ToAddress != "" {
		t.Errorf("forwards = %+v", f)
	}
	if r := byRaw["service http"]; r.Zone != "trusted" || r.From != "192.168.1.0/24" {
		t.Errorf("source zone = %+v", r)
	}
	if got := FirewalldDelete(byRaw[`rule family="ipv4" source address="1.2.3.4" drop`]); got != `--remove-rich-rule='rule family="ipv4" source address="1.2.3.4" drop'` {
		t.Error(got)
	}
	if got := FirewalldDelete(byRaw["port 5000-5010/udp"]); got != "--remove-port=5000-5010/udp" {
		t.Error(got)
	}
}

func TestFirewalldAdd(t *testing.T) {
	check := func(in Input, want ...string) {
		t.Helper()
		if err := in.Normalize(); err != nil {
			t.Fatal(err)
		}
		got, err := FirewalldAdd(in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("got %q\nwant %q", got, want)
		}
	}
	check(Input{Action: "allow", Service: "http"}, "--add-service=http")
	check(Input{Action: "allow", Port: "80,5000-5010", Protocol: "tcp"}, "--add-port=80/tcp", "--add-port=5000-5010/tcp")
	check(Input{Action: "allow", Port: "53"}, "--add-port=53/tcp", "--add-port=53/udp")
	check(Input{Action: "block", From: "203.0.113.9"}, `--add-rich-rule='rule family="ipv4" source address="203.0.113.9" drop'`)
	check(Input{Action: "reject", Port: "25", Protocol: "tcp", From: "2001:db8::/32"},
		`--add-rich-rule='rule family="ipv6" source address="2001:db8::/32" port port="25" protocol="tcp" reject'`)
	check(Input{Action: "limit", Port: "22", Protocol: "tcp"}, `--add-rich-rule='rule port port="22" protocol="tcp" accept limit value="12/m"'`)
	for _, bad := range []Input{
		{Action: "allow"},
		{Action: "block"},
		{Action: "allow", Port: "1", Direction: "out"},
		{Action: "allow", Port: "1", Interface: "eth0"},
		{Action: "allow", Port: "1", Comment: "x"},
	} {
		if err := bad.Normalize(); err != nil {
			t.Fatal(err)
		}
		if _, err := FirewalldAdd(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	// Parsing what was added gives back the same rule.
	r := parseRich(`rule family="ipv4" source address="10.0.0.0/8" port port="5000-5010" protocol="tcp" accept`)
	if r.Port != "5000:5010" || r.From != "10.0.0.0/8" || r.Action != "allow" {
		t.Errorf("%+v", r)
	}
}

func TestIptables(t *testing.T) {
	out := `-P INPUT DROP
-P FORWARD DROP
-A INPUT -i lo -j ACCEPT
-A INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p udp -m multiport --dports 53,123 -j REJECT --reject-with icmp-port-unreachable
-A FORWARD -j DOCKER-USER
`
	rules := ParseIptables(out)
	if len(rules) != 3 || IptablesPolicy(out) != "deny" {
		t.Fatalf("%+v", rules)
	}
	if r := rules[1]; r.Action != "allow" || r.From != "10.0.0.0/8" || r.Port != "22" || r.Protocol != "tcp" || r.Editable || r.Deletable {
		t.Errorf("%+v", r)
	}
	if r := rules[2]; r.Action != "reject" || r.Port != "53,123" {
		t.Errorf("%+v", r)
	}
}

func TestNft(t *testing.T) {
	rules, policy := ParseNft(`table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iifname "lo" accept
		tcp dport { 22, 80 } accept
		ip saddr 10.0.0.0/8 tcp dport 5432 accept
		ip saddr 1.2.3.4 drop
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
		ip saddr 9.9.9.9 drop
	}
	chain mine {
		tcp dport 1 accept
	}
}
`)
	if policy != "deny" || len(rules) != 5 {
		t.Fatalf("%s %+v", policy, rules)
	}
	if r := rules[2]; r.Port != "22,80" || r.Protocol != "tcp" || r.Action != "allow" {
		t.Errorf("%+v", r)
	}
	if r := rules[4]; r.From != "1.2.3.4" || r.Action != "block" {
		t.Errorf("%+v", r)
	}
}

func TestParseLog(t *testing.T) {
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	events := ParseLog(`Dec 31 23:59:01 vm kernel: [ 12.3] [UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=203.0.113.9 DST=10.0.0.1 LEN=44 PROTO=TCP SPT=4000 DPT=3306 WINDOW=1 RES=0x00 SYN URGP=0
2026-01-01T10:00:00+0000 vm kernel: [UFW AUDIT] IN=eth0 SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP DPT=1
2026-01-01T10:00:01+00:00 vm kernel: [UFW ALLOW] IN=eth0 SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP DPT=1
2026-01-01T10:00:02+0000 vm kernel: filter_IN_public_REJECT: IN=eth1 OUT= SRC=198.51.100.1 DST=10.0.0.1 PROTO=ICMP TYPE=8
2026-01-01T10:00:03+0000 vm kernel: [UFW LIMIT BLOCK] IN=eth0 SRC=198.51.100.2 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=22
just a line
`, now)
	if len(events) != 3 {
		t.Fatalf("%+v", events)
	}
	if e := events[0]; e.Action != "limit" || e.Port != 22 || e.Source != "198.51.100.2" {
		t.Errorf("%+v", e)
	}
	if e := events[1]; e.Action != "reject" || e.Port != 0 || e.Protocol != "ICMP" || e.Interface != "eth1" {
		t.Errorf("%+v", e)
	}
	if e := events[2]; e.Action != "block" || e.Port != 3306 || e.At.Year() != 2025 {
		t.Errorf("%+v", e)
	}
}
