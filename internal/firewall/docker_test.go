package firewall

import (
	"strings"
	"testing"
)

func TestContainerLimitNormalize(t *testing.T) {
	l := ContainerLimit{Protocol: "TCP", Port: " 8000:8010 ", Allow: []string{"203.0.113.7", " 203.0.113.7", "10.0.0.0/8", "2001:db8::/32", ""}}
	if err := l.Normalize(); err != nil {
		t.Fatal(err)
	}
	if l.Protocol != "tcp" || l.Port != "8000-8010" || len(l.Allow) != 3 || l.ID == "" {
		t.Errorf("got %+v", l)
	}
	for _, bad := range []ContainerLimit{
		{Protocol: "icmp", Port: "80"},
		{Protocol: "tcp", Port: "0"},
		{Protocol: "tcp", Port: "90-80"},
		{Protocol: "tcp", Port: "80", Allow: []string{"any"}},
		{Protocol: "tcp", Port: "80", Allow: []string{"example.com"}},
	} {
		if bad.Normalize() == nil {
			t.Errorf("%+v should be refused", bad)
		}
	}
	if !l.Covers("tcp", 8005) || l.Covers("udp", 8005) || l.Covers("tcp", 8011) {
		t.Error("Covers")
	}
	if !l.Lets("10.1.2.3") || !l.Lets("::ffff:203.0.113.7") || l.Lets("198.51.100.1") {
		t.Error("Lets")
	}
	o := ContainerLimit{Protocol: "tcp", Port: "8010"}
	if !l.Overlaps(o) {
		t.Error("Overlaps")
	}
}

func TestContainerRules(t *testing.T) {
	l := ContainerLimit{Protocol: "tcp", Port: "3030", Allow: []string{"203.0.113.7", "2001:db8::1"}}
	if err := l.Normalize(); err != nil {
		t.Fatal(err)
	}
	limits := []ContainerLimit{l}
	v4 := ContainerRestore(limits, false)
	for _, want := range []string{
		":MORCHEH-DOCKER - [0:0]",
		"-A MORCHEH-DOCKER -i docker0 -j RETURN",
		"-A MORCHEH-DOCKER -s 203.0.113.7 -p tcp -m conntrack --ctstate DNAT --ctdir ORIGINAL --ctorigdstport 3030 -j RETURN",
		"-A MORCHEH-DOCKER -p tcp -m conntrack --ctstate DNAT --ctdir ORIGINAL --ctorigdstport 3030 -j DROP",
	} {
		if !strings.Contains(v4, want) {
			t.Errorf("missing %q in:\n%s", want, v4)
		}
	}
	if strings.Contains(v4, "2001:db8") {
		t.Error("an IPv6 address in the IPv4 rules")
	}
	if !strings.Contains(ContainerRestore(limits, true), "-s 2001:db8::1 ") {
		t.Error("the IPv6 address is missing")
	}
	if ContainerRestore(nil, false) != "" {
		t.Error("no limits = nothing to load")
	}

	live := `-N MORCHEH-DOCKER
-A MORCHEH-DOCKER -i docker0 -j RETURN
-A MORCHEH-DOCKER -i br-+ -j RETURN
-A MORCHEH-DOCKER -s 203.0.113.7/32 -p tcp -m conntrack --ctstate DNAT --ctdir ORIGINAL --ctorigdstport 3030 -j RETURN
-A MORCHEH-DOCKER -p tcp -m conntrack --ctstate DNAT --ctdir ORIGINAL --ctorigdstport 3030 -j DROP`
	if !ContainerLoaded(limits, false, live) {
		t.Error("the live chain should match")
	}
	if ContainerLoaded(limits, false, "") {
		t.Error("an empty chain doesn't match")
	}
}

func TestParseDockerPorts(t *testing.T) {
	out := "web\t0.0.0.0:3030->3000/tcp, [::]:3030->3000/tcp\n" +
		"db\t127.0.0.1:5432->5432/tcp\n" +
		"plain\t80/tcp\n" +
		"range\t0.0.0.0:8000-8001->9000-9001/udp\n"
	got := ParseDockerPorts(out)
	if len(got) != 4 {
		t.Fatalf("got %d: %+v", len(got), got)
	}
	web := got[0]
	if web.Container != "web" || web.Port != 3030 || web.TargetPort != 3000 || !web.Public || len(web.Addresses) != 2 {
		t.Errorf("web: %+v", web)
	}
	if db := got[1]; db.Public || db.Port != 5432 {
		t.Errorf("db: %+v", db)
	}
	if r := got[3]; r.Port != 8001 || r.TargetPort != 9001 || r.Protocol != "udp" {
		t.Errorf("range: %+v", r)
	}
}
