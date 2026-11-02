package netmap

import (
	"testing"
)

const hostA = `@hostname web-01
@if lo	772	-	0	0	0	0
@if eth0	1	-	0	1	0	0
@if docker0	1	bridge	1	0	0	0
@if veth1a2b	1	-	0	0	0	0
@if tailscale0	65534	-	0	0	0	1
@link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default \    link/ether 02:42:aa:bb:cc:dd brd ff:ff:ff:ff:ff:ff
4: veth1a2b@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP mode DEFAULT group default \    link/ether 6a:1b:2c:3d:4e:5f brd ff:ff:ff:ff:ff:ff link-netnsid 0
6: tailscale0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1280 qdisc fq_codel state UNKNOWN mode DEFAULT group default qlen 500\    link/none
@addr
1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
2: eth0    inet 10.0.0.12/24 brd 10.0.0.255 scope global eth0\       valid_lft forever preferred_lft forever
2: eth0    inet6 fe80::5054:ff:fe12:3456/64 scope link \       valid_lft forever preferred_lft forever
3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\       valid_lft forever preferred_lft forever
6: tailscale0    inet 100.101.102.103/32 scope global tailscale0\       valid_lft forever preferred_lft forever
@route
default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.12 metric 100
@docker docker
0123456789abcdef	bridge	bridge
`

const hostB = `@hostname db-01
@if eth0	1	-	0	1	0	0
@if docker0	1	bridge	1	0	0	0
@link
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\    link/ether 52:54:00:aa:aa:aa brd ff:ff:ff:ff:ff:ff
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN\    link/ether 02:42:00:00:00:01 brd ff:ff:ff:ff:ff:ff
@addr
2: eth0    inet 10.0.0.13/24 brd 10.0.0.255 scope global eth0
2: eth0    inet 203.0.113.9/32 scope global eth0
3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
@route
default via 10.0.0.1 dev eth0
`

func TestParseHost(t *testing.T) {
	h := ParseHost(hostA)
	if h.Hostname != "web-01" || len(h.Interfaces) != 5 {
		t.Fatalf("got %+v", h)
	}
	kinds := map[string]string{}
	for _, i := range h.Interfaces {
		kinds[i.Name] = i.Kind
	}
	want := map[string]string{"lo": "loopback", "eth0": "ethernet", "docker0": "container", "veth1a2b": "veth", "tailscale0": "vpn"}
	for n, k := range want {
		if kinds[n] != k {
			t.Errorf("%s: kind %q, want %q", n, kinds[n], k)
		}
	}
	d := h.Interfaces[2]
	if d.Attached != 1 || d.Label != "bridge" || d.State != "up" {
		t.Errorf("docker0 = %+v", d)
	}
	if ts := h.Interfaces[4]; ts.State != "up" || ts.Addresses[0].Scope != "cgnat" {
		t.Errorf("tailscale0 = %+v", ts)
	}
	if len(h.Routes) != 1 || h.Routes[0].Gateway != "10.0.0.1" || h.Routes[0].Interface != "eth0" {
		t.Errorf("routes = %+v", h.Routes)
	}
}

func TestNetworksAndTargets(t *testing.T) {
	a, b := ParseHost(hostA), ParseHost(hostB)
	nodes := []Node{
		{ID: "a", Host: "198.51.100.1", Port: 22, Scan: &a},
		{ID: "b", Host: "203.0.113.9", Port: 2222, Scan: &b},
		{ID: "c", Host: "10.9.9.9", Port: 22},
	}
	nets := Networks(nodes)
	byID := map[string]Subnet{}
	for _, n := range nets {
		byID[n.ID] = n
	}
	lan := byID["10.0.0.0/24"]
	if lan.Kind != "lan" || len(lan.Members) != 2 || !lan.Internet || lan.Gateways[0] != "10.0.0.1" {
		t.Errorf("lan = %+v", lan)
	}
	if _, ok := byID["172.17.0.0/16"]; ok {
		t.Error("docker bridges must stay per server")
	}
	if byID["a|172.17.0.0/16"].Kind != "container" {
		t.Error("missing a's docker bridge")
	}
	if ts := byID["100.64.0.0/10"]; ts.Label != "Tailscale" {
		t.Errorf("tailscale = %+v", ts)
	}
	if inet := byID[InternetID]; len(inet.Members) != 1 || inet.Members[0].IP != "203.0.113.9" {
		t.Errorf("internet = %+v", inet)
	}

	targets := Targets(nodes, nets)
	ab := targets["a"]
	if ab[0].Address != "10.0.0.13" || ab[0].Via != "lan" || ab[0].Port != 2222 {
		t.Errorf("a's first target = %+v", ab[0])
	}
	if len(targets["c"]) != 0 {
		t.Error("an unscanned server can't probe")
	}

	out := "@probe 0\t10.0.0.13\t2222\t0\t0.31\t10.0.0.13 dev eth0 src 10.0.0.12\t\n" +
		"@probe 1\t203.0.113.9\t2222\t124\tx\t\t\n" +
		"@probe 2\t10.9.9.9\t22\t1\t1.5\t\tbash: connect: Connection refused\n"
	probes := map[string][]ReachProbe{"a": ParseProbes(out, ab)}
	links := Links(nodes, probes, targets)
	for _, l := range links {
		switch {
		case l.From == "a" && l.To == "b":
			if l.Status != "open" || l.Via != "lan" || *l.PingMs != 0.31 {
				t.Errorf("a→b = %+v", l)
			}
		case l.From == "a" && l.To == "c":
			if l.Status != "up" {
				t.Errorf("a→c = %+v", l)
			}
		case l.From == "c":
			if l.Status != "unknown" {
				t.Errorf("c→ = %+v", l)
			}
		}
	}
}

func TestParseProcRoute(t *testing.T) {
	r, ok := parseProcRoute("eth0\t00000000\t0110A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0")
	if !ok || r.Gateway != "192.168.16.1" || r.Interface != "eth0" {
		t.Errorf("got %+v, %v", r, ok)
	}
	if _, ok := parseProcRoute("eth0\t0010A8C0\t00000000\t0001"); ok {
		t.Error("not a default route")
	}
}
