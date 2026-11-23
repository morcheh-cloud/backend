package sysconf

import (
	"slices"
	"strings"
	"testing"
)

const netplanStatic = `# Written by hand, keep it tidy
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      match:
        macaddress: "52:54:00:12:34:56"
      set-name: eth0
      addresses:
        - 192.168.56.102/24
      routes:
        - to: default
          via: 192.168.56.1
        - to: 10.10.0.0/16
          via: 192.168.56.254
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]
        search: [lan]
      mtu: 1500
    eth1:
      dhcp4: true
  vlans:
    vlan20:
      id: 20
      link: eth0
      addresses: [10.20.0.5/24]
      gateway4: 10.20.0.1
`

func TestReadNetplan(t *testing.T) {
	cfgs, where, err := ReadNetplan(map[string]string{
		"/etc/netplan/01-static.yaml": netplanStatic,
		"/etc/netplan/90-extra.yaml":  "network:\n  ethernets:\n    eth1:\n      dhcp6: true\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	e0 := cfgs["eth0"]
	if e0.DHCP4 || !slices.Equal(e0.Addresses, []string{"192.168.56.102/24"}) || e0.Gateway4 != "192.168.56.1" ||
		!slices.Equal(e0.DNS, []string{"1.1.1.1", "8.8.8.8"}) || !slices.Equal(e0.Search, []string{"lan"}) || e0.MTU != 1500 || e0.Kind != "ethernet" {
		t.Fatalf("eth0: %+v", e0)
	}
	if e1 := cfgs["eth1"]; !e1.DHCP4 || !e1.DHCP6 {
		t.Fatalf("eth1 merged: %+v", e1)
	}
	if v := cfgs["vlan20"]; v.Gateway4 != "10.20.0.1" || v.Kind != "vlan" {
		t.Fatalf("vlan: %+v", v)
	}
	if where["eth0"] != "/etc/netplan/01-static.yaml" || where["eth1"] != "/etc/netplan/90-extra.yaml" {
		t.Fatalf("where: %v", where)
	}
}

func TestEditNetplanKeepsComments(t *testing.T) {
	got, err := EditNetplan(netplanStatic, IfaceConfig{
		Name: "eth0", Addresses: []string{"192.168.56.110/24"}, Gateway4: "192.168.56.1",
		DNS: []string{"9.9.9.9"}, MTU: 1450,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# Written by hand, keep it tidy", "macaddress:", "set-name: eth0", "192.168.56.110/24", "mtu: 1450", "9.9.9.9", "10.10.0.0/16", "vlan20"} {
		if !strings.Contains(got, want) {
			t.Errorf("lost %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "192.168.56.102") || strings.Contains(got, "search") {
		t.Errorf("old values left:\n%s", got)
	}
	back, _, err := ReadNetplan(map[string]string{"/etc/netplan/a.yaml": got})
	if err != nil {
		t.Fatal(err)
	}
	if e := back["eth0"]; e.Gateway4 != "192.168.56.1" || e.MTU != 1450 || !slices.Equal(e.Addresses, []string{"192.168.56.110/24"}) {
		t.Fatalf("read back: %+v", e)
	}
}

func TestEditNetplanToDHCP(t *testing.T) {
	got, err := EditNetplan(netplanStatic, IfaceConfig{Name: "vlan20", DHCP4: true})
	if err != nil {
		t.Fatal(err)
	}
	back, _, _ := ReadNetplan(map[string]string{"a": got})
	v := back["vlan20"]
	if !v.DHCP4 || len(v.Addresses) > 0 || v.Gateway4 != "" {
		t.Fatalf("vlan20: %+v\n%s", v, got)
	}
	if !strings.Contains(got, "link: eth0") || strings.Contains(got, "gateway4") {
		t.Fatalf("%s", got)
	}
	if _, err := EditNetplan(netplanStatic, IfaceConfig{Name: "nope"}); err == nil {
		t.Fatal("an interface the file doesn't have should be refused")
	}
}

func TestNetplanEditCloudInitNeedsDisable(t *testing.T) {
	ci := "# This file is generated from information provided by the datasource.  Changes\n# to it will not persist across an instance reboot.\nnetwork:\n  ethernets:\n    ens3:\n      dhcp4: true\n"
	if !CloudInitNetplan("/etc/netplan/50-cloud-init.yaml", "") || !CloudInitNetplan("/etc/netplan/x.yaml", ci) {
		t.Fatal("cloud-init file not recognised")
	}
	if CloudInitNetplan("/etc/netplan/01-static.yaml", netplanStatic) {
		t.Fatal("hand-written file taken for cloud-init")
	}
	if !strings.Contains(CloudInitDisable, "network: {config: disabled}") {
		t.Fatal(CloudInitDisable)
	}
}

const nmShow = `connection.uuid:3f1c-aa
connection.id:Wired connection 1
connection.interface-name:eth0
connection.type:802-3-ethernet
ipv4.method:manual
ipv4.addresses:192.168.56.102/24,10.0.0.9/8
ipv4.gateway:192.168.56.1
ipv4.dns:1.1.1.1,8.8.8.8
ipv4.dns-search:lan
ipv6.method:auto
ipv6.addresses:fd00\:\:5/64
ipv6.gateway:--
ipv6.dns:
802-3-ethernet.mtu:auto

connection.uuid:77-bb
connection.id:wifi
connection.interface-name:wlan0
connection.type:802-11-wireless
ipv4.method:auto
ipv4.addresses:
ipv4.gateway:--
ipv4.dns:
ipv4.dns-search:
ipv6.method:ignore
ipv6.addresses:
ipv6.gateway:--
ipv6.dns:
`

func TestParseNmcli(t *testing.T) {
	cs := ParseNmcli(nmShow)
	if len(cs) != 2 {
		t.Fatalf("%+v", cs)
	}
	c := cs[0]
	if c.UUID != "3f1c-aa" || c.Name != "Wired connection 1" || c.Device != "eth0" || c.Type != "802-3-ethernet" {
		t.Fatalf("%+v", c)
	}
	k := c.Config
	if k.DHCP4 || !k.DHCP6 || !slices.Equal(k.Addresses, []string{"192.168.56.102/24", "10.0.0.9/8", "fd00::5/64"}) ||
		k.Gateway4 != "192.168.56.1" || k.Gateway6 != "" || !slices.Equal(k.DNS, []string{"1.1.1.1", "8.8.8.8"}) || k.MTU != 0 || k.Kind != "ethernet" || k.Name != "eth0" {
		t.Fatalf("%+v", k)
	}
	if w := cs[1].Config; !w.DHCP4 || w.DHCP6 || w.Kind != "wifi" {
		t.Fatalf("wifi: %+v", w)
	}
}

func TestNmcliModify(t *testing.T) {
	c := ParseNmcli(nmShow)[0]
	got := strings.Join(NmcliModify(c, IfaceConfig{Addresses: []string{"192.168.56.110/24"}, Gateway4: "192.168.56.1", DNS: []string{"9.9.9.9"}, MTU: 1450}), "|")
	want := "ipv4.method|manual|ipv4.addresses|192.168.56.110/24|ipv4.gateway|192.168.56.1|ipv4.dns|9.9.9.9|ipv4.dns-search||" +
		"ipv6.method|ignore|ipv6.addresses||ipv6.gateway||ipv6.dns||802-3-ethernet.mtu|1450"
	if got != want {
		t.Fatalf("static:\n%s\n%s", got, want)
	}
	got = strings.Join(NmcliModify(c, IfaceConfig{DHCP4: true, DHCP6: true}), "|")
	if !strings.HasPrefix(got, "ipv4.method|auto|ipv4.addresses||ipv4.gateway||") || !strings.Contains(got, "ipv6.method|auto|") || !strings.HasSuffix(got, "802-3-ethernet.mtu|auto") {
		t.Fatalf("dhcp: %s", got)
	}
	got = strings.Join(NmcliModify(ParseNmcli(nmShow)[1], IfaceConfig{}), "|")
	if !strings.HasPrefix(got, "ipv4.method|disabled|") || strings.Contains(got, "mtu") {
		t.Fatalf("off: %s", got)
	}
}

func TestFilled(t *testing.T) {
	c := IfaceConfig{Name: "x"}.Filled()
	if c.Addresses == nil || c.DNS == nil || c.Search == nil {
		t.Fatal(c)
	}
	r := Repo{}.Filled()
	if r.Types == nil || r.Options == nil || r.Components == nil {
		t.Fatal(r)
	}
}
