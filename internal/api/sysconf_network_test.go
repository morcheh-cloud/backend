package api

import (
	"slices"
	"strings"
	"testing"

	"github.com/morche/backend/internal/sysconf"
)

const ipAddrJSON = `[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP"],"mtu":65536,"operstate":"UNKNOWN","link_type":"loopback","address":"00:00:00:00:00:00","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"}]},
{"ifindex":2,"ifname":"enp0s3","flags":["UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"08:00:27:f4:92:29","addr_info":[{"family":"inet","local":"10.0.2.15","prefixlen":24,"scope":"global","dynamic":true},{"family":"inet6","local":"fe80::a00:27ff:fef4:9229","prefixlen":64,"scope":"link"}]},
{"ifindex":3,"ifname":"enp0s8","flags":["UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"08:00:27:a5:71:3e","addr_info":[{"family":"inet","local":"192.168.56.102","prefixlen":24,"scope":"global"}]},
{"ifindex":4,"ifname":"docker0","flags":["UP"],"mtu":1500,"operstate":"DOWN","link_type":"ether","address":"02:42:aa:bb:cc:dd","addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":16,"scope":"global"}]},
{"ifindex":5,"ifname":"veth01834c0","link_index":2,"flags":["UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"16:60:43:24:6e:12","addr_info":[]}]`

const ipRouteJSON = `[{"dst":"default","gateway":"10.0.2.2","dev":"enp0s3","protocol":"dhcp","metric":100},{"dst":"10.0.2.0/24","dev":"enp0s3","protocol":"kernel","scope":"link"},{"dst":"192.168.56.0/24","dev":"enp0s8","protocol":"kernel","scope":"link"}]`

func TestReadInterfaces(t *testing.T) {
	ifs, routes, err := readInterfaces(ipAddrJSON, ipRouteJSON, "192.168.56.102")
	if err != nil {
		t.Fatal(err)
	}
	if len(ifs) != 4 {
		t.Fatalf("lo should be left out: %+v", ifs)
	}
	e3 := ifs[0]
	if e3.Name != "enp0s3" || e3.State != "up" || e3.MAC != "08:00:27:f4:92:29" || e3.Gateway != "10.0.2.2" ||
		!slices.Equal(e3.Addresses, []string{"10.0.2.15/24", "fe80::a00:27ff:fef4:9229/64"}) || e3.CarriesMorche || e3.Virtual {
		t.Fatalf("enp0s3: %+v", e3)
	}
	if !ifs[1].CarriesMorche {
		t.Fatalf("enp0s8 carries Morche: %+v", ifs[1])
	}
	if !ifs[2].Virtual || !ifs[3].Virtual || ifs[2].State != "down" {
		t.Fatalf("virtual: %+v %+v", ifs[2], ifs[3])
	}
	if len(routes) != 3 || routes[0].To != "default" || routes[0].Via != "10.0.2.2" || routes[0].Dev != "enp0s3" {
		t.Fatalf("routes: %+v", routes)
	}
}

func TestCheckIfaceConfig(t *testing.T) {
	ok := sysconf.IfaceConfig{Name: "enp0s8", Addresses: []string{"192.168.56.102/24"}, Gateway4: "192.168.56.1", DNS: []string{"1.1.1.1"}, MTU: 1450}
	if err := checkIfaceConfig(ok); err != nil {
		t.Fatal(err)
	}
	bad := []sysconf.IfaceConfig{
		{Name: "enp0s8", Addresses: []string{"192.168.56.102"}},
		{Name: "enp0s8", Addresses: []string{"10.0.0.1/24"}, Gateway4: "fd00::1"},
		{Name: "enp0s8", Addresses: []string{"10.0.0.1/24"}, Gateway6: "10.0.0.1"},
		{Name: "enp0s8", DHCP4: true, DNS: []string{"1.1.1.1\n"}},
		{Name: "enp0s8", DHCP4: true, Search: []string{"bad domain"}},
		{Name: "enp0s8", DHCP4: true, MTU: 100},
		{Name: "en p0", DHCP4: true},
	}
	for _, b := range bad {
		if checkIfaceConfig(b) == nil {
			t.Errorf("should refuse %+v", b)
		}
	}
}

func TestMorcheAddressKept(t *testing.T) {
	iface := ServerIface{Name: "enp0s8", CarriesMorche: true}
	if w, refuse := morcheAddressCheck("192.168.56.102", iface, sysconf.IfaceConfig{Addresses: []string{"192.168.56.102/24"}}); refuse || len(w) != 0 {
		t.Fatal(w, refuse)
	}
	if _, refuse := morcheAddressCheck("192.168.56.102", iface, sysconf.IfaceConfig{Addresses: []string{"192.168.56.110/24"}}); !refuse {
		t.Fatal("dropping Morche's address must be refused")
	}
	if w, refuse := morcheAddressCheck("192.168.56.102", iface, sysconf.IfaceConfig{DHCP4: true}); refuse || len(w) != 1 || !strings.Contains(w[0], "DHCP") {
		t.Fatal(w, refuse)
	}
	other := ServerIface{Name: "enp0s3"}
	if w, refuse := morcheAddressCheck("192.168.56.102", other, sysconf.IfaceConfig{}); refuse || len(w) != 0 {
		t.Fatal(w, refuse)
	}
}
