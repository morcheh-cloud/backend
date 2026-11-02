package netmap

import (
	"bufio"
	"cmp"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// HostNet is what one server reported about its own networking.
type HostNet struct {
	Hostname   string         `json:"hostname" example:"web-01"`
	Interfaces []NetInterface `json:"interfaces"`
	Routes     []NetRoute     `json:"routes" doc:"Default routes, v4 and v6"`
	// Set when the server has no `ip` tool (BSD, macOS, Windows).
	Unsupported bool `json:"unsupported" doc:"The server has no ip tool (iproute2), so its addresses couldn't be read"`
}

type NetInterface struct {
	Name      string       `json:"name" example:"eth0"`
	Kind      string       `json:"kind" enum:"loopback,ethernet,wireless,bridge,container,veth,vlan,bond,vpn,overlay,virtual"`
	Label     string       `json:"label" doc:"What it belongs to, when known: a Docker network's name, Tailscale, WireGuard…" example:"Tailscale"`
	State     string       `json:"state" enum:"up,down,unknown"`
	MAC       string       `json:"mac" example:"52:54:00:12:34:56"`
	MTU       int          `json:"mtu" example:"1500"`
	Master    string       `json:"master" doc:"The bridge or bond it is attached to"`
	Attached  int          `json:"attached" doc:"Interfaces attached to this bridge (containers, on a Docker bridge)"`
	Addresses []NetAddress `json:"addresses"`
}

type NetAddress struct {
	IP     string `json:"ip" example:"10.0.0.12"`
	Prefix int    `json:"prefix" example:"24"`
	Subnet string `json:"subnet" doc:"The subnet in CIDR form" example:"10.0.0.0/24"`
	Family string `json:"family" enum:"ipv4,ipv6"`
	Scope  string `json:"scope" enum:"public,private,cgnat,link,host"`
}

type NetRoute struct {
	Gateway   string `json:"gateway" doc:"Empty for a route straight out of an interface (VPNs)" example:"10.0.0.1"`
	Interface string `json:"interface" example:"eth0"`
	Family    string `json:"family" enum:"ipv4,ipv6"`
}

// ParseHost reads CollectScript's output.
func ParseHost(out string) HostNet {
	h := HostNet{Interfaces: []NetInterface{}, Routes: []NetRoute{}}
	type sysInfo struct{ typ, devtype, bridge, device, wireless, tun string }
	sys := map[string]sysInfo{}
	docker := map[string]string{} // network ID → name
	byName := map[string]*NetInterface{}
	var order []string
	iface := func(name string) *NetInterface {
		if i, ok := byName[name]; ok {
			return i
		}
		byName[name] = &NetInterface{Name: name, State: "unknown", Addresses: []NetAddress{}}
		order = append(order, name)
		return byName[name]
	}

	section := ""
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if rest, ok := strings.CutPrefix(line, "@hostname "); ok {
			h.Hostname = strings.TrimSpace(rest)
			continue
		}
		if line == "@noip" {
			h.Unsupported = true
			continue
		}
		if rest, ok := strings.CutPrefix(line, "@if "); ok {
			f := strings.Split(rest, "\t")
			if len(f) >= 7 {
				sys[f[0]] = sysInfo{f[1], f[2], f[3], f[4], f[5], f[6]}
				i := iface(f[0])
				if len(f) >= 10 {
					switch f[7] {
					case "up":
						i.State = "up"
					case "down", "lowerlayerdown":
						i.State = "down"
					}
					if f[8] != "00:00:00:00:00:00" {
						i.MAC = f[8]
					}
					i.MTU, _ = strconv.Atoi(f[9])
				}
			}
			continue
		}
		if strings.HasPrefix(line, "@") {
			section = strings.Fields(line)[0][1:]
			continue
		}
		switch section {
		case "link":
			parseLink(line, iface)
		case "addr":
			parseAddr(line, iface)
		case "route":
			if r, ok := parseRoute(line); ok {
				h.Routes = append(h.Routes, r)
			}
		case "procroute":
			if r, ok := parseProcRoute(line); ok {
				h.Routes = append(h.Routes, r)
			}
		case "docker":
			if f := strings.Split(line, "\t"); len(f) >= 2 {
				docker[f[0]] = f[1]
			}
		}
	}

	for _, name := range order {
		i := byName[name]
		s := sys[name]
		i.Kind, i.Label = classify(name, s.typ, s.devtype, s.bridge == "1", s.device == "1", s.wireless == "1", s.tun == "1")
		if id, ok := strings.CutPrefix(name, "br-"); ok && i.Kind == "container" {
			for full, n := range docker {
				if strings.HasPrefix(full, id) {
					i.Label = n
				}
			}
		}
		if name == "docker0" {
			i.Label = cmp.Or(docker[findDocker(docker, "bridge")], "bridge")
		}
	}
	for _, name := range order {
		if m := byName[name].Master; m != "" {
			if b, ok := byName[m]; ok {
				b.Attached++
			}
		}
	}
	for _, name := range order {
		h.Interfaces = append(h.Interfaces, *byName[name])
	}
	return h
}

func findDocker(networks map[string]string, name string) string {
	for id, n := range networks {
		if n == name {
			return id
		}
	}
	return ""
}

var (
	linkRe  = regexp.MustCompile(`^\d+:\s+([^:\s]+):\s+<([^>]*)>(.*)$`)
	fieldRe = regexp.MustCompile(`\b(mtu|master|state|link/ether)\s+(\S+)`)
)

// `2: eth0@if12: <BROADCAST,UP,LOWER_UP> mtu 1500 qdisc … state UP … link/ether 02:42:… brd …`
func parseLink(line string, iface func(string) *NetInterface) {
	m := linkRe.FindStringSubmatch(line)
	if m == nil {
		return
	}
	i := iface(baseName(m[1]))
	flags := strings.Split(m[2], ",")
	for _, f := range fieldRe.FindAllStringSubmatch(m[3], -1) {
		switch f[1] {
		case "mtu":
			i.MTU, _ = strconv.Atoi(f[2])
		case "master":
			i.Master = f[2]
		case "state":
			switch f[2] {
			case "UP":
				i.State = "up"
			case "DOWN", "LOWERLAYERDOWN":
				i.State = "down"
			}
		case "link/ether":
			i.MAC = f[2]
		}
	}
	// Tunnels and loopback report state UNKNOWN; their flags still say.
	if i.State == "unknown" {
		if slices.Contains(flags, "UP") {
			i.State = "up"
		} else {
			i.State = "down"
		}
	}
}

// `2: eth0    inet 10.0.0.12/24 brd 10.0.0.255 scope global eth0\ …`
// `5: tun0    inet 10.8.0.1 peer 10.8.0.2/32 scope global tun0`
func parseAddr(line string, iface func(string) *NetInterface) {
	f := strings.Fields(line)
	if len(f) < 4 || (f[2] != "inet" && f[2] != "inet6") {
		return
	}
	cidr := f[3]
	if !strings.Contains(cidr, "/") {
		bits := 32
		if f[2] == "inet6" {
			bits = 128
		}
		cidr += "/" + strconv.Itoa(bits)
	}
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return
	}
	i := iface(baseName(f[1]))
	i.Addresses = append(i.Addresses, toAddress(p))
}

func toAddress(p netip.Prefix) NetAddress {
	a := p.Addr().Unmap()
	family := "ipv4"
	if a.Is6() {
		family = "ipv6"
	}
	return NetAddress{
		IP:     a.String(),
		Prefix: p.Bits(),
		Subnet: p.Masked().String(),
		Family: family,
		Scope:  scope(a),
	}
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func scope(a netip.Addr) string {
	switch {
	case a.IsLoopback():
		return "host"
	case a.IsLinkLocalUnicast():
		return "link"
	case a.IsPrivate():
		return "private"
	case cgnat.Contains(a):
		return "cgnat"
	default:
		return "public"
	}
}

func parseRoute(line string) (NetRoute, bool) {
	f := strings.Fields(line)
	if len(f) == 0 || f[0] != "default" {
		return NetRoute{}, false
	}
	r := NetRoute{Family: "ipv4"}
	for i := 1; i+1 < len(f); i++ {
		switch f[i] {
		case "via":
			r.Gateway = f[i+1]
		case "dev":
			r.Interface = f[i+1]
		}
	}
	if strings.Contains(r.Gateway, ":") {
		r.Family = "ipv6"
	}
	return r, r.Interface != "" || r.Gateway != ""
}

// `eth0	00000000	0110A8C0	0003	…`: a default route in /proc/net/route,
// addresses in little-endian hex.
func parseProcRoute(line string) (NetRoute, bool) {
	f := strings.Fields(line)
	if len(f) < 3 || f[1] != "00000000" {
		return NetRoute{}, false
	}
	gw, err := strconv.ParseUint(f[2], 16, 32)
	if err != nil {
		return NetRoute{}, false
	}
	r := NetRoute{Interface: f[0], Family: "ipv4"}
	if gw != 0 {
		r.Gateway = netip.AddrFrom4([4]byte{byte(gw), byte(gw >> 8), byte(gw >> 16), byte(gw >> 24)}).String()
	}
	return r, true
}

func baseName(name string) string {
	name, _, _ = strings.Cut(name, "@")
	return name
}

var dockerBridge = regexp.MustCompile(`^br-[0-9a-f]{12}$`)

// classify tells what an interface is from its name and what /sys says.
// ARP types: 1 ethernet, 772 loopback, 65534 none (tun, WireGuard).
func classify(name, typ, devtype string, bridge, device, wireless, tun bool) (kind, label string) {
	switch {
	case name == "lo" || typ == "772":
		return "loopback", ""
	case strings.HasPrefix(name, "veth"):
		return "veth", ""
	case name == "docker0" || dockerBridge.MatchString(name):
		return "container", "Docker"
	case strings.HasPrefix(name, "podman") || name == "cni-podman0" || name == "cni0" || strings.HasPrefix(name, "lxcbr") || strings.HasPrefix(name, "lxdbr"):
		return "container", "Containers"
	case strings.HasPrefix(name, "virbr"):
		return "container", "libvirt"
	case bridge || devtype == "bridge":
		return "bridge", ""
	case strings.HasPrefix(name, "tailscale"):
		return "vpn", "Tailscale"
	case strings.HasPrefix(name, "zt"):
		return "vpn", "ZeroTier"
	case devtype == "wireguard" || strings.HasPrefix(name, "wg"):
		return "vpn", "WireGuard"
	case strings.HasPrefix(name, "nebula"):
		return "vpn", "Nebula"
	case tun || strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "tap") || strings.HasPrefix(name, "ppp"):
		return "vpn", "Tunnel"
	case strings.HasPrefix(name, "flannel"), strings.HasPrefix(name, "cilium"),
		strings.HasPrefix(name, "cali"), strings.HasPrefix(name, "weave"),
		strings.HasPrefix(name, "vxlan"), strings.HasPrefix(name, "genev"),
		strings.HasPrefix(name, "kube-"), devtype == "vxlan":
		return "overlay", "Kubernetes"
	case devtype == "wlan" || wireless:
		return "wireless", ""
	case devtype == "vlan" || strings.Contains(name, "."):
		return "vlan", ""
	case devtype == "bond" || strings.HasPrefix(name, "bond"):
		return "bond", ""
	case device, strings.HasPrefix(name, "eth"), strings.HasPrefix(name, "en"):
		return "ethernet", ""
	default:
		return "virtual", ""
	}
}
