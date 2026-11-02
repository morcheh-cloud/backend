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

// Node is one server going into the map. Scan is nil when it couldn't be
// read (offline, login failed…); others are still probed for reaching it.
type Node struct {
	ID   string
	Host string // the address Morcheh connects to
	Port int
	Scan *HostNet
}

// Subnet is a network one or more servers have an address in.
type Subnet struct {
	ID       string         `json:"id" doc:"The CIDR; host-only networks (containers) are prefixed with their server's ID" example:"10.0.0.0/24"`
	CIDR     string         `json:"cidr" doc:"Empty for the internet" example:"10.0.0.0/24"`
	Family   string         `json:"family" enum:"ipv4,ipv6,"`
	Kind     string         `json:"kind" enum:"lan,vpn,public,container,internet" doc:"internet gathers the public addresses that share no subnet with another server"`
	Label    string         `json:"label" doc:"Tailscale, a Docker network's name…" example:""`
	Internet bool           `json:"internet" doc:"A default route goes out through it"`
	Gateways []string       `json:"gateways" doc:"Default gateways inside it"`
	Members  []SubnetMember `json:"members"`
}

type SubnetMember struct {
	ServerID  string `json:"server_id" format:"uuid"`
	Interface string `json:"interface" example:"eth0"`
	IP        string `json:"ip" example:"10.0.0.12"`
}

const InternetID = "internet"

// Networks groups every address into the subnets the servers share.
// Container bridges are kept per server (every Docker host has a
// 172.17.0.0/16 of its own). Public addresses that share a subnet with no
// other server, and point-to-point addresses, go to one "internet" network.
func Networks(nodes []Node) []Subnet {
	byID := map[string]*Subnet{}
	var ids []string
	add := func(id string, n Subnet) *Subnet {
		if got, ok := byID[id]; ok {
			return got
		}
		n.ID = id
		n.Gateways, n.Members = []string{}, []SubnetMember{}
		byID[id] = &n
		ids = append(ids, id)
		return byID[id]
	}

	for _, node := range nodes {
		if node.Scan == nil {
			continue
		}
		for _, i := range node.Scan.Interfaces {
			if i.Kind == "loopback" || i.Kind == "veth" {
				continue
			}
			for _, a := range i.Addresses {
				if a.Scope == "host" || a.Scope == "link" {
					continue
				}
				m := SubnetMember{ServerID: node.ID, Interface: i.Name, IP: a.IP}
				hostOnly := (a.Family == "ipv4" && a.Prefix == 32) || (a.Family == "ipv6" && a.Prefix == 128)
				switch {
				case i.Kind == "container":
					n := add(node.ID+"|"+a.Subnet, Subnet{CIDR: a.Subnet, Family: a.Family, Kind: "container", Label: i.Label})
					n.Members = append(n.Members, m)
				case a.Scope == "cgnat" && i.Label == "Tailscale":
					n := add(cgnat.String(), Subnet{CIDR: cgnat.String(), Family: "ipv4", Kind: "vpn", Label: "Tailscale"})
					n.Members = append(n.Members, m)
				case hostOnly:
					if a.Scope == "public" {
						n := add(InternetID, Subnet{Kind: "internet"})
						n.Members = append(n.Members, m)
					}
				default:
					kind := "lan"
					switch {
					case i.Kind == "vpn" || i.Kind == "overlay":
						kind = "vpn"
					case a.Scope == "public":
						kind = "public"
					}
					n := add(a.Subnet, Subnet{CIDR: a.Subnet, Family: a.Family, Kind: kind, Label: cmp.Or(i.Label)})
					n.Members = append(n.Members, m)
				}
			}
		}
	}

	// Default routes: mark the network the gateway sits in.
	for _, node := range nodes {
		if node.Scan == nil {
			continue
		}
		for _, r := range node.Scan.Routes {
			gw, err := netip.ParseAddr(r.Gateway)
			for _, id := range ids {
				n := byID[id]
				if n.Kind == "container" || n.Kind == "internet" || !hasMember(n, node.ID, r.Interface) {
					continue
				}
				if err == nil {
					if p, perr := netip.ParsePrefix(n.CIDR); perr == nil && p.Contains(gw) {
						n.Internet = true
						if !slices.Contains(n.Gateways, r.Gateway) {
							n.Gateways = append(n.Gateways, r.Gateway)
						}
					}
				} else if r.Gateway == "" {
					n.Internet = true // straight out of a tunnel
				}
			}
		}
	}

	// A public subnet only one server is in says nothing more than "it's on
	// the internet".
	inet := byID[InternetID]
	out := []Subnet{}
	for _, id := range ids {
		n := byID[id]
		if n.Kind == "public" && servers(n) == 1 {
			if inet == nil {
				inet = add(InternetID, Subnet{Kind: "internet"})
			}
			inet.Members = append(inet.Members, n.Members...)
			continue
		}
		if id != InternetID {
			out = append(out, *n)
		}
	}
	if inet != nil {
		out = append(out, *inet)
	}
	slices.SortStableFunc(out, func(a, b Subnet) int {
		return cmp.Compare(kindOrder(a.Kind), kindOrder(b.Kind))
	})
	return out
}

func kindOrder(k string) int {
	return slices.Index([]string{"lan", "vpn", "public", "internet", "container"}, k)
}

func hasMember(n *Subnet, serverID, iface string) bool {
	return slices.ContainsFunc(n.Members, func(m SubnetMember) bool {
		return m.ServerID == serverID && (iface == "" || m.Interface == iface)
	})
}

func servers(n *Subnet) int {
	seen := map[string]bool{}
	for _, m := range n.Members {
		seen[m.ServerID] = true
	}
	return len(seen)
}

// Target is one address a server should try to reach another server on.
type Target struct {
	To      string // server ID
	Address string
	Port    int
	Via     string // lan, vpn, host (the address Morcheh uses), address
	Subnet  string // the shared network's ID, for lan/vpn
}

const maxTargetsPerServer = 4

var safeAddr = regexp.MustCompile(`^[A-Za-z0-9._:\-]+$`)

// Targets lists, for each scanned server, the addresses of every other server
// worth trying: its addresses in networks they share first (the LAN path),
// then the address Morcheh itself connects to.
func Targets(nodes []Node, networks []Subnet) map[string][]Target {
	out := map[string][]Target{}
	for _, from := range nodes {
		if from.Scan == nil {
			continue
		}
		for _, to := range nodes {
			if to.ID == from.ID {
				continue
			}
			var list []Target
			seen := map[string]bool{}
			push := func(t Target) {
				if len(list) >= maxTargetsPerServer || seen[t.Address] || !safeAddr.MatchString(t.Address) {
					return
				}
				seen[t.Address] = true
				list = append(list, t)
			}
			for _, n := range networks {
				if (n.Kind != "lan" && n.Kind != "vpn" && n.Kind != "public") || !hasMember(&n, from.ID, "") {
					continue
				}
				for _, m := range n.Members {
					if m.ServerID == to.ID {
						via := "lan"
						if n.Kind == "vpn" {
							via = "vpn"
						}
						push(Target{To: to.ID, Address: m.IP, Port: to.Port, Via: via, Subnet: n.ID})
					}
				}
			}
			if !isLoopback(to.Host) {
				push(Target{To: to.ID, Address: to.Host, Port: to.Port, Via: "host"})
			}
			// Nothing shared and Morcheh reaches it on localhost (a container
			// or a tunnel): try the server's own routable addresses.
			if len(list) == 0 && to.Scan != nil {
				for _, i := range to.Scan.Interfaces {
					if i.Kind == "loopback" || i.Kind == "veth" || i.Kind == "container" {
						continue
					}
					for _, a := range i.Addresses {
						if a.Scope != "host" && a.Scope != "link" {
							push(Target{To: to.ID, Address: a.IP, Port: to.Port, Via: "address"})
						}
					}
				}
			}
			out[from.ID] = append(out[from.ID], list...)
		}
	}
	return out
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// ProbeInput is ProbeScript's stdin for these targets.
func ProbeInput(targets []Target) string {
	var b strings.Builder
	for i, t := range targets {
		b.WriteString(strconv.Itoa(i) + "\t" + t.Address + "\t" + strconv.Itoa(t.Port) + "\n")
	}
	return b.String()
}

type ReachProbe struct {
	Address string   `json:"address" example:"10.0.0.13"`
	Port    int      `json:"port" example:"22"`
	Via     string   `json:"via" enum:"lan,vpn,host,address" doc:"Why this address was tried: a shared LAN or VPN, the address Morcheh uses, or one of the server's own"`
	Subnet  string   `json:"subnet" doc:"The shared network's ID, for lan and vpn"`
	TCP     string   `json:"tcp" enum:"open,refused,timeout,unreachable,dns,failed,unavailable" doc:"refused still means the host answered"`
	Ping    string   `json:"ping" enum:"ok,lost,unavailable"`
	PingMs  *float64 `json:"ping_ms,omitempty" example:"0.42"`
	Route   string   `json:"route" doc:"The route the kernel picked (ip route get)" example:"10.0.0.13 dev eth0 src 10.0.0.12"`
	Message string   `json:"message" doc:"The connect error, if any"`
}

// ParseProbes reads ProbeScript's output for the targets it was given.
func ParseProbes(out string, targets []Target) []ReachProbe {
	probes := make([]ReachProbe, len(targets))
	got := make([]bool, len(targets))
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "@probe ")
		if !ok {
			continue
		}
		f := strings.Split(rest, "\t")
		if len(f) < 7 {
			continue
		}
		i, err := strconv.Atoi(f[0])
		if err != nil || i < 0 || i >= len(targets) {
			continue
		}
		t := targets[i]
		p := ReachProbe{Address: t.Address, Port: t.Port, Via: t.Via, Subnet: t.Subnet, Route: strings.TrimSpace(f[5]), Message: strings.TrimSpace(f[6])}
		p.TCP = tcpResult(f[3], p.Message)
		switch f[4] {
		case "-":
			p.Ping = "unavailable"
		case "x", "":
			p.Ping = "lost"
		default:
			p.Ping = "ok"
			if ms, err := strconv.ParseFloat(f[4], 64); err == nil {
				p.PingMs = &ms
			}
		}
		if p.TCP == "open" || p.TCP == "timeout" {
			p.Message = ""
		}
		probes[i], got[i] = p, true
	}
	for i, t := range targets {
		if !got[i] {
			probes[i] = ReachProbe{Address: t.Address, Port: t.Port, Via: t.Via, Subnet: t.Subnet, TCP: "failed", Ping: "lost", Message: "No result"}
		}
	}
	return probes
}

func tcpResult(rc, msg string) string {
	m := strings.ToLower(msg)
	switch {
	case rc == "0":
		return "open"
	case rc == "127":
		return "unavailable"
	case rc == "124" || strings.Contains(m, "timed out"):
		return "timeout"
	case strings.Contains(m, "refused"):
		return "refused"
	case strings.Contains(m, "no route") || strings.Contains(m, "unreachable"):
		return "unreachable"
	case strings.Contains(m, "name or service") || strings.Contains(m, "not known") ||
		strings.Contains(m, "resolve") || strings.Contains(m, "invalid"):
		return "dns"
	default:
		return "failed"
	}
}

// Reach is what one server found when it tried to reach another.
type Reach struct {
	From   string       `json:"from" format:"uuid"`
	To     string       `json:"to" format:"uuid"`
	Status string       `json:"status" enum:"open,up,blocked,unknown" doc:"open: the SSH port accepts connections; up: the host answers (ping or a refused connect) but the port doesn't; blocked: nothing answered; unknown: the source couldn't be read, or there was no address to try"`
	Via    string       `json:"via" enum:"lan,vpn,host,address," doc:"The best path found"`
	PingMs *float64     `json:"ping_ms,omitempty" doc:"Round trip on the best path" example:"0.42"`
	Probes []ReachProbe `json:"probes"`
}

// Links picks, for every ordered pair, the best of its probes: open over
// up over blocked, then a LAN or VPN path over the rest, then the fastest.
func Links(nodes []Node, probes map[string][]ReachProbe, targets map[string][]Target) []Reach {
	out := []Reach{}
	for _, from := range nodes {
		for _, to := range nodes {
			if from.ID == to.ID {
				continue
			}
			l := Reach{From: from.ID, To: to.ID, Status: "unknown", Probes: []ReachProbe{}}
			if from.Scan != nil {
				for i, t := range targets[from.ID] {
					if t.To == to.ID && i < len(probes[from.ID]) {
						l.Probes = append(l.Probes, probes[from.ID][i])
					}
				}
				l.Status = "blocked"
			}
			slices.SortStableFunc(l.Probes, func(a, b ReachProbe) int {
				return cmp.Or(
					cmp.Compare(rank(a), rank(b)),
					cmp.Compare(viaRank(a.Via), viaRank(b.Via)),
					cmp.Compare(msOr(a.PingMs), msOr(b.PingMs)),
				)
			})
			if len(l.Probes) == 0 {
				l.Status = "unknown" // no address it could try
			} else {
				best := l.Probes[0]
				switch rank(best) {
				case 0:
					l.Status = "open"
				case 1:
					l.Status = "up"
				}
				if l.Status != "blocked" {
					l.Via, l.PingMs = best.Via, best.PingMs
				}
			}
			out = append(out, l)
		}
	}
	return out
}

func rank(p ReachProbe) int {
	switch {
	case p.TCP == "open":
		return 0
	case p.TCP == "refused" || p.Ping == "ok":
		return 1
	default:
		return 2
	}
}

func viaRank(via string) int {
	return slices.Index([]string{"lan", "vpn", "host", "address"}, via)
}

func msOr(ms *float64) float64 {
	if ms == nil {
		return 1e9
	}
	return *ms
}
