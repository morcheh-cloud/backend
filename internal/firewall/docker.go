package firewall

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Docker publishes a port by rewriting its address before the host's own
// rules see it, so ufw and firewalld never filter that traffic. Docker leaves
// the DOCKER-USER chain alone, and it runs before Docker's own rules: Morche
// keeps a chain of its own there that lets in only the addresses allowed for
// each published port.
//
// After the rewrite the port is the container's, so the match is on the port
// the connection first arrived on (conntrack's original destination). Only
// new inbound connections that were rewritten are touched: replies and the
// containers' own outbound traffic go by, and so does traffic between
// containers on Docker's bridges.

// ContainerChain is Morche's chain, jumped to from DOCKER-USER.
const ContainerChain = "MORCHEH-DOCKER"

// ContainerLimit says who may reach one published port (or range).
type ContainerLimit struct {
	ID       string   `json:"id" doc:"Changes when the limit does"`
	Protocol string   `json:"protocol" enum:"tcp,udp"`
	Port     string   `json:"port" doc:"The port on the server, or a range like 8000-8010" example:"3030"`
	Allow    []string `json:"allow" doc:"Addresses and networks let in; empty = nobody from outside this server"`
	Comment  string   `json:"comment,omitempty"`
}

// Normalize checks a limit and puts it in its stored form.
func (l *ContainerLimit) Normalize() error {
	l.Protocol = strings.ToLower(strings.TrimSpace(l.Protocol))
	if l.Protocol != "tcp" && l.Protocol != "udp" {
		return &FieldError{"protocol", "Choose TCP or UDP"}
	}
	lo, hi, err := portRange(l.Port)
	if err != nil {
		return &FieldError{"port", err.Error()}
	}
	l.Port = strconv.Itoa(lo)
	if hi != lo {
		l.Port += "-" + strconv.Itoa(hi)
	}
	seen := map[string]bool{}
	allow := []string{}
	for _, a := range l.Allow {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		v, err := normalizeAddress(a)
		if err != nil || v == "" {
			return &FieldError{"allow", fmt.Sprintf("%q isn't an IP address or a network like 203.0.113.0/24", a)}
		}
		if !seen[v] {
			seen[v] = true
			allow = append(allow, v)
		}
	}
	if len(allow) > 200 {
		return &FieldError{"allow", "Up to 200 addresses per port"}
	}
	l.Allow = allow
	l.Comment = strings.Join(strings.Fields(l.Comment), " ")
	if len(l.Comment) > 120 {
		return &FieldError{"comment", "Keep the note under 120 characters"}
	}
	l.ID = identify("container", l.Protocol, l.Port, strings.Join(l.Allow, ","), l.Comment)
	return nil
}

func portRange(s string) (lo, hi int, err error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	a, b, isRange := strings.Cut(strings.ReplaceAll(s, ":", "-"), "-")
	if !isRange {
		b = a
	}
	lo, errA := strconv.Atoi(a)
	hi, errB := strconv.Atoi(b)
	if errA != nil || errB != nil {
		return 0, 0, fmt.Errorf("Use a port like 3030 or a range like 8000-8010")
	}
	if lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, fmt.Errorf("Ports go from 1 to 65535, the lower one first")
	}
	return lo, hi, nil
}

// Covers says whether the limit applies to a published port.
func (l ContainerLimit) Covers(protocol string, port int) bool {
	lo, hi, err := portRange(l.Port)
	return err == nil && l.Protocol == protocol && lo <= port && port <= hi
}

// Overlaps says whether two limits share a port.
func (l ContainerLimit) Overlaps(o ContainerLimit) bool {
	a1, b1, e1 := portRange(l.Port)
	a2, b2, e2 := portRange(o.Port)
	return e1 == nil && e2 == nil && l.Protocol == o.Protocol && a1 <= b2 && a2 <= b1
}

// Lets says whether ip may reach the port under this limit.
func (l ContainerLimit) Lets(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, spec := range l.Allow {
		if p, err := netip.ParsePrefix(spec); err == nil && p.Contains(a) {
			return true
		}
		if b, err := netip.ParseAddr(spec); err == nil && b == a {
			return true
		}
	}
	return false
}

// ContainerRules is the chain for one address family (v6 or not), as lines
// for `iptables-restore -n`. Nil when there are no limits.
func ContainerRules(limits []ContainerLimit, v6 bool) []string {
	if len(limits) == 0 {
		return nil
	}
	c := ContainerChain
	lines := []string{
		"-A " + c + " -i docker0 -j RETURN",
		"-A " + c + " -i br-+ -j RETURN",
	}
	for _, l := range limits {
		match := fmt.Sprintf("-p %s -m conntrack --ctstate DNAT --ctdir ORIGINAL --ctorigdstport %s",
			l.Protocol, strings.ReplaceAll(l.Port, "-", ":"))
		for _, a := range l.Allow {
			if isV6(a) == v6 {
				lines = append(lines, "-A "+c+" -s "+a+" "+match+" -j RETURN")
			}
		}
		lines = append(lines, "-A "+c+" "+match+" -j DROP")
	}
	return lines
}

// ContainerRestore is the whole payload for `iptables-restore -n`: declaring
// the chain empties it, so loading it again replaces what was there.
func ContainerRestore(limits []ContainerLimit, v6 bool) string {
	rules := ContainerRules(limits, v6)
	if rules == nil {
		return ""
	}
	return "*filter\n:" + ContainerChain + " - [0:0]\n" + strings.Join(rules, "\n") + "\nCOMMIT\n"
}

// ContainerLoaded says whether `iptables -S MORCHEH-DOCKER` output holds
// exactly the rules the limits make.
func ContainerLoaded(limits []ContainerLimit, v6 bool, live string) bool {
	var got []string
	for _, line := range strings.Split(live, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-A "+ContainerChain+" ") {
			got = append(got, normalizeRule(line))
		}
	}
	want := ContainerRules(limits, v6)
	for i := range want {
		want[i] = normalizeRule(want[i])
	}
	slices.Sort(got)
	slices.Sort(want)
	return slices.Equal(got, want)
}

// normalizeRule irons out how iptables -S prints a rule differently from the
// way it was written: single hosts gain /32 or /128, and match options move.
func normalizeRule(line string) string {
	f := strings.Fields(line)
	for i := range f {
		if i > 0 && f[i-1] == "-s" {
			f[i] = strings.TrimSuffix(strings.TrimSuffix(f[i], "/32"), "/128")
		}
	}
	slices.Sort(f)
	return strings.Join(f, " ")
}

// ParseContainerLimits reads the saved list. Anything that no longer passes
// Normalize is dropped, so a hand-edited file can't feed bad values into the
// next change.
func ParseContainerLimits(data string) []ContainerLimit {
	var list []ContainerLimit
	if strings.TrimSpace(data) == "" || json.Unmarshal([]byte(data), &list) != nil {
		return []ContainerLimit{}
	}
	out := []ContainerLimit{}
	for _, l := range list {
		if l.Normalize() == nil {
			out = append(out, l)
		}
	}
	return out
}

// PublishedPort is a container port the server answers on.
type PublishedPort struct {
	Container  string   `json:"container" example:"gereft-console"`
	Protocol   string   `json:"protocol" enum:"tcp,udp"`
	Port       int      `json:"port" doc:"On the server" example:"3030"`
	TargetPort int      `json:"target_port" doc:"Inside the container" example:"3000"`
	Addresses  []string `json:"addresses" doc:"The server addresses it's bound to" example:"[\"0.0.0.0\",\"::\"]"`
	Public     bool     `json:"public" doc:"Bound to an address other machines can reach, not only a loopback one"`
	Limit      string   `json:"limit,omitempty" doc:"The id of the limit that covers it"`
}

// ParseDockerPorts reads `docker ps --format '{{.Names}}\t{{.Ports}}'`.
// A published range becomes one entry per port, up to 100 of them.
func ParseDockerPorts(out string) []PublishedPort {
	type key struct {
		name, proto string
		port        int
	}
	byKey := map[key]*PublishedPort{}
	var order []key
	for _, line := range strings.Split(out, "\n") {
		name, ports, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok {
			continue
		}
		for _, p := range strings.Split(ports, ",") {
			host, target, ok := strings.Cut(strings.TrimSpace(p), "->")
			if !ok {
				continue
			}
			target, proto, _ := strings.Cut(target, "/")
			i := strings.LastIndex(host, ":")
			if i < 0 {
				continue
			}
			addr := strings.Trim(host[:i], "[]")
			hLo, hHi, err1 := portRange(host[i+1:])
			tLo, _, err2 := portRange(target)
			if err1 != nil || err2 != nil || hHi-hLo > 100 {
				continue
			}
			for n := hLo; n <= hHi; n++ {
				k := key{name, proto, n}
				e := byKey[k]
				if e == nil {
					e = &PublishedPort{Container: name, Protocol: proto, Port: n, TargetPort: tLo + n - hLo, Addresses: []string{}}
					byKey[k] = e
					order = append(order, k)
				}
				if !slices.Contains(e.Addresses, addr) {
					e.Addresses = append(e.Addresses, addr)
				}
				if a, err := netip.ParseAddr(addr); err != nil || !a.IsLoopback() {
					e.Public = true
				}
			}
		}
	}
	list := make([]PublishedPort, 0, len(order))
	for _, k := range order {
		list = append(list, *byKey[k])
	}
	slices.SortStableFunc(list, func(a, b PublishedPort) int {
		if a.Port != b.Port {
			return a.Port - b.Port
		}
		return strings.Compare(a.Protocol, b.Protocol)
	})
	return list
}
