package firewall

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Forward sends what arrives on a port of this server to another port or
// another machine. IPv4 only: IPv6 has no NAT worth having here.
type Forward struct {
	ID        string `json:"id" doc:"Stable while its meaning stays the same"`
	Protocol  string `json:"protocol" enum:"tcp,udp"`
	Port      string `json:"port" doc:"The port it arrives on, or a range" example:"8080"`
	ToAddress string `json:"to_address" doc:"Empty = this server" example:"10.0.0.5"`
	ToPort    string `json:"to_port" doc:"Empty = the same port" example:"80"`
	From      string `json:"from,omitempty" doc:"ufw: only from this address or network; empty = anywhere"`
	Interface string `json:"interface,omitempty" doc:"ufw: only arriving on this interface"`
	Comment   string `json:"comment,omitempty" doc:"ufw"`
	Zone      string `json:"zone,omitempty" doc:"firewalld"`

	raw string // firewalld: the value to remove it with
}

func (f *Forward) setID() {
	f.ID = identify("forward", f.Zone, f.Protocol, f.Port, f.ToAddress, f.ToPort, f.From, f.Interface)
}

var forwardPortRe = regexp.MustCompile(`^\d{1,5}(:\d{1,5})?$`)

func onePort(s string) (lo, hi int, ok bool) {
	if !forwardPortRe.MatchString(s) {
		return 0, 0, false
	}
	a, b, isRange := strings.Cut(s, ":")
	if !isRange {
		b = a
	}
	lo, _ = strconv.Atoi(a)
	hi, _ = strconv.Atoi(b)
	return lo, hi, lo >= 1 && hi <= 65535 && lo <= hi
}

// Normalize checks a forward. Everything written to a server's configuration
// passes through here, including what was read back from one.
func (f *Forward) Normalize() error {
	f.Port = strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(f.Port), " ", ""), "-", ":")
	f.ToPort = strings.ReplaceAll(strings.TrimSpace(f.ToPort), " ", "")
	f.ToAddress = strings.TrimSpace(f.ToAddress)
	f.From = strings.TrimSpace(f.From)
	f.Interface = strings.TrimSpace(f.Interface)
	f.Comment = strings.Join(strings.Fields(f.Comment), " ")
	if f.Protocol != "tcp" && f.Protocol != "udp" {
		return &FieldError{"protocol", "Choose TCP or UDP"}
	}
	lo, hi, ok := onePort(f.Port)
	if !ok {
		return &FieldError{"port", "Use a port, or a range like 5000-5010. Ports go from 1 to 65535"}
	}
	if f.ToAddress != "" {
		a, err := netip.ParseAddr(f.ToAddress)
		if err != nil || !a.Is4() || a.IsUnspecified() {
			return &FieldError{"to_address", "Enter an IPv4 address, like 10.0.0.5"}
		}
		f.ToAddress = a.String()
	}
	if f.ToPort != "" {
		to, err := strconv.Atoi(f.ToPort)
		if err != nil || to < 1 || to > 65535 {
			return &FieldError{"to_port", "Ports go from 1 to 65535"}
		}
		f.ToPort = strconv.Itoa(to)
		if lo != hi {
			return &FieldError{"to_port", "A range keeps its ports: leave this empty"}
		}
	}
	if f.ToAddress == "" && (f.ToPort == "" || f.ToPort == f.Port) {
		return &FieldError{"to_port", "Choose a different port, or send it to another machine"}
	}
	from, err := normalizeAddress(f.From)
	if err != nil || isV6(from) {
		return &FieldError{"from", "Enter an IPv4 address or a network like 203.0.113.0/24"}
	}
	f.From = from
	if f.Interface != "" && !ifaceRe.MatchString(f.Interface) {
		return &FieldError{"interface", "That isn't a valid network interface name"}
	}
	if f.Zone != "" && !zoneRe.MatchString(f.Zone) {
		return &FieldError{"zone", "That isn't a valid zone name"}
	}
	f.setID()
	return nil
}

// Remote says whether it leaves this server, which needs routing and
// masquerading on top of the rewrite.
func (f Forward) Remote() bool { return f.ToAddress != "" }

// Target is the port traffic ends up on.
func (f Forward) Target() string {
	if f.ToPort != "" {
		return f.ToPort
	}
	return f.Port
}

// Covers says whether it takes over a port.
func (f Forward) Covers(port int) bool {
	lo, hi, ok := onePort(f.Port)
	return ok && lo <= port && port <= hi
}

// Overlaps says whether two forwards would fight over the same traffic.
func (f Forward) Overlaps(o Forward) bool {
	if f.Protocol != o.Protocol || f.Zone != o.Zone {
		return false
	}
	a, b, ok := onePort(f.Port)
	c, d, ok2 := onePort(o.Port)
	return ok && ok2 && a <= d && c <= b
}

// FilterInput is the rule that lets forwarded traffic through ufw, which
// filters it after the rewrite.
func (f Forward) FilterInput(comment string) Input {
	in := Input{Action: "allow", Direction: "in", Protocol: f.Protocol, Port: f.Target(), From: f.From, Interface: f.Interface, Comment: comment}
	if f.Remote() {
		in.Direction, in.To = "routed", f.ToAddress
	}
	return in
}

// ---- ufw: a block of its own in before.rules ----

// ufw has no forwarding of its own: the way to do it is a *nat table in
// before.rules, which it hands to iptables-restore --noflush. So the block
// uses chains of its own, which a restore does flush, and never touches
// PREROUTING's other rules (Docker keeps its own there). The block stays when
// empty, or a reload would leave the old rules running.
const (
	forwardBegin  = "# BEGIN MORCHEH FORWARDS (changed by Morcheh, edits here are lost)"
	forwardEnd    = "# END MORCHEH FORWARDS"
	forwardMark   = "### forward ###"
	ForwardChainP = "MORCHEH-PRE"
	ForwardChainQ = "MORCHEH-POST"
)

// splitBefore takes the managed block out of before.rules.
func splitBefore(before string) (block, rest string, err error) {
	i := strings.Index(before, forwardBegin)
	if i < 0 {
		return "", before, nil
	}
	j := strings.Index(before, forwardEnd)
	if j < i {
		return "", "", errors.New("The Morcheh block in /etc/ufw/before.rules is damaged: fix it on the server first")
	}
	return before[i:j], before[:i] + strings.TrimPrefix(before[j+len(forwardEnd):], "\n"), nil
}

// ParseUFWForwards reads the forwards back out of before.rules. A line that
// doesn't hold up is left out, and goes when the block is next written.
func ParseUFWForwards(before string) []Forward {
	block, _, err := splitBefore(before)
	if err != nil {
		return nil
	}
	out := []Forward{}
	for _, line := range strings.Split(block, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), forwardMark)
		if !ok {
			continue
		}
		var f Forward
		for _, kv := range strings.Fields(rest) {
			k, v, _ := strings.Cut(kv, "=")
			switch k {
			case "proto":
				f.Protocol = v
			case "port":
				f.Port = v
			case "to":
				f.ToAddress = v
			case "to_port":
				f.ToPort = v
			case "from":
				f.From = v
			case "in":
				f.Interface = v
			case "comment":
				if b, err := hex.DecodeString(v); err == nil {
					f.Comment = string(b)
				}
			}
		}
		if f.Normalize() == nil {
			out = append(out, f)
		}
	}
	return out
}

func forwardRules(f Forward) []string {
	match := "-p " + f.Protocol
	if f.Interface != "" {
		match = "-i " + f.Interface + " " + match
	}
	if f.From != "" {
		match += " -s " + f.From
	}
	match += " --dport " + f.Port
	if !f.Remote() {
		return []string{"-A " + ForwardChainP + " " + match + " -j REDIRECT --to-ports " + f.ToPort}
	}
	to := f.ToAddress
	if f.ToPort != "" {
		to += ":" + f.ToPort
	}
	return []string{
		"-A " + ForwardChainP + " " + match + " -j DNAT --to-destination " + to,
		"-A " + ForwardChainQ + " -p " + f.Protocol + " -d " + f.ToAddress + " --dport " + f.Target() + " -j MASQUERADE",
	}
}

// UFWSetForwards returns before.rules holding exactly these forwards.
func UFWSetForwards(before string, list []Forward) (string, error) {
	_, rest, err := splitBefore(before)
	if err != nil {
		return "", err
	}
	lines := []string{
		forwardBegin, "*nat",
		":" + ForwardChainP + " - [0:0]", ":" + ForwardChainQ + " - [0:0]",
		"-A PREROUTING -j " + ForwardChainP, "-A POSTROUTING -j " + ForwardChainQ,
	}
	for _, f := range list {
		lines = append(lines, fmt.Sprintf("%s proto=%s port=%s to=%s to_port=%s from=%s in=%s comment=%s",
			forwardMark, f.Protocol, f.Port, f.ToAddress, f.ToPort, f.From, f.Interface, hex.EncodeToString([]byte(f.Comment))))
		lines = append(lines, forwardRules(f)...)
	}
	lines = append(lines, "COMMIT", forwardEnd, "")
	// A last line without its newline would join whatever is read after it.
	return strings.Join(lines, "\n") + strings.TrimRight(rest, "\n") + "\n", nil
}

// ---- firewalld: forward-port entries in a zone ----

// FirewalldForwards lists the forward ports of the zones in use and the
// default one.
func FirewalldForwards(zones []Zone) []Forward {
	out := []Forward{}
	for _, z := range zones {
		if !z.Active && !z.Default {
			continue
		}
		for _, raw := range z.forwardPorts {
			f := Forward{Zone: z.Name, raw: raw}
			for _, part := range strings.Split(raw, ":") {
				k, v, _ := strings.Cut(part, "=")
				switch k {
				case "port":
					f.Port = strings.ReplaceAll(v, "-", ":")
				case "proto":
					f.Protocol = v
				case "toport":
					f.ToPort = v
				case "toaddr":
					f.ToAddress = v
				}
			}
			if f.ToPort == f.Port && f.ToAddress != "" {
				f.ToPort = ""
			}
			f.setID()
			if f.Protocol != "" && f.Port != "" && !slices.ContainsFunc(out, func(o Forward) bool { return o.ID == f.ID }) {
				out = append(out, f)
			}
		}
	}
	return out
}

func (f Forward) firewalldValue() string {
	if f.raw != "" {
		return f.raw
	}
	v := "port=" + strings.ReplaceAll(f.Port, ":", "-") + ":proto=" + f.Protocol
	if f.ToPort != "" {
		v += ":toport=" + f.ToPort
	}
	if f.ToAddress != "" {
		v += ":toaddr=" + f.ToAddress
	}
	return v
}

// FirewalldForwardAdd builds what follows `--zone=Z` to add a forward.
func FirewalldForwardAdd(f Forward) string { return "--add-forward-port=" + f.firewalldValue() }

// FirewalldForwardRemove builds what follows `--zone=Z` to remove one.
func FirewalldForwardRemove(f Forward) string { return "--remove-forward-port=" + f.firewalldValue() }
