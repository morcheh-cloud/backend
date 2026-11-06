// Package firewall reads and writes the rules of the firewalls a server can
// run (ufw, firewalld) and reads the ones Morcheh doesn't manage (plain
// nftables, iptables). It only parses and builds text: running anything on a
// server is the api package's job.
package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// FilterRule is one firewall rule in a form that doesn't depend on the tool.
type FilterRule struct {
	ID           string `json:"id" doc:"Stable while the rule's meaning stays the same"`
	Action       string `json:"action" enum:"allow,block,reject,limit,other"`
	Direction    string `json:"direction" enum:"in,out,routed"`
	Protocol     string `json:"protocol" doc:"any, tcp, udp, or another protocol name" example:"tcp"`
	Port         string `json:"port" doc:"Empty = every port. A port, a range or a comma list" example:"5000:5010"`
	SourcePort   string `json:"source_port,omitempty"`
	From         string `json:"from" doc:"Empty = anywhere" example:"203.0.113.0/24"`
	To           string `json:"to" doc:"Empty = this server"`
	Interface    string `json:"interface,omitempty" example:"eth0"`
	OutInterface string `json:"out_interface,omitempty" doc:"Routed rules only"`
	Comment      string `json:"comment,omitempty"`
	Family       string `json:"family" enum:"both,v4,v6"`
	Zone         string `json:"zone,omitempty" doc:"firewalld"`
	Service      string `json:"service,omitempty" doc:"An application profile (ufw) or service (firewalld)" example:"ssh"`
	Log          bool   `json:"log"`
	Raw          string `json:"raw" doc:"The rule as the tool writes it"`
	Editable     bool   `json:"editable" doc:"Can be changed here, not only removed"`
	Deletable    bool   `json:"deletable"`
	ProtectsSSH  bool   `json:"protects_ssh" doc:"Lets SSH in for Morcheh or for everyone"`

	kind       string // firewalld: service, port, rich, source-port, protocol
	logAll     bool   // ufw: log-all
	sourceApp  string // ufw
	position   int    // ufw: 1-based place among the IPv4 rules; 0 when it has none
	rawCommand string // firewalld: the value to remove it with
}

// Position is the rule's 1-based place among the IPv4 rules, 0 if it has none.
func (r FilterRule) Position() int { return r.position }

// Input is a rule as a person asks for it.
type Input struct {
	Action       string
	Direction    string
	Protocol     string
	Port         string
	Service      string
	From         string
	To           string
	Interface    string
	OutInterface string
	Comment      string
	Zone         string
	Log          bool
	Top          bool
}

// FieldError points at the input field that's wrong.
type FieldError struct{ Field, Message string }

func (e *FieldError) Error() string { return e.Message }

var (
	portRe    = regexp.MustCompile(`^\d{1,5}(:\d{1,5})?(,\d{1,5}(:\d{1,5})?)*$`)
	ifaceRe   = regexp.MustCompile(`^[A-Za-z0-9_.:@+-]{1,15}$`)
	serviceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_+. -]{0,63}$`)
	zoneRe    = regexp.MustCompile(`^[A-Za-z0-9_+-]{1,32}$`)
)

// ValidZone says whether name can be a firewalld zone.
func ValidZone(name string) bool { return zoneRe.MatchString(name) }

// Normalize checks a rule and fills in its defaults. Everything a command is
// built from has passed through here.
func (in *Input) Normalize() error {
	if in.Direction == "" {
		in.Direction = "in"
	}
	if in.Protocol == "" {
		in.Protocol = "any"
	}
	in.Port = strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(in.Port), " ", ""), "-", ":")
	in.Service = strings.TrimSpace(in.Service)
	in.From = strings.TrimSpace(in.From)
	in.To = strings.TrimSpace(in.To)
	in.Interface = strings.TrimSpace(in.Interface)
	in.OutInterface = strings.TrimSpace(in.OutInterface)
	// ufw's own parser fails on a straight apostrophe, whatever the quoting.
	in.Comment = strings.ReplaceAll(strings.Join(strings.Fields(in.Comment), " "), "'", "’")

	if in.Port != "" {
		if !portRe.MatchString(in.Port) {
			return &FieldError{"port", "Use a port, a range like 5000-5010, or a list like 80,443"}
		}
		for _, part := range strings.Split(in.Port, ",") {
			lo, hi, isRange := strings.Cut(part, ":")
			if !isRange {
				hi = lo
			}
			a, _ := strconv.Atoi(lo)
			b, _ := strconv.Atoi(hi)
			if a < 1 || b > 65535 || a > b {
				return &FieldError{"port", "Ports go from 1 to 65535, the lower one first"}
			}
		}
	}
	if in.Service != "" {
		if !serviceRe.MatchString(in.Service) {
			return &FieldError{"service", "That isn't a valid service name"}
		}
		if in.Port != "" {
			return &FieldError{"port", "Choose a service or a port, not both"}
		}
	}
	for _, f := range []struct {
		name  string
		value *string
	}{{"from", &in.From}, {"to", &in.To}} {
		v, err := normalizeAddress(*f.value)
		if err != nil {
			return &FieldError{f.name, "Enter an IP address or a network like 203.0.113.0/24"}
		}
		*f.value = v
	}
	if in.From != "" && in.To != "" && isV6(in.From) != isV6(in.To) {
		return &FieldError{"to", "Both addresses must be IPv4 or both IPv6"}
	}
	for _, f := range []struct{ name, value string }{{"interface", in.Interface}, {"out_interface", in.OutInterface}} {
		if f.value != "" && !ifaceRe.MatchString(f.value) {
			return &FieldError{f.name, "That isn't a valid network interface name"}
		}
	}
	if in.Zone != "" && !zoneRe.MatchString(in.Zone) {
		return &FieldError{"zone", "That isn't a valid zone name"}
	}
	if in.OutInterface != "" && in.Direction != "routed" {
		return &FieldError{"out_interface", "Only routed rules have an outgoing interface"}
	}
	if in.Action == "limit" && (in.Direction != "in" || in.Protocol == "any" && in.Service == "") {
		return &FieldError{"action", "Rate limiting works on incoming TCP or UDP traffic: choose a protocol"}
	}
	return nil
}

func normalizeAddress(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	if strings.EqualFold(s, "any") || s == "0.0.0.0/0" || s == "::/0" {
		return "", nil
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", err
		}
		return p.String(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", err
	}
	return a.String(), nil
}

func isV6(s string) bool { return strings.Contains(s, ":") }

// wildcard says whether an address written by a tool means everywhere.
func wildcard(s string) bool {
	return s == "" || s == "any" || s == "0.0.0.0/0" || s == "::/0"
}

// PortCovers says whether a port spec (a port, range or list; empty = all)
// includes port.
func PortCovers(spec string, port int) bool {
	if spec == "" {
		return true
	}
	for _, part := range strings.Split(spec, ",") {
		lo, hi, isRange := strings.Cut(strings.ReplaceAll(strings.TrimSpace(part), "-", ":"), ":")
		if !isRange {
			hi = lo
		}
		a, errA := strconv.Atoi(lo)
		b, errB := strconv.Atoi(hi)
		if errA == nil && errB == nil && a <= port && port <= b {
			return true
		}
	}
	return false
}

// AddressCovers says whether an address spec (an address or network, empty =
// everywhere) includes ip.
func AddressCovers(spec, ip string) bool {
	if wildcard(spec) {
		return true
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, s := range strings.Split(spec, ",") {
		s = strings.TrimSpace(s)
		if p, err := netip.ParsePrefix(s); err == nil {
			if p.Contains(a) {
				return true
			}
		} else if b, err := netip.ParseAddr(s); err == nil && b.Unmap() == a {
			return true
		}
	}
	return false
}

// Lets says whether the rule lets a TCP connection to port in from ip. Empty
// ip stands for everyone.
func (r FilterRule) Lets(port int, ip string) bool {
	if r.Direction != "in" || r.Action != "allow" && r.Action != "limit" {
		return false
	}
	if r.Protocol != "any" && r.Protocol != "tcp" || !PortCovers(r.Port, port) {
		return false
	}
	if ip == "" {
		return wildcard(r.From)
	}
	return AddressCovers(r.From, ip)
}

// Stops says whether an input rule can cut a TCP connection to port from any
// of the addresses (empty addresses are skipped).
func (in Input) Stops(port int, addresses ...string) bool {
	if in.Action != "block" && in.Action != "reject" && in.Action != "limit" {
		return false
	}
	if in.Direction == "routed" {
		return false
	}
	if in.Direction == "out" {
		return in.Action != "limit" && in.Port == ""
	}
	if in.Protocol != "any" && in.Protocol != "tcp" || !PortCovers(in.Port, port) {
		return false
	}
	if in.Service != "" {
		return strings.EqualFold(in.Service, "ssh") || strings.EqualFold(in.Service, "openssh")
	}
	if in.From == "" {
		return true
	}
	for _, a := range addresses {
		if a != "" && AddressCovers(in.From, a) {
			return true
		}
	}
	return false
}

func identify(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:8])
}

func (r *FilterRule) setID() {
	r.ID = identify(r.kind, r.Zone, r.Action, r.Direction, r.Protocol, r.Port, r.SourcePort, r.From, r.To,
		r.Interface, r.OutInterface, r.Service, r.sourceApp, fmt.Sprint(r.Log, r.logAll), r.Family, r.rawCommand)
}

// Find returns the rule with the id.
func Find(rules []FilterRule, id string) (FilterRule, bool) {
	for _, r := range rules {
		if r.ID == id {
			return r, true
		}
	}
	return FilterRule{}, false
}

// Present says whether the rules already do what this normalized input asks,
// so adding it again would change nothing. A note or logging doesn't count.
func (in Input) Present(rules []FilterRule) bool {
	has := func(port, proto string) bool {
		for _, r := range rules {
			if r.Action != in.Action || r.Direction != in.Direction || r.Service != in.Service || r.From != in.From || r.To != in.To ||
				r.Interface != in.Interface || r.OutInterface != in.OutInterface || r.Zone != in.Zone {
				continue
			}
			if in.Service != "" || r.Port == port && r.Protocol == proto {
				return true
			}
		}
		return false
	}
	covered := func(port string) bool {
		if in.Protocol == "any" && port != "" && has(port, "tcp") && has(port, "udp") {
			return true
		}
		return has(port, in.Protocol)
	}
	if covered(in.Port) {
		return true
	}
	parts := strings.Split(in.Port, ",")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if !covered(p) {
			return false
		}
	}
	return true
}
