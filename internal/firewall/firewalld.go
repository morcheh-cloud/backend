package firewall

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Zone is one firewalld zone from `--list-all-zones`.
type Zone struct {
	Name       string   `json:"name" example:"public"`
	Default    bool     `json:"default"`
	Active     bool     `json:"active" doc:"It has interfaces or sources, so it's in use"`
	Target     string   `json:"target" doc:"What happens to traffic no rule matches" example:"default"`
	Interfaces []string `json:"interfaces"`
	Sources    []string `json:"sources"`
	Masquerade bool     `json:"masquerade"`

	services, ports, forwardPorts, sourcePorts, protocols, rich []string
}

// ParseZones reads `firewall-cmd --list-all-zones`. Rich rules and, on newer
// versions, forward ports come as tab-indented lines under their key.
func ParseZones(out string) []Zone {
	var zones []Zone
	var key string
	add := func(z *Zone, key, value string) {
		switch key {
		case "target":
			z.Target = value
		case "masquerade":
			z.Masquerade = value == "yes"
		case "interfaces":
			z.Interfaces = append(z.Interfaces, strings.Fields(value)...)
		case "sources":
			z.Sources = append(z.Sources, strings.Fields(value)...)
		case "services":
			z.services = append(z.services, strings.Fields(value)...)
		case "ports":
			z.ports = append(z.ports, strings.Fields(value)...)
		case "protocols":
			z.protocols = append(z.protocols, strings.Fields(value)...)
		case "source-ports":
			z.sourcePorts = append(z.sourcePorts, strings.Fields(value)...)
		case "forward-ports":
			if value != "" {
				z.forwardPorts = append(z.forwardPorts, value)
			}
		case "rich rules":
			if value != "" {
				z.rich = append(z.rich, value)
			}
		}
	}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			key = ""
		case line[0] != ' ' && line[0] != '\t':
			name, rest, _ := strings.Cut(trimmed, " ")
			key = ""
			zones = append(zones, Zone{Name: name, Default: strings.Contains(rest, "default")})
		case len(zones) == 0:
		case line[0] == '\t':
			add(&zones[len(zones)-1], key, trimmed)
		default:
			k, v, ok := strings.Cut(trimmed, ":")
			if !ok {
				continue
			}
			key = k
			add(&zones[len(zones)-1], key, strings.TrimSpace(v))
		}
	}
	for i := range zones {
		zones[i].Active = len(zones[i].Interfaces) > 0 || len(zones[i].Sources) > 0
	}
	return zones
}

// ParseActiveZones reads `firewall-cmd --get-active-zones`: zone names at the
// start of a line, their interfaces indented below.
func ParseActiveZones(out string) []string {
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if line != "" && line[0] != ' ' && line[0] != '\t' {
			name, _, _ := strings.Cut(strings.TrimSpace(line), " ")
			names = append(names, name)
		}
	}
	return names
}

// ServicePorts is what each firewalld service opens, as port/protocol.
type ServicePorts map[string][]string

var serviceLineRe = regexp.MustCompile(`([^/]+)\.xml:.*<port\b([^>]*)>`)
var xmlAttrRe = regexp.MustCompile(`(\w+)="([^"]*)"`)

// ParseServicePorts reads `grep -H '<port ' services/*.xml`.
func ParseServicePorts(out string) ServicePorts {
	s := ServicePorts{}
	for _, line := range strings.Split(out, "\n") {
		m := serviceLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		var port, proto string
		for _, a := range xmlAttrRe.FindAllStringSubmatch(m[2], -1) {
			switch a[1] {
			case "port":
				port = a[2]
			case "protocol":
				proto = a[2]
			}
		}
		if port != "" {
			s[m[1]] = append(s[m[1]], strings.ReplaceAll(port, "-", ":")+"/"+proto)
		}
	}
	return s
}

// FirewalldRules lists the rules of the zones in use and the default one.
// A zone that only applies to some sources shows them as the rule's From.
func FirewalldRules(zones []Zone, services ServicePorts) []FilterRule {
	var rules []FilterRule
	for _, z := range zones {
		if !z.Active && !z.Default {
			continue
		}
		base := FilterRule{
			Action: "allow", Direction: "in", Protocol: "any", Family: "both", Zone: z.Name,
			From: strings.Join(z.Sources, ", "), Deletable: true,
		}
		for _, name := range z.services {
			r := base
			r.kind, r.Service, r.Raw, r.rawCommand, r.Editable = "service", name, "service "+name, name, true
			r.Port, r.Protocol = serviceRule(services[name])
			rules = append(rules, r)
		}
		for _, p := range z.ports {
			port, proto, _ := strings.Cut(p, "/")
			r := base
			r.kind, r.Raw, r.rawCommand, r.Editable = "port", "port "+p, p, true
			r.Port, r.Protocol = strings.ReplaceAll(port, "-", ":"), proto
			rules = append(rules, r)
		}
		for _, rich := range z.rich {
			r := parseRich(rich)
			r.Zone = z.Name
			if r.From == "" {
				r.From = base.From
			}
			rules = append(rules, r)
		}
		for _, p := range z.sourcePorts {
			port, proto, _ := strings.Cut(p, "/")
			r := base
			r.kind, r.Raw, r.rawCommand = "source-port", "source-port "+p, p
			r.SourcePort, r.Protocol = strings.ReplaceAll(port, "-", ":"), proto
			rules = append(rules, r)
		}
		for _, p := range z.protocols {
			r := base
			r.kind, r.Raw, r.rawCommand, r.Protocol = "protocol", "protocol "+p, p, p
			rules = append(rules, r)
		}
	}
	for i := range rules {
		rules[i].setID()
	}
	return rules
}

// serviceRule sums up what a service opens: its ports, and their protocol
// when they share one.
func serviceRule(ports []string) (port, proto string) {
	var list []string
	proto = ""
	for _, p := range ports {
		n, pr, _ := strings.Cut(p, "/")
		if !slices.Contains(list, n) {
			list = append(list, n)
		}
		switch proto {
		case "":
			proto = pr
		case pr:
		default:
			proto = "any"
		}
	}
	if proto == "" {
		proto = "any"
	}
	return strings.Join(list, ","), proto
}

var (
	richFamilyRe = regexp.MustCompile(`\bfamily="?(ipv[46])"?`)
	richSourceRe = regexp.MustCompile(`\bsource address="?([^" ]+)"?`)
	richDestRe   = regexp.MustCompile(`\bdestination address="?([^" ]+)"?`)
	richPortRe   = regexp.MustCompile(`\bport port="?([^" ]+)"? protocol="?(\w+)"?`)
	richProtoRe  = regexp.MustCompile(`\bprotocol value="?(\w+)"?`)
	richSvcRe    = regexp.MustCompile(`\bservice name="?([^" ]+)"?`)
	richActionRe = regexp.MustCompile(`\s(accept|reject|drop)\b`)
	richLimitRe  = regexp.MustCompile(`\blimit value="`)
	richLogRe    = regexp.MustCompile(`\blog\b`)
	// Anything these match has no place in the form, so an edit would lose it.
	richComplexRe = regexp.MustCompile(`\b(not|audit|nflog|forward-port|masquerade|icmp-block|icmp-type|source-port|mac|ipset|mark|priority)\b`)
)

func parseRich(raw string) FilterRule {
	r := FilterRule{
		kind: "rich", Direction: "in", Protocol: "any", Family: "both", Raw: raw, rawCommand: raw,
		Action: "other", Deletable: true,
	}
	if m := richFamilyRe.FindStringSubmatch(raw); m != nil {
		r.Family = strings.Replace(m[1], "ipv", "v", 1)
	}
	if m := richSourceRe.FindStringSubmatch(raw); m != nil {
		r.From = m[1]
	}
	if m := richDestRe.FindStringSubmatch(raw); m != nil {
		r.To = m[1]
	}
	if m := richPortRe.FindStringSubmatch(raw); m != nil {
		r.Port, r.Protocol = strings.ReplaceAll(m[1], "-", ":"), m[2]
	}
	if m := richProtoRe.FindStringSubmatch(raw); m != nil {
		r.Protocol = m[1]
	}
	if m := richSvcRe.FindStringSubmatch(raw); m != nil {
		r.Service = m[1]
	}
	if m := richActionRe.FindStringSubmatch(raw); m != nil {
		switch m[1] {
		case "accept":
			r.Action = "allow"
		case "reject":
			r.Action = "reject"
		case "drop":
			r.Action = "block"
		}
	}
	limited := richLimitRe.MatchString(raw)
	if limited && r.Action == "allow" {
		r.Action = "limit"
	}
	r.Log = richLogRe.MatchString(raw)
	r.Editable = r.Action != "other" && !richComplexRe.MatchString(raw) && (!limited || r.Action == "limit")
	return r
}

func firewalldPorts(port string) []string {
	var out []string
	for _, p := range strings.Split(port, ",") {
		out = append(out, strings.ReplaceAll(p, ":", "-"))
	}
	return out
}

func protocols(p string) []string {
	if p == "any" || p == "" {
		return []string{"tcp", "udp"}
	}
	return []string{p}
}

// LimitRate is what a firewalld rate-limited rule allows, matching ufw's
// `limit` (6 new connections in 30 seconds).
const LimitRate = "12/m"

// FirewalldAdd builds what follows `--zone=Z` for a new rule, one entry per
// command. Plain allows use ports and services, which is how anyone reading
// the zone expects them; the rest are rich rules.
func FirewalldAdd(in Input) ([]string, error) {
	if in.Direction != "in" {
		return nil, &FieldError{"direction", "firewalld zones only filter incoming traffic"}
	}
	if in.Interface != "" {
		return nil, &FieldError{"interface", "With firewalld, interfaces belong to a zone: choose the zone instead"}
	}
	if in.Comment != "" {
		return nil, &FieldError{"comment", "firewalld rules can't have a note"}
	}
	if in.Action == "allow" && in.From == "" && in.To == "" && !in.Log {
		if in.Service != "" {
			return []string{"--add-service=" + quoteArg(in.Service)}, nil
		}
		if in.Port == "" {
			return nil, &FieldError{"port", "Choose a port. To allow everything, change the incoming default in Settings"}
		}
		var out []string
		for _, port := range firewalldPorts(in.Port) {
			for _, proto := range protocols(in.Protocol) {
				out = append(out, "--add-port="+port+"/"+proto)
			}
		}
		return out, nil
	}
	var head []string
	family := ""
	switch {
	case in.From != "":
		family = addressFamily(in.From)
	case in.To != "":
		family = addressFamily(in.To)
	}
	head = append(head, "rule")
	if family != "" {
		head = append(head, `family="`+family+`"`)
	}
	if in.From != "" {
		head = append(head, `source address="`+in.From+`"`)
	}
	if in.To != "" {
		head = append(head, `destination address="`+in.To+`"`)
	}
	tail := []string{}
	if in.Log {
		tail = append(tail, `log prefix="morcheh " level="info"`)
	}
	switch in.Action {
	case "allow":
		tail = append(tail, "accept")
	case "limit":
		tail = append(tail, `accept limit value="`+LimitRate+`"`)
	case "reject":
		tail = append(tail, "reject")
	default:
		tail = append(tail, "drop")
	}
	rich := func(middle string) string {
		parts := slices.Clone(head)
		if middle != "" {
			parts = append(parts, middle)
		}
		return "--add-rich-rule=" + quoteArg(strings.Join(append(parts, tail...), " "))
	}
	var out []string
	switch {
	case in.Service != "":
		out = append(out, rich(`service name="`+in.Service+`"`))
	case in.Port != "":
		for _, port := range firewalldPorts(in.Port) {
			for _, proto := range protocols(in.Protocol) {
				out = append(out, rich(fmt.Sprintf(`port port="%s" protocol="%s"`, port, proto)))
			}
		}
	case in.Protocol != "any":
		out = append(out, rich(`protocol value="`+in.Protocol+`"`))
	default:
		if in.From == "" && in.To == "" {
			return nil, &FieldError{"from", "Choose a port or an address: this would match all traffic"}
		}
		out = append(out, rich(""))
	}
	return out, nil
}

func addressFamily(s string) string {
	if isV6(s) {
		return "ipv6"
	}
	return "ipv4"
}

// FirewalldDelete builds what follows `--zone=Z` to remove a rule.
func FirewalldDelete(r FilterRule) string {
	return "--remove-" + map[string]string{
		"service": "service", "port": "port", "rich": "rich-rule", "source-port": "source-port", "protocol": "protocol",
	}[r.kind] + "=" + quoteArg(r.rawCommand)
}

// FirewalldTarget turns an incoming default into a zone target, and back.
func FirewalldTarget(policy string) string {
	switch policy {
	case "allow":
		return "ACCEPT"
	case "deny":
		return "DROP"
	}
	return "default"
}

// TargetPolicy is what a zone's target does to unmatched incoming traffic.
func TargetPolicy(target string) string {
	switch target {
	case "ACCEPT":
		return "allow"
	case "DROP":
		return "deny"
	}
	return "reject"
}
