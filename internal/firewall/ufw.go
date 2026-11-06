package firewall

import (
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/morcheh/backend/internal/terminal"
)

// ufw keeps its rules as `### tuple ###` comments in user.rules and
// user6.rules, in a stable format that can be read while it's inactive
// (`ufw status` then lists nothing):
//
//	### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment=535348
//	### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in
//	### tuple ### route:allow tcp 80 10.0.0.0/8 any 0.0.0.0/0 in_eth0!out_eth1
const tuplePrefix = "### tuple ###"

type tuple struct {
	raw                               string
	route                             bool
	action, proto, dport, dst         string
	sport, src, dapp, sapp, direction string
	comment                           string
	log, logAll                       bool
}

func parseTuple(line string) (tuple, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(line), tuplePrefix)
	if !ok {
		return tuple{}, false
	}
	f := strings.Fields(rest)
	t := tuple{raw: strings.TrimSpace(rest)}
	if n := len(f); n > 0 && strings.HasPrefix(f[n-1], "comment=") {
		if b, err := hex.DecodeString(strings.TrimPrefix(f[n-1], "comment=")); err == nil {
			t.comment = string(b)
		}
		f = f[:n-1]
		t.raw = strings.Join(f, " ") // the note is hex here: shown on its own
	}
	switch len(f) {
	case 7:
		t.direction = f[6]
	case 9:
		t.dapp, t.sapp, t.direction = app(f[6]), app(f[7]), f[8]
	default:
		return tuple{}, false
	}
	t.action, t.proto, t.dport, t.dst, t.sport, t.src = f[0], f[1], f[2], f[3], f[4], f[5]
	if a, ok := strings.CutPrefix(t.action, "route:"); ok {
		t.route, t.action = true, a
	}
	switch {
	case strings.HasSuffix(t.action, "_log-all"):
		t.action, t.log, t.logAll = strings.TrimSuffix(t.action, "_log-all"), true, true
	case strings.HasSuffix(t.action, "_log"):
		t.action, t.log = strings.TrimSuffix(t.action, "_log"), true
	}
	return t, true
}

func app(s string) string {
	if s == "-" {
		return ""
	}
	// Profile names with spaces are written with %20.
	return strings.ReplaceAll(s, "%20", " ")
}

func (t tuple) rule() FilterRule {
	r := FilterRule{
		Protocol: t.proto, Comment: t.comment, Raw: t.raw, Service: t.dapp, sourceApp: t.sapp,
		Log: t.log, logAll: t.logAll, Editable: true, Deletable: true, Family: "v4",
	}
	switch t.action {
	case "deny":
		r.Action = "block"
	default:
		r.Action = t.action
	}
	if t.dport != "any" {
		r.Port = t.dport
	}
	if t.sport != "any" {
		r.SourcePort = t.sport
	}
	if !wildcard(t.src) {
		r.From = t.src
	}
	if !wildcard(t.dst) {
		r.To = t.dst
	}
	r.Direction = "in"
	for _, part := range strings.Split(t.direction, "!") {
		dir, iface, _ := strings.Cut(part, "_")
		switch dir {
		case "out":
			if t.route {
				r.OutInterface = iface
			} else {
				r.Direction, r.Interface = "out", iface
			}
		default:
			r.Interface = iface
		}
	}
	if t.route {
		r.Direction = "routed"
	}
	if r.sourceApp != "" || r.SourcePort != "" || r.logAll {
		r.Editable = false // not offered by the form, so an edit would lose it
	}
	return r
}

// twinKey is equal for the IPv4 and IPv6 halves of a rule added for both.
func (r FilterRule) twinKey() string {
	return identify(r.Action, r.Direction, r.Protocol, r.Port, r.SourcePort, r.Interface, r.OutInterface,
		r.Service, r.sourceApp, strconv.FormatBool(r.logAll), strconv.FormatBool(r.Log))
}

// ParseUFW reads user.rules and user6.rules, in order, joining a rule added
// for both IP versions into one.
func ParseUFW(v4, v6 string) []FilterRule {
	var rules []FilterRule
	twins := map[string]int{}
	position := 0
	for _, line := range strings.Split(v4, "\n") {
		t, ok := parseTuple(line)
		if !ok {
			continue
		}
		position++
		r := t.rule()
		r.position = position
		if r.From == "" && r.To == "" {
			twins[r.twinKey()] = len(rules)
		}
		rules = append(rules, r)
	}
	for _, line := range strings.Split(v6, "\n") {
		t, ok := parseTuple(line)
		if !ok {
			continue
		}
		r := t.rule()
		r.Family = "v6"
		if r.From == "" && r.To == "" {
			if i, ok := twins[r.twinKey()]; ok {
				rules[i].Family = "both"
				delete(twins, r.twinKey())
				continue
			}
		}
		rules = append(rules, r)
	}
	for i := range rules {
		rules[i].setID()
	}
	return rules
}

// UFWDefaults reads the policies out of /etc/default/ufw.
func UFWDefaults(file string) (incoming, outgoing, routed string) {
	policy := func(v string) string {
		switch strings.Trim(v, `"' `) {
		case "ACCEPT":
			return "allow"
		case "REJECT":
			return "reject"
		case "DROP":
			return "deny"
		}
		return ""
	}
	for _, line := range strings.Split(file, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "DEFAULT_INPUT_POLICY":
			incoming = policy(v)
		case "DEFAULT_OUTPUT_POLICY":
			outgoing = policy(v)
		case "DEFAULT_FORWARD_POLICY":
			routed = policy(v)
		}
	}
	return incoming, outgoing, routed
}

// UFWConf reads ENABLED and LOGLEVEL out of /etc/ufw/ufw.conf.
func UFWConf(file string) (enabled bool, logging string) {
	logging = "off"
	for _, line := range strings.Split(file, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"' `)
		switch k {
		case "ENABLED":
			enabled = v == "yes"
		case "LOGLEVEL":
			logging = v
		}
	}
	return enabled, logging
}

func ufwAction(a string) string {
	if a == "block" {
		return "deny"
	}
	return a
}

// ufwCommand builds `ufw [route] [verb...] <action> ...` in the extended
// syntax, which says the same thing for adding and for deleting.
func ufwCommand(verb []string, route bool, action, direction, iface, outIface, logWord, proto, from, sourcePort, sourceApp, to, port, service, comment string) string {
	argv := []string{"ufw"}
	if route {
		argv = append(argv, "route")
	}
	argv = append(argv, verb...)
	argv = append(argv, ufwAction(action))
	if iface != "" {
		dir := direction
		if route {
			dir = "in"
		}
		argv = append(argv, dir, "on", iface)
	} else if direction == "out" {
		argv = append(argv, "out")
	}
	if outIface != "" {
		argv = append(argv, "out", "on", outIface)
	}
	if logWord != "" {
		argv = append(argv, logWord)
	}
	if proto != "" && proto != "any" && service == "" {
		argv = append(argv, "proto", proto)
	}
	argv = append(argv, "from", orAny(from))
	if sourcePort != "" {
		argv = append(argv, "port", sourcePort)
	}
	if sourceApp != "" {
		argv = append(argv, "app", sourceApp)
	}
	argv = append(argv, "to", orAny(to))
	switch {
	case service != "":
		argv = append(argv, "app", service)
	case port != "":
		argv = append(argv, "port", port)
	}
	if comment != "" {
		argv = append(argv, "comment", comment)
	}
	for i, a := range argv {
		argv[i] = quoteArg(a)
	}
	return strings.Join(argv, " ")
}

// quoteArg leaves plain words alone so a command stays readable in the logs.
func quoteArg(s string) string {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_./:,=@", c)) {
			return terminal.ShellQuote(s)
		}
	}
	if s == "" {
		return "''"
	}
	return s
}

func orAny(s string) string {
	if s == "" {
		return "any"
	}
	return s
}

// needsSplit says whether ufw refuses the port spec without a protocol.
func needsSplit(port string) bool { return strings.ContainsAny(port, ",:") }

// UFWAdd builds the commands that add a rule. position > 0 puts it at that
// place among the rules; blocking rules and Top go first, or they'd never
// win over an allow further up.
func UFWAdd(in Input, position int) []string {
	verb := func() []string {
		switch {
		case position > 0 && !isV6(in.From) && !isV6(in.To):
			return []string{"insert", strconv.Itoa(position)}
		case in.Top || in.Action == "block" || in.Action == "reject":
			return []string{"prepend"}
		}
		return nil
	}
	logWord := ""
	if in.Log {
		logWord = "log"
	}
	protos := []string{in.Protocol}
	if in.Protocol == "any" && needsSplit(in.Port) {
		protos = []string{"tcp", "udp"}
	}
	var out []string
	for _, p := range protos {
		out = append(out, ufwCommand(verb(), in.Direction == "routed", in.Action, in.Direction, in.Interface, in.OutInterface,
			logWord, p, in.From, "", "", in.To, in.Port, in.Service, in.Comment))
	}
	return out
}

// UFWDelete builds the command that removes a rule, spelled the way it was
// added, which works while ufw is inactive too (unlike numbers).
func UFWDelete(r FilterRule) string {
	logWord := ""
	switch {
	case r.logAll:
		logWord = "log-all"
	case r.Log:
		logWord = "log"
	}
	return ufwCommand([]string{"delete"}, r.Direction == "routed", r.Action, r.Direction, r.Interface, r.OutInterface,
		logWord, r.Protocol, r.From, r.SourcePort, r.sourceApp, r.To, r.Port, r.Service, "")
}

// UFWMove builds the commands that put a rule at a place among the IPv4
// rules, or after them when position is 0. A move is a delete and an exact
// re-add: everything the rule says survives, including what the form doesn't
// offer.
func UFWMove(r FilterRule, position int) []string {
	var verb []string
	if position > 0 {
		verb = []string{"insert", strconv.Itoa(position)}
	}
	logWord := ""
	switch {
	case r.logAll:
		logWord = "log-all"
	case r.Log:
		logWord = "log"
	}
	return []string{UFWDelete(r), ufwCommand(verb, r.Direction == "routed", r.Action, r.Direction, r.Interface, r.OutInterface,
		logWord, r.Protocol, r.From, r.SourcePort, r.sourceApp, r.To, r.Port, r.Service, r.Comment)}
}

// StopsSSH says whether the rule refuses a TCP connection to port from ip.
func (r FilterRule) StopsSSH(port int, ip string) bool {
	if r.Direction != "in" || r.Action != "block" && r.Action != "reject" {
		return false
	}
	if r.Protocol != "any" && r.Protocol != "tcp" || !PortCovers(r.Port, port) {
		return false
	}
	return AddressCovers(r.From, ip)
}
