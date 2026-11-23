// Package sysconf reads and writes the Linux configuration files Morche
// edits for people: /etc/hosts, the DNS resolver, time sync, netplan,
// NetworkManager and package repositories. The text stays the truth: what a
// parser doesn't understand prints back exactly as it was.
package sysconf

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// HostEntry is one address line of /etc/hosts.
type HostEntry struct {
	Line    int      `json:"line" doc:"Its line in the file (1-based); 0 = a new entry"`
	Address string   `json:"address" example:"10.0.0.5"`
	Names   []string `json:"names" example:"[\"db.internal\",\"db\"]"`
	Comment string   `json:"comment" doc:"The text after # on the same line"`
	Enabled bool     `json:"enabled" doc:"false = the line is commented out"`
	System  bool     `json:"system" doc:"A line the system needs (localhost, the IPv6 boilerplate, this machine's own name)"`
}

// ParseHosts reads every address line, commented-out ones included.
func ParseHosts(text string) []HostEntry {
	var out []HostEntry
	for i, line := range lines(text) {
		if e, ok := parseHostLine(line); ok {
			e.Line = i + 1
			out = append(out, e)
		}
	}
	return out
}

func parseHostLine(line string) (HostEntry, bool) {
	s := strings.TrimSpace(line)
	enabled := true
	if strings.HasPrefix(s, "#") {
		enabled = false
		s = strings.TrimSpace(strings.TrimLeft(s, "#"))
	}
	body, comment, _ := strings.Cut(s, "#")
	f := strings.Fields(body)
	if len(f) < 2 {
		return HostEntry{}, false
	}
	if _, err := netip.ParseAddr(f[0]); err != nil {
		return HostEntry{}, false
	}
	if !enabled && !slices.ContainsFunc(f[1:], ValidHostname) {
		return HostEntry{}, false
	}
	e := HostEntry{Address: f[0], Names: f[1:], Comment: strings.TrimSpace(comment), Enabled: enabled}
	e.System = systemHost(e)
	return e, true
}

func systemHost(e HostEntry) bool {
	a, err := netip.ParseAddr(e.Address)
	if err != nil {
		return false
	}
	if a.IsLoopback() || a.IsMulticast() || strings.HasPrefix(strings.ToLower(e.Address), "fe00:") {
		return true
	}
	return slices.ContainsFunc(e.Names, func(n string) bool {
		return n == "localhost" || strings.HasPrefix(n, "ip6-")
	})
}

func sameHost(a, b HostEntry) bool {
	return a.Address == b.Address && slices.Equal(a.Names, b.Names) && a.Comment == b.Comment && a.Enabled == b.Enabled
}

func printHostLine(e HostEntry) string {
	s := e.Address + "\t" + strings.Join(e.Names, " ")
	if e.Comment != "" {
		s += "\t# " + e.Comment
	}
	if !e.Enabled {
		s = "# " + s
	}
	return s
}

// PrintHosts writes entries over old: lines that didn't change stay as they
// were, removed entries go, changed ones are rewritten in place and new ones
// (Line 0, or a line that is no entry) come at the end. Plain comments and
// blank lines are kept.
func PrintHosts(old string, entries []HostEntry) string {
	byLine := map[int]HostEntry{}
	var added []HostEntry
	src := lines(old)
	for _, e := range entries {
		if e.Line > 0 && e.Line <= len(src) {
			if _, ok := parseHostLine(src[e.Line-1]); ok {
				if _, dup := byLine[e.Line]; !dup {
					byLine[e.Line] = e
					continue
				}
			}
		}
		added = append(added, e)
	}
	var b strings.Builder
	for i, line := range src {
		was, isEntry := parseHostLine(line)
		if !isEntry {
			b.WriteString(line + "\n")
			continue
		}
		e, kept := byLine[i+1]
		switch {
		case !kept:
		case sameHost(was, e):
			b.WriteString(line + "\n")
		default:
			b.WriteString(printHostLine(e) + "\n")
		}
	}
	for _, e := range added {
		b.WriteString(printHostLine(e) + "\n")
	}
	return b.String()
}

// HostsProblems lists what's wrong with entries, names on two addresses
// first. Commented-out entries are left alone.
func HostsProblems(entries []HostEntry) []string {
	var out []string
	type key struct {
		name string
		v6   bool
	}
	seen := map[key]string{}
	var order []key
	clash := map[key]bool{}
	for _, e := range entries {
		a, err := netip.ParseAddr(e.Address)
		if !e.Enabled || err != nil {
			continue
		}
		for _, n := range e.Names {
			k := key{strings.ToLower(n), a.Is6() && !a.Is4In6()}
			if prev, ok := seen[k]; !ok {
				seen[k] = e.Address
				order = append(order, k)
			} else if prev != e.Address {
				clash[k] = true
			}
		}
	}
	for _, k := range order {
		if clash[k] {
			out = append(out, fmt.Sprintf("%s points to more than one address, so only the first one is used", k.name))
		}
	}
	for _, e := range entries {
		if !e.Enabled {
			continue
		}
		if _, err := netip.ParseAddr(e.Address); err != nil {
			out = append(out, fmt.Sprintf("%s is not an IP address", e.Address))
			continue
		}
		if len(e.Names) == 0 {
			out = append(out, fmt.Sprintf("%s has no names", e.Address))
		}
		for _, n := range e.Names {
			if !ValidHostname(n) {
				out = append(out, fmt.Sprintf("%s is not a valid name", n))
			}
		}
	}
	return out
}

// SetHostname points 127.0.1.1 at the new name (Debian's way of letting the
// machine resolve its own name), adding the line after 127.0.0.1 when there
// is none.
func SetHostname(text, old, name string) string {
	src := lines(text)
	line := printHostLine(HostEntry{Address: "127.0.1.1", Names: []string{name}, Enabled: true})
	for i, l := range src {
		if e, ok := parseHostLine(l); ok && e.Enabled && e.Address == "127.0.1.1" {
			src[i] = line
			return join(src)
		}
	}
	at := 0
	for i, l := range src {
		if e, ok := parseHostLine(l); ok && e.Enabled && e.Address == "127.0.0.1" {
			at = i + 1
			break
		}
	}
	src = slices.Insert(src, at, line)
	return join(src)
}

// ValidHostname is RFC 1123: dot-separated labels of letters, digits and
// hyphens, 1–63 long, not starting or ending with a hyphen.
func ValidHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// lines splits text into lines without their newlines; a final newline adds
// no empty line.
func lines(text string) []string {
	if text == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

func join(ls []string) string {
	if len(ls) == 0 {
		return ""
	}
	return strings.Join(ls, "\n") + "\n"
}
