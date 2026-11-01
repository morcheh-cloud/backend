// Package fail2ban reads and edits fail2ban's configuration and parses what
// fail2ban-client prints. It runs nothing itself: the API runs the commands
// over SSH and hands the text here.
package fail2ban

import (
	"slices"
	"strings"
)

// Doc is one .conf/.local file kept line by line, so an edit changes only
// the lines it is about and leaves comments and layout alone.
type Doc struct {
	lines []string
}

type keyInfo struct {
	name       string
	start, end int // lines [start, end): the key line and its continuations
	value      string
}

type sectionInfo struct {
	name       string
	header     int // line of [name]
	end        int // next header, or len(lines)
	keys       []keyInfo
	lastKeyEnd int // where a new key goes
}

// Parse reads a file the way fail2ban's config parser does: `key = value`
// or `key: value`, keys case-insensitive, indented lines continue the value,
// # and ; start full-line comments and " ;" an inline one.
func Parse(text string) *Doc {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return &Doc{}
	}
	return &Doc{lines: strings.Split(text, "\n")}
}

// String is the file as text, ending in a newline.
func (d *Doc) String() string {
	if len(d.lines) == 0 {
		return ""
	}
	return strings.Join(d.lines, "\n") + "\n"
}

func (d *Doc) scan() []sectionInfo {
	var secs []sectionInfo
	var cur *sectionInfo
	var key *keyInfo
	keyIndent := 0
	closeKey := func() {
		if key != nil && cur != nil {
			cur.keys = append(cur.keys, *key)
			cur.lastKeyEnd = key.end
		}
		key = nil
	}
	for i, raw := range d.lines {
		trimmed := strings.TrimSpace(raw)
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		switch {
		case trimmed == "":
			closeKey()
		case trimmed[0] == '#' || trimmed[0] == ';':
			// Skipped; a value may continue below it.
		case key != nil && indent > keyIndent:
			if v := stripInline(trimmed); v != "" {
				if key.value != "" {
					key.value += "\n"
				}
				key.value += v
			}
			key.end = i + 1
		case strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"):
			closeKey()
			if cur != nil {
				cur.end = i
				secs = append(secs, *cur)
			}
			cur = &sectionInfo{name: strings.TrimSpace(trimmed[1 : len(trimmed)-1]), header: i, lastKeyEnd: i + 1}
		default:
			closeKey()
			name, value, ok := splitKey(trimmed)
			if !ok || cur == nil {
				continue
			}
			key = &keyInfo{name: name, start: i, end: i + 1, value: stripInline(value)}
			keyIndent = indent
		}
	}
	closeKey()
	if cur != nil {
		cur.end = len(d.lines)
		secs = append(secs, *cur)
	}
	return secs
}

func splitKey(line string) (key, value string, ok bool) {
	i := strings.IndexAny(line, "=:")
	if i <= 0 {
		return "", "", false
	}
	return strings.ToLower(strings.TrimSpace(line[:i])), strings.TrimSpace(line[i+1:]), true
}

func stripInline(v string) string {
	for i := 1; i < len(v); i++ {
		if v[i] == ';' && (v[i-1] == ' ' || v[i-1] == '\t') {
			return strings.TrimSpace(v[:i])
		}
	}
	return v
}

func (d *Doc) section(name string) *sectionInfo {
	secs := d.scan()
	for i := len(secs) - 1; i >= 0; i-- {
		if secs[i].name == name {
			return &secs[i]
		}
	}
	return nil
}

// Sections lists section names in file order, each once.
func (d *Doc) Sections() []string {
	var names []string
	for _, s := range d.scan() {
		if !slices.Contains(names, s.name) {
			names = append(names, s.name)
		}
	}
	return names
}

// Values is every key a section sets, later lines winning.
func (d *Doc) Values(section string) map[string]string {
	out := map[string]string{}
	for _, s := range d.scan() {
		if s.name == section {
			for _, k := range s.keys {
				out[k.name] = k.value
			}
		}
	}
	return out
}

// HasSection reports whether the file has a [name] header.
func (d *Doc) HasSection(name string) bool { return d.section(name) != nil }

// Set writes key = value into section, replacing the key where it is or
// adding it after the section's last key (and the section at the end of the
// file when it's missing; [DEFAULT] goes before the first section). A value with newlines becomes continuation lines.
func (d *Doc) Set(section, key, value string) {
	key = strings.ToLower(key)
	lines := formatKey(key, value)
	s := d.section(section)
	if s == nil {
		// [DEFAULT] reads best first, above the jails.
		if secs := d.scan(); section == "DEFAULT" && len(secs) > 0 {
			at := secs[0].header
			d.lines = slices.Insert(d.lines, at, append(append([]string{"[DEFAULT]"}, lines...), "")...)
			return
		}
		if n := len(d.lines); n > 0 && strings.TrimSpace(d.lines[n-1]) != "" {
			d.lines = append(d.lines, "")
		}
		d.lines = append(d.lines, "["+section+"]")
		d.lines = append(d.lines, lines...)
		return
	}
	for i := len(s.keys) - 1; i >= 0; i-- {
		if k := s.keys[i]; k.name == key {
			d.lines = slices.Replace(d.lines, k.start, k.end, lines...)
			return
		}
	}
	d.lines = slices.Insert(d.lines, s.lastKeyEnd, lines...)
}

// Unset removes key from section; the section stays, even when empty.
func (d *Doc) Unset(section, key string) {
	key = strings.ToLower(key)
	for {
		s := d.section(section)
		if s == nil {
			return
		}
		i := slices.IndexFunc(s.keys, func(k keyInfo) bool { return k.name == key })
		if i < 0 {
			return
		}
		d.lines = slices.Delete(d.lines, s.keys[i].start, s.keys[i].end)
	}
}

// RemoveSection deletes every [name] section with its keys and comments.
func (d *Doc) RemoveSection(name string) {
	for {
		s := d.section(name)
		if s == nil {
			break
		}
		d.lines = slices.Delete(d.lines, s.header, s.end)
	}
	// Collapse the blank lines the removal leaves behind.
	out := d.lines[:0]
	for i, l := range d.lines {
		if strings.TrimSpace(l) == "" && (len(out) == 0 || strings.TrimSpace(out[len(out)-1]) == "") {
			continue
		}
		out = append(out, d.lines[i])
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	d.lines = out
}

func formatKey(key, value string) []string {
	parts := strings.Split(strings.TrimSpace(value), "\n")
	if parts[0] == "" && len(parts) == 1 {
		return []string{key + " ="}
	}
	lines := []string{key + " = " + strings.TrimSpace(parts[0])}
	pad := strings.Repeat(" ", len(key)+3)
	for _, p := range parts[1:] {
		if p = strings.TrimSpace(p); p != "" {
			lines = append(lines, pad+p)
		}
	}
	return lines
}

// ---- Several files together ----

// Layer is one file of the configuration, in the order fail2ban reads them.
type Layer struct {
	Path string
	Doc  *Doc
}

// Setting is a key's effective value and the file it comes from.
type Setting struct {
	Value string
	Path  string
}

// Merged is the whole configuration: every section's effective keys.
type Merged struct {
	Order    []string // section names, by first appearance
	Sections map[string]map[string]Setting
}

// Merge layers files the way fail2ban does: a later file's key replaces an
// earlier one's.
func Merge(layers []Layer) Merged {
	m := Merged{Sections: map[string]map[string]Setting{}}
	for _, l := range layers {
		for _, s := range l.Doc.scan() {
			sec, ok := m.Sections[s.name]
			if !ok {
				sec = map[string]Setting{}
				m.Sections[s.name] = sec
				m.Order = append(m.Order, s.name)
			}
			for _, k := range s.keys {
				sec[k.name] = Setting{Value: k.value, Path: l.Path}
			}
		}
	}
	return m
}

// DefinedIn is where a section first appears.
func DefinedIn(layers []Layer, section string) string {
	for _, l := range layers {
		if l.Doc.HasSection(section) {
			return l.Path
		}
	}
	return ""
}

// Bool reads a config boolean the way Python's configparser does.
func Bool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "yes", "true", "on":
		return true
	}
	return false
}
