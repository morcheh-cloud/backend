package sysconf

import (
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"
)

// Repo is one package source: an apt line, a deb822 stanza or a yum/dnf
// .repo section.
type Repo struct {
	ID         string            `json:"id" doc:"file#n: the line (one-line apt), the stanza (deb822) or the section (.repo) it is in"`
	File       string            `json:"file"`
	Format     string            `json:"format" enum:"line,deb822,repo"`
	Enabled    bool              `json:"enabled"`
	Name       string            `json:"name" doc:"The repo id of a .repo section; empty for apt"`
	Types      []string          `json:"types" doc:"deb and/or deb-src (apt)"`
	URIs       []string          `json:"uris" doc:"apt URIs; for .repo the baseurl, mirrorlist or metalink"`
	Suites     []string          `json:"suites"`
	Components []string          `json:"components"`
	Options    map[string]string `json:"options" doc:"Everything else: signed-by, arch, gpgcheck, name…"`
	Main       bool              `json:"main" doc:"The distribution's own repositories (the ones a mirror replaces)"`
	Morche     bool              `json:"morche" doc:"Added by Morche"`
}

func morcheFile(file string) bool { return strings.HasPrefix(path.Base(file), "morche-") }

func lastElem(uri string) string { return path.Base(strings.TrimRight(uri, "/")) }

func mainURI(uri string) bool {
	return slices.Contains([]string{"ubuntu", "ubuntu-ports", "debian", "debian-security"}, lastElem(uri))
}

func repoID(file string, n int) string { return file + "#" + strconv.Itoa(n) }

type aptLine struct {
	enabled bool
	typ     string
	opts    map[string]string
	uri     string
	suite   string
	comps   []string
}

func parseAptLine(l string) (aptLine, bool) {
	s := strings.TrimSpace(l)
	a := aptLine{enabled: true}
	if strings.HasPrefix(s, "#") {
		a.enabled = false
		s = strings.TrimSpace(strings.TrimLeft(s, "#"))
	}
	s, _, _ = strings.Cut(s, " #")
	f := strings.Fields(s)
	if len(f) < 3 || (f[0] != "deb" && f[0] != "deb-src") {
		return a, false
	}
	a.typ = f[0]
	f = f[1:]
	if strings.HasPrefix(f[0], "[") {
		a.opts = map[string]string{}
		for len(f) > 0 {
			tok := f[0]
			f = f[1:]
			end := strings.HasSuffix(tok, "]")
			tok = strings.Trim(tok, "[]")
			if k, v, ok := strings.Cut(tok, "="); ok {
				a.opts[k] = v
			}
			if end {
				break
			}
		}
	}
	if len(f) < 2 {
		return a, false
	}
	a.uri, a.suite, a.comps = f[0], f[1], f[2:]
	return a, true
}

// ParseAptLine reads a one-line-style sources.list.
func ParseAptLine(file, text string) []Repo {
	var out []Repo
	for i, l := range lines(text) {
		a, ok := parseAptLine(l)
		if !ok {
			continue
		}
		out = append(out, Repo{
			ID: repoID(file, i+1), File: file, Format: "line", Enabled: a.enabled,
			Types: []string{a.typ}, URIs: []string{a.uri}, Suites: []string{a.suite}, Components: a.comps,
			Options: a.opts, Main: mainURI(a.uri) && slices.Contains(a.comps, "main"), Morche: morcheFile(file),
		})
	}
	return out
}

type stanza struct {
	start, end int // line range, end exclusive
	keys       map[string]string
	keyLine    map[string]int
}

func deb822Stanzas(ls []string) []stanza {
	var out []stanza
	var cur *stanza
	last := ""
	flush := func(end int) {
		if cur != nil && len(cur.keys) > 0 {
			cur.end = end
			out = append(out, *cur)
		}
		cur = nil
	}
	for i, l := range ls {
		t := strings.TrimSpace(l)
		if t == "" {
			flush(i)
			continue
		}
		if cur == nil {
			cur = &stanza{start: i, keys: map[string]string{}, keyLine: map[string]int{}}
		}
		if strings.HasPrefix(t, "#") {
			continue
		}
		if l[0] == ' ' || l[0] == '\t' {
			if last != "" {
				cur.keys[last] += " " + t
			}
			continue
		}
		if k, v, ok := strings.Cut(l, ":"); ok {
			last = strings.TrimSpace(k)
			if _, seen := cur.keys[last]; !seen {
				cur.keys[last] = strings.TrimSpace(v)
				cur.keyLine[last] = i
			}
		}
	}
	flush(len(ls))
	return out
}

func keyGet(keys map[string]string, k string) (string, bool) {
	for kk, v := range keys {
		if strings.EqualFold(kk, k) {
			return v, true
		}
	}
	return "", false
}

// ParseDeb822 reads a .sources file.
func ParseDeb822(file, text string) []Repo {
	var out []Repo
	for n, s := range deb822Stanzas(lines(text)) {
		get := func(k string) []string { v, _ := keyGet(s.keys, k); return strings.Fields(v) }
		en, _ := keyGet(s.keys, "Enabled")
		r := Repo{
			ID: repoID(file, n+1), File: file, Format: "deb822", Enabled: !strings.EqualFold(en, "no"),
			Types: get("Types"), URIs: get("URIs"), Suites: get("Suites"), Components: get("Components"),
			Options: map[string]string{}, Morche: morcheFile(file),
		}
		for k, v := range s.keys {
			if !slices.Contains([]string{"types", "uris", "suites", "components", "enabled"}, strings.ToLower(k)) {
				r.Options[k] = v
			}
		}
		r.Main = slices.Contains(r.Components, "main") && slices.ContainsFunc(r.URIs, mainURI)
		out = append(out, r)
	}
	return out
}

type section struct {
	name       string
	start, end int
}

func yumSections(ls []string) []section {
	var out []section
	for i, l := range ls {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			if len(out) > 0 {
				out[len(out)-1].end = i
			}
			out = append(out, section{name: strings.Trim(t, "[]"), start: i, end: len(ls)})
		}
	}
	return out
}

var yumMains = []string{"rocky", "almalinux", "centos", "fedora", "oracle", "redhat", "rhel"}

// ParseYumRepo reads a yum/dnf .repo file.
func ParseYumRepo(file, text string) []Repo {
	ls := lines(text)
	var out []Repo
	base := path.Base(file)
	for n, s := range yumSections(ls) {
		r := Repo{ID: repoID(file, n+1), File: file, Format: "repo", Enabled: true, Name: s.name, Options: map[string]string{}, Morche: morcheFile(file)}
		for _, l := range ls[s.start+1 : s.end] {
			t := strings.TrimSpace(l)
			if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
				continue
			}
			k, v, ok := strings.Cut(t, "=")
			if !ok {
				continue
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			switch k {
			case "enabled":
				r.Enabled = v != "0" && !strings.EqualFold(v, "false") && !strings.EqualFold(v, "no")
			case "baseurl", "mirrorlist", "metalink":
				r.URIs = append(r.URIs, strings.Fields(strings.ReplaceAll(v, ",", " "))...)
			default:
				r.Options[k] = v
			}
		}
		r.Main = !r.Morche && slices.ContainsFunc(yumMains, func(p string) bool { return strings.HasPrefix(base, p) })
		out = append(out, r)
	}
	return out
}

// SetRepoEnabled turns the n-th repo of a file (as numbered in its ID) on or
// off.
func SetRepoEnabled(format, text string, n int, on bool) string {
	ls := lines(text)
	switch format {
	case "line":
		if n < 1 || n > len(ls) {
			return text
		}
		if _, ok := parseAptLine(ls[n-1]); !ok {
			return text
		}
		body := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(ls[n-1]), "#"))
		if on {
			ls[n-1] = body
		} else {
			ls[n-1] = "# " + body
		}
	case "deb822":
		st := deb822Stanzas(ls)
		if n < 1 || n > len(st) {
			return text
		}
		s := st[n-1]
		if i, ok := s.keyLine["Enabled"]; ok {
			ls = slices.Delete(ls, i, i+1)
		}
		if !on {
			at := s.start
			if i, ok := s.keyLine["Types"]; ok {
				at = i + 1
			}
			ls = slices.Insert(ls, at, "Enabled: no")
		}
	case "repo":
		ss := yumSections(ls)
		if n < 1 || n > len(ss) {
			return text
		}
		s := ss[n-1]
		v := "enabled=1"
		if !on {
			v = "enabled=0"
		}
		for i := s.start + 1; i < s.end; i++ {
			if k, _, ok := strings.Cut(strings.TrimSpace(ls[i]), "="); ok && strings.TrimSpace(k) == "enabled" {
				ls[i] = v
				return join(ls)
			}
		}
		ls = slices.Insert(ls, s.start+1, v)
	}
	return join(ls)
}

func mirrorFor(uri, to string) string {
	if lastElem(uri) == "debian-security" {
		return path.Dir(to) + "/debian-security"
	}
	return to
}

// SetMirror points the distribution's own apt repositories at the mirror
// base to (…/ubuntu or …/debian; debian-security goes next to it).
func SetMirror(format, text, to string) string {
	to = strings.TrimRight(to, "/")
	ls := lines(text)
	switch format {
	case "line":
		for i, l := range ls {
			a, ok := parseAptLine(l)
			if ok && mainURI(a.uri) && slices.Contains(a.comps, "main") {
				ls[i] = strings.Replace(l, a.uri, fixScheme(mirrorFor(a.uri, to)), 1)
			}
		}
	case "deb822":
		for _, s := range deb822Stanzas(ls) {
			v, _ := keyGet(s.keys, "URIs")
			comps, _ := keyGet(s.keys, "Components")
			i, ok := s.keyLine["URIs"]
			if !ok || !slices.Contains(strings.Fields(comps), "main") {
				continue
			}
			var uris []string
			changed := false
			for _, u := range strings.Fields(v) {
				if mainURI(u) {
					u = fixScheme(mirrorFor(u, to))
					changed = true
				}
				uris = append(uris, u)
			}
			if changed {
				ls[i] = "URIs: " + strings.Join(uris, " ")
			}
		}
	}
	return join(ls)
}

// fixScheme puts back the "//" path.Dir folds in "https://host".
func fixScheme(u string) string {
	for _, s := range []string{"https:/", "http:/"} {
		if strings.HasPrefix(u, s) && !strings.HasPrefix(u, s+"/") {
			return s + "/" + u[len(s):]
		}
	}
	return u
}

// CurrentMirror is the base of the first enabled main repository.
func CurrentMirror(rs []Repo) string {
	for _, r := range rs {
		if !r.Main || !r.Enabled || r.Format == "repo" {
			continue
		}
		for _, u := range r.URIs {
			if lastElem(u) != "debian-security" && mainURI(u) && !strings.Contains(u, "security.ubuntu.com") {
				return strings.TrimRight(u, "/")
			}
		}
	}
	return ""
}

// PrintDeb822 is a new .sources file holding r.
func PrintDeb822(r Repo) string {
	types := r.Types
	if len(types) == 0 {
		types = []string{"deb"}
	}
	s := "# Added by Morche\nTypes: " + strings.Join(types, " ") + "\nURIs: " + strings.Join(r.URIs, " ") + "\nSuites: " + strings.Join(r.Suites, " ") + "\n"
	if len(r.Components) > 0 {
		s += "Components: " + strings.Join(r.Components, " ") + "\n"
	}
	for _, k := range slices.Sorted(maps.Keys(r.Options)) {
		s += k + ": " + r.Options[k] + "\n"
	}
	return s
}

// PrintYumRepo is a new .repo file holding r (Name = the repo id).
func PrintYumRepo(r Repo) string {
	s := "# Added by Morche\n[" + r.Name + "]\n"
	if n := r.Options["name"]; n != "" {
		s += "name=" + n + "\n"
	}
	s += "baseurl=" + strings.Join(r.URIs, " ") + "\nenabled=1\n"
	for _, k := range slices.Sorted(maps.Keys(r.Options)) {
		if k != "name" && k != "enabled" && k != "baseurl" {
			s += k + "=" + r.Options[k] + "\n"
		}
	}
	return s
}
