package packages

import (
	"regexp"
	"slices"
	"strings"
)

// ParsePreview reads what PreviewScript printed for action.
func ParsePreview(action, out string) PackagePreview {
	s := sections(out)
	pm := keyValues(s["meta"])["pm"]
	lines := s["out"]
	p := PackagePreview{Changes: []PackageChange{}, Problems: []string{}, Deferred: []string{}, KeptBack: []string{}}
	switch pm {
	case APT:
		p.Changes = aptPreview(lines)
	case DNF, YUM:
		p.Changes = dnfPreview(lines)
	case Zypper:
		p.Changes = zypperPreview(lines)
	case APK:
		p.Changes = apkPreview(lines)
	case Pacman:
		p.Changes = pacmanPreview(action, lines, s["installed"])
	}
	if p.Changes == nil {
		p.Changes = []PackageChange{}
	}
	p.Problems = problems(lines)
	if pm == APT {
		p.Deferred = aptList(lines, "deferred due to phasing:")
		p.KeptBack = aptList(lines, "have been kept back:")
	}
	slices.SortStableFunc(p.Changes, func(a, b PackageChange) int { return actionOrder(a.Action) - actionOrder(b.Action) })
	return p
}

func actionOrder(a string) int {
	return slices.Index([]string{"remove", "purge", "downgrade", "install", "upgrade", "reinstall"}, a)
}

var problemRe = regexp.MustCompile(`^(E: |Error|ERROR|error:|Problem|No match for argument|Failed to resolve|No provider of|Package '[^']+' not found|nothing provides|.*not found in package names|.*is not installed|Unable to locate|World updated, but the following packages are not removed|WARNING: The following essential packages will be removed)`)

// aptList reads the indented names under the apt line ending in head.
func aptList(lines []string, head string) []string {
	out := []string{}
	in := false
	for _, l := range lines {
		if strings.HasSuffix(strings.TrimSpace(l), head) {
			in = true
			continue
		}
		if !in {
			continue
		}
		if !strings.HasPrefix(l, " ") {
			in = false
			continue
		}
		for _, n := range strings.Fields(l) {
			n, _, _ = strings.Cut(n, ":")
			out = append(out, n)
		}
	}
	return out
}

// problems keeps the lines saying why it can't be done, with the
// explanation lines indented under them.
func problems(lines []string) []string {
	out := []string{}
	in := false
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" {
			in = false
			continue
		}
		if problemRe.MatchString(t) {
			out = append(out, strings.TrimPrefix(t, "E: "))
			in = true
			continue
		}
		if in && (strings.HasPrefix(l, " ") || strings.HasPrefix(t, "- ")) && len(out) > 0 && len(out[len(out)-1]) < 2000 {
			out[len(out)-1] += "\n" + t
		}
	}
	return uniqKeep(out)
}

var aptPreviewRe = regexp.MustCompile(`^(Inst|Remv|Purg) (\S+)(?: \[([^\]]+)\])?(?: \((\S+))?`)

func aptPreview(lines []string) []PackageChange {
	var out []PackageChange
	for _, l := range lines {
		m := aptPreviewRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		name, _, _ := strings.Cut(m[2], ":")
		c := PackageChange{Name: name, From: m[3], To: m[4]}
		switch m[1] {
		case "Remv":
			c.Action = "remove"
			c.To = ""
		case "Purg":
			c.Action = "purge"
			c.To = ""
		default:
			switch {
			case c.From == "":
				c.Action = "install"
			case c.From == c.To:
				c.Action = "reinstall"
			case CompareVersions(c.To, c.From) < 0:
				c.Action = "downgrade"
			default:
				c.Action = "upgrade"
			}
		}
		out = append(out, c)
	}
	return out
}

// dnfPreview reads dnf's transaction table: section headers ("Installing
// dependencies:"), rows " name arch version repo size", and dnf 5's
// "   replacing name arch version" under an upgrade.
func dnfPreview(lines []string) []PackageChange {
	var out []PackageChange
	act := ""
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		if !strings.HasPrefix(l, " ") {
			h := strings.ToLower(strings.TrimSuffix(t, ":"))
			switch {
			case !strings.HasSuffix(t, ":"):
				act = ""
			case strings.HasPrefix(h, "installing"):
				act = "install"
			case strings.HasPrefix(h, "upgrading"), strings.HasPrefix(h, "updating"):
				act = "upgrade"
			case strings.HasPrefix(h, "downgrading"):
				act = "downgrade"
			case strings.HasPrefix(h, "removing"):
				act = "remove"
			case strings.HasPrefix(h, "reinstalling"):
				act = "reinstall"
			default:
				act = ""
			}
			continue
		}
		if act == "" {
			continue
		}
		f := strings.Fields(t)
		if f[0] == "replacing" && len(f) >= 4 && len(out) > 0 {
			if prev := &out[len(out)-1]; prev.Name == f[1] {
				prev.From = f[3]
			}
			continue
		}
		if len(f) < 4 || !archRe.MatchString("."+f[1]) {
			continue
		}
		c := PackageChange{Name: f[0], Action: act}
		if act == "remove" {
			c.From = f[2]
		} else {
			c.To = f[2]
		}
		out = append(out, c)
	}
	return out
}

var zypperHeadRe = regexp.MustCompile(`^The following (?:\d+ )?(?:NEW )?(?:package|packages|patch|patches) (?:is|are) going to be (\w+)`)

func zypperPreview(lines []string) []PackageChange {
	var out []PackageChange
	act := ""
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if m := zypperHeadRe.FindStringSubmatch(t); m != nil {
			isNew := strings.Contains(t, " NEW ")
			switch strings.ToLower(m[1]) {
			case "installed":
				act = "install"
				if !isNew {
					act = "reinstall"
				}
			case "upgraded":
				act = "upgrade"
			case "downgraded":
				act = "downgrade"
			case "removed":
				act = "remove"
			case "reinstalled":
				act = "reinstall"
			default:
				act = ""
			}
			if strings.Contains(t, " patch") {
				act = ""
			}
			continue
		}
		if t == "" {
			act = ""
			continue
		}
		if act == "" || !strings.HasPrefix(l, " ") {
			continue
		}
		for _, n := range strings.Fields(t) {
			out = append(out, PackageChange{Name: n, Action: act})
		}
	}
	return out
}

var apkPreviewRe = regexp.MustCompile(`^\(\d+/\d+\) (Installing|Upgrading|Downgrading|Purging|Deleting|Reinstalling|Replacing) (\S+) \(([^)]*)\)`)

func apkPreview(lines []string) []PackageChange {
	var out []PackageChange
	for _, l := range lines {
		m := apkPreviewRe.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		c := PackageChange{Name: m[2]}
		switch m[1] {
		case "Installing":
			c.Action, c.To = "install", m[3]
		case "Upgrading", "Downgrading", "Replacing":
			c.Action = "upgrade"
			if m[1] == "Downgrading" {
				c.Action = "downgrade"
			}
			c.From, c.To, _ = strings.Cut(m[3], " -> ")
		case "Purging", "Deleting":
			c.Action, c.From = "remove", m[3]
		case "Reinstalling":
			c.Action, c.To = "reinstall", m[3]
		}
		out = append(out, c)
	}
	return out
}

// pacmanPreview compares --print's "name version" lines with what's
// installed.
func pacmanPreview(action string, lines, installed []string) []PackageChange {
	have := map[string]string{}
	for _, l := range installed {
		if n, v, ok := strings.Cut(strings.TrimSpace(l), " "); ok {
			have[n] = v
		}
	}
	var out []PackageChange
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) != 2 || strings.HasSuffix(f[0], ":") || strings.Contains(f[0], "/") {
			continue
		}
		cur, ok := have[f[0]]
		c := PackageChange{Name: f[0]}
		switch {
		case action == ActRemove || action == ActPurge || action == ActAutoremove:
			c.Action, c.From = "remove", f[1]
		case !ok:
			c.Action, c.To = "install", f[1]
		case cur == f[1]:
			c.Action, c.To = "reinstall", f[1]
		case CompareVersions(f[1], cur) < 0:
			c.Action, c.From, c.To = "downgrade", cur, f[1]
		default:
			c.Action, c.From, c.To = "upgrade", cur, f[1]
		}
		out = append(out, c)
	}
	return out
}
