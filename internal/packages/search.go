package packages

import (
	"cmp"
	"regexp"
	"slices"
	"strings"
)

// ParseSearch reads what SearchScript printed: the best limit matches for
// query, exact names first.
func ParseSearch(out, query string, limit int) []PackageMatch {
	s := sections(out)
	var all []PackageMatch
	for _, l := range s["apt"] {
		n, sum, ok := strings.Cut(l, " - ")
		if ok {
			all = append(all, PackageMatch{Name: strings.TrimSpace(n), Summary: strings.TrimSpace(sum)})
		}
	}
	for _, l := range s["rq"] {
		f := splitTabs(l)
		if len(f) >= 3 {
			m := PackageMatch{Name: f[0], Version: f[1], Repo: f[2]}
			if len(f) >= 4 {
				m.Summary = f[3]
			}
			all = append(all, m)
		}
	}
	for _, l := range s["yum"] {
		f := strings.Fields(l)
		if len(f) == 3 && archRe.MatchString(f[0]) {
			all = append(all, PackageMatch{Name: archRe.ReplaceAllString(f[0], ""), Version: f[1], Repo: f[2]})
		}
	}
	for _, l := range s["zypper"] {
		p := strings.Split(l, "|")
		if len(p) < 4 || strings.TrimSpace(p[3]) != "package" {
			continue
		}
		m := PackageMatch{Name: strings.TrimSpace(p[1]), Summary: strings.TrimSpace(p[2])}
		if strings.HasPrefix(strings.TrimSpace(p[0]), "i") {
			m.Installed = "?"
		}
		all = append(all, m)
	}
	for _, l := range s["apk"] {
		nv, sum, ok := strings.Cut(l, " - ")
		if !ok {
			continue
		}
		n, v := splitAPKName(strings.TrimSpace(nv))
		all = append(all, PackageMatch{Name: n, Version: v, Summary: strings.TrimSpace(sum)})
	}
	pac := s["pacman"]
	for i := 0; i < len(pac); i++ {
		l := pac[i]
		if l == "" || l[0] == ' ' {
			continue
		}
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		repo, name, _ := strings.Cut(f[0], "/")
		m := PackageMatch{Name: name, Version: f[1], Repo: repo}
		if mm := pacInstalledRe.FindStringSubmatch(l); mm != nil {
			m.Installed = f[1]
			if mm[1] != "" {
				m.Installed = mm[1]
			}
		}
		if i+1 < len(pac) && strings.HasPrefix(pac[i+1], " ") {
			m.Summary = strings.TrimSpace(pac[i+1])
			i++
		}
		all = append(all, m)
	}
	return rank(all, query, limit)
}

var pacInstalledRe = regexp.MustCompile(`\[installed(?:: ([^\]]+))?\]`)

func splitTabs(l string) []string {
	if strings.Contains(l, "\t") {
		return strings.Split(l, "\t")
	}
	return strings.Split(l, `\t`)
}

// rank keeps one row per name and sorts exact > prefix > in the name >
// in the summary, shorter names first.
func rank(all []PackageMatch, query string, limit int) []PackageMatch {
	q := strings.ToLower(strings.TrimSpace(query))
	seen := map[string]bool{}
	out := []PackageMatch{}
	for _, m := range all {
		if m.Name == "" || seen[m.Name] {
			continue
		}
		seen[m.Name] = true
		out = append(out, m)
	}
	score := func(m PackageMatch) int {
		n := strings.ToLower(m.Name)
		switch {
		case n == q:
			return 0
		case strings.HasPrefix(n, q):
			return 1
		case strings.Contains(n, q):
			return 2
		}
		return 3
	}
	slices.SortStableFunc(out, func(a, b PackageMatch) int {
		return cmp.Or(cmp.Compare(score(a), score(b)), cmp.Compare(len(a.Name), len(b.Name)), strings.Compare(a.Name, b.Name))
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// NeedsCandidates says whether search results lack versions that
// CandidatesScript can fill in.
func NeedsCandidates(pm string) bool { return pm != Pacman && pm != None && pm != "" }

// ApplyCandidates fills the installed and offered versions from what
// CandidatesScript printed.
func ApplyCandidates(matches []PackageMatch, out string) {
	s := sections(out)
	type cand struct{ installed, candidate, repo string }
	byName := map[string]*cand{}
	var cur *cand
	inTable, wantRepo := false, false
	for _, l := range s["policy"] {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		if l[0] != ' ' && strings.HasSuffix(t, ":") {
			cur = &cand{}
			byName[strings.TrimSuffix(t, ":")] = cur
			inTable, wantRepo = false, false
			continue
		}
		if cur == nil {
			continue
		}
		switch {
		case strings.HasPrefix(t, "Installed:"):
			cur.installed = noneEmpty(strings.TrimSpace(strings.TrimPrefix(t, "Installed:")))
		case strings.HasPrefix(t, "Candidate:"):
			cur.candidate = noneEmpty(strings.TrimSpace(strings.TrimPrefix(t, "Candidate:")))
		case t == "Version table:":
			inTable = true
		case inTable:
			f := strings.Fields(strings.TrimPrefix(t, "*** "))
			if wantRepo && len(f) >= 3 && f[1] != "/var/lib/dpkg/status" {
				cur.repo = f[2]
				wantRepo = false
			} else if len(f) >= 1 && f[0] == cur.candidate && cur.repo == "" {
				wantRepo = true
			}
		}
	}
	for _, l := range s["rpm"] {
		f := strings.Split(l, "\t")
		if len(f) == 2 {
			c := byName[f[0]]
			if c == nil {
				c = &cand{}
				byName[f[0]] = c
			}
			c.installed = f[1]
		}
	}
	for _, l := range s["apk"] {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		n, v := splitAPKName(f[0])
		byName[n] = &cand{installed: v}
	}
	for i := range matches {
		m := &matches[i]
		c := byName[m.Name]
		if m.Installed == "?" {
			m.Installed = ""
		}
		if c == nil {
			continue
		}
		m.Installed = c.installed
		if c.candidate != "" {
			m.Version = c.candidate
		}
		if c.repo != "" && m.Repo == "" {
			m.Repo = c.repo
		}
	}
}

func noneEmpty(s string) string {
	if s == "(none)" {
		return ""
	}
	return s
}
