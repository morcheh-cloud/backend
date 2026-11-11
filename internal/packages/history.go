package packages

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// MaxHistory is how many past runs ParseHistory keeps.
const MaxHistory = 200

// ParseHistory reads what HistoryScript printed, newest first.
func ParseHistory(out string) []PackageHistoryEntry {
	s := sections(out)
	meta := keyValues(s["meta"])
	loc := zoneOf(meta["tz"])
	var h []PackageHistoryEntry
	switch meta["pm"] {
	case APT:
		h = aptHistory(s["apt"], loc)
	case DNF, YUM:
		h = dnfHistory(s["dnfhist"], loc)
		if len(h) == 0 {
			h = rpmHistory(s["rpmlast"])
		}
	case Zypper:
		h = zypperHistory(s["zypp"], loc)
	case Pacman:
		h = pacmanHistory(s["pacman"])
	}
	h = slices.DeleteFunc(h, func(e PackageHistoryEntry) bool { return len(e.Changes) == 0 && e.Error == "" })
	slices.SortStableFunc(h, func(a, b PackageHistoryEntry) int { return b.At.Compare(a.At) })
	if len(h) > MaxHistory {
		h = h[:MaxHistory]
	}
	if h == nil {
		h = []PackageHistoryEntry{}
	}
	for i := range h {
		if h[i].Changes == nil {
			h[i].Changes = []PackageChange{}
		}
	}
	return h
}

// zoneOf reads date's +0330.
func zoneOf(tz string) *time.Location {
	if len(tz) != 5 {
		return time.UTC
	}
	sign := 1
	if tz[0] == '-' {
		sign = -1
	}
	hh, err1 := strconv.Atoi(tz[1:3])
	mm, err2 := strconv.Atoi(tz[3:5])
	if err1 != nil || err2 != nil {
		return time.UTC
	}
	return time.FixedZone(tz, sign*(hh*3600+mm*60))
}

var aptPkgRe = regexp.MustCompile(`([^\s,()]+) \(([^)]*)\)`)

func aptHistory(lines []string, loc *time.Location) []PackageHistoryEntry {
	var out []PackageHistoryEntry
	var cur *PackageHistoryEntry
	acts := map[string]string{"Install": "install", "Upgrade": "upgrade", "Downgrade": "downgrade", "Remove": "remove", "Purge": "purge", "Reinstall": "reinstall"}
	for _, l := range lines {
		k, v, ok := strings.Cut(l, ": ")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Start-Date":
			t, err := time.ParseInLocation("2006-01-02  15:04:05", v, loc)
			if err != nil {
				cur = nil
				continue
			}
			out = append(out, PackageHistoryEntry{At: t.UTC()})
			cur = &out[len(out)-1]
		case "Commandline":
			if cur != nil {
				cur.Command = v
			}
		case "Requested-By":
			if cur != nil {
				cur.User, _, _ = strings.Cut(v, " (")
			}
		case "Error":
			if cur != nil {
				cur.Error = v
			}
		default:
			act, known := acts[k]
			if cur == nil || !known {
				continue
			}
			for _, m := range aptPkgRe.FindAllStringSubmatch(v, -1) {
				name, _, _ := strings.Cut(m[1], ":")
				c := PackageChange{Name: name, Action: act}
				vers := strings.Split(m[2], ", ")
				vers = slices.DeleteFunc(vers, func(x string) bool { return x == "automatic" })
				switch {
				case (act == "upgrade" || act == "downgrade") && len(vers) >= 2:
					c.From, c.To = vers[0], vers[1]
				case act == "remove" || act == "purge":
					if len(vers) > 0 {
						c.From = vers[0]
					}
				case len(vers) > 0:
					c.To = vers[0]
				}
				cur.Changes = append(cur.Changes, c)
			}
		}
	}
	return out
}

var dnfTimeLayouts = []string{"2006-01-02 15:04:05", "2006-01-02 15:04", "Mon Jan _2 15:04:05 2006", "Mon 02 Jan 2006 03:04:05 PM MST", "Mon 02 Jan 2006 15:04:05 MST"}

// dnfHistory reads "dnf history info" (dnf 4, dnf 5 and yum).
func dnfHistory(lines []string, loc *time.Location) []PackageHistoryEntry {
	var out []PackageHistoryEntry
	var cur *PackageHistoryEntry
	inPkgs := false
	replaced := map[string]string{}
	finish := func() {
		if cur == nil {
			return
		}
		for i, c := range cur.Changes {
			if from, ok := replaced[c.Name]; ok && (c.Action == "upgrade" || c.Action == "downgrade") {
				cur.Changes[i].From = from
			}
		}
		replaced = map[string]string{}
	}
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		if k, v, ok := strings.Cut(t, ":"); ok && !strings.HasPrefix(l, " ") {
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			switch strings.ToLower(k) {
			case "transaction id":
				finish()
				out = append(out, PackageHistoryEntry{})
				cur = &out[len(out)-1]
				inPkgs = false
			case "begin time":
				if cur != nil {
					for _, lay := range dnfTimeLayouts {
						if at, err := time.ParseInLocation(lay, v, loc); err == nil {
							cur.At = at.UTC()
							break
						}
					}
				}
			case "user":
				if cur != nil {
					if i := strings.Index(v, "<"); i >= 0 {
						cur.User = strings.TrimSuffix(v[i+1:], ">")
					} else {
						cur.User = v
					}
				}
			case "description", "command line":
				if cur != nil && v != "" {
					cur.Command = v
				}
			case "status", "return-code":
				if cur != nil && v != "" && !strings.EqualFold(v, "ok") && !strings.EqualFold(v, "success") {
					cur.Error = v
				}
			case "packages altered":
				inPkgs = true
			default:
				inPkgs = false
			}
			continue
		}
		if !inPkgs || cur == nil {
			continue
		}
		f := strings.Fields(t)
		if len(f) < 2 || f[0] == "Action" {
			continue
		}
		act := strings.ToLower(f[0])
		nevra := f[1]
		name, ver, _ := nameOfNEVRA(nevra)
		ver = strings.TrimPrefix(ver, "0:")
		switch act {
		case "install", "installed", "dep-install":
			cur.Changes = append(cur.Changes, PackageChange{Name: name, Action: "install", To: ver})
		case "upgrade", "upgraded", "updated", "update":
			if act == "upgraded" || act == "updated" {
				replaced[name] = ver
				continue
			}
			cur.Changes = append(cur.Changes, PackageChange{Name: name, Action: "upgrade", To: ver})
		case "replaced", "obsoleted":
			replaced[name] = ver
		case "downgrade":
			cur.Changes = append(cur.Changes, PackageChange{Name: name, Action: "downgrade", To: ver})
		case "downgraded":
			replaced[name] = ver
		case "remove", "removed", "erase", "erased":
			cur.Changes = append(cur.Changes, PackageChange{Name: name, Action: "remove", From: ver})
		case "reinstall", "reinstalled":
			cur.Changes = append(cur.Changes, PackageChange{Name: name, Action: "reinstall", To: ver})
		}
	}
	finish()
	return slices.DeleteFunc(out, func(e PackageHistoryEntry) bool { return e.At.IsZero() })
}

// rpmHistory groups install times from the rpm database (installs and
// upgrades only) when there's no log.
func rpmHistory(lines []string) []PackageHistoryEntry {
	var out []PackageHistoryEntry
	var last int64
	for _, l := range lines {
		f := strings.Split(l, "\t")
		if len(f) != 3 {
			continue
		}
		sec, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		if len(out) == 0 || sec-last > 120 {
			out = append(out, PackageHistoryEntry{At: time.Unix(sec, 0).UTC(), Partial: true})
		}
		last = sec
		e := &out[len(out)-1]
		e.Changes = append(e.Changes, PackageChange{Name: f[1], Action: "install", To: f[2]})
	}
	return out
}

// zypperHistory reads /var/log/zypp/history: a "command" line, then one
// line per package.
func zypperHistory(lines []string, loc *time.Location) []PackageHistoryEntry {
	var out []PackageHistoryEntry
	var cur *PackageHistoryEntry
	for _, l := range lines {
		if strings.HasPrefix(l, "#") {
			continue
		}
		p := strings.Split(l, "|")
		if len(p) < 3 {
			continue
		}
		at, err := time.ParseInLocation("2006-01-02 15:04:05", p[0], loc)
		if err != nil {
			continue
		}
		kind := strings.TrimSpace(p[1])
		if kind == "command" {
			cmd := ""
			if len(p) > 3 {
				cmd = strings.ReplaceAll(strings.Join(strings.Fields(p[3]), " "), "'", "")
			}
			user, _, _ := strings.Cut(p[2], "@")
			out = append(out, PackageHistoryEntry{At: at.UTC(), Command: cmd, User: user})
			cur = &out[len(out)-1]
			continue
		}
		if kind != "install" && kind != "remove" {
			continue
		}
		if cur == nil || at.UTC().Sub(cur.At) > 10*time.Minute {
			out = append(out, PackageHistoryEntry{At: at.UTC()})
			cur = &out[len(out)-1]
		}
		c := PackageChange{Name: p[2], Action: kind}
		if len(p) > 3 {
			if kind == "install" {
				c.To = p[3]
			} else {
				c.From = p[3]
			}
		}
		cur.Changes = append(cur.Changes, c)
	}
	return out
}

var pacLineRe = regexp.MustCompile(`^\[([^\]]+)\] \[(\w+)\] (.*)$`)
var pacChangeRe = regexp.MustCompile(`^(installed|upgraded|downgraded|removed|reinstalled) (\S+) \(([^)]*)\)$`)

func pacmanHistory(lines []string) []PackageHistoryEntry {
	var out []PackageHistoryEntry
	var cur *PackageHistoryEntry
	for _, l := range lines {
		m := pacLineRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		at, err := time.Parse("2006-01-02T15:04:05-0700", m[1])
		if err != nil {
			if at, err = time.Parse("2006-01-02 15:04", m[1]); err != nil {
				continue
			}
		}
		if m[2] == "PACMAN" {
			if cmd, ok := strings.CutPrefix(m[3], "Running '"); ok {
				out = append(out, PackageHistoryEntry{At: at.UTC(), Command: strings.TrimSuffix(cmd, "'")})
				cur = &out[len(out)-1]
			}
			continue
		}
		if m[2] != "ALPM" {
			continue
		}
		c := pacChangeRe.FindStringSubmatch(m[3])
		if c == nil {
			continue
		}
		if cur == nil {
			out = append(out, PackageHistoryEntry{At: at.UTC()})
			cur = &out[len(out)-1]
		}
		ch := PackageChange{Name: c[2]}
		switch c[1] {
		case "installed":
			ch.Action, ch.To = "install", c[3]
		case "reinstalled":
			ch.Action, ch.To = "reinstall", c[3]
		case "removed":
			ch.Action, ch.From = "remove", c[3]
		default:
			ch.Action = strings.TrimSuffix(c[1], "d")
			ch.From, ch.To, _ = strings.Cut(c[3], " -> ")
		}
		cur.Changes = append(cur.Changes, ch)
	}
	return out
}
