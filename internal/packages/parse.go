package packages

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// sections splits "@@ name" blocks; a name seen twice gets both blocks.
func sections(out string) map[string][]string {
	m := map[string][]string{}
	cur := ""
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimRight(l, "\r")
		if name, ok := strings.CutPrefix(l, "@@ "); ok {
			cur = strings.TrimSpace(name)
			if _, seen := m[cur]; !seen {
				m[cur] = nil
			}
			continue
		}
		if cur != "" {
			m[cur] = append(m[cur], l)
		}
	}
	return m
}

func keyValues(lines []string) map[string]string {
	kv := map[string]string{}
	for _, l := range lines {
		k, v, _ := strings.Cut(strings.TrimSpace(l), " ")
		if k != "" {
			kv[k] = strings.TrimSpace(v)
		}
	}
	return kv
}

func nonEmpty(lines []string) []string {
	var out []string
	for _, l := range lines {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func epochTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f <= 0 {
		return nil
	}
	t := time.Unix(int64(f), 0).UTC()
	return &t
}

// ParseOverview reads what OverviewScript printed.
func ParseOverview(out string) PackagesOverview {
	s := sections(out)
	meta := keyValues(s["meta"])
	pm := meta["pm"]
	if pm == "" {
		pm = None
	}
	o := PackagesOverview{
		Manager:             pm,
		RefreshedAt:         epochTime(meta["lists"]),
		RebootRequired:      meta["reboot"] == "1",
		RebootPackages:      uniq(nonEmpty(s["reboot-pkgs"])),
		CacheBytes:          -1,
		PackageCapabilities: CapabilitiesOf(pm),
		Packages:            []InstalledPackage{},
		Warnings:            []string{},
	}
	if o.RebootPackages == nil {
		o.RebootPackages = []string{}
	}
	if c, err := strconv.ParseInt(meta["cache"], 10, 64); err == nil {
		o.CacheBytes = c
	}
	if meta["versionlock"] == "1" {
		o.PackageCapabilities.Hold = true
	}

	switch pm {
	case APT:
		o.Packages = parseDpkg(s["installed"], s["dates"])
	case DNF, YUM, Zypper:
		o.Packages = parseRPM(s["installed"])
	case APK:
		o.Packages = parseAPKDB(s["apkdb"], s["world"])
	case Pacman:
		o.Packages = parsePacmanDesc(s["pacdesc"])
	}
	if pm != None && len(o.Packages) == 0 {
		o.Warnings = append(o.Warnings, "Couldn't read the installed packages.")
	}

	idx := map[string][]int{}
	for i, p := range o.Packages {
		idx[p.Name] = append(idx[p.Name], i)
	}
	set := func(names []string, fn func(*InstalledPackage)) {
		for _, n := range names {
			n = strings.TrimSpace(n)
			name, arch, _ := strings.Cut(n, ":")
			for _, i := range idx[name] {
				if arch == "" || o.Packages[i].Arch == arch || pm != APT {
					fn(&o.Packages[i])
				}
			}
		}
	}
	set(nonEmpty(s["auto"]), func(p *InstalledPackage) { p.Auto = true })
	set(heldNames(pm, s["held"]), func(p *InstalledPackage) { p.Held = true })
	set(removableNames(pm, s["autoremove"]), func(p *InstalledPackage) { p.Removable = true })
	security := securityNames(s["security"])
	for _, u := range parseUpgradable(pm, s["upgradable"]) {
		for _, i := range idx[u.Name] {
			p := &o.Packages[i]
			if u.Arch != "" && p.Arch != "" && u.Arch != p.Arch && u.Arch != "noarch" && p.Arch != "noarch" && pm != APK {
				continue
			}
			p.Latest, p.Repo = u.Latest, u.Repo
			p.Security = u.Security || security[u.Name]
		}
	}
	for _, p := range o.Packages {
		if p.Latest != "" {
			o.Updates++
			if p.Security {
				o.SecurityCount++
			}
		}
		if p.Removable {
			o.Removable++
		}
	}
	if len(o.Packages) > MaxPackages {
		o.Packages, o.Truncated = o.Packages[:MaxPackages], true
	}

	if o.PackageCapabilities.Security && pm != APT && len(s["security"]) == 0 && o.Updates > 0 {
		// No updateinfo from the repositories (common on Fedora mirrors):
		// can't tell, so don't claim none are.
		o.PackageCapabilities.Security = false
	}

	o.AutoUpdates = autoUpdates(pm, meta)
	o.PackageCapabilities.AutoUpdates = o.AutoUpdates.Supported
	return o
}

func autoUpdates(pm string, meta map[string]string) PackageAutoUpdates {
	switch pm {
	case APT:
		a := PackageAutoUpdates{Supported: true, Tool: "unattended-upgrades", Detail: "Installs security updates every day (APT::Periodic::Unattended-Upgrade)"}
		if meta["auto_tool"] == "" {
			a.Missing = "unattended-upgrades"
			return a
		}
		a.Enabled = meta["auto_value"] != "" && meta["auto_value"] != "0"
		return a
	case DNF:
		a := PackageAutoUpdates{Tool: "dnf-automatic"}
		unit := meta["auto_tool"]
		if unit == "" {
			a.Supported, a.Missing = true, "dnf-automatic"
			return a
		}
		a.Supported = true
		a.Detail = unit
		a.Enabled = meta["auto_value"] == "enabled" && (unit == "dnf-automatic-install.timer" || meta["auto_apply"] == "1")
		return a
	}
	return PackageAutoUpdates{}
}

// dpkg-query: name, version, arch, Installed-Size (KiB), section,
// status abbreviation, summary.
func parseDpkg(lines, dates []string) []InstalledPackage {
	changed := map[string]*time.Time{}
	for _, l := range dates {
		f, t, ok := strings.Cut(l, "\t")
		if !ok {
			continue
		}
		f = strings.TrimSuffix(f, ".list")
		changed[f] = epochTime(t)
	}
	var out []InstalledPackage
	for _, l := range lines {
		f := strings.Split(l, "\t")
		if len(f) < 7 || f[0] == "" {
			continue
		}
		status := f[5]
		if len(status) < 2 || status[1] == 'n' {
			continue // known but not installed
		}
		p := InstalledPackage{
			Name: f[0], Version: f[1], Arch: f[2], Section: f[4], Summary: f[6],
			State: "installed", Held: status[0] == 'h',
		}
		if i := strings.LastIndex(p.Section, "/"); i >= 0 {
			p.Section = p.Section[i+1:]
		}
		if kb, err := strconv.ParseInt(strings.TrimSpace(f[3]), 10, 64); err == nil {
			p.Size = kb * 1024
		}
		switch {
		case status[1] == 'c':
			p.State = "config-files"
		case status[1] != 'i' || (len(status) > 2 && status[2] != ' '):
			p.State = "broken"
		}
		if t, ok := changed[p.Name+":"+p.Arch]; ok {
			p.ChangedAt = t
		} else {
			p.ChangedAt = changed[p.Name]
		}
		out = append(out, p)
	}
	return out
}

// rpm: name, [epoch:]version-release, arch, size, group, ii, summary,
// install time.
func parseRPM(lines []string) []InstalledPackage {
	var out []InstalledPackage
	for _, l := range lines {
		f := strings.Split(l, "\t")
		if len(f) < 8 || f[0] == "" {
			continue
		}
		p := InstalledPackage{Name: f[0], Version: f[1], Arch: f[2], Summary: f[6], State: "installed"}
		if f[4] != "Unspecified" && f[4] != "(none)" {
			p.Section = f[4]
		}
		if p.Arch == "(none)" {
			p.Arch = ""
		}
		p.Size, _ = strconv.ParseInt(f[3], 10, 64)
		p.ChangedAt = epochTime(f[7])
		out = append(out, p)
	}
	return out
}

// apk's installed database (P name, V version, A arch, I size, T summary)
// and world (what was asked for by name).
func parseAPKDB(lines, world []string) []InstalledPackage {
	explicit := map[string]bool{}
	pinned := map[string]bool{}
	for _, w := range nonEmpty(world) {
		name := w
		if i := strings.IndexAny(w, "<>=~@"); i > 0 {
			name = w[:i]
			if w[i] == '=' {
				pinned[name] = true
			}
		}
		explicit[name] = true
	}
	var out []InstalledPackage
	var cur *InstalledPackage
	flush := func() {
		if cur != nil && cur.Name != "" {
			cur.Auto = !explicit[cur.Name]
			cur.Held = pinned[cur.Name]
			out = append(out, *cur)
		}
		cur = nil
	}
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			flush()
			continue
		}
		if len(l) < 2 || l[1] != ':' {
			continue
		}
		if cur == nil {
			cur = &InstalledPackage{State: "installed"}
		}
		v := l[2:]
		switch l[0] {
		case 'P':
			cur.Name = v
		case 'V':
			cur.Version = v
		case 'A':
			cur.Arch = v
		case 'I':
			cur.Size, _ = strconv.ParseInt(v, 10, 64)
		case 'T':
			cur.Summary = v
		}
	}
	flush()
	return out
}

// pacman's local desc files, one after another.
func parsePacmanDesc(lines []string) []InstalledPackage {
	var out []InstalledPackage
	var cur *InstalledPackage
	key := ""
	flush := func() {
		if cur != nil && cur.Name != "" {
			out = append(out, *cur)
		}
	}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "%") && strings.HasSuffix(l, "%") && len(l) > 2 {
			key = l
			if key == "%NAME%" {
				flush()
				cur = &InstalledPackage{State: "installed"}
			}
			continue
		}
		if l == "" {
			key = ""
			continue
		}
		if cur == nil {
			continue
		}
		switch key {
		case "%NAME%":
			cur.Name = l
		case "%VERSION%":
			cur.Version = l
		case "%DESC%":
			cur.Summary = l
		case "%ARCH%":
			cur.Arch = l
		case "%SIZE%":
			cur.Size, _ = strconv.ParseInt(l, 10, 64)
		case "%INSTALLDATE%":
			cur.ChangedAt = epochTime(l)
		case "%REASON%":
			cur.Auto = l == "1"
		case "%GROUPS%":
			if cur.Section == "" {
				cur.Section = l
			}
		}
	}
	flush()
	return out
}

func heldNames(pm string, lines []string) []string {
	var out []string
	switch pm {
	case Zypper:
		// # | Name | Type | Repository
		for _, l := range lines {
			p := strings.Split(l, "|")
			if len(p) < 3 || strings.TrimSpace(p[2]) != "package" {
				continue
			}
			out = append(out, strings.TrimSpace(p[1]))
		}
	case DNF, YUM:
		for _, l := range nonEmpty(lines) {
			if strings.HasPrefix(l, "#") || strings.HasPrefix(l, "Loaded plugins") {
				continue
			}
			if n, ok := strings.CutPrefix(l, "Package name:"); ok {
				out = append(out, strings.TrimSpace(n))
				continue
			}
			l = strings.TrimPrefix(l, "!")
			if m := lockRe.FindStringSubmatch(l); m != nil {
				out = append(out, m[1])
			}
		}
	default:
		out = nonEmpty(lines)
	}
	return out
}

// name-[epoch:]version-release.* in a versionlock list.
var lockRe = regexp.MustCompile(`^(?:\d+:)?(.+?)-(?:\d+:)?[^-]+-[^-]+$`)

func removableNames(pm string, lines []string) []string {
	if pm != Zypper {
		return nonEmpty(lines)
	}
	var out []string
	for _, l := range lines {
		p := strings.Split(l, "|")
		if len(p) < 4 {
			continue
		}
		s := strings.TrimSpace(p[0])
		if s != "i" && s != "i+" {
			continue
		}
		out = append(out, strings.TrimSpace(p[2]))
	}
	return out
}

var archRe = regexp.MustCompile(`\.(x86_64|aarch64|noarch|i686|i586|i386|ppc64le|s390x|armv7hl|armv7l|riscv64|src)$`)

// nameOfNEVRA takes name-[epoch:]version-release.arch apart.
func nameOfNEVRA(s string) (name, version, arch string) {
	if m := archRe.FindStringSubmatchIndex(s); m != nil {
		arch = s[m[2]:m[3]]
		s = s[:m[0]]
	}
	i := strings.LastIndex(s, "-")
	if i <= 0 {
		return s, "", arch
	}
	j := strings.LastIndex(s[:i], "-")
	if j <= 0 {
		return s[:i], s[i+1:], arch
	}
	return s[:j], s[j+1:], arch
}

// dnf/yum updateinfo: ID, type/severity, NEVRA (dnf5: name, type,
// severity, package, issued). The NEVRA is the field with an arch.
func securityNames(lines []string) map[string]bool {
	m := map[string]bool{}
	for _, l := range lines {
		for _, f := range strings.Fields(l) {
			if archRe.MatchString(f) && strings.Count(f, "-") >= 2 {
				n, _, _ := nameOfNEVRA(f)
				m[n] = true
			}
		}
	}
	return m
}

type upgradable struct {
	Name, Arch, Latest, Repo string
	Security                 bool
}

var apkListRe = regexp.MustCompile(`^(\S+?)-(\d\S*-r\d+) (\S+) .*\[upgradable from: (\S+)\]`)

func parseUpgradable(pm string, lines []string) []upgradable {
	var out []upgradable
	switch pm {
	case APT:
		// name/suite version arch [upgradable from: old]
		for _, l := range lines {
			f := strings.Fields(l)
			if len(f) < 3 || !strings.Contains(f[0], "/") {
				continue
			}
			name, suite, _ := strings.Cut(f[0], "/")
			repo := suite
			if i := strings.Index(repo, ","); i >= 0 {
				repo = repo[:i]
			}
			out = append(out, upgradable{Name: name, Arch: f[2], Latest: f[1], Repo: repo, Security: strings.Contains(suite, "-security")})
		}
	case DNF, YUM:
		// name.arch version repo; a long name.arch can wrap onto two lines.
		for i := 0; i < len(lines); i++ {
			l := lines[i]
			if l == "" || strings.HasPrefix(l, " ") {
				continue
			}
			f := strings.Fields(l)
			if len(f) == 1 && i+1 < len(lines) && strings.HasPrefix(lines[i+1], " ") {
				f = append(f, strings.Fields(lines[i+1])...)
				i++
			}
			if len(f) != 3 || f[0] == "Obsoleting" || strings.HasSuffix(f[0], ":") {
				continue
			}
			dot := strings.LastIndex(f[0], ".")
			if dot <= 0 {
				continue
			}
			out = append(out, upgradable{Name: f[0][:dot], Arch: f[0][dot+1:], Latest: f[1], Repo: f[2]})
		}
	case Zypper:
		// S | Repository | Name | Current | Available | Arch
		for _, l := range lines {
			p := strings.Split(l, "|")
			if len(p) < 6 || strings.TrimSpace(p[0]) != "v" {
				continue
			}
			out = append(out, upgradable{
				Repo: strings.TrimSpace(p[1]), Name: strings.TrimSpace(p[2]),
				Latest: strings.TrimSpace(p[4]), Arch: strings.TrimSpace(p[5]),
			})
		}
	case APK:
		for _, l := range lines {
			if m := apkListRe.FindStringSubmatch(l); m != nil {
				out = append(out, upgradable{Name: m[1], Latest: m[2], Arch: m[3]})
			}
		}
	case Pacman:
		// name old -> new
		for _, l := range lines {
			f := strings.Fields(l)
			if len(f) >= 4 && f[2] == "->" {
				out = append(out, upgradable{Name: f[0], Latest: f[3]})
			}
		}
	}
	return out
}

// splitAPKName takes name-version-rN apart.
func splitAPKName(s string) (name, version string) {
	m := apkNameRe.FindStringSubmatch(s)
	if m == nil {
		return s, ""
	}
	return m[1], m[2]
}

var apkNameRe = regexp.MustCompile(`^(.+?)-(\d[^-]*-r\d+)$`)

func sortVersionsKeepOrder(v []PackageVersion) []PackageVersion {
	seen := map[string]bool{}
	return slices.DeleteFunc(v, func(x PackageVersion) bool {
		k := x.Version + "\x00" + x.Repo
		if seen[k] {
			return true
		}
		seen[k] = true
		return false
	})
}
