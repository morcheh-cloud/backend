package packages

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// ParseInfo reads what InfoScript printed. ok is false when the package
// is neither installed nor in any repository.
func ParseInfo(name, out string) (PackageInfo, bool) {
	s := sections(out)
	pm := keyValues(s["meta"])["pm"]
	info := PackageInfo{Name: name, Depends: []string{}, RequiredBy: []string{}, Files: []string{}, Versions: []PackageVersion{}}
	var found bool
	switch pm {
	case APT:
		found = aptInfo(&info, s)
	case DNF, YUM, Zypper:
		found = rpmInfo(&info, pm, s)
	case APK:
		found = apkInfo(&info, s)
	case Pacman:
		found = pacmanInfo(&info, s)
	}
	info.Depends = uniqKeep(info.Depends)
	info.RequiredBy = uniq(slices.DeleteFunc(info.RequiredBy, func(n string) bool { return n == name || n == "" }))
	if info.RequiredBy == nil {
		info.RequiredBy = []string{}
	}
	info.Versions = sortVersionsKeepOrder(info.Versions)
	if info.Latest == "" && len(info.Versions) > 0 {
		info.Latest = info.Versions[0].Version
	}
	return info, found
}

func uniqKeep(s []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range s {
		if x = strings.TrimSpace(x); x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// files drops folders (an entry the next one lives in) and caps the list.
func files(lines []string) ([]string, bool) {
	var all []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || l == "/." || !strings.HasPrefix(l, "/") {
			continue
		}
		all = append(all, l)
	}
	slices.Sort(all)
	all = slices.Compact(all)
	out := []string{}
	for i, f := range all {
		if i+1 < len(all) && strings.HasPrefix(all[i+1], strings.TrimSuffix(f, "/")+"/") {
			continue
		}
		out = append(out, f)
	}
	if len(out) > MaxFiles {
		return out[:MaxFiles], true
	}
	return out, false
}

// deb822 reads the first "Key: value" record; continuation lines start
// with a space, and " ." is an empty line.
func deb822(lines []string) map[string]string {
	m := map[string]string{}
	key := ""
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			if len(m) > 0 {
				break
			}
			continue
		}
		if l[0] == ' ' || l[0] == '\t' {
			if key != "" {
				t := strings.TrimSpace(l)
				if t == "." {
					t = ""
				}
				m[key] += "\n" + t
			}
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(k)
		m[key] = strings.TrimSpace(v)
	}
	return m
}

var constraintRe = regexp.MustCompile(`\s*(\(.*?\)|\[.*?\]|<.*?>)`)

// debDepends turns "a (>= 1), b | c:any" into ["a", "b | c"].
func debDepends(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		var alts []string
		for _, a := range strings.Split(part, "|") {
			a = constraintRe.ReplaceAllString(a, "")
			a = strings.TrimSuffix(strings.TrimSpace(a), ":any")
			if a != "" {
				alts = append(alts, a)
			}
		}
		if len(alts) > 0 {
			out = append(out, strings.Join(alts, " | "))
		}
	}
	return out
}

func describe(info *PackageInfo, d string) {
	first, rest, _ := strings.Cut(d, "\n")
	if info.Summary == "" {
		info.Summary = strings.TrimSpace(first)
	}
	info.Description = strings.TrimSpace(rest)
}

func aptInfo(info *PackageInfo, s map[string][]string) bool {
	st := deb822(s["status"])
	rec := st
	if strings.Contains(st["status"], " installed") || strings.Contains(st["status"], "config-files") {
		info.Installed = strings.Contains(st["status"], " installed")
		info.Version = st["version"]
	}
	if !info.Installed {
		if show := deb822(s["show"]); len(show) > 0 {
			rec = show
		}
	}
	if len(rec) == 0 {
		return false
	}
	info.Arch = rec["architecture"]
	describe(info, rec["description"])
	info.Homepage = rec["homepage"]
	info.Maintainer = rec["maintainer"]
	info.Section = rec["section"]
	if kb, err := strconv.ParseInt(rec["installed-size"], 10, 64); err == nil {
		info.Size = kb * 1024
	}
	for _, k := range []string{"pre-depends", "depends"} {
		info.Depends = append(info.Depends, debDepends(rec[k])...)
	}
	// apt-cache policy: Installed, Candidate and the version table.
	var cur *PackageVersion
	for _, l := range s["policy"] {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "Candidate:"):
			if c := strings.TrimSpace(strings.TrimPrefix(t, "Candidate:")); c != "(none)" {
				info.Latest = c
			}
		case strings.HasPrefix(t, "Installed:"), strings.HasPrefix(t, "Version table:"), t == "":
		case strings.HasPrefix(l, "     ") && strings.HasPrefix(l, "        "):
			// "   500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages"
			if cur == nil {
				continue
			}
			f := strings.Fields(t)
			if len(f) >= 2 && f[1] == "/var/lib/dpkg/status" {
				cur.Installed = true
				continue
			}
			if len(f) >= 3 && cur.Repo == "" {
				cur.Repo = f[2]
			}
		case strings.HasPrefix(l, " *** ") || strings.HasPrefix(l, "     "):
			f := strings.Fields(strings.TrimPrefix(t, "*** "))
			if len(f) == 0 {
				continue
			}
			info.Versions = append(info.Versions, PackageVersion{Version: f[0], Installed: strings.HasPrefix(l, " *** ")})
			cur = &info.Versions[len(info.Versions)-1]
		}
	}
	if info.Repo == "" {
		for _, v := range info.Versions {
			if v.Version == info.Latest {
				info.Repo = v.Repo
			}
		}
	}
	after := false
	for _, l := range s["rdepends"] {
		t := strings.TrimSpace(l)
		if t == "Reverse Depends:" {
			after = true
			continue
		}
		if after && t != "" {
			n, _, _ := strings.Cut(strings.TrimLeft(t, "|"), ":")
			info.RequiredBy = append(info.RequiredBy, n)
		}
	}
	if info.Installed {
		info.Files, info.FilesTruncated = files(s["files"])
	}
	return true
}

var colonKeyRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9 ./()-]*?)\s*:\s?(.*)$`)

// colonRecords reads "Key   : value" records (rpm -qi, dnf info, zypper
// info, pacman -Qi). A record starts at a Name line. With rawDescription,
// every line after Description belongs to it (rpm -qi).
func colonRecords(lines []string, rawDescription bool) []map[string]string {
	var out []map[string]string
	var cur map[string]string
	key := ""
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			if key == "description" && cur != nil && rawDescription {
				cur[key] += "\n"
			}
			continue
		}
		if l[0] == ' ' || l[0] == '\t' {
			if cur == nil || key == "" {
				continue
			}
			t := strings.TrimSpace(l)
			if rest, ok := strings.CutPrefix(t, ": "); ok || t == ":" {
				t = rest
			}
			sep := " "
			if key == "description" {
				sep = "\n"
			}
			cur[key] = strings.TrimSpace(cur[key] + sep + t)
			continue
		}
		m := colonKeyRe.FindStringSubmatch(l)
		if m == nil || (rawDescription && key == "description" && !strings.HasPrefix(l, "Name ")) {
			if cur != nil && key == "description" {
				cur[key] += "\n" + l
			}
			continue
		}
		k := strings.ToLower(strings.TrimSpace(m[1]))
		if k == "name" {
			cur = map[string]string{}
			out = append(out, cur)
		}
		if cur == nil {
			continue
		}
		key = k
		cur[k] = strings.TrimSpace(m[2])
	}
	for _, r := range out {
		if d, ok := r["description"]; ok {
			r["description"] = strings.TrimSpace(d)
		}
	}
	return out
}

func rpmInfo(info *PackageInfo, pm string, s map[string][]string) bool {
	var local map[string]string
	if recs := colonRecords(s["rpm"], true); len(recs) > 0 {
		local = recs[0]
		info.Installed = true
		info.Version = local["version"]
		if r := local["release"]; r != "" {
			info.Version += "-" + r
		}
		if e := local["epoch"]; e != "" && e != "(none)" && e != "0" {
			info.Version = e + ":" + info.Version
		}
	}
	var remote map[string]string
	for _, r := range colonRecords(s["remote"], false) {
		repo := firstOf(r, "repository", "from repo", "repo")
		if strings.HasPrefix(repo, "@") || repo == "installed" || repo == "System" {
			continue
		}
		remote = r
	}
	if pm == Zypper && remote != nil && strings.Contains(remote["installed"], "Yes") && local == nil {
		info.Installed = true
	}
	rec := local
	if rec == nil {
		rec = remote
	}
	if rec == nil {
		return false
	}
	info.Arch = rec["architecture"]
	info.Summary = rec["summary"]
	info.Description = rec["description"]
	info.Homepage = rec["url"]
	info.License = rec["license"]
	info.Maintainer = firstOf(rec, "packager", "vendor")
	if g := rec["group"]; g != "Unspecified" {
		info.Section = g
	}
	info.Size = parseSize(firstOf(rec, "size", "installed size", "installed_size"))
	if remote != nil {
		v := remote["version"]
		if r := remote["release"]; r != "" {
			v += "-" + r
		}
		info.Latest = v
		info.Repo = firstOf(remote, "repository", "repo")
	}
	info.Depends = nonEmpty(s["depends"])
	info.RequiredBy = nonEmpty(s["rdepends"])
	if info.Installed {
		info.Files, info.FilesTruncated = files(s["files"])
	}
	// dnf/yum list --showduplicates: name.arch version repo
	// dnf 5 names the repo it came from under "Installed packages".
	inInstalled := false
	for _, l := range s["versions"] {
		if t := strings.ToLower(strings.TrimSpace(l)); strings.HasSuffix(t, "packages") {
			inInstalled = strings.HasPrefix(t, "installed")
			continue
		}
		f := strings.Fields(l)
		if len(f) != 3 || !strings.Contains(f[0], ".") {
			continue
		}
		inst := inInstalled || strings.HasPrefix(f[2], "@") || f[2] == "installed"
		v := strings.TrimPrefix(f[1], "0:")
		if i := slices.IndexFunc(info.Versions, func(x PackageVersion) bool { return x.Version == v }); i >= 0 {
			info.Versions[i].Installed = info.Versions[i].Installed || inst
			if !strings.HasPrefix(f[2], "@") && f[2] != "installed" {
				info.Versions[i].Repo = f[2]
			}
			continue
		}
		info.Versions = append(info.Versions, PackageVersion{Version: v, Repo: strings.TrimPrefix(f[2], "@"), Installed: inst})
	}
	// zypper se -s: S | Name | Type | Version | Arch | Repository
	for _, l := range s["zversions"] {
		p := strings.Split(l, "|")
		if len(p) < 6 || strings.TrimSpace(p[2]) != "package" {
			continue
		}
		st := strings.TrimSpace(p[0])
		info.Versions = append(info.Versions, PackageVersion{
			Version: strings.TrimSpace(p[3]), Repo: strings.TrimSpace(p[5]),
			Installed: strings.HasPrefix(st, "i"),
		})
	}
	slices.SortStableFunc(info.Versions, func(a, b PackageVersion) int { return CompareVersions(b.Version, a.Version) })
	return true
}

func firstOf(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := m[k]; v != "" && v != "None" && v != "(none)" {
			return v
		}
	}
	return ""
}

var sizeRe = regexp.MustCompile(`^([\d.,]+)\s*([KMGT]?i?B|k|M|G)?`)

// parseSize reads "1234", "36 k", "1.2 MiB", "1408 KiB".
func parseSize(s string) int64 {
	m := sizeRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0
	}
	f, err := strconv.ParseFloat(strings.ReplaceAll(m[1], ",", ""), 64)
	if err != nil {
		return 0
	}
	switch strings.ToUpper(strings.TrimSuffix(strings.TrimSuffix(m[2], "B"), "i")) {
	case "K":
		f *= 1 << 10
	case "M":
		f *= 1 << 20
	case "G":
		f *= 1 << 30
	case "T":
		f *= 1 << 40
	}
	return int64(f)
}

var apkHeadRe = regexp.MustCompile(`^(\S+) ([a-z -]+):$`)

func apkInfo(info *PackageInfo, s map[string][]string) bool {
	parts := map[string][]string{}
	key := ""
	for _, l := range s["apkinfo"] {
		if m := apkHeadRe.FindStringSubmatch(l); m != nil {
			key = m[2]
			_, ver := splitAPKName(m[1])
			if info.Version == "" && ver != "" && key == "description" {
				info.Latest = ver
			}
			continue
		}
		if key != "" && strings.TrimSpace(l) != "" {
			parts[key] = append(parts[key], strings.TrimSpace(l))
		}
	}
	for _, l := range s["apklist"] {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		n, v := splitAPKName(f[0])
		if n != info.Name {
			continue
		}
		if info.Arch == "" {
			info.Arch = f[1]
		}
		if strings.Contains(l, "[installed]") || strings.Contains(l, "[upgradable from") {
			info.Installed = true
		}
		if strings.Contains(l, "[installed]") {
			info.Version = v
		}
		if m := regexp.MustCompile(`\[upgradable from: (\S+)\]`).FindStringSubmatch(l); m != nil {
			_, info.Version = splitAPKName(m[1])
		}
		if i := strings.Index(l, "("); i >= 0 {
			if j := strings.Index(l[i:], ")"); j > 0 {
				info.License = l[i+1 : i+j]
			}
		}
		info.Latest = v
	}
	if len(parts) == 0 && !info.Installed {
		return false
	}
	info.Summary = strings.Join(parts["description"], " ")
	info.Homepage = strings.Join(parts["webpage"], " ")
	if l := strings.Join(parts["license"], " "); l != "" {
		info.License = l
	}
	info.Size = parseSize(strings.Join(parts["installed size"], " "))
	for _, d := range parts["depends on"] {
		if !strings.Contains(d, ":") {
			info.Depends = append(info.Depends, constraintStrip(d))
		}
	}
	if len(info.Depends) == 0 {
		for _, d := range parts["depends on"] {
			info.Depends = append(info.Depends, d)
		}
	}
	for _, r := range parts["is required by"] {
		n, _ := splitAPKName(r)
		info.RequiredBy = append(info.RequiredBy, n)
	}
	var fl []string
	for _, f := range parts["contains"] {
		fl = append(fl, "/"+f)
	}
	info.Files, info.FilesTruncated = files(fl)
	// apk policy: "  1.2-r0:" then repository lines.
	var cur *PackageVersion
	for _, l := range s["policy"] {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(l, "    ") && cur != nil {
			if t == "lib/apk/db/installed" {
				cur.Installed = true
			} else if cur.Repo == "" {
				cur.Repo = t
			}
			continue
		}
		if strings.HasPrefix(l, "  ") && strings.HasSuffix(t, ":") {
			info.Versions = append(info.Versions, PackageVersion{Version: strings.TrimSuffix(t, ":")})
			cur = &info.Versions[len(info.Versions)-1]
		}
	}
	slices.SortStableFunc(info.Versions, func(a, b PackageVersion) int { return CompareVersions(b.Version, a.Version) })
	return true
}

var opRe = regexp.MustCompile(`[<>=~].*$`)

func constraintStrip(s string) string { return opRe.ReplaceAllString(s, "") }

func pacmanList(v string) []string {
	if v == "" || v == "None" {
		return nil
	}
	var out []string
	for _, f := range strings.Fields(v) {
		out = append(out, constraintStrip(f))
	}
	return out
}

func pacmanInfo(info *PackageInfo, s map[string][]string) bool {
	var local, sync map[string]string
	if r := colonRecords(s["local"], false); len(r) > 0 {
		local = r[0]
	}
	if r := colonRecords(s["sync"], false); len(r) > 0 {
		sync = r[0]
	}
	rec := local
	if rec == nil {
		rec = sync
	}
	if rec == nil {
		return false
	}
	if local != nil {
		info.Installed = true
		info.Version = local["version"]
		info.Versions = append(info.Versions, PackageVersion{Version: local["version"], Repo: "local", Installed: true})
	}
	if sync != nil {
		info.Latest = sync["version"]
		info.Repo = sync["repository"]
		if local == nil || sync["version"] != local["version"] {
			info.Versions = append([]PackageVersion{{Version: sync["version"], Repo: sync["repository"]}}, info.Versions...)
		} else {
			info.Versions[0].Repo = sync["repository"]
		}
	}
	info.Arch = rec["architecture"]
	info.Summary = rec["description"]
	info.Homepage = firstOf(rec, "url")
	info.License = firstOf(rec, "licenses")
	info.Maintainer = firstOf(rec, "packager")
	info.Section = firstOf(rec, "groups")
	info.Size = parseSize(rec["installed size"])
	info.Depends = pacmanList(rec["depends on"])
	if local != nil {
		info.RequiredBy = pacmanList(local["required by"])
		info.Files, info.FilesTruncated = files(s["files"])
	}
	return true
}
