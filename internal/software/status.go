package software

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// MaxPackages is how many upgradable packages a scan keeps by name.
const MaxPackages = 300

// Package is an upgradable system package.
type Package struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Latest   string `json:"latest"`
	Security bool   `json:"security,omitempty"`
}

// Host is what a scan says about the server as a whole.
type Host struct {
	PM             string
	Root           bool
	Docker         string
	Compose        string
	Upgradable     int
	Security       int
	RebootRequired bool
	Packages       []Package
}

// Found is one application on the server.
type Found struct {
	RecipeID string
	Name     string
	Kind     string
	// "found": the scan saw it on the server (Morche's own installs are
	// "morche").
	Origin          string
	Version         string
	Latest          string
	UpdateAvailable bool
}

// Scan is a parsed scan.
type Scan struct {
	Host     Host
	Software []Found
	// Recipes the scan looked for (whether found or not), so the caller can
	// tell which records are gone.
	Looked []string
}

// ScanOptions say what a scan looks at.
type ScanOptions struct {
	// The host's packages too, not just the recipes.
	Full bool
}

// ScanScript lists what of recipes is on the server. It runs as root when
// it can (to refresh the package lists), but works as any user.
func ScanScript(recipes []Recipe, opt ScanOptions) string {
	var b strings.Builder
	b.WriteString(lib)
	b.WriteString("set +e\n")
	b.WriteString("ROOT=0; [ \"$(id -u)\" = 0 ] && ROOT=1\n")
	if opt.Full {
		b.WriteString("echo '@@ host'\n")
		b.WriteString("echo \"pm=$PM\"\necho \"root=$ROOT\"\n")
		b.WriteString("echo \"docker=$(docker version --format '{{.Server.Version}}' 2>/dev/null)\"\n")
		b.WriteString("echo \"compose=$(docker compose version --short 2>/dev/null)\"\n")
		// Package lists older than 6 hours are refreshed (root only).
		b.WriteString(`if [ "$ROOT" = 1 ]; then
  case "$PM" in
    apt) [ -n "$(find /var/lib/apt/lists -maxdepth 1 -name '*Packages*' -mmin -360 2>/dev/null | head -n1)" ] || timeout 180 apt-get update -qq >/dev/null 2>&1 ;;
    apk) timeout 120 apk update -q >/dev/null 2>&1 ;;
    zypper) timeout 180 zypper -q -n refresh >/dev/null 2>&1 ;;
  esac
fi
if [ -f /var/run/reboot-required ]; then echo reboot=1
elif command -v needs-restarting >/dev/null 2>&1; then needs-restarting -r >/dev/null 2>&1; [ $? -eq 1 ] && echo reboot=1
fi
case "$PM" in
  dnf) echo "security=$(timeout 120 dnf -q updateinfo list --security --updates 2>/dev/null | grep -c .)" ;;
  yum) echo "security=$(timeout 120 yum -q updateinfo list security 2>/dev/null | grep -c .)" ;;
esac
echo '@@ packages'
case "$PM" in
  apt) apt list --upgradable 2>/dev/null | tail -n +2 ;;
  dnf) timeout 180 dnf -q check-update 2>/dev/null ;;
  yum) timeout 180 yum -q check-update 2>/dev/null ;;
  zypper) timeout 180 zypper -q -n lu 2>/dev/null ;;
  apk) apk list -u 2>/dev/null ;;
  pacman) pacman -Qu 2>/dev/null ;;
esac | head -n 5000
`)
	}
	for _, r := range recipes {
		fmt.Fprintf(&b, "echo '@@ recipe:%s'\n(\n", r.ID)
		if r.Kind == KindPackage {
			b.WriteString(pkgsCase(r))
			b.WriteString("for p in ${PKGS%% *} $ALSO; do v=$(pkg_version \"$p\"); if [ -n \"$v\" ]; then echo \"pkg=$v\"; echo \"latest=$(pkg_latest \"$p\")\"; break; fi; done\n")
		}
		if r.VersionCommand != "" {
			// Only when its program is here: a "not found" printed to
			// stdout (a command with 2>&1) would read as a version.
			guard := ""
			if prog := programOf(r.VersionCommand); prog != "" {
				guard = fmt.Sprintf("command -v %s >/dev/null 2>&1 && ", prog)
			}
			fmt.Fprintf(&b, "v=$( %s(%s) 2>/dev/null </dev/null | head -n1 ); [ -n \"$v\" ] && echo \"version=$v\"\n", guard, r.VersionCommand)
		}
		b.WriteString(")\n")
	}
	b.WriteString("exit 0\n")
	return b.String()
}

// ParseScan reads ScanScript's output.
func ParseScan(out string, recipes []Recipe) Scan {
	var s Scan
	sections := splitSections(out)
	if h, ok := sections["host"]; ok {
		kv := keyValues(h)
		s.Host.PM = kv["pm"]
		s.Host.Root = kv["root"] == "1"
		s.Host.Docker = kv["docker"]
		s.Host.Compose = kv["compose"]
		s.Host.RebootRequired = kv["reboot"] == "1"
		s.Host.Security, _ = strconv.Atoi(kv["security"])
	}
	if p, ok := sections["packages"]; ok {
		pkgs := parsePackages(s.Host.PM, p)
		s.Host.Upgradable = len(pkgs)
		if s.Host.PM == "apt" || s.Host.PM == "zypper" {
			s.Host.Security = 0
			for _, p := range pkgs {
				if p.Security {
					s.Host.Security++
				}
			}
		}
		if len(pkgs) > MaxPackages {
			pkgs = pkgs[:MaxPackages]
		}
		s.Host.Packages = pkgs
	}
	for _, r := range recipes {
		s.Looked = append(s.Looked, r.ID)
		body, ok := sections["recipe:"+r.ID]
		if !ok {
			continue
		}
		kv := keyValues(body)
		pkg, version := kv["pkg"], strings.TrimSpace(kv["version"])
		if pkg == "" && version == "" {
			continue
		}
		f := Found{RecipeID: r.ID, Name: r.Name, Kind: r.Kind, Origin: "found"}
		latest := kv["latest"]
		switch {
		case pkg != "":
			f.Version = prettyVersion(pkg)
			if version != "" && r.Kind == KindPackage && len(version) <= 40 {
				// The program's own word reads better than a package revision.
				f.Version = version
			}
			if latest != "" && normVersion(latest) != normVersion(pkg) {
				f.UpdateAvailable = true
				f.Latest = prettyVersion(latest)
			} else {
				f.Latest = f.Version
			}
		default:
			f.Version = version
			f.Latest = version
		}
		s.Software = append(s.Software, f)
	}
	slices.SortFunc(s.Software, func(a, b Found) int { return strings.Compare(a.RecipeID, b.RecipeID) })
	return s
}

func splitSections(out string) map[string][]string {
	m := map[string][]string{}
	cur := ""
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if name, ok := strings.CutPrefix(line, "@@ "); ok {
			cur = strings.TrimSpace(name)
			if _, seen := m[cur]; !seen {
				m[cur] = nil
			}
			continue
		}
		if cur != "" && line != "" {
			m[cur] = append(m[cur], line)
		}
	}
	return m
}

func keyValues(lines []string) map[string]string {
	kv := map[string]string{}
	for _, l := range lines {
		if k, v, ok := strings.Cut(l, "="); ok && !strings.Contains(k, " ") && !strings.Contains(k, "\t") {
			kv[k] = strings.TrimSpace(v)
		}
	}
	return kv
}

var apkRe = regexp.MustCompile(`^(\S+?)-(\d\S*-r\d+)\s.*upgradable from: \S+?-(\d\S*-r\d+)`)

func parsePackages(pm string, lines []string) []Package {
	var out []Package
	for _, l := range lines {
		f := strings.Fields(l)
		switch pm {
		case "apt":
			// name/suite version arch [upgradable from: old]
			if len(f) < 2 || !strings.Contains(f[0], "/") {
				continue
			}
			name, suite, _ := strings.Cut(f[0], "/")
			p := Package{Name: name, Latest: f[1], Security: strings.Contains(suite, "-security")}
			if i := strings.Index(l, "from: "); i >= 0 {
				p.Version = strings.TrimSuffix(strings.TrimSpace(l[i+6:]), "]")
			}
			out = append(out, p)
		case "dnf", "yum":
			// name.arch version repo
			if len(f) != 3 || !strings.Contains(f[0], ".") || strings.HasPrefix(l, " ") {
				continue
			}
			if f[0] == "Obsoleting" || strings.HasSuffix(f[0], ":") {
				continue
			}
			name := f[0][:strings.LastIndex(f[0], ".")]
			out = append(out, Package{Name: name, Latest: f[1]})
		case "zypper":
			// v | repo | name | current | available | arch
			parts := strings.Split(l, "|")
			if len(parts) < 5 || strings.TrimSpace(parts[0]) != "v" {
				continue
			}
			out = append(out, Package{
				Name:    strings.TrimSpace(parts[2]),
				Version: strings.TrimSpace(parts[3]),
				Latest:  strings.TrimSpace(parts[4]),
			})
		case "apk":
			if m := apkRe.FindStringSubmatch(l); m != nil {
				out = append(out, Package{Name: m[1], Latest: m[2], Version: m[3]})
			}
		case "pacman":
			// name old -> new
			if len(f) >= 4 && f[2] == "->" {
				out = append(out, Package{Name: f[0], Version: f[1], Latest: f[3]})
			}
		}
	}
	return out
}

var (
	epochRe    = regexp.MustCompile(`^[0-9]+:`)
	revisionRe = regexp.MustCompile(`-[^-]*$`)
)

// prettyVersion drops a package's epoch and revision: 5:27.3.1-1~ubuntu → 27.3.1.
func prettyVersion(v string) string {
	v = epochRe.ReplaceAllString(strings.TrimSpace(v), "")
	if s := revisionRe.ReplaceAllString(v, ""); s != "" {
		v = s
	}
	for _, sep := range []string{"+dfsg", "~"} {
		if i := strings.Index(v, sep); i > 0 {
			v = v[:i]
		}
	}
	return v
}

func normVersion(v string) string {
	return epochRe.ReplaceAllString(strings.TrimSpace(v), "")
}

// MarshalPackages is the packages column.
func MarshalPackages(pkgs []Package) []byte {
	if pkgs == nil {
		pkgs = []Package{}
	}
	b, _ := json.Marshal(pkgs)
	return b
}

// programOf is the program a shell command starts with, when it's a plain
// name (no assignment, path trickery or subshell).
func programOf(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return ""
	}
	for _, c := range f[0] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '/') {
			return ""
		}
	}
	return f[0]
}
