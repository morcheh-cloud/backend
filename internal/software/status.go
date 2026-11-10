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

// Image is one container of a Docker app.
type Image struct {
	Service string `json:"service"`
	Image   string `json:"image"`
	// The image's repo digests (sha256:…), as the server has them.
	Digests []string `json:"digests,omitempty"`
	Version string   `json:"version,omitempty"`
	State   string   `json:"state"`
	// What the registry has under the same tag; empty if unknown.
	LatestDigest string `json:"latest_digest,omitempty"`
	Update       bool   `json:"update,omitempty"`
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
	// "morcheh" when Morcheh installed it (a Docker app in AppsDir), else
	// "found".
	Origin          string
	Version         string
	Latest          string
	UpdateAvailable bool
	// Docker apps: running | stopped | partial.
	State       string
	Images      []Image
	Dir         string
	Project     string
	CanRollback bool
	Pinned      bool
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
	// The host's packages, every Docker app folder and every container.
	Full bool
	// Only these Docker apps (when not Full).
	Apps []string
}

// ScanScript lists what of recipes is on the server. It runs as root when
// it can (to refresh the package lists), but works as any user.
func ScanScript(recipes []Recipe, opt ScanOptions) string {
	var b strings.Builder
	b.WriteString(lib)
	b.WriteString("set +e\n")
	b.WriteString("ROOT=0; [ \"$(id -u)\" = 0 ] && ROOT=1\n")
	b.WriteString("DOCKER=0; docker info >/dev/null 2>&1 && DOCKER=1\n")
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
		if r.Kind == KindDocker {
			continue
		}
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
	// Docker apps: every folder in AppsDir (or just the asked ones).
	b.WriteString("if [ \"$DOCKER\" = 1 ]; then\n")
	if opt.Full {
		fmt.Fprintf(&b, "  apps=$(ls -1 %s 2>/dev/null)\n", AppsDir)
	} else {
		fmt.Fprintf(&b, "  apps=%q\n", strings.Join(opt.Apps, " "))
	}
	fmt.Fprintf(&b, `  for id in $apps; do
    d=%s/$id
    [ -f "$d/compose.yml" ] || continue
    echo "@@ app:$id"
    [ -f "$d/compose.rollback.yml" ] && echo rollback=1
    [ -f "$d/compose.override.yml" ] && echo pinned=1
    echo "services=$(cd "$d" && COMPOSE_PROJECT_NAME=morcheh-$id docker compose config --services 2>/dev/null | tr '\n' ' ')"
    for c in $(docker ps -a -q --filter "label=com.docker.compose.project=morcheh-$id"); do
      line=$(docker inspect --format '{{.Image}}	{{index .Config.Labels "com.docker.compose.service"}}	{{.Config.Image}}	{{.State.Status}}' "$c" 2>/dev/null) || continue
      info=$(docker image inspect --format '{{join .RepoDigests ","}}	{{index .Config.Labels "org.opencontainers.image.version"}}' "${line%%%%	*}" 2>/dev/null)
      printf 'c\t%%s\t%%s\n' "$line" "$info"
    done
  done
`, AppsDir)
	if opt.Full {
		b.WriteString(`  echo '@@ containers'
  docker ps -a --format '{{.ID}}	{{.Image}}	{{.State}}	{{.Label "com.docker.compose.project"}}	{{.Label "com.docker.compose.service"}}	{{.Label "com.docker.compose.project.working_dir"}}' 2>/dev/null | while IFS= read -r line; do
    case "$line" in *"	morcheh-"*) continue ;; esac
    info=$(docker image inspect --format '{{join .RepoDigests ","}}	{{index .Config.Labels "org.opencontainers.image.version"}}' "$(docker inspect --format '{{.Image}}' "${line%%	*}" 2>/dev/null)" 2>/dev/null)
    printf '%s\t%s\n' "$line" "$info"
  done
`)
	}
	b.WriteString("fi\nexit 0\n")
	return b.String()
}

// ParseScan reads ScanScript's output.
func ParseScan(out string, recipes []Recipe, opt ScanOptions) Scan {
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
		if r.Kind == KindDocker {
			if opt.Full || slices.Contains(opt.Apps, r.ID) {
				s.Looked = append(s.Looked, r.ID)
			}
			continue
		}
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
	for name, body := range sections {
		id, ok := strings.CutPrefix(name, "app:")
		if !ok {
			continue
		}
		f := parseApp(id, body, recipes)
		if !slices.Contains(s.Looked, id) {
			s.Looked = append(s.Looked, id)
		}
		s.Software = append(s.Software, f)
	}
	if c, ok := sections["containers"]; ok {
		s.Software = append(s.Software, foundContainers(c, recipes, s.Software)...)
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

func parseApp(id string, lines []string, recipes []Recipe) Found {
	kv := keyValues(lines)
	f := Found{
		RecipeID:    id,
		Name:        id,
		Kind:        KindDocker,
		Origin:      "morcheh",
		Dir:         Dir(id),
		Project:     Project(id),
		CanRollback: kv["rollback"] == "1",
		Pinned:      kv["pinned"] == "1",
	}
	if r, ok := Find(recipes, id); ok {
		f.Name = r.Name
	}
	for _, l := range lines {
		rest, ok := strings.CutPrefix(l, "c\t")
		if !ok {
			continue
		}
		// image id, service, image, state, digests, version
		p := strings.Split(rest, "\t")
		for len(p) < 6 {
			p = append(p, "")
		}
		f.Images = append(f.Images, Image{
			Service: p[1], Image: p[2], State: p[3],
			Digests: splitDigests(p[4]), Version: strings.TrimSpace(p[5]),
		})
	}
	services := strings.Fields(kv["services"])
	f.State = appState(f.Images, len(services))
	f.Version = appVersion(f.Images)
	f.Latest = f.Version
	return f
}

func appState(images []Image, services int) string {
	running := 0
	for _, i := range images {
		if i.State == "running" {
			running++
		}
	}
	total := max(services, len(images))
	switch {
	case total == 0 || running == 0:
		return "stopped"
	case running >= total:
		return "running"
	default:
		return "partial"
	}
}

// appVersion is the first image's version label, else its tag.
func appVersion(images []Image) string {
	for _, i := range images {
		if i.Version != "" {
			return i.Version
		}
	}
	for _, i := range images {
		if _, tag := splitTag(i.Image); tag != "" {
			return tag
		}
	}
	return ""
}

func splitDigests(s string) []string {
	var out []string
	for d := range strings.SplitSeq(s, ",") {
		if _, h, ok := strings.Cut(strings.TrimSpace(d), "@"); ok && h != "" {
			out = append(out, h)
		}
	}
	return out
}

// foundContainers are containers Morcheh didn't start whose image is one of
// a recipe's, grouped by compose project (or by container).
func foundContainers(lines []string, recipes []Recipe, have []Found) []Found {
	byRepo := map[string]Recipe{}
	for _, r := range recipes {
		if r.Kind != KindDocker {
			continue
		}
		for _, img := range r.Images() {
			repo, _ := splitTag(img)
			byRepo[NormalizeRepo(repo)] = r
		}
	}
	var out []Found
	for _, l := range lines {
		p := strings.Split(l, "\t")
		for len(p) < 8 {
			p = append(p, "")
		}
		// id, image, state, project, service, dir, digests, version
		img, state, proj, svc, dir := p[1], p[2], p[3], p[4], p[5]
		repo, _ := splitTag(img)
		r, ok := byRepo[NormalizeRepo(repo)]
		if !ok {
			continue
		}
		if slices.ContainsFunc(have, func(f Found) bool { return f.RecipeID == r.ID }) ||
			slices.ContainsFunc(out, func(f Found) bool { return f.RecipeID == r.ID && f.Project != proj }) {
			// One record per recipe and server: the first one wins.
			continue
		}
		image := Image{Service: cmpOr(svc, r.ID), Image: img, State: state, Digests: splitDigests(p[6]), Version: strings.TrimSpace(p[7])}
		if i := slices.IndexFunc(out, func(f Found) bool { return f.RecipeID == r.ID }); i >= 0 {
			out[i].Images = append(out[i].Images, image)
			continue
		}
		out = append(out, Found{
			RecipeID: r.ID, Name: r.Name, Kind: KindDocker, Origin: "found",
			Dir: dir, Project: proj, Images: []Image{image},
		})
	}
	for i := range out {
		out[i].State = appState(out[i].Images, 0)
		out[i].Version = appVersion(out[i].Images)
		out[i].Latest = out[i].Version
	}
	return out
}

// splitTag splits "repo:tag" (a registry port isn't a tag).
func splitTag(ref string) (string, string) {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	slash := strings.LastIndex(ref, "/")
	if i := strings.LastIndex(ref, ":"); i > slash {
		return ref[:i], ref[i+1:]
	}
	return ref, ""
}

// NormalizeRepo makes "grafana/grafana", "docker.io/grafana/grafana" and
// "registry-1.docker.io/grafana/grafana" the same, and "redis" the same as
// "library/redis".
func NormalizeRepo(repo string) string {
	repo = strings.ToLower(repo)
	for _, p := range []string{"docker.io/", "index.docker.io/", "registry-1.docker.io/"} {
		repo = strings.TrimPrefix(repo, p)
	}
	if !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}
	return repo
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

// MarshalImages is the images column.
func MarshalImages(images []Image) []byte {
	if images == nil {
		images = []Image{}
	}
	b, _ := json.Marshal(images)
	return b
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
