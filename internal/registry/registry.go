// Package registry deploys and talks to package registries Morche runs on a
// server as compose projects: Harbor (container images, Helm charts) and
// Verdaccio (npm). It only writes the scripts and files and speaks the
// registries' HTTP APIs; the api package runs the scripts over SSH and
// reaches the APIs through an SSH tunnel to the server's loopback.
package registry

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"regexp"
	"strings"
)

const (
	Harbor    = "harbor"
	Verdaccio = "verdaccio"

	// Versions Morche deploys. Harbor's installer is downloaded from its
	// GitHub release; Verdaccio is one image.
	HarborVersion    = "v2.15.5"
	VerdaccioVersion = "6.11.3"
)

// Kind describes one kind of registry for the panel.
type RegistryKind struct {
	Kind        string   `json:"kind" enum:"harbor,verdaccio"`
	Label       string   `json:"label"`
	Version     string   `json:"version"`
	Formats     []string `json:"formats" doc:"What it holds: docker, helm, npm"`
	License     string   `json:"license"`
	DefaultPort int      `json:"default_port"`
	// Memory it needs to run well, and below which Morche refuses.
	MemoryMB    int `json:"memory_mb"`
	MinMemoryMB int `json:"min_memory_mb"`
	DiskGB      int `json:"disk_gb"`
}

var Kinds = []RegistryKind{
	{Kind: Harbor, Label: "Harbor", Version: HarborVersion, Formats: []string{"docker", "helm"}, License: "Apache-2.0",
		DefaultPort: 8480, MemoryMB: 4096, MinMemoryMB: 1800, DiskGB: 40},
	{Kind: Verdaccio, Label: "Verdaccio", Version: VerdaccioVersion, Formats: []string{"npm"}, License: "MIT",
		DefaultPort: 4873, MemoryMB: 512, MinMemoryMB: 256, DiskGB: 5},
}

func KindOf(k string) (RegistryKind, bool) {
	for _, x := range Kinds {
		if x.Kind == k {
			return x, true
		}
	}
	return RegistryKind{}, false
}

// Settings are what a registry is set up with; each kind reads its part.
type RegistrySettings struct {
	// Who can pull/install without signing in: public = anyone who reaches
	// it, private = signed-in only.
	Public bool `json:"public" doc:"Anyone who reaches it can pull or install without signing in"`
	// Harbor: a proxy-cache project for Docker Hub; Verdaccio: npmjs as uplink.
	Mirror bool `json:"mirror" doc:"Harbor: a Docker Hub cache project; Verdaccio: fetch and keep packages from npmjs"`
	// Harbor: name of the cache project.
	MirrorProject string `json:"mirror_project,omitempty" doc:"Harbor: the cache project's name (default dockerhub)"`
	// Harbor: install the Trivy scanner.
	Scanner bool `json:"scanner,omitempty" doc:"Harbor: install the Trivy vulnerability scanner"`
	// Harbor: weekly garbage collection.
	Cleanup bool `json:"cleanup,omitempty" doc:"Harbor: free the space of deleted images every week"`
	// Verdaccio: scopes that are never fetched from npmjs (@company).
	Scopes []string `json:"scopes,omitempty" maxItems:"20" doc:"Verdaccio: private scopes like @company, never fetched from npmjs"`
	// Verdaccio: the npmjs (or other) address used as the mirror.
	Upstream string `json:"upstream,omitempty" doc:"Verdaccio: where the mirror fetches from (default https://registry.npmjs.org/)"`
}

var (
	scopeRe   = regexp.MustCompile(`^@[a-z0-9][a-z0-9._-]{0,100}$`)
	projectRe = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	userRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// Problem is a refused value; Field is named as in the JSON.
type Problem struct{ Field, Message string }

// Clean tidies s for kind and lists what's wrong.
func (s *RegistrySettings) Clean(kind string) []Problem {
	var out []Problem
	s.MirrorProject = strings.ToLower(strings.TrimSpace(s.MirrorProject))
	s.Upstream = strings.TrimSpace(s.Upstream)
	switch kind {
	case Harbor:
		s.Scopes, s.Upstream = nil, ""
		if s.MirrorProject == "" {
			s.MirrorProject = "dockerhub"
		}
		if !projectRe.MatchString(s.MirrorProject) || len(s.MirrorProject) > 255 || s.MirrorProject == "library" {
			out = append(out, Problem{"mirror_project", "Use lowercase letters, digits and . _ - (not library)"})
		}
	case Verdaccio:
		s.MirrorProject, s.Scanner, s.Cleanup = "", false, false
		var scopes []string
		for i, sc := range s.Scopes {
			sc = strings.ToLower(strings.TrimSpace(sc))
			if sc == "" {
				continue
			}
			if !strings.HasPrefix(sc, "@") {
				sc = "@" + sc
			}
			if !scopeRe.MatchString(sc) {
				out = append(out, Problem{"scopes[" + itoa(i) + "]", "A scope looks like @company"})
				continue
			}
			if !contains(scopes, sc) {
				scopes = append(scopes, sc)
			}
		}
		s.Scopes = scopes
		if s.Upstream == "" {
			s.Upstream = NPMJS
		}
		if !strings.HasPrefix(s.Upstream, "https://") && !strings.HasPrefix(s.Upstream, "http://") {
			out = append(out, Problem{"upstream", "Give an address starting with https://"})
		} else if !strings.HasSuffix(s.Upstream, "/") {
			s.Upstream += "/"
		}
	}
	return out
}

// ValidUser says whether name can be a Verdaccio user.
func ValidUser(name string) bool { return userRe.MatchString(name) }

// ValidRobot says whether name can be a Harbor robot account's name.
func ValidRobot(name string) bool { return userRe.MatchString(name) }

// Password makes a random password with upper, lower case and digits
// (Harbor asks for all three), n ≥ 12 characters.
func Password(n int) string {
	const (
		upper  = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		lower  = "abcdefghijkmnopqrstuvwxyz"
		digits = "23456789"
	)
	all := upper + lower + digits
	pick := func(set string) byte {
		i, _ := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		return set[i.Int64()]
	}
	b := []byte{pick(upper), pick(lower), pick(digits)}
	for len(b) < n {
		b = append(b, pick(all))
	}
	for i := len(b) - 1; i > 0; i-- {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		b[i], b[j.Int64()] = b[j.Int64()], b[i]
	}
	return string(b)
}

// B64 is how files travel inside scripts (hide it from the command log
// when the file holds secrets).
func B64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// Quote quotes s for a POSIX shell.
func Quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func itoa(i int) string {
	return big.NewInt(int64(i)).String()
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// composeDetect sets $C to the compose command the server has.
const composeDetect = `if docker compose version >/dev/null 2>&1; then C="docker compose"; elif command -v docker-compose >/dev/null 2>&1; then C=docker-compose; else echo "Docker Compose isn't installed on this server" >&2; exit 69; fi
`

// writeFile writes base64 text to a path through a temporary file.
func writeFile(path, text string) string {
	return "printf '%s' " + Quote(B64(text)) + " | base64 -d > " + Quote(path+".morche-tmp") + " && mv " + Quote(path+".morche-tmp") + " " + Quote(path) + "\n"
}

// Exit codes the scripts use.
const (
	ExitNoDocker  = 68
	ExitNoCompose = 69
	ExitNoFetch   = 70
)

// PreflightScript reports what deploying needs: Docker, Compose, memory,
// free space under dir's parent, and whether port is taken.
func PreflightScript(dir string, port int) string {
	return `p=` + Quote(dir) + `
while [ ! -d "$p" ]; do p=$(dirname "$p"); done
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then echo "docker=$(docker version --format '{{.Server.Version}}' 2>/dev/null)"; else echo docker=; fi
if docker compose version >/dev/null 2>&1; then echo "compose=$(docker compose version --short 2>/dev/null)"; elif command -v docker-compose >/dev/null 2>&1; then echo compose=v1; else echo compose=; fi
echo "mem=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null)"
echo "free=$(df -Pk "$p" 2>/dev/null | awk 'NR==2 {print int($4/1024/1024)}')"
if (ss -ltnH 2>/dev/null || netstat -ltn 2>/dev/null) | awk '{print $4}' | grep -Eq '[:.]` + itoa(port) + `$'; then echo port=taken; else echo port=free; fi
if [ -e ` + Quote(dir) + ` ]; then echo exists=1; else echo exists=0; fi
if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then echo fetch=1; else echo fetch=0; fi
echo "names=$(docker ps -a --format '{{.Names}}' 2>/dev/null | tr '\n' ',')"
`
}

// Preflight is what PreflightScript found.
type Preflight struct {
	Docker   string `json:"docker" doc:"Docker's version; empty when it isn't installed or running"`
	Compose  string `json:"compose"`
	MemoryMB int    `json:"memory_mb"`
	FreeGB   int    `json:"free_gb" doc:"Free disk space where it would go"`
	PortFree bool   `json:"port_free"`
	Exists   bool   `json:"exists" doc:"Its folder already exists"`
	Fetch    bool   `json:"fetch" doc:"curl or wget is installed"`
	// Containers already on the server (names), for clashes.
	Names []string `json:"-"`
}

func ParsePreflight(out string) Preflight {
	var p Preflight
	for l := range strings.SplitSeq(out, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(l), "=")
		switch k {
		case "docker":
			p.Docker = v
		case "compose":
			p.Compose = v
		case "mem":
			p.MemoryMB = atoi(v)
		case "free":
			p.FreeGB = atoi(v)
		case "port":
			p.PortFree = v == "free"
		case "exists":
			p.Exists = v == "1"
		case "fetch":
			p.Fetch = v == "1"
		case "names":
			for n := range strings.SplitSeq(v, ",") {
				if n != "" {
					p.Names = append(p.Names, n)
				}
			}
		}
	}
	return p
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// RemoveScript takes the project down with its data and removes its folder.
// keepData leaves the folder (images, packages) where it is.
func RemoveScript(dir, project string, keepData bool) string {
	s := composeDetect + `cd ` + Quote(dir) + ` 2>/dev/null || exit 0
$C -p ` + Quote(project) + ` down --remove-orphans 2>&1 || true
`
	if !keepData {
		s += `cd / && rm -rf ` + Quote(dir) + "\n"
	}
	return s
}

// ActionScript runs a compose verb (restart, stop, start, up -d) in dir.
func ActionScript(dir, project, verb string) string {
	return composeDetect + `cd ` + Quote(dir) + ` && $C -p ` + Quote(project) + ` ` + verb + " 2>&1\n"
}
