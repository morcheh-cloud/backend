package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Runtimes a proxy can run in besides the server itself (RuntimeHost).
const (
	RuntimeHost   = "host"
	RuntimeDocker = "docker"
	RuntimePodman = "podman"
)

// Exit codes of Container.Run when it couldn't reach the container; the
// driver's scripts never use them.
const (
	ExitNoRuntime        = 120 // docker/podman isn't on the server
	ExitNoContainer      = 121 // no container with that name
	ExitContainerStopped = 122 // it's there but not running
)

// hostPath finds docker/podman through sudo's secure_path quirks (snap too).
const hostPath = "PATH=$PATH:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/snap/bin\n"

var containerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

// ValidContainerName says whether s is a name docker or podman accepts.
func ValidContainerName(s string) bool { return containerName.MatchString(s) }

// Container is a proxy running in a container on its server: every driver
// script runs inside it through `<runtime> exec`, with the same paths as on
// a server (the official images keep nginx's own layout).
type Container struct {
	Runtime string // RuntimeDocker or RuntimePodman
	Name    string
}

// Label is the runtime as people know it.
func (c Container) Label() string {
	if c.Runtime == RuntimePodman {
		return "Podman"
	}
	return "Docker"
}

// Host is a host-side command calling the runtime (quoted name and all).
func (c Container) Host(args string) string {
	return c.Runtime + " " + strings.ReplaceAll(args, "@", shq(c.Name))
}

// Run wraps a script to run as root inside the container. It is a host
// script: a subshell that stops with ExitNoRuntime, ExitNoContainer or
// ExitContainerStopped (and a line on stderr) when it can't get in, else
// exits with the script's own status. The script reaches the container on
// stdin and runs from a temporary file, so it may use heredocs; its own
// stdin is empty.
func (c Container) Run(script string) string {
	sum := sha256.Sum256([]byte(script))
	eof := "MORCHEH_IN_" + hex.EncodeToString(sum[:6])
	inner := `f=$(mktemp) && cat > "$f" && { sh "$f" </dev/null; r=$?; rm -f "$f"; exit $r; }`
	if !strings.HasSuffix(script, "\n") {
		script += "\n"
	}
	return "(\n" + c.Check() + c.Runtime + " exec -i -u 0 " + shq(c.Name) + " sh -c " + shq(inner) + " <<'" + eof + "'\n" +
		script + eof + "\n)\n"
}

// Check is a host script that exits like Run when the container can't be
// reached, and carries on when it runs.
func (c Container) Check() string {
	n := shq(c.Name)
	rt := c.Runtime
	return hostPath + `command -v ` + rt + ` >/dev/null 2>&1 || { echo "` + c.Label() + ` isn't installed on this server" >&2; exit ` + strconv.Itoa(ExitNoRuntime) + `; }
s=$(` + rt + ` inspect --type container -f '{{.State.Running}}' ` + n + ` 2>/dev/null)
case "$s" in
true) ;;
false) echo "The container ` + c.Name + ` isn't running" >&2; exit ` + strconv.Itoa(ExitContainerStopped) + ` ;;
*) echo "There's no container named ` + c.Name + ` on this server" >&2; exit ` + strconv.Itoa(ExitNoContainer) + ` ;;
esac
`
}

// HostDir is the folder on the server holding what Morcheh keeps there for
// this container (certbot's hooks, log rotation).
func (c Container) HostDir() string { return "/etc/morcheh/proxy/" + c.Runtime + "-" + c.Name }

// CronFile is the cron.d entry for this container (cron skips names with
// dots).
func (c Container) CronFile() string {
	return "/etc/cron.d/morcheh-proxy-" + c.Runtime + "-" + strings.ReplaceAll(c.Name, ".", "_")
}

// HostPath is the PATH line host scripts start with.
func HostPath() string { return hostPath }

// PushFn is a host script defining push FILE...: each file of the server
// that exists is copied into the container at the same path, unless it's
// already there unchanged (one exec compares them all). Folders are made,
// the mode is kept and a symlink inside is written through. It returns 1
// when one couldn't be copied, saying which on stderr.
func (c Container) PushFn() string {
	ex := c.Runtime + " exec -i -u 0 " + shq(c.Name)
	return `push() {
  have=$(` + c.Runtime + ` exec -u 0 ` + shq(c.Name) + ` sh -c 'for f in "$@"; do [ -f "$f" ] && printf "%s %s\n" "$(cksum < "$f")" "$f"; done; exit 0' sh "$@" 2>/dev/null | tr -s ' ')
  rc=0
  for f in "$@"; do
    [ -f "$f" ] || continue
    want="$(cksum < "$f" | tr -s ' ') $f"
    printf '%s\n' "$have" | grep -qxF "$want" && continue
    m=$(stat -L -c %a "$f" 2>/dev/null) || m=600
    ` + ex + ` sh -c 'mkdir -p "$(dirname "$1")" || exit 1
if [ -L "$1" ]; then cat > "$1"; else cat > "$1.morcheh-new" && chmod "$2" "$1.morcheh-new" && mv -f "$1.morcheh-new" "$1"; fi' sh "$f" "$m" < "$f" || { echo "Couldn't copy $f into the container ` + c.Name + `" >&2; rc=1; }
  done
  return $rc
}
`
}

// Push is a host script copying files of the server into the container
// (see PushFn); it exits like Check when the container can't be reached.
func (c Container) Push(paths ...string) string {
	q := make([]string, len(paths))
	for i, p := range paths {
		q[i] = shq(p)
	}
	return hostPath + c.Check() + c.PushFn() + "push " + strings.Join(q, " ") + "\n"
}

// shq quotes s for sh.
func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// ---- What the runtime says about a container ----

// ContainerPort is one published port: Port/Proto inside, HostPort on the
// server (on HostIP, "" = every address).
type ContainerPort struct {
	Port     int    `json:"port"`
	Proto    string `json:"proto" enum:"tcp,udp"`
	HostIP   string `json:"host_ip,omitempty"`
	HostPort int    `json:"host_port"`
}

// ContainerMount is a folder of the server (or a volume) inside it.
type ContainerMount struct {
	Type        string `json:"type" doc:"bind, volume or tmpfs"`
	Source      string `json:"source" doc:"The folder on the server (for a volume, where the runtime keeps it)"`
	Destination string `json:"destination" doc:"Where it appears inside the container"`
	Name        string `json:"name,omitempty" doc:"The volume's name"`
	ReadOnly    bool   `json:"read_only,omitempty"`
}

// ContainerNetwork is a network it's attached to.
type ContainerNetwork struct {
	Name    string   `json:"name"`
	IP      string   `json:"ip,omitempty"`
	Gateway string   `json:"gateway,omitempty" doc:"The server's own address on this network: how the container reaches programs on the server"`
	Aliases []string `json:"aliases,omitempty"`
}

// ContainerInfo is what docker/podman inspect says about it.
type ContainerInfo struct {
	Runtime     string             `json:"runtime" enum:"docker,podman"`
	Name        string             `json:"name"`
	ID          string             `json:"id"`
	Image       string             `json:"image"`
	State       string             `json:"state" doc:"running, exited, paused, restarting, created…"`
	Running     bool               `json:"running"`
	Pid         int                `json:"pid,omitempty"`
	NetworkMode string             `json:"network_mode" doc:"host = shares the server's network; else a bridge (ports must be published)"`
	Networks    []ContainerNetwork `json:"networks"`
	Ports       []ContainerPort    `json:"ports"`
	Mounts      []ContainerMount   `json:"mounts"`
	Restart     string             `json:"restart" doc:"Restart policy: no, always, unless-stopped, on-failure"`
	Compose     string             `json:"compose,omitempty" doc:"The Compose project it belongs to"`
	Service     string             `json:"service,omitempty" doc:"Its Compose service"`
	ComposeDir  string             `json:"compose_dir,omitempty" doc:"The Compose project's folder on the server"`
	Managed     string             `json:"managed,omitempty" doc:"The image is a proxy manager that writes nginx's config itself (Nginx Proxy Manager, nginx-proxy, SWAG): Morcheh doesn't take it over"`
}

// HostNetwork: it shares the server's network (no publishing needed).
func (c ContainerInfo) HostNetwork() bool { return c.NetworkMode == "host" }

// Published says whether port/proto inside is reachable from outside: with
// the host network always, else when it's published.
func (c ContainerInfo) Published(port int, proto string) bool {
	if c.HostNetwork() {
		return true
	}
	return slices.ContainsFunc(c.Ports, func(p ContainerPort) bool { return p.Port == port && p.Proto == proto })
}

// InsidePath maps a folder of the server to where the container sees it
// (through a bind mount or a volume), "" when it can't.
func (c ContainerInfo) InsidePath(hostPath string) string {
	hostPath = path.Clean(hostPath)
	best, out := -1, ""
	for _, m := range c.Mounts {
		src := path.Clean(m.Source)
		if m.Source == "" || (hostPath != src && !strings.HasPrefix(hostPath, strings.TrimSuffix(src, "/")+"/")) {
			continue
		}
		if len(src) > best {
			best, out = len(src), path.Join(m.Destination, strings.TrimPrefix(hostPath, src))
		}
	}
	return out
}

// managers are images that write nginx's config themselves.
var managers = []struct{ match, label string }{
	{"nginx-proxy-manager", "Nginx Proxy Manager"},
	{"nginxproxy/nginx-proxy", "nginx-proxy"},
	{"jwilder/nginx-proxy", "nginx-proxy"},
	{"nginx-proxy", "nginx-proxy"},
	{"docker-gen", "docker-gen"},
	{"linuxserver/swag", "SWAG"},
	{"linuxserver/letsencrypt", "SWAG"},
}

// ManagerOf names the proxy manager an image is, "" when it isn't one.
func ManagerOf(image string) string {
	image = strings.ToLower(image)
	for _, m := range managers {
		if strings.Contains(image, m.match) {
			return m.label
		}
	}
	return ""
}

// rawInspect is the part of `docker inspect` (and podman's, which follows it)
// Morcheh reads.
type rawInspect struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	Image string `json:"Image"`
	State struct {
		Status  string `json:"Status"`
		Running bool   `json:"Running"`
		Pid     int    `json:"Pid"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode   string `json:"NetworkMode"`
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
		PortBindings map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"PortBindings"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
		Networks map[string]struct {
			IPAddress string   `json:"IPAddress"`
			Gateway   string   `json:"Gateway"`
			Aliases   []string `json:"Aliases"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
}

// ParseContainers reads the JSON array `<runtime> inspect` prints.
func ParseContainers(runtime, out string) ([]ContainerInfo, error) {
	var raw []rawInspect
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &raw); err != nil {
		return nil, fmt.Errorf("reading %s inspect: %w", runtime, err)
	}
	list := make([]ContainerInfo, 0, len(raw))
	for _, r := range raw {
		c := ContainerInfo{
			Runtime: runtime, Name: strings.TrimPrefix(r.Name, "/"), ID: r.ID, Image: r.Config.Image,
			State: r.State.Status, Running: r.State.Running, NetworkMode: r.HostConfig.NetworkMode,
			Restart: r.HostConfig.RestartPolicy.Name, Networks: []ContainerNetwork{}, Ports: []ContainerPort{},
			Mounts: []ContainerMount{},
		}
		if len(c.ID) > 12 {
			c.ID = c.ID[:12]
		}
		if c.Image == "" {
			c.Image = r.Image
		}
		if c.Running {
			c.Pid = r.State.Pid
		}
		if c.Restart == "" {
			c.Restart = "no"
		}
		if c.NetworkMode == "" || c.NetworkMode == "default" {
			c.NetworkMode = "bridge"
		}
		c.Compose = r.Config.Labels["com.docker.compose.project"]
		c.Service = r.Config.Labels["com.docker.compose.service"]
		c.ComposeDir = r.Config.Labels["com.docker.compose.project.working_dir"]
		c.Managed = ManagerOf(c.Image)
		for name, n := range r.NetworkSettings.Networks {
			aliases := slices.DeleteFunc(slices.Clone(n.Aliases), func(a string) bool { return strings.HasPrefix(c.ID, a) || a == "" })
			c.Networks = append(c.Networks, ContainerNetwork{Name: name, IP: n.IPAddress, Gateway: n.Gateway, Aliases: aliases})
		}
		slices.SortFunc(c.Networks, func(a, b ContainerNetwork) int { return strings.Compare(a.Name, b.Name) })
		ports := r.NetworkSettings.Ports
		if len(ports) == 0 || !c.Running {
			ports = r.HostConfig.PortBindings // a stopped container still says what it publishes
		}
		seen := map[string]bool{}
		for spec, binds := range ports {
			p, proto, _ := strings.Cut(spec, "/")
			n, err := strconv.Atoi(p)
			if err != nil {
				continue
			}
			if proto == "" {
				proto = "tcp"
			}
			for _, b := range binds {
				hp, _ := strconv.Atoi(b.HostPort)
				key := fmt.Sprintf("%d/%s/%d", n, proto, hp)
				if hp == 0 || seen[key] {
					continue // the same port on 0.0.0.0 and :: counts once
				}
				seen[key] = true
				ip := b.HostIP
				if ip == "0.0.0.0" || ip == "::" {
					ip = ""
				}
				c.Ports = append(c.Ports, ContainerPort{Port: n, Proto: proto, HostIP: ip, HostPort: hp})
			}
		}
		slices.SortFunc(c.Ports, func(a, b ContainerPort) int {
			if a.Port != b.Port {
				return a.Port - b.Port
			}
			return strings.Compare(a.Proto, b.Proto)
		})
		for _, m := range r.Mounts {
			c.Mounts = append(c.Mounts, ContainerMount{Type: m.Type, Source: m.Source, Destination: m.Destination, Name: m.Name, ReadOnly: !m.RW})
		}
		slices.SortFunc(c.Mounts, func(a, b ContainerMount) int { return strings.Compare(a.Destination, b.Destination) })
		list = append(list, c)
	}
	return list, nil
}

// ---- Detection: is the proxy on the server, in a container, or both ----

// Detection is what a driver's DetectScript found on a server.
type Detection struct {
	Native     NativeProxy     `json:"native"`
	Runtimes   []string        `json:"runtimes" doc:"Container runtimes found and working on the server"`
	Down       []string        `json:"down,omitempty" doc:"Runtimes installed but not answering (daemon stopped)"`
	Containers []ContainerInfo `json:"containers" doc:"Containers whose image or command looks like this proxy"`
}

// NativeProxy is the proxy installed on the server itself.
type NativeProxy struct {
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
	Running   bool   `json:"running"`
}

// DetectRuntimes is the part of a DetectScript that lists the containers
// whose `ps` line matches pattern (an extended regex, case-insensitive).
func DetectRuntimes(pattern string) string {
	return hostPath + `for rt in docker podman; do
  command -v $rt >/dev/null 2>&1 || continue
  if [ $rt = docker ] && docker --version 2>/dev/null | grep -qi podman; then continue; fi
  list=$($rt ps -a --no-trunc --format '{{.Names}}	{{.Image}}	{{.Command}}' 2>/dev/null) || { echo "down $rt"; continue; }
  echo "runtime $rt"
  names=$(printf '%s\n' "$list" | grep -iE '` + pattern + `' | cut -f1 | tr ',\n' '  ')
  [ -n "$(echo $names)" ] || continue
  echo "@@inspect $rt"
  $rt inspect --type container $names 2>/dev/null
  echo "@@end"
done
`
}

// ParseDetect reads a DetectScript's output: "native <version>",
// "native_running", "runtime <rt>", "down <rt>", and "@@inspect <rt>" …
// "@@end" blocks of inspect JSON.
func ParseDetect(out string) Detection {
	d := Detection{Runtimes: []string{}, Containers: []ContainerInfo{}}
	var block []string
	rt := ""
	for _, line := range strings.Split(out, "\n") {
		if rt != "" {
			if strings.TrimSpace(line) == "@@end" {
				if list, err := ParseContainers(rt, strings.Join(block, "\n")); err == nil {
					d.Containers = append(d.Containers, list...)
				}
				rt, block = "", nil
				continue
			}
			block = append(block, line)
			continue
		}
		line = strings.TrimSpace(line)
		key, val, _ := strings.Cut(line, " ")
		switch key {
		case "native":
			d.Native.Installed, d.Native.Version = true, strings.TrimSpace(val)
		case "native_running":
			d.Native.Running = true
		case "runtime":
			d.Runtimes = append(d.Runtimes, val)
		case "down":
			d.Down = append(d.Down, val)
		case "@@inspect":
			if val == RuntimeDocker || val == RuntimePodman {
				rt = val
			}
		}
	}
	slices.SortStableFunc(d.Containers, func(a, b ContainerInfo) int {
		if a.Running != b.Running {
			if a.Running {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	return d
}
