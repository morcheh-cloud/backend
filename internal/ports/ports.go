// Package ports finds what listens on a server, and says what each socket
// is: the process, its systemd unit, the container a port forwards to, and
// a best guess at the service behind it.
package ports

import (
	"cmp"
	"encoding/json"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ---- Report ----

type PortsReport struct {
	Ports []OpenPort `json:"ports"`
	Tool  string     `json:"tool" enum:"ss,netstat,none" doc:"What listed the sockets; none means neither ss nor netstat is installed"`
	// Without root, ss/netstat only name the login user's own processes.
	Privileged  bool         `json:"privileged" doc:"Read as root (the login user is root, or sudo -n works), so every socket's process is known"`
	Docker      DockerStatus `json:"docker"`
	CollectedAt time.Time    `json:"collected_at"`
}

type DockerStatus struct {
	Status     string `json:"status" enum:"ok,denied,error,absent" doc:"absent: no docker or podman CLI; denied: the login user can't reach the daemon"`
	Runtime    string `json:"runtime,omitempty" enum:"docker,podman"`
	Message    string `json:"message,omitempty" doc:"What the CLI said when it failed"`
	Containers int    `json:"containers" doc:"Running containers"`
}

type OpenPort struct {
	Protocol  string   `json:"protocol" enum:"tcp,udp"`
	Port      int      `json:"port" example:"5432"`
	Addresses []string `json:"addresses" doc:"Local addresses it is bound to; 0.0.0.0, :: and * mean every interface" example:"[\"0.0.0.0\",\"::\"]"`
	Exposure  string   `json:"exposure" enum:"public,private,local" doc:"public: every interface or a public address; private: a LAN/link-local address only; local: loopback only"`
	Service   string   `json:"service" doc:"Best guess at what this is; empty when nothing is known" example:"PostgreSQL"`
	// container/process: known for sure; port: only what the port number
	// usually carries.
	ServiceSource string         `json:"service_source" enum:"container,process,port,none"`
	Sensitive     bool           `json:"sensitive" doc:"A service that shouldn't be reachable from the internet (databases, caches, remote desktop…)"`
	Process       *PortProcess   `json:"process,omitempty"`
	Unit          *PortUnit      `json:"unit,omitempty"`
	Container     *PortContainer `json:"container,omitempty"`
}

type PortProcess struct {
	PID     int    `json:"pid"`
	PIDs    []int  `json:"pids" doc:"Every process holding the socket (e.g. a server's workers)"`
	Name    string `json:"name" example:"postgres"`
	User    string `json:"user,omitempty" example:"postgres"`
	Command string `json:"command,omitempty" example:"/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main"`
}

type PortUnit struct {
	Name        string `json:"name" example:"nginx.service"`
	Description string `json:"description,omitempty" example:"A high performance web server and a reverse proxy server"`
}

type PortContainer struct {
	ID             string `json:"id" doc:"Short (12 character) ID" example:"3f2a9c1b7d4e"`
	Name           string `json:"name" example:"app-db-1"`
	Image          string `json:"image" example:"postgres:18"`
	State          string `json:"state,omitempty" example:"running"`
	Network        string `json:"network,omitempty" doc:"Network mode; host means the container shares the server's network" example:"bridge"`
	ComposeProject string `json:"compose_project,omitempty" example:"app"`
	ComposeService string `json:"compose_service,omitempty" example:"db"`
	TargetPort     int    `json:"target_port,omitempty" doc:"The container's own port this host port forwards to (unset for host networking)" example:"5432"`
}

// ---- Parsing ----

type socket struct {
	proto string
	host  string
	port  int
	procs []procRef
}

type procRef struct {
	name string
	pid  int
}

type pidInfo struct {
	comm, user, cmdline, cgroup string
}

type container struct {
	ID      string                                         `json:"id"`
	Name    string                                         `json:"name"`
	Image   string                                         `json:"image"`
	State   string                                         `json:"state"`
	Network string                                         `json:"network"`
	Labels  map[string]string                              `json:"labels"`
	Ports   map[string][]struct{ HostIp, HostPort string } `json:"ports"`
}

// binding is one host port a container publishes.
type binding struct {
	c      *container
	target int
	hosts  []string
	used   bool
}

type collected struct {
	privileged bool
	tool       string
	sockets    []socket
	pids       map[int]pidInfo
	units      map[string]string
	docker     DockerStatus
	containers []*container
}

// Parse turns what Script printed into a report.
func Parse(out string, now time.Time) PortsReport {
	c := collect(out)
	return PortsReport{
		Ports:       c.ports(),
		Tool:        c.tool,
		Privileged:  c.privileged,
		Docker:      c.docker,
		CollectedAt: now,
	}
}

func collect(out string) *collected {
	c := &collected{
		tool:   "none",
		pids:   map[int]pidInfo{},
		units:  map[string]string{},
		docker: DockerStatus{Status: "absent"},
	}
	section := ""
	var unitBlock map[string]string
	flushUnit := func() {
		if id := unitBlock["Id"]; id != "" {
			c.units[id] = unitBlock["Description"]
		}
		unitBlock = map[string]string{}
	}
	for line := range strings.Lines(out) {
		line = strings.TrimRight(line, "\r\n")
		if marker, ok := strings.CutPrefix(line, "@"); ok {
			name, rest, _ := strings.Cut(marker, " ")
			switch name {
			case "priv":
				c.privileged = rest == "1"
			case "tool":
				c.tool = rest
			case "pid":
				c.addPid(rest)
				continue // keeps the current section
			case "units":
				unitBlock = map[string]string{}
			case "docker":
				status, rt, _ := strings.Cut(rest, " ")
				rt, msg, _ := strings.Cut(rt, " ")
				c.docker = DockerStatus{Status: status, Runtime: rt}
				if status != "ok" {
					c.docker.Message = strings.TrimSpace(msg)
					if strings.Contains(strings.ToLower(msg), "permission denied") {
						c.docker.Status = "denied"
					}
				}
			}
			section = name
			continue
		}
		switch section {
		case "sockets":
			if s, ok := parseSocket(c.tool, line); ok {
				c.sockets = append(c.sockets, s)
			}
		case "units":
			if line == "" {
				flushUnit()
			} else if k, v, ok := strings.Cut(line, "="); ok {
				unitBlock[k] = v
			}
		case "docker":
			var ct container
			if json.Unmarshal([]byte(line), &ct) == nil && ct.ID != "" {
				ct.Name = strings.TrimPrefix(ct.Name, "/")
				c.containers = append(c.containers, &ct)
			}
		}
	}
	if unitBlock != nil {
		flushUnit()
	}
	c.docker.Containers = len(c.containers)
	return c
}

func (c *collected) addPid(rest string) {
	f := strings.Split(rest, "\t")
	pid, err := strconv.Atoi(f[0])
	if err != nil {
		return
	}
	for len(f) < 5 {
		f = append(f, "")
	}
	c.pids[pid] = pidInfo{
		comm:    strings.TrimSpace(f[1]),
		user:    strings.TrimSpace(f[2]),
		cmdline: strings.TrimSpace(f[3]),
		cgroup:  f[4],
	}
}

var ssUsers = regexp.MustCompile(`\("([^"]*)",pid=(\d+)`)

// parseSocket reads one line of `ss -tulpn` or `netstat -tulpn`.
func parseSocket(tool, line string) (socket, bool) {
	f := strings.Fields(line)
	if len(f) < 5 {
		return socket{}, false
	}
	var s socket
	var local string
	switch tool {
	case "ss":
		// Netid State Recv-Q Send-Q Local Peer [Process]
		if len(f) < 6 {
			return socket{}, false
		}
		s.proto, local = f[0], f[4]
		for _, m := range ssUsers.FindAllStringSubmatch(strings.Join(f[6:], " "), -1) {
			pid, _ := strconv.Atoi(m[2])
			s.procs = append(s.procs, procRef{name: m[1], pid: pid})
		}
	case "netstat":
		// Proto Recv-Q Send-Q Local Foreign [State] PID/Program
		s.proto, local = strings.TrimSuffix(strings.TrimSuffix(f[0], "6"), "4"), f[3]
		if pid, name, ok := strings.Cut(f[len(f)-1], "/"); ok {
			if n, err := strconv.Atoi(pid); err == nil {
				s.procs = append(s.procs, procRef{name: name, pid: n})
			}
		}
	default:
		return socket{}, false
	}
	if s.proto != "tcp" && s.proto != "udp" {
		return socket{}, false
	}
	i := strings.LastIndexByte(local, ':')
	if i < 0 {
		return socket{}, false
	}
	port, err := strconv.Atoi(local[i+1:])
	if err != nil || port <= 0 {
		return socket{}, false
	}
	host := strings.Trim(local[:i], "[]")
	if j := strings.IndexByte(host, '%'); j >= 0 {
		host = host[:j]
	}
	s.host, s.port = host, port
	return s, true
}

var containerIDRe = regexp.MustCompile(`[0-9a-f]{64}`)

// ports joins sockets, processes and containers into one entry per service
// listening on a port (its IPv4 and IPv6 sockets together).
func (c *collected) ports() []OpenPort {
	bindings := map[string][]*binding{}
	byID := map[string]*container{}
	for _, ct := range c.containers {
		byID[ct.ID] = ct
		for spec, hosts := range ct.Ports {
			target, proto, _ := strings.Cut(spec, "/")
			t, _ := strconv.Atoi(target)
			perPort := map[string]*binding{}
			for _, h := range hosts {
				if h.HostPort == "" {
					continue
				}
				key := proto + "/" + h.HostPort
				b := perPort[key]
				if b == nil {
					b = &binding{c: ct, target: t}
					perPort[key] = b
					bindings[key] = append(bindings[key], b)
				}
				b.hosts = append(b.hosts, cmp.Or(h.HostIp, "0.0.0.0"))
			}
		}
	}

	type group struct {
		port      OpenPort
		container *container
		target    int
		pids      []int
		name      string
	}
	groups := map[string]*group{}
	var order []string
	add := func(key string, g *group, host string) *group {
		if have, ok := groups[key]; ok {
			g = have
		} else {
			groups[key] = g
			order = append(order, key)
		}
		if !slices.Contains(g.port.Addresses, host) {
			g.port.Addresses = append(g.port.Addresses, host)
		}
		return g
	}

	for _, s := range c.sockets {
		g := &group{port: OpenPort{Protocol: s.proto, Port: s.port}}
		for _, p := range s.procs {
			g.pids = append(g.pids, p.pid)
			if g.name == "" {
				g.name = p.name
			}
		}
		slices.Sort(g.pids)
		// A published port: whatever holds it on the host (docker-proxy,
		// rootlesskit, conmon…) forwards to the container.
		if bs := bindings[portKey(s.proto, s.port)]; len(bs) > 0 {
			b := matchBinding(bs, s.host)
			b.used = true
			g.container, g.target = b.c, b.target
		} else if len(g.pids) > 0 {
			// Host networking: the container's own process holds it.
			if id := containerIDRe.FindString(c.pids[g.pids[0]].cgroup); id != "" {
				g.container = byID[id]
			}
		}
		owner := "?"
		switch {
		case g.container != nil:
			owner = "c:" + g.container.ID
		case g.name != "":
			owner = "p:" + g.name
		}
		have := add(portKey(s.proto, s.port)+"|"+owner, g, s.host)
		if have != g {
			for _, pid := range g.pids {
				if !slices.Contains(have.pids, pid) {
					have.pids = append(have.pids, pid)
				}
			}
			slices.Sort(have.pids)
		}
	}

	// Published ports with no socket on the host: Docker with the userland
	// proxy off forwards them in iptables alone.
	for key, bs := range bindings {
		for _, b := range bs {
			if b.used {
				continue
			}
			proto, p, _ := strings.Cut(key, "/")
			port, _ := strconv.Atoi(p)
			g := &group{port: OpenPort{Protocol: proto, Port: port}, container: b.c, target: b.target}
			for _, h := range b.hosts {
				g = add(key+"|c:"+b.c.ID, g, h)
			}
		}
	}

	out := make([]OpenPort, 0, len(order))
	for _, key := range order {
		g := groups[key]
		p := g.port
		p.Exposure = exposure(p.Addresses)
		if len(g.pids) > 0 {
			info := c.pids[g.pids[0]]
			p.Process = &PortProcess{
				PID:     g.pids[0],
				PIDs:    g.pids,
				Name:    cmp.Or(info.comm, g.name),
				User:    info.user,
				Command: info.cmdline,
			}
			if u := unitOf(info.cgroup); u != "" && g.container == nil {
				p.Unit = &PortUnit{Name: u, Description: c.units[u]}
			}
		}
		if ct := g.container; ct != nil {
			p.Container = &PortContainer{
				ID:             ct.ID[:min(12, len(ct.ID))],
				Name:           ct.Name,
				Image:          ct.Image,
				State:          ct.State,
				Network:        ct.Network,
				ComposeProject: ct.Labels["com.docker.compose.project"],
				ComposeService: ct.Labels["com.docker.compose.service"],
				TargetPort:     g.target,
			}
		}
		describe(&p)
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b OpenPort) int {
		return cmp.Or(
			cmp.Compare(a.Port, b.Port),
			cmp.Compare(a.Protocol, b.Protocol),
			cmp.Compare(a.Service, b.Service),
		)
	})
	return out
}

func portKey(proto string, port int) string {
	return proto + "/" + strconv.Itoa(port)
}

// matchBinding picks the container publishing this host port on the
// socket's address (two containers can share a port on different IPs).
func matchBinding(bs []*binding, host string) *binding {
	for _, b := range bs {
		for _, h := range b.hosts {
			if h == host || (wildcard(h) && wildcard(host)) {
				return b
			}
		}
	}
	return bs[0]
}

func wildcard(host string) bool {
	return host == "" || host == "*" || host == "0.0.0.0" || host == "::"
}

// exposure is the widest reach among the addresses.
func exposure(addrs []string) string {
	best := "local"
	for _, a := range addrs {
		switch reach(a) {
		case "public":
			return "public"
		case "private":
			best = "private"
		}
	}
	return best
}

func reach(host string) string {
	if wildcard(host) {
		return "public"
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "public"
	}
	ip = ip.Unmap()
	switch {
	case ip.IsLoopback():
		return "local"
	case ip.IsPrivate(), ip.IsLinkLocalUnicast(), cgnat.Contains(ip):
		return "private"
	}
	return "public"
}

// Carrier-grade NAT (also Tailscale's range): not reachable from outside.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// unitOf is the systemd service a process runs under, from its cgroup
// (0::/system.slice/nginx.service).
func unitOf(cgroup string) string {
	var unit string
	for part := range strings.FieldsFuncSeq(cgroup, func(r rune) bool { return r == '/' || r == ' ' || r == ':' }) {
		if strings.HasSuffix(part, ".service") && !strings.HasPrefix(part, "user@") {
			unit = part
		}
	}
	return unit
}

// describe fills in Service, ServiceSource and Sensitive.
func describe(p *OpenPort) {
	port := wellKnown[portKey(p.Protocol, p.Port)]
	if ct := p.Container; ct != nil {
		p.ServiceSource = "container"
		target := wellKnown[portKey(p.Protocol, cmp.Or(ct.TargetPort, p.Port))]
		if k, ok := program(imageName(ct.Image)); ok {
			p.Service, p.Sensitive = k.name, k.sensitive
		} else if target.name != "" && !target.generic {
			p.Service, p.Sensitive = target.name, target.sensitive
		} else {
			p.Service = cmp.Or(ct.ComposeService, ct.Name)
		}
		return
	}
	if pr := p.Process; pr != nil {
		p.ServiceSource = "process"
		p.Sensitive = port.sensitive
		// comm can be a thread name (node-MainThread); argv[0] is the binary.
		names := []string{pr.Name}
		if f := strings.Fields(pr.Command); len(f) > 0 {
			names = append(names, strings.TrimSuffix(path.Base(f[0]), ":"))
		}
		for _, n := range names {
			if k, ok := program(n); ok {
				p.Service, p.Sensitive = k.name, k.sensitive
				return
			}
		}
		lang, isInterp := interpreter(names[0])
		if !isInterp && len(names) > 1 {
			lang, isInterp = interpreter(names[1])
		}
		if isInterp {
			// gunicorn, uvicorn, jupyter… run as `python3 /usr/bin/gunicorn`.
			if script := scriptName(pr.Command); script != "" {
				if k, ok := program(strings.TrimSuffix(script, path.Ext(script))); ok {
					p.Service, p.Sensitive = k.name, k.sensitive
					return
				}
			}
		}
		if p.Unit != nil {
			p.Service = strings.TrimSuffix(p.Unit.Name, ".service")
			return
		}
		if isInterp {
			p.Service = lang
			if script := scriptName(pr.Command); script != "" {
				p.Service += " · " + script
			}
			return
		}
		p.Service = pr.Name
		// The kernel cuts comm at 15 characters ("next-server (v1").
		if len(pr.Name) == 15 && len(names) > 1 {
			p.Service = names[1]
		}
		return
	}
	if port.name != "" {
		p.Service, p.ServiceSource, p.Sensitive = port.name, "port", port.sensitive
		return
	}
	p.ServiceSource = "none"
}

// scriptName is the program an interpreter runs: its first argument that
// isn't a flag (`node --enable-x dist/server.js` → server.js).
func scriptName(cmdline string) string {
	f := strings.Fields(cmdline)
	for i := 1; i < len(f); i++ {
		a := f[i]
		if a == "-m" && i+1 < len(f) {
			return f[i+1]
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return path.Base(a)
	}
	return ""
}
