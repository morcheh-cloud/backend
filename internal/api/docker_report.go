package api

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/docker"
)

// A server's containers as one report: every container's state, uptime and
// live numbers, its networks, and which containers talk to which (read from
// the TCP tables of each container's network namespace).

const (
	reportFresh   = 8 * time.Second  // a report this young is reused as is
	reportStale   = 60 * time.Second // one this young is answered while a new one is taken
	reportTimeout = time.Minute      // a measurement taken in the background
	reportPoints  = 120              // live history points kept
	reportGap     = 9 * time.Second  // closest two history points
	reportSpark   = 30               // CPU points kept per container
	reportIdle    = 15 * time.Minute
	reportSockets = 6000 // TCP lines read per container
	reportPeers   = 5    // outside addresses listed per link
)

// ---- API shapes ----

type DockerReportEndpoint struct {
	Network string `json:"network"`
	IPv4    string `json:"ipv4,omitempty"`
	IPv6    string `json:"ipv6,omitempty"`
}

type DockerReportContainer struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Image       string                 `json:"image"`
	Project     string                 `json:"project,omitempty"`
	Service     string                 `json:"service,omitempty"`
	State       string                 `json:"state"`
	Status      string                 `json:"status"`
	Health      string                 `json:"health" enum:"healthy,unhealthy,starting,none"`
	Created     time.Time              `json:"created"`
	StartedAt   *time.Time             `json:"started_at,omitempty" doc:"Running: when it last started"`
	FinishedAt  *time.Time             `json:"finished_at,omitempty" doc:"Stopped: when it last ended"`
	Restarts    int                    `json:"restarts"`
	ExitCode    int                    `json:"exit_code"`
	OOMKilled   bool                   `json:"oom_killed"`
	Measured    bool                   `json:"measured"`
	CPU         float64                `json:"cpu" doc:"Percent of one core"`
	MemoryUsed  int64                  `json:"memory_used"`
	MemoryLimit int64                  `json:"memory_limit" doc:"Its own limit; 0 = none"`
	NetRxRate   float64                `json:"net_rx_rate"`
	NetTxRate   float64                `json:"net_tx_rate"`
	Pids        int64                  `json:"pids"`
	Ports       []DockerPortOut        `json:"ports"`
	Networks    []DockerReportEndpoint `json:"networks"`
	NetworkMode string                 `json:"network_mode"`
	Listening   []int                  `json:"listening" doc:"TCP ports it listens on (when its connections were read)"`
	Connections bool                   `json:"connections" doc:"Its connections were read"`
	CPUHistory  []float64              `json:"cpu_history" doc:"Recent CPU points, oldest first"`
}

type DockerReportNetwork struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Driver   string `json:"driver"`
	Internal bool   `json:"internal"`
	Builtin  bool   `json:"builtin"`
	Subnet   string `json:"subnet,omitempty"`
	Gateway  string `json:"gateway,omitempty"`
	Project  string `json:"project,omitempty"`
}

type DockerReportLink struct {
	From        string   `json:"from" doc:"Container id that opened the connections, or host / outside"`
	To          string   `json:"to" doc:"Container id that accepted them, or host / outside"`
	Port        int      `json:"port" doc:"The port connected to"`
	Connections int      `json:"connections" doc:"Open TCP connections now"`
	Up          float64  `json:"up" doc:"Bytes per second from → to (when bytes are read)"`
	Down        float64  `json:"down" doc:"Bytes per second to → from"`
	Peers       []string `json:"peers" doc:"Outside addresses, a few"`
}

type DockerReport struct {
	At          time.Time               `json:"at"`
	CPUs        int                     `json:"cpus"`
	HostMemory  int64                   `json:"host_memory"`
	CPU         float64                 `json:"cpu" doc:"Every measured container, percent of one core"`
	MemoryUsed  int64                   `json:"memory_used"`
	NetRxRate   float64                 `json:"net_rx_rate"`
	NetTxRate   float64                 `json:"net_tx_rate"`
	Unmeasured  int                     `json:"unmeasured" doc:"Running containers left out of this pass"`
	FirstSample bool                    `json:"first_sample" doc:"No earlier pass: rates aren't known yet"`
	Containers  []DockerReportContainer `json:"containers"`
	Networks    []DockerReportNetwork   `json:"networks"`
	Links       []DockerReportLink      `json:"links"`
	LinksState  string                  `json:"links_state" enum:"read,partial,unavailable" doc:"read = every running container's connections were read"`
	LinksNote   string                  `json:"links_note,omitempty"`
	LinkBytes   bool                    `json:"link_bytes" doc:"Bytes per connection were read (needs root, nsenter and ss)"`
	History     []DockerStatsPoint      `json:"history" doc:"Live totals while someone looks"`
	Day         []DockerHistoryPoint    `json:"day" doc:"Compose projects added up over 24 hours, 15-minute points"`
	DayStep     int                     `json:"day_step"`
}

// ---- State per server ----

type sockKey struct {
	pid           int
	local, remote string
}

type sockTotal struct {
	at              time.Time
	acked, received int64
}

type serverReport struct {
	run   sync.Mutex
	mu    sync.Mutex
	last  *DockerReport
	asked time.Time

	prev    map[string]netTotal
	socks   map[sockKey]sockTotal
	history []DockerStatsPoint
	sparks  map[string][]float64
}

var reportsByServer = struct {
	sync.Mutex
	m map[string]*serverReport
}{m: map[string]*serverReport{}}

func reportFor(id string) *serverReport {
	reportsByServer.Lock()
	defer reportsByServer.Unlock()
	for k, r := range reportsByServer.m {
		r.mu.Lock()
		idle := time.Since(r.asked) > reportIdle
		r.mu.Unlock()
		if idle && k != id {
			delete(reportsByServer.m, k)
		}
	}
	r := reportsByServer.m[id]
	if r == nil {
		r = &serverReport{prev: map[string]netTotal{}, socks: map[sockKey]sockTotal{}, sparks: map[string][]float64{}}
		reportsByServer.m[id] = r
	}
	return r
}

// ---- Measuring ----

func (h *serverHandler) dockerReport(ctx context.Context, id string) (DockerReport, error) {
	r := reportFor(id)
	r.mu.Lock()
	r.asked = time.Now()
	r.mu.Unlock()
	// Keep the compose projects' history recording while the report is open.
	ps := projectStatsFor(id)
	ps.mu.Lock()
	ps.asked = time.Now()
	ps.mu.Unlock()

	r.mu.Lock()
	last := r.last
	r.mu.Unlock()
	if last != nil && time.Since(last.At) < reportStale {
		// Answer the last report at once; a new one is taken behind it, so
		// the page never waits for every container to be measured.
		if time.Since(last.At) >= reportFresh && r.run.TryLock() {
			go func() {
				defer r.run.Unlock()
				bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), reportTimeout)
				defer cancel()
				if _, err := h.measureReport(bg, id, r); err != nil {
					slog.Debug("docker report: measure", "server", id, "error", err)
				}
			}()
		}
		return *last, nil
	}

	r.run.Lock()
	defer r.run.Unlock()
	r.mu.Lock()
	if r.last != nil && time.Since(r.last.At) < reportFresh {
		out := *r.last
		r.mu.Unlock()
		return out, nil
	}
	r.mu.Unlock()
	return h.measureReport(ctx, id, r)
}

// measureReport reads the server's containers and keeps the result; the
// caller holds r.run.
func (h *serverHandler) measureReport(ctx context.Context, id string, r *serverReport) (DockerReport, error) {
	var cs []docker.ContainerSummary
	var nets []docker.Network
	var ins map[string]docker.ContainerInspect
	var samples map[string]docker.Sample
	var socks netScan
	err := h.withDocker(ctx, id, func(e *dockerEngine) error {
		all, err := e.client.Containers(ctx)
		if err != nil {
			return err
		}
		cs = all
		if n, err := e.client.Networks(ctx); err == nil {
			nets = n
		}
		ins = inspectAll(ctx, e, cs)
		var wg sync.WaitGroup
		wg.Go(func() { samples = sampleRunning(ctx, id, e, cs) })
		wg.Go(func() { socks = h.scanSockets(ctx, id, e, cs, ins) })
		wg.Wait()
		return nil
	})
	if err != nil {
		return DockerReport{}, err
	}
	out := r.build(cs, nets, ins, samples, socks)
	if day, step, err := h.dockerDay(ctx, id); err == nil {
		out.Day, out.DayStep = day, step
	}
	r.mu.Lock()
	r.last = &out
	r.mu.Unlock()
	return out, nil
}

func (h *serverHandler) dockerDay(ctx context.Context, id string) ([]DockerHistoryPoint, int, error) {
	s, err := h.get(ctx, id)
	if err != nil {
		return nil, 0, err
	}
	rg := projectHistoryRanges["24h"]
	rows, err := h.q.DockerServerStatsHistory(ctx, sqlc.DockerServerStatsHistoryParams{
		StepSeconds: int32(rg.step.Seconds()), ServerID: s.ID, Since: time.Now().Add(-rg.span).Truncate(rg.step),
	})
	if err != nil {
		return nil, 0, err
	}
	out := make([]DockerHistoryPoint, 0, len(rows))
	for _, p := range rows {
		out = append(out, DockerHistoryPoint{
			At: p.Bucket.UTC(), CPU: p.Cpu, CPUMax: p.CpuMax, Memory: int64(p.Memory), MemoryMax: p.MemoryMax,
			NetRx: p.NetRx, NetTx: p.NetTx, Running: int(p.Running), Total: int(p.Total),
		})
	}
	return out, int(rg.step.Seconds()), nil
}

// ---- Connections ----

type socket struct {
	state         string // ESTAB, LISTEN…
	local, remote sockAddr
	acked, recv   int64
	bytes         bool
}

type sockAddr struct {
	ip   string
	port int
}

type netScan struct {
	byPid map[int][]socket
	bytes bool
	note  string
	tried int
}

// ownNetwork says whether a container has a network namespace of its own
// worth reading (not the host's, not another container's).
func ownNetwork(c docker.ContainerSummary) bool {
	m := c.HostConfig.NetworkMode
	return c.State == "running" && m != "host" && m != "none" && !strings.HasPrefix(m, "container:")
}

// scanSockets reads every running container's TCP sockets in one script:
// `ss` inside its namespace when root (gives bytes), else /proc/<pid>/net/tcp.
func (h *serverHandler) scanSockets(ctx context.Context, id string, e *dockerEngine, cs []docker.ContainerSummary, ins map[string]docker.ContainerInspect) netScan {
	out := netScan{byPid: map[int][]socket{}}
	var pids []int
	for _, c := range cs {
		if !ownNetwork(c) {
			continue
		}
		if v, ok := ins[c.ID]; ok && v.State.Pid > 0 {
			pids = append(pids, v.State.Pid)
		}
	}
	out.tried = len(pids)
	if len(pids) == 0 {
		return out
	}
	if len(pids) > projectStatsMeasure {
		pids = pids[:projectStatsMeasure]
	}
	var list strings.Builder
	for _, p := range pids {
		fmt.Fprintf(&list, " %d", p)
	}
	script := fmt.Sprintf(`S=0
if [ "$(id -u)" = 0 ] && command -v nsenter >/dev/null 2>&1 && command -v ss >/dev/null 2>&1; then S=1; fi
for p in%s; do
  if [ "$S" = 1 ] && o=$(nsenter -t "$p" -n ss -tainH 2>/dev/null); then
    echo "@ss $p"; printf '%%s\n' "$o" | head -n %d
  else
    echo "@proc $p"; cat "/proc/$p/net/tcp" "/proc/$p/net/tcp6" 2>/dev/null | head -n %d
  fi
done
exit 0`, list.String(), reportSockets*2, reportSockets)
	sh, err := h.rootShell(ctx, id, e.conn)
	if err != nil {
		out.note = "Couldn't read the connections: " + err.Error()
		return out
	}
	text, err := sh.hiding(true).run(ctx, script)
	if err != nil {
		out.note = "Couldn't read the connections: " + err.Error()
		return out
	}
	parseSockets(text, &out)
	return out
}

func parseSockets(text string, out *netScan) {
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	pid, mode := 0, ""
	var cur []socket
	flush := func() {
		if pid > 0 {
			out.byPid[pid] = cur
		}
		cur = nil
	}
	for sc.Scan() {
		line := sc.Text()
		if f, ok := strings.CutPrefix(line, "@"); ok {
			flush()
			parts := strings.Fields(f)
			if len(parts) == 2 {
				mode = parts[0]
				pid, _ = strconv.Atoi(parts[1])
				if mode == "ss" {
					out.bytes = true
				}
			}
			continue
		}
		switch mode {
		case "ss":
			if line == "" {
				continue
			}
			if line[0] == ' ' || line[0] == '\t' { // info line of the socket above
				if n := len(cur); n > 0 {
					cur[n-1].acked = ssCounter(line, "bytes_acked:")
					cur[n-1].recv = ssCounter(line, "bytes_received:")
					cur[n-1].bytes = true
				}
				continue
			}
			f := strings.Fields(line)
			if len(f) < 5 {
				continue
			}
			l, ok1 := ssAddr(f[3])
			r, ok2 := ssAddr(f[4])
			if !ok1 || !ok2 {
				continue
			}
			cur = append(cur, socket{state: ssState(f[0]), local: l, remote: r})
		case "proc":
			f := strings.Fields(line)
			if len(f) < 4 || f[0] == "sl" {
				continue
			}
			st := ""
			switch f[3] {
			case "01":
				st = "ESTAB"
			case "0A":
				st = "LISTEN"
			default:
				continue
			}
			l, ok1 := procAddr(f[1])
			r, ok2 := procAddr(f[2])
			if ok1 && ok2 {
				cur = append(cur, socket{state: st, local: l, remote: r})
			}
		}
	}
	flush()
}

func ssState(s string) string {
	switch s {
	case "ESTAB", "LISTEN":
		return s
	}
	return ""
}

func ssCounter(line, key string) int64 {
	i := strings.Index(line, key)
	if i < 0 {
		return 0
	}
	v := line[i+len(key):]
	if j := strings.IndexAny(v, " \t"); j >= 0 {
		v = v[:j]
	}
	n, _ := strconv.ParseInt(v, 10, 64)
	return n
}

func ssAddr(s string) (sockAddr, bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return sockAddr{}, false
	}
	host, port := s[:i], s[i+1:]
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if j := strings.Index(host, "%"); j >= 0 {
		host = host[:j]
	}
	p := 0
	if port != "*" {
		v, err := strconv.Atoi(port)
		if err != nil {
			return sockAddr{}, false
		}
		p = v
	}
	return sockAddr{ip: plainIP(host), port: p}, true
}

func procAddr(s string) (sockAddr, bool) {
	ipHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return sockAddr{}, false
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return sockAddr{}, false
	}
	b, err := hex.DecodeString(ipHex)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return sockAddr{}, false
	}
	// The kernel prints each 32-bit word in host (little-endian) order.
	for w := 0; w < len(b); w += 4 {
		b[w], b[w+1], b[w+2], b[w+3] = b[w+3], b[w+2], b[w+1], b[w]
	}
	return sockAddr{ip: plainIP(net.IP(b).String()), port: int(port)}, true
}

// plainIP turns an IPv4-mapped IPv6 address back into IPv4.
func plainIP(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}
	return s
}

func loopback(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && p.IsLoopback()
}

// ---- Building ----

func (r *serverReport) build(cs []docker.ContainerSummary, nets []docker.Network, ins map[string]docker.ContainerInspect, samples map[string]docker.Sample, scan netScan) DockerReport {
	now := time.Now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	out := DockerReport{
		At: now, Containers: []DockerReportContainer{}, Networks: []DockerReportNetwork{},
		Links: []DockerReportLink{}, LinkBytes: scan.bytes, LinksNote: scan.note,
	}

	// Who owns which address, and which addresses are the host's side.
	owner := map[string]string{}
	gateways := map[string]bool{}
	pidOf := map[string]int{}
	for _, c := range cs {
		for _, ep := range c.NetworkSettings.Networks {
			if ep.IPAddress != "" {
				owner[ep.IPAddress] = c.ID
			}
			if ep.GlobalIPv6 != "" {
				owner[plainIP(ep.GlobalIPv6)] = c.ID
			}
			if ep.Gateway != "" {
				gateways[ep.Gateway] = true
			}
		}
		if v, ok := ins[c.ID]; ok && v.State.Pid > 0 && ownNetwork(c) {
			pidOf[c.ID] = v.State.Pid
		}
	}
	for _, n := range nets {
		row := DockerReportNetwork{
			ID: n.ID, Name: n.Name, Driver: n.Driver, Internal: n.Internal,
			Builtin: n.Name == "bridge" || n.Name == "host" || n.Name == "none",
			Project: n.Labels["com.docker.compose.project"],
		}
		for _, c := range n.IPAM.Config {
			if c.Gateway != "" {
				gateways[c.Gateway] = true
			}
			if row.Subnet == "" && c.Subnet != "" {
				row.Subnet, row.Gateway = c.Subnet, c.Gateway
			}
		}
		out.Networks = append(out.Networks, row)
	}
	sort.Slice(out.Networks, func(i, j int) bool { return out.Networks[i].Name < out.Networks[j].Name })

	// Containers.
	seen := map[string]bool{}
	running := 0
	for _, c := range cs {
		row := DockerReportContainer{
			ID: c.ID, Name: containerName(c.Names), Image: c.Image, State: c.State, Status: c.Status,
			Project: c.Labels["com.docker.compose.project"], Service: c.Labels["com.docker.compose.service"],
			Created: time.Unix(c.Created, 0).UTC(), Ports: portsOf(c.Ports), Networks: []DockerReportEndpoint{},
			NetworkMode: c.HostConfig.NetworkMode, Listening: []int{}, CPUHistory: []float64{},
		}
		row.Health = containerHealth(c)
		if v, ok := ins[c.ID]; ok {
			row.Restarts = v.RestartCount
			row.ExitCode = v.State.ExitCode
			row.OOMKilled = v.State.OOMKilled
			if v.State.Health != nil && v.State.Health.Status != "" {
				row.Health = v.State.Health.Status
			}
			if t, err := time.Parse(time.RFC3339Nano, v.State.StartedAt); err == nil && t.Year() > 2000 && c.State == "running" {
				t = t.UTC()
				row.StartedAt = &t
			}
			if t, err := time.Parse(time.RFC3339Nano, v.State.FinishedAt); err == nil && t.Year() > 2000 && c.State != "running" {
				t = t.UTC()
				row.FinishedAt = &t
			}
			row.MemoryLimit = v.HostConfig.Memory
		}
		switch row.Health {
		case "healthy", "unhealthy", "starting":
		default:
			row.Health = "none"
		}
		names := make([]string, 0, len(c.NetworkSettings.Networks))
		for n := range c.NetworkSettings.Networks {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			ep := c.NetworkSettings.Networks[n]
			row.Networks = append(row.Networks, DockerReportEndpoint{Network: n, IPv4: ep.IPAddress, IPv6: ep.GlobalIPv6})
		}
		if c.State == "running" {
			running++
		}
		if s, ok := samples[c.ID]; ok {
			seen[c.ID] = true
			row.Measured = true
			row.CPU = s.CPUPercent
			row.MemoryUsed = s.MemoryUsed
			row.Pids = s.Pids
			if prev, ok := r.prev[c.ID]; ok && s.Time.After(prev.at) {
				secs := s.Time.Sub(prev.at).Seconds()
				if s.NetRx >= prev.rx && s.NetTx >= prev.tx {
					row.NetRxRate = float64(s.NetRx-prev.rx) / secs
					row.NetTxRate = float64(s.NetTx-prev.tx) / secs
				}
			} else {
				out.FirstSample = true
			}
			r.prev[c.ID] = netTotal{at: s.Time, rx: s.NetRx, tx: s.NetTx}
			out.CPU += row.CPU
			out.MemoryUsed += row.MemoryUsed
			out.NetRxRate += row.NetRxRate
			out.NetTxRate += row.NetTxRate
			out.CPUs = max(out.CPUs, s.CPUs)
			if row.MemoryLimit == 0 || s.MemoryLimit > row.MemoryLimit {
				out.HostMemory = max(out.HostMemory, s.MemoryLimit)
			}
			sp := append(r.sparks[c.ID], row.CPU)
			if len(sp) > reportSpark {
				sp = slices.Clone(sp[len(sp)-reportSpark:])
			}
			r.sparks[c.ID] = sp
			row.CPUHistory = slices.Clone(sp)
		} else if c.State == "running" {
			out.Unmeasured++
		}
		if pid, ok := pidOf[c.ID]; ok {
			if ss, ok := scan.byPid[pid]; ok {
				row.Connections = true
				for _, s := range ss {
					if s.state == "LISTEN" && !loopback(s.local.ip) && !slices.Contains(row.Listening, s.local.port) {
						row.Listening = append(row.Listening, s.local.port)
					}
				}
				sort.Ints(row.Listening)
			}
		}
		out.Containers = append(out.Containers, row)
	}
	for id := range r.prev {
		if !seen[id] {
			delete(r.prev, id)
		}
	}
	for id := range r.sparks {
		if !seen[id] {
			delete(r.sparks, id)
		}
	}
	sort.Slice(out.Containers, func(i, j int) bool {
		a, b := out.Containers[i], out.Containers[j]
		if a.Project != b.Project {
			return a.Project < b.Project
		}
		return a.Name < b.Name
	})

	// Links.
	listening := map[string][]int{}
	for _, c := range out.Containers {
		listening[c.ID] = c.Listening
	}
	where := func(ip string) string {
		if id, ok := owner[ip]; ok {
			return id
		}
		if gateways[ip] {
			return "host"
		}
		return "outside"
	}
	type agg struct {
		DockerReportLink
		up, down float64
	}
	links := map[string]*agg{}
	add := func(from, to string, port int, peer string, up, down float64) {
		k := from + "|" + to + "|" + strconv.Itoa(port)
		l := links[k]
		if l == nil {
			l = &agg{DockerReportLink: DockerReportLink{From: from, To: to, Port: port, Peers: []string{}}}
			links[k] = l
		}
		l.Connections++
		l.up += up
		l.down += down
		if peer != "" && len(l.Peers) < reportPeers && !slices.Contains(l.Peers, peer) {
			l.Peers = append(l.Peers, peer)
		}
	}
	keep := map[sockKey]sockTotal{}
	read := 0
	for id, pid := range pidOf {
		ss, ok := scan.byPid[pid]
		if !ok {
			continue
		}
		read++
		mine := listening[id]
		for _, s := range ss {
			if s.state != "ESTAB" || loopback(s.local.ip) || loopback(s.remote.ip) {
				continue
			}
			// Rates from the connection's byte counters since the last pass.
			var sent, got float64
			if s.bytes {
				k := sockKey{pid: pid, local: s.local.ip + ":" + strconv.Itoa(s.local.port), remote: s.remote.ip + ":" + strconv.Itoa(s.remote.port)}
				if p, ok := r.socks[k]; ok && now.After(p.at) && s.acked >= p.acked && s.recv >= p.received {
					secs := now.Sub(p.at).Seconds()
					sent = float64(s.acked-p.acked) / secs
					got = float64(s.recv-p.received) / secs
				}
				keep[k] = sockTotal{at: now, acked: s.acked, received: s.recv}
			}
			peer := where(s.remote.ip)
			inbound := slices.Contains(mine, s.local.port)
			switch {
			case inbound && peer == "outside":
				add("outside", id, s.local.port, s.remote.ip, got, sent)
			case inbound && peer == "host":
				add("host", id, s.local.port, "", got, sent)
			case inbound:
				// Another container's connection: counted from its side,
				// unless that side wasn't read.
				if _, ok := scan.byPid[pidOf[peer]]; !ok {
					add(peer, id, s.local.port, "", got, sent)
				}
			case peer == "outside":
				add(id, "outside", s.remote.port, s.remote.ip, sent, got)
			default:
				if peer == id {
					continue
				}
				add(id, peer, s.remote.port, "", sent, got)
			}
		}
	}
	r.socks = keep
	for _, l := range links {
		l.Up, l.Down = l.up, l.down
		out.Links = append(out.Links, l.DockerReportLink)
	}
	sort.Slice(out.Links, func(i, j int) bool {
		a, b := out.Links[i], out.Links[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.Port < b.Port
	})
	switch {
	case scan.tried == 0:
		out.LinksState = "read"
	case read == 0:
		out.LinksState = "unavailable"
		if out.LinksNote == "" {
			out.LinksNote = "The server didn't let Morche read its containers' connections."
		}
	case read < scan.tried:
		out.LinksState = "partial"
		if out.LinksNote == "" {
			out.LinksNote = fmt.Sprintf("Connections were read for %d of %d running containers.", read, scan.tried)
		}
	default:
		out.LinksState = "read"
	}

	// Live history.
	if n := len(r.history); n == 0 || now.Sub(r.history[n-1].At) >= reportGap {
		r.history = append(r.history, DockerStatsPoint{At: now, CPU: out.CPU, Memory: out.MemoryUsed, NetRx: out.NetRxRate, NetTx: out.NetTxRate})
		if len(r.history) > reportPoints {
			r.history = slices.Clone(r.history[len(r.history)-reportPoints:])
		}
	}
	out.History = slices.Clone(r.history)
	out.Day = []DockerHistoryPoint{}
	return out
}

// ---- Handler ----

func registerDockerReport(api huma.API, h *serverHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "docker-report",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/docker/report",
		Summary:     "A report on a server's containers and their network",
		Description: "Every container's state, uptime, restarts and live CPU, memory and network; the networks; and which containers talk to which, read from each running container's TCP table (with bytes per connection when Morche is root on the server and `nsenter` + `ss` exist). Live totals keep a short history while someone looks; `day` adds up the compose projects' recorded points over 24 hours. Answers are shared for a few seconds.",
		Tags:        []string{"Containers"},
	}, func(ctx context.Context, in *struct{ ServerIDPath }) (*struct{ Body DockerReport }, error) {
		out, err := h.dockerReport(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body DockerReport }{out}, nil
	})
}
