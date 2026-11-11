// Package procs reads a Linux server's processes from /proc in one shell
// script run over SSH: who they are, what they use (CPU sampled over a
// second, memory) and where they belong (systemd unit, container, login
// session). It only parses; the API runs the scripts.
package procs

import (
	"bufio"
	"cmp"
	"errors"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Script prints each source under an "@name" marker. Every process's stat
// line is read twice, a second apart, so CPU comes out as a rate; the
// uptime read with each sample gives the exact interval. Plain POSIX sh,
// busybox works (ps falls back to reading cmdline files).
const Script = `export LC_ALL=C
echo @os; uname -s
[ -r /proc/stat ] || exit 0
echo @self; echo $$
echo @tick; getconf CLK_TCK 2>/dev/null || echo 100
echo @page; getconf PAGESIZE 2>/dev/null || echo 4096
echo @cpus; nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo
echo @load; cat /proc/loadavg
echo @btime; grep '^btime' /proc/stat
echo @mem; grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo
echo @sample1; cat /proc/uptime; cat /proc/[0-9]*/stat 2>/dev/null
sleep 1
echo @sample2; cat /proc/uptime; cat /proc/[0-9]*/stat 2>/dev/null
echo @status; grep -sHE '^(Uid|VmSwap):' /proc/[0-9]*/status
echo @cgroup; grep -sHE '^0::|:name=systemd:' /proc/[0-9]*/cgroup
echo @cmd
ps -ww -eo pid=,args= 2>/dev/null || for d in /proc/[0-9]*; do
  printf '%s ' "${d#/proc/}"; tr '\0\n' '  ' <"$d/cmdline" 2>/dev/null; echo
done
echo @passwd; cat /etc/passwd 2>/dev/null
echo @containers
for rt in docker podman; do
  command -v $rt >/dev/null 2>&1 || continue
  $rt ps --no-trunc --format '{{.ID}} {{.Names}}' 2>/dev/null | sed "s/^/$rt /"
done
exit 0
`

// ErrUnsupported means the server isn't Linux (no /proc to read).
var ErrUnsupported = errors.New("processes can only be read on Linux servers")

// ProcessesReport is every process on the server right now.
type ProcessesReport struct {
	CollectedAt  time.Time `json:"collected_at"`
	Cores        int       `json:"cores" example:"4"`
	Load1        float64   `json:"load1" example:"0.42"`
	Load5        float64   `json:"load5" example:"0.38"`
	Load15       float64   `json:"load15" example:"0.30"`
	MemoryTotal  int64     `json:"memory_total" doc:"Bytes of RAM"`
	MemoryUsed   int64     `json:"memory_used" doc:"Total minus available"`
	SwapTotal    int64     `json:"swap_total"`
	SwapUsed     int64     `json:"swap_used"`
	CPUPercent   float64   `json:"cpu_percent" doc:"Every process's CPU added up, in percent of ALL cores (0–100)" example:"12.5"`
	Threads      int       `json:"threads" doc:"Threads of every process added up"`
	BootedAt     time.Time `json:"booted_at"`
	SampleMillis int       `json:"sample_ms" doc:"How long CPU was measured over" example:"1003"`
	Processes    []Process `json:"processes" doc:"Busiest first (CPU, then memory)"`
	Access       string    `json:"access" enum:"root,sudo,user" doc:"How it was read: user = the login user can't act as root, so it can only signal its own processes"`
	Login        string    `json:"login" doc:"The login user Morcheh connects as" example:"deploy"`
	// Set by the API for Viewers: command lines often carry passwords.
	CommandsHidden bool `json:"commands_hidden" doc:"Command lines are left out: they need Operator access"`
}

type Process struct {
	PID     int    `json:"pid" example:"812"`
	PPID    int    `json:"ppid" example:"1"`
	Start   int64  `json:"start" doc:"When it started, in clock ticks since boot: with the PID it names this one process, so send it back with actions (a reused PID is refused)" example:"1532"`
	Name    string `json:"name" doc:"The kernel's name for it (comm, at most 15 characters)" example:"nginx"`
	Command string `json:"command" doc:"Its full command line; empty for kernel threads and zombies" example:"nginx: worker process"`
	User    string `json:"user" doc:"The account it runs as (the UID when /etc/passwd doesn't name it)" example:"www-data"`
	UID     int    `json:"uid" example:"33"`
	State   string `json:"state" enum:"running,sleeping,disk,stopped,zombie,idle,other" doc:"disk = waiting on I/O and can't be interrupted (D); idle = an idle kernel thread"`
	// Percent of ONE core, like top: a process busy on two cores shows 200.
	CPU           float64   `json:"cpu" doc:"Percent of one core over the sample, like top (two busy cores = 200)" example:"3.2"`
	CPUTime       float64   `json:"cpu_time" doc:"Seconds of CPU it has used since it started" example:"81.4"`
	Memory        int64     `json:"memory" doc:"Resident memory (RSS) in bytes"`
	MemoryPercent float64   `json:"memory_percent" doc:"Of the server's RAM" example:"1.4"`
	Virtual       int64     `json:"virtual" doc:"Virtual memory size in bytes"`
	Swap          int64     `json:"swap" doc:"Bytes swapped out (when readable)"`
	Threads       int       `json:"threads" example:"4"`
	Nice          int       `json:"nice" minimum:"-20" maximum:"19"`
	StartedAt     time.Time `json:"started_at"`
	Kernel        bool      `json:"kernel" doc:"A kernel thread: no program behind it, can't be signalled"`
	Unit          string    `json:"unit,omitempty" doc:"The systemd service it belongs to" example:"nginx.service"`
	Session       string    `json:"session,omitempty" doc:"The login session it belongs to (logind)" example:"3"`
	Container     string    `json:"container,omitempty" doc:"Name of the Docker/Podman container it runs in, else a short container id" example:"web-1"`
	Runtime       string    `json:"runtime,omitempty" enum:"docker,podman,other"`
	Morcheh       bool      `json:"morcheh" doc:"Part of Morcheh's own SSH connection: ending it closes open terminals and running tasks here"`
	Protected     bool      `json:"protected" doc:"The system or Morcheh relies on it (init, sshd, journald, dbus…): signals need force"`
}

// Protected says whether stopping a process with this name would break the
// server or cut Morcheh off.
func Protected(pid int, name string) bool {
	if pid == 1 {
		return true
	}
	return slices.Contains(protectedNames, name)
}

// protectedNames are processes (by comm) the server or Morcheh relies on.
var protectedNames = []string{
	"sshd", "sshd-session", "systemd-journal", "systemd-logind", "systemd-udevd", "dbus-daemon", "dbus-broker",
	"systemd-network", "systemd-resolve", "NetworkManager", "init", "containerd", "dockerd",
}

var (
	idRe      = regexp.MustCompile(`[0-9a-f]{64}`)
	sessionRe = regexp.MustCompile(`/session-([^/]+)\.scope`)
)

// Parse turns Script's output into a ProcessesReport.
func Parse(out string, now time.Time) (ProcessesReport, error) {
	sec := Sections(out)
	if strings.TrimSpace(sec["os"]) != "Linux" || sec["sample2"] == "" {
		return ProcessesReport{}, ErrUnsupported
	}
	tick := float64(atoiOr(firstLine(sec["tick"]), 100))
	page := int64(atoiOr(firstLine(sec["page"]), 4096))
	self := atoiOr(firstLine(sec["self"]), 0)
	r := ProcessesReport{CollectedAt: now, Cores: max(1, atoiOr(firstLine(sec["cpus"]), 1)), Processes: []Process{}}
	if f := strings.Fields(sec["load"]); len(f) >= 3 {
		r.Load1, r.Load5, r.Load15 = atof(f[0]), atof(f[1]), atof(f[2])
	}
	if f := strings.Fields(sec["btime"]); len(f) == 2 {
		r.BootedAt = time.Unix(int64(atoiOr(f[1], 0)), 0).UTC()
	}
	mem := map[string]int64{}
	for _, l := range lines(sec["mem"]) {
		if f := strings.Fields(l); len(f) >= 2 {
			mem[strings.TrimSuffix(f[0], ":")] = int64(atoiOr(f[1], 0)) * 1024
		}
	}
	r.MemoryTotal = mem["MemTotal"]
	r.MemoryUsed = max(0, mem["MemTotal"]-mem["MemAvailable"])
	r.SwapTotal = mem["SwapTotal"]
	r.SwapUsed = max(0, mem["SwapTotal"]-mem["SwapFree"])

	up1, s1 := sample(sec["sample1"])
	up2, s2 := sample(sec["sample2"])
	interval := up2 - up1
	if interval <= 0 {
		interval = 1
	}
	r.SampleMillis = int(math.Round(interval * 1000))

	users := passwd(sec["passwd"])
	uids, swaps := status(sec["status"])
	cgroups := cgroupPaths(sec["cgroup"])
	cmds := commands(sec["cmd"])
	names := containers(sec["containers"])

	// Morcheh's own processes: the script and what it started are left out,
	// the chain above it (sudo, the login shell, the connection's sshd) marked.
	parent := map[int]int{}
	for pid, st := range s2 {
		parent[pid] = st.ppid
	}
	own := map[int]bool{}
	for p := parent[self]; p > 1 && !own[p]; p = parent[p] {
		own[p] = true
	}
	mine := func(pid int) bool {
		for seen := 0; pid > 1 && seen < 64; seen++ {
			if pid == self {
				return true
			}
			pid = parent[pid]
		}
		return false
	}

	var total float64
	for pid, st := range s2 {
		if mine(pid) {
			continue
		}
		p := Process{
			PID: pid, PPID: st.ppid, Start: st.start, Name: st.comm,
			State: stateOf(st.state), Threads: st.threads, Nice: st.nice,
			Memory: st.rss * page, Virtual: st.vsize, Swap: swaps[pid],
			CPUTime:   round(float64(st.utime+st.stime)/tick, 2),
			Kernel:    st.flags&0x00200000 != 0 || pid == 2 || st.ppid == 2,
			Morcheh:   own[pid],
			StartedAt: r.BootedAt.Add(time.Duration(float64(st.start) / tick * float64(time.Second))),
		}
		if prev, ok := s1[pid]; ok && prev.start == st.start {
			used := float64((st.utime + st.stime) - (prev.utime + prev.stime))
			p.CPU = round(max(0, used/tick/interval*100), 1)
		}
		total += p.CPU
		if r.MemoryTotal > 0 {
			p.MemoryPercent = round(float64(p.Memory)/float64(r.MemoryTotal)*100, 1)
		}
		if uid, ok := uids[pid]; ok {
			p.UID = uid
			p.User = users[uid]
			if p.User == "" {
				p.User = strconv.Itoa(uid)
			}
		}
		if c := cmds[pid]; !p.Kernel && p.State != "zombie" && !(strings.HasPrefix(c, "[") && strings.HasSuffix(c, "]")) {
			p.Command = c
		}
		if cg := cgroups[pid]; cg != "" {
			p.Unit, p.Session = unitOf(cg)
			if id := idRe.FindString(cg); id != "" {
				p.Runtime = "other"
				p.Container = id[:12]
				if c, ok := names[id]; ok {
					p.Runtime, p.Container = c.runtime, c.name
				}
				p.Unit = "" // the container's own scope, not a service
			}
		}
		p.Protected = Protected(pid, p.Name) || p.Morcheh
		r.Threads += p.Threads
		r.Processes = append(r.Processes, p)
	}
	r.CPUPercent = round(min(100, total/float64(r.Cores)), 1)
	slices.SortFunc(r.Processes, func(a, b Process) int {
		return cmp.Or(cmp.Compare(b.CPU, a.CPU), cmp.Compare(b.Memory, a.Memory), cmp.Compare(a.PID, b.PID))
	})
	return r, nil
}

// unitOf names the systemd service and login session a cgroup path is in.
// Services of a user's own manager (user@1000.service/…) don't count.
func unitOf(cg string) (unit, session string) {
	if m := sessionRe.FindStringSubmatch(cg); m != nil {
		session = m[1]
	}
	if strings.Contains(cg, "/user@") {
		return "", session
	}
	parts := strings.Split(cg, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if strings.HasSuffix(parts[i], ".service") {
			return parts[i], session
		}
	}
	return "", session
}

func stateOf(s string) string {
	switch s {
	case "R":
		return "running"
	case "S":
		return "sleeping"
	case "D":
		return "disk"
	case "T", "t":
		return "stopped"
	case "Z", "X", "x":
		return "zombie"
	case "I":
		return "idle"
	}
	return "other"
}

// ---- /proc/<pid>/stat ----

type stat struct {
	comm, state              string
	ppid, threads, nice      int
	flags                    uint64
	utime, stime, start, rss int64
	vsize                    int64
}

// ParseStat reads one /proc/<pid>/stat line. The name sits in parentheses
// and may hold spaces or parentheses itself, so fields count from the last ")".
func ParseStat(line string) (int, stat, bool) {
	open, end := strings.IndexByte(line, '('), strings.LastIndexByte(line, ')')
	if open < 1 || end < open {
		return 0, stat{}, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(line[:open]))
	if err != nil {
		return 0, stat{}, false
	}
	f := strings.Fields(line[end+1:])
	// f[0] is field 3 (state): field n is f[n-3].
	if len(f) < 22 {
		return 0, stat{}, false
	}
	n := func(i int) int64 { v, _ := strconv.ParseInt(f[i], 10, 64); return v }
	flags, _ := strconv.ParseUint(f[6], 10, 64)
	return pid, stat{
		comm: line[open+1 : end], state: f[0], ppid: int(n(1)), flags: flags,
		utime: n(11), stime: n(12), nice: int(n(16)), threads: int(n(17)),
		start: n(19), vsize: n(20), rss: n(21),
	}, true
}

func sample(body string) (uptime float64, m map[int]stat) {
	m = map[int]stat{}
	for i, l := range lines(body) {
		if i == 0 {
			if f := strings.Fields(l); len(f) > 0 {
				uptime = atof(f[0])
			}
			continue
		}
		if pid, st, ok := ParseStat(l); ok {
			m[pid] = st
		}
	}
	return
}

// ---- other sources ----

// status reads `grep -H` lines of /proc/<pid>/status: real UID and swap.
func status(body string) (uids map[int]int, swaps map[int]int64) {
	uids, swaps = map[int]int{}, map[int]int64{}
	for _, l := range lines(body) {
		pid, rest, ok := procLine(l)
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		switch {
		case len(f) >= 2 && f[0] == "Uid:":
			uids[pid] = atoiOr(f[1], 0)
		case len(f) >= 2 && f[0] == "VmSwap:":
			swaps[pid] = int64(atoiOr(f[1], 0)) * 1024
		}
	}
	return
}

// cgroupPaths keeps each process's unified (0::) path, else the systemd one.
func cgroupPaths(body string) map[int]string {
	m := map[int]string{}
	for _, l := range lines(body) {
		pid, rest, ok := procLine(l)
		if !ok {
			continue
		}
		i := strings.LastIndexByte(rest, ':')
		if i < 0 {
			continue
		}
		if path := rest[i+1:]; strings.HasPrefix(rest, "0::") || m[pid] == "" {
			m[pid] = path
		}
	}
	return m
}

// procLine splits "/proc/123/status:Uid: …" into 123 and what follows.
func procLine(l string) (int, string, bool) {
	rest, ok := strings.CutPrefix(l, "/proc/")
	if !ok {
		return 0, "", false
	}
	slash := strings.IndexByte(rest, '/')
	colon := strings.IndexByte(rest, ':')
	if slash < 1 || colon < slash {
		return 0, "", false
	}
	pid, err := strconv.Atoi(rest[:slash])
	if err != nil {
		return 0, "", false
	}
	return pid, rest[colon+1:], true
}

// MaxCommand caps a command line (some Java ones run to kilobytes).
const MaxCommand = 4096

func commands(body string) map[int]string {
	m := map[int]string{}
	for _, l := range lines(body) {
		l = strings.TrimLeft(l, " ")
		i := strings.IndexByte(l, ' ')
		if i < 1 {
			continue
		}
		pid, err := strconv.Atoi(l[:i])
		if err != nil {
			continue
		}
		c := strings.TrimSpace(l[i+1:])
		if len(c) > MaxCommand {
			c = c[:MaxCommand] + "…"
		}
		m[pid] = c
	}
	return m
}

func passwd(body string) map[int]string {
	m := map[int]string{}
	for _, l := range lines(body) {
		f := strings.Split(l, ":")
		if len(f) < 3 {
			continue
		}
		if uid, err := strconv.Atoi(f[2]); err == nil {
			if _, ok := m[uid]; !ok {
				m[uid] = f[0]
			}
		}
	}
	return m
}

type container struct{ runtime, name string }

func containers(body string) map[string]container {
	m := map[string]container{}
	for _, l := range lines(body) {
		if f := strings.Fields(l); len(f) >= 3 {
			m[f[1]] = container{f[0], f[2]}
		}
	}
	return m
}

// ---- helpers ----

// Sections splits script output at its "@name" marker lines.
func Sections(out string) map[string]string {
	sec := map[string]string{}
	var name string
	var b strings.Builder
	flush := func() {
		if name != "" {
			sec[name] += b.String()
		}
		b.Reset()
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		l := sc.Text()
		if strings.HasPrefix(l, "@") && !strings.ContainsAny(l[1:], " \t/") && len(l) > 1 {
			flush()
			name = l[1:]
			continue
		}
		b.WriteString(l)
		b.WriteByte('\n')
	}
	flush()
	return sec
}

func lines(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(l)
}

func atoiOr(s string, d int) int {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return d
	}
	return v
}

func atof(s string) float64 {
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

func round(v float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}
