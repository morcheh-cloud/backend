package procs

import (
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// startOf prints a process's start time (stat field 22) so a script can
// tell it from another process that later got the same PID.
const startOf = `startof() { awk '{sub(/.*\) /,""); print $20}' /proc/$1/stat 2>/dev/null; }`

// MaxFiles caps how many open files a details answer lists.
const MaxFiles = 500

// DetailsScript reads one process in depth. withEnv adds its environment
// (often holds secrets). Lines of argv and env are prefixed with "=" so a
// value can never look like a section marker.
func DetailsScript(pid int, start int64, withEnv bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "export LC_ALL=C\n%s\nP=%d\n[ \"$(startof $P)\" = %d ] || { echo @gone; exit 0; }\n", startOf, pid, start)
	b.WriteString(`echo @exe; readlink /proc/$P/exe 2>/dev/null
echo @cwd; readlink /proc/$P/cwd 2>/dev/null
echo @root; readlink /proc/$P/root 2>/dev/null
echo @status; cat /proc/$P/status 2>/dev/null
echo @io; cat /proc/$P/io 2>/dev/null
echo @limits; grep -E '^Max (open files|processes)' /proc/$P/limits 2>/dev/null
echo @oom; cat /proc/$P/oom_score /proc/$P/oom_score_adj 2>/dev/null
echo @cgroup; cat /proc/$P/cgroup 2>/dev/null
echo @fdcount; ls /proc/$P/fd 2>/dev/null | wc -l
echo @fds; ls -l /proc/$P/fd 2>/dev/null | head -n ` + strconv.Itoa(MaxFiles+1) + `
echo @net
for f in tcp tcp6 udp udp6; do echo "#$f"; cat /proc/$P/net/$f 2>/dev/null; done
echo @argv; tr '\0' '\n' </proc/$P/cmdline 2>/dev/null | head -c 65536 | sed 's/^/=/'
`)
	if withEnv {
		b.WriteString(`echo @env; tr '\0' '\n' </proc/$P/environ 2>/dev/null | head -c 65536 | sed 's/^/=/'` + "\n")
	}
	b.WriteString("exit 0\n")
	return b.String()
}

type ProcessDetails struct {
	PID            int             `json:"pid"`
	Start          int64           `json:"start"`
	Exe            string          `json:"exe,omitempty" doc:"The program file it runs" example:"/usr/sbin/nginx"`
	ExeDeleted     bool            `json:"exe_deleted" doc:"The program file was replaced or removed since it started (an update it hasn't restarted for)"`
	Cwd            string          `json:"cwd,omitempty" doc:"Its working folder"`
	Root           string          `json:"root,omitempty" doc:"Its root folder, when not / (chroot or container)"`
	Argv           []string        `json:"argv" doc:"Command line split into arguments"`
	Env            []ProcessEnv    `json:"env,omitempty"`
	EnvHidden      bool            `json:"env_hidden" doc:"The environment is left out: it needs Engineer access"`
	Limited        bool            `json:"limited" doc:"Some details couldn't be read: the login user can't act as root on this server"`
	MemoryPeak     int64           `json:"memory_peak" doc:"Most resident memory it has used (VmHWM), bytes"`
	MemoryAnon     int64           `json:"memory_anon" doc:"Resident memory that is its own data (RssAnon), bytes"`
	MemoryFile     int64           `json:"memory_file" doc:"Resident memory backed by files (RssFile), bytes"`
	MemoryShared   int64           `json:"memory_shared" doc:"Resident shared memory (RssShmem), bytes"`
	Swap           int64           `json:"swap"`
	Switches       int64           `json:"switches_voluntary" doc:"Times it gave up the CPU to wait"`
	SwitchesForced int64           `json:"switches_forced" doc:"Times the kernel took the CPU from it"`
	ReadBytes      int64           `json:"read_bytes" doc:"Bytes it has read from storage (-1 = unknown)"`
	WriteBytes     int64           `json:"write_bytes" doc:"Bytes it has written to storage (-1 = unknown)"`
	OOMScore       int             `json:"oom_score" doc:"How likely the kernel is to kill it when memory runs out (0–1000+)"`
	OOMAdjust      int             `json:"oom_adjust" doc:"oom_score_adj (-1000 = never)"`
	OpenFiles      int             `json:"open_files" doc:"How many files, sockets and pipes it holds open"`
	MaxOpenFiles   string          `json:"max_open_files,omitempty" doc:"Its open-files limit (soft)" example:"1024"`
	Files          []ProcessFile   `json:"files"`
	FilesTruncated bool            `json:"files_truncated"`
	Sockets        []ProcessSocket `json:"sockets"`
	Cgroup         string          `json:"cgroup,omitempty"`
	Groups         []int           `json:"groups,omitempty" doc:"Supplementary group IDs"`
}

type ProcessEnv struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ProcessFile struct {
	FD            int    `json:"fd" example:"3"`
	ProcessTarget string `json:"target" example:"/var/log/nginx/access.log"`
	Kind          string `json:"kind" enum:"file,socket,pipe,device,anon,other"`
	Deleted       bool   `json:"deleted" doc:"The file was removed while still open (its space isn't freed until the process closes it)"`
}

type ProcessSocket struct {
	Proto  string `json:"proto" enum:"tcp,udp"`
	Local  string `json:"local" example:"0.0.0.0:80"`
	Remote string `json:"remote,omitempty" example:"10.0.0.5:51544"`
	State  string `json:"state" example:"listen"`
}

// ErrGone means the process ended (or its PID now belongs to another one).
var ErrGone = fmt.Errorf("that process has ended")

var fdRe = regexp.MustCompile(`\s(\d+) -> (.*)$`)

// ParseDetails reads DetailsScript's output.
func ParseDetails(out string, pid int, start int64) (ProcessDetails, error) {
	if strings.Contains(out, "@gone\n") || strings.HasPrefix(out, "@gone") {
		return ProcessDetails{}, ErrGone
	}
	sec := Sections(out)
	d := ProcessDetails{PID: pid, Start: start, Argv: prefixed(sec["argv"]), Files: []ProcessFile{}, Sockets: []ProcessSocket{}, ReadBytes: -1, WriteBytes: -1}
	d.Exe = firstLine(sec["exe"])
	if e, ok := strings.CutSuffix(d.Exe, " (deleted)"); ok {
		d.Exe, d.ExeDeleted = e, true
	}
	d.Cwd = firstLine(sec["cwd"])
	if r := firstLine(sec["root"]); r != "/" {
		d.Root = r
	}
	if d.Exe == "" && d.Cwd == "" && sec["status"] != "" {
		d.Limited = true
	}
	for _, l := range lines(sec["status"]) {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		kb := func() int64 { f := strings.Fields(v); return int64(atoiOr(firstOr(f), 0)) * 1024 }
		switch k {
		case "VmHWM":
			d.MemoryPeak = kb()
		case "RssAnon":
			d.MemoryAnon = kb()
		case "RssFile":
			d.MemoryFile = kb()
		case "RssShmem":
			d.MemoryShared = kb()
		case "VmSwap":
			d.Swap = kb()
		case "voluntary_ctxt_switches":
			d.Switches = int64(atoiOr(v, 0))
		case "nonvoluntary_ctxt_switches":
			d.SwitchesForced = int64(atoiOr(v, 0))
		case "Groups":
			for _, g := range strings.Fields(v) {
				if n, err := strconv.Atoi(g); err == nil {
					d.Groups = append(d.Groups, n)
				}
			}
		}
	}
	for _, l := range lines(sec["io"]) {
		k, v, _ := strings.Cut(l, ":")
		switch k {
		case "read_bytes":
			d.ReadBytes = int64(atoiOr(v, -1))
		case "write_bytes":
			d.WriteBytes = int64(atoiOr(v, -1))
		}
	}
	for _, l := range lines(sec["limits"]) {
		if f := strings.Fields(l); strings.HasPrefix(l, "Max open files") && len(f) >= 4 {
			d.MaxOpenFiles = f[3]
		}
	}
	if o := strings.Fields(sec["oom"]); len(o) == 2 {
		d.OOMScore, d.OOMAdjust = atoiOr(o[0], 0), atoiOr(o[1], 0)
	}
	for _, l := range lines(sec["cgroup"]) {
		if p, ok := strings.CutPrefix(l, "0::"); ok {
			d.Cgroup = p
		}
	}
	d.OpenFiles = atoiOr(firstLine(sec["fdcount"]), 0)

	inodes := map[string]bool{}
	for _, l := range lines(sec["fds"]) {
		m := fdRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if len(d.Files) == MaxFiles {
			d.FilesTruncated = true
			break
		}
		f := ProcessFile{FD: atoiOr(m[1], 0), ProcessTarget: m[2]}
		switch t := f.ProcessTarget; {
		case strings.HasPrefix(t, "socket:["):
			f.Kind = "socket"
			inodes[strings.TrimSuffix(strings.TrimPrefix(t, "socket:["), "]")] = true
		case strings.HasPrefix(t, "pipe:["):
			f.Kind = "pipe"
		case strings.HasPrefix(t, "anon_inode:"):
			f.Kind = "anon"
		case strings.HasPrefix(t, "/dev/"):
			f.Kind = "device"
		case strings.HasPrefix(t, "/"):
			f.Kind = "file"
			if p, ok := strings.CutSuffix(t, " (deleted)"); ok {
				f.ProcessTarget, f.Deleted = p, true
			}
		default:
			f.Kind = "other"
		}
		d.Files = append(d.Files, f)
	}
	if d.OpenFiles > len(d.Files) {
		d.FilesTruncated = true
	}
	d.Sockets = sockets(sec["net"], inodes)

	if env, ok := sec["env"]; ok {
		for _, kv := range prefixed(env) {
			k, v, _ := strings.Cut(kv, "=")
			if k != "" {
				d.Env = append(d.Env, ProcessEnv{k, v})
			}
		}
		slices.SortFunc(d.Env, func(a, b ProcessEnv) int { return strings.Compare(a.Name, b.Name) })
		if d.Env == nil && d.Limited {
			d.Env = []ProcessEnv{}
		}
	} else {
		d.EnvHidden = true
	}
	return d, nil
}

func prefixed(body string) []string {
	out := []string{}
	for _, l := range lines(body) {
		if v, ok := strings.CutPrefix(l, "="); ok {
			out = append(out, v)
		} else if n := len(out); n > 0 {
			out[n-1] += "\n" + l // a value that held a newline
		}
	}
	if n := len(out); n > 0 && out[n-1] == "" {
		out = out[:n-1]
	}
	return out
}

var tcpStates = map[string]string{
	"01": "established", "02": "syn-sent", "03": "syn-received", "04": "fin-wait-1", "05": "fin-wait-2",
	"06": "time-wait", "07": "close", "08": "close-wait", "09": "last-ack", "0A": "listen", "0B": "closing",
}

// sockets picks the process's sockets (by inode) out of its network
// namespace's /proc/net tables.
func sockets(body string, inodes map[string]bool) []ProcessSocket {
	out := []ProcessSocket{}
	if len(inodes) == 0 {
		return out
	}
	proto := ""
	for _, l := range lines(body) {
		if p, ok := strings.CutPrefix(l, "#"); ok {
			proto = strings.TrimSuffix(p, "6")
			continue
		}
		f := strings.Fields(l)
		if len(f) < 10 || f[0] == "sl" || !inodes[f[9]] {
			continue
		}
		s := ProcessSocket{Proto: proto, Local: hexAddr(f[1])}
		remote := hexAddr(f[2])
		switch {
		case proto == "tcp":
			s.State = tcpStates[strings.ToUpper(f[3])]
			if s.State != "listen" {
				s.Remote = remote
			}
		case strings.HasSuffix(remote, ":0"):
			s.State = "listen"
		default:
			s.State = "connected"
			s.Remote = remote
		}
		if s.State == "" {
			s.State = "other"
		}
		out = append(out, s)
	}
	slices.SortStableFunc(out, func(a, b ProcessSocket) int {
		return boolRank(a.State != "listen") - boolRank(b.State != "listen")
	})
	return out
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// hexAddr decodes /proc/net's "0100007F:0050" (little-endian words) to
// "127.0.0.1:80".
func hexAddr(s string) string {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return s
	}
	raw, err := hex.DecodeString(h)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return s
	}
	for i := 0; i+4 <= len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	port, _ := strconv.ParseUint(p, 16, 16)
	ip := net.IP(raw)
	if v4 := ip.To4(); v4 != nil && len(raw) == 16 && !ip.IsUnspecified() {
		ip = v4
	}
	return net.JoinHostPort(ip.String(), strconv.FormatUint(port, 10))
}

func firstOr(f []string) string {
	if len(f) == 0 {
		return ""
	}
	return f[0]
}
