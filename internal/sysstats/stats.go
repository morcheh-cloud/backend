// Package sysstats reads a Linux server's live resource usage (uptime, CPU,
// memory, disks, network) from one shell script run over SSH.
package sysstats

import (
	"bufio"
	"cmp"
	"errors"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Script prints each source under an "@name" marker. CPU and network are
// sampled twice, a second apart, so they come out as rates; /proc/uptime is
// read with each sample to know the exact interval.
const Script = `export LC_ALL=C
echo @os; uname -s
[ -r /proc/stat ] || exit 0
echo @cpus; nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo
echo @load; cat /proc/loadavg
echo @sample1; cat /proc/uptime; grep '^cpu ' /proc/stat; cat /proc/net/dev
sleep 1
echo @sample2; cat /proc/uptime; grep '^cpu ' /proc/stat; cat /proc/net/dev
echo @mem; cat /proc/meminfo
echo @df; df -PkT 2>/dev/null || df -Pk 2>/dev/null || true
`

// ErrUnsupported means the server isn't Linux (no /proc to read).
var ErrUnsupported = errors.New("live stats are only available for Linux servers")

type Stats struct {
	CollectedAt   time.Time `json:"collected_at"`
	UptimeSeconds int64     `json:"uptime_seconds" example:"864000"`
	BootedAt      time.Time `json:"booted_at"`
	Processes     int       `json:"processes" doc:"Processes and threads that exist right now" example:"231"`
	CPU           CPU       `json:"cpu"`
	Memory        Memory    `json:"memory"`
	Network       Network   `json:"network"`
	Disks         []Disk    `json:"disks" doc:"Real filesystems, largest first; pseudo ones (tmpfs, proc, snaps…) are left out"`
}

type CPU struct {
	Cores         int     `json:"cores" example:"4"`
	UsagePercent  float64 `json:"usage_percent" doc:"Busy share of all cores over the last second" example:"12.5"`
	IOWaitPercent float64 `json:"iowait_percent" doc:"Time spent waiting on disk" example:"0.4"`
	StealPercent  float64 `json:"steal_percent" doc:"Time the hypervisor gave to other VMs" example:"0"`
	Load1         float64 `json:"load1" example:"0.42"`
	Load5         float64 `json:"load5" example:"0.38"`
	Load15        float64 `json:"load15" example:"0.30"`
}

type Memory struct {
	TotalBytes     int64 `json:"total_bytes"`
	UsedBytes      int64 `json:"used_bytes" doc:"Total minus available"`
	AvailableBytes int64 `json:"available_bytes" doc:"What programs can still get without swapping"`
	CachedBytes    int64 `json:"cached_bytes" doc:"Page cache and buffers (reclaimable)"`
	SwapTotalBytes int64 `json:"swap_total_bytes"`
	SwapUsedBytes  int64 `json:"swap_used_bytes"`
}

type Network struct {
	RxBytesPerSec float64 `json:"rx_bytes_per_sec" doc:"Received over the last second, all interfaces except loopback and virtual ones"`
	TxBytesPerSec float64 `json:"tx_bytes_per_sec"`
	RxBytesTotal  int64   `json:"rx_bytes_total" doc:"Received since boot"`
	TxBytesTotal  int64   `json:"tx_bytes_total"`
}

type Disk struct {
	Mount          string  `json:"mount" example:"/"`
	Device         string  `json:"device" example:"/dev/sda1"`
	Type           string  `json:"type" doc:"Empty when the server's df can't print it" example:"ext4"`
	TotalBytes     int64   `json:"total_bytes"`
	UsedBytes      int64   `json:"used_bytes"`
	AvailableBytes int64   `json:"available_bytes"`
	UsedPercent    float64 `json:"used_percent" doc:"Used share of what non-root users can use, like df's Use%" example:"41.2"`
}

// StreamScript prints a frame every second until the session closes (the
// next echo then dies of SIGPIPE). Each frame ends with "@end"; disks are read
// every tenth frame only, under a timeout where there is one, since df can
// hang on a dead network mount.
const StreamScript = `export LC_ALL=C
[ "$(uname -s)" = Linux ] && [ -r /proc/stat ] || { echo @unsupported; exit 0; }
t=; command -v timeout >/dev/null 2>&1 && t="timeout 5"
i=0
while :; do
echo @cpus; nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo
echo @load; cat /proc/loadavg
echo @sample; cat /proc/uptime; grep '^cpu ' /proc/stat; cat /proc/net/dev
echo @mem; cat /proc/meminfo
if [ $((i % 10)) -eq 0 ]; then echo @df; $t df -PkT 2>/dev/null || $t df -Pk 2>/dev/null || true; fi
echo @end
i=$((i + 1))
sleep 1
done
`

// Parse reads what Script printed.
func Parse(out string, now time.Time) (Stats, error) {
	sec := sections(out)
	if os := strings.TrimSpace(sec["os"]); os != "Linux" || sec["sample2"] == "" {
		return Stats{}, ErrUnsupported
	}
	a := parseFrame(sec)
	b := a
	a.sample, b.sample = parseSample(sec["sample1"]), parseSample(sec["sample2"])
	return diff(a, b, now), nil
}

// Stream reads StreamScript's output and calls emit with each second's
// Stats (from the second frame on). Frames without disks reuse the last
// list. It returns when the output ends: ErrUnsupported, the read error, or
// io.ErrUnexpectedEOF.
func Stream(r io.Reader, now func() time.Time, emit func(Stats)) error {
	sc := bufio.NewScanner(r)
	var body strings.Builder
	var prev *frame
	var disks []Disk
	for sc.Scan() {
		switch line := sc.Text(); line {
		case "@unsupported":
			return ErrUnsupported
		case "@end":
			f := parseFrame(sections(body.String()))
			body.Reset()
			if f.disks != nil {
				disks = f.disks
			}
			f.disks = disks
			if prev != nil {
				emit(diff(*prev, f, now()))
			}
			prev = &f
		default:
			body.WriteString(line)
			body.WriteByte('\n')
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return io.ErrUnexpectedEOF
}

// frame is one reading; rates come from two of them.
type frame struct {
	cores     int
	load      [3]float64
	processes int
	memory    Memory
	disks     []Disk // nil when the frame didn't read them
	sample    sample
}

func parseFrame(sec map[string]string) frame {
	var f frame
	f.cores, _ = strconv.Atoi(strings.TrimSpace(sec["cpus"]))
	if l := strings.Fields(sec["load"]); len(l) >= 4 {
		f.load = [3]float64{num(l[0]), num(l[1]), num(l[2])}
		if _, total, ok := strings.Cut(l[3], "/"); ok {
			f.processes, _ = strconv.Atoi(total)
		}
	}
	f.sample = parseSample(sec["sample"])
	f.memory = parseMeminfo(sec["mem"])
	if df, ok := sec["df"]; ok {
		f.disks = parseDf(df)
	}
	return f
}

// diff turns two frames into Stats: counters from b, rates over a → b.
func diff(a, b frame, now time.Time) Stats {
	s := Stats{CollectedAt: now, Processes: b.processes, Memory: b.memory, Disks: b.disks}
	if s.Disks == nil {
		s.Disks = []Disk{}
	}
	s.CPU.Cores = b.cores
	s.CPU.Load1, s.CPU.Load5, s.CPU.Load15 = b.load[0], b.load[1], b.load[2]

	x, y := a.sample, b.sample
	s.UptimeSeconds = int64(y.uptime)
	s.BootedAt = now.Add(-time.Duration(y.uptime * float64(time.Second))).Truncate(time.Second)

	if total := y.cpu.total() - x.cpu.total(); total > 0 {
		idle := (y.cpu.idle - x.cpu.idle) + (y.cpu.iowait - x.cpu.iowait)
		s.CPU.UsagePercent = pct(total-idle, total)
		s.CPU.IOWaitPercent = pct(y.cpu.iowait-x.cpu.iowait, total)
		s.CPU.StealPercent = pct(y.cpu.steal-x.cpu.steal, total)
	}

	s.Network.RxBytesTotal, s.Network.TxBytesTotal = y.rx, y.tx
	if dt := y.uptime - x.uptime; dt > 0 {
		s.Network.RxBytesPerSec = math.Round(float64(max(0, y.rx-x.rx)) / dt)
		s.Network.TxBytesPerSec = math.Round(float64(max(0, y.tx-x.tx)) / dt)
	}
	return s
}

func sections(out string) map[string]string {
	sec := map[string]string{}
	var name string
	var body strings.Builder
	flush := func() {
		if name != "" {
			sec[name] = body.String()
		}
		body.Reset()
	}
	for line := range strings.Lines(out) {
		if after, ok := strings.CutPrefix(line, "@"); ok {
			flush()
			name = strings.TrimSpace(after)
			continue
		}
		body.WriteString(line)
	}
	flush()
	return sec
}

type cpuTimes struct{ user, nice, system, idle, iowait, irq, softirq, steal int64 }

// total leaves out guest time: the kernel already counts it in user.
func (c cpuTimes) total() int64 {
	return c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq + c.steal
}

type sample struct {
	uptime float64
	cpu    cpuTimes
	rx, tx int64
}

func parseSample(text string) sample {
	var s sample
	for line := range strings.Lines(text) {
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case f[0] == "cpu":
			v := make([]int64, 8)
			for i := range v {
				if i+1 < len(f) {
					v[i] = i64(f[i+1])
				}
			}
			s.cpu = cpuTimes{v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]}
		case strings.Contains(line, ":"):
			// /proc/net/dev: "  eth0: rx_bytes … (8 rx fields) tx_bytes …"
			name, rest, _ := strings.Cut(line, ":")
			name = strings.TrimSpace(name)
			f := strings.Fields(rest)
			if len(f) < 9 || virtualIface(name) {
				continue
			}
			s.rx += i64(f[0])
			s.tx += i64(f[8])
		case len(f) == 2 && s.uptime == 0:
			s.uptime = num(f[0])
		}
	}
	return s
}

// Loopback, and the bridges/veths containers and VMs use: their traffic also
// crosses a real interface, so counting them would count it twice.
func virtualIface(name string) bool {
	if name == "lo" {
		return true
	}
	for _, p := range []string{"veth", "docker", "br-", "virbr", "cni", "flannel", "cali", "vnet", "kube-"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func parseMeminfo(text string) Memory {
	kb := map[string]int64{}
	for line := range strings.Lines(text) {
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if f := strings.Fields(rest); len(f) > 0 {
			kb[key] = i64(f[0]) * 1024
		}
	}
	avail, ok := kb["MemAvailable"]
	if !ok { // kernels before 3.14
		avail = kb["MemFree"] + kb["Buffers"] + kb["Cached"]
	}
	return Memory{
		TotalBytes:     kb["MemTotal"],
		AvailableBytes: avail,
		UsedBytes:      max(0, kb["MemTotal"]-avail),
		CachedBytes:    kb["Buffers"] + kb["Cached"] + kb["SReclaimable"],
		SwapTotalBytes: kb["SwapTotal"],
		SwapUsedBytes:  max(0, kb["SwapTotal"]-kb["SwapFree"]),
	}
}

var pseudoFS = map[string]bool{
	"tmpfs": true, "devtmpfs": true, "devfs": true, "proc": true, "sysfs": true,
	"cgroup": true, "cgroup2": true, "squashfs": true, "efivarfs": true,
	"ramfs": true, "nsfs": true, "tracefs": true, "debugfs": true,
	"securityfs": true, "pstore": true, "bpf": true, "autofs": true,
	"mqueue": true, "hugetlbfs": true, "fusectl": true, "configfs": true,
	"binfmt_misc": true, "shm": true, "none": true, "udev": true,
}

// parseDf reads `df -PkT` (or `df -Pk` where -T isn't supported). The mount
// point is everything after the numbers, so one with spaces survives.
func parseDf(text string) []Disk {
	disks := []Disk{}
	seen := map[string]bool{}
	typed := false
	for i, line := range strings.Split(strings.TrimSpace(text), "\n") {
		f := strings.Fields(line)
		if i == 0 {
			typed = len(f) > 1 && f[1] == "Type"
			continue
		}
		if len(f) == 0 {
			continue
		}
		d := Disk{Device: f[0]}
		if typed {
			if len(f) < 7 {
				continue
			}
			d.Type = f[1]
			f = append(f[:1], f[2:]...)
		}
		if len(f) < 6 {
			continue
		}
		d.TotalBytes = i64(f[1]) * 1024
		d.UsedBytes = i64(f[2]) * 1024
		d.AvailableBytes = i64(f[3]) * 1024
		d.Mount = strings.Join(f[5:], " ")

		fsType := d.Type
		if fsType == "" {
			fsType = d.Device // busybox df without -T: tmpfs etc. show as the device
		}
		// A container's root is an overlay; that one is the disk it has.
		if (pseudoFS[fsType] || fsType == "overlay") && !(fsType == "overlay" && d.Mount == "/") ||
			d.TotalBytes == 0 || strings.HasPrefix(d.Mount, "/snap/") || seen[d.Mount] {
			continue
		}
		seen[d.Mount] = true
		d.UsedPercent = pct(d.UsedBytes, d.UsedBytes+d.AvailableBytes)
		disks = append(disks, d)
	}
	// Bind mounts (and a container's mounts of its host disk) repeat one
	// filesystem's numbers exactly; keep it once, under the shortest path.
	type key struct{ total, used, avail int64 }
	first := map[key]int{}
	out := disks[:0]
	for _, d := range disks {
		k := key{d.TotalBytes, d.UsedBytes, d.AvailableBytes}
		if j, ok := first[k]; ok {
			if len(d.Mount) < len(out[j].Mount) {
				out[j] = d
			}
			continue
		}
		first[k] = len(out)
		out = append(out, d)
	}
	sortDisks(out)
	return out
}

// sortDisks puts / first, then the rest largest first.
func sortDisks(d []Disk) {
	slices.SortStableFunc(d, func(a, b Disk) int {
		if (a.Mount == "/") != (b.Mount == "/") {
			if a.Mount == "/" {
				return -1
			}
			return 1
		}
		return cmp.Compare(b.TotalBytes, a.TotalBytes)
	})
}

func i64(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func num(s string) float64 {
	n, _ := strconv.ParseFloat(s, 64)
	return n
}

// pct rounds to one decimal.
func pct(part, whole int64) float64 {
	if whole <= 0 {
		return 0
	}
	return math.Round(float64(part)/float64(whole)*1000) / 10
}
