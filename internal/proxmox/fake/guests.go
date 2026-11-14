package fake

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type node struct {
	name     string
	ip       string
	idx      int
	cores    int
	mem      int64
	online   bool
	bootedAt time.Time
	bridges  []map[string]any
}

type snapshot struct {
	name, desc, parent string
	taken              int64
	vmstate            bool
	running            bool
	conf               map[string]string
}

type guest struct {
	vmid       int
	kind       string // qemu | lxc
	node       string
	status     string // running | stopped
	paused     bool
	conf       map[string]string
	pending    map[string]string
	pendingDel map[string]bool
	snaps      []*snapshot
	parent     string
	startedAt  time.Time
	lock       string
	rules      []map[string]string
	fwOpts     map[string]string
}

type haResource struct {
	sid, state, group, comment string
	maxRestart, maxRelocate    int
}

func (g *guest) name() string {
	if g.kind == "lxc" {
		return g.conf["hostname"]
	}
	return g.conf["name"]
}

func (g *guest) template() bool { return g.conf["template"] == "1" }

func (g *guest) running() bool { return g.status == "running" }

func (g *guest) noun() string {
	if g.kind == "lxc" {
		return "CT"
	}
	return "VM"
}

func (g *guest) sid() string {
	if g.kind == "lxc" {
		return "ct:" + strconv.Itoa(g.vmid)
	}
	return "vm:" + strconv.Itoa(g.vmid)
}

func (g *guest) cpus() int {
	c, _ := strconv.Atoi(g.conf["cores"])
	if c == 0 {
		c = 1
	}
	if s, _ := strconv.Atoi(g.conf["sockets"]); s > 1 {
		c *= s
	}
	return c
}

func (g *guest) maxMem() int64 {
	m, _ := strconv.ParseInt(g.conf["memory"], 10, 64)
	if m == 0 {
		m = 512
	}
	return m * mib
}

var diskKey = regexp.MustCompile(`^((scsi|virtio|sata|ide)\d+|efidisk0|tpmstate0|rootfs|mp\d+|unused\d+)$`)

// disk reads "storage:volume,opt=…,size=32G".
type disk struct {
	volid   string
	storage string
	size    int64
	cdrom   bool
}

func parseDisk(v string) disk {
	parts := strings.Split(v, ",")
	d := disk{volid: parts[0]}
	if i := strings.Index(d.volid, ":"); i > 0 {
		d.storage = d.volid[:i]
	}
	for _, p := range parts[1:] {
		if k, val, ok := strings.Cut(p, "="); ok {
			switch k {
			case "size":
				d.size = parseSize(val)
			case "media":
				d.cdrom = val == "cdrom"
			}
		}
	}
	if strings.Contains(d.volid, "cloudinit") {
		d.cdrom = true
	}
	return d
}

// disks lists a guest's real disk images (no CD drives).
func (g *guest) disks() map[string]disk {
	out := map[string]disk{}
	for k, v := range g.conf {
		if !diskKey.MatchString(k) {
			continue
		}
		d := parseDisk(v)
		if d.cdrom || d.storage == "" || d.volid == "none" {
			continue
		}
		out[k] = d
	}
	return out
}

func (g *guest) bootDisk() (string, disk) {
	ds := g.disks()
	if g.kind == "lxc" {
		return "rootfs", ds["rootfs"]
	}
	if b := g.conf["boot"]; strings.HasPrefix(b, "order=") {
		for _, k := range strings.Split(strings.TrimPrefix(b, "order="), ";") {
			if d, ok := ds[k]; ok {
				return k, d
			}
		}
	}
	for _, k := range []string{"scsi0", "virtio0", "sata0", "ide0"} {
		if d, ok := ds[k]; ok {
			return k, d
		}
	}
	return "", disk{}
}

func parseSize(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	mult := int64(1)
	switch s[len(s)-1] {
	case 'K':
		mult = 1 << 10
	case 'M':
		mult = mib
	case 'G':
		mult = gib
	case 'T':
		mult = gib << 10
	}
	if mult != 1 {
		s = s[:len(s)-1]
	}
	f, _ := strconv.ParseFloat(s, 64)
	return int64(f * float64(mult))
}

func sizeText(b int64) string {
	switch {
	case b%gib == 0:
		return strconv.FormatInt(b/gib, 10) + "G"
	case b%mib == 0:
		return strconv.FormatInt(b/mib, 10) + "M"
	}
	return strconv.FormatInt(b/(1<<10), 10) + "K"
}

func digest(conf map[string]string) string {
	h := sha1.New()
	for _, k := range sortedKeys(conf) {
		fmt.Fprintf(h, "%s=%s\n", k, conf[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func macFor(seed int) string {
	return fmt.Sprintf("BC:24:11:%02X:%02X:%02X", (seed>>16)&0xff, (seed>>8)&0xff, seed&0xff)
}

func randMAC() string {
	return "BC:24:11:" + strings.ToUpper(randHex(1)+":"+randHex(1)+":"+randHex(1))
}

// live numbers, made up but steady: a wave per machine.
func wave(t float64, seed int, period float64) float64 {
	return 0.5 + 0.5*math.Sin(t/period+float64(seed)*1.7)
}

func (g *guest) busy() float64 {
	switch {
	case strings.Contains(g.conf["tags"], "ci"):
		return 0.55
	case strings.Contains(g.conf["tags"], "db"):
		return 0.3
	}
	return 0.12
}

// sample is the guest's numbers at time t (rates per second for the rrd).
func (g *guest) sample(t float64) map[string]float64 {
	if !g.running() {
		return map[string]float64{"cpu": 0, "maxcpu": float64(g.cpus()), "mem": 0, "maxmem": float64(g.maxMem())}
	}
	cpu := g.busy() * (0.4 + 1.2*wave(t, g.vmid, 45)) * (0.9 + 0.2*wave(t, g.vmid*3, 7))
	if g.paused {
		cpu = 0
	}
	_, d := g.bootDisk()
	return map[string]float64{
		"cpu": math.Min(cpu, 1), "maxcpu": float64(g.cpus()),
		"mem":    float64(g.maxMem()) * (0.3 + 0.25*wave(t, g.vmid, 600)),
		"maxmem": float64(g.maxMem()),
		"disk":   float64(d.size) * 0.42, "maxdisk": float64(d.size),
		"netin":     20000 + 400000*wave(t, g.vmid+1, 30)*g.busy()*4,
		"netout":    15000 + 900000*wave(t, g.vmid+2, 50)*g.busy()*4,
		"diskread":  5000 + 2e6*wave(t, g.vmid+3, 80)*g.busy(),
		"diskwrite": 8000 + 3e6*wave(t, g.vmid+4, 65)*g.busy(),
	}
}

func (g *guest) uptime() int64 {
	if !g.running() {
		return 0
	}
	return int64(time.Since(g.startedAt).Seconds())
}

func (s *Server) seed() {
	now := time.Now()
	for i, n := range []struct {
		name  string
		cores int
		mem   int64
		days  int
	}{{"pve1", 16, 64, 41}, {"pve2", 12, 48, 23}, {"pve3", 8, 32, 9}} {
		nd := &node{
			name: n.name, ip: fmt.Sprintf("10.10.0.%d", 11+i), idx: i + 1, cores: n.cores, mem: n.mem * gib,
			online: true, bootedAt: now.Add(-time.Duration(n.days) * 24 * time.Hour),
		}
		nd.bridges = []map[string]any{
			{"iface": "vmbr0", "type": "bridge", "active": 1, "cidr": nd.ip + "/16", "comments": "LAN\n", "autostart": 1, "bridge_ports": "eno1"},
			{"iface": "vmbr1", "type": "bridge", "active": 1, "cidr": fmt.Sprintf("172.16.0.%d/24", 11+i), "comments": "Storage and backups\n", "autostart": 1, "bridge_ports": "eno2"},
			{"iface": "vmbr2", "type": "bridge", "active": 1, "comments": "Isolated lab\n", "autostart": 1},
		}
		s.nodes = append(s.nodes, nd)
	}
	s.storages = []*storage{
		{name: "local", typ: "dir", content: "iso,vztmpl,backup,snippets", total: 100 * gib, base: 14 * gib},
		{name: "local-lvm", typ: "lvmthin", content: "images,rootdir", total: 500 * gib},
		{name: "ceph-vm", typ: "rbd", content: "images,rootdir", shared: true, total: 2048 * gib, base: 300 * gib},
		{name: "pbs", typ: "pbs", content: "backup", shared: true, total: 4096 * gib, base: 1200 * gib},
		{name: "nfs-iso", typ: "nfs", content: "iso,vztmpl", shared: true, total: 1024 * gib, base: 40 * gib},
	}

	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	day := 24 * time.Hour
	add := func(g *guest) {
		if g.conf["net0"] != "" && !strings.Contains(g.conf["net0"], "BC:24:11") {
			if g.kind == "qemu" {
				model, rest, _ := strings.Cut(g.conf["net0"], ",")
				g.conf["net0"] = model + "=" + macFor(g.vmid*7) + "," + rest
			} else {
				g.conf["net0"] = strings.Replace(g.conf["net0"], "bridge=", "hwaddr="+macFor(g.vmid*7)+",bridge=", 1)
			}
		}
		if g.kind == "qemu" {
			g.conf["smbios1"] = fmt.Sprintf("uuid=%s-%s-4%s-8%s-%s", randHex(4), randHex(2), randHex(2)[1:], randHex(2)[1:], randHex(6))
			g.conf["vmgenid"] = randHex(4) + "-" + randHex(2) + "-" + randHex(2) + "-" + randHex(2) + "-" + randHex(6)
		}
		if g.status == "" {
			g.status = "stopped"
		}
		g.pending, g.pendingDel = map[string]string{}, map[string]bool{}
		if g.fwOpts == nil {
			g.fwOpts = map[string]string{"enable": "0", "policy_in": "DROP", "policy_out": "ACCEPT"}
		}
		s.guests[g.vmid] = g
	}
	add(&guest{vmid: 100, kind: "qemu", node: "pve1", status: "running", startedAt: ago(6*day + 3*time.Hour), conf: map[string]string{
		"name": "web-01", "cores": "4", "sockets": "1", "memory": "8192", "cpu": "x86-64-v2-AES", "ostype": "l26",
		"scsihw": "virtio-scsi-single", "scsi0": "local-lvm:vm-100-disk-0,iothread=1,size=40G",
		"ide2": "local-lvm:vm-100-cloudinit,media=cdrom", "net0": "virtio,bridge=vmbr0,firewall=1",
		"boot": "order=scsi0;net0", "agent": "1", "onboot": "1", "tags": "prod;web", "ciuser": "ubuntu",
		"ipconfig0": "ip=10.10.1.21/16,gw=10.10.0.1", "serial0": "socket", "description": "Public web front end.\n",
	}, snaps: []*snapshot{{name: "before-upgrade", desc: "Before moving to 24.04", taken: ago(2 * day).Unix()}}, parent: "before-upgrade",
		fwOpts: map[string]string{"enable": "1", "policy_in": "DROP", "policy_out": "ACCEPT"},
		rules: []map[string]string{
			{"type": "in", "action": "ACCEPT", "proto": "tcp", "dport": "80,443", "enable": "1", "comment": "Web"},
			{"type": "in", "action": "ACCEPT", "macro": "SSH", "source": "10.10.0.0/16", "enable": "1", "comment": "SSH from the LAN"},
			{"type": "in", "action": "DROP", "source": "203.0.113.0/24", "enable": "0", "log": "info"},
		}})
	add(&guest{vmid: 101, kind: "qemu", node: "pve1", status: "running", startedAt: ago(14 * day), conf: map[string]string{
		"name": "db-01", "cores": "8", "sockets": "1", "memory": "16384", "cpu": "host", "ostype": "l26",
		"scsihw": "virtio-scsi-single", "scsi0": "ceph-vm:vm-101-disk-0,iothread=1,size=60G",
		"scsi1": "ceph-vm:vm-101-disk-1,iothread=1,size=500G", "net0": "virtio,bridge=vmbr0",
		"net1": "virtio,bridge=vmbr1", "boot": "order=scsi0", "agent": "1", "onboot": "1", "tags": "db;prod",
		"ipconfig0": "ip=10.10.1.31/16,gw=10.10.0.1",
	}})
	add(&guest{vmid: 102, kind: "qemu", node: "pve2", conf: map[string]string{
		"name": "win-ad", "cores": "4", "sockets": "1", "memory": "8192", "ostype": "win11", "bios": "ovmf",
		"machine": "pc-q35-8.1", "cpu": "x86-64-v2-AES",
		"efidisk0":  "local-lvm:vm-102-disk-0,efitype=4m,pre-enrolled-keys=1,size=4M",
		"tpmstate0": "local-lvm:vm-102-disk-1,size=4M,version=v2.0",
		"sata0":     "local-lvm:vm-102-disk-2,size=80G", "ide2": "local:iso/virtio-win-0.1.262.iso,media=cdrom",
		"net0": "e1000,bridge=vmbr0", "boot": "order=sata0;ide2", "tags": "windows",
	}})
	add(&guest{vmid: 103, kind: "lxc", node: "pve2", status: "running", startedAt: ago(9 * day), conf: map[string]string{
		"arch": "amd64", "hostname": "nginx-ct", "cores": "2", "memory": "1024", "swap": "512",
		"rootfs": "local-lvm:vm-103-disk-0,size=8G", "ostype": "debian", "unprivileged": "1",
		"features": "nesting=1", "onboot": "1", "tags": "prod;web",
		"net0": "name=eth0,bridge=vmbr0,firewall=1,gw=10.10.0.1,ip=10.10.2.31/16,type=veth",
	}, snaps: []*snapshot{{name: "pre-nginx-1-27", desc: "Before nginx 1.27", taken: ago(5 * day).Unix()}}, parent: "pre-nginx-1-27"})
	add(&guest{vmid: 104, kind: "lxc", node: "pve1", status: "running", startedAt: ago(30 * day), conf: map[string]string{
		"arch": "amd64", "hostname": "redis-ct", "cores": "1", "memory": "2048", "swap": "0",
		"rootfs": "ceph-vm:vm-104-disk-0,size=4G", "ostype": "alpine", "unprivileged": "1", "tags": "cache;prod",
		"net0": "name=eth0,bridge=vmbr0,ip=dhcp,type=veth", "onboot": "1",
	}})
	add(&guest{vmid: 105, kind: "qemu", node: "pve3", status: "running", startedAt: ago(2*day + 5*time.Hour), conf: map[string]string{
		"name": "build-runner", "cores": "6", "sockets": "1", "memory": "12288", "cpu": "host", "ostype": "l26",
		"scsihw": "virtio-scsi-single", "scsi0": "local-lvm:vm-105-disk-0,iothread=1,discard=on,size=120G",
		"net0": "virtio,bridge=vmbr0", "boot": "order=scsi0", "agent": "1", "tags": "ci",
		"ipconfig0": "ip=dhcp", "ide2": "local-lvm:vm-105-cloudinit,media=cdrom", "ciuser": "runner",
	}})
	add(&guest{vmid: 106, kind: "lxc", node: "pve3", conf: map[string]string{
		"arch": "amd64", "hostname": "test-ct", "cores": "2", "memory": "512", "swap": "512",
		"rootfs": "local-lvm:vm-106-disk-0,size=8G", "ostype": "ubuntu", "unprivileged": "1", "tags": "test",
		"net0": "name=eth0,bridge=vmbr0,ip=dhcp,type=veth",
	}})
	add(&guest{vmid: 9000, kind: "qemu", node: "pve1", conf: map[string]string{
		"name": "ubuntu-24.04-cloud", "template": "1", "cores": "2", "sockets": "1", "memory": "2048", "ostype": "l26",
		"scsihw": "virtio-scsi-single", "scsi0": "ceph-vm:base-9000-disk-0,iothread=1,size=3584M",
		"ide2": "ceph-vm:vm-9000-cloudinit,media=cdrom", "net0": "virtio,bridge=vmbr0", "boot": "order=scsi0",
		"agent": "1", "serial0": "socket", "vga": "serial0", "tags": "template",
		"description": "Ubuntu 24.04 cloud image with qemu-guest-agent.\n",
	}})
	add(&guest{vmid: 9001, kind: "qemu", node: "pve2", conf: map[string]string{
		"name": "debian-12-cloud", "template": "1", "cores": "1", "sockets": "1", "memory": "1024", "ostype": "l26",
		"scsihw": "virtio-scsi-single", "scsi0": "ceph-vm:base-9001-disk-0,iothread=1,size=2G",
		"ide2": "ceph-vm:vm-9001-cloudinit,media=cdrom", "net0": "virtio,bridge=vmbr0", "boot": "order=scsi0",
		"agent": "1", "serial0": "socket", "vga": "serial0", "tags": "template",
	}})
	for _, g := range s.guests {
		for _, sn := range g.snaps {
			sn.conf = cloneMap(g.conf)
		}
	}
	s.ha["vm:100"] = &haResource{sid: "vm:100", state: "started", group: "prefer-pve1", maxRestart: 1, maxRelocate: 1}
	s.ha["ct:103"] = &haResource{sid: "ct:103", state: "started", maxRestart: 1, maxRelocate: 1, comment: "Front proxy"}

	s.seedVolumes(now)
	s.seedTasks(now)
}

func cloneMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Cluster-wide lists

func (s *Server) haState(g *guest) string {
	if r := s.ha[g.sid()]; r != nil {
		return r.state
	}
	return ""
}

func (s *Server) resources(kind string) []map[string]any {
	now := float64(time.Now().Unix())
	var out []map[string]any
	if kind == "" || kind == "node" {
		for _, n := range s.nodes {
			out = append(out, s.nodeRow(n, true))
		}
	}
	if kind == "" || kind == "vm" {
		for _, id := range s.ids() {
			g := s.guests[id]
			sm := g.sample(now)
			st := g.status
			if n := s.node(g.node); n != nil && !n.online {
				st = "unknown"
			}
			_, d := g.bootDisk()
			row := map[string]any{
				"id": g.kind + "/" + strconv.Itoa(id), "type": g.kind, "node": g.node, "status": st, "name": g.name(),
				"vmid": id, "cpu": sm["cpu"], "maxcpu": g.cpus(), "mem": int64(sm["mem"]), "maxmem": g.maxMem(),
				"disk": 0, "maxdisk": d.size, "uptime": g.uptime(), "template": b2i(g.template()),
				"netin": int64(sm["netin"] * float64(g.uptime())), "netout": int64(sm["netout"] * float64(g.uptime())),
				"diskread": int64(sm["diskread"] * float64(g.uptime())), "diskwrite": int64(sm["diskwrite"] * float64(g.uptime())),
			}
			if g.kind == "lxc" {
				row["disk"] = int64(sm["disk"])
			}
			if t := g.conf["tags"]; t != "" {
				row["tags"] = t
			}
			if h := s.haState(g); h != "" {
				row["hastate"] = h
			}
			if g.lock != "" {
				row["lock"] = g.lock
			}
			if g.paused {
				row["status"] = "running"
			}
			out = append(out, row)
		}
	}
	if kind == "" || kind == "storage" {
		for _, n := range s.nodes {
			for _, st := range s.storages {
				used, total := s.storageUse(st, n.name)
				status := "available"
				if !n.online {
					status = "unknown"
				}
				out = append(out, map[string]any{
					"id": "storage/" + n.name + "/" + st.name, "type": "storage", "node": n.name, "storage": st.name,
					"status": status, "disk": used, "maxdisk": total, "content": st.content, "plugintype": st.typ,
					"shared": b2i(st.shared),
				})
			}
		}
	}
	return out
}

func (s *Server) ids() []int {
	ids := make([]int, 0, len(s.guests))
	for id := range s.guests {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func (s *Server) nodeUse(n *node) (cpu float64, mem int64) {
	t := float64(time.Now().Unix())
	cpu, mem = 0.02+0.02*wave(t, n.idx, 20), 3*gib+int64(n.idx)*400*mib
	for _, g := range s.guests {
		if g.node == n.name && g.running() {
			sm := g.sample(t)
			cpu += sm["cpu"] * float64(g.cpus()) / float64(n.cores)
			mem += int64(sm["mem"])
		}
	}
	return math.Min(cpu, 1), min(mem, n.mem)
}

func (s *Server) nodeRow(n *node, resource bool) map[string]any {
	row := map[string]any{"node": n.name, "status": "offline", "level": "", "maxcpu": n.cores, "maxmem": n.mem, "maxdisk": 98 * gib}
	if resource {
		row["id"], row["type"] = "node/"+n.name, "node"
	} else {
		row["ssl_fingerprint"] = "4E:1F:7A:21:9C:0B:5D:33:8A:E2:41:6F:90:CC:12:7B:AB:58:03:D9:66:E4:2F:81:C7:3A:95:0D:BE:14:72:A6"
	}
	if !n.online {
		return row
	}
	cpu, mem := s.nodeUse(n)
	row["status"], row["cpu"], row["mem"] = "online", cpu, mem
	row["disk"], row["uptime"] = 9*gib+int64(n.idx)*gib, int64(time.Since(n.bootedAt).Seconds())
	return row
}

func (s *Server) listNodes() []map[string]any {
	out := make([]map[string]any, 0, len(s.nodes))
	for _, n := range s.nodes {
		out = append(out, s.nodeRow(n, false))
	}
	return out
}

func (s *Server) nodeStatus(n *node) map[string]any {
	cpu, mem := s.nodeUse(n)
	load := func(f float64) string { return strconv.FormatFloat(cpu*float64(n.cores)*f, 'f', 2, 64) }
	return map[string]any{
		"pveversion": "pve-manager/8.3.2/3e76eec21c4a14a7", "kversion": "Linux 6.8.12-5-pve #1 SMP PREEMPT_DYNAMIC PMX 6.8.12-5 (2024-12-03T10:26Z)",
		"uptime": int64(time.Since(n.bootedAt).Seconds()), "loadavg": []string{load(1), load(0.9), load(0.8)},
		"cpu": cpu, "wait": 0.002 + 0.01*wave(float64(time.Now().Unix()), n.idx, 33),
		"cpuinfo":   map[string]any{"model": "AMD EPYC 7313P 16-Core Processor", "cpus": n.cores, "sockets": 1, "cores": n.cores, "mhz": "3000.000"},
		"memory":    map[string]any{"total": n.mem, "used": mem, "free": n.mem - mem},
		"swap":      map[string]any{"total": 8 * gib, "used": int64(n.idx) * 120 * mib, "free": 8*gib - int64(n.idx)*120*mib},
		"rootfs":    map[string]any{"total": 98 * gib, "used": 9*gib + int64(n.idx)*gib, "avail": 89*gib - int64(n.idx)*gib},
		"boot-info": map[string]any{"mode": "efi"},
	}
}

// Guest calls

func (s *Server) guestCall(r *http.Request, n *node, g *guest, p []string) (any, error) {
	m := r.Method
	key := strings.Join(p, "/")
	switch {
	case key == "" && m == http.MethodDelete:
		return s.destroy(r, n, g)
	case key == "status/current":
		return s.guestStatus(g), nil
	case len(p) == 2 && p[0] == "status" && m == http.MethodPost:
		return s.power(r, n, g, p[1])
	case key == "config" && m == http.MethodGet:
		out := map[string]any{"digest": digest(g.conf)}
		for k, v := range g.conf {
			if k == "cipassword" {
				v = "**********"
			}
			out[k] = v
		}
		if g.lock != "" {
			out["lock"] = g.lock
		}
		return out, nil
	case key == "config":
		return s.setConfig(r, n, g)
	case key == "pending":
		return s.pendingList(g), nil
	case key == "resize" && m == http.MethodPut:
		return s.resize(r, n, g)
	case key == "rrddata":
		return rrd(r.URL.Query().Get("timeframe"), g.sample), nil
	case p[0] == "snapshot":
		return s.snapshotCall(r, n, g, p[1:])
	case key == "clone" && m == http.MethodPost:
		return s.clone(r, n, g)
	case key == "template" && m == http.MethodPost:
		return s.makeTemplate(n, g)
	case key == "migrate" && m == http.MethodGet:
		return s.migrateCheck(r, g)
	case key == "migrate" && m == http.MethodPost:
		return s.migrate(r, n, g)
	case key == "interfaces" && g.kind == "lxc":
		return s.lxcInterfaces(g)
	case key == "agent/network-get-interfaces" && g.kind == "qemu":
		return s.agentInterfaces(g)
	case p[0] == "firewall":
		return s.firewall(r, g, p[1:])
	case key == "vncproxy" && m == http.MethodPost:
		return s.consoleTicket(r, n, g, "vnc")
	case key == "termproxy" && m == http.MethodPost:
		return s.consoleTicket(r, n, g, "term")
	}
	return nil, errNotFound
}

func (s *Server) guestStatus(g *guest) map[string]any {
	sm := g.sample(float64(time.Now().Unix()))
	_, d := g.bootDisk()
	out := map[string]any{
		"vmid": g.vmid, "status": g.status, "name": g.name(), "cpu": sm["cpu"], "cpus": g.cpus(),
		"mem": int64(sm["mem"]), "maxmem": g.maxMem(), "disk": 0, "maxdisk": d.size, "uptime": g.uptime(),
		"netin": int64(sm["netin"] * float64(g.uptime())), "netout": int64(sm["netout"] * float64(g.uptime())),
		"diskread": int64(sm["diskread"] * float64(g.uptime())), "diskwrite": int64(sm["diskwrite"] * float64(g.uptime())),
		"ha": map[string]any{"managed": 0},
	}
	if g.kind == "lxc" {
		out["disk"] = int64(sm["disk"])
		out["type"] = "lxc"
		out["swap"], out["maxswap"] = 0, parseSize(g.conf["swap"]+"M")
	} else {
		qmp := g.status
		if g.paused {
			qmp = "paused"
		}
		out["qmpstatus"] = qmp
		if strings.HasPrefix(g.conf["agent"], "1") || strings.Contains(g.conf["agent"], "enabled=1") {
			out["agent"] = 1
		}
		if g.running() {
			out["pid"] = 10000 + g.vmid
			out["running-machine"] = "pc-i440fx-9.0+pve0"
			out["running-qemu"] = "9.0.2"
		}
	}
	if r := s.ha[g.sid()]; r != nil {
		out["ha"] = map[string]any{"managed": 1, "state": r.state, "group": r.group}
	}
	if g.lock != "" {
		out["lock"] = g.lock
	}
	if t := g.conf["tags"]; t != "" {
		out["tags"] = t
	}
	if g.template() {
		out["template"] = 1
	}
	return out
}

func (s *Server) lockedErr(g *guest) error {
	return fail(http.StatusInternalServerError, "%s is locked (%s)", g.noun(), g.lock)
}

// coldKeys need a VM restart to apply.
var coldKeys = []string{"cores", "sockets", "cpu", "machine", "bios", "scsihw", "vga", "numa", "balloon", "ostype", "serial0", "serial1", "args", "hookscript", "affinity", "cpulimit", "cpuunits"}

var dnsName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)

func (s *Server) setConfig(r *http.Request, n *node, g *guest) (any, error) {
	if g.lock != "" && g.lock != "create" {
		return nil, s.lockedErr(g)
	}
	if d := form(r, "digest"); d != "" && d != digest(g.conf) {
		return nil, fail(http.StatusInternalServerError, "detected modified configuration - file changed by other user? Try again.")
	}
	set := map[string]string{}
	for k := range r.PostForm {
		switch k {
		case "digest", "delete", "skiplock", "background_delay", "revert":
			continue
		}
		set[k] = r.PostForm.Get(k)
	}
	for k, v := range set {
		switch k {
		case "cores", "sockets", "memory", "swap", "balloon", "cpuunits", "cpulimit":
			x, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return nil, badParam(k, "type check ('number') failed - got '"+v+"'")
			}
			if (k == "cores" || k == "sockets") && (x < 1 || x > 128) {
				return nil, badParam(k, "value must have a minimum value of 1")
			}
			if k == "memory" && x < 16 {
				return nil, badParam(k, "value must have a minimum value of 16")
			}
		case "name", "hostname":
			if !dnsName.MatchString(v) {
				return nil, badParam(k, "value does not look like a valid DNS name")
			}
		}
		if diskKey.MatchString(k) && !strings.HasPrefix(k, "unused") {
			nv, err := s.allocDisk(g, n, k, v)
			if err != nil {
				return nil, err
			}
			set[k] = nv
		}
		if strings.HasPrefix(k, "net") {
			set[k] = withMAC(g.kind, v)
		}
	}
	var del []string
	for _, k := range strings.FieldsFunc(form(r, "delete"), func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		del = append(del, k)
	}
	cold := g.kind == "qemu" && g.running()
	for k, v := range set {
		if cold && slices.Contains(coldKeys, k) && g.conf[k] != v {
			g.pending[k] = v
			continue
		}
		g.conf[k] = v
		delete(g.pending, k)
	}
	for _, k := range del {
		if cold && slices.Contains(coldKeys, k) {
			g.pendingDel[k] = true
			continue
		}
		s.dropKey(g, k)
	}
	if g.kind == "lxc" {
		return nil, nil
	}
	return s.run(n.name, "qmconfig", strconv.Itoa(g.vmid), 500*time.Millisecond, []string{"update VM " + strconv.Itoa(g.vmid) + ": " + strings.Join(sortedKeys(set), " ")}, nil), nil
}

// dropKey removes a key; a disk goes to unusedN (and an unused one is deleted).
func (s *Server) dropKey(g *guest, k string) {
	v, ok := g.conf[k]
	if !ok {
		return
	}
	delete(g.conf, k)
	delete(g.pending, k)
	delete(g.pendingDel, k)
	if diskKey.MatchString(k) && !strings.HasPrefix(k, "unused") && k != "rootfs" {
		if d := parseDisk(v); !d.cdrom && d.storage != "" {
			for i := 0; ; i++ {
				uk := "unused" + strconv.Itoa(i)
				if _, used := g.conf[uk]; !used {
					g.conf[uk] = d.volid + ",size=" + sizeText(d.size)
					break
				}
			}
		}
	}
}

func (s *Server) applyPending(g *guest) {
	for k, v := range g.pending {
		g.conf[k] = v
	}
	for k := range g.pendingDel {
		s.dropKey(g, k)
	}
	g.pending, g.pendingDel = map[string]string{}, map[string]bool{}
}

func (s *Server) pendingList(g *guest) []map[string]any {
	keys := map[string]bool{}
	for k := range g.conf {
		keys[k] = true
	}
	for k := range g.pending {
		keys[k] = true
	}
	var out []map[string]any
	for _, k := range sortedKeys(keys) {
		row := map[string]any{"key": k}
		if v, ok := g.conf[k]; ok {
			row["value"] = v
		}
		if v, ok := g.pending[k]; ok {
			row["pending"] = v
		}
		if g.pendingDel[k] {
			row["delete"] = 1
		}
		out = append(out, row)
	}
	return out
}

var newDisk = regexp.MustCompile(`^([A-Za-z0-9_-]+):(\d+(\.\d+)?|cloudinit)(,.*)?$`)

// allocDisk turns "storage:32,opts" into a new volume "storage:vm-ID-disk-N,opts,size=32G".
func (s *Server) allocDisk(g *guest, n *node, key, v string) (string, error) {
	m := newDisk.FindStringSubmatch(v)
	if m == nil {
		if d := parseDisk(v); d.storage != "" && !d.cdrom && !strings.Contains(v, "media=cdrom") {
			if _, ok := s.volume(n.name, d.volid); !ok && !s.guestDisk(d.volid) {
				return "", badParam(key, "unable to parse volume ID '"+d.volid+"'")
			}
		}
		return v, nil
	}
	st := s.storageOn(m[1], n.name)
	if st == nil {
		return "", fail(http.StatusInternalServerError, "storage '%s' does not exist", m[1])
	}
	opts := m[4]
	if m[2] == "cloudinit" {
		return m[1] + ":vm-" + strconv.Itoa(g.vmid) + "-cloudinit,media=cdrom", nil
	}
	want := "images"
	if g.kind == "lxc" {
		want = "rootdir"
	}
	if !strings.Contains(st.content, want) {
		return "", fail(http.StatusInternalServerError, "storage '%s' does not support %s content", st.name, want)
	}
	gb, _ := strconv.ParseFloat(m[2], 64)
	size := int64(gb * float64(gib))
	switch key {
	case "efidisk0", "tpmstate0":
		size = 4 * mib
	}
	if size <= 0 {
		return "", badParam(key, "size must be at least 1G")
	}
	idx := 0
	for s.guestDisk(fmt.Sprintf("%s:vm-%d-disk-%d", m[1], g.vmid, idx)) || strings.Contains(fmt.Sprint(g.conf), fmt.Sprintf("vm-%d-disk-%d", g.vmid, idx)) {
		idx++
	}
	opts = strings.ReplaceAll(opts, ",format=raw", "")
	return fmt.Sprintf("%s:vm-%d-disk-%d%s,size=%s", m[1], g.vmid, idx, opts, sizeText(size)), nil
}

func (s *Server) guestDisk(volid string) bool {
	for _, g := range s.guests {
		for _, d := range g.disks() {
			if d.volid == volid {
				return true
			}
		}
	}
	return false
}

func withMAC(kind, v string) string {
	if strings.Contains(v, "BC:24:11") || strings.Contains(strings.ToLower(v), "hwaddr=") {
		return v
	}
	if kind == "lxc" {
		if !strings.Contains(v, "name=") {
			v = "name=eth0," + v
		}
		return v + ",hwaddr=" + randMAC()
	}
	model, rest, _ := strings.Cut(v, ",")
	if strings.Contains(model, "=") {
		return v
	}
	if rest != "" {
		rest = "," + rest
	}
	return model + "=" + randMAC() + rest
}

func (s *Server) resize(r *http.Request, n *node, g *guest) (any, error) {
	if g.lock != "" {
		return nil, s.lockedErr(g)
	}
	key, size := form(r, "disk"), form(r, "size")
	v, ok := g.conf[key]
	if !ok {
		return nil, fail(http.StatusInternalServerError, "disk '%s' does not exist", key)
	}
	d := parseDisk(v)
	if d.cdrom {
		return nil, fail(http.StatusInternalServerError, "you can't resize a cdrom")
	}
	want := parseSize(strings.TrimPrefix(size, "+"))
	if strings.HasPrefix(size, "+") {
		want += d.size
	}
	if want < d.size {
		return nil, fail(http.StatusInternalServerError, "unable to skrink disk size")
	}
	if want == 0 {
		return nil, badParam("size", "value does not match the regex pattern")
	}
	re := regexp.MustCompile(`size=[0-9.]+[KMGT]?`)
	g.conf[key] = re.ReplaceAllString(v, "size="+sizeText(want))
	return s.run(n.name, "resize", strconv.Itoa(g.vmid), time.Second, []string{
		fmt.Sprintf("  Size of logical volume %s changed from %s to %s.", d.volid, sizeText(d.size), sizeText(want)),
		"  Logical volume " + d.volid + " successfully resized.",
	}, nil), nil
}

// Power

func (s *Server) power(r *http.Request, n *node, g *guest, action string) (any, error) {
	if g.lock != "" && !formBool(r, "skiplock") {
		return nil, s.lockedErr(g)
	}
	id := strconv.Itoa(g.vmid)
	pre := "qm"
	if g.kind == "lxc" {
		pre = "vz"
	}
	switch action {
	case "start":
		if g.template() {
			return nil, fail(http.StatusInternalServerError, "you can't start a vm if it's a template")
		}
		if g.running() {
			return nil, fail(http.StatusInternalServerError, "%s %d already running", g.noun(), g.vmid)
		}
		lines := []string{"generating cloud-init ISO"}
		if g.kind == "lxc" {
			lines = []string{"starting container " + id}
		}
		return s.run(n.name, pre+"start", id, 2*time.Second, lines, func() error {
			s.applyPending(g)
			g.status, g.paused, g.startedAt = "running", false, time.Now()
			return nil
		}), nil
	case "stop", "shutdown":
		d := 1500 * time.Millisecond
		if action == "shutdown" {
			d = 3 * time.Second
		}
		return s.run(n.name, pre+action, id, d, nil, func() error {
			g.status, g.paused = "stopped", false
			return nil
		}), nil
	case "reboot":
		if !g.running() {
			return nil, fail(http.StatusInternalServerError, "%s %d not running", g.noun(), g.vmid)
		}
		return s.run(n.name, pre+"reboot", id, 3*time.Second, nil, func() error {
			s.applyPending(g)
			g.paused, g.startedAt = false, time.Now()
			return nil
		}), nil
	case "suspend", "resume":
		if !g.running() {
			return nil, fail(http.StatusInternalServerError, "%s %d not running", g.noun(), g.vmid)
		}
		return s.run(n.name, pre+action, id, 800*time.Millisecond, nil, func() error {
			g.paused = action == "suspend"
			return nil
		}), nil
	}
	return nil, errNotFound
}

// Snapshots

var snapName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{1,39}$`)

func (s *Server) snapshotCall(r *http.Request, n *node, g *guest, p []string) (any, error) {
	id := strconv.Itoa(g.vmid)
	pre := "qm"
	if g.kind == "lxc" {
		pre = "vz"
	}
	switch {
	case len(p) == 0 && r.Method == http.MethodGet:
		out := []map[string]any{}
		for _, sn := range g.snaps {
			row := map[string]any{"name": sn.name, "description": sn.desc, "snaptime": sn.taken}
			if sn.parent != "" {
				row["parent"] = sn.parent
			}
			if sn.vmstate {
				row["vmstate"] = 1
			}
			out = append(out, row)
		}
		cur := map[string]any{"name": "current", "description": "You are here!", "running": b2i(g.running())}
		if g.parent != "" {
			cur["parent"] = g.parent
		}
		return append(out, cur), nil
	case len(p) == 0 && r.Method == http.MethodPost:
		name := form(r, "snapname")
		if !snapName.MatchString(name) {
			return nil, badParam("snapname", "invalid format - invalid configuration ID '"+name+"'")
		}
		if g.lock != "" {
			return nil, s.lockedErr(g)
		}
		if s.snap(g, name) != nil {
			return nil, fail(http.StatusInternalServerError, "snapshot name '%s' already used", name)
		}
		sn := &snapshot{name: name, desc: form(r, "description"), parent: g.parent, conf: cloneMap(g.conf),
			vmstate: formBool(r, "vmstate") && g.running() && g.kind == "qemu"}
		sn.running = sn.vmstate
		g.lock = "snapshot"
		lines := []string{"snapshotting 'drive-scsi0' (" + name + ")"}
		if sn.vmstate {
			lines = append([]string{"saving VM state and RAM using storage 'local-lvm'", "completed saving the VM state in 2s, saved 1.12 GiB"}, lines...)
		}
		return s.run(n.name, pre+"snapshot", id, 2*time.Second, lines, func() error {
			g.lock = ""
			sn.taken = time.Now().Unix()
			g.snaps = append(g.snaps, sn)
			g.parent = name
			return nil
		}), nil
	case len(p) == 1 && r.Method == http.MethodDelete:
		sn := s.snap(g, p[0])
		if sn == nil {
			return nil, fail(http.StatusInternalServerError, "snapshot '%s' does not exist", p[0])
		}
		if g.lock != "" {
			return nil, s.lockedErr(g)
		}
		g.lock = "snapshot-delete"
		return s.run(n.name, pre+"delsnapshot", id, 1500*time.Millisecond, nil, func() error {
			g.lock = ""
			g.snaps = slices.DeleteFunc(g.snaps, func(x *snapshot) bool { return x == sn })
			for _, x := range g.snaps {
				if x.parent == sn.name {
					x.parent = sn.parent
				}
			}
			if g.parent == sn.name {
				g.parent = sn.parent
			}
			return nil
		}), nil
	case len(p) == 2 && p[1] == "rollback" && r.Method == http.MethodPost:
		sn := s.snap(g, p[0])
		if sn == nil {
			return nil, fail(http.StatusInternalServerError, "snapshot '%s' does not exist", p[0])
		}
		if g.lock != "" {
			return nil, s.lockedErr(g)
		}
		start := formBool(r, "start")
		g.lock = "rollback"
		return s.run(n.name, pre+"rollback", id, 3*time.Second, []string{"Logical volume \"snap_vm-" + id + "-disk-0_" + sn.name + "\" successfully restored"}, func() error {
			g.lock = ""
			g.conf = cloneMap(sn.conf)
			g.pending, g.pendingDel = map[string]string{}, map[string]bool{}
			g.parent = sn.name
			if sn.vmstate || start {
				g.status, g.paused, g.startedAt = "running", false, time.Now()
			} else {
				g.status = "stopped"
			}
			return nil
		}), nil
	}
	return nil, errNotFound
}

func (s *Server) snap(g *guest, name string) *snapshot {
	for _, sn := range g.snaps {
		if sn.name == name {
			return sn
		}
	}
	return nil
}

// Lifecycle

func (s *Server) clone(r *http.Request, n *node, g *guest) (any, error) {
	newID, err := strconv.Atoi(form(r, "newid"))
	if err != nil || newID < 100 {
		return nil, badParam("newid", "value must have a minimum value of 100")
	}
	if other := s.guests[newID]; other != nil {
		return nil, fail(http.StatusInternalServerError, "unable to create %s %d: config file already exists", other.noun(), newID)
	}
	if g.lock != "" {
		return nil, s.lockedErr(g)
	}
	target := n.name
	if t := form(r, "target"); t != "" {
		tn := s.node(t)
		if tn == nil || !tn.online {
			return nil, fail(http.StatusInternalServerError, "target node '%s' is not online", t)
		}
		target = t
	}
	full := formBool(r, "full") || !g.template()
	storageName := form(r, "storage")
	if storageName != "" && s.storageOn(storageName, target) == nil {
		return nil, fail(http.StatusInternalServerError, "storage '%s' does not exist", storageName)
	}
	name := form(r, "name")
	if g.kind == "lxc" {
		name = form(r, "hostname")
	}
	if name == "" {
		name = "Copy-of-" + g.name()
	}
	conf := cloneMap(g.conf)
	delete(conf, "template")
	if g.kind == "lxc" {
		conf["hostname"] = name
	} else {
		conf["name"] = name
		conf["vmgenid"] = randHex(4) + "-" + randHex(2) + "-" + randHex(2) + "-" + randHex(2) + "-" + randHex(6)
	}
	idx := 0
	var lines []string
	for _, k := range sortedKeys(conf) {
		v := conf[k]
		if strings.HasPrefix(k, "unused") {
			delete(conf, k)
			continue
		}
		if strings.HasPrefix(k, "net") {
			conf[k] = regexp.MustCompile(`([0-9A-F]{2}:){5}[0-9A-F]{2}`).ReplaceAllString(v, randMAC())
			continue
		}
		if !diskKey.MatchString(k) {
			continue
		}
		d := parseDisk(v)
		if d.storage == "" || d.volid == "none" || strings.Contains(v, "media=cdrom") && !strings.Contains(v, "cloudinit") {
			continue
		}
		st := d.storage
		if storageName != "" && full {
			st = storageName
		}
		if strings.Contains(d.volid, "cloudinit") {
			conf[k] = fmt.Sprintf("%s:vm-%d-cloudinit,media=cdrom", st, newID)
			continue
		}
		vol := fmt.Sprintf("%s:vm-%d-disk-%d", st, newID, idx)
		if !full {
			vol = fmt.Sprintf("%s:%s/vm-%d-disk-%d", st, strings.TrimPrefix(d.volid, d.storage+":"), newID, idx)
		}
		idx++
		_, rest, _ := strings.Cut(v, ",")
		conf[k] = vol + "," + rest
		lines = append(lines, fmt.Sprintf("create full clone of drive %s (%s)", k, d.volid))
	}
	if !full {
		lines = []string{"create linked clone of drive scsi0 (" + parseDisk(g.conf["scsi0"]).volid + ")"}
	}
	ng := &guest{vmid: newID, kind: g.kind, node: target, status: "stopped", conf: conf, lock: "create",
		pending: map[string]string{}, pendingDel: map[string]bool{},
		fwOpts: map[string]string{"enable": "0", "policy_in": "DROP", "policy_out": "ACCEPT"}}
	s.guests[newID] = ng
	for i := 0; i <= 10; i++ {
		lines = append(lines, fmt.Sprintf("transferred %d.%d GiB of 3.5 GiB (%d.00%%)", i*35/100, i*35%100/10, i*10))
	}
	typ := "qmclone"
	if g.kind == "lxc" {
		typ = "vzclone"
	}
	t := s.runTask(n.name, typ, strconv.Itoa(g.vmid), 5*time.Second, lines, func() error {
		ng.lock = ""
		return nil
	})
	t.undo = func() {
		if s.guests[newID] == ng {
			delete(s.guests, newID)
		}
	}
	return t.upid, nil
}

func (s *Server) makeTemplate(n *node, g *guest) (any, error) {
	if g.running() {
		return nil, fail(http.StatusInternalServerError, "you can't convert a running VM to a template")
	}
	if g.template() {
		return nil, fail(http.StatusInternalServerError, "%s %d is already a template", g.noun(), g.vmid)
	}
	if g.lock != "" {
		return nil, s.lockedErr(g)
	}
	if len(g.snaps) > 0 && g.kind == "lxc" {
		return nil, fail(http.StatusInternalServerError, "you can't convert a CT to template if the CT has snapshots")
	}
	typ := "qmtemplate"
	if g.kind == "lxc" {
		typ = "vztemplate"
	}
	g.lock = "create"
	return s.run(n.name, typ, strconv.Itoa(g.vmid), 2*time.Second, []string{"  Renamed \"vm-" + strconv.Itoa(g.vmid) + "-disk-0\" to \"base-" + strconv.Itoa(g.vmid) + "-disk-0\""}, func() error {
		g.lock = ""
		for k, v := range g.conf {
			if diskKey.MatchString(k) {
				g.conf[k] = strings.ReplaceAll(v, fmt.Sprintf(":vm-%d-disk-", g.vmid), fmt.Sprintf(":base-%d-disk-", g.vmid))
			}
		}
		g.conf["template"] = "1"
		return nil
	}), nil
}

func (s *Server) destroy(r *http.Request, n *node, g *guest) (any, error) {
	if g.running() {
		return nil, fail(http.StatusInternalServerError, "%s %d is running - destroy failed", g.noun(), g.vmid)
	}
	if g.lock != "" {
		return nil, s.lockedErr(g)
	}
	if g.template() {
		for _, o := range s.guests {
			for _, d := range o.disks() {
				if o != g && strings.Contains(d.volid, fmt.Sprintf("base-%d-disk", g.vmid)) {
					return nil, fail(http.StatusInternalServerError, "base volume '%s' is still in use by linked cloned", d.volid)
				}
			}
		}
	}
	typ := "qmdestroy"
	if g.kind == "lxc" {
		typ = "vzdestroy"
	}
	g.lock = "destroyed"
	var lines []string
	for _, d := range g.disks() {
		lines = append(lines, "  Logical volume \""+d.volid+"\" successfully removed.")
	}
	return s.run(n.name, typ, strconv.Itoa(g.vmid), 2*time.Second, lines, func() error {
		delete(s.guests, g.vmid)
		if formBool(r, "purge") {
			delete(s.ha, g.sid())
		}
		return nil
	}), nil
}

func (s *Server) migrateCheck(r *http.Request, g *guest) (any, error) {
	out := map[string]any{"running": b2i(g.running()), "allowed_nodes": []string{}, "not_allowed_nodes": map[string]any{},
		"local_disks": []map[string]any{}, "local_resources": []string{}}
	var local []string
	for k, d := range g.disks() {
		if st := s.storageOn(d.storage, g.node); st != nil && !st.shared {
			out["local_disks"] = append(out["local_disks"].([]map[string]any), map[string]any{
				"volid": d.volid, "size": d.size, "drivename": k, "is_unused": b2i(strings.HasPrefix(k, "unused")), "cdrom": 0, "replicated": 0,
			})
			local = append(local, d.storage)
		}
	}
	var allowed []string
	notAllowed := map[string]any{}
	for _, n := range s.nodes {
		if n.name == g.node {
			continue
		}
		if !n.online {
			notAllowed[n.name] = map[string]any{"unavailable_storages": []string{"ceph-vm"}}
			continue
		}
		allowed = append(allowed, n.name)
	}
	out["allowed_nodes"], out["not_allowed_nodes"] = allowed, notAllowed
	if strings.Contains(g.conf["hostpci0"], ":") {
		out["local_resources"] = []string{"hostpci0"}
	}
	_ = r
	return out, nil
}

func (s *Server) migrate(r *http.Request, n *node, g *guest) (any, error) {
	target := form(r, "target")
	tn := s.node(target)
	if tn == nil {
		return nil, badParam("target", "no such cluster node '"+target+"'")
	}
	if target == g.node {
		return nil, fail(http.StatusInternalServerError, "target is local node.")
	}
	if !tn.online {
		return nil, fail(http.StatusInternalServerError, "target node '%s' is not online", target)
	}
	if g.lock != "" {
		return nil, s.lockedErr(g)
	}
	if g.template() && g.running() {
		return nil, fail(http.StatusInternalServerError, "can't migrate running template")
	}
	online, restart := formBool(r, "online"), formBool(r, "restart")
	if g.running() {
		if g.kind == "qemu" && !online {
			return nil, fail(http.StatusInternalServerError, "can't migrate running VM without --online")
		}
		if g.kind == "lxc" && !restart {
			return nil, fail(http.StatusInternalServerError, "lxc live migration is currently not implemented - use 'restart' mode")
		}
	}
	var localDisks []disk
	for _, d := range g.disks() {
		if st := s.storageOn(d.storage, g.node); st != nil && !st.shared {
			localDisks = append(localDisks, d)
		}
	}
	if len(localDisks) > 0 && g.running() && g.kind == "qemu" && !formBool(r, "with-local-disks") {
		return nil, fail(http.StatusInternalServerError, "can't live migrate attached local disks without with-local-disks option")
	}
	from := g.node
	typ := "qmigrate"
	if g.kind == "lxc" {
		typ = "vzmigrate"
	}
	lines := []string{fmt.Sprintf("starting migration of %s %d to node '%s' (%s)", g.noun(), g.vmid, target, tn.ip)}
	for _, d := range localDisks {
		lines = append(lines, "found local disk '"+d.volid+"' (attached)")
	}
	if g.running() && g.kind == "qemu" {
		lines = append(lines, "starting VM "+strconv.Itoa(g.vmid)+" on remote node '"+target+"'", "start remote tunnel", "starting online/live migration on unix:/run/qemu-server/"+strconv.Itoa(g.vmid)+".migrate")
		for i := 1; i <= 8; i++ {
			lines = append(lines, fmt.Sprintf("migration active, transferred %d.0 MiB of %d.0 MiB VM-state, %d.0 MiB/s", i*120, g.maxMem()/mib, 110+i))
		}
		lines = append(lines, "migration status: completed", "migration finished successfully (duration 00:00:09)")
	} else {
		if g.running() {
			lines = append(lines, "shutdown CT "+strconv.Itoa(g.vmid))
		}
		for i := 1; i <= 4; i++ {
			lines = append(lines, fmt.Sprintf("%d%% of the disks copied", i*25))
		}
		if g.running() {
			lines = append(lines, "start final cleanup", "start container on target node")
		}
	}
	g.lock = "migrate"
	return s.run(n.name, typ, strconv.Itoa(g.vmid), 8*time.Second, lines, func() error {
		g.lock = ""
		if !s.node(target).online {
			return fmt.Errorf("migration aborted: target node '%s' went offline", target)
		}
		g.node = target
		if g.running() && g.kind == "lxc" {
			g.startedAt = time.Now()
		}
		_ = from
		return nil
	}), nil
}

// Addresses

func (s *Server) addrOf(g *guest, cfg string) (ip string, prefix int) {
	for _, part := range strings.Split(cfg, ",") {
		if v, ok := strings.CutPrefix(part, "ip="); ok && v != "dhcp" && v != "" {
			a, p, _ := strings.Cut(v, "/")
			n, _ := strconv.Atoi(p)
			return a, n
		}
	}
	idx := 1
	if n := s.node(g.node); n != nil {
		idx = n.idx
	}
	return fmt.Sprintf("10.10.%d.%d", idx, 100+g.vmid%150), 16
}

func (s *Server) agentInterfaces(g *guest) (any, error) {
	if !strings.HasPrefix(g.conf["agent"], "1") && !strings.Contains(g.conf["agent"], "enabled=1") {
		return nil, fail(http.StatusInternalServerError, "No QEMU guest agent configured")
	}
	if !g.running() || g.paused || time.Since(g.startedAt) < s.dur(5*time.Second) {
		return nil, fail(http.StatusInternalServerError, "QEMU guest agent is not running")
	}
	type addr struct {
		Type   string `json:"ip-address-type"`
		IP     string `json:"ip-address"`
		Prefix int    `json:"prefix"`
	}
	type iface struct {
		Name  string `json:"name"`
		MAC   string `json:"hardware-address"`
		Addrs []addr `json:"ip-addresses"`
	}
	out := []iface{{Name: "lo", MAC: "00:00:00:00:00:00", Addrs: []addr{{"ipv4", "127.0.0.1", 8}, {"ipv6", "::1", 128}}}}
	for i := 0; i < 4; i++ {
		v, ok := g.conf["net"+strconv.Itoa(i)]
		if !ok {
			continue
		}
		mac := regexp.MustCompile(`([0-9A-F]{2}:){5}[0-9A-F]{2}`).FindString(v)
		ip, prefix := s.addrOf(g, g.conf["ipconfig"+strconv.Itoa(i)])
		if i > 0 {
			ip, prefix = fmt.Sprintf("172.16.0.%d", 100+g.vmid%150), 24
		}
		out = append(out, iface{Name: "eth" + strconv.Itoa(i), MAC: strings.ToLower(mac), Addrs: []addr{
			{"ipv4", ip, prefix}, {"ipv6", "fe80::be24:11ff:fe" + strings.ToLower(randHex(1)) + ":" + strings.ToLower(randHex(2)), 64},
		}})
	}
	if strings.Contains(g.conf["tags"], "ci") {
		out = append(out, iface{Name: "docker0", MAC: "02:42:ac:11:00:01", Addrs: []addr{{"ipv4", "172.17.0.1", 16}}})
	}
	return map[string]any{"result": out}, nil
}

func (s *Server) lxcInterfaces(g *guest) (any, error) {
	if !g.running() {
		return nil, fail(http.StatusInternalServerError, "CT %d not running", g.vmid)
	}
	out := []map[string]any{{"name": "lo", "hwaddr": "00:00:00:00:00:00", "inet": "127.0.0.1/8", "inet6": "::1/128"}}
	for i := 0; i < 4; i++ {
		v, ok := g.conf["net"+strconv.Itoa(i)]
		if !ok {
			continue
		}
		name := "eth" + strconv.Itoa(i)
		mac := ""
		for _, part := range strings.Split(v, ",") {
			if x, ok := strings.CutPrefix(part, "name="); ok {
				name = x
			}
			if x, ok := strings.CutPrefix(part, "hwaddr="); ok {
				mac = strings.ToLower(x)
			}
		}
		ip, prefix := s.addrOf(g, v)
		out = append(out, map[string]any{"name": name, "hwaddr": mac, "inet": ip + "/" + strconv.Itoa(prefix)})
	}
	return out, nil
}

// Firewall

var ruleKeys = []string{"type", "action", "enable", "source", "dest", "proto", "dport", "sport", "iface", "macro", "comment", "log"}

func (s *Server) firewall(r *http.Request, g *guest, p []string) (any, error) {
	m := r.Method
	switch {
	case len(p) == 1 && p[0] == "rules" && m == http.MethodGet:
		out := []map[string]any{}
		for i, rule := range g.rules {
			row := map[string]any{"pos": i}
			for k, v := range rule {
				if k == "enable" {
					n, _ := strconv.Atoi(v)
					row[k] = n
					continue
				}
				row[k] = v
			}
			out = append(out, row)
		}
		return out, nil
	case len(p) == 1 && p[0] == "rules" && m == http.MethodPost:
		rule, err := ruleFrom(r, nil)
		if err != nil {
			return nil, err
		}
		pos, _ := strconv.Atoi(form(r, "pos"))
		pos = max(0, min(pos, len(g.rules)))
		g.rules = slices.Insert(g.rules, pos, rule)
		return nil, nil
	case len(p) == 2 && p[0] == "rules":
		pos, err := strconv.Atoi(p[1])
		if err != nil || pos < 0 || pos >= len(g.rules) {
			return nil, fail(http.StatusInternalServerError, "no rule at position %s", p[1])
		}
		switch m {
		case http.MethodDelete:
			g.rules = slices.Delete(g.rules, pos, pos+1)
			return nil, nil
		case http.MethodPut:
			if to := form(r, "moveto"); to != "" {
				t, _ := strconv.Atoi(to)
				rule := g.rules[pos]
				g.rules = slices.Delete(g.rules, pos, pos+1)
				if t > pos {
					t--
				}
				t = max(0, min(t, len(g.rules)))
				g.rules = slices.Insert(g.rules, t, rule)
				return nil, nil
			}
			rule, err := ruleFrom(r, g.rules[pos])
			if err != nil {
				return nil, err
			}
			g.rules[pos] = rule
			return nil, nil
		}
	case len(p) == 1 && p[0] == "options" && m == http.MethodGet:
		out := map[string]any{}
		for k, v := range g.fwOpts {
			if n, err := strconv.Atoi(v); err == nil {
				out[k] = n
				continue
			}
			out[k] = v
		}
		return out, nil
	case len(p) == 1 && p[0] == "options" && m == http.MethodPut:
		for _, k := range []string{"enable", "policy_in", "policy_out", "macfilter", "dhcp", "ipfilter", "log_level_in", "log_level_out", "ndp", "radv"} {
			if v := form(r, k); v != "" {
				if strings.HasPrefix(k, "policy") && v != "ACCEPT" && v != "DROP" && v != "REJECT" {
					return nil, badParam(k, "value '"+v+"' does not have a value in the enumeration 'ACCEPT, REJECT, DROP'")
				}
				g.fwOpts[k] = v
			}
		}
		return nil, nil
	}
	return nil, errNotFound
}

var portList = regexp.MustCompile(`^[0-9]+([:-][0-9]+)?(,[0-9]+([:-][0-9]+)?)*$`)

func ruleFrom(r *http.Request, old map[string]string) (map[string]string, error) {
	rule := map[string]string{}
	if old != nil {
		rule = cloneMap(old)
	}
	for _, k := range ruleKeys {
		if v := form(r, k); v != "" {
			rule[k] = v
		}
	}
	for _, k := range strings.Split(form(r, "delete"), ",") {
		delete(rule, strings.TrimSpace(k))
	}
	switch rule["type"] {
	case "in", "out", "group":
	default:
		return nil, badParam("type", "value '"+rule["type"]+"' does not have a value in the enumeration 'in, out, forward, group'")
	}
	switch rule["action"] {
	case "ACCEPT", "DROP", "REJECT":
	default:
		if rule["type"] != "group" {
			return nil, badParam("action", "invalid format - value does not look like a valid security group name or action")
		}
	}
	for _, k := range []string{"dport", "sport"} {
		if v := rule[k]; v != "" && !portList.MatchString(v) {
			return nil, badParam(k, "invalid port '"+v+"'")
		}
	}
	if (rule["dport"] != "" || rule["sport"] != "") && rule["proto"] == "" {
		return nil, badParam("proto", "missing property - 'proto' is required with 'dport' or 'sport'")
	}
	if rule["enable"] == "" {
		rule["enable"] = "0"
	}
	return rule, nil
}

// HA

func (s *Server) haCall(r *http.Request, p []string) (any, error) {
	m := r.Method
	switch {
	case p[0] == "groups" && len(p) == 1:
		return []map[string]any{
			{"group": "prefer-pve1", "nodes": "pve1:2,pve2:1", "type": "group", "restricted": 0, "nofailback": 0},
			{"group": "pve2-pve3", "nodes": "pve2,pve3", "type": "group", "restricted": 1, "nofailback": 0},
		}, nil
	case p[0] == "resources" && len(p) == 1 && m == http.MethodGet:
		out := []map[string]any{}
		for _, k := range sortedKeys(s.ha) {
			h := s.ha[k]
			row := map[string]any{"sid": h.sid, "state": h.state, "max_restart": h.maxRestart, "max_relocate": h.maxRelocate, "type": h.sid[:2]}
			if h.group != "" {
				row["group"] = h.group
			}
			if h.comment != "" {
				row["comment"] = h.comment
			}
			out = append(out, row)
		}
		return out, nil
	case p[0] == "resources" && len(p) == 1 && m == http.MethodPost:
		sid := form(r, "sid")
		if s.ha[sid] != nil {
			return nil, fail(http.StatusInternalServerError, "resource ID '%s' already defined", sid)
		}
		_, idText, _ := strings.Cut(sid, ":")
		id, _ := strconv.Atoi(idText)
		if s.guests[id] == nil {
			return nil, fail(http.StatusInternalServerError, "no such VM %d", id)
		}
		h := &haResource{sid: sid}
		if err := s.haFill(r, h); err != nil {
			return nil, err
		}
		s.ha[sid] = h
		return nil, nil
	case p[0] == "resources" && len(p) == 2:
		h := s.ha[p[1]]
		if h == nil {
			return nil, fail(http.StatusInternalServerError, "no such resource '%s'", p[1])
		}
		switch m {
		case http.MethodDelete:
			delete(s.ha, p[1])
			return nil, nil
		case http.MethodPut:
			return nil, s.haFill(r, h)
		}
	}
	return nil, errNotFound
}

func (s *Server) haFill(r *http.Request, h *haResource) error {
	if v := form(r, "state"); v != "" {
		switch v {
		case "started", "stopped", "ignored", "disabled":
			h.state = v
		default:
			return badParam("state", "value '"+v+"' does not have a value in the enumeration 'started, stopped, enabled, disabled, ignored'")
		}
	}
	if h.state == "" {
		h.state = "started"
	}
	if v := form(r, "group"); v != "" {
		if v != "prefer-pve1" && v != "pve2-pve3" {
			return fail(http.StatusInternalServerError, "ha group '%s' does not exist", v)
		}
		h.group = v
	}
	if r.PostForm.Has("comment") {
		h.comment = form(r, "comment")
	}
	if v := form(r, "max_restart"); v != "" {
		h.maxRestart, _ = strconv.Atoi(v)
	}
	if v := form(r, "max_relocate"); v != "" {
		h.maxRelocate, _ = strconv.Atoi(v)
	}
	for _, k := range strings.Split(form(r, "delete"), ",") {
		switch k {
		case "group":
			h.group = ""
		case "comment":
			h.comment = ""
		}
	}
	return nil
}
