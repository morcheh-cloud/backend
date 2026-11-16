package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/jobs"
	"github.com/morche/backend/internal/proxmox"
)

type PVEGuestPath struct {
	ID   string `path:"id" format:"uuid"`
	VMID int    `path:"vmid" minimum:"1" maximum:"999999999"`
}

// PVEGuestLink is the Morche server a machine is.
type PVEGuestLink struct {
	ServerID     string `json:"server_id" format:"uuid"`
	ServerName   string `json:"server_name"`
	ServerStatus string `json:"server_status"`
}

// PVEGuest is a VM (qemu) or a container (lxc), as the cluster lists it.
type PVEGuest struct {
	ClusterID   string        `json:"cluster_id" format:"uuid"`
	ClusterName string        `json:"cluster_name"`
	VMID        int           `json:"vmid"`
	Kind        string        `json:"kind" enum:"qemu,lxc"`
	Name        string        `json:"name"`
	Node        string        `json:"node"`
	Status      string        `json:"status" doc:"running, stopped, paused (suspended) or unknown"`
	Template    bool          `json:"template"`
	CPU         float64       `json:"cpu" doc:"Share of its cores in use, 0–1"`
	CPUs        float64       `json:"cpus"`
	Mem         int64         `json:"mem"`
	MaxMem      int64         `json:"maxmem"`
	Disk        int64         `json:"disk"`
	MaxDisk     int64         `json:"maxdisk"`
	Uptime      int64         `json:"uptime"`
	NetIn       int64         `json:"netin"`
	NetOut      int64         `json:"netout"`
	Tags        []string      `json:"tags"`
	HAState     string        `json:"ha_state"`
	Lock        string        `json:"lock"`
	Pool        string        `json:"pool"`
	IPs         []string      `json:"ips" doc:"Addresses the guest agent (or the container) reports; empty when not known"`
	Link        *PVEGuestLink `json:"link,omitempty"`
}

func toPVEGuest(c sqlc.PveCluster, r proxmox.Resource) PVEGuest {
	status := r.Status
	if status == "" {
		status = "unknown"
	}
	return PVEGuest{
		ClusterID: c.ID.String(), ClusterName: c.Name, VMID: r.VMID, Kind: r.Type, Name: r.Name,
		Node: r.Node, Status: status, Template: r.Template == 1, CPU: r.CPU, CPUs: r.MaxCPU,
		Mem: r.Mem, MaxMem: r.MaxMem, Disk: r.Disk, MaxDisk: r.MaxDisk, Uptime: r.Uptime,
		NetIn: r.NetIn, NetOut: r.NetOut, Tags: nonNil(r.TagList()), HAState: r.HAState,
		Lock: r.Lock, Pool: r.Pool, IPs: []string{},
	}
}

// Guest addresses come from the guest agent, one request per machine: kept a
// minute so a list that polls doesn't ask every time.
var pveIPCache sync.Map // "cluster/vmid" → pveIPs

type pveIPs struct {
	ips []string
	at  time.Time
}

func usefulIPs(ifaces []proxmox.Interface) []string {
	out := []string{}
	for _, i := range ifaces {
		if i.Name == "lo" || strings.HasPrefix(i.Name, "docker") || strings.HasPrefix(i.Name, "veth") || strings.HasPrefix(i.Name, "br-") {
			continue
		}
		for _, a := range i.Addresses {
			ip := net.ParseIP(strings.Split(a, "/")[0])
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, ip.String())
		}
	}
	// IPv4 first.
	sort.SliceStable(out, func(a, b int) bool {
		return strings.Contains(out[b], ":") && !strings.Contains(out[a], ":")
	})
	return out
}

func (h *pveHandler) guestIPs(ctx context.Context, c sqlc.PveCluster, cl *proxmox.Client, g *PVEGuest, fresh bool) {
	key := fmt.Sprintf("%s/%d", c.ID, g.VMID)
	if v, ok := pveIPCache.Load(key); ok && !fresh && time.Since(v.(pveIPs).at) < time.Minute {
		g.IPs = v.(pveIPs).ips
		return
	}
	if g.Status != "running" || g.Template {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ifaces, err := cl.Interfaces(cctx, g.Node, proxmox.Kind(g.Kind), g.VMID)
	ips := []string{}
	if err == nil {
		ips = usefulIPs(ifaces)
	}
	pveIPCache.Store(key, pveIPs{ips, time.Now()})
	g.IPs = ips
}

// guestsOf lists a cluster's guests with their addresses and links.
func (h *pveHandler) guestsOf(ctx context.Context, c sqlc.PveCluster) ([]PVEGuest, error) {
	cl, err := h.savedClient(c)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	res, err := cl.Resources(cctx, "vm")
	if err != nil {
		return nil, err
	}
	out := make([]PVEGuest, 0, len(res))
	for _, r := range res {
		if r.Type == "qemu" || r.Type == "lxc" {
			out = append(out, toPVEGuest(c, r))
		}
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i := range out {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			h.guestIPs(ctx, c, cl, &out[i], false)
		}()
	}
	wg.Wait()
	sort.Slice(out, func(a, b int) bool { return out[a].VMID < out[b].VMID })
	return out, nil
}

func (h *pveHandler) addLinks(ctx context.Context, guests []PVEGuest) {
	ids := []uuid.UUID{}
	for _, g := range guests {
		id := uuid.MustParse(g.ClusterID)
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return
	}
	links, err := h.q.ListPVELinks(ctx, ids)
	if err != nil {
		return
	}
	p := principalOf(ctx)
	for i := range guests {
		for _, l := range links {
			if l.ClusterID.String() == guests[i].ClusterID && int(l.Vmid) == guests[i].VMID {
				// A server they can't see stays hidden.
				if lvl, err := h.authz.serverLevel(ctx, p.Access, l.ServerID); err != nil || lvl == auth.None {
					continue
				}
				guests[i].Link = &PVEGuestLink{ServerID: l.ServerID.String(), ServerName: l.ServerName, ServerStatus: l.ServerStatus}
			}
		}
	}
}

// PVEProblem is a cluster that didn't answer.
type PVEProblem struct {
	ClusterID   string `json:"cluster_id" format:"uuid"`
	ClusterName string `json:"cluster_name"`
	Message     string `json:"message"`
}

type PVEGuestsOutput struct {
	Body struct {
		Items    []PVEGuest   `json:"items"`
		Problems []PVEProblem `json:"problems"`
	}
}

// pveGuest finds a guest: its node and kind come from the cluster.
func (h *pveHandler) pveGuest(ctx context.Context, in PVEGuestPath) (sqlc.PveCluster, *proxmox.Client, proxmox.Resource, error) {
	c, cl, err := h.withCluster(ctx, in.ID)
	if err != nil {
		return c, nil, proxmox.Resource{}, err
	}
	r, err := cl.Find(ctx, in.VMID)
	if err != nil {
		if proxmox.IsMissing(err) {
			return c, nil, r, huma.Error404NotFound(fmt.Sprintf("Machine %d not found on this cluster", in.VMID))
		}
		return c, nil, r, pveError(err)
	}
	return c, cl, r, nil
}

// PVEGuestDetail is one guest with its settings and live state.
type PVEGuestDetail struct {
	PVEGuest
	QMPStatus      string             `json:"qmp_status"`
	Agent          bool               `json:"agent" doc:"The QEMU guest agent is turned on"`
	HAManaged      bool               `json:"ha_managed"`
	HAGroup        string             `json:"ha_group"`
	RunningMachine string             `json:"running_machine"`
	RunningQEMU    string             `json:"running_qemu"`
	Config         map[string]string  `json:"config" doc:"Proxmox's own keys (cores, memory, scsi0, net0…); cipassword is never sent"`
	Digest         string             `json:"digest" doc:"Send it back with a change: the change fails if the config moved on meanwhile"`
	Pending        []PVEPendingChange `json:"pending" doc:"Changes waiting for a restart"`
	Description    string             `json:"description"`
	OnBoot         bool               `json:"onboot"`
	Interfaces     []PVEInterface     `json:"interfaces"`
}

type PVEPendingChange struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Pending string `json:"pending"`
	Delete  bool   `json:"delete"`
}

type PVEInterface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac"`
	Addresses []string `json:"addresses"`
}

func redactConfig(s proxmox.Settings) map[string]string {
	out := map[string]string{}
	for k, v := range s {
		switch k {
		case "digest":
			continue
		case "cipassword":
			out[k] = "********"
		default:
			out[k] = v
		}
	}
	return out
}

func (h *pveHandler) detail(ctx context.Context, c sqlc.PveCluster, cl *proxmox.Client, r proxmox.Resource) (PVEGuestDetail, error) {
	kind := proxmox.Kind(r.Type)
	g := toPVEGuest(c, r)
	d := PVEGuestDetail{PVEGuest: g, Config: map[string]string{}, Pending: []PVEPendingChange{}, Interfaces: []PVEInterface{}}
	var (
		wg        sync.WaitGroup
		st        proxmox.GuestStatus
		cfg       proxmox.Settings
		pend      []proxmox.PendingItem
		ifaces    []proxmox.Interface
		stErr     error
		cfgErr    error
		ifacesErr error
	)
	wg.Add(3)
	go func() { defer wg.Done(); st, stErr = cl.GuestStatus(ctx, r.Node, kind, r.VMID) }()
	go func() {
		defer wg.Done()
		cfg, cfgErr = cl.GuestConfig(ctx, r.Node, kind, r.VMID)
		pend, _ = cl.Pending(ctx, r.Node, kind, r.VMID)
	}()
	go func() {
		defer wg.Done()
		if r.Status != "running" {
			return
		}
		ictx, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		ifaces, ifacesErr = cl.Interfaces(ictx, r.Node, kind, r.VMID)
	}()
	wg.Wait()
	if cfgErr != nil {
		return d, pveError(cfgErr)
	}
	if stErr == nil {
		d.QMPStatus, d.HAManaged, d.HAGroup = st.QMPStatus, st.HA.Managed == 1, st.HA.Group
		d.RunningMachine, d.RunningQEMU = st.RunningMachine, st.RunningQEMU
		// status/current is live; cluster/resources lags pvestatd by ~10 s,
		// so a power change shows at once.
		if st.Status != "" {
			d.Status = st.Status
			if st.Status != "running" {
				d.Uptime = 0
			}
		}
		if st.QMPStatus == "paused" || st.QMPStatus == "suspended" || st.QMPStatus == "prelaunch" {
			d.Status = "paused"
		}
		if st.Uptime > 0 {
			d.Uptime = st.Uptime
		}
	}
	d.Digest = cfg["digest"]
	if cfg["template"] == "1" {
		d.Template = true // cluster/resources lags a fresh conversion
	}
	d.Config = redactConfig(cfg)
	d.Description = cfg["description"]
	d.OnBoot = cfg["onboot"] == "1"
	d.Agent = strings.HasPrefix(cfg["agent"], "1") || strings.Contains(cfg["agent"], "enabled=1")
	for _, p := range pend {
		if p.Pending == nil && p.Delete == 0 {
			continue
		}
		v, pv := proxmox.Str(p.Value), proxmox.Str(p.Pending)
		if p.Key == "cipassword" {
			v, pv = "********", "********"
		}
		d.Pending = append(d.Pending, PVEPendingChange{Key: p.Key, Value: v, Pending: pv, Delete: p.Delete > 0})
	}
	if ifacesErr == nil {
		for _, i := range ifaces {
			d.Interfaces = append(d.Interfaces, PVEInterface{Name: i.Name, MAC: i.MAC, Addresses: nonNil(i.Addresses)})
		}
		d.IPs = usefulIPs(ifaces)
		pveIPCache.Store(fmt.Sprintf("%s/%d", c.ID, r.VMID), pveIPs{d.IPs, time.Now()})
	}
	gs := []PVEGuest{d.PVEGuest}
	h.addLinks(ctx, gs)
	d.Link = gs[0].Link
	return d, nil
}

type PVEGuestDetailOutput struct {
	Body PVEGuestDetail
}

// The generic task job: the request starts a Proxmox task (so a refusal shows
// at once), the job follows it to the end with its log.
type pveTaskParams struct {
	Cluster string `json:"cluster"`
	Node    string `json:"node"`
	Kind    string `json:"kind"`
	VMID    int    `json:"vmid"`
	UPID    string `json:"upid"`
	// Then is a step after the task: "delete" (a machine stopped to be
	// removed), "start" (after a clone or a restore).
	Then string `json:"then,omitempty"`
	// Unlink forgets the server link once the machine is gone.
	Unlink bool `json:"unlink,omitempty"`
}

func (h *pveHandler) follow(ctx context.Context, c sqlc.PveCluster, r proxmox.Resource, title, upid string, extra func(*pveTaskParams)) (*JobOutput, error) {
	p := pveTaskParams{Cluster: c.ID.String(), Node: r.Node, Kind: r.Type, VMID: r.VMID, UPID: upid}
	if extra != nil {
		extra(&p)
	}
	name := r.Name
	if name == "" {
		name = strconv.Itoa(r.VMID)
	}
	return submit(ctx, h.runner, jobs.Spec{
		Kind: "pve-task", Title: title, Params: p, Refs: []uuid.UUID{c.ID},
		Target: JobPlace{ClusterID: c.ID.String(), VMID: r.VMID, Name: name}, Quick: true,
	})
}

func guestName(r proxmox.Resource) string {
	if r.Name != "" {
		return r.Name
	}
	return strconv.Itoa(r.VMID)
}

var powerActions = map[string]string{
	"start": "Start", "stop": "Stop", "shutdown": "Shut down", "reboot": "Reboot",
	"suspend": "Suspend", "resume": "Resume", "reset": "Reset",
}

type PVEPowerBody struct {
	Action  string `json:"action" enum:"start,stop,shutdown,reboot,suspend,resume,reset"`
	Timeout int    `json:"timeout,omitempty" minimum:"0" maximum:"3600" doc:"Shut down: seconds to wait for the guest before giving up"`
	Force   bool   `json:"force,omitempty" doc:"Shut down: stop it when the timeout passes"`
	ToDisk  bool   `json:"to_disk,omitempty" doc:"Suspend (VMs): hibernate to disk instead of pausing in memory"`
}

var snapName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{1,39}$`)

type PVEHardwareBody struct {
	Set    map[string]string `json:"set,omitempty" doc:"Proxmox config keys to set (cores, memory, net0, scsi1 = local-lvm:32, boot…)"`
	Delete []string          `json:"delete,omitempty" doc:"Keys to remove (an unused disk, a NIC)"`
	Digest string            `json:"digest,omitempty"`
}

// Keys a hardware change may touch. Hookscripts, raw QEMU args and
// passthrough are left to the Proxmox UI: they can reach the host itself.
var pveKeyAllowed = regexp.MustCompile(`^(name|description|tags|onboot|startup|protection|cores|sockets|vcpus|cpu|cpulimit|cpuunits|numa|memory|balloon|shares|swap|boot|bootdisk|ostype|machine|bios|agent|scsihw|vga|tablet|hotplug|localtime|keyboard|ciuser|cipassword|citype|ciupgrade|sshkeys|nameserver|searchdomain|ipconfig\d+|net\d+|(scsi|sata|virtio|ide|efidisk|tpmstate|unused|mp|rootfs)\d*|serial\d|cdrom|hostname|arch|unprivileged|features|nesting|console|tty|cmode)$`)

func (h *pveHandler) checkKeys(b PVEHardwareBody) error {
	for k, v := range b.Set {
		if !pveKeyAllowed.MatchString(k) {
			return huma.Error422UnprocessableEntity("Morche doesn't change " + k + ": use the Proxmox web interface for it")
		}
		if strings.ContainsAny(v, "\n\r") {
			return huma.Error422UnprocessableEntity("A value can't hold a new line: " + k)
		}
	}
	for _, k := range b.Delete {
		if !pveKeyAllowed.MatchString(k) {
			return huma.Error422UnprocessableEntity("Morche doesn't remove " + k + ": use the Proxmox web interface for it")
		}
	}
	return nil
}

// PVETask is a task in a guest's or node's history.
type PVETask struct {
	UPID      string     `json:"upid"`
	Node      string     `json:"node"`
	Type      string     `json:"type"`
	ID        string     `json:"id"`
	User      string     `json:"user"`
	Status    string     `json:"status" doc:"running, ok or what went wrong"`
	OK        bool       `json:"ok"`
	Running   bool       `json:"running"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
}

func toPVETask(t proxmox.TaskStatus) PVETask {
	out := PVETask{
		UPID: t.UPID, Node: t.Node, Type: t.Type, ID: t.ID, User: t.User,
		Running: t.Status == "running", StartedAt: time.Unix(t.StartTime, 0),
	}
	if t.EndTime > 0 {
		e := time.Unix(t.EndTime, 0)
		out.EndedAt = &e
	}
	out.OK = !out.Running && t.OK()
	switch {
	case out.Running:
		out.Status = "running"
	case out.OK:
		out.Status = "ok"
	default:
		out.Status = t.ExitStatus
	}
	return out
}

type PVETasksOutput struct {
	Body struct {
		Items []PVETask `json:"items"`
	}
}

func (h *pveHandler) tasksOf(ctx context.Context, cl *proxmox.Client, vmid, limit int) ([]PVETask, error) {
	nodes, err := cl.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		out = []PVETask{}
	)
	for _, n := range nodes {
		if n.Status != "online" {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			ts, err := cl.Tasks(ctx, n.Node, vmid, limit)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, t := range ts {
				out = append(out, toPVETask(t))
			}
		}()
	}
	wg.Wait()
	sort.Slice(out, func(a, b int) bool { return out[a].StartedAt.After(out[b].StartedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

type PVESnapshot struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Parent      string     `json:"parent"`
	TakenAt     *time.Time `json:"taken_at,omitempty"`
	WithRAM     bool       `json:"with_ram"`
	Current     bool       `json:"current" doc:"The 'now' entry: where the machine is"`
}

type PVEBackup struct {
	VolID     string    `json:"volid"`
	Storage   string    `json:"storage"`
	Node      string    `json:"node"`
	Format    string    `json:"format"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
	Notes     string    `json:"notes"`
	Protected bool      `json:"protected"`
	Verified  string    `json:"verified" doc:"ok, failed or empty (PBS only)"`
	VMID      int       `json:"vmid"`
}

func toPVEBackup(node, storage string, v proxmox.Volume) PVEBackup {
	return PVEBackup{
		VolID: v.VolID, Storage: storage, Node: node, Format: v.Format, Size: v.Size,
		CreatedAt: time.Unix(v.CTime, 0), Notes: v.Notes, Protected: v.Protected == 1,
		Verified: v.Verification.State, VMID: v.VMID,
	}
}

// backupsOf lists a guest's backups on every storage that holds backups on
// its node (shared storages show once).
func (h *pveHandler) backupsOf(ctx context.Context, cl *proxmox.Client, node string, vmid int) ([]PVEBackup, []string, error) {
	stores, err := cl.Storages(ctx, node, "backup")
	if err != nil {
		return nil, nil, err
	}
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		out      = []PVEBackup{}
		problems = []string{}
	)
	for _, s := range stores {
		if s.Active != 1 {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			vols, err := cl.Content(ctx, node, s.Storage, "backup", vmid)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				_, m := pveStatus(err)
				problems = append(problems, s.Storage+": "+m)
				return
			}
			for _, v := range vols {
				out = append(out, toPVEBackup(node, s.Storage, v))
			}
		}()
	}
	wg.Wait()
	sort.Slice(out, func(a, b int) bool { return out[a].CreatedAt.After(out[b].CreatedAt) })
	return out, problems, nil
}

type PVECloudInit struct {
	User         string            `json:"user"`
	HasPassword  bool              `json:"has_password"`
	SSHKeys      string            `json:"ssh_keys" doc:"One public key per line"`
	IPConfig     map[string]string `json:"ip_config" doc:"ipconfig0… as Proxmox writes them: ip=dhcp or ip=10.0.0.5/24,gw=10.0.0.1"`
	Nameserver   string            `json:"nameserver"`
	SearchDomain string            `json:"search_domain"`
	Type         string            `json:"type" doc:"nocloud, configdrive2 or opennebula; empty = Proxmox's default"`
	Upgrade      bool              `json:"upgrade" doc:"Upgrade packages on first boot"`
	HasDrive     bool              `json:"has_drive" doc:"The VM has a cloud-init drive"`
}

func cloudInitOf(cfg proxmox.Settings) PVECloudInit {
	ci := PVECloudInit{
		User: cfg["ciuser"], HasPassword: cfg["cipassword"] != "", Nameserver: cfg["nameserver"],
		SearchDomain: cfg["searchdomain"], Type: cfg["citype"], Upgrade: cfg["ciupgrade"] != "0",
		IPConfig: map[string]string{},
	}
	if k, err := url.PathUnescape(cfg["sshkeys"]); err == nil {
		ci.SSHKeys = strings.TrimSpace(k)
	}
	for k, v := range cfg {
		if strings.HasPrefix(k, "ipconfig") {
			ci.IPConfig[k] = v
		}
		if strings.Contains(v, "cloudinit") && regexp.MustCompile(`^(ide|scsi|sata)\d+$`).MatchString(k) {
			ci.HasDrive = true
		}
	}
	return ci
}

// Proxmox wants sshkeys URL-encoded, with %20 for spaces.
func encodeSSHKeys(keys string) string {
	lines := []string{}
	for l := range strings.SplitSeq(keys, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return strings.ReplaceAll(url.QueryEscape(strings.Join(lines, "\n")), "+", "%20")
}

type PVECloudInitBody struct {
	User         string            `json:"user,omitempty" maxLength:"64"`
	Password     string            `json:"password,omitempty" maxLength:"200" doc:"Blank keeps the saved one"`
	ClearPass    bool              `json:"clear_password,omitempty"`
	SSHKeys      string            `json:"ssh_keys,omitempty" maxLength:"20000"`
	IPConfig     map[string]string `json:"ip_config,omitempty"`
	Nameserver   string            `json:"nameserver,omitempty" maxLength:"200"`
	SearchDomain string            `json:"search_domain,omitempty" maxLength:"200"`
	Upgrade      *bool             `json:"upgrade,omitempty"`
}

var ipconfigKey = regexp.MustCompile(`^ipconfig\d+$`)

type PVEFirewall struct {
	Options PVEFirewallOptions `json:"options"`
	Rules   []PVEFirewallRule  `json:"rules"`
}

type PVEFirewallOptions struct {
	Enable    bool   `json:"enable"`
	PolicyIn  string `json:"policy_in" enum:"ACCEPT,DROP,REJECT,"`
	PolicyOut string `json:"policy_out" enum:"ACCEPT,DROP,REJECT,"`
	MACFilter bool   `json:"macfilter"`
	DHCP      bool   `json:"dhcp"`
	IPFilter  bool   `json:"ipfilter"`
}

type PVEFirewallRule struct {
	Pos     int    `json:"pos" doc:"Its place; ignored when adding"`
	Type    string `json:"type" enum:"in,out,group"`
	Action  string `json:"action" minLength:"1" maxLength:"64" doc:"ACCEPT, DROP, REJECT, or a security group's name"`
	Enable  bool   `json:"enable"`
	Source  string `json:"source" maxLength:"512"`
	Dest    string `json:"dest" maxLength:"512"`
	Proto   string `json:"proto" maxLength:"20"`
	DPort   string `json:"dport" maxLength:"200"`
	SPort   string `json:"sport" maxLength:"200"`
	Iface   string `json:"iface" maxLength:"20"`
	Macro   string `json:"macro" maxLength:"64"`
	Comment string `json:"comment" maxLength:"500"`
	Log     string `json:"log" maxLength:"20"`
}

func fromFWRule(r proxmox.FirewallRule) PVEFirewallRule {
	return PVEFirewallRule{
		Pos: r.Pos, Type: r.Type, Action: r.Action, Enable: r.Enable == 1, Source: r.Source,
		Dest: r.Dest, Proto: r.Proto, DPort: r.DPort, SPort: r.SPort, Iface: r.Iface,
		Macro: r.Macro, Comment: r.Comment, Log: r.Log,
	}
}

func toFWRule(r PVEFirewallRule) proxmox.FirewallRule {
	en := 0
	if r.Enable {
		en = 1
	}
	return proxmox.FirewallRule{
		Pos: r.Pos, Type: r.Type, Action: r.Action, Enable: en, Source: r.Source, Dest: r.Dest,
		Proto: r.Proto, DPort: r.DPort, SPort: r.SPort, Iface: r.Iface, Macro: r.Macro,
		Comment: r.Comment, Log: r.Log,
	}
}

type PVEHABody struct {
	State       string `json:"state" enum:"started,stopped,disabled,ignored"`
	Group       string `json:"group,omitempty" maxLength:"64"`
	MaxRestart  int    `json:"max_restart" minimum:"0" maximum:"10"`
	MaxRelocate int    `json:"max_relocate" minimum:"0" maximum:"10"`
	Comment     string `json:"comment,omitempty" maxLength:"500"`
}

type PVEFirewallRulePath struct {
	PVEGuestPath
	Pos int `path:"pos" minimum:"0" maximum:"9999"`
}

type PVESnapshotPath struct {
	PVEGuestPath
	Name string `path:"name" minLength:"1" maxLength:"40"`
}

func registerPVEGuests(api huma.API, h *pveHandler) {
	tags := []string{"Virtual machines"}

	huma.Register(api, huma.Operation{
		OperationID: "list-pve-guests-everywhere", Method: http.MethodGet, Path: "/pve-guests",
		Summary:     "Machines on every Proxmox cluster",
		Description: "VMs and containers of every cluster in scope, asked at once. A cluster that doesn't answer is listed under problems.",
		Tags:        tags,
	}, func(ctx context.Context, _ *struct{}) (*PVEGuestsOutput, error) {
		rows, err := h.listClusters(ctx)
		if err != nil {
			return nil, err
		}
		var (
			mu  sync.Mutex
			wg  sync.WaitGroup
			out = &PVEGuestsOutput{}
		)
		out.Body.Items, out.Body.Problems = []PVEGuest{}, []PVEProblem{}
		for _, c := range rows {
			wg.Add(1)
			go func() {
				defer wg.Done()
				gs, err := h.guestsOf(ctx, c)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					_, m := pveStatus(err)
					out.Body.Problems = append(out.Body.Problems, PVEProblem{ClusterID: c.ID.String(), ClusterName: c.Name, Message: m})
					return
				}
				out.Body.Items = append(out.Body.Items, gs...)
			}()
		}
		wg.Wait()
		h.addLinks(ctx, out.Body.Items)
		sort.SliceStable(out.Body.Items, func(a, b int) bool {
			x, y := out.Body.Items[a], out.Body.Items[b]
			if x.ClusterName != y.ClusterName {
				return x.ClusterName < y.ClusterName
			}
			return x.VMID < y.VMID
		})
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-pve-guests", Method: http.MethodGet, Path: "/pve-clusters/{id}/guests",
		Summary: "Machines on a Proxmox cluster", Tags: tags,
	}, func(ctx context.Context, in *struct{ PVEClusterIDPath }) (*PVEGuestsOutput, error) {
		c, err := h.cluster(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		gs, err := h.guestsOf(ctx, c)
		if err != nil {
			return nil, pveError(err)
		}
		h.addLinks(ctx, gs)
		out := &PVEGuestsOutput{}
		out.Body.Items, out.Body.Problems = gs, []PVEProblem{}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-pve-guest", Method: http.MethodGet, Path: "/pve-clusters/{id}/guests/{vmid}",
		Summary: "A machine with its settings", Tags: tags,
	}, func(ctx context.Context, in *struct{ PVEGuestPath }) (*PVEGuestDetailOutput, error) {
		c, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		d, err := h.detail(ctx, c, cl, r)
		if err != nil {
			return nil, err
		}
		return &PVEGuestDetailOutput{Body: d}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "power-pve-guest", Method: http.MethodPost, Path: "/pve-clusters/{id}/guests/{vmid}/power",
		Summary: "Start, stop, shut down, reboot, suspend or resume a machine", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEGuestPath
		Body PVEPowerBody
	}) (*JobOutput, error) {
		c, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		b := in.Body
		if r.Template == 1 {
			return nil, huma.Error422UnprocessableEntity("A template can't be started: clone it first")
		}
		opts := url.Values{}
		if b.Action == "shutdown" {
			if b.Timeout > 0 {
				opts.Set("timeout", strconv.Itoa(b.Timeout))
			}
			if b.Force {
				opts.Set("forceStop", "1")
			}
		}
		if b.Action == "suspend" && b.ToDisk && r.Type == "qemu" {
			opts.Set("todisk", "1")
		}
		if r.Type == "lxc" && (b.Action == "reset") {
			return nil, huma.Error422UnprocessableEntity("A container can't be reset: reboot it")
		}
		upid, err := cl.Power(ctx, r.Node, proxmox.Kind(r.Type), r.VMID, b.Action, opts)
		if err != nil {
			return nil, pveError(err)
		}
		if b.Action == "start" || b.Action == "stop" {
			markPVEPower(c.ID, r.VMID)
		}
		if b.Action == "shutdown" || b.Action == "suspend" {
			markPVEPower(c.ID, r.VMID)
		}
		return h.follow(ctx, c, r, powerActions[b.Action]+" "+guestName(r), upid, nil)
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-pve-guest-rrd", Method: http.MethodGet, Path: "/pve-clusters/{id}/guests/{vmid}/rrd",
		Summary: "A machine's usage over time", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEGuestPath
		Timeframe string `query:"timeframe" enum:"hour,day,week,month,year" default:"hour"`
	}) (*PVERRDOutput, error) {
		_, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		pts, err := cl.GuestRRD(ctx, r.Node, proxmox.Kind(r.Type), r.VMID, in.Timeframe)
		if err != nil {
			return nil, pveError(err)
		}
		return rrdOutput(pts), nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-pve-guest-config", Method: http.MethodPut, Path: "/pve-clusters/{id}/guests/{vmid}/config",
		Summary:     "Change a machine's hardware or options",
		Description: "Sends Proxmox config keys as they are. A change that needs a restart shows under pending.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		PVEGuestPath
		Body PVEHardwareBody
	}) (*JobOutput, error) {
		c, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		if err := h.checkKeys(in.Body); err != nil {
			return nil, err
		}
		if len(in.Body.Set) == 0 && len(in.Body.Delete) == 0 {
			return nil, huma.Error422UnprocessableEntity("Nothing to change")
		}
		upid, err := cl.SetConfig(ctx, r.Node, proxmox.Kind(r.Type), r.VMID, in.Body.Set, in.Body.Delete, in.Body.Digest)
		if err != nil {
			// Proxmox 8+ says "detected modified configuration - file changed
			// by other user?", older ones mention the digest.
			if msg := strings.ToLower(err.Error()); strings.Contains(msg, "digest") || strings.Contains(msg, "modified configuration") {
				return nil, huma.Error409Conflict("The machine's settings changed since you opened them. Reload and try again.")
			}
			return nil, pveError(err)
		}
		return h.follow(ctx, c, r, "Change settings of "+guestName(r), upid, nil)
	})

	huma.Register(api, huma.Operation{
		OperationID: "resize-pve-guest-disk", Method: http.MethodPost, Path: "/pve-clusters/{id}/guests/{vmid}/resize",
		Summary: "Grow a machine's disk", Description: "Disks only grow. The filesystem inside still needs growing (cloud-init images do it on boot).", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEGuestPath
		Body struct {
			Disk string `json:"disk" pattern:"^(scsi|sata|virtio|ide|mp|rootfs)[0-9]*$"`
			Size string `json:"size" pattern:"^\\+?[0-9]+(\\.[0-9]+)?[KMGT]?$" doc:"+10G grows by 10 GiB, 40G sets it to 40 GiB"`
		}
	}) (*JobOutput, error) {
		c, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		upid, err := cl.Resize(ctx, r.Node, proxmox.Kind(r.Type), r.VMID, in.Body.Disk, in.Body.Size)
		if err != nil {
			return nil, pveError(err)
		}
		return h.follow(ctx, c, r, "Grow "+in.Body.Disk+" of "+guestName(r), upid, nil)
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-pve-snapshots", Method: http.MethodGet, Path: "/pve-clusters/{id}/guests/{vmid}/snapshots",
		Summary: "A machine's snapshots", Tags: tags,
	}, func(ctx context.Context, in *struct{ PVEGuestPath }) (*struct {
		Body struct {
			Items []PVESnapshot `json:"items"`
		}
	}, error) {
		_, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		snaps, err := cl.Snapshots(ctx, r.Node, proxmox.Kind(r.Type), r.VMID)
		if err != nil {
			return nil, pveError(err)
		}
		out := &struct {
			Body struct {
				Items []PVESnapshot `json:"items"`
			}
		}{}
		out.Body.Items = []PVESnapshot{}
		for _, s := range snaps {
			ps := PVESnapshot{Name: s.Name, Description: strings.TrimSpace(s.Description), Parent: s.Parent, WithRAM: s.VMState == 1, Current: s.Name == "current"}
			if s.SnapTime > 0 {
				t := time.Unix(s.SnapTime, 0)
				ps.TakenAt = &t
			}
			out.Body.Items = append(out.Body.Items, ps)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-pve-snapshot", Method: http.MethodPost, Path: "/pve-clusters/{id}/guests/{vmid}/snapshots",
		Summary: "Take a snapshot", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEGuestPath
		Body struct {
			Name        string `json:"name" minLength:"2" maxLength:"40"`
			Description string `json:"description,omitempty" maxLength:"1000"`
			WithRAM     bool   `json:"with_ram,omitempty" doc:"VMs: keep the memory too, so a rollback lands in the running machine"`
		}
	}) (*JobOutput, error) {
		c, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		if !snapName.MatchString(in.Body.Name) || in.Body.Name == "current" {
			return nil, fieldError("body.name", "Start with a letter; use letters, digits, - and _ (2–40)", in.Body.Name)
		}
		upid, err := cl.CreateSnapshot(ctx, r.Node, proxmox.Kind(r.Type), r.VMID, in.Body.Name, in.Body.Description, in.Body.WithRAM && r.Type == "qemu" && r.Status == "running")
		if err != nil {
			return nil, pveError(err)
		}
		return h.follow(ctx, c, r, "Snapshot "+guestName(r)+" ("+in.Body.Name+")", upid, nil)
	})

	huma.Register(api, huma.Operation{
		OperationID: "rollback-pve-snapshot", Method: http.MethodPost, Path: "/pve-clusters/{id}/guests/{vmid}/snapshots/{name}/rollback",
		Summary: "Go back to a snapshot", Description: "Everything since the snapshot is lost.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVESnapshotPath
		Body struct {
			Start bool `json:"start,omitempty" doc:"Start the machine afterwards (when the snapshot has no memory)"`
		}
	}) (*JobOutput, error) {
		c, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		upid, err := cl.RollbackSnapshot(ctx, r.Node, proxmox.Kind(r.Type), r.VMID, in.Name, in.Body.Start)
		if err != nil {
			return nil, pveError(err)
		}
		markPVEPower(c.ID, r.VMID)
		return h.follow(ctx, c, r, "Roll "+guestName(r)+" back to "+in.Name, upid, nil)
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-pve-snapshot", Method: http.MethodDelete, Path: "/pve-clusters/{id}/guests/{vmid}/snapshots/{name}",
		Summary: "Delete a snapshot", Tags: tags,
	}, func(ctx context.Context, in *struct{ PVESnapshotPath }) (*JobOutput, error) {
		c, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		upid, err := cl.DeleteSnapshot(ctx, r.Node, proxmox.Kind(r.Type), r.VMID, in.Name)
		if err != nil {
			return nil, pveError(err)
		}
		return h.follow(ctx, c, r, "Delete snapshot "+in.Name+" of "+guestName(r), upid, nil)
	})

	huma.Register(api, huma.Operation{
		OperationID: "clone-pve-guest", Method: http.MethodPost, Path: "/pve-clusters/{id}/guests/{vmid}/clone",
		Summary: "Clone a machine or template", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEGuestPath
		Body struct {
			NewID    int    `json:"new_id,omitempty" minimum:"0" maximum:"999999999" doc:"0 = the next free id"`
			Name     string `json:"name,omitempty" maxLength:"63"`
			Full     bool   `json:"full" doc:"A full copy. A linked clone (templates only) shares the template's disks"`
			Target   string `json:"target,omitempty" maxLength:"64" doc:"Node to put it on"`
			Storage  string `json:"storage,omitempty" maxLength:"64" doc:"Full clone: storage for its disks"`
			Start    bool   `json:"start,omitempty"`
			Snapshot string `json:"snapshot,omitempty" maxLength:"40" doc:"Clone from this snapshot instead of the current state"`
		}
	}) (*JobOutput, error) {
		c, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		b := in.Body
		if !b.Full && r.Template != 1 {
			// cluster/resources lags a fresh conversion: ask the config.
			if cfg, err := cl.GuestConfig(ctx, r.Node, proxmox.Kind(r.Type), r.VMID); err == nil && cfg["template"] == "1" {
				r.Template = 1
			}
		}
		if !b.Full && r.Template != 1 {
			return nil, fieldError("body.full", "Only a template can be linked-cloned: make a full copy", false)
		}
		if b.Snapshot == "current" {
			b.Snapshot = ""
		}
		if b.Snapshot == "" && r.Type == "lxc" && r.Status == "running" && r.Template != 1 {
			return nil, fieldError("body.snapshot", "A running container can only be copied from a snapshot: pick one, or shut it down first", "")
		}
		if b.NewID == 0 {
			if b.NewID, err = cl.NextID(ctx); err != nil {
				return nil, pveError(err)
			}
		}
		if b.Name != "" && !pveNameRe.MatchString(b.Name) {
			return nil, fieldError("body.name", "Use letters, digits, dots and dashes", b.Name)
		}
		upid, err := cl.Clone(ctx, r.Node, proxmox.Kind(r.Type), r.VMID, proxmox.CloneOptions{
			NewID: b.NewID, Name: b.Name, Full: b.Full, Target: b.Target, Storage: b.Storage,
			Snapshot: b.Snapshot,
		})
		if err != nil {
			return nil, pveError(err)
		}
		return h.follow(ctx, c, r, fmt.Sprintf("Clone %s to %d", guestName(r), b.NewID), upid, func(p *pveTaskParams) {
			if b.Start {
				p.Then = "start-clone"
			}
			p.VMID = b.NewID
			if b.Target != "" {
				p.Node = b.Target
			}
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "convert-pve-guest-to-template", Method: http.MethodPost, Path: "/pve-clusters/{id}/guests/{vmid}/template",
		Summary: "Turn a machine into a template", Description: "It can't be started any more, only cloned. There is no way back.", Tags: tags,
	}, func(ctx context.Context, in *struct{ PVEGuestPath }) (*JobOutput, error) {
		c, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		if r.Status == "running" {
			return nil, huma.Error422UnprocessableEntity("Shut the machine down first")
		}
		upid, err := cl.Template(ctx, r.Node, proxmox.Kind(r.Type), r.VMID)
		if err != nil {
			return nil, pveError(err)
		}
		return h.follow(ctx, c, r, "Make "+guestName(r)+" a template", upid, nil)
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-pve-guest", Method: http.MethodDelete, Path: "/pve-clusters/{id}/guests/{vmid}",
		Summary:     "Delete a machine",
		Description: "Removes it with its disks. A running machine is stopped first when stop is set.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		PVEGuestPath
		Stop bool `query:"stop" doc:"Stop it first when it runs"`
	}) (*JobOutput, error) {
		c, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		kind := proxmox.Kind(r.Type)
		if r.Status == "running" {
			if !in.Stop {
				return nil, huma.Error422UnprocessableEntity("The machine is running: stop it first")
			}
			upid, err := cl.Power(ctx, r.Node, kind, r.VMID, "stop", nil)
			if err != nil {
				return nil, pveError(err)
			}
			markPVEPower(c.ID, r.VMID)
			return h.follow(ctx, c, r, "Delete "+guestName(r), upid, func(p *pveTaskParams) {
				p.Then, p.Unlink = "delete", true
			})
		}
		upid, err := cl.Delete(ctx, r.Node, kind, r.VMID)
		if err != nil {
			return nil, pveError(err)
		}
		markPVEPower(c.ID, r.VMID)
		return h.follow(ctx, c, r, "Delete "+guestName(r), upid, func(p *pveTaskParams) { p.Unlink = true })
	})

	huma.Register(api, huma.Operation{
		OperationID: "check-pve-migration", Method: http.MethodGet, Path: "/pve-clusters/{id}/guests/{vmid}/migrate",
		Summary: "Can a machine move, and where", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEGuestPath
		Target string `query:"target" maxLength:"64"`
	}) (*struct {
		Body struct {
			Node            string            `json:"node"`
			Running         bool              `json:"running"`
			Allowed         []string          `json:"allowed"`
			NotAllowed      map[string]string `json:"not_allowed"`
			LocalDisks      []string          `json:"local_disks"`
			LocalResources  []string          `json:"local_resources"`
			OnlineSupported bool              `json:"online_supported" doc:"Containers move by restarting, VMs live"`
		}
	}, error) {
		_, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		out := &struct {
			Body struct {
				Node            string            `json:"node"`
				Running         bool              `json:"running"`
				Allowed         []string          `json:"allowed"`
				NotAllowed      map[string]string `json:"not_allowed"`
				LocalDisks      []string          `json:"local_disks"`
				LocalResources  []string          `json:"local_resources"`
				OnlineSupported bool              `json:"online_supported" doc:"Containers move by restarting, VMs live"`
			}
		}{}
		b := &out.Body
		b.Node, b.Running, b.OnlineSupported = r.Node, r.Status == "running", r.Type == "qemu"
		b.Allowed, b.NotAllowed, b.LocalDisks, b.LocalResources = []string{}, map[string]string{}, []string{}, []string{}
		if r.Type == "qemu" {
			mc, err := cl.MigrateCheck(ctx, r.Node, proxmox.QEMU, r.VMID, in.Target)
			if err != nil {
				return nil, pveError(err)
			}
			b.Allowed = nonNil(mc.AllowedNodes)
			for n, why := range mc.NotAllowedNodes {
				b.NotAllowed[n] = describeNotAllowed(why)
			}
			for _, d := range mc.LocalDisks {
				b.LocalDisks = append(b.LocalDisks, proxmox.Str(d["volid"]))
			}
			b.LocalResources = nonNil(mc.LocalResources)
			return out, nil
		}
		nodes, err := cl.Nodes(ctx)
		if err != nil {
			return nil, pveError(err)
		}
		for _, n := range nodes {
			if n.Node == r.Node {
				continue
			}
			if n.Status == "online" {
				b.Allowed = append(b.Allowed, n.Node)
			} else {
				b.NotAllowed[n.Node] = "offline"
			}
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "migrate-pve-guest", Method: http.MethodPost, Path: "/pve-clusters/{id}/guests/{vmid}/migrate",
		Summary: "Move a machine to another node", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEGuestPath
		Body struct {
			Target     string `json:"target" minLength:"1" maxLength:"64"`
			Online     bool   `json:"online" doc:"VMs: move while running. Containers restart on the new node."`
			LocalDisks bool   `json:"with_local_disks,omitempty" doc:"Copy disks that aren't on shared storage"`
		}
	}) (*JobOutput, error) {
		c, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		if in.Body.Target == r.Node {
			return nil, fieldError("body.target", "It's already on this node", in.Body.Target)
		}
		upid, err := cl.Migrate(ctx, r.Node, proxmox.Kind(r.Type), r.VMID, in.Body.Target, in.Body.Online && r.Status == "running", in.Body.LocalDisks)
		if err != nil {
			return nil, pveError(err)
		}
		markPVEPower(c.ID, r.VMID)
		return h.follow(ctx, c, r, "Move "+guestName(r)+" to "+in.Body.Target, upid, nil)
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-pve-guest-tasks", Method: http.MethodGet, Path: "/pve-clusters/{id}/guests/{vmid}/tasks",
		Summary: "What was done to a machine", Description: "Proxmox's task history for it, newest first, from every node.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEGuestPath
		Limit int `query:"limit" minimum:"1" maximum:"500" default:"100"`
	}) (*PVETasksOutput, error) {
		_, cl, _, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		ts, err := h.tasksOf(ctx, cl, in.VMID, in.Limit)
		if err != nil {
			return nil, pveError(err)
		}
		out := &PVETasksOutput{}
		out.Body.Items = ts
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-pve-guest-backups", Method: http.MethodGet, Path: "/pve-clusters/{id}/guests/{vmid}/backups",
		Summary: "A machine's backups", Description: "On every backup storage its node sees (PBS included).", Tags: tags,
	}, func(ctx context.Context, in *struct{ PVEGuestPath }) (*PVEBackupsOutput, error) {
		_, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		items, problems, err := h.backupsOf(ctx, cl, r.Node, r.VMID)
		if err != nil {
			return nil, pveError(err)
		}
		out := &PVEBackupsOutput{}
		out.Body.Items, out.Body.Problems = items, problems
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "backup-pve-guest", Method: http.MethodPost, Path: "/pve-clusters/{id}/guests/{vmid}/backups",
		Summary: "Back up a machine now (vzdump)", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEGuestPath
		Body PVEBackupBody
	}) (*JobOutput, error) {
		c, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		upid, err := cl.Vzdump(ctx, r.Node, r.VMID, in.Body.options())
		if err != nil {
			return nil, pveError(err)
		}
		return h.follow(ctx, c, r, "Back up "+guestName(r)+" to "+in.Body.Storage, upid, nil)
	})

	huma.Register(api, huma.Operation{
		OperationID: "restore-pve-guest", Method: http.MethodPost, Path: "/pve-clusters/{id}/guests/{vmid}/restore",
		Summary:     "Restore a backup",
		Description: "Over this machine (Owner; it's replaced, so stop it first) or as a new one (Engineer).",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		PVEGuestPath
		Body struct {
			VolID   string `json:"volid" minLength:"1" maxLength:"500"`
			Storage string `json:"storage,omitempty" maxLength:"64" doc:"Where the disks go; empty = where they were"`
			AsNew   bool   `json:"as_new,omitempty" doc:"Restore into a new machine instead of replacing this one"`
			NewID   int    `json:"new_id,omitempty" minimum:"0" maximum:"999999999"`
			Unique  bool   `json:"unique,omitempty" doc:"New MAC addresses (do it for a copy next to the original)"`
			Start   bool   `json:"start,omitempty"`
		}
	}) (*JobOutput, error) {
		c, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		b := in.Body
		p := principalOf(ctx)
		vmid := r.VMID
		if b.AsNew {
			if vmid = b.NewID; vmid == 0 {
				if vmid, err = cl.NextID(ctx); err != nil {
					return nil, pveError(err)
				}
			}
		} else {
			if p.Access.WorkspaceLevel(c.WorkspaceID) < auth.Owner {
				return nil, huma.Error403Forbidden("You need Owner access to replace a machine with a backup.")
			}
			if r.Status == "running" {
				return nil, huma.Error422UnprocessableEntity("Stop the machine first: a restore replaces it")
			}
		}
		upid, err := cl.Restore(ctx, r.Node, proxmox.Kind(r.Type), vmid, b.VolID, b.Storage, !b.AsNew, b.Unique, false)
		if err != nil {
			return nil, pveError(err)
		}
		title := "Restore " + guestName(r)
		if b.AsNew {
			title = fmt.Sprintf("Restore %s as %d", guestName(r), vmid)
		}
		return h.follow(ctx, c, r, title, upid, func(tp *pveTaskParams) {
			tp.VMID = vmid
			if b.Start {
				tp.Then = "start"
			}
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-pve-cloud-init", Method: http.MethodGet, Path: "/pve-clusters/{id}/guests/{vmid}/cloud-init",
		Summary: "A VM's cloud-init settings", Tags: tags,
	}, func(ctx context.Context, in *struct{ PVEGuestPath }) (*struct{ Body PVECloudInit }, error) {
		_, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		if r.Type != "qemu" {
			return nil, huma.Error422UnprocessableEntity("Cloud-init is for VMs")
		}
		cfg, err := cl.GuestConfig(ctx, r.Node, proxmox.QEMU, r.VMID)
		if err != nil {
			return nil, pveError(err)
		}
		return &struct{ Body PVECloudInit }{cloudInitOf(cfg)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-pve-cloud-init", Method: http.MethodPut, Path: "/pve-clusters/{id}/guests/{vmid}/cloud-init",
		Summary: "Change a VM's cloud-init settings", Description: "They apply on the next boot.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEGuestPath
		Body PVECloudInitBody
	}) (*JobOutput, error) {
		c, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		if r.Type != "qemu" {
			return nil, huma.Error422UnprocessableEntity("Cloud-init is for VMs")
		}
		set, del, err := cloudInitChanges(in.Body)
		if err != nil {
			return nil, err
		}
		upid, err := cl.SetConfig(ctx, r.Node, proxmox.QEMU, r.VMID, set, del, "")
		if err != nil {
			return nil, pveError(err)
		}
		return h.follow(ctx, c, r, "Change cloud-init of "+guestName(r), upid, nil)
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-pve-guest-firewall", Method: http.MethodGet, Path: "/pve-clusters/{id}/guests/{vmid}/firewall",
		Summary: "A machine's Proxmox firewall", Tags: tags,
	}, func(ctx context.Context, in *struct{ PVEGuestPath }) (*struct{ Body PVEFirewall }, error) {
		_, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		return h.firewall(ctx, cl, r)
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-pve-guest-firewall-options", Method: http.MethodPut, Path: "/pve-clusters/{id}/guests/{vmid}/firewall/options",
		Summary: "Turn a machine's firewall on or off, set its policies", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEGuestPath
		Body PVEFirewallOptions
	}) (*struct{ Body PVEFirewall }, error) {
		_, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		o := in.Body
		if err := cl.SetFirewallOptions(ctx, r.Node, proxmox.Kind(r.Type), r.VMID, proxmox.FirewallOptions{
			Enable: o.Enable, PolicyIn: o.PolicyIn, PolicyOut: o.PolicyOut, MACFilter: o.MACFilter, DHCP: o.DHCP, IPFilter: o.IPFilter,
		}); err != nil {
			return nil, pveError(err)
		}
		return h.firewall(ctx, cl, r)
	})

	huma.Register(api, huma.Operation{
		OperationID: "add-pve-guest-firewall-rule", Method: http.MethodPost, Path: "/pve-clusters/{id}/guests/{vmid}/firewall/rules",
		Summary: "Add a firewall rule", Description: "It goes to the top.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEGuestPath
		Body PVEFirewallRule
	}) (*struct{ Body PVEFirewall }, error) {
		_, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		if err := cl.AddFirewallRule(ctx, r.Node, proxmox.Kind(r.Type), r.VMID, toFWRule(in.Body)); err != nil {
			return nil, pveError(err)
		}
		return h.firewall(ctx, cl, r)
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-pve-guest-firewall-rule", Method: http.MethodPut, Path: "/pve-clusters/{id}/guests/{vmid}/firewall/rules/{pos}",
		Summary: "Change a firewall rule", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEFirewallRulePath
		Body PVEFirewallRule
	}) (*struct{ Body PVEFirewall }, error) {
		_, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		rule := toFWRule(in.Body)
		rule.Pos = in.Pos
		if err := cl.UpdateFirewallRule(ctx, r.Node, proxmox.Kind(r.Type), r.VMID, rule); err != nil {
			return nil, pveError(err)
		}
		return h.firewall(ctx, cl, r)
	})

	huma.Register(api, huma.Operation{
		OperationID: "move-pve-guest-firewall-rule", Method: http.MethodPost, Path: "/pve-clusters/{id}/guests/{vmid}/firewall/rules/{pos}/move",
		Summary: "Move a firewall rule", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEFirewallRulePath
		Body struct {
			To int `json:"to" minimum:"0" maximum:"9999"`
		}
	}) (*struct{ Body PVEFirewall }, error) {
		_, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		if err := cl.MoveFirewallRule(ctx, r.Node, proxmox.Kind(r.Type), r.VMID, in.Pos, in.Body.To); err != nil {
			return nil, pveError(err)
		}
		return h.firewall(ctx, cl, r)
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-pve-guest-firewall-rule", Method: http.MethodDelete, Path: "/pve-clusters/{id}/guests/{vmid}/firewall/rules/{pos}",
		Summary: "Delete a firewall rule", Tags: tags,
	}, func(ctx context.Context, in *struct{ PVEFirewallRulePath }) (*struct{ Body PVEFirewall }, error) {
		_, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		if err := cl.DeleteFirewallRule(ctx, r.Node, proxmox.Kind(r.Type), r.VMID, in.Pos); err != nil {
			return nil, pveError(err)
		}
		return h.firewall(ctx, cl, r)
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-pve-guest-ha", Method: http.MethodPut, Path: "/pve-clusters/{id}/guests/{vmid}/ha",
		Summary: "Put a machine under high availability, or change how", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEGuestPath
		Body PVEHABody
	}) (*PVEGuestDetailOutput, error) {
		c, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		b := in.Body
		if err := cl.SetHA(ctx, proxmox.Kind(r.Type), r.VMID, proxmox.HAResource{
			State: b.State, Group: b.Group, MaxRestart: b.MaxRestart, MaxRelocate: b.MaxRelocate, Comment: b.Comment,
		}, r.HAState != ""); err != nil {
			return nil, pveError(err)
		}
		r, _ = cl.Find(ctx, r.VMID)
		d, err := h.detail(ctx, c, cl, r)
		if err != nil {
			return nil, err
		}
		return &PVEGuestDetailOutput{Body: d}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "remove-pve-guest-ha", Method: http.MethodDelete, Path: "/pve-clusters/{id}/guests/{vmid}/ha",
		Summary: "Take a machine out of high availability", Tags: tags,
	}, func(ctx context.Context, in *struct{ PVEGuestPath }) (*PVEGuestDetailOutput, error) {
		c, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		if err := cl.RemoveHA(ctx, proxmox.Kind(r.Type), r.VMID); err != nil {
			return nil, pveError(err)
		}
		r, _ = cl.Find(ctx, r.VMID)
		d, err := h.detail(ctx, c, cl, r)
		if err != nil {
			return nil, err
		}
		return &PVEGuestDetailOutput{Body: d}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "link-pve-guest", Method: http.MethodPut, Path: "/pve-clusters/{id}/guests/{vmid}/link",
		Summary:     "Say which Morche server a machine is",
		Description: "The server's page then shows the machine, its node, power and console. A server is linked to one machine at most.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		PVEGuestPath
		Body struct {
			ServerID string `json:"server_id" format:"uuid"`
		}
	}) (*PVEGuestDetailOutput, error) {
		c, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		sid, err := uuid.Parse(in.Body.ServerID)
		if err != nil {
			return nil, fieldError("body.server_id", "Pick a server", in.Body.ServerID)
		}
		p := principalOf(ctx)
		lvl, err := h.authz.serverLevel(ctx, p.Access, sid)
		if err != nil {
			return nil, internalError(err)
		}
		if lvl == auth.None {
			return nil, fieldError("body.server_id", "Server not found", in.Body.ServerID)
		}
		if lvl < auth.Engineer {
			return nil, huma.Error403Forbidden("You need Engineer access to the server to link it.")
		}
		if err := h.link(ctx, c.ID, r.VMID, sid); err != nil {
			return nil, internalError(err)
		}
		d, err := h.detail(ctx, c, cl, r)
		if err != nil {
			return nil, err
		}
		return &PVEGuestDetailOutput{Body: d}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "unlink-pve-guest", Method: http.MethodDelete, Path: "/pve-clusters/{id}/guests/{vmid}/link",
		Summary: "Forget which server a machine is", Tags: tags, DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *struct{ PVEGuestPath }) (*struct{}, error) {
		if err := h.q.DeletePVELink(ctx, sqlc.DeletePVELinkParams{ClusterID: uuid.MustParse(in.ID), Vmid: int32(in.VMID)}); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-server-pve-link", Method: http.MethodGet, Path: "/servers/{id}/pve-link",
		Summary:     "The Proxmox machine a server is",
		Description: "linked = false when the server isn't tied to a machine.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ID string `path:"id" format:"uuid"`
	}) (*struct{ Body PVEServerLink }, error) {
		return h.serverLink(ctx, in.ID)
	})
}

// PVEServerLink is the Proxmox machine a server is, as its page shows it.
type PVEServerLink struct {
	Linked      bool      `json:"linked"`
	ClusterID   string    `json:"cluster_id,omitempty"`
	ClusterName string    `json:"cluster_name,omitempty"`
	VMID        int       `json:"vmid,omitempty"`
	Level       string    `json:"level,omitempty" doc:"The caller's level on the cluster: none means they see only that a link exists"`
	Guest       *PVEGuest `json:"guest,omitempty" doc:"The machine right now; missing when the cluster can't be read or the caller can't see it"`
	Problem     string    `json:"problem,omitempty" doc:"Why the machine couldn't be read"`
}

func (h *pveHandler) serverLink(ctx context.Context, rawID string) (*struct{ Body PVEServerLink }, error) {
	out := &struct{ Body PVEServerLink }{}
	sid, err := uuid.Parse(rawID)
	if err != nil {
		return nil, huma.Error404NotFound("Server not found")
	}
	l, err := h.q.GetPVELinkForServer(ctx, sid)
	if isNotFound(err) {
		return out, nil
	}
	if err != nil {
		return nil, internalError(err)
	}
	lvl := principalOf(ctx).Access.WorkspaceLevel(l.WorkspaceID)
	out.Body = PVEServerLink{Linked: true, ClusterID: l.ClusterID.String(), ClusterName: l.ClusterName, VMID: int(l.Vmid), Level: lvl.String()}
	if lvl == auth.None {
		return out, nil
	}
	c, cl, err := h.withCluster(ctx, l.ClusterID.String())
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	r, err := cl.Find(cctx, int(l.Vmid))
	if err != nil {
		if proxmox.IsMissing(err) {
			out.Body.Problem = "The machine is no longer on the cluster"
		} else {
			_, msg := pveStatus(err)
			out.Body.Problem = cmpOr(msg, "The cluster can't be reached")
		}
		return out, nil
	}
	g := toPVEGuest(c, r)
	out.Body.Guest = &g
	return out, nil
}

func (h *pveHandler) link(ctx context.Context, cluster uuid.UUID, vmid int, server uuid.UUID) error {
	if err := h.q.DeletePVELinkForServer(ctx, server); err != nil {
		return err
	}
	_, err := h.q.SetPVELink(ctx, sqlc.SetPVELinkParams{ClusterID: cluster, Vmid: int32(vmid), ServerID: server})
	return err
}

func (h *pveHandler) firewall(ctx context.Context, cl *proxmox.Client, r proxmox.Resource) (*struct{ Body PVEFirewall }, error) {
	kind := proxmox.Kind(r.Type)
	o, err := cl.FirewallOptions(ctx, r.Node, kind, r.VMID)
	if err != nil {
		return nil, pveError(err)
	}
	rules, err := cl.FirewallRules(ctx, r.Node, kind, r.VMID)
	if err != nil {
		return nil, pveError(err)
	}
	out := &struct{ Body PVEFirewall }{}
	out.Body.Options = PVEFirewallOptions{Enable: o.Enable, PolicyIn: o.PolicyIn, PolicyOut: o.PolicyOut, MACFilter: o.MACFilter, DHCP: o.DHCP, IPFilter: o.IPFilter}
	out.Body.Rules = []PVEFirewallRule{}
	for _, x := range rules {
		out.Body.Rules = append(out.Body.Rules, fromFWRule(x))
	}
	return out, nil
}

func describeNotAllowed(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return "not allowed"
	}
	if s := proxmox.Str(m["unavailable_storages"]); s != "" {
		return "storage missing there: " + s
	}
	if _, ok := m["unavailable-resources"]; ok {
		return "a mapped device is missing there"
	}
	for k := range m {
		return strings.ReplaceAll(k, "_", " ")
	}
	return "not allowed"
}

func cloudInitChanges(b PVECloudInitBody) (map[string]string, []string, error) {
	set := map[string]string{}
	del := []string{}
	put := func(k, v string) {
		if v = strings.TrimSpace(v); v == "" {
			del = append(del, k)
		} else {
			set[k] = v
		}
	}
	if b.User != "" && !linuxUser.MatchString(b.User) {
		return nil, nil, fieldError("body.user", "Use lower-case letters, digits, - and _", b.User)
	}
	put("ciuser", b.User)
	if b.ClearPass {
		del = append(del, "cipassword")
	} else if b.Password != "" {
		set["cipassword"] = b.Password
	}
	if k := strings.TrimSpace(b.SSHKeys); k != "" {
		for l := range strings.SplitSeq(k, "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "ssh-") && !strings.HasPrefix(l, "ecdsa-") && !strings.HasPrefix(l, "sk-") {
				return nil, nil, fieldError("body.ssh_keys", "One public key per line, like ssh-ed25519 AAAA…", l)
			}
		}
		set["sshkeys"] = encodeSSHKeys(k)
	} else {
		del = append(del, "sshkeys")
	}
	for k, v := range b.IPConfig {
		if !ipconfigKey.MatchString(k) {
			return nil, nil, fieldError("body.ip_config", "Keys are ipconfig0, ipconfig1…", k)
		}
		put(k, v)
	}
	put("nameserver", b.Nameserver)
	put("searchdomain", b.SearchDomain)
	if b.Upgrade != nil {
		if *b.Upgrade {
			set["ciupgrade"] = "1"
		} else {
			set["ciupgrade"] = "0"
		}
	}
	return set, del, nil
}

var (
	pveNameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,61}[A-Za-z0-9])?$`)
	linuxUser = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

type PVEBackupsOutput struct {
	Body struct {
		Items    []PVEBackup `json:"items"`
		Problems []string    `json:"problems" doc:"Storages that couldn't be read"`
	}
}

type PVEBackupBody struct {
	Storage   string `json:"storage" minLength:"1" maxLength:"64"`
	Mode      string `json:"mode" enum:"snapshot,suspend,stop" default:"snapshot"`
	Compress  string `json:"compress,omitempty" enum:"zstd,lzo,gzip,0," doc:"Not for PBS, which compresses by itself"`
	Notes     string `json:"notes,omitempty" maxLength:"500" doc:"Proxmox's notes template: {{guestname}}, {{vmid}}, {{node}}, {{cluster}}"`
	Protected bool   `json:"protected,omitempty" doc:"Pruning leaves it alone"`
}

func (b PVEBackupBody) options() proxmox.BackupOptions {
	return proxmox.BackupOptions{Storage: b.Storage, Mode: b.Mode, Compress: b.Compress, Notes: b.Notes, Protected: b.Protected}
}

// RRD

type PVERRDOutput struct {
	Body struct {
		Points []map[string]float64 `json:"points" doc:"time (Unix seconds), cpu (0–1), maxcpu, mem, maxmem, disk, maxdisk, netin, netout, diskread, diskwrite (bytes/s); keys missing when unknown"`
	}
}

func rrdOutput(pts []proxmox.RRDPoint) *PVERRDOutput {
	out := &PVERRDOutput{}
	out.Body.Points = make([]map[string]float64, 0, len(pts))
	for _, p := range pts {
		if _, ok := p["time"]; !ok {
			continue
		}
		out.Body.Points = append(out.Body.Points, map[string]float64(p))
	}
	return out
}

// Power changes Morche starts: the alert loop doesn't call them unexpected.
var pvePowerMarks sync.Map // "cluster/vmid" → time

func markPVEPower(cluster uuid.UUID, vmid int) {
	pvePowerMarks.Store(fmt.Sprintf("%s/%d", cluster, vmid), time.Now())
}

func pvePowerMarked(cluster uuid.UUID, vmid int, within time.Duration) bool {
	v, ok := pvePowerMarks.Load(fmt.Sprintf("%s/%d", cluster, vmid))
	return ok && time.Since(v.(time.Time)) < within
}
