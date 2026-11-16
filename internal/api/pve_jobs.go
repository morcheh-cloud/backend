package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/jobs"
	"github.com/morche/backend/internal/proxmox"
)

// registerPVEJobs teaches the runner the Proxmox job kinds.
func (h *pveHandler) registerJobs() {
	h.runner.Handle("pve-task", h.runTask)
	h.runner.Handle("pve-create", h.runCreate)
}

func (h *pveHandler) jobClient(ctx context.Context, raw string) (sqlc.PveCluster, *proxmox.Client, error) {
	id, err := uuid.Parse(raw)
	if err != nil {
		return sqlc.PveCluster{}, nil, err
	}
	c, err := h.q.GetPVECluster(ctx, id)
	if err != nil {
		return c, nil, errors.New("The cluster was removed from Morche.")
	}
	cl, err := h.savedClient(c)
	return c, cl, err
}

// followUPID waits for a Proxmox task, copying its log into the job's.
// Canceling the job stops the task.
func followUPID(ctx context.Context, t *jobs.Task, cl *proxmox.Client, upid, phase string) error {
	if upid == "" {
		return nil
	}
	t.Update(func(p *jobs.Progress) { p.Phase = phase })
	err := cl.Run(ctx, upid, func(lines []proxmox.LogLine) {
		for _, l := range lines {
			if s := strings.TrimSpace(l.T); s != "" && s != "no content" {
				t.Logf("%s", s)
			}
		}
	})
	if ctx.Err() != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = cl.StopTask(sctx, upid)
		return ctx.Err()
	}
	return err
}

func (h *pveHandler) runTask(ctx context.Context, t *jobs.Task) (any, error) {
	var p pveTaskParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	c, cl, err := h.jobClient(ctx, p.Cluster)
	if err != nil {
		return nil, err
	}
	if err := followUPID(ctx, t, cl, p.UPID, "Working"); err != nil {
		return nil, err
	}
	kind := proxmox.Kind(p.Kind)
	switch p.Then {
	case "delete":
		t.Logf("Stopped. Deleting the machine and its disks…")
		upid, err := cl.Delete(ctx, p.Node, kind, p.VMID)
		if err != nil {
			return nil, err
		}
		if err := followUPID(ctx, t, cl, upid, "Deleting"); err != nil {
			return nil, err
		}
	case "start", "start-clone":
		node := p.Node
		if r, err := cl.Find(ctx, p.VMID); err == nil {
			node = r.Node
		}
		t.Logf("Starting %d…", p.VMID)
		upid, err := cl.Power(ctx, node, kind, p.VMID, "start", nil)
		if err != nil {
			return nil, err
		}
		markPVEPower(c.ID, p.VMID)
		if err := followUPID(ctx, t, cl, upid, "Starting"); err != nil {
			return nil, err
		}
	}
	if p.Unlink {
		_ = h.q.DeletePVELink(context.Background(), sqlc.DeletePVELinkParams{ClusterID: c.ID, Vmid: int32(p.VMID)})
	}
	return map[string]any{"vmid": p.VMID}, nil
}

// pveCreateParams is a new machine, as the wizard sent it. Secrets are sealed.
type pveCreateParams struct {
	Cluster string `json:"cluster"`
	Node    string `json:"node"`
	Kind    string `json:"kind"`
	// Source: "clone" (a template), "iso" (install from an ISO, VMs),
	// "ostemplate" (containers).
	Source       string `json:"source"`
	Template     int    `json:"template,omitempty"`
	Full         bool   `json:"full,omitempty"`
	ISO          string `json:"iso,omitempty"`
	OSTemplate   string `json:"ostemplate,omitempty"`
	VMID         int    `json:"vmid"`
	Name         string `json:"name"`
	Storage      string `json:"storage,omitempty"`
	Cores        int    `json:"cores,omitempty"`
	Memory       int    `json:"memory,omitempty"`
	Swap         int    `json:"swap,omitempty"`
	DiskGB       int    `json:"disk_gb,omitempty"`
	Bridge       string `json:"bridge,omitempty"`
	VLAN         int    `json:"vlan,omitempty"`
	IPConfig     string `json:"ip_config,omitempty"`
	Nameserver   string `json:"nameserver,omitempty"`
	User         string `json:"user,omitempty"`
	PasswordEnc  []byte `json:"password_enc,omitempty"`
	SSHKeys      string `json:"ssh_keys,omitempty"`
	Tags         string `json:"tags,omitempty"`
	OnBoot       bool   `json:"onboot,omitempty"`
	Start        bool   `json:"start,omitempty"`
	Unprivileged bool   `json:"unprivileged,omitempty"`
	Nesting      bool   `json:"nesting,omitempty"`
	// AddServer makes it a Morche server once it answers SSH, with a key
	// Morche generates (its public half goes in by cloud-init).
	AddServer  bool     `json:"add_server,omitempty"`
	ServerName string   `json:"server_name,omitempty"`
	FolderID   *string  `json:"folder_id,omitempty"`
	ServerTags []string `json:"server_tags,omitempty"`
}

type pveCreateResult struct {
	VMID     int    `json:"vmid"`
	Node     string `json:"node"`
	IP       string `json:"ip,omitempty"`
	ServerID string `json:"server_id,omitempty"`
	Note     string `json:"note,omitempty"`
}

func newSSHKey(comment string) (private []byte, public string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, "", err
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(block), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " " + comment, nil
}

var diskSize = regexp.MustCompile(`(?:^|,)size=(\d+(?:\.\d+)?)([KMGT]?)`)

// sizeGB reads a disk's size=… in GiB.
func sizeGB(v string) float64 {
	m := diskSize.FindStringSubmatch(v)
	if m == nil {
		return 0
	}
	n, _ := strconv.ParseFloat(m[1], 64)
	switch m[2] {
	case "T":
		return n * 1024
	case "M":
		return n / 1024
	case "K":
		return n / 1024 / 1024
	}
	return n
}

// bootDisk is the disk a cloned VM boots from: the first real disk.
func bootDisk(cfg proxmox.Settings) string {
	if b := cfg["bootdisk"]; b != "" {
		return b
	}
	if b := cfg["boot"]; strings.HasPrefix(b, "order=") {
		for d := range strings.SplitSeq(strings.TrimPrefix(b, "order="), ";") {
			if v := cfg[d]; v != "" && !strings.Contains(v, "media=cdrom") && !strings.Contains(v, "cloudinit") {
				return d
			}
		}
	}
	for _, d := range []string{"scsi0", "virtio0", "sata0", "ide0"} {
		if v := cfg[d]; v != "" && !strings.Contains(v, "media=cdrom") && !strings.Contains(v, "cloudinit") {
			return d
		}
	}
	return ""
}

func staticIP(ipconfig string) string {
	for part := range strings.SplitSeq(ipconfig, ",") {
		if v, ok := strings.CutPrefix(part, "ip="); ok && v != "dhcp" {
			if ip, _, err := net.ParseCIDR(v); err == nil {
				return ip.String()
			}
		}
	}
	return ""
}

func netLine(kind, bridge string, vlan int, ipconfig string) string {
	var s string
	if kind == "lxc" {
		s = "name=eth0,bridge=" + bridge
		if ipconfig == "" {
			ipconfig = "ip=dhcp"
		}
		s += "," + ipconfig
	} else {
		s = "virtio,bridge=" + bridge
	}
	if vlan > 0 {
		s += ",tag=" + strconv.Itoa(vlan)
	}
	return s
}

func (h *pveHandler) runCreate(ctx context.Context, t *jobs.Task) (any, error) {
	var p pveCreateParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	c, cl, err := h.jobClient(ctx, p.Cluster)
	if err != nil {
		return nil, err
	}
	kind := proxmox.Kind(p.Kind)
	res := pveCreateResult{VMID: p.VMID, Node: p.Node}
	password := ""
	if len(p.PasswordEnc) > 0 {
		if password, err = h.box.Open(p.PasswordEnc); err != nil {
			return nil, err
		}
	}

	// A key for Morche to log in with.
	var privKey []byte
	keys := strings.TrimSpace(p.SSHKeys)
	if p.AddServer {
		priv, pub, err := newSSHKey("morche@" + p.Name)
		if err != nil {
			return nil, err
		}
		privKey = priv
		keys = strings.TrimSpace(keys + "\n" + pub)
		t.Logf("Made an SSH key for Morche to log in with.")
	}

	// 1. The machine itself.
	switch p.Source {
	case "clone":
		tr, err := cl.Find(ctx, p.Template)
		if err != nil {
			return nil, fmt.Errorf("template %d: %w", p.Template, err)
		}
		t.Logf("Cloning %s (%d) to %d on %s…", tr.Name, tr.VMID, p.VMID, p.Node)
		target := ""
		if p.Node != tr.Node {
			target = p.Node
		}
		storage := ""
		if p.Full {
			storage = p.Storage
		}
		upid, err := cl.Clone(ctx, tr.Node, kind, tr.VMID, proxmox.CloneOptions{
			NewID: p.VMID, Name: p.Name, Full: p.Full, Target: target, Storage: storage,
		})
		if err != nil {
			return nil, err
		}
		if err := followUPID(ctx, t, cl, upid, "Cloning"); err != nil {
			return nil, err
		}
		// 2. Its settings.
		set := map[string]string{}
		if p.Cores > 0 {
			set["cores"] = strconv.Itoa(p.Cores)
		}
		if p.Memory > 0 {
			set["memory"] = strconv.Itoa(p.Memory)
		}
		if p.Tags != "" {
			set["tags"] = p.Tags
		}
		if p.OnBoot {
			set["onboot"] = "1"
		}
		if kind == proxmox.LXC {
			set["hostname"] = p.Name
			if p.Bridge != "" {
				set["net0"] = netLine("lxc", p.Bridge, p.VLAN, p.IPConfig)
			}
			if p.Swap > 0 {
				set["swap"] = strconv.Itoa(p.Swap)
			}
		} else {
			if p.Bridge != "" {
				set["net0"] = netLine("qemu", p.Bridge, p.VLAN, "")
			}
			set["agent"] = "1"
			if p.User != "" {
				set["ciuser"] = p.User
			}
			if password != "" {
				set["cipassword"] = password
			}
			if keys != "" {
				set["sshkeys"] = encodeSSHKeys(keys)
			}
			ipc := p.IPConfig
			if ipc == "" {
				ipc = "ip=dhcp"
			}
			set["ipconfig0"] = ipc
			if p.Nameserver != "" {
				set["nameserver"] = p.Nameserver
			}
		}
		t.Logf("Setting %d cores, %d MiB memory, network and cloud-init…", p.Cores, p.Memory)
		upid, err = cl.SetConfig(ctx, p.Node, kind, p.VMID, set, nil, "")
		if err != nil {
			return nil, err
		}
		if err := followUPID(ctx, t, cl, upid, "Configuring"); err != nil {
			return nil, err
		}
		// 3. A bigger disk.
		if p.DiskGB > 0 {
			cfg, err := cl.GuestConfig(ctx, p.Node, kind, p.VMID)
			if err != nil {
				return nil, err
			}
			disk := "rootfs"
			if kind == proxmox.QEMU {
				disk = bootDisk(cfg)
			}
			if have := sizeGB(cfg[disk]); disk != "" && float64(p.DiskGB) > have {
				t.Logf("Growing %s from %.0f to %d GiB…", disk, have, p.DiskGB)
				upid, err := cl.Resize(ctx, p.Node, kind, p.VMID, disk, strconv.Itoa(p.DiskGB)+"G")
				if err != nil {
					return nil, err
				}
				if err := followUPID(ctx, t, cl, upid, "Growing the disk"); err != nil {
					return nil, err
				}
			}
		}
	case "iso":
		params := map[string]string{
			"vmid": strconv.Itoa(p.VMID), "name": p.Name, "cores": strconv.Itoa(max(p.Cores, 1)),
			"memory": strconv.Itoa(max(p.Memory, 512)), "scsihw": "virtio-scsi-single",
			"scsi0": fmt.Sprintf("%s:%d,iothread=1", p.Storage, max(p.DiskGB, 8)),
			"net0":  netLine("qemu", p.Bridge, p.VLAN, ""), "ostype": "l26", "agent": "1",
			"boot": "order=scsi0;ide2",
		}
		if p.ISO != "" {
			params["ide2"] = p.ISO + ",media=cdrom"
		}
		if p.Tags != "" {
			params["tags"] = p.Tags
		}
		if p.OnBoot {
			params["onboot"] = "1"
		}
		t.Logf("Creating VM %d on %s…", p.VMID, p.Node)
		upid, err := cl.CreateGuest(ctx, p.Node, kind, params)
		if err != nil {
			return nil, err
		}
		if err := followUPID(ctx, t, cl, upid, "Creating"); err != nil {
			return nil, err
		}
	case "ostemplate":
		params := map[string]string{
			"vmid": strconv.Itoa(p.VMID), "hostname": p.Name, "ostemplate": p.OSTemplate,
			"rootfs": fmt.Sprintf("%s:%d", p.Storage, max(p.DiskGB, 4)),
			"cores":  strconv.Itoa(max(p.Cores, 1)), "memory": strconv.Itoa(max(p.Memory, 256)),
			"swap": strconv.Itoa(p.Swap), "net0": netLine("lxc", p.Bridge, p.VLAN, p.IPConfig),
		}
		if p.Unprivileged {
			params["unprivileged"] = "1"
		}
		if p.Nesting {
			params["features"] = "nesting=1"
		}
		if password != "" {
			params["password"] = password
		}
		if keys != "" {
			params["ssh-public-keys"] = keys + "\n"
		}
		if p.Nameserver != "" {
			params["nameserver"] = p.Nameserver
		}
		if p.Tags != "" {
			params["tags"] = p.Tags
		}
		if p.OnBoot {
			params["onboot"] = "1"
		}
		t.Logf("Creating container %d on %s…", p.VMID, p.Node)
		upid, err := cl.CreateGuest(ctx, p.Node, kind, params)
		if err != nil {
			return nil, err
		}
		if err := followUPID(ctx, t, cl, upid, "Creating"); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown source %q", p.Source)
	}
	t.Logf("Machine %d is ready.", p.VMID)

	// 4. Start it.
	if !p.Start {
		if p.AddServer {
			res.Note = "Not started, so it wasn't added to Servers."
		}
		return res, nil
	}
	t.Logf("Starting…")
	upid, err := cl.Power(ctx, p.Node, kind, p.VMID, "start", nil)
	if err != nil {
		return nil, err
	}
	markPVEPower(c.ID, p.VMID)
	if err := followUPID(ctx, t, cl, upid, "Starting"); err != nil {
		return nil, err
	}
	if !p.AddServer {
		return res, nil
	}

	// 5. Its address.
	user := p.User
	if kind == proxmox.LXC || user == "" {
		user = "root"
		if kind == proxmox.QEMU {
			user = "morche"
		}
	}
	ip := staticIP(p.IPConfig)
	if ip == "" {
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Waiting for its address" })
		t.Logf("Waiting for the machine to report an address (guest agent or DHCP)…")
		deadline := time.Now().Add(6 * time.Minute)
		for ip == "" && time.Now().Before(deadline) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			ictx, cancel := context.WithTimeout(ctx, 5*time.Second)
			ifaces, err := cl.Interfaces(ictx, p.Node, kind, p.VMID)
			cancel()
			if err == nil {
				if ips := usefulIPs(ifaces); len(ips) > 0 && !strings.Contains(ips[0], ":") {
					ip = ips[0]
					break
				}
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(5 * time.Second):
			}
		}
	}
	if ip == "" {
		res.Note = "It never reported an address (is the guest agent installed in the template?), so it wasn't added to Servers. Add it by hand with the key from its cloud-init."
		t.Logf("%s", res.Note)
		return res, nil
	}
	res.IP = ip
	t.Logf("It answers on %s.", ip)

	// 6. A Morche server, linked to the machine.
	ctx, err = h.jobPrincipal(ctx, t)
	if err != nil {
		return nil, err
	}
	name := p.ServerName
	if name == "" {
		name = p.Name
	}
	tags, _ := normalizeTags(p.ServerTags)
	if tags == nil {
		tags = []string{}
	}
	params := sqlc.CreateServerParams{
		WorkspaceID: c.WorkspaceID, FolderID: parseOptionalID(p.FolderID), Name: name, Host: ip,
		Port: 22, Username: user, AuthMethod: "private_key", PrivateKeyEnc: h.box.Seal(string(privKey)),
		Description: fmt.Sprintf("Proxmox %s %d on %s", strings.ToUpper(p.Kind), p.VMID, c.Name), Tags: tags,
	}
	var s sqlc.Server
	for i := 0; i < 5; i++ {
		s, err = h.servers.insert(ctx, principalOf(ctx), params)
		if !isUniqueViolation(err) {
			break
		}
		params.Name = fmt.Sprintf("%s-%d", name, p.VMID+i)
	}
	if err != nil {
		return nil, err
	}
	res.ServerID = s.ID.String()
	if err := h.link(ctx, c.ID, p.VMID, s.ID); err != nil {
		return nil, err
	}
	t.Logf("Added to Servers as %s and linked to the machine.", params.Name)
	// SSH may still be starting: the regular checks pick it up.
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for range 6 {
		if s2, err := h.servers.check(cctx, s); err == nil && s2.Status == "online" {
			t.Logf("Morche logged in over SSH.")
			break
		}
		select {
		case <-cctx.Done():
		case <-time.After(5 * time.Second):
		}
		if cctx.Err() != nil {
			break
		}
	}
	return res, nil
}

// jobPrincipal acts as the person who started the job.
func (h *pveHandler) jobPrincipal(ctx context.Context, t *jobs.Task) (context.Context, error) {
	by := t.CreatedBy()
	if by == nil {
		return ctx, errors.New("this job has no owner")
	}
	u, err := h.q.GetUser(ctx, *by)
	if err != nil {
		return ctx, errors.New("the person who started this job is gone")
	}
	acc, err := h.authz.accessOf(ctx, u)
	if err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, principalKey{}, &principal{User: u, Access: acc}), nil
}
