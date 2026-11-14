package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/proxmox"
)

// Nodes, storage, ISOs and creating machines.

var (
	pveNodeName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$`)
	pveStorageName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,99}$`)
	pveFileName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,200}\.(iso|img|tar\.gz|tar\.xz|tar\.zst|tgz)$`)
	pveUPIDRe      = regexp.MustCompile(`^UPID:[A-Za-z0-9.-]+:[0-9A-Fa-f]+:[0-9A-Fa-f]+:[0-9A-Fa-f]+:[A-Za-z0-9_-]+:[^:]*:[^:]+:$`)
)

type PVENodePath struct {
	ID   string `path:"id" format:"uuid"`
	Node string `path:"node" maxLength:"63"`
}

type PVEStoragePath struct {
	PVENodePath
	Storage string `path:"storage" maxLength:"100"`
}

func checkNodeStorage(node, storage string) error {
	if !pveNodeName.MatchString(node) {
		return huma.Error404NotFound("Node not found")
	}
	if storage != "" && !pveStorageName.MatchString(storage) {
		return huma.Error404NotFound("Storage not found")
	}
	return nil
}

// PVENode is one Proxmox host in a cluster.
type PVENode struct {
	ClusterID   string  `json:"cluster_id" format:"uuid"`
	ClusterName string  `json:"cluster_name"`
	Node        string  `json:"node"`
	Status      string  `json:"status" enum:"online,offline,unknown"`
	CPU         float64 `json:"cpu"`
	MaxCPU      int     `json:"max_cpu"`
	Mem         int64   `json:"mem"`
	MaxMem      int64   `json:"max_mem"`
	Disk        int64   `json:"disk"`
	MaxDisk     int64   `json:"max_disk"`
	Uptime      int64   `json:"uptime"`
	Guests      int     `json:"guests"`
	Running     int     `json:"running"`
}

// PVEStorage is one storage as a node sees it (a shared one shows on each).
type PVEStorage struct {
	ClusterID   string   `json:"cluster_id" format:"uuid"`
	ClusterName string   `json:"cluster_name"`
	Node        string   `json:"node"`
	Storage     string   `json:"storage"`
	Type        string   `json:"type"`
	Content     []string `json:"content"`
	Shared      bool     `json:"shared"`
	Status      string   `json:"status"`
	Used        int64    `json:"used"`
	Total       int64    `json:"total"`
}

type PVEInfrastructureOutput struct {
	Body struct {
		Nodes    []PVENode    `json:"nodes"`
		Storages []PVEStorage `json:"storages"`
		Problems []PVEProblem `json:"problems"`
	}
}

func splitContent(s string) []string {
	out := []string{}
	for c := range strings.SplitSeq(s, ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

func (h *pveHandler) infraOf(ctx context.Context, c sqlc.PveCluster) ([]PVENode, []PVEStorage, error) {
	cl, err := h.savedClient(c)
	if err != nil {
		return nil, nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	res, err := cl.Resources(cctx, "")
	if err != nil {
		return nil, nil, err
	}
	nodes := []PVENode{}
	storages := []PVEStorage{}
	count := map[string][2]int{}
	for _, r := range res {
		if (r.Type == "qemu" || r.Type == "lxc") && r.Template != 1 {
			n := count[r.Node]
			n[0]++
			if r.Status == "running" {
				n[1]++
			}
			count[r.Node] = n
		}
	}
	for _, r := range res {
		switch r.Type {
		case "node":
			st := r.Status
			if st != "online" && st != "offline" {
				st = "unknown"
			}
			nodes = append(nodes, PVENode{
				ClusterID: c.ID.String(), ClusterName: c.Name, Node: r.Node, Status: st,
				CPU: r.CPU, MaxCPU: int(r.MaxCPU), Mem: r.Mem, MaxMem: r.MaxMem, Disk: r.Disk,
				MaxDisk: r.MaxDisk, Uptime: r.Uptime, Guests: count[r.Node][0], Running: count[r.Node][1],
			})
		case "storage":
			storages = append(storages, PVEStorage{
				ClusterID: c.ID.String(), ClusterName: c.Name, Node: r.Node, Storage: r.Storage,
				Type: r.PluginType, Content: splitContent(r.Content), Shared: r.Shared == 1,
				Status: r.Status, Used: r.Disk, Total: r.MaxDisk,
			})
		}
	}
	sort.Slice(nodes, func(a, b int) bool { return nodes[a].Node < nodes[b].Node })
	sort.Slice(storages, func(a, b int) bool {
		if storages[a].Storage != storages[b].Storage {
			return storages[a].Storage < storages[b].Storage
		}
		return storages[a].Node < storages[b].Node
	})
	return nodes, storages, nil
}

type PVENodeDetail struct {
	PVENode
	PVEVersion string       `json:"pve_version"`
	Kernel     string       `json:"kernel"`
	CPUModel   string       `json:"cpu_model"`
	Sockets    int          `json:"sockets"`
	Cores      int          `json:"cores"`
	Load       []float64    `json:"load"`
	IOWait     float64      `json:"io_wait"`
	SwapUsed   int64        `json:"swap_used"`
	SwapTotal  int64        `json:"swap_total"`
	RootUsed   int64        `json:"root_used"`
	RootTotal  int64        `json:"root_total"`
	Bridges    []PVEBridge  `json:"bridges"`
	Storages   []PVEStorage `json:"storages"`
	Guests     []PVEGuest   `json:"guest_list"`
}

type PVEBridge struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Active  bool   `json:"active"`
	CIDR    string `json:"cidr,omitempty"`
	Comment string `json:"comment,omitempty"`
}

func toBridges(ns []proxmox.Network) []PVEBridge {
	out := make([]PVEBridge, 0, len(ns))
	for _, n := range ns {
		out = append(out, PVEBridge{Name: n.Iface, Type: n.Type, Active: n.Active == 1, CIDR: n.CIDR, Comment: strings.TrimSpace(n.Comments)})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}

// PVEVolume is a file on a storage: an ISO, a container template, a backup, a disk.
type PVEVolume struct {
	VolID     string `json:"volid"`
	Name      string `json:"name"`
	Content   string `json:"content"`
	Format    string `json:"format"`
	Size      int64  `json:"size"`
	Created   int64  `json:"created,omitempty"`
	VMID      int    `json:"vmid,omitempty"`
	Notes     string `json:"notes,omitempty"`
	Protected bool   `json:"protected"`
	Verified  string `json:"verified,omitempty"`
}

func volumeName(volid string) string {
	_, rest, ok := strings.Cut(volid, ":")
	if !ok {
		return volid
	}
	return path.Base(rest)
}

func toPVEVolume(v proxmox.Volume) PVEVolume {
	return PVEVolume{
		VolID: v.VolID, Name: volumeName(v.VolID), Content: v.Content, Format: v.Format, Size: v.Size,
		Created: v.CTime, VMID: v.VMID, Notes: v.Notes, Protected: v.Protected == 1, Verified: v.Verification.State,
	}
}

type PVEVolumesOutput struct {
	Body struct {
		Items []PVEVolume `json:"items"`
	}
}

// PVECreateOptions is what the new-machine wizard offers on a cluster.
type PVECreateOptions struct {
	NextID    int                    `json:"next_id"`
	Nodes     []PVENode              `json:"nodes"`
	Storages  []PVEStorage           `json:"storages"`
	Bridges   map[string][]PVEBridge `json:"bridges"`
	Templates []PVEGuest             `json:"templates"`
	ISOs      []PVEVolumeAt          `json:"isos"`
	CTs       []PVEVolumeAt          `json:"ct_templates"`
	HAGroups  []string               `json:"ha_groups"`
	Problems  []string               `json:"problems"`
}

// PVEVolumeAt is a volume with the node it was seen from.
type PVEVolumeAt struct {
	PVEVolume
	Node    string `json:"node"`
	Storage string `json:"storage"`
	Shared  bool   `json:"shared"`
}

type PVEClusterTasksOutput struct {
	Body struct {
		Items []PVETask `json:"items"`
	}
}

type PVETaskLogOutput struct {
	Body struct {
		Task  PVETask  `json:"task"`
		Lines []string `json:"lines"`
		Total int      `json:"total"`
	}
}

type PVEHAItem struct {
	SID         string `json:"sid"`
	Kind        string `json:"kind"`
	VMID        int    `json:"vmid"`
	Name        string `json:"name"`
	Node        string `json:"node"`
	State       string `json:"state"`
	Group       string `json:"group,omitempty"`
	MaxRestart  int    `json:"max_restart"`
	MaxRelocate int    `json:"max_relocate"`
	Comment     string `json:"comment,omitempty"`
}

type PVEHAOutput struct {
	Body struct {
		Items   []PVEHAItem `json:"items"`
		Groups  []string    `json:"groups"`
		Quorate bool        `json:"quorate"`
	}
}

// PVEDownloadBody has a node download an ISO or a container template.
type PVEDownloadBody struct {
	URL       string `json:"url" maxLength:"2048"`
	Filename  string `json:"filename,omitempty" maxLength:"200"`
	Content   string `json:"content" enum:"iso,vztmpl"`
	Checksum  string `json:"checksum,omitempty" maxLength:"256"`
	Algorithm string `json:"algorithm,omitempty" enum:"md5,sha1,sha224,sha256,sha384,sha512,"`
}

// PVEUploadInput streams a file from the browser straight to the node.
type PVEUploadInput struct {
	PVEStoragePath
	Content  string `query:"content" enum:"iso,vztmpl"`
	Filename string `query:"filename" maxLength:"200"`
	body     io.Reader
	length   int64
}

func (in *PVEUploadInput) Resolve(ctx huma.Context) []error {
	in.body = ctx.BodyReader()
	in.length, _ = strconv.ParseInt(ctx.Header("Content-Length"), 10, 64)
	return nil
}

type PVEVolumeBody struct {
	VolID string `json:"volid" maxLength:"400"`
}

// PVECreateBody is a new machine.
type PVECreateBody struct {
	Kind         string   `json:"kind" enum:"qemu,lxc"`
	Source       string   `json:"source" enum:"clone,iso,ostemplate"`
	Node         string   `json:"node" maxLength:"63"`
	VMID         int      `json:"vmid,omitempty" minimum:"0" maximum:"999999999"`
	Name         string   `json:"name" maxLength:"63"`
	Template     int      `json:"template,omitempty"`
	Full         bool     `json:"full,omitempty"`
	ISO          string   `json:"iso,omitempty" maxLength:"400"`
	OSTemplate   string   `json:"ostemplate,omitempty" maxLength:"400"`
	Storage      string   `json:"storage,omitempty" maxLength:"100"`
	Cores        int      `json:"cores,omitempty" minimum:"0" maximum:"512"`
	Memory       int      `json:"memory,omitempty" minimum:"0" maximum:"8388608" doc:"MiB"`
	Swap         int      `json:"swap,omitempty" minimum:"0" maximum:"8388608" doc:"MiB, containers"`
	DiskGB       int      `json:"disk_gb,omitempty" minimum:"0" maximum:"131072"`
	Bridge       string   `json:"bridge,omitempty" maxLength:"64"`
	VLAN         int      `json:"vlan,omitempty" minimum:"0" maximum:"4094"`
	IPConfig     string   `json:"ip_config,omitempty" maxLength:"200" doc:"ip=dhcp or ip=10.0.0.5/24,gw=10.0.0.1"`
	Nameserver   string   `json:"nameserver,omitempty" maxLength:"200"`
	User         string   `json:"user,omitempty" maxLength:"32"`
	Password     string   `json:"password,omitempty" maxLength:"200"`
	SSHKeys      string   `json:"ssh_keys,omitempty" maxLength:"20000"`
	Tags         []string `json:"tags,omitempty" maxItems:"20"`
	OnBoot       bool     `json:"onboot,omitempty"`
	Start        bool     `json:"start,omitempty"`
	Unprivileged bool     `json:"unprivileged,omitempty"`
	Nesting      bool     `json:"nesting,omitempty"`
	AddServer    bool     `json:"add_server,omitempty"`
	ServerName   string   `json:"server_name,omitempty" maxLength:"100"`
	ServerTags   []string `json:"server_tags,omitempty" maxItems:"20"`
}

var (
	pveIPConfig = regexp.MustCompile(`^ip=(dhcp|[0-9.]+/\d{1,2})(,gw=[0-9.]+)?$`)
	pveTag      = regexp.MustCompile(`^[a-z0-9_][a-z0-9_+.-]{0,59}$`)
	pveVolID    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]*:[^\s]+$`)
)

func (h *pveHandler) checkCreate(b *PVECreateBody) error {
	b.Name = strings.TrimSpace(b.Name)
	if !pveNameRe.MatchString(b.Name) {
		return fieldError("body.name", "Use letters, digits and dashes (a host name)", b.Name)
	}
	if !pveNodeName.MatchString(b.Node) {
		return fieldError("body.node", "Pick a node", b.Node)
	}
	switch {
	case b.Source == "clone" && b.Template <= 0:
		return fieldError("body.template", "Pick a template", b.Template)
	case b.Source == "iso" && b.Kind != "qemu":
		return fieldError("body.source", "Only a VM installs from an ISO", b.Source)
	case b.Source == "ostemplate" && b.Kind != "lxc":
		return fieldError("body.source", "Only a container starts from a container template", b.Source)
	case b.Source == "ostemplate" && !pveVolID.MatchString(b.OSTemplate):
		return fieldError("body.ostemplate", "Pick a container template", b.OSTemplate)
	case b.Source == "iso" && b.ISO != "" && !pveVolID.MatchString(b.ISO):
		return fieldError("body.iso", "Pick an ISO", b.ISO)
	}
	if b.Source != "clone" || b.Full {
		if b.Source != "clone" && !pveStorageName.MatchString(b.Storage) {
			return fieldError("body.storage", "Pick a storage for the disk", b.Storage)
		}
		if b.Storage != "" && !pveStorageName.MatchString(b.Storage) {
			return fieldError("body.storage", "Pick a storage for the disk", b.Storage)
		}
	}
	if b.Bridge != "" && !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(b.Bridge) {
		return fieldError("body.bridge", "Pick a network", b.Bridge)
	}
	if b.Source != "clone" && b.Bridge == "" {
		return fieldError("body.bridge", "Pick a network", b.Bridge)
	}
	if b.IPConfig != "" && !pveIPConfig.MatchString(b.IPConfig) {
		return fieldError("body.ip_config", "Write ip=dhcp or ip=10.0.0.5/24,gw=10.0.0.1", b.IPConfig)
	}
	if b.Nameserver != "" && !regexp.MustCompile(`^[0-9a-fA-F.: ]+$`).MatchString(b.Nameserver) {
		return fieldError("body.nameserver", "Write addresses separated by spaces", b.Nameserver)
	}
	if b.User != "" && !linuxUser.MatchString(b.User) {
		return fieldError("body.user", "Use a Linux user name: lowercase letters, digits, - and _", b.User)
	}
	if b.User == "root" && b.Kind == "qemu" {
		return fieldError("body.user", "Cloud images usually lock root: pick another user", b.User)
	}
	for i, t := range b.Tags {
		if !pveTag.MatchString(t) {
			return fieldError(fmt.Sprintf("body.tags[%d]", i), "Lowercase letters, digits, - _ . +", t)
		}
	}
	if b.AddServer && !b.Start {
		return fieldError("body.add_server", "Start it too, so Morche can log in", b.AddServer)
	}
	if b.AddServer && b.Kind == "qemu" && b.Source != "clone" {
		return fieldError("body.add_server", "Only a machine from a cloud-init template can be added by itself", b.AddServer)
	}
	if b.AddServer && b.Kind == "lxc" && b.Source == "clone" {
		// A cloned container keeps the template's keys: Morche's key can't go in.
		return fieldError("body.add_server", "A cloned container keeps its template's keys: add it to Servers by hand", b.AddServer)
	}
	return nil
}

// nodeFollow starts a pve-task job for a task not tied to a machine.
func (h *pveHandler) nodeFollow(ctx context.Context, c sqlc.PveCluster, node, title, upid, name string) (*JobOutput, error) {
	return submit(ctx, h.runner, jobs.Spec{
		Kind: "pve-task", Title: title, Refs: []uuid.UUID{c.ID},
		Params: pveTaskParams{Cluster: c.ID.String(), Node: node, UPID: upid},
		Target: JobPlace{ClusterID: c.ID.String(), Name: name}, Quick: true,
	})
}

func registerPVEInfra(api huma.API, h *pveHandler) {
	tags := []string{"Virtual machines"}

	huma.Register(api, huma.Operation{
		OperationID: "list-pve-infrastructure", Method: http.MethodGet, Path: "/pve-infrastructure",
		Summary: "Nodes and storage of every Proxmox cluster", Tags: tags,
	}, func(ctx context.Context, _ *struct{}) (*PVEInfrastructureOutput, error) {
		rows, err := h.listClusters(ctx)
		if err != nil {
			return nil, err
		}
		out := &PVEInfrastructureOutput{}
		out.Body.Nodes, out.Body.Storages, out.Body.Problems = []PVENode{}, []PVEStorage{}, []PVEProblem{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, c := range rows {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ns, ss, err := h.infraOf(ctx, c)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					_, m := pveStatus(err)
					out.Body.Problems = append(out.Body.Problems, PVEProblem{ClusterID: c.ID.String(), ClusterName: c.Name, Message: m})
					return
				}
				out.Body.Nodes = append(out.Body.Nodes, ns...)
				out.Body.Storages = append(out.Body.Storages, ss...)
			}()
		}
		wg.Wait()
		sort.SliceStable(out.Body.Nodes, func(a, b int) bool {
			x, y := out.Body.Nodes[a], out.Body.Nodes[b]
			if x.ClusterName != y.ClusterName {
				return x.ClusterName < y.ClusterName
			}
			return x.Node < y.Node
		})
		sort.SliceStable(out.Body.Storages, func(a, b int) bool {
			x, y := out.Body.Storages[a], out.Body.Storages[b]
			if x.ClusterName != y.ClusterName {
				return x.ClusterName < y.ClusterName
			}
			if x.Storage != y.Storage {
				return x.Storage < y.Storage
			}
			return x.Node < y.Node
		})
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-pve-node", Method: http.MethodGet, Path: "/pve-clusters/{id}/nodes/{node}",
		Summary: "A Proxmox node with its networks, storage and machines", Tags: tags,
	}, func(ctx context.Context, in *struct{ PVENodePath }) (*struct{ Body PVENodeDetail }, error) {
		if err := checkNodeStorage(in.Node, ""); err != nil {
			return nil, err
		}
		c, cl, err := h.withCluster(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		nodes, storages, err := h.infraOf(ctx, c)
		if err != nil {
			return nil, pveError(err)
		}
		i := slices.IndexFunc(nodes, func(n PVENode) bool { return n.Node == in.Node })
		if i < 0 {
			return nil, huma.Error404NotFound("Node not found on this cluster")
		}
		d := PVENodeDetail{PVENode: nodes[i], Load: []float64{}, Bridges: []PVEBridge{}, Storages: []PVEStorage{}, Guests: []PVEGuest{}}
		for _, s := range storages {
			if s.Node == in.Node {
				d.Storages = append(d.Storages, s)
			}
		}
		if d.Status == "online" {
			if st, err := cl.NodeStatus(ctx, in.Node); err == nil {
				d.PVEVersion, d.Kernel = st.PVEVersion, st.KVersion
				d.CPUModel, d.Sockets, d.Cores = st.CPUInfo.Model, st.CPUInfo.Sockets, st.CPUInfo.Cores
				d.IOWait = st.Wait
				d.SwapUsed, d.SwapTotal = st.Swap.Used, st.Swap.Total
				d.RootUsed, d.RootTotal = st.RootFS.Used, st.RootFS.Total
				for _, l := range st.LoadAvg {
					f, _ := strconv.ParseFloat(l, 64)
					d.Load = append(d.Load, f)
				}
			}
			if bs, err := cl.Bridges(ctx, in.Node); err == nil {
				d.Bridges = toBridges(bs)
			}
		}
		if gs, err := h.guestsOf(ctx, c); err == nil {
			for _, g := range gs {
				if g.Node == in.Node {
					d.Guests = append(d.Guests, g)
				}
			}
			h.addLinks(ctx, d.Guests)
		}
		return &struct{ Body PVENodeDetail }{d}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-pve-node-rrd", Method: http.MethodGet, Path: "/pve-clusters/{id}/nodes/{node}/rrd",
		Summary: "A node's history: CPU, memory, network, load", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVENodePath
		Timeframe string `query:"timeframe" enum:"hour,day,week,month,year" default:"hour"`
	}) (*PVERRDOutput, error) {
		if err := checkNodeStorage(in.Node, ""); err != nil {
			return nil, err
		}
		_, cl, err := h.withCluster(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		pts, err := cl.NodeRRD(ctx, in.Node, in.Timeframe)
		if err != nil {
			return nil, pveError(err)
		}
		return rrdOutput(pts), nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-pve-storage-content", Method: http.MethodGet, Path: "/pve-clusters/{id}/nodes/{node}/storages/{storage}/content",
		Summary: "Files on a storage: ISOs, container templates, backups, disks", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEStoragePath
		Content string `query:"content" enum:"iso,vztmpl,backup,images,rootdir,import,snippets,"`
	}) (*PVEVolumesOutput, error) {
		if err := checkNodeStorage(in.Node, in.Storage); err != nil {
			return nil, err
		}
		_, cl, err := h.withCluster(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		vs, err := cl.Content(ctx, in.Node, in.Storage, in.Content, 0)
		if err != nil {
			return nil, pveError(err)
		}
		out := &PVEVolumesOutput{}
		out.Body.Items = make([]PVEVolume, 0, len(vs))
		for _, v := range vs {
			out.Body.Items = append(out.Body.Items, toPVEVolume(v))
		}
		sort.Slice(out.Body.Items, func(a, b int) bool {
			x, y := out.Body.Items[a], out.Body.Items[b]
			if x.Content != y.Content {
				return x.Content < y.Content
			}
			if x.Created != y.Created {
				return x.Created > y.Created
			}
			return x.Name < y.Name
		})
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "download-pve-storage-url", Method: http.MethodPost, Path: "/pve-clusters/{id}/nodes/{node}/storages/{storage}/download",
		Summary: "Have the node download an ISO or a container template", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEStoragePath
		Body PVEDownloadBody
	}) (*JobOutput, error) {
		if err := checkNodeStorage(in.Node, in.Storage); err != nil {
			return nil, err
		}
		b := in.Body
		u, err := url.Parse(strings.TrimSpace(b.URL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fieldError("body.url", "Enter an http(s) address", b.URL)
		}
		name := strings.TrimSpace(b.Filename)
		if name == "" {
			name = path.Base(u.Path)
		}
		if !pveFileName.MatchString(name) {
			return nil, fieldError("body.filename", "Name it like ubuntu-24.04.iso (letters, digits, . _ - +; .iso, .img or a .tar.* for containers)", name)
		}
		if b.Checksum != "" && b.Algorithm == "" {
			return nil, fieldError("body.algorithm", "Pick the checksum's algorithm", b.Algorithm)
		}
		c, cl, err := h.withCluster(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		upid, err := cl.DownloadURL(ctx, in.Node, in.Storage, b.Content, u.String(), name, strings.TrimSpace(b.Checksum), b.Algorithm)
		if err != nil {
			return nil, pveError(err)
		}
		return h.nodeFollow(ctx, c, in.Node, "Download "+name+" to "+in.Storage, upid, name)
	})

	huma.Register(api, huma.Operation{
		OperationID: "upload-pve-storage-file", Method: http.MethodPut, Path: "/pve-clusters/{id}/nodes/{node}/storages/{storage}/upload",
		Summary:     "Upload an ISO or a container template",
		Description: "The request body is the file itself, streamed to the node. The answer comes once Proxmox has it; moving it into place follows as a background task.",
		Tags:        tags, MaxBodyBytes: 64 << 30,
		RequestBody: &huma.RequestBody{Required: true, Content: map[string]*huma.MediaType{
			"application/octet-stream": {Schema: &huma.Schema{Type: "string", Format: "binary"}},
		}},
	}, func(ctx context.Context, in *PVEUploadInput) (*JobOutput, error) {
		if err := checkNodeStorage(in.Node, in.Storage); err != nil {
			return nil, err
		}
		if !pveFileName.MatchString(in.Filename) {
			return nil, huma.Error422UnprocessableEntity("Name it like ubuntu-24.04.iso (letters, digits, . _ - +)")
		}
		if in.Content == "iso" && !strings.HasSuffix(in.Filename, ".iso") && !strings.HasSuffix(in.Filename, ".img") {
			return nil, huma.Error422UnprocessableEntity("An ISO's name ends in .iso or .img")
		}
		c, cl, err := h.withCluster(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		upid, err := cl.Upload(ctx, in.Node, in.Storage, in.Content, in.Filename, in.length, in.body)
		if err != nil {
			return nil, pveError(err)
		}
		if upid == "" {
			return h.nodeFollow(ctx, c, in.Node, "Upload "+in.Filename+" to "+in.Storage, "", in.Filename)
		}
		return h.nodeFollow(ctx, c, in.Node, "Upload "+in.Filename+" to "+in.Storage, upid, in.Filename)
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-pve-volume", Method: http.MethodPost, Path: "/pve-clusters/{id}/nodes/{node}/storages/{storage}/delete",
		Summary: "Delete a file from a storage (an ISO, a template or a backup)", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEStoragePath
		Body PVEVolumeBody
	}) (*JobOutput, error) {
		if err := checkNodeStorage(in.Node, in.Storage); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(in.Body.VolID, in.Storage+":") {
			return nil, fieldError("body.volid", "That file isn't on this storage", in.Body.VolID)
		}
		c, cl, err := h.withCluster(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		// A disk in use belongs to its machine's page.
		vs, err := cl.Content(ctx, in.Node, in.Storage, "", 0)
		if err != nil {
			return nil, pveError(err)
		}
		i := slices.IndexFunc(vs, func(v proxmox.Volume) bool { return v.VolID == in.Body.VolID })
		if i < 0 {
			return nil, huma.Error404NotFound("That file is no longer there")
		}
		switch vs[i].Content {
		case "images", "rootdir":
			return nil, huma.Error422UnprocessableEntity("A machine's disk is removed from the machine's Hardware tab")
		}
		if vs[i].Protected == 1 {
			return nil, huma.Error422UnprocessableEntity("This backup is protected: unprotect it first")
		}
		upid, err := cl.DeleteVolume(ctx, in.Node, in.Storage, in.Body.VolID)
		if err != nil {
			return nil, pveError(err)
		}
		name := volumeName(in.Body.VolID)
		return h.nodeFollow(ctx, c, in.Node, "Delete "+name, upid, name)
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-pve-cluster-tasks", Method: http.MethodGet, Path: "/pve-clusters/{id}/tasks",
		Summary: "Recent Proxmox tasks on every node", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEClusterIDPath
		Limit int `query:"limit" minimum:"1" maximum:"500" default:"100"`
	}) (*PVEClusterTasksOutput, error) {
		_, cl, err := h.withCluster(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		ts, err := h.tasksOf(ctx, cl, 0, in.Limit)
		if err != nil {
			return nil, pveError(err)
		}
		out := &PVEClusterTasksOutput{}
		out.Body.Items = ts
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-pve-task-log", Method: http.MethodGet, Path: "/pve-clusters/{id}/task-log",
		Summary: "A Proxmox task's state and log", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEClusterIDPath
		UPID  string `query:"upid" maxLength:"300"`
		Start int    `query:"start" minimum:"0"`
	}) (*PVETaskLogOutput, error) {
		if !pveUPIDRe.MatchString(in.UPID) {
			return nil, huma.Error404NotFound("Task not found")
		}
		_, cl, err := h.withCluster(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		st, err := cl.TaskStatus(ctx, in.UPID)
		if err != nil {
			return nil, pveError(err)
		}
		lines, err := cl.TaskLog(ctx, in.UPID, in.Start, 5000)
		if err != nil {
			return nil, pveError(err)
		}
		out := &PVETaskLogOutput{}
		st.UPID = in.UPID
		out.Body.Task = toPVETask(st)
		out.Body.Lines = make([]string, 0, len(lines))
		for _, l := range lines {
			if l.T != "no content" {
				out.Body.Lines = append(out.Body.Lines, l.T)
			}
		}
		out.Body.Total = in.Start + len(lines)
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-pve-ha", Method: http.MethodGet, Path: "/pve-clusters/{id}/ha",
		Summary: "High availability: guarded machines and groups", Tags: tags,
	}, func(ctx context.Context, in *struct{ PVEClusterIDPath }) (*PVEHAOutput, error) {
		_, cl, err := h.withCluster(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		rs, err := cl.HAResources(ctx)
		if err != nil {
			return nil, pveError(err)
		}
		gs, _ := cl.HAGroups(ctx)
		guests, _ := cl.Resources(ctx, "vm")
		out := &PVEHAOutput{}
		out.Body.Items, out.Body.Groups = []PVEHAItem{}, []string{}
		for _, g := range gs {
			out.Body.Groups = append(out.Body.Groups, g.Group)
		}
		if st, err := cl.ClusterStatus(ctx); err == nil {
			for _, e := range st {
				if e.Type == "cluster" {
					out.Body.Quorate = e.Quorate == 1
				}
			}
			if len(st) > 0 && !slices.ContainsFunc(st, func(e proxmox.StatusEntry) bool { return e.Type == "cluster" }) {
				out.Body.Quorate = true // a single node is its own quorum
			}
		}
		for _, r := range rs {
			kind, id, _ := strings.Cut(r.SID, ":")
			vmid, _ := strconv.Atoi(id)
			it := PVEHAItem{SID: r.SID, VMID: vmid, State: r.State, Group: r.Group, MaxRestart: r.MaxRestart, MaxRelocate: r.MaxRelocate, Comment: r.Comment}
			it.Kind = "qemu"
			if kind == "ct" {
				it.Kind = "lxc"
			}
			for _, g := range guests {
				if g.VMID == vmid {
					it.Name, it.Node = g.Name, g.Node
				}
			}
			out.Body.Items = append(out.Body.Items, it)
		}
		sort.Slice(out.Body.Items, func(a, b int) bool { return out.Body.Items[a].VMID < out.Body.Items[b].VMID })
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-pve-create-options", Method: http.MethodGet, Path: "/pve-clusters/{id}/create-options",
		Summary: "What a new machine can be made from on this cluster", Tags: tags,
	}, func(ctx context.Context, in *struct{ PVEClusterIDPath }) (*struct{ Body PVECreateOptions }, error) {
		c, cl, err := h.withCluster(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		nodes, storages, err := h.infraOf(ctx, c)
		if err != nil {
			return nil, pveError(err)
		}
		o := PVECreateOptions{
			Nodes: nodes, Storages: storages, Bridges: map[string][]PVEBridge{}, Templates: []PVEGuest{},
			ISOs: []PVEVolumeAt{}, CTs: []PVEVolumeAt{}, HAGroups: []string{}, Problems: []string{},
		}
		if id, err := cl.NextID(ctx); err == nil {
			o.NextID = id
		}
		if gs, err := cl.Resources(ctx, "vm"); err == nil {
			for _, r := range gs {
				if r.Template == 1 && (r.Type == "qemu" || r.Type == "lxc") {
					o.Templates = append(o.Templates, toPVEGuest(c, r))
				}
			}
		}
		if hg, err := cl.HAGroups(ctx); err == nil {
			for _, g := range hg {
				o.HAGroups = append(o.HAGroups, g.Group)
			}
		}
		var mu sync.Mutex
		var wg sync.WaitGroup
		seen := map[string]bool{}
		for _, n := range nodes {
			if n.Status != "online" {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				nctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				bs, err := cl.Bridges(nctx, n.Node)
				mu.Lock()
				if err == nil {
					o.Bridges[n.Node] = toBridges(bs)
				} else {
					o.Problems = append(o.Problems, fmt.Sprintf("Couldn't read %s's networks", n.Node))
				}
				mu.Unlock()
				for _, s := range storages {
					if s.Node != n.Node || s.Status != "available" {
						continue
					}
					want := []string{}
					for _, ct := range s.Content {
						if ct == "iso" || ct == "vztmpl" {
							want = append(want, ct)
						}
					}
					for _, ct := range want {
						vs, err := cl.Content(nctx, n.Node, s.Storage, ct, 0)
						mu.Lock()
						if err != nil {
							o.Problems = append(o.Problems, fmt.Sprintf("Couldn't read %s on %s", s.Storage, n.Node))
						}
						for _, v := range vs {
							key := v.VolID
							if !s.Shared {
								key = n.Node + "/" + v.VolID
							}
							if seen[key] {
								continue
							}
							seen[key] = true
							at := PVEVolumeAt{PVEVolume: toPVEVolume(v), Node: n.Node, Storage: s.Storage, Shared: s.Shared}
							if ct == "iso" {
								o.ISOs = append(o.ISOs, at)
							} else {
								o.CTs = append(o.CTs, at)
							}
						}
						mu.Unlock()
					}
				}
			}()
		}
		wg.Wait()
		byName := func(xs []PVEVolumeAt) {
			sort.Slice(xs, func(a, b int) bool { return xs[a].Name < xs[b].Name })
		}
		byName(o.ISOs)
		byName(o.CTs)
		sort.Strings(o.Problems)
		return &struct{ Body PVECreateOptions }{o}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-pve-guest", Method: http.MethodPost, Path: "/pve-clusters/{id}/guests",
		Summary:     "Create a VM or a container",
		Description: "From a cloud-init template (clone, set up, grow the disk, start, add to Servers), an ISO, or a container template. Runs as a background task.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		PVEClusterIDPath
		Body PVECreateBody
	}) (*JobOutput, error) {
		b := in.Body
		if err := h.checkCreate(&b); err != nil {
			return nil, err
		}
		c, cl, err := h.withCluster(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		p := principalOf(ctx)
		if b.AddServer && !p.Access.CanCreateIn(c.WorkspaceID) {
			return nil, fieldError("body.add_server", "You can't add servers to this workspace", b.AddServer)
		}
		if b.VMID == 0 {
			if b.VMID, err = cl.NextID(ctx); err != nil {
				return nil, pveError(err)
			}
		} else if b.VMID < 100 {
			return nil, fieldError("body.vmid", "IDs start at 100", b.VMID)
		} else if _, err := cl.Find(ctx, b.VMID); err == nil {
			return nil, fieldError("body.vmid", fmt.Sprintf("%d is taken", b.VMID), b.VMID)
		}
		if b.Source == "clone" {
			t, err := cl.Find(ctx, b.Template)
			if err != nil {
				return nil, fieldError("body.template", "That template is gone", b.Template)
			}
			if t.Template != 1 {
				return nil, fieldError("body.template", "That machine isn't a template", b.Template)
			}
			if t.Type != b.Kind {
				return nil, fieldError("body.template", "That template is another kind", b.Template)
			}
		}
		params := pveCreateParams{
			Cluster: c.ID.String(), Node: b.Node, Kind: b.Kind, Source: b.Source, Template: b.Template,
			Full: b.Full, ISO: b.ISO, OSTemplate: b.OSTemplate, VMID: b.VMID, Name: b.Name, Storage: b.Storage,
			Cores: b.Cores, Memory: b.Memory, Swap: b.Swap, DiskGB: b.DiskGB, Bridge: b.Bridge, VLAN: b.VLAN,
			IPConfig: b.IPConfig, Nameserver: strings.TrimSpace(b.Nameserver), User: b.User,
			SSHKeys: b.SSHKeys, Tags: strings.Join(b.Tags, ";"), OnBoot: b.OnBoot, Start: b.Start,
			Unprivileged: b.Unprivileged, Nesting: b.Nesting, AddServer: b.AddServer,
			ServerName: strings.TrimSpace(b.ServerName), ServerTags: b.ServerTags,
		}
		if b.Password != "" {
			params.PasswordEnc = h.box.Seal(b.Password)
		}
		noun := "VM"
		if b.Kind == "lxc" {
			noun = "container"
		}
		return submit(ctx, h.runner, jobs.Spec{
			Kind: "pve-create", Title: fmt.Sprintf("Create %s %s (%d)", noun, b.Name, b.VMID),
			Params: params, Refs: []uuid.UUID{c.ID},
			Target: JobPlace{ClusterID: c.ID.String(), VMID: b.VMID, Name: b.Name},
		})
	})
}
