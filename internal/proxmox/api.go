package proxmox

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Kind is a guest's type: a QEMU virtual machine or an LXC container.
type Kind string

const (
	QEMU Kind = "qemu"
	LXC  Kind = "lxc"
)

// Valid says whether k is one of the two kinds.
func (k Kind) Valid() bool { return k == QEMU || k == LXC }

func guestPath(node string, kind Kind, vmid int) string {
	return fmt.Sprintf("/nodes/%s/%s/%d", url.PathEscape(node), kind, vmid)
}

// Info is what a connection check learns.
type Info struct {
	Version     string
	ClusterName string
	Nodes       int
	NodesOnline int
	Guests      int
	Running     int
	Latency     time.Duration
}

// Check reads the version and the cluster's shape, which needs only
// Sys.Audit (or less: a token without it still sees its own guests).
func (c *Client) Check(ctx context.Context) (Info, error) {
	start := time.Now()
	var v struct {
		Version string `json:"version"`
		Release string `json:"release"`
	}
	if err := c.get(ctx, "/version", nil, &v); err != nil {
		return Info{}, err
	}
	info := Info{Version: v.Version, Latency: time.Since(start)}
	if st, err := c.ClusterStatus(ctx); err == nil {
		for _, s := range st {
			switch s.Type {
			case "cluster":
				info.ClusterName = s.Name
			case "node":
				info.Nodes++
				if s.Online == 1 {
					info.NodesOnline++
				}
			}
		}
	}
	if res, err := c.Resources(ctx, ""); err == nil {
		for _, r := range res {
			if (r.Type == "qemu" || r.Type == "lxc") && r.Template != 1 {
				info.Guests++
				if r.Status == "running" {
					info.Running++
				}
			}
		}
	}
	return info, nil
}

// Cluster

type StatusEntry struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	Online  int    `json:"online"`
	Local   int    `json:"local"`
	IP      string `json:"ip"`
	Nodes   int    `json:"nodes"`
	Quorate int    `json:"quorate"`
	Version int    `json:"version"`
}

func (c *Client) ClusterStatus(ctx context.Context) ([]StatusEntry, error) {
	var out []StatusEntry
	return out, c.get(ctx, "/cluster/status", nil, &out)
}

// Resource is one row of /cluster/resources: a guest, a node or a storage.
type Resource struct {
	ID         string  `json:"id"`
	Type       string  `json:"type"`
	Node       string  `json:"node"`
	Status     string  `json:"status"`
	Name       string  `json:"name"`
	VMID       int     `json:"vmid"`
	CPU        float64 `json:"cpu"`
	MaxCPU     float64 `json:"maxcpu"`
	Mem        int64   `json:"mem"`
	MaxMem     int64   `json:"maxmem"`
	Disk       int64   `json:"disk"`
	MaxDisk    int64   `json:"maxdisk"`
	Uptime     int64   `json:"uptime"`
	Template   int     `json:"template"`
	Tags       string  `json:"tags"`
	NetIn      int64   `json:"netin"`
	NetOut     int64   `json:"netout"`
	DiskRead   int64   `json:"diskread"`
	DiskWrite  int64   `json:"diskwrite"`
	HAState    string  `json:"hastate"`
	Lock       string  `json:"lock"`
	Pool       string  `json:"pool"`
	Storage    string  `json:"storage"`
	Content    string  `json:"content"`
	PluginType string  `json:"plugintype"`
	Shared     int     `json:"shared"`
}

// TagList splits Proxmox's tag string (; or , or space separated).
func (r Resource) TagList() []string { return SplitTags(r.Tags) }

func SplitTags(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' || r == ' ' })
	out := make([]string, 0, len(f))
	for _, t := range f {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// Resources lists the cluster's resources; kind narrows to vm, node or storage.
func (c *Client) Resources(ctx context.Context, kind string) ([]Resource, error) {
	q := url.Values{}
	if kind != "" {
		q.Set("type", kind)
	}
	var out []Resource
	return out, c.get(ctx, "/cluster/resources", q, &out)
}

func (c *Client) NextID(ctx context.Context) (int, error) {
	var out any
	if err := c.get(ctx, "/cluster/nextid", nil, &out); err != nil {
		return 0, err
	}
	return int(Num(out)), nil
}

// Find locates a guest by id: its node and kind.
func (c *Client) Find(ctx context.Context, vmid int) (Resource, error) {
	res, err := c.Resources(ctx, "vm")
	if err != nil {
		return Resource{}, err
	}
	for _, r := range res {
		if r.VMID == vmid && (r.Type == "qemu" || r.Type == "lxc") {
			return r, nil
		}
	}
	return Resource{}, &APIError{Status: http.StatusNotFound, Message: fmt.Sprintf("VM %d does not exist", vmid)}
}

// Nodes

type Node struct {
	Node           string  `json:"node"`
	Status         string  `json:"status"`
	CPU            float64 `json:"cpu"`
	MaxCPU         float64 `json:"maxcpu"`
	Mem            int64   `json:"mem"`
	MaxMem         int64   `json:"maxmem"`
	Disk           int64   `json:"disk"`
	MaxDisk        int64   `json:"maxdisk"`
	Uptime         int64   `json:"uptime"`
	Level          string  `json:"level"`
	SSLFingerprint string  `json:"ssl_fingerprint"`
}

func (c *Client) Nodes(ctx context.Context) ([]Node, error) {
	var out []Node
	return out, c.get(ctx, "/nodes", nil, &out)
}

type NodeStatus struct {
	PVEVersion string   `json:"pveversion"`
	KVersion   string   `json:"kversion"`
	Uptime     int64    `json:"uptime"`
	LoadAvg    []string `json:"loadavg"`
	CPU        float64  `json:"cpu"`
	Wait       float64  `json:"wait"`
	CPUInfo    struct {
		Model   string `json:"model"`
		CPUs    int    `json:"cpus"`
		Sockets int    `json:"sockets"`
		Cores   int    `json:"cores"`
	} `json:"cpuinfo"`
	Memory struct {
		Total int64 `json:"total"`
		Used  int64 `json:"used"`
		Free  int64 `json:"free"`
	} `json:"memory"`
	Swap struct {
		Total int64 `json:"total"`
		Used  int64 `json:"used"`
	} `json:"swap"`
	RootFS struct {
		Total int64 `json:"total"`
		Used  int64 `json:"used"`
	} `json:"rootfs"`
}

func (c *Client) NodeStatus(ctx context.Context, node string) (NodeStatus, error) {
	var out NodeStatus
	return out, c.get(ctx, "/nodes/"+url.PathEscape(node)+"/status", nil, &out)
}

// RRDPoint is one sample. Proxmox leaves out what it has no value for.
type RRDPoint map[string]float64

func (c *Client) rrd(ctx context.Context, path, timeframe string) ([]RRDPoint, error) {
	var raw []map[string]any
	if err := c.get(ctx, path, url.Values{"timeframe": {timeframe}, "cf": {"AVERAGE"}}, &raw); err != nil {
		return nil, err
	}
	out := make([]RRDPoint, 0, len(raw))
	for _, r := range raw {
		p := RRDPoint{}
		for k, v := range r {
			if v == nil {
				continue
			}
			p[k] = Num(v)
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["time"] < out[j]["time"] })
	return out, nil
}

func (c *Client) NodeRRD(ctx context.Context, node, timeframe string) ([]RRDPoint, error) {
	return c.rrd(ctx, "/nodes/"+url.PathEscape(node)+"/rrddata", timeframe)
}

func (c *Client) GuestRRD(ctx context.Context, node string, kind Kind, vmid int, timeframe string) ([]RRDPoint, error) {
	return c.rrd(ctx, guestPath(node, kind, vmid)+"/rrddata", timeframe)
}

// Guests

type GuestStatus struct {
	Status    string  `json:"status"`
	QMPStatus string  `json:"qmpstatus"`
	Name      string  `json:"name"`
	CPU       float64 `json:"cpu"`
	CPUs      float64 `json:"cpus"`
	Mem       int64   `json:"mem"`
	MaxMem    int64   `json:"maxmem"`
	Disk      int64   `json:"disk"`
	MaxDisk   int64   `json:"maxdisk"`
	Uptime    int64   `json:"uptime"`
	Agent     any     `json:"agent"`
	HA        struct {
		Managed int    `json:"managed"`
		State   string `json:"state"`
		Group   string `json:"group"`
	} `json:"ha"`
	Lock           string `json:"lock"`
	Tags           string `json:"tags"`
	Template       any    `json:"template"`
	NetIn          int64  `json:"netin"`
	NetOut         int64  `json:"netout"`
	PID            any    `json:"pid"`
	RunningMachine string `json:"running-machine"`
	RunningQEMU    string `json:"running-qemu"`
}

func (c *Client) GuestStatus(ctx context.Context, node string, kind Kind, vmid int) (GuestStatus, error) {
	var out GuestStatus
	return out, c.get(ctx, guestPath(node, kind, vmid)+"/status/current", nil, &out)
}

// Settings is a guest's configuration, as Proxmox's flat key → value map.
type Settings map[string]string

func (c *Client) GuestConfig(ctx context.Context, node string, kind Kind, vmid int) (Settings, error) {
	var raw map[string]any
	if err := c.get(ctx, guestPath(node, kind, vmid)+"/config", nil, &raw); err != nil {
		return nil, err
	}
	out := Settings{}
	for k, v := range raw {
		out[k] = Str(v)
	}
	return out, nil
}

// PendingItem is one key with a change that waits for a restart.
type PendingItem struct {
	Key     string `json:"key"`
	Value   any    `json:"value"`
	Pending any    `json:"pending"`
	Delete  int    `json:"delete"`
}

func (c *Client) Pending(ctx context.Context, node string, kind Kind, vmid int) ([]PendingItem, error) {
	var out []PendingItem
	return out, c.get(ctx, guestPath(node, kind, vmid)+"/pending", nil, &out)
}

// SetConfig changes keys (and removes those in del). digest makes it fail if
// the config changed since it was read.
func (c *Client) SetConfig(ctx context.Context, node string, kind Kind, vmid int, set map[string]string, del []string, digest string) (string, error) {
	form := url.Values{}
	for k, v := range set {
		form.Set(k, v)
	}
	if len(del) > 0 {
		form.Set("delete", strings.Join(del, ","))
	}
	if digest != "" {
		form.Set("digest", digest)
	}
	if kind == QEMU {
		// POST runs it as a task, so a slow disk change doesn't time out.
		return c.upid(ctx, http.MethodPost, guestPath(node, kind, vmid)+"/config", form)
	}
	return c.upid(ctx, http.MethodPut, guestPath(node, kind, vmid)+"/config", form)
}

// Resize grows a disk; size is like "+10G" or "40G".
func (c *Client) Resize(ctx context.Context, node string, kind Kind, vmid int, disk, size string) (string, error) {
	return c.upid(ctx, http.MethodPut, guestPath(node, kind, vmid)+"/resize", url.Values{"disk": {disk}, "size": {size}})
}

// Power runs start, stop, shutdown, reboot, suspend or resume.
func (c *Client) Power(ctx context.Context, node string, kind Kind, vmid int, action string, opts url.Values) (string, error) {
	if opts == nil {
		opts = url.Values{}
	}
	return c.upid(ctx, http.MethodPost, guestPath(node, kind, vmid)+"/status/"+action, opts)
}

// Snapshots

type Snapshot struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Parent      string `json:"parent"`
	SnapTime    int64  `json:"snaptime"`
	VMState     int    `json:"vmstate"`
	Running     int    `json:"running"`
}

func (c *Client) Snapshots(ctx context.Context, node string, kind Kind, vmid int) ([]Snapshot, error) {
	var raw []map[string]any
	if err := c.get(ctx, guestPath(node, kind, vmid)+"/snapshot", nil, &raw); err != nil {
		return nil, err
	}
	out := make([]Snapshot, 0, len(raw))
	for _, r := range raw {
		out = append(out, Snapshot{
			Name: Str(r["name"]), Description: Str(r["description"]), Parent: Str(r["parent"]),
			SnapTime: int64(Num(r["snaptime"])), VMState: int(Num(r["vmstate"])), Running: int(Num(r["running"])),
		})
	}
	return out, nil
}

func (c *Client) CreateSnapshot(ctx context.Context, node string, kind Kind, vmid int, name, description string, vmstate bool) (string, error) {
	form := url.Values{"snapname": {name}}
	if description != "" {
		form.Set("description", description)
	}
	if vmstate && kind == QEMU {
		form.Set("vmstate", "1")
	}
	return c.upid(ctx, http.MethodPost, guestPath(node, kind, vmid)+"/snapshot", form)
}

func (c *Client) RollbackSnapshot(ctx context.Context, node string, kind Kind, vmid int, name string, start bool) (string, error) {
	form := url.Values{}
	if start {
		form.Set("start", "1")
	}
	return c.upid(ctx, http.MethodPost, guestPath(node, kind, vmid)+"/snapshot/"+url.PathEscape(name)+"/rollback", form)
}

func (c *Client) DeleteSnapshot(ctx context.Context, node string, kind Kind, vmid int, name string) (string, error) {
	return c.upid(ctx, http.MethodDelete, guestPath(node, kind, vmid)+"/snapshot/"+url.PathEscape(name), nil)
}

// Lifecycle

type CloneOptions struct {
	NewID   int
	Name    string
	Full    bool
	Target  string
	Storage string
	Pool    string
}

func (c *Client) Clone(ctx context.Context, node string, kind Kind, vmid int, o CloneOptions) (string, error) {
	form := url.Values{"newid": {strconv.Itoa(o.NewID)}}
	if o.Name != "" {
		if kind == LXC {
			form.Set("hostname", o.Name)
		} else {
			form.Set("name", o.Name)
		}
	}
	if o.Full {
		form.Set("full", "1")
	}
	if o.Target != "" && o.Target != node {
		form.Set("target", o.Target)
	}
	if o.Storage != "" && o.Full {
		form.Set("storage", o.Storage)
	}
	if o.Pool != "" {
		form.Set("pool", o.Pool)
	}
	return c.upid(ctx, http.MethodPost, guestPath(node, kind, vmid)+"/clone", form)
}

func (c *Client) Template(ctx context.Context, node string, kind Kind, vmid int) (string, error) {
	return c.upid(ctx, http.MethodPost, guestPath(node, kind, vmid)+"/template", url.Values{})
}

// Delete removes a guest with its disks, its backup jobs and HA entry.
func (c *Client) Delete(ctx context.Context, node string, kind Kind, vmid int) (string, error) {
	q := url.Values{"purge": {"1"}, "destroy-unreferenced-disks": {"1"}}
	return c.upid(ctx, http.MethodDelete, guestPath(node, kind, vmid), q)
}

// MigrateCheck is what Proxmox says about moving a VM.
type MigrateCheck struct {
	Running         bool             `json:"running"`
	AllowedNodes    []string         `json:"allowed_nodes"`
	NotAllowedNodes map[string]any   `json:"not_allowed_nodes"`
	LocalDisks      []map[string]any `json:"local_disks"`
	LocalResources  []string         `json:"local_resources"`
}

func (c *Client) MigrateCheck(ctx context.Context, node string, kind Kind, vmid int, target string) (MigrateCheck, error) {
	var raw map[string]any
	q := url.Values{}
	if target != "" {
		q.Set("target", target)
	}
	if kind != QEMU {
		return MigrateCheck{}, nil
	}
	if err := c.get(ctx, guestPath(node, kind, vmid)+"/migrate", q, &raw); err != nil {
		return MigrateCheck{}, err
	}
	out := MigrateCheck{Running: Num(raw["running"]) == 1}
	if a, ok := raw["allowed_nodes"].([]any); ok {
		for _, n := range a {
			out.AllowedNodes = append(out.AllowedNodes, Str(n))
		}
	}
	if m, ok := raw["not_allowed_nodes"].(map[string]any); ok {
		out.NotAllowedNodes = m
	}
	if d, ok := raw["local_disks"].([]any); ok {
		for _, x := range d {
			if m, ok := x.(map[string]any); ok {
				out.LocalDisks = append(out.LocalDisks, m)
			}
		}
	}
	if r, ok := raw["local_resources"].([]any); ok {
		for _, x := range r {
			out.LocalResources = append(out.LocalResources, Str(x))
		}
	}
	return out, nil
}

// Migrate moves a guest. A running VM moves live; a running container
// restarts on the target.
func (c *Client) Migrate(ctx context.Context, node string, kind Kind, vmid int, target string, running, localDisks bool) (string, error) {
	form := url.Values{"target": {target}}
	if running {
		if kind == QEMU {
			form.Set("online", "1")
		} else {
			form.Set("restart", "1")
		}
	}
	if localDisks && kind == QEMU {
		form.Set("with-local-disks", "1")
	}
	return c.upid(ctx, http.MethodPost, guestPath(node, kind, vmid)+"/migrate", form)
}

// Tasks

type TaskStatus struct {
	UPID       string `json:"upid"`
	Node       string `json:"node"`
	Type       string `json:"type"`
	ID         string `json:"id"`
	User       string `json:"user"`
	Status     string `json:"status"`
	ExitStatus string `json:"exitstatus"`
	StartTime  int64  `json:"starttime"`
	EndTime    int64  `json:"endtime"`
}

// OK says a stopped task ended well. Proxmox writes warnings as "WARNINGS: n".
func (t TaskStatus) OK() bool {
	return t.ExitStatus == "OK" || strings.HasPrefix(t.ExitStatus, "WARNINGS")
}

// NodeOfUPID reads the node out of UPID:node:pid:….
func NodeOfUPID(upid string) string {
	parts := strings.Split(upid, ":")
	if len(parts) > 1 {
		return parts[1]
	}
	return ""
}

func taskPath(upid string) string {
	return "/nodes/" + url.PathEscape(NodeOfUPID(upid)) + "/tasks/" + url.PathEscape(upid)
}

func (c *Client) TaskStatus(ctx context.Context, upid string) (TaskStatus, error) {
	var raw map[string]any
	if err := c.get(ctx, taskPath(upid)+"/status", nil, &raw); err != nil {
		return TaskStatus{}, err
	}
	return TaskStatus{
		UPID: Str(raw["upid"]), Node: Str(raw["node"]), Type: Str(raw["type"]), ID: Str(raw["id"]),
		User: Str(raw["user"]), Status: Str(raw["status"]), ExitStatus: Str(raw["exitstatus"]),
		StartTime: int64(Num(raw["starttime"])), EndTime: int64(Num(raw["endtime"])),
	}, nil
}

type LogLine struct {
	N int    `json:"n"`
	T string `json:"t"`
}

func (c *Client) TaskLog(ctx context.Context, upid string, start, limit int) ([]LogLine, error) {
	var out []LogLine
	q := url.Values{"start": {strconv.Itoa(start)}, "limit": {strconv.Itoa(limit)}}
	return out, c.get(ctx, taskPath(upid)+"/log", q, &out)
}

func (c *Client) StopTask(ctx context.Context, upid string) error {
	return c.del(ctx, taskPath(upid), nil, nil)
}

// Tasks lists a node's recent tasks; vmid narrows them to one guest.
func (c *Client) Tasks(ctx context.Context, node string, vmid int, limit int) ([]TaskStatus, error) {
	q := url.Values{"limit": {strconv.Itoa(limit)}, "source": {"all"}}
	if vmid > 0 {
		q.Set("vmid", strconv.Itoa(vmid))
	}
	var raw []map[string]any
	if err := c.get(ctx, "/nodes/"+url.PathEscape(node)+"/tasks", q, &raw); err != nil {
		return nil, err
	}
	out := make([]TaskStatus, 0, len(raw))
	for _, r := range raw {
		st := Str(r["status"])
		t := TaskStatus{
			UPID: Str(r["upid"]), Node: Str(r["node"]), Type: Str(r["type"]), ID: Str(r["id"]),
			User: Str(r["user"]), StartTime: int64(Num(r["starttime"])), EndTime: int64(Num(r["endtime"])),
		}
		if t.EndTime > 0 {
			t.Status, t.ExitStatus = "stopped", st
		} else {
			t.Status = "running"
		}
		out = append(out, t)
	}
	return out, nil
}

// Wait polls a task until it stops. each gets new log lines as they come.
func (c *Client) Wait(ctx context.Context, upid string, each func([]LogLine)) (TaskStatus, error) {
	seen := 0
	for {
		st, err := c.TaskStatus(ctx, upid)
		if err != nil {
			return st, err
		}
		if each != nil {
			if lines, err := c.TaskLog(ctx, upid, seen, 500); err == nil && len(lines) > 0 {
				// The log answers "no content" as a single line 0 sometimes.
				var fresh []LogLine
				for _, l := range lines {
					if l.N > seen {
						fresh = append(fresh, l)
						seen = l.N
					}
				}
				if len(fresh) > 0 {
					each(fresh)
				}
			}
		}
		if st.Status == "stopped" {
			return st, nil
		}
		select {
		case <-ctx.Done():
			return st, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// TaskError is a task that ended badly.
type TaskError struct{ Status string }

func (e *TaskError) Error() string { return "Proxmox task failed: " + e.Status }

// Run waits for a task (when there is one) and turns a failed end into an error.
func (c *Client) Run(ctx context.Context, upid string, each func([]LogLine)) error {
	if upid == "" {
		return nil
	}
	st, err := c.Wait(ctx, upid, each)
	if err != nil {
		return err
	}
	if !st.OK() {
		return &TaskError{Status: st.ExitStatus}
	}
	return nil
}

// Storage

type Storage struct {
	Storage      string  `json:"storage"`
	Type         string  `json:"type"`
	Content      string  `json:"content"`
	Active       int     `json:"active"`
	Enabled      int     `json:"enabled"`
	Shared       int     `json:"shared"`
	Total        int64   `json:"total"`
	Used         int64   `json:"used"`
	Avail        int64   `json:"avail"`
	UsedFraction float64 `json:"used_fraction"`
}

// Storages lists a node's storages; content narrows to those holding it.
func (c *Client) Storages(ctx context.Context, node, content string) ([]Storage, error) {
	q := url.Values{}
	if content != "" {
		q.Set("content", content)
	}
	var out []Storage
	return out, c.get(ctx, "/nodes/"+url.PathEscape(node)+"/storage", q, &out)
}

type Volume struct {
	VolID        string `json:"volid"`
	Format       string `json:"format"`
	Content      string `json:"content"`
	Size         int64  `json:"size"`
	Used         int64  `json:"used"`
	CTime        int64  `json:"ctime"`
	VMID         int    `json:"vmid"`
	Notes        string `json:"notes"`
	Protected    int    `json:"protected"`
	Verification struct {
		State string `json:"state"`
	} `json:"verification"`
	Subtype string `json:"subtype"`
}

func (c *Client) Content(ctx context.Context, node, storage, content string, vmid int) ([]Volume, error) {
	q := url.Values{}
	if content != "" {
		q.Set("content", content)
	}
	if vmid > 0 {
		q.Set("vmid", strconv.Itoa(vmid))
	}
	var raw []map[string]any
	if err := c.get(ctx, "/nodes/"+url.PathEscape(node)+"/storage/"+url.PathEscape(storage)+"/content", q, &raw); err != nil {
		return nil, err
	}
	out := make([]Volume, 0, len(raw))
	for _, r := range raw {
		v := Volume{
			VolID: Str(r["volid"]), Format: Str(r["format"]), Content: Str(r["content"]),
			Size: int64(Num(r["size"])), Used: int64(Num(r["used"])), CTime: int64(Num(r["ctime"])),
			VMID: int(Num(r["vmid"])), Notes: Str(r["notes"]), Protected: int(Num(r["protected"])),
			Subtype: Str(r["subtype"]),
		}
		if m, ok := r["verification"].(map[string]any); ok {
			v.Verification.State = Str(m["state"])
		}
		out = append(out, v)
	}
	return out, nil
}

// DownloadURL has the node fetch a file (an ISO or a container template).
func (c *Client) DownloadURL(ctx context.Context, node, storage, content, fileURL, filename, checksum, algorithm string) (string, error) {
	form := url.Values{"content": {content}, "url": {fileURL}, "filename": {filename}}
	if checksum != "" {
		form.Set("checksum", checksum)
		form.Set("checksum-algorithm", algorithm)
	}
	return c.upid(ctx, http.MethodPost, "/nodes/"+url.PathEscape(node)+"/storage/"+url.PathEscape(storage)+"/download-url", form)
}

func (c *Client) DeleteVolume(ctx context.Context, node, storage, volid string) (string, error) {
	return c.upid(ctx, http.MethodDelete, "/nodes/"+url.PathEscape(node)+"/storage/"+url.PathEscape(storage)+"/content/"+url.PathEscape(volid), nil)
}

// Backups

type BackupOptions struct {
	Storage   string
	Mode      string // snapshot, suspend, stop
	Compress  string // zstd, lzo, gzip, 0
	Notes     string
	Protected bool
	Remove    bool
}

func (c *Client) Vzdump(ctx context.Context, node string, vmid int, o BackupOptions) (string, error) {
	form := url.Values{"vmid": {strconv.Itoa(vmid)}, "storage": {o.Storage}}
	form.Set("mode", firstOf(o.Mode, "snapshot"))
	form.Set("compress", firstOf(o.Compress, "zstd"))
	if o.Notes != "" {
		form.Set("notes-template", o.Notes)
	}
	if o.Protected {
		form.Set("protected", "1")
	}
	if o.Remove {
		form.Set("remove", "1")
	}
	return c.upid(ctx, http.MethodPost, "/nodes/"+url.PathEscape(node)+"/vzdump", form)
}

// Restore puts a backup back as vmid on node. force replaces a guest that
// has that id.
func (c *Client) Restore(ctx context.Context, node string, kind Kind, vmid int, archive, storage string, force, unique, start bool) (string, error) {
	form := url.Values{"vmid": {strconv.Itoa(vmid)}}
	if kind == LXC {
		form.Set("ostemplate", archive)
		form.Set("restore", "1")
	} else {
		form.Set("archive", archive)
	}
	if storage != "" {
		form.Set("storage", storage)
	}
	if force {
		form.Set("force", "1")
	}
	if unique {
		form.Set("unique", "1")
	}
	if start {
		form.Set("start", "1")
	}
	return c.upid(ctx, http.MethodPost, "/nodes/"+url.PathEscape(node)+"/"+string(kind), form)
}

// CreateGuest makes a new VM or container from raw parameters.
func (c *Client) CreateGuest(ctx context.Context, node string, kind Kind, params map[string]string) (string, error) {
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	return c.upid(ctx, http.MethodPost, "/nodes/"+url.PathEscape(node)+"/"+string(kind), form)
}

// Guest addresses

type Interface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac"`
	Addresses []string `json:"addresses"`
}

// Interfaces asks the QEMU guest agent, or the container, for its addresses.
func (c *Client) Interfaces(ctx context.Context, node string, kind Kind, vmid int) ([]Interface, error) {
	var out []Interface
	if kind == LXC {
		var raw []map[string]any
		if err := c.get(ctx, guestPath(node, kind, vmid)+"/interfaces", nil, &raw); err != nil {
			return nil, err
		}
		for _, r := range raw {
			i := Interface{Name: Str(r["name"]), MAC: Str(r["hwaddr"])}
			for _, k := range []string{"inet", "inet6"} {
				if a := Str(r[k]); a != "" {
					i.Addresses = append(i.Addresses, a)
				}
			}
			out = append(out, i)
		}
		return out, nil
	}
	var raw struct {
		Result []struct {
			Name  string `json:"name"`
			MAC   string `json:"hardware-address"`
			Addrs []struct {
				Type   string `json:"ip-address-type"`
				IP     string `json:"ip-address"`
				Prefix int    `json:"prefix"`
			} `json:"ip-addresses"`
		} `json:"result"`
	}
	if err := c.get(ctx, guestPath(node, kind, vmid)+"/agent/network-get-interfaces", nil, &raw); err != nil {
		return nil, err
	}
	for _, r := range raw.Result {
		i := Interface{Name: r.Name, MAC: r.MAC}
		for _, a := range r.Addrs {
			i.Addresses = append(i.Addresses, a.IP+"/"+strconv.Itoa(a.Prefix))
		}
		out = append(out, i)
	}
	return out, nil
}

// Firewall

type FirewallRule struct {
	Pos     int    `json:"pos"`
	Type    string `json:"type"`
	Action  string `json:"action"`
	Enable  int    `json:"enable"`
	Source  string `json:"source"`
	Dest    string `json:"dest"`
	Proto   string `json:"proto"`
	DPort   string `json:"dport"`
	SPort   string `json:"sport"`
	Iface   string `json:"iface"`
	Macro   string `json:"macro"`
	Comment string `json:"comment"`
	Log     string `json:"log"`
}

func (c *Client) FirewallRules(ctx context.Context, node string, kind Kind, vmid int) ([]FirewallRule, error) {
	var raw []map[string]any
	if err := c.get(ctx, guestPath(node, kind, vmid)+"/firewall/rules", nil, &raw); err != nil {
		return nil, err
	}
	out := make([]FirewallRule, 0, len(raw))
	for _, r := range raw {
		out = append(out, FirewallRule{
			Pos: int(Num(r["pos"])), Type: Str(r["type"]), Action: Str(r["action"]), Enable: int(Num(r["enable"])),
			Source: Str(r["source"]), Dest: Str(r["dest"]), Proto: Str(r["proto"]), DPort: Str(r["dport"]),
			SPort: Str(r["sport"]), Iface: Str(r["iface"]), Macro: Str(r["macro"]), Comment: Str(r["comment"]),
			Log: Str(r["log"]),
		})
	}
	return out, nil
}

func ruleForm(r FirewallRule) url.Values {
	form := url.Values{"type": {r.Type}, "action": {r.Action}, "enable": {strconv.Itoa(r.Enable)}}
	for k, v := range map[string]string{
		"source": r.Source, "dest": r.Dest, "proto": r.Proto, "dport": r.DPort, "sport": r.SPort,
		"iface": r.Iface, "macro": r.Macro, "comment": r.Comment, "log": r.Log,
	} {
		if v != "" {
			form.Set(k, v)
		}
	}
	return form
}

func (c *Client) AddFirewallRule(ctx context.Context, node string, kind Kind, vmid int, r FirewallRule) error {
	form := ruleForm(r)
	form.Set("pos", "0")
	return c.post(ctx, guestPath(node, kind, vmid)+"/firewall/rules", form, nil)
}

func (c *Client) UpdateFirewallRule(ctx context.Context, node string, kind Kind, vmid int, r FirewallRule) error {
	form := ruleForm(r)
	var del []string
	for _, k := range []string{"source", "dest", "proto", "dport", "sport", "iface", "macro", "comment"} {
		if form.Get(k) == "" {
			del = append(del, k)
		}
	}
	if len(del) > 0 {
		form.Set("delete", strings.Join(del, ","))
	}
	return c.put(ctx, guestPath(node, kind, vmid)+"/firewall/rules/"+strconv.Itoa(r.Pos), form, nil)
}

func (c *Client) MoveFirewallRule(ctx context.Context, node string, kind Kind, vmid int, pos, to int) error {
	return c.put(ctx, guestPath(node, kind, vmid)+"/firewall/rules/"+strconv.Itoa(pos), url.Values{"moveto": {strconv.Itoa(to)}}, nil)
}

func (c *Client) DeleteFirewallRule(ctx context.Context, node string, kind Kind, vmid int, pos int) error {
	return c.del(ctx, guestPath(node, kind, vmid)+"/firewall/rules/"+strconv.Itoa(pos), nil, nil)
}

type FirewallOptions struct {
	Enable    bool   `json:"enable"`
	PolicyIn  string `json:"policy_in"`
	PolicyOut string `json:"policy_out"`
	MACFilter bool   `json:"macfilter"`
	DHCP      bool   `json:"dhcp"`
	IPFilter  bool   `json:"ipfilter"`
}

func (c *Client) FirewallOptions(ctx context.Context, node string, kind Kind, vmid int) (FirewallOptions, error) {
	var raw map[string]any
	if err := c.get(ctx, guestPath(node, kind, vmid)+"/firewall/options", nil, &raw); err != nil {
		return FirewallOptions{}, err
	}
	o := FirewallOptions{
		Enable: Num(raw["enable"]) == 1, PolicyIn: firstOf(Str(raw["policy_in"]), "DROP"),
		PolicyOut: firstOf(Str(raw["policy_out"]), "ACCEPT"), MACFilter: Str(raw["macfilter"]) != "0",
		DHCP: Num(raw["dhcp"]) == 1, IPFilter: Num(raw["ipfilter"]) == 1,
	}
	return o, nil
}

func (c *Client) SetFirewallOptions(ctx context.Context, node string, kind Kind, vmid int, o FirewallOptions) error {
	b := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	form := url.Values{
		"enable": {b(o.Enable)}, "policy_in": {o.PolicyIn}, "policy_out": {o.PolicyOut},
		"macfilter": {b(o.MACFilter)}, "dhcp": {b(o.DHCP)}, "ipfilter": {b(o.IPFilter)},
	}
	return c.put(ctx, guestPath(node, kind, vmid)+"/firewall/options", form, nil)
}

// High availability

type HAResource struct {
	SID         string `json:"sid"`
	State       string `json:"state"`
	Group       string `json:"group"`
	MaxRestart  int    `json:"max_restart"`
	MaxRelocate int    `json:"max_relocate"`
	Comment     string `json:"comment"`
}

func (c *Client) HAResources(ctx context.Context) ([]HAResource, error) {
	var raw []map[string]any
	if err := c.get(ctx, "/cluster/ha/resources", nil, &raw); err != nil {
		return nil, err
	}
	out := make([]HAResource, 0, len(raw))
	for _, r := range raw {
		out = append(out, HAResource{
			SID: Str(r["sid"]), State: Str(r["state"]), Group: Str(r["group"]),
			MaxRestart: int(Num(r["max_restart"])), MaxRelocate: int(Num(r["max_relocate"])), Comment: Str(r["comment"]),
		})
	}
	return out, nil
}

func haSID(kind Kind, vmid int) string {
	if kind == LXC {
		return "ct:" + strconv.Itoa(vmid)
	}
	return "vm:" + strconv.Itoa(vmid)
}

func (c *Client) SetHA(ctx context.Context, kind Kind, vmid int, r HAResource, exists bool) error {
	form := url.Values{
		"state": {firstOf(r.State, "started")}, "max_restart": {strconv.Itoa(r.MaxRestart)},
		"max_relocate": {strconv.Itoa(r.MaxRelocate)},
	}
	if r.Group != "" {
		form.Set("group", r.Group)
	}
	if r.Comment != "" {
		form.Set("comment", r.Comment)
	}
	if exists {
		return c.put(ctx, "/cluster/ha/resources/"+url.PathEscape(haSID(kind, vmid)), form, nil)
	}
	form.Set("sid", haSID(kind, vmid))
	return c.post(ctx, "/cluster/ha/resources", form, nil)
}

func (c *Client) RemoveHA(ctx context.Context, kind Kind, vmid int) error {
	return c.del(ctx, "/cluster/ha/resources/"+url.PathEscape(haSID(kind, vmid)), nil, nil)
}

type HAGroup struct {
	Group string `json:"group"`
	Nodes string `json:"nodes"`
}

func (c *Client) HAGroups(ctx context.Context) ([]HAGroup, error) {
	var out []HAGroup
	err := c.get(ctx, "/cluster/ha/groups", nil, &out)
	return out, err
}

// Networks a node offers to guests (bridges).
type Network struct {
	Iface    string `json:"iface"`
	Type     string `json:"type"`
	Active   int    `json:"active"`
	CIDR     string `json:"cidr"`
	Comments string `json:"comments"`
}

func (c *Client) Bridges(ctx context.Context, node string) ([]Network, error) {
	var out []Network
	return out, c.get(ctx, "/nodes/"+url.PathEscape(node)+"/network", url.Values{"type": {"any_bridge"}}, &out)
}

// Consoles

type ConsoleTicket struct {
	User     string `json:"user"`
	Ticket   string `json:"ticket"`
	Port     string `json:"port"`
	UPID     string `json:"upid"`
	Password string `json:"password"`
	Cert     string `json:"cert"`
}

// VNCProxy opens a VNC console for a VM (or a container's terminal shown as
// VNC) that a websocket can attach to.
func (c *Client) VNCProxy(ctx context.Context, node string, kind Kind, vmid int) (ConsoleTicket, error) {
	var raw map[string]any
	form := url.Values{"websocket": {"1"}}
	if kind == QEMU {
		form.Set("generate-password", "1")
	}
	if err := c.post(ctx, guestPath(node, kind, vmid)+"/vncproxy", form, &raw); err != nil {
		return ConsoleTicket{}, err
	}
	return ConsoleTicket{
		User: Str(raw["user"]), Ticket: Str(raw["ticket"]), Port: Str(raw["port"]),
		UPID: Str(raw["upid"]), Password: Str(raw["password"]), Cert: Str(raw["cert"]),
	}, nil
}

// TermProxy opens a text console: a container's shell, or a VM's serial port.
func (c *Client) TermProxy(ctx context.Context, node string, kind Kind, vmid int, serial string) (ConsoleTicket, error) {
	var raw map[string]any
	form := url.Values{}
	if kind == QEMU && serial != "" {
		form.Set("serial", serial)
	}
	if err := c.post(ctx, guestPath(node, kind, vmid)+"/termproxy", form, &raw); err != nil {
		return ConsoleTicket{}, err
	}
	return ConsoleTicket{
		User: Str(raw["user"]), Ticket: Str(raw["ticket"]), Port: Str(raw["port"]), UPID: Str(raw["upid"]),
	}, nil
}

// WebsocketURL is where to attach to a console made by VNCProxy or TermProxy.
func (c *Client) WebsocketURL(node string, kind Kind, vmid int, t ConsoleTicket) string {
	base := strings.Replace(c.base, "https://", "wss://", 1)
	base = strings.Replace(base, "http://", "ws://", 1)
	q := url.Values{"port": {t.Port}, "vncticket": {t.Ticket}}
	return base + guestPath(node, kind, vmid) + "/vncwebsocket?" + q.Encode()
}
