package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
)

// The engine's own shapes, only the fields Morche reads.

type Info struct {
	ID                string   `json:"ID"`
	Name              string   `json:"Name"`
	ServerVersion     string   `json:"ServerVersion"`
	OperatingSystem   string   `json:"OperatingSystem"`
	OSType            string   `json:"OSType"`
	KernelVersion     string   `json:"KernelVersion"`
	Architecture      string   `json:"Architecture"`
	NCPU              int      `json:"NCPU"`
	MemTotal          int64    `json:"MemTotal"`
	Driver            string   `json:"Driver"`
	DockerRootDir     string   `json:"DockerRootDir"`
	LoggingDriver     string   `json:"LoggingDriver"`
	CgroupVersion     string   `json:"CgroupVersion"`
	Containers        int      `json:"Containers"`
	ContainersRunning int      `json:"ContainersRunning"`
	ContainersPaused  int      `json:"ContainersPaused"`
	ContainersStopped int      `json:"ContainersStopped"`
	Images            int      `json:"Images"`
	SecurityOptions   []string `json:"SecurityOptions"`
	Warnings          []string `json:"Warnings"`
	Swarm             struct {
		LocalNodeState string `json:"LocalNodeState"`
	} `json:"Swarm"`
}

type Version struct {
	Version       string `json:"Version"`
	APIVersion    string `json:"ApiVersion"`
	MinAPIVersion string `json:"MinAPIVersion"`
	Os            string `json:"Os"`
	Arch          string `json:"Arch"`
	Components    []struct {
		Name    string `json:"Name"`
		Version string `json:"Version"`
	} `json:"Components"`
}

type Port struct {
	IP          string `json:"IP"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
}

type Mount struct {
	Type        string `json:"Type"`
	Name        string `json:"Name"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	Mode        string `json:"Mode"`
	RW          bool   `json:"RW"`
}

type EndpointSettings struct {
	NetworkID   string   `json:"NetworkID"`
	IPAddress   string   `json:"IPAddress"`
	IPPrefixLen int      `json:"IPPrefixLen"`
	Gateway     string   `json:"Gateway"`
	GlobalIPv6  string   `json:"GlobalIPv6Address"`
	MacAddress  string   `json:"MacAddress"`
	Aliases     []string `json:"Aliases"`
	DNSNames    []string `json:"DNSNames"`
}

type ContainerSummary struct {
	ID              string            `json:"Id"`
	Names           []string          `json:"Names"`
	Image           string            `json:"Image"`
	ImageID         string            `json:"ImageID"`
	Command         string            `json:"Command"`
	Created         int64             `json:"Created"`
	Ports           []Port            `json:"Ports"`
	Labels          map[string]string `json:"Labels"`
	State           string            `json:"State"`
	Status          string            `json:"Status"`
	Mounts          []Mount           `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]EndpointSettings `json:"Networks"`
	} `json:"NetworkSettings"`
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
	Health *struct {
		Status string `json:"Status"`
	} `json:"Health"`
}

type HealthLog struct {
	Start    string `json:"Start"`
	End      string `json:"End"`
	ExitCode int    `json:"ExitCode"`
	Output   string `json:"Output"`
}

type PortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

type ContainerInspect struct {
	ID           string   `json:"Id"`
	Name         string   `json:"Name"`
	Created      string   `json:"Created"`
	Path         string   `json:"Path"`
	Args         []string `json:"Args"`
	Image        string   `json:"Image"`
	RestartCount int      `json:"RestartCount"`
	Platform     string   `json:"Platform"`
	Driver       string   `json:"Driver"`
	SizeRw       *int64   `json:"SizeRw"`
	SizeRootFs   *int64   `json:"SizeRootFs"`
	State        struct {
		Status     string `json:"Status"`
		Running    bool   `json:"Running"`
		Paused     bool   `json:"Paused"`
		Restarting bool   `json:"Restarting"`
		OOMKilled  bool   `json:"OOMKilled"`
		Dead       bool   `json:"Dead"`
		Pid        int    `json:"Pid"`
		ExitCode   int    `json:"ExitCode"`
		Error      string `json:"Error"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
		Health     *struct {
			Status        string      `json:"Status"`
			FailingStreak int         `json:"FailingStreak"`
			Log           []HealthLog `json:"Log"`
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Hostname     string              `json:"Hostname"`
		Domainname   string              `json:"Domainname"`
		User         string              `json:"User"`
		Tty          bool                `json:"Tty"`
		OpenStdin    bool                `json:"OpenStdin"`
		Env          []string            `json:"Env"`
		Cmd          []string            `json:"Cmd"`
		Entrypoint   []string            `json:"Entrypoint"`
		Image        string              `json:"Image"`
		WorkingDir   string              `json:"WorkingDir"`
		Labels       map[string]string   `json:"Labels"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
		StopSignal   string              `json:"StopSignal"`
		StopTimeout  *int                `json:"StopTimeout"`
		Healthcheck  *struct {
			Test     []string `json:"Test"`
			Interval int64    `json:"Interval"`
			Timeout  int64    `json:"Timeout"`
			Retries  int      `json:"Retries"`
		} `json:"Healthcheck"`
	} `json:"Config"`
	HostConfig struct {
		RestartPolicy struct {
			Name              string `json:"Name"`
			MaximumRetryCount int    `json:"MaximumRetryCount"`
		} `json:"RestartPolicy"`
		NetworkMode    string                   `json:"NetworkMode"`
		Privileged     bool                     `json:"Privileged"`
		ReadonlyRootfs bool                     `json:"ReadonlyRootfs"`
		AutoRemove     bool                     `json:"AutoRemove"`
		Memory         int64                    `json:"Memory"`
		MemoryReserve  int64                    `json:"MemoryReservation"`
		NanoCPUs       int64                    `json:"NanoCpus"`
		CPUShares      int64                    `json:"CpuShares"`
		CPUSetCPUs     string                   `json:"CpusetCpus"`
		PidsLimit      *int64                   `json:"PidsLimit"`
		CapAdd         []string                 `json:"CapAdd"`
		CapDrop        []string                 `json:"CapDrop"`
		Binds          []string                 `json:"Binds"`
		PortBindings   map[string][]PortBinding `json:"PortBindings"`
		DNS            []string                 `json:"Dns"`
		ExtraHosts     []string                 `json:"ExtraHosts"`
		Devices        []struct {
			PathOnHost      string `json:"PathOnHost"`
			PathInContainer string `json:"PathInContainer"`
		} `json:"Devices"`
		LogConfig struct {
			Type   string            `json:"Type"`
			Config map[string]string `json:"Config"`
		} `json:"LogConfig"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports    map[string][]PortBinding    `json:"Ports"`
		Networks map[string]EndpointSettings `json:"Networks"`
	} `json:"NetworkSettings"`
	Mounts []Mount `json:"Mounts"`
}

type ImageSummary struct {
	ID          string            `json:"Id"`
	ParentID    string            `json:"ParentId"`
	RepoTags    []string          `json:"RepoTags"`
	RepoDigests []string          `json:"RepoDigests"`
	Created     int64             `json:"Created"`
	Size        int64             `json:"Size"`
	SharedSize  int64             `json:"SharedSize"`
	Containers  int               `json:"Containers"`
	Labels      map[string]string `json:"Labels"`
}

type ImageInspect struct {
	ID            string   `json:"Id"`
	RepoTags      []string `json:"RepoTags"`
	RepoDigests   []string `json:"RepoDigests"`
	Created       string   `json:"Created"`
	Author        string   `json:"Author"`
	Architecture  string   `json:"Architecture"`
	Variant       string   `json:"Variant"`
	Os            string   `json:"Os"`
	Size          int64    `json:"Size"`
	DockerVersion string   `json:"DockerVersion"`
	Config        struct {
		User         string              `json:"User"`
		Env          []string            `json:"Env"`
		Cmd          []string            `json:"Cmd"`
		Entrypoint   []string            `json:"Entrypoint"`
		WorkingDir   string              `json:"WorkingDir"`
		Labels       map[string]string   `json:"Labels"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
		Volumes      map[string]struct{} `json:"Volumes"`
	} `json:"Config"`
	RootFS struct {
		Layers []string `json:"Layers"`
	} `json:"RootFS"`
}

type HistoryItem struct {
	ID        string   `json:"Id"`
	Created   int64    `json:"Created"`
	CreatedBy string   `json:"CreatedBy"`
	Tags      []string `json:"Tags"`
	Size      int64    `json:"Size"`
	Comment   string   `json:"Comment"`
}

type Volume struct {
	Name       string            `json:"Name"`
	Driver     string            `json:"Driver"`
	Mountpoint string            `json:"Mountpoint"`
	CreatedAt  string            `json:"CreatedAt"`
	Labels     map[string]string `json:"Labels"`
	Scope      string            `json:"Scope"`
	Options    map[string]string `json:"Options"`
	UsageData  *struct {
		Size     int64 `json:"Size"`
		RefCount int64 `json:"RefCount"`
	} `json:"UsageData"`
}

type IPAMConfig struct {
	Subnet  string `json:"Subnet,omitempty"`
	IPRange string `json:"IPRange,omitempty"`
	Gateway string `json:"Gateway,omitempty"`
}

type Network struct {
	Name       string            `json:"Name"`
	ID         string            `json:"Id"`
	Created    string            `json:"Created"`
	Scope      string            `json:"Scope"`
	Driver     string            `json:"Driver"`
	EnableIPv6 bool              `json:"EnableIPv6"`
	Internal   bool              `json:"Internal"`
	Attachable bool              `json:"Attachable"`
	Ingress    bool              `json:"Ingress"`
	Labels     map[string]string `json:"Labels"`
	Options    map[string]string `json:"Options"`
	IPAM       struct {
		Driver string       `json:"Driver"`
		Config []IPAMConfig `json:"Config"`
	} `json:"IPAM"`
	Containers map[string]struct {
		Name        string `json:"Name"`
		IPv4Address string `json:"IPv4Address"`
		IPv6Address string `json:"IPv6Address"`
		MacAddress  string `json:"MacAddress"`
	} `json:"Containers"`
}

type DiskUsage struct {
	LayersSize int64 `json:"LayersSize"`
	Images     []struct {
		ID         string `json:"Id"`
		Size       int64  `json:"Size"`
		SharedSize int64  `json:"SharedSize"`
		Containers int    `json:"Containers"`
	} `json:"Images"`
	Containers []struct {
		ID         string `json:"Id"`
		SizeRw     int64  `json:"SizeRw"`
		SizeRootFs int64  `json:"SizeRootFs"`
		State      string `json:"State"`
	} `json:"Containers"`
	Volumes    []Volume `json:"Volumes"`
	BuildCache []struct {
		Size   int64 `json:"Size"`
		InUse  bool  `json:"InUse"`
		Shared bool  `json:"Shared"`
	} `json:"BuildCache"`
}

// PruneReport is what a prune removed.
type PruneReport struct {
	ContainersDeleted []string `json:"ContainersDeleted"`
	VolumesDeleted    []string `json:"VolumesDeleted"`
	NetworksDeleted   []string `json:"NetworksDeleted"`
	ImagesDeleted     []struct {
		Untagged string `json:"Untagged"`
		Deleted  string `json:"Deleted"`
	} `json:"ImagesDeleted"`
	CachesDeleted  []string `json:"CachesDeleted"`
	SpaceReclaimed int64    `json:"SpaceReclaimed"`
}

// Calls.

func (c *Client) Info(ctx context.Context) (Info, error) {
	var v Info
	return v, c.Get(ctx, "/info", nil, &v)
}

func (c *Client) Version(ctx context.Context) (Version, error) {
	var v Version
	return v, c.Get(ctx, "/version", nil, &v)
}

func (c *Client) Containers(ctx context.Context) ([]ContainerSummary, error) {
	var v []ContainerSummary
	return v, c.Get(ctx, "/containers/json", url.Values{"all": {"1"}}, &v)
}

func (c *Client) Inspect(ctx context.Context, id string, size bool) (ContainerInspect, json.RawMessage, error) {
	var raw json.RawMessage
	q := url.Values{}
	if size {
		q.Set("size", "1")
	}
	if err := c.Get(ctx, "/containers/"+PathEscape(id)+"/json", q, &raw); err != nil {
		return ContainerInspect{}, nil, err
	}
	var v ContainerInspect
	err := json.Unmarshal(raw, &v)
	return v, raw, err
}

// Act runs start, stop, restart, pause, unpause or kill on a container.
// timeout (seconds, stop/restart) < 0 = the container's own; signal is for kill.
func (c *Client) Act(ctx context.Context, id, action string, timeout int, signal string) error {
	q := url.Values{}
	if timeout >= 0 && (action == "stop" || action == "restart") {
		q.Set("t", strconv.Itoa(timeout))
	}
	if signal != "" && action == "kill" {
		q.Set("signal", signal)
	}
	return c.Do(ctx, http.MethodPost, "/containers/"+PathEscape(id)+"/"+action, q, nil, nil)
}

func (c *Client) RemoveContainer(ctx context.Context, id string, force, volumes bool) error {
	q := url.Values{"force": {strconv.FormatBool(force)}, "v": {strconv.FormatBool(volumes)}}
	return c.Do(ctx, http.MethodDelete, "/containers/"+PathEscape(id), q, nil, nil)
}

func (c *Client) Rename(ctx context.Context, id, name string) error {
	return c.Do(ctx, http.MethodPost, "/containers/"+PathEscape(id)+"/rename", url.Values{"name": {name}}, nil, nil)
}

func (c *Client) Images(ctx context.Context) ([]ImageSummary, error) {
	var v []ImageSummary
	return v, c.Get(ctx, "/images/json", url.Values{"all": {"0"}}, &v)
}

func (c *Client) InspectImage(ctx context.Context, id string) (ImageInspect, error) {
	var v ImageInspect
	return v, c.Get(ctx, "/images/"+PathEscape(id)+"/json", nil, &v)
}

func (c *Client) ImageHistory(ctx context.Context, id string) ([]HistoryItem, error) {
	var v []HistoryItem
	return v, c.Get(ctx, "/images/"+PathEscape(id)+"/history", nil, &v)
}

// RemoveImage removes an image (or one of its tags, when ref is a tag).
func (c *Client) RemoveImage(ctx context.Context, ref string, force bool) error {
	q := url.Values{"force": {strconv.FormatBool(force)}}
	return c.Do(ctx, http.MethodDelete, "/images/"+PathEscape(ref), q, nil, nil)
}

func (c *Client) TagImage(ctx context.Context, id, repo, tag string) error {
	return c.Do(ctx, http.MethodPost, "/images/"+PathEscape(id)+"/tag", url.Values{"repo": {repo}, "tag": {tag}}, nil, nil)
}

func (c *Client) Volumes(ctx context.Context) ([]Volume, error) {
	var v struct {
		Volumes []Volume `json:"Volumes"`
	}
	return v.Volumes, c.Get(ctx, "/volumes", nil, &v)
}

type VolumeCreate struct {
	Name       string            `json:"Name,omitempty"`
	Driver     string            `json:"Driver,omitempty"`
	DriverOpts map[string]string `json:"DriverOpts,omitempty"`
	Labels     map[string]string `json:"Labels,omitempty"`
}

func (c *Client) CreateVolume(ctx context.Context, body VolumeCreate) (Volume, error) {
	var v Volume
	return v, c.Do(ctx, http.MethodPost, "/volumes/create", nil, body, &v)
}

func (c *Client) RemoveVolume(ctx context.Context, name string, force bool) error {
	return c.Do(ctx, http.MethodDelete, "/volumes/"+PathEscape(name), url.Values{"force": {strconv.FormatBool(force)}}, nil, nil)
}

func (c *Client) Networks(ctx context.Context) ([]Network, error) {
	var v []Network
	return v, c.Get(ctx, "/networks", nil, &v)
}

func (c *Client) InspectNetwork(ctx context.Context, id string) (Network, error) {
	var v Network
	return v, c.Get(ctx, "/networks/"+PathEscape(id), nil, &v)
}

type NetworkCreate struct {
	Name       string            `json:"Name"`
	Driver     string            `json:"Driver,omitempty"`
	Internal   bool              `json:"Internal,omitempty"`
	Attachable bool              `json:"Attachable,omitempty"`
	EnableIPv6 bool              `json:"EnableIPv6,omitempty"`
	Labels     map[string]string `json:"Labels,omitempty"`
	Options    map[string]string `json:"Options,omitempty"`
	IPAM       *struct {
		Driver string       `json:"Driver,omitempty"`
		Config []IPAMConfig `json:"Config,omitempty"`
	} `json:"IPAM,omitempty"`
}

func (c *Client) CreateNetwork(ctx context.Context, body NetworkCreate) (string, error) {
	var v struct {
		ID string `json:"Id"`
	}
	return v.ID, c.Do(ctx, http.MethodPost, "/networks/create", nil, body, &v)
}

func (c *Client) RemoveNetwork(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, "/networks/"+PathEscape(id), nil, nil, nil)
}

// Connect attaches a container to a network, with optional aliases and a
// fixed address.
func (c *Client) Connect(ctx context.Context, network, container string, aliases []string, ipv4 string) error {
	ep := map[string]any{}
	if len(aliases) > 0 {
		ep["Aliases"] = aliases
	}
	if ipv4 != "" {
		ep["IPAMConfig"] = map[string]string{"IPv4Address": ipv4}
	}
	body := map[string]any{"Container": container, "EndpointConfig": ep}
	return c.Do(ctx, http.MethodPost, "/networks/"+PathEscape(network)+"/connect", nil, body, nil)
}

func (c *Client) Disconnect(ctx context.Context, network, container string, force bool) error {
	body := map[string]any{"Container": container, "Force": force}
	return c.Do(ctx, http.MethodPost, "/networks/"+PathEscape(network)+"/disconnect", nil, body, nil)
}

func (c *Client) DiskUsage(ctx context.Context) (DiskUsage, error) {
	var v DiskUsage
	return v, c.Get(ctx, "/system/df", nil, &v)
}

// Prune removes unused things of one kind: "containers", "images",
// "volumes", "networks" or "build". filters is the engine's filter map.
func (c *Client) Prune(ctx context.Context, kind string, filters map[string][]string) (PruneReport, error) {
	q := url.Values{}
	if len(filters) > 0 {
		b, _ := json.Marshal(filters)
		q.Set("filters", string(b))
	}
	path := "/" + kind + "/prune"
	if kind == "build" {
		path = "/build/prune"
	}
	var v PruneReport
	return v, c.Do(ctx, http.MethodPost, path, q, nil, &v)
}
