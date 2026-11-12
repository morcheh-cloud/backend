package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/sse"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/docker"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/sshpool"
)

// ---- API shapes ----

type DockerEngine struct {
	State         string   `json:"state" enum:"ready,not-installed,stopped,no-access,error" doc:"Whether Morche can use the server's Docker engine"`
	Message       string   `json:"message,omitempty" doc:"Why it can't, in plain words"`
	Via           string   `json:"via,omitempty" enum:"socket,sudo,cli," doc:"How Morche reaches it: the socket through SSH, docker system dial-stdio through sudo, or as the login user"`
	AsRoot        bool     `json:"as_root" doc:"Changes count as root's in the command log"`
	Podman        bool     `json:"podman" doc:"The engine is Podman's Docker-compatible API"`
	Version       string   `json:"version,omitempty"`
	APIVersion    string   `json:"api_version,omitempty"`
	Name          string   `json:"name,omitempty" doc:"The engine's host name"`
	OS            string   `json:"os,omitempty"`
	OSType        string   `json:"os_type,omitempty"`
	Kernel        string   `json:"kernel,omitempty"`
	Arch          string   `json:"arch,omitempty"`
	CPUs          int      `json:"cpus"`
	Memory        int64    `json:"memory" doc:"Bytes"`
	Driver        string   `json:"driver,omitempty" doc:"Storage driver"`
	RootDir       string   `json:"root_dir,omitempty"`
	LoggingDriver string   `json:"logging_driver,omitempty"`
	CgroupVersion string   `json:"cgroup_version,omitempty"`
	Swarm         string   `json:"swarm,omitempty" doc:"Swarm state of this node: inactive, active…"`
	Containers    int      `json:"containers"`
	Running       int      `json:"running"`
	Paused        int      `json:"paused"`
	Stopped       int      `json:"stopped"`
	Images        int      `json:"images"`
	Warnings      []string `json:"warnings"`
}

type DockerPort struct {
	IP       string `json:"ip,omitempty" doc:"Host address it's published on; empty = not published"`
	Private  int    `json:"private" doc:"Port inside the container"`
	Public   int    `json:"public" doc:"Port on the host; 0 = not published"`
	Protocol string `json:"protocol" example:"tcp"`
}

type DockerMount struct {
	Type        string `json:"type" example:"volume"`
	Name        string `json:"name,omitempty" doc:"Volume name"`
	Source      string `json:"source,omitempty" doc:"Path on the host"`
	Destination string `json:"destination"`
	Mode        string `json:"mode,omitempty"`
	RW          bool   `json:"rw"`
}

type DockerContainer struct {
	ServerID    string        `json:"server_id" format:"uuid"`
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Image       string        `json:"image"`
	ImageID     string        `json:"image_id"`
	Created     time.Time     `json:"created"`
	State       string        `json:"state" doc:"created, running, paused, restarting, removing, exited or dead"`
	Status      string        `json:"status" doc:"The engine's own words" example:"Up 3 hours"`
	Health      string        `json:"health,omitempty" enum:"healthy,unhealthy,starting," doc:"Only for containers with a health check"`
	Ports       []DockerPort  `json:"ports"`
	Networks    []string      `json:"networks"`
	Mounts      []DockerMount `json:"mounts"`
	NetworkMode string        `json:"network_mode,omitempty"`
	Project     string        `json:"project,omitempty" doc:"Compose project"`
	Service     string        `json:"service,omitempty" doc:"Compose service"`
	ComposeDir  string        `json:"compose_dir,omitempty" doc:"Folder the compose project was started from"`
}

type DockerEnv struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type DockerEndpoint struct {
	Network   string   `json:"network"`
	NetworkID string   `json:"network_id"`
	IP        string   `json:"ip,omitempty"`
	PrefixLen int      `json:"prefix_len,omitempty"`
	Gateway   string   `json:"gateway,omitempty"`
	IPv6      string   `json:"ipv6,omitempty"`
	MAC       string   `json:"mac,omitempty"`
	Aliases   []string `json:"aliases"`
}

type DockerHealthCheck struct {
	Start    string `json:"start"`
	End      string `json:"end"`
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output"`
}

type DockerDevice struct {
	Host      string `json:"host"`
	Container string `json:"container"`
}

type DockerContainerDetails struct {
	DockerContainer
	Command           []string            `json:"command" doc:"Entrypoint and arguments; empty below Operator"`
	Entrypoint        []string            `json:"entrypoint"`
	Args              []string            `json:"args"`
	Env               []DockerEnv         `json:"env" doc:"Only for Engineer and up"`
	EnvHidden         bool                `json:"env_hidden" doc:"Env was left out for this person's level"`
	Labels            map[string]string   `json:"labels"`
	User              string              `json:"user,omitempty"`
	WorkingDir        string              `json:"working_dir,omitempty"`
	Hostname          string              `json:"hostname,omitempty"`
	TTY               bool                `json:"tty"`
	Platform          string              `json:"platform,omitempty"`
	StartedAt         *time.Time          `json:"started_at,omitempty"`
	FinishedAt        *time.Time          `json:"finished_at,omitempty"`
	ExitCode          int                 `json:"exit_code"`
	Error             string              `json:"error,omitempty"`
	OOMKilled         bool                `json:"oom_killed"`
	PID               int                 `json:"pid"`
	RestartCount      int                 `json:"restart_count"`
	RestartPolicy     string              `json:"restart_policy" example:"unless-stopped"`
	RestartMax        int                 `json:"restart_max"`
	HealthTest        []string            `json:"health_test"`
	HealthFailing     int                 `json:"health_failing" doc:"Failed checks in a row"`
	HealthLog         []DockerHealthCheck `json:"health_log"`
	Privileged        bool                `json:"privileged"`
	ReadOnly          bool                `json:"read_only"`
	AutoRemove        bool                `json:"auto_remove"`
	MemoryLimit       int64               `json:"memory_limit" doc:"Bytes; 0 = none"`
	MemoryReservation int64               `json:"memory_reservation"`
	CPUs              float64             `json:"cpus" doc:"CPU limit; 0 = none"`
	CPUShares         int64               `json:"cpu_shares"`
	CPUSet            string              `json:"cpuset,omitempty"`
	PidsLimit         int64               `json:"pids_limit"`
	CapAdd            []string            `json:"cap_add"`
	CapDrop           []string            `json:"cap_drop"`
	DNS               []string            `json:"dns"`
	ExtraHosts        []string            `json:"extra_hosts"`
	Devices           []DockerDevice      `json:"devices"`
	LogDriver         string              `json:"log_driver,omitempty"`
	LogOptions        map[string]string   `json:"log_options"`
	Endpoints         []DockerEndpoint    `json:"endpoints"`
	SizeRW            int64               `json:"size_rw" doc:"Bytes the container wrote; -1 = not measured"`
	SizeRootFS        int64               `json:"size_root_fs" doc:"-1 = not measured"`
	StopSignal        string              `json:"stop_signal,omitempty"`
	StopTimeout       int                 `json:"stop_timeout" doc:"Seconds; 0 = the engine's default"`
	ExposedPorts      []string            `json:"exposed_ports"`
	PortBindings      map[string][]string `json:"port_bindings" doc:"As configured, also while stopped"`
}

type DockerLogLine struct {
	Time   *time.Time `json:"time,omitempty"`
	Stream string     `json:"stream" enum:"stdout,stderr"`
	Text   string     `json:"text"`
}

type DockerLogs struct {
	Lines     []DockerLogLine `json:"lines"`
	Truncated bool            `json:"truncated" doc:"There are older lines than these"`
}

type DockerLogBatch struct {
	Lines []DockerLogLine `json:"lines"`
}

type DockerStreamEnd struct {
	Reason string `json:"reason" doc:"Why it ended: stopped (the container), error, gone"`
	Detail string `json:"detail,omitempty"`
}

type DockerStats struct {
	Time        time.Time `json:"time"`
	CPU         float64   `json:"cpu" doc:"Percent of one CPU: 250 = two and a half busy"`
	CPUs        int       `json:"cpus"`
	MemoryUsed  int64     `json:"memory_used"`
	MemoryLimit int64     `json:"memory_limit"`
	NetRx       int64     `json:"net_rx"`
	NetTx       int64     `json:"net_tx"`
	NetRxRate   float64   `json:"net_rx_rate"`
	NetTxRate   float64   `json:"net_tx_rate"`
	BlockRead   int64     `json:"block_read"`
	BlockWrite  int64     `json:"block_write"`
	ReadRate    float64   `json:"read_rate"`
	WriteRate   float64   `json:"write_rate"`
	Pids        int64     `json:"pids"`
}

type DockerRef struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
}

type DockerImage struct {
	ID         string    `json:"id"`
	Tags       []string  `json:"tags"`
	Digests    []string  `json:"digests"`
	Created    time.Time `json:"created"`
	Size       int64     `json:"size"`
	Containers int       `json:"containers" doc:"Containers made from it, running or not"`
	Dangling   bool      `json:"dangling" doc:"No tag left"`
}

type DockerImageLayer struct {
	ID        string    `json:"id"`
	Created   time.Time `json:"created"`
	CreatedBy string    `json:"created_by"`
	Size      int64     `json:"size"`
	Comment   string    `json:"comment,omitempty"`
	Tags      []string  `json:"tags"`
}

type DockerImageDetails struct {
	DockerImage
	Architecture  string             `json:"architecture,omitempty"`
	Variant       string             `json:"variant,omitempty"`
	OS            string             `json:"os,omitempty"`
	Author        string             `json:"author,omitempty"`
	DockerVersion string             `json:"docker_version,omitempty"`
	User          string             `json:"user,omitempty"`
	Env           []DockerEnv        `json:"env"`
	EnvHidden     bool               `json:"env_hidden"`
	Command       []string           `json:"command"`
	Entrypoint    []string           `json:"entrypoint"`
	WorkingDir    string             `json:"working_dir,omitempty"`
	Labels        map[string]string  `json:"labels"`
	ExposedPorts  []string           `json:"exposed_ports"`
	Volumes       []string           `json:"volumes"`
	Layers        int                `json:"layers"`
	History       []DockerImageLayer `json:"history"`
	UsedBy        []DockerRef        `json:"used_by"`
}

type DockerVolume struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Mountpoint string            `json:"mountpoint"`
	Created    *time.Time        `json:"created,omitempty"`
	Scope      string            `json:"scope"`
	Labels     map[string]string `json:"labels"`
	Options    map[string]string `json:"options"`
	Size       int64             `json:"size" doc:"Bytes; -1 = not measured (ask with sizes=true)"`
	Project    string            `json:"project,omitempty"`
	Anonymous  bool              `json:"anonymous"`
	UsedBy     []DockerRef       `json:"used_by"`
}

type DockerSubnet struct {
	Subnet  string `json:"subnet"`
	Gateway string `json:"gateway,omitempty"`
	IPRange string `json:"ip_range,omitempty"`
}

type DockerNetworkMember struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
	IPv4  string `json:"ipv4,omitempty"`
	IPv6  string `json:"ipv6,omitempty"`
	MAC   string `json:"mac,omitempty"`
}

type DockerNetwork struct {
	ID         string                `json:"id"`
	Name       string                `json:"name"`
	Driver     string                `json:"driver"`
	Scope      string                `json:"scope"`
	Internal   bool                  `json:"internal"`
	Attachable bool                  `json:"attachable"`
	IPv6       bool                  `json:"ipv6"`
	Created    *time.Time            `json:"created,omitempty"`
	Subnets    []DockerSubnet        `json:"subnets"`
	Labels     map[string]string     `json:"labels"`
	Options    map[string]string     `json:"options"`
	Project    string                `json:"project,omitempty"`
	Builtin    bool                  `json:"builtin" doc:"bridge, host or none: can't be removed"`
	Containers []DockerNetworkMember `json:"containers"`
}

type DockerUsage struct {
	Count       int   `json:"count"`
	Active      int   `json:"active" doc:"In use"`
	Size        int64 `json:"size"`
	Reclaimable int64 `json:"reclaimable" doc:"What a prune could free"`
}

type DockerDiskUsage struct {
	Images      DockerUsage `json:"images"`
	Containers  DockerUsage `json:"containers"`
	Volumes     DockerUsage `json:"volumes"`
	BuildCache  DockerUsage `json:"build_cache"`
	Total       int64       `json:"total"`
	Reclaimable int64       `json:"reclaimable"`
}

type DockerFleetServer struct {
	ServerID    string `json:"server_id" format:"uuid"`
	WorkspaceID string `json:"workspace_id" format:"uuid"`
	Name        string `json:"name"`
	Address     string `json:"address" doc:"The server's host"`
	OSID        string `json:"os_id,omitempty" doc:"os-release ID, for its logo"`
	Status      string `json:"status" doc:"The server's own status"`
	State       string `json:"state" enum:"ready,not-installed,stopped,no-access,error,offline" doc:"The engine's; offline = the server isn't reachable"`
	Message     string `json:"message,omitempty"`
	Running     int    `json:"running"`
	Total       int    `json:"total"`
	Paused      int    `json:"paused"`
	Restarting  int    `json:"restarting"`
	Stopped     int    `json:"stopped" doc:"Exited, created or dead"`
	Failed      int    `json:"failed" doc:"Stopped with a non-zero exit code, or dead"`
	Healthy     int    `json:"healthy"`
	Unhealthy   int    `json:"unhealthy"`
	Starting    int    `json:"starting" doc:"Health check still starting"`
	Projects    int    `json:"projects" doc:"Compose projects"`
	// Engine facts, when it's ready.
	Version string `json:"version,omitempty"`
	Via     string `json:"via,omitempty" enum:"socket,sudo,cli,"`
	Podman  bool   `json:"podman"`
	Images  int    `json:"images"`
	CPUs    int    `json:"cpus"`
	Memory  int64  `json:"memory" doc:"Bytes the engine sees"`
	// The host's last resource sample (Morche samples online servers every
	// minute); absent until there is one.
	Host *DockerFleetHost `json:"host,omitempty"`
}

type DockerFleetHost struct {
	At         time.Time `json:"at"`
	CPUPercent float64   `json:"cpu_percent"`
	Cores      int       `json:"cores"`
	Load1      float64   `json:"load1"`
	MemUsed    int64     `json:"mem_used"`
	MemTotal   int64     `json:"mem_total"`
	DiskUsed   int64     `json:"disk_used" doc:"Root (or largest) filesystem"`
	DiskTotal  int64     `json:"disk_total"`
	DiskMount  string    `json:"disk_max_mount" doc:"Fullest filesystem"`
	DiskMax    float64   `json:"disk_max_percent"`
}

type DockerFleet struct {
	Servers    []DockerFleetServer `json:"servers"`
	Containers []DockerContainer   `json:"containers"`
}

// ---- Inputs ----

type DockerContainerPath struct {
	ServerIDPath
	Container string `path:"container" doc:"Container id or name"`
}

type DockerImagePath struct {
	ServerIDPath
	Image string `path:"image" doc:"Image id or reference"`
}

type DockerVolumePath struct {
	ServerIDPath
	Volume string `path:"volume"`
}

type DockerNetworkPath struct {
	ServerIDPath
	Network string `path:"network" doc:"Network id or name"`
}

type DockerActionBody struct {
	Timeout int `json:"timeout,omitempty" minimum:"0" maximum:"3600" doc:"Seconds to wait before killing it (stop, restart); 0 = the container's own"`
}

type DockerKillBody struct {
	Signal string `json:"signal,omitempty" pattern:"^[A-Z0-9+]{0,16}$" doc:"Empty = SIGKILL" example:"SIGTERM"`
}

type DockerRenameBody struct {
	Name string `json:"name" minLength:"1" maxLength:"128" pattern:"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$"`
}

type DockerPullBody struct {
	Image    string `json:"image" minLength:"1" maxLength:"512" example:"nginx:alpine"`
	Platform string `json:"platform,omitempty" maxLength:"64" example:"linux/amd64"`
}

type DockerTagBody struct {
	Repo string `json:"repo" minLength:"1" maxLength:"256" example:"registry.example.com/web"`
	Tag  string `json:"tag,omitempty" maxLength:"128" example:"v2"`
}

type DockerVolumeBody struct {
	Name    string            `json:"name,omitempty" maxLength:"128" pattern:"^([a-zA-Z0-9][a-zA-Z0-9_.-]*)?$" doc:"Empty = a generated name"`
	Driver  string            `json:"driver,omitempty" maxLength:"64" doc:"Empty = local"`
	Options map[string]string `json:"options,omitempty" doc:"Driver options (local: type, device, o)"`
	Labels  map[string]string `json:"labels,omitempty"`
}

type DockerNetworkBody struct {
	Name       string            `json:"name" minLength:"1" maxLength:"128" pattern:"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$"`
	Driver     string            `json:"driver,omitempty" maxLength:"64" doc:"Empty = bridge"`
	Subnet     string            `json:"subnet,omitempty" maxLength:"64" example:"172.30.0.0/24"`
	Gateway    string            `json:"gateway,omitempty" maxLength:"64"`
	IPRange    string            `json:"ip_range,omitempty" maxLength:"64"`
	Internal   bool              `json:"internal,omitempty" doc:"No way out to other networks"`
	Attachable bool              `json:"attachable,omitempty"`
	IPv6       bool              `json:"ipv6,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
}

type DockerConnectBody struct {
	Container string   `json:"container" minLength:"1"`
	Aliases   []string `json:"aliases,omitempty"`
	IPv4      string   `json:"ipv4,omitempty" maxLength:"64"`
}

type DockerDisconnectBody struct {
	Container string `json:"container" minLength:"1"`
	Force     bool   `json:"force,omitempty"`
}

type DockerPruneBody struct {
	Containers bool   `json:"containers,omitempty" doc:"Stopped containers"`
	Images     string `json:"images,omitempty" enum:"none,dangling,all," doc:"dangling = untagged ones; all = every image no container uses"`
	Volumes    string `json:"volumes,omitempty" enum:"none,anonymous,all," doc:"Volumes no container uses; anonymous = only unnamed ones"`
	Networks   bool   `json:"networks,omitempty" doc:"Networks no container uses"`
	BuildCache bool   `json:"build_cache,omitempty"`
}

type dockerPullParams struct {
	ServerID string `json:"server_id"`
	Image    string `json:"image"`
	Platform string `json:"platform,omitempty"`
}

type dockerPruneParams struct {
	ServerID string `json:"server_id"`
	DockerPruneBody
}

type DockerPruneResult struct {
	Containers int   `json:"containers"`
	Images     int   `json:"images"`
	Volumes    int   `json:"volumes"`
	Networks   int   `json:"networks"`
	Caches     int   `json:"caches"`
	Space      int64 `json:"space" doc:"Bytes freed"`
}

const (
	dockerPullKind  = "docker-pull"
	dockerPruneKind = "docker-prune"
)

// ---- Conversions ----

var hexID = regexp.MustCompile(`^[0-9a-f]{64}$`)

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func containerName(names []string) string {
	for _, n := range names {
		n = strings.TrimPrefix(n, "/")
		if !strings.Contains(n, "/") { // links show as other/name
			return n
		}
	}
	if len(names) > 0 {
		return strings.TrimPrefix(names[0], "/")
	}
	return ""
}

// healthOf reads the health from the summary, or from its status words.
func healthOf(c docker.ContainerSummary) string {
	if c.Health != nil && c.Health.Status != "" && c.Health.Status != "none" {
		return c.Health.Status
	}
	switch {
	case strings.Contains(c.Status, "(healthy)"):
		return "healthy"
	case strings.Contains(c.Status, "(unhealthy)"):
		return "unhealthy"
	case strings.Contains(c.Status, "(health: starting)"):
		return "starting"
	}
	return ""
}

func toDockerMounts(ms []docker.Mount) []DockerMount {
	out := make([]DockerMount, 0, len(ms))
	for _, m := range ms {
		out = append(out, DockerMount{Type: m.Type, Name: m.Name, Source: m.Source, Destination: m.Destination, Mode: m.Mode, RW: m.RW})
	}
	return out
}

func toDockerContainer(serverID string, c docker.ContainerSummary) DockerContainer {
	out := DockerContainer{
		ServerID: serverID, ID: c.ID, Name: containerName(c.Names), Image: c.Image, ImageID: c.ImageID,
		Created: time.Unix(c.Created, 0).UTC(), State: c.State, Status: c.Status, Health: healthOf(c),
		Ports: []DockerPort{}, Networks: []string{}, Mounts: toDockerMounts(c.Mounts),
		NetworkMode: c.HostConfig.NetworkMode,
		Project:     c.Labels["com.docker.compose.project"],
		Service:     c.Labels["com.docker.compose.service"],
		ComposeDir:  c.Labels["com.docker.compose.project.working_dir"],
	}
	seen := map[string]bool{}
	for _, p := range c.Ports {
		k := fmt.Sprint(p.PrivatePort, p.PublicPort, p.Type)
		if p.PublicPort != 0 && seen[k] { // the same binding on 0.0.0.0 and ::
			continue
		}
		seen[k] = true
		out.Ports = append(out.Ports, DockerPort{IP: p.IP, Private: p.PrivatePort, Public: p.PublicPort, Protocol: p.Type})
	}
	sort.Slice(out.Ports, func(i, j int) bool {
		a, b := out.Ports[i], out.Ports[j]
		if a.Private != b.Private {
			return a.Private < b.Private
		}
		return a.Public < b.Public
	})
	for n := range c.NetworkSettings.Networks {
		out.Networks = append(out.Networks, n)
	}
	sort.Strings(out.Networks)
	return out
}

func parseDockerTime(s string) *time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Year() < 1971 {
		return nil
	}
	t = t.UTC()
	return &t
}

func splitEnv(env []string) []DockerEnv {
	out := make([]DockerEnv, 0, len(env))
	for _, e := range env {
		k, v, _ := strings.Cut(e, "=")
		out = append(out, DockerEnv{Name: k, Value: v})
	}
	return out
}

func dockerList[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func orEmptyMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func dockerKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func toDockerDetails(serverID string, in docker.ContainerInspect, level auth.Level) DockerContainerDetails {
	sum := docker.ContainerSummary{
		ID: in.ID, Names: []string{in.Name}, Image: in.Config.Image, ImageID: in.Image,
		State: in.State.Status, Labels: in.Config.Labels, Mounts: in.Mounts,
	}
	if t := parseDockerTime(in.Created); t != nil {
		sum.Created = t.Unix()
	}
	sum.HostConfig.NetworkMode = in.HostConfig.NetworkMode
	sum.NetworkSettings.Networks = in.NetworkSettings.Networks
	for port, bs := range in.NetworkSettings.Ports {
		num, proto, _ := strings.Cut(port, "/")
		priv, _ := strconv.Atoi(num)
		if len(bs) == 0 {
			sum.Ports = append(sum.Ports, docker.Port{PrivatePort: priv, Type: proto})
		}
		for _, b := range bs {
			pub, _ := strconv.Atoi(b.HostPort)
			sum.Ports = append(sum.Ports, docker.Port{IP: b.HostIP, PrivatePort: priv, PublicPort: pub, Type: proto})
		}
	}
	d := DockerContainerDetails{DockerContainer: toDockerContainer(serverID, sum)}
	d.Status = statusWords(in)
	if h := in.State.Health; h != nil {
		d.Health = h.Status
		d.HealthFailing = h.FailingStreak
		for _, l := range h.Log {
			d.HealthLog = append(d.HealthLog, DockerHealthCheck{Start: l.Start, End: l.End, ExitCode: l.ExitCode, Output: strings.TrimSpace(l.Output)})
		}
	}
	if d.Health == "none" {
		d.Health = ""
	}
	if level >= auth.Operator {
		d.Entrypoint, d.Args = in.Config.Entrypoint, in.Args
		d.Command = append([]string{in.Path}, in.Args...)
		if hc := in.Config.Healthcheck; hc != nil {
			d.HealthTest = hc.Test
		}
	}
	if level >= auth.Engineer {
		d.Env = splitEnv(in.Config.Env)
	} else {
		d.EnvHidden = len(in.Config.Env) > 0
	}
	d.Labels = orEmptyMap(in.Config.Labels)
	d.User, d.WorkingDir, d.Hostname, d.TTY = in.Config.User, in.Config.WorkingDir, in.Config.Hostname, in.Config.Tty
	d.Platform = in.Platform
	if in.State.Running || in.State.Paused || in.State.Restarting {
		d.StartedAt = parseDockerTime(in.State.StartedAt)
	} else {
		d.StartedAt = parseDockerTime(in.State.StartedAt)
		d.FinishedAt = parseDockerTime(in.State.FinishedAt)
	}
	d.ExitCode, d.Error, d.OOMKilled, d.PID = in.State.ExitCode, in.State.Error, in.State.OOMKilled, in.State.Pid
	d.RestartCount = in.RestartCount
	hc := in.HostConfig
	d.RestartPolicy, d.RestartMax = hc.RestartPolicy.Name, hc.RestartPolicy.MaximumRetryCount
	if d.RestartPolicy == "" {
		d.RestartPolicy = "no"
	}
	d.Privileged, d.ReadOnly, d.AutoRemove = hc.Privileged, hc.ReadonlyRootfs, hc.AutoRemove
	d.MemoryLimit, d.MemoryReservation = hc.Memory, hc.MemoryReserve
	d.CPUs = float64(hc.NanoCPUs) / 1e9
	d.CPUShares, d.CPUSet = hc.CPUShares, hc.CPUSetCPUs
	if hc.PidsLimit != nil {
		d.PidsLimit = *hc.PidsLimit
	}
	d.CapAdd, d.CapDrop = dockerList(hc.CapAdd), dockerList(hc.CapDrop)
	d.DNS, d.ExtraHosts = dockerList(hc.DNS), dockerList(hc.ExtraHosts)
	d.Devices = []DockerDevice{}
	for _, dev := range hc.Devices {
		d.Devices = append(d.Devices, DockerDevice{Host: dev.PathOnHost, Container: dev.PathInContainer})
	}
	d.LogDriver, d.LogOptions = hc.LogConfig.Type, orEmptyMap(hc.LogConfig.Config)
	d.Endpoints = []DockerEndpoint{}
	for _, name := range dockerKeys(in.NetworkSettings.Networks) {
		ep := in.NetworkSettings.Networks[name]
		d.Endpoints = append(d.Endpoints, DockerEndpoint{
			Network: name, NetworkID: ep.NetworkID, IP: ep.IPAddress, PrefixLen: ep.IPPrefixLen,
			Gateway: ep.Gateway, IPv6: ep.GlobalIPv6, MAC: ep.MacAddress, Aliases: dockerList(ep.DNSNames),
		})
		if len(ep.DNSNames) == 0 {
			d.Endpoints[len(d.Endpoints)-1].Aliases = dockerList(ep.Aliases)
		}
	}
	d.SizeRW, d.SizeRootFS = -1, -1
	if in.SizeRw != nil {
		d.SizeRW = *in.SizeRw
	}
	if in.SizeRootFs != nil {
		d.SizeRootFS = *in.SizeRootFs
	}
	d.StopSignal = in.Config.StopSignal
	if in.Config.StopTimeout != nil {
		d.StopTimeout = *in.Config.StopTimeout
	}
	d.ExposedPorts = dockerKeys(in.Config.ExposedPorts)
	d.PortBindings = map[string][]string{}
	for port, bs := range hc.PortBindings {
		for _, b := range bs {
			host := b.HostPort
			if b.HostIP != "" {
				host = b.HostIP + ":" + host
			}
			d.PortBindings[port] = append(d.PortBindings[port], host)
		}
	}
	d.Command, d.Entrypoint, d.Args = dockerList(d.Command), dockerList(d.Entrypoint), dockerList(d.Args)
	d.Env, d.HealthTest, d.HealthLog = dockerList(d.Env), dockerList(d.HealthTest), dockerList(d.HealthLog)
	return d
}

// statusWords says what the list's Status would, from an inspect.
func statusWords(in docker.ContainerInspect) string {
	s := in.State
	switch {
	case s.Paused:
		return "Paused"
	case s.Restarting:
		return "Restarting"
	case s.Running:
		if t := parseDockerTime(s.StartedAt); t != nil {
			return "Up " + roughDuration(time.Since(*t))
		}
		return "Up"
	case s.Status == "created":
		return "Created"
	}
	if t := parseDockerTime(s.FinishedAt); t != nil {
		return fmt.Sprintf("Exited (%d) %s ago", s.ExitCode, roughDuration(time.Since(*t)))
	}
	return fmt.Sprintf("Exited (%d)", s.ExitCode)
}

func roughDuration(d time.Duration) string {
	plural := func(n int, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return fmt.Sprintf("%d %ss", n, unit)
	}
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return plural(int(d.Minutes()), "minute")
	case d < 48*time.Hour:
		return plural(int(d.Hours()), "hour")
	case d < 14*24*time.Hour:
		return plural(int(d.Hours()/24), "day")
	case d < 60*24*time.Hour:
		return plural(int(d.Hours()/24/7), "week")
	}
	return plural(int(d.Hours()/24/30), "month")
}

func toDockerStats(s docker.Sample) DockerStats {
	return DockerStats{
		Time: s.Time, CPU: s.CPUPercent, CPUs: s.CPUs, MemoryUsed: s.MemoryUsed, MemoryLimit: s.MemoryLimit,
		NetRx: s.NetRx, NetTx: s.NetTx, NetRxRate: s.NetRxRate, NetTxRate: s.NetTxRate,
		BlockRead: s.BlockRead, BlockWrite: s.BlockWrite, ReadRate: s.ReadRate, WriteRate: s.WriteRate, Pids: s.Pids,
	}
}

func toDockerLogLine(l docker.LogLine) DockerLogLine {
	out := DockerLogLine{Stream: l.Stream, Text: l.Text}
	if !l.Time.IsZero() {
		t := l.Time.UTC()
		out.Time = &t
	}
	return out
}

func refsOf(cs []docker.ContainerSummary, keep func(docker.ContainerSummary) bool) []DockerRef {
	out := []DockerRef{}
	for _, c := range cs {
		if keep(c) {
			out = append(out, DockerRef{ID: c.ID, Name: containerName(c.Names), State: c.State})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func toDockerImage(im docker.ImageSummary, cs []docker.ContainerSummary) DockerImage {
	out := DockerImage{
		ID: im.ID, Tags: []string{}, Digests: dockerList(im.RepoDigests), Created: time.Unix(im.Created, 0).UTC(), Size: im.Size,
	}
	for _, t := range im.RepoTags {
		if t != "<none>:<none>" {
			out.Tags = append(out.Tags, t)
		}
	}
	out.Dangling = len(out.Tags) == 0
	for _, c := range cs {
		if c.ImageID == im.ID {
			out.Containers++
		}
	}
	return out
}

func anonymousVolume(v docker.Volume) bool {
	if _, ok := v.Labels["com.docker.volume.anonymous"]; ok {
		return true
	}
	return hexID.MatchString(v.Name) && v.Labels["com.docker.compose.project"] == ""
}

func toDockerVolume(v docker.Volume, cs []docker.ContainerSummary) DockerVolume {
	out := DockerVolume{
		Name: v.Name, Driver: v.Driver, Mountpoint: v.Mountpoint, Created: parseDockerTime(v.CreatedAt), Scope: v.Scope,
		Labels: orEmptyMap(v.Labels), Options: orEmptyMap(v.Options), Size: -1,
		Project: v.Labels["com.docker.compose.project"], Anonymous: anonymousVolume(v),
	}
	if v.UsageData != nil && v.UsageData.Size >= 0 {
		out.Size = v.UsageData.Size
	}
	out.UsedBy = refsOf(cs, func(c docker.ContainerSummary) bool {
		return slices.ContainsFunc(c.Mounts, func(m docker.Mount) bool { return m.Type == "volume" && m.Name == v.Name })
	})
	return out
}

var builtinNetworks = map[string]bool{"bridge": true, "host": true, "none": true}

func toDockerNetwork(n docker.Network, cs []docker.ContainerSummary) DockerNetwork {
	out := DockerNetwork{
		ID: n.ID, Name: n.Name, Driver: n.Driver, Scope: n.Scope, Internal: n.Internal, Attachable: n.Attachable,
		IPv6: n.EnableIPv6, Created: parseDockerTime(n.Created), Subnets: []DockerSubnet{},
		Labels: orEmptyMap(n.Labels), Options: orEmptyMap(n.Options), Project: n.Labels["com.docker.compose.project"],
		Builtin: builtinNetworks[n.Name], Containers: []DockerNetworkMember{},
	}
	for _, c := range n.IPAM.Config {
		if c.Subnet != "" {
			out.Subnets = append(out.Subnets, DockerSubnet{Subnet: c.Subnet, Gateway: c.Gateway, IPRange: c.IPRange})
		}
	}
	for _, c := range cs {
		for _, ep := range c.NetworkSettings.Networks {
			if ep.NetworkID == n.ID {
				out.Containers = append(out.Containers, DockerNetworkMember{
					ID: c.ID, Name: containerName(c.Names), State: c.State, IPv4: ep.IPAddress, IPv6: ep.GlobalIPv6, MAC: ep.MacAddress,
				})
			}
		}
	}
	sort.Slice(out.Containers, func(i, j int) bool { return out.Containers[i].Name < out.Containers[j].Name })
	return out
}

// ---- Handlers ----

func registerDocker(api huma.API, h *serverHandler) {
	tags := []string{"Containers"}
	base := "/servers/{id}/docker"

	huma.Register(api, huma.Operation{
		OperationID: "get-docker-engine",
		Method:      http.MethodGet,
		Path:        base,
		Summary:     "Docker engine on a server",
		Description: "Whether Morche can use the server's Docker (or Podman) engine, and what it is. Never fails because the engine can't be reached: `state` says why.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body DockerEngine }, error) {
		out := &struct{ Body DockerEngine }{DockerEngine{Warnings: []string{}}}
		b := &out.Body
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			e, err := h.engine(ctx, in.ID, c)
			if err != nil {
				return err
			}
			info, err := e.client.Info(ctx)
			if err != nil {
				return err
			}
			v, err := e.client.Version(ctx)
			if err != nil {
				return err
			}
			b.State, b.Via, b.AsRoot = dockerReady, e.via, e.asRoot
			b.Version, b.APIVersion = v.Version, v.APIVersion
			for _, comp := range v.Components {
				if strings.Contains(strings.ToLower(comp.Name), "podman") {
					b.Podman = true
				}
			}
			b.Name, b.OS, b.OSType, b.Kernel, b.Arch = info.Name, info.OperatingSystem, info.OSType, info.KernelVersion, info.Architecture
			b.CPUs, b.Memory, b.Driver, b.RootDir = info.NCPU, info.MemTotal, info.Driver, info.DockerRootDir
			b.LoggingDriver, b.CgroupVersion, b.Swarm = info.LoggingDriver, info.CgroupVersion, info.Swarm.LocalNodeState
			b.Containers, b.Running, b.Paused, b.Stopped, b.Images = info.Containers, info.ContainersRunning, info.ContainersPaused, info.ContainersStopped, info.Images
			b.Warnings = dockerList(info.Warnings)
			return nil
		})
		var un *dockerUnavailable
		if errors.As(err, &un) {
			b.State, b.Message = un.state, un.message
			return out, nil
		}
		if err != nil {
			return nil, dockerProblem(err)
		}
		return out, nil
	})

	// -- Containers --

	huma.Register(api, huma.Operation{
		OperationID: "list-docker-containers",
		Method:      http.MethodGet,
		Path:        base + "/containers",
		Summary:     "List a server's containers",
		Description: "Every container, running or not. 422 when the engine can't be used (see get-docker-engine).",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body []DockerContainer }, error) {
		out := &struct{ Body []DockerContainer }{[]DockerContainer{}}
		err := h.withDocker(ctx, in.ID, func(e *dockerEngine) error {
			cs, err := e.client.Containers(ctx)
			for _, c := range cs {
				out.Body = append(out.Body, toDockerContainer(in.ID, c))
			}
			return err
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-docker-container",
		Method:      http.MethodGet,
		Path:        base + "/containers/{container}",
		Summary:     "A container's details",
		Description: "Config, state, health, resources, networks. The command needs Operator, the environment Engineer.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerContainerPath
		Size bool `query:"size" doc:"Also measure what it wrote to its file system (slow on big containers)"`
	}) (*struct{ Body DockerContainerDetails }, error) {
		out := &struct{ Body DockerContainerDetails }{}
		err := h.withDocker(ctx, in.ID, func(e *dockerEngine) error {
			v, _, err := e.client.Inspect(ctx, in.Container, in.Size)
			if err != nil {
				return err
			}
			out.Body = toDockerDetails(in.ID, v, principalOf(ctx).Level)
			return nil
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "inspect-docker-container",
		Method:      http.MethodGet,
		Path:        base + "/containers/{container}/inspect",
		Summary:     "A container's raw inspect",
		Description: "What `docker inspect` prints, environment included (Engineer).",
		Tags:        tags,
	}, func(ctx context.Context, in *DockerContainerPath) (*struct{ Body map[string]any }, error) {
		out := &struct{ Body map[string]any }{}
		err := h.withDocker(ctx, in.ID, func(e *dockerEngine) error {
			_, raw, err := e.client.Inspect(ctx, in.Container, false)
			if err != nil {
				return err
			}
			return json.Unmarshal(raw, &out.Body)
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "docker-container-logs",
		Method:      http.MethodGet,
		Path:        base + "/containers/{container}/logs",
		Summary:     "A container's log",
		Description: "The last `tail` lines (up to 5000), optionally between `since` and `until`.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerContainerPath
		Tail  int       `query:"tail" minimum:"1" maximum:"5000" default:"500"`
		Since time.Time `query:"since" required:"false"`
		Until time.Time `query:"until" required:"false"`
	}) (*struct{ Body DockerLogs }, error) {
		out := &struct{ Body DockerLogs }{DockerLogs{Lines: []DockerLogLine{}}}
		err := h.withDocker(ctx, in.ID, func(e *dockerEngine) error {
			v, _, err := e.client.Inspect(ctx, in.Container, false)
			if err != nil {
				return err
			}
			out.Body.Lines = out.Body.Lines[:0]
			return e.client.Logs(ctx, v.ID, v.Config.Tty, docker.LogQuery{Tail: in.Tail, Since: in.Since, Until: in.Until}, func(l docker.LogLine) bool {
				out.Body.Lines = append(out.Body.Lines, toDockerLogLine(l))
				return true
			})
		})
		out.Body.Truncated = len(out.Body.Lines) >= in.Tail
		return out, err
	})

	sse.Register(api, huma.Operation{
		OperationID: "stream-docker-container-logs",
		Method:      http.MethodGet,
		Path:        base + "/containers/{container}/logs/stream",
		Summary:     "Follow a container's log",
		Description: "Server-sent events: `lines` (batched, about four a second) as the container prints them, from `since` (default: now) on; `end` when the container stops or the stream fails.",
		Tags:        tags,
	}, map[string]any{"lines": DockerLogBatch{}, "end": DockerStreamEnd{}},
		func(ctx context.Context, in *struct {
			DockerContainerPath
			Since time.Time `query:"since" required:"false"`
		}, send sse.Sender) {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			var mu sync.Mutex
			batch := []DockerLogLine{}
			var sendErr error
			flush := func() {
				mu.Lock()
				defer mu.Unlock()
				if len(batch) == 0 || sendErr != nil {
					return
				}
				if sendErr = send.Data(DockerLogBatch{Lines: batch}); sendErr != nil {
					cancel()
				}
				batch = []DockerLogLine{}
			}
			go func() {
				tick := time.NewTicker(250 * time.Millisecond)
				defer tick.Stop()
				pings := 0
				for {
					select {
					case <-ctx.Done():
						return
					case <-tick.C:
						flush()
						if pings++; pings%80 == 0 {
							mu.Lock()
							_ = send(sse.Message{Comment: "ping"})
							mu.Unlock()
						}
					}
				}
			}()
			since := in.Since
			if since.IsZero() {
				since = time.Now()
			}
			err := h.withDocker(ctx, in.ID, func(e *dockerEngine) error {
				v, _, err := e.client.Inspect(ctx, in.Container, false)
				if err != nil {
					return err
				}
				return e.client.Logs(ctx, v.ID, v.Config.Tty, docker.LogQuery{Since: since, Follow: true}, func(l docker.LogLine) bool {
					mu.Lock()
					batch = append(batch, toDockerLogLine(l))
					full := len(batch) >= 500
					mu.Unlock()
					if full {
						flush()
					}
					return ctx.Err() == nil
				})
			})
			if ctx.Err() != nil {
				return
			}
			flush()
			cancel()
			mu.Lock()
			defer mu.Unlock()
			_ = send.Data(streamEnd(err))
		})

	sse.Register(api, huma.Operation{
		OperationID: "stream-docker-container-stats",
		Method:      http.MethodGet,
		Path:        base + "/containers/{container}/stats/stream",
		Summary:     "Live resource use of a container",
		Description: "Server-sent events: `stats` about once a second while it runs; `end` when it stops.",
		Tags:        tags,
	}, map[string]any{"stats": DockerStats{}, "end": DockerStreamEnd{}},
		func(ctx context.Context, in *DockerContainerPath, send sse.Sender) {
			err := h.withDocker(ctx, in.ID, func(e *dockerEngine) error {
				return e.client.Stats(ctx, in.Container, func(s docker.Sample) bool {
					return send.Data(toDockerStats(s)) == nil
				})
			})
			if ctx.Err() == nil {
				_ = send.Data(streamEnd(err))
			}
		})

	huma.Register(api, huma.Operation{
		OperationID: "docker-container-action",
		Method:      http.MethodPost,
		Path:        base + "/containers/{container}/actions/{action}",
		Summary:     "Start, stop, restart, pause or unpause a container",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerContainerPath
		Action string            `path:"action" enum:"start,stop,restart,pause,unpause"`
		Body   *DockerActionBody `required:"false"`
	}) (*struct{}, error) {
		timeout := -1
		text := "docker " + in.Action
		if in.Body != nil && in.Body.Timeout > 0 && (in.Action == "stop" || in.Action == "restart") {
			timeout = in.Body.Timeout
			text += " -t " + strconv.Itoa(timeout)
		}
		return nil, h.dockerDo(ctx, in.ID, text+" "+in.Container, func(e *dockerEngine) error {
			err := e.client.Act(ctx, in.Container, in.Action, timeout, "")
			if docker.StatusOf(err) == http.StatusNotModified {
				return nil
			}
			return err
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "kill-docker-container",
		Method:      http.MethodPost,
		Path:        base + "/containers/{container}/kill",
		Summary:     "Send a signal to a container",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerContainerPath
		Body DockerKillBody
	}) (*struct{}, error) {
		text := "docker kill "
		if in.Body.Signal != "" {
			text += "-s " + in.Body.Signal + " "
		}
		return nil, h.dockerDo(ctx, in.ID, text+in.Container, func(e *dockerEngine) error {
			return e.client.Act(ctx, in.Container, "kill", -1, in.Body.Signal)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "remove-docker-container",
		Method:      http.MethodDelete,
		Path:        base + "/containers/{container}",
		Summary:     "Remove a container",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerContainerPath
		Force   bool `query:"force" doc:"Also when it's running"`
		Volumes bool `query:"volumes" doc:"Also its anonymous volumes"`
	}) (*struct{}, error) {
		text := "docker rm "
		if in.Force {
			text += "-f "
		}
		if in.Volumes {
			text += "-v "
		}
		return nil, h.dockerDo(ctx, in.ID, text+in.Container, func(e *dockerEngine) error {
			return e.client.RemoveContainer(ctx, in.Container, in.Force, in.Volumes)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "rename-docker-container",
		Method:      http.MethodPost,
		Path:        base + "/containers/{container}/rename",
		Summary:     "Rename a container",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerContainerPath
		Body DockerRenameBody
	}) (*struct{}, error) {
		return nil, h.dockerDo(ctx, in.ID, "docker rename "+in.Container+" "+in.Body.Name, func(e *dockerEngine) error {
			return e.client.Rename(ctx, in.Container, in.Body.Name)
		})
	})

	// -- Images --

	huma.Register(api, huma.Operation{
		OperationID: "list-docker-images",
		Method:      http.MethodGet,
		Path:        base + "/images",
		Summary:     "List a server's images",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body []DockerImage }, error) {
		out := &struct{ Body []DockerImage }{[]DockerImage{}}
		err := h.withDocker(ctx, in.ID, func(e *dockerEngine) error {
			ims, err := e.client.Images(ctx)
			if err != nil {
				return err
			}
			cs, err := e.client.Containers(ctx)
			if err != nil {
				return err
			}
			for _, im := range ims {
				out.Body = append(out.Body, toDockerImage(im, cs))
			}
			return nil
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-docker-image",
		Method:      http.MethodGet,
		Path:        base + "/images/{image}",
		Summary:     "An image's details, layers and the containers using it",
		Tags:        tags,
	}, func(ctx context.Context, in *DockerImagePath) (*struct{ Body DockerImageDetails }, error) {
		out := &struct{ Body DockerImageDetails }{}
		err := h.withDocker(ctx, in.ID, func(e *dockerEngine) error {
			im, err := e.client.InspectImage(ctx, in.Image)
			if err != nil {
				return err
			}
			hist, err := e.client.ImageHistory(ctx, im.ID)
			if err != nil {
				return err
			}
			cs, err := e.client.Containers(ctx)
			if err != nil {
				return err
			}
			sum := docker.ImageSummary{ID: im.ID, RepoTags: im.RepoTags, RepoDigests: im.RepoDigests, Size: im.Size}
			if t := parseDockerTime(im.Created); t != nil {
				sum.Created = t.Unix()
			}
			d := DockerImageDetails{DockerImage: toDockerImage(sum, cs)}
			d.Architecture, d.Variant, d.OS, d.Author, d.DockerVersion = im.Architecture, im.Variant, im.Os, im.Author, im.DockerVersion
			d.User, d.WorkingDir = im.Config.User, im.Config.WorkingDir
			d.Command, d.Entrypoint = dockerList(im.Config.Cmd), dockerList(im.Config.Entrypoint)
			if principalOf(ctx).Level >= auth.Engineer {
				d.Env = splitEnv(im.Config.Env)
			} else {
				d.Env, d.EnvHidden = []DockerEnv{}, len(im.Config.Env) > 0
			}
			d.Labels = orEmptyMap(im.Config.Labels)
			d.ExposedPorts, d.Volumes = dockerKeys(im.Config.ExposedPorts), dockerKeys(im.Config.Volumes)
			d.Layers = len(im.RootFS.Layers)
			d.History = []DockerImageLayer{}
			for _, l := range hist {
				id := l.ID
				if id == "<missing>" {
					id = ""
				}
				d.History = append(d.History, DockerImageLayer{
					ID: id, Created: time.Unix(l.Created, 0).UTC(), CreatedBy: l.CreatedBy, Size: l.Size, Comment: l.Comment, Tags: dockerList(l.Tags),
				})
			}
			d.UsedBy = refsOf(cs, func(c docker.ContainerSummary) bool { return c.ImageID == im.ID })
			out.Body = d
			return nil
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID:   "pull-docker-image",
		Method:        http.MethodPost,
		Path:          base + "/images/pull",
		Summary:       "Pull an image",
		Description:   "Runs as a background job (kind `docker-pull`) with per-layer progress.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body DockerPullBody
	}) (*JobOutput, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		image := strings.TrimSpace(in.Body.Image)
		if strings.ContainsAny(image, " \t\n") {
			return nil, huma.Error422UnprocessableEntity("An image name has no spaces")
		}
		return submit(ctx, h.jobs, jobs.Spec{
			Kind: dockerPullKind, Title: "Pull " + image + " on " + s.Name,
			Params: dockerPullParams{ServerID: in.ID, Image: image, Platform: in.Body.Platform},
			Refs:   placeRefs(in.ID), Target: &JobPlace{ServerID: in.ID, Name: s.Name},
		})
	})
	h.jobs.Handle(dockerPullKind, h.runDockerPull)
	registerDockerEvents(api, h)
	registerDockerProjects(api, h)
	registerDockerUpdates(api, h)
	registerDockerScans(api, h)
	registerDockerSettings(api, h)

	huma.Register(api, huma.Operation{
		OperationID: "remove-docker-image",
		Method:      http.MethodDelete,
		Path:        base + "/images/{image}",
		Summary:     "Remove an image, or one of its tags",
		Description: "With an image id it removes the image (every tag, with `force`); with a tag (repo:tag) only that tag goes, and the image too when it was the last one.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerImagePath
		Force bool `query:"force"`
	}) (*struct{}, error) {
		text := "docker rmi "
		if in.Force {
			text += "-f "
		}
		return nil, h.dockerDo(ctx, in.ID, text+in.Image, func(e *dockerEngine) error {
			return e.client.RemoveImage(ctx, in.Image, in.Force)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "tag-docker-image",
		Method:      http.MethodPost,
		Path:        base + "/images/{image}/tag",
		Summary:     "Give an image another tag",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerImagePath
		Body DockerTagBody
	}) (*struct{}, error) {
		tag := in.Body.Tag
		if tag == "" {
			tag = "latest"
		}
		return nil, h.dockerDo(ctx, in.ID, "docker tag "+in.Image+" "+in.Body.Repo+":"+tag, func(e *dockerEngine) error {
			return e.client.TagImage(ctx, in.Image, in.Body.Repo, tag)
		})
	})

	// -- Volumes --

	huma.Register(api, huma.Operation{
		OperationID: "list-docker-volumes",
		Method:      http.MethodGet,
		Path:        base + "/volumes",
		Summary:     "List a server's volumes",
		Description: "With `sizes`, also how much each holds (the engine measures them all, which can be slow).",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Sizes bool `query:"sizes"`
	}) (*struct{ Body []DockerVolume }, error) {
		out := &struct{ Body []DockerVolume }{[]DockerVolume{}}
		err := h.withDocker(ctx, in.ID, func(e *dockerEngine) error {
			vs, err := e.client.Volumes(ctx)
			if err != nil {
				return err
			}
			cs, err := e.client.Containers(ctx)
			if err != nil {
				return err
			}
			sizes := map[string]int64{}
			if in.Sizes {
				du, err := e.client.DiskUsage(ctx)
				if err != nil {
					return err
				}
				for _, v := range du.Volumes {
					if v.UsageData != nil {
						sizes[v.Name] = v.UsageData.Size
					}
				}
			}
			for _, v := range vs {
				dv := toDockerVolume(v, cs)
				if s, ok := sizes[v.Name]; ok && s >= 0 {
					dv.Size = s
				}
				out.Body = append(out.Body, dv)
			}
			return nil
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-docker-volume",
		Method:      http.MethodPost,
		Path:        base + "/volumes",
		Summary:     "Create a volume",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body DockerVolumeBody
	}) (*struct{ Body DockerVolume }, error) {
		out := &struct{ Body DockerVolume }{}
		text := "docker volume create"
		if in.Body.Driver != "" {
			text += " -d " + in.Body.Driver
		}
		err := h.dockerDo(ctx, in.ID, strings.TrimSpace(text+" "+in.Body.Name), func(e *dockerEngine) error {
			v, err := e.client.CreateVolume(ctx, docker.VolumeCreate{Name: in.Body.Name, Driver: in.Body.Driver, DriverOpts: in.Body.Options, Labels: in.Body.Labels})
			out.Body = toDockerVolume(v, nil)
			return err
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "remove-docker-volume",
		Method:      http.MethodDelete,
		Path:        base + "/volumes/{volume}",
		Summary:     "Remove a volume and everything in it",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerVolumePath
		Force bool `query:"force"`
	}) (*struct{}, error) {
		return nil, h.dockerDo(ctx, in.ID, "docker volume rm "+in.Volume, func(e *dockerEngine) error {
			return e.client.RemoveVolume(ctx, in.Volume, in.Force)
		})
	})

	// -- Networks --

	huma.Register(api, huma.Operation{
		OperationID: "list-docker-networks",
		Method:      http.MethodGet,
		Path:        base + "/networks",
		Summary:     "List a server's networks with the containers on each",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body []DockerNetwork }, error) {
		out := &struct{ Body []DockerNetwork }{[]DockerNetwork{}}
		err := h.withDocker(ctx, in.ID, func(e *dockerEngine) error {
			ns, err := e.client.Networks(ctx)
			if err != nil {
				return err
			}
			cs, err := e.client.Containers(ctx)
			if err != nil {
				return err
			}
			for _, n := range ns {
				out.Body = append(out.Body, toDockerNetwork(n, cs))
			}
			sort.Slice(out.Body, func(i, j int) bool { return out.Body[i].Name < out.Body[j].Name })
			return nil
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-docker-network",
		Method:      http.MethodPost,
		Path:        base + "/networks",
		Summary:     "Create a network",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body DockerNetworkBody
	}) (*struct{ Body DockerNetwork }, error) {
		b := in.Body
		req := docker.NetworkCreate{
			Name: b.Name, Driver: b.Driver, Internal: b.Internal, Attachable: b.Attachable, EnableIPv6: b.IPv6,
			Labels: b.Labels, Options: b.Options,
		}
		if b.Subnet != "" || b.Gateway != "" || b.IPRange != "" {
			if b.Subnet == "" {
				return nil, huma.Error422UnprocessableEntity("A gateway or IP range needs a subnet")
			}
			req.IPAM = &struct {
				Driver string              `json:"Driver,omitempty"`
				Config []docker.IPAMConfig `json:"Config,omitempty"`
			}{Config: []docker.IPAMConfig{{Subnet: b.Subnet, Gateway: b.Gateway, IPRange: b.IPRange}}}
		}
		text := "docker network create"
		if b.Driver != "" {
			text += " -d " + b.Driver
		}
		if b.Subnet != "" {
			text += " --subnet " + b.Subnet
		}
		if b.Internal {
			text += " --internal"
		}
		out := &struct{ Body DockerNetwork }{}
		err := h.dockerDo(ctx, in.ID, text+" "+b.Name, func(e *dockerEngine) error {
			id, err := e.client.CreateNetwork(ctx, req)
			if err != nil {
				return err
			}
			n, err := e.client.InspectNetwork(ctx, id)
			out.Body = toDockerNetwork(n, nil)
			return err
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "remove-docker-network",
		Method:      http.MethodDelete,
		Path:        base + "/networks/{network}",
		Summary:     "Remove a network",
		Tags:        tags,
	}, func(ctx context.Context, in *DockerNetworkPath) (*struct{}, error) {
		if builtinNetworks[in.Network] {
			return nil, huma.Error422UnprocessableEntity("Docker's own networks can't be removed")
		}
		return nil, h.dockerDo(ctx, in.ID, "docker network rm "+in.Network, func(e *dockerEngine) error {
			return e.client.RemoveNetwork(ctx, in.Network)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "connect-docker-network",
		Method:      http.MethodPost,
		Path:        base + "/networks/{network}/connect",
		Summary:     "Attach a container to a network",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerNetworkPath
		Body DockerConnectBody
	}) (*struct{}, error) {
		text := "docker network connect "
		if in.Body.IPv4 != "" {
			text += "--ip " + in.Body.IPv4 + " "
		}
		for _, a := range in.Body.Aliases {
			text += "--alias " + a + " "
		}
		return nil, h.dockerDo(ctx, in.ID, text+in.Network+" "+in.Body.Container, func(e *dockerEngine) error {
			return e.client.Connect(ctx, in.Network, in.Body.Container, in.Body.Aliases, in.Body.IPv4)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "disconnect-docker-network",
		Method:      http.MethodPost,
		Path:        base + "/networks/{network}/disconnect",
		Summary:     "Detach a container from a network",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerNetworkPath
		Body DockerDisconnectBody
	}) (*struct{}, error) {
		text := "docker network disconnect "
		if in.Body.Force {
			text += "-f "
		}
		return nil, h.dockerDo(ctx, in.ID, text+in.Network+" "+in.Body.Container, func(e *dockerEngine) error {
			return e.client.Disconnect(ctx, in.Network, in.Body.Container, in.Body.Force)
		})
	})

	// -- System --

	huma.Register(api, huma.Operation{
		OperationID: "docker-disk-usage",
		Method:      http.MethodGet,
		Path:        base + "/disk-usage",
		Summary:     "Space used by images, containers, volumes and the build cache",
		Description: "What `docker system df` shows, with what a prune of each could free. The engine measures everything, so it can take a while.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body DockerDiskUsage }, error) {
		out := &struct{ Body DockerDiskUsage }{}
		err := h.withDocker(ctx, in.ID, func(e *dockerEngine) error {
			du, err := e.client.DiskUsage(ctx)
			if err != nil {
				return err
			}
			b := &out.Body
			b.Images.Size = du.LayersSize
			for _, im := range du.Images {
				b.Images.Count++
				if im.Containers > 0 {
					b.Images.Active++
				} else {
					b.Images.Reclaimable += im.Size - max(im.SharedSize, 0)
				}
			}
			for _, c := range du.Containers {
				b.Containers.Count++
				b.Containers.Size += c.SizeRw
				if c.State == "running" || c.State == "paused" || c.State == "restarting" {
					b.Containers.Active++
				} else {
					b.Containers.Reclaimable += c.SizeRw
				}
			}
			for _, v := range du.Volumes {
				b.Volumes.Count++
				if v.UsageData == nil {
					continue
				}
				size := max(v.UsageData.Size, 0)
				b.Volumes.Size += size
				if v.UsageData.RefCount > 0 {
					b.Volumes.Active++
				} else {
					b.Volumes.Reclaimable += size
				}
			}
			for _, bc := range du.BuildCache {
				b.BuildCache.Count++
				b.BuildCache.Size += bc.Size
				if bc.InUse {
					b.BuildCache.Active++
				} else if !bc.Shared {
					b.BuildCache.Reclaimable += bc.Size
				}
			}
			b.Images.Reclaimable = min(max(b.Images.Reclaimable, 0), b.Images.Size)
			b.Total = b.Images.Size + b.Containers.Size + b.Volumes.Size + b.BuildCache.Size
			b.Reclaimable = b.Images.Reclaimable + b.Containers.Reclaimable + b.Volumes.Reclaimable + b.BuildCache.Reclaimable
			return nil
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID:   "prune-docker",
		Method:        http.MethodPost,
		Path:          base + "/prune",
		Summary:       "Remove what isn't used",
		Description:   "Stopped containers, unused images, volumes, networks and the build cache, as chosen. Runs as a background job (kind `docker-prune`); its result says what went.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body DockerPruneBody
	}) (*JobOutput, error) {
		b := in.Body
		if !b.Containers && !b.Networks && !b.BuildCache && (b.Images == "" || b.Images == "none") && (b.Volumes == "" || b.Volumes == "none") {
			return nil, huma.Error422UnprocessableEntity("Pick something to remove")
		}
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return submit(ctx, h.jobs, jobs.Spec{
			Kind: dockerPruneKind, Title: "Clean up Docker on " + s.Name,
			Params: dockerPruneParams{ServerID: in.ID, DockerPruneBody: b},
			Refs:   placeRefs(in.ID), Target: &JobPlace{ServerID: in.ID, Name: s.Name},
		})
	})
	h.jobs.Handle(dockerPruneKind, h.runDockerPrune)

	// -- Fleet --

	huma.Register(api, huma.Operation{
		OperationID: "list-docker-fleet",
		Method:      http.MethodGet,
		Path:        "/docker/containers",
		Summary:     "Containers on every server of the workspace",
		Description: "Asks each online server this person can see (8 at a time); `servers` says how each one went, so a server without Docker doesn't fail the list.",
		Tags:        tags,
	}, func(ctx context.Context, _ *struct{}) (*struct{ Body DockerFleet }, error) {
		sc := principalOf(ctx).scope()
		rows, err := h.q.ListServers(ctx, sqlc.ListServersParams{
			SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, ServerIds: sc.servers, WorkspaceID: sc.current,
			OsIds: []string{}, Statuses: []string{}, Tags: []string{}, AuthMethods: []string{},
			Sort: "name", Lim: 10000,
		})
		if err != nil {
			return nil, internalError(err)
		}
		ids := make([]uuid.UUID, len(rows))
		for i, r := range rows {
			ids[i] = r.Server.ID
		}
		samples := map[uuid.UUID]sqlc.ServerSample{}
		if ls, err := h.q.LatestServerSamples(ctx, ids); err == nil {
			for _, l := range ls {
				samples[l.ServerID] = l
			}
		}
		out := &struct{ Body DockerFleet }{DockerFleet{Servers: make([]DockerFleetServer, len(rows)), Containers: []DockerContainer{}}}
		lists := make([][]DockerContainer, len(rows))
		sem := make(chan struct{}, 8)
		var wg sync.WaitGroup
		for i, r := range rows {
			s := r.Server
			id := s.ID.String()
			fs := &out.Body.Servers[i]
			*fs = DockerFleetServer{ServerID: id, WorkspaceID: s.WorkspaceID.String(), Name: s.Name, Address: s.Host, OSID: s.OsID, Status: s.Status}
			if smp, ok := samples[s.ID]; ok && time.Since(smp.At) < 10*time.Minute {
				fs.Host = &DockerFleetHost{
					At: smp.At, CPUPercent: smp.CpuPercent, Cores: int(smp.Cores), Load1: smp.Load1,
					MemUsed: smp.MemUsedBytes, MemTotal: smp.MemTotalBytes,
					DiskUsed: smp.DiskUsedBytes, DiskTotal: smp.DiskTotalBytes,
					DiskMount: smp.DiskMaxMount, DiskMax: smp.DiskMaxPercent,
				}
			}
			if s.Status != "online" && s.Status != "unknown" {
				fs.State, fs.Message = "offline", "The server isn't reachable"
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
				defer cancel()
				err := h.withConn(cctx, id, func(c *sshpool.Conn) error {
					e, err := h.engine(cctx, id, c)
					if err != nil {
						return err
					}
					cs, err := e.client.Containers(cctx)
					if err != nil {
						return err
					}
					projects := map[string]bool{}
					for _, c := range cs {
						dc := toDockerContainer(id, c)
						lists[i] = append(lists[i], dc)
						fs.Total++
						switch c.State {
						case "running":
							fs.Running++
						case "paused":
							fs.Paused++
						case "restarting":
							fs.Restarting++
						default:
							fs.Stopped++
							if c.State == "dead" || dockerExitFailed(c.Status) {
								fs.Failed++
							}
						}
						switch dc.Health {
						case "healthy":
							fs.Healthy++
						case "unhealthy":
							fs.Unhealthy++
						case "starting":
							fs.Starting++
						}
						if dc.Project != "" {
							projects[dc.Project] = true
						}
					}
					fs.Projects = len(projects)
					fs.Via = e.via
					if info, err := e.client.Info(cctx); err == nil {
						fs.Images, fs.CPUs, fs.Memory = info.Images, info.NCPU, info.MemTotal
						fs.Version = info.ServerVersion
					}
					if v, err := e.client.Version(cctx); err == nil {
						fs.Version = v.Version
						for _, comp := range v.Components {
							if strings.Contains(strings.ToLower(comp.Name), "podman") {
								fs.Podman = true
							}
						}
					}
					return nil
				})
				var un *dockerUnavailable
				switch {
				case err == nil:
					fs.State = dockerReady
				case errors.As(err, &un):
					fs.State, fs.Message = un.state, un.message
				default:
					fs.State, fs.Message = "offline", dockerProblemText(dockerProblem(err))
				}
			}()
		}
		wg.Wait()
		for _, l := range lists {
			out.Body.Containers = append(out.Body.Containers, l...)
		}
		return out, nil
	})
}

// dockerExitFailed says a stopped container's status ("Exited (1) 3 hours
// ago") shows a non-zero exit code.
func dockerExitFailed(status string) bool {
	rest, ok := strings.CutPrefix(status, "Exited (")
	if !ok {
		return false
	}
	code, _, _ := strings.Cut(rest, ")")
	return code != "0" && code != ""
}

// dockerProblemText is the message of a problem error.
func dockerProblemText(err error) string {
	var se huma.StatusError
	if errors.As(err, &se) {
		if m, ok := se.(*huma.ErrorModel); ok && m.Detail != "" {
			return m.Detail
		}
	}
	return err.Error()
}

func streamEnd(err error) DockerStreamEnd {
	if err == nil {
		return DockerStreamEnd{Reason: "stopped"}
	}
	p := dockerProblem(err)
	if se, ok := p.(huma.StatusError); ok && se.GetStatus() == http.StatusNotFound {
		return DockerStreamEnd{Reason: "gone", Detail: dockerProblemText(p)}
	}
	return DockerStreamEnd{Reason: "error", Detail: dockerProblemText(p)}
}

// ---- Jobs ----

func (h *serverHandler) runDockerPull(ctx context.Context, t *jobs.Task) (any, error) {
	var p dockerPullParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	type layer struct {
		current, total int64
		done           bool
	}
	layers := map[string]*layer{}
	var order []string
	status := ""
	err := h.dockerDo(ctx, p.ServerID, "docker pull "+p.Image, func(e *dockerEngine) error {
		last := time.Time{}
		return e.client.Pull(ctx, p.Image, p.Platform, h.serverRegistryAuth(ctx, p.ServerID, p.Image), func(ev docker.PullEvent) {
			if ev.ID != "" && len(ev.ID) == 12 { // a layer
				l := layers[ev.ID]
				if l == nil {
					l = &layer{}
					layers[ev.ID] = l
					order = append(order, ev.ID)
				}
				switch ev.Status {
				case "Downloading":
					l.current, l.total = ev.Progress.Current, ev.Progress.Total
				case "Download complete", "Pull complete", "Already exists":
					l.done = true
					if l.total > 0 {
						l.current = l.total
					}
				}
			} else if ev.Status != "" {
				status = ev.Status
				t.Logf("%s", ev.Status)
			}
			if time.Since(last) < 300*time.Millisecond {
				return
			}
			last = time.Now()
			t.Update(func(pr *jobs.Progress) {
				pr.Phase = "Downloading"
				pr.Done, pr.Total, pr.Items = 0, 0, 0
				for _, id := range order {
					l := layers[id]
					pr.Done += l.current
					pr.Total += l.total
					if l.done {
						pr.Items++
					}
				}
				pr.ItemsTotal = len(order)
				pr.Current = p.Image
			})
		})
	})
	if err != nil {
		return nil, jobError(err)
	}
	t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Items = "Done", len(order) })
	return map[string]any{"image": p.Image, "status": status, "layers": len(order)}, nil
}

func (h *serverHandler) runDockerPrune(ctx context.Context, t *jobs.Task) (any, error) {
	var p dockerPruneParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	res := DockerPruneResult{}
	type step struct {
		kind, phase, text string
		filters           map[string][]string
		on                bool
	}
	steps := []step{
		{"containers", "Removing stopped containers", "docker container prune -f", nil, p.Containers},
		{"networks", "Removing unused networks", "docker network prune -f", nil, p.Networks},
		{"images", "Removing unused images", "docker image prune -f", map[string][]string{"dangling": {"true"}}, p.Images == "dangling"},
		{"images", "Removing unused images", "docker image prune -a -f", map[string][]string{"dangling": {"false"}}, p.Images == "all"},
		{"volumes", "Removing unused volumes", "docker volume prune -f", nil, p.Volumes == "anonymous"},
		{"volumes", "Removing unused volumes", "docker volume prune -a -f", map[string][]string{"all": {"true"}}, p.Volumes == "all"},
		{"build", "Clearing the build cache", "docker builder prune -f", nil, p.BuildCache},
	}
	total := 0
	for _, s := range steps {
		if s.on {
			total++
		}
	}
	n := 0
	for _, s := range steps {
		if !s.on {
			continue
		}
		t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Items, pr.ItemsTotal = s.phase, n, total })
		err := h.dockerDo(ctx, p.ServerID, s.text, func(e *dockerEngine) error {
			r, err := e.client.Prune(ctx, s.kind, s.filters)
			if err != nil {
				return err
			}
			res.Containers += len(r.ContainersDeleted)
			res.Networks += len(r.NetworksDeleted)
			res.Volumes += len(r.VolumesDeleted)
			res.Caches += len(r.CachesDeleted)
			for _, im := range r.ImagesDeleted {
				if im.Deleted != "" {
					res.Images++
				}
			}
			res.Space += r.SpaceReclaimed
			t.Logf("%s: freed %d bytes", s.phase, r.SpaceReclaimed)
			return nil
		})
		if err != nil {
			// An old engine without volume prune's "all" filter: say so plainly.
			return nil, jobError(err)
		}
		n++
	}
	t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Items, pr.ItemsTotal = "Done", total, total })
	return res, nil
}
