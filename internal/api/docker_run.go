package api

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/terminal"
)

// Run wizard: `docker run` from an image, with the common options. The
// panel builds the body; this turns it into the Engine API's create call and
// starts the container.

type DockerRunPort struct {
	HostIP        string `json:"host_ip,omitempty" maxLength:"64" doc:"Empty = every address"`
	HostPort      int    `json:"host_port,omitempty" minimum:"0" maximum:"65535" doc:"0 = a free port Docker picks"`
	ContainerPort int    `json:"container_port" minimum:"1" maximum:"65535"`
	Protocol      string `json:"protocol,omitempty" enum:"tcp,udp"`
}

type DockerRunVolume struct {
	Source   string `json:"source" minLength:"1" maxLength:"4096" doc:"A volume's name, or a folder on the server (starts with /)"`
	Target   string `json:"target" minLength:"1" maxLength:"4096" doc:"Folder inside the container"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

type DockerRunBody struct {
	Image      string            `json:"image" minLength:"1" maxLength:"500"`
	Name       string            `json:"name,omitempty" maxLength:"128" pattern:"^[a-zA-Z0-9][a-zA-Z0-9_.-]+$"`
	Command    []string          `json:"command,omitempty" maxItems:"100" doc:"Replaces the image's command"`
	Entrypoint []string          `json:"entrypoint,omitempty" maxItems:"20"`
	User       string            `json:"user,omitempty" maxLength:"100"`
	Workdir    string            `json:"workdir,omitempty" maxLength:"4096"`
	Env        []DockerEnv       `json:"env,omitempty" maxItems:"200"`
	Labels     map[string]string `json:"labels,omitempty"`
	Ports      []DockerRunPort   `json:"ports,omitempty" maxItems:"100"`
	Volumes    []DockerRunVolume `json:"volumes,omitempty" maxItems:"100"`
	Restart    string            `json:"restart,omitempty" enum:"no,always,unless-stopped,on-failure"`
	Network    string            `json:"network,omitempty" maxLength:"200" doc:"Empty = the default bridge"`
	MemoryMB   int64             `json:"memory_mb,omitempty" minimum:"0" maximum:"1048576"`
	CPUs       float64           `json:"cpus,omitempty" minimum:"0" maximum:"1024"`
	Privileged bool              `json:"privileged,omitempty"`
	CreateOnly bool              `json:"create_only,omitempty" doc:"Create it without starting it"`
}

type DockerRunResult struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Started  bool     `json:"started"`
	Warnings []string `json:"warnings"`
	Error    string   `json:"error,omitempty" doc:"Created, but it didn't start: why"`
}

type runPortBinding struct {
	HostIP   string `json:"HostIp,omitempty"`
	HostPort string `json:"HostPort,omitempty"`
}

// runRequest is the Engine API's create body (only what the wizard sets).
type runRequest struct {
	Image        string              `json:"Image"`
	Cmd          []string            `json:"Cmd,omitempty"`
	Entrypoint   []string            `json:"Entrypoint,omitempty"`
	User         string              `json:"User,omitempty"`
	WorkingDir   string              `json:"WorkingDir,omitempty"`
	Env          []string            `json:"Env,omitempty"`
	Labels       map[string]string   `json:"Labels,omitempty"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
	HostConfig   struct {
		Binds         []string                    `json:"Binds,omitempty"`
		PortBindings  map[string][]runPortBinding `json:"PortBindings,omitempty"`
		RestartPolicy struct {
			Name string `json:"Name,omitempty"`
		} `json:"RestartPolicy"`
		NetworkMode string `json:"NetworkMode,omitempty"`
		Memory      int64  `json:"Memory,omitempty"`
		NanoCpus    int64  `json:"NanoCpus,omitempty"`
		Privileged  bool   `json:"Privileged,omitempty"`
	} `json:"HostConfig"`
}

// runPlan checks the body and builds the create request plus the `docker
// run` line it matches (for the command log).
func runPlan(b DockerRunBody) (runRequest, string, error) {
	var r runRequest
	args := []string{"docker", "run"}
	if b.CreateOnly {
		args[1] = "create"
	} else {
		args = append(args, "-d")
	}
	r.Image = strings.TrimSpace(b.Image)
	if b.Name != "" {
		args = append(args, "--name", b.Name)
	}
	for i, e := range b.Env {
		name := strings.TrimSpace(e.Name)
		if name == "" || strings.ContainsAny(name, "= \t\n") {
			return r, "", fieldError(fmt.Sprintf("body.env[%d].name", i), "Not a variable name.", e.Name)
		}
		r.Env = append(r.Env, name+"="+e.Value)
		args = append(args, "-e", name+"=…")
	}
	seen := map[string]bool{}
	for i, p := range b.Ports {
		proto := cmpOr(p.Protocol, "tcp")
		key := strconv.Itoa(p.ContainerPort) + "/" + proto
		if r.ExposedPorts == nil {
			r.ExposedPorts = map[string]struct{}{}
			r.HostConfig.PortBindings = map[string][]runPortBinding{}
		}
		if p.HostPort > 0 {
			hk := p.HostIP + ":" + strconv.Itoa(p.HostPort) + "/" + proto
			if seen[hk] {
				return r, "", fieldError(fmt.Sprintf("body.ports[%d].host_port", i), "Two rows use this port.", p.HostPort)
			}
			seen[hk] = true
		}
		r.ExposedPorts[key] = struct{}{}
		bind := runPortBinding{HostIP: strings.TrimSpace(p.HostIP)}
		if p.HostPort > 0 {
			bind.HostPort = strconv.Itoa(p.HostPort)
		}
		r.HostConfig.PortBindings[key] = append(r.HostConfig.PortBindings[key], bind)
		arg := strconv.Itoa(p.ContainerPort)
		if proto != "tcp" {
			arg += "/" + proto
		}
		if bind.HostPort != "" {
			arg = bind.HostPort + ":" + arg
		} else {
			arg = ":" + arg
		}
		if bind.HostIP != "" {
			arg = bind.HostIP + ":" + strings.TrimPrefix(arg, ":")
			if bind.HostPort == "" {
				arg = bind.HostIP + "::" + strings.TrimPrefix(arg, bind.HostIP+":")
			}
		}
		args = append(args, "-p", arg)
	}
	for i, v := range b.Volumes {
		src, dst := strings.TrimSpace(v.Source), strings.TrimSpace(v.Target)
		if strings.ContainsAny(src, ":\n") || src == "" {
			return r, "", fieldError(fmt.Sprintf("body.volumes[%d].source", i), "Not a volume or folder.", v.Source)
		}
		if !strings.HasPrefix(dst, "/") || strings.ContainsAny(dst, ":\n") {
			return r, "", fieldError(fmt.Sprintf("body.volumes[%d].target", i), "A folder inside the container, starting with /.", v.Target)
		}
		bind := src + ":" + dst
		if v.ReadOnly {
			bind += ":ro"
		}
		r.HostConfig.Binds = append(r.HostConfig.Binds, bind)
		args = append(args, "-v", bind)
	}
	if b.Restart != "" && b.Restart != "no" {
		r.HostConfig.RestartPolicy.Name = b.Restart
		args = append(args, "--restart", b.Restart)
	}
	if n := strings.TrimSpace(b.Network); n != "" {
		r.HostConfig.NetworkMode = n
		args = append(args, "--network", n)
	}
	if b.MemoryMB > 0 {
		if b.MemoryMB < 6 {
			return r, "", fieldError("body.memory_mb", "Docker needs at least 6 MB.", b.MemoryMB)
		}
		r.HostConfig.Memory = b.MemoryMB << 20
		args = append(args, "-m", strconv.FormatInt(b.MemoryMB, 10)+"m")
	}
	if b.CPUs > 0 {
		r.HostConfig.NanoCpus = int64(math.Round(b.CPUs * 1e9))
		args = append(args, "--cpus", strconv.FormatFloat(b.CPUs, 'f', -1, 64))
	}
	if b.Privileged {
		r.HostConfig.Privileged = true
		args = append(args, "--privileged")
	}
	if b.User != "" {
		r.User = b.User
		args = append(args, "-u", b.User)
	}
	if b.Workdir != "" {
		if !strings.HasPrefix(b.Workdir, "/") {
			return r, "", fieldError("body.workdir", "A folder inside the container, starting with /.", b.Workdir)
		}
		r.WorkingDir = b.Workdir
		args = append(args, "-w", b.Workdir)
	}
	if len(b.Entrypoint) > 0 {
		r.Entrypoint = b.Entrypoint
		args = append(args, "--entrypoint", terminal.ShellQuote(strings.Join(b.Entrypoint, " ")))
	}
	r.Labels = b.Labels
	args = append(args, r.Image)
	if len(b.Command) > 0 {
		r.Cmd = b.Command
		for _, c := range b.Command {
			args = append(args, terminal.ShellQuote(c))
		}
	}
	return r, strings.Join(args, " "), nil
}

func registerDockerRun(api huma.API, h *serverHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "run-docker-container",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/docker/containers",
		Summary:     "Run a container from an image",
		Description: "Like `docker run -d`: creates the container and starts it (`create_only` leaves it stopped). The image must be on the server already. A container that is created but fails to start is kept and comes back with `error`.",
		Tags:        []string{"Containers"},
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body DockerRunBody
	}) (*struct{ Body DockerRunResult }, error) {
		if _, err := h.get(ctx, in.ID); err != nil {
			return nil, err
		}
		req, text, err := runPlan(in.Body)
		if err != nil {
			return nil, err
		}
		out := &struct{ Body DockerRunResult }{}
		// Never retried: a second create would make a second container.
		err = h.withEngine(ctx, in.ID, func(e *dockerEngine) error {
			end := h.dockerLog(ctx, in.ID, e, text)
			made, err := e.client.CreateContainer(ctx, in.Body.Name, "", req)
			if err != nil {
				end(err)
				return err
			}
			out.Body = DockerRunResult{ID: made.ID, Name: in.Body.Name, Warnings: nonNil(made.Warnings)}
			if !in.Body.CreateOnly {
				if err := e.client.Act(ctx, made.ID, "start", 0, ""); err != nil {
					out.Body.Error = problemText(dockerProblem(err))
					end(err)
					return nil
				}
				out.Body.Started = true
			}
			end(nil)
			if c, _, err := e.client.Inspect(ctx, made.ID, false); err == nil {
				out.Body.Name = strings.TrimPrefix(c.Name, "/")
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return out, nil
	})
}
