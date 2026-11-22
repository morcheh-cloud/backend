package api

// Zero-downtime updates of compose services ("start-first", Swarm's word).
// A service whose compose file says
//
//	deploy:
//	  update_config:
//	    order: start-first
//
// is updated by starting the new container beside the old one, waiting for
// it to turn healthy, giving traffic a moment to move over (both answer to
// the service's name on the project's networks) and only then stopping the
// old one. If the new one never turns healthy it is removed and the old one
// keeps serving. Services that can't run twice at once (a fixed
// container_name, a fixed host port, the host's network) are updated the
// usual way, and the log says why.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/morche/backend/internal/docker"
	"github.com/morche/backend/internal/jobs"
	"github.com/morche/backend/internal/sshpool"
	"github.com/morche/backend/internal/terminal"
)

// composeService is the part of `compose config --format json` a rollout
// reads.
type composeService struct {
	Image         string `json:"image"`
	ContainerName string `json:"container_name"`
	NetworkMode   string `json:"network_mode"`
	Scale         *int   `json:"scale"`
	Ports         []struct {
		Published string `json:"published"`
		Target    int    `json:"target"`
	} `json:"ports"`
	Healthcheck *struct {
		Test        []string `json:"test"`
		Disable     bool     `json:"disable"`
		Interval    string   `json:"interval"`
		Timeout     string   `json:"timeout"`
		Retries     *int     `json:"retries"`
		StartPeriod string   `json:"start_period"`
	} `json:"healthcheck"`
	Deploy *struct {
		Replicas     *int `json:"replicas"`
		UpdateConfig *struct {
			Order   string `json:"order"`
			Delay   string `json:"delay"`
			Monitor string `json:"monitor"`
		} `json:"update_config"`
	} `json:"deploy"`
}

// rolloutWarning is what compose prints about update_config outside Swarm:
// Morche does read it, so the line is left out of the job's log.
const rolloutWarning = "deploy.update_config only applies to rolling updates in Swarm mode"

// startFirst says the file asks for zero-downtime updates.
func (s composeService) startFirst() bool {
	return s.Deploy != nil && s.Deploy.UpdateConfig != nil && strings.EqualFold(s.Deploy.UpdateConfig.Order, "start-first")
}

// rollBlocker is why two copies of the service can't run at once ("" = they can).
func (s composeService) rollBlocker() string {
	if s.ContainerName != "" {
		return "it has a fixed container_name (" + s.ContainerName + "), so a second copy can't be made"
	}
	if s.NetworkMode == "host" {
		return "it uses the host's network, so two copies would want the same ports"
	}
	for _, p := range s.Ports {
		if p.Published != "" && p.Published != "0" {
			return "it publishes host port " + p.Published + ", which only one copy can hold (put a reverse proxy on its network in front instead)"
		}
	}
	if s.Scale != nil && *s.Scale > 1 {
		return "it runs several copies"
	}
	if s.Deploy != nil && s.Deploy.Replicas != nil && *s.Deploy.Replicas > 1 {
		return "it runs several copies"
	}
	if s.Healthcheck != nil && s.Healthcheck.Disable {
		return "its healthcheck is turned off, so there's no way to tell when the new copy is ready"
	}
	if s.Healthcheck != nil && len(s.Healthcheck.Test) > 0 && s.Healthcheck.Test[0] == "NONE" {
		return "its healthcheck is turned off, so there's no way to tell when the new copy is ready"
	}
	return ""
}

func durationOr(s string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return def
}

// healthWait is how long the new copy gets to turn healthy: the
// healthcheck's start period plus all its retries, and a margin.
func (s composeService) healthWait() time.Duration {
	if s.Deploy != nil && s.Deploy.UpdateConfig != nil && s.Deploy.UpdateConfig.Monitor != "" {
		return durationOr(s.Deploy.UpdateConfig.Monitor, 3*time.Minute)
	}
	interval, timeout, retries, start := 30*time.Second, 30*time.Second, 3, time.Duration(0)
	if hc := s.Healthcheck; hc != nil {
		interval = durationOr(hc.Interval, interval)
		timeout = durationOr(hc.Timeout, timeout)
		start = durationOr(hc.StartPeriod, 0)
		if hc.Retries != nil && *hc.Retries > 0 {
			retries = *hc.Retries
		}
	}
	d := start + time.Duration(retries+1)*(interval+timeout) + 30*time.Second
	return min(max(d, time.Minute), 15*time.Minute)
}

// grace is how long an unhealthy answer isn't final yet: the start period,
// or 30 s when the file gives none (apps that take a while to listen would
// fail their first checks otherwise).
func (s composeService) grace() time.Duration {
	if s.Healthcheck != nil {
		if d := durationOr(s.Healthcheck.StartPeriod, 0); d > 0 {
			return d
		}
	}
	return 30 * time.Second
}

// overlap is how long both copies serve before the old one stops.
func (s composeService) overlap() time.Duration {
	if s.Deploy != nil && s.Deploy.UpdateConfig != nil {
		return min(durationOr(s.Deploy.UpdateConfig.Delay, 5*time.Second), 5*time.Minute)
	}
	return 5 * time.Second
}

// composeScript is a compose command for the project, run in its folder.
func composeScript(p dockerComposeParams, args string) string {
	cd := ""
	if p.Dir != "" {
		cd = "cd " + terminal.ShellQuote(p.Dir) + " && "
	}
	return composeDetect + cd + "$C " + composeArgs(p.Project, p.Dir, p.Files) + " " + args
}

// composeConfig reads the project's services as compose resolves them. nil
// (no error) when this compose can't print them as JSON (docker-compose v1,
// podman-compose): then nothing is rolled.
func composeConfig(ctx context.Context, sh *rootShell, p dockerComposeParams) map[string]composeService {
	res, err := sh.exec(ctx, composeScript(p, "config --format json 2>/dev/null"), execTimeout, 4<<20)
	if err != nil || res.code != 0 || res.truncated {
		return nil
	}
	var cfg struct {
		Services map[string]composeService `json:"services"`
	}
	if json.Unmarshal(res.output, &cfg) != nil {
		return nil
	}
	return cfg.Services
}

// composeHashes is each service's config hash, the one compose labels its
// containers with (com.docker.compose.config-hash).
func composeHashes(ctx context.Context, sh *rootShell, p dockerComposeParams) map[string]string {
	res, err := sh.exec(ctx, composeScript(p, "config --hash='*' 2>/dev/null"), execTimeout, 1<<20)
	out := map[string]string{}
	if err != nil || res.code != 0 {
		return out
	}
	for l := range strings.SplitSeq(string(res.output), "\n") {
		if f := strings.Fields(l); len(f) == 2 {
			out[f[0]] = f[1]
		}
	}
	return out
}

// serviceContainers lists the containers of one compose service.
func (h *serverHandler) serviceContainers(ctx context.Context, serverID, project, service string) ([]docker.ContainerSummary, error) {
	var out []docker.ContainerSummary
	err := h.withDocker(ctx, serverID, func(e *dockerEngine) error {
		all, err := e.client.Containers(ctx)
		if err != nil {
			return err
		}
		for _, c := range all {
			if c.Labels["com.docker.compose.project"] == project && c.Labels["com.docker.compose.service"] == service {
				out = append(out, c)
			}
		}
		return nil
	})
	return out, err
}

// rollTarget is the running container a rollout would replace, or why it
// can't (reason) or needn't (both empty) be rolled.
func (h *serverHandler) rollTarget(ctx context.Context, serverID string, p dockerComposeParams, name string, svc composeService) (old docker.ContainerSummary, ok bool, reason string) {
	if !svc.startFirst() {
		return old, false, ""
	}
	if why := svc.rollBlocker(); why != "" {
		return old, false, why
	}
	cs, err := h.serviceContainers(ctx, serverID, p.Project, name)
	if err != nil {
		return old, false, "its containers couldn't be listed: " + err.Error()
	}
	var running []docker.ContainerSummary
	for _, c := range cs {
		if c.State == "running" {
			running = append(running, c)
		}
	}
	switch {
	case len(running) == 0:
		return old, false, "" // nothing serving now: nothing to keep up
	case len(running) > 1:
		return old, false, fmt.Sprintf("%d copies of it are running", len(running))
	}
	if svc.Healthcheck == nil {
		// The image may bring its own.
		var hc bool
		_ = h.withDocker(ctx, serverID, func(e *dockerEngine) error {
			in, _, err := e.client.Inspect(ctx, running[0].ID, false)
			if err == nil && in.Config.Healthcheck != nil && len(in.Config.Healthcheck.Test) > 0 && in.Config.Healthcheck.Test[0] != "NONE" {
				hc = true
			}
			return nil
		})
		if !hc {
			return old, false, "it has no healthcheck, so there's no way to tell when the new copy is ready"
		}
	}
	return running[0], true, ""
}

// rollNeeded says whether compose would replace old now: another config, or
// its image's tag points to another image.
func (h *serverHandler) rollNeeded(ctx context.Context, serverID string, p dockerComposeParams, name string, svc composeService, old docker.ContainerSummary, hashes map[string]string) bool {
	if want := hashes[name]; want != "" && want != old.Labels["com.docker.compose.config-hash"] {
		return true
	}
	img := svc.Image
	if img == "" {
		img = p.Project + "-" + name // compose's name for a built image
	}
	changed := false
	_ = h.withDocker(ctx, serverID, func(e *dockerEngine) error {
		in, err := e.client.InspectImage(ctx, img)
		if err == nil && in.ID != "" && old.ImageID != "" && in.ID != old.ImageID {
			changed = true
		}
		return nil
	})
	return changed
}

// rollService puts a new container of the service beside old, waits for it
// to turn healthy, then stops old (stop seconds, < 0 = the container's own).
// On any failure before old is stopped, the new one is removed and old keeps
// running.
func (h *serverHandler) rollService(ctx context.Context, t *jobs.Task, serverID string, p dockerComposeParams, name string, svc composeService, old docker.ContainerSummary, stop int) error {
	q := terminal.ShellQuote(name)
	t.Logf("==> Updating %s without downtime", name)
	t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Current = "Starting the new copy", name })
	t.Logf("Starting the new %s beside the old one", name)
	// Created, not started: it joins the networks without the service's
	// name first, so nothing sends it traffic before it's healthy (Docker's
	// DNS doesn't look at health). It still reaches the other services.
	err := h.withShell(ctx, serverID, func(_ *sshpool.Conn, sh *rootShell) error {
		return h.composeRun(ctx, t, sh, p, "up --no-deps --no-recreate --no-start --scale "+q+"=2 "+q)
	})
	cs, lerr := h.serviceContainers(ctx, serverID, p.Project, name)
	var fresh docker.ContainerSummary
	for _, c := range cs {
		if c.ID != old.ID && c.Created >= fresh.Created {
			fresh = c
		}
	}
	drop := func(why string) error {
		t.Logf("The new %s isn't healthy (%s): removing it, the old one keeps running", name, why)
		h.dropContainer(context.WithoutCancel(ctx), serverID, fresh.ID)
		return fmt.Errorf("The new version of %s didn't turn healthy (%s), so it was removed and the old one keeps running", name, why)
	}
	if err != nil {
		if fresh.ID != "" {
			h.dropContainer(context.WithoutCancel(ctx), serverID, fresh.ID)
		}
		return fmt.Errorf("Couldn't make the new %s (the old one keeps running): %w", name, err)
	}
	if lerr != nil || fresh.ID == "" {
		return fmt.Errorf("Couldn't find the new %s after making it (the old one keeps running)", name)
	}
	var nets map[string][]string
	err = h.withDocker(ctx, serverID, func(e *dockerEngine) error {
		var err error
		if nets, err = endpointAliases(ctx, e.client, fresh.ID); err != nil {
			return err
		}
		if err := setAliases(ctx, e.client, fresh.ID, nets, name, true); err != nil {
			return err
		}
		return e.client.Act(ctx, fresh.ID, "start", -1, "")
	})
	if err != nil {
		return drop("it couldn't be started: " + err.Error())
	}

	t.Update(func(pr *jobs.Progress) { pr.Phase = "Waiting for it to turn healthy" })
	if why := h.waitHealthy(ctx, t, serverID, name, fresh.ID, svc.grace(), svc.healthWait()); why != "" {
		return drop(why)
	}
	// Now it answers to the service's name too.
	err = h.withDocker(ctx, serverID, func(e *dockerEngine) error {
		return setAliases(ctx, e.client, fresh.ID, nets, name, false)
	})
	if err != nil {
		return drop("it couldn't take the service's name on its network: " + err.Error())
	}

	wait := svc.overlap()
	t.Logf("The new %s is healthy; both serve for %s while traffic moves over", name, wait)
	t.Update(func(pr *jobs.Progress) { pr.Phase = "Moving traffic over" })
	if err := sleepCtx(ctx, wait); err != nil {
		return err
	}

	t.Update(func(pr *jobs.Progress) { pr.Phase = "Stopping the old copy" })
	t.Logf("Stopping the old %s (%s)", name, containerName(old.Names))
	err = h.withDocker(context.WithoutCancel(ctx), serverID, func(e *dockerEngine) error {
		if err := e.client.Act(ctx, old.ID, "stop", stop, ""); err != nil {
			return err
		}
		return e.client.RemoveContainer(ctx, old.ID, false, false)
	})
	if err != nil {
		// Two copies left would make compose drop one of them on its own
		// next time, maybe the new one: say so instead.
		return fmt.Errorf("The new %s runs, but the old one couldn't be stopped: %w", name, err)
	}
	t.Logf("%s updated without downtime (now %s)", name, containerName(fresh.Names))
	return nil
}

// endpointAliases is each network the container is on, with its aliases.
func endpointAliases(ctx context.Context, c *docker.Client, id string) (map[string][]string, error) {
	_, raw, err := c.Inspect(ctx, id, false)
	if err != nil {
		return nil, err
	}
	var in struct {
		HostConfig struct {
			NetworkMode string `json:"NetworkMode"`
		} `json:"HostConfig"`
		NetworkSettings struct {
			Networks map[string]struct {
				Aliases []string `json:"Aliases"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	out := map[string][]string{}
	// Sharing another container's network (service:, container:) leaves
	// nothing to rename.
	if m := in.HostConfig.NetworkMode; strings.HasPrefix(m, "container:") || strings.HasPrefix(m, "service:") || m == "host" || m == "none" {
		return out, nil
	}
	for n, ep := range in.NetworkSettings.Networks {
		out[n] = ep.Aliases
	}
	return out, nil
}

// setAliases reconnects the container to each network where it's known as
// name: without that alias when hide, else with all its aliases back.
func setAliases(ctx context.Context, c *docker.Client, id string, nets map[string][]string, name string, hide bool) error {
	for n, aliases := range nets {
		if !slices.Contains(aliases, name) {
			continue
		}
		keep := aliases
		if hide {
			keep = slices.DeleteFunc(slices.Clone(aliases), func(a string) bool { return a == name })
		}
		if err := c.Disconnect(ctx, n, id, true); err != nil {
			return err
		}
		if err := c.Connect(ctx, n, id, keep, ""); err != nil {
			return err
		}
	}
	return nil
}

// dropContainer removes a container a rollout made, whatever its state.
func (h *serverHandler) dropContainer(ctx context.Context, serverID, id string) {
	_ = h.withDocker(ctx, serverID, func(e *dockerEngine) error {
		return e.client.RemoveContainer(ctx, id, true, false)
	})
}

// waitHealthy polls the container until it's healthy. "" = healthy, else why
// not. Unhealthy only counts after grace; a container without a healthcheck
// counts as ready once it has run for 10 s.
func (h *serverHandler) waitHealthy(ctx context.Context, t *jobs.Task, serverID, name, id string, grace, limit time.Duration) string {
	start := time.Now()
	lastLog := start
	var steady time.Time
	for {
		var in docker.ContainerInspect
		err := h.withDocker(ctx, serverID, func(e *dockerEngine) error {
			var err error
			in, _, err = e.client.Inspect(ctx, id, false)
			return err
		})
		switch {
		case ctx.Err() != nil:
			return "the task was canceled"
		case err != nil:
			return "it couldn't be read: " + err.Error()
		case in.State.Restarting:
			return "it keeps restarting"
		case !in.State.Running:
			return fmt.Sprintf("it stopped (exit code %d)", in.State.ExitCode)
		case in.State.Health == nil:
			if steady.IsZero() {
				steady = time.Now()
				t.Logf("The new %s has no healthcheck: it counts as ready once it has run for 10 s", name)
			}
			if time.Since(steady) >= 10*time.Second {
				return ""
			}
		case in.State.Health.Status == "healthy":
			return ""
		case in.State.Health.Status == "unhealthy" && time.Since(start) >= grace:
			why := "its healthcheck failed"
			if n := len(in.State.Health.Log); n > 0 {
				if out := strings.TrimSpace(in.State.Health.Log[n-1].Output); out != "" {
					if len(out) > 300 {
						out = out[:300] + "…"
					}
					why += ": " + out
				}
			}
			return why
		}
		if time.Since(start) > limit {
			return "it wasn't healthy after " + limit.Round(time.Second).String()
		}
		if time.Since(lastLog) >= 15*time.Second {
			lastLog = time.Now()
			t.Logf("Waiting for the new %s to turn healthy (%s so far)", name, time.Since(start).Round(time.Second))
		}
		if err := sleepCtx(ctx, 2*time.Second); err != nil {
			return "the task was canceled"
		}
	}
}

// composeUp runs a deploy's `compose up` (args), first rolling every
// start-first service that would be replaced. build = build the images
// first (a deploy from git), so the rollouts start from the new ones.
func (h *serverHandler) composeUp(ctx context.Context, t *jobs.Task, p dockerComposeParams, args string, build bool) error {
	var cfg map[string]composeService
	var hashes map[string]string
	_ = h.withShell(ctx, p.ServerID, func(_ *sshpool.Conn, sh *rootShell) error {
		cfg = composeConfig(ctx, sh, p)
		hashes = composeHashes(ctx, sh, p)
		return nil
	})
	var names []string
	for n, s := range cfg {
		if s.startFirst() {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	if len(names) > 0 && build {
		t.Logf("==> docker compose build")
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Building" })
		err := h.withShell(ctx, p.ServerID, func(_ *sshpool.Conn, sh *rootShell) error {
			return h.composeRun(ctx, t, sh, p, "build")
		})
		if err != nil {
			return err
		}
		build = false
		// A build changes no config hash, but the image the tag names.
	}
	for _, n := range names {
		old, ok, why := h.rollTarget(ctx, p.ServerID, p, n, cfg[n])
		if !ok {
			if why != "" {
				t.Logf("%s asks for updates without downtime, but %s: it's updated the usual way (stop, then start)", n, why)
			}
			continue
		}
		if !h.rollNeeded(ctx, p.ServerID, p, n, cfg[n], old, hashes) {
			continue
		}
		if err := h.rollService(ctx, t, p.ServerID, p, n, cfg[n], old, -1); err != nil {
			return err
		}
	}
	if build {
		args += " --build"
	}
	t.Logf("==> docker compose %s", args)
	t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Current = composePhases["up"], p.Project })
	return h.withShell(ctx, p.ServerID, func(_ *sshpool.Conn, sh *rootShell) error {
		return h.composeRun(ctx, t, sh, p, args)
	})
}

// updateService recreates one compose service on the image its tag names
// now: without downtime when its file asks for it and it can, else with
// `compose up -d --no-deps` (args = extra flags, like --timeout).
func (h *serverHandler) updateService(ctx context.Context, t *jobs.Task, p dockerComposeParams, service, args string, stop int) error {
	var cfg map[string]composeService
	_ = h.withShell(ctx, p.ServerID, func(_ *sshpool.Conn, sh *rootShell) error {
		cfg = composeConfig(ctx, sh, p)
		return nil
	})
	if svc, has := cfg[service]; has {
		old, ok, why := h.rollTarget(ctx, p.ServerID, p, service, svc)
		if ok {
			return h.rollService(ctx, t, p.ServerID, p, service, svc, old, stop)
		}
		if why != "" {
			t.Logf("%s asks for updates without downtime, but %s: it's updated the usual way (stop, then start)", service, why)
		}
	}
	return h.withShell(ctx, p.ServerID, func(_ *sshpool.Conn, sh *rootShell) error {
		return h.composeRun(ctx, t, sh, p, strings.TrimSpace("up -d --no-deps "+args)+" "+terminal.ShellQuote(service))
	})
}

// errRollLater ends a shell callback so its caller can go on to
// updateService, which opens its own connections.
var errRollLater = errors.New("update the service after the check")
