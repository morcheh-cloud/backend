package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/proxy"
	"github.com/morcheh/backend/internal/sshpool"
)

// proxyShell is a root shell on a proxy's server that runs the driver's
// scripts where the proxy is: on the server itself, or inside its container.
// The host* methods always run on the server.
type proxyShell struct {
	*rootShell
	box *proxy.Container // nil: the proxy is installed on the server
	// ci is what the runtime said about the container at the last
	// inspection.
	ci *proxy.ContainerInfo
}

// boxError is a container proxy whose container couldn't be reached.
type boxError struct {
	code int
	msg  string
}

func (e *boxError) Error() string { return e.msg }

// stopped says the container is there but not running.
func (e *boxError) stopped() bool { return e.code == proxy.ExitContainerStopped }

// containerOf is a proxy's container, nil when it runs on the server.
func containerOf(p sqlc.Proxy) *proxy.Container {
	if p.Runtime == "" || p.Runtime == proxy.RuntimeHost {
		return nil
	}
	return &proxy.Container{Runtime: p.Runtime, Name: p.Container}
}

// shell opens a root shell for a proxy.
func (h *proxyHandler) shell(ctx context.Context, p sqlc.Proxy, c *sshpool.Conn) (*proxyShell, error) {
	sh, err := h.root(ctx, p.ServerID.String(), c)
	if err != nil {
		return nil, err
	}
	return &proxyShell{rootShell: sh, box: containerOf(p)}, nil
}

// wrap is script as it runs: inside the container when there is one.
func (s *proxyShell) wrap(script string) string {
	if s.box == nil {
		return script
	}
	return s.box.Run(script)
}

// boxErr turns the exit codes of Container.Run into a boxError.
func (s *proxyShell) boxErr(code int) error {
	if s.box == nil {
		return nil
	}
	b := s.box
	switch code {
	case proxy.ExitNoRuntime:
		return &boxError{code, b.Label() + " isn't installed on this server"}
	case proxy.ExitNoContainer:
		return &boxError{code, "There's no container named " + b.Name + " on this server"}
	case proxy.ExitContainerStopped:
		return &boxError{code, "The container " + b.Name + " isn't running"}
	}
	return nil
}

func (s *proxyShell) mapRun(out string, err error) (string, error) {
	var ce *cmdError
	if errors.As(err, &ce) {
		if be := s.boxErr(ce.code); be != nil {
			return "", be
		}
	}
	return out, err
}

func (s *proxyShell) mapExec(res *execResult, err error) (*execResult, error) {
	if err == nil && !res.timedOut {
		if be := s.boxErr(res.code); be != nil {
			return nil, be
		}
	}
	return res, err
}

// run runs a driver script where the proxy is and returns its stdout.
func (s *proxyShell) run(ctx context.Context, script string) (string, error) {
	return s.mapRun(s.rootShell.run(ctx, s.wrap(script)))
}

// exec is rootShell.exec where the proxy is.
func (s *proxyShell) exec(ctx context.Context, script string, timeout time.Duration, limit int) (*execResult, error) {
	return s.mapExec(s.rootShell.exec(ctx, s.wrap(script), timeout, limit))
}

// execTo is rootShell.execTo where the proxy is.
func (s *proxyShell) execTo(ctx context.Context, script string, timeout time.Duration, w io.Writer) (*execResult, error) {
	return s.mapExec(s.rootShell.execTo(ctx, s.wrap(script), timeout, w))
}

// hostRun runs a script on the server itself; a host script built with the
// container's Check still fails with a boxError.
func (s *proxyShell) hostRun(ctx context.Context, script string) (string, error) {
	return s.mapRun(s.rootShell.run(ctx, script))
}

func (s *proxyShell) hostExec(ctx context.Context, script string, timeout time.Duration, limit int) (*execResult, error) {
	return s.mapExec(s.rootShell.exec(ctx, script, timeout, limit))
}

func (s *proxyShell) hostExecTo(ctx context.Context, script string, timeout time.Duration, w io.Writer) (*execResult, error) {
	return s.mapExec(s.rootShell.execTo(ctx, script, timeout, w))
}

// info is what the runtime says about the proxy's container (nil on the
// server itself).
func (s *proxyShell) info(ctx context.Context) (*proxy.ContainerInfo, error) {
	if s.box == nil {
		return nil, nil
	}
	b := s.box
	// A missing container: docker prints [] and fails, podman may print
	// nothing.
	out, err := s.hostRun(ctx, proxy.HostPath()+"command -v "+b.Runtime+" >/dev/null 2>&1 || exit "+
		strconv.Itoa(proxy.ExitNoRuntime)+"\n"+b.Host("inspect --type container @ 2>/dev/null")+"\nexit 0\n")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(out) == "" {
		out = "[]"
	}
	list, err := proxy.ParseContainers(b.Runtime, out)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, &boxError{proxy.ExitNoContainer, "There's no container named " + b.Name + " on this server"}
	}
	return &list[0], nil
}

// hostInspect adds what lives on the server to a container's inspection:
// certificates (certbot runs on the server) and certbot itself.
func (s *proxyShell) hostInspect(ctx context.Context, d proxy.Driver, in *proxy.Inspection) {
	if s.box == nil {
		return
	}
	out, err := s.rootShell.run(ctx, d.HostInspectScript())
	if err != nil {
		slog.Warn("proxy host inspection", "container", s.box.Name, "error", err)
		return
	}
	host := d.ParseInspect(out)
	in.Certbot = host.Certbot
	seen := map[string]bool{}
	merged := make([]proxy.Certificate, 0, len(host.Certificates)+len(in.Certificates))
	for _, c := range host.Certificates {
		seen[c.Certificate] = true
		merged = append(merged, c)
	}
	for _, c := range in.Certificates {
		if !seen[c.Certificate] {
			merged = append(merged, c)
		}
	}
	in.Certificates = merged
}

// pushFiles copies the files of the server the sites point at (certificates,
// keys, CA files) into the container before they're written, so a path
// picked on the server works inside too. Files already inside are left
// alone; a file that's on neither side is left to the proxy's test.
func (s *proxyShell) pushFiles(ctx context.Context, files []proxy.File) error {
	if s.box == nil {
		return nil
	}
	var paths []string
	add := func(p string) {
		if p != "" && strings.HasPrefix(p, "/") && !slices.Contains(paths, p) {
			paths = append(paths, p)
		}
	}
	for _, f := range files {
		c := f.Config
		if c.IsCustom() {
			continue
		}
		add(c.TLS.Certificate)
		add(c.TLS.Key)
		add(c.TLS.ClientCA)
		add(c.UpstreamTLS.CA)
		add(c.UpstreamTLS.Certificate)
		add(c.UpstreamTLS.Key)
	}
	if len(paths) == 0 {
		return nil
	}
	res, err := s.hostExec(ctx, s.box.Push(paths...), 2*time.Minute, 16<<10)
	if err != nil {
		var be *boxError
		if errors.As(err, &be) {
			return err
		}
		slog.Warn("push files into the proxy container", "container", s.box.Name, "error", err)
		return nil
	}
	if res.code != 0 {
		slog.Warn("push files into the proxy container", "container", s.box.Name, "output", lastLines(string(res.output), 3))
	}
	return nil
}

// boxProblem is a boxError as an API answer.
func boxProblem(be *boxError) error { return huma.Error409Conflict(be.msg) }

// containerOf is the last inspection of a container proxy's container, nil
// for one on the server or before the first check.
func (h *proxyHandler) containerOf(p sqlc.Proxy) *proxy.ContainerInfo {
	if containerOf(p) == nil {
		return nil
	}
	if v, ok := h.containers.Load(p.ID); ok {
		return v.(*proxy.ContainerInfo)
	}
	return nil
}

// healEvery is how often a container proxy may be set up again by itself.
const healEvery = 5 * time.Minute

// heal sets a container proxy up again when its container was recreated
// (a new image, compose up): its files outside volumes are gone, so the
// panel's sites aren't loaded any more. Only for a proxy that has sites,
// at most once per healEvery. It says whether it changed anything.
func (h *proxyHandler) heal(ctx context.Context, p sqlc.Proxy, d proxy.Driver, sh *proxyShell, in proxy.Inspection) bool {
	if sh.box == nil || !in.Installed || in.SetUp {
		return false
	}
	if v, ok := h.healed.Load(p.ID); ok && time.Since(v.(time.Time)) < healEvery {
		return false
	}
	hosts, err := h.s.q.ListProxyHosts(ctx, p.ID)
	if err != nil || len(hosts) == 0 {
		return false
	}
	h.healed.Store(p.ID, time.Now())
	log := slog.With("proxy", p.ID, "container", sh.box.Name)
	res, err := sh.exec(ctx, d.SetupScript(proxy.Setup{Init: "none", Container: sh.box}), 2*time.Minute, 64<<10)
	if err != nil || res.code != 0 {
		out := ""
		if res != nil {
			out = lastLines(string(res.output), 3)
		}
		log.Warn("set the proxy's container up again", "error", err, "output", out)
		return false
	}
	again, err := inspectWith(ctx, sh, d)
	if err != nil {
		return true
	}
	if err := applyFiles(ctx, sh, d, render(d, hosts, envOf(again)), takeoverOf(hosts, again)); err != nil {
		log.Warn("write the sites into the recreated container", "error", proxyProblemText(err))
	} else {
		log.Info("the proxy's container was recreated; its sites were written again")
	}
	return true
}

// containerAction runs a proxy action on a container: test and reload
// inside it, start/stop/restart through the runtime (restart tests the
// config first).
func containerAction(ctx context.Context, sh *proxyShell, d proxy.Driver, action string) (*execResult, error) {
	b := *sh.box
	host := func(args string) (*execResult, error) {
		script := proxy.HostPath() + "command -v " + b.Runtime + " >/dev/null 2>&1 || exit " +
			strconv.Itoa(proxy.ExitNoRuntime) + "\n" + b.Host(args) + " 2>&1\n"
		return sh.hostExec(ctx, script, 2*time.Minute, 64<<10)
	}
	switch action {
	case "test", "reload":
		script, err := d.ActionScript(action, "none")
		if err != nil {
			return nil, err
		}
		return sh.exec(ctx, script, time.Minute, 64<<10)
	case "restart":
		script, err := d.ActionScript("test", "none")
		if err != nil {
			return nil, err
		}
		res, err := sh.exec(ctx, script, time.Minute, 64<<10)
		if err != nil || res.code != 0 {
			return res, err
		}
		return host("restart @")
	case "start":
		return host("start @")
	case "stop":
		return host("stop @")
	}
	return nil, fieldError("body.action", "Unknown action", action)
}

// containerLogScript reads nginx's own log from the container's output (the
// official images link access.log to stdout and error.log to stderr).
func containerLogScript(b proxy.Container, log string, lines int) string {
	pick := "2>/dev/null | grep -vE '^/docker-entrypoint|^[0-9]+-[A-Za-z0-9_-]+\\.(sh|envsh): '"
	if log == "error" {
		pick = "2>&1 >/dev/null"
	}
	return proxy.HostPath() + b.Host("logs --tail 20000 @ "+pick) + " | tail -n " + strconv.Itoa(lines) + "\nexit 0\n"
}

// markUnpublished flags port forwards a bridged container doesn't publish:
// nothing outside reaches them.
func markUnpublished(ci *proxy.ContainerInfo, hosts []sqlc.ProxyHost, states []ProxyHostState) {
	if ci == nil || ci.HostNetwork() {
		return
	}
	for i := range states {
		for _, x := range hosts {
			if x.ID != states[i].ID || !x.Enabled {
				continue
			}
			c := configOf(x)
			if c.IsStream() && !ci.Published(c.ListenPort, c.Protocol) {
				states[i].Unpublished = true
			}
		}
	}
}

// checkContainer makes sure a container to add as a proxy is on the server
// and isn't a proxy manager that writes its own config.
func (h *proxyHandler) checkContainer(ctx context.Context, serverID uuid.UUID, runtime, name string) error {
	err := h.s.withConn(ctx, serverID.String(), func(c *sshpool.Conn) error {
		sh, err := h.shell(ctx, sqlc.Proxy{ServerID: serverID, Runtime: runtime, Container: name}, c)
		if err != nil {
			return err
		}
		ci, err := sh.info(ctx)
		if err != nil {
			return err
		}
		if ci.Managed != "" {
			return fieldError("body.container", ci.Name+" runs "+ci.Managed+", which writes nginx's config itself. Manage it there.", name)
		}
		return nil
	})
	var be *boxError
	if errors.As(err, &be) {
		return fieldError("body.container", be.msg, name)
	}
	if err != nil {
		return toProblem(err)
	}
	return nil
}

// DetectedContainer is a container that looks like the proxy.
type DetectedContainer struct {
	proxy.ContainerInfo
	Recommended bool   `json:"recommended" doc:"Running, not a proxy manager, and serving the web (80/443 published or the server's network)"`
	ProxyID     string `json:"proxy_id,omitempty" doc:"Already in the panel as this proxy"`
}

// ProxyDetection is where a proxy kind is on a server.
type ProxyDetection struct {
	Kind       string              `json:"kind"`
	Native     proxy.NativeProxy   `json:"native"`
	NativeID   string              `json:"native_id,omitempty" doc:"The one on the server is already in the panel as this proxy"`
	Runtimes   []string            `json:"runtimes"`
	Down       []string            `json:"down,omitempty"`
	Containers []DetectedContainer `json:"containers"`
	Suggestion string              `json:"suggestion" enum:"host,container,choose,install,added" doc:"host: only on the server; container: one container fits; choose: both, or several containers; install: none found; added: everything found is already in the panel"`
}

// registerDetect: look at a server before adding its proxy.
func (h *proxyHandler) registerDetect(api huma.API, tags []string) {
	huma.Register(api, huma.Operation{
		OperationID: "detect-proxy", Method: http.MethodGet, Path: "/servers/{id}/proxy-detect",
		Summary:     "Find a proxy on a server",
		Description: "Looks for the proxy installed on the server and in its Docker / Podman containers, so it can be added the right way. Needs Engineer on the server.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ID   string `path:"id" format:"uuid"`
		Kind string `query:"kind" default:"nginx"`
	}) (*struct{ Body ProxyDetection }, error) {
		d, ok := proxy.Get(in.Kind)
		if !ok {
			return nil, fieldError("query.kind", "Morcheh can't manage this kind of proxy.", in.Kind)
		}
		sid := uuid.MustParse(in.ID)
		var found proxy.Detection
		err := h.s.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.root(ctx, in.ID, c)
			if err != nil {
				return err
			}
			res, err := sh.exec(ctx, d.DetectScript(), time.Minute, 4<<20)
			if err != nil {
				return err
			}
			found = proxy.ParseDetect(string(res.output))
			return nil
		})
		if err != nil {
			return nil, toProblem(err)
		}
		rows, err := h.s.q.ListProxies(ctx, sqlc.ListProxiesParams{SeeAll: true, ServerID: &sid})
		if err != nil {
			return nil, internalError(err)
		}
		out := ProxyDetection{Kind: d.Kind(), Native: found.Native, Runtimes: found.Runtimes, Down: found.Down,
			Containers: make([]DetectedContainer, 0, len(found.Containers))}
		for _, r := range rows {
			if r.Proxy.Kind == d.Kind() && containerOf(r.Proxy) == nil {
				out.NativeID = r.Proxy.ID.String()
			}
		}
		fits, open := 0, 0
		for _, ci := range found.Containers {
			dc := DetectedContainer{ContainerInfo: ci}
			for _, r := range rows {
				if r.Proxy.Kind == d.Kind() && r.Proxy.Runtime == ci.Runtime && r.Proxy.Container == ci.Name {
					dc.ProxyID = r.Proxy.ID.String()
				}
			}
			dc.Recommended = dc.ProxyID == "" && ci.Running && ci.Managed == "" &&
				(ci.HostNetwork() || ci.Published(80, "tcp") || ci.Published(443, "tcp"))
			if dc.Recommended {
				fits++
			}
			if dc.ProxyID == "" && ci.Managed == "" {
				open++
			}
			out.Containers = append(out.Containers, dc)
		}
		native := found.Native.Installed && out.NativeID == ""
		switch {
		case native && open == 0:
			out.Suggestion = "host"
		case !native && open == 1 && fits == 1:
			out.Suggestion = "container"
		case native || open > 0:
			out.Suggestion = "choose"
		case found.Native.Installed || len(found.Containers) > 0:
			out.Suggestion = "added"
		default:
			out.Suggestion = "install"
		}
		return &struct{ Body ProxyDetection }{out}, nil
	})
}
