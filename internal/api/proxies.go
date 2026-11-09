package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/proxy"
	"github.com/morcheh/backend/internal/sshpool"
)

// Reverse proxies: a proxy kind (nginx first) on one of the panel's servers,
// reached over SSH like everything else. The database holds the panel's own
// sites; every change renders all of them and replaces Morcheh's files on the
// server in one go, then tests and reloads, putting the old files back if the
// proxy refuses. Sites written by hand are read, never touched.

type proxyHandler struct {
	s *serverHandler

	mu      sync.Mutex
	locks   map[uuid.UUID]*sync.Mutex
	traffic map[uuid.UUID]*trafficState
	// containers is the last inspection of each container proxy's
	// container (proxy id → *proxy.ContainerInfo).
	containers sync.Map
	// healed is when a container proxy was last set up again by itself
	// (proxy id → time.Time).
	healed sync.Map
}

func newProxyHandler(s *serverHandler) *proxyHandler {
	return &proxyHandler{s: s, locks: map[uuid.UUID]*sync.Mutex{}, traffic: map[uuid.UUID]*trafficState{}}
}

// lock serializes writes to one proxy: each write replaces every file.
func (h *proxyHandler) lock(id uuid.UUID) func() {
	h.mu.Lock()
	l, ok := h.locks[id]
	if !ok {
		l = &sync.Mutex{}
		h.locks[id] = l
	}
	h.mu.Unlock()
	l.Lock()
	return l.Unlock
}

const (
	proxySetupKind  = "proxy-setup"
	proxyGeoKind    = "proxy-geo"
	proxyKeepChange = 50
	proxyNoRoot     = "Managing the proxy needs root or sudo on this server"
)

// proxyModuleKinds are the job kinds that add a module to the proxy, by
// module (proxy.Modules).
var proxyModuleKinds = map[string]string{
	proxy.ModuleBrotli:      "proxy-brotli",
	proxy.ModuleWAF:         "proxy-waf",
	proxy.ModuleImageFilter: "proxy-image-filter",
	proxy.ModuleStreamGeo:   "proxy-stream-geo",
}

// proxyModuleNames name each module in job titles and errors.
var proxyModuleNames = map[string]string{
	proxy.ModuleBrotli:      "Brotli",
	proxy.ModuleWAF:         "the web application firewall",
	proxy.ModuleImageFilter: "image resizing",
	proxy.ModuleStreamGeo:   "country rules for port forwards",
}

// moduleOfKind is the module a job kind adds, "" when it adds none.
func moduleOfKind(kind string) string {
	for m, k := range proxyModuleKinds {
		if k == kind {
			return m
		}
	}
	return ""
}

// isSetupKind says whether a job kind changes the proxy's install.
func isSetupKind(kind string) bool {
	return kind == proxySetupKind || kind == proxyGeoKind || moduleOfKind(kind) != ""
}

// ---- Types ----

type Proxy struct {
	ID            uuid.UUID          `json:"id"`
	ServerID      uuid.UUID          `json:"server_id"`
	ServerName    string             `json:"server_name"`
	ServerHost    string             `json:"server_host"`
	WorkspaceID   uuid.UUID          `json:"workspace_id"`
	ServerStatus  string             `json:"server_status"`
	Kind          string             `json:"kind"`
	KindLabel     string             `json:"kind_label"`
	Runtime       string             `json:"runtime" enum:"host,docker,podman" doc:"host = installed on the server; docker/podman = runs in a container"`
	Container     string             `json:"container,omitempty" doc:"The container's name (docker/podman)"`
	Status        string             `json:"status" enum:"unknown,online,stopped,not_installed,not_set_up,config_error,unreachable,error"`
	StatusMessage string             `json:"status_message"`
	Version       string             `json:"version"`
	HostProblems  int                `json:"host_problems" doc:"Sites whose file on the server isn't what the panel last wrote"`
	HostCount     int                `json:"host_count"`
	LastCheckedAt *time.Time         `json:"last_checked_at,omitempty"`
	CreatedAt     time.Time          `json:"created_at"`
	Capabilities  proxy.Capabilities `json:"capabilities"`
}

type ProxyHost struct {
	ID            uuid.UUID        `json:"id"`
	ProxyID       uuid.UUID        `json:"proxy_id"`
	Domains       []string         `json:"domains"`
	Enabled       bool             `json:"enabled"`
	Config        proxy.HostConfig `json:"config"`
	Note          string           `json:"note"`
	Redacted      bool             `json:"redacted,omitempty" doc:"Header values and raw directives left out (needs Operator)"`
	Handwritten   bool             `json:"handwritten,omitempty" doc:"Its config file is written by hand (config.custom)"`
	CreatedByName string           `json:"created_by_name"`
	UpdatedByName string           `json:"updated_by_name"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at" doc:"Send it back as revision when saving"`
}

type ProxyDetail struct {
	Proxy Proxy       `json:"proxy"`
	Hosts []ProxyHost `json:"hosts"`
}

type ProxyKind struct {
	Kind         string             `json:"kind"`
	Label        string             `json:"label"`
	Capabilities proxy.Capabilities `json:"capabilities"`
}

type ProxySiteRef struct {
	Domain string `json:"domain"`
	File   string `json:"file"`
	Line   int    `json:"line"`
}

type ProxyHostState struct {
	ID          uuid.UUID      `json:"id"`
	State       string         `json:"state" enum:"ok,changed,missing,off" doc:"changed = the file on the server differs from what the panel wrote; missing = not on the server"`
	Conflicts   []ProxySiteRef `json:"conflicts" doc:"Hand-written sites answering the same name"`
	Unpublished bool           `json:"unpublished,omitempty" doc:"A port forward the proxy's container doesn't publish: nothing outside the server reaches it"`
}

type ProxyInspection struct {
	Proxy        Proxy                `json:"proxy"`
	Installed    bool                 `json:"installed"`
	Running      bool                 `json:"running"`
	Enabled      bool                 `json:"enabled" doc:"Starts at boot"`
	SetUp        bool                 `json:"set_up" doc:"The panel's sites are loaded"`
	ConfigOK     bool                 `json:"config_ok"`
	ConfigError  string               `json:"config_error,omitempty"`
	Version      string               `json:"version"`
	IPv6         bool                 `json:"ipv6"`
	Init         string               `json:"init"`
	Sites        []proxy.Site         `json:"sites"`
	Certificates []proxy.Certificate  `json:"certificates"`
	Hosts        []ProxyHostState     `json:"hosts"`
	Unknown      []string             `json:"unknown" doc:"Files in Morcheh's folder the panel doesn't know"`
	HTTP3        bool                 `json:"http3" doc:"The proxy was built with HTTP/3 (QUIC)"`
	Certbot      string               `json:"certbot,omitempty" doc:"certbot's version when it's installed (it renews certificates)"`
	Streams      string               `json:"streams" enum:",ready,no_module,not_wired,taken" doc:"Port forwards: ready; no_module = the stream module is missing; not_wired = setup hasn't added the stream block; taken = nginx.conf has its own stream block. Empty when the kind has no streams"`
	Geo          string               `json:"geo" enum:",ready,off" doc:"Country lookup for country rules: ready, off (not turned on yet). Empty when the kind can't"`
	AuthRequest  bool                 `json:"auth_request" doc:"Signing in through another service (forward auth) works"`
	Brotli       bool                 `json:"brotli" doc:"The Brotli module is loaded"`
	WAF          bool                 `json:"waf" doc:"The web application firewall works: ModSecurity is loaded and Morcheh's rule set is written"`
	ImageFilter  bool                 `json:"image_filter" doc:"The image filter module is loaded (resizing pictures)"`
	StreamGeo    string               `json:"stream_geo" enum:",ready,off" doc:"Country rules for port forwards: ready, off (not turned on yet). Empty when the kind can't"`
	CABundle     string               `json:"ca_bundle,omitempty" doc:"The system's CA file, used to check https upstreams"`
	Container    *proxy.ContainerInfo `json:"container,omitempty" doc:"What the runtime says about the proxy's container (docker/podman only)"`
	Released     []string             `json:"released_default" doc:"Hand-written files Morcheh took default_server from (ports 80 and 443) because one of its sites answers unknown names; they get it back when none does, or when the proxy is removed with its files"`
}

type ProxyChangeSummary struct {
	ID        uuid.UUID `json:"id"`
	UserName  string    `json:"user_name"`
	Summary   string    `json:"summary"`
	HostCount int       `json:"host_count"`
	CreatedAt time.Time `json:"created_at"`
}

type ProxyChangeDetail struct {
	ProxyChangeSummary
	Hosts []ProxyHost `json:"hosts" doc:"Every site as it was right after this change"`
}

type ProxyFleetHost struct {
	Host        ProxyHost `json:"host"`
	Kind        string    `json:"kind"`
	ServerID    uuid.UUID `json:"server_id"`
	ServerName  string    `json:"server_name"`
	Container   string    `json:"container,omitempty" doc:"The proxy's container, when it runs in one"`
	ProxyStatus string    `json:"proxy_status"`
	WorkspaceID uuid.UUID `json:"workspace_id"`
}

type ProxyHostBody struct {
	Config   proxy.HostConfig `json:"config"`
	Enabled  *bool            `json:"enabled,omitempty" doc:"Default true"`
	Note     string           `json:"note,omitempty" maxLength:"2000"`
	Revision *time.Time       `json:"revision,omitempty" doc:"updated_at as you read it; 409 when someone saved since"`
}

type ProxyProblem struct {
	Field   string `json:"field" doc:"Where, like body.config.domains[1]"`
	Message string `json:"message"`
}

type ProxyActionResult struct {
	OK       bool   `json:"ok"`
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output"`
}

// ProxyPurgeBody picks the answers to clear; empty = all of them.
type ProxyPurgeBody struct {
	Paths  []string `json:"paths,omitempty" maxItems:"200" doc:"Addresses: /blog/post (that page, everything under it, any query string), * for any characters (/img/*.png), ?query (/search?q=*), a domain in front (shop.example.com/cart) or a whole URL"`
	Header string   `json:"header,omitempty" maxLength:"64" doc:"Only answers the app sent with this header, like Cache-Tag"`
	Value  string   `json:"value,omitempty" maxLength:"200" doc:"That header's value, or one item of its comma-separated list; * = any characters; empty = any value"`
	Group  string   `json:"group,omitempty" maxLength:"60" doc:"A saved group of the site (cache.groups), instead of paths and header"`
	DryRun bool     `json:"dry_run,omitempty" doc:"Only count what would be cleared"`
}

type ProxyPurgeResult struct {
	OK       bool   `json:"ok"`
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output" doc:"What happened, in words; the script's output when it failed"`
	Matched  int    `json:"matched" doc:"Answers cleared (or, with dry_run, that would be)"`
	Bytes    int64  `json:"bytes" doc:"Their size on disk"`
}

// purgeFilter checks a purge request and turns a group into its filter.
func purgeFilter(b ProxyPurgeBody, c proxy.Cache) (proxy.PurgeFilter, error) {
	if b.Group != "" {
		if len(b.Paths) > 0 || b.Header != "" {
			return proxy.PurgeFilter{}, huma.Error422UnprocessableEntity("Pick a group or addresses, not both")
		}
		g, ok := c.FindGroup(b.Group)
		if !ok {
			return proxy.PurgeFilter{}, huma.Error422UnprocessableEntity("The site has no group " + strconv.Quote(b.Group) + "; save the site first")
		}
		return g.Filter(), nil
	}
	f := proxy.PurgeFilter{Header: strings.TrimSuffix(strings.TrimSpace(b.Header), ":"), Value: strings.TrimSpace(b.Value)}
	var errs []error
	for i, p := range b.Paths {
		if p = strings.TrimSpace(p); p == "" {
			continue
		} else if msg := proxy.CheckPurgePath(p); msg != "" {
			errs = append(errs, &huma.ErrorDetail{Location: fmt.Sprintf("body.paths[%d]", i), Message: msg, Value: p})
		} else if !slices.Contains(f.Paths, p) {
			f.Paths = append(f.Paths, p)
		}
	}
	if field, msg := proxy.CheckPurgeHeader(f.Header, f.Value); msg != "" {
		errs = append(errs, &huma.ErrorDetail{Location: "body." + field, Message: msg})
	}
	if len(errs) > 0 {
		return f, huma.Error422UnprocessableEntity("Check the addresses", errs...)
	}
	return f, nil
}

// purgeSummary says what a purge did, or (dry run) would do.
func purgeSummary(n int, bytes int64, dry, all bool) string {
	what := fmt.Sprintf("%d kept answers", n)
	if n == 1 {
		what = "1 kept answer"
	}
	if n > 0 {
		what += " (" + humanBytes(bytes) + ")"
	}
	switch {
	case n == 0 && all:
		return "The cache is empty."
	case n == 0:
		return "Nothing kept matches."
	case dry && all:
		return what + " in the cache."
	case dry:
		return what + " match."
	}
	return "Cleared " + what + "."
}

type ProxyHostPath struct {
	ID   string `path:"id" format:"uuid"`
	Host string `path:"host" format:"uuid"`
}

type ProxyChangePath struct {
	ID     string `path:"id" format:"uuid"`
	Change string `path:"change" format:"uuid"`
}

type ProxyIDPath struct {
	ID string `path:"id" format:"uuid"`
}

// ---- Conversions ----

func proxyOut(p sqlc.Proxy, name, host string, ws uuid.UUID, serverStatus string, hosts int32) Proxy {
	out := Proxy{
		ID: p.ID, ServerID: p.ServerID, ServerName: name, ServerHost: host, WorkspaceID: ws,
		ServerStatus: serverStatus, Kind: p.Kind, KindLabel: p.Kind, Status: p.Status,
		StatusMessage: p.StatusMessage, Version: p.Version, HostProblems: int(p.HostProblems),
		HostCount: int(hosts), LastCheckedAt: p.LastCheckedAt, CreatedAt: p.CreatedAt,
		Capabilities: proxy.Capabilities{Types: []string{}},
		Runtime:      p.Runtime, Container: p.Container,
	}
	if out.Runtime == "" {
		out.Runtime = proxy.RuntimeHost
	}
	if d, ok := proxy.Get(p.Kind); ok {
		out.KindLabel, out.Capabilities = d.Label(), d.Capabilities()
	}
	return out
}

func proxyRowOut(r sqlc.GetProxyRow) Proxy {
	return proxyOut(r.Proxy, r.ServerName, r.ServerHost, r.WorkspaceID, r.ServerStatus, r.HostCount)
}

func hostOut(h sqlc.ProxyHost, full bool) ProxyHost {
	var cfg proxy.HostConfig
	_ = json.Unmarshal(h.Config, &cfg)
	cfg.Domains = h.Domains
	out := ProxyHost{
		ID: h.ID, ProxyID: h.ProxyID, Domains: h.Domains, Enabled: h.Enabled, Config: cfg,
		Note: h.Note, CreatedByName: h.CreatedByName, UpdatedByName: h.UpdatedByName,
		CreatedAt: h.CreatedAt, UpdatedAt: h.UpdatedAt, Handwritten: cfg.IsCustom(),
	}
	if !full {
		out.Config, out.Redacted = redactHost(cfg), true
	}
	out.Config = withoutPasswords(out.Config)
	return out
}

// snapshotOf is every host as stored, password hashes included, for the
// history (going back must keep the sign-ins).
func snapshotOf(rows []sqlc.ProxyHost) []ProxyHost {
	out := make([]ProxyHost, len(rows))
	for i, r := range rows {
		out[i] = hostOut(r, true)
		out[i].Config.Auth.Users = configOf(r).Auth.Users
	}
	return out
}

// redactHost hides what may hold secrets (tokens in headers, raw config)
// from Viewers.
func redactHost(c proxy.HostConfig) proxy.HostConfig {
	headers := make([]proxy.HeaderRule, len(c.Headers))
	for i, x := range c.Headers {
		headers[i] = proxy.HeaderRule{To: x.To, Name: x.Name}
	}
	c.Headers = headers
	paths := make([]proxy.PathRule, len(c.Paths))
	for i, p := range c.Paths {
		p.Advanced = ""
		paths[i] = p
	}
	c.Paths = paths
	c.Advanced = ""
	c.Custom = ""
	return c
}

func hostsOut(rows []sqlc.ProxyHost, full bool) []ProxyHost {
	out := make([]ProxyHost, len(rows))
	for i, r := range rows {
		out[i] = hostOut(r, full)
	}
	return out
}

func (h *proxyHandler) getProxy(ctx context.Context, rawID string) (sqlc.GetProxyRow, proxy.Driver, error) {
	r, err := h.s.q.GetProxy(ctx, uuid.MustParse(rawID))
	if isNotFound(err) {
		return r, nil, huma.Error404NotFound("proxy not found")
	}
	if err != nil {
		return r, nil, internalError(err)
	}
	d, ok := proxy.Get(r.Proxy.Kind)
	if !ok {
		return r, nil, huma.Error422UnprocessableEntity("This version of Morcheh can't manage " + r.Proxy.Kind)
	}
	return r, d, nil
}

func (h *proxyHandler) detail(ctx context.Context, rawID string) (*ProxyDetail, error) {
	r, _, err := h.getProxy(ctx, rawID)
	if err != nil {
		return nil, err
	}
	hosts, err := h.s.q.ListProxyHosts(ctx, r.Proxy.ID)
	if err != nil {
		return nil, internalError(err)
	}
	return &ProxyDetail{Proxy: proxyRowOut(r), Hosts: hostsOut(hosts, canSeeSecrets(ctx))}, nil
}

// canSeeSecrets: the caller has Operator on the proxy in the path.
func canSeeSecrets(ctx context.Context) bool {
	p := principalOf(ctx)
	return p == nil || p.Level >= auth.Operator
}

// ---- SSH ----

// root opens a root shell on the proxy's server.
func (h *proxyHandler) root(ctx context.Context, serverID string, c *sshpool.Conn) (*rootShell, error) {
	sh, err := h.s.rootShell(ctx, serverID, c)
	if err != nil {
		return nil, err
	}
	if sh.priv == privUser {
		return nil, huma.Error403Forbidden(proxyNoRoot)
	}
	return sh, nil
}

// inspect reads the proxy's state on its server. For a container it also
// reads the container (sh.ci), and the certificates and certbot on the
// server itself.
func inspectWith(ctx context.Context, sh *proxyShell, d proxy.Driver) (proxy.Inspection, error) {
	if sh.box != nil {
		ci, err := sh.info(ctx)
		if err != nil {
			return proxy.Inspection{}, err
		}
		sh.ci = ci
		if !ci.Running {
			return proxy.Inspection{}, &boxError{proxy.ExitContainerStopped, "The container " + ci.Name + " isn't running"}
		}
	}
	out, err := sh.run(ctx, d.InspectScript())
	if err != nil {
		return proxy.Inspection{}, err
	}
	in := d.ParseInspect(out)
	if sh.box != nil {
		sh.hostInspect(ctx, d, &in)
		in.Init = sh.box.Runtime
		in.Enabled = sh.ci.Restart == "always" || sh.ci.Restart == "unless-stopped"
	}
	return in, nil
}

// modulesMissing refuses to write sites that use something the proxy on
// this server can't do yet (a module that isn't added).
func modulesMissing(d proxy.Driver, in proxy.Inspection, hosts []sqlc.ProxyHost) error {
	uses := func(fn func(c proxy.HostConfig) bool) bool {
		return slices.ContainsFunc(hosts, func(x sqlc.ProxyHost) bool {
			c := configOf(x)
			return x.Enabled && !c.IsCustom() && fn(c)
		})
	}
	stream := func(c proxy.HostConfig) bool { return c.Type == proxy.TypeStream }
	switch {
	case in.Geo != "ready" && uses(func(c proxy.HostConfig) bool { return !stream(c) && len(c.Countries) > 0 }):
		return fieldError("body.config.countries", "Country lookup isn't on for this proxy yet: turn it on in Security first.", nil)
	case in.StreamGeo != "ready" && uses(func(c proxy.HostConfig) bool { return stream(c) && len(c.Countries) > 0 }):
		return fieldError("body.config.countries", "Country rules for port forwards aren't on for this proxy yet: turn them on first.", nil)
	case !in.WAF && uses(func(c proxy.HostConfig) bool { return c.WAF.On() }):
		return fieldError("body.config.waf.mode", d.Label()+" on this server has no web application firewall yet: add it first.", nil)
	case !in.ImageFilter && uses(func(c proxy.HostConfig) bool { return c.Images.Enabled }):
		return fieldError("body.config.images.enabled", d.Label()+" on this server has no image filter module yet: add it first.", nil)
	}
	return nil
}

// streamGeoState is the inspection's country lookup state for port
// forwards, "" when the kind can't.
func streamGeoState(d proxy.Driver, in proxy.Inspection) string {
	if !d.Capabilities().Countries || !d.Capabilities().Streams || !in.Installed {
		return ""
	}
	return in.StreamGeo
}

// geoState is the inspection's country lookup state, "" when the kind can't.
func geoState(d proxy.Driver, in proxy.Inspection) string {
	if !d.Capabilities().Countries || !in.Installed {
		return ""
	}
	return in.Geo
}

func envOf(in proxy.Inspection) proxy.Env {
	return proxy.Env{
		Version: in.Version, IPv6: in.IPv6, Brotli: in.Brotli, CABundle: in.CABundle,
		WAF: in.WAF, ImageFilter: in.ImageFilter,
	}
}

// configOf is a stored host's settings.
func configOf(x sqlc.ProxyHost) proxy.HostConfig {
	var cfg proxy.HostConfig
	_ = json.Unmarshal(x.Config, &cfg)
	cfg.Domains = x.Domains
	return cfg
}

// render builds the file of every enabled host.
func render(d proxy.Driver, hosts []sqlc.ProxyHost, env proxy.Env) []proxy.File {
	files := []proxy.File{}
	quic := false
	for _, x := range hosts {
		if !x.Enabled {
			continue
		}
		cfg := configOf(x)
		e := env
		// One HTTP/3 site carries reuseport for every one on the server.
		if cfg.TLS.HTTP3 && !cfg.IsCustom() && !quic {
			e.QUICReuseport, quic = true, true
		}
		files = append(files, proxy.File{ID: x.ID.String(), Config: cfg, Text: proxy.FileText(d, x.ID.String(), cfg, e)})
	}
	return files
}

// takeoverOf says what happens to the hand-written default server: an
// enabled catch-all site of Morcheh's takes it over, else it goes back.
func takeoverOf(hosts []sqlc.ProxyHost, in proxy.Inspection) proxy.Takeover {
	hold := slices.ContainsFunc(hosts, func(x sqlc.ProxyHost) bool {
		c := configOf(x)
		return x.Enabled && c.CatchAll && !c.IsCustom()
	})
	t := proxy.Takeover{Hold: hold}
	if hold {
		t.From = proxy.DefaultHolders(in.Sites)
	}
	return t
}

// applyFiles replaces Morcheh's files on the server and reloads.
func applyFiles(ctx context.Context, sh *proxyShell, d proxy.Driver, files []proxy.File, t proxy.Takeover) error {
	if err := sh.pushFiles(ctx, files); err != nil {
		return err
	}
	res, err := sh.exec(ctx, d.ApplyScript(files, t), 2*time.Minute, 64<<10)
	if err != nil {
		return err
	}
	out := strings.TrimSpace(string(res.output))
	switch {
	case res.timedOut:
		return huma.Error422UnprocessableEntity(d.Label() + " didn't answer in time; nothing was changed")
	case res.code == 0:
		return nil
	case res.code == proxy.ExitNotInstalled:
		return huma.Error409Conflict(d.Label() + " isn't installed on this server. Set it up first.")
	case res.code == proxy.ExitTestFailed:
		return huma.Error422UnprocessableEntity(d.Label() + " refused the change, so nothing was changed: " + out)
	case res.code == proxy.ExitReloadFailed:
		return huma.Error422UnprocessableEntity(d.Label() + " couldn't reload, so the old sites were put back: " + out)
	case res.code == proxy.ExitNoStreams, res.code == proxy.ExitPortTaken:
		return fieldError("body.config.listen_port", lastLines(out, 1)+" Nothing was changed.", nil)
	}
	return huma.Error422UnprocessableEntity(fmt.Sprintf("Writing the sites failed (exit %d): %s", res.code, lastLines(out, 5)))
}

// ---- Checks ----

// states compares what's on the server with what the panel wrote.
func states(d proxy.Driver, hosts []sqlc.ProxyHost, in proxy.Inspection) ([]ProxyHostState, []string, int) {
	files := map[string]string{}
	for _, f := range render(d, hosts, envOf(in)) {
		files[f.ID] = f.Text
	}
	out := make([]ProxyHostState, 0, len(hosts))
	problems := 0
	known := map[string]bool{}
	for _, x := range hosts {
		id := x.ID.String()
		known[id] = true
		st := ProxyHostState{ID: x.ID, State: "ok", Conflicts: []ProxySiteRef{}}
		have, onServer := in.Files[id]
		switch {
		case !x.Enabled && onServer:
			st.State = "changed"
		case !x.Enabled:
			st.State = "off"
		case !onServer:
			st.State = "missing"
		case have != files[id]:
			st.State = "changed"
		}
		if st.State == "changed" || st.State == "missing" {
			problems++
		}
		if x.Enabled {
			for _, s := range in.Sites {
				if s.Managed {
					continue
				}
				for _, dom := range proxy.Overlaps(x.Domains, s.Domains) {
					st.Conflicts = append(st.Conflicts, ProxySiteRef{Domain: dom, File: s.File, Line: s.Line})
				}
			}
		}
		out = append(out, st)
	}
	unknown := []string{}
	for id := range in.Files {
		if !known[id] {
			unknown = append(unknown, id)
		}
	}
	slices.Sort(unknown)
	return out, unknown, problems + len(unknown)
}

func statusOf(in proxy.Inspection, label string) (string, string) {
	switch {
	case !in.Installed:
		return "not_installed", label + " isn't installed"
	case !in.SetUp:
		return "not_set_up", label + " is installed but doesn't load the panel's sites yet"
	case !in.ConfigOK:
		return "config_error", in.ConfigError
	case !in.Running:
		return "stopped", label + " isn't running"
	}
	return "online", ""
}

// check inspects a proxy and records what it found. The inspection is nil
// when the server couldn't be read.
func (h *proxyHandler) check(ctx context.Context, p sqlc.Proxy, d proxy.Driver) (*proxy.Inspection, []ProxyHostState, []string, error) {
	var in proxy.Inspection
	var ci *proxy.ContainerInfo
	err := h.s.withConn(ctx, p.ServerID.String(), func(c *sshpool.Conn) error {
		sh, err := h.shell(ctx, p, c)
		if err != nil {
			return err
		}
		in, err = inspectWith(ctx, sh, d)
		ci = sh.ci
		if err == nil && h.heal(ctx, p, d, sh, in) {
			in, err = inspectWith(ctx, sh, d)
		}
		return err
	})
	rec := sqlc.RecordProxyCheckParams{ID: p.ID}
	var hs []ProxyHostState
	unknown := []string{}
	var be *boxError
	if errors.As(err, &be) {
		// The container is the proxy: a stopped one is a stopped proxy.
		rec.Status, rec.StatusMessage = "error", be.msg
		if be.stopped() {
			rec.Status = "stopped"
		}
		if rerr := h.s.q.RecordProxyCheck(context.WithoutCancel(ctx), rec); rerr != nil {
			slog.Warn("record proxy check", "proxy", p.ID, "error", rerr)
		}
		if be.stopped() && ci != nil {
			stopped := proxy.Inspection{}
			stopped.Installed, stopped.SetUp, stopped.ConfigOK = true, true, true
			stopped.Init = ci.Runtime
			stopped.Enabled = ci.Restart == "always" || ci.Restart == "unless-stopped"
			h.containers.Store(p.ID, ci)
			return &stopped, []ProxyHostState{}, []string{}, nil
		}
		return nil, nil, nil, err
	}
	if ci != nil {
		h.containers.Store(p.ID, ci)
	}
	if err != nil {
		rec.Status, rec.StatusMessage = "unreachable", proxyProblemText(err)
		var se huma.StatusError
		if errors.As(err, &se) && se.GetStatus() == http.StatusForbidden {
			rec.Status = "error"
		}
	} else {
		hosts, herr := h.s.q.ListProxyHosts(ctx, p.ID)
		if herr != nil {
			return nil, nil, nil, internalError(herr)
		}
		var problems int
		hs, unknown, problems = states(d, hosts, in)
		markUnpublished(ci, hosts, hs)
		rec.Status, rec.StatusMessage = statusOf(in, d.Label())
		rec.Version, rec.HostProblems = in.Version, int32(problems)
	}
	if rerr := h.s.q.RecordProxyCheck(context.WithoutCancel(ctx), rec); rerr != nil {
		slog.Warn("record proxy check", "proxy", p.ID, "error", rerr)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	return &in, hs, unknown, nil
}

// proxyProblemText is an error as the panel shows it.
func proxyProblemText(err error) string {
	var se huma.StatusError
	if errors.As(toProblem(err), &se) {
		var m *huma.ErrorModel
		if errors.As(se, &m) {
			return m.Detail
		}
		return se.Error()
	}
	return err.Error()
}

// refresh re-checks a proxy in the background after a change.
func (h *proxyHandler) refresh(id uuid.UUID) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		r, err := h.s.q.GetProxy(ctx, id)
		if err != nil {
			return
		}
		if d, ok := proxy.Get(r.Proxy.Kind); ok {
			_, _, _, _ = h.check(ctx, r.Proxy, d)
		}
	}()
}

// ---- Writes ----

func actorName(ctx context.Context) (string, *uuid.UUID) {
	p := principalOf(ctx)
	if p == nil {
		return "Morcheh", nil
	}
	return displayName(p.User), p.ID()
}

// write runs one change: edit the rows in a transaction, render every enabled
// host, replace the files on the server and reload, then keep a snapshot in
// the history. Nothing is saved when the proxy refuses the change.
func (h *proxyHandler) write(ctx context.Context, rawID string, edit func(q *sqlc.Queries, proxyID uuid.UUID) (string, error)) (*ProxyDetail, error) {
	r, d, err := h.getProxy(ctx, rawID)
	if err != nil {
		return nil, err
	}
	defer h.lock(r.Proxy.ID)()

	tx, err := h.s.db.Begin(ctx)
	if err != nil {
		return nil, internalError(err)
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck
	q := h.s.q.WithTx(tx)
	summary, err := edit(q, r.Proxy.ID)
	if err != nil {
		return nil, err
	}
	hosts, err := q.ListProxyHosts(ctx, r.Proxy.ID)
	if err != nil {
		return nil, internalError(err)
	}
	if err := checkOverlaps(hosts); err != nil {
		return nil, err
	}

	err = h.s.withConn(ctx, r.Proxy.ServerID.String(), func(c *sshpool.Conn) error {
		sh, err := h.shell(ctx, r.Proxy, c)
		if err != nil {
			return err
		}
		in, err := inspectWith(ctx, sh, d)
		if err != nil {
			return err
		}
		if !in.Installed {
			return huma.Error409Conflict(d.Label() + " isn't installed on this server. Set it up first.")
		}
		if err := modulesMissing(d, in, hosts); err != nil {
			return err
		}
		if !in.AuthRequest && slices.ContainsFunc(hosts, func(x sqlc.ProxyHost) bool {
			c := configOf(x)
			return x.Enabled && !c.IsCustom() && c.Auth.Mode == "forward"
		}) {
			return fieldError("body.config.auth.mode", d.Label()+" on this server has no auth_request module, which signing in through another service needs.", nil)
		}
		return applyFiles(ctx, sh, d, render(d, hosts, envOf(in)), takeoverOf(hosts, in))
	})
	if err != nil {
		return nil, toProblem(err)
	}

	snap, err := json.Marshal(snapshotOf(hosts))
	if err != nil {
		return nil, internalError(err)
	}
	name, uid := actorName(ctx)
	if err := q.AddProxyChange(ctx, sqlc.AddProxyChangeParams{
		ProxyID: r.Proxy.ID, UserID: uid, UserName: name, Summary: summary, Hosts: snap,
	}); err != nil {
		return nil, internalError(err)
	}
	if err := q.PruneProxyChanges(ctx, sqlc.PruneProxyChangesParams{ProxyID: r.Proxy.ID, Keep: proxyKeepChange}); err != nil {
		return nil, internalError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, internalError(err)
	}
	h.refresh(r.Proxy.ID)
	return h.detail(ctx, rawID)
}

// checkOverlaps refuses two sites answering the same name, and two forwards
// on the same port.
func checkOverlaps(hosts []sqlc.ProxyHost) error {
	ports := map[string]bool{}
	catchAll := false
	for i, a := range hosts {
		if c := configOf(a); c.CatchAll && a.Enabled && !c.IsCustom() {
			if catchAll {
				return fieldError("body.config.catch_all", "Another site here already answers unknown names. Turn that one off first.", nil)
			}
			catchAll = true
		}
		for _, b := range hosts[i+1:] {
			if dup := proxy.Overlaps(a.Domains, b.Domains); len(dup) > 0 {
				return fieldError("body.config.domains", fmt.Sprintf("%s is already used by another site here.", dup[0]), dup[0])
			}
		}
		if c := configOf(a); c.IsStream() && a.Enabled {
			key := fmt.Sprintf("%s/%d", c.Protocol, c.ListenPort)
			if ports[key] {
				return fieldError("body.config.listen_port", fmt.Sprintf("Port %d (%s) is already forwarded by another stream here.", c.ListenPort, strings.ToUpper(c.Protocol)), c.ListenPort)
			}
			ports[key] = true
		}
	}
	return nil
}

// cleanHost normalizes and checks a host; problems come back as field errors.
func cleanHost(d proxy.Driver, c proxy.HostConfig) (proxy.HostConfig, error) {
	c = proxy.Normalize(c)
	probs := append(proxy.Validate(c), d.Validate(c)...)
	if len(probs) == 0 {
		return c, nil
	}
	details := make([]error, len(probs))
	for i, p := range probs {
		details[i] = &huma.ErrorDetail{Location: "body.config." + p.Field, Message: p.Message, Value: p.Value}
	}
	return c, huma.Error422UnprocessableEntity(probs[0].Message, details...)
}

// hostLabel names a site in the history: its first domain, or a forward's
// port.
func hostLabel(c proxy.HostConfig) string {
	if c.IsStream() {
		return fmt.Sprintf("%s port %d", strings.ToUpper(c.Protocol), c.ListenPort)
	}
	domains := c.Domains
	if len(domains) == 0 {
		return "a site"
	}
	if len(domains) == 1 {
		return domains[0]
	}
	return domains[0] + " (+" + strconv.Itoa(len(domains)-1) + ")"
}

// ---- Setup job ----

type proxySetupParams struct {
	ProxyID  string `json:"proxy_id"`
	ServerID string `json:"server_id"`
}

// submitSetup starts kind proxySetupKind (install and wire up),
// proxyGeoKind (turn the country lookup on) or one of proxyModuleKinds (add
// a module); one at a time per proxy.
func (h *proxyHandler) submitSetup(ctx context.Context, rawID, kind string) (*JobOutput, error) {
	r, d, err := h.getProxy(ctx, rawID)
	if err != nil {
		return nil, err
	}
	server := r.Proxy.ServerID.String()
	if box := containerOf(r.Proxy); box != nil && kind != proxySetupKind {
		what := "Country lookup"
		if m := moduleOfKind(kind); m != "" {
			what = proxyModuleNames[m]
		}
		return nil, huma.Error422UnprocessableEntity(what + " can't be added to " + d.Label() + " in the container " + box.Name +
			": Morcheh doesn't change a container's image. Use an image that has it, then check the proxy again.")
	}
	err = h.s.withConn(ctx, server, func(c *sshpool.Conn) error {
		_, err := h.shell(ctx, r.Proxy, c)
		return err
	})
	if err != nil {
		return nil, toProblem(err)
	}
	refs := placeRefs(rawID, server)
	active := true
	list, err := h.s.jobs.List(ctx, sqlc.ListJobsParams{Ref: &refs[0], Active: &active, Lim: 200})
	if err != nil {
		return nil, internalError(err)
	}
	if slices.ContainsFunc(list, func(j sqlc.Job) bool {
		return isSetupKind(j.Kind)
	}) {
		return nil, huma.Error409Conflict(d.Label() + " is already being set up on this server")
	}
	title := "Set up " + d.Label() + " on " + r.ServerName
	if kind == proxyGeoKind {
		if !d.Capabilities().Countries {
			return nil, huma.Error422UnprocessableEntity(d.Label() + " can't limit by country")
		}
		title = "Turn on country lookup on " + r.ServerName
	}
	if m := moduleOfKind(kind); m != "" {
		title = "Add " + proxyModuleNames[m] + " to " + d.Label() + " on " + r.ServerName
	}
	return submit(ctx, h.s.jobs, jobs.Spec{
		Kind: kind, Title: title,
		Params: proxySetupParams{ProxyID: rawID, ServerID: server}, Refs: refs,
	})
}

// runSetup installs the proxy when it's missing (the package manager can't be
// stopped half way, so the job is locked then), wires in Morcheh's folder,
// starts it and writes the panel's sites. proxyGeoKind turns the country
// lookup on instead; a module kind adds that module, then writes the sites
// again so those using it start to.
func (h *proxyHandler) runSetup(ctx context.Context, t *jobs.Task, kind string) (any, error) {
	geo, module := kind == proxyGeoKind, moduleOfKind(kind)
	mod := module != ""
	var p proxySetupParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	r, d, err := h.getProxy(ctx, p.ProxyID)
	if err != nil {
		return nil, jobError(err)
	}
	err = h.s.withConn(ctx, p.ServerID, func(c *sshpool.Conn) error {
		sh, err := h.shell(ctx, r.Proxy, c)
		if err != nil {
			return err
		}
		if (geo || mod) && sh.box != nil {
			return fmt.Errorf("Morcheh doesn't change a container's image: use one that has it")
		}
		facts, err := sh.hostRun(ctx, hostScript)
		if err != nil {
			return err
		}
		f := parseHost(facts)
		install := func(pkgs ...string) string {
			s, err := packageScript(f.pm, "install", pkgs...)
			if err != nil {
				return "echo 'No package manager Morcheh knows here: install " + strings.Join(pkgs, " ") + " by hand, then set it up again.'; false"
			}
			return s
		}
		t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Locked = "Setting up", sh.box == nil })
		var last string
		lines := &lineWriter{fn: func(l string) {
			last = l
			t.Logf("%s", l)
			t.Update(func(pr *jobs.Progress) { pr.Current = l })
		}}
		su := proxy.Setup{Init: f.init, PM: f.pm, Install: install, Container: sh.box}
		script := d.SetupScript(su)
		switch {
		case geo:
			script = d.GeoScript(su)
		case mod:
			script = d.ModuleScript(module, su)
		}
		res, err := sh.execTo(ctx, script, packageTimeout, lines)
		lines.flush()
		switch {
		case err != nil:
			return err
		case res.timedOut:
			return fmt.Errorf("It took longer than %d minutes, so Morcheh stopped waiting", int(packageTimeout.Minutes()))
		case geo && res.code == proxy.ExitNotInstalled:
			return fmt.Errorf("%s isn't installed on this server. Set it up first", d.Label())
		case geo && res.code == proxy.ExitTestFailed:
			return fmt.Errorf("Country lookup couldn't be turned on: %s", last)
		case geo && res.code == proxy.ExitReloadFailed:
			return fmt.Errorf("%s didn't reload: %s", d.Label(), last)
		case geo && res.code != 0:
			return fmt.Errorf("Turning on country lookup failed (exit %d): %s", res.code, last)
		case geo:
			return nil
		case mod && res.code == proxy.ExitNotInstalled:
			return fmt.Errorf("%s isn't installed on this server. Set it up first", d.Label())
		case mod && res.code == proxy.ExitTestFailed:
			return fmt.Errorf("Adding %s didn't work: %s", proxyModuleNames[module], last)
		case mod && res.code == proxy.ExitReloadFailed:
			return fmt.Errorf("%s didn't reload: %s", d.Label(), last)
		case mod && res.code != 0:
			return fmt.Errorf("Adding %s failed: %s", proxyModuleNames[module], last)
		case res.code == proxy.ExitTestFailed:
			return fmt.Errorf("%s's configuration has a problem, so it wasn't started: %s", d.Label(), last)
		case res.code == proxy.ExitReloadFailed:
			return fmt.Errorf("%s didn't start: %s", d.Label(), last)
		case res.code != 0:
			return fmt.Errorf("Setting up failed (exit %d): %s", res.code, last)
		}
		if sh.box != nil {
			t.Logf("Setting up log rotation on the server…")
			res, err := sh.hostExecTo(ctx, d.HostSetupScript(*sh.box), time.Minute, lines)
			lines.flush()
			switch {
			case err != nil:
				return err
			case res.code != 0:
				return fmt.Errorf("Setting up the server's side failed (exit %d): %s", res.code, last)
			}
		}
		hosts, err := h.s.q.ListProxyHosts(ctx, r.Proxy.ID)
		if err != nil || len(hosts) == 0 {
			return err
		}
		t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Locked, pr.Current = "Writing sites", false, "" })
		t.Logf("Writing %d site(s)…", len(hosts))
		in, err := inspectWith(ctx, sh, d)
		if err != nil {
			return err
		}
		if err := applyFiles(ctx, sh, d, render(d, hosts, envOf(in)), takeoverOf(hosts, in)); err != nil {
			return errors.New(proxyProblemText(err))
		}
		return nil
	})
	h.refresh(r.Proxy.ID)
	if err != nil {
		var se huma.StatusError
		if errors.As(err, &se) {
			err = errors.New(proxyProblemText(err))
		}
	}
	return nil, jobError(err)
}

// ---- Routes ----

func registerProxies(api huma.API, h *proxyHandler) {
	tags := []string{"Reverse proxy"}
	h.registerTraffic(api, tags)
	h.registerRequests(api, tags)
	base := "/proxies/{id}"
	registerProxyCertificates(api, h, base, tags)
	h.registerUpstreamTest(api, base, tags)
	h.registerDetect(api, tags)
	h.registerKeptPages(api, base, tags)

	huma.Register(api, huma.Operation{
		OperationID: "list-proxy-kinds", Method: http.MethodGet, Path: "/proxy-kinds",
		Summary: "Proxy kinds Morcheh can manage", Tags: tags,
	}, func(ctx context.Context, _ *struct{}) (*struct {
		Body struct {
			Items []ProxyKind `json:"items"`
		}
	}, error) {
		out := &struct {
			Body struct {
				Items []ProxyKind `json:"items"`
			}
		}{}
		out.Body.Items = []ProxyKind{}
		for _, d := range proxy.Kinds() {
			out.Body.Items = append(out.Body.Items, ProxyKind{Kind: d.Kind(), Label: d.Label(), Capabilities: d.Capabilities()})
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-proxies", Method: http.MethodGet, Path: "/proxies",
		Summary: "Reverse proxies you can see", Tags: tags,
	}, func(ctx context.Context, in *struct {
		ServerID string `query:"server_id" format:"uuid" doc:"Only this server's"`
	}) (*struct {
		Body struct {
			Items []Proxy `json:"items"`
		}
	}, error) {
		sc := principalOf(ctx).scope()
		rows, err := h.s.q.ListProxies(ctx, sqlc.ListProxiesParams{
			SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, ServerIds: sc.servers, WorkspaceID: sc.current,
			ServerID: parseOptionalID(&in.ServerID),
		})
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []Proxy `json:"items"`
			}
		}{}
		out.Body.Items = make([]Proxy, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = proxyOut(r.Proxy, r.ServerName, r.ServerHost, r.WorkspaceID, r.ServerStatus, r.HostCount)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-proxy-hosts-everywhere", Method: http.MethodGet, Path: "/proxy-hosts",
		Summary: "Every site on every proxy you can see", Tags: tags,
	}, func(ctx context.Context, _ *struct{}) (*struct {
		Body struct {
			Items []ProxyFleetHost `json:"items"`
		}
	}, error) {
		p := principalOf(ctx)
		sc := p.scope()
		rows, err := h.s.q.ListProxyHostsEverywhere(ctx, sqlc.ListProxyHostsEverywhereParams{
			SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, ServerIds: sc.servers, WorkspaceID: sc.current,
		})
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []ProxyFleetHost `json:"items"`
			}
		}{}
		out.Body.Items = make([]ProxyFleetHost, len(rows))
		for i, r := range rows {
			full := p.Access.ServerLevel(r.WorkspaceID, r.ServerID) >= auth.Operator
			out.Body.Items[i] = ProxyFleetHost{
				Host: hostOut(r.ProxyHost, full), Kind: r.Kind, ServerID: r.ServerID,
				ServerName: r.ServerName, Container: r.Container, ProxyStatus: r.ProxyStatus, WorkspaceID: r.WorkspaceID,
			}
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-proxy", Method: http.MethodPost, Path: "/proxies",
		Summary:     "Manage a proxy on a server",
		Description: "Adds the proxy to the panel and checks the server. Nothing is installed or written yet: call setup for that. Needs Engineer on the server.",
		Tags:        tags, DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		Body struct {
			ServerID  string `json:"server_id" format:"uuid"`
			Kind      string `json:"kind" example:"nginx"`
			Runtime   string `json:"runtime,omitempty" enum:"host,docker,podman" default:"host" doc:"Where the proxy runs: on the server itself, or in a Docker / Podman container"`
			Container string `json:"container,omitempty" maxLength:"128" doc:"The container's name, for docker and podman"`
		}
	}) (*struct{ Body Proxy }, error) {
		d, ok := proxy.Get(in.Body.Kind)
		if !ok {
			return nil, fieldError("body.kind", "Morcheh can't manage this kind of proxy.", in.Body.Kind)
		}
		sid := uuid.MustParse(in.Body.ServerID)
		level, err := h.s.authz.serverLevel(ctx, principalOf(ctx).Access, sid)
		if err != nil {
			return nil, internalError(err)
		}
		switch {
		case level == auth.None:
			return nil, huma.Error404NotFound("server not found")
		case level < auth.Engineer:
			return nil, forbidden(auth.Engineer)
		}
		rt, box := in.Body.Runtime, strings.TrimSpace(in.Body.Container)
		if rt == "" {
			rt = proxy.RuntimeHost
		}
		if rt == proxy.RuntimeHost {
			box = ""
		} else {
			if !proxy.ValidContainerName(box) {
				return nil, fieldError("body.container", "Give the container's name.", box)
			}
			if err := h.checkContainer(ctx, sid, rt, box); err != nil {
				return nil, err
			}
		}
		p, err := h.s.q.CreateProxy(ctx, sqlc.CreateProxyParams{ServerID: sid, Kind: d.Kind(), Runtime: rt, Container: box})
		if isUniqueViolation(err) {
			if box != "" {
				return nil, huma.Error409Conflict("The container " + box + " is already in the panel.")
			}
			return nil, huma.Error409Conflict("This server already has " + d.Label() + " in the panel.")
		}
		if err != nil {
			return nil, internalError(err)
		}
		h.refresh(p.ID)
		r, _, err := h.getProxy(ctx, p.ID.String())
		if err != nil {
			return nil, err
		}
		return &struct{ Body Proxy }{proxyRowOut(r)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-proxy", Method: http.MethodGet, Path: base,
		Summary: "A proxy and its sites", Tags: tags,
	}, func(ctx context.Context, in *ProxyIDPath) (*struct{ Body ProxyDetail }, error) {
		out, err := h.detail(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body ProxyDetail }{*out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "inspect-proxy", Method: http.MethodGet, Path: base + "/inspect",
		Summary:     "Read the proxy's live state from its server",
		Description: "Status, every site in its live config (text only for Operator+), certificates found, and whether each panel site's file is what the panel wrote. Also records the check.",
		Tags:        tags,
	}, func(ctx context.Context, in *ProxyIDPath) (*struct{ Body ProxyInspection }, error) {
		r, d, err := h.getProxy(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		ins, hs, unknown, err := h.check(ctx, r.Proxy, d)
		if err != nil {
			return nil, toProblem(err)
		}
		r, _, err = h.getProxy(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		sites := ins.Sites
		if sites == nil {
			sites = []proxy.Site{}
		}
		if !canSeeSecrets(ctx) {
			for i := range sites {
				sites[i].Text = ""
			}
		}
		certs := ins.Certificates
		if certs == nil {
			certs = []proxy.Certificate{}
		}
		released := ins.Released
		if released == nil {
			released = []string{}
		}
		return &struct{ Body ProxyInspection }{ProxyInspection{
			Proxy: proxyRowOut(r), Installed: ins.Installed, Running: ins.Running, Enabled: ins.Enabled,
			SetUp: ins.SetUp, ConfigOK: ins.ConfigOK, ConfigError: ins.ConfigError, Version: ins.Version,
			IPv6: ins.IPv6, Init: ins.Init, Sites: sites, Certificates: certs, Hosts: hs, Unknown: unknown,
			Streams: ins.Streams, Geo: geoState(d, *ins),
			HTTP3: ins.HTTP3, Certbot: ins.Certbot,
			AuthRequest: ins.AuthRequest, Brotli: ins.Brotli, CABundle: ins.CABundle,
			WAF: ins.WAF, ImageFilter: ins.ImageFilter, StreamGeo: streamGeoState(d, *ins),
			Released: released, Container: h.containerOf(r.Proxy),
		}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-proxy", Method: http.MethodDelete, Path: base,
		Summary:     "Stop managing a proxy",
		Description: "With remove_files, first takes Morcheh's sites off the server and reloads (the proxy itself stays installed). Hand-written sites are left as they are, except that files Morcheh took default_server from get it back.",
		Tags:        tags, DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *struct {
		ID          string `path:"id" format:"uuid"`
		RemoveFiles bool   `query:"remove_files"`
	}) (*struct{}, error) {
		r, d, err := h.getProxy(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		defer h.lock(r.Proxy.ID)()
		if in.RemoveFiles {
			server := r.Proxy.ServerID.String()
			err := h.s.withConn(ctx, server, func(c *sshpool.Conn) error {
				sh, err := h.shell(ctx, r.Proxy, c)
				if err != nil {
					return err
				}
				_, err = sh.run(ctx, d.RemoveScript())
				var be *boxError
				if errors.As(err, &be) {
					// Nothing to take out of a container that's gone or
					// stopped; the server's side still goes.
					slog.Info("proxy removed without its container", "proxy", r.Proxy.ID, "reason", be.msg)
					err = nil
				}
				if err != nil || sh.box == nil {
					return err
				}
				_, err = sh.hostRun(ctx, d.HostRemoveScript(*sh.box))
				return err
			})
			if err != nil {
				return nil, toProblem(err)
			}
		}
		if err := h.s.q.DeleteProxy(ctx, r.Proxy.ID); err != nil {
			return nil, internalError(err)
		}
		h.containers.Delete(r.Proxy.ID)
		h.healed.Delete(r.Proxy.ID)
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "setup-proxy", Method: http.MethodPost, Path: base + "/setup",
		Summary: "Install (when missing) and wire up the proxy",
		Description: "Installs the package if needed, adds Morcheh's include, starts the proxy and writes the panel's sites. " +
			"Runs as a background job (kind `" + proxySetupKind + "`); 409 when one is already running.",
		Tags: tags, DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *ProxyIDPath) (*JobOutput, error) {
		return h.submitSetup(ctx, in.ID, proxySetupKind)
	})
	h.s.jobs.Handle(proxySetupKind, func(ctx context.Context, t *jobs.Task) (any, error) { return h.runSetup(ctx, t, proxySetupKind) })

	huma.Register(api, huma.Operation{
		OperationID: "setup-proxy-geo", Method: http.MethodPost, Path: base + "/geo",
		Summary: "Turn on the IP-to-country lookup for country rules",
		Description: "Adds nginx's GeoIP2 module, downloads DB-IP's free country database (CC BY 4.0) and refreshes it monthly. " +
			"Runs as a background job (kind `" + proxyGeoKind + "`); 409 when a setup is already running.",
		Tags: tags, DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *ProxyIDPath) (*JobOutput, error) {
		return h.submitSetup(ctx, in.ID, proxyGeoKind)
	})
	h.s.jobs.Handle(proxyGeoKind, func(ctx context.Context, t *jobs.Task) (any, error) { return h.runSetup(ctx, t, proxyGeoKind) })

	huma.Register(api, huma.Operation{
		OperationID: "setup-proxy-module", Method: http.MethodPost, Path: base + "/modules/{module}",
		Summary: "Add a module to the proxy",
		Description: "Installs one of nginx's extra modules from the system's packages, reloads, and writes the panel's sites again: " +
			"`brotli` (Brotli compression), `waf` (ModSecurity with the OWASP Core Rule Set; Debian/Ubuntu), " +
			"`image-filter` (resizing pictures) or `stream-geo` (country rules for port forwards; also downloads the country database). " +
			"Runs as a background job (kind `proxy-<module>`); 409 when a setup is already running.",
		Tags: tags, DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		ID     string `path:"id" format:"uuid"`
		Module string `path:"module" enum:"brotli,waf,image-filter,stream-geo"`
	}) (*JobOutput, error) {
		if in.Module == proxy.ModuleStreamGeo {
			_, d, err := h.getProxy(ctx, in.ID)
			if err != nil {
				return nil, err
			}
			if caps := d.Capabilities(); !caps.Countries || !caps.Streams {
				return nil, huma.Error422UnprocessableEntity(d.Label() + " can't limit port forwards by country")
			}
		}
		return h.submitSetup(ctx, in.ID, proxyModuleKinds[in.Module])
	})
	for _, kind := range proxyModuleKinds {
		h.s.jobs.Handle(kind, func(ctx context.Context, t *jobs.Task) (any, error) { return h.runSetup(ctx, t, kind) })
	}

	huma.Register(api, huma.Operation{
		OperationID: "list-proxy-host-waf-events", Method: http.MethodGet, Path: base + "/hosts/{host}/waf-events",
		Summary:     "Requests the site's firewall flagged, newest first",
		Description: "Read from the site's ModSecurity audit log on the server (only requests that matched a rule). Empty when the firewall is off or nothing matched yet.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ID    string `path:"id" format:"uuid"`
		Host  string `path:"host" format:"uuid"`
		Limit int    `query:"limit" minimum:"1" maximum:"500" default:"100"`
	}) (*struct {
		Body struct {
			Events []proxy.WAFEvent `json:"events"`
		}
	}, error) {
		r, d, err := h.getProxy(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if _, err := h.s.q.GetProxyHost(ctx, sqlc.GetProxyHostParams{ID: uuid.MustParse(in.Host), ProxyID: r.Proxy.ID}); isNotFound(err) {
			return nil, huma.Error404NotFound("site not found")
		} else if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Events []proxy.WAFEvent `json:"events"`
			}
		}{}
		server := r.Proxy.ServerID.String()
		err = h.s.withConn(ctx, server, func(c *sshpool.Conn) error {
			sh, err := h.shell(ctx, r.Proxy, c)
			if err != nil {
				return err
			}
			text, err := sh.run(ctx, d.WAFEventsScript(in.Host, in.Limit))
			if err != nil {
				return err
			}
			out.Body.Events = d.ParseWAFEvents(text)
			return nil
		})
		if err != nil {
			return nil, toProblem(err)
		}
		if out.Body.Events == nil {
			out.Body.Events = []proxy.WAFEvent{}
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "proxy-action", Method: http.MethodPost, Path: base + "/action",
		Summary:     "Test, reload, start, restart or stop the proxy",
		Description: "Start, restart and reload test the config first. Stop needs Engineer.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ID   string `path:"id" format:"uuid"`
		Body struct {
			Action string `json:"action" enum:"test,reload,start,restart,stop"`
		}
	}) (*struct{ Body ProxyActionResult }, error) {
		if in.Body.Action == "stop" && principalOf(ctx).Level < auth.Engineer {
			return nil, forbidden(auth.Engineer)
		}
		r, d, err := h.getProxy(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		server := r.Proxy.ServerID.String()
		out := &struct{ Body ProxyActionResult }{}
		err = h.s.withConn(ctx, server, func(c *sshpool.Conn) error {
			sh, err := h.shell(ctx, r.Proxy, c)
			if err != nil {
				return err
			}
			var res *execResult
			if sh.box != nil {
				res, err = containerAction(ctx, sh, d, in.Body.Action)
			} else {
				facts, ferr := sh.hostRun(ctx, hostScript)
				if ferr != nil {
					return ferr
				}
				script, serr := d.ActionScript(in.Body.Action, parseHost(facts).init)
				if serr != nil {
					return fieldError("body.action", serr.Error(), in.Body.Action)
				}
				res, err = sh.exec(ctx, script, time.Minute, 64<<10)
			}
			if err != nil {
				return err
			}
			if res.code == proxy.ExitNotInstalled {
				return huma.Error409Conflict(d.Label() + " isn't installed on this server")
			}
			out.Body = ProxyActionResult{OK: res.code == 0, ExitCode: res.code, Output: strings.TrimSpace(string(res.output))}
			return nil
		})
		if err != nil {
			return nil, toProblem(err)
		}
		h.refresh(r.Proxy.ID)
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "preview-proxy-host", Method: http.MethodPost, Path: base + "/hosts/preview",
		Summary:     "The config a site would get",
		Description: "Renders without saving. Problems with the values come back as a list, not an error.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ID   string `path:"id" format:"uuid"`
		Body struct {
			Host   string           `json:"host,omitempty" format:"uuid" doc:"The site being edited; empty for a new one"`
			Config proxy.HostConfig `json:"config"`
		}
	}) (*struct {
		Body struct {
			Text     string         `json:"text"`
			Problems []ProxyProblem `json:"problems"`
		}
	}, error) {
		r, d, err := h.getProxy(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		out := &struct {
			Body struct {
				Text     string         `json:"text"`
				Problems []ProxyProblem `json:"problems"`
			}
		}{}
		out.Body.Problems = []ProxyProblem{}
		p, err := h.resolveStorage(ctx, &in.Body.Config)
		if err != nil {
			return nil, err
		}
		if p != nil {
			out.Body.Problems = append(out.Body.Problems, ProxyProblem{Field: "body.config." + p.Field, Message: p.Message})
			return out, nil
		}
		c := proxy.Normalize(in.Body.Config)
		for _, p := range append(proxy.Validate(c), d.Validate(c)...) {
			out.Body.Problems = append(out.Body.Problems, ProxyProblem{Field: "body.config." + p.Field, Message: p.Message})
		}
		if len(out.Body.Problems) > 0 {
			return out, nil
		}
		id := in.Body.Host
		if id == "" {
			id = "new"
		}
		version := r.Proxy.Version
		out.Body.Text = proxy.FileText(d, id, c, proxy.Env{Version: version, IPv6: true, Brotli: true})
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "test-proxy-host", Method: http.MethodPost, Path: base + "/hosts/test",
		Summary:     "Test a site on the server without saving",
		Description: "Puts every site's file in place with this one as sent, runs the proxy's own config test and puts the old files back. Nothing is reloaded or saved. ok=false carries the proxy's message.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ID   string `path:"id" format:"uuid"`
		Body struct {
			Host   string           `json:"host,omitempty" format:"uuid" doc:"The site being edited; empty for a new one"`
			Config proxy.HostConfig `json:"config"`
		}
	}) (*struct{ Body ProxyActionResult }, error) {
		r, d, err := h.getProxy(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if err := h.withStorage(ctx, &in.Body.Config); err != nil {
			return nil, err
		}
		c, err := cleanHost(d, in.Body.Config)
		if err != nil {
			return nil, err
		}
		defer h.lock(r.Proxy.ID)()
		hosts, err := h.s.q.ListProxyHosts(ctx, r.Proxy.ID)
		if err != nil {
			return nil, internalError(err)
		}
		var was *proxy.HostConfig
		for _, x := range hosts {
			if x.ID.String() == in.Body.Host {
				old := configOf(x)
				was = &old
			}
		}
		if err := hashPasswords(&c, was); err != nil {
			return nil, err
		}
		cfg, _ := json.Marshal(c)
		this := sqlc.ProxyHost{ID: uuid.New(), ProxyID: r.Proxy.ID, Domains: c.Domains, Enabled: true, Config: cfg}
		found := false
		for i, x := range hosts {
			if x.ID.String() == in.Body.Host {
				this.ID = x.ID
				hosts[i], found = this, true
			}
		}
		if !found {
			hosts = append(hosts, this)
		}
		if err := checkOverlaps(hosts); err != nil {
			return nil, err
		}
		out := &struct{ Body ProxyActionResult }{}
		server := r.Proxy.ServerID.String()
		err = h.s.withConn(ctx, server, func(conn *sshpool.Conn) error {
			sh, err := h.shell(ctx, r.Proxy, conn)
			if err != nil {
				return err
			}
			state, err := inspectWith(ctx, sh, d)
			if err != nil {
				return err
			}
			if !state.Installed {
				return huma.Error409Conflict(d.Label() + " isn't installed on this server. Set it up first.")
			}
			files := render(d, hosts, envOf(state))
			if err := sh.pushFiles(ctx, files); err != nil {
				return err
			}
			res, err := sh.exec(ctx, d.TestScript(files, takeoverOf(hosts, state)), 2*time.Minute, 64<<10)
			if err != nil {
				return err
			}
			if res.timedOut {
				return huma.Error422UnprocessableEntity(d.Label() + " didn't answer in time")
			}
			out.Body = ProxyActionResult{OK: res.code == 0, ExitCode: res.code, Output: strings.TrimSpace(string(res.output))}
			return nil
		})
		if err != nil {
			return nil, toProblem(err)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-proxy-host", Method: http.MethodPost, Path: base + "/hosts",
		Summary:     "Add a site",
		Description: "Writes it to the server, tests and reloads. 422 when a value is wrong or the proxy refuses it (nothing is saved then).",
		Tags:        tags, DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		ID   string `path:"id" format:"uuid"`
		Body ProxyHostBody
	}) (*struct{ Body ProxyDetail }, error) {
		_, d, err := h.getProxy(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if err := h.withStorage(ctx, &in.Body.Config); err != nil {
			return nil, err
		}
		c, err := cleanHost(d, in.Body.Config)
		if err != nil {
			return nil, err
		}
		if err := hashPasswords(&c, nil); err != nil {
			return nil, err
		}
		cfg, _ := json.Marshal(c)
		name, _ := actorName(ctx)
		out, err := h.write(ctx, in.ID, func(q *sqlc.Queries, pid uuid.UUID) (string, error) {
			_, err := q.CreateProxyHost(ctx, sqlc.CreateProxyHostParams{
				ProxyID: pid, Domains: c.Domains, Enabled: in.Body.Enabled == nil || *in.Body.Enabled,
				Config: cfg, Note: strings.TrimSpace(in.Body.Note), ByName: name,
			})
			if err != nil {
				return "", internalError(err)
			}
			return "Added " + hostLabel(c), nil
		})
		if err != nil {
			return nil, err
		}
		return &struct{ Body ProxyDetail }{*out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-proxy-host", Method: http.MethodPut, Path: base + "/hosts/{host}",
		Summary: "Change a site", Tags: tags,
	}, func(ctx context.Context, in *struct {
		ProxyHostPath
		Body ProxyHostBody
	}) (*struct{ Body ProxyDetail }, error) {
		_, d, err := h.getProxy(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if err := h.withStorage(ctx, &in.Body.Config); err != nil {
			return nil, err
		}
		c, err := cleanHost(d, in.Body.Config)
		if err != nil {
			return nil, err
		}
		name, _ := actorName(ctx)
		out, err := h.write(ctx, in.ID, func(q *sqlc.Queries, pid uuid.UUID) (string, error) {
			old, err := q.GetProxyHost(ctx, sqlc.GetProxyHostParams{ID: uuid.MustParse(in.Host), ProxyID: pid})
			if isNotFound(err) {
				return "", huma.Error404NotFound("site not found")
			}
			if err != nil {
				return "", internalError(err)
			}
			if in.Body.Revision != nil && !in.Body.Revision.Equal(old.UpdatedAt) {
				return "", huma.Error409Conflict("Someone else saved this site after you opened it.")
			}
			was := configOf(old)
			if err := hashPasswords(&c, &was); err != nil {
				return "", err
			}
			cfg, _ := json.Marshal(c)
			enabled := old.Enabled
			if in.Body.Enabled != nil {
				enabled = *in.Body.Enabled
			}
			if _, err := q.UpdateProxyHost(ctx, sqlc.UpdateProxyHostParams{
				Domains: c.Domains, Enabled: enabled, Config: cfg, Note: strings.TrimSpace(in.Body.Note),
				ByName: name, ID: old.ID, ProxyID: pid,
			}); err != nil {
				return "", internalError(err)
			}
			return "Changed " + hostLabel(c), nil
		})
		if err != nil {
			return nil, err
		}
		return &struct{ Body ProxyDetail }{*out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-proxy-host-enabled", Method: http.MethodPut, Path: base + "/hosts/{host}/enabled",
		Summary: "Turn a site on or off", Description: "A site that's off keeps its settings but its file is taken off the server.",
		Tags: tags,
	}, func(ctx context.Context, in *struct {
		ProxyHostPath
		Body struct {
			Enabled bool `json:"enabled"`
		}
	}) (*struct{ Body ProxyDetail }, error) {
		name, _ := actorName(ctx)
		out, err := h.write(ctx, in.ID, func(q *sqlc.Queries, pid uuid.UUID) (string, error) {
			old, err := q.GetProxyHost(ctx, sqlc.GetProxyHostParams{ID: uuid.MustParse(in.Host), ProxyID: pid})
			if isNotFound(err) {
				return "", huma.Error404NotFound("site not found")
			}
			if err != nil {
				return "", internalError(err)
			}
			if _, err := q.UpdateProxyHost(ctx, sqlc.UpdateProxyHostParams{
				Domains: old.Domains, Enabled: in.Body.Enabled, Config: old.Config, Note: old.Note,
				ByName: name, ID: old.ID, ProxyID: pid,
			}); err != nil {
				return "", internalError(err)
			}
			if in.Body.Enabled {
				return "Turned on " + hostLabel(configOf(old)), nil
			}
			return "Turned off " + hostLabel(configOf(old)), nil
		})
		if err != nil {
			return nil, err
		}
		return &struct{ Body ProxyDetail }{*out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-proxy-host", Method: http.MethodDelete, Path: base + "/hosts/{host}",
		Summary: "Remove a site", Tags: tags,
	}, func(ctx context.Context, in *ProxyHostPath) (*struct{ Body ProxyDetail }, error) {
		out, err := h.write(ctx, in.ID, func(q *sqlc.Queries, pid uuid.UUID) (string, error) {
			old, err := q.GetProxyHost(ctx, sqlc.GetProxyHostParams{ID: uuid.MustParse(in.Host), ProxyID: pid})
			if isNotFound(err) {
				return "", huma.Error404NotFound("site not found")
			}
			if err != nil {
				return "", internalError(err)
			}
			if err := q.DeleteProxyHost(ctx, sqlc.DeleteProxyHostParams{ID: old.ID, ProxyID: pid}); err != nil {
				return "", internalError(err)
			}
			return "Removed " + hostLabel(configOf(old)), nil
		})
		if err != nil {
			return nil, err
		}
		return &struct{ Body ProxyDetail }{*out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "purge-proxy-host-cache", Method: http.MethodPost, Path: base + "/hosts/{host}/cache/purge",
		Summary:     "Clear a site's cache, or part of it",
		Description: "Removes the answers the proxy kept for the site (all of them, those of some addresses, of a saved group or carrying an answer header); the next visits ask the upstream again. Browsers keep their own copies. `dry_run` only counts them.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ProxyHostPath
		Body *ProxyPurgeBody
	}) (*struct{ Body ProxyPurgeResult }, error) {
		r, d, err := h.getProxy(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if !d.Capabilities().Cache {
			return nil, huma.Error422UnprocessableEntity(d.Label() + " can't cache answers")
		}
		host, err := h.s.q.GetProxyHost(ctx, sqlc.GetProxyHostParams{ID: uuid.MustParse(in.Host), ProxyID: r.Proxy.ID})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("site not found")
		} else if err != nil {
			return nil, internalError(err)
		}
		var b ProxyPurgeBody
		if in.Body != nil {
			b = *in.Body
		}
		f, err := purgeFilter(b, configOf(host).Cache)
		if err != nil {
			return nil, err
		}
		out := &struct{ Body ProxyPurgeResult }{}
		server := r.Proxy.ServerID.String()
		err = h.s.withConn(ctx, server, func(c *sshpool.Conn) error {
			sh, err := h.shell(ctx, r.Proxy, c)
			if err != nil {
				return err
			}
			res, err := sh.exec(ctx, d.PurgeCacheScript(in.Host, f, b.DryRun), 5*time.Minute, 16<<10)
			if err != nil {
				return err
			}
			text := strings.TrimSpace(string(res.output))
			n, kb, ok := proxy.ParsePurge(text)
			if res.code != 0 || !ok {
				out.Body = ProxyPurgeResult{ExitCode: res.code, Output: text}
				return nil
			}
			out.Body = ProxyPurgeResult{OK: true, Matched: n, Bytes: kb * 1024, Output: purgeSummary(n, kb*1024, b.DryRun, f.Empty())}
			return nil
		})
		if err != nil {
			return nil, toProblem(err)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-proxy-logs", Method: http.MethodGet, Path: base + "/logs",
		Summary: "The last lines of a site's log, or the proxy's own", Tags: tags,
	}, func(ctx context.Context, in *struct {
		ID    string `path:"id" format:"uuid"`
		Host  string `query:"host" format:"uuid" doc:"A site; empty = the proxy's own log"`
		Log   string `query:"log" enum:"access,error" default:"access"`
		Lines int    `query:"lines" minimum:"1" maximum:"2000" default:"200"`
	}) (*struct {
		Body struct {
			Text    string `json:"text"`
			Missing bool   `json:"missing" doc:"No such log on the server yet"`
		}
	}, error) {
		r, d, err := h.getProxy(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if in.Host != "" {
			if _, err := h.s.q.GetProxyHost(ctx, sqlc.GetProxyHostParams{ID: uuid.MustParse(in.Host), ProxyID: r.Proxy.ID}); isNotFound(err) {
				return nil, huma.Error404NotFound("site not found")
			} else if err != nil {
				return nil, internalError(err)
			}
		}
		out := &struct {
			Body struct {
				Text    string `json:"text"`
				Missing bool   `json:"missing" doc:"No such log on the server yet"`
			}
		}{}
		server := r.Proxy.ServerID.String()
		err = h.s.withConn(ctx, server, func(c *sshpool.Conn) error {
			sh, err := h.shell(ctx, r.Proxy, c)
			if err != nil {
				return err
			}
			text, err := sh.run(ctx, d.LogScript(in.Host, in.Log, in.Lines))
			if err != nil {
				return err
			}
			if strings.TrimSpace(text) == "@@morcheh-nolog" && in.Host == "" && sh.box != nil {
				// The official images send nginx's own logs to the
				// container's output.
				text, err = sh.hostRun(ctx, containerLogScript(*sh.box, in.Log, in.Lines))
				if err != nil {
					return err
				}
			}
			if strings.TrimSpace(text) == "@@morcheh-nolog" {
				out.Body.Missing = true
				return nil
			}
			out.Body.Text = text
			return nil
		})
		if err != nil {
			return nil, toProblem(err)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-proxy-history", Method: http.MethodGet, Path: base + "/history",
		Summary: "Changes to the proxy's sites, newest first", Description: "The last 50 are kept.", Tags: tags,
	}, func(ctx context.Context, in *ProxyIDPath) (*struct {
		Body struct {
			Items []ProxyChangeSummary `json:"items"`
		}
	}, error) {
		r, _, err := h.getProxy(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		rows, err := h.s.q.ListProxyChanges(ctx, r.Proxy.ID)
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []ProxyChangeSummary `json:"items"`
			}
		}{}
		out.Body.Items = make([]ProxyChangeSummary, len(rows))
		for i, c := range rows {
			out.Body.Items[i] = ProxyChangeSummary{ID: c.ID, UserName: c.UserName, Summary: c.Summary, HostCount: int(c.HostCount), CreatedAt: c.CreatedAt}
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-proxy-change", Method: http.MethodGet, Path: base + "/history/{change}",
		Summary: "Every site as it was after one change", Tags: tags,
	}, func(ctx context.Context, in *ProxyChangePath) (*struct{ Body ProxyChangeDetail }, error) {
		c, hosts, err := h.change(ctx, in.ID, in.Change)
		if err != nil {
			return nil, err
		}
		for i := range hosts {
			if !canSeeSecrets(ctx) {
				hosts[i].Config, hosts[i].Redacted = redactHost(hosts[i].Config), true
			}
			hosts[i].Config = withoutPasswords(hosts[i].Config)
		}
		return &struct{ Body ProxyChangeDetail }{ProxyChangeDetail{
			ProxyChangeSummary: ProxyChangeSummary{ID: c.ID, UserName: c.UserName, Summary: c.Summary, HostCount: len(hosts), CreatedAt: c.CreatedAt},
			Hosts:              hosts,
		}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "restore-proxy-change", Method: http.MethodPost, Path: base + "/history/{change}/restore",
		Summary:     "Go back to how the sites were after a change",
		Description: "Replaces every site with the snapshot and writes them to the server, as one new change.",
		Tags:        tags,
	}, func(ctx context.Context, in *ProxyChangePath) (*struct{ Body ProxyDetail }, error) {
		c, hosts, err := h.change(ctx, in.ID, in.Change)
		if err != nil {
			return nil, err
		}
		out, err := h.write(ctx, in.ID, func(q *sqlc.Queries, pid uuid.UUID) (string, error) {
			if err := q.DeleteProxyHosts(ctx, pid); err != nil {
				return "", internalError(err)
			}
			for _, x := range hosts {
				cfg, _ := json.Marshal(x.Config)
				if err := q.RestoreProxyHost(ctx, sqlc.RestoreProxyHostParams{
					ID: x.ID, ProxyID: pid, Domains: x.Domains, Enabled: x.Enabled, Config: cfg, Note: x.Note,
					CreatedByName: x.CreatedByName, UpdatedByName: x.UpdatedByName, CreatedAt: x.CreatedAt,
				}); err != nil {
					return "", internalError(err)
				}
			}
			return "Went back to “" + c.Summary + "” (" + c.CreatedAt.UTC().Format("2006-01-02 15:04") + " UTC)", nil
		})
		if err != nil {
			return nil, err
		}
		return &struct{ Body ProxyDetail }{*out}, nil
	})
}

func (h *proxyHandler) change(ctx context.Context, rawID, rawChange string) (sqlc.ProxyChange, []ProxyHost, error) {
	r, _, err := h.getProxy(ctx, rawID)
	if err != nil {
		return sqlc.ProxyChange{}, nil, err
	}
	c, err := h.s.q.GetProxyChange(ctx, sqlc.GetProxyChangeParams{ID: uuid.MustParse(rawChange), ProxyID: r.Proxy.ID})
	if isNotFound(err) {
		return c, nil, huma.Error404NotFound("change not found")
	}
	if err != nil {
		return c, nil, internalError(err)
	}
	hosts := []ProxyHost{}
	if err := json.Unmarshal(c.Hosts, &hosts); err != nil {
		return c, nil, internalError(err)
	}
	return c, hosts, nil
}

// ---- Monitor ----

type proxyMonitor struct {
	h     *proxyHandler
	every time.Duration

	mu      sync.Mutex
	running map[uuid.UUID]bool
}

// startProxyMonitor re-checks every proxy on its own, so the list and the
// menu's red count stay current.
func startProxyMonitor(h *proxyHandler, every time.Duration) {
	if every <= 0 {
		return
	}
	m := &proxyMonitor{h: h, every: every, running: map[uuid.UUID]bool{}}
	go m.loop()
}

func (m *proxyMonitor) loop() {
	sem := make(chan struct{}, checkConcurrency)
	for range time.Tick(min(m.every, 5*time.Second)) {
		due, err := m.h.s.q.ListProxiesDueForCheck(context.Background(), time.Now().Add(-m.every))
		if err != nil {
			slog.Warn("list proxies due for check", "error", err)
			continue
		}
		for _, p := range due {
			d, ok := proxy.Get(p.Kind)
			if !ok || !m.claim(p.ID) {
				continue
			}
			sem <- struct{}{}
			go func(p sqlc.Proxy) {
				defer func() { <-sem; m.unclaim(p.ID) }()
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				_, _, _, _ = m.h.check(ctx, p, d)
			}(p)
		}
	}
}

func (m *proxyMonitor) claim(id uuid.UUID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running[id] {
		return false
	}
	m.running[id] = true
	return true
}

func (m *proxyMonitor) unclaim(id uuid.UUID) {
	m.mu.Lock()
	delete(m.running, id)
	m.mu.Unlock()
}
