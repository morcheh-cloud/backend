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
	proxyKeepChange = 50
	proxyNoRoot     = "Managing the proxy needs root or sudo on this server"
)

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
	ID        uuid.UUID      `json:"id"`
	State     string         `json:"state" enum:"ok,changed,missing,off" doc:"changed = the file on the server differs from what the panel wrote; missing = not on the server"`
	Conflicts []ProxySiteRef `json:"conflicts" doc:"Hand-written sites answering the same name"`
}

type ProxyInspection struct {
	Proxy        Proxy               `json:"proxy"`
	Installed    bool                `json:"installed"`
	Running      bool                `json:"running"`
	Enabled      bool                `json:"enabled" doc:"Starts at boot"`
	SetUp        bool                `json:"set_up" doc:"The panel's sites are loaded"`
	ConfigOK     bool                `json:"config_ok"`
	ConfigError  string              `json:"config_error,omitempty"`
	Version      string              `json:"version"`
	IPv6         bool                `json:"ipv6"`
	Init         string              `json:"init"`
	Sites        []proxy.Site        `json:"sites"`
	Certificates []proxy.Certificate `json:"certificates"`
	Hosts        []ProxyHostState    `json:"hosts"`
	Unknown      []string            `json:"unknown" doc:"Files in Morcheh's folder the panel doesn't know"`
	Streams      string              `json:"streams" enum:",ready,no_module,not_wired,taken" doc:"Port forwards: ready; no_module = the stream module is missing; not_wired = setup hasn't added the stream block; taken = nginx.conf has its own stream block. Empty when the kind has no streams"`
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
		CreatedAt: h.CreatedAt, UpdatedAt: h.UpdatedAt,
	}
	if !full {
		out.Config, out.Redacted = redactHost(cfg), true
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

// inspect reads the proxy's state on its server.
func inspectWith(ctx context.Context, sh *rootShell, d proxy.Driver) (proxy.Inspection, error) {
	out, err := sh.run(ctx, d.InspectScript())
	if err != nil {
		return proxy.Inspection{}, err
	}
	return d.ParseInspect(out), nil
}

func envOf(in proxy.Inspection) proxy.Env {
	return proxy.Env{Version: in.Version, IPv6: in.IPv6}
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
	for _, x := range hosts {
		if !x.Enabled {
			continue
		}
		cfg := configOf(x)
		files = append(files, proxy.File{ID: x.ID.String(), Config: cfg, Text: d.Render(x.ID.String(), cfg, env)})
	}
	return files
}

// applyFiles replaces Morcheh's files on the server and reloads.
func applyFiles(ctx context.Context, sh *rootShell, d proxy.Driver, files []proxy.File) error {
	res, err := sh.exec(ctx, d.ApplyScript(files), 2*time.Minute, 64<<10)
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
	err := h.s.withConn(ctx, p.ServerID.String(), func(c *sshpool.Conn) error {
		sh, err := h.root(ctx, p.ServerID.String(), c)
		if err != nil {
			return err
		}
		in, err = inspectWith(ctx, sh, d)
		return err
	})
	rec := sqlc.RecordProxyCheckParams{ID: p.ID}
	var hs []ProxyHostState
	unknown := []string{}
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
		sh, err := h.root(ctx, r.Proxy.ServerID.String(), c)
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
		return applyFiles(ctx, sh, d, render(d, hosts, envOf(in)))
	})
	if err != nil {
		return nil, toProblem(err)
	}

	snap, err := json.Marshal(hostsOut(hosts, true))
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
	for i, a := range hosts {
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

func (h *proxyHandler) submitSetup(ctx context.Context, rawID string) (*JobOutput, error) {
	r, d, err := h.getProxy(ctx, rawID)
	if err != nil {
		return nil, err
	}
	server := r.Proxy.ServerID.String()
	err = h.s.withConn(ctx, server, func(c *sshpool.Conn) error {
		_, err := h.root(ctx, server, c)
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
	if slices.ContainsFunc(list, func(j sqlc.Job) bool { return j.Kind == proxySetupKind }) {
		return nil, huma.Error409Conflict(d.Label() + " is already being set up on this server")
	}
	return submit(ctx, h.s.jobs, jobs.Spec{
		Kind: proxySetupKind, Title: "Set up " + d.Label() + " on " + r.ServerName,
		Params: proxySetupParams{ProxyID: rawID, ServerID: server}, Refs: refs,
	})
}

// runSetup installs the proxy when it's missing (the package manager can't be
// stopped half way, so the job is locked then), wires in Morcheh's folder,
// starts it and writes the panel's sites.
func (h *proxyHandler) runSetup(ctx context.Context, t *jobs.Task) (any, error) {
	var p proxySetupParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	r, d, err := h.getProxy(ctx, p.ProxyID)
	if err != nil {
		return nil, jobError(err)
	}
	err = h.s.withConn(ctx, p.ServerID, func(c *sshpool.Conn) error {
		sh, err := h.root(ctx, p.ServerID, c)
		if err != nil {
			return err
		}
		facts, err := sh.run(ctx, hostScript)
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
		t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Locked = "Setting up", true })
		var last string
		lines := &lineWriter{fn: func(l string) {
			last = l
			t.Logf("%s", l)
			t.Update(func(pr *jobs.Progress) { pr.Current = l })
		}}
		res, err := sh.execTo(ctx, d.SetupScript(proxy.Setup{Init: f.init, PM: f.pm, Install: install}), packageTimeout, lines)
		lines.flush()
		switch {
		case err != nil:
			return err
		case res.timedOut:
			return fmt.Errorf("It took longer than %d minutes, so Morcheh stopped waiting", int(packageTimeout.Minutes()))
		case res.code == proxy.ExitTestFailed:
			return fmt.Errorf("%s's configuration has a problem, so it wasn't started: %s", d.Label(), last)
		case res.code == proxy.ExitReloadFailed:
			return fmt.Errorf("%s didn't start: %s", d.Label(), last)
		case res.code != 0:
			return fmt.Errorf("Setting up failed (exit %d): %s", res.code, last)
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
		if err := applyFiles(ctx, sh, d, render(d, hosts, envOf(in))); err != nil {
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
	base := "/proxies/{id}"

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
				ServerName: r.ServerName, ProxyStatus: r.ProxyStatus, WorkspaceID: r.WorkspaceID,
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
			ServerID string `json:"server_id" format:"uuid"`
			Kind     string `json:"kind" example:"nginx"`
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
		p, err := h.s.q.CreateProxy(ctx, sqlc.CreateProxyParams{ServerID: sid, Kind: d.Kind()})
		if isUniqueViolation(err) {
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
		return &struct{ Body ProxyInspection }{ProxyInspection{
			Proxy: proxyRowOut(r), Installed: ins.Installed, Running: ins.Running, Enabled: ins.Enabled,
			SetUp: ins.SetUp, ConfigOK: ins.ConfigOK, ConfigError: ins.ConfigError, Version: ins.Version,
			IPv6: ins.IPv6, Init: ins.Init, Sites: sites, Certificates: certs, Hosts: hs, Unknown: unknown,
			Streams: ins.Streams,
		}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-proxy", Method: http.MethodDelete, Path: base,
		Summary:     "Stop managing a proxy",
		Description: "With remove_files, first takes Morcheh's sites off the server and reloads (the proxy itself stays installed). Hand-written sites are never touched.",
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
				sh, err := h.root(ctx, server, c)
				if err != nil {
					return err
				}
				_, err = sh.run(ctx, d.RemoveScript())
				return err
			})
			if err != nil {
				return nil, toProblem(err)
			}
		}
		if err := h.s.q.DeleteProxy(ctx, r.Proxy.ID); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "setup-proxy", Method: http.MethodPost, Path: base + "/setup",
		Summary: "Install (when missing) and wire up the proxy",
		Description: "Installs the package if needed, adds Morcheh's include, starts the proxy and writes the panel's sites. " +
			"Runs as a background job (kind `" + proxySetupKind + "`); 409 when one is already running.",
		Tags: tags, DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *ProxyIDPath) (*JobOutput, error) {
		return h.submitSetup(ctx, in.ID)
	})
	h.s.jobs.Handle(proxySetupKind, h.runSetup)

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
			sh, err := h.root(ctx, server, c)
			if err != nil {
				return err
			}
			facts, err := sh.run(ctx, hostScript)
			if err != nil {
				return err
			}
			script, err := d.ActionScript(in.Body.Action, parseHost(facts).init)
			if err != nil {
				return fieldError("body.action", err.Error(), in.Body.Action)
			}
			res, err := sh.exec(ctx, script, time.Minute, 64<<10)
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
		out.Body.Text = d.Render(id, c, proxy.Env{Version: version, IPv6: true})
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
		c, err := cleanHost(d, in.Body.Config)
		if err != nil {
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
		c, err := cleanHost(d, in.Body.Config)
		if err != nil {
			return nil, err
		}
		cfg, _ := json.Marshal(c)
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
			sh, err := h.root(ctx, server, c)
			if err != nil {
				return err
			}
			text, err := sh.run(ctx, d.LogScript(in.Host, in.Log, in.Lines))
			if err != nil {
				return err
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
		if !canSeeSecrets(ctx) {
			for i := range hosts {
				hosts[i].Config, hosts[i].Redacted = redactHost(hosts[i].Config), true
			}
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
