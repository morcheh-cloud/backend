package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/jobs"
	"github.com/morche/backend/internal/proxy"
	"github.com/morche/backend/internal/registry"
	"github.com/morche/backend/internal/sshpool"
)

// Package registries: Harbor (images, Helm charts) and Verdaccio (npm)
// deployed by Morche as compose projects on a server, published through the
// server's reverse proxy with HTTPS, then managed through their API (over an
// SSH tunnel to the server's loopback) or, for Verdaccio, their files.

const (
	registryDeployKind = "registry-deploy"
	registryHTTPSKind  = "registry-https"
	registryRemoveKind = "registry-remove"
	registryCheckEvery = 2 * time.Minute
)

type registryHandler struct {
	s       *serverHandler
	proxies *proxyHandler
	mu      sync.Mutex
	busy    map[uuid.UUID]bool
}

func newRegistryHandler(s *serverHandler, p *proxyHandler) *registryHandler {
	return &registryHandler{s: s, proxies: p, busy: map[uuid.UUID]bool{}}
}

// ---- API types ----

type PackageRegistry struct {
	ID               string                    `json:"id" format:"uuid"`
	WorkspaceID      string                    `json:"workspace_id" format:"uuid"`
	ServerID         string                    `json:"server_id" format:"uuid"`
	ServerName       string                    `json:"server_name"`
	ServerStatus     string                    `json:"server_status"`
	Kind             string                    `json:"kind" enum:"harbor,verdaccio"`
	Label            string                    `json:"label"`
	Name             string                    `json:"name"`
	Note             string                    `json:"note"`
	Project          string                    `json:"project" doc:"The compose project it runs as (Containers lists it)"`
	Dir              string                    `json:"dir"`
	Port             int                       `json:"port"`
	Domain           string                    `json:"domain" doc:"The name clients use; empty = the server's address and the port"`
	HTTPS            bool                      `json:"https"`
	Address          string                    `json:"address" doc:"What image names and npm settings spell: registry.example.com or host:port"`
	URL              string                    `json:"url" doc:"Its web address"`
	Version          string                    `json:"version"`
	AdminUser        string                    `json:"admin_user"`
	ProxyHostID      string                    `json:"proxy_host_id,omitempty" format:"uuid"`
	ProxyID          string                    `json:"proxy_id,omitempty" format:"uuid"`
	DockerRegistryID string                    `json:"docker_registry_id,omitempty" format:"uuid" doc:"The Containers registry login made for it"`
	Settings         registry.RegistrySettings `json:"settings"`
	State            string                    `json:"state" enum:"deploying,ready,failed,removing"`
	Health           string                    `json:"health" enum:"unknown,online,degraded,down"`
	Problem          string                    `json:"problem"`
	JobID            string                    `json:"job_id,omitempty" format:"uuid" doc:"The last deploy, HTTPS or remove job"`
	UsageBytes       int64                     `json:"usage_bytes"`
	Items            int                       `json:"items" doc:"Repositories (Harbor) or packages (Verdaccio)"`
	CheckedAt        *time.Time                `json:"checked_at"`
	CreatedByName    string                    `json:"created_by_name"`
	CreatedAt        time.Time                 `json:"created_at"`
	UpdatedAt        time.Time                 `json:"updated_at"`
}

type RegistryProxyChoice struct {
	ID     string `json:"id" format:"uuid"`
	Label  string `json:"label"`
	Status string `json:"status"`
	Usable bool   `json:"usable" doc:"Set up and not read only"`
}

type RegistryPreflight struct {
	registry.Preflight
	Proxies  []RegistryProxyChoice `json:"proxies" doc:"Reverse proxies on this server"`
	Problems []string              `json:"problems" doc:"What stops it from being deployed"`
	Warnings []string              `json:"warnings"`
	Dir      string                `json:"dir" doc:"Where it would go"`
	Project  string                `json:"project"`
	Port     int                   `json:"port" doc:"The port it would use (a free one when the asked port is taken)"`
}

type RegistryCreateBody struct {
	ServerID string                    `json:"server_id" format:"uuid"`
	Kind     string                    `json:"kind" enum:"harbor,verdaccio"`
	Name     string                    `json:"name" minLength:"1" maxLength:"100"`
	Note     string                    `json:"note,omitempty" maxLength:"1000"`
	Port     int                       `json:"port,omitempty" minimum:"0" maximum:"65535" doc:"0 = the kind's default"`
	Domain   string                    `json:"domain,omitempty" maxLength:"253" doc:"Publish it under this name through the server's reverse proxy; empty = open the port instead (plain http)"`
	HTTPS    bool                      `json:"https,omitempty" doc:"Get a Let's Encrypt certificate for the domain"`
	Email    string                    `json:"email,omitempty" maxLength:"200" doc:"Where Let's Encrypt sends expiry warnings"`
	Settings registry.RegistrySettings `json:"settings"`
}

type RegistryUpdateBody struct {
	Name     string                    `json:"name" minLength:"1" maxLength:"100"`
	Note     string                    `json:"note" maxLength:"1000"`
	Settings registry.RegistrySettings `json:"settings"`
}

type RegistryCreated struct {
	Registry PackageRegistry `json:"registry"`
	Job      Job             `json:"job"`
}

type RegistryCredentials struct {
	User     string `json:"user"`
	Password string `json:"password"`
	URL      string `json:"url"`
}

type RegistryProject struct {
	Name   string `json:"name"`
	Public bool   `json:"public"`
	Mirror bool   `json:"mirror" doc:"A proxy cache of another registry"`
	Repos  int    `json:"repos"`
}

type RegistryItem struct {
	Name        string    `json:"name" doc:"Harbor: project/repository; Verdaccio: the package name"`
	Project     string    `json:"project,omitempty"`
	Versions    int       `json:"versions" doc:"Artifacts (Harbor) or versions (Verdaccio)"`
	Pulls       int       `json:"pulls"`
	Size        int64     `json:"size"`
	Latest      string    `json:"latest,omitempty"`
	Description string    `json:"description,omitempty"`
	Private     bool      `json:"private" doc:"Verdaccio: published here, not a copy from the mirror"`
	Mirror      bool      `json:"mirror" doc:"Kept from the mirror"`
	Updated     time.Time `json:"updated"`
}

type RegistryItems struct {
	Items    []RegistryItem    `json:"items"`
	Total    int               `json:"total"`
	Projects []RegistryProject `json:"projects"`
}

type RegistryVersion struct {
	Ref        string     `json:"ref" doc:"Harbor: the digest; Verdaccio: the version"`
	Tags       []string   `json:"tags"`
	Size       int64      `json:"size" doc:"-1 = not kept here"`
	Pushed     *time.Time `json:"pushed"`
	Pulled     *time.Time `json:"pulled"`
	Platforms  []string   `json:"platforms"`
	Kind       string     `json:"kind,omitempty" doc:"Harbor's artifact type: IMAGE, CHART…"`
	Deprecated string     `json:"deprecated,omitempty"`
	Author     string     `json:"author,omitempty"`
}

type RegistryItemDetail struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	License     string            `json:"license,omitempty"`
	Homepage    string            `json:"homepage,omitempty"`
	Private     bool              `json:"private"`
	DistTags    map[string]string `json:"dist_tags"`
	Versions    []RegistryVersion `json:"versions"`
}

type RegistryAccount struct {
	ID        string     `json:"id" doc:"Harbor: the robot's id; Verdaccio: the user name"`
	Name      string     `json:"name"`
	Kind      string     `json:"kind" enum:"robot,user"`
	Push      bool       `json:"push" doc:"May push or publish"`
	Morche    bool       `json:"morche" doc:"Made by Morche for its own use (Containers login, its admin)"`
	Disabled  bool       `json:"disabled"`
	Note      string     `json:"note"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedAt *time.Time `json:"created_at"`
}

type RegistryAccountBody struct {
	Name string `json:"name" minLength:"1" maxLength:"64"`
	Note string `json:"note,omitempty" maxLength:"200"`
	Push bool   `json:"push,omitempty" doc:"Harbor: may push and delete; Verdaccio users may always publish"`
	Days int    `json:"days,omitempty" minimum:"0" maximum:"3650" doc:"Harbor: valid for this many days, 0 = never expires"`
}

type RegistryAccountSecret struct {
	Account RegistryAccount `json:"account"`
	Secret  string          `json:"secret" doc:"Shown only now"`
}

type RegistryIDPath struct {
	ID string `path:"id" format:"uuid"`
}

type registryJobParams struct {
	RegistryID string `json:"registry_id"`
	ServerID   string `json:"server_id"`
	Email      string `json:"email,omitempty"`
	KeepData   bool   `json:"keep_data,omitempty"`
}

var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// ---- helpers ----

func registryOut(r sqlc.PackageRegistry, serverName, serverHost, serverStatus string, ws uuid.UUID, proxyID *uuid.UUID) PackageRegistry {
	k, _ := registry.KindOf(r.Kind)
	var set registry.RegistrySettings
	_ = json.Unmarshal(r.Settings, &set)
	out := PackageRegistry{
		ID: r.ID.String(), WorkspaceID: ws.String(), ServerID: r.ServerID.String(), ServerName: serverName, ServerStatus: serverStatus,
		Kind: r.Kind, Label: k.Label, Name: r.Name, Note: r.Note, Project: r.Project, Dir: r.Dir, Port: int(r.Port),
		Domain: r.Domain, HTTPS: r.Https, Version: r.Version, AdminUser: r.AdminUser, Settings: set,
		State: r.State, Health: r.Health, Problem: r.Problem, UsageBytes: r.UsageBytes, Items: int(r.Items),
		CheckedAt: r.CheckedAt, CreatedByName: r.CreatedByName, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
	out.Address, out.URL = registryAddress(r, serverHost)
	if r.ProxyHostID != nil {
		out.ProxyHostID = r.ProxyHostID.String()
	}
	if proxyID != nil && r.ProxyHostID != nil {
		out.ProxyID = proxyID.String()
	}
	if r.DockerRegistryID != nil {
		out.DockerRegistryID = r.DockerRegistryID.String()
	}
	if r.JobID != nil {
		out.JobID = r.JobID.String()
	}
	return out
}

func registryAddress(r sqlc.PackageRegistry, serverHost string) (address, url string) {
	if r.Domain != "" {
		scheme := "http://"
		if r.Https {
			scheme = "https://"
		}
		return r.Domain, scheme + r.Domain
	}
	hp := net.JoinHostPort(serverHost, strconv.Itoa(int(r.Port)))
	return hp, "http://" + hp
}

func (h *registryHandler) get(ctx context.Context, rawID string) (sqlc.GetPackageRegistryRow, error) {
	id, err := uuid.Parse(rawID)
	if err != nil {
		return sqlc.GetPackageRegistryRow{}, huma.Error404NotFound("registry not found")
	}
	r, err := h.s.q.GetPackageRegistry(ctx, id)
	if isNotFound(err) {
		return r, huma.Error404NotFound("registry not found")
	}
	if err != nil {
		return r, internalError(err)
	}
	return r, nil
}

func (h *registryHandler) out(ctx context.Context, r sqlc.GetPackageRegistryRow) PackageRegistry {
	var pid *uuid.UUID
	if r.PackageRegistry.ProxyHostID != nil {
		if hp, err := h.s.q.GetProxyHostProxy(ctx, *r.PackageRegistry.ProxyHostID); err == nil {
			pid = &hp
		}
	}
	return registryOut(r.PackageRegistry, r.ServerName, r.ServerHost, r.ServerStatus, r.WorkspaceID, pid)
}

func (h *registryHandler) adminSecret(r sqlc.PackageRegistry) (string, error) {
	if len(r.AdminSecretEnc) == 0 {
		return "", errors.New("Morche has no admin password for this registry")
	}
	return h.s.box.Open(r.AdminSecretEnc)
}

// withAPI reaches the registry's HTTP API on the server's loopback through
// the server's SSH connection, signed in as its admin.
func (h *registryHandler) withAPI(ctx context.Context, r sqlc.PackageRegistry, fn func(c registry.HTTP) error) error {
	secret, err := h.adminSecret(r)
	if err != nil {
		return err
	}
	return h.s.withConn(ctx, r.ServerID.String(), func(c *sshpool.Conn) error {
		addr := "127.0.0.1:" + strconv.Itoa(int(r.Port))
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return c.Client.DialContext(ctx, "tcp", addr)
			},
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 60 * time.Second,
		}
		defer tr.CloseIdleConnections()
		return fn(registry.HTTP{Client: &http.Client{Transport: tr, Timeout: 2 * time.Minute}, Base: "http://" + addr, User: r.AdminUser, Password: secret})
	})
}

func (h *registryHandler) harbor(ctx context.Context, r sqlc.PackageRegistry, fn func(c registry.HarborClient) error) error {
	return h.withAPI(ctx, r, func(c registry.HTTP) error { return fn(registry.HarborClient{HTTP: c}) })
}

func (h *registryHandler) verdaccio(ctx context.Context, r sqlc.PackageRegistry, fn func(c registry.VerdaccioClient) error) error {
	return h.withAPI(ctx, r, func(c registry.HTTP) error { return fn(registry.VerdaccioClient{HTTP: c}) })
}

// root runs script as root on the registry's server and returns stdout.
func (h *registryHandler) root(ctx context.Context, serverID uuid.UUID, script string, secrets ...string) (string, error) {
	var out string
	err := h.s.withShell(ctx, serverID.String(), func(_ *sshpool.Conn, sh *rootShell) error {
		var err error
		out, err = sh.hiding(false, secrets...).run(ctx, script)
		return err
	})
	return out, err
}

// registryProblem turns what talking to a registry returned into an answer.
func registryProblem(err error) error {
	var ae *registry.APIError
	if errors.As(err, &ae) {
		switch ae.Status {
		case http.StatusNotFound:
			return huma.Error404NotFound(ae.Message)
		case http.StatusConflict:
			return huma.Error409Conflict(ae.Message)
		case http.StatusBadRequest, http.StatusUnprocessableEntity, http.StatusForbidden:
			return huma.Error422UnprocessableEntity(ae.Message)
		}
		return huma.Error502BadGateway(ae.Message)
	}
	var ne net.Error
	if errors.As(err, &ne) || strings.Contains(err.Error(), "connect failed") || strings.Contains(err.Error(), "connection refused") {
		return huma.Error502BadGateway("The registry doesn't answer on the server. Is it running?")
	}
	return toProblem(err)
}

func mustReady(r sqlc.PackageRegistry) error {
	switch r.State {
	case "deploying":
		return huma.Error409Conflict("It's still being deployed")
	case "removing":
		return huma.Error409Conflict("It's being removed")
	case "failed":
		return huma.Error409Conflict("Its deploy failed: deploy it again first")
	}
	return nil
}

// usableProxy is the server's reverse proxy a registry's site goes on.
func (h *registryHandler) usableProxy(ctx context.Context, serverID uuid.UUID) (*sqlc.Proxy, []RegistryProxyChoice, error) {
	rows, err := h.s.q.ListProxies(ctx, sqlc.ListProxiesParams{SeeAll: true, WorkspaceIds: []uuid.UUID{}, ServerIds: []uuid.UUID{}, ServerID: &serverID})
	if err != nil {
		return nil, nil, internalError(err)
	}
	var pick *sqlc.Proxy
	choices := []RegistryProxyChoice{}
	for _, r := range rows {
		usable := r.Proxy.Manager == "" && r.Proxy.Status != "not_installed" && r.Proxy.Status != "not_set_up"
		label := r.Proxy.Kind
		if d, ok := proxy.Get(r.Proxy.Kind); ok {
			label = d.Label()
		}
		if r.Proxy.Container != "" {
			label += " · " + r.Proxy.Container
		}
		choices = append(choices, RegistryProxyChoice{ID: r.Proxy.ID.String(), Label: label, Status: r.Proxy.Status, Usable: usable})
		if usable && pick == nil {
			p := r.Proxy
			pick = &p
		}
	}
	return pick, choices, nil
}

func registryProject(kind, name string) string {
	if kind == registry.Harbor {
		return "harbor"
	}
	var b strings.Builder
	for _, c := range strings.ToLower(name) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteRune(c)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		s = "npm"
	}
	if len(s) > 40 {
		s = strings.Trim(s[:40], "-")
	}
	return "verdaccio-" + s
}

func (h *registryHandler) preflight(ctx context.Context, serverID uuid.UUID, kind string, port int, domain string, name string) (RegistryPreflight, error) {
	k, ok := registry.KindOf(kind)
	if !ok {
		return RegistryPreflight{}, fieldError("body.kind", "Choose harbor or verdaccio", kind)
	}
	s, err := h.s.get(ctx, serverID.String())
	if err != nil {
		return RegistryPreflight{}, err
	}
	set, err := h.s.serverDockerSettings(ctx, s)
	if err != nil {
		return RegistryPreflight{}, err
	}
	if port == 0 {
		port = k.DefaultPort
	}
	used, err := h.s.q.ListServerPackageRegistryPorts(ctx, serverID)
	if err != nil {
		return RegistryPreflight{}, internalError(err)
	}
	for taken := func(p int) bool {
		for _, u := range used {
			if int(u) == p {
				return true
			}
		}
		return false
	}; taken(port); port++ {
	}
	project := registryProject(kind, name)
	out := RegistryPreflight{Problems: []string{}, Warnings: []string{}, Project: project, Port: port, Dir: strings.TrimSuffix(set.ProjectsDir, "/") + "/" + project}
	text, err := h.root(ctx, serverID, registry.PreflightScript(out.Dir, port))
	if err != nil {
		return out, toProblem(err)
	}
	out.Preflight = registry.ParsePreflight(text)
	if !out.PortFree {
		// Look for the next free one once.
		for p := port + 1; p < port+20; p++ {
			text, err := h.root(ctx, serverID, registry.PreflightScript(out.Dir, p))
			if err == nil && registry.ParsePreflight(text).PortFree {
				out.Port, out.PortFree = p, true
				out.Warnings = append(out.Warnings, fmt.Sprintf("Port %d is taken on the server, so it will use %d.", port, p))
				break
			}
		}
		if !out.PortFree {
			out.Problems = append(out.Problems, fmt.Sprintf("Port %d is taken on the server: pick another one.", port))
		}
	}
	if out.Docker == "" {
		out.Problems = append(out.Problems, "Docker isn't installed or running on this server. Install it from Applications first.")
	} else if out.Compose == "" {
		out.Problems = append(out.Problems, "Docker Compose isn't installed on this server.")
	}
	if out.Exists {
		out.Problems = append(out.Problems, out.Dir+" already exists on the server.")
	}
	if kind == registry.Harbor {
		var clash []string
		for _, n := range registry.HarborContainers {
			if slices.Contains(out.Names, n) {
				clash = append(clash, n)
			}
		}
		if len(clash) > 0 {
			out.Problems = append(out.Problems, "Harbor's containers have fixed names, and this server already has containers called "+strings.Join(clash, ", ")+". Rename or remove them first, or use another server.")
		}
		if strings.ContainsAny(out.Dir, " \t'\"") {
			out.Problems = append(out.Problems, "Harbor can't live in a folder with spaces or quotes ("+out.Dir+"): change the projects folder in Containers › Global settings.")
		}
	}
	if kind == registry.Harbor && !out.Fetch {
		out.Problems = append(out.Problems, "Harbor's installer is downloaded with curl or wget, and neither is installed.")
	}
	if out.MemoryMB > 0 && out.MemoryMB < k.MinMemoryMB {
		out.Problems = append(out.Problems, fmt.Sprintf("%s needs at least %d MB of memory; this server has %d MB.", k.Label, k.MinMemoryMB, out.MemoryMB))
	} else if out.MemoryMB > 0 && out.MemoryMB < k.MemoryMB {
		out.Warnings = append(out.Warnings, fmt.Sprintf("%s runs best with %d MB of memory; this server has %d MB.", k.Label, k.MemoryMB, out.MemoryMB))
	}
	if out.FreeGB > 0 && out.FreeGB < k.DiskGB {
		out.Warnings = append(out.Warnings, fmt.Sprintf("Only %d GB free where it goes; %s wants %d GB or more.", out.FreeGB, k.Label, k.DiskGB))
	}
	if kind == registry.Harbor {
		rows, _ := h.s.q.ListPackageRegistries(ctx, sqlc.ListPackageRegistriesParams{SeeAll: true, WorkspaceIds: []uuid.UUID{}, ServerIds: []uuid.UUID{}, ServerID: &serverID})
		for _, r := range rows {
			if r.PackageRegistry.Kind == registry.Harbor {
				out.Problems = append(out.Problems, "This server already runs a Harbor (its containers have fixed names, so one per server).")
			}
		}
	}
	pick, choices, err := h.usableProxy(ctx, serverID)
	if err != nil {
		return out, err
	}
	out.Proxies = choices
	if domain != "" {
		if pick == nil {
			out.Problems = append(out.Problems, "A domain needs a reverse proxy on this server, set up in Reverse proxy. Add one, or leave the domain empty to open the port instead.")
		} else if hosts, err := h.s.q.ListProxyHosts(ctx, pick.ID); err == nil {
			for _, x := range hosts {
				for _, d := range x.Domains {
					if strings.EqualFold(d, domain) {
						out.Problems = append(out.Problems, domain+" is already a site on this server's proxy.")
					}
				}
			}
		}
	} else {
		out.Warnings = append(out.Warnings, "Without a domain it answers plain http on the port, so Docker clients must list it under insecure-registries.")
	}
	return out, nil
}

// ---- endpoints ----

func registerPackageRegistries(api huma.API, h *registryHandler) {
	tags := []string{"Package registries"}
	base := "/package-registries/{id}"

	huma.Register(api, huma.Operation{
		OperationID: "list-package-registry-kinds", Method: http.MethodGet, Path: "/package-registry-kinds",
		Summary: "Kinds of registry Morche can deploy", Tags: tags,
	}, func(ctx context.Context, _ *struct{}) (*struct {
		Body struct {
			Items []registry.RegistryKind `json:"items"`
		}
	}, error) {
		out := &struct {
			Body struct {
				Items []registry.RegistryKind `json:"items"`
			}
		}{}
		out.Body.Items = registry.Kinds
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-package-registries", Method: http.MethodGet, Path: "/package-registries",
		Summary: "Package registries you can see", Tags: tags,
	}, func(ctx context.Context, in *struct {
		ServerID string `query:"server_id" format:"uuid" doc:"Only this server's"`
	}) (*struct {
		Body struct {
			Items []PackageRegistry `json:"items"`
		}
	}, error) {
		sc := principalOf(ctx).scope()
		rows, err := h.s.q.ListPackageRegistries(ctx, sqlc.ListPackageRegistriesParams{
			SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, ServerIds: sc.servers, WorkspaceID: sc.current,
			ServerID: parseOptionalID(&in.ServerID),
		})
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []PackageRegistry `json:"items"`
			}
		}{}
		out.Body.Items = make([]PackageRegistry, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = h.out(ctx, sqlc.GetPackageRegistryRow(r))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "package-registry-preflight", Method: http.MethodPost, Path: "/servers/{id}/package-registry-preflight",
		Summary:     "What deploying a registry on this server needs",
		Description: "Docker, Compose, memory, disk, a free port, the folder, and the server's reverse proxy for a domain.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body struct {
			Kind   string `json:"kind" enum:"harbor,verdaccio"`
			Name   string `json:"name,omitempty" maxLength:"100"`
			Port   int    `json:"port,omitempty" minimum:"0" maximum:"65535"`
			Domain string `json:"domain,omitempty" maxLength:"253"`
		}
	}) (*struct{ Body RegistryPreflight }, error) {
		p, err := h.preflight(ctx, uuid.MustParse(in.ID), in.Body.Kind, in.Body.Port, strings.ToLower(strings.TrimSpace(in.Body.Domain)), in.Body.Name)
		if err != nil {
			return nil, err
		}
		return &struct{ Body RegistryPreflight }{p}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-package-registry", Method: http.MethodPost, Path: "/package-registries",
		Summary: "Deploy a package registry on a server",
		Description: "Checks the server, then deploys it as a background job (kind `" + registryDeployKind + "`): the compose project, a first admin with a random password, " +
			"its settings (mirror, cleanup), a site on the server's reverse proxy with a Let's Encrypt certificate when a domain is given, and for Harbor a robot login in Containers › Registries. Needs Engineer on the server.",
		Tags: tags, DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct{ Body RegistryCreateBody }) (*struct{ Body RegistryCreated }, error) {
		b := in.Body
		sid, err := uuid.Parse(b.ServerID)
		if err != nil {
			return nil, fieldError("body.server_id", "Pick a server", b.ServerID)
		}
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
		b.Name = strings.TrimSpace(b.Name)
		b.Domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(b.Domain)), ".")
		if b.Domain != "" && !domainRe.MatchString(b.Domain) {
			return nil, fieldError("body.domain", "Give a name like registry.example.com", b.Domain)
		}
		if b.Domain == "" {
			b.HTTPS = false
		}
		if probs := b.Settings.Clean(b.Kind); len(probs) > 0 {
			return nil, fieldError("body.settings."+probs[0].Field, probs[0].Message, nil)
		}
		pf, err := h.preflight(ctx, sid, b.Kind, b.Port, b.Domain, b.Name)
		if err != nil {
			return nil, err
		}
		if len(pf.Problems) > 0 {
			return nil, huma.Error422UnprocessableEntity(pf.Problems[0])
		}
		admin := "admin"
		secret := registry.Password(24)
		k, _ := registry.KindOf(b.Kind)
		set, _ := json.Marshal(b.Settings)
		name, _ := actorName(ctx)
		r, err := h.s.q.CreatePackageRegistry(ctx, sqlc.CreatePackageRegistryParams{
			ServerID: sid, Kind: b.Kind, Name: b.Name, Note: strings.TrimSpace(b.Note), Project: pf.Project, Dir: pf.Dir,
			Port: int32(pf.Port), Domain: b.Domain, Https: b.HTTPS, Version: strings.TrimPrefix(k.Version, "v"), AdminUser: admin,
			AdminSecretEnc: h.s.box.Seal(secret), Settings: set, CreatedByName: name,
		})
		if isUniqueViolation(err) {
			return nil, huma.Error409Conflict("This server already has a registry with that name or kind")
		}
		if err != nil {
			return nil, internalError(err)
		}
		job, err := h.submit(ctx, r, registryDeployKind, "Deploy "+k.Label+" "+r.Name, registryJobParams{Email: strings.TrimSpace(b.Email)})
		if err != nil {
			_ = h.s.q.DeletePackageRegistry(context.WithoutCancel(ctx), r.ID)
			return nil, err
		}
		row, err := h.get(ctx, r.ID.String())
		if err != nil {
			return nil, err
		}
		return &struct{ Body RegistryCreated }{RegistryCreated{Registry: h.out(ctx, row), Job: job.Body}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-package-registry", Method: http.MethodGet, Path: base,
		Summary: "A package registry", Tags: tags,
	}, func(ctx context.Context, in *RegistryIDPath) (*struct{ Body PackageRegistry }, error) {
		r, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body PackageRegistry }{h.out(ctx, r)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-package-registry", Method: http.MethodPut, Path: base,
		Summary:     "Change a registry's name, note and settings",
		Description: "Settings are applied at once: Harbor through its API (mirror project, who can pull, weekly cleanup; the scanner only changes on a new deploy), Verdaccio by rewriting its config and restarting it (a few seconds).",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		RegistryIDPath
		Body RegistryUpdateBody
	}) (*struct{ Body PackageRegistry }, error) {
		row, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		r := row.PackageRegistry
		b := in.Body
		if probs := b.Settings.Clean(r.Kind); len(probs) > 0 {
			return nil, fieldError("body.settings."+probs[0].Field, probs[0].Message, nil)
		}
		var was registry.RegistrySettings
		_ = json.Unmarshal(r.Settings, &was)
		if r.Kind == registry.Harbor {
			b.Settings.Scanner = was.Scanner
		}
		if r.State == "ready" {
			if err := h.applySettings(ctx, r, row.ServerHost, was, b.Settings, strings.TrimSpace(b.Name)); err != nil {
				return nil, registryProblem(err)
			}
		}
		set, _ := json.Marshal(b.Settings)
		if _, err := h.s.q.UpdatePackageRegistry(ctx, sqlc.UpdatePackageRegistryParams{
			ID: r.ID, Name: strings.TrimSpace(b.Name), Note: strings.TrimSpace(b.Note), Settings: set,
		}); err != nil {
			return nil, internalError(err)
		}
		row, err = h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body PackageRegistry }{h.out(ctx, row)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-package-registry", Method: http.MethodDelete, Path: base,
		Summary: "Remove a registry",
		Description: "A background job (kind `" + registryRemoveKind + "`): takes the compose project down, removes its folder with every image or package (unless `keep_data`), " +
			"its reverse proxy site and its Containers registry login. Needs Owner on the server.",
		Tags: tags, DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		RegistryIDPath
		KeepData bool `query:"keep_data" doc:"Leave its folder (images, packages, database) on the server"`
	}) (*JobOutput, error) {
		row, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if row.PackageRegistry.State == "deploying" || row.PackageRegistry.State == "removing" {
			if row.PackageRegistry.JobID != nil {
				if j, err := h.s.jobs.Get(ctx, *row.PackageRegistry.JobID); err == nil && (j.State == "queued" || j.State == "running") {
					return nil, huma.Error409Conflict("A job is still working on it: cancel it first")
				}
			}
		}
		return h.submit(ctx, row.PackageRegistry, registryRemoveKind, "Remove "+row.PackageRegistry.Name, registryJobParams{KeepData: in.KeepData})
	})

	huma.Register(api, huma.Operation{
		OperationID: "redeploy-package-registry", Method: http.MethodPost, Path: base + "/redeploy",
		Summary:     "Deploy a registry again",
		Description: "Writes its files and starts it again with the same admin, data and settings (after a failed deploy, or to apply Harbor's scanner setting). A job of kind `" + registryDeployKind + "`.",
		Tags:        tags, DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		RegistryIDPath
		Body struct {
			Scanner *bool `json:"scanner,omitempty" doc:"Harbor: turn the Trivy scanner on or off with it"`
		}
	}) (*JobOutput, error) {
		row, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		r := row.PackageRegistry
		if r.State == "removing" {
			return nil, huma.Error409Conflict("It's being removed")
		}
		if in.Body.Scanner != nil && r.Kind == registry.Harbor {
			var set registry.RegistrySettings
			_ = json.Unmarshal(r.Settings, &set)
			set.Scanner = *in.Body.Scanner
			raw, _ := json.Marshal(set)
			if _, err := h.s.q.UpdatePackageRegistry(ctx, sqlc.UpdatePackageRegistryParams{ID: r.ID, Name: r.Name, Note: r.Note, Settings: raw}); err != nil {
				return nil, internalError(err)
			}
		}
		k, _ := registry.KindOf(r.Kind)
		return h.submit(ctx, r, registryDeployKind, "Deploy "+k.Label+" "+r.Name+" again", registryJobParams{})
	})

	huma.Register(api, huma.Operation{
		OperationID: "secure-package-registry", Method: http.MethodPost, Path: base + "/https",
		Summary:     "Get HTTPS for a registry's domain",
		Description: "Makes its reverse proxy site when it has none, gets a Let's Encrypt certificate and turns https on. A job of kind `" + registryHTTPSKind + "`.",
		Tags:        tags, DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		RegistryIDPath
		Body struct {
			Email string `json:"email,omitempty" maxLength:"200"`
		}
	}) (*JobOutput, error) {
		row, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		r := row.PackageRegistry
		if err := mustReady(r); err != nil {
			return nil, err
		}
		if r.Domain == "" {
			return nil, huma.Error422UnprocessableEntity("It has no domain: HTTPS needs one")
		}
		return h.submit(ctx, r, registryHTTPSKind, "Get HTTPS for "+r.Domain, registryJobParams{Email: strings.TrimSpace(in.Body.Email)})
	})

	huma.Register(api, huma.Operation{
		OperationID: "check-package-registry", Method: http.MethodPost, Path: base + "/check",
		Summary: "Check a registry now", Tags: tags,
	}, func(ctx context.Context, in *RegistryIDPath) (*struct{ Body PackageRegistry }, error) {
		row, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if row.PackageRegistry.State == "ready" {
			h.check(ctx, row.PackageRegistry)
		}
		row, err = h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body PackageRegistry }{h.out(ctx, row)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "package-registry-action", Method: http.MethodPost, Path: base + "/actions/{action}",
		Summary:     "Start, stop or restart a registry",
		Description: "Its compose project's start, stop or restart. `cleanup` (Harbor) runs garbage collection now, freeing the space of deleted images.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		RegistryIDPath
		Action string `path:"action" enum:"start,stop,restart,cleanup"`
	}) (*struct{ Body PackageRegistry }, error) {
		row, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		r := row.PackageRegistry
		if err := mustReady(r); err != nil {
			return nil, err
		}
		if in.Action == "cleanup" {
			if r.Kind != registry.Harbor {
				return nil, huma.Error422UnprocessableEntity("Only Harbor has a cleanup to run")
			}
			if err := h.harbor(ctx, r, func(c registry.HarborClient) error { return c.ScheduleGC(ctx, true) }); err != nil {
				return nil, registryProblem(err)
			}
		} else {
			verb := in.Action
			if _, err := h.root(ctx, r.ServerID, registry.ActionScript(r.Dir, r.Project, verb)); err != nil {
				return nil, shellFailure(err, "")
			}
			if in.Action != "stop" {
				time.Sleep(2 * time.Second)
			}
			h.check(ctx, r)
		}
		row, err = h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body PackageRegistry }{h.out(ctx, row)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-package-registry-credentials", Method: http.MethodGet, Path: base + "/credentials",
		Summary: "The registry's admin login", Description: "Needs Owner on the server.", Tags: tags,
	}, func(ctx context.Context, in *RegistryIDPath) (*struct{ Body RegistryCredentials }, error) {
		row, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		secret, err := h.adminSecret(row.PackageRegistry)
		if err != nil {
			return nil, huma.Error422UnprocessableEntity(err.Error())
		}
		_, url := registryAddress(row.PackageRegistry, row.ServerHost)
		return &struct{ Body RegistryCredentials }{RegistryCredentials{User: row.PackageRegistry.AdminUser, Password: secret, URL: url}}, nil
	})

	registerPackageRegistryContents(api, h, base, tags)

	h.s.jobs.Handle(registryDeployKind, h.runDeploy)
	h.s.jobs.Handle(registryHTTPSKind, h.runHTTPS)
	h.s.jobs.Handle(registryRemoveKind, h.runRemove)
}

func (h *registryHandler) submit(ctx context.Context, r sqlc.PackageRegistry, kind, title string, p registryJobParams) (*JobOutput, error) {
	s, err := h.s.get(ctx, r.ServerID.String())
	if err != nil {
		return nil, err
	}
	p.RegistryID, p.ServerID = r.ID.String(), r.ServerID.String()
	j, err := submit(ctx, h.s.jobs, jobs.Spec{
		Kind: kind, Title: title + " on " + s.Name, Params: p,
		Refs:   placeRefs(r.ServerID.String(), r.ID.String()),
		Target: &JobPlace{ServerID: r.ServerID.String(), Name: s.Name, Path: r.Dir, PackageRegistry: r.ID.String()},
	})
	if err != nil {
		return nil, err
	}
	state := r.State
	switch kind {
	case registryDeployKind:
		state = "deploying"
	case registryRemoveKind:
		state = "removing"
	}
	jid := uuid.MustParse(j.Body.ID)
	if err := h.s.q.SetPackageRegistryJob(ctx, sqlc.SetPackageRegistryJobParams{ID: r.ID, JobID: &jid, State: state}); err != nil {
		return nil, internalError(err)
	}
	return j, nil
}

// applySettings puts changed settings into a running registry.
func (h *registryHandler) applySettings(ctx context.Context, r sqlc.PackageRegistry, serverHost string, was, now registry.RegistrySettings, name string) error {
	switch r.Kind {
	case registry.Harbor:
		return h.harbor(ctx, r, func(c registry.HarborClient) error { return harborSettings(ctx, c, now, nil) })
	case registry.Verdaccio:
		if was.Public == now.Public && was.Mirror == now.Mirror && was.Upstream == now.Upstream &&
			strings.Join(was.Scopes, ",") == strings.Join(now.Scopes, ",") && name == r.Name {
			return nil
		}
		_, err := h.root(ctx, r.ServerID, registry.VerdaccioConfigScript(verdaccioConfig(r, serverHost, now, name), r.Project))
		if err != nil {
			return shellFailure(err, "")
		}
		return nil
	}
	return nil
}

func verdaccioConfig(r sqlc.PackageRegistry, serverHost string, set registry.RegistrySettings, name string) registry.VerdaccioConfig {
	_, url := registryAddress(r, serverHost)
	if r.Domain == "" {
		url = ""
	}
	return registry.VerdaccioConfig{Dir: r.Dir, Name: name, Port: int(r.Port), Open: r.Domain == "", PublicURL: url, Settings: set}
}

// harborSettings puts Harbor in step with set: the library project's
// visibility, the Docker Hub cache project, weekly cleanup. logf may be nil.
func harborSettings(ctx context.Context, c registry.HarborClient, set registry.RegistrySettings, logf func(string, ...any)) error {
	say := func(f string, a ...any) {
		if logf != nil {
			logf(f, a...)
		}
	}
	ps, err := c.Projects(ctx)
	if err != nil {
		return err
	}
	has := map[string]registry.HarborProject{}
	for _, p := range ps {
		has[p.Name] = p
	}
	public := strconv.FormatBool(set.Public)
	for _, p := range ps {
		if p.Name == "library" || (p.Name == set.MirrorProject && p.RegistryID > 0) {
			if p.Metadata["public"] != public {
				if err := c.SetProjectPublic(ctx, p.Name, set.Public); err != nil {
					return err
				}
				say("Made the %s project %s.", p.Name, map[bool]string{true: "public", false: "private"}[set.Public])
			}
		}
	}
	if set.Mirror {
		if _, ok := has[set.MirrorProject]; !ok {
			id, err := c.DockerHubEndpoint(ctx)
			if err != nil {
				return err
			}
			if err := c.CreateProject(ctx, set.MirrorProject, set.Public, id); err != nil {
				return err
			}
			say("Made the %s project, a cache of Docker Hub.", set.MirrorProject)
		}
	}
	if set.Cleanup {
		if err := c.ScheduleGC(ctx, false); err != nil {
			return err
		}
		say("Cleanup runs every Sunday at 03:00.")
	}
	return nil
}

// ---- health ----

// check asks the registry how it is and records it.
func (h *registryHandler) check(ctx context.Context, r sqlc.PackageRegistry) {
	h.mu.Lock()
	if h.busy[r.ID] {
		h.mu.Unlock()
		return
	}
	h.busy[r.ID] = true
	h.mu.Unlock()
	defer func() { h.mu.Lock(); delete(h.busy, r.ID); h.mu.Unlock() }()

	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	health, problem, version := "online", "", ""
	var usage int64
	items := int(r.Items)
	switch r.Kind {
	case registry.Harbor:
		err := h.harbor(ctx, r, func(c registry.HarborClient) error {
			hh, err := c.Health(ctx)
			if err != nil {
				return err
			}
			if hh.Status != "healthy" {
				health = "degraded"
				var bad []string
				for _, x := range hh.Components {
					if x.Status != "healthy" {
						bad = append(bad, x.Name)
					}
				}
				problem = "Not healthy: " + strings.Join(bad, ", ")
			}
			if v, err := c.Version(ctx); err == nil {
				version = strings.TrimPrefix(v, "v")
			}
			if st, err := c.Statistics(ctx); err == nil {
				usage, items = st.Storage, st.Repos
			}
			return nil
		})
		if err != nil {
			health, problem = "down", registryProblem(err).Error()
		}
	case registry.Verdaccio:
		err := h.verdaccio(ctx, r, func(c registry.VerdaccioClient) error { return c.Ping(ctx) })
		if err != nil {
			health, problem = "down", registryProblem(err).Error()
		} else {
			if out, err := h.root(ctx, r.ServerID, registry.UsageScript(r.Dir+"/storage")); err == nil {
				usage, _ = strconv.ParseInt(strings.TrimSpace(out), 10, 64)
			}
			if out, err := h.root(ctx, r.ServerID, registry.ListPackagesScript(r.Project)); err == nil {
				if ps, err := registry.ParsePackages(out); err == nil {
					items = len(ps)
				}
			}
		}
	}
	if err := h.s.q.SetPackageRegistryHealth(context.WithoutCancel(ctx), sqlc.SetPackageRegistryHealthParams{
		ID: r.ID, Health: health, Problem: problem, Version: version, UsageBytes: usage, Items: int32(items),
	}); err != nil {
		slog.Warn("registry health", "id", r.ID, "err", err)
	}
}

func startRegistryMonitor(h *registryHandler) {
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			rows, err := h.s.q.ListAllPackageRegistries(context.Background())
			if err != nil {
				continue
			}
			for _, r := range rows {
				if r.CheckedAt != nil && time.Since(*r.CheckedAt) < registryCheckEvery {
					continue
				}
				go h.check(context.Background(), r)
			}
		}
	}()
}
