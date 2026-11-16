package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/dbmon"
	"github.com/morche/backend/internal/jobs"
	"github.com/morche/backend/internal/proxmox"
	"github.com/morche/backend/internal/secrets"
)

// pveHandler connects Morche to Proxmox VE clusters. Only the connection and
// the last check are stored; machines, nodes and storages are read live.
type pveHandler struct {
	q       *sqlc.Queries
	box     *secrets.Box
	authz   *authz
	servers *serverHandler
	runner  *jobs.Runner
}

type PVEClusterIDPath struct {
	ID string `path:"id" format:"uuid"`
}

// PVECluster is a connection. The token's secret never leaves the backend.
type PVECluster struct {
	ID            string     `json:"id" format:"uuid"`
	WorkspaceID   string     `json:"workspace_id" format:"uuid"`
	Name          string     `json:"name"`
	URL           string     `json:"url"`
	TokenID       string     `json:"token_id" doc:"user@realm!tokenname"`
	Fingerprint   string     `json:"fingerprint" doc:"The pinned certificate (SHA-256), empty when not pinned"`
	TLSSkipVerify bool       `json:"tls_skip_verify"`
	AllowInternal bool       `json:"allow_internal"`
	Description   string     `json:"description"`
	Favorite      bool       `json:"favorite"`
	Status        string     `json:"status" enum:"unknown,online,unreachable,auth_failed,tls_error,blocked,error"`
	StatusMessage string     `json:"status_message"`
	Version       string     `json:"version"`
	ClusterName   string     `json:"cluster_name" doc:"Proxmox's own name for the cluster; empty for a single node"`
	NodeCount     int32      `json:"node_count"`
	NodesOnline   int32      `json:"nodes_online"`
	GuestCount    int32      `json:"guest_count"`
	RunningCount  int32      `json:"running_count"`
	LatencyMs     *int32     `json:"latency_ms,omitempty"`
	LastCheckedAt *time.Time `json:"last_checked_at,omitempty"`
	LastOnlineAt  *time.Time `json:"last_online_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func toPVECluster(c sqlc.PveCluster) PVECluster {
	return PVECluster{
		ID: c.ID.String(), WorkspaceID: c.WorkspaceID.String(), Name: c.Name, URL: c.Url,
		TokenID: c.TokenID, Fingerprint: c.Fingerprint, TLSSkipVerify: c.TlsSkipVerify,
		AllowInternal: c.AllowInternal, Description: c.Description, Favorite: c.Favorite,
		Status: c.Status, StatusMessage: c.StatusMessage, Version: c.Version,
		ClusterName: c.ClusterName, NodeCount: c.NodeCount, NodesOnline: c.NodesOnline,
		GuestCount: c.GuestCount, RunningCount: c.RunningCount, LatencyMs: c.LatencyMs,
		LastCheckedAt: c.LastCheckedAt, LastOnlineAt: c.LastOnlineAt,
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
}

type PVEClusterOutput struct {
	Body PVECluster
}

type PVEClusterBody struct {
	Name          string `json:"name" minLength:"1" maxLength:"100"`
	URL           string `json:"url" minLength:"1" maxLength:"500" doc:"Any node's address, like https://pve1.example.com:8006"`
	TokenID       string `json:"token_id" minLength:"1" maxLength:"300" doc:"user@realm!tokenname, or the whole user@realm!tokenname=secret"`
	Secret        string `json:"secret,omitempty" maxLength:"300" doc:"The token's secret. Blank on update keeps the saved one."`
	Fingerprint   string `json:"fingerprint,omitempty" maxLength:"200" doc:"Pin the certificate (SHA-256). Safer than skipping the check."`
	TLSSkipVerify bool   `json:"tls_skip_verify,omitempty"`
	AllowInternal bool   `json:"allow_internal,omitempty" doc:"Reach a private or loopback address. System admins only."`
	Description   string `json:"description,omitempty" maxLength:"500"`
}

var pveTokenID = regexp.MustCompile(`^[^\s@!=]+@[^\s@!=]+![A-Za-z0-9._-]+$`)

// splitToken accepts the token as Proxmox shows it once, id=secret, or the
// two apart.
func splitToken(id, secret string) (string, string, error) {
	id, secret = strings.TrimSpace(id), strings.TrimSpace(secret)
	if strings.HasPrefix(id, "PVEAPIToken=") {
		id = strings.TrimPrefix(id, "PVEAPIToken=")
	}
	if i := strings.Index(id, "="); i > 0 {
		if secret == "" {
			secret = strings.TrimSpace(id[i+1:])
		}
		id = id[:i]
	}
	if !pveTokenID.MatchString(id) {
		return "", "", fieldError("body.token_id", "Enter the token ID like root@pam!morche", id)
	}
	return id, secret, nil
}

// cleanPVEURL accepts a plain https base address. Port 8006 is added when
// none is given, since that's where Proxmox listens.
func cleanPVEURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fieldError("body.url", "Enter an address like https://pve1.example.com:8006", raw)
	}
	if u.User != nil {
		return "", fieldError("body.url", "Leave the user and password out of the address", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fieldError("body.url", "Enter just the node's address, with no query", raw)
	}
	host := u.Host
	if u.Port() == "" {
		host += ":8006"
	}
	path := strings.TrimSuffix(strings.TrimRight(u.EscapedPath(), "/"), "/api2/json")
	return strings.TrimRight(u.Scheme+"://"+host+path, "/"), nil
}

type pveConnection struct {
	url, tokenID, secret, fingerprint string
	skipVerify, allowInternal         bool
}

func pveClient(c pveConnection) *proxmox.Client {
	return proxmox.New(proxmox.Config{
		URL: c.url, TokenID: c.tokenID, Secret: c.secret, Fingerprint: c.fingerprint,
		SkipVerify: c.skipVerify, Dial: dbmon.DirectDialer(c.allowInternal),
	})
}

func (h *pveHandler) savedClient(c sqlc.PveCluster) (*proxmox.Client, error) {
	secret, err := h.box.Open(c.SecretEnc)
	if err != nil {
		return nil, err
	}
	return pveClient(pveConnection{c.Url, c.TokenID, secret, c.Fingerprint, c.TlsSkipVerify, c.AllowInternal}), nil
}

// pveStatus adds the status only this layer knows about to the client's.
func pveStatus(err error) (string, string) {
	var blocked *dbmon.BlockedError
	if errors.As(err, &blocked) {
		return dbmon.StatusBlocked, blocked.Error()
	}
	return proxmox.Classify(err)
}

func (h *pveHandler) record(ctx context.Context, id uuid.UUID, info proxmox.Info, checkErr error) (sqlc.PveCluster, error) {
	status, message := pveStatus(checkErr)
	var latency *int32
	if checkErr == nil {
		ms := int32(info.Latency.Milliseconds())
		latency = &ms
	}
	return h.q.RecordPVEClusterCheck(ctx, sqlc.RecordPVEClusterCheckParams{
		ID: id, Status: status, StatusMessage: message, Version: info.Version,
		ClusterName: info.ClusterName, NodeCount: int32(info.Nodes), NodesOnline: int32(info.NodesOnline),
		GuestCount: int32(info.Guests), RunningCount: int32(info.Running), LatencyMs: latency,
	})
}

// pveError turns what Proxmox said into the API's answer. A refusal (a bad
// value, a locked machine) is the caller's to fix.
func pveError(err error) error {
	var se huma.StatusError
	if errors.As(err, &se) {
		return err
	}
	var api *proxmox.APIError
	if errors.As(err, &api) {
		if proxmox.IsMissing(err) {
			return huma.Error404NotFound(api.Error())
		}
		return huma.Error422UnprocessableEntity(api.Error())
	}
	var perm *proxmox.PermissionError
	if errors.As(err, &perm) {
		return huma.Error422UnprocessableEntity("Proxmox refused: " + perm.Error() + ". Give the API token the privilege on the cluster.")
	}
	_, message := pveStatus(err)
	return huma.Error502BadGateway("Couldn't reach the Proxmox cluster: " + message)
}

func (h *pveHandler) cluster(ctx context.Context, rawID string) (sqlc.PveCluster, error) {
	id, err := uuid.Parse(rawID)
	if err != nil {
		return sqlc.PveCluster{}, huma.Error404NotFound("Cluster not found")
	}
	c, err := h.q.GetPVECluster(ctx, id)
	if isNotFound(err) {
		return sqlc.PveCluster{}, huma.Error404NotFound("Cluster not found")
	}
	if err != nil {
		return sqlc.PveCluster{}, internalError(err)
	}
	return c, nil
}

// withCluster loads a cluster and hands over its client.
func (h *pveHandler) withCluster(ctx context.Context, rawID string) (sqlc.PveCluster, *proxmox.Client, error) {
	c, err := h.cluster(ctx, rawID)
	if err != nil {
		return c, nil, err
	}
	cl, err := h.savedClient(c)
	if err != nil {
		return c, nil, internalError(err)
	}
	return c, cl, nil
}

// resolveSecret: blank = the saved one, only for the address it was saved for.
func (h *pveHandler) resolveSecret(prev *sqlc.PveCluster, cleanURL, tokenID, secret string) (string, error) {
	if secret != "" {
		return secret, nil
	}
	if prev == nil {
		return "", fieldError("body.secret", "Enter the token's secret", "")
	}
	if !sameDNSOrigin(prev.Url, cleanURL) {
		return "", fieldError("body.secret", "The address changed: enter the secret again", "")
	}
	if prev.TokenID != tokenID {
		return "", fieldError("body.secret", "The token changed: enter its secret", "")
	}
	saved, err := h.box.Open(prev.SecretEnc)
	if err != nil {
		return "", internalError(err)
	}
	return saved, nil
}

func pveAllowInternal(p *principal, prev *sqlc.PveCluster, cleanURL string, want bool) error {
	if !want || p.Access.Admin {
		return nil
	}
	if prev != nil && prev.AllowInternal && sameDNSOrigin(prev.Url, cleanURL) {
		return nil
	}
	return fieldError("body.allow_internal", "Only a system admin can allow private addresses", true)
}

type pveSaved struct {
	url, tokenID, secret, fingerprint string
}

func (h *pveHandler) resolve(p *principal, prev *sqlc.PveCluster, b PVEClusterBody) (pveSaved, error) {
	clean, err := cleanPVEURL(b.URL)
	if err != nil {
		return pveSaved{}, err
	}
	if err := pveAllowInternal(p, prev, clean, b.AllowInternal); err != nil {
		return pveSaved{}, err
	}
	id, secret, err := splitToken(b.TokenID, b.Secret)
	if err != nil {
		return pveSaved{}, err
	}
	secret, err = h.resolveSecret(prev, clean, id, secret)
	if err != nil {
		return pveSaved{}, err
	}
	fp := ""
	if strings.TrimSpace(b.Fingerprint) != "" {
		if fp = proxmox.NormalizeFingerprint(b.Fingerprint); fp == "" {
			return pveSaved{}, fieldError("body.fingerprint", "Enter a SHA-256 fingerprint, like AB:CD:… (32 pairs)", b.Fingerprint)
		}
	}
	return pveSaved{clean, id, secret, fp}, nil
}

func (h *pveHandler) create(ctx context.Context, in *struct{ Body PVEClusterBody }) (*PVEClusterOutput, error) {
	p := principalOf(ctx)
	b := in.Body
	ws, err := h.authz.createTarget(ctx, p)
	if err != nil {
		return nil, err
	}
	if p.Access.WorkspaceLevel(ws) < auth.Owner {
		return nil, huma.Error403Forbidden("You need Owner access to the workspace to connect a Proxmox cluster.")
	}
	s, err := h.resolve(p, nil, b)
	if err != nil {
		return nil, err
	}
	c, err := h.q.CreatePVECluster(ctx, sqlc.CreatePVEClusterParams{
		WorkspaceID: ws, Name: strings.TrimSpace(b.Name), Url: s.url, TokenID: s.tokenID,
		SecretEnc: h.box.Seal(s.secret), Fingerprint: s.fingerprint,
		TlsSkipVerify: b.TLSSkipVerify && s.fingerprint == "", AllowInternal: b.AllowInternal,
		Description: strings.TrimSpace(b.Description),
	})
	if isUniqueViolation(err) {
		return nil, fieldError("body.name", "A cluster with this name already exists", b.Name)
	}
	if err != nil {
		return nil, internalError(err)
	}
	return &PVEClusterOutput{Body: toPVECluster(h.checkNow(ctx, c))}, nil
}

// checkNow checks a cluster just saved, so it doesn't show "unknown" until
// the monitor comes round.
func (h *pveHandler) checkNow(ctx context.Context, c sqlc.PveCluster) sqlc.PveCluster {
	cl, err := h.savedClient(c)
	if err != nil {
		return c
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	info, checkErr := cl.Check(cctx)
	saved, err := h.record(ctx, c.ID, info, checkErr)
	if err != nil {
		return c
	}
	return saved
}

func (h *pveHandler) update(ctx context.Context, in *struct {
	PVEClusterIDPath
	Body PVEClusterBody
}) (*PVEClusterOutput, error) {
	p := principalOf(ctx)
	b := in.Body
	prev, err := h.cluster(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	s, err := h.resolve(p, &prev, b)
	if err != nil {
		return nil, err
	}
	c, err := h.q.UpdatePVECluster(ctx, sqlc.UpdatePVEClusterParams{
		ID: prev.ID, Name: strings.TrimSpace(b.Name), Url: s.url, TokenID: s.tokenID,
		SecretEnc: h.box.Seal(s.secret), Fingerprint: s.fingerprint,
		TlsSkipVerify: b.TLSSkipVerify && s.fingerprint == "", AllowInternal: b.AllowInternal,
		Description: strings.TrimSpace(b.Description),
	})
	if isUniqueViolation(err) {
		return nil, fieldError("body.name", "A cluster with this name already exists", b.Name)
	}
	if err != nil {
		return nil, internalError(err)
	}
	return &PVEClusterOutput{Body: toPVECluster(h.checkNow(ctx, c))}, nil
}

type PVETestBody struct {
	URL           string  `json:"url" minLength:"1" maxLength:"500"`
	TokenID       string  `json:"token_id" minLength:"1" maxLength:"300"`
	Secret        string  `json:"secret,omitempty" maxLength:"300"`
	Fingerprint   string  `json:"fingerprint,omitempty" maxLength:"200"`
	TLSSkipVerify bool    `json:"tls_skip_verify,omitempty"`
	AllowInternal bool    `json:"allow_internal,omitempty"`
	ClusterID     *string `json:"cluster_id,omitempty" format:"uuid" doc:"When editing: the saved cluster, whose secret a blank one stands for."`
}

type PVETestOutput struct {
	Body struct {
		OK          bool   `json:"ok"`
		Status      string `json:"status"`
		Message     string `json:"message"`
		Version     string `json:"version"`
		ClusterName string `json:"cluster_name"`
		Nodes       int    `json:"nodes"`
		NodesOnline int    `json:"nodes_online"`
		Guests      int    `json:"guests"`
		Running     int    `json:"running"`
		LatencyMs   int64  `json:"latency_ms"`
		Fingerprint string `json:"fingerprint" doc:"The certificate the address shows now; pin it when you trust it"`
	}
}

func (h *pveHandler) test(ctx context.Context, in *struct{ Body PVETestBody }) (*PVETestOutput, error) {
	p := principalOf(ctx)
	b := in.Body
	var prev *sqlc.PveCluster
	if id := parseOptionalID(b.ClusterID); id != nil {
		c, err := h.q.GetPVECluster(ctx, *id)
		if isNotFound(err) || (err == nil && p.Access.WorkspaceLevel(c.WorkspaceID) == auth.None) {
			return nil, huma.Error404NotFound("Cluster not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if p.Access.WorkspaceLevel(c.WorkspaceID) < auth.Owner {
			return nil, huma.Error403Forbidden("You need Owner access to use this cluster's saved token.")
		}
		prev = &c
	} else {
		ws, err := h.authz.createTarget(ctx, p)
		if err != nil {
			return nil, err
		}
		if p.Access.WorkspaceLevel(ws) < auth.Owner {
			return nil, huma.Error403Forbidden("You need Owner access to the workspace to connect a Proxmox cluster.")
		}
	}
	s, err := h.resolve(p, prev, PVEClusterBody{
		URL: b.URL, TokenID: b.TokenID, Secret: b.Secret, Fingerprint: b.Fingerprint,
		TLSSkipVerify: b.TLSSkipVerify, AllowInternal: b.AllowInternal,
	})
	if err != nil {
		return nil, err
	}
	out := &PVETestOutput{}
	dial := dbmon.DirectDialer(b.AllowInternal)
	if strings.HasPrefix(s.url, "https://") {
		out.Body.Fingerprint, _ = proxmox.PeekFingerprint(ctx, s.url, dial)
	}
	cl := pveClient(pveConnection{s.url, s.tokenID, s.secret, s.fingerprint, b.TLSSkipVerify && s.fingerprint == "", b.AllowInternal})
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	info, checkErr := cl.Check(cctx)
	out.Body.Status, out.Body.Message = pveStatus(checkErr)
	out.Body.OK = checkErr == nil
	out.Body.Version, out.Body.ClusterName = info.Version, info.ClusterName
	out.Body.Nodes, out.Body.NodesOnline = info.Nodes, info.NodesOnline
	out.Body.Guests, out.Body.Running = info.Guests, info.Running
	out.Body.LatencyMs = info.Latency.Milliseconds()
	return out, nil
}

func (h *pveHandler) listClusters(ctx context.Context) ([]sqlc.PveCluster, error) {
	sc := principalOf(ctx).scope()
	rows, err := h.q.ListPVEClusters(ctx, sqlc.ListPVEClustersParams{
		SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, WorkspaceID: sc.current,
	})
	if err != nil {
		return nil, internalError(err)
	}
	return rows, nil
}

type PVEClustersOutput struct {
	Body struct {
		Items []PVECluster `json:"items"`
	}
}

func registerPVEClusters(api huma.API, h *pveHandler) {
	tags := []string{"Virtual machines"}

	huma.Register(api, huma.Operation{
		OperationID: "list-pve-clusters", Method: http.MethodGet, Path: "/pve-clusters",
		Summary: "List Proxmox clusters", Description: "Favourites first, then by name.", Tags: tags,
	}, func(ctx context.Context, _ *struct{}) (*PVEClustersOutput, error) {
		rows, err := h.listClusters(ctx)
		if err != nil {
			return nil, err
		}
		out := &PVEClustersOutput{}
		out.Body.Items = make([]PVECluster, 0, len(rows))
		for _, r := range rows {
			out.Body.Items = append(out.Body.Items, toPVECluster(r))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-pve-cluster", Method: http.MethodPost, Path: "/pve-clusters",
		Summary: "Connect a Proxmox cluster", Tags: tags, DefaultStatus: http.StatusCreated,
	}, h.create)

	huma.Register(api, huma.Operation{
		OperationID: "test-pve-connection", Method: http.MethodPost, Path: "/pve-clusters/test-connection",
		Summary:     "Test Proxmox connection settings",
		Description: "Connects with the given settings without saving anything, and shows the certificate's fingerprint to pin.",
		Tags:        tags,
	}, h.test)

	huma.Register(api, huma.Operation{
		OperationID: "get-pve-cluster", Method: http.MethodGet, Path: "/pve-clusters/{id}",
		Summary: "Get a Proxmox cluster", Tags: tags,
	}, func(ctx context.Context, in *struct{ PVEClusterIDPath }) (*PVEClusterOutput, error) {
		c, err := h.cluster(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &PVEClusterOutput{Body: toPVECluster(c)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-pve-cluster", Method: http.MethodPut, Path: "/pve-clusters/{id}",
		Summary: "Change a Proxmox cluster's connection", Tags: tags,
	}, h.update)

	huma.Register(api, huma.Operation{
		OperationID: "delete-pve-cluster", Method: http.MethodDelete, Path: "/pve-clusters/{id}",
		Summary:     "Disconnect a Proxmox cluster",
		Description: "Morche forgets the connection and its token. Nothing on the cluster changes.",
		Tags:        tags, DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *struct{ PVEClusterIDPath }) (*struct{}, error) {
		if err := h.q.DeletePVECluster(ctx, uuid.MustParse(in.ID)); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-pve-cluster-favorite", Method: http.MethodPut, Path: "/pve-clusters/{id}/favorite",
		Summary: "Star or unstar a Proxmox cluster", Tags: tags,
	}, func(ctx context.Context, in *struct {
		PVEClusterIDPath
		Body struct {
			Favorite bool `json:"favorite"`
		}
	}) (*PVEClusterOutput, error) {
		c, err := h.q.SetPVEClusterFavorite(ctx, sqlc.SetPVEClusterFavoriteParams{ID: uuid.MustParse(in.ID), Favorite: in.Body.Favorite})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("Cluster not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &PVEClusterOutput{Body: toPVECluster(c)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "check-pve-cluster", Method: http.MethodPost, Path: "/pve-clusters/{id}/check",
		Summary: "Check a Proxmox cluster's connection", Tags: tags,
	}, func(ctx context.Context, in *struct{ PVEClusterIDPath }) (*PVEClusterOutput, error) {
		c, err := h.cluster(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &PVEClusterOutput{Body: toPVECluster(h.checkNow(ctx, c))}, nil
	})
}
