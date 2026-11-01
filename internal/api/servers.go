package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/secrets"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/sshprobe"
	"github.com/morcheh/backend/internal/terminal"
)

// ---- Response types ----

type ServerOS struct {
	Family  string `json:"family" doc:"linux, darwin, freebsd, windows…; empty until a check detects it" example:"linux"`
	ID      string `json:"id" doc:"os-release ID (ubuntu, debian, rocky…), macos or windows" example:"ubuntu"`
	Name    string `json:"name" example:"Ubuntu"`
	Version string `json:"version" example:"24.04"`
	Kernel  string `json:"kernel" example:"6.8.0-45-generic"`
	Arch    string `json:"arch" example:"x86_64"`
}

type Server struct {
	ID         string  `json:"id" format:"uuid"`
	FolderID   *string `json:"folder_id" format:"uuid" nullable:"true"`
	Name       string  `json:"name" example:"web-01"`
	Host       string  `json:"host" doc:"IP address or DNS name" example:"10.0.0.12"`
	Port       int32   `json:"port" example:"22"`
	Username   string  `json:"username" example:"root"`
	AuthMethod string  `json:"auth_method" enum:"password,private_key"`
	// Secrets are write-only; these flags say which ones are stored.
	HasPassword        bool       `json:"has_password"`
	HasPrivateKey      bool       `json:"has_private_key"`
	HasPassphrase      bool       `json:"has_passphrase"`
	HostKeyFingerprint string     `json:"host_key_fingerprint" doc:"SHA256 fingerprint of the trusted host key; empty until the first successful check"`
	Description        string     `json:"description"`
	Tags               []string   `json:"tags"`
	Favorite           bool       `json:"favorite"`
	Status             string     `json:"status" enum:"unknown,online,unreachable,auth_failed,host_key_mismatch,error" doc:"Result of the last connection check"`
	StatusMessage      string     `json:"status_message" doc:"Human-readable detail for the status"`
	LatencyMs          *int32     `json:"latency_ms" nullable:"true" doc:"Time to connect and finish the SSH handshake on the last successful check"`
	OS                 ServerOS   `json:"os"`
	Hostname           string     `json:"hostname" doc:"The server's own hostname, as reported by uname"`
	LastCheckedAt      *time.Time `json:"last_checked_at" nullable:"true"`
	LastSeenAt         *time.Time `json:"last_seen_at" nullable:"true" doc:"Last time a check reached the server"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

func toServer(s sqlc.Server) Server {
	tags := s.Tags
	if tags == nil {
		tags = []string{}
	}
	return Server{
		ID:                 s.ID.String(),
		FolderID:           optionalIDString(s.FolderID),
		Name:               s.Name,
		Host:               s.Host,
		Port:               s.Port,
		Username:           s.Username,
		AuthMethod:         s.AuthMethod,
		HasPassword:        len(s.PasswordEnc) > 0,
		HasPrivateKey:      len(s.PrivateKeyEnc) > 0,
		HasPassphrase:      len(s.PassphraseEnc) > 0,
		HostKeyFingerprint: sshprobe.Fingerprint(s.HostKey),
		Description:        s.Description,
		Tags:               tags,
		Favorite:           s.Favorite,
		Status:             s.Status,
		StatusMessage:      s.StatusMessage,
		LatencyMs:          s.LatencyMs,
		OS: ServerOS{
			Family: s.OsFamily, ID: s.OsID, Name: s.OsName, Version: s.OsVersion,
			Kernel: s.Kernel, Arch: s.Arch,
		},
		Hostname:      s.Hostname,
		LastCheckedAt: s.LastCheckedAt,
		LastSeenAt:    s.LastSeenAt,
		CreatedAt:     s.CreatedAt,
		UpdatedAt:     s.UpdatedAt,
	}
}

type ServerOutput struct {
	Body Server
}

type ServerItemsOutput struct {
	Body struct {
		Items []Server `json:"items"`
	}
}

type AffectedOutput struct {
	Body struct {
		Affected int64 `json:"affected" doc:"How many servers changed"`
	}
}

// ---- Request types ----

// Connection is everything needed to open an SSH session.
type Connection struct {
	Host       string `json:"host" minLength:"1" maxLength:"253" doc:"IP address or DNS name" example:"10.0.0.12"`
	Port       int32  `json:"port,omitempty" minimum:"1" maximum:"65535" default:"22"`
	Username   string `json:"username" minLength:"1" maxLength:"64" example:"root"`
	AuthMethod string `json:"auth_method" enum:"password,private_key"`
	Password   string `json:"password,omitempty" maxLength:"1024" doc:"For auth_method=password. On update, leave out to keep the stored one"`
	PrivateKey string `json:"private_key,omitempty" maxLength:"16384" doc:"PEM or OpenSSH private key, for auth_method=private_key. On update, leave out to keep the stored one"`
	Passphrase string `json:"passphrase,omitempty" maxLength:"1024" doc:"Passphrase of an encrypted private key"`
}

type ServerBody struct {
	Name string `json:"name" minLength:"1" maxLength:"64" example:"web-01"`
	Connection
	FolderID    *string  `json:"folder_id,omitempty" format:"uuid" nullable:"true" doc:"Leave out or null for no folder"`
	Description string   `json:"description,omitempty" maxLength:"500"`
	Tags        []string `json:"tags,omitempty" maxItems:"20" doc:"Lowercase letters, digits and . _ - : /; at most 32 characters each"`
	Favorite    bool     `json:"favorite,omitempty"`
}

type ServerIDPath struct {
	ID string `path:"id" format:"uuid"`
}

type IDsBody struct {
	IDs []string `json:"ids" minItems:"1" maxItems:"500" doc:"Server ids"`
}

type ListServersInput struct {
	Q          string   `query:"q" maxLength:"200" doc:"Case-insensitive match on name, host, hostname or description, or an exact tag"`
	FolderID   string   `query:"folder" doc:"A folder id (subfolders included), or 'none' for servers outside every folder"`
	Favorites  bool     `query:"favorites" doc:"Only favourites"`
	OS         []string `query:"os,explode" doc:"OS ids from the facets (ubuntu, debian…, 'unknown' for undetected)"`
	Status     []string `query:"status,explode" enum:"unknown,online,unreachable,auth_failed,host_key_mismatch,error"`
	Tag        []string `query:"tag,explode" doc:"Servers with any of these tags"`
	AuthMethod []string `query:"auth,explode" enum:"password,private_key"`
	Sort       string   `query:"sort" enum:"name,host,os,status,last_checked,created" default:"name"`
	Order      string   `query:"order" enum:"asc,desc" default:"asc"`
	Limit      int32    `query:"limit" minimum:"1" maximum:"500" default:"50"`
	Offset     int32    `query:"offset" minimum:"0" default:"0"`
}

type ServerListOutput struct {
	Body struct {
		Items []Server `json:"items"`
		Total int32    `json:"total" doc:"Matches across all pages"`
	}
}

type Facet struct {
	Value string `json:"value"`
	Count int32  `json:"count"`
}

type OSFacet struct {
	Value  string `json:"value" doc:"OS id; 'unknown' for servers never detected" example:"ubuntu"`
	Label  string `json:"label" example:"Ubuntu"`
	Family string `json:"family" example:"linux"`
	Count  int32  `json:"count"`
}

type FacetsOutput struct {
	Body struct {
		Total     int32     `json:"total"`
		Favorites int32     `json:"favorites"`
		Unfiled   int32     `json:"unfiled" doc:"Servers outside every folder"`
		OS        []OSFacet `json:"os"`
		Status    []Facet   `json:"status"`
		Tags      []Facet   `json:"tags"`
	}
}

type ConnectionTestBody struct {
	Connection
	ServerID *string `json:"server_id,omitempty" format:"uuid" doc:"When editing a saved server: reuse its stored credentials (for fields left out) and its trusted host key"`
}

type ConnectionTestOutput struct {
	Body struct {
		Status             string   `json:"status" enum:"online,unreachable,auth_failed,host_key_mismatch,error"`
		Message            string   `json:"message"`
		LatencyMs          int32    `json:"latency_ms"`
		HostKeyFingerprint string   `json:"host_key_fingerprint"`
		OS                 ServerOS `json:"os"`
		Hostname           string   `json:"hostname"`
	}
}

// ---- Validation ----

var (
	hostnameRe = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$`)
	usernameRe = regexp.MustCompile(`^[^\s:@]+$`)
	tagRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,31}$`)
)

// normalizeHost accepts IPv4, IPv6 (with or without brackets) and DNS names.
func normalizeHost(raw string) (string, error) {
	host := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(raw), "["), "]")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	if hostnameRe.MatchString(host) {
		return strings.ToLower(strings.TrimSuffix(host, ".")), nil
	}
	return "", fieldError("body.host", "Enter an IP address or a hostname", raw)
}

func normalizeTags(raw []string) ([]string, error) {
	tags := make([]string, 0, len(raw))
	for _, t := range raw {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if !tagRe.MatchString(t) {
			return nil, fieldError("body.tags", fmt.Sprintf("Tag %q: use lowercase letters, digits and . _ - : / (max 32)", t), t)
		}
		tags = append(tags, t)
	}
	slices.Sort(tags)
	return slices.Compact(tags), nil
}

func (c *Connection) normalize() error {
	host, err := normalizeHost(c.Host)
	if err != nil {
		return err
	}
	c.Host = host
	c.Username = strings.TrimSpace(c.Username)
	if !usernameRe.MatchString(c.Username) {
		return fieldError("body.username", "Usernames can't contain spaces, ':' or '@'", c.Username)
	}
	if c.Port == 0 {
		c.Port = 22
	}
	// A key pasted from a terminal often loses its trailing newline.
	if c.PrivateKey != "" {
		c.PrivateKey = strings.TrimSpace(c.PrivateKey) + "\n"
	}
	return nil
}

// ---- Handlers ----

type serverHandler struct {
	db    *pgxpool.Pool
	q     *sqlc.Queries
	box   *secrets.Box
	pool  *sshpool.Pool
	terms *terminal.Manager
	stats *statsHub
	privs privileges
}

// forget closes everything still connected to deleted servers.
func (h *serverHandler) forget(ids []uuid.UUID) {
	for _, id := range ids {
		h.terms.KillServer(id.String())
		h.pool.Drop(id.String())
	}
}

func registerServers(api huma.API, h *serverHandler) {
	tags := []string{"Servers"}

	huma.Register(api, huma.Operation{
		OperationID: "list-servers",
		Method:      http.MethodGet,
		Path:        "/servers",
		Summary:     "List servers",
		Description: "Search, filter, sort and page servers. Filters combine with AND; several values of one filter combine with OR.",
		Tags:        tags,
	}, h.list)

	huma.Register(api, huma.Operation{
		OperationID: "get-server-facets",
		Method:      http.MethodGet,
		Path:        "/servers/facets",
		Summary:     "Counts for the server filters",
		Description: "Totals and per-value counts (OS, status, tags) over all servers, for filter menus.",
		Tags:        tags,
	}, h.facets)

	huma.Register(api, huma.Operation{
		OperationID:   "create-server",
		Method:        http.MethodPost,
		Path:          "/servers",
		Summary:       "Add a server",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, h.create)

	huma.Register(api, huma.Operation{
		OperationID: "test-server-connection",
		Method:      http.MethodPost,
		Path:        "/servers/test-connection",
		Summary:     "Test SSH connection settings",
		Description: "Connects with the given settings without saving anything, and reports what it found.",
		Tags:        tags,
	}, h.testConnection)

	huma.Register(api, huma.Operation{
		OperationID: "get-server",
		Method:      http.MethodGet,
		Path:        "/servers/{id}",
		Summary:     "Get a server",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*ServerOutput, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &ServerOutput{Body: toServer(s)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-server",
		Method:      http.MethodPut,
		Path:        "/servers/{id}",
		Summary:     "Update a server",
		Description: "Replaces the editable fields. Secrets left out keep their stored values. Changing host or port forgets the trusted host key.",
		Tags:        tags,
	}, h.update)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-server",
		Method:        http.MethodDelete,
		Path:          "/servers/{id}",
		Summary:       "Delete a server",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{}, error) {
		ids := parseIDs([]string{in.ID})
		n, err := h.q.DeleteServers(ctx, ids)
		if err != nil {
			return nil, internalError(err)
		}
		if n == 0 {
			return nil, huma.Error404NotFound("server not found")
		}
		h.forget(ids)
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-server-favorite",
		Method:      http.MethodPut,
		Path:        "/servers/{id}/favorite",
		Summary:     "Star or unstar a server",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body struct {
			Favorite bool `json:"favorite"`
		}
	}) (*ServerOutput, error) {
		s, err := h.q.SetServerFavorite(ctx, sqlc.SetServerFavoriteParams{ID: uuid.MustParse(in.ID), Favorite: in.Body.Favorite})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("server not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &ServerOutput{Body: toServer(s)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "duplicate-server",
		Method:        http.MethodPost,
		Path:          "/servers/{id}/duplicate",
		Summary:       "Duplicate a server",
		Description:   "Copies the server's settings and credentials under a new name (\"web-01 copy\"). Status, OS and host key start fresh.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, h.duplicate)

	huma.Register(api, huma.Operation{
		OperationID: "check-server",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/check",
		Summary:     "Check a server's connection",
		Description: "Connects over SSH, records the status and detects the OS. The first successful check trusts the host key; pass trust_new_host_key after a legitimate key change.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		TrustNewHostKey bool `query:"trust_new_host_key" doc:"Forget the trusted host key and trust the one the server presents now"`
	}) (*ServerOutput, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if in.TrustNewHostKey {
			s.HostKey = ""
			if err := h.q.ResetServerHostKey(ctx, s.ID); err != nil {
				return nil, internalError(err)
			}
		}
		checked, err := h.check(ctx, s)
		if err != nil {
			return nil, err
		}
		return &ServerOutput{Body: toServer(checked)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "bulk-check-servers",
		Method:      http.MethodPost,
		Path:        "/servers/bulk/check",
		Summary:     "Check several servers",
		Description: "Runs connection checks in parallel and returns the updated servers.",
		Tags:        tags,
	}, h.bulkCheck)

	huma.Register(api, huma.Operation{
		OperationID: "bulk-move-servers",
		Method:      http.MethodPost,
		Path:        "/servers/bulk/move",
		Summary:     "Move servers to a folder",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		Body struct {
			IDsBody
			FolderID *string `json:"folder_id,omitempty" format:"uuid" nullable:"true" doc:"Target folder; leave out or null to take them out of every folder"`
		}
	}) (*AffectedOutput, error) {
		folder := parseOptionalID(in.Body.FolderID)
		if err := checkParent(ctx, h.q, folder); err != nil {
			return nil, err
		}
		n, err := h.q.MoveServers(ctx, sqlc.MoveServersParams{Ids: parseIDs(in.Body.IDs), FolderID: folder})
		if err != nil {
			return nil, internalError(err)
		}
		return affected(n), nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "bulk-tag-servers",
		Method:      http.MethodPost,
		Path:        "/servers/bulk/tags",
		Summary:     "Add or remove tags on servers",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		Body struct {
			IDsBody
			Add    []string `json:"add,omitempty" maxItems:"20"`
			Remove []string `json:"remove,omitempty" maxItems:"20"`
		}
	}) (*AffectedOutput, error) {
		add, err := normalizeTags(in.Body.Add)
		if err != nil {
			return nil, err
		}
		remove, err := normalizeTags(in.Body.Remove)
		if err != nil {
			return nil, err
		}
		ids := parseIDs(in.Body.IDs)
		var n int64
		if len(add) > 0 {
			if n, err = h.q.AddServerTags(ctx, sqlc.AddServerTagsParams{Ids: ids, Tags: add}); err != nil {
				return nil, internalError(err)
			}
		}
		if len(remove) > 0 {
			if n, err = h.q.RemoveServerTags(ctx, sqlc.RemoveServerTagsParams{Ids: ids, Tags: remove}); err != nil {
				return nil, internalError(err)
			}
		}
		return affected(n), nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "bulk-delete-servers",
		Method:      http.MethodPost,
		Path:        "/servers/bulk/delete",
		Summary:     "Delete several servers",
		Tags:        tags,
	}, func(ctx context.Context, in *struct{ Body IDsBody }) (*AffectedOutput, error) {
		ids := parseIDs(in.Body.IDs)
		n, err := h.q.DeleteServers(ctx, ids)
		if err != nil {
			return nil, internalError(err)
		}
		h.forget(ids)
		return affected(n), nil
	})
}

func affected(n int64) *AffectedOutput {
	out := &AffectedOutput{}
	out.Body.Affected = n
	return out
}

func (h *serverHandler) get(ctx context.Context, rawID string) (sqlc.Server, error) {
	s, err := h.q.GetServer(ctx, uuid.MustParse(rawID))
	if isNotFound(err) {
		return s, huma.Error404NotFound("server not found")
	}
	if err != nil {
		return s, internalError(err)
	}
	return s, nil
}

func (h *serverHandler) list(ctx context.Context, in *ListServersInput) (*ServerListOutput, error) {
	params := sqlc.ListServersParams{
		FavoritesOnly: in.Favorites,
		OsIds:         nonNil(in.OS),
		Statuses:      nonNil(in.Status),
		Tags:          nonNil(in.Tag),
		AuthMethods:   nonNil(in.AuthMethod),
		Sort:          in.Sort,
		Descending:    in.Order == "desc",
		Lim:           in.Limit,
		Off:           in.Offset,
	}
	if q := strings.TrimSpace(in.Q); q != "" {
		// ILIKE wildcards in the user's text match literally.
		escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q)
		params.Q = &escaped
	}
	switch in.FolderID {
	case "":
	case "none":
		params.Unfiled = true
	default:
		id, err := uuid.Parse(in.FolderID)
		if err != nil {
			return nil, fieldError("query.folder", "Expected a folder id or 'none'", in.FolderID)
		}
		params.FolderID = &id
	}

	rows, err := h.q.ListServers(ctx, params)
	if err != nil {
		return nil, internalError(err)
	}
	out := &ServerListOutput{}
	out.Body.Items = make([]Server, 0, len(rows))
	for _, r := range rows {
		out.Body.Items = append(out.Body.Items, toServer(r.Server))
		out.Body.Total = r.Total
	}
	return out, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (h *serverHandler) facets(ctx context.Context, _ *struct{}) (*FacetsOutput, error) {
	counts, err := h.q.CountServers(ctx)
	if err != nil {
		return nil, internalError(err)
	}
	osRows, err := h.q.ServerOSFacets(ctx)
	if err != nil {
		return nil, internalError(err)
	}
	statusRows, err := h.q.ServerStatusFacets(ctx)
	if err != nil {
		return nil, internalError(err)
	}
	tagRows, err := h.q.ServerTagFacets(ctx)
	if err != nil {
		return nil, internalError(err)
	}

	out := &FacetsOutput{}
	out.Body.Total, out.Body.Favorites, out.Body.Unfiled = counts.Total, counts.Favorites, counts.Unfiled
	out.Body.OS = make([]OSFacet, 0, len(osRows))
	for _, r := range osRows {
		out.Body.OS = append(out.Body.OS, OSFacet{Value: r.Value, Label: r.Label, Family: r.Family, Count: r.Count})
	}
	out.Body.Status = make([]Facet, 0, len(statusRows))
	for _, r := range statusRows {
		out.Body.Status = append(out.Body.Status, Facet{Value: r.Value, Count: r.Count})
	}
	out.Body.Tags = make([]Facet, 0, len(tagRows))
	for _, r := range tagRows {
		out.Body.Tags = append(out.Body.Tags, Facet{Value: r.Value, Count: r.Count})
	}
	return out, nil
}

// sealed are the encrypted credentials to store for a server.
type sealed struct {
	password, privateKey, passphrase []byte
}

// resolveSecrets validates the credentials for the chosen auth method and
// seals them. prev holds the stored ones (update) and fills fields the
// request left out; it's nil on create.
func (h *serverHandler) resolveSecrets(c Connection, prev *sqlc.Server) (sealed, error) {
	var out sealed
	switch c.AuthMethod {
	case "password":
		switch {
		case c.Password != "":
			out.password = h.box.Seal(c.Password)
		case prev != nil && len(prev.PasswordEnc) > 0:
			out.password = prev.PasswordEnc
		default:
			return out, fieldError("body.password", "Enter the password", nil)
		}
	case "private_key":
		key, passphrase := c.PrivateKey, c.Passphrase
		keepKey := key == "" && prev != nil && len(prev.PrivateKeyEnc) > 0
		if keepKey {
			var err error
			if key, err = h.box.Open(prev.PrivateKeyEnc); err != nil {
				return out, internalError(err)
			}
			if passphrase == "" {
				if passphrase, err = h.box.Open(prev.PassphraseEnc); err != nil {
					return out, internalError(err)
				}
			}
		}
		if key == "" {
			return out, fieldError("body.private_key", "Paste the private key", nil)
		}
		if _, err := sshprobe.ParseSigner(key, passphrase); err != nil {
			loc := "body.private_key"
			if strings.Contains(err.Error(), "passphrase") || strings.Contains(err.Error(), "decryption") {
				loc = "body.passphrase"
			}
			return out, fieldError(loc, "Private key: "+err.Error(), nil)
		}
		out.privateKey = h.box.Seal(key)
		out.passphrase = h.box.Seal(passphrase)
	}
	return out, nil
}

func (h *serverHandler) create(ctx context.Context, in *struct{ Body ServerBody }) (*ServerOutput, error) {
	b := in.Body
	if err := b.normalize(); err != nil {
		return nil, err
	}
	tags, err := normalizeTags(b.Tags)
	if err != nil {
		return nil, err
	}
	folder := parseOptionalID(b.FolderID)
	if err := checkFolder(ctx, h.q, folder); err != nil {
		return nil, err
	}
	sec, err := h.resolveSecrets(b.Connection, nil)
	if err != nil {
		return nil, err
	}
	s, err := h.q.CreateServer(ctx, sqlc.CreateServerParams{
		FolderID:      folder,
		Name:          strings.TrimSpace(b.Name),
		Host:          b.Host,
		Port:          b.Port,
		Username:      b.Username,
		AuthMethod:    b.AuthMethod,
		PasswordEnc:   sec.password,
		PrivateKeyEnc: sec.privateKey,
		PassphraseEnc: sec.passphrase,
		Description:   strings.TrimSpace(b.Description),
		Tags:          tags,
		Favorite:      b.Favorite,
	})
	if isUniqueViolation(err) {
		return nil, fieldError("body.name", "A server with this name already exists", b.Name)
	}
	if err != nil {
		return nil, internalError(err)
	}
	return &ServerOutput{Body: toServer(s)}, nil
}

func (h *serverHandler) update(ctx context.Context, in *struct {
	ServerIDPath
	Body ServerBody
}) (*ServerOutput, error) {
	prev, err := h.get(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	b := in.Body
	if err := b.normalize(); err != nil {
		return nil, err
	}
	tags, err := normalizeTags(b.Tags)
	if err != nil {
		return nil, err
	}
	folder := parseOptionalID(b.FolderID)
	if err := checkFolder(ctx, h.q, folder); err != nil {
		return nil, err
	}
	sec, err := h.resolveSecrets(b.Connection, &prev)
	if err != nil {
		return nil, err
	}

	// A different address is a different machine as far as trust goes; any
	// connection change makes the last status stale.
	hostKey, status, message := prev.HostKey, prev.Status, prev.StatusMessage
	if b.Host != prev.Host || b.Port != prev.Port {
		hostKey = ""
	}
	if b.Host != prev.Host || b.Port != prev.Port || b.Username != prev.Username ||
		b.AuthMethod != prev.AuthMethod || b.Password != "" || b.PrivateKey != "" || b.Passphrase != "" {
		status, message = "unknown", ""
	}

	s, err := h.q.UpdateServer(ctx, sqlc.UpdateServerParams{
		ID:            prev.ID,
		FolderID:      folder,
		Name:          strings.TrimSpace(b.Name),
		Host:          b.Host,
		Port:          b.Port,
		Username:      b.Username,
		AuthMethod:    b.AuthMethod,
		PasswordEnc:   sec.password,
		PrivateKeyEnc: sec.privateKey,
		PassphraseEnc: sec.passphrase,
		HostKey:       hostKey,
		Status:        status,
		StatusMessage: message,
		Description:   strings.TrimSpace(b.Description),
		Tags:          tags,
		Favorite:      b.Favorite,
	})
	if isUniqueViolation(err) {
		return nil, fieldError("body.name", "A server with this name already exists", b.Name)
	}
	if err != nil {
		return nil, internalError(err)
	}
	return &ServerOutput{Body: toServer(s)}, nil
}

func checkFolder(ctx context.Context, q *sqlc.Queries, folder *uuid.UUID) error {
	if err := checkParent(ctx, q, folder); err != nil {
		if se, ok := err.(huma.StatusError); ok && se.GetStatus() == http.StatusUnprocessableEntity {
			return fieldError("body.folder_id", "Folder not found", folder.String())
		}
		return err
	}
	return nil
}

func (h *serverHandler) duplicate(ctx context.Context, in *ServerIDPath) (*ServerOutput, error) {
	src, err := h.get(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	params := sqlc.CreateServerParams{
		FolderID:      src.FolderID,
		Host:          src.Host,
		Port:          src.Port,
		Username:      src.Username,
		AuthMethod:    src.AuthMethod,
		PasswordEnc:   src.PasswordEnc,
		PrivateKeyEnc: src.PrivateKeyEnc,
		PassphraseEnc: src.PassphraseEnc,
		Description:   src.Description,
		Tags:          src.Tags,
	}
	for i := 1; i <= 50; i++ {
		suffix := " copy"
		if i > 1 {
			suffix = fmt.Sprintf(" copy %d", i)
		}
		base := src.Name
		if len(base)+len(suffix) > 64 {
			base = base[:64-len(suffix)]
		}
		params.Name = base + suffix
		s, err := h.q.CreateServer(ctx, params)
		if isUniqueViolation(err) {
			continue
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &ServerOutput{Body: toServer(s)}, nil
	}
	return nil, huma.Error409Conflict("too many copies of this server already exist")
}

// target builds an SSH target from a stored server, opening its secrets.
func (h *serverHandler) target(s sqlc.Server) (sshprobe.Target, error) {
	t := sshprobe.Target{Host: s.Host, Port: int(s.Port), User: s.Username, KnownHostKey: s.HostKey}
	var err error
	if t.Password, err = h.box.Open(s.PasswordEnc); err != nil {
		return t, err
	}
	if t.PrivateKey, err = h.box.Open(s.PrivateKeyEnc); err != nil {
		return t, err
	}
	if t.Passphrase, err = h.box.Open(s.PassphraseEnc); err != nil {
		return t, err
	}
	// Only offer the credentials of the chosen method.
	if s.AuthMethod == "password" {
		t.PrivateKey, t.Passphrase = "", ""
	} else {
		t.Password = ""
	}
	return t, nil
}

func (h *serverHandler) check(ctx context.Context, s sqlc.Server) (sqlc.Server, error) {
	t, err := h.target(s)
	if err != nil {
		return s, internalError(err)
	}
	res := sshprobe.Probe(ctx, t)

	params := sqlc.RecordServerCheckParams{
		ID:            s.ID,
		Status:        res.Status,
		StatusMessage: res.Message,
		Detected:      res.Detected,
		OsFamily:      res.OS.Family,
		OsID:          res.OS.ID,
		OsName:        res.OS.Name,
		OsVersion:     res.OS.Version,
		Kernel:        res.OS.Kernel,
		Arch:          res.OS.Arch,
		Hostname:      res.OS.Hostname,
	}
	if res.Status == sshprobe.StatusOnline {
		params.LatencyMs = &res.LatencyMs
		// First successful connection: trust this key from now on.
		if s.HostKey == "" {
			params.HostKey = res.HostKey
		}
	}
	// The request may be gone by now; still record what we learned.
	checked, err := h.q.RecordServerCheck(context.WithoutCancel(ctx), params)
	if err != nil {
		return s, internalError(err)
	}
	return checked, nil
}

const checkConcurrency = 8

func (h *serverHandler) bulkCheck(ctx context.Context, in *struct{ Body IDsBody }) (*ServerItemsOutput, error) {
	servers, err := h.q.GetServers(ctx, parseIDs(in.Body.IDs))
	if err != nil {
		return nil, internalError(err)
	}
	results := make([]Server, len(servers))
	sem := make(chan struct{}, checkConcurrency)
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			checked, err := h.check(ctx, s)
			if err != nil {
				checked = s // keep the old state; the error is already logged
			}
			results[i] = toServer(checked)
		}()
	}
	wg.Wait()
	out := &ServerItemsOutput{}
	out.Body.Items = results
	return out, nil
}

func (h *serverHandler) testConnection(ctx context.Context, in *struct{ Body ConnectionTestBody }) (*ConnectionTestOutput, error) {
	c := in.Body.Connection
	if err := c.normalize(); err != nil {
		return nil, err
	}
	t := sshprobe.Target{Host: c.Host, Port: int(c.Port), User: c.Username}

	var prev *sqlc.Server
	if in.Body.ServerID != nil && *in.Body.ServerID != "" {
		s, err := h.get(ctx, *in.Body.ServerID)
		if err != nil {
			return nil, err
		}
		prev = &s
		// The stored host key only vouches for the stored address.
		if s.Host == c.Host && s.Port == c.Port {
			t.KnownHostKey = s.HostKey
		}
	}

	switch c.AuthMethod {
	case "password":
		t.Password = c.Password
		if t.Password == "" && prev != nil {
			pw, err := h.box.Open(prev.PasswordEnc)
			if err != nil {
				return nil, internalError(err)
			}
			t.Password = pw
		}
		if t.Password == "" {
			return nil, fieldError("body.password", "Enter the password", nil)
		}
	case "private_key":
		t.PrivateKey, t.Passphrase = c.PrivateKey, c.Passphrase
		if t.PrivateKey == "" && prev != nil {
			var err error
			if t.PrivateKey, err = h.box.Open(prev.PrivateKeyEnc); err != nil {
				return nil, internalError(err)
			}
			if t.Passphrase == "" {
				if t.Passphrase, err = h.box.Open(prev.PassphraseEnc); err != nil {
					return nil, internalError(err)
				}
			}
		}
		if t.PrivateKey == "" {
			return nil, fieldError("body.private_key", "Paste the private key", nil)
		}
	}

	res := sshprobe.Probe(ctx, t)
	out := &ConnectionTestOutput{}
	out.Body.Status = res.Status
	out.Body.Message = res.Message
	out.Body.LatencyMs = res.LatencyMs
	out.Body.HostKeyFingerprint = res.Fingerprint
	out.Body.OS = ServerOS{
		Family: res.OS.Family, ID: res.OS.ID, Name: res.OS.Name, Version: res.OS.Version,
		Kernel: res.OS.Kernel, Arch: res.OS.Arch,
	}
	out.Body.Hostname = res.OS.Hostname
	return out, nil
}
