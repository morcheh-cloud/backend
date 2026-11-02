package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/secrets"
	"github.com/morcheh/backend/internal/sshprobe"
	"github.com/morcheh/backend/internal/storage"
)

// ---- Response types ----

type StorageCapabilities struct {
	Buckets    bool `json:"buckets" doc:"Top-level folders are buckets (S3 without a fixed bucket)"`
	ShareLinks bool `json:"share_links" doc:"Can make time-limited public download links"`
	ServerCopy bool `json:"server_copy" doc:"Copies happen on the storage itself"`
	Ranges     bool `json:"ranges" doc:"Downloads resume and media can seek"`
}

type Storage struct {
	ID          string `json:"id" format:"uuid"`
	Name        string `json:"name" example:"Backups"`
	Protocol    string `json:"protocol" enum:"s3,ftp,sftp,webdav"`
	Provider    string `json:"provider" doc:"Preset the settings came from (aws, minio, r2, nextcloud…)" example:"minio"`
	Host        string `json:"host" doc:"S3 endpoint or WebDAV URL; host name for FTP and SFTP" example:"https://s3.example.com"`
	Port        int32  `json:"port" doc:"0 = the protocol's default"`
	Username    string `json:"username" doc:"Access key for S3"`
	AuthMethod  string `json:"auth_method" enum:"password,private_key"`
	HasSecret   bool   `json:"has_secret" doc:"A password (or S3 secret key) is stored"`
	HasPrivKey  bool   `json:"has_private_key"`
	HasPassph   bool   `json:"has_passphrase"`
	Bucket      string `json:"bucket"`
	Region      string `json:"region"`
	PathStyle   bool   `json:"path_style"`
	TLS         string `json:"tls" enum:"none,explicit,implicit"`
	InsecureTLS bool   `json:"insecure_tls"`
	// SFTP trust on first use.
	HostKeyFingerprint string              `json:"host_key_fingerprint"`
	RootPath           string              `json:"root_path" doc:"Folder shown as the top; empty = the login folder (or every bucket)"`
	ReadOnly           bool                `json:"read_only" doc:"Refuse every change through Morcheh"`
	Description        string              `json:"description"`
	Favorite           bool                `json:"favorite"`
	Status             string              `json:"status" enum:"unknown,online,unreachable,auth_failed,host_key_mismatch,error"`
	StatusMessage      string              `json:"status_message"`
	Detail             string              `json:"detail" doc:"What the last good check found, e.g. \"3 buckets\""`
	LatencyMs          *int32              `json:"latency_ms" nullable:"true"`
	LastCheckedAt      *time.Time          `json:"last_checked_at" nullable:"true"`
	Capabilities       StorageCapabilities `json:"capabilities"`
	CreatedAt          time.Time           `json:"created_at"`
	UpdatedAt          time.Time           `json:"updated_at"`
}

// capabilities without connecting: they only depend on the settings.
func capabilities(s sqlc.Storage) StorageCapabilities {
	switch s.Protocol {
	case storage.ProtoS3:
		return StorageCapabilities{Buckets: s.Bucket == "" && storage.Clean(s.RootPath) == "/", ShareLinks: true, ServerCopy: true, Ranges: true}
	case storage.ProtoSFTP:
		return StorageCapabilities{Ranges: true}
	case storage.ProtoWebDAV:
		return StorageCapabilities{ServerCopy: true}
	}
	return StorageCapabilities{}
}

func toStorage(s sqlc.Storage) Storage {
	return Storage{
		ID:                 s.ID.String(),
		Name:               s.Name,
		Protocol:           s.Protocol,
		Provider:           s.Provider,
		Host:               s.Host,
		Port:               s.Port,
		Username:           s.Username,
		AuthMethod:         s.AuthMethod,
		HasSecret:          len(s.SecretEnc) > 0,
		HasPrivKey:         len(s.PrivateKeyEnc) > 0,
		HasPassph:          len(s.PassphraseEnc) > 0,
		Bucket:             s.Bucket,
		Region:             s.Region,
		PathStyle:          s.PathStyle,
		TLS:                s.Tls,
		InsecureTLS:        s.InsecureTls,
		HostKeyFingerprint: sshprobe.Fingerprint(s.HostKey),
		RootPath:           s.RootPath,
		ReadOnly:           s.ReadOnly,
		Description:        s.Description,
		Favorite:           s.Favorite,
		Status:             s.Status,
		StatusMessage:      s.StatusMessage,
		Detail:             s.Detail,
		LatencyMs:          s.LatencyMs,
		LastCheckedAt:      s.LastCheckedAt,
		Capabilities:       capabilities(s),
		CreatedAt:          s.CreatedAt,
		UpdatedAt:          s.UpdatedAt,
	}
}

type StorageOutput struct{ Body Storage }

type StorageIDPath struct {
	ID string `path:"id" format:"uuid"`
}

// ---- Request types ----

// StorageSettings is how to reach a storage.
type StorageSettings struct {
	Protocol    string `json:"protocol" enum:"s3,ftp,sftp,webdav"`
	Provider    string `json:"provider,omitempty" maxLength:"32"`
	Host        string `json:"host" minLength:"1" maxLength:"500" doc:"S3: endpoint URL or host (https unless given); WebDAV: the folder's URL; FTP/SFTP: host name or IP"`
	Port        int32  `json:"port,omitempty" minimum:"0" maximum:"65535" doc:"0 or left out = the default (21, 990 for implicit FTPS, 22; S3 and WebDAV take it from the URL)"`
	Username    string `json:"username,omitempty" maxLength:"256" doc:"S3: access key id. Empty FTP user logs in anonymously"`
	AuthMethod  string `json:"auth_method,omitempty" enum:"password,private_key" default:"password" doc:"private_key is SFTP only"`
	Secret      string `json:"secret,omitempty" maxLength:"4096" doc:"Password, or S3 secret key. On update, leave out to keep the stored one"`
	ClearSecret bool   `json:"clear_secret,omitempty" doc:"On update: forget the stored password / secret key"`
	PrivateKey  string `json:"private_key,omitempty" maxLength:"16384" doc:"On update, leave out to keep the stored one"`
	Passphrase  string `json:"passphrase,omitempty" maxLength:"1024"`
	Bucket      string `json:"bucket,omitempty" maxLength:"63" doc:"S3: stay in one bucket; empty lists every bucket"`
	Region      string `json:"region,omitempty" maxLength:"64"`
	PathStyle   bool   `json:"path_style,omitempty" doc:"S3: endpoint/bucket/key URLs (MinIO and most self-hosted servers)"`
	TLS         string `json:"tls,omitempty" enum:"none,explicit,implicit" default:"none" doc:"FTP: explicit = AUTH TLS on the normal port, implicit = FTPS (990)"`
	InsecureTLS bool   `json:"insecure_tls,omitempty" doc:"Accept any TLS certificate (self-signed). Anyone on the path can then read the traffic"`
	RootPath    string `json:"root_path,omitempty" maxLength:"1024" doc:"Folder to show as the top (S3: bucket/prefix)"`
}

type StorageBody struct {
	Name string `json:"name" minLength:"1" maxLength:"64"`
	StorageSettings
	ReadOnly    bool   `json:"read_only,omitempty"`
	Description string `json:"description,omitempty" maxLength:"500"`
	Favorite    bool   `json:"favorite,omitempty"`
}

type StorageTestBody struct {
	StorageSettings
	StorageID *string `json:"storage_id,omitempty" format:"uuid" doc:"When editing a saved storage: reuse its stored secrets (for fields left out) and trusted host key"`
}

type StorageTestOutput struct {
	Body struct {
		Status             string `json:"status" enum:"online,unreachable,auth_failed,host_key_mismatch,error"`
		Message            string `json:"message"`
		LatencyMs          int32  `json:"latency_ms"`
		Detail             string `json:"detail"`
		HostKeyFingerprint string `json:"host_key_fingerprint"`
	}
}

func (s *StorageSettings) normalize() error {
	s.Host = strings.TrimSpace(s.Host)
	s.Username = strings.TrimSpace(s.Username)
	s.Bucket = strings.TrimSpace(s.Bucket)
	s.Region = strings.TrimSpace(s.Region)
	s.RootPath = strings.TrimSpace(s.RootPath)
	if s.RootPath != "" {
		s.RootPath = storage.Clean(s.RootPath)
	}
	if s.AuthMethod == "" {
		s.AuthMethod = "password"
	}
	if s.TLS == "" {
		s.TLS = "none"
	}
	switch s.Protocol {
	case storage.ProtoS3, storage.ProtoWebDAV:
		if strings.ContainsAny(s.Host, " \t") {
			return fieldError("body.host", "Enter a URL like https://s3.example.com", s.Host)
		}
	default:
		host, err := normalizeHost(s.Host)
		if err != nil {
			return err
		}
		s.Host = host
	}
	if s.Protocol != storage.ProtoSFTP {
		s.AuthMethod = "password"
	} else if s.Username == "" {
		return fieldError("body.username", "Enter the user name", nil)
	}
	if s.Protocol != storage.ProtoFTP {
		s.TLS = "none"
	}
	if s.Protocol != storage.ProtoS3 {
		s.Bucket, s.Region, s.PathStyle = "", "", false
	}
	if s.PrivateKey != "" {
		s.PrivateKey = strings.TrimSpace(s.PrivateKey) + "\n"
	}
	return nil
}

// ---- Handler & connection cache ----

type storageHandler struct {
	q       *sqlc.Queries
	box     *secrets.Box
	servers *serverHandler

	mu    sync.Mutex
	conns map[uuid.UUID]*storageConn
}

// storageConn is an open storage shared by requests. It's tied to the row's
// updated_at, so editing the settings reconnects.
type storageConn struct {
	fs      storage.FS
	version time.Time
	users   int
	last    time.Time
	dead    bool
}

const storageIdle = 5 * time.Minute

func newStorageHandler(q *sqlc.Queries, box *secrets.Box, servers *serverHandler) *storageHandler {
	h := &storageHandler{q: q, box: box, servers: servers, conns: map[uuid.UUID]*storageConn{}}
	go h.reap()
	return h
}

func (h *storageHandler) reap() {
	for range time.Tick(time.Minute) {
		h.mu.Lock()
		for id, c := range h.conns {
			if c.users == 0 && time.Since(c.last) > storageIdle {
				delete(h.conns, id)
				go c.fs.Close()
			}
		}
		h.mu.Unlock()
	}
}

// acquire returns the open storage for row, connecting if needed. Every
// acquire needs a release.
func (h *storageHandler) acquire(ctx context.Context, row sqlc.Storage) (*storageConn, error) {
	h.mu.Lock()
	if c := h.conns[row.ID]; c != nil {
		if c.version.Equal(row.UpdatedAt) {
			c.users++
			h.mu.Unlock()
			return c, nil
		}
		h.dropLocked(row.ID)
	}
	h.mu.Unlock()

	cfg, err := h.config(row)
	if err != nil {
		return nil, internalError(err)
	}
	f, info, err := storage.Open(ctx, cfg)
	h.record(ctx, row, info, err)
	if err != nil {
		var ce *storage.ConnError
		if errors.As(err, &ce) && ce.Status == storage.StatusHostKeyMismatch {
			return nil, huma.Error502BadGateway("The SFTP server's host key changed. Check the storage again and trust the new key if the change is expected.")
		}
		return nil, huma.Error502BadGateway("Can't connect to the storage: " + storage.Message(err))
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if c := h.conns[row.ID]; c != nil && c.version.Equal(row.UpdatedAt) {
		// Someone else connected meanwhile.
		go f.Close()
		c.users++
		return c, nil
	}
	c := &storageConn{fs: f, version: row.UpdatedAt, users: 1}
	h.conns[row.ID] = c
	return c, nil
}

func (h *storageHandler) release(c *storageConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	c.users--
	c.last = time.Now()
	if c.dead && c.users == 0 {
		go c.fs.Close()
	}
}

func (h *storageHandler) drop(id uuid.UUID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dropLocked(id)
}

func (h *storageHandler) dropLocked(id uuid.UUID) {
	c := h.conns[id]
	if c == nil {
		return
	}
	delete(h.conns, id)
	c.dead = true
	if c.users == 0 {
		go c.fs.Close()
	}
}

// withFS runs fn on the storage's open connection, once more on a fresh one
// if the cached one turns out to be dead.
func (h *storageHandler) withFS(ctx context.Context, rawID string, fn func(row sqlc.Storage, f storage.FS) error) error {
	row, err := h.get(ctx, rawID)
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		c, err := h.acquire(ctx, row)
		if err != nil {
			return err
		}
		err = fn(row, c.fs)
		h.release(c)
		if err != nil && attempt == 0 && storage.IsConnLost(err) && ctx.Err() == nil {
			h.drop(row.ID)
			continue
		}
		return err
	}
}

// record stores the outcome of a connection attempt.
func (h *storageHandler) record(ctx context.Context, row sqlc.Storage, info storage.Info, err error) sqlc.Storage {
	params := sqlc.RecordStorageCheckParams{ID: row.ID, Status: storage.StatusOnline, Detail: info.Detail}
	if err != nil {
		params.Status, params.StatusMessage = storage.StatusError, storage.Message(err)
		var ce *storage.ConnError
		if errors.As(err, &ce) {
			params.Status, params.StatusMessage = ce.Status, ce.Message
		}
	} else {
		params.LatencyMs = &info.LatencyMs
		if row.HostKey == "" {
			params.HostKey = info.HostKey // trust on first use
		}
	}
	checked, rerr := h.q.RecordStorageCheck(context.WithoutCancel(ctx), params)
	if rerr != nil {
		return row
	}
	return checked
}

func (h *storageHandler) config(s sqlc.Storage) (storage.Config, error) {
	cfg := storage.Config{
		Protocol: s.Protocol, Host: s.Host, Port: int(s.Port), Username: s.Username,
		Bucket: s.Bucket, Region: s.Region, PathStyle: s.PathStyle, TLS: s.Tls,
		InsecureTLS: s.InsecureTls, HostKey: s.HostKey, Root: s.RootPath,
	}
	var err error
	if cfg.Secret, err = h.box.Open(s.SecretEnc); err != nil {
		return cfg, err
	}
	if s.AuthMethod == "private_key" {
		if cfg.PrivateKey, err = h.box.Open(s.PrivateKeyEnc); err != nil {
			return cfg, err
		}
		if cfg.Passphrase, err = h.box.Open(s.PassphraseEnc); err != nil {
			return cfg, err
		}
		cfg.Secret = ""
	}
	return cfg, nil
}

func (h *storageHandler) get(ctx context.Context, rawID string) (sqlc.Storage, error) {
	s, err := h.q.GetStorage(ctx, uuid.MustParse(rawID))
	if isNotFound(err) {
		return s, huma.Error404NotFound("storage not found")
	}
	if err != nil {
		return s, internalError(err)
	}
	return s, nil
}

type storageSealed struct {
	secret, privateKey, passphrase []byte
}

// resolveSecrets seals the request's secrets; prev (on update) fills the
// ones left out.
func (h *storageHandler) resolveSecrets(c StorageSettings, prev *sqlc.Storage) (storageSealed, error) {
	var out storageSealed
	if c.AuthMethod == "private_key" {
		key, passphrase := c.PrivateKey, c.Passphrase
		if key == "" && prev != nil && len(prev.PrivateKeyEnc) > 0 {
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
		out.privateKey, out.passphrase = h.box.Seal(key), h.box.Seal(passphrase)
		return out, nil
	}
	switch {
	case c.Secret != "":
		out.secret = h.box.Seal(c.Secret)
	case c.ClearSecret:
	case prev != nil && len(prev.SecretEnc) > 0:
		out.secret = prev.SecretEnc
	case c.Protocol == storage.ProtoSFTP:
		return out, fieldError("body.secret", "Enter the password", nil)
	}
	return out, nil
}

func registerStorages(api huma.API, h *storageHandler) {
	tags := []string{"Storage"}

	huma.Register(api, huma.Operation{
		OperationID: "list-storages",
		Method:      http.MethodGet,
		Path:        "/storages",
		Summary:     "List storages",
		Description: "Favourites first, then by name.",
		Tags:        tags,
	}, func(ctx context.Context, _ *struct{}) (*struct {
		Body struct {
			Items []Storage `json:"items"`
		}
	}, error) {
		rows, err := h.q.ListStorages(ctx)
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []Storage `json:"items"`
			}
		}{}
		out.Body.Items = make([]Storage, 0, len(rows))
		for _, r := range rows {
			out.Body.Items = append(out.Body.Items, toStorage(r))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-storage",
		Method:        http.MethodPost,
		Path:          "/storages",
		Summary:       "Add a storage",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, h.create)

	huma.Register(api, huma.Operation{
		OperationID: "test-storage-connection",
		Method:      http.MethodPost,
		Path:        "/storages/test-connection",
		Summary:     "Test storage settings",
		Description: "Connects with the given settings without saving anything.",
		Tags:        tags,
	}, h.testConnection)

	huma.Register(api, huma.Operation{
		OperationID: "get-storage",
		Method:      http.MethodGet,
		Path:        "/storages/{id}",
		Summary:     "Get a storage",
		Tags:        tags,
	}, func(ctx context.Context, in *StorageIDPath) (*StorageOutput, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &StorageOutput{Body: toStorage(s)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-storage",
		Method:      http.MethodPut,
		Path:        "/storages/{id}",
		Summary:     "Update a storage",
		Description: "Replaces the editable fields. Secrets left out keep their stored values. Changing the host or port forgets the trusted SFTP host key.",
		Tags:        tags,
	}, h.update)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-storage",
		Method:        http.MethodDelete,
		Path:          "/storages/{id}",
		Summary:       "Remove a storage",
		Description:   "Forgets the storage in Morcheh; nothing on the storage itself is touched.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *StorageIDPath) (*struct{}, error) {
		id := uuid.MustParse(in.ID)
		n, err := h.q.DeleteStorage(ctx, id)
		if err != nil {
			return nil, internalError(err)
		}
		if n == 0 {
			return nil, huma.Error404NotFound("storage not found")
		}
		h.drop(id)
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-storage-favorite",
		Method:      http.MethodPut,
		Path:        "/storages/{id}/favorite",
		Summary:     "Star or unstar a storage",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		StorageIDPath
		Body struct {
			Favorite bool `json:"favorite"`
		}
	}) (*StorageOutput, error) {
		s, err := h.q.SetStorageFavorite(ctx, sqlc.SetStorageFavoriteParams{ID: uuid.MustParse(in.ID), Favorite: in.Body.Favorite})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("storage not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &StorageOutput{Body: toStorage(s)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "check-storage",
		Method:      http.MethodPost,
		Path:        "/storages/{id}/check",
		Summary:     "Check a storage's connection",
		Description: "Connects afresh and records the status. For SFTP, the first good check trusts the host key; pass trust_new_host_key after a legitimate key change.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		StorageIDPath
		TrustNewHostKey bool `query:"trust_new_host_key"`
	}) (*StorageOutput, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if in.TrustNewHostKey {
			s.HostKey = ""
			if err := h.q.ResetStorageHostKey(ctx, s.ID); err != nil {
				return nil, internalError(err)
			}
		}
		h.drop(s.ID)
		cfg, err := h.config(s)
		if err != nil {
			return nil, internalError(err)
		}
		f, info, err := storage.Open(ctx, cfg)
		if err == nil {
			f.Close()
		}
		return &StorageOutput{Body: toStorage(h.record(ctx, s, info, err))}, nil
	})
}

func (h *storageHandler) create(ctx context.Context, in *struct{ Body StorageBody }) (*StorageOutput, error) {
	b := in.Body
	if err := b.normalize(); err != nil {
		return nil, err
	}
	sec, err := h.resolveSecrets(b.StorageSettings, nil)
	if err != nil {
		return nil, err
	}
	s, err := h.q.CreateStorage(ctx, sqlc.CreateStorageParams{
		Name: strings.TrimSpace(b.Name), Protocol: b.Protocol, Provider: b.Provider,
		Host: b.Host, Port: b.Port, Username: b.Username, AuthMethod: b.AuthMethod,
		SecretEnc: sec.secret, PrivateKeyEnc: sec.privateKey, PassphraseEnc: sec.passphrase,
		Bucket: b.Bucket, Region: b.Region, PathStyle: b.PathStyle, Tls: b.TLS,
		InsecureTls: b.InsecureTLS, RootPath: b.RootPath, ReadOnly: b.ReadOnly,
		Description: strings.TrimSpace(b.Description), Favorite: b.Favorite,
	})
	if isUniqueViolation(err) {
		return nil, fieldError("body.name", "A storage with this name already exists", b.Name)
	}
	if err != nil {
		return nil, internalError(err)
	}
	return &StorageOutput{Body: toStorage(s)}, nil
}

func (h *storageHandler) update(ctx context.Context, in *struct {
	StorageIDPath
	Body StorageBody
}) (*StorageOutput, error) {
	prev, err := h.get(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	b := in.Body
	if err := b.normalize(); err != nil {
		return nil, err
	}
	sec, err := h.resolveSecrets(b.StorageSettings, &prev)
	if err != nil {
		return nil, err
	}
	hostKey, status, message := prev.HostKey, prev.Status, prev.StatusMessage
	if b.Host != prev.Host || b.Port != prev.Port || b.Protocol != prev.Protocol {
		hostKey = ""
	}
	if b.Host != prev.Host || b.Port != prev.Port || b.Protocol != prev.Protocol ||
		b.Username != prev.Username || b.AuthMethod != prev.AuthMethod || b.Secret != "" ||
		b.ClearSecret || b.PrivateKey != "" || b.Bucket != prev.Bucket || b.RootPath != prev.RootPath ||
		b.TLS != prev.Tls || b.PathStyle != prev.PathStyle || b.Region != prev.Region {
		status, message = "unknown", ""
	}
	s, err := h.q.UpdateStorage(ctx, sqlc.UpdateStorageParams{
		ID: prev.ID, Name: strings.TrimSpace(b.Name), Protocol: b.Protocol, Provider: b.Provider,
		Host: b.Host, Port: b.Port, Username: b.Username, AuthMethod: b.AuthMethod,
		SecretEnc: sec.secret, PrivateKeyEnc: sec.privateKey, PassphraseEnc: sec.passphrase,
		Bucket: b.Bucket, Region: b.Region, PathStyle: b.PathStyle, Tls: b.TLS,
		InsecureTls: b.InsecureTLS, HostKey: hostKey, RootPath: b.RootPath, ReadOnly: b.ReadOnly,
		Description: strings.TrimSpace(b.Description), Favorite: b.Favorite,
		Status: status, StatusMessage: message,
	})
	if isUniqueViolation(err) {
		return nil, fieldError("body.name", "A storage with this name already exists", b.Name)
	}
	if err != nil {
		return nil, internalError(err)
	}
	h.drop(s.ID)
	return &StorageOutput{Body: toStorage(s)}, nil
}

func (h *storageHandler) testConnection(ctx context.Context, in *struct{ Body StorageTestBody }) (*StorageTestOutput, error) {
	c := in.Body.StorageSettings
	if err := c.normalize(); err != nil {
		return nil, err
	}
	var prev *sqlc.Storage
	if id := parseOptionalID(in.Body.StorageID); id != nil {
		s, err := h.q.GetStorage(ctx, *id)
		if err != nil && !isNotFound(err) {
			return nil, internalError(err)
		}
		if err == nil {
			prev = &s
		}
	}
	sec, err := h.resolveSecrets(c, prev)
	if err != nil {
		return nil, err
	}
	cfg := storage.Config{
		Protocol: c.Protocol, Host: c.Host, Port: int(c.Port), Username: c.Username,
		Bucket: c.Bucket, Region: c.Region, PathStyle: c.PathStyle, TLS: c.TLS,
		InsecureTLS: c.InsecureTLS, Root: c.RootPath,
	}
	if prev != nil && prev.Host == c.Host && prev.Port == c.Port && prev.Protocol == c.Protocol {
		cfg.HostKey = prev.HostKey
	}
	if cfg.Secret, err = h.box.Open(sec.secret); err != nil {
		return nil, internalError(err)
	}
	if cfg.PrivateKey, err = h.box.Open(sec.privateKey); err != nil {
		return nil, internalError(err)
	}
	if cfg.Passphrase, err = h.box.Open(sec.passphrase); err != nil {
		return nil, internalError(err)
	}

	out := &StorageTestOutput{}
	f, info, err := storage.Open(ctx, cfg)
	out.Body.LatencyMs, out.Body.Detail, out.Body.HostKeyFingerprint = info.LatencyMs, info.Detail, info.Fingerprint
	if err != nil {
		out.Body.Status, out.Body.Message = storage.StatusError, storage.Message(err)
		var ce *storage.ConnError
		if errors.As(err, &ce) {
			out.Body.Status, out.Body.Message = ce.Status, ce.Message
		}
		return out, nil
	}
	f.Close()
	out.Body.Status, out.Body.Message = storage.StatusOnline, "Connected"
	return out, nil
}
