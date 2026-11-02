package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/dbmon"
	"github.com/morcheh/backend/internal/secrets"
)

// ---- Response types ----

type Database struct {
	ID          string  `json:"id" format:"uuid"`
	WorkspaceID string  `json:"workspace_id" format:"uuid"`
	Name        string  `json:"name" example:"Shop primary"`
	Engine      string  `json:"engine" enum:"postgres,mysql,mssql,redis,mongodb"`
	Mode        string  `json:"mode" enum:"server,direct" doc:"server: reached through one of your servers over SSH; direct: Morcheh connects itself"`
	ServerID    *string `json:"server_id" format:"uuid" nullable:"true" doc:"The server it's reached through; null when direct, or when that server was removed"`
	Host        string  `json:"host" doc:"As the server sees it (mode server), or its public address"`
	Port        int32   `json:"port"`
	Username    string  `json:"username"`
	HasPassword bool    `json:"has_password"`
	Dbname      string  `json:"dbname" doc:"Database it signs in to"`
	TLS         string  `json:"tls" enum:"disable,require,verify"`
	CACert      string  `json:"ca_cert" doc:"PEM the certificate is checked against (verify); empty = the system's CAs"`
	// Direct only: private and loopback addresses are refused unless a system
	// admin allowed them.
	AllowInternal   bool                           `json:"allow_internal"`
	Container       string                         `json:"container" doc:"Docker container it runs in, on the server"`
	Description     string                         `json:"description"`
	Favorite        bool                           `json:"favorite"`
	Paused          bool                           `json:"paused" doc:"Monitoring stopped"`
	IntervalSeconds int32                          `json:"interval_seconds"`
	Thresholds      map[string]dbmon.DatabaseLimit `json:"thresholds" doc:"Limits changed from the defaults, by check id"`
	MutedChecks     []string                       `json:"muted_checks"`
	AlertsEnabled   bool                           `json:"alerts_enabled"`
	Status          string                         `json:"status" enum:"unknown,online,unreachable,auth_failed,tls_error,blocked,error"`
	StatusMessage   string                         `json:"status_message"`
	Version         string                         `json:"version"`
	Flavor          string                         `json:"flavor" example:"MariaDB"`
	Role            string                         `json:"role" doc:"primary, replica or standalone; empty until known"`
	LatencyMs       *int32                         `json:"latency_ms" nullable:"true"`
	SizeBytes       *int64                         `json:"size_bytes" nullable:"true"`
	Connections     *int32                         `json:"connections" nullable:"true"`
	MaxConnections  *int32                         `json:"max_connections" nullable:"true"`
	LastCheckedAt   *time.Time                     `json:"last_checked_at" nullable:"true"`
	LastOnlineAt    *time.Time                     `json:"last_online_at" nullable:"true"`
	Health          string                         `json:"health" enum:"unknown,ok,warning,critical" doc:"The worst check that isn't muted"`
	Checks          []dbmon.DatabaseCheck          `json:"checks"`
	CreatedAt       time.Time                      `json:"created_at"`
	UpdatedAt       time.Time                      `json:"updated_at"`
}

func toDatabase(d sqlc.Database) Database {
	out := Database{
		ID: d.ID.String(), WorkspaceID: d.WorkspaceID.String(), Name: d.Name,
		Engine: d.Engine, Mode: d.Mode, ServerID: optionalIDString(d.ServerID),
		Host: d.Host, Port: d.Port, Username: d.Username, HasPassword: len(d.PasswordEnc) > 0,
		Dbname: d.Dbname, TLS: d.Tls, CACert: d.CaCert, AllowInternal: d.AllowInternal,
		Container: d.Container, Description: d.Description, Favorite: d.Favorite,
		Paused: d.Paused, IntervalSeconds: d.IntervalSeconds,
		Thresholds: limitsOf(d), MutedChecks: d.MutedChecks, AlertsEnabled: d.AlertsEnabled,
		Status: d.Status, StatusMessage: d.StatusMessage, Version: d.Version,
		Flavor: d.Flavor, Role: d.Role, LatencyMs: d.LatencyMs, SizeBytes: d.SizeBytes,
		Connections: d.Connections, MaxConnections: d.MaxConnections,
		LastCheckedAt: d.LastCheckedAt, LastOnlineAt: d.LastOnlineAt,
		Health: d.Health, Checks: checksOf(d), CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
	}
	if out.MutedChecks == nil {
		out.MutedChecks = []string{}
	}
	return out
}

func limitsOf(d sqlc.Database) map[string]dbmon.DatabaseLimit {
	m := map[string]dbmon.DatabaseLimit{}
	if len(d.Thresholds) > 0 {
		_ = json.Unmarshal(d.Thresholds, &m)
	}
	return m
}

func checksOf(d sqlc.Database) []dbmon.DatabaseCheck {
	var c []dbmon.DatabaseCheck
	if len(d.Checks) > 0 {
		_ = json.Unmarshal(d.Checks, &c)
	}
	if c == nil {
		c = []dbmon.DatabaseCheck{}
	}
	return c
}

type DatabaseOutput struct{ Body Database }

type DatabaseIDPath struct {
	ID string `path:"id" format:"uuid"`
}

// ---- Request types ----

// DatabaseSettings is how to reach a database.
type DatabaseSettings struct {
	Engine   string  `json:"engine" enum:"postgres,mysql,mssql,redis,mongodb"`
	Mode     string  `json:"mode" enum:"server,direct" doc:"server: through one of your servers over SSH (the database may run on it, in Docker on it, or behind it); direct: Morcheh connects to a public address itself"`
	ServerID *string `json:"server_id,omitempty" format:"uuid" doc:"mode server: the server it's reached through"`
	Host     string  `json:"host,omitempty" maxLength:"255" doc:"mode server: as that server sees it (empty = 127.0.0.1, or the container's own address when a container is set). direct: public IP or domain"`
	Port     int32   `json:"port,omitempty" minimum:"0" maximum:"65535" doc:"0 or left out = the engine's default"`
	Username string  `json:"username,omitempty" maxLength:"128"`
	Password string  `json:"password,omitempty" maxLength:"1024" doc:"On update, leave out to keep the stored one"`
	// On update: forget the stored password.
	ClearPassword bool   `json:"clear_password,omitempty"`
	Dbname        string `json:"dbname,omitempty" maxLength:"128" doc:"Database to sign in to (MongoDB: the auth database; Redis: the db number). Empty = the engine's usual one"`
	TLS           string `json:"tls,omitempty" enum:"disable,require,verify" doc:"require: encrypted, the certificate isn't checked; verify: also checks it (against ca_cert, or the system's CAs). Default: require when direct, disable through a server (SSH already encrypts)"`
	CACert        string `json:"ca_cert,omitempty" maxLength:"65536" doc:"verify only: PEM of the CA that signed the database's certificate"`
	AllowInternal bool   `json:"allow_internal,omitempty" doc:"direct only: allow private, loopback and link-local addresses. System admins only"`
	Container     string `json:"container,omitempty" maxLength:"128" doc:"mode server: the Docker container it runs in. Disk is then read inside it"`
}

type DatabaseBody struct {
	Name string `json:"name" minLength:"1" maxLength:"64"`
	DatabaseSettings
	Description     string `json:"description,omitempty" maxLength:"500"`
	Favorite        bool   `json:"favorite,omitempty"`
	IntervalSeconds int32  `json:"interval_seconds,omitempty" minimum:"0" maximum:"3600" doc:"How often it's checked; 0 or left out = 60. At least 15"`
}

type DatabaseTestBody struct {
	DatabaseSettings
	DatabaseID *string `json:"database_id,omitempty" format:"uuid" doc:"When editing a saved database: reuse its stored password for a field left out"`
}

var containerRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func (s *DatabaseSettings) normalize() error {
	s.Host = strings.TrimSpace(s.Host)
	s.Username = strings.TrimSpace(s.Username)
	s.Dbname = strings.TrimSpace(s.Dbname)
	s.Container = strings.TrimSpace(s.Container)
	s.CACert = strings.TrimSpace(s.CACert)
	if s.Mode == "direct" {
		s.ServerID, s.Container = nil, ""
		if s.Host == "" {
			return fieldError("body.host", "Enter the database's address", nil)
		}
	} else {
		if parseOptionalID(s.ServerID) == nil {
			return fieldError("body.server_id", "Pick the server it's reached through", nil)
		}
		// The server's network decides what it can reach.
		s.AllowInternal = false
		if s.Container != "" && !containerRe.MatchString(s.Container) {
			return fieldError("body.container", "Enter the container's name or id", s.Container)
		}
		if s.Host == "" && s.Container == "" {
			s.Host = "127.0.0.1"
		}
	}
	if s.Host != "" {
		host, err := normalizeHost(s.Host)
		if err != nil {
			return err
		}
		s.Host = host
	}
	if s.Port == 0 {
		s.Port = int32(dbmon.DefaultPort(s.Engine))
	}
	if s.TLS == "" {
		s.TLS = dbmon.TLSDisable
		if s.Mode == "direct" {
			s.TLS = dbmon.TLSRequire
		}
	}
	if s.TLS != dbmon.TLSVerify {
		s.CACert = ""
	} else if s.CACert != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(s.CACert)) {
		return fieldError("body.ca_cert", "Paste the CA certificate in PEM form (-----BEGIN CERTIFICATE-----)", nil)
	}
	if s.Engine == dbmon.Redis && s.Dbname != "" {
		if n, err := strconv.Atoi(s.Dbname); err != nil || n < 0 || n > 255 {
			return fieldError("body.dbname", "Redis: enter a database number, like 0", s.Dbname)
		}
	}
	return nil
}

// local reports whether the database runs on the server it's reached through
// (or in a container there), so the server's disk is its disk.
func local(d sqlc.Database) bool {
	if d.Mode != "server" {
		return false
	}
	return d.Container != "" || d.Host == "127.0.0.1" || d.Host == "::1" || d.Host == "localhost"
}

// ---- Handler ----

type databaseHandler struct {
	q       *sqlc.Queries
	box     *secrets.Box
	servers *serverHandler

	mu       sync.Mutex
	conns    map[uuid.UUID]*dbConn
	running  map[uuid.UUID]bool
	public   map[string]publicEntry
	outbound outboundEntry
}

type publicEntry struct {
	public bool
	at     time.Time
}

type outboundEntry struct {
	ip string
	at time.Time
}

func newDatabaseHandler(q *sqlc.Queries, box *secrets.Box, servers *serverHandler) *databaseHandler {
	h := &databaseHandler{
		q: q, box: box, servers: servers,
		conns: map[uuid.UUID]*dbConn{}, running: map[uuid.UUID]bool{}, public: map[string]publicEntry{},
	}
	go h.reap()
	go h.monitor()
	return h
}

func (h *databaseHandler) get(ctx context.Context, rawID string) (sqlc.Database, error) {
	d, err := h.q.GetDatabase(ctx, uuid.MustParse(rawID))
	if isNotFound(err) {
		return d, huma.Error404NotFound("database not found")
	}
	if err != nil {
		return d, internalError(err)
	}
	return d, nil
}

// level is the caller's level on a database: its workspace's, or the server's
// it goes through when that's higher.
func databaseLevelOf(acc *auth.Access, d sqlc.Database) auth.Level {
	return databaseLevel(acc, d.WorkspaceID, d.ServerID)
}

// serverFor checks the caller may put a database behind this server
// (Engineer) and returns it.
func (h *databaseHandler) serverFor(ctx context.Context, acc *auth.Access, rawID string) (sqlc.Server, error) {
	s, err := h.servers.q.GetServer(ctx, uuid.MustParse(rawID))
	if isNotFound(err) {
		return s, fieldError("body.server_id", "server not found", rawID)
	}
	if err != nil {
		return s, internalError(err)
	}
	switch l := acc.ServerLevel(s.WorkspaceID, s.ID); {
	case l == auth.None:
		return s, fieldError("body.server_id", "server not found", rawID)
	case l < auth.Engineer:
		return s, huma.Error403Forbidden("You need Engineer access to " + s.Name + " to reach databases through it.")
	}
	return s, nil
}

// sealPassword seals the request's password; prev (on update) keeps the
// stored one when it's left out.
func (h *databaseHandler) sealPassword(c DatabaseSettings, prev *sqlc.Database) []byte {
	switch {
	case c.Password != "":
		return h.box.Seal(c.Password)
	case c.ClearPassword:
		return nil
	case prev != nil:
		return prev.PasswordEnc
	}
	return nil
}

func interval(v int32) int32 {
	if v == 0 {
		return 60
	}
	return max(v, 15)
}

func (h *databaseHandler) create(ctx context.Context, in *struct{ Body DatabaseBody }) (*DatabaseOutput, error) {
	p := principalOf(ctx)
	b := in.Body
	if err := b.normalize(); err != nil {
		return nil, err
	}
	var ws uuid.UUID
	if b.Mode == "server" {
		s, err := h.serverFor(ctx, p.Access, *b.ServerID)
		if err != nil {
			return nil, err
		}
		ws = s.WorkspaceID
	} else {
		var err error
		if ws, err = h.servers.authz.createTarget(ctx, p); err != nil {
			return nil, err
		}
		// Access to a direct database is the workspace's; without Engineer
		// there they couldn't even look at what they added.
		if p.Access.WorkspaceLevel(ws) < auth.Engineer {
			return nil, huma.Error403Forbidden("You need Engineer access to the workspace to add a database that isn't behind one of its servers.")
		}
	}
	if b.AllowInternal && !p.Access.Admin {
		return nil, fieldError("body.allow_internal", "Only a system admin can allow private addresses", true)
	}
	d, err := h.q.CreateDatabase(ctx, sqlc.CreateDatabaseParams{
		WorkspaceID: ws, Name: strings.TrimSpace(b.Name), Engine: b.Engine, Mode: b.Mode,
		ServerID: parseOptionalID(b.ServerID), Host: b.Host, Port: b.Port, Username: b.Username,
		PasswordEnc: h.sealPassword(b.DatabaseSettings, nil), Dbname: b.Dbname, Tls: b.TLS,
		CaCert: b.CACert, AllowInternal: b.AllowInternal, Container: b.Container,
		Description: strings.TrimSpace(b.Description), Favorite: b.Favorite,
		IntervalSeconds: interval(b.IntervalSeconds),
	})
	if isUniqueViolation(err) {
		return nil, fieldError("body.name", "A database with this name already exists", b.Name)
	}
	if err != nil {
		return nil, internalError(err)
	}
	return &DatabaseOutput{Body: toDatabase(d)}, nil
}

func (h *databaseHandler) update(ctx context.Context, in *struct {
	DatabaseIDPath
	Body DatabaseBody
}) (*DatabaseOutput, error) {
	p := principalOf(ctx)
	prev, err := h.get(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	b := in.Body
	if err := b.normalize(); err != nil {
		return nil, err
	}
	server := parseOptionalID(b.ServerID)
	switch {
	case b.Mode == "server" && (prev.ServerID == nil || *server != *prev.ServerID):
		s, err := h.serverFor(ctx, p.Access, *b.ServerID)
		if err != nil {
			return nil, err
		}
		if s.WorkspaceID != prev.WorkspaceID {
			return nil, fieldError("body.server_id", "Pick a server in the database's own workspace", *b.ServerID)
		}
	case b.Mode == "direct" && prev.Mode != "direct" && p.Access.WorkspaceLevel(prev.WorkspaceID) < auth.Engineer:
		return nil, huma.Error403Forbidden("You need Engineer access to the workspace to connect to this database directly.")
	}
	moved := b.Host != prev.Host || b.Port != prev.Port || b.Mode != prev.Mode
	allowInternal := b.AllowInternal
	if !p.Access.Admin {
		if b.AllowInternal && (moved || !prev.AllowInternal) {
			return nil, fieldError("body.allow_internal", "Only a system admin can allow private addresses", true)
		}
		// A permission an admin gave covers that address only.
		allowInternal = prev.AllowInternal && !moved && b.Mode == "direct"
	}
	status, message := prev.Status, prev.StatusMessage
	reconnect := moved || b.Engine != prev.Engine || !sameID(server, prev.ServerID) ||
		b.Username != prev.Username || b.Password != "" || b.ClearPassword || b.Dbname != prev.Dbname ||
		b.TLS != prev.Tls || b.CACert != prev.CaCert || b.Container != prev.Container || allowInternal != prev.AllowInternal
	if reconnect {
		status, message = "unknown", ""
	}
	d, err := h.q.UpdateDatabase(ctx, sqlc.UpdateDatabaseParams{
		ID: prev.ID, Name: strings.TrimSpace(b.Name), Engine: b.Engine, Mode: b.Mode,
		ServerID: server, Host: b.Host, Port: b.Port, Username: b.Username,
		PasswordEnc: h.sealPassword(b.DatabaseSettings, &prev), Dbname: b.Dbname, Tls: b.TLS,
		CaCert: b.CACert, AllowInternal: allowInternal, Container: b.Container,
		Description: strings.TrimSpace(b.Description), Favorite: b.Favorite,
		IntervalSeconds: interval(b.IntervalSeconds), Status: status, StatusMessage: message,
	})
	if isUniqueViolation(err) {
		return nil, fieldError("body.name", "A database with this name already exists", b.Name)
	}
	if err != nil {
		return nil, internalError(err)
	}
	h.drop(d.ID)
	return &DatabaseOutput{Body: toDatabase(d)}, nil
}

func sameID(a, b *uuid.UUID) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func (h *databaseHandler) testConnection(ctx context.Context, in *struct{ Body DatabaseTestBody }) (*struct{ Body *dbmon.DatabaseTest }, error) {
	p := principalOf(ctx)
	c := in.Body.DatabaseSettings
	if err := c.normalize(); err != nil {
		return nil, err
	}
	var prev *sqlc.Database
	if id := parseOptionalID(in.Body.DatabaseID); id != nil {
		d, err := h.q.GetDatabase(ctx, *id)
		if err != nil && !isNotFound(err) {
			return nil, internalError(err)
		}
		if err == nil {
			// Reusing the stored password against an address of their choosing
			// would hand it over, so only someone who could read it may.
			switch databaseLevelOf(p.Access, d) {
			case auth.Owner:
			case auth.None:
				return nil, huma.Error404NotFound("database not found")
			default:
				return nil, forbidden(auth.Owner)
			}
			prev = &d
		}
	}
	row := sqlc.Database{
		Engine: c.Engine, Mode: c.Mode, ServerID: parseOptionalID(c.ServerID), Host: c.Host,
		Port: c.Port, Username: c.Username, PasswordEnc: h.sealPassword(c, prev), Dbname: c.Dbname,
		Tls: c.TLS, CaCert: c.CACert, Container: c.Container,
	}
	if c.Mode == "server" {
		if _, err := h.serverFor(ctx, p.Access, *c.ServerID); err != nil {
			return nil, err
		}
	} else if prev == nil && !p.Access.CanCreateAnywhere() {
		return nil, huma.Error403Forbidden("You can't add databases.")
	}
	switch {
	case p.Access.Admin:
		row.AllowInternal = c.AllowInternal
	case prev != nil:
		row.AllowInternal = prev.AllowInternal && prev.Mode == c.Mode && prev.Host == c.Host && prev.Port == c.Port
	}

	cfg, ssh, err := h.config(ctx, row)
	if err != nil {
		status, msg := classifyDB(err)
		return &struct{ Body *dbmon.DatabaseTest }{&dbmon.DatabaseTest{
			Status: status, Message: msg, Steps: []dbmon.DatabaseTestStep{},
		}}, nil
	}
	if ssh != nil {
		defer ssh.Release()
	}
	return &struct{ Body *dbmon.DatabaseTest }{dbmon.Diagnose(ctx, cfg)}, nil
}

// ---- Live view ----

type DatabaseLive struct {
	Status   string                  `json:"status" enum:"online,unreachable,auth_failed,tls_error,blocked,error"`
	Message  string                  `json:"message"`
	Snapshot *dbmon.DatabaseSnapshot `json:"snapshot,omitempty" doc:"Absent when the database couldn't be reached"`
}

// liveFresh is how old a look may be and still be served as live.
const liveFresh = 3 * time.Second

func (h *databaseHandler) live(ctx context.Context, d sqlc.Database) DatabaseLive {
	h.mu.Lock()
	if c := h.conns[d.ID]; c != nil && c.version.Equal(d.UpdatedAt) && c.latest != nil &&
		time.Since(c.latest.CollectedAt) < liveFresh {
		s := c.latest
		h.mu.Unlock()
		return DatabaseLive{Status: dbmon.StatusOnline, Snapshot: s}
	}
	h.mu.Unlock()
	s, err := h.collect(ctx, d, false)
	if err != nil {
		status, msg := classifyDB(err)
		return DatabaseLive{Status: status, Message: msg}
	}
	return DatabaseLive{Status: dbmon.StatusOnline, Snapshot: s}
}

// redact hides what statements say from anyone below Engineer: queries carry
// customer data and secrets. The snapshot is shared, so it's copied.
func redact(s *dbmon.DatabaseSnapshot) *dbmon.DatabaseSnapshot {
	c := *s
	c.Sessions = slices.Clone(s.Sessions)
	for i := range c.Sessions {
		c.Sessions[i].Query = ""
	}
	c.Queries = slices.Clone(s.Queries)
	for i := range c.Queries {
		c.Queries[i].Query = ""
	}
	return &c
}

// ---- History ----

type DatabaseHistoryPoint struct {
	At             time.Time `json:"at"`
	Online         *float64  `json:"online" nullable:"true" doc:"Share of looks that got in, 0–1"`
	LatencyMs      *float64  `json:"latency_ms" nullable:"true"`
	Connections    *float64  `json:"connections" nullable:"true" doc:"Peak"`
	Active         *float64  `json:"active" nullable:"true"`
	MaxConnections *float64  `json:"max_connections" nullable:"true"`
	Qps            *float64  `json:"qps" nullable:"true"`
	Tps            *float64  `json:"tps" nullable:"true"`
	CacheHit       *float64  `json:"cache_hit" nullable:"true"`
	SizeBytes      *float64  `json:"size_bytes" nullable:"true"`
	DiskFreeBytes  *float64  `json:"disk_free_bytes" nullable:"true" doc:"Lowest"`
	DiskTotalBytes *float64  `json:"disk_total_bytes" nullable:"true"`
	ReplicationLag *float64  `json:"replication_lag" nullable:"true" doc:"Peak, seconds"`
	Blocked        *float64  `json:"blocked" nullable:"true" doc:"Peak"`
	Deadlocks      *float64  `json:"deadlocks" nullable:"true" doc:"Sum"`
	MemoryBytes    *float64  `json:"memory_bytes" nullable:"true"`
}

// DatabaseHourAverages is what one hour of the day usually looks like.
type DatabaseHourAverages struct {
	Samples     int32    `json:"samples" doc:"0 = no data to compare with"`
	Qps         *float64 `json:"qps" nullable:"true"`
	LatencyMs   *float64 `json:"latency_ms" nullable:"true"`
	Connections *float64 `json:"connections" nullable:"true"`
	Active      *float64 `json:"active" nullable:"true"`
}

// DatabaseGrowth is a straight line through the last week's sizes.
type DatabaseGrowth struct {
	SizeBytesPerDay *float64 `json:"size_bytes_per_day" nullable:"true"`
	DiskFullDays    *float64 `json:"disk_full_days" nullable:"true" doc:"Days until the disk is full at this pace; null when it isn't filling up"`
}

type DatabaseHistory struct {
	Range         string                 `json:"range" enum:"1h,6h,24h,7d,30d"`
	BucketSeconds int32                  `json:"bucket_seconds"`
	Points        []DatabaseHistoryPoint `json:"points"`
	// This hour of the day: yesterday, and on average over the week before.
	Yesterday DatabaseHourAverages `json:"yesterday"`
	Usual     DatabaseHourAverages `json:"usual"`
	Growth    DatabaseGrowth       `json:"growth"`
}

var historyRanges = map[string]struct {
	span   time.Duration
	bucket int32
}{
	"1h":  {time.Hour, 60},
	"6h":  {6 * time.Hour, 300},
	"24h": {24 * time.Hour, 600},
	"7d":  {7 * 24 * time.Hour, 3600},
	"30d": {30 * 24 * time.Hour, 4 * 3600},
}

// num turns the queries' NaN (nothing measured) into null.
func num(v float64) *float64 {
	if math.IsNaN(v) {
		return nil
	}
	return &v
}

func (h *databaseHandler) history(ctx context.Context, id uuid.UUID, rng string) (*DatabaseHistory, error) {
	r := historyRanges[rng]
	now := time.Now()
	rows, err := h.q.DatabaseHistory(ctx, sqlc.DatabaseHistoryParams{
		BucketSeconds: r.bucket, DatabaseID: id, Since: now.Add(-r.span), Until: now,
	})
	if err != nil {
		return nil, internalError(err)
	}
	out := &DatabaseHistory{Range: rng, BucketSeconds: r.bucket, Points: make([]DatabaseHistoryPoint, 0, len(rows))}
	for _, p := range rows {
		online := float64(p.OnlineSamples) / float64(max(p.Samples, 1))
		out.Points = append(out.Points, DatabaseHistoryPoint{
			At: p.Bucket, Online: &online, LatencyMs: num(p.LatencyMs), Connections: num(p.Connections),
			Active: num(p.Active), MaxConnections: num(p.MaxConnections), Qps: num(p.Qps), Tps: num(p.Tps),
			CacheHit: num(p.CacheHit), SizeBytes: num(p.SizeBytes), DiskFreeBytes: num(p.DiskFreeBytes),
			DiskTotalBytes: num(p.DiskTotalBytes), ReplicationLag: num(p.ReplicationLag),
			Blocked: num(p.Blocked), Deadlocks: num(p.Deadlocks), MemoryBytes: num(p.MemoryBytes),
		})
	}

	day := now.Truncate(24 * time.Hour)
	avg := func(since, until time.Time) (DatabaseHourAverages, error) {
		a, err := h.q.DatabaseAverages(ctx, sqlc.DatabaseAveragesParams{DatabaseID: id, Since: since, Until: until, Now: now})
		if err != nil {
			return DatabaseHourAverages{}, internalError(err)
		}
		return DatabaseHourAverages{Samples: a.Samples, Qps: num(a.Qps), LatencyMs: num(a.LatencyMs),
			Connections: num(a.Connections), Active: num(a.Active)}, nil
	}
	if out.Yesterday, err = avg(day.Add(-24*time.Hour), day); err != nil {
		return nil, err
	}
	if out.Usual, err = avg(day.Add(-8*24*time.Hour), day.Add(-24*time.Hour)); err != nil {
		return nil, err
	}

	trend, err := h.q.DatabaseSizeTrend(ctx, sqlc.DatabaseSizeTrendParams{DatabaseID: id, Since: now.Add(-7 * 24 * time.Hour)})
	if err != nil {
		return nil, internalError(err)
	}
	var sizes, free []point
	for _, t := range trend {
		x := t.At.Sub(now).Hours() / 24
		if t.SizeBytes != nil {
			sizes = append(sizes, point{x, float64(*t.SizeBytes)})
		}
		if t.DiskFreeBytes != nil {
			free = append(free, point{x, float64(*t.DiskFreeBytes)})
		}
	}
	if slope, _, ok := fit(sizes); ok {
		out.Growth.SizeBytesPerDay = &slope
	}
	if slope, intercept, ok := fit(free); ok && slope < 0 && intercept > 0 {
		days := intercept / -slope
		out.Growth.DiskFullDays = &days
	}
	return out, nil
}

type point struct{ x, y float64 }

// fit is a least-squares line; it needs a day's worth of spread to mean
// anything.
func fit(ps []point) (slope, intercept float64, ok bool) {
	if len(ps) < 10 || ps[len(ps)-1].x-ps[0].x < 1 {
		return 0, 0, false
	}
	var sx, sy, sxx, sxy float64
	n := float64(len(ps))
	for _, p := range ps {
		sx += p.x
		sy += p.y
		sxx += p.x * p.x
		sxy += p.x * p.y
	}
	d := n*sxx - sx*sx
	if d == 0 {
		return 0, 0, false
	}
	slope = (n*sxy - sx*sy) / d
	return slope, (sy - slope*sx) / n, true
}

// ---- Events ----

type DatabaseEvent struct {
	ID       string    `json:"id" format:"uuid"`
	At       time.Time `json:"at"`
	Kind     string    `json:"kind" doc:"check, version, restart, user, admin, address, setting, backup" example:"check"`
	Severity string    `json:"severity" enum:"info,ok,warning,critical"`
	CheckID  string    `json:"check_id" doc:"The check that changed (kind check)"`
	Title    string    `json:"title"`
	Detail   string    `json:"detail"`
}

func toDatabaseEvent(e sqlc.DatabaseEvent) DatabaseEvent {
	return DatabaseEvent{ID: e.ID.String(), At: e.At, Kind: e.Kind, Severity: e.Severity,
		CheckID: e.CheckID, Title: e.Title, Detail: e.Detail}
}

// ---- Outbound address ----

const outboundTTL = 10 * time.Minute

// outboundIP is the address databases see Morcheh connect from, for their
// firewalls' allow lists.
func (h *databaseHandler) outboundIP(ctx context.Context) (string, error) {
	h.mu.Lock()
	if h.outbound.ip != "" && time.Since(h.outbound.at) < outboundTTL {
		ip := h.outbound.ip
		h.mu.Unlock()
		return ip, nil
	}
	h.mu.Unlock()
	var last error
	for _, u := range []string{"https://api.ipify.org", "https://ifconfig.me/ip"} {
		ip, err := fetchIP(ctx, u)
		if err != nil {
			last = err
			continue
		}
		h.mu.Lock()
		h.outbound = outboundEntry{ip: ip, at: time.Now()}
		h.mu.Unlock()
		return ip, nil
	}
	return "", last
}

func fetchIP(ctx context.Context, url string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 64))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(b))
	if res.StatusCode != http.StatusOK {
		return "", errors.New(url + ": " + res.Status)
	}
	if _, err := normalizeHost(ip); err != nil || !strings.ContainsAny(ip, ".:") {
		return "", errors.New(url + " didn't answer with an address")
	}
	return ip, nil
}

// ---- Credentials ----

type DatabaseCredentials struct {
	Engine   string `json:"engine" enum:"postgres,mysql,mssql,redis,mongodb"`
	Host     string `json:"host" doc:"As the server it goes through sees it, when mode is server"`
	Port     int32  `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Dbname   string `json:"dbname"`
	TLS      string `json:"tls" enum:"disable,require,verify"`
}

type DatabaseCredentialsOutput struct {
	CacheControl string `header:"Cache-Control"`
	Body         DatabaseCredentials
}

type DatabaseList struct {
	Items []Database `json:"items"`
}

type DatabaseEventList struct {
	Items []DatabaseEvent `json:"items"`
}

type DatabaseCheckList struct {
	Items []dbmon.DatabaseCheckInfo `json:"items"`
}

type DatabaseOutboundIP struct {
	IP string `json:"ip" doc:"Empty when it couldn't be found out"`
}

// ---- Routes ----

func registerDatabases(api huma.API, h *databaseHandler) {
	tags := []string{"Databases"}

	huma.Register(api, huma.Operation{
		OperationID: "list-databases",
		Method:      http.MethodGet,
		Path:        "/databases",
		Summary:     "List databases",
		Description: "Worst health first, then favourites, then by name.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerID string `query:"server_id" format:"uuid" doc:"Only the ones reached through this server"`
	}) (*struct{ Body DatabaseList }, error) {
		p := principalOf(ctx)
		sc := p.scope()
		params := sqlc.ListDatabasesParams{
			SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, ServerIds: sc.servers, WorkspaceID: sc.current,
		}
		if in.ServerID != "" {
			// A server's own tab shows its databases whichever workspace is open.
			params.ServerID, params.WorkspaceID = parseOptionalID(&in.ServerID), nil
		}
		rows, err := h.q.ListDatabases(ctx, params)
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct{ Body DatabaseList }{}
		out.Body.Items = make([]Database, 0, len(rows))
		for _, r := range rows {
			out.Body.Items = append(out.Body.Items, toDatabase(r))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-database",
		Method:        http.MethodPost,
		Path:          "/databases",
		Summary:       "Add a database",
		Description:   "Through a server: Engineer on that server; it joins the server's workspace. Direct: Engineer and the right to add in the open workspace. Monitoring starts at once.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, h.create)

	huma.Register(api, huma.Operation{
		OperationID: "test-database-connection",
		Method:      http.MethodPost,
		Path:        "/databases/test-connection",
		Summary:     "Test database settings",
		Description: "Connects step by step (name, port, encryption, sign-in, monitoring permissions) without saving anything. The failure is in the result, not the status code.",
		Tags:        tags,
	}, h.testConnection)

	huma.Register(api, huma.Operation{
		OperationID: "get-database-outbound-ip",
		Method:      http.MethodGet,
		Path:        "/databases/outbound-ip",
		Summary:     "Morcheh's outbound address",
		Description: "The public address direct connections come from, to allow in the database's firewall. Asked from api.ipify.org (or ifconfig.me) and cached for 10 minutes.",
		Tags:        tags,
	}, func(ctx context.Context, _ *struct{}) (*struct{ Body DatabaseOutboundIP }, error) {
		out := &struct{ Body DatabaseOutboundIP }{}
		out.Body.IP, _ = h.outboundIP(ctx)
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-database-checks",
		Method:      http.MethodGet,
		Path:        "/databases/checks",
		Summary:     "Health checks",
		Description: "Every check with its default limits.",
		Tags:        tags,
	}, func(ctx context.Context, _ *struct{}) (*struct{ Body DatabaseCheckList }, error) {
		out := &struct{ Body DatabaseCheckList }{}
		out.Body.Items = dbmon.Checks
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-database",
		Method:      http.MethodGet,
		Path:        "/databases/{id}",
		Summary:     "Get a database",
		Tags:        tags,
	}, func(ctx context.Context, in *DatabaseIDPath) (*DatabaseOutput, error) {
		d, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &DatabaseOutput{Body: toDatabase(d)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-database",
		Method:      http.MethodPut,
		Path:        "/databases/{id}",
		Summary:     "Update a database",
		Description: "Replaces the connection settings. A password left out keeps the stored one. Moving it to another address drops an admin's permission for private addresses unless an admin makes the change.",
		Tags:        tags,
	}, h.update)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-database",
		Method:        http.MethodDelete,
		Path:          "/databases/{id}",
		Summary:       "Remove a database",
		Description:   "Forgets it in Morcheh with its history and events; nothing on the database itself is touched.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *DatabaseIDPath) (*struct{}, error) {
		id := uuid.MustParse(in.ID)
		n, err := h.q.DeleteDatabase(ctx, id)
		if err != nil {
			return nil, internalError(err)
		}
		if n == 0 {
			return nil, huma.Error404NotFound("database not found")
		}
		h.drop(id)
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-database-favorite",
		Method:      http.MethodPut,
		Path:        "/databases/{id}/favorite",
		Summary:     "Star or unstar a database",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Body struct {
			Favorite bool `json:"favorite"`
		}
	}) (*DatabaseOutput, error) {
		d, err := h.q.SetDatabaseFavorite(ctx, sqlc.SetDatabaseFavoriteParams{ID: uuid.MustParse(in.ID), Favorite: in.Body.Favorite})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("database not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &DatabaseOutput{Body: toDatabase(d)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-database-paused",
		Method:      http.MethodPut,
		Path:        "/databases/{id}/paused",
		Summary:     "Pause or resume monitoring",
		Description: "A paused database isn't checked, recorded or alerted on; its live view still works.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Body struct {
			Paused bool `json:"paused"`
		}
	}) (*DatabaseOutput, error) {
		d, err := h.q.SetDatabasePaused(ctx, sqlc.SetDatabasePausedParams{ID: uuid.MustParse(in.ID), Paused: in.Body.Paused})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("database not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &DatabaseOutput{Body: toDatabase(d)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-database-monitoring",
		Method:      http.MethodPut,
		Path:        "/databases/{id}/monitoring",
		Summary:     "Change limits, muted checks and alerts",
		Description: "thresholds replaces every override; a check left out goes back to its default limits.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Body struct {
			Thresholds    map[string]dbmon.DatabaseLimit `json:"thresholds"`
			MutedChecks   []string                       `json:"muted_checks"`
			AlertsEnabled bool                           `json:"alerts_enabled"`
		}
	}) (*DatabaseOutput, error) {
		b := in.Body
		for id, l := range b.Thresholds {
			i := slices.IndexFunc(dbmon.Checks, func(c dbmon.DatabaseCheckInfo) bool { return c.ID == id })
			if i < 0 || dbmon.Checks[i].Limit == nil {
				return nil, fieldError("body.thresholds."+id, "This check has no adjustable limits", id)
			}
			if c := dbmon.Checks[i]; (c.Lower && l.Warn <= l.Crit) || (!c.Lower && l.Warn >= l.Crit) || l.Warn < 0 || l.Crit < 0 {
				msg := "The warning limit must be below the critical one"
				if c.Lower {
					msg = "Lower is worse here: the warning limit must be above the critical one"
				}
				return nil, fieldError("body.thresholds."+id, msg, l)
			}
		}
		muted := []string{}
		for _, id := range b.MutedChecks {
			if !slices.ContainsFunc(dbmon.Checks, func(c dbmon.DatabaseCheckInfo) bool { return c.ID == id }) {
				return nil, fieldError("body.muted_checks", "Unknown check "+id, id)
			}
			if !slices.Contains(muted, id) {
				muted = append(muted, id)
			}
		}
		if b.Thresholds == nil {
			b.Thresholds = map[string]dbmon.DatabaseLimit{}
		}
		raw, _ := json.Marshal(b.Thresholds)
		d, err := h.q.SetDatabaseMonitoring(ctx, sqlc.SetDatabaseMonitoringParams{
			ID: uuid.MustParse(in.ID), Thresholds: raw, MutedChecks: muted, AlertsEnabled: b.AlertsEnabled,
		})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("database not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &DatabaseOutput{Body: toDatabase(d)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "check-database",
		Method:      http.MethodPost,
		Path:        "/databases/{id}/check",
		Summary:     "Check a database now",
		Description: "Connects afresh, runs every check and records the result.",
		Tags:        tags,
	}, func(ctx context.Context, in *DatabaseIDPath) (*DatabaseOutput, error) {
		d, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if err := h.claimWait(ctx, d.ID); err != nil {
			return nil, err
		}
		defer h.unclaim(d.ID)
		h.drop(d.ID)
		return &DatabaseOutput{Body: toDatabase(h.look(ctx, d))}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-database-live",
		Method:      http.MethodGet,
		Path:        "/databases/{id}/live",
		Summary:     "What the database is doing now",
		Description: "One look (at most a few seconds old): connections, sessions, queries, sizes, replication. Statement text is empty below Engineer access.",
		Tags:        tags,
	}, func(ctx context.Context, in *DatabaseIDPath) (*struct{ Body DatabaseLive }, error) {
		d, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		l := h.live(ctx, d)
		if l.Snapshot != nil {
			l.Snapshot = dbmon.MarkNew(baselineOf(d), l.Snapshot)
		}
		if l.Snapshot != nil && principalOf(ctx).Level < auth.Engineer {
			l.Snapshot = redact(l.Snapshot)
		}
		return &struct{ Body DatabaseLive }{l}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "kill-database-session",
		Method:        http.MethodPost,
		Path:          "/databases/{id}/kill",
		Summary:       "Stop a session's statement, or close it",
		Description:   "connection=false cancels what it runs (where the engine can); true closes the connection and rolls back its transaction.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Body struct {
			ID         string `json:"id" minLength:"1" maxLength:"64" doc:"The session's id from the live view"`
			Connection bool   `json:"connection,omitempty"`
		}
	}) (*struct{}, error) {
		d, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		err = h.with(ctx, d, func(c *dbmon.Conn) error { return c.Kill(ctx, in.Body.ID, in.Body.Connection) })
		if err != nil {
			return nil, actionError("Couldn't stop it", err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "explain-database-query",
		Method:      http.MethodPost,
		Path:        "/databases/{id}/explain",
		Summary:     "Show a query's plan",
		Description: "Asks the database how it would run the statement, without running it (EXPLAIN without ANALYZE, SHOWPLAN, explain queryPlanner). Not available for Redis.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Body struct {
			Database string `json:"database,omitempty" maxLength:"128" doc:"Database to plan it in"`
			Query    string `json:"query" minLength:"1" maxLength:"100000" doc:"MongoDB: {\"collection\": …, \"filter\": …} as JSON"`
		}
	}) (*struct{ Body *dbmon.DatabasePlan }, error) {
		d, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		var plan *dbmon.DatabasePlan
		err = h.with(ctx, d, func(c *dbmon.Conn) error {
			plan, err = c.Explain(ctx, in.Body.Database, in.Body.Query)
			return err
		})
		if err != nil {
			return nil, actionError("Couldn't get the plan", err)
		}
		if plan.Warnings == nil {
			plan.Warnings = []string{}
		}
		return &struct{ Body *dbmon.DatabasePlan }{plan}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-database-events",
		Method:      http.MethodGet,
		Path:        "/databases/{id}/events",
		Summary:     "What happened to a database",
		Description: "Newest first: checks changing state, restarts, new versions, logins, client addresses and settings. Kept 90 days.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Before time.Time `query:"before" doc:"Older than this (the last item's at), for the next page"`
		Limit  int32     `query:"limit" minimum:"1" maximum:"200" default:"50"`
	}) (*struct{ Body DatabaseEventList }, error) {
		params := sqlc.ListDatabaseEventsParams{DatabaseID: uuid.MustParse(in.ID), Lim: in.Limit}
		if !in.Before.IsZero() {
			params.Before = &in.Before
		}
		rows, err := h.q.ListDatabaseEvents(ctx, params)
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct{ Body DatabaseEventList }{}
		out.Body.Items = make([]DatabaseEvent, 0, len(rows))
		for _, e := range rows {
			out.Body.Items = append(out.Body.Items, toDatabaseEvent(e))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-database-history",
		Method:      http.MethodGet,
		Path:        "/databases/{id}/history",
		Summary:     "Charts over time",
		Description: "Recorded looks in buckets, this hour compared with yesterday and the usual, and how fast it grows. Kept 30 days.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Range string `query:"range" enum:"1h,6h,24h,7d,30d" default:"24h"`
	}) (*struct{ Body *DatabaseHistory }, error) {
		hist, err := h.history(ctx, uuid.MustParse(in.ID), in.Range)
		if err != nil {
			return nil, err
		}
		return &struct{ Body *DatabaseHistory }{hist}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "reveal-database-credentials",
		Method:      http.MethodPost,
		Path:        "/databases/{id}/credentials",
		Summary:     "Reveal a database's sign-in",
		Description: "Opens the stored password. POST and `Cache-Control: no-store` so nothing caches it.",
		Tags:        tags,
	}, func(ctx context.Context, in *DatabaseIDPath) (*DatabaseCredentialsOutput, error) {
		d, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		pw, err := h.box.Open(d.PasswordEnc)
		if err != nil {
			return nil, internalError(err)
		}
		return &DatabaseCredentialsOutput{CacheControl: "no-store", Body: DatabaseCredentials{
			Engine: d.Engine, Host: d.Host, Port: d.Port, Username: d.Username,
			Password: pw, Dbname: d.Dbname, TLS: d.Tls,
		}}, nil
	})
}

// actionError explains a refused kill or explain: the engine's own words, as
// a 422 (the request was fine, the database said no).
func actionError(what string, err error) error {
	if errors.Is(err, dbmon.ErrUnsupported) {
		return huma.Error422UnprocessableEntity(what + ": not possible for this database.")
	}
	var se huma.StatusError
	if errors.As(err, &se) {
		return err
	}
	return huma.Error422UnprocessableEntity(what + ": " + err.Error())
}
