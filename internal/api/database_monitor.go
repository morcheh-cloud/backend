package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/dbmon"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/terminal"
)

const (
	// databaseIdle closes a monitoring connection nobody used for this long
	// (a paused database, a dashboard left).
	databaseIdle = 5 * time.Minute
	// heavyEvery is how often sizes, tables, users and settings are re-read.
	heavyEvery = 10 * time.Minute
	// lookWorkers caps looks running at once.
	lookWorkers = 8
	publicTTL   = time.Hour
	sampleKeep  = 30 * 24 * time.Hour
	eventKeep   = 90 * 24 * time.Hour
)

// dbConn is an open monitoring connection and what it learned. Fields after
// conn are guarded by databaseHandler.mu.
type dbConn struct {
	conn *dbmon.Conn
	ssh  *sshpool.Conn // held while the connection goes through it

	version time.Time
	users   int
	last    time.Time
	dead    bool
	latest  *dbmon.DatabaseSnapshot
	heavyAt time.Time
	disk    *dbmon.DatabaseDisk // read with df on the server
}

func (c *dbConn) close() {
	c.conn.Close()
	if c.ssh != nil {
		c.ssh.Release()
	}
}

// dbConnError is a failure before the database was even tried, with the
// status it ends in.
type dbConnError struct {
	status  string
	message string
}

func (e *dbConnError) Error() string { return e.message }

func classifyDB(err error) (string, string) {
	var ce *dbConnError
	if errors.As(err, &ce) {
		return ce.status, ce.message
	}
	return dbmon.Classify(err)
}

// config builds how to reach d. Through a server it holds that server's SSH
// connection, which the caller releases.
func (h *databaseHandler) config(ctx context.Context, d sqlc.Database) (dbmon.Config, *sshpool.Conn, error) {
	pw, err := h.box.Open(d.PasswordEnc)
	if err != nil {
		return dbmon.Config{}, nil, err
	}
	cfg := dbmon.Config{
		Engine: d.Engine, Host: d.Host, Port: int(d.Port), Username: d.Username, Password: pw,
		Database: d.Dbname, TLS: d.Tls, CACert: d.CaCert, Timeout: 10 * time.Second,
	}
	if d.Mode == "direct" {
		cfg.Dial = dbmon.DirectDialer(d.AllowInternal)
		return cfg, nil, nil
	}
	if d.ServerID == nil {
		return cfg, nil, &dbConnError{dbmon.StatusError, "The server it was reached through was removed. Edit the database and pick another."}
	}
	c, err := h.servers.conn(ctx, d.ServerID.String())
	if err != nil {
		return cfg, nil, &dbConnError{dbmon.StatusUnreachable, "Can't reach the server it goes through: " + err.Error()}
	}
	c.Acquire()
	cfg.Dial, cfg.Tunneled = c.Client.DialContext, true
	if cfg.Host == "" {
		cfg.Host = h.containerIP(ctx, d, c)
	}
	return cfg, c, nil
}

// containerIP is the container's address on its Docker network; 127.0.0.1
// when it has none (host networking, or a published port).
func (h *databaseHandler) containerIP(ctx context.Context, d sqlc.Database, c *sshpool.Conn) string {
	sh, err := h.servers.rootShell(ctx, d.ServerID.String(), c)
	if err == nil {
		out, err := sh.run(ctx, "docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' -- "+terminal.ShellQuote(d.Container))
		if err == nil {
			for _, f := range strings.Fields(out) {
				if net.ParseIP(f) != nil {
					return f
				}
			}
		}
	}
	return "127.0.0.1"
}

// ---- Connection cache ----

func (h *databaseHandler) reap() {
	for range time.Tick(time.Minute) {
		h.mu.Lock()
		for id, c := range h.conns {
			if c.users == 0 && time.Since(c.last) > databaseIdle {
				delete(h.conns, id)
				go c.close()
			}
		}
		h.mu.Unlock()
	}
}

// acquire returns the open connection for d, connecting if needed; fresh
// says it was just opened. Every acquire needs a release.
func (h *databaseHandler) acquire(ctx context.Context, d sqlc.Database) (c *dbConn, fresh bool, err error) {
	h.mu.Lock()
	if c := h.conns[d.ID]; c != nil {
		if c.version.Equal(d.UpdatedAt) && !gone(c.ssh) {
			c.users++
			h.mu.Unlock()
			return c, false, nil
		}
		h.dropLocked(d.ID)
	}
	h.mu.Unlock()

	cfg, ssh, err := h.config(ctx, d)
	if err != nil {
		return nil, false, err
	}
	conn, err := dbmon.Open(ctx, cfg)
	if err != nil {
		if ssh != nil {
			ssh.Release()
		}
		return nil, false, err
	}
	c = &dbConn{conn: conn, ssh: ssh, version: d.UpdatedAt, users: 1, last: time.Now()}
	h.mu.Lock()
	if old := h.conns[d.ID]; old != nil {
		h.dropLocked(d.ID)
	}
	h.conns[d.ID] = c
	h.mu.Unlock()
	return c, true, nil
}

func gone(c *sshpool.Conn) bool {
	if c == nil {
		return false
	}
	select {
	case <-c.Done():
		return true
	default:
		return false
	}
}

func (h *databaseHandler) release(c *dbConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	c.users--
	c.last = time.Now()
	if c.dead && c.users == 0 {
		go c.close()
	}
}

func (h *databaseHandler) drop(id uuid.UUID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dropLocked(id)
}

// retire drops c if it's still the cached connection.
func (h *databaseHandler) retire(id uuid.UUID, c *dbConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conns[id] == c {
		h.dropLocked(id)
	}
}

func (h *databaseHandler) dropLocked(id uuid.UUID) {
	c := h.conns[id]
	if c == nil {
		return
	}
	delete(h.conns, id)
	c.dead = true
	if c.users == 0 {
		go c.close()
	}
}

// with runs fn on d's open connection, once more on a fresh one if the
// cached one turns out to be dead.
func (h *databaseHandler) with(ctx context.Context, d sqlc.Database, fn func(c *dbmon.Conn) error) error {
	for {
		c, fresh, err := h.acquire(ctx, d)
		if err != nil {
			_, msg := classifyDB(err)
			return huma.Error502BadGateway("Can't connect to the database: " + msg)
		}
		err = fn(c.conn)
		h.release(c)
		if err == nil || fresh || !lost(err) {
			return err
		}
		h.retire(d.ID, c)
	}
}

// lost reports whether err means the connection itself broke, not that the
// database refused what was asked.
func lost(err error) bool {
	status, _ := dbmon.Classify(err)
	return status == dbmon.StatusUnreachable || sshpool.Lost(err)
}

// collect takes one look at d. A look is heavy (sizes, tables, users,
// settings) when asked for or when the last heavy one is old.
func (h *databaseHandler) collect(ctx context.Context, d sqlc.Database, heavy bool) (*dbmon.DatabaseSnapshot, error) {
	for {
		c, fresh, err := h.acquire(ctx, d)
		if err != nil {
			return nil, err
		}
		h.mu.Lock()
		heavy := heavy || time.Since(c.heavyAt) > heavyEvery
		h.mu.Unlock()
		s, err := c.conn.Collect(ctx, heavy)
		if err != nil {
			h.release(c)
			h.retire(d.ID, c)
			if fresh || ctx.Err() != nil {
				return nil, err
			}
			continue
		}
		disk := h.serverDisk(ctx, d, c, s, heavy)
		h.mu.Lock()
		if heavy {
			c.heavyAt = s.CollectedAt
			c.disk = disk
		}
		if s.Disk == nil {
			s.Disk = c.disk
		}
		c.latest = s
		h.mu.Unlock()
		h.release(c)
		return s, nil
	}
}

// serverDisk reads the data directory's disk with df on the server when the
// engine doesn't say and the database runs there. Only on heavy looks; the
// result is carried until the next one.
func (h *databaseHandler) serverDisk(ctx context.Context, d sqlc.Database, c *dbConn, s *dbmon.DatabaseSnapshot, heavy bool) *dbmon.DatabaseDisk {
	if !heavy || s.Disk != nil || s.DataDir == "" || c.ssh == nil || !local(d) {
		return nil
	}
	sh, err := h.servers.rootShell(ctx, d.ServerID.String(), c.ssh)
	if err != nil {
		return nil
	}
	cmd := "df -Pk -- " + terminal.ShellQuote(s.DataDir)
	if d.Container != "" {
		cmd = "docker exec " + terminal.ShellQuote(d.Container) + " " + cmd
	}
	out, err := sh.run(ctx, cmd+" | tail -n 1")
	if err != nil {
		return nil
	}
	f := strings.Fields(out)
	if len(f) < 6 {
		return nil
	}
	total, err1 := strconv.ParseInt(f[1], 10, 64)
	free, err2 := strconv.ParseInt(f[3], 10, 64)
	if err1 != nil || err2 != nil || total <= 0 {
		return nil
	}
	return &dbmon.DatabaseDisk{Path: f[len(f)-1], TotalBytes: total * 1024, FreeBytes: free * 1024, Source: "server"}
}

// isPublic says whether host answers on the internet, cached for an hour.
func (h *databaseHandler) isPublic(ctx context.Context, host string) bool {
	h.mu.Lock()
	e, ok := h.public[host]
	h.mu.Unlock()
	if ok && time.Since(e.at) < publicTTL {
		return e.public
	}
	p := dbmon.Public(ctx, host)
	h.mu.Lock()
	h.public[host] = publicEntry{public: p, at: time.Now()}
	h.mu.Unlock()
	return p
}

// ---- Looks ----

// claim marks d as being looked at; false when a look already runs.
func (h *databaseHandler) claim(id uuid.UUID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.running[id] {
		return false
	}
	h.running[id] = true
	return true
}

// claimWait waits for a running look to end, then claims.
func (h *databaseHandler) claimWait(ctx context.Context, id uuid.UUID) error {
	for !h.claim(id) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return nil
}

func (h *databaseHandler) unclaim(id uuid.UUID) {
	h.mu.Lock()
	delete(h.running, id)
	h.mu.Unlock()
}

// look checks d once: runs every check, records what changed as events,
// stores the verdict and a sample. It returns the updated row.
func (h *databaseHandler) look(ctx context.Context, d sqlc.Database) sqlc.Database {
	now := time.Now()
	s, err := h.collect(ctx, d, false)
	status, msg := dbmon.StatusOnline, ""
	if err != nil {
		status, msg = classifyDB(err)
	}

	in := dbmon.EvalInput{
		Engine: d.Engine, Snapshot: s, Status: status, Message: msg,
		Direct: !local(d), Limits: limitsOf(d), Muted: d.MutedChecks, Now: now,
	}
	if d.Mode == "direct" {
		in.Public = h.isPublic(ctx, d.Host)
	}
	if b, err := h.q.LastGoodBackup(ctx, d.ID); err == nil {
		at := b.CreatedAt
		if b.FinishedAt != nil {
			at = *b.FinishedAt
		}
		in.LastBackup = &at
		if b.VerifiedAt != nil {
			in.LastRestoreTest, in.RestoreTestOK = b.VerifiedAt, b.VerifyError == ""
		}
	}
	if planned, err := h.q.AnyBackupPlanEnabled(ctx, d.ID); err == nil {
		in.BackupPlanned = planned
	}

	checks, changes := dbmon.Settle(checksOf(d), dbmon.Evaluate(in), now)
	if checks == nil {
		checks = []dbmon.DatabaseCheck{}
	}
	for _, c := range changes {
		h.event(ctx, d.ID, "check", checkSeverity(c.Check.Level), c.Check.ID, checkTitle(c), c.Check.Reason)
	}

	baseline := d.Baseline
	if s != nil {
		diffs, next := dbmon.Diff(baselineOf(d), s)
		for _, c := range diffs {
			h.event(ctx, d.ID, c.Kind, c.Severity, "", c.Title, c.Detail)
		}
		if b, err := json.Marshal(next); err == nil {
			baseline = b
		}
	}

	raw, _ := json.Marshal(checks)
	rec := sqlc.RecordDatabaseCheckParams{
		ID: d.ID, Status: status, StatusMessage: msg, Health: dbmon.Health(checks),
		Checks: raw, Baseline: baseline,
	}
	sample := sqlc.InsertDatabaseSampleParams{DatabaseID: d.ID, At: now}
	if s != nil {
		rec.Version, rec.Flavor, rec.Role = s.Version, s.Flavor, s.Role
		rec.LatencyMs, rec.SizeBytes = &s.LatencyMs, s.SizeBytes
		rec.Connections, rec.MaxConnections = &s.Connections.Total, s.Connections.Max
		sample = sampleOf(d.ID, now, s)
	}
	out, err := h.q.RecordDatabaseCheck(ctx, rec)
	if err != nil {
		if !isNotFound(err) {
			slog.Warn("record database check", "database", d.ID, "error", err)
		}
		return d
	}
	if err := h.q.InsertDatabaseSample(ctx, sample); err != nil {
		slog.Warn("record database sample", "database", d.ID, "error", err)
	}
	if alerts := h.servers.alerts; alerts != nil {
		var problems []string
		for _, c := range checks {
			if c.Level == "critical" && !c.Muted {
				problems = append(problems, c.Title)
			}
		}
		alerts.onDatabase(context.WithoutCancel(ctx), out, status, msg, out.Health, problems)
	}
	return out
}

func sampleOf(id uuid.UUID, at time.Time, s *dbmon.DatabaseSnapshot) sqlc.InsertDatabaseSampleParams {
	p := sqlc.InsertDatabaseSampleParams{
		DatabaseID: id, At: at, Online: true, LatencyMs: &s.LatencyMs,
		Connections: &s.Connections.Total, Active: &s.Connections.Active,
		MaxConnections: s.Connections.Max, CacheHit: s.CacheHit, SizeBytes: s.SizeBytes,
		Blocked: &s.Connections.Blocked,
	}
	if r := s.Rates; r != nil {
		p.Qps, p.Tps, p.Deadlocks = r.Queries, r.Transactions, r.Deadlocks
	}
	if s.Disk != nil {
		p.DiskFreeBytes, p.DiskTotalBytes = &s.Disk.FreeBytes, &s.Disk.TotalBytes
	}
	if s.Memory != nil {
		p.MemoryBytes = &s.Memory.UsedBytes
	}
	lag := func(v *float64) {
		if v != nil && (p.ReplicationLag == nil || *v > *p.ReplicationLag) {
			p.ReplicationLag = v
		}
	}
	for _, r := range s.Replication.Replicas {
		lag(r.LagSeconds)
	}
	if src := s.Replication.Source; src != nil {
		lag(src.LagSeconds)
	}
	return p
}

func (h *databaseHandler) event(ctx context.Context, id uuid.UUID, kind, severity, check, title, detail string) {
	_, err := h.q.InsertDatabaseEvent(ctx, sqlc.InsertDatabaseEventParams{
		DatabaseID: id, Kind: kind, Severity: severity, CheckID: check, Title: title, Detail: detail,
	})
	if err != nil {
		slog.Warn("record database event", "database", id, "error", err)
	}
}

func checkSeverity(level string) string {
	switch level {
	case dbmon.LevelOK:
		return "ok"
	case dbmon.LevelUnknown:
		return "info"
	}
	return level
}

func checkTitle(c dbmon.CheckChange) string {
	switch c.Check.Level {
	case dbmon.LevelOK:
		return c.Check.Title + " back to normal"
	case dbmon.LevelUnknown:
		return c.Check.Title + " can't be checked"
	}
	return c.Check.Title + ": " + c.Check.Level
}

// monitor looks at every database when it's due, a few at a time, and
// prunes old history hourly.
func (h *databaseHandler) monitor() {
	sem := make(chan struct{}, lookWorkers)
	var pruned time.Time
	for range time.Tick(5 * time.Second) {
		ctx := context.Background()
		due, err := h.q.ListDatabasesDue(ctx)
		if err != nil {
			slog.Warn("list databases due", "error", err)
			continue
		}
		for _, d := range due {
			if !h.claim(d.ID) {
				continue
			}
			sem <- struct{}{}
			go func(d sqlc.Database) {
				defer func() { <-sem; h.unclaim(d.ID) }()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				h.look(ctx, d)
			}(d)
		}
		if time.Since(pruned) > time.Hour {
			pruned = time.Now()
			if err := h.q.PruneDatabaseSamples(ctx, pruned.Add(-sampleKeep)); err != nil {
				slog.Warn("prune database samples", "error", err)
			}
			if err := h.q.PruneDatabaseEvents(ctx, pruned.Add(-eventKeep)); err != nil {
				slog.Warn("prune database events", "error", err)
			}
		}
	}
}

// baselineOf reads what the database looked like at the last compare; nil
// when it was never compared ('{}') or the record can't be read.
func baselineOf(d sqlc.Database) *dbmon.DatabaseBaseline {
	if len(d.Baseline) <= 2 {
		return nil
	}
	base := &dbmon.DatabaseBaseline{}
	if json.Unmarshal(d.Baseline, base) != nil {
		return nil
	}
	return base
}
