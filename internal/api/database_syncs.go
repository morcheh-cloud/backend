package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/dbbackup"
	"github.com/morche/backend/internal/dbmon"
	"github.com/morche/backend/internal/dbsync"
	"github.com/morche/backend/internal/jobs"
)

// Database syncs copy data from one database to another, like Navicat's Data
// Sync. Four modes:
//   - tables: chosen tables, with rules for rows that differ and rows the
//     target refuses;
//   - mirror: every table, row by row, so the target ends up the same (no
//     downtime: only the differences are written);
//   - incremental: only rows added or changed since the last run, read by a
//     growing column (id or updated_at);
//   - replace: the target is dropped and loaded again from a fresh dump
//     (any engine with backups; the target is briefly empty).
// Row modes work on PostgreSQL, MySQL/MariaDB and ClickHouse, between the
// same engine, and from PostgreSQL or MySQL/MariaDB into ClickHouse
// (analytics copies; see dbsync's clickhouse.go for what it can't write).

const (
	databaseSyncKind     = "database-sync"
	databaseSyncRunsKept = 200
	syncApp              = "morche-sync"
)

// ---- Types ----

type DatabaseSyncOptions struct {
	Pairs           []dbsync.Pair `json:"pairs,omitempty" maxItems:"1000" doc:"tables/incremental: which source table goes to which target table"`
	Exclude         []string      `json:"exclude,omitempty" maxItems:"1000" doc:"mirror: tables left out (schema.name or name)"`
	Insert          bool          `json:"insert,omitempty" doc:"tables: add rows the target lacks"`
	Delete          bool          `json:"delete,omitempty" doc:"tables: delete target rows the source lacks"`
	Conflict        string        `json:"conflict,omitempty" doc:"Rows on both sides that differ: overwrite (default), keep_target, newer_wins, stop"`
	NewerColumn     string        `json:"newer_column,omitempty" maxLength:"128" doc:"newer_wins: the column holding when a row last changed"`
	OnError         string        `json:"on_error,omitempty" doc:"A row the target refuses: skip (default), stop_table, stop"`
	Create          bool          `json:"create,omitempty" doc:"Create tables the target lacks"`
	NoKey           string        `json:"no_key,omitempty" doc:"Tables without a key: skip (default) or reload (emptied and copied again)"`
	PauseChecks     bool          `json:"pause_checks,omitempty" doc:"Foreign key checks off while writing"`
	LookbackSeconds int           `json:"lookback_seconds,omitempty" minimum:"0" maximum:"86400" doc:"incremental: read again this far behind the mark (time columns)"`
	Batch           int           `json:"batch,omitempty" minimum:"0" maximum:"10000" doc:"Rows per page (default 1000)"`
	FullEveryHours  int           `json:"full_every_hours,omitempty" minimum:"0" maximum:"8760" doc:"incremental: compare every row once in this many hours (0 = never)"`
	SourceRunner    string        `json:"source_runner,omitempty" doc:"replace, direct source: a server id, or \"local\" / empty = Morche's machine"`
	TargetRunner    string        `json:"target_runner,omitempty" doc:"replace, direct target: a server id, or \"local\" / empty = Morche's machine"`
}

type DatabaseSyncEnd struct {
	DatabaseID string `json:"database_id" format:"uuid"`
	Label      string `json:"label" doc:"The database connection's name in Morche"`
	Engine     string `json:"engine"`
	Mode       string `json:"mode" doc:"direct or server"`
	Name       string `json:"name" doc:"The database inside it"`
}

type DatabaseSyncRunBrief struct {
	ID         string     `json:"id" format:"uuid"`
	State      string     `json:"state"`
	DryRun     bool       `json:"dry_run"`
	At         time.Time  `json:"at"`
	FinishedAt *time.Time `json:"finished_at"`
	Error      string     `json:"error"`
}

type DatabaseSync struct {
	ID              string                `json:"id" format:"uuid"`
	WorkspaceID     string                `json:"workspace_id" format:"uuid"`
	Name            string                `json:"name"`
	Mode            string                `json:"mode" enum:"tables,mirror,incremental,replace"`
	Source          DatabaseSyncEnd       `json:"source"`
	Target          DatabaseSyncEnd       `json:"target"`
	Trigger         string                `json:"trigger" enum:"manual,schedule,interval"`
	Cron            string                `json:"cron"`
	Timezone        string                `json:"timezone"`
	IntervalMinutes int                   `json:"interval_minutes"`
	Options         DatabaseSyncOptions   `json:"options"`
	Paused          bool                  `json:"paused"`
	NextRunAt       *time.Time            `json:"next_run_at"`
	FullAt          *time.Time            `json:"full_at" doc:"incremental: when every row was last compared"`
	Problem         string                `json:"problem"`
	RunsAs          string                `json:"runs_as" doc:"Whose access runs use: the person who saved it last"`
	LastRun         *DatabaseSyncRunBrief `json:"last_run"`
	CreatedAt       time.Time             `json:"created_at"`
	UpdatedAt       time.Time             `json:"updated_at"`
}

type DatabaseSyncBody struct {
	Name             string              `json:"name" minLength:"1" maxLength:"100"`
	Mode             string              `json:"mode" enum:"tables,mirror,incremental,replace"`
	SourceDatabaseID string              `json:"source_database_id" format:"uuid"`
	SourceName       string              `json:"source_name" minLength:"1" maxLength:"128"`
	TargetDatabaseID string              `json:"target_database_id" format:"uuid"`
	TargetName       string              `json:"target_name" minLength:"1" maxLength:"128"`
	Trigger          string              `json:"trigger,omitempty" enum:"manual,schedule,interval"`
	Cron             string              `json:"cron,omitempty" maxLength:"200"`
	Timezone         string              `json:"timezone,omitempty" maxLength:"64"`
	IntervalMinutes  int                 `json:"interval_minutes,omitempty" minimum:"0" maximum:"10080"`
	Options          DatabaseSyncOptions `json:"options,omitempty"`
	Paused           *bool               `json:"paused,omitempty"`
	Confirm          string              `json:"confirm,omitempty" maxLength:"128" doc:"The target's name, when this can delete or replace data there"`
	Revision         *time.Time          `json:"revision,omitempty" doc:"updated_at as read; a newer save is refused"`
}

type DatabaseSyncReplace struct {
	Existed bool  `json:"existed" doc:"The target database was there before"`
	Bytes   int64 `json:"bytes" doc:"Dump size moved"`
}

type DatabaseSyncResult struct {
	Tables  []dbsync.TableResult `json:"tables"`
	Notes   []string             `json:"notes,omitempty"`
	Full    bool                 `json:"full,omitempty" doc:"incremental: this run compared every row"`
	Replace *DatabaseSyncReplace `json:"replace,omitempty"`
}

type DatabaseSyncRun struct {
	ID            string              `json:"id" format:"uuid"`
	SyncID        string              `json:"sync_id" format:"uuid"`
	Trigger       string              `json:"trigger"`
	DryRun        bool                `json:"dry_run" doc:"A preview: compared, nothing written"`
	State         string              `json:"state"`
	Phase         string              `json:"phase"`
	Error         string              `json:"error"`
	RowsWritten   int64               `json:"rows_written"`
	JobID         *string             `json:"job_id"`
	CreatedByName string              `json:"created_by_name"`
	CreatedAt     time.Time           `json:"created_at"`
	StartedAt     *time.Time          `json:"started_at"`
	FinishedAt    *time.Time          `json:"finished_at"`
	Result        *DatabaseSyncResult `json:"result"`
	Progress      *jobs.Progress      `json:"progress" doc:"While it runs"`
}

type DatabaseSyncTables struct {
	Name      string         `json:"name"`
	Databases []string       `json:"databases" doc:"Databases on this connection"`
	Tables    []dbsync.Table `json:"tables" doc:"Tables of name (engines with row modes only)"`
	Rows      bool           `json:"rows" doc:"Row-by-row modes work on this engine"`
	RowsInto  []string       `json:"rows_into" doc:"Engines this database's rows can be synced into (tables, mirror, incremental)"`
}

// ---- Handler ----

type databaseSyncHandler struct {
	q       *sqlc.Queries
	db      *databaseHandler
	backups *backupHandler
	authz   *authz
	runner  *jobs.Runner
}

func newDatabaseSyncHandler(b *backupHandler, a *authz) *databaseSyncHandler {
	return &databaseSyncHandler{q: b.q, db: b.db, backups: b, authz: a, runner: b.runner}
}

func rowEngine(engine string) bool {
	return engine == dbmon.Postgres || engine == dbmon.MySQL || engine == dbmon.ClickHouse
}

// rowTargets are the engines a row sync from engine can write into: its own,
// and ClickHouse from PostgreSQL and MySQL/MariaDB.
func rowTargets(engine string) []string {
	switch engine {
	case dbmon.Postgres, dbmon.MySQL:
		return []string{engine, dbmon.ClickHouse}
	case dbmon.ClickHouse:
		return []string{engine}
	}
	return []string{}
}

func destructive(mode string, o DatabaseSyncOptions) bool {
	return mode == "mirror" || mode == "replace" || (mode == "tables" && o.Delete)
}

func decodeDatabaseSyncOptions(raw []byte) DatabaseSyncOptions {
	var o DatabaseSyncOptions
	decodeInto(raw, &o)
	return o
}

func endOf(d sqlc.Database, name string) DatabaseSyncEnd {
	return DatabaseSyncEnd{DatabaseID: d.ID.String(), Label: d.Name, Engine: d.Engine, Mode: d.Mode, Name: name}
}

type dbSyncNames struct {
	dbs   map[uuid.UUID]sqlc.Database
	users map[uuid.UUID]string
}

func (h *databaseSyncHandler) lookup(ctx context.Context, list ...sqlc.DatabaseSync) (dbSyncNames, error) {
	n := dbSyncNames{dbs: map[uuid.UUID]sqlc.Database{}, users: map[uuid.UUID]string{}}
	for _, s := range list {
		for _, id := range []uuid.UUID{s.SourceDbID, s.TargetDbID} {
			if _, ok := n.dbs[id]; ok {
				continue
			}
			d, err := h.q.GetDatabase(ctx, id)
			if err != nil && !isNotFound(err) {
				return n, err
			}
			n.dbs[id] = d
		}
		if s.UpdatedBy != nil {
			if _, ok := n.users[*s.UpdatedBy]; !ok {
				if u, err := h.q.GetUser(ctx, *s.UpdatedBy); err == nil {
					n.users[*s.UpdatedBy] = cmpOr(u.FullName, u.Username)
				}
			}
		}
	}
	return n, nil
}

func (n dbSyncNames) level(acc *auth.Access, s sqlc.DatabaseSync) auth.Level {
	return min(databaseLevelOf(acc, n.dbs[s.SourceDbID]), databaseLevelOf(acc, n.dbs[s.TargetDbID]))
}

func toDatabaseSync(s sqlc.DatabaseSync, n dbSyncNames, last *DatabaseSyncRunBrief) DatabaseSync {
	out := DatabaseSync{
		ID: s.ID.String(), WorkspaceID: s.WorkspaceID.String(), Name: s.Name, Mode: s.Mode,
		Source: endOf(n.dbs[s.SourceDbID], s.SourceName), Target: endOf(n.dbs[s.TargetDbID], s.TargetName),
		Trigger: s.Trigger, Cron: s.Cron, Timezone: s.Timezone, IntervalMinutes: int(s.IntervalMinutes),
		Options: decodeDatabaseSyncOptions(s.Options), Paused: s.Paused, NextRunAt: s.NextRunAt, FullAt: s.FullAt,
		Problem: s.Problem, LastRun: last, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
	if s.UpdatedBy != nil {
		out.RunsAs = n.users[*s.UpdatedBy]
	}
	if out.Options.Pairs == nil {
		out.Options.Pairs = []dbsync.Pair{}
	}
	return out
}

func listRowSync(r sqlc.ListDatabaseSyncsRow) (sqlc.DatabaseSync, *DatabaseSyncRunBrief) {
	s := sqlc.DatabaseSync{
		ID: r.ID, WorkspaceID: r.WorkspaceID, Name: r.Name, Mode: r.Mode, SourceDbID: r.SourceDbID,
		SourceName: r.SourceName, TargetDbID: r.TargetDbID, TargetName: r.TargetName, Trigger: r.Trigger,
		Cron: r.Cron, Timezone: r.Timezone, IntervalMinutes: r.IntervalMinutes, Options: r.Options, Marks: r.Marks,
		FullAt: r.FullAt, Paused: r.Paused, NextRunAt: r.NextRunAt, Problem: r.Problem, CreatedBy: r.CreatedBy,
		UpdatedBy: r.UpdatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
	if r.LastRunID == nil {
		return s, nil
	}
	b := &DatabaseSyncRunBrief{ID: r.LastRunID.String(), FinishedAt: r.LastRunFinishedAt}
	if r.LastRunState != nil {
		b.State = *r.LastRunState
	}
	if r.LastRunAt != nil {
		b.At = *r.LastRunAt
	}
	if r.LastRunError != nil {
		b.Error = *r.LastRunError
	}
	if r.LastRunDryRun != nil {
		b.DryRun = *r.LastRunDryRun
	}
	return s, b
}

func (h *databaseSyncHandler) list(ctx context.Context, p sqlc.ListDatabaseSyncsParams) ([]DatabaseSync, error) {
	rows, err := h.q.ListDatabaseSyncs(ctx, p)
	if err != nil {
		return nil, internalError(err)
	}
	syncs := make([]sqlc.DatabaseSync, len(rows))
	lasts := make([]*DatabaseSyncRunBrief, len(rows))
	for i, r := range rows {
		syncs[i], lasts[i] = listRowSync(r)
	}
	n, err := h.lookup(ctx, syncs...)
	if err != nil {
		return nil, internalError(err)
	}
	acc := principalOf(ctx).Access
	out := []DatabaseSync{}
	for i, s := range syncs {
		if n.level(acc, s) >= auth.Viewer {
			out = append(out, toDatabaseSync(s, n, lasts[i]))
		}
	}
	return out, nil
}

func (h *databaseSyncHandler) one(ctx context.Context, s sqlc.DatabaseSync) (DatabaseSync, error) {
	n, err := h.lookup(ctx, s)
	if err != nil {
		return DatabaseSync{}, internalError(err)
	}
	runs, err := h.q.ListDatabaseSyncRuns(ctx, sqlc.ListDatabaseSyncRunsParams{SyncID: s.ID, Lim: 5})
	if err != nil {
		return DatabaseSync{}, internalError(err)
	}
	var last *DatabaseSyncRunBrief
	for _, r := range runs {
		if r.State == "skipped" {
			continue
		}
		last = &DatabaseSyncRunBrief{ID: r.ID.String(), State: r.State, DryRun: r.DryRun, At: r.CreatedAt, FinishedAt: r.FinishedAt, Error: r.Error}
		break
	}
	return toDatabaseSync(s, n, last), nil
}

func (h *databaseSyncHandler) load(ctx context.Context, raw string) (sqlc.DatabaseSync, error) {
	s, err := h.q.GetDatabaseSync(ctx, uuid.MustParse(raw))
	if isNotFound(err) {
		return s, huma.Error404NotFound("sync not found")
	}
	if err != nil {
		return s, internalError(err)
	}
	return s, nil
}

// syncRunner is where a dump or restore of d runs in replace mode.
func (h *databaseSyncHandler) syncRunner(ctx context.Context, d sqlc.Database, asked, field string) (string, error) {
	if d.Mode != "direct" {
		return "", nil
	}
	if asked == "" || asked == localRunner {
		if lt := localTools(d); !lt.Supported {
			return "", fieldError(field, lt.Note, nil)
		}
		return "", nil
	}
	id, err := uuid.Parse(asked)
	if err != nil {
		return "", fieldError(field, "Choose a server.", asked)
	}
	server, err := h.q.GetServer(ctx, id)
	if isNotFound(err) || (err == nil && server.WorkspaceID != d.WorkspaceID) {
		return "", fieldError(field, "That server was removed. Choose another one.", asked)
	}
	if err != nil {
		return "", internalError(err)
	}
	if principalOf(ctx).Access.ServerLevel(d.WorkspaceID, server.ID) < auth.Engineer {
		return "", huma.Error403Forbidden(fmt.Sprintf("You need %s access to %s.", auth.Engineer, server.Name))
	}
	return id.String(), nil
}

type checkedDatabaseSync struct {
	b        DatabaseSyncBody
	src, tgt sqlc.Database
	options  []byte
	next     *time.Time
}

func (h *databaseSyncHandler) check(ctx context.Context, ws uuid.UUID, b DatabaseSyncBody, old *sqlc.DatabaseSync) (checkedDatabaseSync, error) {
	c := checkedDatabaseSync{b: b}
	acc := principalOf(ctx).Access
	b.Name = strings.TrimSpace(b.Name)
	if b.Name == "" {
		return c, fieldError("body.name", "Give it a name.", b.Name)
	}
	getDB := func(raw, field string) (sqlc.Database, error) {
		d, err := h.q.GetDatabase(ctx, uuid.MustParse(raw))
		if isNotFound(err) || (err == nil && d.WorkspaceID != ws) {
			return d, fieldError(field, "database not found", raw)
		}
		if err != nil {
			return d, internalError(err)
		}
		return d, nil
	}
	var err error
	if c.src, err = getDB(b.SourceDatabaseID, "body.source_database_id"); err != nil {
		return c, err
	}
	if c.tgt, err = getDB(b.TargetDatabaseID, "body.target_database_id"); err != nil {
		return c, err
	}
	if databaseLevelOf(acc, c.src) < auth.Operator {
		return c, huma.Error403Forbidden(fmt.Sprintf("You need %s access to %s.", auth.Operator, c.src.Name))
	}
	if databaseLevelOf(acc, c.tgt) < auth.Owner {
		return c, huma.Error403Forbidden(fmt.Sprintf("You need %s access to %s to write into it.", auth.Owner, c.tgt.Name))
	}
	if c.src.ID == c.tgt.ID && b.SourceName == b.TargetName {
		return c, fieldError("body.target_name", "The source and the target are the same database.", b.TargetName)
	}
	if err := dbbackup.CheckName(b.SourceName); err != nil {
		return c, fieldError("body.source_name", problemText(err), b.SourceName)
	}
	if err := dbbackup.CheckName(b.TargetName); err != nil {
		return c, fieldError("body.target_name", problemText(err), b.TargetName)
	}
	if c.src.Engine != c.tgt.Engine && (b.Mode == "replace" || !slices.Contains(rowTargets(c.src.Engine), c.tgt.Engine)) {
		msg := "Both databases must be the same engine."
		if b.Mode != "replace" && c.tgt.Engine == dbmon.ClickHouse {
			msg = "ClickHouse takes rows from PostgreSQL, MySQL/MariaDB or another ClickHouse."
		} else if b.Mode == "replace" && c.tgt.Engine == dbmon.ClickHouse && rowEngine(c.src.Engine) {
			msg = "Replacing needs the same engine on both sides. To copy into ClickHouse, sync row by row."
		}
		return c, fieldError("body.target_database_id", msg, b.TargetDatabaseID)
	}
	o := &b.Options
	switch b.Mode {
	case "replace":
		switch c.src.Engine {
		case dbmon.Postgres, dbmon.MySQL, dbmon.Mongo, dbmon.ClickHouse, dbmon.Elastic, dbmon.Meili:
		default:
			return c, fieldError("body.mode", "Replacing works on PostgreSQL, MySQL/MariaDB, MongoDB, ClickHouse, Elasticsearch and Meilisearch.", b.Mode)
		}
		src, err := h.syncRunner(ctx, c.src, o.SourceRunner, "body.options.source_runner")
		if err != nil {
			return c, err
		}
		tgt, err := h.syncRunner(ctx, c.tgt, o.TargetRunner, "body.options.target_runner")
		if err != nil {
			return c, err
		}
		*o = DatabaseSyncOptions{SourceRunner: src, TargetRunner: tgt}
	default:
		if !rowEngine(c.src.Engine) {
			return c, fieldError("body.mode", "Row by row works on PostgreSQL, MySQL/MariaDB and ClickHouse. Use Replace for this engine.", b.Mode)
		}
		o.SourceRunner, o.TargetRunner = "", ""
		if o.Conflict == "" {
			o.Conflict = dbsync.Overwrite
		}
		if !slices.Contains([]string{dbsync.Overwrite, dbsync.KeepTarget, dbsync.NewerWins, dbsync.StopRun}, o.Conflict) {
			return c, fieldError("body.options.conflict", "Choose what happens to rows that differ.", o.Conflict)
		}
		if o.OnError == "" {
			o.OnError = dbsync.SkipRow
		}
		if !slices.Contains([]string{dbsync.SkipRow, dbsync.StopTable, dbsync.StopAll}, o.OnError) {
			return c, fieldError("body.options.on_error", "Choose what happens to a row the target refuses.", o.OnError)
		}
		if o.NoKey == "" {
			o.NoKey = "skip"
		}
		if o.NoKey != "skip" && o.NoKey != "reload" {
			return c, fieldError("body.options.no_key", "Choose skip or reload.", o.NoKey)
		}
		if o.Conflict == dbsync.NewerWins && strings.TrimSpace(o.NewerColumn) == "" {
			return c, fieldError("body.options.newer_column", "Name the column that says when a row changed.", o.NewerColumn)
		}
		switch b.Mode {
		case "mirror":
			o.Insert, o.Delete, o.Create, o.Conflict, o.Pairs = true, true, true, dbsync.Overwrite, nil
		case "incremental":
			o.Delete, o.Exclude = false, nil
			o.Insert = true
			if len(o.Pairs) == 0 {
				return c, fieldError("body.options.pairs", "Choose at least one table.", nil)
			}
			for i, p := range o.Pairs {
				if strings.TrimSpace(p.Track) == "" {
					return c, fieldError(fmt.Sprintf("body.options.pairs[%d].track", i), "Choose the column that grows with new rows.", p.From.Name)
				}
			}
		case "tables":
			o.Exclude = nil
			if len(o.Pairs) == 0 {
				return c, fieldError("body.options.pairs", "Choose at least one table.", nil)
			}
			if !o.Insert && !o.Delete && o.Conflict == dbsync.KeepTarget {
				return c, fieldError("body.options.insert", "With nothing to add, update or delete, it would do nothing.", nil)
			}
		}
		for i, p := range o.Pairs {
			if p.To.Name == "" {
				o.Pairs[i].To = p.From
			}
			if c.tgt.Engine == dbmon.ClickHouse {
				o.Pairs[i].To.Schema = "" // its tables sit right in the database
			}
		}
	}
	switch b.Trigger {
	case "", "manual":
		b.Trigger = "manual"
	case "schedule":
		if b.Timezone != "" {
			if _, err := time.LoadLocation(b.Timezone); err != nil {
				return c, fieldError("body.timezone", "Unknown time zone.", b.Timezone)
			}
		}
		if nextRun(b.Cron, b.Timezone, time.Now()) == nil {
			return c, fieldError("body.cron", "This schedule isn't valid.", b.Cron)
		}
	case "interval":
		if b.IntervalMinutes < 1 {
			return c, fieldError("body.interval_minutes", "Run it at least every minute.", b.IntervalMinutes)
		}
	}
	if destructive(b.Mode, *o) {
		fresh := old == nil || !destructive(old.Mode, decodeDatabaseSyncOptions(old.Options)) ||
			old.TargetDbID != c.tgt.ID || old.TargetName != b.TargetName
		if fresh && b.Confirm != b.TargetName {
			return c, fieldError("body.confirm", "Type "+b.TargetName+" to confirm: this can delete data there.", b.Confirm)
		}
	}
	paused := b.Paused != nil && *b.Paused
	if b.Paused == nil && old != nil {
		paused = old.Paused
	}
	c.next = nextOf(b.Trigger, b.Cron, b.Timezone, b.IntervalMinutes, paused, time.Now())
	c.options, _ = json.Marshal(o)
	c.b = b
	return c, nil
}

// ---- Runs ----

func (h *databaseSyncHandler) toRun(r sqlc.DatabaseSyncRun) DatabaseSyncRun {
	out := DatabaseSyncRun{
		ID: r.ID.String(), SyncID: r.SyncID.String(), Trigger: r.Trigger, DryRun: r.DryRun, State: r.State,
		Phase: r.Phase, Error: r.Error, RowsWritten: r.RowsWritten, JobID: optionalIDString(r.JobID),
		CreatedByName: r.CreatedByName, CreatedAt: r.CreatedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
	}
	if len(r.Result) > 0 && string(r.Result) != "null" && string(r.Result) != "{}" {
		var res DatabaseSyncResult
		decodeInto(r.Result, &res)
		out.Result = &res
	}
	return out
}

func (h *databaseSyncHandler) live(ctx context.Context, r *DatabaseSyncRun) {
	if !jobs.Active(r.State) || r.JobID == nil {
		return
	}
	j, err := h.runner.Get(ctx, uuid.MustParse(*r.JobID))
	if err != nil || !jobs.Active(j.State) {
		return
	}
	p := toJob(j, false).Progress
	r.Progress = &p
}

func (h *databaseSyncHandler) syncRun(ctx context.Context, r sqlc.DatabaseSyncRun) bool {
	if !jobs.Active(r.State) {
		return false
	}
	end := func(state, msg string) bool {
		if err := h.q.EndDatabaseSyncRun(ctx, sqlc.EndDatabaseSyncRunParams{ID: r.ID, State: state, Error: msg}); err != nil {
			slog.Warn("end a database sync run", "run", r.ID, "error", err)
			return false
		}
		return true
	}
	const lost = "Morche restarted before it finished."
	if r.JobID == nil {
		if time.Since(r.CreatedAt) < time.Minute {
			return false
		}
		return end(jobs.Interrupted, lost)
	}
	j, err := h.runner.Get(ctx, *r.JobID)
	switch {
	case errors.Is(err, jobs.ErrNotFound):
		return end(jobs.Interrupted, lost)
	case err != nil, jobs.Active(j.State):
		return false
	case j.State == jobs.Canceled:
		return end(jobs.Canceled, "")
	case j.State == jobs.Failed:
		return end(jobs.Failed, j.Error)
	}
	return end(jobs.Interrupted, cmpOr(j.Error, lost))
}

func (h *databaseSyncHandler) busy(ctx context.Context, id uuid.UUID) (bool, error) {
	rows, err := h.q.ListActiveDatabaseSyncRuns(ctx, id)
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		if !h.syncRun(ctx, r) {
			return true, nil
		}
	}
	return false, nil
}

type databaseSyncRunParams struct {
	RunID uuid.UUID `json:"run_id"`
}

func (h *databaseSyncHandler) start(ctx context.Context, s sqlc.DatabaseSync, by *principal, trigger string, dryRun bool) (*sqlc.DatabaseSyncRun, *Job, error) {
	busy, err := h.busy(ctx, s.ID)
	if err != nil {
		return nil, nil, internalError(err)
	}
	byName := ""
	var byID *uuid.UUID
	if by != nil {
		trigger, byID, byName = "manual", by.ID(), cmpOr(by.User.FullName, by.User.Username)
	}
	if busy && by != nil {
		return nil, nil, huma.Error409Conflict("It's running now. Wait for it to finish, or stop it first.")
	}
	if busy && trigger == "interval" {
		return nil, nil, nil
	}
	params := sqlc.CreateDatabaseSyncRunParams{
		SyncID: s.ID, WorkspaceID: s.WorkspaceID, Trigger: trigger, DryRun: dryRun,
		State: jobs.Queued, CreatedBy: byID, CreatedByName: byName,
	}
	if busy {
		now := time.Now()
		params.State, params.Error, params.FinishedAt = "skipped", "The run before was still going.", &now
	}
	run, err := h.q.CreateDatabaseSyncRun(ctx, params)
	if err != nil {
		return nil, nil, internalError(err)
	}
	if err := h.q.PruneDatabaseSyncRuns(ctx, sqlc.PruneDatabaseSyncRunsParams{SyncID: s.ID, Keep: databaseSyncRunsKept}); err != nil {
		slog.Warn("prune database sync runs", "sync", s.ID, "error", err)
	}
	if busy {
		return &run, nil, nil
	}
	verb := "Sync "
	if dryRun {
		verb = "Compare "
	}
	j, err := h.runner.Submit(ctx, jobs.Spec{
		Kind: databaseSyncKind, Title: verb + s.Name, Params: databaseSyncRunParams{RunID: run.ID},
		Refs:      []uuid.UUID{s.SourceDbID, s.TargetDbID},
		Target:    JobPlace{SyncID: s.ID.String(), RunID: run.ID.String(), DatabaseID: s.TargetDbID.String(), Name: s.Name},
		CreatedBy: byID,
	})
	if err != nil {
		_ = h.q.EndDatabaseSyncRun(context.WithoutCancel(ctx), sqlc.EndDatabaseSyncRunParams{ID: run.ID, State: jobs.Failed, Error: "It couldn't be queued."})
		return &run, nil, internalError(err)
	}
	if err := h.q.SetDatabaseSyncRunJob(ctx, sqlc.SetDatabaseSyncRunJobParams{ID: run.ID, JobID: &j.ID}); err != nil {
		return &run, nil, internalError(err)
	}
	run.JobID = &j.ID
	job := toJob(j, false)
	return &run, &job, nil
}

func (h *databaseSyncHandler) runAs(ctx context.Context, s sqlc.DatabaseSync) (string, *auth.Access, error) {
	gone := errors.New("The person who saved this was removed. Someone with access should open it and save it again.")
	if s.UpdatedBy == nil {
		return "", nil, gone
	}
	u, err := h.q.GetUser(ctx, *s.UpdatedBy)
	if isNotFound(err) {
		return "", nil, gone
	}
	if err != nil {
		return "", nil, err
	}
	name := cmpOr(u.FullName, u.Username)
	if u.Status != "active" {
		return name, nil, fmt.Errorf("%s's account isn't active, so this doesn't run. Someone with access should open it and save it again.", name)
	}
	acc, err := h.authz.accessOf(ctx, u)
	return name, acc, err
}

// open connects to one end, as monitoring does.
func (h *databaseSyncHandler) open(ctx context.Context, d sqlc.Database, name string) (dbsync.Side, func(), error) {
	cfg, conn, err := h.db.config(ctx, d)
	if err != nil {
		return dbsync.Side{}, nil, err
	}
	db, err := dbmon.OpenSQL(ctx, cfg, name, syncApp)
	if err != nil {
		if conn != nil {
			conn.Release()
		}
		return dbsync.Side{}, nil, err
	}
	closeAll := func() {
		_ = db.Close()
		if conn != nil {
			conn.Release()
		}
	}
	return dbsync.Side{DB: db, Dialect: dbsync.Dialect(d.Engine), Database: name}, closeAll, nil
}

func (h *databaseSyncHandler) runJob(ctx context.Context, t *jobs.Task) (any, error) {
	var params databaseSyncRunParams
	if err := t.Decode(&params); err != nil {
		return nil, err
	}
	bg := context.WithoutCancel(ctx)
	run, err := h.q.GetDatabaseSyncRun(ctx, params.RunID)
	if isNotFound(err) {
		return nil, errors.New("It was deleted before this run started.")
	}
	if err != nil {
		return nil, err
	}
	if !jobs.Active(run.State) {
		return nil, nil
	}
	var res DatabaseSyncResult
	written := func() int64 {
		var n int64
		for _, r := range res.Tables {
			n += r.Written()
		}
		return n
	}
	fail := func(err error) (any, error) {
		raw, _ := json.Marshal(res)
		_ = h.q.FinishDatabaseSyncRun(bg, sqlc.FinishDatabaseSyncRunParams{ID: run.ID, State: jobs.Failed, Error: problemText(err), Result: raw, RowsWritten: written()})
		return nil, errors.New(problemText(err))
	}
	s, err := h.q.GetDatabaseSync(ctx, run.SyncID)
	if err != nil {
		return fail(errors.New("It was deleted before this run started."))
	}
	if err := h.q.StartDatabaseSyncRun(ctx, run.ID); err != nil {
		return nil, err
	}
	who, acc, err := h.runAs(ctx, s)
	if err != nil {
		return fail(err)
	}
	src, err := h.q.GetDatabase(ctx, s.SourceDbID)
	if err != nil {
		return fail(errors.New("The source database was removed."))
	}
	tgt, err := h.q.GetDatabase(ctx, s.TargetDbID)
	if err != nil {
		return fail(errors.New("The target database was removed."))
	}
	if databaseLevelOf(acc, src) < auth.Operator {
		return fail(fmt.Errorf("%s no longer has %s access to the source.", who, auth.Operator))
	}
	if databaseLevelOf(acc, tgt) < auth.Owner {
		return fail(fmt.Errorf("%s no longer has %s access to the target.", who, auth.Owner))
	}
	if !run.DryRun {
		if n, err := h.q.CountActiveDatabaseSyncRunsTo(ctx, sqlc.CountActiveDatabaseSyncRunsToParams{TargetDbID: s.TargetDbID, TargetName: s.TargetName}); err != nil {
			return fail(err)
		} else if n > 1 {
			return fail(errors.New("Another sync is writing into " + s.TargetName + " now. Try again when it ends."))
		}
	}
	o := decodeDatabaseSyncOptions(s.Options)
	save := func(phase string) {
		raw, _ := json.Marshal(res)
		if err := h.q.SaveDatabaseSyncRun(bg, sqlc.SaveDatabaseSyncRunParams{ID: run.ID, Phase: phase, Result: raw, RowsWritten: written()}); err != nil {
			slog.Warn("save a database sync run", "run", run.ID, "error", err)
		}
	}

	var runErr error
	if s.Mode == "replace" {
		runErr = h.replace(ctx, t, s, src, tgt, o, run.DryRun, &res, save)
	} else {
		runErr = h.rows(ctx, t, s, src, tgt, o, run.DryRun, &res, save)
	}

	state, msg := jobs.Succeeded, ""
	failedTables := 0
	for _, r := range res.Tables {
		if r.State == "failed" || r.Failed > 0 {
			failedTables++
		}
	}
	switch {
	case runErr != nil && ctx.Err() != nil && t.Canceled():
		state = jobs.Canceled
	case runErr != nil && ctx.Err() != nil:
		state, msg = jobs.Interrupted, "Morche stopped before it finished."
	case runErr != nil && !errors.Is(runErr, dbsync.ErrStopped):
		state, msg = jobs.Failed, problemText(runErr)
	case runErr != nil:
		state, msg = "partial", "It stopped, as its rules say, after a problem."
	case failedTables > 0:
		state, msg = "partial", plural(failedTables, "table")+" had problems."
	}
	raw, _ := json.Marshal(res)
	if err := h.q.FinishDatabaseSyncRun(bg, sqlc.FinishDatabaseSyncRunParams{ID: run.ID, State: state, Error: msg, Result: raw, RowsWritten: written()}); err != nil {
		slog.Warn("finish a database sync run", "run", run.ID, "error", err)
	}
	switch state {
	case jobs.Canceled, jobs.Interrupted:
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New(cmpOr(msg, "It was stopped."))
	case jobs.Failed, "partial":
		return nil, errors.New(msg)
	}
	return map[string]any{"rows": written(), "tables": len(res.Tables)}, nil
}

// rows runs the row-by-row modes.
func (h *databaseSyncHandler) rows(ctx context.Context, t *jobs.Task, s sqlc.DatabaseSync, src, tgt sqlc.Database, o DatabaseSyncOptions, dry bool, res *DatabaseSyncResult, save func(string)) error {
	t.Update(func(p *jobs.Progress) { p.Phase = "Connecting" })
	from, closeFrom, err := h.open(ctx, src, s.SourceName)
	if err != nil {
		return fmt.Errorf("The source: %s", problemText(err))
	}
	defer closeFrom()
	to, closeTo, err := h.open(ctx, tgt, s.TargetName)
	if err != nil {
		return fmt.Errorf("The target: %s", problemText(err))
	}
	defer closeTo()

	pairs := o.Pairs
	if s.Mode == "mirror" {
		tables, err := dbsync.Tables(ctx, from.DB, from.Dialect, s.SourceName)
		if err != nil {
			return fmt.Errorf("Couldn't list the source's tables: %s", problemText(err))
		}
		pairs = nil
		for _, tb := range tables {
			if slices.Contains(o.Exclude, tb.Ref.String()) || slices.Contains(o.Exclude, tb.Name) {
				continue
			}
			pairs = append(pairs, dbsync.Pair{From: tb.Ref, To: tb.Ref})
		}
	}
	r := &dbsync.Run{
		Src: from, Dst: to, DryRun: dry,
		Rules: dbsync.Rules{
			Insert: o.Insert, Delete: o.Delete, Conflict: o.Conflict, NewerColumn: o.NewerColumn,
			OnError: o.OnError, Create: o.Create, NoKey: o.NoKey, PauseChecks: o.PauseChecks,
			Lookback: o.LookbackSeconds, Batch: o.Batch,
		},
		Progress: func(table string, index, count int, read, estimate int64) {
			t.Update(func(p *jobs.Progress) {
				p.Phase, p.Current, p.Items, p.ItemsTotal, p.Done, p.Total = "Comparing", table, index, count, read, estimate
			})
		},
		Log: func(format string, args ...any) { t.Logf(format, args...) },
	}
	if s.Mode == "incremental" {
		r.Marks = map[string]dbsync.Mark{}
		decodeInto(s.Marks, &r.Marks)
		full := o.FullEveryHours > 0 && (s.FullAt == nil || time.Since(*s.FullAt) >= time.Duration(o.FullEveryHours)*time.Hour)
		r.Incremental = !full
		res.Full = full
	}
	save("Comparing")
	tables, runErr := r.Do(ctx, pairs)
	res.Tables, res.Notes = tables, r.Notes()
	if s.Mode == "incremental" && !dry && ctx.Err() == nil {
		raw, _ := json.Marshal(r.Marks)
		fullAt := s.FullAt
		if res.Full && runErr == nil {
			now := time.Now()
			fullAt = &now
		}
		if err := h.q.SetDatabaseSyncMarks(context.WithoutCancel(ctx), sqlc.SetDatabaseSyncMarksParams{ID: s.ID, Marks: raw, FullAt: fullAt}); err != nil {
			slog.Warn("save database sync marks", "sync", s.ID, "error", err)
		}
	}
	return runErr
}

// replace dumps the source and loads it into the target in one stream.
func (h *databaseSyncHandler) replace(ctx context.Context, t *jobs.Task, s sqlc.DatabaseSync, src, tgt sqlc.Database, o DatabaseSyncOptions, dry bool, res *DatabaseSyncResult, save func(string)) error {
	t.Update(func(p *jobs.Progress) { p.Phase = "Checking the target" })
	names, err := h.backups.databaseNames(ctx, tgt)
	if err != nil {
		return fmt.Errorf("The target: %s", problemText(err))
	}
	res.Replace = &DatabaseSyncReplace{Existed: slices.Contains(names, s.TargetName)}
	if dry {
		if res.Replace.Existed {
			res.Notes = append(res.Notes, s.TargetName+" will be dropped and loaded again from "+s.SourceName+".")
		} else {
			res.Notes = append(res.Notes, s.TargetName+" doesn't exist yet: it will be created from "+s.SourceName+".")
		}
		return nil
	}
	srcPass, err := h.db.box.Open(src.PasswordEnc)
	if err != nil {
		return err
	}
	tgtPass, err := h.db.box.Open(tgt.PasswordEnc)
	if err != nil {
		return err
	}
	srcTarget := backupTarget(src, src.Username, srcPass, s.SourceName, s.ID.String())
	spec, err := dbbackup.Build(srcTarget)
	if err != nil {
		return err
	}
	tgtTarget := backupTarget(tgt, tgt.Username, tgtPass, s.TargetName, s.ID.String())
	loadOpts := dbbackup.RestoreOptions{
		Format: spec.Format, Source: s.SourceName, Replace: res.Replace.Existed, First: true, Last: true, CreateNamed: true,
	}
	script, err := dbbackup.BuildRestore(tgtTarget, loadOpts)
	if err != nil {
		return err
	}
	scriptFor := func(d sqlc.Database, runner, sh, pass string) dumpScript {
		ds := dumpScript{script: sh, secrets: []string{pass}, root: d.Container != "" || d.Engine == dbmon.MSSQL}
		switch {
		case d.Mode == "server" && d.ServerID != nil:
			ds.server, ds.container = *d.ServerID, d.Container
		case runner != "":
			ds.server = uuid.MustParse(runner)
		}
		return ds
	}
	dump := scriptFor(src, o.SourceRunner, spec.Script, srcPass)
	load := scriptFor(tgt, o.TargetRunner, script, tgtPass)
	dump.native = h.backups.nativeFor(src, srcTarget, nil)
	load.native = h.backups.nativeFor(tgt, tgtTarget, &loadOpts)

	save("Copying")
	t.Update(func(p *jobs.Progress) { p.Phase, p.Current = "Copying", s.SourceName+" → "+s.TargetName })
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	dumped := make(chan error, 1)
	go func() {
		_, err := h.backups.runDump(ctx, t, dump, pw)
		_ = pw.CloseWithError(err)
		if err != nil {
			cancel()
		}
		dumped <- err
	}()
	counter := &countBytes{r: pr}
	load.data = &countingReader{r: counter, t: t}
	_, loadErr := h.backups.runDump(ctx, t, load, nil)
	_ = pr.CloseWithError(io.ErrClosedPipe)
	dumpErr := <-dumped
	res.Replace.Bytes = counter.n
	switch {
	case dumpErr != nil && !errors.Is(dumpErr, io.ErrClosedPipe):
		return fmt.Errorf("Reading the source: %s", problemText(dumpErr))
	case loadErr != nil:
		return fmt.Errorf("Loading the target: %s", problemText(loadErr))
	}
	t.Logf("Loaded %s into %s", s.SourceName, s.TargetName)
	return nil
}

type countBytes struct {
	r io.Reader
	n int64
}

func (c *countBytes) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// ---- Scheduler ----

func startDatabaseSyncScheduler(h *databaseSyncHandler, every time.Duration) {
	if every <= 0 {
		return
	}
	go func() {
		ctx := context.Background()
		for range time.Tick(every) {
			h.fire(ctx)
		}
	}()
}

func (h *databaseSyncHandler) fire(ctx context.Context) {
	now := time.Now()
	due, err := h.q.ListDueDatabaseSyncs(ctx, &now)
	if err != nil {
		slog.Warn("list due database syncs", "error", err)
		return
	}
	for _, s := range due {
		next := nextOf(s.Trigger, s.Cron, s.Timezone, int(s.IntervalMinutes), false, now)
		n, err := h.q.ClaimDatabaseSync(ctx, sqlc.ClaimDatabaseSyncParams{ID: s.ID, Due: s.NextRunAt, NextRunAt: next})
		if err != nil || n == 0 {
			continue
		}
		if _, _, err := h.start(ctx, s, nil, s.Trigger, false); err != nil {
			slog.Warn("start a database sync", "sync", s.ID, "error", err)
		}
	}
}

// ---- Routes ----

type DatabaseSyncPath struct {
	ID string `path:"id" format:"uuid"`
}

type DatabaseSyncListOutput struct {
	Body struct {
		Items []DatabaseSync `json:"items"`
	}
}

type DatabaseSyncOutput struct{ Body DatabaseSync }

type DatabaseSyncRunOutput struct {
	Body struct {
		Run *DatabaseSyncRun `json:"run" doc:"null when an interval run was left for the next turn"`
		Job *Job             `json:"job" doc:"null when the run was skipped"`
	}
}

type DatabaseSyncRunListOutput struct {
	Body struct {
		Items []DatabaseSyncRun `json:"items"`
	}
}

type DatabaseSyncRunOneOutput struct{ Body DatabaseSyncRun }

func registerDatabaseSyncs(api huma.API, h *databaseSyncHandler) {
	tags := []string{"Database syncs"}
	h.runner.Handle(databaseSyncKind, h.runJob)

	huma.Register(api, huma.Operation{
		OperationID: "list-database-syncs", Method: http.MethodGet, Path: "/workspaces/{id}/database-syncs",
		Summary: "List a workspace's database syncs", Tags: tags,
	}, func(ctx context.Context, in *WorkspacePath) (*DatabaseSyncListOutput, error) {
		ws := uuid.MustParse(in.ID)
		items, err := h.list(ctx, sqlc.ListDatabaseSyncsParams{WorkspaceID: &ws})
		if err != nil {
			return nil, err
		}
		out := &DatabaseSyncListOutput{}
		out.Body.Items = items
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-database-sync-plans", Method: http.MethodGet, Path: "/databases/{id}/syncs",
		Summary: "List the syncs reading from or writing into a database", Tags: tags,
	}, func(ctx context.Context, in *DatabaseSyncPath) (*DatabaseSyncListOutput, error) {
		id := uuid.MustParse(in.ID)
		items, err := h.list(ctx, sqlc.ListDatabaseSyncsParams{DatabaseID: &id})
		if err != nil {
			return nil, err
		}
		out := &DatabaseSyncListOutput{}
		out.Body.Items = items
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-database-sync-tables", Method: http.MethodGet, Path: "/databases/{id}/sync-tables",
		Summary: "List a database's databases and the tables of one, for a sync", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DatabaseSyncPath
		Name string `query:"name" maxLength:"128" doc:"The database to list the tables of"`
	}) (*struct{ Body DatabaseSyncTables }, error) {
		d, err := h.q.GetDatabase(ctx, uuid.MustParse(in.ID))
		if isNotFound(err) {
			return nil, huma.Error404NotFound("database not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct{ Body DatabaseSyncTables }{}
		out.Body = DatabaseSyncTables{Name: in.Name, Databases: []string{}, Tables: []dbsync.Table{}, Rows: rowEngine(d.Engine), RowsInto: rowTargets(d.Engine)}
		names, err := h.backups.databaseNames(ctx, d)
		if err != nil {
			return nil, huma.Error422UnprocessableEntity(problemText(err))
		}
		out.Body.Databases = names
		if in.Name == "" || !rowEngine(d.Engine) || !slices.Contains(names, in.Name) {
			return out, nil
		}
		side, done, err := h.open(ctx, d, in.Name)
		if err != nil {
			return nil, huma.Error422UnprocessableEntity(problemText(err))
		}
		defer done()
		tables, err := dbsync.Tables(ctx, side.DB, side.Dialect, in.Name)
		if err != nil {
			return nil, huma.Error422UnprocessableEntity(problemText(err))
		}
		out.Body.Tables = tables
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-database-sync", Method: http.MethodPost, Path: "/workspaces/{id}/database-syncs",
		Summary: "Create a database sync", Tags: tags, DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body DatabaseSyncBody
	}) (*DatabaseSyncOutput, error) {
		c, err := h.check(ctx, uuid.MustParse(in.ID), in.Body, nil)
		if err != nil {
			return nil, err
		}
		b := c.b
		s, err := h.q.CreateDatabaseSync(ctx, sqlc.CreateDatabaseSyncParams{
			WorkspaceID: c.src.WorkspaceID, Name: strings.TrimSpace(b.Name), Mode: b.Mode,
			SourceDbID: c.src.ID, SourceName: b.SourceName, TargetDbID: c.tgt.ID, TargetName: b.TargetName,
			Trigger: b.Trigger, Cron: b.Cron, Timezone: b.Timezone, IntervalMinutes: int32(b.IntervalMinutes),
			Options: c.options, NextRunAt: c.next, Paused: b.Paused != nil && *b.Paused, CreatedBy: principalOf(ctx).ID(),
		})
		if isUniqueViolation(err) {
			return nil, fieldError("body.name", "One with this name already exists.", b.Name)
		}
		if err != nil {
			return nil, internalError(err)
		}
		one, err := h.one(ctx, s)
		return &DatabaseSyncOutput{Body: one}, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-database-sync", Method: http.MethodGet, Path: "/database-syncs/{id}",
		Summary: "Get a database sync", Tags: tags,
	}, func(ctx context.Context, in *DatabaseSyncPath) (*DatabaseSyncOutput, error) {
		s, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		one, err := h.one(ctx, s)
		return &DatabaseSyncOutput{Body: one}, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-database-sync", Method: http.MethodPut, Path: "/database-syncs/{id}",
		Summary: "Save changes to a database sync", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DatabaseSyncPath
		Body DatabaseSyncBody
	}) (*DatabaseSyncOutput, error) {
		old, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if in.Body.Revision != nil && !in.Body.Revision.Equal(old.UpdatedAt) {
			return nil, huma.Error409Conflict("Someone else saved this after you opened it.")
		}
		c, err := h.check(ctx, old.WorkspaceID, in.Body, &old)
		if err != nil {
			return nil, err
		}
		b := c.b
		paused := old.Paused
		if b.Paused != nil {
			paused = *b.Paused
		}
		marks := old.Marks
		reset := old.Mode != b.Mode || old.SourceDbID != c.src.ID || old.SourceName != b.SourceName ||
			old.TargetDbID != c.tgt.ID || old.TargetName != b.TargetName
		if reset {
			marks = []byte("{}")
		}
		s, err := h.q.UpdateDatabaseSync(ctx, sqlc.UpdateDatabaseSyncParams{
			ID: old.ID, Name: strings.TrimSpace(b.Name), Mode: b.Mode,
			SourceDbID: c.src.ID, SourceName: b.SourceName, TargetDbID: c.tgt.ID, TargetName: b.TargetName,
			Trigger: b.Trigger, Cron: b.Cron, Timezone: b.Timezone, IntervalMinutes: int32(b.IntervalMinutes),
			Options: c.options, Marks: marks, NextRunAt: c.next, Paused: paused, UpdatedBy: principalOf(ctx).ID(),
		})
		if isUniqueViolation(err) {
			return nil, fieldError("body.name", "One with this name already exists.", b.Name)
		}
		if err != nil {
			return nil, internalError(err)
		}
		if reset {
			if err := h.q.SetDatabaseSyncMarks(ctx, sqlc.SetDatabaseSyncMarksParams{ID: s.ID, Marks: marks}); err != nil {
				return nil, internalError(err)
			}
			s.FullAt = nil
		}
		one, err := h.one(ctx, s)
		return &DatabaseSyncOutput{Body: one}, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "pause-database-sync", Method: http.MethodPost, Path: "/database-syncs/{id}/pause",
		Summary: "Pause or resume a database sync", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DatabaseSyncPath
		Body struct {
			Paused bool `json:"paused"`
		}
	}) (*DatabaseSyncOutput, error) {
		old, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		next := nextOf(old.Trigger, old.Cron, old.Timezone, int(old.IntervalMinutes), in.Body.Paused, time.Now())
		s, err := h.q.SetDatabaseSyncPaused(ctx, sqlc.SetDatabaseSyncPausedParams{ID: old.ID, Paused: in.Body.Paused, NextRunAt: next})
		if err != nil {
			return nil, internalError(err)
		}
		one, err := h.one(ctx, s)
		return &DatabaseSyncOutput{Body: one}, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-database-sync", Method: http.MethodDelete, Path: "/database-syncs/{id}",
		Summary: "Delete a database sync and its runs", Tags: tags, DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *DatabaseSyncPath) (*struct{}, error) {
		s, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if tgt, err := h.q.GetDatabase(ctx, s.TargetDbID); err == nil && databaseLevelOf(principalOf(ctx).Access, tgt) < auth.Owner {
			return nil, huma.Error403Forbidden(fmt.Sprintf("You need %s access to %s.", auth.Owner, tgt.Name))
		}
		active, err := h.q.ListActiveDatabaseSyncRuns(ctx, s.ID)
		if err != nil {
			return nil, internalError(err)
		}
		for _, r := range active {
			if r.JobID != nil {
				_, _ = h.runner.Cancel(ctx, *r.JobID)
			}
		}
		if _, err := h.q.DeleteDatabaseSync(ctx, s.ID); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "run-database-sync", Method: http.MethodPost, Path: "/database-syncs/{id}/run",
		Summary: "Run a database sync now, or compare only (dry_run)", Tags: tags, DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		DatabaseSyncPath
		Body struct {
			DryRun bool `json:"dry_run,omitempty" doc:"Compare and report what would change; write nothing"`
		}
	}) (*DatabaseSyncRunOutput, error) {
		s, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		run, job, err := h.start(ctx, s, principalOf(ctx), "manual", in.Body.DryRun)
		if err != nil {
			return nil, err
		}
		out := &DatabaseSyncRunOutput{}
		if run != nil {
			r := h.toRun(*run)
			out.Body.Run = &r
		}
		out.Body.Job = job
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-database-sync-runs", Method: http.MethodGet, Path: "/database-syncs/{id}/runs",
		Summary: "List a database sync's runs, newest first", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DatabaseSyncPath
		Limit int `query:"limit" minimum:"1" maximum:"200" default:"50"`
	}) (*DatabaseSyncRunListOutput, error) {
		id := uuid.MustParse(in.ID)
		list := func() ([]sqlc.DatabaseSyncRun, error) {
			return h.q.ListDatabaseSyncRuns(ctx, sqlc.ListDatabaseSyncRunsParams{SyncID: id, Lim: int32(in.Limit)})
		}
		rows, err := list()
		if err != nil {
			return nil, internalError(err)
		}
		changed := false
		for _, r := range rows {
			changed = h.syncRun(ctx, r) || changed
		}
		if changed {
			if rows, err = list(); err != nil {
				return nil, internalError(err)
			}
		}
		out := &DatabaseSyncRunListOutput{}
		out.Body.Items = make([]DatabaseSyncRun, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = h.toRun(r)
			h.live(ctx, &out.Body.Items[i])
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-database-sync-run", Method: http.MethodGet, Path: "/database-sync-runs/{id}",
		Summary: "Get one database sync run", Tags: tags,
	}, func(ctx context.Context, in *DatabaseSyncPath) (*DatabaseSyncRunOneOutput, error) {
		id := uuid.MustParse(in.ID)
		r, err := h.q.GetDatabaseSyncRun(ctx, id)
		if isNotFound(err) {
			return nil, huma.Error404NotFound("run not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if h.syncRun(ctx, r) {
			if r, err = h.q.GetDatabaseSyncRun(ctx, id); err != nil {
				return nil, internalError(err)
			}
		}
		out := &DatabaseSyncRunOneOutput{Body: h.toRun(r)}
		h.live(ctx, &out.Body)
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "cancel-database-sync-run", Method: http.MethodPost, Path: "/database-sync-runs/{id}/cancel",
		Summary: "Stop a database sync run", Tags: tags,
	}, func(ctx context.Context, in *DatabaseSyncPath) (*DatabaseSyncRunOneOutput, error) {
		id := uuid.MustParse(in.ID)
		r, err := h.q.GetDatabaseSyncRun(ctx, id)
		if isNotFound(err) {
			return nil, huma.Error404NotFound("run not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if !jobs.Active(r.State) {
			return nil, huma.Error409Conflict("It already ended.")
		}
		if r.JobID != nil {
			if _, err := h.runner.Cancel(ctx, *r.JobID); err != nil && !errors.Is(err, jobs.ErrNotFound) {
				return nil, jobProblem(err)
			}
		} else if err := h.q.EndDatabaseSyncRun(ctx, sqlc.EndDatabaseSyncRunParams{ID: r.ID, State: jobs.Canceled}); err != nil {
			return nil, internalError(err)
		}
		if r, err = h.q.GetDatabaseSyncRun(ctx, id); err != nil {
			return nil, internalError(err)
		}
		h.syncRun(ctx, r)
		if r, err = h.q.GetDatabaseSyncRun(ctx, id); err != nil {
			return nil, internalError(err)
		}
		out := &DatabaseSyncRunOneOutput{Body: h.toRun(r)}
		h.live(ctx, &out.Body)
		return out, nil
	})
}
