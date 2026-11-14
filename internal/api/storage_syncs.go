package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/storage"
)

// Storage syncs move or keep files in step between two storages of a
// workspace. A migration copies everything once (optionally checking every
// copy and then emptying the source); a sync keeps a destination folder up to
// date, by hand, on a cron schedule or every N minutes. A sync between two
// MinIO storages can instead be done by MinIO itself (engine "replication"):
// Morche only sets it up and reads its numbers.

const (
	storageMigrateKind  = "storage-migrate"
	storageSyncKind     = "storage-sync"
	storageSyncRunsKept = 200
	// Held deletions kept in a sync's record at most.
	maxHeld = 5000
)

// ---- Types ----

type StorageSyncReplication struct {
	Sync           bool   `json:"sync,omitempty" doc:"Write to the destination before the source answers (slower writes, never behind)"`
	BandwidthMbps  int    `json:"bandwidth_mbps,omitempty" minimum:"0" maximum:"100000" doc:"Megabits per second, 0 = no limit"`
	Deletes        bool   `json:"deletes,omitempty" doc:"Delete on the destination what's deleted on the source"`
	Existing       bool   `json:"existing,omitempty" doc:"Copy what the bucket already holds, not only new writes"`
	TargetEndpoint string `json:"target_endpoint,omitempty" maxLength:"500" doc:"Where the source MinIO reaches the destination, when not at the address Morche uses"`
}

type StorageSyncOptions struct {
	Excludes []string `json:"excludes,omitempty" maxItems:"100" doc:"Patterns left out"`
	Existing string   `json:"existing,omitempty" enum:"changed,all,missing" doc:"Files the destination already has: copy again when changed (default), always, or never"`
	// Migration only.
	Verify       bool `json:"verify,omitempty" doc:"Migration: check every copy is there with the same size"`
	DeleteSource bool `json:"delete_source,omitempty" doc:"Migration: delete each file from the source once its copy checks out"`
	// Sync only.
	SettleMinutes    int                     `json:"settle_minutes,omitempty" minimum:"0" maximum:"1440" doc:"Sync: leave files changed in the last N minutes for the next run"`
	DeleteDelayHours int                     `json:"delete_delay_hours,omitempty" minimum:"0" maximum:"8760" doc:"Sync (mirror): delete from the destination only N hours after a file left the source"`
	Replication      *StorageSyncReplication `json:"replication,omitempty" doc:"Engine replication: how MinIO copies"`
}

type StorageSyncEnd struct {
	StorageID string `json:"storage_id" format:"uuid"`
	Name      string `json:"name"`
	Protocol  string `json:"protocol"`
	Provider  string `json:"provider"`
	Path      string `json:"path"`
	ReadOnly  bool   `json:"read_only"`
	Missing   bool   `json:"missing" doc:"The storage was deleted"`
}

type StorageSyncHeld struct {
	Path  string    `json:"path"`
	Since time.Time `json:"since" doc:"When it was first missing from the source"`
	Due   time.Time `json:"due" doc:"When it'll be deleted from the destination"`
}

type StorageSyncRunBrief struct {
	ID         string     `json:"id" format:"uuid"`
	State      string     `json:"state"`
	DryRun     bool       `json:"dry_run"`
	At         time.Time  `json:"at"`
	FinishedAt *time.Time `json:"finished_at"`
	Error      string     `json:"error"`
}

type StorageSyncNative struct {
	Bucket       string `json:"bucket"`
	Prefix       string `json:"prefix"`
	TargetBucket string `json:"target_bucket"`
	Endpoint     string `json:"endpoint"`
}

type StorageSync struct {
	ID              string               `json:"id" format:"uuid"`
	WorkspaceID     string               `json:"workspace_id" format:"uuid"`
	Kind            string               `json:"kind" enum:"migrate,sync"`
	Name            string               `json:"name"`
	Source          StorageSyncEnd       `json:"source"`
	Dest            StorageSyncEnd       `json:"dest"`
	Engine          string               `json:"engine" enum:"morche,replication"`
	Mode            string               `json:"mode" enum:"update,mirror"`
	Trigger         string               `json:"trigger" enum:"manual,schedule,interval"`
	Cron            string               `json:"cron"`
	Timezone        string               `json:"timezone"`
	IntervalMinutes int                  `json:"interval_minutes"`
	Options         StorageSyncOptions   `json:"options"`
	Paused          bool                 `json:"paused"`
	NextRunAt       *time.Time           `json:"next_run_at"`
	Held            []StorageSyncHeld    `json:"held" doc:"Deletions waiting for their delay, oldest first (first 100)"`
	HeldCount       int                  `json:"held_count"`
	Native          *StorageSyncNative   `json:"native" doc:"What replication set up on MinIO"`
	Problem         string               `json:"problem" doc:"Why replication isn't set up as saved"`
	RunsAs          string               `json:"runs_as" doc:"Whose access runs use: the person who saved it last"`
	LastRun         *StorageSyncRunBrief `json:"last_run"`
	CreatedAt       time.Time            `json:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at"`
}

type StorageSyncBody struct {
	Kind            string             `json:"kind" enum:"migrate,sync" doc:"Ignored when saving changes"`
	Name            string             `json:"name" minLength:"1" maxLength:"100"`
	SourceStorageID string             `json:"source_storage_id" format:"uuid"`
	SourcePath      string             `json:"source_path" minLength:"1" maxLength:"1024"`
	DestStorageID   string             `json:"dest_storage_id" format:"uuid"`
	DestPath        string             `json:"dest_path" minLength:"1" maxLength:"1024"`
	Engine          string             `json:"engine,omitempty" enum:"morche,replication"`
	Mode            string             `json:"mode,omitempty" enum:"update,mirror"`
	Trigger         string             `json:"trigger,omitempty" enum:"manual,schedule,interval"`
	Cron            string             `json:"cron,omitempty" maxLength:"200"`
	Timezone        string             `json:"timezone,omitempty" maxLength:"64"`
	IntervalMinutes int                `json:"interval_minutes,omitempty" minimum:"0" maximum:"10080"`
	Options         StorageSyncOptions `json:"options,omitempty"`
	Paused          *bool              `json:"paused,omitempty"`
}

type StorageSyncUpdate struct {
	StorageSyncBody
	Revision *time.Time `json:"revision,omitempty" doc:"updated_at as you loaded it; 409 when it changed since"`
}

type StorageSyncOutput struct{ Body StorageSync }

type StorageSyncVerify struct {
	Checked   int      `json:"checked" doc:"Files compared"`
	Missing   int      `json:"missing" doc:"Not on the destination"`
	Different int      `json:"different" doc:"On the destination with another size"`
	Problems  []string `json:"problems,omitempty"`
}

type StorageSyncResult struct {
	storage.SyncResult
	Verify       *StorageSyncVerify `json:"verify,omitempty"`
	Removed      int                `json:"removed,omitempty" doc:"Migration: files deleted from the source"`
	RemoveFailed int                `json:"remove_failed,omitempty" doc:"Migration: files that couldn't be deleted from the source"`
	KeptSource   string             `json:"kept_source,omitempty" doc:"Migration: why the source wasn't emptied"`
}

type StorageSyncRun struct {
	ID            string             `json:"id" format:"uuid"`
	SyncID        string             `json:"sync_id" format:"uuid"`
	Trigger       string             `json:"trigger" enum:"manual,schedule,interval"`
	DryRun        bool               `json:"dry_run"`
	State         string             `json:"state" enum:"queued,running,succeeded,partial,failed,canceled,interrupted,skipped"`
	Phase         string             `json:"phase"`
	Error         string             `json:"error"`
	Result        *StorageSyncResult `json:"result"`
	Files         int                `json:"files"`
	Bytes         int64              `json:"bytes"`
	JobID         *string            `json:"job_id" format:"uuid"`
	Progress      *jobs.Progress     `json:"progress" doc:"While it runs"`
	CreatedByName string             `json:"created_by_name"`
	CreatedAt     time.Time          `json:"created_at"`
	StartedAt     *time.Time         `json:"started_at"`
	FinishedAt    *time.Time         `json:"finished_at"`
}

// ---- Handler ----

type storageSyncHandler struct {
	q      *sqlc.Queries
	st     *storageHandler
	authz  *authz
	runner *jobs.Runner
}

func newStorageSyncHandler(st *storageHandler, a *authz) *storageSyncHandler {
	return &storageSyncHandler{q: st.q, st: st, authz: a, runner: st.servers.jobs}
}

func decodeSyncOptions(raw []byte) StorageSyncOptions {
	var o StorageSyncOptions
	decodeInto(raw, &o)
	if o.Existing == "" {
		o.Existing = "changed"
	}
	if o.Excludes == nil {
		o.Excludes = []string{}
	}
	return o
}

func existingOf(o StorageSyncOptions) string {
	switch o.Existing {
	case "all":
		return storage.ExistingAll
	case "missing":
		return storage.ExistingKeep
	}
	return storage.ExistingChanged
}

func decodeHeld(raw []byte) map[string]time.Time {
	held := map[string]time.Time{}
	decodeInto(raw, &held)
	return held
}

func decodeNative(raw []byte) *storage.ReplicationSetup {
	var s storage.ReplicationSetup
	if decodeInto(raw, &s); s.Arn == "" {
		return nil
	}
	return &s
}

// syncNames looks up storages and people once for a list.
type syncNames struct {
	storages map[uuid.UUID]sqlc.Storage
	users    map[uuid.UUID]string
}

func (h *storageSyncHandler) names(ctx context.Context, storages, users []uuid.UUID) (syncNames, error) {
	n := syncNames{storages: map[uuid.UUID]sqlc.Storage{}, users: map[uuid.UUID]string{}}
	for _, id := range storages {
		if _, ok := n.storages[id]; ok {
			continue
		}
		s, err := h.q.GetStorage(ctx, id)
		if isNotFound(err) {
			continue
		}
		if err != nil {
			return n, err
		}
		n.storages[id] = s
	}
	for _, id := range users {
		if _, ok := n.users[id]; ok {
			continue
		}
		u, err := h.q.GetUser(ctx, id)
		if isNotFound(err) {
			n.users[id] = ""
			continue
		}
		if err != nil {
			return n, err
		}
		n.users[id] = cmpOr(u.FullName, u.Username)
	}
	return n, nil
}

func (n syncNames) end(id uuid.UUID, p string) StorageSyncEnd {
	e := StorageSyncEnd{StorageID: id.String(), Path: p}
	s, ok := n.storages[id]
	if !ok {
		e.Missing, e.Name = true, "Deleted storage"
		return e
	}
	e.Name, e.Protocol, e.Provider, e.ReadOnly = s.Name, s.Protocol, s.Provider, s.ReadOnly
	return e
}

func (h *storageSyncHandler) toSync(s sqlc.StorageSync, n syncNames, last *StorageSyncRunBrief) StorageSync {
	o := decodeSyncOptions(s.Options)
	out := StorageSync{
		ID: s.ID.String(), WorkspaceID: s.WorkspaceID.String(), Kind: s.Kind, Name: s.Name,
		Source: n.end(s.SourceStorageID, s.SourcePath), Dest: n.end(s.DestStorageID, s.DestPath),
		Engine: s.Engine, Mode: s.Mode, Trigger: s.Trigger, Cron: s.Cron, Timezone: s.Timezone,
		IntervalMinutes: int(s.IntervalMinutes), Options: o, Paused: s.Paused, NextRunAt: s.NextRunAt,
		Held: []StorageSyncHeld{}, Problem: s.Problem, LastRun: last, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
	if s.UpdatedBy != nil {
		out.RunsAs = n.users[*s.UpdatedBy]
	}
	if nat := decodeNative(s.Native); nat != nil {
		out.Native = &StorageSyncNative{Bucket: nat.Bucket, Prefix: nat.Prefix, TargetBucket: nat.TargetBucket, Endpoint: nat.Endpoint}
	}
	held := decodeHeld(s.Held)
	out.HeldCount = len(held)
	delay := time.Duration(o.DeleteDelayHours) * time.Hour
	for p, since := range held {
		out.Held = append(out.Held, StorageSyncHeld{Path: path.Join(s.DestPath, p), Since: since, Due: since.Add(delay)})
	}
	sort.Slice(out.Held, func(i, j int) bool {
		if !out.Held[i].Since.Equal(out.Held[j].Since) {
			return out.Held[i].Since.Before(out.Held[j].Since)
		}
		return out.Held[i].Path < out.Held[j].Path
	})
	if len(out.Held) > 100 {
		out.Held = out.Held[:100]
	}
	return out
}

func syncPeople(s sqlc.StorageSync) []uuid.UUID {
	if s.UpdatedBy != nil {
		return []uuid.UUID{*s.UpdatedBy}
	}
	return nil
}

func (h *storageSyncHandler) one(ctx context.Context, s sqlc.StorageSync) (StorageSync, error) {
	n, err := h.names(ctx, []uuid.UUID{s.SourceStorageID, s.DestStorageID}, syncPeople(s))
	if err != nil {
		return StorageSync{}, internalError(err)
	}
	rows, err := h.q.ListStorageSyncRuns(ctx, sqlc.ListStorageSyncRunsParams{SyncID: s.ID, Lim: 5})
	if err != nil {
		return StorageSync{}, internalError(err)
	}
	var last *StorageSyncRunBrief
	for _, r := range rows {
		if r.State == "skipped" {
			continue
		}
		if h.syncRun(ctx, r) {
			if r, err = h.q.GetStorageSyncRun(ctx, r.ID); err != nil {
				return StorageSync{}, internalError(err)
			}
		}
		last = &StorageSyncRunBrief{ID: r.ID.String(), State: r.State, DryRun: r.DryRun, At: r.CreatedAt, FinishedAt: r.FinishedAt, Error: r.Error}
		break
	}
	return h.toSync(s, n, last), nil
}

func (h *storageSyncHandler) load(ctx context.Context, rawID string) (sqlc.StorageSync, error) {
	s, err := h.q.GetStorageSync(ctx, uuid.MustParse(rawID))
	if isNotFound(err) {
		return s, huma.Error404NotFound("sync not found")
	}
	if err != nil {
		return s, internalError(err)
	}
	return s, nil
}

// ---- Checking what's saved ----

type checkedSync struct {
	kind, name, engine, mode, trigger, cron, tz string
	interval                                    int
	src, dst                                    sqlc.Storage
	srcPath, dstPath                            string
	options                                     StorageSyncOptions
	optionsJSON                                 []byte
}

func isMinIO(s sqlc.Storage) bool { return s.Protocol == "s3" && s.Provider == "minio" }

// check validates a sync for the person saving it.
func (h *storageSyncHandler) check(ctx context.Context, ws uuid.UUID, kind string, b StorageSyncBody) (checkedSync, error) {
	c := checkedSync{
		kind: kind, name: strings.TrimSpace(b.Name), engine: cmpOr(b.Engine, "morche"),
		mode: cmpOr(b.Mode, storage.SyncUpdate), trigger: cmpOr(b.Trigger, "manual"), options: b.Options,
	}
	if c.name == "" {
		return c, fieldError("body.name", "Give it a name.", b.Name)
	}
	acc := principalOf(ctx).Access
	storageOf := func(raw, loc string) (sqlc.Storage, error) {
		s, err := h.q.GetStorage(ctx, uuid.MustParse(raw))
		if isNotFound(err) || (err == nil && s.WorkspaceID != ws) {
			return s, fieldError(loc, "This storage isn't in this workspace.", raw)
		}
		if err != nil {
			return s, internalError(err)
		}
		if acc.StorageLevel(ws, s.ID) == auth.None {
			return s, fieldError(loc, "Not found.", raw)
		}
		return s, nil
	}
	pathOf := func(raw, loc string) (string, error) {
		p := strings.TrimSpace(raw)
		if !strings.HasPrefix(p, "/") || strings.ContainsRune(p, 0) {
			return "", fieldError(loc, "Use a full path, starting with /.", raw)
		}
		return storage.Clean(p), nil
	}
	var err error
	if c.src, err = storageOf(b.SourceStorageID, "body.source_storage_id"); err != nil {
		return c, err
	}
	if c.dst, err = storageOf(b.DestStorageID, "body.dest_storage_id"); err != nil {
		return c, err
	}
	if c.srcPath, err = pathOf(b.SourcePath, "body.source_path"); err != nil {
		return c, err
	}
	if c.dstPath, err = pathOf(b.DestPath, "body.dest_path"); err != nil {
		return c, err
	}
	if c.dst.ReadOnly {
		return c, fieldError("body.dest_storage_id", c.dst.Name+" is read-only in Morche, so nothing can be written to it.", b.DestStorageID)
	}
	if c.src.ID == c.dst.ID && (storage.Within(c.srcPath, c.dstPath) || storage.Within(c.dstPath, c.srcPath)) {
		return c, fieldError("body.dest_path", "On the same storage the two folders can't be inside one another.", b.DestPath)
	}
	excludes, err := cleanExcludes(c.options.Excludes)
	if err != nil {
		return c, err
	}
	c.options.Excludes = excludes
	if c.options.Existing == "" {
		c.options.Existing = "changed"
	}

	needSrc := auth.Operator
	switch kind {
	case "migrate":
		if c.engine != "morche" {
			return c, fieldError("body.engine", "A migration is always copied by Morche.", b.Engine)
		}
		c.mode, c.trigger, c.cron, c.tz, c.interval = storage.SyncUpdate, "manual", "", "", 0
		c.options.SettleMinutes, c.options.DeleteDelayHours, c.options.Replication = 0, 0, nil
		if c.options.DeleteSource {
			if c.src.ReadOnly {
				return c, fieldError("body.options.delete_source", c.src.Name+" is read-only in Morche, so nothing can be deleted from it.", true)
			}
			c.options.Verify = true
			needSrc = auth.Engineer
		}
	case "sync":
		c.options.Verify, c.options.DeleteSource = false, false
		if c.engine == "replication" {
			if !isMinIO(c.src) || !isMinIO(c.dst) {
				return c, fieldError("body.engine", "MinIO replication needs a MinIO storage at both ends.", b.Engine)
			}
			if acc.StorageLevel(ws, c.src.ID) < auth.Owner || acc.StorageLevel(ws, c.dst.ID) < auth.Owner {
				return c, forbidden(auth.Owner)
			}
			srcCfg, _ := h.st.config(c.src)
			dstCfg, _ := h.st.config(c.dst)
			_, sp, err := storage.S3Place(srcCfg, c.srcPath)
			if err != nil {
				return c, fieldError("body.source_path", upperFirst(err.Error())+".", b.SourcePath)
			}
			_, dp, err := storage.S3Place(dstCfg, c.dstPath)
			if err != nil {
				return c, fieldError("body.dest_path", upperFirst(err.Error())+".", b.DestPath)
			}
			if sp != dp {
				return c, fieldError("body.dest_path", fmt.Sprintf("MinIO keeps object names as they are, so the destination folder must be %q inside its bucket.", "/"+strings.TrimSuffix(sp, "/")), b.DestPath)
			}
			if c.options.Replication == nil {
				c.options.Replication = &StorageSyncReplication{}
			}
			c.options.Replication.TargetEndpoint = strings.TrimSpace(c.options.Replication.TargetEndpoint)
			c.mode, c.trigger, c.cron, c.tz, c.interval = storage.SyncUpdate, "manual", "", "", 0
			c.options.Excludes, c.options.SettleMinutes, c.options.DeleteDelayHours, c.options.Existing = []string{}, 0, 0, "changed"
		} else {
			c.options.Replication = nil
			if c.mode != storage.SyncUpdate && c.mode != storage.SyncMirror {
				return c, fieldError("body.mode", "Pick update or mirror.", b.Mode)
			}
			if c.mode == storage.SyncMirror && c.dstPath == "/" {
				return c, fieldError("body.dest_path", "A mirror deletes what the source doesn't have, so pick a folder, not the whole storage.", b.DestPath)
			}
			if c.mode != storage.SyncMirror {
				c.options.DeleteDelayHours = 0
			}
			switch c.trigger {
			case "schedule":
				if _, _, err := parseCron(b.Cron, b.Timezone); err != nil {
					return c, err
				}
				c.cron, c.tz = strings.TrimSpace(b.Cron), cmpOr(strings.TrimSpace(b.Timezone), "UTC")
			case "interval":
				if b.IntervalMinutes < 5 {
					return c, fieldError("body.interval_minutes", "Every 5 minutes at the most often.", b.IntervalMinutes)
				}
				c.interval = b.IntervalMinutes
			}
		}
	}
	if acc.StorageLevel(ws, c.src.ID) < needSrc {
		return c, forbidden(needSrc)
	}
	if acc.StorageLevel(ws, c.dst.ID) < auth.Engineer {
		return c, forbidden(auth.Engineer)
	}
	if c.tz == "" && c.trigger != "schedule" {
		c.tz = cmpOr(strings.TrimSpace(b.Timezone), "UTC")
		if _, err := time.LoadLocation(c.tz); err != nil {
			c.tz = "UTC"
		}
	}
	c.optionsJSON, _ = json.Marshal(c.options)
	return c, nil
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// nextOf is when a sync runs on its own next; nil = only by hand.
func nextOf(trigger, cronExpr, tz string, interval int, paused bool, after time.Time) *time.Time {
	if paused {
		return nil
	}
	switch trigger {
	case "schedule":
		return nextRun(cronExpr, tz, after)
	case "interval":
		if interval > 0 {
			t := after.Add(time.Duration(interval) * time.Minute)
			return &t
		}
	}
	return nil
}

// ---- Replication ----

func (h *storageSyncHandler) replicationPlan(id uuid.UUID, c checkedSync, paused bool) storage.ReplicationPlan {
	r := c.options.Replication
	if r == nil {
		r = &StorageSyncReplication{}
	}
	return storage.ReplicationPlan{
		RuleID: "morche-" + id.String(), SourcePath: c.srcPath, DestPath: c.dstPath, Enabled: !paused,
		Deletes: r.Deletes, Existing: r.Existing, Synchronous: r.Sync,
		Bandwidth: int64(r.BandwidthMbps) * 125_000, TargetEndpoint: r.TargetEndpoint,
	}
}

// setUp (re)creates the MinIO replication for a checked sync. prev is what
// was set up on prevSource before, removed first.
func (h *storageSyncHandler) setUp(ctx context.Context, id uuid.UUID, c checkedSync, paused bool, prev *storage.ReplicationSetup, prevSource *sqlc.Storage) ([]byte, error) {
	srcCfg, err := h.st.config(c.src)
	if err != nil {
		return nil, internalError(err)
	}
	dstCfg, err := h.st.config(c.dst)
	if err != nil {
		return nil, internalError(err)
	}
	if prev != nil && prevSource != nil && prevSource.ID != c.src.ID {
		h.tearDown(ctx, *prevSource, *prev)
		prev = nil
	}
	setup, err := storage.SetUpReplication(ctx, srcCfg, dstCfg, h.replicationPlan(id, c, paused), prev)
	if err != nil {
		return nil, huma.Error422UnprocessableEntity(upperFirst(problemText(err)))
	}
	raw, _ := json.Marshal(setup)
	return raw, nil
}

// tearDown removes a replication, as far as it can.
func (h *storageSyncHandler) tearDown(ctx context.Context, src sqlc.Storage, s storage.ReplicationSetup) {
	cfg, err := h.st.config(src)
	if err == nil {
		err = storage.RemoveReplication(ctx, cfg, s)
	}
	if err != nil {
		slog.Warn("remove a MinIO replication", "storage", src.ID, "error", err)
	}
}

// ---- Runs ----

func (h *storageSyncHandler) toRun(r sqlc.StorageSyncRun) StorageSyncRun {
	out := StorageSyncRun{
		ID: r.ID.String(), SyncID: r.SyncID.String(), Trigger: r.Trigger, DryRun: r.DryRun, State: r.State,
		Phase: r.Phase, Error: r.Error, Files: int(r.Files), Bytes: r.Bytes, JobID: optionalIDString(r.JobID),
		CreatedByName: r.CreatedByName, CreatedAt: r.CreatedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
	}
	if len(r.Result) > 0 && string(r.Result) != "null" && string(r.Result) != "{}" {
		var res StorageSyncResult
		decodeInto(r.Result, &res)
		out.Result = &res
	}
	return out
}

func (h *storageSyncHandler) live(ctx context.Context, r *StorageSyncRun) {
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

// syncRun ends a stored run whose job ended without it.
func (h *storageSyncHandler) syncRun(ctx context.Context, r sqlc.StorageSyncRun) bool {
	if !jobs.Active(r.State) {
		return false
	}
	end := func(state, msg string) bool {
		if err := h.q.EndStorageSyncRun(ctx, sqlc.EndStorageSyncRunParams{ID: r.ID, State: state, Error: msg}); err != nil {
			slog.Warn("end a storage sync run", "run", r.ID, "error", err)
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

func (h *storageSyncHandler) busy(ctx context.Context, id uuid.UUID) (bool, error) {
	rows, err := h.q.ListActiveStorageSyncRuns(ctx, id)
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

type storageSyncRunParams struct {
	RunID uuid.UUID `json:"run_id"`
}

// start queues a run. by is nil for a run on time. A scheduled run while the
// last one is still going is recorded as skipped; one by interval just waits
// for the next turn.
func (h *storageSyncHandler) start(ctx context.Context, s sqlc.StorageSync, by *principal, trigger string, dryRun bool) (*sqlc.StorageSyncRun, *Job, error) {
	if s.Engine != "morche" {
		return nil, nil, huma.Error422UnprocessableEntity("MinIO copies this one by itself. Use Copy existing files to have it go over what's there.")
	}
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
	params := sqlc.CreateStorageSyncRunParams{
		SyncID: s.ID, WorkspaceID: s.WorkspaceID, Trigger: trigger, DryRun: dryRun,
		State: jobs.Queued, CreatedBy: byID, CreatedByName: byName,
	}
	if busy {
		now := time.Now()
		params.State, params.Error, params.FinishedAt = "skipped", "The run before was still going.", &now
	}
	run, err := h.q.CreateStorageSyncRun(ctx, params)
	if err != nil {
		return nil, nil, internalError(err)
	}
	if err := h.q.PruneStorageSyncRuns(ctx, sqlc.PruneStorageSyncRunsParams{SyncID: s.ID, Keep: storageSyncRunsKept}); err != nil {
		slog.Warn("prune storage sync runs", "sync", s.ID, "error", err)
	}
	if busy {
		return &run, nil, nil
	}
	kind, verb := storageSyncKind, "Sync "
	if s.Kind == "migrate" {
		kind, verb = storageMigrateKind, "Migrate "
	}
	if dryRun {
		verb = "Test "
	}
	j, err := h.runner.Submit(ctx, jobs.Spec{
		Kind: kind, Title: verb + s.Name, Params: storageSyncRunParams{RunID: run.ID},
		Refs:      []uuid.UUID{s.SourceStorageID, s.DestStorageID},
		Target:    JobPlace{SyncID: s.ID.String(), RunID: run.ID.String(), StorageID: s.DestStorageID.String(), Path: s.DestPath, Name: s.Name},
		CreatedBy: byID,
	})
	if err != nil {
		_ = h.q.EndStorageSyncRun(context.WithoutCancel(ctx), sqlc.EndStorageSyncRunParams{ID: run.ID, State: jobs.Failed, Error: "It couldn't be queued."})
		return &run, nil, internalError(err)
	}
	if err := h.q.SetStorageSyncRunJob(ctx, sqlc.SetStorageSyncRunJobParams{ID: run.ID, JobID: &j.ID}); err != nil {
		return &run, nil, internalError(err)
	}
	run.JobID = &j.ID
	job := toJob(j, false)
	return &run, &job, nil
}

// runAs is the person a sync acts as, with their access now.
func (h *storageSyncHandler) runAs(ctx context.Context, s sqlc.StorageSync) (string, *auth.Access, error) {
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

func (h *storageSyncHandler) runJob(ctx context.Context, t *jobs.Task) (any, error) {
	var params storageSyncRunParams
	if err := t.Decode(&params); err != nil {
		return nil, err
	}
	bg := context.WithoutCancel(ctx)
	run, err := h.q.GetStorageSyncRun(ctx, params.RunID)
	if isNotFound(err) {
		return nil, errors.New("It was deleted before this run started.")
	}
	if err != nil {
		return nil, err
	}
	if !jobs.Active(run.State) {
		return nil, nil
	}
	var res StorageSyncResult
	fail := func(err error) (any, error) {
		raw, _ := json.Marshal(res)
		_ = h.q.FinishStorageSyncRun(bg, sqlc.FinishStorageSyncRunParams{ID: run.ID, State: jobs.Failed, Error: problemText(err), Result: raw, Files: int32(res.Copied), Bytes: res.Bytes})
		return nil, errors.New(problemText(err))
	}
	s, err := h.q.GetStorageSync(ctx, run.SyncID)
	if err != nil {
		return fail(errors.New("It was deleted before this run started."))
	}
	if err := h.q.StartStorageSyncRun(ctx, run.ID); err != nil {
		return nil, err
	}
	o := decodeSyncOptions(s.Options)
	migrate := s.Kind == "migrate"
	removeSource := migrate && o.DeleteSource && !run.DryRun

	who, acc, err := h.runAs(ctx, s)
	if err != nil {
		return fail(err)
	}
	needSrc := auth.Operator
	if removeSource {
		needSrc = auth.Engineer
	}
	for _, e := range []struct {
		id   uuid.UUID
		need auth.Level
		what string
	}{{s.SourceStorageID, needSrc, "the source"}, {s.DestStorageID, auth.Engineer, "the destination"}} {
		if acc.StorageLevel(s.WorkspaceID, e.id) < e.need {
			return fail(fmt.Errorf("%s no longer has %s access to %s.", who, e.need, e.what))
		}
	}

	save := func(phase string) {
		raw, _ := json.Marshal(res)
		if err := h.q.SaveStorageSyncRun(bg, sqlc.SaveStorageSyncRunParams{ID: run.ID, Phase: phase, Result: raw, Files: int32(res.Copied), Bytes: res.Bytes}); err != nil {
			slog.Warn("save a storage sync run", "run", run.ID, "error", err)
		}
	}
	verb := "Copying"
	if run.DryRun {
		verb = "Counting"
	}
	save("Comparing")
	t.Update(func(p *jobs.Progress) { p.Phase = "Comparing the two sides" })

	held := decodeHeld(s.Held)
	var deleted []string
	srcID, dstID := s.SourceStorageID.String(), s.DestStorageID.String()
	runErr := h.st.with(ctx, StorageTransferEnd{StorageID: &srcID}, func(src place) error {
		return h.st.with(ctx, StorageTransferEnd{StorageID: &dstID}, func(dst place) error {
			if dst.readOnly {
				return errors.New(dst.name + " is read-only in Morche.")
			}
			t.Logf("%s %s:%s to %s:%s", verb, src.name, s.SourcePath, dst.name, s.DestPath)
			var prog storage.Progress
			prog.OnBytes = t.Add
			prog.OnFile = func(f string) {
				done := prog.Files
				t.Update(func(p *jobs.Progress) {
					p.Current = strings.TrimPrefix(strings.TrimPrefix(f, s.SourcePath), "/")
					p.Items = done
				})
			}
			so := storage.SyncOptions{
				Mode: s.Mode, Excludes: o.Excludes, Now: time.Now().In(scheduleLoc(s.Timezone)), DryRun: run.DryRun,
				Existing: existingOf(o), SameFS: s.SourceStorageID == s.DestStorageID,
				Plan: func(n int, size int64) {
					save(verb)
					t.Update(func(p *jobs.Progress) {
						p.Phase, p.Done, p.Total, p.Items, p.ItemsTotal = verb, 0, size, 0, n
					})
				},
			}
			if migrate {
				so.Mode = storage.SyncUpdate
			} else {
				if o.SettleMinutes > 0 {
					so.SettleBefore = time.Now().Add(-time.Duration(o.SettleMinutes) * time.Minute)
				}
				if s.Mode == storage.SyncMirror && o.DeleteDelayHours > 0 {
					delay := time.Duration(o.DeleteDelayHours) * time.Hour
					so.Removals = func(cands []string) []string {
						now := time.Now()
						seen := map[string]bool{}
						var out []string
						for _, c := range cands {
							seen[c] = true
							first, ok := held[c]
							if !ok {
								first = now
								if len(held) < maxHeld {
									held[c] = now
								}
							}
							if now.Sub(first) >= delay {
								out = append(out, c)
							}
						}
						// Back on the source: no longer waiting.
						for k := range held {
							if !seen[k] {
								delete(held, k)
							}
						}
						deleted = out
						return out
					}
				}
			}
			r, err := storage.Sync(ctx, src.fs, s.SourcePath, dst.fs, s.DestPath, so, &prog)
			res.SyncResult = r
			if err != nil {
				return err
			}
			t.Logf("%d copied (%s), %d up to date, %d deleted, %d couldn't be copied", r.Copied, humanBytes(r.Bytes), r.Skipped, r.Deleted, r.Failed)
			if r.Waiting > 0 {
				t.Logf("%d changed too recently, left for the next run", r.Waiting)
			}
			if r.Held > 0 {
				t.Logf("%d deletion(s) held back for %d hours", r.Held, o.DeleteDelayHours)
			}
			if !migrate || run.DryRun || !(o.Verify || o.DeleteSource) {
				return nil
			}
			save("Checking")
			ok, err := h.verify(ctx, t, src, dst, s, o, &res)
			if err != nil {
				return err
			}
			switch {
			case !removeSource:
			case r.Failed > 0:
				res.KeptSource = "Some files couldn't be copied, so the source was left as it is."
			case len(ok) == 0 && res.Verify.Checked > 0:
				res.KeptSource = "No copy checked out, so the source was left as it is."
			case res.Verify.Missing > 0 || res.Verify.Different > 0:
				res.KeptSource = "Some copies don't match, so the source was left as it is."
			default:
				save("Removing")
				return h.emptySource(ctx, t, src, s, ok, &res)
			}
			if res.KeptSource != "" {
				t.Logf("%s", res.KeptSource)
			}
			return nil
		})
	})

	if !migrate && !run.DryRun && runErr == nil && heldChanged(s, held, deleted) {
		for _, d := range deleted {
			delete(held, d)
		}
		raw, _ := json.Marshal(held)
		if err := h.q.SetStorageSyncHeld(bg, sqlc.SetStorageSyncHeldParams{ID: s.ID, Held: raw}); err != nil {
			slog.Warn("save held deletions", "sync", s.ID, "error", err)
		}
	}

	state, msg := jobs.Succeeded, ""
	switch {
	case runErr != nil && ctx.Err() != nil && t.Canceled():
		state = jobs.Canceled
	case runErr != nil && ctx.Err() != nil:
		state, msg = jobs.Interrupted, "Morche stopped before it finished."
	case runErr != nil:
		state, msg = jobs.Failed, problemText(runErr)
	case res.Failed > 0:
		state, msg = "partial", plural(res.Failed, "file")+" couldn't be copied."
	case res.Verify != nil && (res.Verify.Missing > 0 || res.Verify.Different > 0):
		state, msg = "partial", countOf(res.Verify.Missing+res.Verify.Different, "copy", "copies")+" didn't check out."
	case res.RemoveFailed > 0:
		state, msg = "partial", plural(res.RemoveFailed, "file")+" couldn't be deleted from the source."
	}
	raw, _ := json.Marshal(res)
	if err := h.q.FinishStorageSyncRun(bg, sqlc.FinishStorageSyncRunParams{
		ID: run.ID, State: state, Error: msg, Result: raw, Files: int32(res.Copied), Bytes: res.Bytes,
	}); err != nil {
		slog.Warn("finish a storage sync run", "run", run.ID, "error", err)
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
	return res, nil
}

// heldChanged says the held map needs saving.
func heldChanged(s sqlc.StorageSync, held map[string]time.Time, deleted []string) bool {
	return len(deleted) > 0 || len(held) != len(decodeHeld(s.Held)) || len(held) > 0
}

func countOf(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// verify compares every source file with its copy by size. It answers the
// relative paths that checked out.
func (h *storageSyncHandler) verify(ctx context.Context, t *jobs.Task, src, dst place, s sqlc.StorageSync, o StorageSyncOptions, res *StorageSyncResult) ([]string, error) {
	t.Update(func(p *jobs.Progress) {
		p.Phase, p.Current, p.Done, p.Total, p.Items, p.ItemsTotal = "Checking the copies", "", 0, 0, 0, 0
	})
	m, err := storage.NewMatcher(o.Excludes)
	if err != nil {
		return nil, err
	}
	want := map[string]int64{}
	root, err := src.fs.Stat(ctx, s.SourcePath)
	if err != nil {
		return nil, fmt.Errorf("source %s: %w", s.SourcePath, err)
	}
	if root.Dir {
		err = storage.Walk(ctx, src.fs, root.Path, func(e storage.Entry) error {
			rel := relPath(e.Path, root.Path)
			if rel != "" && !e.Dir && !m.Excluded(rel) {
				want[rel] = e.Size
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("source %s: %w", s.SourcePath, err)
		}
	} else {
		want[root.Name] = root.Size
	}
	have := map[string]int64{}
	err = storage.Walk(ctx, dst.fs, s.DestPath, func(e storage.Entry) error {
		if rel := relPath(e.Path, s.DestPath); rel != "" && !e.Dir {
			have[rel] = e.Size
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("destination %s: %w", s.DestPath, err)
	}
	v := &StorageSyncVerify{}
	res.Verify = v
	var ok []string
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, rel := range keys {
		v.Checked++
		size, found := have[rel]
		switch {
		case !found:
			v.Missing++
			if len(v.Problems) < 20 {
				v.Problems = append(v.Problems, rel+": not on the destination")
			}
		case size != want[rel]:
			v.Different++
			if len(v.Problems) < 20 {
				v.Problems = append(v.Problems, fmt.Sprintf("%s: %s here, %s there", rel, humanBytes(want[rel]), humanBytes(size)))
			}
		default:
			ok = append(ok, rel)
		}
	}
	t.Logf("Checked %d copies: %d missing, %d with another size", v.Checked, v.Missing, v.Different)
	return ok, nil
}

func relPath(p, base string) string {
	if base == "/" {
		return strings.TrimPrefix(p, "/")
	}
	return strings.TrimPrefix(strings.TrimPrefix(p, base), "/")
}

// emptySource deletes the copied files from the source, then the folders
// left empty, deepest first. The source folder itself stays.
func (h *storageSyncHandler) emptySource(ctx context.Context, t *jobs.Task, src place, s sqlc.StorageSync, files []string, res *StorageSyncResult) error {
	t.Update(func(p *jobs.Progress) {
		p.Phase, p.Current, p.Done, p.Total, p.Items, p.ItemsTotal = "Deleting from the source", "", 0, 0, 0, len(files)
	})
	root, err := src.fs.Stat(ctx, s.SourcePath)
	if err != nil {
		return err
	}
	if !root.Dir {
		if err := src.fs.Remove(ctx, root.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			res.RemoveFailed++
			return nil
		}
		res.Removed++
		return nil
	}
	dirs := map[string]bool{}
	for i, rel := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		for d := path.Dir(rel); d != "." && d != "/"; d = path.Dir(d) {
			dirs[d] = true
		}
		if err := src.fs.Remove(ctx, path.Join(s.SourcePath, rel)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			res.RemoveFailed++
			if len(res.Problems) < 20 {
				res.Problems = append(res.Problems, rel+": couldn't delete it from the source: "+storage.Message(err))
			}
		} else {
			res.Removed++
		}
		t.Update(func(p *jobs.Progress) { p.Items, p.Current = i+1, rel })
	}
	list := make([]string, 0, len(dirs))
	for d := range dirs {
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool {
		if a, b := strings.Count(list[i], "/"), strings.Count(list[j], "/"); a != b {
			return a > b
		}
		return list[i] > list[j]
	})
	for _, d := range list {
		full := path.Join(s.SourcePath, d)
		left, err := src.fs.List(ctx, full, 1)
		if err != nil || len(left) > 0 {
			continue
		}
		_ = src.fs.Remove(ctx, full)
	}
	t.Logf("Deleted %d file(s) from the source", res.Removed)
	return nil
}

// ---- The clock ----

func startStorageSyncScheduler(h *storageSyncHandler, every time.Duration) {
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

func (h *storageSyncHandler) fire(ctx context.Context) {
	now := time.Now()
	due, err := h.q.ListDueStorageSyncs(ctx, &now)
	if err != nil {
		slog.Warn("list due storage syncs", "error", err)
		return
	}
	for _, s := range due {
		next := nextOf(s.Trigger, s.Cron, s.Timezone, int(s.IntervalMinutes), false, now)
		n, err := h.q.ClaimStorageSync(ctx, sqlc.ClaimStorageSyncParams{ID: s.ID, Due: s.NextRunAt, NextRunAt: next})
		if err != nil || n == 0 {
			continue
		}
		if _, _, err := h.start(ctx, s, nil, s.Trigger, false); err != nil {
			slog.Warn("start a storage sync", "sync", s.ID, "error", err)
		}
	}
}

// ---- Routes ----

type StorageSyncPath struct {
	ID string `path:"id" format:"uuid"`
}

type StorageSyncRunPath struct {
	ID string `path:"id" format:"uuid"`
}

type StorageSyncRunOutput struct {
	Body struct {
		Run *StorageSyncRun `json:"run" doc:"null when an interval run was left for the next turn"`
		Job *Job            `json:"job" doc:"The background job; null when the run was skipped"`
	}
}

type StorageSyncReplicationOutput struct {
	Body struct {
		State *storage.ReplicationState `json:"state"`
		Error string                    `json:"error" doc:"Why the source MinIO couldn't be asked"`
	}
}

type StorageSyncListOutput struct {
	Body struct {
		Items []StorageSync `json:"items"`
	}
}

type StorageSyncRunListOutput struct {
	Body struct {
		Items []StorageSyncRun `json:"items"`
	}
}

type StorageSyncRunOneOutput struct{ Body StorageSyncRun }

func registerStorageSyncs(api huma.API, h *storageSyncHandler) {
	tags := []string{"Storage syncs"}
	h.runner.Handle(storageSyncKind, h.runJob)
	h.runner.Handle(storageMigrateKind, h.runJob)

	huma.Register(api, huma.Operation{
		OperationID: "list-storage-syncs",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/storage-syncs",
		Summary:     "List a workspace's storage migrations and syncs",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		StorageID string `query:"storage_id" format:"uuid" doc:"Only those with this storage at either end"`
	}) (*StorageSyncListOutput, error) {
		params := sqlc.ListStorageSyncsParams{WorkspaceID: uuid.MustParse(in.ID)}
		if in.StorageID != "" {
			id := uuid.MustParse(in.StorageID)
			params.StorageID = &id
		}
		rows, err := h.q.ListStorageSyncs(ctx, params)
		if err != nil {
			return nil, internalError(err)
		}
		var ends, users []uuid.UUID
		for _, r := range rows {
			ends = append(ends, r.SourceStorageID, r.DestStorageID)
			if r.UpdatedBy != nil {
				users = append(users, *r.UpdatedBy)
			}
		}
		n, err := h.names(ctx, ends, users)
		if err != nil {
			return nil, internalError(err)
		}
		out := &StorageSyncListOutput{}
		out.Body.Items = make([]StorageSync, len(rows))
		for i, r := range rows {
			s := sqlc.StorageSync{
				ID: r.ID, WorkspaceID: r.WorkspaceID, Kind: r.Kind, Name: r.Name,
				SourceStorageID: r.SourceStorageID, SourcePath: r.SourcePath, DestStorageID: r.DestStorageID, DestPath: r.DestPath,
				Engine: r.Engine, Mode: r.Mode, Trigger: r.Trigger, Cron: r.Cron, Timezone: r.Timezone,
				IntervalMinutes: r.IntervalMinutes, Options: r.Options, Paused: r.Paused, NextRunAt: r.NextRunAt,
				Held: r.Held, Native: r.Native, Problem: r.Problem, CreatedBy: r.CreatedBy, UpdatedBy: r.UpdatedBy,
				CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
			}
			var last *StorageSyncRunBrief
			if r.LastRunID != nil {
				last = &StorageSyncRunBrief{
					ID: r.LastRunID.String(), State: deref(r.LastRunState), At: *r.LastRunAt,
					FinishedAt: r.LastRunFinishedAt, Error: deref(r.LastRunError),
				}
				if r.LastRunDryRun != nil {
					last.DryRun = *r.LastRunDryRun
				}
				if jobs.Active(last.State) {
					if run, err := h.q.GetStorageSyncRun(ctx, *r.LastRunID); err == nil && h.syncRun(ctx, run) {
						if run, err = h.q.GetStorageSyncRun(ctx, run.ID); err == nil {
							last.State, last.Error, last.FinishedAt = run.State, run.Error, run.FinishedAt
						}
					}
				}
			}
			out.Body.Items[i] = h.toSync(s, n, last)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-storage-sync",
		Method:        http.MethodPost,
		Path:          "/workspaces/{id}/storage-syncs",
		Summary:       "Create a storage migration or sync",
		Description:   "You need Engineer on the workspace and the destination, and Operator on the source (Engineer when a migration empties it). MinIO replication needs Owner on both and is set up on the source MinIO at once (422 with its answer when it refuses). Runs act with your access, checked each time.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body StorageSyncBody
	}) (*StorageSyncOutput, error) {
		ws := uuid.MustParse(in.ID)
		c, err := h.check(ctx, ws, in.Body.Kind, in.Body)
		if err != nil {
			return nil, err
		}
		paused := in.Body.Paused != nil && *in.Body.Paused
		s, err := h.q.CreateStorageSync(ctx, sqlc.CreateStorageSyncParams{
			WorkspaceID: ws, Kind: c.kind, Name: c.name, SourceStorageID: c.src.ID, SourcePath: c.srcPath,
			DestStorageID: c.dst.ID, DestPath: c.dstPath, Engine: c.engine, Mode: c.mode, Trigger: c.trigger,
			Cron: c.cron, Timezone: c.tz, IntervalMinutes: int32(c.interval), Options: c.optionsJSON,
			NextRunAt: nextOf(c.trigger, c.cron, c.tz, c.interval, paused, time.Now()), CreatedBy: principalOf(ctx).ID(),
		})
		if isUniqueViolation(err) {
			return nil, fieldError("body.name", "One with this name already exists.", in.Body.Name)
		}
		if err != nil {
			return nil, internalError(err)
		}
		if paused {
			if s, err = h.q.SetStorageSyncPaused(ctx, sqlc.SetStorageSyncPausedParams{ID: s.ID, Paused: true}); err != nil {
				return nil, internalError(err)
			}
		}
		if c.engine == "replication" {
			native, err := h.setUp(ctx, s.ID, c, paused, nil, nil)
			if err != nil {
				_, _ = h.q.DeleteStorageSync(context.WithoutCancel(ctx), s.ID)
				return nil, err
			}
			if err := h.q.SetStorageSyncNative(ctx, sqlc.SetStorageSyncNativeParams{ID: s.ID, Native: native, Problem: ""}); err != nil {
				return nil, internalError(err)
			}
			s.Native = native
		}
		out, err := h.one(ctx, s)
		if err != nil {
			return nil, err
		}
		return &StorageSyncOutput{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-storage-sync",
		Method:      http.MethodGet,
		Path:        "/storage-syncs/{id}",
		Summary:     "Get a storage migration or sync",
		Tags:        tags,
	}, func(ctx context.Context, in *StorageSyncPath) (*StorageSyncOutput, error) {
		s, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		out, err := h.one(ctx, s)
		if err != nil {
			return nil, err
		}
		return &StorageSyncOutput{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-storage-sync",
		Method:      http.MethodPut,
		Path:        "/storage-syncs/{id}",
		Summary:     "Save changes to a storage migration or sync",
		Description: "The whole thing is sent; its kind can't change. From now on it runs with your access. With revision, answers 409 when someone else saved in between.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		StorageSyncPath
		Body StorageSyncUpdate
	}) (*StorageSyncOutput, error) {
		old, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if in.Body.Revision != nil && !in.Body.Revision.Equal(old.UpdatedAt) {
			return nil, huma.Error409Conflict("Someone else saved this after you opened it.")
		}
		c, err := h.check(ctx, old.WorkspaceID, old.Kind, in.Body.StorageSyncBody)
		if err != nil {
			return nil, err
		}
		paused := old.Paused
		if in.Body.Paused != nil {
			paused = *in.Body.Paused
		}
		var native []byte
		prev := decodeNative(old.Native)
		var prevSource *sqlc.Storage
		if prev != nil {
			if ps, err := h.q.GetStorage(ctx, old.SourceStorageID); err == nil {
				prevSource = &ps
			}
		}
		switch {
		case c.engine == "replication":
			if native, err = h.setUp(ctx, old.ID, c, paused, prev, prevSource); err != nil {
				return nil, err
			}
		case prev != nil && prevSource != nil:
			h.tearDown(ctx, *prevSource, *prev)
		}
		s, err := h.q.UpdateStorageSync(ctx, sqlc.UpdateStorageSyncParams{
			ID: old.ID, Name: c.name, SourceStorageID: c.src.ID, SourcePath: c.srcPath,
			DestStorageID: c.dst.ID, DestPath: c.dstPath, Engine: c.engine, Mode: c.mode, Trigger: c.trigger,
			Cron: c.cron, Timezone: c.tz, IntervalMinutes: int32(c.interval), Options: c.optionsJSON,
			NextRunAt: nextOf(c.trigger, c.cron, c.tz, c.interval, paused, time.Now()), UpdatedBy: principalOf(ctx).ID(),
		})
		if isUniqueViolation(err) {
			return nil, fieldError("body.name", "One with this name already exists.", in.Body.Name)
		}
		if err != nil {
			return nil, internalError(err)
		}
		if paused != old.Paused {
			if s, err = h.q.SetStorageSyncPaused(ctx, sqlc.SetStorageSyncPausedParams{ID: s.ID, Paused: paused, NextRunAt: s.NextRunAt}); err != nil {
				return nil, internalError(err)
			}
		}
		// Moved ends or another mode start the held deletions over.
		if old.SourceStorageID != s.SourceStorageID || old.SourcePath != s.SourcePath || old.DestStorageID != s.DestStorageID ||
			old.DestPath != s.DestPath || old.Mode != s.Mode {
			_ = h.q.SetStorageSyncHeld(ctx, sqlc.SetStorageSyncHeldParams{ID: s.ID, Held: []byte("{}")})
			s.Held = []byte("{}")
		}
		if native == nil {
			native = []byte("{}")
		}
		if err := h.q.SetStorageSyncNative(ctx, sqlc.SetStorageSyncNativeParams{ID: s.ID, Native: native, Problem: ""}); err != nil {
			return nil, internalError(err)
		}
		s.Native, s.Problem = native, ""
		out, err := h.one(ctx, s)
		if err != nil {
			return nil, err
		}
		return &StorageSyncOutput{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "pause-storage-sync",
		Method:      http.MethodPost,
		Path:        "/storage-syncs/{id}/pause",
		Summary:     "Pause or resume a sync",
		Description: "A run going now isn't stopped. A MinIO replication is turned off or on at the source. Resuming doesn't make up for runs missed while paused.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		StorageSyncPath
		Body struct {
			Paused bool `json:"paused"`
		}
	}) (*StorageSyncOutput, error) {
		old, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if nat := decodeNative(old.Native); nat != nil {
			src, err := h.q.GetStorage(ctx, old.SourceStorageID)
			if err != nil {
				return nil, internalError(err)
			}
			cfg, err := h.st.config(src)
			if err != nil {
				return nil, internalError(err)
			}
			if err := storage.SetReplicationEnabled(ctx, cfg, *nat, !in.Body.Paused); err != nil {
				return nil, huma.Error422UnprocessableEntity(upperFirst(problemText(err)))
			}
		}
		next := nextOf(old.Trigger, old.Cron, old.Timezone, int(old.IntervalMinutes), in.Body.Paused, time.Now())
		s, err := h.q.SetStorageSyncPaused(ctx, sqlc.SetStorageSyncPausedParams{ID: old.ID, Paused: in.Body.Paused, NextRunAt: next})
		if err != nil {
			return nil, internalError(err)
		}
		out, err := h.one(ctx, s)
		if err != nil {
			return nil, err
		}
		return &StorageSyncOutput{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-storage-sync",
		Method:        http.MethodDelete,
		Path:          "/storage-syncs/{id}",
		Summary:       "Delete a storage migration or sync and its runs",
		Description:   "A run going now is stopped; what it copied stays. A MinIO replication is removed from the source bucket (the copies stay).",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *StorageSyncPath) (*struct{}, error) {
		s, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if active, err := h.q.ListActiveStorageSyncRuns(ctx, s.ID); err == nil {
			for _, r := range active {
				if r.JobID != nil {
					_, _ = h.runner.Cancel(ctx, *r.JobID)
				}
			}
		}
		if nat := decodeNative(s.Native); nat != nil {
			if src, err := h.q.GetStorage(ctx, s.SourceStorageID); err == nil {
				h.tearDown(ctx, src, *nat)
			}
		}
		if _, err := h.q.DeleteStorageSync(ctx, s.ID); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "run-storage-sync",
		Method:        http.MethodPost,
		Path:          "/storage-syncs/{id}/run",
		Summary:       "Run a migration or sync now",
		Description:   "Queues a background job, with the access of the person who saved it. dry_run counts what would change and changes nothing. 409 while a run is going; 422 for a MinIO replication (it copies by itself).",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		StorageSyncPath
		Body struct {
			DryRun bool `json:"dry_run,omitempty" doc:"Only count what would be copied and deleted"`
		}
	}) (*StorageSyncRunOutput, error) {
		s, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		run, job, err := h.start(ctx, s, principalOf(ctx), "manual", in.Body.DryRun)
		if err != nil {
			return nil, err
		}
		out := &StorageSyncRunOutput{}
		if run != nil {
			r := h.toRun(*run)
			out.Body.Run = &r
		}
		out.Body.Job = job
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-storage-sync-runs",
		Method:      http.MethodGet,
		Path:        "/storage-syncs/{id}/runs",
		Summary:     "List a migration's or sync's runs, newest first",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		StorageSyncPath
		Limit int `query:"limit" minimum:"1" maximum:"200" default:"50"`
	}) (*StorageSyncRunListOutput, error) {
		rows, err := h.q.ListStorageSyncRuns(ctx, sqlc.ListStorageSyncRunsParams{SyncID: uuid.MustParse(in.ID), Lim: int32(max(in.Limit, 1))})
		if err != nil {
			return nil, internalError(err)
		}
		out := &StorageSyncRunListOutput{}
		out.Body.Items = make([]StorageSyncRun, len(rows))
		for i, r := range rows {
			if h.syncRun(ctx, r) {
				if r, err = h.q.GetStorageSyncRun(ctx, r.ID); err != nil {
					return nil, internalError(err)
				}
			}
			out.Body.Items[i] = h.toRun(r)
			h.live(ctx, &out.Body.Items[i])
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-storage-sync-run",
		Method:      http.MethodGet,
		Path:        "/storage-sync-runs/{id}",
		Summary:     "Get a run of a migration or sync",
		Tags:        tags,
	}, func(ctx context.Context, in *StorageSyncRunPath) (*StorageSyncRunOneOutput, error) {
		r, err := h.q.GetStorageSyncRun(ctx, uuid.MustParse(in.ID))
		if isNotFound(err) {
			return nil, huma.Error404NotFound("run not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if h.syncRun(ctx, r) {
			if r, err = h.q.GetStorageSyncRun(ctx, r.ID); err != nil {
				return nil, internalError(err)
			}
		}
		out := &StorageSyncRunOneOutput{h.toRun(r)}
		h.live(ctx, &out.Body)
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "cancel-storage-sync-run",
		Method:      http.MethodPost,
		Path:        "/storage-sync-runs/{id}/cancel",
		Summary:     "Stop a run",
		Description: "Files already copied stay; a migration that was deleting from the source stops between files.",
		Tags:        tags,
	}, func(ctx context.Context, in *StorageSyncRunPath) (*StorageSyncRunOneOutput, error) {
		r, err := h.q.GetStorageSyncRun(ctx, uuid.MustParse(in.ID))
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
		} else {
			_ = h.q.EndStorageSyncRun(ctx, sqlc.EndStorageSyncRunParams{ID: r.ID, State: jobs.Canceled})
		}
		if r, err = h.q.GetStorageSyncRun(ctx, r.ID); err != nil {
			return nil, internalError(err)
		}
		h.syncRun(ctx, r)
		if r, err = h.q.GetStorageSyncRun(ctx, r.ID); err != nil {
			return nil, internalError(err)
		}
		return &StorageSyncRunOneOutput{h.toRun(r)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-storage-sync-replication",
		Method:      http.MethodGet,
		Path:        "/storage-syncs/{id}/replication",
		Summary:     "How a MinIO replication is doing",
		Description: "Asks the source MinIO. When it can't be asked, state is null and error says why.",
		Tags:        tags,
	}, func(ctx context.Context, in *StorageSyncPath) (*StorageSyncReplicationOutput, error) {
		s, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		nat := decodeNative(s.Native)
		if nat == nil {
			return nil, huma.Error422UnprocessableEntity("It isn't a MinIO replication.")
		}
		out := &StorageSyncReplicationOutput{}
		src, err := h.q.GetStorage(ctx, s.SourceStorageID)
		if err != nil {
			out.Body.Error = "The source storage was deleted."
			return out, nil
		}
		cfg, err := h.st.config(src)
		if err != nil {
			return nil, internalError(err)
		}
		st, err := storage.ReadReplication(ctx, cfg, *nat)
		if err != nil {
			out.Body.Error = upperFirst(problemText(err))
			return out, nil
		}
		out.Body.State = &st
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "resync-storage-sync-replication",
		Method:        http.MethodPost,
		Path:          "/storage-syncs/{id}/replication/resync",
		Summary:       "Have MinIO copy what the bucket already holds",
		Description:   "The source MinIO goes over every object and copies what the destination lacks, in the background. Its progress shows in the replication state.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *StorageSyncPath) (*struct{}, error) {
		s, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		nat := decodeNative(s.Native)
		if nat == nil {
			return nil, huma.Error422UnprocessableEntity("It isn't a MinIO replication.")
		}
		src, err := h.q.GetStorage(ctx, s.SourceStorageID)
		if err != nil {
			return nil, huma.Error422UnprocessableEntity("The source storage was deleted.")
		}
		cfg, err := h.st.config(src)
		if err != nil {
			return nil, internalError(err)
		}
		if err := storage.ResyncReplication(ctx, cfg, *nat); err != nil {
			return nil, huma.Error422UnprocessableEntity(upperFirst(problemText(err)))
		}
		return nil, nil
	})
}
