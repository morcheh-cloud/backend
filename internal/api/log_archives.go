package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
)

// ---- Views ----

type LogTableSize struct {
	Name     string     `json:"name"`
	Bytes    int64      `json:"bytes" doc:"On disk, indexes included"`
	Rows     int64      `json:"rows" doc:"Rows, estimated by PostgreSQL"`
	DeadRows int64      `json:"dead_rows" doc:"Deleted rows whose space isn't reused yet"`
	Vacuumed *time.Time `json:"vacuumed,omitempty" doc:"Last tidied (VACUUM)"`
}

type LogPolicy struct {
	Enabled    bool       `json:"enabled"`
	Mode       string     `json:"mode" enum:"archive,copy,delete" doc:"archive = file then delete, copy = file only, delete = no file"`
	AfterDays  int        `json:"after_days" doc:"Rows older than this go"`
	MaxMB      int        `json:"max_mb" doc:"Also take older periods until the tables fit this size; 0 = no limit"`
	Period     string     `json:"period" enum:"day,week,month" doc:"One file per period"`
	KeepLocal  bool       `json:"keep_local" doc:"Keep the files on Morche's own disk"`
	StorageIDs []string   `json:"storage_ids" doc:"Storages a copy goes to"`
	Folder     string     `json:"folder" doc:"Folder on the storages; {year} {month} {day} are filled in"`
	KeepDays   int        `json:"keep_days" doc:"Delete files after this many days; 0 = keep them"`
	Cron       string     `json:"cron"`
	Timezone   string     `json:"timezone"`
	NextRunAt  *time.Time `json:"next_run_at,omitempty"`
	LastRunAt  *time.Time `json:"last_run_at,omitempty"`
	LastState  string     `json:"last_state"`
	LastNote   string     `json:"last_note"`
	LastJobID  string     `json:"last_job_id,omitempty"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type LogArchiveTotals struct {
	Files  int64      `json:"files"`
	Bytes  int64      `json:"bytes"`
	Rows   int64      `json:"rows"`
	Oldest *time.Time `json:"oldest,omitempty" doc:"Start of the oldest period in a file"`
	Held   int64      `json:"held" doc:"Archives whose rows are back in the database for now"`
}

type LogDatasetView struct {
	Key           string           `json:"key"`
	Title         string           `json:"title"`
	Group         string           `json:"group"`
	About         string           `json:"about"`
	Builtin       string           `json:"builtin" doc:"What happens to old rows without a policy"`
	SuggestedDays int              `json:"suggested_days"`
	Bytes         int64            `json:"bytes"`
	Rows          int64            `json:"rows"`
	DeadRows      int64            `json:"dead_rows"`
	Oldest        *time.Time       `json:"oldest,omitempty"`
	Tables        []LogTableSize   `json:"tables"`
	Policy        *LogPolicy       `json:"policy,omitempty"`
	Default       LogPolicyBody    `json:"default" doc:"The policy this kind starts with, and what Reset to default puts back"`
	IsDefault     bool             `json:"is_default" doc:"The policy is still the default one"`
	Owned         bool             `json:"owned" doc:"A policy removes old rows, so the built-in clean-up is off"`
	Archives      LogArchiveTotals `json:"archives"`
	Error         string           `json:"error,omitempty"`
}

type LogOverview struct {
	Items         []LogDatasetView `json:"items"`
	DatabaseBytes int64            `json:"database_bytes" doc:"The whole of Morche's database"`
	LogBytes      int64            `json:"log_bytes" doc:"Of which these logs"`
	LocalDir      string           `json:"local_dir" doc:"Where files kept on Morche's disk go"`
	LocalBytes    int64            `json:"local_bytes" doc:"Archive files there"`
	LocalFree     int64            `json:"local_free" doc:"Free space on that disk; 0 = not known"`
	LocalTotal    int64            `json:"local_total"`
	ReadAt        time.Time        `json:"read_at"`
}

type LogPeriod struct {
	From     time.Time `json:"from"`
	To       time.Time `json:"to"`
	Rows     int64     `json:"rows"`
	Bytes    int64     `json:"bytes" doc:"Estimated share of the tables' size"`
	Archived bool      `json:"archived" doc:"In a stored archive file"`
	Held     bool      `json:"held" doc:"Rows put back from an archive for now"`
}

type LogPreview struct {
	Periods []LogPeriod `json:"periods" doc:"What a run would take now"`
	Rows    int64       `json:"rows"`
	Bytes   int64       `json:"bytes"`
	Skipped []string    `json:"skipped"`
	Over    bool        `json:"over" doc:"The size limit takes newer periods than the age does"`
	Note    string      `json:"note"`
}

type LogArchiveCopyView struct {
	ID          int64  `json:"id"`
	Local       bool   `json:"local"`
	StorageID   string `json:"storage_id,omitempty"`
	StorageName string `json:"storage_name"`
	Path        string `json:"path"`
	State       string `json:"state" enum:"pending,stored,failed"`
	Error       string `json:"error"`
}

type LogArchiveView struct {
	ID            string               `json:"id"`
	Dataset       string               `json:"dataset"`
	DatasetTitle  string               `json:"dataset_title"`
	Mode          string               `json:"mode" enum:"archive,copy"`
	From          time.Time            `json:"from"`
	To            time.Time            `json:"to"`
	State         string               `json:"state" enum:"running,stored,failed,interrupted"`
	Error         string               `json:"error"`
	FileName      string               `json:"file_name"`
	Rows          int64                `json:"rows"`
	Tables        map[string]int64     `json:"tables"`
	Bytes         int64                `json:"bytes"`
	Sha256        string               `json:"sha256"`
	Note          string               `json:"note"`
	JobID         string               `json:"job_id,omitempty"`
	CreatedByName string               `json:"created_by_name"`
	CreatedAt     time.Time            `json:"created_at"`
	FinishedAt    *time.Time           `json:"finished_at,omitempty"`
	ExpiresAt     *time.Time           `json:"expires_at,omitempty" doc:"When its policy deletes the files"`
	Restore       LogArchiveRestore    `json:"restore"`
	Copies        []LogArchiveCopyView `json:"copies"`
}

type LogArchiveRestore struct {
	State     string     `json:"state" enum:",running,held,done" doc:"held = rows back until put away; done = missing rows put back (copy)"`
	At        *time.Time `json:"at,omitempty"`
	Rows      int64      `json:"rows"`
	By        string     `json:"by"`
	Error     string     `json:"error"`
	HoldUntil *time.Time `json:"hold_until,omitempty" doc:"When they're put away by themselves; none = until someone does"`
}

func toLogPolicy(p sqlc.LogArchivePolicy) *LogPolicy {
	out := &LogPolicy{
		Enabled: p.Enabled, Mode: p.Mode, AfterDays: int(p.AfterDays), MaxMB: int(p.MaxMb), Period: p.Period,
		KeepLocal: p.KeepLocal, StorageIDs: make([]string, len(p.StorageIds)), Folder: p.Folder,
		KeepDays: int(p.KeepDays), Cron: p.Cron, Timezone: p.Timezone, NextRunAt: p.NextRunAt,
		LastRunAt: p.LastRunAt, LastState: p.LastState, LastNote: p.LastNote, UpdatedAt: p.UpdatedAt,
	}
	for i, id := range p.StorageIds {
		out.StorageIDs[i] = id.String()
	}
	if p.LastJobID != nil {
		out.LastJobID = p.LastJobID.String()
	}
	if !p.Enabled {
		out.NextRunAt = nil
	}
	return out
}

func (h *logArchiveHandler) archiveViews(ctx context.Context, rows []sqlc.LogArchive) ([]LogArchiveView, error) {
	ids := make([]uuid.UUID, len(rows))
	for i, a := range rows {
		ids[i] = a.ID
	}
	copies := map[uuid.UUID][]LogArchiveCopyView{}
	if len(ids) > 0 {
		cs, err := h.q.ListLogArchiveCopies(ctx, ids)
		if err != nil {
			return nil, err
		}
		for _, c := range cs {
			v := LogArchiveCopyView{ID: c.ID, Local: c.Local, StorageName: c.StorageName, Path: c.Path, State: c.State, Error: c.Error}
			if c.StorageID != nil {
				v.StorageID = c.StorageID.String()
			}
			if c.Local {
				v.StorageName = "Morche"
			}
			copies[c.ArchiveID] = append(copies[c.ArchiveID], v)
		}
	}
	keep := map[string]int32{}
	if ps, err := h.q.ListLogArchivePolicies(ctx); err == nil {
		for _, p := range ps {
			keep[p.Dataset] = p.KeepDays
		}
	}
	out := make([]LogArchiveView, len(rows))
	for i, a := range rows {
		d, _ := logDatasetByKey(a.Dataset)
		v := LogArchiveView{
			ID: a.ID.String(), Dataset: a.Dataset, DatasetTitle: cmpOr(d.Title, a.Dataset), Mode: a.Mode,
			From: a.PeriodFrom, To: a.PeriodTo, State: a.State, Error: a.Error, FileName: a.FileName,
			Rows: a.Rows, Tables: map[string]int64{}, Bytes: a.Bytes, Sha256: a.Sha256, Note: a.Note,
			CreatedByName: a.CreatedByName, CreatedAt: a.CreatedAt, FinishedAt: a.FinishedAt,
			Restore: LogArchiveRestore{
				State: a.RestoreState, At: a.RestoredAt, Rows: a.RestoredRows, By: a.RestoredByName,
				Error: a.RestoreError, HoldUntil: a.HoldUntil,
			},
			Copies: copies[a.ID],
		}
		if v.Copies == nil {
			v.Copies = []LogArchiveCopyView{}
		}
		_ = json.Unmarshal(a.Tables, &v.Tables)
		if a.JobID != nil {
			v.JobID = a.JobID.String()
		}
		if days := keep[a.Dataset]; days > 0 && a.State == "stored" {
			at := a.CreatedAt.AddDate(0, 0, int(days))
			v.ExpiresAt = &at
		}
		out[i] = v
	}
	return out, nil
}

// ---- Sizes, cached: reading them touches every table ----

type logStatsCache struct {
	mu   sync.Mutex
	at   time.Time
	data *LogOverview
}

func (c *logStatsCache) drop() {
	c.mu.Lock()
	c.data = nil
	c.mu.Unlock()
}

func (h *logArchiveHandler) overview(ctx context.Context, fresh bool) (*LogOverview, error) {
	h.stats.mu.Lock()
	defer h.stats.mu.Unlock()
	if !fresh && h.stats.data != nil && time.Since(h.stats.at) < time.Minute {
		return h.withPolicies(ctx, *h.stats.data)
	}
	out := LogOverview{LocalDir: h.dir, ReadAt: time.Now()}
	if abs, err := filepath.Abs(h.dir); err == nil {
		out.LocalDir = abs
	}
	_ = h.db.QueryRow(ctx, "SELECT pg_database_size(current_database())").Scan(&out.DatabaseBytes)
	totals := map[string]sqlc.LogArchiveTotalsRow{}
	if rows, err := h.q.LogArchiveTotals(ctx); err == nil {
		for _, r := range rows {
			totals[r.Dataset] = r
		}
	}
	for _, d := range logDatasets {
		v := LogDatasetView{
			Key: d.Key, Title: d.Title, Group: d.Group, About: d.About, Builtin: d.Builtin,
			SuggestedDays: d.Days, Tables: []LogTableSize{}, Default: d.defaultPolicy(),
		}
		for _, table := range d.tables() {
			s, err := readTableStats(ctx, h.db, table)
			if err != nil {
				v.Error = problemText(err)
				continue
			}
			v.Bytes += s.TotalBytes
			v.DeadRows += s.DeadRows
			if table == d.Table {
				v.Rows = s.Rows
			}
			v.Tables = append(v.Tables, LogTableSize{Name: table, Bytes: s.TotalBytes, Rows: s.Rows, DeadRows: s.DeadRows, Vacuumed: s.Vacuumed})
		}
		var oldest *time.Time
		if err := h.db.QueryRow(ctx, fmt.Sprintf("SELECT min(%s) FROM %s", ident(d.Time), ident(d.Table))).Scan(&oldest); err == nil {
			v.Oldest = oldest
		}
		if t, ok := totals[d.Key]; ok {
			v.Archives = LogArchiveTotals{Files: t.Files, Bytes: t.Bytes, Rows: t.Rows, Held: t.Held}
			if !t.Oldest.IsZero() {
				o := t.Oldest
				v.Archives.Oldest = &o
			}
		}
		out.LogBytes += v.Bytes
		out.Items = append(out.Items, v)
	}
	out.LocalBytes = dirSize(h.dir)
	var fs syscall.Statfs_t
	dir := h.dir
	for dir != "" {
		if err := syscall.Statfs(dir, &fs); err == nil {
			out.LocalFree = int64(fs.Bavail) * int64(fs.Bsize)
			out.LocalTotal = int64(fs.Blocks) * int64(fs.Bsize)
			break
		}
		if parent := filepath.Dir(dir); parent != dir {
			dir = parent
		} else {
			break
		}
	}
	h.stats.data, h.stats.at = &out, time.Now()
	return h.withPolicies(ctx, out)
}

// withPolicies adds the policies, which change more often than sizes.
func (h *logArchiveHandler) withPolicies(ctx context.Context, o LogOverview) (*LogOverview, error) {
	ps, err := h.q.ListLogArchivePolicies(ctx)
	if err != nil {
		return nil, internalError(err)
	}
	byKey := map[string]sqlc.LogArchivePolicy{}
	for _, p := range ps {
		byKey[p.Dataset] = p
	}
	items := make([]LogDatasetView, len(o.Items))
	for i, v := range o.Items {
		v.Policy = nil
		if p, ok := byKey[v.Key]; ok {
			v.Policy = toLogPolicy(p)
		}
		v.IsDefault = isDefaultPolicy(v.Policy, v.Default)
		v.Owned = logOwned(v.Key)
		items[i] = v
	}
	o.Items = items
	return &o, nil
}

func dirSize(dir string) int64 {
	var n int64
	_ = filepath.WalkDir(dir, func(_ string, e os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !e.IsDir() {
			if info, err := e.Info(); err == nil {
				n += info.Size()
			}
		}
		return nil
	})
	return n
}

// ---- Input ----

type LogDatasetPath struct {
	Key string `path:"key" doc:"Kind of logs"`
}

type LogArchiveIDPath struct {
	ID string `path:"id" format:"uuid"`
}

type LogPolicyBody struct {
	Enabled    bool     `json:"enabled"`
	Mode       string   `json:"mode" enum:"archive,copy,delete"`
	AfterDays  int      `json:"after_days" minimum:"1" maximum:"3650"`
	MaxMB      int      `json:"max_mb" minimum:"0"`
	Period     string   `json:"period" enum:"day,week,month"`
	KeepLocal  bool     `json:"keep_local"`
	StorageIDs []string `json:"storage_ids" maxItems:"10"`
	Folder     string   `json:"folder" required:"false"`
	KeepDays   int      `json:"keep_days" minimum:"0"`
	Cron       string   `json:"cron"`
	Timezone   string   `json:"timezone" required:"false"`
}

type LogExportBody struct {
	From       time.Time `json:"from"`
	To         time.Time `json:"to"`
	KeepLocal  bool      `json:"keep_local"`
	StorageIDs []string  `json:"storage_ids" maxItems:"10"`
	Folder     string    `json:"folder" required:"false"`
	Note       string    `json:"note" required:"false" maxLength:"500"`
}

func (h *logArchiveHandler) dataset(key string) (logDataset, error) {
	d, ok := logDatasetByKey(key)
	if !ok {
		return d, huma.Error404NotFound("No such kind of logs.")
	}
	return d, nil
}

// places checks storages a file goes to.
func (h *logArchiveHandler) places(ctx context.Context, ids []string, local bool, folder, loc string, need bool) ([]uuid.UUID, error) {
	var out []uuid.UUID
	for i, raw := range ids {
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, fieldError(fmt.Sprintf("%s.storage_ids[%d]", loc, i), "Not a storage.", raw)
		}
		s, err := h.q.GetStorage(ctx, id)
		if err != nil {
			if isNotFound(err) {
				return nil, fieldError(fmt.Sprintf("%s.storage_ids[%d]", loc, i), "That storage doesn't exist.", raw)
			}
			return nil, internalError(err)
		}
		if s.ReadOnly {
			return nil, fieldError(fmt.Sprintf("%s.storage_ids[%d]", loc, i), s.Name+" is read-only in Morche.", raw)
		}
		if !slicesContainsUUID(out, id) {
			out = append(out, id)
		}
	}
	if need && !local && len(out) == 0 {
		return nil, fieldError(loc+".storage_ids", "Pick where the files go: Morche's disk or a storage.", ids)
	}
	if len(out) > 0 {
		if msg := backupFolderProblem(folder); msg != "" {
			return nil, fieldError(loc+".folder", msg, folder)
		}
	}
	return out, nil
}

func slicesContainsUUID(ids []uuid.UUID, id uuid.UUID) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func registerLogArchives(api huma.API, h *logArchiveHandler) {
	tags := []string{"Log retention"}
	h.runner.Handle(logArchiveKind, h.runArchive)
	h.runner.Handle(logRestoreKind, h.runRestore)
	h.runner.Handle(logPutAwayKind, h.runPutAway)
	h.runner.Handle(logCompactKind, h.runCompact)

	type overviewOut struct{ Body LogOverview }
	huma.Register(api, huma.Operation{
		OperationID: "list-log-datasets",
		Method:      http.MethodGet,
		Path:        "/log-datasets",
		Summary:     "Every kind of log Morche keeps, with its size and policy",
		Description: "Sizes are read at most once a minute unless fresh is set.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		Fresh bool `query:"fresh"`
	}) (*overviewOut, error) {
		o, err := h.overview(ctx, in.Fresh)
		if err != nil {
			return nil, err
		}
		return &overviewOut{*o}, nil
	})

	type periodsOut struct {
		Body struct {
			Periods []LogPeriod `json:"periods"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "list-log-dataset-periods",
		Method:      http.MethodGet,
		Path:        "/log-datasets/{key}/periods",
		Summary:     "A kind of logs' rows per month (or week or day), newest first",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		LogDatasetPath
		Period   string `query:"period" enum:"day,week,month" default:"month"`
		Timezone string `query:"tz" required:"false"`
	}) (*periodsOut, error) {
		d, err := h.dataset(in.Key)
		if err != nil {
			return nil, err
		}
		loc := scheduleLoc(in.Timezone)
		ws, err := h.periods(ctx, d, in.Period, loc, time.Now().Add(24*time.Hour))
		if err != nil {
			return nil, internalError(err)
		}
		size, rows, _ := h.datasetBytes(ctx, d)
		var total int64
		for _, w := range ws {
			total += w.Rows
		}
		if total > rows {
			rows = total
		}
		stored, _ := h.q.StoredLogArchiveWindows(ctx, d.Key)
		held, _ := h.q.HeldLogArchives(ctx, d.Key)
		out := &periodsOut{}
		out.Body.Periods = []LogPeriod{}
		for i := len(ws) - 1; i >= 0; i-- {
			w := ws[i]
			p := LogPeriod{From: w.From, To: w.To, Rows: w.Rows}
			if rows > 0 {
				p.Bytes = int64(float64(size) * float64(w.Rows) / float64(rows))
			}
			for _, s := range stored {
				if s.PeriodFrom.Before(w.To) && w.From.Before(s.PeriodTo) {
					p.Archived = true
				}
			}
			for _, a := range held {
				if a.PeriodFrom.Before(w.To) && w.From.Before(a.PeriodTo) {
					p.Held = true
				}
			}
			out.Body.Periods = append(out.Body.Periods, p)
		}
		// Periods whose rows all went into files show too, with no rows.
		for _, a := range stored {
			seen := false
			for _, p := range out.Body.Periods {
				if a.PeriodFrom.Before(p.To) && p.From.Before(a.PeriodTo) {
					seen = true
					break
				}
			}
			if !seen {
				out.Body.Periods = append(out.Body.Periods, LogPeriod{From: a.PeriodFrom.In(loc), To: a.PeriodTo.In(loc), Archived: true})
			}
		}
		slices.SortFunc(out.Body.Periods, func(a, b LogPeriod) int { return b.From.Compare(a.From) })
		return out, nil
	})

	// policyRow checks a body and turns it into a policy.
	policyRow := func(ctx context.Context, key string, b LogPolicyBody) (sqlc.SaveLogArchivePolicyParams, error) {
		p := sqlc.SaveLogArchivePolicyParams{
			Dataset: key, Enabled: b.Enabled, Mode: b.Mode, AfterDays: int32(b.AfterDays), MaxMb: int32(b.MaxMB),
			Period: b.Period, KeepLocal: b.KeepLocal, Folder: strings.TrimSpace(b.Folder), KeepDays: int32(b.KeepDays),
			Cron: strings.TrimSpace(b.Cron), Timezone: cmpOr(strings.TrimSpace(b.Timezone), "UTC"),
			StorageIds: []uuid.UUID{},
		}
		if p.Folder == "" {
			p.Folder = defaultLogFolder
		}
		if _, _, err := parseCron(p.Cron, p.Timezone); err != nil {
			return p, err
		}
		if b.Mode != "delete" {
			ids, err := h.places(ctx, b.StorageIDs, b.KeepLocal, p.Folder, "body", true)
			if err != nil {
				return p, err
			}
			if ids != nil {
				p.StorageIds = ids
			}
		} else {
			p.KeepLocal, p.KeepDays = false, 0
		}
		return p, nil
	}

	type previewOut struct{ Body LogPreview }
	huma.Register(api, huma.Operation{
		OperationID: "preview-log-policy",
		Method:      http.MethodPost,
		Path:        "/log-datasets/{key}/preview",
		Summary:     "What a policy would take if it ran now",
		Description: "Nothing is saved or changed.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		LogDatasetPath
		Body LogPolicyBody
	}) (*previewOut, error) {
		d, err := h.dataset(in.Key)
		if err != nil {
			return nil, err
		}
		row, err := policyRow(ctx, d.Key, in.Body)
		if err != nil {
			return nil, err
		}
		p := sqlc.LogArchivePolicy{
			Dataset: d.Key, Enabled: true, Mode: row.Mode, AfterDays: row.AfterDays, MaxMb: row.MaxMb,
			Period: row.Period, Timezone: row.Timezone,
		}
		plan, err := h.plan(ctx, d, p, time.Now())
		if err != nil {
			return nil, internalError(err)
		}
		size, rows, _ := h.datasetBytes(ctx, d)
		out := LogPreview{Periods: []LogPeriod{}, Skipped: plan.Skipped, Over: plan.Over}
		if out.Skipped == nil {
			out.Skipped = []string{}
		}
		for _, w := range plan.Windows {
			lp := LogPeriod{From: w.From, To: w.To, Rows: w.Rows}
			if rows > 0 {
				lp.Bytes = int64(float64(size) * float64(w.Rows) / float64(rows))
			}
			out.Rows += lp.Rows
			out.Bytes += lp.Bytes
			out.Periods = append(out.Periods, lp)
		}
		switch {
		case len(out.Periods) == 0 && len(out.Skipped) > 0:
			out.Note = "Every period old enough is left alone for now (see below)."
		case len(out.Periods) == 0:
			out.Note = "Nothing is old enough to go yet."
		case p.Mode == "delete":
			out.Note = fmt.Sprintf("About %d rows would be deleted, freeing about %s.", out.Rows, humanBytes(out.Bytes))
		case p.Mode == "copy":
			out.Note = fmt.Sprintf("About %d rows would be copied into %d files; the database keeps them.", out.Rows, len(out.Periods))
		default:
			out.Note = fmt.Sprintf("About %d rows would move into %d files, freeing about %s.", out.Rows, len(out.Periods), humanBytes(out.Bytes))
		}
		return &previewOut{out}, nil
	})

	type policyOut struct{ Body LogPolicy }
	savePolicy := func(ctx context.Context, d logDataset, b LogPolicyBody) (*policyOut, error) {
		row, err := policyRow(ctx, d.Key, b)
		if err != nil {
			return nil, err
		}
		row.NextRunAt = nextRun(row.Cron, row.Timezone, time.Now())
		row.UpdatedBy = principalOf(ctx).ID()
		p, err := h.q.SaveLogArchivePolicy(ctx, row)
		if err != nil {
			return nil, internalError(err)
		}
		h.loadOwners(ctx)
		return &policyOut{*toLogPolicy(p)}, nil
	}
	huma.Register(api, huma.Operation{
		OperationID: "save-log-policy",
		Method:      http.MethodPut,
		Path:        "/log-datasets/{key}/policy",
		Summary:     "Set a kind of logs' retention policy",
		Description: "An enabled archive or delete policy takes over from the built-in clean-up of these logs.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		LogDatasetPath
		Body LogPolicyBody
	}) (*policyOut, error) {
		d, err := h.dataset(in.Key)
		if err != nil {
			return nil, err
		}
		return savePolicy(ctx, d, in.Body)
	})

	huma.Register(api, huma.Operation{
		OperationID: "reset-log-policy",
		Method:      http.MethodPost,
		Path:        "/log-datasets/{key}/policy/reset",
		Summary:     "Put a kind of logs' default policy back",
		Description: "The policy goes back to the one every kind starts with (archive to Morche's disk after the kind's suggested days, nightly). Its last run and the files already written stay.",
		Tags:        tags,
	}, func(ctx context.Context, in *LogDatasetPath) (*policyOut, error) {
		d, err := h.dataset(in.Key)
		if err != nil {
			return nil, err
		}
		return savePolicy(ctx, d, d.defaultPolicy())
	})

	huma.Register(api, huma.Operation{
		OperationID: "run-log-policy",
		Method:      http.MethodPost,
		Path:        "/log-datasets/{key}/run",
		Summary:     "Run a kind of logs' policy now",
		Tags:        tags,
	}, func(ctx context.Context, in *LogDatasetPath) (*JobOutput, error) {
		d, err := h.dataset(in.Key)
		if err != nil {
			return nil, err
		}
		p, err := h.q.GetLogArchivePolicy(ctx, d.Key)
		if err != nil {
			if isNotFound(err) {
				return nil, huma.Error409Conflict("Set a policy first.")
			}
			return nil, internalError(err)
		}
		j, err := h.startRun(ctx, d.Key, p.StorageIds, nil)
		if err != nil {
			return nil, internalError(err)
		}
		return &JobOutput{toJob(j, false)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "export-log-dataset",
		Method:      http.MethodPost,
		Path:        "/log-datasets/{key}/export",
		Summary:     "Copy a period of logs into a file",
		Description: "The rows stay in the database. The file is listed with the archives and can be downloaded.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		LogDatasetPath
		Body LogExportBody
	}) (*JobOutput, error) {
		d, err := h.dataset(in.Key)
		if err != nil {
			return nil, err
		}
		b := in.Body
		if !b.To.After(b.From) {
			return nil, fieldError("body.to", "Pick an end after the start.", b.To)
		}
		folder := cmpOr(strings.TrimSpace(b.Folder), "/morcheh-archives")
		ids, err := h.places(ctx, b.StorageIDs, b.KeepLocal, folder, "body", true)
		if err != nil {
			return nil, err
		}
		j, err := h.startRun(ctx, d.Key, ids, &logExport{
			From: b.From, To: b.To, KeepLocal: b.KeepLocal, StorageIDs: ids, Folder: folder, Note: strings.TrimSpace(b.Note),
		})
		if err != nil {
			return nil, internalError(err)
		}
		return &JobOutput{toJob(j, false)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "compact-log-dataset",
		Method:      http.MethodPost,
		Path:        "/log-datasets/{key}/compact",
		Summary:     "Give a kind of logs' unused space back",
		Description: "Plain compacting lets PostgreSQL reuse the space of deleted rows. Full gives it back to the disk, but locks the tables (writes wait) until it ends.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		LogDatasetPath
		Body struct {
			Full bool `json:"full"`
		}
	}) (*JobOutput, error) {
		d, err := h.dataset(in.Key)
		if err != nil {
			return nil, err
		}
		return submit(ctx, h.runner, jobs.Spec{
			Kind: logCompactKind, Title: "Compact " + strings.ToLower(d.Title),
			Params: logJobParams{Dataset: d.Key, Full: in.Body.Full},
			Target: JobPlace{Dataset: d.Key},
		})
	})

	type archiveList struct {
		Body struct {
			Items []LogArchiveView `json:"items"`
			Total int64            `json:"total"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "list-log-archives",
		Method:      http.MethodGet,
		Path:        "/log-archives",
		Summary:     "List archive files, newest period first",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		Dataset string `query:"dataset" required:"false"`
		State   string `query:"state" required:"false" enum:",running,stored,failed,interrupted"`
		Held    bool   `query:"held" doc:"Only archives whose rows are back for now"`
		Page    int    `query:"page" minimum:"1" default:"1"`
		Limit   int    `query:"limit" minimum:"1" maximum:"200" default:"50"`
	}) (*archiveList, error) {
		var dataset, state *string
		if in.Dataset != "" {
			dataset = &in.Dataset
		}
		if in.State != "" {
			state = &in.State
		}
		rows, err := h.q.ListLogArchives(ctx, sqlc.ListLogArchivesParams{
			Dataset: dataset, State: state, HeldOnly: in.Held,
			Off: int32((in.Page - 1) * in.Limit), Lim: int32(in.Limit),
		})
		if err != nil {
			return nil, internalError(err)
		}
		total, err := h.q.CountLogArchives(ctx, sqlc.CountLogArchivesParams{Dataset: dataset, State: state, HeldOnly: in.Held})
		if err != nil {
			return nil, internalError(err)
		}
		out := &archiveList{}
		if out.Body.Items, err = h.archiveViews(ctx, rows); err != nil {
			return nil, internalError(err)
		}
		out.Body.Total = total
		return out, nil
	})

	get := func(ctx context.Context, raw string) (sqlc.LogArchive, error) {
		id, err := uuid.Parse(raw)
		if err != nil {
			return sqlc.LogArchive{}, huma.Error404NotFound("No such archive.")
		}
		a, err := h.q.GetLogArchive(ctx, id)
		if err != nil {
			if isNotFound(err) {
				return a, huma.Error404NotFound("No such archive.")
			}
			return a, internalError(err)
		}
		return a, nil
	}
	type archiveOut struct{ Body LogArchiveView }
	one := func(ctx context.Context, a sqlc.LogArchive) (*archiveOut, error) {
		vs, err := h.archiveViews(ctx, []sqlc.LogArchive{a})
		if err != nil {
			return nil, internalError(err)
		}
		return &archiveOut{vs[0]}, nil
	}

	huma.Register(api, huma.Operation{
		OperationID: "get-log-archive",
		Method:      http.MethodGet,
		Path:        "/log-archives/{id}",
		Summary:     "Get an archive file's details",
		Tags:        tags,
	}, func(ctx context.Context, in *LogArchiveIDPath) (*archiveOut, error) {
		a, err := get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return one(ctx, a)
	})

	huma.Register(api, huma.Operation{
		OperationID: "download-log-archive",
		Method:      http.MethodGet,
		Path:        "/log-archives/{id}/download",
		Summary:     "Download an archive's zip file",
		Description: "From the copy named, or else Morche's own copy, or else the first storage holding it.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		LogArchiveIDPath
		Copy int64 `query:"copy" required:"false" doc:"Which copy"`
	}) (*huma.StreamResponse, error) {
		a, err := get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		copies, err := h.q.ListLogArchiveCopies(ctx, []uuid.UUID{a.ID})
		if err != nil {
			return nil, internalError(err)
		}
		var refused error = huma.Error409Conflict("No copy of the file is left.")
		for _, c := range copies {
			if c.State != "stored" || (in.Copy != 0 && c.ID != in.Copy) {
				continue
			}
			if c.Local {
				f, err := os.Open(h.localPath(c))
				if err != nil {
					refused = huma.Error409Conflict("The file isn't on Morche's disk any more.")
					continue
				}
				st, err := f.Stat()
				if err != nil {
					f.Close()
					return nil, internalError(err)
				}
				return &huma.StreamResponse{Body: func(hctx huma.Context) {
					defer f.Close()
					r, w := humachi.Unwrap(hctx)
					w.Header().Set("X-Content-Type-Options", "nosniff")
					w.Header().Set("Content-Type", "application/zip")
					w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", a.FileName))
					http.ServeContent(w, r, a.FileName, st.ModTime(), f)
				}}, nil
			}
			if c.StorageID == nil {
				continue
			}
			s, err := h.q.GetStorage(ctx, *c.StorageID)
			if err != nil {
				continue
			}
			conn, err := h.st.acquire(ctx, s)
			if err != nil {
				refused = err
				continue
			}
			file, err := conn.fs.Open(ctx, c.Path)
			if err != nil {
				h.st.release(conn)
				refused = storageProblem(c.Path, err)
				continue
			}
			return &huma.StreamResponse{Body: func(hctx huma.Context) {
				defer h.st.release(conn)
				defer file.Close()
				r, w := humachi.Unwrap(hctx)
				w.Header().Set("X-Content-Type-Options", "nosniff")
				serveStorageFile(w, r, file, false, conn.fs.Capabilities().Ranges)
			}}, nil
		}
		return nil, refused
	})

	huma.Register(api, huma.Operation{
		OperationID: "restore-log-archive",
		Method:      http.MethodPost,
		Path:        "/log-archives/{id}/restore",
		Summary:     "Put an archive's rows back in the database",
		Description: "Rows already there are left as they are. Rows of an archive (not a copy) stay back for hold_days, or until put away when 0; the file is kept either way.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		LogArchiveIDPath
		Body struct {
			HoldDays int `json:"hold_days" minimum:"0" maximum:"3650" doc:"0 = until someone puts them away"`
		}
	}) (*JobOutput, error) {
		a, err := get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if a.State != "stored" {
			return nil, huma.Error409Conflict("This archive has no file to put back from.")
		}
		switch a.RestoreState {
		case "running":
			return nil, huma.Error409Conflict("It's being put back already.")
		case "held":
			return nil, huma.Error409Conflict("Its rows are back already.")
		}
		d, _ := logDatasetByKey(a.Dataset)
		return submit(ctx, h.runner, jobs.Spec{
			Kind:   logRestoreKind,
			Title:  "Put back " + strings.ToLower(cmpOr(d.Title, a.Dataset)) + " from " + a.FileName,
			Params: logJobParams{Dataset: a.Dataset, Archive: a.ID.String(), HoldDays: in.Body.HoldDays},
			Refs:   archiveRefs(ctx, h, a),
			Target: JobPlace{Dataset: a.Dataset, Archive: a.ID.String()},
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "put-away-log-archive",
		Method:      http.MethodPost,
		Path:        "/log-archives/{id}/put-away",
		Summary:     "Take an archive's restored rows out again",
		Description: "Only rows the file holds are deleted; the file stays.",
		Tags:        tags,
	}, func(ctx context.Context, in *LogArchiveIDPath) (*JobOutput, error) {
		a, err := get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if a.RestoreState != "held" {
			return nil, huma.Error409Conflict("Its rows aren't back, so there's nothing to put away.")
		}
		h.mu.Lock()
		started := h.putting[a.ID]
		h.putting[a.ID] = true
		h.mu.Unlock()
		if started {
			return nil, huma.Error409Conflict("They're being put away already.")
		}
		spec := h.putAwaySpec(a)
		spec.Refs = archiveRefs(ctx, h, a)
		out, err := submit(ctx, h.runner, spec)
		if err != nil {
			h.mu.Lock()
			delete(h.putting, a.ID)
			h.mu.Unlock()
		}
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-log-archive-hold",
		Method:      http.MethodPut,
		Path:        "/log-archives/{id}/hold",
		Summary:     "Change how long restored rows stay",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		LogArchiveIDPath
		Body struct {
			Days int `json:"days" minimum:"0" maximum:"3650" doc:"From now; 0 = until someone puts them away"`
		}
	}) (*archiveOut, error) {
		a, err := get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if a.RestoreState != "held" {
			return nil, huma.Error409Conflict("Its rows aren't back.")
		}
		var until *time.Time
		if in.Body.Days > 0 {
			t := time.Now().AddDate(0, 0, in.Body.Days)
			until = &t
		}
		a, err = h.q.SetLogArchiveHold(ctx, sqlc.SetLogArchiveHoldParams{ID: a.ID, HoldUntil: until})
		if err != nil {
			if isNotFound(err) {
				return nil, huma.Error409Conflict("Its rows aren't back.")
			}
			return nil, internalError(err)
		}
		return one(ctx, a)
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-log-archive",
		Method:        http.MethodDelete,
		Path:          "/log-archives/{id}",
		Summary:       "Delete an archive and its files",
		Description:   "Deletes the file from Morche's disk and every storage. Its rows are gone for good unless they're back in the database.",
		DefaultStatus: http.StatusNoContent,
		Tags:          tags,
	}, func(ctx context.Context, in *LogArchiveIDPath) (*struct{}, error) {
		a, err := get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		switch {
		case a.State == "running":
			return nil, huma.Error409Conflict("It's being written now.")
		case a.RestoreState == "running":
			return nil, huma.Error409Conflict("It's being put back now.")
		case a.RestoreState == "held":
			return nil, huma.Error409Conflict("Its rows are back in the database: put them away first, or they'd stay with no file behind them.")
		}
		if err := h.removeArchive(ctx, a); err != nil {
			return nil, huma.Error409Conflict(err.Error())
		}
		h.stats.drop()
		return nil, nil
	})
}

// archiveRefs are the storages an archive's copies are on.
func archiveRefs(ctx context.Context, h *logArchiveHandler, a sqlc.LogArchive) []uuid.UUID {
	copies, err := h.q.ListLogArchiveCopies(ctx, []uuid.UUID{a.ID})
	if err != nil {
		return nil
	}
	var out []uuid.UUID
	for _, c := range copies {
		if c.StorageID != nil && c.State == "stored" && !slicesContainsUUID(out, *c.StorageID) {
			out = append(out, *c.StorageID)
		}
	}
	return out
}

var _ = errors.New
