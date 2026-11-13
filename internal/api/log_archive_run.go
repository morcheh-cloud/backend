package api

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
)

// Job kinds of the log retention.
const (
	logArchiveKind = "log-archive"         // a policy's run, or an export
	logRestoreKind = "log-archive-restore" // put an archive's rows back
	logPutAwayKind = "log-archive-putaway" // take restored rows out again
	logCompactKind = "log-compact"         // give a dataset's space back to the disk
)

// logArchiveFormat is the version of the zip layout (manifest.json + one CSV
// per table).
const logArchiveFormat = 1

type logArchiveHandler struct {
	q      *sqlc.Queries
	db     *pgxpool.Pool
	st     *storageHandler
	runner *jobs.Runner
	// dir holds the archives kept on Morche's own disk, one folder per
	// dataset, and .tmp for files being written.
	dir string

	mu    sync.Mutex
	locks map[string]chan struct{}
	// Put-aways the scheduler started and that haven't ended yet.
	putting map[uuid.UUID]bool

	stats logStatsCache
}

func newLogArchiveHandler(q *sqlc.Queries, db *pgxpool.Pool, st *storageHandler, runner *jobs.Runner, dir string) *logArchiveHandler {
	return &logArchiveHandler{
		q: q, db: db, st: st, runner: runner, dir: dir,
		locks: map[string]chan struct{}{}, putting: map[uuid.UUID]bool{},
	}
}

// lock waits until no other job works on the dataset. Archiving, putting
// back and compacting one dataset never overlap.
func (h *logArchiveHandler) lock(ctx context.Context, t *jobs.Task, key string) (func(), error) {
	h.mu.Lock()
	ch := h.locks[key]
	if ch == nil {
		ch = make(chan struct{}, 1)
		h.locks[key] = ch
	}
	h.mu.Unlock()
	select {
	case ch <- struct{}{}:
	default:
		t.Update(func(p *jobs.Progress) { p.Phase = "Waiting for another job on these logs" })
		select {
		case ch <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return func() { <-ch }, nil
}

// loadOwners tells the built-in pruning which datasets a policy looks after.
// A copy policy keeps the rows, so the built-in pruning still runs for it.
func (h *logArchiveHandler) loadOwners(ctx context.Context) { loadLogOwners(ctx, h.q) }

// loadLogOwners reads which kinds of logs a policy removes old rows from,
// so the built-in clean-up of those stays off. build() calls it before any
// clean-up loop starts.
func loadLogOwners(ctx context.Context, q *sqlc.Queries) {
	ps, err := q.ListLogArchivePolicies(ctx)
	if err != nil {
		slog.Warn("load log retention policies", "error", err)
		return
	}
	var keys []string
	for _, p := range ps {
		if p.Enabled && p.Mode != "copy" {
			keys = append(keys, p.Dataset)
		}
	}
	setLogOwners(keys)
}

// ---- Params and results ----

type logJobParams struct {
	Dataset string `json:"dataset"`
	// Export is a one-off copy of a chosen period; nil = the policy's run.
	Export   *logExport `json:"export,omitempty"`
	Archive  string     `json:"archive,omitempty"`
	HoldDays int        `json:"hold_days,omitempty"`
	// Full compacts with VACUUM FULL (locks the tables), else plain VACUUM.
	Full bool `json:"full,omitempty"`
}

type logExport struct {
	From       time.Time   `json:"from"`
	To         time.Time   `json:"to"`
	KeepLocal  bool        `json:"keep_local"`
	StorageIDs []uuid.UUID `json:"storage_ids"`
	Folder     string      `json:"folder"`
	Note       string      `json:"note"`
}

// LogRunResult is what a log-archive job did.
type LogRunResult struct {
	Archives []string `json:"archives" doc:"Archive files written"`
	Rows     int64    `json:"rows" doc:"Rows written to files"`
	Bytes    int64    `json:"bytes" doc:"Size of the files written"`
	Deleted  int64    `json:"deleted" doc:"Rows taken out of the database"`
	Skipped  []string `json:"skipped,omitempty" doc:"Periods left alone, and why"`
	Note     string   `json:"note" doc:"One line about the run"`
}

// LogRestoreResult is what a restore or a put-away did.
type LogRestoreResult struct {
	Rows   int64            `json:"rows"`
	Tables map[string]int64 `json:"tables"`
	Note   string           `json:"note"`
}

type logManifest struct {
	Format    int                `json:"format"`
	Dataset   string             `json:"dataset"`
	Title     string             `json:"title"`
	Mode      string             `json:"mode"`
	From      time.Time          `json:"from"`
	To        time.Time          `json:"to"`
	CreatedAt time.Time          `json:"created_at"`
	Schema    int64              `json:"schema_version"`
	Tables    []logManifestTable `json:"tables"`
	Note      string             `json:"note,omitempty"`
}

type logManifestTable struct {
	Name    string   `json:"name"`
	File    string   `json:"file"`
	Columns []string `json:"columns"`
	Types   []string `json:"types"`
	Rows    int64    `json:"rows"`
}

// ---- Which periods go ----

// logWindow is one period of a dataset: [From, To).
type logWindow struct {
	From time.Time
	To   time.Time
	Rows int64 // all its rows, busy ones too
}

// periodStart is the start of the period holding at, in loc.
func periodStart(period string, at time.Time, loc *time.Location) time.Time {
	at = at.In(loc)
	y, m, d := at.Date()
	switch period {
	case "month":
		return time.Date(y, m, 1, 0, 0, 0, 0, loc)
	case "week":
		day := time.Date(y, m, d, 0, 0, 0, 0, loc)
		back := (int(day.Weekday()) + 6) % 7 // weeks start on Monday
		return day.AddDate(0, 0, -back)
	}
	return time.Date(y, m, d, 0, 0, 0, 0, loc)
}

func periodEnd(period string, start time.Time) time.Time {
	switch period {
	case "month":
		return start.AddDate(0, 1, 0)
	case "week":
		return start.AddDate(0, 0, 7)
	}
	return start.AddDate(0, 0, 1)
}

// periods counts the dataset's rows per period, oldest first, up to before.
func (h *logArchiveHandler) periods(ctx context.Context, d logDataset, period string, loc *time.Location, before time.Time) ([]logWindow, error) {
	trunc := map[string]string{"day": "day", "week": "week", "month": "month"}[period]
	if trunc == "" {
		return nil, fmt.Errorf("unknown period %q", period)
	}
	rows, err := h.db.Query(ctx, fmt.Sprintf(`
		SELECT date_trunc('%s', t.%s AT TIME ZONE $1) AS p, count(*)
		FROM %s t WHERE t.%s < $2
		GROUP BY 1 ORDER BY 1`, trunc, ident(d.Time), ident(d.Table), ident(d.Time)),
		loc.String(), before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []logWindow
	for rows.Next() {
		var local time.Time
		var n int64
		if err := rows.Scan(&local, &n); err != nil {
			return nil, err
		}
		// The database answers the period's local wall time; place it in loc.
		start := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
		out = append(out, logWindow{From: start, To: periodEnd(period, start), Rows: n})
	}
	return out, rows.Err()
}

// datasetBytes is the dataset's tables' size on disk, indexes included.
func (h *logArchiveHandler) datasetBytes(ctx context.Context, d logDataset) (bytes, rows int64, err error) {
	for _, table := range d.tables() {
		s, err := readTableStats(ctx, h.db, table)
		if err != nil {
			return 0, 0, err
		}
		bytes += s.TotalBytes
		if table == d.Table {
			rows = s.Rows
		}
	}
	return bytes, rows, nil
}

// logPlan is what a policy's run would do now.
type logPlan struct {
	Windows []logWindow
	Skipped []string
	// Over is set when the size limit asks for more than the age does.
	Over bool
}

// plan picks the periods a policy's run takes: whole periods older than
// after_days, then (archive and delete only) older periods until the dataset
// fits max_mb. Never the current period, a period whose rows were put back
// for now, or (copy) one already in a file.
func (h *logArchiveHandler) plan(ctx context.Context, d logDataset, p sqlc.LogArchivePolicy, now time.Time) (logPlan, error) {
	var out logPlan
	loc := scheduleLoc(p.Timezone)
	current := periodStart(p.Period, now, loc)
	all, err := h.periods(ctx, d, p.Period, loc, current)
	if err != nil {
		return out, err
	}
	cutoff := now.AddDate(0, 0, -int(p.AfterDays))

	held, err := h.q.HeldLogArchives(ctx, d.Key)
	if err != nil {
		return out, err
	}
	var stored []sqlc.StoredLogArchiveWindowsRow
	if p.Mode == "copy" {
		if stored, err = h.q.StoredLogArchiveWindows(ctx, d.Key); err != nil {
			return out, err
		}
	}
	skip := func(w logWindow) string {
		for _, a := range held {
			if a.PeriodFrom.Before(w.To) && w.From.Before(a.PeriodTo) {
				return "its rows were put back from an archive for now"
			}
		}
		for _, s := range stored {
			if s.PeriodFrom.Equal(w.From) && s.PeriodTo.Equal(w.To) {
				return "already in a file"
			}
		}
		return ""
	}
	label := func(w logWindow) string { return periodLabel(p.Period, w.From) }

	var rest []logWindow
	for _, w := range all {
		if !w.To.After(cutoff) {
			if why := skip(w); why != "" {
				if p.Mode != "copy" || why != "already in a file" {
					out.Skipped = append(out.Skipped, label(w)+": "+why)
				}
				continue
			}
			out.Windows = append(out.Windows, w)
		} else {
			rest = append(rest, w)
		}
	}

	if p.MaxMb > 0 && p.Mode != "copy" {
		size, rows, err := h.datasetBytes(ctx, d)
		if err != nil {
			return out, err
		}
		limit := int64(p.MaxMb) << 20
		share := func(n int64) int64 {
			if rows <= 0 {
				return 0
			}
			return int64(float64(size) * float64(n) / float64(rows))
		}
		for _, w := range out.Windows {
			size -= share(w.Rows)
		}
		for _, w := range rest {
			if size <= limit {
				break
			}
			if why := skip(w); why != "" {
				out.Skipped = append(out.Skipped, label(w)+": "+why)
				continue
			}
			out.Windows = append(out.Windows, w)
			out.Over = true
			size -= share(w.Rows)
		}
	}
	return out, nil
}

// periodLabel names a period for people: "2026-10", "2026-10-05", "week of
// 2026-10-05".
func periodLabel(period string, from time.Time) string {
	switch period {
	case "month":
		return from.Format("2006-01")
	case "week":
		return "week of " + from.Format("2006-01-02")
	}
	return from.Format("2006-01-02")
}

// ---- Running a policy, or an export ----

func (h *logArchiveHandler) runArchive(ctx context.Context, t *jobs.Task) (any, error) {
	var params logJobParams
	if err := t.Decode(&params); err != nil {
		return nil, err
	}
	d, ok := logDatasetByKey(params.Dataset)
	if !ok {
		return nil, fmt.Errorf("unknown kind of logs %q", params.Dataset)
	}
	unlock, err := h.lock(ctx, t, d.Key)
	if err != nil {
		return nil, err
	}
	defer unlock()

	res, err := h.archive(ctx, t, d, params)
	if params.Export == nil {
		state, note := jobs.Succeeded, res.Note
		if err != nil {
			state, note = jobs.Failed, err.Error()
		}
		bg := context.WithoutCancel(ctx)
		id := t.ID
		if e := h.q.SetLogArchivePolicyRun(bg, sqlc.SetLogArchivePolicyRunParams{
			Dataset: d.Key, LastState: state, LastNote: note, LastJobID: &id,
		}); e != nil {
			slog.Warn("record a log policy's run", "dataset", d.Key, "error", e)
		}
	}
	h.stats.drop()
	if err != nil {
		return nil, err
	}
	return res, nil
}

// logPlaces is where an archive's file goes.
type logPlaces struct {
	local    bool
	storages []sqlc.Storage
	folder   string
}

func (h *logArchiveHandler) archive(ctx context.Context, t *jobs.Task, d logDataset, params logJobParams) (LogRunResult, error) {
	var res LogRunResult
	now := time.Now()
	by, byName := t.CreatedBy(), ""
	if by != nil {
		if u, err := h.q.GetUser(ctx, *by); err == nil {
			byName = cmpOr(u.FullName, u.Username)
		}
	}

	var (
		mode    string
		places  logPlaces
		windows []logWindow
		note    string
	)
	if e := params.Export; e != nil {
		mode, note = "copy", e.Note
		places = logPlaces{local: e.KeepLocal, folder: e.Folder}
		windows = []logWindow{{From: e.From, To: e.To}}
		var err error
		if places.storages, err = h.storageRows(ctx, e.StorageIDs); err != nil {
			return res, err
		}
	} else {
		p, err := h.q.GetLogArchivePolicy(ctx, d.Key)
		if err != nil {
			if isNotFound(err) {
				return res, errors.New("This kind of logs has no policy any more.")
			}
			return res, err
		}
		mode = p.Mode
		places = logPlaces{local: p.KeepLocal, folder: p.Folder}
		if mode != "delete" {
			if places.storages, err = h.storageRows(ctx, p.StorageIds); err != nil {
				return res, err
			}
		}
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Looking for old periods" })
		plan, err := h.plan(ctx, d, p, now)
		if err != nil {
			return res, err
		}
		windows, res.Skipped = plan.Windows, plan.Skipped
		for _, s := range plan.Skipped {
			t.Logf("Left alone: %s", s)
		}
		if plan.Over {
			t.Logf("Over %d MB: newer periods go too.", p.MaxMb)
		}
	}
	if mode != "delete" && !places.local && len(places.storages) == 0 {
		return res, errors.New("There is nowhere to keep the files: keep them on Morche's disk or pick a storage.")
	}
	if len(windows) == 0 {
		res.Note = "Nothing old enough to take."
		t.Logf("%s", res.Note)
		return res, nil
	}

	info, err := readTableInfo(ctx, h.db, d.Table)
	if err != nil {
		return res, err
	}
	infos := map[string]tableInfo{d.Table: info}
	for _, c := range d.Children {
		if infos[c.Table], err = readTableInfo(ctx, h.db, c.Table); err != nil {
			return res, err
		}
	}

	t.Update(func(pr *jobs.Progress) { pr.Items, pr.ItemsTotal = 0, len(windows) })
	var problems []string
	for i, w := range windows {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		label := w.From.Format("2006-01-02") + " – " + w.To.Add(-time.Second).Format("2006-01-02")
		t.Update(func(pr *jobs.Progress) { pr.Current = label })
		if mode == "delete" {
			t.Update(func(pr *jobs.Progress) { pr.Phase = "Deleting" })
			n, err := h.deleteWindow(ctx, d, info, w)
			if err != nil {
				return res, err
			}
			res.Deleted += n
			t.Logf("%s: %d rows deleted.", label, n)
		} else {
			a, deleted, err := h.writeWindow(ctx, t, d, infos, w, mode, places, note, by, byName)
			switch {
			case err != nil:
				t.Logf("%s: %s", label, problemText(err))
				problems = append(problems, label+": "+problemText(err))
				if ctx.Err() != nil {
					return res, ctx.Err()
				}
			case a == nil:
				t.Logf("%s: nothing to take (rows still in use).", label)
			default:
				res.Archives = append(res.Archives, a.FileName)
				res.Rows += a.Rows
				res.Bytes += a.Bytes
				res.Deleted += deleted
				t.Logf("%s: %d rows in %s (%s).", label, a.Rows, a.FileName, humanBytes(a.Bytes))
			}
		}
		t.Update(func(pr *jobs.Progress) { pr.Items = i + 1 })
	}

	if res.Deleted > 0 {
		t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Current = "Tidying the tables", "" })
		h.vacuum(ctx, d, false)
	}
	switch {
	case mode == "delete":
		res.Note = fmt.Sprintf("%d rows deleted.", res.Deleted)
	case mode == "copy":
		res.Note = fmt.Sprintf("%d rows copied into %d files (%s).", res.Rows, len(res.Archives), humanBytes(res.Bytes))
	default:
		res.Note = fmt.Sprintf("%d rows archived into %d files (%s).", res.Rows, len(res.Archives), humanBytes(res.Bytes))
	}
	if len(problems) > 0 {
		if len(res.Archives) == 0 {
			return res, errors.New(strings.Join(problems, "; "))
		}
		res.Note += " Not done: " + strings.Join(problems, "; ")
	}
	return res, nil
}

// storageRows loads the storages a file goes to.
func (h *logArchiveHandler) storageRows(ctx context.Context, ids []uuid.UUID) ([]sqlc.Storage, error) {
	var out []sqlc.Storage
	for _, id := range ids {
		s, err := h.q.GetStorage(ctx, id)
		if err != nil {
			if isNotFound(err) {
				continue // deleted since: the others still work
			}
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (h *logArchiveHandler) deleteWindow(ctx context.Context, d logDataset, info tableInfo, w logWindow) (int64, error) {
	tag, err := h.db.Exec(ctx, fmt.Sprintf("DELETE FROM %s t WHERE %s", ident(d.Table), d.windowWhere(info, w.From, w.To)))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// vacuum lets the space of deleted rows be reused (FULL gives it back to the
// disk, locking the tables meanwhile). Failures only cost space.
func (h *logArchiveHandler) vacuum(ctx context.Context, d logDataset, full bool) error {
	opts := "ANALYZE"
	if full {
		opts = "FULL, ANALYZE"
	}
	var first error
	for _, table := range d.tables() {
		if _, err := h.db.Exec(ctx, fmt.Sprintf("VACUUM (%s) %s", opts, ident(table))); err != nil {
			slog.Warn("vacuum a log table", "table", table, "error", err)
			if first == nil {
				first = err
			}
		}
	}
	return first
}

// logCountWriter counts and hashes what goes to the file.
type logCountWriter struct {
	w io.Writer
	n int64
	t *jobs.Task
}

func (c *logCountWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	if c.t != nil {
		c.t.Add(int64(n))
	}
	return n, err
}

// writeWindow writes one period's rows into a zip, stores it, and (archive)
// deletes the rows, all in one snapshot: what's deleted is exactly what's in
// the file. A nil archive means there was nothing to take.
func (h *logArchiveHandler) writeWindow(ctx context.Context, t *jobs.Task, d logDataset, infos map[string]tableInfo,
	w logWindow, mode string, places logPlaces, note string, by *uuid.UUID, byName string) (*sqlc.LogArchive, int64, error) {
	info := infos[d.Table]
	where := d.windowWhere(info, w.From, w.To)

	tx, err := h.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))

	var rows int64
	if err := tx.QueryRow(ctx, fmt.Sprintf("SELECT count(*) FROM %s t WHERE %s", ident(d.Table), where)).Scan(&rows); err != nil {
		return nil, 0, err
	}
	if rows == 0 {
		return nil, 0, nil
	}

	jobID := t.ID
	name := fmt.Sprintf("%s_%s-%s_%s.zip", d.Key, w.From.Format("20060102"), w.To.Add(-time.Second).Format("20060102"), uuid.NewString()[:8])
	bg := context.WithoutCancel(ctx)
	a, err := h.q.CreateLogArchive(ctx, sqlc.CreateLogArchiveParams{
		Dataset: d.Key, Mode: mode, PeriodFrom: w.From, PeriodTo: w.To, FileName: name,
		Note: note, JobID: &jobID, CreatedBy: by, CreatedByName: byName,
	})
	if err != nil {
		return nil, 0, err
	}
	fail := func(err error) (*sqlc.LogArchive, int64, error) {
		if _, e := h.q.FinishLogArchive(bg, sqlc.FinishLogArchiveParams{
			ID: a.ID, State: "failed", Error: problemText(err), Tables: []byte("{}"),
		}); e != nil {
			slog.Warn("record a failed log archive", "archive", a.ID, "error", e)
		}
		return nil, 0, err
	}

	tmpDir := filepath.Join(h.dir, ".tmp")
	if err := os.MkdirAll(tmpDir, 0o750); err != nil {
		return fail(fmt.Errorf("can't write to %s: %w", h.dir, err))
	}
	tmp := filepath.Join(tmpDir, a.ID.String()+".zip")
	defer os.Remove(tmp)

	t.Update(func(pr *jobs.Progress) { pr.Phase = "Writing the file" })
	manifest, sum, size, err := h.writeZip(ctx, t, tx, d, infos, where, w, mode, note, tmp)
	if err != nil {
		return fail(err)
	}
	if manifest.Tables[0].Rows != rows {
		return fail(fmt.Errorf("counted %d rows but wrote %d", rows, manifest.Tables[0].Rows))
	}

	// Store it: storages first (from the temp file), then Morche's disk.
	t.Update(func(pr *jobs.Progress) { pr.Phase = "Storing the file" })
	var stored []sqlc.LogArchiveCopy
	var problems []string
	folder := path.Join(backupFolder(places.folder, time.Now()), d.Key)
	for _, s := range places.storages {
		c, err := h.putOnStorage(ctx, a, s, folder, tmp, size)
		if err != nil {
			problems = append(problems, s.Name+": "+problemText(err))
			continue
		}
		stored = append(stored, c)
	}
	if places.local {
		c, err := h.keepLocal(ctx, a, d, tmp)
		if err != nil {
			problems = append(problems, "Morche's disk: "+err.Error())
		} else {
			stored = append(stored, c)
		}
	}
	undo := func() {
		for _, c := range stored {
			h.removeCopy(bg, c)
		}
	}
	if len(stored) == 0 {
		return fail(errors.New("Not stored anywhere: " + strings.Join(problems, "; ")))
	}
	for _, p := range problems {
		t.Logf("Not stored on %s", p)
	}

	var deleted int64
	if mode == "archive" {
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Taking the rows out" })
		tag, err := tx.Exec(ctx, fmt.Sprintf("DELETE FROM %s t WHERE %s", ident(d.Table), where))
		if err != nil {
			undo()
			return fail(err)
		}
		if deleted = tag.RowsAffected(); deleted != rows {
			undo()
			return fail(fmt.Errorf("would have deleted %d rows, not the %d in the file; nothing was deleted", deleted, rows))
		}
	}
	if err := tx.Commit(ctx); err != nil {
		undo()
		return fail(err)
	}

	tables := map[string]int64{}
	for _, mt := range manifest.Tables {
		tables[mt.Name] = mt.Rows
	}
	tj, _ := json.Marshal(tables)
	done, err := h.q.FinishLogArchive(bg, sqlc.FinishLogArchiveParams{
		ID: a.ID, State: "stored", Rows: rows, Tables: tj, Bytes: size, Sha256: sum,
	})
	if err != nil {
		return nil, deleted, err
	}
	return &done, deleted, nil
}

// writeZip copies the window's rows of every table into a zip at file.
func (h *logArchiveHandler) writeZip(ctx context.Context, t *jobs.Task, tx pgx.Tx, d logDataset, infos map[string]tableInfo,
	where string, w logWindow, mode, note, file string) (logManifest, string, int64, error) {
	m := logManifest{
		Format: logArchiveFormat, Dataset: d.Key, Title: d.Title, Mode: mode,
		From: w.From, To: w.To, CreatedAt: time.Now().UTC(), Note: note,
	}
	_ = tx.QueryRow(ctx, "SELECT coalesce(max(version_id), 0) FROM goose_db_version").Scan(&m.Schema)

	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return m, "", 0, err
	}
	defer f.Close()
	hash := sha256.New()
	out := &logCountWriter{w: io.MultiWriter(f, hash)}
	zw := zip.NewWriter(out)

	parentKey := infos[d.Table].Key
	for i, table := range d.tables() {
		info := infos[table]
		cols := d.archivedColumns(info)
		var types []string
		for _, c := range cols {
			col, _ := info.column(c)
			types = append(types, col.Type)
		}
		var sel string
		if i == 0 {
			sel = fmt.Sprintf("SELECT %s FROM %s t WHERE %s", aliasedCols("t", cols), ident(table), where)
		} else {
			c := d.Children[i-1]
			sel = fmt.Sprintf("SELECT %s FROM %s c WHERE c.%s IN (SELECT t.%s FROM %s t WHERE %s)",
				aliasedCols("c", cols), ident(table), ident(c.Column), ident(c.Parent), ident(d.Table), where)
		}
		_ = parentKey
		entry := table + ".csv"
		zf, err := zw.CreateHeader(&zip.FileHeader{Name: entry, Method: zip.Deflate, Modified: time.Now()})
		if err != nil {
			return m, "", 0, err
		}
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Writing " + table })
		tag, err := tx.Conn().PgConn().CopyTo(ctx, &logCountWriter{w: zf, t: t}, "COPY ("+sel+") TO STDOUT WITH (FORMAT csv, HEADER true)")
		if err != nil {
			return m, "", 0, err
		}
		m.Tables = append(m.Tables, logManifestTable{Name: table, File: entry, Columns: cols, Types: types, Rows: tag.RowsAffected()})
	}

	mj, _ := json.MarshalIndent(m, "", "  ")
	if zf, err := zw.Create("manifest.json"); err != nil {
		return m, "", 0, err
	} else if _, err := zf.Write(mj); err != nil {
		return m, "", 0, err
	}
	if zf, err := zw.Create("README.txt"); err != nil {
		return m, "", 0, err
	} else if _, err := io.WriteString(zf, logReadme(m)); err != nil {
		return m, "", 0, err
	}
	if err := zw.Close(); err != nil {
		return m, "", 0, err
	}
	if err := f.Sync(); err != nil {
		return m, "", 0, err
	}
	return m, hex.EncodeToString(hash.Sum(nil)), out.n, nil
}

func aliasedCols(alias string, cols []string) string {
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = alias + "." + ident(c)
	}
	return strings.Join(q, ", ")
}

func logReadme(m logManifest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Morche log archive: %s\n\n", m.Title)
	fmt.Fprintf(&b, "Rows from %s up to (not including) %s.\n", m.From.UTC().Format(time.RFC3339), m.To.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "Written %s.\n\n", m.CreatedAt.Format(time.RFC3339))
	b.WriteString("Each table is a CSV file with a header row (PostgreSQL's CSV format:\n")
	b.WriteString("an empty unquoted field is NULL). manifest.json lists the tables, their\n")
	b.WriteString("columns and types, and how many rows each holds.\n\n")
	b.WriteString("To put the rows back, use Put back on this file in Morche\n")
	b.WriteString("(Settings › Logs & archives › Files).\n\n")
	for _, t := range m.Tables {
		fmt.Fprintf(&b, "  %-32s %d rows\n", t.File, t.Rows)
	}
	return b.String()
}

// putOnStorage uploads the file and checks what arrived.
func (h *logArchiveHandler) putOnStorage(ctx context.Context, a sqlc.LogArchive, s sqlc.Storage, folder, file string, size int64) (sqlc.LogArchiveCopy, error) {
	p := path.Join(folder, a.FileName)
	c, err := h.q.AddLogArchiveCopy(ctx, sqlc.AddLogArchiveCopyParams{ArchiveID: a.ID, StorageID: &s.ID, StorageName: s.Name, Path: p})
	if err != nil {
		return c, err
	}
	err = func() error {
		if s.ReadOnly {
			return errors.New("the storage is read-only")
		}
		conn, err := h.st.acquire(ctx, s)
		if err != nil {
			return err
		}
		defer h.st.release(conn)
		if err := conn.fs.Mkdir(ctx, folder); err != nil {
			return err
		}
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := conn.fs.Put(ctx, p, f, size); err != nil {
			removeQuietly(ctx, conn.fs, p)
			return err
		}
		e, err := conn.fs.Stat(ctx, p)
		if err != nil {
			return err
		}
		if e.Size != size {
			removeQuietly(ctx, conn.fs, p)
			return fmt.Errorf("the storage holds %s, not the %s sent", humanBytes(e.Size), humanBytes(size))
		}
		return nil
	}()
	h.setCopy(ctx, &c, err)
	return c, err
}

// keepLocal moves the temp file into the dataset's folder on Morche's disk.
// It copies instead when the rename can't (another filesystem).
func (h *logArchiveHandler) keepLocal(ctx context.Context, a sqlc.LogArchive, d logDataset, file string) (sqlc.LogArchiveCopy, error) {
	dir := filepath.Join(h.dir, d.Key)
	dst := filepath.Join(dir, a.FileName)
	c, err := h.q.AddLogArchiveCopy(ctx, sqlc.AddLogArchiveCopyParams{ArchiveID: a.ID, Local: true, Path: filepath.Join(d.Key, a.FileName)})
	if err != nil {
		return c, err
	}
	err = func() error {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
		// Hard link, so the temp file stays for nothing else and is removed.
		if err := os.Link(file, dst); err == nil {
			return nil
		}
		in, err := os.Open(file)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o640)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			os.Remove(dst)
			return err
		}
		if err := out.Sync(); err != nil {
			out.Close()
			os.Remove(dst)
			return err
		}
		return out.Close()
	}()
	h.setCopy(ctx, &c, err)
	return c, err
}

func (h *logArchiveHandler) setCopy(ctx context.Context, c *sqlc.LogArchiveCopy, err error) {
	c.State, c.Error = "stored", ""
	if err != nil {
		c.State, c.Error = "failed", problemText(err)
	}
	if e := h.q.SetLogArchiveCopy(context.WithoutCancel(ctx), sqlc.SetLogArchiveCopyParams{ID: c.ID, State: c.State, Error: c.Error}); e != nil {
		slog.Warn("record a log archive copy", "copy", c.ID, "error", e)
	}
}

// localPath is where a local copy's file is.
func (h *logArchiveHandler) localPath(c sqlc.LogArchiveCopy) string {
	return filepath.Join(h.dir, filepath.FromSlash(path.Clean("/"+c.Path)))
}

// removeCopy deletes one copy's file. Errors are logged: the row goes anyway
// only when the file is gone.
func (h *logArchiveHandler) removeCopy(ctx context.Context, c sqlc.LogArchiveCopy) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	var err error
	switch {
	case c.Local:
		if err = os.Remove(h.localPath(c)); errors.Is(err, fs.ErrNotExist) {
			err = nil
		}
	case c.StorageID != nil:
		var s sqlc.Storage
		if s, err = h.q.GetStorage(ctx, *c.StorageID); isNotFound(err) {
			err = nil // the storage is gone, and the file with it as far as Morche goes
			break
		} else if err != nil {
			break
		}
		var conn *storageConn
		if conn, err = h.st.acquire(ctx, s); err == nil {
			if err = conn.fs.Remove(ctx, c.Path); errors.Is(err, fs.ErrNotExist) {
				err = nil
			}
			h.st.release(conn)
		}
	}
	if err != nil {
		slog.Warn("remove a log archive file", "copy", c.ID, "path", c.Path, "error", err)
		return err
	}
	return h.q.DeleteLogArchiveCopy(ctx, c.ID)
}

// removeArchive deletes an archive's files and then its row. It stops at the
// first copy that can't be removed, so nothing is forgotten while it's still
// taking space somewhere.
func (h *logArchiveHandler) removeArchive(ctx context.Context, a sqlc.LogArchive) error {
	copies, err := h.q.ListLogArchiveCopies(ctx, []uuid.UUID{a.ID})
	if err != nil {
		return err
	}
	var problems []string
	for _, c := range copies {
		if c.State == "failed" {
			_ = h.q.DeleteLogArchiveCopy(ctx, c.ID)
			continue
		}
		if err := h.removeCopy(ctx, c); err != nil {
			where := "Morche's disk"
			if !c.Local {
				where = c.StorageName
			}
			problems = append(problems, where+": "+problemText(err))
		}
	}
	if len(problems) > 0 {
		return errors.New("Couldn't delete the file on " + strings.Join(problems, "; "))
	}
	return h.q.DeleteLogArchive(ctx, a.ID)
}

// ---- Getting a file back ----

// fetch puts an archive's file on Morche's disk for reading: the local copy
// itself, or one downloaded from a storage into .tmp (done removes it). It
// checks the file is the one written.
func (h *logArchiveHandler) fetch(ctx context.Context, t *jobs.Task, a sqlc.LogArchive) (string, func(), error) {
	copies, err := h.q.ListLogArchiveCopies(ctx, []uuid.UUID{a.ID})
	if err != nil {
		return "", nil, err
	}
	var problems []string
	try := func(file string, done func()) (string, func(), error) {
		if err := checkSum(file, a.Sha256); err != nil {
			done()
			return "", nil, err
		}
		return file, done, nil
	}
	for _, c := range copies {
		if c.State != "stored" || !c.Local {
			continue
		}
		f, done, err := try(h.localPath(c), func() {})
		if err == nil {
			return f, done, nil
		}
		problems = append(problems, "Morche's disk: "+err.Error())
	}
	for _, c := range copies {
		if c.State != "stored" || c.Local || c.StorageID == nil {
			continue
		}
		t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Current = "Downloading the file", c.StorageName })
		file, err := h.download(ctx, t, c, a)
		if err == nil {
			var f string
			var done func()
			if f, done, err = try(file, func() { os.Remove(file) }); err == nil {
				return f, done, nil
			}
		}
		problems = append(problems, c.StorageName+": "+problemText(err))
	}
	if len(problems) == 0 {
		return "", nil, errors.New("No copy of the file is left.")
	}
	return "", nil, errors.New("Couldn't read the file: " + strings.Join(problems, "; "))
}

func (h *logArchiveHandler) download(ctx context.Context, t *jobs.Task, c sqlc.LogArchiveCopy, a sqlc.LogArchive) (string, error) {
	s, err := h.q.GetStorage(ctx, *c.StorageID)
	if err != nil {
		return "", err
	}
	conn, err := h.st.acquire(ctx, s)
	if err != nil {
		return "", err
	}
	defer h.st.release(conn)
	in, err := conn.fs.Open(ctx, c.Path)
	if err != nil {
		return "", storageProblem(c.Path, err)
	}
	defer in.Close()
	tmpDir := filepath.Join(h.dir, ".tmp")
	if err := os.MkdirAll(tmpDir, 0o750); err != nil {
		return "", err
	}
	out, err := os.CreateTemp(tmpDir, a.ID.String()+"-*.zip")
	if err != nil {
		return "", err
	}
	t.Update(func(pr *jobs.Progress) { pr.Done, pr.Total = 0, a.Bytes })
	if _, err := io.Copy(&logCountWriter{w: out, t: t}, in); err != nil {
		out.Close()
		os.Remove(out.Name())
		return "", err
	}
	if err := out.Close(); err != nil {
		os.Remove(out.Name())
		return "", err
	}
	return out.Name(), nil
}

func checkSum(file, want string) error {
	f, err := os.Open(file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return errors.New("the file isn't there any more")
		}
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if want != "" && hex.EncodeToString(h.Sum(nil)) != want {
		return errors.New("the file was changed or damaged since it was written")
	}
	return nil
}

// openArchive opens a fetched zip and reads its manifest.
func openArchive(file string, d logDataset) (*zip.ReadCloser, logManifest, error) {
	var m logManifest
	zr, err := zip.OpenReader(file)
	if err != nil {
		return nil, m, fmt.Errorf("not a zip file: %w", err)
	}
	mf, err := zr.Open("manifest.json")
	if err != nil {
		zr.Close()
		return nil, m, errors.New("the file has no manifest.json")
	}
	err = json.NewDecoder(mf).Decode(&m)
	mf.Close()
	if err != nil {
		zr.Close()
		return nil, m, fmt.Errorf("can't read manifest.json: %w", err)
	}
	if m.Format != logArchiveFormat || m.Dataset != d.Key || len(m.Tables) == 0 {
		zr.Close()
		return nil, m, errors.New("the file isn't an archive of these logs")
	}
	for _, t := range m.Tables {
		if !slices.Contains(d.tables(), t.Name) {
			zr.Close()
			return nil, m, fmt.Errorf("the file holds an unknown table %q", t.Name)
		}
	}
	return zr, m, nil
}

// loadCSV copies one table of the archive into a temp table of text columns
// (the archive's own columns), so a newer schema can still take it.
func loadCSV(ctx context.Context, tx pgx.Tx, zr *zip.ReadCloser, mt logManifestTable, temp string) error {
	cols := make([]string, len(mt.Columns))
	for i, c := range mt.Columns {
		cols[i] = ident(c) + " text"
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf("CREATE TEMP TABLE %s (%s) ON COMMIT DROP", ident(temp), strings.Join(cols, ", "))); err != nil {
		return err
	}
	f, err := zr.Open(mt.File)
	if err != nil {
		return fmt.Errorf("the file has no %s", mt.File)
	}
	defer f.Close()
	_, err = tx.Conn().PgConn().CopyFrom(ctx, f, fmt.Sprintf("COPY %s FROM STDIN WITH (FORMAT csv, HEADER true)", ident(temp)))
	return err
}

// ---- Putting rows back ----

func (h *logArchiveHandler) runRestore(ctx context.Context, t *jobs.Task) (any, error) {
	var params logJobParams
	if err := t.Decode(&params); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(params.Archive)
	if err != nil {
		return nil, err
	}
	a, err := h.q.GetLogArchive(ctx, id)
	if err != nil {
		if isNotFound(err) {
			return nil, errors.New("The archive was deleted.")
		}
		return nil, err
	}
	d, ok := logDatasetByKey(a.Dataset)
	if !ok {
		return nil, fmt.Errorf("unknown kind of logs %q", a.Dataset)
	}
	unlock, err := h.lock(ctx, t, d.Key)
	if err != nil {
		return nil, err
	}
	defer unlock()
	defer h.stats.drop()

	if n, err := h.q.ClaimLogArchiveRestore(ctx, a.ID); err != nil {
		return nil, err
	} else if n == 0 {
		return nil, errors.New("It's being put back already.")
	}
	before := a
	bg := context.WithoutCancel(ctx)
	res, err := h.restore(ctx, t, d, a)
	if err != nil {
		if _, e := h.q.SetLogArchiveRestore(bg, sqlc.SetLogArchiveRestoreParams{
			ID: a.ID, RestoreState: before.RestoreState, RestoredAt: before.RestoredAt, RestoredRows: before.RestoredRows,
			RestoredByName: before.RestoredByName, RestoreError: problemText(err), HoldUntil: before.HoldUntil,
		}); e != nil {
			slog.Warn("record a failed log restore", "archive", a.ID, "error", e)
		}
		return nil, err
	}

	byName := ""
	if by := t.CreatedBy(); by != nil {
		if u, err := h.q.GetUser(ctx, *by); err == nil {
			byName = cmpOr(u.FullName, u.Username)
		}
	}
	now := time.Now()
	state := "done"
	var hold *time.Time
	if a.Mode == "archive" {
		state = "held"
		if params.HoldDays > 0 {
			until := now.AddDate(0, 0, params.HoldDays)
			hold = &until
		}
	}
	if _, err := h.q.SetLogArchiveRestore(bg, sqlc.SetLogArchiveRestoreParams{
		ID: a.ID, RestoreState: state, RestoredAt: &now, RestoredRows: res.Rows,
		RestoredByName: byName, HoldUntil: hold,
	}); err != nil {
		return nil, err
	}
	switch {
	case state == "done":
		res.Note = fmt.Sprintf("%d missing rows put back.", res.Rows)
	case hold != nil:
		res.Note = fmt.Sprintf("%d rows put back until %s.", res.Rows, hold.Format("2006-01-02"))
	default:
		res.Note = fmt.Sprintf("%d rows put back until you put them away.", res.Rows)
	}
	t.Logf("%s", res.Note)
	return res, nil
}

func (h *logArchiveHandler) restore(ctx context.Context, t *jobs.Task, d logDataset, a sqlc.LogArchive) (LogRestoreResult, error) {
	res := LogRestoreResult{Tables: map[string]int64{}}
	file, done, err := h.fetch(ctx, t, a)
	if err != nil {
		return res, err
	}
	defer done()
	zr, m, err := openArchive(file, d)
	if err != nil {
		return res, err
	}
	defer zr.Close()

	tx, err := h.db.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	t.Update(func(pr *jobs.Progress) { pr.Items, pr.ItemsTotal, pr.Current = 0, len(m.Tables), "" })
	for i, mt := range m.Tables {
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Putting back " + mt.Name })
		temp := fmt.Sprintf("morcheh_restore_%d", i)
		if err := loadCSV(ctx, tx, zr, mt, temp); err != nil {
			return res, fmt.Errorf("%s: %w", mt.Name, err)
		}
		info, err := readTableInfo(ctx, tx, mt.Name)
		if err != nil {
			return res, err
		}
		n, err := insertFrom(ctx, tx, mt, info, temp)
		if err != nil {
			return res, fmt.Errorf("%s: %w", mt.Name, err)
		}
		res.Tables[mt.Name] = n
		if mt.Name == d.Table {
			res.Rows = n
		}
		if n < mt.Rows {
			t.Logf("%s: %d of %d rows put back (the others are there already, or point at things deleted since).", mt.Name, n, mt.Rows)
		} else {
			t.Logf("%s: %d rows put back.", mt.Name, n)
		}
		t.Update(func(pr *jobs.Progress) { pr.Items = i + 1 })
	}
	if err := tx.Commit(ctx); err != nil {
		return res, err
	}
	return res, nil
}

// insertFrom moves the temp table's rows into the real one: only columns both
// have, cast to today's types; links to rows deleted since are cleared, or the
// row is left out when the link can't be empty; rows already there stay.
func insertFrom(ctx context.Context, tx pgx.Tx, mt logManifestTable, info tableInfo, temp string) (int64, error) {
	var cols, exprs []string
	expr := map[string]string{}
	for _, c := range info.Columns {
		if c.Generated || !slices.Contains(mt.Columns, c.Name) {
			continue
		}
		e := fmt.Sprintf("(r.%s)::%s", ident(c.Name), c.Type)
		expr[c.Name] = e
		cols = append(cols, c.Name)
	}
	if len(cols) == 0 {
		return 0, errors.New("no columns in common with the table today")
	}
	var conds []string
	nulled := map[string]string{} // column → condition that keeps its value
	for _, fk := range info.Out {
		if !slices.ContainsFunc(fk.Columns, func(c string) bool { _, ok := expr[c]; return ok }) {
			continue
		}
		var on []string
		for i, c := range fk.Columns {
			e, ok := expr[c]
			if !ok {
				on = nil
				break
			}
			on = append(on, fmt.Sprintf("x.%s = %s", ident(fk.RefCols[i]), e))
		}
		if on == nil {
			continue // a column it doesn't hold: the table's default fills it
		}
		exists := fmt.Sprintf("EXISTS (SELECT 1 FROM %s x WHERE %s)", fk.RefTable, strings.Join(on, " AND "))
		nullable := true
		var anyNull []string
		for _, c := range fk.Columns {
			col, _ := info.column(c)
			nullable = nullable && col.Nullable
			anyNull = append(anyNull, fmt.Sprintf("r.%s IS NULL", ident(c)))
		}
		keep := "(" + strings.Join(anyNull, " OR ") + " OR " + exists + ")"
		if nullable {
			for _, c := range fk.Columns {
				if prev, ok := nulled[c]; ok {
					nulled[c] = prev + " AND " + keep
				} else {
					nulled[c] = keep
				}
			}
		} else {
			conds = append(conds, keep)
		}
	}
	for _, c := range cols {
		e := expr[c]
		if keep, ok := nulled[c]; ok {
			e = fmt.Sprintf("CASE WHEN %s THEN %s END", keep, e)
		}
		exprs = append(exprs, e)
	}
	sql := fmt.Sprintf("INSERT INTO %s (%s) OVERRIDING SYSTEM VALUE SELECT %s FROM %s r",
		ident(mt.Name), identList(cols), strings.Join(exprs, ", "), ident(temp))
	if len(conds) > 0 {
		sql += " WHERE " + strings.Join(conds, " AND ")
	}
	tag, err := tx.Exec(ctx, sql+" ON CONFLICT DO NOTHING")
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ---- Putting restored rows away again ----

func (h *logArchiveHandler) runPutAway(ctx context.Context, t *jobs.Task) (any, error) {
	var params logJobParams
	if err := t.Decode(&params); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(params.Archive)
	if err != nil {
		return nil, err
	}
	defer func() {
		h.mu.Lock()
		delete(h.putting, id)
		h.mu.Unlock()
	}()
	a, err := h.q.GetLogArchive(ctx, id)
	if err != nil {
		if isNotFound(err) {
			return nil, errors.New("The archive was deleted.")
		}
		return nil, err
	}
	if a.RestoreState != "held" {
		return LogRestoreResult{Note: "Its rows aren't back, so there was nothing to put away."}, nil
	}
	d, ok := logDatasetByKey(a.Dataset)
	if !ok {
		return nil, fmt.Errorf("unknown kind of logs %q", a.Dataset)
	}
	unlock, err := h.lock(ctx, t, d.Key)
	if err != nil {
		return nil, err
	}
	defer unlock()
	defer h.stats.drop()

	file, done, err := h.fetch(ctx, t, a)
	if err != nil {
		return nil, err
	}
	defer done()
	zr, m, err := openArchive(file, d)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	info, err := readTableInfo(ctx, h.db, d.Table)
	if err != nil {
		return nil, err
	}
	if len(info.Key) == 0 {
		return nil, fmt.Errorf("%s has no primary key", d.Table)
	}
	mt := m.Tables[0]
	for _, k := range info.Key {
		if !slices.Contains(mt.Columns, k) {
			return nil, fmt.Errorf("the file lacks the key column %s", k)
		}
	}
	t.Update(func(pr *jobs.Progress) { pr.Phase = "Taking the rows out" })
	tx, err := h.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err := loadCSV(ctx, tx, zr, mt, "morcheh_putaway"); err != nil {
		return nil, err
	}
	// Only rows the file holds go: anything else in the period stays.
	var on []string
	for _, k := range info.Key {
		col, _ := info.column(k)
		on = append(on, fmt.Sprintf("t.%s = (r.%s)::%s", ident(k), ident(k), col.Type))
	}
	tag, err := tx.Exec(ctx, fmt.Sprintf("DELETE FROM %s t USING %s r WHERE %s AND %s",
		ident(d.Table), ident("morcheh_putaway"), strings.Join(on, " AND "), d.windowWhere(info, a.PeriodFrom, a.PeriodTo)))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	n := tag.RowsAffected()
	if _, err := h.q.SetLogArchiveRestore(context.WithoutCancel(ctx), sqlc.SetLogArchiveRestoreParams{
		ID: a.ID, RestoreState: "", RestoredAt: a.RestoredAt, RestoredRows: a.RestoredRows, RestoredByName: a.RestoredByName,
	}); err != nil {
		return nil, err
	}
	t.Update(func(pr *jobs.Progress) { pr.Phase = "Tidying the tables" })
	h.vacuum(ctx, d, false)
	res := LogRestoreResult{Rows: n, Tables: map[string]int64{d.Table: n}, Note: fmt.Sprintf("%d rows taken out again; the file still holds them.", n)}
	t.Logf("%s", res.Note)
	return res, nil
}

// ---- Compacting ----

func (h *logArchiveHandler) runCompact(ctx context.Context, t *jobs.Task) (any, error) {
	var params logJobParams
	if err := t.Decode(&params); err != nil {
		return nil, err
	}
	d, ok := logDatasetByKey(params.Dataset)
	if !ok {
		return nil, fmt.Errorf("unknown kind of logs %q", params.Dataset)
	}
	unlock, err := h.lock(ctx, t, d.Key)
	if err != nil {
		return nil, err
	}
	defer unlock()
	defer h.stats.drop()
	before, _, err := h.datasetBytes(ctx, d)
	if err != nil {
		return nil, err
	}
	t.Update(func(pr *jobs.Progress) {
		pr.Phase = "Compacting"
		pr.Locked = params.Full // VACUUM FULL can't be stopped half way
	})
	if err := h.vacuum(ctx, d, params.Full); err != nil {
		return nil, err
	}
	after, _, err := h.datasetBytes(ctx, d)
	if err != nil {
		return nil, err
	}
	note := fmt.Sprintf("%s before, %s now.", humanBytes(before), humanBytes(after))
	t.Logf("%s", note)
	return map[string]any{"before": before, "after": after, "note": note}, nil
}

// ---- The clock ----

// startLogArchiveScheduler runs due policies, puts away rows whose hold is
// over and deletes files past their policy's keep days.
func startLogArchiveScheduler(h *logArchiveHandler, every time.Duration) {
	ctx := context.Background()
	if err := h.q.InterruptLogArchives(ctx); err != nil {
		slog.Warn("mark interrupted log archives", "error", err)
	}
	if err := h.q.ResetLogArchiveRestores(ctx); err != nil {
		slog.Warn("reset interrupted log restores", "error", err)
	}
	h.loadOwners(ctx)
	if every <= 0 {
		return
	}
	go func() {
		h.fixNext(ctx)
		var expired time.Time
		for range time.Tick(every) {
			h.fire(ctx)
			h.holds(ctx)
			if time.Since(expired) >= time.Hour {
				expired = time.Now()
				h.expire(ctx)
			}
		}
	}()
}

func (h *logArchiveHandler) fixNext(ctx context.Context) {
	ps, err := h.q.LogArchivePoliciesWithoutNext(ctx)
	if err != nil {
		slog.Warn("list log policies without a next run", "error", err)
		return
	}
	for _, p := range ps {
		if err := h.q.SetLogArchivePolicyNext(ctx, sqlc.SetLogArchivePolicyNextParams{
			Dataset: p.Dataset, NextRunAt: nextRun(p.Cron, p.Timezone, time.Now()),
		}); err != nil {
			slog.Warn("set a log policy's next run", "dataset", p.Dataset, "error", err)
		}
	}
}

func (h *logArchiveHandler) fire(ctx context.Context) {
	due, err := h.q.DueLogArchivePolicies(ctx)
	if err != nil {
		slog.Warn("list due log policies", "error", err)
		return
	}
	now := time.Now()
	for _, p := range due {
		n, err := h.q.ClaimLogArchivePolicy(ctx, sqlc.ClaimLogArchivePolicyParams{
			Dataset: p.Dataset, Due: p.NextRunAt, NextRunAt: nextRun(p.Cron, p.Timezone, now),
		})
		if err != nil || n == 0 {
			if err != nil {
				slog.Warn("claim a log policy", "dataset", p.Dataset, "error", err)
			}
			continue
		}
		if _, err := h.startRun(ctx, p.Dataset, p.StorageIds, nil); err != nil {
			slog.Warn("start a log policy", "dataset", p.Dataset, "error", err)
		}
	}
}

// startRun submits a policy's run (or an export).
func (h *logArchiveHandler) startRun(ctx context.Context, key string, refs []uuid.UUID, export *logExport) (sqlc.Job, error) {
	d, _ := logDatasetByKey(key)
	title := "Apply the retention policy to " + strings.ToLower(d.Title)
	if export != nil {
		title = "Export " + strings.ToLower(d.Title)
	}
	spec := jobs.Spec{
		Kind: logArchiveKind, Title: title, Refs: refs,
		Params: logJobParams{Dataset: key, Export: export},
		Target: JobPlace{Dataset: key},
	}
	if p := principalOf(ctx); p != nil {
		spec.CreatedBy = p.ID()
	}
	return h.runner.Submit(ctx, spec)
}

// holds starts a put-away for every restore whose time is up.
func (h *logArchiveHandler) holds(ctx context.Context) {
	due, err := h.q.ExpiredLogArchiveHolds(ctx)
	if err != nil {
		slog.Warn("list expired log holds", "error", err)
		return
	}
	for _, a := range due {
		h.mu.Lock()
		started := h.putting[a.ID]
		h.putting[a.ID] = true
		h.mu.Unlock()
		if started {
			continue
		}
		if _, err := h.runner.Submit(ctx, h.putAwaySpec(a)); err != nil {
			h.mu.Lock()
			delete(h.putting, a.ID)
			h.mu.Unlock()
			slog.Warn("start a log put-away", "archive", a.ID, "error", err)
		}
	}
}

func (h *logArchiveHandler) putAwaySpec(a sqlc.LogArchive) jobs.Spec {
	d, _ := logDatasetByKey(a.Dataset)
	return jobs.Spec{
		Kind:   logPutAwayKind,
		Title:  "Put away " + strings.ToLower(d.Title) + " from " + a.FileName,
		Params: logJobParams{Dataset: a.Dataset, Archive: a.ID.String()},
		Target: JobPlace{Dataset: a.Dataset, Archive: a.ID.String()},
	}
}

// expire deletes archive files their policy no longer keeps.
func (h *logArchiveHandler) expire(ctx context.Context) {
	old, err := h.q.ExpiredLogArchives(ctx)
	if err != nil {
		slog.Warn("list expired log archives", "error", err)
		return
	}
	for _, a := range old {
		if err := h.removeArchive(ctx, a); err != nil {
			slog.Warn("delete an expired log archive", "archive", a.ID, "error", err)
		}
	}
	if len(old) > 0 {
		h.stats.drop()
	}
}
