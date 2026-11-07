package api

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/storage"
)

// Insights: uptime, latency, space and activity of the storages, for the
// Storage page's charts. Check history comes from every recorded check
// (storage_checks), space from measurements (storage_usage) made by walking
// each storage: daily in the background (STORAGE_SCAN_INTERVAL) or on demand.

const (
	// A measurement stops after this long and is kept as partial.
	storageScanTimeout = 30 * time.Minute
	// Biggest top-level folders kept per measurement; the rest are summed.
	usageTopParts = 12
	// Measurements are kept this long (one a day is about 400 rows).
	usageKeep       = 400 * 24 * time.Hour
	storageScanKind = "storage-scan"
)

// ---- Response types ----

type StorageUsagePart struct {
	Name  string `json:"name" doc:"Top-level folder or bucket; empty = files right in the top folder"`
	Bytes int64  `json:"bytes"`
	Files int64  `json:"files"`
	Other bool   `json:"other" doc:"Everything past the biggest folders, summed"`
}

type StorageUsageInfo struct {
	MeasuredAt time.Time          `json:"measured_at"`
	UsedBytes  int64              `json:"used_bytes"`
	Files      int64              `json:"files"`
	Folders    int64              `json:"folders"`
	TotalBytes *int64             `json:"total_bytes" nullable:"true" doc:"Size of the disk behind it (SFTP only)"`
	FreeBytes  *int64             `json:"free_bytes" nullable:"true" doc:"Free space on that disk (SFTP only)"`
	Partial    bool               `json:"partial" doc:"Stopped before the end: too big to walk in time"`
	Top        []StorageUsagePart `json:"top"`
	DurationMs int32              `json:"duration_ms"`
}

type StorageActivityTotals struct {
	Ok     int64 `json:"ok"`
	Failed int64 `json:"failed"`
	Bytes  int64 `json:"bytes"`
}

type StorageInsight struct {
	ID          string `json:"id" format:"uuid"`
	WorkspaceID string `json:"workspace_id" format:"uuid"`
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	Provider    string `json:"provider"`
	Status      string `json:"status"`
	LatencyMs   *int32 `json:"latency_ms" nullable:"true" doc:"From the last check"`
	// Over the range.
	Checks       int64                 `json:"checks"`
	Failures     int64                 `json:"failures"`
	Uptime       *float64              `json:"uptime" nullable:"true" doc:"Share of checks that found it online, 0–1; null without checks"`
	LatencyAvg   *float64              `json:"latency_avg" nullable:"true"`
	LatencyP95   *float64              `json:"latency_p95" nullable:"true"`
	HistorySince *time.Time            `json:"history_since" nullable:"true" doc:"First check in the range"`
	Activity     StorageActivityTotals `json:"activity"`
	Usage        *StorageUsageInfo     `json:"usage,omitempty" doc:"Last measurement, any age; missing = never measured"`
}

type StorageLatencyPoint struct {
	T          time.Time `json:"t"`
	StorageID  string    `json:"storage_id" format:"uuid"`
	Checks     int64     `json:"checks"`
	Failures   int64     `json:"failures"`
	LatencyAvg float64   `json:"latency_avg" doc:"Online checks only; 0 when none"`
	LatencyMax int32     `json:"latency_max"`
}

type StorageActivityPoint struct {
	T      time.Time `json:"t"`
	Kind   string    `json:"kind" enum:"transfer,sync,backup" doc:"transfer = copies and moves, sync = cron job runs, backup = database backups"`
	Ok     int64     `json:"ok"`
	Failed int64     `json:"failed"`
	Bytes  int64     `json:"bytes"`
	Files  int64     `json:"files"`
}

type StorageUsagePoint struct {
	StorageID string    `json:"storage_id" format:"uuid"`
	T         time.Time `json:"t"`
	UsedBytes int64     `json:"used_bytes"`
	Files     int64     `json:"files"`
}

type StorageStatusEvent struct {
	StorageID  string    `json:"storage_id" format:"uuid"`
	At         time.Time `json:"at"`
	Status     string    `json:"status"`
	PrevStatus string    `json:"prev_status"`
	Message    string    `json:"message"`
}

type StorageInsights struct {
	Range         string                 `json:"range"`
	From          time.Time              `json:"from"`
	To            time.Time              `json:"to"`
	BucketSeconds int                    `json:"bucket_seconds"`
	Storages      []StorageInsight       `json:"storages"`
	Latency       []StorageLatencyPoint  `json:"latency"`
	Activity      []StorageActivityPoint `json:"activity"`
	Usage         []StorageUsagePoint    `json:"usage" doc:"Measurements in the range, plus each storage's last one before it"`
	Events        []StorageStatusEvent   `json:"events" doc:"Status changes, newest first (at most 200)"`
}

type StorageInsightsInput struct {
	Range string `query:"range" enum:"24h,7d,30d" default:"7d"`
	TZ    string `query:"tz" doc:"IANA time zone the buckets line up with (days start at its midnight)" example:"Europe/Berlin"`
}

// window turns a range into [from, now] split in buckets that start at
// midnight in loc.
func insightWindow(rng string, loc *time.Location, now time.Time) (from time.Time, bucket time.Duration) {
	span, bucket := 7*24*time.Hour, 4*time.Hour
	switch rng {
	case "24h":
		span, bucket = 24*time.Hour, 30*time.Minute
	case "30d":
		span, bucket = 30*24*time.Hour, 24*time.Hour
	}
	start := now.Add(-span).In(loc)
	origin := time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, loc)
	// The bucket holding start, so the first one isn't cut short.
	from = origin.Add(start.Sub(origin) / bucket * bucket)
	return from, bucket
}

func toUsageInfo(u sqlc.StorageUsage) *StorageUsageInfo {
	out := &StorageUsageInfo{
		MeasuredAt: u.MeasuredAt, UsedBytes: u.UsedBytes, Files: u.Files, Folders: u.Folders,
		TotalBytes: u.TotalBytes, FreeBytes: u.FreeBytes, Partial: u.Partial, DurationMs: u.DurationMs,
		Top: []StorageUsagePart{},
	}
	_ = json.Unmarshal(u.Top, &out.Top)
	return out
}

func (h *storageHandler) insights(ctx context.Context, in *StorageInsightsInput) (*struct{ Body StorageInsights }, error) {
	loc := time.UTC
	if in.TZ != "" {
		if l, err := time.LoadLocation(in.TZ); err == nil {
			loc = l
		}
	}
	now := time.Now()
	from, bucket := insightWindow(in.Range, loc, now)

	sc := principalOf(ctx).scope()
	rows, err := h.q.ListStorages(ctx, sqlc.ListStoragesParams{
		SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, StorageIds: sc.storages, WorkspaceID: sc.current,
	})
	if err != nil {
		return nil, internalError(err)
	}
	out := &struct{ Body StorageInsights }{}
	b := &out.Body
	b.Range, b.From, b.To, b.BucketSeconds = in.Range, from, now, int(bucket.Seconds())
	b.Storages, b.Latency, b.Activity = []StorageInsight{}, []StorageLatencyPoint{}, []StorageActivityPoint{}
	b.Usage, b.Events = []StorageUsagePoint{}, []StorageStatusEvent{}
	if len(rows) == 0 {
		return out, nil
	}

	ids := make([]uuid.UUID, len(rows))
	index := make(map[uuid.UUID]int, len(rows))
	for i, r := range rows {
		ids[i], index[r.ID] = r.ID, i
		b.Storages = append(b.Storages, StorageInsight{
			ID: r.ID.String(), WorkspaceID: r.WorkspaceID.String(), Name: r.Name,
			Protocol: r.Protocol, Provider: r.Provider, Status: r.Status, LatencyMs: r.LatencyMs,
		})
	}
	secs := bucket.Seconds()

	summary, err := h.q.StorageCheckSummary(ctx, sqlc.StorageCheckSummaryParams{Ids: ids, Since: from})
	if err != nil {
		return nil, internalError(err)
	}
	for _, s := range summary {
		st := &b.Storages[index[s.StorageID]]
		st.Checks, st.Failures = s.Checks, s.Failures
		if s.Checks > 0 {
			up := float64(s.Checks-s.Failures) / float64(s.Checks)
			st.Uptime = &up
			first := s.FirstAt
			st.HistorySince = &first
		}
		if s.Checks > s.Failures {
			avg, p95 := s.LatencyAvg, s.LatencyP95
			st.LatencyAvg, st.LatencyP95 = &avg, &p95
		}
	}

	series, err := h.q.StorageCheckSeries(ctx, sqlc.StorageCheckSeriesParams{BucketSecs: secs, Origin: from, Ids: ids, Since: from})
	if err != nil {
		return nil, internalError(err)
	}
	for _, p := range series {
		b.Latency = append(b.Latency, StorageLatencyPoint{
			T: p.T, StorageID: p.StorageID.String(), Checks: p.Checks, Failures: p.Failures,
			LatencyAvg: p.LatencyAvg, LatencyMax: p.LatencyMax,
		})
	}

	activity, err := h.q.StorageActivitySeries(ctx, sqlc.StorageActivitySeriesParams{BucketSecs: secs, Origin: from, Ids: ids, Since: from})
	if err != nil {
		return nil, internalError(err)
	}
	for _, a := range activity {
		b.Activity = append(b.Activity, StorageActivityPoint{T: a.T, Kind: a.Kind, Ok: a.Ok, Failed: a.Failed, Bytes: a.Bytes, Files: a.Files})
	}
	per, err := h.q.StorageActivityByStorage(ctx, sqlc.StorageActivityByStorageParams{Ids: ids, Since: from})
	if err != nil {
		return nil, internalError(err)
	}
	for _, a := range per {
		if i, ok := index[a.StorageID]; ok {
			b.Storages[i].Activity = StorageActivityTotals{Ok: a.Ok, Failed: a.Failed, Bytes: a.Bytes}
		}
	}

	latest, err := h.q.LatestStorageUsage(ctx, ids)
	if err != nil {
		return nil, internalError(err)
	}
	for _, u := range latest {
		b.Storages[index[u.StorageID]].Usage = toUsageInfo(u)
	}
	history, err := h.q.StorageUsageHistory(ctx, sqlc.StorageUsageHistoryParams{Ids: ids, Since: from})
	if err != nil {
		return nil, internalError(err)
	}
	for _, u := range history {
		b.Usage = append(b.Usage, StorageUsagePoint{StorageID: u.StorageID.String(), T: u.MeasuredAt, UsedBytes: u.UsedBytes, Files: u.Files})
	}

	events, err := h.q.StorageStatusChanges(ctx, sqlc.StorageStatusChangesParams{Ids: ids, Lookback: from.Add(-24 * time.Hour), Since: from})
	if err != nil {
		return nil, internalError(err)
	}
	for _, e := range events {
		b.Events = append(b.Events, StorageStatusEvent{
			StorageID: e.StorageID.String(), At: e.CheckedAt, Status: e.Status, PrevStatus: e.PrevStatus, Message: e.Message,
		})
	}
	return out, nil
}

// ---- Measuring ----

// One measurement per storage at a time (background or a job).
var storageScans sync.Map

var errMeasuring = huma.Error409Conflict("It's being measured already")

// measure walks the whole storage over a fresh connection (leaving the
// pooled one to whoever is browsing) and stores what it found. progress, if
// set, is called every thousand files.
func (h *storageHandler) measure(ctx context.Context, row sqlc.Storage, progress func(files, bytes int64)) (sqlc.StorageUsage, error) {
	if _, busy := storageScans.LoadOrStore(row.ID, true); busy {
		return sqlc.StorageUsage{}, errMeasuring
	}
	defer storageScans.Delete(row.ID)

	cfg, err := h.config(row)
	if err != nil {
		return sqlc.StorageUsage{}, internalError(err)
	}
	f, info, err := storage.Open(ctx, cfg)
	h.record(ctx, row, info, err)
	if err != nil {
		return sqlc.StorageUsage{}, huma.Error502BadGateway(storage.Message(err))
	}
	defer f.Close()

	start := time.Now()
	p := sqlc.InsertStorageUsageParams{StorageID: row.ID}
	if sp, err := storage.SpaceOf(ctx, f); err == nil && sp.Total > 0 {
		p.TotalBytes, p.FreeBytes = &sp.Total, &sp.Free
	}
	parts := map[string]*StorageUsagePart{}
	part := func(name string) *StorageUsagePart {
		if parts[name] == nil {
			parts[name] = &StorageUsagePart{Name: name}
		}
		return parts[name]
	}
	wctx, cancel := context.WithTimeout(ctx, storageScanTimeout)
	defer cancel()
	err = storage.Walk(wctx, f, "/", func(e storage.Entry) error {
		top, rest, _ := strings.Cut(strings.TrimPrefix(e.Path, "/"), "/")
		if e.Dir {
			p.Folders++
			if rest == "" {
				part(top)
			}
			return nil
		}
		if rest == "" {
			top = "" // a file right in the top folder
		}
		pt := part(top)
		pt.Bytes += e.Size
		pt.Files++
		p.Files++
		p.UsedBytes += e.Size
		if progress != nil && p.Files%1000 == 0 {
			progress(p.Files, p.UsedBytes)
		}
		return nil
	})
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		p.Partial, err = true, nil
	}
	if err != nil {
		return sqlc.StorageUsage{}, storageProblem("/", err)
	}

	list := make([]StorageUsagePart, 0, len(parts))
	for _, pt := range parts {
		list = append(list, *pt)
	}
	slices.SortFunc(list, func(a, b StorageUsagePart) int {
		return cmp.Or(cmp.Compare(b.Bytes, a.Bytes), cmp.Compare(a.Name, b.Name))
	})
	if len(list) > usageTopParts {
		other := StorageUsagePart{Other: true}
		for _, pt := range list[usageTopParts:] {
			other.Bytes += pt.Bytes
			other.Files += pt.Files
		}
		list = append(list[:usageTopParts], other)
	}
	p.Top, _ = json.Marshal(list)
	p.DurationMs = int32(time.Since(start).Milliseconds())
	u, err := h.q.InsertStorageUsage(context.WithoutCancel(ctx), p)
	if err != nil {
		return u, internalError(err)
	}
	return u, nil
}

type storageScanParams struct {
	StorageID string `json:"storage_id"`
}

func (h *storageHandler) runStorageScan(ctx context.Context, t *jobs.Task) (any, error) {
	var p storageScanParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(p.StorageID)
	if err != nil {
		return nil, err
	}
	row, err := h.q.GetStorage(ctx, id)
	if err != nil {
		return nil, errors.New("The storage was removed")
	}
	t.Update(func(pr *jobs.Progress) { pr.Phase = "Counting files" })
	u, err := h.measure(ctx, row, func(files, bytes int64) {
		t.Update(func(pr *jobs.Progress) { pr.Items, pr.Done = int(files), bytes })
	})
	if err != nil {
		return nil, err
	}
	note := ""
	if u.Partial {
		note = " (stopped early: too big to walk in time)"
	}
	t.Logf("%d files in %d folders, %s%s", u.Files, u.Folders, humanBytes(u.UsedBytes), note)
	return toUsageInfo(u), nil
}

// startStorageScanner measures each online storage once per `every` (0 =
// never on its own) and prunes old history.
func startStorageScanner(h *storageHandler, every, keep time.Duration) {
	go func() {
		time.Sleep(time.Minute) // let the monitor find out what's online first
		failed := map[uuid.UUID]time.Time{}
		var pruned time.Time
		for {
			ctx := context.Background()
			if keep > 0 && time.Since(pruned) > time.Hour {
				pruned = time.Now()
				if _, err := h.q.PruneStorageChecks(ctx, time.Now().Add(-keep)); err != nil {
					slog.Warn("prune storage checks", "error", err)
				}
				if _, err := h.q.PruneStorageUsage(ctx, time.Now().Add(-usageKeep)); err != nil {
					slog.Warn("prune storage usage", "error", err)
				}
			}
			if every > 0 {
				h.scanDue(ctx, every, failed)
			}
			time.Sleep(10 * time.Minute)
		}
	}()
}

// scanDue measures the storages due, one at a time; one that failed waits
// a full interval before the next try.
func (h *storageHandler) scanDue(ctx context.Context, every time.Duration, failed map[uuid.UUID]time.Time) {
	due, err := h.q.ListStoragesDueForScan(ctx, time.Now().Add(-every))
	if err != nil {
		slog.Warn("list storages due for measuring", "error", err)
		return
	}
	for _, row := range due {
		if t, ok := failed[row.ID]; ok && time.Since(t) < every {
			continue
		}
		sctx, cancel := context.WithTimeout(ctx, storageScanTimeout+5*time.Minute)
		_, err := h.measure(sctx, row, nil)
		cancel()
		if err != nil && !errors.Is(err, errMeasuring) {
			failed[row.ID] = time.Now()
			slog.Warn("measure storage", "storage", row.ID, "error", err)
		} else {
			delete(failed, row.ID)
		}
	}
}

func registerStorageInsights(api huma.API, h *storageHandler) {
	tags := []string{"Storage"}

	huma.Register(api, huma.Operation{
		OperationID: "storage-insights",
		Method:      http.MethodGet,
		Path:        "/storages/insights",
		Summary:     "Uptime, latency, space and activity of the storages",
		Description: "For the storages this person can see (in the selected workspace). Latency and activity come bucketed: 30 min for 24h, 4 h for 7d, a day for 30d.",
		Tags:        tags,
	}, h.insights)

	huma.Register(api, huma.Operation{
		OperationID:   "measure-storage-usage",
		Method:        http.MethodPost,
		Path:          "/storages/{id}/usage/measure",
		Summary:       "Measure how much a storage holds",
		Description:   "Walks the whole storage in the background (a job of kind storage-scan) and stores the result for Insights. 409 while it's being measured.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		ID string `path:"id" format:"uuid"`
	}) (*JobOutput, error) {
		row, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if _, busy := storageScans.Load(row.ID); busy {
			return nil, errMeasuring
		}
		return submit(ctx, h.servers.jobs, jobs.Spec{
			Kind: storageScanKind, Title: "Measure " + row.Name, Refs: placeRefs(in.ID),
			Params: storageScanParams{in.ID},
			Target: &JobPlace{StorageID: in.ID, Path: "/", Name: row.Name},
		})
	})
	h.servers.jobs.Handle(storageScanKind, h.runStorageScan)
}
