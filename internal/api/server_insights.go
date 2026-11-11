package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/sshprobe"
	"github.com/morcheh/backend/internal/sysstats"
	"github.com/morcheh/backend/internal/terminal"
)

// Insights for the Servers page: uptime and response time from every
// connection check (rolled up in 5-minute buckets), status changes, and CPU,
// memory, disk and network read from each online Linux server every
// SERVER_SAMPLE_INTERVAL.

const (
	sampleConcurrency = 4
	sampleTimeout     = 30 * time.Second
	// A server that isn't Linux is asked again after this long.
	sampleUnsupportedWait = 24 * time.Hour
)

// ---- Recording ----

// recordCheckHistory adds a check to its bucket and notes a status change.
// History is a nice-to-have: failures are logged, never returned.
func (h *serverHandler) recordCheckHistory(ctx context.Context, prev sqlc.Server, res sshprobe.Result) {
	b := sqlc.RecordServerCheckBucketParams{ServerID: prev.ID}
	if res.Status == sshprobe.StatusOnline {
		b.LatencySum, b.LatencyMax = int64(res.LatencyMs), res.LatencyMs
	} else {
		b.Failures = 1
	}
	if err := h.q.RecordServerCheckBucket(ctx, b); err != nil {
		slog.Warn("record server check history", "server", prev.ID, "error", err)
	}
	if h.alerts != nil {
		h.alerts.onStatus(ctx, prev, res)
	}
	// The first check of a new server isn't a change.
	if prev.LastCheckedAt == nil || prev.Status == res.Status {
		return
	}
	msg := res.Message
	if res.Status == sshprobe.StatusOnline {
		msg = ""
	}
	if err := h.q.InsertServerStatusChange(ctx, sqlc.InsertServerStatusChangeParams{
		ServerID: prev.ID, Status: res.Status, PrevStatus: prev.Status, Message: msg,
	}); err != nil {
		slog.Warn("record server status change", "server", prev.ID, "error", err)
	}
}

func startServerSampler(h *serverHandler, every, keep time.Duration) {
	go func() {
		time.Sleep(30 * time.Second) // let the monitor find out what's online first
		skip := map[uuid.UUID]time.Time{}
		var pruned time.Time
		for {
			ctx := context.Background()
			if keep > 0 && time.Since(pruned) > time.Hour {
				pruned = time.Now()
				before := pruned.Add(-keep)
				if _, err := h.q.PruneServerCheckBuckets(ctx, before); err != nil {
					slog.Warn("prune server check history", "error", err)
				}
				if _, err := h.q.PruneServerStatusChanges(ctx, before); err != nil {
					slog.Warn("prune server status changes", "error", err)
				}
				if _, err := h.q.PruneServerSamples(ctx, before); err != nil {
					slog.Warn("prune server samples", "error", err)
				}
				if _, err := h.q.PruneAlertEvents(ctx, before); err != nil {
					slog.Warn("prune alert events", "error", err)
				}
				if _, err := h.q.PruneAlertMutes(ctx, before); err != nil {
					slog.Warn("prune alert mutes", "error", err)
				}
			}
			if every <= 0 {
				time.Sleep(10 * time.Minute)
				continue
			}
			started := time.Now()
			h.sampleAll(ctx, skip)
			time.Sleep(max(every-time.Since(started), time.Second))
		}
	}()
}

// sampleAll reads every online server's resources, a few at a time.
func (h *serverHandler) sampleAll(ctx context.Context, skip map[uuid.UUID]time.Time) {
	servers, err := h.q.ListServersToSample(ctx)
	if err != nil {
		slog.Warn("list servers to sample", "error", err)
		return
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, sampleConcurrency)
	for _, s := range servers {
		if t, ok := skip[s.ID]; ok && time.Since(t) < sampleUnsupportedWait {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			sctx, cancel := context.WithTimeout(ctx, sampleTimeout)
			defer cancel()
			err := h.sample(sctx, s)
			if errors.Is(err, sysstats.ErrUnsupported) {
				mu.Lock()
				skip[s.ID] = time.Now()
				mu.Unlock()
			} else if err != nil {
				slog.Debug("sample server", "server", s.ID, "error", err)
			}
		}()
	}
	wg.Wait()
}

func (h *serverHandler) sample(ctx context.Context, srv sqlc.Server) error {
	id := srv.ID
	var out string
	if err := h.withConn(ctx, id.String(), func(c *sshpool.Conn) (err error) {
		out, err = run(ctx, c, sysstats.Script)
		return err
	}); err != nil {
		return err
	}
	st, err := sysstats.Parse(out, time.Now().UTC())
	if err != nil {
		return err
	}
	p := sqlc.InsertServerSampleParams{
		ServerID: id, At: st.CollectedAt,
		CpuPercent: st.CPU.UsagePercent, IowaitPercent: st.CPU.IOWaitPercent,
		Cores: int32(st.CPU.Cores), Load1: st.CPU.Load1,
		MemUsedBytes: st.Memory.UsedBytes, MemTotalBytes: st.Memory.TotalBytes,
		SwapUsedBytes: st.Memory.SwapUsedBytes, SwapTotalBytes: st.Memory.SwapTotalBytes,
		RxBytesPerSec: st.Network.RxBytesPerSec, TxBytesPerSec: st.Network.TxBytesPerSec,
	}
	disks := make([]sampleDisk, 0, len(st.Disks))
	// Disks come largest first: / if it's there, else the largest.
	for i, d := range st.Disks {
		disks = append(disks, sampleDisk{Mount: d.Mount, Used: d.UsedBytes, Total: d.TotalBytes, Percent: d.UsedPercent})
		if i == 0 || d.Mount == "/" {
			p.DiskUsedBytes, p.DiskTotalBytes = d.UsedBytes, d.TotalBytes
		}
		if d.UsedPercent > p.DiskMaxPercent || p.DiskMaxMount == "" {
			p.DiskMaxPercent, p.DiskMaxMount = d.UsedPercent, d.Mount
		}
	}
	p.Disks, _ = json.Marshal(disks)
	ctx = context.WithoutCancel(ctx)
	if err := h.q.InsertServerSample(ctx, p); err != nil {
		return err
	}
	if h.alerts != nil {
		ms := metricSampleOf(sqlc.ServerSample(p))
		ms.services = func(ctx context.Context, unit string) ([]string, error) {
			return h.failedServices(ctx, id, unit)
		}
		h.alerts.onSample(ctx, srv, ms)
	}
	return nil
}

// failedServices lists a server's failed systemd services, or, with a unit,
// that unit's state when it isn't running (empty when it is). Servers
// without systemd give an error.
func (h *serverHandler) failedServices(ctx context.Context, id uuid.UUID, unit string) ([]string, error) {
	cmd := "command -v systemctl >/dev/null 2>&1 || exit 3; " +
		"systemctl list-units --type=service --state=failed --no-legend --plain --no-pager 2>/dev/null | awk '{print $1}'"
	if unit != "" {
		cmd = "command -v systemctl >/dev/null 2>&1 || exit 3; systemctl is-active -- " +
			terminal.ShellQuote(unit) + " 2>/dev/null; true"
	}
	var out string
	if err := h.withConn(ctx, id.String(), func(c *sshpool.Conn) (err error) {
		out, err = run(ctx, c, cmd)
		return err
	}); err != nil {
		return nil, err
	}
	var names []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if unit != "" {
			// is-active says active, reloading, activating… or inactive/failed.
			if l == "inactive" || l == "failed" {
				names = append(names, l)
			}
			continue
		}
		names = append(names, strings.TrimPrefix(l, "● "))
	}
	return names, nil
}

// sampleDisk is one filesystem in server_samples.disks.
type sampleDisk struct {
	Mount string `json:"mount"`
	Used  int64  `json:"used"`
	Total int64  `json:"total"`
	// df's Use%: of what non-root users can use, so a bit above used/total.
	Percent float64 `json:"pct"`
}

func pct(used, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return 100 * float64(used) / float64(total)
}

// metricSampleOf reads a stored sample in the units alert rules use.
func metricSampleOf(r sqlc.ServerSample) metricSample {
	s := metricSample{
		at: r.At, cpu: r.CpuPercent, iowait: r.IowaitPercent,
		mem: pct(r.MemUsedBytes, r.MemTotalBytes), swap: -1,
		rx: r.RxBytesPerSec, tx: r.TxBytesPerSec,
	}
	if r.Cores > 0 {
		s.load = r.Load1 / float64(r.Cores)
	}
	if r.SwapTotalBytes > 0 {
		s.swap = pct(r.SwapUsedBytes, r.SwapTotalBytes)
	}
	var disks []sampleDisk
	_ = json.Unmarshal(r.Disks, &disks)
	for _, d := range disks {
		p := d.Percent
		if p == 0 {
			p = pct(d.Used, d.Total)
		}
		s.disks = append(s.disks, diskUse{mount: d.Mount, percent: p})
	}
	// Samples from before per-disk history only know the fullest one.
	if len(s.disks) == 0 && r.DiskMaxMount != "" {
		s.disks = append(s.disks, diskUse{mount: r.DiskMaxMount, percent: r.DiskMaxPercent})
	}
	return s
}

// ---- Response types ----

type ServerResourceInfo struct {
	At             time.Time `json:"at"`
	CPUPercent     float64   `json:"cpu_percent"`
	Cores          int32     `json:"cores"`
	Load1          float64   `json:"load1"`
	MemUsedBytes   int64     `json:"mem_used_bytes"`
	MemTotalBytes  int64     `json:"mem_total_bytes"`
	SwapUsedBytes  int64     `json:"swap_used_bytes"`
	SwapTotalBytes int64     `json:"swap_total_bytes"`
	DiskUsedBytes  int64     `json:"disk_used_bytes" doc:"The root filesystem (the largest one without /)"`
	DiskTotalBytes int64     `json:"disk_total_bytes"`
	DiskMaxPercent float64   `json:"disk_max_percent" doc:"The fullest filesystem's Use%"`
	DiskMaxMount   string    `json:"disk_max_mount"`
	RxBytesPerSec  float64   `json:"rx_bytes_per_sec"`
	TxBytesPerSec  float64   `json:"tx_bytes_per_sec"`
}

type ServerResourceSummary struct {
	Samples int64     `json:"samples"`
	CPUAvg  float64   `json:"cpu_avg"`
	CPUMax  float64   `json:"cpu_max"`
	MemAvg  float64   `json:"mem_avg" doc:"Percent of memory used"`
	MemMax  float64   `json:"mem_max"`
	DiskMax float64   `json:"disk_max" doc:"Fullest filesystem's highest Use%"`
	RxAvg   float64   `json:"rx_avg"`
	TxAvg   float64   `json:"tx_avg"`
	FirstAt time.Time `json:"first_at"`
	LastAt  time.Time `json:"last_at"`
	// The root disk's used bytes at the first and last sample in the range.
	DiskFirst int64 `json:"disk_first"`
	DiskLast  int64 `json:"disk_last"`
}

type ServerInsight struct {
	ID          string `json:"id" format:"uuid"`
	WorkspaceID string `json:"workspace_id" format:"uuid"`
	Name        string `json:"name"`
	Host        string `json:"host"`
	OsID        string `json:"os_id"`
	OsName      string `json:"os_name"`
	Status      string `json:"status"`
	Favorite    bool   `json:"favorite"`
	LatencyMs   *int32 `json:"latency_ms" nullable:"true" doc:"From the last check"`
	// Over the range.
	Checks       int64                  `json:"checks"`
	Failures     int64                  `json:"failures"`
	Uptime       *float64               `json:"uptime" nullable:"true" doc:"Share of checks that found it online, 0–1; null without checks"`
	LatencyAvg   *float64               `json:"latency_avg" nullable:"true"`
	LatencyMax   *int32                 `json:"latency_max" nullable:"true"`
	HistorySince *time.Time             `json:"history_since" nullable:"true" doc:"First check in the range"`
	Resources    *ServerResourceSummary `json:"resources,omitempty" doc:"Missing = no sample in the range"`
	Latest       *ServerResourceInfo    `json:"latest,omitempty" doc:"Last sample, any age; missing = never sampled"`
}

type ServerCheckPoint struct {
	T          time.Time `json:"t"`
	ServerID   string    `json:"server_id" format:"uuid"`
	Checks     int64     `json:"checks"`
	Failures   int64     `json:"failures"`
	LatencyAvg float64   `json:"latency_avg" doc:"Online checks only; 0 when none"`
	LatencyMax int32     `json:"latency_max"`
}

type ServerResourcePoint struct {
	T        time.Time `json:"t"`
	ServerID string    `json:"server_id" format:"uuid"`
	Samples  int64     `json:"samples"`
	CPUAvg   float64   `json:"cpu_avg"`
	CPUMax   float64   `json:"cpu_max"`
	MemAvg   float64   `json:"mem_avg"`
	MemMax   float64   `json:"mem_max"`
	DiskMax  float64   `json:"disk_max"`
	DiskUsed int64     `json:"disk_used"`
	RxAvg    float64   `json:"rx_avg"`
	TxAvg    float64   `json:"tx_avg"`
	LoadAvg  float64   `json:"load_avg"`
}

type ServerStatusEvent struct {
	ServerID   string    `json:"server_id" format:"uuid"`
	At         time.Time `json:"at"`
	Status     string    `json:"status"`
	PrevStatus string    `json:"prev_status"`
	Message    string    `json:"message"`
}

type ServerInsights struct {
	Range         string                `json:"range"`
	From          time.Time             `json:"from"`
	To            time.Time             `json:"to"`
	BucketSeconds int                   `json:"bucket_seconds"`
	SampleSeconds int                   `json:"sample_seconds" doc:"How often resources are read; 0 = off"`
	Servers       []ServerInsight       `json:"servers"`
	Checks        []ServerCheckPoint    `json:"checks"`
	Resources     []ServerResourcePoint `json:"resources"`
	Events        []ServerStatusEvent   `json:"events" doc:"Status changes, newest first (at most 200)"`
}

type ServerInsightsInput struct {
	Range string `query:"range" enum:"24h,7d,30d" default:"7d"`
	TZ    string `query:"tz" doc:"IANA time zone the buckets line up with (days start at its midnight)" example:"Europe/Berlin"`
}

// insightLocation is tz, or UTC when it's empty or unknown.
func insightLocation(tz string) *time.Location {
	if tz != "" {
		if l, err := time.LoadLocation(tz); err == nil {
			return l
		}
	}
	return time.UTC
}

func (h *serverHandler) insights(ctx context.Context, in *ServerInsightsInput, sampleEvery time.Duration) (*struct{ Body ServerInsights }, error) {
	now := time.Now()
	from, bucket := insightWindow(in.Range, insightLocation(in.TZ), now)

	sc := principalOf(ctx).scope()
	rows, err := h.q.ListServers(ctx, sqlc.ListServersParams{
		SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, ServerIds: sc.servers, WorkspaceID: sc.current,
		OsIds: []string{}, Statuses: []string{}, Tags: []string{}, AuthMethods: []string{},
		Sort: "name", Lim: 10000,
	})
	if err != nil {
		return nil, internalError(err)
	}
	out := &struct{ Body ServerInsights }{}
	b := &out.Body
	b.Range, b.From, b.To, b.BucketSeconds = in.Range, from, now, int(bucket.Seconds())
	b.SampleSeconds = int(max(sampleEvery, 0).Seconds())
	b.Servers, b.Checks, b.Resources, b.Events = []ServerInsight{}, []ServerCheckPoint{}, []ServerResourcePoint{}, []ServerStatusEvent{}
	if len(rows) == 0 {
		return out, nil
	}

	ids := make([]uuid.UUID, len(rows))
	index := make(map[uuid.UUID]int, len(rows))
	for i, r := range rows {
		s := r.Server
		ids[i], index[s.ID] = s.ID, i
		b.Servers = append(b.Servers, ServerInsight{
			ID: s.ID.String(), WorkspaceID: s.WorkspaceID.String(), Name: s.Name, Host: s.Host,
			OsID: s.OsID, OsName: s.OsName, Status: s.Status, Favorite: s.Favorite, LatencyMs: s.LatencyMs,
		})
	}
	secs := bucket.Seconds()

	summary, err := h.q.ServerCheckSummary(ctx, sqlc.ServerCheckSummaryParams{Ids: ids, Since: from})
	if err != nil {
		return nil, internalError(err)
	}
	for _, s := range summary {
		sv := &b.Servers[index[s.ServerID]]
		sv.Checks, sv.Failures = s.Checks, s.Failures
		if s.Checks > 0 {
			up := float64(s.Checks-s.Failures) / float64(s.Checks)
			first := s.FirstAt
			sv.Uptime, sv.HistorySince = &up, &first
		}
		if s.Checks > s.Failures {
			avg, mx := s.LatencyAvg, s.LatencyMax
			sv.LatencyAvg, sv.LatencyMax = &avg, &mx
		}
	}

	series, err := h.q.ServerCheckSeries(ctx, sqlc.ServerCheckSeriesParams{BucketSecs: secs, Origin: from, Ids: ids, Since: from})
	if err != nil {
		return nil, internalError(err)
	}
	for _, p := range series {
		b.Checks = append(b.Checks, ServerCheckPoint{
			T: p.T, ServerID: p.ServerID.String(), Checks: p.Checks, Failures: p.Failures,
			LatencyAvg: p.LatencyAvg, LatencyMax: p.LatencyMax,
		})
	}

	res, err := h.q.ServerSampleSummary(ctx, sqlc.ServerSampleSummaryParams{Ids: ids, Since: from})
	if err != nil {
		return nil, internalError(err)
	}
	for _, r := range res {
		b.Servers[index[r.ServerID]].Resources = &ServerResourceSummary{
			Samples: r.Samples, CPUAvg: r.CpuAvg, CPUMax: r.CpuMax, MemAvg: r.MemAvg, MemMax: r.MemMax,
			DiskMax: r.DiskMax, RxAvg: r.RxAvg, TxAvg: r.TxAvg, FirstAt: r.FirstAt, LastAt: r.LastAt,
			DiskFirst: r.DiskFirst, DiskLast: r.DiskLast,
		}
	}
	latest, err := h.q.LatestServerSamples(ctx, ids)
	if err != nil {
		return nil, internalError(err)
	}
	for _, l := range latest {
		b.Servers[index[l.ServerID]].Latest = &ServerResourceInfo{
			At: l.At, CPUPercent: l.CpuPercent, Cores: l.Cores, Load1: l.Load1,
			MemUsedBytes: l.MemUsedBytes, MemTotalBytes: l.MemTotalBytes,
			SwapUsedBytes: l.SwapUsedBytes, SwapTotalBytes: l.SwapTotalBytes,
			DiskUsedBytes: l.DiskUsedBytes, DiskTotalBytes: l.DiskTotalBytes,
			DiskMaxPercent: l.DiskMaxPercent, DiskMaxMount: l.DiskMaxMount,
			RxBytesPerSec: l.RxBytesPerSec, TxBytesPerSec: l.TxBytesPerSec,
		}
	}
	points, err := h.q.ServerSampleSeries(ctx, sqlc.ServerSampleSeriesParams{BucketSecs: secs, Origin: from, Ids: ids, Since: from})
	if err != nil {
		return nil, internalError(err)
	}
	for _, p := range points {
		b.Resources = append(b.Resources, ServerResourcePoint{
			T: p.T, ServerID: p.ServerID.String(), Samples: p.Samples,
			CPUAvg: p.CpuAvg, CPUMax: p.CpuMax, MemAvg: p.MemAvg, MemMax: p.MemMax,
			DiskMax: p.DiskMax, DiskUsed: p.DiskUsed, RxAvg: p.RxAvg, TxAvg: p.TxAvg, LoadAvg: p.LoadAvg,
		})
	}

	events, err := h.q.ServerStatusChanges(ctx, sqlc.ServerStatusChangesParams{Ids: ids, Since: from})
	if err != nil {
		return nil, internalError(err)
	}
	for _, e := range events {
		b.Events = append(b.Events, ServerStatusEvent{
			ServerID: e.ServerID.String(), At: e.At, Status: e.Status, PrevStatus: e.PrevStatus, Message: e.Message,
		})
	}
	return out, nil
}

func registerServerInsights(api huma.API, h *serverHandler, sampleEvery time.Duration) {
	huma.Register(api, huma.Operation{
		OperationID: "server-insights",
		Method:      http.MethodGet,
		Path:        "/servers/insights",
		Summary:     "Uptime, response time and resources of the servers",
		Description: "For the servers this person can see (in the selected workspace). Series come bucketed: 30 min for 24h, 4 h for 7d, a day for 30d. Resources are read from online Linux servers every SERVER_SAMPLE_INTERVAL.",
		Tags:        []string{"Servers"},
	}, func(ctx context.Context, in *ServerInsightsInput) (*struct{ Body ServerInsights }, error) {
		return h.insights(ctx, in, sampleEvery)
	})
}
