package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
)

// One server's resource history for its Metrics tab, read from the samples
// the sampler takes every SERVER_SAMPLE_INTERVAL.

type ServerMetricsInput struct {
	ServerIDPath
	Range string `query:"range" enum:"1h,6h,24h,7d,30d" default:"24h"`
	TZ    string `query:"tz" doc:"IANA time zone the buckets line up with, e.g. Asia/Tehran"`
}

type MetricPoint struct {
	T         time.Time `json:"t" doc:"Start of the bucket"`
	Samples   int64     `json:"samples"`
	CPU       float64   `json:"cpu" doc:"Average %"`
	CPUMax    float64   `json:"cpu_max"`
	Iowait    float64   `json:"iowait"`
	Load      float64   `json:"load" doc:"1-minute load per core"`
	LoadMax   float64   `json:"load_max"`
	Memory    float64   `json:"memory" doc:"%"`
	MemoryMax float64   `json:"memory_max"`
	Swap      float64   `json:"swap" doc:"%; 0 without swap"`
	Disk      float64   `json:"disk" doc:"Root filesystem %"`
	DiskMax   float64   `json:"disk_max"`
	Rx        float64   `json:"rx" doc:"Bytes per second in"`
	RxMax     float64   `json:"rx_max"`
	Tx        float64   `json:"tx" doc:"Bytes per second out"`
	TxMax     float64   `json:"tx_max"`
}

type DiskPoint struct {
	T       time.Time `json:"t"`
	Used    int64     `json:"used"`
	Total   int64     `json:"total"`
	Percent float64   `json:"percent"`
}

type DiskSeries struct {
	Mount  string      `json:"mount"`
	Points []DiskPoint `json:"points"`
}

type LatestSample struct {
	At        time.Time    `json:"at"`
	CPU       float64      `json:"cpu"`
	Iowait    float64      `json:"iowait"`
	Cores     int32        `json:"cores"`
	Load1     float64      `json:"load1"`
	MemUsed   int64        `json:"mem_used"`
	MemTotal  int64        `json:"mem_total"`
	SwapUsed  int64        `json:"swap_used"`
	SwapTotal int64        `json:"swap_total"`
	Rx        float64      `json:"rx"`
	Tx        float64      `json:"tx"`
	Disks     []sampleDisk `json:"disks"`
}

type ServerMetrics struct {
	Range         string        `json:"range"`
	From          time.Time     `json:"from"`
	To            time.Time     `json:"to"`
	BucketSeconds int64         `json:"bucket_seconds"`
	SampleSeconds int64         `json:"sample_seconds" doc:"How often samples are taken; 0 = sampling is off"`
	Points        []MetricPoint `json:"points" doc:"Only buckets with samples, oldest first"`
	Disks         []DiskSeries  `json:"disks" doc:"Each filesystem's use over the range"`
	Latest        *LatestSample `json:"latest,omitempty" doc:"The newest sample, at any age"`
}

// metricWindow is a range's span and bucket, never finer than the samples.
func metricWindow(rng string, sampleEvery time.Duration) (span, bucket time.Duration) {
	switch rng {
	case "1h":
		span, bucket = time.Hour, time.Minute
	case "6h":
		span, bucket = 6*time.Hour, 5*time.Minute
	case "7d":
		span, bucket = 7*24*time.Hour, time.Hour
	case "30d":
		span, bucket = 30*24*time.Hour, 6*time.Hour
	default:
		span, bucket = 24*time.Hour, 15*time.Minute
	}
	if sampleEvery > bucket {
		bucket = sampleEvery
	}
	return span, bucket
}

func (h *serverHandler) metrics(ctx context.Context, in *ServerMetricsInput, sampleEvery time.Duration) (*struct{ Body ServerMetrics }, error) {
	id, err := uuid.Parse(in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("Server not found")
	}
	loc := insightLocation(in.TZ)
	now := time.Now().In(loc)
	span, bucket := metricWindow(in.Range, sampleEvery)
	// Buckets line up with the local day, so hours read as whole hours.
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	from := now.Add(-span)
	from = day.Add(from.Sub(day).Truncate(bucket))
	if from.After(now.Add(-span)) {
		from = from.Add(-bucket)
	}
	from = from.Add(bucket) // the window holds span/bucket buckets ending now

	rows, err := h.q.ServerMetricSeries(ctx, sqlc.ServerMetricSeriesParams{
		BucketSecs: bucket.Seconds(), Origin: day, ServerID: id, Since: from,
	})
	if err != nil {
		return nil, internalError(err)
	}
	out := ServerMetrics{
		Range: cmpOr(in.Range, "24h"), From: from, To: now,
		BucketSeconds: int64(bucket.Seconds()), SampleSeconds: int64(sampleEvery.Seconds()),
		Points: make([]MetricPoint, 0, len(rows)), Disks: []DiskSeries{},
	}
	for _, r := range rows {
		out.Points = append(out.Points, MetricPoint{
			T: r.T, Samples: r.Samples, CPU: r.CpuAvg, CPUMax: r.CpuMax, Iowait: r.IowaitAvg,
			Load: r.LoadAvg, LoadMax: r.LoadMax, Memory: r.MemAvg, MemoryMax: r.MemMax,
			Swap: r.SwapAvg, Disk: r.DiskAvg, DiskMax: r.DiskMax,
			Rx: r.RxAvg, RxMax: r.RxMax, Tx: r.TxAvg, TxMax: r.TxMax,
		})
	}

	disks, err := h.q.ServerDiskSeries(ctx, sqlc.ServerDiskSeriesParams{
		BucketSecs: bucket.Seconds(), Origin: day, ServerID: id, Since: from,
	})
	if err != nil {
		return nil, internalError(err)
	}
	at := map[string]int{}
	for _, d := range disks {
		i, ok := at[d.Mount]
		if !ok {
			i = len(out.Disks)
			at[d.Mount] = i
			out.Disks = append(out.Disks, DiskSeries{Mount: d.Mount, Points: []DiskPoint{}})
		}
		out.Disks[i].Points = append(out.Disks[i].Points, DiskPoint{
			T: d.T, Used: d.Used, Total: d.Total, Percent: d.Percent,
		})
	}

	latest, err := h.q.LatestServerSamples(ctx, []uuid.UUID{id})
	if err != nil {
		return nil, internalError(err)
	}
	if len(latest) > 0 {
		l := latest[0]
		ls := &LatestSample{
			At: l.At, CPU: l.CpuPercent, Iowait: l.IowaitPercent, Cores: l.Cores, Load1: l.Load1,
			MemUsed: l.MemUsedBytes, MemTotal: l.MemTotalBytes, SwapUsed: l.SwapUsedBytes,
			SwapTotal: l.SwapTotalBytes, Rx: l.RxBytesPerSec, Tx: l.TxBytesPerSec, Disks: []sampleDisk{},
		}
		if len(l.Disks) > 0 {
			_ = json.Unmarshal(l.Disks, &ls.Disks)
		}
		if len(ls.Disks) == 0 && l.DiskTotalBytes > 0 {
			ls.Disks = []sampleDisk{{Mount: "/", Used: l.DiskUsedBytes, Total: l.DiskTotalBytes,
				Percent: float64(l.DiskUsedBytes) * 100 / float64(l.DiskTotalBytes)}}
		}
		out.Latest = ls
	}
	return &struct{ Body ServerMetrics }{out}, nil
}

func registerServerMetrics(api huma.API, h *serverHandler, sampleEvery time.Duration) {
	huma.Register(api, huma.Operation{
		OperationID: "get-server-metrics",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/metrics",
		Summary:     "Resource history of a server",
		Description: "CPU, load, memory, swap, disks and network from the samples taken every SERVER_SAMPLE_INTERVAL. Buckets: 1 min for 1h, 5 min for 6h, 15 min for 24h, 1 h for 7d, 6 h for 30d (never finer than the sampling).",
		Tags:        []string{"Servers"},
	}, func(ctx context.Context, in *ServerMetricsInput) (*struct{ Body ServerMetrics }, error) {
		return h.metrics(ctx, in, sampleEvery)
	})
}
