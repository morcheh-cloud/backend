package api

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
)

// Insights for the Databases page, read from the monitor's samples (one per
// pass, kept 30 days) and its events.

type DatabaseInsight struct {
	ID          string `json:"id" format:"uuid"`
	WorkspaceID string `json:"workspace_id" format:"uuid"`
	Name        string `json:"name"`
	Engine      string `json:"engine"`
	Flavor      string `json:"flavor" doc:"mariadb for MariaDB; empty otherwise"`
	Status      string `json:"status"`
	Health      string `json:"health"`
	Paused      bool   `json:"paused"`
	Favorite    bool   `json:"favorite"`
	SizeBytes   *int64 `json:"size_bytes" nullable:"true" doc:"From the last check"`
	// Over the range.
	Samples        int64      `json:"samples"`
	Failures       int64      `json:"failures"`
	Uptime         *float64   `json:"uptime" nullable:"true" doc:"Share of checks that reached it, 0–1; null without checks"`
	LatencyAvg     *float64   `json:"latency_avg" nullable:"true"`
	LatencyP95     *float64   `json:"latency_p95" nullable:"true"`
	QpsAvg         *float64   `json:"qps_avg" nullable:"true"`
	QpsMax         *float64   `json:"qps_max" nullable:"true"`
	ConnectionsMax *float64   `json:"connections_max" nullable:"true"`
	CacheHit       *float64   `json:"cache_hit" nullable:"true" doc:"Average share of reads served from memory, 0–1"`
	Deadlocks      *float64   `json:"deadlocks" nullable:"true" doc:"Sum over the range"`
	BlockedMax     *float64   `json:"blocked_max" nullable:"true"`
	SizeFirst      *float64   `json:"size_first" nullable:"true" doc:"First measured size in the range"`
	SizeLast       *float64   `json:"size_last" nullable:"true"`
	HistorySince   *time.Time `json:"history_since" nullable:"true" doc:"First sample in the range"`
}

type DatabaseInsightPoint struct {
	T              time.Time `json:"t"`
	DatabaseID     string    `json:"database_id" format:"uuid"`
	Samples        int64     `json:"samples"`
	Failures       int64     `json:"failures"`
	LatencyAvg     *float64  `json:"latency_avg" nullable:"true"`
	LatencyMax     int32     `json:"latency_max"`
	Qps            *float64  `json:"qps" nullable:"true"`
	Tps            *float64  `json:"tps" nullable:"true"`
	Connections    *float64  `json:"connections" nullable:"true" doc:"Highest in the bucket"`
	MaxConnections *float64  `json:"max_connections" nullable:"true"`
	SizeBytes      *float64  `json:"size_bytes" nullable:"true"`
}

type DatabaseInsightEvent struct {
	DatabaseID string    `json:"database_id" format:"uuid"`
	At         time.Time `json:"at"`
	Kind       string    `json:"kind"`
	Severity   string    `json:"severity"`
	CheckID    string    `json:"check_id"`
	Title      string    `json:"title"`
	Detail     string    `json:"detail"`
}

type DatabaseInsights struct {
	Range         string                 `json:"range"`
	From          time.Time              `json:"from"`
	To            time.Time              `json:"to"`
	BucketSeconds int                    `json:"bucket_seconds"`
	Databases     []DatabaseInsight      `json:"databases"`
	Series        []DatabaseInsightPoint `json:"series"`
	Events        []DatabaseInsightEvent `json:"events" doc:"Problems and recoveries, newest first (at most 200)"`
}

type DatabaseInsightsInput struct {
	Range string `query:"range" enum:"24h,7d,30d" default:"7d"`
	TZ    string `query:"tz" doc:"IANA time zone the buckets line up with (days start at its midnight)" example:"Europe/Berlin"`
}

func (h *databaseHandler) insights(ctx context.Context, in *DatabaseInsightsInput) (*struct{ Body DatabaseInsights }, error) {
	now := time.Now()
	from, bucket := insightWindow(in.Range, insightLocation(in.TZ), now)

	sc := principalOf(ctx).scope()
	rows, err := h.q.ListDatabases(ctx, sqlc.ListDatabasesParams{
		SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, ServerIds: sc.servers, WorkspaceID: sc.current,
	})
	if err != nil {
		return nil, internalError(err)
	}
	out := &struct{ Body DatabaseInsights }{}
	b := &out.Body
	b.Range, b.From, b.To, b.BucketSeconds = in.Range, from, now, int(bucket.Seconds())
	b.Databases, b.Series, b.Events = []DatabaseInsight{}, []DatabaseInsightPoint{}, []DatabaseInsightEvent{}
	if len(rows) == 0 {
		return out, nil
	}

	ids := make([]uuid.UUID, len(rows))
	index := make(map[uuid.UUID]int, len(rows))
	for i, d := range rows {
		ids[i], index[d.ID] = d.ID, i
		b.Databases = append(b.Databases, DatabaseInsight{
			ID: d.ID.String(), WorkspaceID: d.WorkspaceID.String(), Name: d.Name, Engine: d.Engine, Flavor: d.Flavor,
			Status: d.Status, Health: d.Health, Paused: d.Paused, Favorite: d.Favorite, SizeBytes: d.SizeBytes,
		})
	}

	summary, err := h.q.DatabaseInsightSummary(ctx, sqlc.DatabaseInsightSummaryParams{Ids: ids, Since: from})
	if err != nil {
		return nil, internalError(err)
	}
	for _, s := range summary {
		d := &b.Databases[index[s.DatabaseID]]
		d.Samples, d.Failures = s.Samples, s.Failures
		if s.Samples > 0 {
			up := float64(s.Samples-s.Failures) / float64(s.Samples)
			first := s.FirstAt
			d.Uptime, d.HistorySince = &up, &first
		}
		d.LatencyAvg, d.LatencyP95 = num(s.LatencyAvg), num(s.LatencyP95)
		d.QpsAvg, d.QpsMax, d.ConnectionsMax = num(s.QpsAvg), num(s.QpsMax), num(s.ConnectionsMax)
		d.CacheHit, d.Deadlocks, d.BlockedMax = num(s.CacheHit), num(s.Deadlocks), num(s.BlockedMax)
		d.SizeFirst, d.SizeLast = num(s.SizeFirst), num(s.SizeLast)
	}

	series, err := h.q.DatabaseInsightSeries(ctx, sqlc.DatabaseInsightSeriesParams{
		BucketSecs: bucket.Seconds(), Origin: from, Ids: ids, Since: from,
	})
	if err != nil {
		return nil, internalError(err)
	}
	for _, p := range series {
		b.Series = append(b.Series, DatabaseInsightPoint{
			T: p.T, DatabaseID: p.DatabaseID.String(), Samples: p.Samples, Failures: p.Failures,
			LatencyAvg: num(p.LatencyAvg), LatencyMax: p.LatencyMax, Qps: num(p.Qps), Tps: num(p.Tps),
			Connections: num(p.Connections), MaxConnections: num(p.MaxConnections), SizeBytes: num(p.SizeBytes),
		})
	}

	events, err := h.q.DatabaseInsightEvents(ctx, sqlc.DatabaseInsightEventsParams{Ids: ids, Since: from})
	if err != nil {
		return nil, internalError(err)
	}
	for _, e := range events {
		b.Events = append(b.Events, DatabaseInsightEvent{
			DatabaseID: e.DatabaseID.String(), At: e.At, Kind: e.Kind, Severity: e.Severity,
			CheckID: e.CheckID, Title: e.Title, Detail: e.Detail,
		})
	}
	return out, nil
}

func registerDatabaseInsights(api huma.API, h *databaseHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "database-insights",
		Method:      http.MethodGet,
		Path:        "/databases/insights",
		Summary:     "Availability, response time, load and size of the databases",
		Description: "For the databases this person can see (in the selected workspace), from the monitor's samples (kept 30 days). Series come bucketed: 30 min for 24h, 4 h for 7d, a day for 30d.",
		Tags:        []string{"Databases"},
	}, h.insights)
}
