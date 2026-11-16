package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/cmdlog"
	"github.com/morche/backend/internal/database/sqlc"
)

// Compose projects' numbers over days: every 5 minutes each recorded
// server is measured (the same measurement as the live cards) and one point
// per project is stored, kept for the workspace's stats_days.

const projectHistoryEvery = 5 * time.Minute

type DockerHistoryPoint struct {
	At        time.Time `json:"at" doc:"Start of the bucket"`
	CPU       float64   `json:"cpu" doc:"Average, percent of one core"`
	CPUMax    float64   `json:"cpu_max" doc:"Highest sample in the bucket"`
	Memory    int64     `json:"memory" doc:"Average bytes"`
	MemoryMax int64     `json:"memory_max"`
	NetRx     float64   `json:"net_rx" doc:"Average bytes per second"`
	NetTx     float64   `json:"net_tx"`
	Running   int       `json:"running" doc:"Fewest containers running in the bucket"`
	Total     int       `json:"total"`
	Unhealthy int       `json:"unhealthy" doc:"Most unhealthy containers in the bucket"`
}

type DockerProjectHistory struct {
	Range     string               `json:"range" enum:"24h,7d,30d"`
	Step      int                  `json:"step" doc:"Seconds per point"`
	KeepDays  int                  `json:"keep_days" doc:"How long points are kept (0 = history is off for this workspace)"`
	Since     *time.Time           `json:"since,omitempty" doc:"The oldest point kept for this project"`
	Points    []DockerHistoryPoint `json:"points"`
	Recording bool                 `json:"recording" doc:"Points are being added for this server now"`
}

var projectHistoryRanges = map[string]struct{ span, step time.Duration }{
	"24h": {24 * time.Hour, 15 * time.Minute},
	"7d":  {7 * 24 * time.Hour, time.Hour},
	"30d": {30 * 24 * time.Hour, 6 * time.Hour},
}

// recordProjectStats measures a server and stores one point per project.
func (h *serverHandler) recordProjectStats(ctx context.Context, id string) {
	sid, err := uuid.Parse(id)
	if err != nil {
		return
	}
	list, err := h.projectStats(ctx, id, false)
	if err != nil {
		if ctx.Err() == nil {
			slog.Debug("docker: project history", "server", id, "error", err)
		}
		return
	}
	st := projectStatsFor(id)
	st.mu.Lock()
	st.recorded = time.Now()
	st.mu.Unlock()
	at := list.At.Truncate(projectHistoryEvery)
	from := list.At.Add(-projectHistoryEvery)
	for _, p := range list.Projects {
		// Average the in-memory points of the last 5 minutes (several while
		// someone watches the live cards; else just this measurement).
		var n int
		var cpu, rx, tx, cpuMax float64
		var mem, memMax int64
		for _, pt := range p.History {
			if pt.At.Before(from) {
				continue
			}
			n++
			cpu += pt.CPU
			rx += pt.NetRx
			tx += pt.NetTx
			mem += pt.Memory
			cpuMax = max(cpuMax, pt.CPU)
			memMax = max(memMax, pt.Memory)
		}
		if n == 0 {
			n, cpu, rx, tx, mem = 1, p.CPU, p.NetRxRate, p.NetTxRate, p.MemoryUsed
			cpuMax, memMax = p.CPU, p.MemoryUsed
		}
		if err := h.q.AddDockerProjectStat(ctx, sqlc.AddDockerProjectStatParams{
			ServerID: sid, Project: p.Name, At: at,
			Cpu: cpu / float64(n), CpuMax: cpuMax, Memory: mem / int64(n), MemoryMax: memMax,
			NetRx: rx / float64(n), NetTx: tx / float64(n),
			Running: int32(p.Running), Total: int32(p.Total), Unhealthy: int32(p.Unhealthy),
		}); err != nil {
			slog.Warn("docker: keeping a project point", "server", id, "project", p.Name, "error", err)
		}
	}
}

func startProjectHistoryLoop(h *serverHandler) {
	go func() {
		var pruned time.Time
		tick := time.NewTicker(projectHistoryEvery)
		defer tick.Stop()
		for range tick.C {
			projectStatsByServer.Lock()
			ids := make([]uuid.UUID, 0, len(projectStatsByServer.m))
			for id := range projectStatsByServer.m {
				if u, err := uuid.Parse(id); err == nil {
					ids = append(ids, u)
				}
			}
			projectStatsByServer.Unlock()
			ctx := cmdlog.Background(context.Background(), "Container history")
			rows, err := h.q.DockerStatsServers(ctx, ids)
			if err != nil {
				slog.Warn("docker: servers to record", "error", err)
				continue
			}
			sem := make(chan struct{}, 4)
			for _, r := range rows {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					c, cancel := context.WithTimeout(ctx, time.Minute)
					defer cancel()
					h.recordProjectStats(c, r.ID.String())
				}()
			}
			if time.Since(pruned) > time.Hour {
				pruned = time.Now()
				if !logOwned("docker-stats") {
					if n, err := h.q.PruneDockerProjectStats(ctx); err != nil {
						slog.Warn("docker: pruning project history", "error", err)
					} else if n > 0 {
						slog.Debug("docker: pruned project history", "rows", n)
					}
				}
			}
		}
	}()
}

type DockerProjectHistoryInput struct {
	DockerProjectPath
	Range string `query:"range" enum:"24h,7d,30d" default:"24h"`
}

func registerDockerProjectHistory(api huma.API, h *serverHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "docker-project-history",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/docker/projects/{project}/history",
		Summary:     "A project's CPU, memory and network over days",
		Description: "Points recorded every 5 minutes, averaged per 15 minutes (24h), hour (7d) or 6 hours (30d). Recording starts once the server's projects have been opened or its images checked for updates, and stops when the workspace's `stats_days` is 0.",
		Tags:        []string{"Containers"},
	}, func(ctx context.Context, in *DockerProjectHistoryInput) (*struct{ Body DockerProjectHistory }, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		set, err := h.serverDockerSettings(ctx, s)
		if err != nil {
			return nil, err
		}
		rg, ok := projectHistoryRanges[in.Range]
		if !ok {
			in.Range, rg = "24h", projectHistoryRanges["24h"]
		}
		out := DockerProjectHistory{Range: in.Range, Step: int(rg.step.Seconds()), KeepDays: set.StatsDays, Points: []DockerHistoryPoint{}}
		rows, err := h.q.DockerProjectStatsHistory(ctx, sqlc.DockerProjectStatsHistoryParams{
			StepSeconds: int32(rg.step.Seconds()), ServerID: s.ID, Project: in.Project,
			Since: time.Now().Add(-rg.span).Truncate(rg.step),
		})
		if err != nil {
			return nil, internalError(err)
		}
		for _, r := range rows {
			out.Points = append(out.Points, DockerHistoryPoint{
				At: r.Bucket.UTC(), CPU: r.Cpu, CPUMax: r.CpuMax, Memory: int64(r.Memory), MemoryMax: r.MemoryMax,
				NetRx: r.NetRx, NetTx: r.NetTx, Running: int(r.Running), Total: int(r.Total), Unhealthy: int(r.Unhealthy),
			})
		}
		if first, err := h.q.FirstDockerProjectStat(ctx, sqlc.FirstDockerProjectStatParams{ServerID: s.ID, Project: in.Project}); err == nil && !first.IsZero() {
			f := first.UTC()
			out.Since = &f
		}
		st := projectStatsFor(in.ID)
		st.mu.Lock()
		out.Recording = set.StatsDays > 0 && time.Since(st.recorded) < 3*projectHistoryEvery
		st.mu.Unlock()
		if set.StatsDays > 0 && !out.Recording && len(out.Points) > 0 {
			out.Recording = time.Since(out.Points[len(out.Points)-1].At) < 2*rg.step
		}
		return &struct{ Body DockerProjectHistory }{out}, nil
	})
}
