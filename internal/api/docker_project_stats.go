package api

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/sse"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/cmdlog"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/docker"
)

// Live numbers for compose projects: one measurement covers every compose
// container on a server and is shared for a few seconds; each project keeps
// a short history in memory while someone looks (and a while after).

const (
	projectStatsFresh   = 8 * time.Second  // a measurement this young is reused
	projectStatsEvery   = 30 * time.Second // background pace while watched
	projectStatsWatch   = 30 * time.Minute // how long after the last look
	projectStatsPoints  = 120              // history kept per project
	projectStatsGap     = 9 * time.Second  // closest two history points
	projectStatsMeasure = 80               // running containers measured per pass
	projectStatsHold    = time.Minute      // a missed sample reuses the last good one this long
	projectLogsMax      = 40               // containers a project log reads
)

// ---- API shapes ----

type DockerPortOut struct {
	IP      string `json:"ip,omitempty"`
	Public  int    `json:"public"`
	Private int    `json:"private"`
	Proto   string `json:"proto"`
}

type DockerProjectContainer struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Service   string     `json:"service"`
	Image     string     `json:"image"`
	State     string     `json:"state"`
	Status    string     `json:"status"`
	Health    string     `json:"health" enum:"healthy,unhealthy,starting,none"`
	ExitCode  int        `json:"exit_code"`
	OOMKilled bool       `json:"oom_killed"`
	Restarts  int        `json:"restarts" doc:"Times the engine restarted it (its restart policy)"`
	StartedAt *time.Time `json:"started_at,omitempty"`
	// Why the engine couldn't start it (a port already taken, a missing
	// mount source…); empty when it could.
	Error      string          `json:"error,omitempty" doc:"What the engine said when it couldn't start it"`
	FinishedAt *time.Time      `json:"finished_at,omitempty" doc:"When it last stopped"`
	Ports      []DockerPortOut `json:"ports"`

	Measured    bool    `json:"measured" doc:"The numbers below were read (running and within the per-pass limit)"`
	CPU         float64 `json:"cpu" doc:"Percent of one core"`
	MemoryUsed  int64   `json:"memory_used"`
	MemoryLimit int64   `json:"memory_limit" doc:"Its own limit; 0 = none"`
	HostMemory  int64   `json:"host_memory" doc:"The memory it could use (the host's when it has no limit)"`
	NetRxRate   float64 `json:"net_rx_rate" doc:"Bytes per second, since the previous pass"`
	NetTxRate   float64 `json:"net_tx_rate"`
	Pids        int64   `json:"pids"`

	// How it's set up, for the production checklist.
	RestartPolicy string  `json:"restart_policy"`
	Privileged    bool    `json:"privileged"`
	CPULimit      float64 `json:"cpu_limit" doc:"Cores; 0 = none"`
	Healthcheck   bool    `json:"healthcheck"`
	LogDriver     string  `json:"log_driver"`
	LogMaxSize    string  `json:"log_max_size"`
	LogMaxFile    string  `json:"log_max_file"`
	ReadOnly      bool    `json:"read_only"`
	User          string  `json:"user"`
}

type DockerStatsPoint struct {
	At     time.Time `json:"at"`
	CPU    float64   `json:"cpu"`
	Memory int64     `json:"memory"`
	NetRx  float64   `json:"net_rx"`
	NetTx  float64   `json:"net_tx"`
}

type DockerProjectStats struct {
	Name        string                   `json:"name"`
	Running     int                      `json:"running"`
	Total       int                      `json:"total"`
	CPU         float64                  `json:"cpu" doc:"Percent of one core, all its containers"`
	CPUs        int                      `json:"cpus" doc:"Cores the host has"`
	MemoryUsed  int64                    `json:"memory_used"`
	HostMemory  int64                    `json:"host_memory"`
	NetRxRate   float64                  `json:"net_rx_rate"`
	NetTxRate   float64                  `json:"net_tx_rate"`
	Healthy     int                      `json:"healthy"`
	Unhealthy   int                      `json:"unhealthy"`
	Starting    int                      `json:"starting"`
	Restarts    int                      `json:"restarts"`
	Since       *time.Time               `json:"since,omitempty" doc:"When its longest-running container started"`
	Ports       []DockerPortOut          `json:"ports"`
	Containers  []DockerProjectContainer `json:"containers"`
	History     []DockerStatsPoint       `json:"history"`
	Unmeasured  int                      `json:"unmeasured" doc:"Running containers left out of this pass"`
	MeasuredAt  time.Time                `json:"measured_at"`
	FirstSample bool                     `json:"first_sample" doc:"No earlier pass: network rates aren't known yet"`
}

type DockerProjectStatsList struct {
	At       time.Time            `json:"at"`
	Projects []DockerProjectStats `json:"projects"`
}

type DockerProjectLogLine struct {
	Container string     `json:"container"`
	Service   string     `json:"service"`
	Time      *time.Time `json:"time,omitempty"`
	Stream    string     `json:"stream"`
	Text      string     `json:"text"`
}

type DockerProjectLogs struct {
	Lines      []DockerProjectLogLine `json:"lines"`
	Truncated  bool                   `json:"truncated"`
	Containers []DockerRef            `json:"containers" doc:"Whose logs were read"`
}

type DockerProjectLogBatch struct {
	Lines []DockerProjectLogLine `json:"lines"`
}

type DockerProjectMetaBody struct {
	Title string `json:"title" maxLength:"80" doc:"Empty = show the project's name"`
	Note  string `json:"note" maxLength:"2000"`
}

// ---- Measuring ----

type netTotal struct {
	at     time.Time
	rx, tx int64
}

// heldSample = a container's last good sample and the rates it gave, reused
// when one pass misses it so a project's totals don't swing.
type heldSample struct {
	s      docker.Sample
	rx, tx float64
}

type serverProjectStats struct {
	run   sync.Mutex // one measurement at a time
	mu    sync.Mutex // the fields below
	last  *DockerProjectStatsList
	asked time.Time
	// recorded = the history recorder measured it lately: its state stays
	// so network rates keep working between its passes.
	recorded time.Time
	prev     map[string]netTotal
	history  map[string][]DockerStatsPoint
	held     map[string]heldSample
}

var projectStatsByServer = struct {
	sync.Mutex
	m map[string]*serverProjectStats
}{m: map[string]*serverProjectStats{}}

func projectStatsFor(id string) *serverProjectStats {
	projectStatsByServer.Lock()
	defer projectStatsByServer.Unlock()
	s := projectStatsByServer.m[id]
	if s == nil {
		s = &serverProjectStats{prev: map[string]netTotal{}, history: map[string][]DockerStatsPoint{}, held: map[string]heldSample{}}
		projectStatsByServer.m[id] = s
	}
	return s
}

// forgetProjectStats drops the kept measurement, so the next ask reads the
// containers again (after a compose job changed them).
func forgetProjectStats(id string) {
	st := projectStatsFor(id)
	st.mu.Lock()
	st.last = nil
	st.mu.Unlock()
}

// projectStats answers a recent measurement or takes a new one.
func (h *serverHandler) projectStats(ctx context.Context, id string, asked bool) (DockerProjectStatsList, error) {
	st := projectStatsFor(id)
	if asked {
		st.mu.Lock()
		st.asked = time.Now()
		st.mu.Unlock()
	}
	st.run.Lock()
	defer st.run.Unlock()
	st.mu.Lock()
	if st.last != nil && time.Since(st.last.At) < projectStatsFresh {
		out := *st.last
		st.mu.Unlock()
		return out, nil
	}
	st.mu.Unlock()

	var cs []docker.ContainerSummary
	var ins map[string]docker.ContainerInspect
	var samples map[string]docker.Sample
	err := h.withDocker(ctx, id, func(e *dockerEngine) error {
		all, err := e.client.Containers(ctx)
		if err != nil {
			return err
		}
		cs = cs[:0]
		for _, c := range all {
			if c.Labels["com.docker.compose.project"] != "" && c.Labels["com.docker.compose.oneoff"] != "True" {
				cs = append(cs, c)
			}
		}
		ins = inspectAll(ctx, e, cs)
		samples = sampleRunning(ctx, e, cs)
		return nil
	})
	if err != nil {
		return DockerProjectStatsList{}, err
	}
	out := st.build(cs, ins, samples)
	st.mu.Lock()
	st.last = &out
	st.mu.Unlock()
	return out, nil
}

func inspectAll(ctx context.Context, e *dockerEngine, cs []docker.ContainerSummary) map[string]docker.ContainerInspect {
	out := map[string]docker.ContainerInspect{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, c := range cs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			ictx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if v, _, err := e.client.Inspect(ictx, c.ID, false); err == nil {
				mu.Lock()
				out[c.ID] = v
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out
}

func sampleRunning(ctx context.Context, e *dockerEngine, cs []docker.ContainerSummary) map[string]docker.Sample {
	out := map[string]docker.Sample{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	n := 0
	for _, c := range cs {
		if c.State != "running" {
			continue
		}
		if n++; n > projectStatsMeasure {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if s, err := e.client.StatsNow(sctx, c.ID); err == nil {
				mu.Lock()
				out[c.ID] = s
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out
}

func portsOf(ps []docker.Port) []DockerPortOut {
	out := []DockerPortOut{}
	for _, p := range ps {
		if p.PublicPort == 0 {
			continue
		}
		o := DockerPortOut{IP: p.IP, Public: p.PublicPort, Private: p.PrivatePort, Proto: p.Type}
		if o.IP == "0.0.0.0" || o.IP == "::" {
			o.IP = ""
		}
		if !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Public != out[j].Public {
			return out[i].Public < out[j].Public
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}

func (st *serverProjectStats) build(cs []docker.ContainerSummary, ins map[string]docker.ContainerInspect, samples map[string]docker.Sample) DockerProjectStatsList {
	now := time.Now().UTC()
	st.mu.Lock()
	defer st.mu.Unlock()
	byName := map[string]*DockerProjectStats{}
	seen := map[string]bool{}
	for _, c := range cs {
		name := c.Labels["com.docker.compose.project"]
		p := byName[name]
		if p == nil {
			p = &DockerProjectStats{Name: name, Ports: []DockerPortOut{}, Containers: []DockerProjectContainer{}, MeasuredAt: now}
			byName[name] = p
		}
		row := DockerProjectContainer{
			ID: c.ID, Name: containerName(c.Names), Service: c.Labels["com.docker.compose.service"],
			Image: c.Image, State: c.State, Status: c.Status, Health: "none", Ports: portsOf(c.Ports),
		}
		if v, ok := ins[c.ID]; ok {
			row.Restarts = v.RestartCount
			row.ExitCode = v.State.ExitCode
			row.OOMKilled = v.State.OOMKilled
			row.Error = strings.TrimSpace(v.State.Error)
			if t, err := time.Parse(time.RFC3339Nano, v.State.FinishedAt); err == nil && t.Year() > 2000 && c.State != "running" {
				t = t.UTC()
				row.FinishedAt = &t
			}
			if v.State.Health != nil && v.State.Health.Status != "" {
				row.Health = v.State.Health.Status
			}
			if t, err := time.Parse(time.RFC3339Nano, v.State.StartedAt); err == nil && t.Year() > 2000 && c.State == "running" {
				t = t.UTC()
				row.StartedAt = &t
			}
			hc := v.HostConfig
			row.RestartPolicy = hc.RestartPolicy.Name
			if row.RestartPolicy == "" {
				row.RestartPolicy = "no"
			}
			row.Privileged = hc.Privileged
			row.MemoryLimit = hc.Memory
			row.CPULimit = float64(hc.NanoCPUs) / 1e9
			row.Healthcheck = v.Config.Healthcheck != nil && len(v.Config.Healthcheck.Test) > 0 && v.Config.Healthcheck.Test[0] != "NONE"
			row.LogDriver = hc.LogConfig.Type
			row.LogMaxSize = hc.LogConfig.Config["max-size"]
			row.LogMaxFile = hc.LogConfig.Config["max-file"]
			row.ReadOnly = hc.ReadonlyRootfs
			row.User = v.Config.User
		} else {
			row.Health = containerHealth(c)
			if row.Health == "" {
				row.Health = "none"
			}
		}
		switch row.Health {
		case "healthy", "unhealthy", "starting":
		default:
			row.Health = "none"
		}
		s, ok := samples[c.ID]
		h, held := st.held[c.ID]
		held = held && !ok && c.State == "running" && now.Sub(h.s.Time) < projectStatsHold
		if held {
			s, ok = h.s, true
		}
		if ok {
			seen[c.ID] = true
			row.Measured = true
			row.CPU = s.CPUPercent
			row.MemoryUsed = s.MemoryUsed
			row.HostMemory = s.MemoryLimit
			row.Pids = s.Pids
			if held {
				row.NetRxRate, row.NetTxRate = h.rx, h.tx
			} else {
				if prev, ok := st.prev[c.ID]; ok && s.Time.After(prev.at) {
					secs := s.Time.Sub(prev.at).Seconds()
					if s.NetRx >= prev.rx && s.NetTx >= prev.tx {
						row.NetRxRate = float64(s.NetRx-prev.rx) / secs
						row.NetTxRate = float64(s.NetTx-prev.tx) / secs
					}
				} else {
					p.FirstSample = true
				}
				st.prev[c.ID] = netTotal{at: s.Time, rx: s.NetRx, tx: s.NetTx}
				st.held[c.ID] = heldSample{s: s, rx: row.NetRxRate, tx: row.NetTxRate}
			}
			p.CPU += row.CPU
			p.MemoryUsed += row.MemoryUsed
			p.NetRxRate += row.NetRxRate
			p.NetTxRate += row.NetTxRate
			if s.MemoryLimit > p.HostMemory && row.MemoryLimit == 0 {
				p.HostMemory = s.MemoryLimit
			}
			if s.CPUs > p.CPUs {
				p.CPUs = s.CPUs
			}
		} else if c.State == "running" {
			p.Unmeasured++
		}
		p.Total++
		if c.State == "running" {
			p.Running++
			if row.StartedAt != nil && (p.Since == nil || row.StartedAt.Before(*p.Since)) {
				p.Since = row.StartedAt
			}
		}
		switch row.Health {
		case "healthy":
			p.Healthy++
		case "unhealthy":
			p.Unhealthy++
		case "starting":
			p.Starting++
		}
		p.Restarts += row.Restarts
		for _, port := range row.Ports {
			if !slices.Contains(p.Ports, port) {
				p.Ports = append(p.Ports, port)
			}
		}
		p.Containers = append(p.Containers, row)
	}
	// Forget containers that are gone.
	for id := range st.prev {
		if !seen[id] {
			delete(st.prev, id)
		}
	}
	for id := range st.held {
		if !seen[id] {
			delete(st.held, id)
		}
	}
	out := DockerProjectStatsList{At: now, Projects: make([]DockerProjectStats, 0, len(byName))}
	for name, p := range byName {
		if p.HostMemory == 0 {
			for _, c := range p.Containers {
				p.HostMemory = max(p.HostMemory, c.HostMemory)
			}
		}
		hist := st.history[name]
		if n := len(hist); n == 0 || now.Sub(hist[n-1].At) >= projectStatsGap {
			hist = append(hist, DockerStatsPoint{At: now, CPU: p.CPU, Memory: p.MemoryUsed, NetRx: p.NetRxRate, NetTx: p.NetTxRate})
			if len(hist) > projectStatsPoints {
				hist = slices.Clone(hist[len(hist)-projectStatsPoints:])
			}
			st.history[name] = hist
		}
		p.History = slices.Clone(hist)
		sort.Slice(p.Ports, func(i, j int) bool { return p.Ports[i].Public < p.Ports[j].Public })
		sort.Slice(p.Containers, func(i, j int) bool { return p.Containers[i].Name < p.Containers[j].Name })
		out.Projects = append(out.Projects, *p)
	}
	for name := range st.history {
		if byName[name] == nil {
			delete(st.history, name)
		}
	}
	sort.Slice(out.Projects, func(i, j int) bool { return out.Projects[i].Name < out.Projects[j].Name })
	return out
}

// startProjectStatsLoop keeps measuring servers whose projects someone
// looked at lately, so their charts have a history when they come back.
func startProjectStatsLoop(h *serverHandler) {
	go func() {
		tick := time.NewTicker(projectStatsEvery)
		defer tick.Stop()
		for range tick.C {
			projectStatsByServer.Lock()
			var due []string
			for id, st := range projectStatsByServer.m {
				st.mu.Lock()
				watched := time.Since(st.asked) < projectStatsWatch
				if !watched && time.Since(st.asked) > 2*projectStatsWatch && time.Since(st.recorded) > 3*projectHistoryEvery {
					delete(projectStatsByServer.m, id)
				}
				st.mu.Unlock()
				if watched {
					due = append(due, id)
				}
			}
			projectStatsByServer.Unlock()
			for _, id := range due {
				go func() {
					ctx, cancel := context.WithTimeout(cmdlog.Background(context.Background(), "Container charts"), 25*time.Second)
					defer cancel()
					if _, err := h.projectStats(ctx, id, false); err != nil && ctx.Err() == nil {
						slog.Debug("docker: project stats", "server", id, "error", err)
					}
				}()
			}
		}
	}()
}

// ---- Logs ----

// projectContainers is the project's containers, optionally only some (by
// name, id or service).
func (h *serverHandler) projectContainers(ctx context.Context, e *dockerEngine, project string, only []string) ([]docker.ContainerSummary, error) {
	all, err := e.client.Containers(ctx)
	if err != nil {
		return nil, err
	}
	var out []docker.ContainerSummary
	for _, c := range all {
		if c.Labels["com.docker.compose.project"] != project {
			continue
		}
		if len(only) > 0 {
			name := containerName(c.Names)
			svc := c.Labels["com.docker.compose.service"]
			if !slices.ContainsFunc(only, func(o string) bool {
				return o == name || o == svc || strings.HasPrefix(c.ID, o)
			}) {
				continue
			}
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return containerName(out[i].Names) < containerName(out[j].Names) })
	if len(out) > projectLogsMax {
		out = out[:projectLogsMax]
	}
	return out, nil
}

func splitList(s string) []string {
	var out []string
	for v := range strings.SplitSeq(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func projectLine(c docker.ContainerSummary, l docker.LogLine) DockerProjectLogLine {
	out := DockerProjectLogLine{
		Container: containerName(c.Names), Service: c.Labels["com.docker.compose.service"],
		Stream: l.Stream, Text: l.Text,
	}
	if !l.Time.IsZero() {
		t := l.Time.UTC()
		out.Time = &t
	}
	return out
}

func sortLines(ls []DockerProjectLogLine) {
	sort.SliceStable(ls, func(i, j int) bool {
		a, b := ls[i].Time, ls[j].Time
		if a == nil || b == nil {
			return a == nil && b != nil
		}
		return a.Before(*b)
	})
}

// ---- Handlers ----

func registerDockerProjectStats(api huma.API, h *serverHandler) {
	tags := []string{"Containers"}

	huma.Register(api, huma.Operation{
		OperationID: "docker-project-stats",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/docker/project-stats",
		Summary:     "Live numbers for a server's compose projects",
		Description: "CPU, memory, network, health, restarts and ports per project and per container, plus a short history (kept in memory while someone looks, about one point every 10 to 30 seconds). Measuring takes a couple of seconds; answers are shared for a few seconds. `project` narrows the answer (the measurement still covers the whole server).",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Project string `query:"project" required:"false" maxLength:"63"`
	}) (*struct{ Body DockerProjectStatsList }, error) {
		out, err := h.projectStats(ctx, in.ID, true)
		if err != nil {
			return nil, err
		}
		if in.Project != "" {
			keep := []DockerProjectStats{}
			for _, p := range out.Projects {
				if p.Name == in.Project {
					keep = append(keep, p)
				}
			}
			out.Projects = keep
		}
		return &struct{ Body DockerProjectStatsList }{out}, nil
	})

	base := "/servers/{id}/docker/projects/{project}"

	huma.Register(api, huma.Operation{
		OperationID: "docker-project-logs",
		Method:      http.MethodGet,
		Path:        base + "/logs",
		Summary:     "A project's log",
		Description: "The logs of its containers (up to 40) merged by time: the last `tail` lines overall (up to 5000). `containers` = comma-separated names, ids or services to read only those.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerProjectPath
		Tail       int       `query:"tail" minimum:"1" maximum:"5000" default:"500"`
		Since      time.Time `query:"since" required:"false"`
		Until      time.Time `query:"until" required:"false"`
		Containers string    `query:"containers" required:"false" maxLength:"2000"`
	}) (*struct{ Body DockerProjectLogs }, error) {
		out := &struct{ Body DockerProjectLogs }{DockerProjectLogs{Lines: []DockerProjectLogLine{}, Containers: []DockerRef{}}}
		err := h.withDocker(ctx, in.ID, func(e *dockerEngine) error {
			cs, err := h.projectContainers(ctx, e, in.Project, splitList(in.Containers))
			if err != nil {
				return err
			}
			out.Body.Containers = refsOf(cs, func(docker.ContainerSummary) bool { return true })
			var mu sync.Mutex
			var wg sync.WaitGroup
			sem := make(chan struct{}, 6)
			var lines []DockerProjectLogLine
			for _, c := range cs {
				wg.Add(1)
				sem <- struct{}{}
				go func() {
					defer wg.Done()
					defer func() { <-sem }()
					lctx, cancel := context.WithTimeout(ctx, 20*time.Second)
					defer cancel()
					tty := false
					if v, _, err := e.client.Inspect(lctx, c.ID, false); err == nil {
						tty = v.Config.Tty
					}
					var mine []DockerProjectLogLine
					_ = e.client.Logs(lctx, c.ID, tty, docker.LogQuery{Tail: in.Tail, Since: in.Since, Until: in.Until}, func(l docker.LogLine) bool {
						mine = append(mine, projectLine(c, l))
						return true
					})
					if len(mine) >= in.Tail {
						mu.Lock()
						out.Body.Truncated = true
						mu.Unlock()
					}
					mu.Lock()
					lines = append(lines, mine...)
					mu.Unlock()
				}()
			}
			wg.Wait()
			sortLines(lines)
			if len(lines) > in.Tail {
				lines = lines[len(lines)-in.Tail:]
				out.Body.Truncated = true
			}
			if lines != nil {
				out.Body.Lines = lines
			}
			return nil
		})
		return out, err
	})

	sse.Register(api, huma.Operation{
		OperationID: "stream-docker-project-logs",
		Method:      http.MethodGet,
		Path:        base + "/logs/stream",
		Summary:     "Follow a project's log",
		Description: "Server-sent events: `lines` (batched, about four a second) from all its running containers (or `containers`), from `since` (default: now) on; `end` when every one of them stopped, or the stream failed. A container started later isn't picked up: connect again.",
		Tags:        tags,
	}, map[string]any{"lines": DockerProjectLogBatch{}, "end": DockerStreamEnd{}},
		func(ctx context.Context, in *struct {
			DockerProjectPath
			Since      time.Time `query:"since" required:"false"`
			Containers string    `query:"containers" required:"false" maxLength:"2000"`
		}, send sse.Sender) {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			var mu sync.Mutex
			batch := []DockerProjectLogLine{}
			var sendErr error
			flush := func() {
				mu.Lock()
				defer mu.Unlock()
				if len(batch) == 0 || sendErr != nil {
					return
				}
				sortLines(batch)
				if sendErr = send.Data(DockerProjectLogBatch{Lines: batch}); sendErr != nil {
					cancel()
				}
				batch = []DockerProjectLogLine{}
			}
			go func() {
				tick := time.NewTicker(250 * time.Millisecond)
				defer tick.Stop()
				pings := 0
				for {
					select {
					case <-ctx.Done():
						return
					case <-tick.C:
						flush()
						if pings++; pings%80 == 0 {
							mu.Lock()
							_ = send(sse.Message{Comment: "ping"})
							mu.Unlock()
						}
					}
				}
			}()
			since := in.Since
			if since.IsZero() {
				since = time.Now()
			}
			err := h.withDocker(ctx, in.ID, func(e *dockerEngine) error {
				cs, err := h.projectContainers(ctx, e, in.Project, splitList(in.Containers))
				if err != nil {
					return err
				}
				var wg sync.WaitGroup
				var first error
				var emu sync.Mutex
				followed := 0
				for _, c := range cs {
					if c.State != "running" {
						continue
					}
					followed++
					wg.Add(1)
					go func() {
						defer wg.Done()
						tty := false
						if v, _, err := e.client.Inspect(ctx, c.ID, false); err == nil {
							tty = v.Config.Tty
						}
						err := e.client.Logs(ctx, c.ID, tty, docker.LogQuery{Since: since, Follow: true}, func(l docker.LogLine) bool {
							mu.Lock()
							batch = append(batch, projectLine(c, l))
							full := len(batch) >= 500
							mu.Unlock()
							if full {
								flush()
							}
							return ctx.Err() == nil
						})
						if err != nil && ctx.Err() == nil {
							emu.Lock()
							if first == nil {
								first = err
							}
							emu.Unlock()
						}
					}()
				}
				if followed == 0 {
					return nil
				}
				wg.Wait()
				return first
			})
			if ctx.Err() != nil {
				return
			}
			flush()
			cancel()
			mu.Lock()
			defer mu.Unlock()
			_ = send.Data(streamEnd(err))
		})

	huma.Register(api, huma.Operation{
		OperationID: "set-docker-project-meta",
		Method:      http.MethodPut,
		Path:        base + "/meta",
		Summary:     "Name and describe a project",
		Description: "A display title and a note kept in Morche (the compose files don't change).",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerProjectPath
		Body DockerProjectMetaBody
	}) (*struct{ Body DockerProject }, error) {
		p, _, err := h.dockerProject(ctx, in.ID, in.Project)
		if err != nil {
			return nil, err
		}
		sid, err := uuid.Parse(in.ID)
		if err != nil {
			return nil, huma.Error404NotFound("server not found")
		}
		pr := principalOf(ctx)
		title := strings.TrimSpace(in.Body.Title)
		note := strings.TrimSpace(in.Body.Note)
		if _, err := h.q.UpsertDockerProjectMeta(ctx, sqlc.UpsertDockerProjectMetaParams{
			ServerID: sid, Project: p.Name, Title: title, Note: note,
			UpdatedByName: cmpOr(pr.User.FullName, pr.User.Username),
		}); err != nil {
			return nil, internalError(err)
		}
		p.Title, p.Note = title, note
		return &struct{ Body DockerProject }{p}, nil
	})
}
