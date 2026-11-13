package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/cmdlog"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/docker"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/sshprobe"
)

// Container alert rules are read here, once a minute, on every online
// server a rule covers: one container list per server, the engine's recent
// "die" events only when a restarts rule asks, and resource use only for the
// running containers a CPU or memory rule watches.

const (
	dockerAlertEvery = time.Minute
	// restartWindow is how far back container_restarts counts stops.
	restartWindow = 10 * time.Minute
	// At most this many containers are measured per server and pass.
	dockerAlertStatsMax = 60
)

// containerWhich names what a container rule watches, for messages.
func containerWhich(r sqlc.AlertRule) string {
	switch {
	case r.Project != "" && r.Container != "":
		return r.Container + " in " + r.Project
	case r.Project != "":
		return "a container of " + r.Project
	case r.Container != "":
		return r.Container
	}
	return "a container"
}

// globMatch matches a name against a pattern where * is anything; without
// a wildcard it's a plain, case-insensitive comparison.
func globMatch(pattern, name string) bool {
	pattern, name = strings.ToLower(pattern), strings.ToLower(name)
	if !strings.ContainsAny(pattern, "*?[") {
		return pattern == name
	}
	ok, _ := path.Match(pattern, name)
	return ok
}

// containerWatched says whether a rule's project/container filter takes a
// container in.
func containerWatched(r sqlc.AlertRule, project, name, service string) bool {
	if r.Project != "" && !globMatch(r.Project, project) {
		return false
	}
	if r.Container != "" && !globMatch(r.Container, name) && !globMatch(r.Container, service) {
		return false
	}
	return true
}

var exitedRe = regexp.MustCompile(`^Exited \((\d+)\)`)

// exitCode reads "Exited (137) 2 hours ago"; -1 when the status doesn't say.
func exitCode(status string) int {
	if m := exitedRe.FindStringSubmatch(status); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return -1
}

// containerDown says whether a container counts as down for a rule. With
// a project or container named, anything not running does; without, only
// crashes (an error exit code, or stuck restarting), so containers stopped
// on purpose and finished one-off runs stay quiet.
func containerDown(r sqlc.AlertRule, c docker.ContainerSummary) (bool, string) {
	switch c.State {
	case "running":
		return false, ""
	case "restarting":
		return true, "restarting"
	}
	code := exitCode(c.Status)
	named := r.Project != "" || r.Container != ""
	if !named {
		if c.Labels["com.docker.compose.oneoff"] == "True" || c.State == "created" || c.State == "paused" {
			return false, ""
		}
		// 0 = finished, 143 = stopped (SIGTERM).
		if code == 0 || code == 143 || code == -1 {
			return false, ""
		}
	}
	if code >= 0 {
		return true, "exit " + strconv.Itoa(code)
	}
	return true, c.State
}

func containerHealth(c docker.ContainerSummary) string {
	if c.Health != nil && c.Health.Status != "" {
		return c.Health.Status
	}
	switch {
	case strings.Contains(c.Status, "(unhealthy)"):
		return "unhealthy"
	case strings.Contains(c.Status, "(healthy)"):
		return "healthy"
	case strings.Contains(c.Status, "(health: starting)"):
		return "starting"
	}
	return ""
}

func startDockerAlertLoop(h *serverHandler) {
	go func() {
		var mu sync.Mutex
		busy := map[uuid.UUID]bool{}
		for range time.Tick(dockerAlertEvery) {
			ctx := context.Background()
			rules, err := h.q.EnabledContainerAlertRules(ctx)
			if err != nil {
				slog.Warn("alerts: container rules", "error", err)
				continue
			}
			if len(rules) == 0 {
				continue
			}
			byWorkspace := map[uuid.UUID][]sqlc.AlertRule{}
			for _, r := range rules {
				byWorkspace[r.WorkspaceID] = append(byWorkspace[r.WorkspaceID], r)
			}
			for ws, rs := range byWorkspace {
				servers, err := h.q.ListServers(ctx, sqlc.ListServersParams{
					SeeAll: true, WorkspaceID: &ws, WorkspaceIds: []uuid.UUID{}, ServerIds: []uuid.UUID{},
					OsIds: []string{}, Statuses: []string{}, Tags: []string{}, AuthMethods: []string{},
					Sort: "name", Lim: 10000,
				})
				if err != nil {
					slog.Warn("alerts: servers for container rules", "workspace", ws, "error", err)
					continue
				}
				for _, row := range servers {
					s := row.Server
					var mine []sqlc.AlertRule
					for _, r := range rs {
						if ruleCovers(r, s) {
							mine = append(mine, r)
						}
					}
					if len(mine) == 0 || s.Status != sshprobe.StatusOnline {
						continue
					}
					mu.Lock()
					if busy[s.ID] || len(busy) >= 4 {
						mu.Unlock()
						continue
					}
					busy[s.ID] = true
					mu.Unlock()
					go func() {
						defer func() {
							mu.Lock()
							delete(busy, s.ID)
							mu.Unlock()
						}()
						h.checkContainerRules(s, mine)
					}()
				}
			}
		}
	}()
}

// containerReading is what one pass found on a server.
type containerReading struct {
	containers []docker.ContainerSummary
	stops      map[string]int // container name → "die" events in the window
	stats      map[string]docker.Sample
	scans      map[string]sqlc.DockerImageScan // image id → its last good scan
}

func (h *serverHandler) checkContainerRules(s sqlc.Server, rules []sqlc.AlertRule) {
	ctx, cancel := context.WithTimeout(cmdlog.Background(context.Background(), "Alerts"), 50*time.Second)
	defer cancel()
	needStops, needStats, needScans := false, false, false
	for _, r := range rules {
		needStops = needStops || r.Metric == metricContainerRestarts
		needStats = needStats || r.Metric == metricContainerCPU || r.Metric == metricContainerMemory
		needScans = needScans || vulnMetric(r.Metric)
	}
	now := time.Now().UTC()
	var read containerReading
	if needScans {
		read.scans = map[string]sqlc.DockerImageScan{}
		rows, err := h.q.ListDockerImageScans(ctx, s.ID)
		if err != nil {
			slog.Warn("alerts: image scans", "server", s.ID, "error", err)
			return
		}
		for _, r := range rows {
			if r.Error == "" {
				read.scans[r.ImageID] = r
			}
		}
	}
	var engineErr error
	err := h.withConn(ctx, s.ID.String(), func(c *sshpool.Conn) error {
		e, err := h.engine(ctx, s.ID.String(), c)
		if err != nil {
			engineErr = err
			return nil
		}
		if read.containers, err = e.client.Containers(ctx); err != nil {
			return err
		}
		if needStops {
			read.stops = map[string]int{}
			evs, err := e.client.Events(ctx, now.Add(-restartWindow), now,
				map[string][]string{"type": {"container"}, "event": {"die"}}, 5000)
			if err != nil {
				return err
			}
			for _, ev := range evs {
				if n := ev.Actor.Attributes["name"]; n != "" {
					read.stops[n]++
				}
			}
		}
		if needStats {
			read.stats = h.measureForRules(ctx, e, read.containers, rules)
		}
		return nil
	})
	if err != nil {
		if ctx.Err() == nil {
			slog.Debug("alerts: read containers", "server", s.ID, "error", err)
		}
		return
	}
	e := h.alerts
	t := serverTarget(s)
	var un *dockerUnavailable
	if engineErr != nil {
		if !errors.As(engineErr, &un) {
			return // the connection broke: the next pass asks again
		}
		down := un.state != dockerNotInstalled
		for _, r := range rules {
			if r.Metric == metricDockerEngine {
				v := 0.0
				if down {
					v = 1
				}
				e.step(ctx, r, t, down, v, un.message, now)
			}
		}
		return
	}
	for _, r := range rules {
		met, v, detail := evalContainerRule(r, read)
		e.step(ctx, r, t, met, v, detail, now)
	}
	if needScans {
		h.autoScan(s, rules, read)
	}
}

// Images a vulnerability rule watches are scanned by Morche itself when
// they have no scan or it's older than a day, so a rule never waits on
// someone pressing Scan. At most one such job per server every few hours.
const (
	autoScanAge   = 24 * time.Hour
	autoScanEvery = 6 * time.Hour
)

var (
	autoScanMu   sync.Mutex
	autoScanLast = map[uuid.UUID]time.Time{}
)

func (h *serverHandler) autoScan(s sqlc.Server, rules []sqlc.AlertRule, read containerReading) {
	var ids []string
	seen := map[string]bool{}
	for _, c := range read.containers {
		if c.State != "running" || seen[c.ImageID] || !strings.HasPrefix(c.ImageID, "sha256:") {
			continue
		}
		name := containerName(c.Names)
		watched := false
		for _, r := range rules {
			if vulnMetric(r.Metric) && containerWatched(r, c.Labels["com.docker.compose.project"], name, c.Labels["com.docker.compose.service"]) {
				watched = true
				break
			}
		}
		if !watched {
			continue
		}
		seen[c.ImageID] = true
		if sc, ok := read.scans[c.ImageID]; !ok || time.Since(sc.ScannedAt) > autoScanAge {
			ids = append(ids, c.ImageID)
		}
	}
	if len(ids) == 0 {
		return
	}
	autoScanMu.Lock()
	if time.Since(autoScanLast[s.ID]) < autoScanEvery {
		autoScanMu.Unlock()
		return
	}
	autoScanLast[s.ID] = time.Now()
	autoScanMu.Unlock()
	if len(ids) > 30 {
		ids = ids[:30]
	}
	id := s.ID.String()
	if _, err := h.jobs.Submit(context.Background(), jobs.Spec{
		Kind: dockerScanKind, Title: "Scan " + plural(len(ids), "image") + " on " + s.Name + " (for alert rules)",
		Params: dockerScanParams{ServerID: id, Images: ids},
		Refs:   placeRefs(id), Target: &JobPlace{ServerID: id, Name: s.Name},
	}); err != nil {
		slog.Warn("alerts: start an image scan", "server", s.ID, "error", err)
	}
}

// measureForRules reads resource use of the running containers a CPU or
// memory rule watches, a few at a time.
func (h *serverHandler) measureForRules(ctx context.Context, e *dockerEngine, cs []docker.ContainerSummary, rules []sqlc.AlertRule) map[string]docker.Sample {
	var want []docker.ContainerSummary
	for _, c := range cs {
		if c.State != "running" {
			continue
		}
		name := containerName(c.Names)
		for _, r := range rules {
			if (r.Metric == metricContainerCPU || r.Metric == metricContainerMemory) &&
				containerWatched(r, c.Labels["com.docker.compose.project"], name, c.Labels["com.docker.compose.service"]) {
				want = append(want, c)
				break
			}
		}
		if len(want) >= dockerAlertStatsMax {
			break
		}
	}
	out := map[string]docker.Sample{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, c := range want {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if st, err := e.client.StatsNow(sctx, c.ID); err == nil {
				mu.Lock()
				out[c.ID] = st
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out
}

type offender struct {
	name string
	v    float64
	note string
}

// evalContainerRule says whether a rule holds on what a pass read: v is
// how many containers are down/unhealthy, the most stops, or the worst
// CPU/memory.
func evalContainerRule(r sqlc.AlertRule, read containerReading) (bool, float64, string) {
	var bad []offender
	best, seen := 0.0, false
	for _, c := range read.containers {
		name := containerName(c.Names)
		if !containerWatched(r, c.Labels["com.docker.compose.project"], name, c.Labels["com.docker.compose.service"]) {
			continue
		}
		switch r.Metric {
		case metricContainerDown:
			if down, why := containerDown(r, c); down {
				bad = append(bad, offender{name: name, note: why})
			}
		case metricContainerUnhealthy:
			if containerHealth(c) == "unhealthy" {
				bad = append(bad, offender{name: name})
			}
		case metricContainerRestarts:
			n := float64(read.stops[name])
			if n > best || !seen {
				best, seen = max(n, best), true
			}
			if n > r.Threshold {
				bad = append(bad, offender{name: name, v: n, note: fmt.Sprintf("%g×", n)})
			}
		case metricVulnsCritical, metricVulnsHigh:
			if c.State != "running" {
				continue
			}
			sc, ok := read.scans[c.ImageID]
			if !ok {
				continue
			}
			n := float64(sc.Critical)
			if r.Metric == metricVulnsHigh {
				n += float64(sc.High)
			}
			if !seen || n > best {
				best, seen = n, true
			}
			if n > r.Threshold {
				bad = append(bad, offender{name: name, v: n, note: formatMetric(r.Metric, n) + " in " + sc.Image})
			}
		case metricContainerCPU, metricContainerMemory:
			st, ok := read.stats[c.ID]
			if !ok {
				continue
			}
			v := st.CPUPercent
			if r.Metric == metricContainerMemory {
				if st.MemoryLimit <= 0 {
					continue
				}
				v = float64(st.MemoryUsed) / float64(st.MemoryLimit) * 100
			}
			if !seen || (r.Op == "below" && v < best) || (r.Op != "below" && v > best) {
				best, seen = v, true
			}
			if breached(r, v) {
				bad = append(bad, offender{name: name, v: v, note: formatMetric(r.Metric, v)})
			}
		}
	}
	switch r.Metric {
	case metricContainerDown, metricContainerUnhealthy:
		best = float64(len(bad))
	default:
		slices.SortFunc(bad, func(a, b offender) int {
			if r.Op == "below" {
				return cmpFloat(a.v, b.v)
			}
			return cmpFloat(b.v, a.v)
		})
	}
	parts := make([]string, 0, len(bad))
	for i, b := range bad {
		if i == 8 {
			parts = append(parts, fmt.Sprintf("and %d more", len(bad)-8))
			break
		}
		if b.note != "" {
			parts = append(parts, b.name+" ("+b.note+")")
		} else {
			parts = append(parts, b.name)
		}
	}
	return len(bad) > 0, best, strings.Join(parts, ", ")
}

func cmpFloat(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
