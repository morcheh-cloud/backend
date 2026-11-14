package api

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/proxmox"
)

// pveMonitor re-checks every Proxmox cluster in the background and runs the
// clusters' alert rules (node down, storage full, a machine that stopped on
// its own) against what it read.
type pveMonitor struct {
	h     *pveHandler
	every time.Duration

	mu      sync.Mutex
	running map[uuid.UUID]bool
	// seen is each cluster's machines and whether they ran at the last look.
	seen map[uuid.UUID]map[int]bool
	// stopped is the machines that stopped without Morche stopping them,
	// until they run again or are gone.
	stopped map[uuid.UUID]map[int]string
}

// powerGrace is how long after Morche changed a machine's power a stop is
// counted as expected.
const powerGrace = 15 * time.Minute

func startPVEMonitor(h *pveHandler, every time.Duration) {
	if every <= 0 {
		return
	}
	m := &pveMonitor{
		h: h, every: every, running: map[uuid.UUID]bool{},
		seen: map[uuid.UUID]map[int]bool{}, stopped: map[uuid.UUID]map[int]string{},
	}
	go m.loop()
}

func (m *pveMonitor) loop() {
	sem := make(chan struct{}, checkConcurrency)
	for range time.Tick(min(m.every, 5*time.Second)) {
		due, err := m.h.q.ListPVEClustersDueForCheck(context.Background(), time.Now().Add(-m.every))
		if err != nil {
			slog.Warn("list Proxmox clusters due for check", "error", err)
			continue
		}
		for _, c := range due {
			if !m.claim(c.ID) {
				continue
			}
			sem <- struct{}{}
			go func(c sqlc.PveCluster) {
				defer func() { <-sem; m.unclaim(c.ID) }()
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				m.check(ctx, c)
			}(c)
		}
	}
}

func (m *pveMonitor) check(ctx context.Context, c sqlc.PveCluster) {
	cl, err := m.h.savedClient(c)
	if err != nil {
		slog.Warn("background Proxmox check", "cluster", c.ID, "error", err)
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	info, checkErr := cl.Check(cctx)
	cancel()
	saved, err := m.h.record(ctx, c.ID, info, checkErr)
	if err != nil {
		slog.Warn("record Proxmox check", "cluster", c.ID, "error", err)
		return
	}
	m.alerts(ctx, saved, cl, checkErr)
}

// rulesFor is the enabled Proxmox rules that cover a cluster.
func (m *pveMonitor) rulesFor(ctx context.Context, c sqlc.PveCluster) []sqlc.AlertRule {
	all, err := m.h.q.EnabledPVEAlertRules(ctx)
	if err != nil {
		slog.Warn("alerts: Proxmox rules", "error", err)
		return nil
	}
	out := []sqlc.AlertRule{}
	for _, r := range all {
		if r.WorkspaceID == c.WorkspaceID && pveCovered(r, c) {
			out = append(out, r)
		}
	}
	return out
}

// pveCovered says whether a Proxmox rule takes in a cluster.
func pveCovered(r sqlc.AlertRule, c sqlc.PveCluster) bool {
	if !pveMetric(r.Metric) {
		return false
	}
	return r.Scope != "clusters" || slices.Contains(r.ClusterIds, c.ID)
}

// pveReading is what a cluster says right now, in the terms rules use.
type pveReading struct {
	down        []string // offline nodes
	storage     []pveStorageUse
	stoppedText string
	stoppedN    int
}

type pveStorageUse struct {
	name string // "local-lvm on pve1", or the storage alone when shared
	pct  float64
}

func (m *pveMonitor) alerts(ctx context.Context, c sqlc.PveCluster, cl *proxmox.Client, checkErr error) {
	engine := m.h.servers.alerts
	if engine == nil {
		return
	}
	rules := m.rulesFor(ctx, c)
	if len(rules) == 0 {
		m.forget(c.ID)
		return
	}
	now := time.Now().UTC()
	target := clusterTarget(c)
	if checkErr != nil {
		// Unreachable: only "node down" can say anything, the rest waits.
		for _, r := range rules {
			if r.Metric == metricPVENodeDown {
				_, msg := pveStatus(checkErr)
				engine.step(ctx, r, target, true, 1, "the cluster can't be reached ("+cmpOr(msg, "no answer")+")", now)
			}
		}
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	res, err := cl.Resources(cctx, "")
	cancel()
	if err != nil {
		slog.Warn("alerts: Proxmox resources", "cluster", c.ID, "error", err)
		return
	}
	read := m.read(c.ID, res)
	for _, r := range rules {
		switch r.Metric {
		case metricPVENodeDown:
			n := len(read.down)
			engine.step(ctx, r, target, n > 0, float64(n), strings.Join(read.down, ", "), now)
		case metricPVEVMStopped:
			engine.step(ctx, r, target, read.stoppedN > 0, float64(read.stoppedN), read.stoppedText, now)
		case metricPVEStorageFull:
			met, worst, parts := false, 0.0, []string{}
			for i, s := range read.storage {
				if i == 0 || (r.Op == "below" && s.pct < worst) || (r.Op != "below" && s.pct > worst) {
					worst = s.pct
				}
				if breached(r, s.pct) {
					met = true
					parts = append(parts, fmt.Sprintf("%s %.0f%%", s.name, s.pct))
				}
			}
			if len(read.storage) == 0 {
				continue
			}
			engine.step(ctx, r, target, met, worst, strings.Join(parts, ", "), now)
		}
	}
}

// read turns the cluster's resources into a reading, and moves the record
// of which machines run along.
func (m *pveMonitor) read(cluster uuid.UUID, res []proxmox.Resource) pveReading {
	out := pveReading{}
	shared := map[string]bool{}
	now := map[int]bool{}
	names := map[int]string{}
	for _, r := range res {
		switch r.Type {
		case "node":
			if r.Status != "online" {
				out.down = append(out.down, r.Node)
			}
		case "storage":
			if r.MaxDisk <= 0 || r.Status != "available" {
				continue
			}
			name := r.Storage + " on " + r.Node
			if r.Shared == 1 {
				if shared[r.Storage] {
					continue
				}
				shared[r.Storage], name = true, r.Storage
			}
			out.storage = append(out.storage, pveStorageUse{name, float64(r.Disk) / float64(r.MaxDisk) * 100})
		case "qemu", "lxc":
			if r.Template == 1 {
				continue
			}
			now[r.VMID] = r.Status == "running"
			names[r.VMID] = guestName(r)
		}
	}
	sort.Strings(out.down)

	m.mu.Lock()
	defer m.mu.Unlock()
	before, known := m.seen[cluster]
	stopped := m.stopped[cluster]
	if stopped == nil {
		stopped = map[int]string{}
	}
	for id, running := range now {
		switch {
		case running:
			delete(stopped, id)
		case known && before[id] && !pvePowerMarked(cluster, id, powerGrace):
			stopped[id] = fmt.Sprintf("%s (%d)", names[id], id)
		}
	}
	for id := range stopped {
		if _, ok := now[id]; !ok {
			delete(stopped, id) // gone
		}
	}
	m.seen[cluster], m.stopped[cluster] = now, stopped
	ids := make([]int, 0, len(stopped))
	for id := range stopped {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, stopped[id])
	}
	out.stoppedN, out.stoppedText = len(ids), strings.Join(parts, ", ")
	return out
}

func (m *pveMonitor) forget(cluster uuid.UUID) {
	m.mu.Lock()
	delete(m.seen, cluster)
	delete(m.stopped, cluster)
	m.mu.Unlock()
}

func (m *pveMonitor) claim(id uuid.UUID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running[id] {
		return false
	}
	m.running[id] = true
	return true
}

func (m *pveMonitor) unclaim(id uuid.UUID) {
	m.mu.Lock()
	delete(m.running, id)
	m.mu.Unlock()
}
