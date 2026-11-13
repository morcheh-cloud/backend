package api

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/cmdlog"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/notify"
)

// ---- Messages ----

// dockerNotify sends msg to the channels a server's container settings name.
// It runs in the background and never fails the caller.
func (h *serverHandler) dockerNotify(s sqlc.Server, channels []string, msg notify.Message) {
	if h.alerts == nil || h.alerts.up == nil || len(channels) == 0 {
		return
	}
	up := h.alerts.up
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if msg.At.IsZero() {
			msg.At = time.Now()
		}
		for _, raw := range channels {
			id, err := uuid.Parse(raw)
			if err != nil {
				continue
			}
			c, err := h.q.GetNotificationChannel(ctx, id)
			if err != nil || !c.Enabled || c.WorkspaceID != s.WorkspaceID {
				continue
			}
			ch, err := up.sendable(c)
			if err == nil {
				sctx, scancel := context.WithTimeout(ctx, 30*time.Second)
				err = notify.Send(sctx, ch, msg)
				scancel()
			}
			up.recordSend(ctx, c.ID, nil, msg.Title, err)
		}
	}()
}

// dockerLink is a link into the panel's containers pages for one server.
func (h *serverHandler) dockerLink(page string, s sqlc.Server) string {
	if h.alerts == nil || h.alerts.up == nil || h.alerts.up.panelURL == "" {
		return ""
	}
	return h.alerts.up.panelURL + "/containers/" + page + "?env=" + s.ID.String()
}

func listText(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:max], ", "), len(items)-max)
}

// notifyDockerUpdates tells the server's channels about images that newly
// have a version waiting.
func (h *serverHandler) notifyDockerUpdates(ctx context.Context, s sqlc.Server, images []string) {
	if len(images) == 0 {
		return
	}
	set, err := h.serverDockerSettings(ctx, s)
	if err != nil || !set.NotifyUpdates {
		return
	}
	title := fmt.Sprintf("New image version on %s", s.Name)
	if len(images) > 1 {
		title = fmt.Sprintf("%d new image versions on %s", len(images), s.Name)
	}
	h.dockerNotify(s, set.NotifyChannels, notify.Message{
		Event: "docker_update", Title: title,
		Text:   "A newer version is waiting for " + listText(images, 5) + ". Pull and recreate the containers from Updates.",
		URL:    h.dockerLink("updates", s),
		Fields: []notify.Field{{Name: "Server", Value: s.Name}, {Name: "Images", Value: fmt.Sprint(len(images))}},
		Data:   map[string]any{"server_id": s.ID.String(), "images": images},
	})
}

// scanWorse is an image whose scan found more vulnerabilities than before.
type scanWorse struct {
	image          string
	critical, high int
}

func (h *serverHandler) notifyDockerVulns(s sqlc.Server, set DockerSettings, worse []scanWorse) {
	if len(worse) == 0 || set.NotifyVulns == "off" {
		return
	}
	names := make([]string, len(worse))
	crit, high := 0, 0
	for i, w := range worse {
		names[i] = fmt.Sprintf("%s (%d critical, %d high)", w.image, w.critical, w.high)
		crit += w.critical
		high += w.high
	}
	title := fmt.Sprintf("New vulnerabilities in %s on %s", worse[0].image, s.Name)
	if len(worse) > 1 {
		title = fmt.Sprintf("New vulnerabilities in %d images on %s", len(worse), s.Name)
	}
	h.dockerNotify(s, set.NotifyChannels, notify.Message{
		Event: "docker_vulnerabilities", Title: title,
		Text:   "A scan found more vulnerabilities than last time: " + listText(names, 5) + ".",
		URL:    h.dockerLink("security", s),
		Fields: []notify.Field{{Name: "Server", Value: s.Name}, {Name: "Critical", Value: fmt.Sprint(crit)}, {Name: "High", Value: fmt.Sprint(high)}},
		Data:   map[string]any{"server_id": s.ID.String(), "images": names},
	})
}

// worseScan says whether row found more of what the settings watch than prev.
func worseScan(level string, prev *sqlc.DockerImageScan, row sqlc.UpsertDockerImageScanParams) bool {
	pc, ph := int32(0), int32(0)
	if prev != nil && prev.Error == "" {
		pc, ph = prev.Critical, prev.High
	}
	switch level {
	case "critical":
		return row.Critical > pc
	case "high":
		return row.Critical > pc || row.High > ph
	}
	return false
}

// ---- Automatic clean-up ----

// startDockerAutoPruneLoop cleans up servers whose container settings ask for
// it, as often as they say. Volumes are never touched.
func startDockerAutoPruneLoop(h *serverHandler) {
	go func() {
		for range time.Tick(time.Hour) {
			ids, err := h.q.DockerAutoPruneServers(context.Background())
			if err != nil {
				slog.Warn("list servers for automatic clean-up", "error", err)
				continue
			}
			for _, id := range ids {
				h.autoPrune(id)
			}
		}
	}()
}

func (h *serverHandler) autoPrune(id uuid.UUID) {
	ctx, cancel := context.WithTimeout(cmdlog.Background(context.Background(), "Docker clean-up"), 20*time.Minute)
	defer cancel()
	s, err := h.q.GetServer(ctx, id)
	if err != nil {
		return
	}
	set, err := h.serverDockerSettings(ctx, s)
	if err != nil || !set.PruneAuto {
		return
	}
	b := DockerPruneBody{Containers: set.PruneContainers, Images: set.PruneImages, Volumes: "none", Networks: set.PruneNetworks, BuildCache: set.PruneBuildCache}
	res, err := h.pruneDocker(ctx, nil, id.String(), b, set.PruneOlderHours, "")
	msg := ""
	if err != nil {
		msg = problemText(err)
		slog.Warn("automatic docker clean-up", "server", id, "error", err)
	}
	removed := res.Containers + res.Images + res.Networks + res.Caches
	if err := h.q.RecordDockerAutoPrune(ctx, sqlc.RecordDockerAutoPruneParams{ServerID: id, Space: res.Space, Removed: int32(removed), Error: truncate(msg, 500)}); err != nil {
		slog.Warn("record automatic docker clean-up", "error", err)
	}
}
