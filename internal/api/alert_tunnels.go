package api

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/tunnel"
)

// Tunnel alerts: a "tunnel_down" rule covers every tunnel in its workspace
// that something goes through. The servers, databases, clusters and monitors
// using a tunnel keep it busy (each is re-checked on its own), so its state
// says whether it works; the watcher feeds that state to the rules.

const tunnelAlertEvery = 20 * time.Second

func (h *tunnelHandler) startAlerts() {
	go func() {
		for range time.Tick(tunnelAlertEvery) {
			h.alertTick(context.Background())
		}
	}()
}

// stateOf is what a tunnel is doing: live when open, else what was stored.
func (h *tunnelHandler) stateOf(t sqlc.Tunnel) (status, message string) {
	if st, ok := h.mgr.State(t.ID.String()); ok {
		return st.Status, st.Message
	}
	return t.Status, t.StatusMessage
}

func (h *tunnelHandler) alertTick(ctx context.Context) {
	engine := h.servers.alerts
	if engine == nil {
		return
	}
	rules, err := h.q.EnabledTunnelAlertRules(ctx)
	if err != nil {
		slog.Warn("alerts: tunnel rules", "error", err)
		return
	}
	if len(rules) == 0 {
		return
	}
	inUse, err := h.q.TunnelsInUse(ctx)
	if err != nil {
		slog.Warn("alerts: tunnels in use", "error", err)
		return
	}
	byWS := map[uuid.UUID][]sqlc.Tunnel{}
	for _, t := range inUse {
		byWS[t.WorkspaceID] = append(byWS[t.WorkspaceID], t)
	}
	now := time.Now().UTC()
	for _, r := range rules {
		for _, t := range byWS[r.WorkspaceID] {
			status, message := h.stateOf(t)
			if status == tunnel.StatusConnecting {
				// Trying again: neither down nor back yet.
				continue
			}
			met := status == tunnel.StatusFailed
			v, detail := 0.0, ""
			if met {
				v, detail = 1, cmpOr(message, "the last try failed")
			}
			engine.step(ctx, r, tunnelTarget(t), met, v, detail, now)
		}
	}
}

// previewTunnels: who a tunnel rule would cover now.
func (h *alertRuleHandler) previewTunnels(ctx context.Context, ws uuid.UUID) (*AlertPreviewOutput, error) {
	out := &AlertPreviewOutput{}
	out.Body.Items = []AlertPreviewItem{}
	rows, err := h.q.TunnelsInUse(ctx)
	if err != nil {
		return nil, internalError(err)
	}
	for _, t := range rows {
		if t.WorkspaceID != ws {
			continue
		}
		status, message := t.Status, t.StatusMessage
		if h.tunnels != nil {
			status, message = h.tunnels.stateOf(t)
		}
		it := AlertPreviewItem{TargetID: t.ID.String(), TargetKind: "tunnel", TargetName: t.Name, Status: status}
		if status == tunnel.StatusFailed {
			v := 1.0
			it.Met, it.Value, it.Detail, it.At = true, &v, message, t.StatusAt
		}
		out.Body.Items = append(out.Body.Items, it)
	}
	metFirst(out.Body.Items)
	return out, nil
}
