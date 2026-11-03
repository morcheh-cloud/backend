package api

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
)

// serverMonitor re-checks every server's connection in the background, so a
// status doesn't stay "online" after the server went away.
type serverMonitor struct {
	h     *serverHandler
	every time.Duration

	mu      sync.Mutex
	running map[uuid.UUID]bool
}

func startServerMonitor(h *serverHandler, every time.Duration) {
	if every <= 0 {
		return
	}
	m := &serverMonitor{h: h, every: every, running: map[uuid.UUID]bool{}}
	go m.loop()
}

// loop looks for servers due every few seconds and checks them a few at a
// time. A server still being checked from the last round is skipped (an
// unreachable one takes up to the probe's 15 s timeout).
func (m *serverMonitor) loop() {
	sem := make(chan struct{}, checkConcurrency)
	for range time.Tick(min(m.every, 5*time.Second)) {
		due, err := m.h.q.ListServersDueForCheck(context.Background(), time.Now().Add(-m.every))
		if err != nil {
			slog.Warn("list servers due for check", "error", err)
			continue
		}
		for _, s := range due {
			if !m.claim(s.ID) {
				continue
			}
			sem <- struct{}{}
			go func(s sqlc.Server) {
				defer func() { <-sem; m.unclaim(s.ID) }()
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				if _, err := m.h.check(ctx, s); err != nil {
					slog.Warn("background server check", "server", s.ID, "error", err)
				}
			}(s)
		}
	}
}

func (m *serverMonitor) claim(id uuid.UUID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running[id] {
		return false
	}
	m.running[id] = true
	return true
}

func (m *serverMonitor) unclaim(id uuid.UUID) {
	m.mu.Lock()
	delete(m.running, id)
	m.mu.Unlock()
}
