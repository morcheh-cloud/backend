package api

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/storage"
)

// storageMonitor re-checks every storage's connection in the background, so
// a status doesn't stay "online" after the service went away.
type storageMonitor struct {
	h     *storageHandler
	every time.Duration

	mu      sync.Mutex
	running map[uuid.UUID]bool
}

func startStorageMonitor(h *storageHandler, every time.Duration) {
	if every <= 0 {
		return
	}
	m := &storageMonitor{h: h, every: every, running: map[uuid.UUID]bool{}}
	go m.loop()
}

// loop looks for storages due every few seconds and checks them a few at a
// time; one still being checked from the last round is skipped.
func (m *storageMonitor) loop() {
	sem := make(chan struct{}, checkConcurrency)
	for range time.Tick(min(m.every, 5*time.Second)) {
		due, err := m.h.q.ListStoragesDueForCheck(context.Background(), time.Now().Add(-m.every))
		if err != nil {
			slog.Warn("list storages due for check", "error", err)
			continue
		}
		for _, s := range due {
			if !m.claim(s.ID) {
				continue
			}
			sem <- struct{}{}
			go func(s sqlc.Storage) {
				defer func() { <-sem; m.unclaim(s.ID) }()
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				m.check(ctx, s)
			}(s)
		}
	}
}

// check connects afresh and records the outcome, like POST /check, but
// leaves the pooled connection alone: someone may be browsing through it.
func (m *storageMonitor) check(ctx context.Context, s sqlc.Storage) {
	cfg, err := m.h.config(s)
	if err != nil {
		slog.Warn("background storage check", "storage", s.ID, "error", err)
		return
	}
	f, info, err := storage.Open(ctx, cfg)
	if err == nil {
		f.Close()
	}
	m.h.record(ctx, s, info, err)
}

func (m *storageMonitor) claim(id uuid.UUID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running[id] {
		return false
	}
	m.running[id] = true
	return true
}

func (m *storageMonitor) unclaim(id uuid.UUID) {
	m.mu.Lock()
	delete(m.running, id)
	m.mu.Unlock()
}
