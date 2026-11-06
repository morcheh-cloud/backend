package api

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
)

// dnsMonitor re-checks every DNS server's connection in the background, so a
// status doesn't stay "online" after the server went away.
type dnsMonitor struct {
	h     *dnsHandler
	every time.Duration

	mu      sync.Mutex
	running map[uuid.UUID]bool
}

func startDNSMonitor(h *dnsHandler, every time.Duration) {
	if every <= 0 {
		return
	}
	m := &dnsMonitor{h: h, every: every, running: map[uuid.UUID]bool{}}
	go m.loop()
}

func (m *dnsMonitor) loop() {
	sem := make(chan struct{}, checkConcurrency)
	for range time.Tick(min(m.every, 5*time.Second)) {
		due, err := m.h.q.ListDNSServersDueForCheck(context.Background(), time.Now().Add(-m.every))
		if err != nil {
			slog.Warn("list DNS servers due for check", "error", err)
			continue
		}
		for _, s := range due {
			if !m.claim(s.ID) {
				continue
			}
			sem <- struct{}{}
			go func(s sqlc.DnsServer) {
				defer func() { <-sem; m.unclaim(s.ID) }()
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				m.check(ctx, s)
			}(s)
		}
	}
}

func (m *dnsMonitor) check(ctx context.Context, s sqlc.DnsServer) {
	c, err := m.h.savedClient(s)
	if err != nil {
		slog.Warn("background DNS check", "server", s.ID, "error", err)
		return
	}
	info, checkErr := c.Check(ctx)
	if _, err := m.h.record(ctx, s.ID, info, checkErr); err != nil {
		slog.Warn("record DNS check", "server", s.ID, "error", err)
	}
}

func (m *dnsMonitor) claim(id uuid.UUID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running[id] {
		return false
	}
	m.running[id] = true
	return true
}

func (m *dnsMonitor) unclaim(id uuid.UUID) {
	m.mu.Lock()
	delete(m.running, id)
	m.mu.Unlock()
}
