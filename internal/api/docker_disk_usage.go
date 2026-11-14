package api

import (
	"context"
	"sync"
	"time"

	"github.com/morcheh/backend/internal/docker"
)

// `docker system df` is slow: the engine walks every volume and container
// layer (seconds to minutes on a server with a lot of data). Each server's
// last answer is kept here: reads get it at once and a newer one is measured
// behind them, one at a time per server. Only a server never measured waits.

const (
	// Younger than this, a read doesn't start a new measurement.
	diskUsageFresh = 30 * time.Second
	// A measurement that runs longer is given up.
	diskUsageTimeout = 5 * time.Minute
)

type diskUsageEntry struct {
	du docker.DiskUsage
	at time.Time // when du was measured; zero = never yet
	// A change went through the engine since du was measured.
	stale bool
	gen   int
	// Closed when the measurement in flight ends; nil = none running.
	running chan struct{}
	err     error // of the last measurement
}

type diskUsageCache struct {
	mu    sync.Mutex
	items map[string]*diskUsageEntry
}

// entry returns id's entry, made if missing. The caller holds mu.
func (c *diskUsageCache) entry(id string) *diskUsageEntry {
	if c.items == nil {
		c.items = map[string]*diskUsageEntry{}
	}
	e := c.items[id]
	if e == nil {
		e = &diskUsageEntry{}
		c.items[id] = e
	}
	return e
}

// changed marks a server's numbers out of date: the next read measures again.
func (c *diskUsageCache) changed(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.items[id]; e != nil {
		e.stale = true
		e.gen++
	}
}

func (c *diskUsageCache) drop(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, id)
}

type diskUsageRead struct {
	du        docker.DiskUsage
	at        time.Time
	measuring bool
}

// diskUsage answers the server's last measurement. refresh, an out of date
// one or one older than diskUsageFresh starts a new measurement behind it.
func (h *serverHandler) diskUsage(ctx context.Context, id string, refresh bool) (diskUsageRead, error) {
	c := &h.diskUsages
	c.mu.Lock()
	e := c.entry(id)
	if !e.at.IsZero() {
		if e.running == nil && (refresh || e.stale || time.Since(e.at) > diskUsageFresh) {
			h.measureDiskUsage(ctx, id, e)
		}
		r := diskUsageRead{du: e.du, at: e.at, measuring: e.running != nil}
		c.mu.Unlock()
		return r, nil
	}
	if e.running == nil {
		h.measureDiskUsage(ctx, id, e)
	}
	done := e.running
	c.mu.Unlock()

	select {
	case <-done:
	case <-ctx.Done():
		return diskUsageRead{}, ctx.Err()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e.at.IsZero() {
		return diskUsageRead{}, e.err
	}
	return diskUsageRead{du: e.du, at: e.at, measuring: e.running != nil}, nil
}

// measureDiskUsage starts measuring id in the background. The caller holds
// the cache's mu.
func (h *serverHandler) measureDiskUsage(ctx context.Context, id string, e *diskUsageEntry) {
	done := make(chan struct{})
	e.running = done
	gen := e.gen
	// Not cut short with the request that started it: others wait on it too.
	mctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), diskUsageTimeout)
	go func() {
		defer cancel()
		var du docker.DiskUsage
		err := h.withDocker(mctx, id, func(d *dockerEngine) error {
			var err error
			du, err = d.client.DiskUsage(mctx)
			return err
		})
		c := &h.diskUsages
		c.mu.Lock()
		e.err = err
		if err == nil {
			e.du, e.at = du, time.Now()
			// A change made while it measured may not be in it.
			e.stale = e.gen != gen
		}
		e.running = nil
		c.mu.Unlock()
		close(done)
	}()
}
