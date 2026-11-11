package api

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/sse"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/cmdlog"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/sysstats"
)

// StatsProblem is sent on the stream instead of stats while they can't be read.
type StatsProblem struct {
	Status   int    `json:"status" doc:"What a request would have failed with: 404 no such server, 422 not Linux, 409 host key mismatch, 502 can't connect" example:"502"`
	Detail   string `json:"detail" example:"Lost the connection to the server"`
	Retrying bool   `json:"retrying" doc:"The backend keeps trying and the stream resumes on its own; false means it's final"`
}

func registerStats(api huma.API, h *serverHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "get-server-stats",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/stats",
		Summary:     "Live resource usage",
		Description: "Uptime, CPU, memory, disks and network, read from /proc and df over SSH. " +
			"CPU and network are sampled over one second, so the request takes about that long. " +
			"Linux only (422 elsewhere). For a live view use the stream.",
		Tags: []string{"Servers"},
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body sysstats.Stats }, error) {
		var out string
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) (err error) {
			out, err = run(ctx, c, sysstats.Script)
			return err
		})
		if err != nil {
			return nil, toProblem(err)
		}
		s, err := sysstats.Parse(out, time.Now().UTC())
		if errors.Is(err, sysstats.ErrUnsupported) {
			return nil, huma.Error422UnprocessableEntity(unsupportedStats)
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &struct{ Body sysstats.Stats }{s}, nil
	})

	sse.Register(api, huma.Operation{
		OperationID: "stream-server-stats",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/stats/stream",
		Summary:     "Stream live resource usage",
		Description: "Server-sent events: `stats` every second, `problem` while they can't be read. " +
			"One script runs on the server however many clients watch; a new client gets the latest event at once.",
		Tags: []string{"Servers"},
	}, map[string]any{"stats": sysstats.Stats{}, "problem": StatsProblem{}},
		func(ctx context.Context, in *ServerIDPath, send sse.Sender) {
			if _, err := uuid.Parse(in.ID); err != nil {
				send.Data(StatsProblem{Status: http.StatusNotFound, Detail: "server not found"})
				return
			}
			events, leave := h.stats.subscribe(in.ID)
			defer leave()
			// Comments keep proxies from timing out a quiet stream (retry waits).
			ping := time.NewTicker(20 * time.Second)
			defer ping.Stop()
			for {
				var err error
				select {
				case <-ctx.Done():
					return
				case ev := <-events:
					err = send.Data(ev)
				case <-ping.C:
					err = send(sse.Message{Comment: "ping"})
				}
				if err != nil {
					return
				}
			}
		})
}

const unsupportedStats = "Live stats are only available for Linux servers"

// statsHub runs one stats script per watched server and fans its frames out
// to every watcher. A feed outlives its last watcher by statsGrace, so a
// reload or a quick tab switch doesn't restart it.
type statsHub struct {
	h     *serverHandler
	mu    sync.Mutex
	feeds map[string]*statsFeed
}

const (
	statsGrace    = 10 * time.Second
	statsStall    = 20 * time.Second // no frame for this long: restart the script
	statsRetryMin = 2 * time.Second
	statsRetryMax = 30 * time.Second
)

type statsFeed struct {
	subs map[chan any]struct{}
	last any // *sysstats.Stats or StatsProblem
	stop context.CancelFunc
	idle *time.Timer
}

func newStatsHub(h *serverHandler) *statsHub {
	return &statsHub{h: h, feeds: map[string]*statsFeed{}}
}

// subscribe returns a channel holding the newest event (older ones the
// watcher didn't get to are dropped) and a func to stop watching.
func (hub *statsHub) subscribe(id string) (<-chan any, func()) {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	f := hub.feeds[id]
	if f == nil {
		ctx, stop := context.WithCancel(context.Background())
		f = &statsFeed{subs: map[chan any]struct{}{}, stop: stop}
		hub.feeds[id] = f
		go hub.run(ctx, id, f)
	}
	if f.idle != nil {
		f.idle.Stop()
		f.idle = nil
	}
	ch := make(chan any, 1)
	if f.last != nil {
		ch <- f.last
	}
	f.subs[ch] = struct{}{}

	return ch, func() {
		hub.mu.Lock()
		defer hub.mu.Unlock()
		delete(f.subs, ch)
		if len(f.subs) == 0 && f.idle == nil {
			f.idle = time.AfterFunc(statsGrace, func() {
				hub.mu.Lock()
				defer hub.mu.Unlock()
				if len(f.subs) == 0 && hub.feeds[id] == f {
					delete(hub.feeds, id)
					f.stop()
				}
			})
		}
	}
}

func (hub *statsHub) broadcast(f *statsFeed, ev any) {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	f.last = ev
	for ch := range f.subs {
		select { // only we send, under the lock, so after a drain there's room
		case <-ch:
		default:
		}
		ch <- ev
	}
}

// run keeps the script going, retrying with backoff, until the feed stops
// or the error is final.
func (hub *statsHub) run(ctx context.Context, id string, f *statsFeed) {
	wait := statsRetryMin
	for {
		err := hub.stream(ctx, id, func(s sysstats.Stats) {
			wait = statsRetryMin
			hub.broadcast(f, &s)
		})
		if ctx.Err() != nil {
			return
		}
		p := statsProblem(err)
		hub.broadcast(f, p)
		if !p.Retrying {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, statsRetryMax)
	}
}

// stream runs StreamScript on one SSH session until it ends.
func (hub *statsHub) stream(ctx context.Context, id string, emit func(sysstats.Stats)) error {
	c, err := hub.h.conn(ctx, id)
	if err != nil {
		return err
	}
	c.Acquire() // keep the pool from closing it as idle
	defer c.Release()

	sess, err := c.Session(cmdlog.Background(ctx, "Live resources"))
	if err != nil {
		hub.h.pool.Drop(id) // a half-dead connection; redial next time
		return err
	}
	defer sess.Close()
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return err
	}
	if err := sess.Start(sysstats.StreamScript); err != nil {
		return err
	}

	stalled := time.AfterFunc(statsStall, func() { sess.Close() })
	defer stalled.Stop()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
		case <-c.Done():
		case <-done:
			return
		}
		sess.Close()
	}()

	now := func() time.Time { return time.Now().UTC() }
	return sysstats.Stream(stdout, now, func(s sysstats.Stats) {
		stalled.Reset(statsStall)
		emit(s)
	})
}

func statsProblem(err error) StatsProblem {
	if errors.Is(err, sysstats.ErrUnsupported) {
		return StatsProblem{Status: http.StatusUnprocessableEntity, Detail: unsupportedStats}
	}
	p := StatsProblem{Status: http.StatusBadGateway, Detail: "Lost the connection to the server", Retrying: true}
	var se huma.StatusError
	if errors.As(toProblem(err), &se) {
		p.Status, p.Detail = se.GetStatus(), se.Error()
	}
	p.Retrying = p.Status != http.StatusNotFound
	return p
}
