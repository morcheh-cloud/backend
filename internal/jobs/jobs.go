// Package jobs runs long operations in the background: transfers, archives,
// downloads onto a server. A job is a row in the jobs table plus, while it is
// queued or running, an entry in the Runner's memory that holds its live
// progress. Handlers are registered by kind, so a queued job survives a
// restart and a finished one can be retried from its params alone.
//
// Jobs run in this process: there is one backend, so a database queue with
// workers polling it would only add latency. Limits keep a busy server or
// storage from being hammered: at most Limit jobs run at once, and at most
// PerRef of them touch the same server or storage.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/morcheh/backend/internal/database/sqlc"
)

const (
	Queued      = "queued"
	Running     = "running"
	Succeeded   = "succeeded"
	Failed      = "failed"
	Canceled    = "canceled"
	Interrupted = "interrupted"
)

// Active reports whether a job in this state hasn't finished yet.
func Active(state string) bool { return state == Queued || state == Running }

const (
	keep      = 30 * 24 * time.Hour // finished jobs are deleted after this
	logCap    = 32 << 10            // bytes of log kept, newest last
	tick      = 500 * time.Millisecond
	saveEvery = 3 * time.Second // progress writes to the database
)

var (
	ErrNotFound = errors.New("job not found")
	ErrFinished = errors.New("the job has already finished")
	ErrActive   = errors.New("the job is still queued or running")
	ErrLocked   = errors.New("the job is at a step that can't be stopped safely")
)

// Progress is what a running job reports. Every field is optional; Total 0
// means the size isn't known (an indeterminate bar).
type Progress struct {
	Phase      string  `json:"phase,omitempty" doc:"What it's doing now" example:"Copying"`
	Current    string  `json:"current,omitempty" doc:"The file it's on" example:"backup/db.sql.gz"`
	Done       int64   `json:"done" doc:"Bytes done"`
	Total      int64   `json:"total" doc:"Bytes in all; 0 = not known"`
	Items      int     `json:"items" doc:"Files (or other units) done"`
	ItemsTotal int     `json:"items_total" doc:"Files in all; 0 = not known"`
	Rate       float64 `json:"rate" doc:"Bytes per second, smoothed"`
	Locked     bool    `json:"locked" doc:"At a step that can't be stopped safely; cancel answers 409 until it's over"`
}

// Handler runs one job. It returns what the job produced (stored as JSON) or
// an error; the error's message is shown to the user as is. It must stop
// when ctx is done.
type Handler func(ctx context.Context, t *Task) (any, error)

// Spec is a job to submit.
type Spec struct {
	Kind   string
	Title  string
	Params any
	// Servers and storages it touches.
	Refs []uuid.UUID
	// Where its output lands, for links; nil for none.
	Target  any
	RetryOf *uuid.UUID
	// CreatedBy is the user who started it; only they and admins see it.
	CreatedBy *uuid.UUID
	// Quick starts it at once, past both limits: for work that normally takes
	// no time and shouldn't wait behind long jobs (a rename). Not stored, so
	// after a restart or a retry it waits its turn like any other.
	Quick bool
}

// Event is one change: Job is set when a job changed, Removed when one was
// deleted.
type Event struct {
	Job     *sqlc.Job
	Removed uuid.UUID
}

type Runner struct {
	q        sqlc.Querier
	handlers map[string]Handler
	// Limit is how many jobs run at once; PerRef how many of them may touch
	// one server or storage.
	Limit, PerRef int

	base context.Context
	stop context.CancelFunc
	wg   sync.WaitGroup

	mu      sync.Mutex
	queue   []*entry
	running map[uuid.UUID]*entry
	busy    map[uuid.UUID]int
	subs    map[*sub]struct{}
}

type entry struct {
	job      sqlc.Job
	progress Progress
	log      strings.Builder
	cancel   context.CancelFunc
	canceled bool // by the user, as opposed to a shutdown
	dirty    bool // changed since the last event
	quick    bool
	saved    time.Time
	// For the rate.
	lastDone int64
	lastAt   time.Time
}

func New(q sqlc.Querier) *Runner {
	base, stop := context.WithCancel(context.Background())
	return &Runner{
		q: q, handlers: map[string]Handler{},
		Limit: 4, PerRef: 2,
		base: base, stop: stop,
		running: map[uuid.UUID]*entry{},
		busy:    map[uuid.UUID]int{},
		subs:    map[*sub]struct{}{},
	}
}

// Handle registers the handler for a kind. Call it before Start.
func (r *Runner) Handle(kind string, h Handler) { r.handlers[kind] = h }

// Start marks jobs the last process left running as interrupted, picks up
// the queued ones and starts the background loops.
func (r *Runner) Start(ctx context.Context) error {
	if n, err := r.q.InterruptRunningJobs(ctx); err != nil {
		return err
	} else if n > 0 {
		slog.Info("jobs interrupted by the restart", "count", n)
	}
	queued, err := r.q.ListQueuedJobs(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	for _, j := range queued {
		r.queue = append(r.queue, &entry{job: j})
	}
	r.schedule()
	r.mu.Unlock()
	r.wg.Add(2)
	go r.ticker()
	go r.cleaner()
	return nil
}

// Close cancels running jobs (they end up interrupted) and waits for them,
// up to the deadline in ctx.
func (r *Runner) Close(ctx context.Context) {
	r.stop()
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// Submit stores a job and queues it.
func (r *Runner) Submit(ctx context.Context, s Spec) (sqlc.Job, error) {
	if _, ok := r.handlers[s.Kind]; !ok {
		return sqlc.Job{}, fmt.Errorf("no handler for job kind %q", s.Kind)
	}
	params, err := json.Marshal(s.Params)
	if err != nil {
		return sqlc.Job{}, err
	}
	var target []byte
	if s.Target != nil {
		if target, err = json.Marshal(s.Target); err != nil {
			return sqlc.Job{}, err
		}
	}
	refs := s.Refs
	if refs == nil {
		refs = []uuid.UUID{}
	}
	j, err := r.q.CreateJob(ctx, sqlc.CreateJobParams{
		Kind: s.Kind, Title: s.Title, Params: params, Refs: refs, Target: target, RetryOf: s.RetryOf, CreatedBy: s.CreatedBy,
	})
	if err != nil {
		return j, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e := &entry{job: j, quick: s.Quick}
	r.queue = append(r.queue, e)
	r.emit(e)
	r.schedule()
	return r.snapshot(e), nil
}

// Retry submits a finished job again with the same params.
func (r *Runner) Retry(ctx context.Context, id uuid.UUID, by *uuid.UUID) (sqlc.Job, error) {
	j, err := r.Get(ctx, id)
	if err != nil {
		return j, err
	}
	if Active(j.State) {
		return j, ErrActive
	}
	spec := Spec{Kind: j.Kind, Title: j.Title, Params: json.RawMessage(j.Params), Refs: j.Refs, RetryOf: &j.ID, CreatedBy: by}
	if j.Target != nil {
		spec.Target = json.RawMessage(j.Target)
	}
	return r.Submit(ctx, spec)
}

// Get returns a job, live while it is queued or running.
func (r *Runner) Get(ctx context.Context, id uuid.UUID) (sqlc.Job, error) {
	r.mu.Lock()
	if e := r.find(id); e != nil {
		defer r.mu.Unlock()
		return r.snapshot(e), nil
	}
	r.mu.Unlock()
	j, err := r.q.GetJob(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return j, ErrNotFound
	}
	return j, err
}

// List returns jobs newest first, the active ones live.
func (r *Runner) List(ctx context.Context, p sqlc.ListJobsParams) ([]sqlc.Job, error) {
	jobs, err := r.q.ListJobs(ctx, p)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, j := range jobs {
		if e := r.find(j.ID); e != nil {
			jobs[i] = r.snapshot(e)
		}
	}
	return jobs, nil
}

// Cancel stops a running job or drops a queued one.
func (r *Runner) Cancel(ctx context.Context, id uuid.UUID) (sqlc.Job, error) {
	r.mu.Lock()
	if e := r.running[id]; e != nil {
		defer r.mu.Unlock()
		// It stays in running until its final state is saved.
		if e.job.FinishedAt != nil {
			return r.snapshot(e), ErrFinished
		}
		if e.progress.Locked {
			return r.snapshot(e), ErrLocked
		}
		e.canceled = true
		e.progress.Phase = "Canceling"
		e.dirty = true
		e.cancel()
		return r.snapshot(e), nil
	}
	if i := slices.IndexFunc(r.queue, func(e *entry) bool { return e.job.ID == id }); i >= 0 {
		e := r.queue[i]
		r.queue = slices.Delete(r.queue, i, i+1)
		r.mu.Unlock()
		if _, err := r.q.CancelQueuedJob(ctx, id); err != nil {
			return e.job, err
		}
		now := time.Now()
		e.job.State, e.job.FinishedAt = Canceled, &now
		r.mu.Lock()
		r.emit(e)
		r.mu.Unlock()
		return e.job, nil
	}
	r.mu.Unlock()
	j, err := r.Get(ctx, id)
	if err != nil {
		return j, err
	}
	return j, ErrFinished
}

// Delete removes a finished job.
func (r *Runner) Delete(ctx context.Context, id uuid.UUID) error {
	n, err := r.q.DeleteJob(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		if _, err := r.Get(ctx, id); err != nil {
			return err
		}
		return ErrActive
	}
	r.mu.Lock()
	r.broadcast(Event{Removed: id})
	r.mu.Unlock()
	return nil
}

// Clear removes finished jobs, those touching ref when it's set. Watchers
// are told to reload rather than sent one event per job.
func (r *Runner) Clear(ctx context.Context, ref, createdBy *uuid.UUID) (int64, error) {
	n, err := r.q.DeleteFinishedJobs(ctx, sqlc.DeleteFinishedJobsParams{Ref: ref, CreatedBy: createdBy})
	if err == nil && n > 0 {
		r.mu.Lock()
		r.broadcast(Event{Removed: uuid.Nil})
		r.mu.Unlock()
	}
	return n, err
}

// ---- Running ----

func (r *Runner) find(id uuid.UUID) *entry {
	if e := r.running[id]; e != nil {
		return e
	}
	for _, e := range r.queue {
		if e.job.ID == id {
			return e
		}
	}
	return nil
}

// schedule starts queued jobs, oldest first, while the limits allow. A job
// waiting on a busy server doesn't hold up one for an idle server.
// Called with r.mu held.
func (r *Runner) schedule() {
	if r.base.Err() != nil {
		return
	}
	for i := 0; i < len(r.queue); {
		e := r.queue[i]
		full := len(r.running) >= r.Limit ||
			slices.ContainsFunc(e.job.Refs, func(ref uuid.UUID) bool { return r.busy[ref] >= r.PerRef })
		if full && !e.quick {
			i++
			continue
		}
		r.queue = slices.Delete(r.queue, i, i+1)
		r.start(e)
	}
}

// Called with r.mu held.
func (r *Runner) start(e *entry) {
	ctx, cancel := context.WithCancel(r.base)
	now := time.Now()
	e.cancel = cancel
	e.job.State, e.job.StartedAt = Running, &now
	e.saved, e.lastAt = now, now
	r.running[e.job.ID] = e
	for _, ref := range e.job.Refs {
		r.busy[ref]++
	}
	r.emit(e)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer cancel()
		if err := r.q.StartJob(context.WithoutCancel(ctx), e.job.ID); err != nil {
			slog.Error("job start", "id", e.job.ID, "error", err)
		}
		result, err := r.call(ctx, e)
		r.finish(e, result, err)
	}()
}

func (r *Runner) call(ctx context.Context, e *entry) (result any, err error) {
	defer func() {
		if p := recover(); p != nil {
			slog.Error("job panicked", "id", e.job.ID, "kind", e.job.Kind, "panic", p)
			err = fmt.Errorf("the job crashed: %v", p)
		}
	}()
	h := r.handlers[e.job.Kind]
	if h == nil {
		return nil, fmt.Errorf("this version of Morcheh can't run %q jobs", e.job.Kind)
	}
	return h(ctx, &Task{ID: e.job.ID, Kind: e.job.Kind, Params: e.job.Params, r: r, e: e})
}

func (r *Runner) finish(e *entry, result any, err error) {
	r.mu.Lock()
	state := Succeeded
	msg := ""
	switch {
	case err == nil:
	case e.canceled:
		state = Canceled
	case r.base.Err() != nil:
		state, msg = Interrupted, "Morcheh stopped while this was running"
	default:
		state, msg = Failed, err.Error()
	}
	if err == nil && e.progress.Total > 0 {
		e.progress.Done = e.progress.Total
	}
	e.progress.Phase, e.progress.Current, e.progress.Rate, e.progress.Locked = "", "", 0, false
	var res []byte
	if err == nil && result != nil {
		var merr error
		if res, merr = json.Marshal(result); merr != nil {
			slog.Error("job result", "id", e.job.ID, "error", merr)
			res = nil
		}
	}
	now := time.Now()
	e.job.State, e.job.Error, e.job.Result, e.job.FinishedAt = state, msg, res, &now
	j := r.snapshot(e)
	r.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.q.FinishJob(ctx, sqlc.FinishJobParams{
		ID: j.ID, State: j.State, Progress: j.Progress, Result: j.Result, Error: j.Error, Log: j.Log,
	}); err != nil {
		slog.Error("job finish", "id", j.ID, "error", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.running, e.job.ID)
	for _, ref := range e.job.Refs {
		if r.busy[ref]--; r.busy[ref] <= 0 {
			delete(r.busy, ref)
		}
	}
	r.broadcast(Event{Job: &j})
	r.schedule()
}

// snapshot copies the job with its live progress and log.
// Called with r.mu held.
func (r *Runner) snapshot(e *entry) sqlc.Job {
	j := e.job
	j.Progress, _ = json.Marshal(e.progress)
	j.Log = e.log.String()
	return j
}

// ticker sends progress events and saves progress now and then.
func (r *Runner) ticker() {
	defer r.wg.Done()
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-r.base.Done():
			return
		case now := <-t.C:
			var save []sqlc.Job
			r.mu.Lock()
			for _, e := range r.running {
				if dt := now.Sub(e.lastAt).Seconds(); dt >= 1 {
					rate := float64(e.progress.Done-e.lastDone) / dt
					if e.progress.Rate == 0 {
						e.progress.Rate = rate
					} else {
						e.progress.Rate = 0.6*e.progress.Rate + 0.4*rate
					}
					e.lastDone, e.lastAt, e.dirty = e.progress.Done, now, true
				}
				if !e.dirty {
					continue
				}
				e.dirty = false
				r.emit(e)
				if now.Sub(e.saved) >= saveEvery {
					e.saved = now
					save = append(save, r.snapshot(e))
				}
			}
			r.mu.Unlock()
			for _, j := range save {
				if err := r.q.SaveJobProgress(r.base, sqlc.SaveJobProgressParams{ID: j.ID, Progress: j.Progress, Log: j.Log}); err != nil && r.base.Err() == nil {
					slog.Error("job progress", "id", j.ID, "error", err)
				}
			}
		}
	}
}

// cleaner deletes old finished jobs once an hour.
func (r *Runner) cleaner() {
	defer r.wg.Done()
	for {
		before := time.Now().Add(-keep)
		if _, err := r.q.DeleteFinishedJobs(r.base, sqlc.DeleteFinishedJobsParams{Before: &before}); err != nil && r.base.Err() == nil {
			slog.Error("job cleanup", "error", err)
		}
		select {
		case <-r.base.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

// ---- Task: what a handler sees ----

type Task struct {
	ID     uuid.UUID
	Kind   string
	Params json.RawMessage
	r      *Runner
	e      *entry
}

// Decode reads the job's params.
func (t *Task) Decode(v any) error { return json.Unmarshal(t.Params, v) }

// Update changes the progress.
func (t *Task) Update(fn func(p *Progress)) {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	fn(&t.e.progress)
	t.e.dirty = true
}

// Add counts n more bytes done.
func (t *Task) Add(n int64) {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	t.e.progress.Done += n
	t.e.dirty = true
}

// Logf appends a line to the job's log; the oldest lines go past logCap.
func (t *Task) Logf(format string, args ...any) {
	line := strings.TrimRight(fmt.Sprintf(format, args...), "\n") + "\n"
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	b := &t.e.log
	if b.Len()+len(line) > logCap {
		s := b.String()
		cut := b.Len() + len(line) - logCap
		if i := strings.IndexByte(s[min(cut, len(s)):], '\n'); i >= 0 {
			cut += i + 1
		}
		b.Reset()
		b.WriteString(s[min(cut, len(s)):])
	}
	b.WriteString(line)
	t.e.dirty = true
}

// ---- Watching ----

// sub coalesces a watcher's events: it holds the newest per job, so a slow
// reader never blocks the runner and never misses a job's final state.
type sub struct {
	mu      sync.Mutex
	pending map[uuid.UUID]Event
	order   []uuid.UUID
	ready   chan struct{}
}

// Subscribe returns a channel that is signalled when events are waiting,
// a func that takes them, and one to stop watching.
func (r *Runner) Subscribe() (ready <-chan struct{}, take func() []Event, leave func()) {
	s := &sub{pending: map[uuid.UUID]Event{}, ready: make(chan struct{}, 1)}
	r.mu.Lock()
	r.subs[s] = struct{}{}
	r.mu.Unlock()
	take = func() []Event {
		s.mu.Lock()
		defer s.mu.Unlock()
		out := make([]Event, 0, len(s.order))
		for _, id := range s.order {
			out = append(out, s.pending[id])
		}
		clear(s.pending)
		s.order = s.order[:0]
		return out
	}
	leave = func() {
		r.mu.Lock()
		delete(r.subs, s)
		r.mu.Unlock()
	}
	return s.ready, take, leave
}

// emit broadcasts a job's current state. Called with r.mu held.
func (r *Runner) emit(e *entry) {
	j := r.snapshot(e)
	r.broadcast(Event{Job: &j})
}

// Called with r.mu held.
func (r *Runner) broadcast(ev Event) {
	id := ev.Removed
	if ev.Job != nil {
		id = ev.Job.ID
	}
	for s := range r.subs {
		s.mu.Lock()
		if _, ok := s.pending[id]; !ok {
			s.order = append(s.order, id)
		}
		s.pending[id] = ev
		s.mu.Unlock()
		select {
		case s.ready <- struct{}{}:
		default:
		}
	}
}
