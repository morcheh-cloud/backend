package jobs

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
)

// fakeDB keeps jobs in memory; only the job queries are implemented.
type fakeDB struct {
	sqlc.Querier
	mu   sync.Mutex
	rows map[uuid.UUID]sqlc.Job
}

func (f *fakeDB) CreateJob(_ context.Context, p sqlc.CreateJobParams) (sqlc.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	j := sqlc.Job{ID: uuid.Must(uuid.NewV7()), Kind: p.Kind, Title: p.Title, Params: p.Params, Refs: p.Refs, State: Queued, CreatedAt: time.Now()}
	f.rows[j.ID] = j
	return j, nil
}

func (f *fakeDB) GetJob(_ context.Context, id uuid.UUID) (sqlc.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rows[id], nil
}

func (f *fakeDB) set(id uuid.UUID, fn func(*sqlc.Job)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	j := f.rows[id]
	fn(&j)
	f.rows[id] = j
}

func (f *fakeDB) StartJob(_ context.Context, id uuid.UUID) error {
	f.set(id, func(j *sqlc.Job) { j.State = Running })
	return nil
}

func (f *fakeDB) SaveJobProgress(context.Context, sqlc.SaveJobProgressParams) error { return nil }

func (f *fakeDB) FinishJob(_ context.Context, p sqlc.FinishJobParams) error {
	f.set(p.ID, func(j *sqlc.Job) { j.State, j.Error = p.State, p.Error })
	return nil
}

func (f *fakeDB) CancelQueuedJob(_ context.Context, id uuid.UUID) (int64, error) {
	f.set(id, func(j *sqlc.Job) { j.State = Canceled })
	return 1, nil
}

func (f *fakeDB) InterruptRunningJobs(context.Context) (int64, error) { return 0, nil }
func (f *fakeDB) ListQueuedJobs(context.Context) ([]sqlc.Job, error)  { return nil, nil }
func (f *fakeDB) DeleteFinishedJobs(context.Context, sqlc.DeleteFinishedJobsParams) (int64, error) {
	return 0, nil
}

func newRunner(t *testing.T) (*Runner, *fakeDB) {
	db := &fakeDB{rows: map[uuid.UUID]sqlc.Job{}}
	r := New(db)
	t.Cleanup(func() { r.Close(context.Background()) })
	return r, db
}

// wait polls until the job reaches state.
func wait(t *testing.T, r *Runner, id uuid.UUID, state string) sqlc.Job {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if j, _ := r.Get(context.Background(), id); j.State == state {
			return j
		}
		time.Sleep(5 * time.Millisecond)
	}
	j, _ := r.Get(context.Background(), id)
	t.Fatalf("job %s is %s, want %s", id, j.State, state)
	return j
}

func TestRunsAndFails(t *testing.T) {
	r, _ := newRunner(t)
	r.Handle("ok", func(_ context.Context, t *Task) (any, error) {
		t.Logf("hello")
		return map[string]int{"n": 1}, nil
	})
	r.Handle("bad", func(context.Context, *Task) (any, error) { return nil, errors.New("boom") })
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ok, _ := r.Submit(context.Background(), Spec{Kind: "ok", Title: "ok"})
	bad, _ := r.Submit(context.Background(), Spec{Kind: "bad", Title: "bad"})
	wait(t, r, ok.ID, Succeeded)
	if j := wait(t, r, bad.ID, Failed); j.Error != "boom" {
		t.Errorf("error = %q", j.Error)
	}
}

func TestPerRefLimitAndCancel(t *testing.T) {
	r, _ := newRunner(t)
	r.PerRef = 1
	release := make(chan struct{})
	r.Handle("block", func(ctx context.Context, _ *Task) (any, error) {
		select {
		case <-release:
			return nil, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	server := uuid.New()
	a, _ := r.Submit(context.Background(), Spec{Kind: "block", Refs: []uuid.UUID{server}})
	b, _ := r.Submit(context.Background(), Spec{Kind: "block", Refs: []uuid.UUID{server}})
	other, _ := r.Submit(context.Background(), Spec{Kind: "block", Refs: []uuid.UUID{uuid.New()}})
	wait(t, r, a.ID, Running)
	wait(t, r, other.ID, Running) // not held up by b
	if j, _ := r.Get(context.Background(), b.ID); j.State != Queued {
		t.Fatalf("b is %s, want queued behind a", j.State)
	}
	if _, err := r.Cancel(context.Background(), a.ID); err != nil {
		t.Fatal(err)
	}
	wait(t, r, a.ID, Canceled)
	wait(t, r, b.ID, Running) // a's slot freed
	if _, err := r.Cancel(context.Background(), a.ID); !errors.Is(err, ErrFinished) {
		t.Errorf("cancel twice: %v", err)
	}
	close(release)
	wait(t, r, b.ID, Succeeded)
	wait(t, r, other.ID, Succeeded)
}

func TestQuickSkipsTheLimits(t *testing.T) {
	r, _ := newRunner(t)
	r.Limit, r.PerRef = 1, 1
	release := make(chan struct{})
	r.Handle("block", func(context.Context, *Task) (any, error) {
		<-release
		return nil, nil
	})
	r.Handle("noop", func(context.Context, *Task) (any, error) { return nil, nil })
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	server := uuid.New()
	long, _ := r.Submit(context.Background(), Spec{Kind: "block", Refs: []uuid.UUID{server}})
	wait(t, r, long.ID, Running)
	waiting, _ := r.Submit(context.Background(), Spec{Kind: "noop", Refs: []uuid.UUID{server}})
	quick, _ := r.Submit(context.Background(), Spec{Kind: "noop", Refs: []uuid.UUID{server}, Quick: true})
	wait(t, r, quick.ID, Succeeded)
	if j, _ := r.Get(context.Background(), waiting.ID); j.State != Queued {
		t.Errorf("the ordinary job is %s, want queued", j.State)
	}
	close(release)
	wait(t, r, waiting.ID, Succeeded)
}

func TestLockedRefusesCancel(t *testing.T) {
	r, _ := newRunner(t)
	locked, release := make(chan struct{}), make(chan struct{})
	r.Handle("lock", func(ctx context.Context, t *Task) (any, error) {
		t.Update(func(p *Progress) { p.Locked = true })
		close(locked)
		<-release
		t.Update(func(p *Progress) { p.Locked = false })
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	j, _ := r.Submit(context.Background(), Spec{Kind: "lock"})
	<-locked
	if _, err := r.Cancel(context.Background(), j.ID); !errors.Is(err, ErrLocked) {
		t.Fatalf("cancel while locked: %v", err)
	}
	if got, _ := r.Get(context.Background(), j.ID); got.State != Running {
		t.Fatalf("state = %s, want still running", got.State)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := r.Cancel(context.Background(), j.ID); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("cancel after unlock: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	wait(t, r, j.ID, Canceled)
}

func TestSubscribeCoalesces(t *testing.T) {
	r, _ := newRunner(t)
	r.Handle("noop", func(context.Context, *Task) (any, error) { return nil, nil })
	ready, take, leave := r.Subscribe()
	defer leave()
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	j, _ := r.Submit(context.Background(), Spec{Kind: "noop"})
	wait(t, r, j.ID, Succeeded)
	<-ready
	evs := take()
	if len(evs) != 1 || evs[0].Job == nil || evs[0].Job.State != Succeeded {
		t.Fatalf("events = %+v, want one with the final state", evs)
	}
}

func TestLogKeepsTheTail(t *testing.T) {
	r, _ := newRunner(t)
	task := &Task{r: r, e: &entry{}}
	for i := 0; i < 5000; i++ {
		task.Logf("line %d with some padding to fill the log quickly", i)
	}
	log := task.e.log.String()
	if len(log) > logCap {
		t.Fatalf("log is %d bytes, cap %d", len(log), logCap)
	}
	if want := "line 4999 with some padding to fill the log quickly\n"; log[len(log)-len(want):] != want {
		t.Errorf("newest line missing")
	}
	if log[:5] != "line " {
		t.Errorf("log doesn't start at a line: %q", log[:20])
	}
}
