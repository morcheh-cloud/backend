package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/sse"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/sshpool"
)

// Job is a background operation: it outlives the request that started it,
// reports progress and can be canceled.
type Job struct {
	ID         string         `json:"id" format:"uuid"`
	Kind       string         `json:"kind" doc:"What it does: transfer, copy, move, storage-copy, storage-move, compress, extract, fetch, fail2ban-install or fail2ban-uninstall" example:"transfer"`
	Title      string         `json:"title" example:"Copy backup.tar.gz from MinIO to web-01"`
	State      string         `json:"state" enum:"queued,running,succeeded,failed,canceled,interrupted"`
	Refs       []string       `json:"refs" doc:"Servers and storages it touches"`
	Target     *JobPlace      `json:"target,omitempty" doc:"Where its output lands"`
	Progress   jobs.Progress  `json:"progress"`
	Result     map[string]any `json:"result,omitempty" doc:"What it produced; the shape depends on kind"`
	Error      string         `json:"error" doc:"Why it failed or was interrupted"`
	Log        string         `json:"log,omitempty" doc:"What it printed (newest last); only on GET /jobs/{id}"`
	RetryOf    *string        `json:"retry_of,omitempty" format:"uuid"`
	CreatedAt  time.Time      `json:"created_at"`
	StartedAt  *time.Time     `json:"started_at,omitempty"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
}

// JobPlace is a folder on a server or storage.
type JobPlace struct {
	ServerID  string `json:"server_id,omitempty" format:"uuid"`
	StorageID string `json:"storage_id,omitempty" format:"uuid"`
	Path      string `json:"path"`
	Name      string `json:"name,omitempty" doc:"The server's or storage's name when the job started"`
}

// JobRemoved is sent on the stream when a job is deleted; an empty id means
// many were (reload the list).
type JobRemoved struct {
	ID string `json:"id"`
}

type JobOutput struct{ Body Job }

func toJob(j sqlc.Job, withLog bool) Job {
	out := Job{
		ID: j.ID.String(), Kind: j.Kind, Title: j.Title, State: j.State,
		Refs: make([]string, len(j.Refs)), Error: j.Error,
		RetryOf:   optionalIDString(j.RetryOf),
		CreatedAt: j.CreatedAt, StartedAt: j.StartedAt, FinishedAt: j.FinishedAt,
	}
	for i, r := range j.Refs {
		out.Refs[i] = r.String()
	}
	if len(j.Target) > 0 {
		out.Target = &JobPlace{}
		_ = json.Unmarshal(j.Target, out.Target)
	}
	_ = json.Unmarshal(j.Progress, &out.Progress)
	if len(j.Result) > 0 {
		_ = json.Unmarshal(j.Result, &out.Result)
	}
	if withLog {
		out.Log = j.Log
	}
	return out
}

func jobProblem(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, jobs.ErrNotFound):
		return huma.Error404NotFound("job not found")
	case errors.Is(err, jobs.ErrFinished):
		return huma.Error409Conflict("The job has already finished")
	case errors.Is(err, jobs.ErrActive):
		return huma.Error409Conflict("The job is still queued or running; cancel it first")
	case errors.Is(err, jobs.ErrLocked):
		return huma.Error409Conflict("This step can't be stopped safely. It will finish on its own.")
	}
	return internalError(err)
}

// submit queues a job and answers with it.
func submit(ctx context.Context, r *jobs.Runner, s jobs.Spec) (*JobOutput, error) {
	if p := principalOf(ctx); p != nil {
		s.CreatedBy = p.ID()
	}
	j, err := r.Submit(ctx, s)
	if err != nil {
		return nil, internalError(err)
	}
	return &JobOutput{toJob(j, false)}, nil
}

type JobIDPath struct {
	ID string `path:"id" format:"uuid"`
}

// ownsJob says whether they may see a job: who started it, and admins.
func ownsJob(p *principal, j sqlc.Job) bool {
	return p.Access.Admin || (j.CreatedBy != nil && *j.CreatedBy == p.User.ID)
}

// ownJob loads a job they may see. Someone else's looks like no job at all.
func ownJob(ctx context.Context, r *jobs.Runner, raw string) (sqlc.Job, error) {
	j, err := r.Get(ctx, uuid.MustParse(raw))
	if err != nil {
		return j, jobProblem(err)
	}
	if !ownsJob(principalOf(ctx), j) {
		return j, huma.Error404NotFound("job not found")
	}
	return j, nil
}

// mayRetry checks they could still start this job today: retrying must not
// outlive the access it was started with. A job touching nothing they can reach
// stays with admins.
func (a *authz) mayRetry(ctx context.Context, p *principal, j sqlc.Job) error {
	if p.Access.Admin {
		return nil
	}
	if len(j.Refs) == 0 {
		return forbidden(auth.Owner)
	}
	for _, ref := range j.Refs {
		level, err := a.serverLevel(ctx, p.Access, ref)
		if err != nil {
			return internalError(err)
		}
		if level == auth.None {
			if level, err = a.storageLevel(ctx, p.Access, ref); err != nil {
				return internalError(err)
			}
		}
		if level < auth.Engineer {
			return forbidden(auth.Engineer)
		}
	}
	return nil
}

func registerJobs(api huma.API, a *authz) {
	r := a.runner
	tags := []string{"Jobs"}

	huma.Register(api, huma.Operation{
		OperationID: "list-jobs",
		Method:      http.MethodGet,
		Path:        "/jobs",
		Summary:     "List background jobs",
		Description: "Newest first. Finished jobs are kept for 30 days.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		Ref   string `query:"ref" format:"uuid" doc:"Only jobs touching this server or storage"`
		Kind  string `query:"kind" doc:"Only this kind"`
		Show  string `query:"show" enum:"all,active,finished" default:"all"`
		Limit int32  `query:"limit" minimum:"1" maximum:"200" default:"50"`
	}) (*struct {
		Body struct {
			Items []Job `json:"items"`
		}
	}, error) {
		p := sqlc.ListJobsParams{Lim: in.Limit}
		if who := principalOf(ctx); !who.Access.Admin {
			p.CreatedBy = who.ID()
		}
		if in.Ref != "" {
			id := uuid.MustParse(in.Ref)
			p.Ref = &id
		}
		if in.Kind != "" {
			p.Kind = &in.Kind
		}
		if in.Show != "all" {
			active := in.Show == "active"
			p.Active = &active
		}
		list, err := r.List(ctx, p)
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []Job `json:"items"`
			}
		}{}
		out.Body.Items = make([]Job, len(list))
		for i, j := range list {
			out.Body.Items[i] = toJob(j, false)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-job",
		Method:      http.MethodGet,
		Path:        "/jobs/{id}",
		Summary:     "Get a job with its log",
		Tags:        tags,
	}, func(ctx context.Context, in *JobIDPath) (*JobOutput, error) {
		j, err := ownJob(ctx, r, in.ID)
		if err != nil {
			return nil, err
		}
		return &JobOutput{toJob(j, true)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "cancel-job",
		Method:      http.MethodPost,
		Path:        "/jobs/{id}/cancel",
		Summary:     "Cancel a job",
		Description: "A queued job is dropped at once; a running one stops as soon as it can (its state changes on the stream). 409 when it has already finished, or while progress.locked is true (a package manager running).",
		Tags:        tags,
	}, func(ctx context.Context, in *JobIDPath) (*JobOutput, error) {
		if _, err := ownJob(ctx, r, in.ID); err != nil {
			return nil, err
		}
		j, err := r.Cancel(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, jobProblem(err)
		}
		return &JobOutput{toJob(j, false)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "retry-job",
		Method:        http.MethodPost,
		Path:          "/jobs/{id}/retry",
		Summary:       "Run a finished job again",
		Description:   "Queues a new job with the same settings. Checks (like a name already taken) run again when it starts.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *JobIDPath) (*JobOutput, error) {
		old, err := ownJob(ctx, r, in.ID)
		if err != nil {
			return nil, err
		}
		p := principalOf(ctx)
		if err := a.mayRetry(ctx, p, old); err != nil {
			return nil, err
		}
		j, err := r.Retry(ctx, old.ID, p.ID())
		if err != nil {
			return nil, jobProblem(err)
		}
		return &JobOutput{toJob(j, false)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-job",
		Method:        http.MethodDelete,
		Path:          "/jobs/{id}",
		Summary:       "Remove a finished job from the list",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *JobIDPath) (*struct{}, error) {
		if _, err := ownJob(ctx, r, in.ID); err != nil {
			return nil, err
		}
		return nil, jobProblem(r.Delete(ctx, uuid.MustParse(in.ID)))
	})

	huma.Register(api, huma.Operation{
		OperationID: "clear-jobs",
		Method:      http.MethodDelete,
		Path:        "/jobs",
		Summary:     "Remove finished jobs",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		Ref string `query:"ref" format:"uuid" doc:"Only jobs touching this server or storage"`
	}) (*struct {
		Body struct {
			Deleted int64 `json:"deleted"`
		}
	}, error) {
		var ref *uuid.UUID
		if in.Ref != "" {
			id := uuid.MustParse(in.Ref)
			ref = &id
		}
		var by *uuid.UUID
		if p := principalOf(ctx); !p.Access.Admin {
			by = p.ID()
		}
		n, err := r.Clear(ctx, ref, by)
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Deleted int64 `json:"deleted"`
			}
		}{}
		out.Body.Deleted = n
		return out, nil
	})

	sse.Register(api, huma.Operation{
		OperationID: "stream-jobs",
		Method:      http.MethodGet,
		Path:        "/jobs/stream",
		Summary:     "Stream job changes",
		Description: "Server-sent events: `job` whenever one is queued, makes progress (about twice a second) or finishes; " +
			"`removed` when one is deleted (empty id: several were, reload the list). Load GET /jobs once connected; the stream only sends changes.",
		Tags: tags,
	}, map[string]any{"job": Job{}, "removed": JobRemoved{}},
		func(ctx context.Context, _ *struct{}, send sse.Sender) {
			p := principalOf(ctx)
			ready, take, leave := r.Subscribe()
			defer leave()
			// Tell the client it's connected, so it loads the list.
			if send(sse.Message{Comment: "ready"}) != nil {
				return
			}
			ping := time.NewTicker(20 * time.Second)
			defer ping.Stop()
			for {
				var err error
				select {
				case <-ctx.Done():
					return
				case <-ready:
					for _, ev := range take() {
						if ev.Job != nil {
							if !ownsJob(p, *ev.Job) {
								continue
							}
							err = send.Data(toJob(*ev.Job, false))
						} else if ev.Removed == uuid.Nil {
							err = send.Data(JobRemoved{})
						} else {
							err = send.Data(JobRemoved{ID: ev.Removed.String()})
						}
						if err != nil {
							return
						}
					}
				case <-ping.C:
					err = send(sse.Message{Comment: "ping"})
				}
				if err != nil {
					return
				}
			}
		})
}

// placeRefs turns the ids of a job's ends into its refs.
func placeRefs(ids ...string) []uuid.UUID {
	var out []uuid.UUID
	for _, s := range ids {
		if id, err := uuid.Parse(s); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// ---- Long commands on a server ----

// runStream runs a long command on the server for a job. Lines it prints go
// to onOut (stdout) and onErr (stderr) as they come; onErr returns whether
// the line is a message worth showing if the command fails (nil keeps
// them all). When ctx ends the command's whole process group is killed, so
// cancel stops tar, curl and the rest rather than leaving them running.
func runStream(ctx context.Context, c *sshpool.Conn, cmd string, onOut func(string), onErr func(string) bool) error {
	sess, err := c.Client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return err
	}
	// sshd makes the command's shell a session leader, so its pid is the
	// process group to kill.
	if err := sess.Start("echo @pid $$; " + cmd); err != nil {
		return err
	}

	var (
		mu   sync.Mutex
		pid  int
		tail []string
		wg   sync.WaitGroup
	)
	scan := func(r interface{ Read([]byte) (int, error) }, line func(string)) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			line(strings.TrimRight(sc.Text(), "\r"))
		}
	}
	wg.Add(2)
	go scan(stdout, func(l string) {
		if p, ok := strings.CutPrefix(l, "@pid "); ok {
			mu.Lock()
			if pid == 0 {
				pid, _ = strconv.Atoi(p)
				mu.Unlock()
				return
			}
			mu.Unlock()
		}
		if onOut != nil {
			onOut(l)
		}
	})
	go scan(stderr, func(l string) {
		if onErr == nil || onErr(l) {
			mu.Lock()
			tail = append(tail[max(0, len(tail)-2):], l)
			mu.Unlock()
		}
	})
	done := make(chan error, 1)
	go func() {
		wg.Wait()
		done <- sess.Wait()
	}()

	select {
	case err = <-done:
	case <-ctx.Done():
		mu.Lock()
		p := pid
		mu.Unlock()
		if p > 0 {
			kctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			q := strconv.Itoa(p)
			_, _ = run(kctx, c, "kill -TERM -- -"+q+" 2>/dev/null || kill -TERM "+q+" 2>/dev/null; true")
			cancel()
		}
		sess.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		return ctx.Err()
	}
	if err == nil {
		return nil
	}
	var exit *ssh.ExitError
	if errors.As(err, &exit) {
		mu.Lock()
		msg := strings.Join(tail, "\n")
		mu.Unlock()
		switch {
		case exit.ExitStatus() == 127:
			if m := notFoundRe.FindStringSubmatch(msg); m != nil {
				msg = m[1] + " isn't installed on the server"
			} else if msg == "" {
				msg = "A command this needs isn't installed on the server"
			}
		case msg == "":
			msg = fmt.Sprintf("The command failed (exit %d)", exit.ExitStatus())
		}
		return &cmdError{exit.ExitStatus(), msg}
	}
	return err
}

// every calls fn once a second until ctx ends or stop is called.
func every(ctx context.Context, fn func()) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				fn()
			}
		}
	}()
	return cancel
}

// humanBytes is a size for a job's log: 1.5 GB.
func humanBytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTPE"[exp])
}
