package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/procs"
	"github.com/morcheh/backend/internal/sshpool"
)

type ProcessPath struct {
	ID    string `path:"id" format:"uuid"`
	PID   int    `path:"pid" minimum:"1"`
	Start int64  `query:"start" required:"true" minimum:"0" doc:"The process's start from the list: a PID reused by another process answers 404"`
}

type SignalProcessesInput struct {
	ServerIDPath
	Body struct {
		Signal  string                `json:"signal" enum:"TERM,KILL,HUP,INT,QUIT,STOP,CONT,USR1,USR2" doc:"TERM asks it to stop, KILL ends it at once, HUP often reloads its configuration, STOP/CONT pause and resume it"`
		Targets []procs.ProcessTarget `json:"targets" minItems:"1" maxItems:"200"`
		Force   bool                  `json:"force,omitempty" doc:"Also signal protected processes (PID 1, sshd, journald, Morcheh's own connection…)"`
	}
}

type ReniceProcessesInput struct {
	ServerIDPath
	Body struct {
		Nice    int                   `json:"nice" minimum:"-20" maximum:"19" doc:"-20 = most CPU, 19 = least"`
		Targets []procs.ProcessTarget `json:"targets" minItems:"1" maxItems:"200"`
		Force   bool                  `json:"force,omitempty"`
	}
}

type ProcessResults struct {
	Results []procs.ProcessResult `json:"results" doc:"One per target, in the order sent"`
}

func registerProcesses(api huma.API, h *serverHandler) {
	tags := []string{"Processes"}

	huma.Register(api, huma.Operation{
		OperationID: "list-processes",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/processes",
		Summary:     "Processes on a server",
		Description: "Every process from /proc with CPU measured over about a second (percent of one core, like top), memory, " +
			"user, state, threads, nice, start time and the systemd service, container or login session it belongs to. " +
			"Read as root when the login user can be; Viewers get no command lines. Linux only (422 otherwise).",
		Tags: tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body procs.ProcessesReport }, error) {
		out := &struct{ Body procs.ProcessesReport }{}
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.rootShell(ctx, in.ID, c)
			if err != nil {
				return err
			}
			text, err := sh.run(ctx, procs.Script)
			if err != nil {
				return err
			}
			r, err := procs.Parse(text, time.Now())
			if errors.Is(err, procs.ErrUnsupported) {
				return huma.Error422UnprocessableEntity(err.Error())
			}
			r.Access = sh.priv.access()
			r.Login = c.Client.User()
			if principalOf(ctx).Level < auth.Operator {
				r.CommandsHidden = true
				for i := range r.Processes {
					r.Processes[i].Command = ""
				}
			}
			out.Body = r
			return nil
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-process",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/processes/{pid}",
		Summary:     "One process in detail",
		Description: "Its program file, working folder, arguments, memory breakdown, disk I/O, open files and sockets " +
			"(with connections), limits and OOM score. The environment only for Engineers (it often holds secrets).",
		Tags: tags,
	}, func(ctx context.Context, in *ProcessPath) (*struct{ Body procs.ProcessDetails }, error) {
		out := &struct{ Body procs.ProcessDetails }{}
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.rootShell(ctx, in.ID, c)
			if err != nil {
				return err
			}
			env := principalOf(ctx).Level >= auth.Engineer
			text, err := sh.run(ctx, procs.DetailsScript(in.PID, in.Start, env))
			if err != nil {
				return err
			}
			d, err := procs.ParseDetails(text, in.PID, in.Start)
			if errors.Is(err, procs.ErrGone) {
				return huma.Error404NotFound("That process has ended")
			}
			out.Body = d
			return err
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "signal-processes",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/processes/signal",
		Summary:     "Send a signal to processes",
		Description: "Sends one signal to each target (checked by PID and start, so a reused PID is never hit). For " +
			"TERM/KILL/INT/QUIT/HUP it waits up to 2 seconds and says which ones ended. Protected processes are " +
			"refused unless force is set.",
		Tags: tags,
	}, func(ctx context.Context, in *SignalProcessesInput) (*struct{ Body ProcessResults }, error) {
		b := in.Body
		if !slices.Contains(procs.Signals, b.Signal) {
			return nil, huma.Error422UnprocessableEntity("Unknown signal " + b.Signal)
		}
		return h.processChange(ctx, in.ID, b.Targets, func(ts []procs.ProcessTarget) string {
			return procs.SignalScript(b.Signal, ts, b.Force)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "renice-processes",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/processes/renice",
		Summary:     "Change processes' priority",
		Description: "Sets the nice value of each target (renice). Raising priority (lowering nice) needs root.",
		Tags:        tags,
	}, func(ctx context.Context, in *ReniceProcessesInput) (*struct{ Body ProcessResults }, error) {
		b := in.Body
		return h.processChange(ctx, in.ID, b.Targets, func(ts []procs.ProcessTarget) string {
			return procs.ReniceScript(b.Nice, ts, b.Force)
		})
	})
}

func (h *serverHandler) processChange(ctx context.Context, id string, ts []procs.ProcessTarget, script func([]procs.ProcessTarget) string) (*struct{ Body ProcessResults }, error) {
	seen := map[int]bool{}
	uniq := ts[:0:0]
	for _, t := range ts {
		if !seen[t.PID] {
			seen[t.PID] = true
			uniq = append(uniq, t)
		}
	}
	out := &struct{ Body ProcessResults }{}
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.rootShell(ctx, id, c)
		if err != nil {
			return err
		}
		text, err := sh.run(ctx, script(uniq))
		if err != nil {
			return err
		}
		out.Body.Results = procs.ParseResults(text, uniq)
		return nil
	})
	if err != nil {
		return nil, toProblem(err)
	}
	if len(out.Body.Results) == 1 && strings.HasPrefix(out.Body.Results[0].Error, "Protected") {
		return nil, huma.Error422UnprocessableEntity(out.Body.Results[0].Error)
	}
	return out, nil
}
