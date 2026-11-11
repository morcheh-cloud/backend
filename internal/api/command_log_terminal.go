package api

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/morcheh/backend/internal/cmdlog"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/terminal"
)

// termCommands logs one terminal: a "shell" row for the terminal itself and
// a row per command line its hooks report (terminal.Commands).
type termCommands struct {
	l        *commandLog
	serverID string
	origin   cmdlog.Origin
	rec      *liveRecording

	mu     sync.Mutex
	sess   *terminal.Session
	shell  *logHandle
	open   *logHandle
	cmd    string
	out    *cmdlog.OutputBuffer
	ready  bool
	kind   string
	root   bool
	closed bool
}

func newTermCommands(l *commandLog, serverID string, p *principal, clientIP string, rec *liveRecording) *termCommands {
	id := p.User.ID
	return &termCommands{
		l: l, serverID: serverID, rec: rec,
		origin: cmdlog.Origin{Kind: cmdlog.Terminal, UserID: &id, ClientIP: clientIP},
	}
}

// attach starts the shell's own row once the session exists.
func (t *termCommands) attach(s *terminal.Session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sess = s
	t.origin.Ref = s.ID
	h := t.begin("Terminal opened", "", true, s.Created)
	t.shell = h
	if h == nil {
		return
	}
	if t.ready {
		t.l.update(h.row, func(r *sqlc.SaveCommandLogParams) { r.Note = readyNote(t.kind) })
	}
	if t.closed {
		// The shell ended before this ran.
		h.once.Do(func() { t.l.end(h.row, cmdlog.Result{Code: -1}, time.Now()) })
	}
}

func readyNote(shell string) string {
	return "Commands typed here are listed (" + shell + ")"
}

// begin logs a row; caller holds t.mu.
func (t *termCommands) begin(text, cwd string, shell bool, at time.Time) *logHandle {
	o := t.origin
	if t.sess != nil {
		o.Source = t.sess.Title()
	}
	c := cmdlog.Command{
		ServerID: t.serverID, Origin: o, Text: text, Cwd: cwd, Shell: shell, Started: at,
		AsRoot: t.root || (!shell && strings.HasPrefix(text, "sudo ")),
	}
	if t.rec != nil {
		id := t.rec.id
		c.RecordingID = &id
		c.RecordingMs = max(0, at.Sub(t.rec.started).Milliseconds())
	}
	h, _ := t.l.Begin(context.Background(), c).(*logHandle)
	return h
}

func (t *termCommands) Ready(shell string, uid int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ready, t.kind, t.root = true, shell, uid == 0
	if t.shell != nil {
		t.l.update(t.shell.row, func(r *sqlc.SaveCommandLogParams) {
			r.AsRoot = t.root
			r.Note = readyNote(shell)
		})
	}
}

func (t *termCommands) Started(cmd, cwd string, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	// Hooks report a start only for a line the shell runs; one still open
	// means its end was missed (a subshell, Ctrl+Z).
	t.endOpen(cmdlog.Result{Code: -1}, at)
	t.open, t.cmd = t.begin(cmd, cwd, false, at), cmd
	if t.open != nil && t.open.row.keepOutput {
		t.out = &cmdlog.OutputBuffer{}
	}
}

func (t *termCommands) Output(data []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.out != nil {
		t.out.Write(data)
	}
}

func (t *termCommands) Finished(code int, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.endOpen(cmdlog.Result{Code: code}, at)
}

func (t *termCommands) Closed(code int, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	if t.open != nil {
		// "exit 3" ends the shell with its own code.
		r := cmdlog.Result{Code: -1, Error: "The terminal closed while it ran"}
		if f := strings.Fields(t.cmd); len(f) > 0 && (f[0] == "exit" || f[0] == "logout") {
			r = cmdlog.Result{Code: code}
		}
		t.endOpen(r, at)
	}
	if t.shell != nil {
		if !t.ready {
			t.l.update(t.shell.row, func(r *sqlc.SaveCommandLogParams) {
				r.Note = "Commands typed here weren't listed: only bash and zsh report them"
			})
		}
		t.shell.once.Do(func() { t.l.end(t.shell.row, cmdlog.Result{Code: code}, at) })
	}
}

// endOpen ends the open command; caller holds t.mu.
func (t *termCommands) endOpen(r cmdlog.Result, at time.Time) {
	if t.open == nil {
		return
	}
	h := t.open
	if t.out != nil {
		r.Output = terminalOutput(t.out.Result())
	}
	t.open, t.cmd, t.out = nil, "", nil
	h.once.Do(func() { t.l.end(h.row, r, at) })
}

// terminalOutput drops the bare line ends a command that printed nothing
// leaves behind.
func terminalOutput(o *cmdlog.Output) *cmdlog.Output {
	if o != nil && o.Note == "" && strings.TrimSpace(o.Text) == "" {
		return nil
	}
	return o
}
