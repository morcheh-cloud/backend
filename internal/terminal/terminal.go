// Package terminal runs interactive shells on servers. A session lives on
// the backend, not in a browser tab: clients attach and detach (a reload, a
// dropped network), get the recent output replayed, and the shell keeps
// running until it exits, is killed, or stays detached too long.
package terminal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/morcheh/backend/internal/sshpool"
)

const (
	// Output kept for replay when a client attaches.
	scrollback = 512 << 10
	// Limit per person on a server, so a stuck client can't open shells forever.
	MaxPerServer = 10
	// Events queued for one client before it counts as too slow.
	subBuffer = 512
)

var (
	ErrTooMany = fmt.Errorf("you can have at most %d open terminals on a server", MaxPerServer)
	ErrNoPTY   = errors.New("the server refused a terminal (PTY)")
)

// Event is one thing a client should see: output, a new title, or the end.
type Event struct {
	Data  []byte
	Title string
	// Exited is set on the last event; Code is the shell's exit status, or
	// -1 when the server didn't say.
	Exited bool
	Code   int
}

// Sub is one attached client.
type Sub struct {
	C       <-chan Event
	c       chan Event
	dropped bool
}

type Session struct {
	ID       string
	ServerID string
	// Owner is the user who opened it; nobody else can see or attach to it.
	Owner   string
	Created time.Time

	m     *Manager
	conn  *sshpool.Conn
	ssh   *ssh.Session
	stdin io.WriteCloser
	rec   Recorder
	cmds  Commands
	osc   *oscFilter

	mu       sync.Mutex
	number   int
	title    string
	cols     int
	rows     int
	buf      []byte
	subs     map[*Sub]struct{}
	detached time.Time
	exited   bool
}

// Info is a session as the API lists it.
type Info struct {
	ID       string
	Title    string
	Created  time.Time
	Cols     int
	Rows     int
	Clients  int
	Recorded bool
}

type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	// A session with no client attached for this long is killed.
	detachedTTL time.Duration
}

func NewManager(detachedTTL time.Duration) *Manager {
	m := &Manager{sessions: map[string]*Session{}, detachedTTL: detachedTTL}
	go m.reap()
	return m
}

type Options struct {
	Cols, Rows int
	// Cwd, if set, is where the shell starts.
	Cwd string
	// Owner is the user opening it.
	Owner string
	// Recorder, if set, gets every byte of output and each resize.
	Recorder Recorder
	// Commands, if set, gets each command line typed into the shell (bash
	// and zsh only, through hooks installed in the login user's home).
	Commands Commands
}

// Recorder keeps a copy of a session: its output (never its input), its
// size changes, and the end with the shell's exit code (-1 when unknown).
type Recorder interface {
	Output(data []byte)
	Resize(cols, rows int)
	Ended(code int)
}

// Start opens a shell over conn. The session holds the connection (Acquire)
// until it ends.
func (m *Manager) Start(serverID string, conn *sshpool.Conn, o Options) (*Session, error) {
	o.Cols, o.Rows = clamp(o.Cols, 80), clamp(o.Rows, 24)

	m.mu.Lock()
	used := map[int]bool{}
	for _, s := range m.sessions {
		if s.ServerID == serverID && s.Owner == o.Owner {
			used[s.number] = true
		}
	}
	m.mu.Unlock()
	if len(used) >= MaxPerServer {
		return nil, ErrTooMany
	}

	// The shell itself isn't a logged command; what is typed into it is.
	ctx := context.Background()
	var nonce string
	if o.Commands != nil {
		if err := InstallHooks(ctx, conn); err != nil {
			slog.Info("terminal without command capture", "server", serverID, "error", err)
		} else {
			nonce = newNonce()
		}
	}
	wrapped, err := conn.Session(ctx)
	if err != nil {
		return nil, err
	}
	wrapped.Quiet = true
	sess := wrapped.Session
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 115200, ssh.TTY_OP_OSPEED: 115200}
	if err := sess.RequestPty("xterm-256color", o.Rows, o.Cols, modes); err != nil {
		sess.Close()
		return nil, ErrNoPTY
	}
	// Most servers ignore this (AcceptEnv), which is fine.
	_ = sess.Setenv("COLORTERM", "truecolor")
	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		return nil, err
	}
	switch {
	case nonce != "":
		err = sess.Start(startCommand(o.Cwd, nonce))
	case o.Cwd != "":
		err = sess.Start("cd -- " + ShellQuote(o.Cwd) + `; exec "${SHELL:-/bin/sh}" -l`)
	default:
		err = sess.Shell()
	}
	if err != nil {
		sess.Close()
		return nil, err
	}

	s := &Session{
		ID: uuid.NewString(), ServerID: serverID, Owner: o.Owner, Created: time.Now(),
		m: m, conn: conn, ssh: sess, stdin: stdin, rec: o.Recorder, cmds: o.Commands,
		cols: o.Cols, rows: o.Rows, subs: map[*Sub]struct{}{}, detached: time.Now(),
	}
	m.mu.Lock()
	for s.number = 1; used[s.number]; s.number++ {
	}
	s.title = fmt.Sprintf("Shell %d", s.number)
	m.sessions[s.ID] = s
	m.mu.Unlock()
	if nonce != "" {
		s.osc = &oscFilter{nonce: nonce}
	}

	conn.Acquire()
	go s.run(stdout)
	return s, nil
}

func clamp(n, fallback int) int {
	if n <= 0 {
		return fallback
	}
	return min(n, 1000)
}

func (s *Session) run(stdout io.Reader) {
	chunk := make([]byte, 32<<10)
	for {
		n, err := stdout.Read(chunk)
		if n > 0 {
			data := bytes.Clone(chunk[:n])
			var events []hookEvent
			if s.osc != nil {
				data, events = s.osc.feed(data)
			}
			s.report(data, events)
			if len(data) > 0 {
				s.mu.Lock()
				s.buf = trim(append(s.buf, data...))
				if s.rec != nil {
					s.rec.Output(data)
				}
				s.broadcastLocked(Event{Data: data})
				s.mu.Unlock()
			}
		}
		if err != nil {
			break
		}
	}

	code := 0
	if err := s.ssh.Wait(); err != nil {
		var exit *ssh.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitStatus()
		} else {
			code = -1
		}
	}
	s.ssh.Close()
	s.conn.Release()
	if s.rec != nil {
		s.rec.Ended(code)
	}
	if s.cmds != nil {
		s.cmds.Closed(code, time.Now())
	}

	s.m.mu.Lock()
	delete(s.m.sessions, s.ID)
	s.m.mu.Unlock()

	s.mu.Lock()
	s.exited = true
	s.broadcastLocked(Event{Exited: true, Code: code})
	for sub := range s.subs {
		close(sub.c)
	}
	s.subs = nil
	s.mu.Unlock()
}

// report hands the hooks' events to Commands.
// report hands the hooks' events and the output around them to cmds, in
// the order they came.
func (s *Session) report(data []byte, events []hookEvent) {
	if s.cmds == nil {
		return
	}
	now := time.Now()
	prev := 0
	for _, ev := range events {
		if ev.at > prev && ev.at <= len(data) {
			s.cmds.Output(data[prev:ev.at])
			prev = ev.at
		}
		switch ev.kind {
		case 'r':
			s.cmds.Ready(ev.shell, ev.uid)
		case 's':
			s.cmds.Started(ev.cmd, ev.cwd, now)
		case 'e':
			s.cmds.Finished(ev.code, now)
		}
	}
	if prev < len(data) {
		s.cmds.Output(data[prev:])
	}
}

// trim keeps the scrollback bounded, cutting at a line start so replay
// doesn't begin in the middle of an escape sequence (usually).
func trim(buf []byte) []byte {
	if len(buf) <= scrollback {
		return buf
	}
	cut := len(buf) - scrollback*3/4
	if i := bytes.IndexByte(buf[cut:], '\n'); i >= 0 && i < 4096 {
		cut += i + 1
	}
	return slices.Clone(buf[cut:])
}

// broadcastLocked sends to every client; one that can't keep up is dropped
// (its channel closes) rather than stalling the shell. Caller holds s.mu.
func (s *Session) broadcastLocked(ev Event) {
	for sub := range s.subs {
		select {
		case sub.c <- ev:
		default:
			sub.dropped = true
			close(sub.c)
			delete(s.subs, sub)
		}
	}
	if len(s.subs) == 0 && s.detached.IsZero() {
		s.detached = time.Now()
	}
}

// Attach adds a client and returns the scrollback to replay first; no output
// is lost or repeated between the two. ok is false if the shell has ended.
func (s *Session) Attach() (replay []byte, sub *Sub, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exited {
		return nil, nil, false
	}
	c := make(chan Event, subBuffer)
	sub = &Sub{C: c, c: c}
	s.subs[sub] = struct{}{}
	s.detached = time.Time{}
	return bytes.Clone(s.buf), sub, true
}

func (s *Session) Detach(sub *Sub) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.subs[sub]; !ok {
		return
	}
	delete(s.subs, sub)
	close(sub.c)
	if len(s.subs) == 0 {
		s.detached = time.Now()
	}
}

// Dropped: the client was cut off for being too slow.
func (sub *Sub) Dropped() bool { return sub.dropped }

func (s *Session) Write(p []byte) error {
	_, err := s.stdin.Write(p)
	return err
}

// Resize follows the client that resized last.
func (s *Session) Resize(cols, rows int) error {
	cols, rows = clamp(cols, 80), clamp(rows, 24)
	s.mu.Lock()
	same := cols == s.cols && rows == s.rows
	s.cols, s.rows = cols, rows
	if !same && s.rec != nil {
		s.rec.Resize(cols, rows)
	}
	s.mu.Unlock()
	if same {
		return nil
	}
	return s.ssh.WindowChange(rows, cols)
}

// Recorded: the session's output is being kept.
func (s *Session) Recorded() bool { return s.rec != nil }

// Size is the terminal's current size.
func (s *Session) Size() (cols, rows int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cols, s.rows
}

func (s *Session) Title() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.title
}

func (s *Session) SetTitle(title string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.title = title
	s.broadcastLocked(Event{Title: title})
}

// Kill closes the shell; attached clients get the exit event.
func (s *Session) Kill() {
	s.ssh.Close()
}

func (s *Session) info() Info {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Info{ID: s.ID, Title: s.title, Created: s.Created, Cols: s.cols, Rows: s.rows, Clients: len(s.subs), Recorded: s.rec != nil}
}

// Get finds a running session of the server opened by owner.
func (m *Manager) Get(serverID, owner, id string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.sessions[id]; s != nil && s.ServerID == serverID && s.Owner == owner {
		return s
	}
	return nil
}

// All returns every running session.
func (m *Manager) All() []*Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	all := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		all = append(all, s)
	}
	return all
}

// KillOwner ends every session someone opened, e.g. when they are blocked.
func (m *Manager) KillOwner(owner string) {
	for _, s := range m.All() {
		if s.Owner == owner {
			s.Kill()
		}
	}
}

// List returns the sessions owner has on the server, oldest first.
func (m *Manager) List(serverID, owner string) []Info {
	m.mu.Lock()
	var sessions []*Session
	for _, s := range m.sessions {
		if s.ServerID == serverID && s.Owner == owner {
			sessions = append(sessions, s)
		}
	}
	m.mu.Unlock()
	infos := make([]Info, 0, len(sessions))
	for _, s := range sessions {
		infos = append(infos, s.info())
	}
	slices.SortFunc(infos, func(a, b Info) int { return a.Created.Compare(b.Created) })
	return infos
}

// KillServer ends every session of a server, e.g. when it is deleted.
func (m *Manager) KillServer(serverID string) {
	m.mu.Lock()
	var doomed []*Session
	for _, s := range m.sessions {
		if s.ServerID == serverID {
			doomed = append(doomed, s)
		}
	}
	m.mu.Unlock()
	for _, s := range doomed {
		s.Kill()
	}
}

func (m *Manager) reap() {
	for range time.Tick(30 * time.Second) {
		m.mu.Lock()
		var doomed []*Session
		for _, s := range m.sessions {
			s.mu.Lock()
			if len(s.subs) == 0 && !s.detached.IsZero() && time.Since(s.detached) > m.detachedTTL {
				doomed = append(doomed, s)
			}
			s.mu.Unlock()
		}
		m.mu.Unlock()
		for _, s := range doomed {
			s.Kill()
		}
	}
}

// ShellQuote wraps s in single quotes for a POSIX shell.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
