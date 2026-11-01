// Package terminal runs interactive shells on servers. A session lives on
// the backend, not in a browser tab: clients attach and detach (a reload, a
// dropped network), get the recent output replayed, and the shell keeps
// running until it exits, is killed, or stays detached too long.
package terminal

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
	// Per-server limit, so a stuck client can't open shells forever.
	MaxPerServer = 10
	// Events queued for one client before it counts as too slow.
	subBuffer = 512
)

var (
	ErrTooMany = fmt.Errorf("a server can have at most %d open terminals", MaxPerServer)
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
	Created  time.Time

	m     *Manager
	conn  *sshpool.Conn
	ssh   *ssh.Session
	stdin io.WriteCloser

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
	ID      string
	Title   string
	Created time.Time
	Cols    int
	Rows    int
	Clients int
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
}

// Start opens a shell over conn. The session holds the connection (Acquire)
// until it ends.
func (m *Manager) Start(serverID string, conn *sshpool.Conn, o Options) (*Session, error) {
	o.Cols, o.Rows = clamp(o.Cols, 80), clamp(o.Rows, 24)

	m.mu.Lock()
	used := map[int]bool{}
	for _, s := range m.sessions {
		if s.ServerID == serverID {
			used[s.number] = true
		}
	}
	m.mu.Unlock()
	if len(used) >= MaxPerServer {
		return nil, ErrTooMany
	}

	sess, err := conn.Client.NewSession()
	if err != nil {
		return nil, err
	}
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
	if o.Cwd != "" {
		err = sess.Start("cd -- " + ShellQuote(o.Cwd) + `; exec "${SHELL:-/bin/sh}" -l`)
	} else {
		err = sess.Shell()
	}
	if err != nil {
		sess.Close()
		return nil, err
	}

	s := &Session{
		ID: uuid.NewString(), ServerID: serverID, Created: time.Now(),
		m: m, conn: conn, ssh: sess, stdin: stdin,
		cols: o.Cols, rows: o.Rows, subs: map[*Sub]struct{}{}, detached: time.Now(),
	}
	m.mu.Lock()
	for s.number = 1; used[s.number]; s.number++ {
	}
	s.title = fmt.Sprintf("Shell %d", s.number)
	m.sessions[s.ID] = s
	m.mu.Unlock()

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
			s.mu.Lock()
			s.buf = trim(append(s.buf, data...))
			s.broadcastLocked(Event{Data: data})
			s.mu.Unlock()
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
	s.mu.Unlock()
	if same {
		return nil
	}
	return s.ssh.WindowChange(rows, cols)
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
	return Info{ID: s.ID, Title: s.title, Created: s.Created, Cols: s.cols, Rows: s.rows, Clients: len(s.subs)}
}

// Get finds a running session of the server.
func (m *Manager) Get(serverID, id string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.sessions[id]; s != nil && s.ServerID == serverID {
		return s
	}
	return nil
}

// List returns the server's running sessions, oldest first.
func (m *Manager) List(serverID string) []Info {
	m.mu.Lock()
	var sessions []*Session
	for _, s := range m.sessions {
		if s.ServerID == serverID {
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
