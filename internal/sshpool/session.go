package sshpool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morcheh/backend/internal/cmdlog"
)

// Session is an SSH session whose command goes into the command log. Every
// command Morcheh runs on a server goes through one: open them with
// Conn.Session, never Client.NewSession.
type Session struct {
	*ssh.Session

	// What to log instead of the command line, e.g. the script a "sh -s"
	// reads on stdin, or the script inside a sudo wrapper. Never stdin
	// itself: it can hold sudo's password.
	Script string
	// Values replaced in the logged text and error (passwords on a command line).
	Secrets []string
	// The command runs as root (through sudo, or the login user is root).
	AsRoot bool
	// Not logged: the terminal's own shell, which logs what is typed into it.
	Quiet bool
	// Stdout carries data, not messages (a dump, a file's bytes): only
	// stderr goes into the logged output.
	NoStdout bool

	ctx       context.Context
	conn      *Conn
	handle    cmdlog.Handle
	tail      tailBuffer
	out       cmdlog.OutputBuffer
	capturing atomic.Bool
	outPiped  bool
	errPiped  bool
	once      sync.Once
}

// capture writes into the logged output while the command is logged.
type capture struct{ s *Session }

func (c capture) Write(p []byte) (int, error) {
	if c.s.capturing.Load() {
		c.s.out.Write(p)
	}
	return len(p), nil
}

// StdoutPipe is ssh.Session's, with what is read also kept for the log.
func (s *Session) StdoutPipe() (io.Reader, error) {
	r, err := s.Session.StdoutPipe()
	if err != nil || s.NoStdout {
		return r, err
	}
	s.outPiped = true
	return io.TeeReader(r, capture{s}), nil
}

// StderrPipe is ssh.Session's, with what is read also kept for the log.
func (s *Session) StderrPipe() (io.Reader, error) {
	r, err := s.Session.StderrPipe()
	if err != nil {
		return r, err
	}
	s.errPiped = true
	return io.TeeReader(r, io.MultiWriter(capture{s}, &s.tail)), nil
}

// Session opens a session on the connection. ctx says who the command runs
// for (see cmdlog.With); it doesn't limit the session's life.
func (c *Conn) Session(ctx context.Context) (*Session, error) {
	s, err := c.Client.NewSession()
	if err != nil {
		return nil, err
	}
	return &Session{Session: s, ctx: ctx, conn: c}, nil
}

// Run runs cmd and logs it with how it ended.
func (s *Session) Run(cmd string) error {
	if err := s.Start(cmd); err != nil {
		return err
	}
	return s.Wait()
}

// Start starts cmd and logs it; Wait (or Close) records how it ended.
func (s *Session) Start(cmd string) error {
	switch {
	case s.Stderr != nil:
		s.Session.Stderr = io.MultiWriter(s.Stderr, &s.tail, capture{s})
	case !s.errPiped:
		s.Session.Stderr = io.MultiWriter(&s.tail, capture{s})
	}
	if !s.NoStdout {
		switch {
		case s.Stdout != nil:
			s.Session.Stdout = io.MultiWriter(s.Stdout, capture{s})
		case !s.outPiped:
			s.Session.Stdout = capture{s}
		}
	}
	s.begin(cmd)
	err := s.Session.Start(cmd)
	if err != nil {
		s.end(err)
	}
	return err
}

// Wait waits for the command and records how it ended.
func (s *Session) Wait() error {
	err := s.Session.Wait()
	s.end(err)
	return err
}

// Close closes the session; a command still running counts as stopped.
func (s *Session) Close() error {
	s.end(errStopped)
	return s.Session.Close()
}

var errStopped = errors.New("stopped by Morcheh")

func (s *Session) begin(cmd string) {
	sink := s.conn.pool.Log
	if s.Quiet || sink == nil {
		return
	}
	text := cmd
	if s.Script != "" {
		text = s.Script
	}
	asRoot := s.AsRoot || strings.HasPrefix(cmd, "sudo ")
	s.handle = sink.Begin(s.ctx, cmdlog.Command{
		ServerID: s.conn.id,
		Origin:   cmdlog.Of(s.ctx),
		Text:     cmdlog.Redact(strings.TrimSpace(text), s.Secrets...),
		AsRoot:   asRoot,
		Started:  time.Now(),
	})
	s.capturing.Store(s.handle != nil)
}

func (s *Session) end(err error) {
	s.once.Do(func() {
		if s.handle == nil {
			return
		}
		s.handle.End(s.result(err))
	})
}

func (s *Session) result(err error) cmdlog.Result {
	var exit *ssh.ExitError
	var missing *ssh.ExitMissingError
	r := cmdlog.Result{Code: -1}
	switch {
	case err == nil:
		r.Code = 0
	case errors.As(err, &exit) && exit.Signal() != "":
		r.Error = "Killed by signal " + exit.Signal()
	case errors.As(err, &exit):
		r.Code = exit.ExitStatus()
	case errors.As(err, &missing):
		r.Error = "The connection closed before it finished"
	case errors.Is(err, errStopped):
		r.Error = "Stopped before it finished"
	default:
		r.Error = err.Error()
	}
	if r.Code != 0 {
		if t := strings.TrimSpace(s.tail.String()); t != "" {
			if r.Error != "" {
				r.Error = fmt.Sprintf("%s\n%s", r.Error, t)
			} else {
				r.Error = t
			}
		}
	}
	r.Error = cmdlog.Redact(r.Error, s.Secrets...)
	r.Output = s.out.Result(s.Secrets...)
	return r
}

// tailBuffer keeps the last bytes of stderr, for a failed command's message.
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
}

const tailMax = 2 << 10

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > tailMax {
		t.buf = append([]byte(nil), t.buf[len(t.buf)-tailMax:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.ToValidUTF8(string(t.buf), "")
}
