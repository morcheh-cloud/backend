package api

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/terminal"
)

// privilege is how a server's login user can act as root.
type privilege int

const (
	privUser         privilege = iota // only as itself
	privRoot                          // it is root
	privSudo                          // passwordless sudo
	privSudoPassword                  // sudo with the stored login password
)

func (p privilege) access() string {
	switch p {
	case privRoot:
		return "root"
	case privSudo, privSudoPassword:
		return "sudo"
	default:
		return "user"
	}
}

// How long a detected privilege is trusted. A failed sudo attempt is logged
// (and often mailed) by the server, so it isn't retried on every request.
const privilegeTTL = 10 * time.Minute

type privileges struct {
	mu sync.Mutex
	m  map[string]privEntry
}

type privEntry struct {
	conn *sshpool.Conn // a new connection (new credentials) detects again
	p    privilege
	at   time.Time
}

// rootShell runs scripts on one server with the most privilege its login
// user has: as root, through sudo, or as itself.
type rootShell struct {
	c        *sshpool.Conn
	priv     privilege
	password string
}

func (h *serverHandler) rootShell(ctx context.Context, id string, c *sshpool.Conn) (*rootShell, error) {
	h.privs.mu.Lock()
	e, ok := h.privs.m[id]
	h.privs.mu.Unlock()
	if !ok || e.conn != c || time.Since(e.at) > privilegeTTL {
		p, err := h.detectPrivilege(ctx, id, c)
		if err != nil {
			return nil, err
		}
		e = privEntry{conn: c, p: p, at: time.Now()}
		h.privs.mu.Lock()
		if h.privs.m == nil {
			h.privs.m = map[string]privEntry{}
		}
		h.privs.m[id] = e
		h.privs.mu.Unlock()
	}
	sh := &rootShell{c: c, priv: e.p}
	if e.p == privSudoPassword {
		s, err := h.get(ctx, id)
		if err != nil {
			return nil, err
		}
		t, err := h.target(s)
		if err != nil {
			return nil, internalError(err)
		}
		sh.password = t.Password
	}
	return sh, nil
}

func (h *serverHandler) detectPrivilege(ctx context.Context, id string, c *sshpool.Conn) (privilege, error) {
	out, err := run(ctx, c, "sh -c "+terminal.ShellQuote(`id -u; sudo -n true >/dev/null 2>&1 && echo sudo; exit 0`))
	if err != nil {
		return privUser, err
	}
	fields := strings.Fields(out)
	switch {
	case len(fields) > 0 && fields[0] == "0":
		return privRoot, nil
	case slices.Contains(fields, "sudo"):
		return privSudo, nil
	}
	s, err := h.get(ctx, id)
	if err != nil {
		return privUser, err
	}
	t, err := h.target(s)
	if err != nil || t.Password == "" {
		return privUser, nil
	}
	if _, err := runInput(ctx, c, "sudo -S -p '' true", t.Password+"\n", 15*time.Second); err == nil {
		return privSudoPassword, nil
	}
	return privUser, nil
}

// command wraps a POSIX sh script to run as root when possible, and returns
// what to feed its stdin (sudo's password, or nothing). The script itself
// must not read stdin; heredocs are fine.
func (r *rootShell) command(script string) (cmd, stdin string) {
	cmd = "sh -c " + terminal.ShellQuote(script)
	switch r.priv {
	case privSudo:
		return "sudo -n " + cmd, ""
	case privSudoPassword:
		return "sudo -S -p '' " + cmd, r.password + "\n"
	}
	return cmd, ""
}

// run runs script (as root when possible) and returns its stdout.
func (r *rootShell) run(ctx context.Context, script string) (string, error) {
	cmd, stdin := r.command(script)
	return runInput(ctx, r.c, cmd, stdin, execTimeout)
}

// execResult is a command whose output and exit status are the point, not
// a step that has to succeed.
type execResult struct {
	output    []byte
	truncated bool
	code      int
	timedOut  bool
	duration  time.Duration
}

// exec runs script and collects stdout and stderr together, keeping at most
// limit bytes. A non-zero exit is a result, not an error.
func (r *rootShell) exec(ctx context.Context, script string, timeout time.Duration, limit int) (*execResult, error) {
	cmd, stdin := r.command(script)
	sess, err := r.c.Client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	out := &cappedBuffer{limit: limit}
	sess.Stdout, sess.Stderr = out, out
	if stdin != "" {
		sess.Stdin = strings.NewReader(stdin)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { sess.Close() })
	defer stop()

	start := time.Now()
	err = sess.Run(cmd)
	res := &execResult{duration: time.Since(start)}
	res.output, res.truncated = out.bytes()
	var exit *ssh.ExitError
	switch {
	case err == nil:
	case ctx.Err() != nil:
		res.code, res.timedOut = -1, true
	case errors.As(err, &exit):
		res.code = exit.ExitStatus()
	default:
		return nil, err
	}
	return res, nil
}

// cappedBuffer keeps the first limit bytes written to it, from any number of
// goroutines (stdout and stderr share one).
type cappedBuffer struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	limit   int
	dropped bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	room := b.limit - b.buf.Len()
	if room < len(p) {
		b.dropped = true
	}
	if room > 0 {
		b.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

func (b *cappedBuffer) bytes() ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Bytes(), b.dropped
}
