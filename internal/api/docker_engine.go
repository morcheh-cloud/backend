package api

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/cmdlog"
	"github.com/morcheh/backend/internal/docker"
	"github.com/morcheh/backend/internal/sshpool"
)

// How Morche reaches a server's Docker engine, found once per pooled
// connection and kept while it lives:
//
//   - "socket": a direct-streamlocal channel to the engine's socket (the
//     login user is root or in the docker group);
//   - "sudo": `docker system dial-stdio` (or socat on the socket) through
//     sudo, one SSH session per HTTP connection;
//   - "cli": the same without sudo (streamlocal forwarding is off, but the
//     login user may use the socket).
type dockerEngine struct {
	conn   *sshpool.Conn
	client *docker.Client
	via    string
	asRoot bool
}

// dockerFailure is why the engine couldn't be reached, kept a little while
// so lists across many servers don't probe them all on every poll.
type dockerFailure struct {
	conn    *sshpool.Conn
	state   string
	message string
	at      time.Time
}

const dockerFailureTTL = 30 * time.Second

type dockerEngines struct {
	mu     sync.Mutex
	ready  map[string]*dockerEngine
	failed map[string]dockerFailure
}

func (d *dockerEngines) drop(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if e := d.ready[id]; e != nil {
		e.client.Close()
		delete(d.ready, id)
	}
	delete(d.failed, id)
}

// Engine states as the panel shows them.
const (
	dockerReady        = "ready"
	dockerNotInstalled = "not-installed"
	dockerStopped      = "stopped"
	dockerNoAccess     = "no-access"
	dockerError        = "error"
)

// dockerUnavailable is a reachable server whose engine can't be used.
type dockerUnavailable struct {
	state, message string
}

func (e *dockerUnavailable) Error() string { return e.message }

var dockerSockets = []string{"/var/run/docker.sock", "/run/docker.sock"}

// dockerStdioScript turns stdin/stdout into a stream to the engine.
const dockerStdioScript = `if command -v docker >/dev/null 2>&1; then exec docker system dial-stdio; fi
for s in /var/run/docker.sock /run/docker.sock; do
  [ -S "$s" ] || continue
  if command -v socat >/dev/null 2>&1; then exec socat - "UNIX-CONNECT:$s"; fi
done
echo "docker: command not found" >&2; exit 127`

// dockerProbeScript says what's on the server when the engine can't be reached.
const dockerProbeScript = `command -v docker >/dev/null 2>&1 && echo cli
for s in /var/run/docker.sock /run/docker.sock; do [ -S "$s" ] && echo socket && break; done
command -v systemctl >/dev/null 2>&1 && echo "active=$(systemctl is-active docker 2>/dev/null)"
command -v podman >/dev/null 2>&1 && echo podman
exit 0`

// engine returns the server's engine on c, finding how to reach it first.
func (h *serverHandler) engine(ctx context.Context, id string, c *sshpool.Conn) (*dockerEngine, error) {
	d := &h.docker
	d.mu.Lock()
	if e := d.ready[id]; e != nil && e.conn == c {
		d.mu.Unlock()
		return e, nil
	}
	if f, ok := d.failed[id]; ok && f.conn == c && time.Since(f.at) < dockerFailureTTL {
		d.mu.Unlock()
		return nil, &dockerUnavailable{f.state, f.message}
	}
	d.mu.Unlock()

	e, err := h.findEngine(ctx, id, c)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ready == nil {
		d.ready, d.failed = map[string]*dockerEngine{}, map[string]dockerFailure{}
	}
	if old := d.ready[id]; old != nil {
		old.client.Close()
		delete(d.ready, id)
	}
	var un *dockerUnavailable
	switch {
	case err == nil:
		d.ready[id] = e
		delete(d.failed, id)
	case errors.As(err, &un):
		d.failed[id] = dockerFailure{conn: c, state: un.state, message: un.message, at: time.Now()}
	}
	return e, err
}

func (h *serverHandler) findEngine(ctx context.Context, id string, c *sshpool.Conn) (*dockerEngine, error) {
	ping := func(cl *docker.Client) error {
		pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return cl.Ping(pctx)
	}

	// 1. The socket, straight through the SSH connection.
	for _, sock := range dockerSockets {
		dial := func(ctx context.Context) (net.Conn, error) { return c.Client.DialContext(ctx, "unix", sock) }
		probe, err := dial(ctx)
		if err != nil {
			continue
		}
		probe.Close()
		cl := docker.New(dial, 16)
		if err := ping(cl); err == nil {
			return &dockerEngine{conn: c, client: cl, via: "socket", asRoot: true}, nil
		}
		cl.Close()
	}
	if c.Client == nil || isClosed(c) {
		return nil, net.ErrClosed
	}

	// 2. dial-stdio, through sudo when the login user has it.
	sh, err := h.rootShell(ctx, id, c)
	if err != nil {
		return nil, err
	}
	var stderr string
	var mu sync.Mutex
	dial := func(ctx context.Context) (net.Conn, error) {
		conn, err := dialStdio(ctx, c, sh)
		if err == nil {
			conn.onStderr = func(s string) { mu.Lock(); stderr = s; mu.Unlock() }
		}
		return conn, err
	}
	// Each stream is an SSH session: sshd allows 10 per connection.
	cl := docker.New(dial, 4)
	if err := ping(cl); err == nil {
		via := "cli"
		if sh.priv == privSudo || sh.priv == privSudoPassword {
			via = "sudo"
		}
		return &dockerEngine{conn: c, client: cl, via: via, asRoot: sh.priv != privUser}, nil
	}
	cl.Close()
	if isClosed(c) {
		return nil, net.ErrClosed
	}

	// 3. Say why.
	out, err := sh.run(cmdlog.Background(ctx, "Docker"), dockerProbeScript)
	if err != nil {
		return nil, err
	}
	facts := map[string]bool{}
	active := ""
	for _, l := range strings.Fields(out) {
		if v, ok := strings.CutPrefix(l, "active="); ok {
			active = v
			continue
		}
		facts[l] = true
	}
	mu.Lock()
	msg := strings.TrimSpace(stderr)
	mu.Unlock()
	switch {
	case !facts["cli"] && !facts["socket"]:
		if facts["podman"] {
			return nil, &dockerUnavailable{dockerNotInstalled, "Podman is installed but its Docker-compatible socket isn't on. Run: sudo systemctl enable --now podman.socket"}
		}
		return nil, &dockerUnavailable{dockerNotInstalled, "Docker isn't installed on this server"}
	case !facts["socket"] || (active != "" && active != "active"):
		return nil, &dockerUnavailable{dockerStopped, "Docker is installed but its engine isn't running"}
	case strings.Contains(strings.ToLower(msg), "permission denied") || sh.priv == privUser:
		return nil, &dockerUnavailable{dockerNoAccess, "The login user can't use Docker: add it to the docker group, or give it sudo"}
	}
	if msg == "" {
		msg = "Docker didn't answer"
	}
	return nil, &dockerUnavailable{dockerError, msg}
}

func isClosed(c *sshpool.Conn) bool {
	select {
	case <-c.Done():
		return true
	default:
		return false
	}
}

// stdioConn is an SSH session's stdin/stdout as a net.Conn.
type stdioConn struct {
	sess     *sshpool.Session
	in       io.WriteCloser
	out      io.Reader
	errs     *cappedBuffer
	onStderr func(string)
	once     sync.Once
}

func dialStdio(ctx context.Context, c *sshpool.Conn, sh *rootShell) (*stdioConn, error) {
	cmd, stdin := sh.command(dockerStdioScript)
	sess, err := c.Session(ctx)
	if err != nil {
		return nil, err
	}
	// The stream itself isn't a command anyone ran: what goes through it
	// is logged by each action.
	sess.Quiet = true
	in, err := sess.Session.StdinPipe()
	if err != nil {
		sess.Close()
		return nil, err
	}
	out, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		return nil, err
	}
	errs := &cappedBuffer{limit: 4 << 10}
	sess.Stderr = errs
	if err := sess.Start(cmd); err != nil {
		sess.Close()
		return nil, err
	}
	if stdin != "" { // sudo reads its password a byte at a time, then hands stdin on
		if _, err := io.WriteString(in, stdin); err != nil {
			sess.Close()
			return nil, err
		}
	}
	return &stdioConn{sess: sess, in: in, out: out, errs: errs}, nil
}

func (s *stdioConn) Read(p []byte) (int, error) {
	n, err := s.out.Read(p)
	if err == io.EOF {
		if b, _ := s.errs.bytes(); len(b) > 0 {
			msg := strings.TrimSpace(string(b))
			if s.onStderr != nil {
				s.onStderr(msg)
			}
			return n, errors.New(msg)
		}
	}
	return n, err
}

func (s *stdioConn) Write(p []byte) (int, error) { return s.in.Write(p) }

func (s *stdioConn) Close() error {
	s.once.Do(func() {
		s.in.Close()
		s.sess.Close()
	})
	return nil
}

type stdioAddr struct{}

func (stdioAddr) Network() string { return "ssh" }
func (stdioAddr) String() string  { return "docker" }

func (s *stdioConn) LocalAddr() net.Addr              { return stdioAddr{} }
func (s *stdioConn) RemoteAddr() net.Addr             { return stdioAddr{} }
func (s *stdioConn) SetDeadline(time.Time) error      { return nil }
func (s *stdioConn) SetReadDeadline(time.Time) error  { return nil }
func (s *stdioConn) SetWriteDeadline(time.Time) error { return nil }

// dockerStreamError is a failed request to the engine on a connection that
// is still fine, so withConn doesn't drop it and retry.
type dockerStreamError struct{ err error }

func (e *dockerStreamError) Error() string { return "Docker: " + e.err.Error() }
func (e *dockerStreamError) Unwrap() error { return nil }

// withDocker runs fn with the server's engine. Errors come back as problems.
func (h *serverHandler) withDocker(ctx context.Context, id string, fn func(e *dockerEngine) error) error {
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		e, err := h.engine(ctx, id, c)
		if err != nil {
			return err
		}
		err = fn(e)
		var de *docker.Error
		var se huma.StatusError
		if err == nil || errors.As(err, &de) || errors.As(err, &se) || ctx.Err() != nil {
			return err
		}
		if isClosed(c) {
			return err // withConn retries on a fresh connection
		}
		// The engine stream broke (dockerd restarted?): find it again next time.
		h.docker.drop(id)
		return &dockerStreamError{err}
	})
	return dockerProblem(err)
}

// dockerProblem turns an engine error into the status the panel expects.
func dockerProblem(err error) error {
	if err == nil {
		return nil
	}
	var un *dockerUnavailable
	if errors.As(err, &un) {
		return huma.Error422UnprocessableEntity(un.message)
	}
	var de *docker.Error
	if errors.As(err, &de) {
		msg := de.Message
		switch de.Status {
		case http.StatusNotFound:
			return huma.Error404NotFound(msg)
		case http.StatusConflict:
			return huma.Error409Conflict(msg)
		case http.StatusBadRequest:
			return huma.Error422UnprocessableEntity(msg)
		case http.StatusForbidden, http.StatusUnauthorized:
			return huma.Error403Forbidden(msg)
		}
		return huma.Error422UnprocessableEntity("Docker: " + msg)
	}
	var st *dockerStreamError
	if errors.As(err, &st) {
		return huma.Error502BadGateway(st.Error())
	}
	return toProblem(err)
}

// dockerLog writes a change made through the engine into the command log,
// as the docker command that would do the same. Call the result with how
// it went.
func (h *serverHandler) dockerLog(ctx context.Context, id string, e *dockerEngine, text string) func(error) {
	sink := h.pool.Log
	if sink == nil {
		return func(error) {}
	}
	hd := sink.Begin(ctx, cmdlog.Command{
		ServerID: id, Origin: cmdlog.Of(ctx), Text: text, AsRoot: e.asRoot, Started: time.Now(),
	})
	if hd == nil {
		return func(error) {}
	}
	return func(err error) {
		r := cmdlog.Result{}
		if err != nil {
			r.Code, r.Error = 1, err.Error()
		}
		hd.End(r)
	}
}

// dockerDo runs one logged change on the engine.
func (h *serverHandler) dockerDo(ctx context.Context, id, text string, fn func(e *dockerEngine) error) error {
	return h.withDocker(ctx, id, func(e *dockerEngine) error {
		end := h.dockerLog(ctx, id, e, text)
		err := fn(e)
		end(err)
		return err
	})
}
