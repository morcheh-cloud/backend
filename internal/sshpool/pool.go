// Package sshpool keeps one SSH connection per server open while something
// uses it, so terminals and file operations share a login instead of
// connecting for every request.
package sshpool

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	// An unused connection is closed after this long.
	idleTimeout = 5 * time.Minute
	keepalive   = 30 * time.Second
	// How long cached user and group names stay fresh.
	namesTTL = 5 * time.Minute
)

// DialFunc opens a new authenticated client for a server.
type DialFunc func(ctx context.Context) (*ssh.Client, error)

// Conn is a shared connection to one server. Close it only through the pool.
type Conn struct {
	Client *ssh.Client

	pool    *Pool
	id      string
	version string
	done    chan struct{}

	mu       sync.Mutex
	refs     int
	lastUsed time.Time
	sftp     *sftp.Client
	names    *names
}

type names struct {
	users, groups map[uint32]string
	loaded        time.Time
}

// Pool hands out connections by server id. A connection is reused while the
// server's connection settings (summarised as version) stay the same.
type Pool struct {
	mu      sync.Mutex
	conns   map[string]*Conn
	dialing map[string]*dial
}

type dial struct {
	version string
	done    chan struct{}
	conn    *Conn
	err     error
}

func New() *Pool {
	p := &Pool{conns: map[string]*Conn{}, dialing: map[string]*dial{}}
	go p.reap()
	return p
}

// Get returns the open connection for id, or dials one. Concurrent callers
// for the same server share one dial.
func (p *Pool) Get(ctx context.Context, id, version string, dialFn DialFunc) (*Conn, error) {
	for {
		p.mu.Lock()
		if c := p.conns[id]; c != nil {
			if c.version == version && !c.closed() {
				c.touch()
				p.mu.Unlock()
				return c, nil
			}
			// Settings changed or the link died: new users get a fresh
			// connection; terminals still on the old one keep it.
			delete(p.conns, id)
			c.retireLocked()
		}
		if d := p.dialing[id]; d != nil {
			p.mu.Unlock()
			select {
			case <-d.done:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			if d.version != version {
				continue
			}
			if d.err != nil {
				return nil, d.err
			}
			continue // pick it up from conns, checking it is still alive
		}
		d := &dial{version: version, done: make(chan struct{})}
		p.dialing[id] = d
		p.mu.Unlock()

		// The dial outlives this request: others may be waiting on it.
		client, err := dialFn(context.WithoutCancel(ctx))

		p.mu.Lock()
		delete(p.dialing, id)
		if err != nil {
			d.err = err
		} else {
			c := &Conn{Client: client, pool: p, id: id, version: version, done: make(chan struct{}), lastUsed: time.Now()}
			p.conns[id] = c
			d.conn = c
			go c.watch()
		}
		close(d.done)
		p.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return d.conn, nil
	}
}

// Drop closes the server's connection, e.g. after the server is deleted.
func (p *Pool) Drop(id string) {
	p.mu.Lock()
	c := p.conns[id]
	delete(p.conns, id)
	p.mu.Unlock()
	if c != nil {
		c.Client.Close()
	}
}

func (p *Pool) reap() {
	for range time.Tick(time.Minute) {
		p.mu.Lock()
		for id, c := range p.conns {
			c.mu.Lock()
			idle := c.refs == 0 && time.Since(c.lastUsed) > idleTimeout
			c.mu.Unlock()
			if idle {
				delete(p.conns, id)
				c.Client.Close()
			}
		}
		p.mu.Unlock()
	}
}

// Acquire marks the connection as in use (a terminal), so it isn't closed
// for being idle. Every Acquire needs a Release.
func (c *Conn) Acquire() {
	c.mu.Lock()
	c.refs++
	c.lastUsed = time.Now()
	c.mu.Unlock()
}

func (c *Conn) Release() {
	c.mu.Lock()
	c.refs--
	c.lastUsed = time.Now()
	unused := c.refs == 0
	c.mu.Unlock()
	if unused && c.retired() {
		c.Client.Close()
	}
}

// Done is closed when the connection is gone.
func (c *Conn) Done() <-chan struct{} { return c.done }

func (c *Conn) closed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *Conn) touch() {
	c.mu.Lock()
	c.lastUsed = time.Now()
	c.mu.Unlock()
}

// retired: the pool no longer hands this connection out.
func (c *Conn) retired() bool {
	c.pool.mu.Lock()
	defer c.pool.mu.Unlock()
	return c.pool.conns[c.id] != c
}

// retireLocked closes a replaced connection unless a terminal still uses it.
// Caller holds p.mu.
func (c *Conn) retireLocked() {
	c.mu.Lock()
	refs := c.refs
	c.mu.Unlock()
	if refs == 0 {
		go c.Client.Close()
	}
}

// watch pings the server and forgets the connection once it drops.
func (c *Conn) watch() {
	lost := make(chan struct{})
	go func() {
		_ = c.Client.Wait()
		close(lost)
	}()
	t := time.NewTicker(keepalive)
	defer t.Stop()
	for {
		select {
		case <-lost:
			c.forget()
			return
		case <-t.C:
			ok := make(chan bool, 1)
			go func() {
				_, _, err := c.Client.SendRequest("keepalive@openssh.com", true, nil)
				ok <- err == nil
			}()
			select {
			case alive := <-ok:
				if !alive {
					c.Client.Close()
				}
			case <-time.After(15 * time.Second):
				c.Client.Close()
			case <-lost:
			}
		}
	}
}

func (c *Conn) forget() {
	c.pool.mu.Lock()
	if c.pool.conns[c.id] == c {
		delete(c.pool.conns, c.id)
	}
	c.pool.mu.Unlock()
	close(c.done)
}

// SFTP returns the connection's SFTP client, starting it on first use.
func (c *Conn) SFTP() (*sftp.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastUsed = time.Now()
	if c.sftp != nil {
		return c.sftp, nil
	}
	s, err := sftp.NewClient(c.Client, sftp.UseConcurrentReads(true), sftp.UseConcurrentWrites(true))
	if err != nil {
		return nil, err
	}
	c.sftp = s
	go func() {
		// The subsystem can die on its own (e.g. killed on the server).
		_ = s.Wait()
		c.mu.Lock()
		if c.sftp == s {
			c.sftp = nil
		}
		c.mu.Unlock()
	}()
	return s, nil
}

// Names maps uids and gids to names from /etc/passwd and /etc/group, cached
// for a few minutes. Missing files just leave the maps empty.
func (c *Conn) Names() (users, groups map[uint32]string) {
	c.mu.Lock()
	n := c.names
	c.mu.Unlock()
	if n != nil && time.Since(n.loaded) < namesTTL {
		return n.users, n.groups
	}
	n = &names{users: map[uint32]string{}, groups: map[uint32]string{}, loaded: time.Now()}
	if s, err := c.SFTP(); err == nil {
		readIDs(s, "/etc/passwd", n.users)
		readIDs(s, "/etc/group", n.groups)
	}
	c.mu.Lock()
	c.names = n
	c.mu.Unlock()
	return n.users, n.groups
}

// readIDs parses "name:x:id:…" lines.
func readIDs(s *sftp.Client, path string, into map[uint32]string) {
	f, err := s.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, 4<<20))
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 4)
		if len(parts) < 3 {
			continue
		}
		if id, err := strconv.ParseUint(parts[2], 10, 32); err == nil {
			if _, dup := into[uint32(id)]; !dup {
				into[uint32(id)] = parts[0]
			}
		}
	}
}

// Lost reports whether err means the connection itself broke, so the caller
// can retry once on a fresh one.
func Lost(err error) bool {
	return errors.Is(err, sftp.ErrSSHFxConnectionLost) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed)
}
