package storage

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/textproto"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jlaffaye/ftp"
)

// FTP and FTPS. A control connection does one thing at a time (a download
// holds it until the transfer ends), so connections come from a small pool
// and every streaming operation gets its own.
type ftpfs struct {
	cfg  Config
	addr string

	mu     sync.Mutex
	idle   []*ftp.ServerConn
	closed bool
}

const ftpMaxIdle = 4

func openFTP(ctx context.Context, cfg Config) (FS, Info, error) {
	port := cfg.Port
	if port == 0 {
		port = 21
		if cfg.TLS == "implicit" {
			port = 990
		}
	}
	f := &ftpfs{cfg: cfg, addr: net.JoinHostPort(strings.TrimSpace(cfg.Host), strconv.Itoa(port))}
	start := time.Now()
	c, err := f.dial(ctx)
	if err != nil {
		return nil, Info{}, err
	}
	info := Info{LatencyMs: int32(time.Since(start).Milliseconds())}
	// The login folder is the natural start (most servers jail users in it
	// anyway, so it's often "/").
	home, err := c.CurrentDir()
	if err != nil {
		c.Quit()
		return nil, info, &ConnError{StatusError, ftpText(err), err}
	}
	info.Home = home
	f.release(c, nil)
	return f, info, nil
}

func (f *ftpfs) dial(ctx context.Context) (*ftp.ServerConn, error) {
	opts := []ftp.DialOption{ftp.DialWithContext(ctx), ftp.DialWithTimeout(dialTimeout)}
	if f.cfg.TLS != "" && f.cfg.TLS != "none" {
		host, _, _ := net.SplitHostPort(f.addr)
		conf := &tls.Config{ServerName: host, InsecureSkipVerify: f.cfg.InsecureTLS} //nolint:gosec // opt-in for self-signed servers
		if f.cfg.TLS == "implicit" {
			opts = append(opts, ftp.DialWithTLS(conf))
		} else {
			opts = append(opts, ftp.DialWithExplicitTLS(conf))
		}
	}
	c, err := ftp.Dial(f.addr, opts...)
	if err != nil {
		var te *textproto.Error
		if errors.As(err, &te) {
			return nil, &ConnError{StatusError, ftpText(err), err}
		}
		if strings.Contains(err.Error(), "tls:") || strings.Contains(err.Error(), "x509:") {
			return nil, &ConnError{StatusError, "TLS: " + err.Error(), err}
		}
		return nil, &ConnError{StatusUnreachable, netMessage(err), err}
	}
	user, pass := f.cfg.Username, f.cfg.Secret
	if user == "" {
		user, pass = "anonymous", "anonymous"
	}
	if err := c.Login(user, pass); err != nil {
		c.Quit()
		var te *textproto.Error
		if errors.As(err, &te) && (te.Code == ftp.StatusNotLoggedIn || te.Code == ftp.StatusUserOK) {
			return nil, &ConnError{StatusAuthFailed, "Login failed: " + ftpText(err), err}
		}
		return nil, &ConnError{StatusError, ftpText(err), err}
	}
	return c, nil
}

// conn returns an idle connection, or dials a new one.
func (f *ftpfs) conn(ctx context.Context) (*ftp.ServerConn, bool, error) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil, false, errors.New("storage closed")
	}
	if n := len(f.idle); n > 0 {
		c := f.idle[n-1]
		f.idle = f.idle[:n-1]
		f.mu.Unlock()
		return c, true, nil
	}
	f.mu.Unlock()
	c, err := f.dial(ctx)
	return c, false, err
}

// release returns a healthy connection to the pool. FTP replies (550…)
// leave it usable; anything else (a broken socket) drops it.
func (f *ftpfs) release(c *ftp.ServerConn, err error) {
	var te *textproto.Error
	if err != nil && !errors.As(err, &te) {
		c.Quit()
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || len(f.idle) >= ftpMaxIdle {
		go c.Quit()
		return
	}
	f.idle = append(f.idle, c)
}

// do runs fn on a pooled connection, once more on a fresh one when a reused
// connection turns out to be dead (servers drop idle sessions).
func (f *ftpfs) do(ctx context.Context, fn func(*ftp.ServerConn) error) error {
	c, reused, err := f.conn(ctx)
	if err != nil {
		return err
	}
	err = fn(c)
	f.release(c, err)
	var te *textproto.Error
	if err != nil && reused && !errors.As(err, &te) && ctx.Err() == nil {
		if c, err = f.dial(ctx); err != nil {
			return err
		}
		err = fn(c)
		f.release(c, err)
	}
	return ftpErr(err)
}

func ftpText(err error) string {
	var te *textproto.Error
	if errors.As(err, &te) {
		return strings.TrimSpace(te.Msg)
	}
	return err.Error()
}

func ftpErr(err error) error {
	var te *textproto.Error
	if err == nil || !errors.As(err, &te) {
		return err
	}
	switch te.Code {
	case ftp.StatusFileUnavailable: // 550: missing, or not allowed
		msg := strings.ToLower(te.Msg)
		if strings.Contains(msg, "permission") || strings.Contains(msg, "denied") {
			return fmt.Errorf("%s: %w", ftpText(err), fs.ErrPermission)
		}
		if strings.Contains(msg, "exist") && !strings.Contains(msg, "not exist") && !strings.Contains(msg, "no such") {
			return fmt.Errorf("%s: %w", ftpText(err), fs.ErrExist)
		}
		return fmt.Errorf("%s: %w", ftpText(err), fs.ErrNotExist)
	case ftp.StatusNotLoggedIn, ftp.StatusFileActionIgnored, ftp.StatusBadFileName:
		return fmt.Errorf("%s: %w", ftpText(err), fs.ErrPermission)
	}
	return errors.New(ftpText(err))
}

func ftpEntry(dir string, e *ftp.Entry) Entry {
	return Entry{
		Name:     e.Name,
		Path:     path.Join(dir, e.Name),
		Dir:      e.Type == ftp.EntryTypeFolder,
		Size:     int64(e.Size),
		Modified: e.Time,
	}
}

func (f *ftpfs) list(c *ftp.ServerConn, dir string) ([]*ftp.Entry, error) {
	// Some servers answer LIST on a missing folder with an empty listing:
	// entering it first tells the two apart.
	if err := c.ChangeDir(dir); err != nil {
		return nil, err
	}
	return c.List(dir)
}

func (f *ftpfs) List(ctx context.Context, dir string, limit int) ([]Entry, error) {
	var out []Entry
	err := f.do(ctx, func(c *ftp.ServerConn) error {
		raw, err := f.list(c, dir)
		if err != nil {
			return err
		}
		out = make([]Entry, 0, len(raw))
		for _, e := range raw {
			if e.Name == "." || e.Name == ".." {
				continue
			}
			if len(out) >= limit {
				break
			}
			out = append(out, ftpEntry(dir, e))
		}
		return nil
	})
	return out, err
}

func (f *ftpfs) Stat(ctx context.Context, p string) (Entry, error) {
	p = Clean(p)
	if p == "/" {
		return Entry{Name: "/", Path: "/", Dir: true}, nil
	}
	var out Entry
	err := f.do(ctx, func(c *ftp.ServerConn) error {
		// MLST isn't everywhere; the parent's listing is.
		if e, err := c.GetEntry(p); err == nil {
			out = ftpEntry(path.Dir(p), e)
			out.Name, out.Path = path.Base(p), p
			return nil
		}
		raw, err := f.list(c, path.Dir(p))
		if err != nil {
			return err
		}
		for _, e := range raw {
			if e.Name == path.Base(p) {
				out = ftpEntry(path.Dir(p), e)
				return nil
			}
		}
		return &textproto.Error{Code: ftp.StatusFileUnavailable, Msg: "No such file: " + p}
	})
	return out, err
}

type ftpFile struct {
	*ftp.Response
	f    *ftpfs
	c    *ftp.ServerConn
	e    Entry
	once sync.Once
}

func (r *ftpFile) Entry() Entry { return r.e }

func (r *ftpFile) Close() error {
	var err error
	r.once.Do(func() {
		err = r.Response.Close()
		r.f.release(r.c, err)
	})
	return err
}

func (f *ftpfs) Open(ctx context.Context, p string) (File, error) {
	e, err := f.Stat(ctx, p)
	if err != nil {
		return nil, err
	}
	if e.Dir {
		return nil, fmt.Errorf("that's a folder: %w", fs.ErrInvalid)
	}
	c, _, err := f.conn(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := c.Retr(p)
	if err != nil {
		f.release(c, err)
		return nil, ftpErr(err)
	}
	return &ftpFile{Response: resp, f: f, c: c, e: e}, nil
}

func (f *ftpfs) Put(ctx context.Context, p string, r io.Reader, _ int64) error {
	if err := f.Mkdir(ctx, path.Dir(p)); err != nil {
		return err
	}
	c, _, err := f.conn(ctx)
	if err != nil {
		return err
	}
	err = c.Stor(p, r)
	f.release(c, err)
	if err != nil {
		// Don't leave half a file behind.
		_ = f.do(context.WithoutCancel(ctx), func(c *ftp.ServerConn) error { return c.Delete(p) })
	}
	return ftpErr(err)
}

func (f *ftpfs) Mkdir(ctx context.Context, p string) error {
	p = Clean(p)
	if p == "/" {
		return nil
	}
	return f.do(ctx, func(c *ftp.ServerConn) error {
		if c.ChangeDir(p) == nil {
			return nil
		}
		cur := ""
		for part := range strings.SplitSeq(strings.TrimPrefix(p, "/"), "/") {
			cur += "/" + part
			if c.ChangeDir(cur) == nil {
				continue
			}
			if err := c.MakeDir(cur); err != nil {
				return err
			}
		}
		return nil
	})
}

func (f *ftpfs) Remove(ctx context.Context, p string) error {
	e, err := f.Stat(ctx, p)
	if err != nil {
		return err
	}
	return f.do(ctx, func(c *ftp.ServerConn) error {
		if e.Dir {
			return c.RemoveDirRecur(p)
		}
		return c.Delete(p)
	})
}

func (f *ftpfs) Rename(ctx context.Context, from, to string) error {
	if err := f.Mkdir(ctx, path.Dir(to)); err != nil {
		return err
	}
	return f.do(ctx, func(c *ftp.ServerConn) error { return c.Rename(from, to) })
}

func (f *ftpfs) Copy(context.Context, string, string) error { return ErrUnsupported }

func (f *ftpfs) Walk(context.Context, string, func(Entry) error) error { return ErrUnsupported }

func (f *ftpfs) Share(context.Context, string, time.Duration, string) (string, error) {
	return "", ErrUnsupported
}

func (f *ftpfs) Capabilities() Capabilities { return Capabilities{} }

func (f *ftpfs) Close() error {
	f.mu.Lock()
	idle := f.idle
	f.idle, f.closed = nil, true
	f.mu.Unlock()
	for _, c := range idle {
		c.Quit()
	}
	return nil
}
