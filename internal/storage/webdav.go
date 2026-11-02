package storage

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/studio-b12/gowebdav"
)

// WebDAV (Nextcloud, ownCloud, Synology, Apache mod_dav…). The client has
// no context support; dropped downloads end when their reader is closed.
type davfs struct {
	c  *gowebdav.Client
	tr *http.Transport
}

func openWebDAV(_ context.Context, cfg Config) (FS, Info, error) {
	raw := strings.TrimSpace(cfg.Host)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, Info{}, &ConnError{StatusError, "URL: expected something like https://cloud.example.com/remote.php/dav/files/me/", err}
	}
	if cfg.Port > 0 && u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), fmt.Sprint(cfg.Port))
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.InsecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in for self-signed servers
	}
	tr.ResponseHeaderTimeout = dialTimeout
	c := gowebdav.NewClient(u.String(), cfg.Username, cfg.Secret)
	c.SetTransport(slashRedirects{tr})
	d := &davfs{c: c, tr: tr}

	fi, err := c.Stat("/")
	if err != nil {
		var ue *url.Error
		switch {
		case gowebdav.IsErrCode(err, http.StatusUnauthorized), errors.Is(err, gowebdav.ErrAuthChanged):
			return nil, Info{}, &ConnError{StatusAuthFailed, "Wrong user name or password", err}
		case gowebdav.IsErrCode(err, http.StatusForbidden):
			return nil, Info{}, &ConnError{StatusAuthFailed, "Access denied", err}
		case gowebdav.IsErrNotFound(err):
			return nil, Info{}, &ConnError{StatusError, "Nothing at that URL (404). Check the path, e.g. /remote.php/dav/files/<user>/ on Nextcloud", err}
		case errors.As(err, &ue):
			return nil, Info{}, &ConnError{StatusUnreachable, netMessage(err), err}
		}
		return nil, Info{}, &ConnError{StatusError, davText(err), err}
	}
	if !fi.IsDir() {
		return nil, Info{}, &ConnError{StatusError, "That URL is a file, not a folder", nil}
	}
	return d, Info{}, nil
}

// slashRedirects repeats a request on "dir/" when the server redirects
// "dir" there (Apache mod_dav does). Go's client would follow the 301 as a
// GET, so PROPFIND sees HTML and DELETE "succeeds" without deleting.
type slashRedirects struct{ base http.RoundTripper }

func (t slashRedirects) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := t.base.RoundTrip(r)
	if err != nil || r.Method == http.MethodGet || r.Method == http.MethodHead {
		return res, err
	}
	switch res.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return res, nil
	}
	loc, err := res.Location()
	if err != nil || loc.Host != r.URL.Host || loc.Path != r.URL.Path+"/" || (r.Body != nil && r.GetBody == nil) {
		return res, nil
	}
	again := r.Clone(r.Context())
	again.URL = loc
	if r.GetBody != nil {
		if again.Body, err = r.GetBody(); err != nil {
			return res, nil
		}
	}
	res.Body.Close()
	return t.base.RoundTrip(again)
}

func davText(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		var se gowebdav.StatusError
		if errors.As(pe.Err, &se) {
			return fmt.Sprintf("%s: HTTP %d %s", pe.Op, se.Status, http.StatusText(se.Status))
		}
	}
	return err.Error()
}

func davErr(err error) error {
	if err == nil {
		return nil
	}
	var pe *os.PathError
	if errors.As(err, &pe) {
		var se gowebdav.StatusError
		if errors.As(pe.Err, &se) {
			switch se.Status {
			case http.StatusNotFound, http.StatusConflict:
				return fmt.Errorf("%s: %w", davText(err), fs.ErrNotExist)
			case http.StatusUnauthorized, http.StatusForbidden:
				return fmt.Errorf("%s: %w", davText(err), fs.ErrPermission)
			case http.StatusMethodNotAllowed, http.StatusPreconditionFailed:
				return fmt.Errorf("%s: %w", davText(err), fs.ErrExist)
			}
			return errors.New(davText(err))
		}
	}
	return err
}

func davEntry(dir string, fi os.FileInfo) Entry {
	e := Entry{Name: fi.Name(), Path: path.Join(dir, fi.Name()), Dir: fi.IsDir(), Size: fi.Size(), Modified: fi.ModTime()}
	if f, ok := fi.(gowebdav.File); ok {
		e.ContentType = f.ContentType()
		e.ETag = strings.Trim(f.ETag(), `"`)
	}
	if e.Dir {
		e.Size = 0
	}
	return e
}

func (d *davfs) List(_ context.Context, dir string, limit int) ([]Entry, error) {
	infos, err := d.c.ReadDir(dir)
	if err != nil {
		return nil, davErr(err)
	}
	out := make([]Entry, 0, len(infos))
	for _, fi := range infos {
		if len(out) >= limit {
			break
		}
		out = append(out, davEntry(dir, fi))
	}
	return out, nil
}

func (d *davfs) Stat(_ context.Context, p string) (Entry, error) {
	fi, err := d.c.Stat(p)
	if err != nil {
		return Entry{}, davErr(err)
	}
	e := davEntry(path.Dir(p), fi)
	e.Path, e.Name = p, path.Base(p)
	return e, nil
}

type davFile struct {
	io.ReadCloser
	e Entry
}

func (f *davFile) Entry() Entry { return f.e }

func (d *davfs) Open(ctx context.Context, p string) (File, error) {
	e, err := d.Stat(ctx, p)
	if err != nil {
		return nil, err
	}
	if e.Dir {
		return nil, fmt.Errorf("that's a folder: %w", fs.ErrInvalid)
	}
	r, err := d.c.ReadStream(p)
	if err != nil {
		return nil, davErr(err)
	}
	return &davFile{r, e}, nil
}

func (d *davfs) Put(_ context.Context, p string, r io.Reader, size int64) error {
	if size < 0 {
		// The client would buffer the whole stream in memory: spool to disk.
		tmp, err := os.CreateTemp("", "morcheh-dav-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		defer tmp.Close()
		if size, err = io.Copy(tmp, r); err != nil {
			return err
		}
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return err
		}
		r = tmp
	}
	return davErr(d.c.WriteStreamWithLength(p, r, size, 0o644))
}

func (d *davfs) Mkdir(_ context.Context, p string) error { return davErr(d.c.MkdirAll(p, 0o755)) }

func (d *davfs) Remove(_ context.Context, p string) error { return davErr(d.c.RemoveAll(p)) }

func (d *davfs) Rename(_ context.Context, from, to string) error {
	if err := d.c.MkdirAll(path.Dir(to), 0o755); err != nil {
		return davErr(err)
	}
	return davErr(d.c.Rename(from, to, false))
}

func (d *davfs) Copy(_ context.Context, from, to string) error {
	if err := d.c.MkdirAll(path.Dir(to), 0o755); err != nil {
		return davErr(err)
	}
	return davErr(d.c.Copy(from, to, false))
}

func (d *davfs) Walk(context.Context, string, func(Entry) error) error { return ErrUnsupported }

func (d *davfs) Share(context.Context, string, time.Duration, string) (string, error) {
	return "", ErrUnsupported
}

func (d *davfs) Capabilities() Capabilities { return Capabilities{ServerCopy: true} }

func (d *davfs) Close() error {
	d.tr.CloseIdleConnections()
	return nil
}

// netMessage turns a dial error into a short sentence.
func netMessage(err error) string {
	var dnsErr *net.DNSError
	var opErr *net.OpError
	switch {
	case errors.As(err, &dnsErr):
		return "Can't resolve " + dnsErr.Name
	case errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err):
		return "Timed out connecting"
	case errors.As(err, &opErr) && strings.Contains(opErr.Error(), "refused"):
		return "Connection refused"
	}
	return err.Error()
}
