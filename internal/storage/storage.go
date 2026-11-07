// Package storage reaches file storages over several protocols (S3, FTP,
// SFTP, WebDAV) behind one interface. Paths are always clean and absolute
// ("/", "/reports/2026.csv"), relative to the storage's root folder.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
	"time"
)

const (
	ProtoS3     = "s3"
	ProtoFTP    = "ftp"
	ProtoSFTP   = "sftp"
	ProtoWebDAV = "webdav"
)

// Connection statuses, shared with servers where they mean the same.
const (
	StatusOnline          = "online"
	StatusUnreachable     = "unreachable"
	StatusAuthFailed      = "auth_failed"
	StatusHostKeyMismatch = "host_key_mismatch"
	StatusError           = "error"
)

const dialTimeout = 15 * time.Second

var (
	// ErrNotEmpty: the folder (or bucket) still has contents.
	ErrNotEmpty = errors.New("folder is not empty")
	// ErrUnsupported: this protocol can't do that (e.g. share links on FTP).
	ErrUnsupported = errors.ErrUnsupported
)

// Config is everything needed to connect. Fields that don't apply to a
// protocol are ignored.
type Config struct {
	Protocol string
	// Host name (FTP, SFTP) or URL (S3 endpoint, WebDAV).
	Host     string
	Port     int
	Username string
	// Password, or the S3 secret key.
	Secret     string
	PrivateKey string
	Passphrase string
	// S3: a fixed bucket; empty shows every bucket as a top-level folder.
	Bucket    string
	Region    string
	PathStyle bool
	// FTP: none, explicit (AUTH TLS) or implicit (FTPS on 990).
	TLS         string
	InsecureTLS bool
	// SFTP: the trusted host key (authorized_keys format); empty trusts
	// whatever the server presents.
	HostKey string
	// Folder shown as "/". Empty is the protocol's natural start: the login
	// folder for SFTP, "/" elsewhere.
	Root string
}

// Info describes a successful connection.
type Info struct {
	LatencyMs int32
	// SFTP: the host key the server presented, and its fingerprint.
	HostKey     string
	Fingerprint string
	// A short human note, e.g. "3 buckets" or the server's banner.
	Detail string
	// The login folder (FTP, SFTP): the root when Config.Root is empty.
	Home string
}

// ConnError is a failure to connect, classified for the status badge.
type ConnError struct {
	Status  string
	Message string
	Err     error
}

func (e *ConnError) Error() string { return e.Message }
func (e *ConnError) Unwrap() error { return e.Err }

type Entry struct {
	Name     string
	Path     string
	Dir      bool
	Size     int64
	Modified time.Time // zero when the protocol doesn't know (S3 prefixes)
	// Optional metadata.
	ContentType  string
	ETag         string
	StorageClass string
	// S3 without a fixed bucket: a top-level folder that is a bucket.
	Bucket bool
}

// File is an open file for reading. S3 and SFTP files also implement
// io.Seeker, which enables Range requests.
type File interface {
	io.ReadCloser
	Entry() Entry
}

// Capabilities a client may adapt its UI to.
type Capabilities struct {
	Buckets    bool // top-level folders are buckets
	ShareLinks bool // Share works
	ServerCopy bool // Copy happens on the storage, without streaming through us
	Ranges     bool // downloads resume and media seeks
}

type FS interface {
	// List a folder's direct children, at most limit of them.
	List(ctx context.Context, dir string, limit int) ([]Entry, error)
	Stat(ctx context.Context, p string) (Entry, error)
	Open(ctx context.Context, p string) (File, error)
	// Put writes a file, creating missing parent folders. size is -1 when
	// unknown.
	Put(ctx context.Context, p string, r io.Reader, size int64) error
	// Mkdir creates a folder and its missing parents.
	Mkdir(ctx context.Context, p string) error
	// Remove deletes a file, or a folder with everything in it.
	Remove(ctx context.Context, p string) error
	// Rename moves a file or folder; the caller checks that `to` is free.
	Rename(ctx context.Context, from, to string) error
	// Copy duplicates a file or folder on the storage itself, or returns
	// ErrUnsupported (callers then stream it with CopyTree).
	Copy(ctx context.Context, from, to string) error
	// Walk visits everything under dir (not dir itself), or returns
	// ErrUnsupported (callers then use the generic Walk).
	Walk(ctx context.Context, dir string, fn func(Entry) error) error
	// Share returns a time-limited public download link, or ErrUnsupported.
	Share(ctx context.Context, p string, expiry time.Duration, filename string) (string, error)
	Capabilities() Capabilities
	Close() error
}

// Open connects and checks that the storage answers (credentials, bucket,
// root folder). Errors are *ConnError.
func Open(ctx context.Context, cfg Config) (FS, Info, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	var (
		f    FS
		info Info
		err  error
	)
	start := time.Now()
	switch cfg.Protocol {
	case ProtoS3:
		f, info, err = openS3(ctx, cfg)
	case ProtoFTP:
		f, info, err = openFTP(ctx, cfg)
	case ProtoSFTP:
		f, info, err = openSFTP(ctx, cfg)
	case ProtoWebDAV:
		f, info, err = openWebDAV(ctx, cfg)
	default:
		return nil, info, &ConnError{StatusError, "Unknown protocol " + cfg.Protocol, nil}
	}
	if err != nil {
		var ce *ConnError
		if !errors.As(err, &ce) {
			err = &ConnError{StatusError, err.Error(), err}
		}
		return nil, info, err
	}
	if info.LatencyMs == 0 {
		info.LatencyMs = int32(time.Since(start).Milliseconds())
	}

	root := cfg.Root
	if root == "" {
		root = info.Home
	}
	if root = Clean(root); root != "/" {
		e, err := f.Stat(ctx, root)
		if err == nil && !e.Dir {
			err = fmt.Errorf("%s is a file", root)
		}
		if err != nil {
			f.Close()
			return nil, info, &ConnError{StatusError, "Root folder: " + Message(err), err}
		}
		f = &rooted{FS: f, root: root}
	}
	return f, info, nil
}

// Clean makes p absolute and clean; "" is "/".
func Clean(p string) string {
	return path.Clean("/" + p)
}

// Message is a short user-facing text for an operation error.
func Message(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "Not found"
	case errors.Is(err, fs.ErrExist):
		return "Already exists"
	case errors.Is(err, fs.ErrPermission):
		return "Permission denied"
	case errors.Is(err, ErrNotEmpty):
		return "Not empty"
	case errors.Is(err, ErrUnsupported):
		return "Not supported by this storage"
	}
	return err.Error()
}

// Walk visits everything under dir, using the storage's own recursive
// listing when it has one (S3 lists a whole tree in a few requests).
func Walk(ctx context.Context, f FS, dir string, fn func(Entry) error) error {
	err := f.Walk(ctx, dir, fn)
	if !errors.Is(err, ErrUnsupported) {
		return err
	}
	return walkList(ctx, f, dir, fn)
}

const walkPage = 100_000

func walkList(ctx context.Context, f FS, dir string, fn func(Entry) error) error {
	entries, err := f.List(ctx, dir, walkPage)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
		if e.Dir {
			if err := walkList(ctx, f, e.Path, fn); err != nil {
				return err
			}
		}
	}
	return nil
}

// ErrSkip from a Walk callback stops the walk without an error.
var ErrSkip = errors.New("skip")

// Progress counts what a copy moved. The hooks, when set, see it happen:
// OnFile as each file starts, OnBytes as its contents go through.
type Progress struct {
	Files   int
	Bytes   int64
	OnFile  func(path string)
	OnBytes func(n int64)
}

func (p *Progress) file(path string) {
	if p != nil && p.OnFile != nil {
		p.OnFile(path)
	}
}

// Measure counts the files under p (p itself when it's a file) and their
// bytes, for a progress bar's total.
func Measure(ctx context.Context, f FS, p string) (files int, bytes int64, err error) {
	e, err := f.Stat(ctx, p)
	if err != nil {
		return 0, 0, err
	}
	if !e.Dir {
		return 1, e.Size, nil
	}
	err = Walk(ctx, f, p, func(e Entry) error {
		if !e.Dir {
			files++
			bytes += e.Size
		}
		return nil
	})
	return files, bytes, err
}

// CopyTree copies a file or folder from one storage (or the same one) to
// another, streaming file contents through this process. It uses the
// storage's own copy when both ends are the same storage.
func CopyTree(ctx context.Context, src FS, from string, dst FS, to string, p *Progress) error {
	if src == dst {
		p.file(from)
		if err := src.Copy(ctx, from, to); !errors.Is(err, ErrUnsupported) {
			if err == nil && p != nil {
				p.Files++
			}
			return err
		}
	}
	e, err := src.Stat(ctx, from)
	if err != nil {
		return err
	}
	if !e.Dir {
		return copyFile(ctx, src, e, dst, to, p)
	}
	if err := dst.Mkdir(ctx, to); err != nil {
		return err
	}
	return Walk(ctx, src, from, func(e Entry) error {
		target := path.Join(to, strings.TrimPrefix(e.Path, from))
		if e.Dir {
			return dst.Mkdir(ctx, target)
		}
		return copyFile(ctx, src, e, dst, target, p)
	})
}

func copyFile(ctx context.Context, src FS, e Entry, dst FS, to string, p *Progress) error {
	r, err := src.Open(ctx, e.Path)
	if err != nil {
		return err
	}
	defer r.Close()
	size := e.Size
	if size == 0 && e.Modified.IsZero() {
		size = -1
	}
	p.file(e.Path)
	cr := &countingReader{r: r}
	if p != nil {
		cr.on = p.OnBytes
	}
	if err := dst.Put(ctx, to, cr, size); err != nil {
		return err
	}
	if p != nil {
		p.Files++
		p.Bytes += cr.n
	}
	return nil
}

type countingReader struct {
	r  io.Reader
	n  int64
	on func(int64)
}

func (c *countingReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.n += int64(n)
	if c.on != nil && n > 0 {
		c.on(int64(n))
	}
	return n, err
}

// Within reports whether p is base or inside it.
func Within(p, base string) bool {
	return p == base || base == "/" || strings.HasPrefix(p, base+"/")
}

// rooted shows a subfolder of a storage as its "/".
type rooted struct {
	FS
	root string
}

func (r *rooted) abs(p string) string { return path.Join(r.root, Clean(p)) }

func (r *rooted) rel(p string) string {
	if p == r.root {
		return "/"
	}
	return Clean(strings.TrimPrefix(p, r.root))
}

func (r *rooted) entry(e Entry) Entry {
	e.Path = r.rel(e.Path)
	e.Bucket = false
	return e
}

func (r *rooted) List(ctx context.Context, dir string, limit int) ([]Entry, error) {
	entries, err := r.FS.List(ctx, r.abs(dir), limit)
	for i := range entries {
		entries[i] = r.entry(entries[i])
	}
	return entries, err
}

func (r *rooted) Stat(ctx context.Context, p string) (Entry, error) {
	e, err := r.FS.Stat(ctx, r.abs(p))
	if err == nil && Clean(p) == "/" {
		e.Name = "/"
	}
	return r.entry(e), err
}

func (r *rooted) Open(ctx context.Context, p string) (File, error) {
	f, err := r.FS.Open(ctx, r.abs(p))
	if err != nil {
		return nil, err
	}
	return &rootedFile{f, r}, nil
}

type rootedFile struct {
	File
	r *rooted
}

func (f *rootedFile) Entry() Entry { return f.r.entry(f.File.Entry()) }

func (f *rootedFile) Seek(offset int64, whence int) (int64, error) {
	if s, ok := f.File.(io.Seeker); ok {
		return s.Seek(offset, whence)
	}
	return 0, ErrUnsupported
}

func (r *rooted) Put(ctx context.Context, p string, rd io.Reader, size int64) error {
	return r.FS.Put(ctx, r.abs(p), rd, size)
}

func (r *rooted) Mkdir(ctx context.Context, p string) error { return r.FS.Mkdir(ctx, r.abs(p)) }

func (r *rooted) Remove(ctx context.Context, p string) error {
	if Clean(p) == "/" {
		return fs.ErrPermission
	}
	return r.FS.Remove(ctx, r.abs(p))
}

func (r *rooted) Rename(ctx context.Context, from, to string) error {
	return r.FS.Rename(ctx, r.abs(from), r.abs(to))
}

func (r *rooted) Copy(ctx context.Context, from, to string) error {
	return r.FS.Copy(ctx, r.abs(from), r.abs(to))
}

func (r *rooted) Walk(ctx context.Context, dir string, fn func(Entry) error) error {
	return r.FS.Walk(ctx, r.abs(dir), func(e Entry) error { return fn(r.entry(e)) })
}

func (r *rooted) Share(ctx context.Context, p string, expiry time.Duration, filename string) (string, error) {
	return r.FS.Share(ctx, r.abs(p), expiry, filename)
}

// Below a root inside a bucket there are no bucket folders.
func (r *rooted) Capabilities() Capabilities {
	c := r.FS.Capabilities()
	c.Buckets = false
	return c
}

// Space is the size of the disk behind a storage, when the protocol tells.
type Space struct {
	Total int64
	Free  int64
}

type spacer interface {
	space(ctx context.Context, p string) (Space, error)
}

// SpaceOf reports the disk's size and free space at the storage's root, or
// ErrUnsupported (only SFTP servers with the statvfs extension answer).
func SpaceOf(ctx context.Context, f FS) (Space, error) {
	p := "/"
	if r, ok := f.(*rooted); ok {
		f, p = r.FS, r.root
	}
	if s, ok := f.(spacer); ok {
		return s.space(ctx, p)
	}
	return Space{}, ErrUnsupported
}
