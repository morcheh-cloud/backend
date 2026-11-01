package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/morcheh/backend/internal/sshprobe"
)

// SFTP over its own SSH connection (servers already in Morcheh have theirs
// in sshpool; NewSFTP wraps one of those).
type sftpfs struct {
	ssh *ssh.Client // nil when the connection belongs to someone else
	c   *sftp.Client
}

func openSFTP(ctx context.Context, cfg Config) (FS, Info, error) {
	port := cfg.Port
	if port == 0 {
		port = 22
	}
	client, presented, err := sshprobe.Dial(ctx, sshprobe.Target{
		Host: strings.TrimSpace(cfg.Host), Port: port, User: cfg.Username,
		Password: cfg.Secret, PrivateKey: cfg.PrivateKey, Passphrase: cfg.Passphrase,
		KnownHostKey: cfg.HostKey,
	})
	info := Info{LatencyMs: presented.LatencyMs, HostKey: presented.HostKey, Fingerprint: presented.Fingerprint}
	if err != nil {
		var de *sshprobe.DialError
		if errors.As(err, &de) {
			return nil, info, &ConnError{de.Status, de.Message, err}
		}
		return nil, info, &ConnError{StatusError, err.Error(), err}
	}
	c, err := sftp.NewClient(client, sftp.UseConcurrentReads(true), sftp.UseConcurrentWrites(true))
	if err != nil {
		client.Close()
		return nil, info, &ConnError{StatusError, "The server doesn't offer SFTP: " + err.Error(), err}
	}
	if info.Home, err = c.Getwd(); err != nil {
		info.Home = "/"
	}
	info.Detail = string(client.ServerVersion())
	return &sftpfs{ssh: client, c: c}, info, nil
}

// NewSFTP shows an existing SFTP session as a storage. Close leaves the
// session open.
func NewSFTP(c *sftp.Client) FS {
	return &sftpfs{c: c}
}

// IsConnLost reports whether err means the SSH connection died, so a cached
// storage should be reopened.
func IsConnLost(err error) bool {
	return errors.Is(err, sftp.ErrSSHFxConnectionLost) || errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed)
}

func sftpErr(err error) error {
	if err == nil {
		return nil
	}
	var se *sftp.StatusError
	if errors.As(err, &se) {
		switch se.FxCode() {
		case sftp.ErrSSHFxNoSuchFile:
			return fmt.Errorf("%s: %w", se.Error(), fs.ErrNotExist)
		case sftp.ErrSSHFxPermissionDenied:
			return fmt.Errorf("%s: %w", se.Error(), fs.ErrPermission)
		}
	}
	return err
}

func (s *sftpfs) entry(p string, fi os.FileInfo) Entry {
	e := Entry{Name: fi.Name(), Path: p, Dir: fi.IsDir(), Size: fi.Size(), Modified: fi.ModTime()}
	if fi.Mode()&os.ModeSymlink != 0 {
		// Links show as what they point to.
		if t, err := s.c.Stat(p); err == nil {
			e.Dir, e.Size = t.IsDir(), t.Size()
		}
	}
	if e.Dir {
		e.Size = 0
	}
	return e
}

func (s *sftpfs) List(_ context.Context, dir string, limit int) ([]Entry, error) {
	fi, err := s.c.Stat(dir)
	if err != nil {
		return nil, sftpErr(err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("not a folder: %w", fs.ErrInvalid)
	}
	infos, err := s.c.ReadDir(dir)
	if err != nil {
		return nil, sftpErr(err)
	}
	if len(infos) > limit {
		infos = infos[:limit]
	}
	out := make([]Entry, 0, len(infos))
	for _, fi := range infos {
		out = append(out, s.entry(path.Join(dir, fi.Name()), fi))
	}
	return out, nil
}

func (s *sftpfs) Stat(_ context.Context, p string) (Entry, error) {
	fi, err := s.c.Lstat(p)
	if err != nil {
		return Entry{}, sftpErr(err)
	}
	e := s.entry(p, fi)
	if p == "/" {
		e.Name = "/"
	}
	return e, nil
}

type sftpFile struct {
	*sftp.File
	e Entry
}

func (f *sftpFile) Entry() Entry { return f.e }

func (s *sftpfs) Open(_ context.Context, p string) (File, error) {
	f, err := s.c.Open(p)
	if err != nil {
		return nil, sftpErr(err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, sftpErr(err)
	}
	if fi.IsDir() {
		f.Close()
		return nil, fmt.Errorf("that's a folder: %w", fs.ErrInvalid)
	}
	return &sftpFile{f, s.entry(p, fi)}, nil
}

// Put writes next to the destination and renames into place, so a broken
// upload never leaves half a file.
func (s *sftpfs) Put(ctx context.Context, p string, r io.Reader, _ int64) error {
	dir := path.Dir(p)
	if err := s.c.MkdirAll(dir); err != nil {
		return sftpErr(err)
	}
	tmp := path.Join(dir, "."+path.Base(p)+".morcheh-"+fmt.Sprint(time.Now().UnixNano()))
	f, err := s.c.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return sftpErr(err)
	}
	_, err = f.ReadFrom(r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		_ = s.c.Remove(tmp)
		return sftpErr(err)
	}
	if err := s.c.PosixRename(tmp, p); err != nil {
		_ = s.c.Remove(p)
		if err := s.c.Rename(tmp, p); err != nil {
			_ = s.c.Remove(tmp)
			return sftpErr(err)
		}
	}
	return nil
}

func (s *sftpfs) Mkdir(_ context.Context, p string) error { return sftpErr(s.c.MkdirAll(p)) }

func (s *sftpfs) Remove(_ context.Context, p string) error {
	fi, err := s.c.Lstat(p)
	if err != nil {
		return sftpErr(err)
	}
	if fi.IsDir() {
		return sftpErr(s.c.RemoveAll(p))
	}
	return sftpErr(s.c.Remove(p))
}

func (s *sftpfs) Rename(_ context.Context, from, to string) error {
	if err := s.c.MkdirAll(path.Dir(to)); err != nil {
		return sftpErr(err)
	}
	return sftpErr(s.c.Rename(from, to))
}

func (s *sftpfs) Copy(context.Context, string, string) error { return ErrUnsupported }

func (s *sftpfs) Walk(context.Context, string, func(Entry) error) error { return ErrUnsupported }

func (s *sftpfs) Share(context.Context, string, time.Duration, string) (string, error) {
	return "", ErrUnsupported
}

func (s *sftpfs) Capabilities() Capabilities { return Capabilities{Ranges: true} }

func (s *sftpfs) Close() error {
	if s.ssh == nil {
		return nil
	}
	s.c.Close()
	return s.ssh.Close()
}
