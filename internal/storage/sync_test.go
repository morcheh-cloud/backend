package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// memFS is an in-memory storage for tests. Folders are explicit, like SFTP.
type memFS struct {
	mu    sync.Mutex
	now   time.Time
	files map[string]memFile // path → file; folders have dir set
}

type memFile struct {
	data []byte
	dir  bool
	mod  time.Time
}

func newMem(now time.Time) *memFS {
	return &memFS{now: now, files: map[string]memFile{"/": {dir: true, mod: now}}}
}

func (m *memFS) write(p, data string, mod time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mkdirLocked(path.Dir(p))
	m.files[p] = memFile{data: []byte(data), mod: mod}
}

func (m *memFS) mkdirLocked(p string) {
	for d := p; ; d = path.Dir(d) {
		if _, ok := m.files[d]; !ok {
			m.files[d] = memFile{dir: true, mod: m.now}
		}
		if d == "/" {
			return
		}
	}
}

func (m *memFS) entry(p string, f memFile) Entry {
	return Entry{Name: path.Base(p), Path: p, Dir: f.dir, Size: int64(len(f.data)), Modified: f.mod}
}

func (m *memFS) List(_ context.Context, dir string, _ int) ([]Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f, ok := m.files[dir]; !ok || !f.dir {
		return nil, fs.ErrNotExist
	}
	var out []Entry
	for p, f := range m.files {
		if p != dir && path.Dir(p) == dir {
			out = append(out, m.entry(p, f))
		}
	}
	slices.SortFunc(out, func(a, b Entry) int { return strings.Compare(a.Path, b.Path) })
	return out, nil
}

func (m *memFS) Stat(_ context.Context, p string) (Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.files[p]
	if !ok {
		return Entry{}, fs.ErrNotExist
	}
	return m.entry(p, f), nil
}

type memReader struct {
	io.Reader
	e Entry
}

func (r memReader) Close() error { return nil }
func (r memReader) Entry() Entry { return r.e }
func (m *memFS) Open(_ context.Context, p string) (File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	if f.dir {
		return nil, errors.New("is a folder")
	}
	return memReader{bytes.NewReader(f.data), m.entry(p, f)}, nil
}

func (m *memFS) Put(_ context.Context, p string, r io.Reader, _ int64) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if f, ok := m.files[p]; ok && f.dir {
		return fs.ErrExist
	}
	m.mkdirLocked(path.Dir(p))
	m.files[p] = memFile{data: data, mod: m.now}
	return nil
}

func (m *memFS) Mkdir(_ context.Context, p string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f, ok := m.files[p]; ok && !f.dir {
		return fs.ErrExist
	}
	m.mkdirLocked(p)
	return nil
}

func (m *memFS) Remove(_ context.Context, p string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[p]; !ok {
		return fs.ErrNotExist
	}
	for q := range m.files {
		if Within(q, p) {
			delete(m.files, q)
		}
	}
	return nil
}

func (m *memFS) Rename(context.Context, string, string) error { return ErrUnsupported }
func (m *memFS) Copy(context.Context, string, string) error   { return ErrUnsupported }
func (m *memFS) Walk(context.Context, string, func(Entry) error) error {
	return ErrUnsupported
}
func (m *memFS) Share(context.Context, string, time.Duration, string) (string, error) {
	return "", ErrUnsupported
}
func (m *memFS) Capabilities() Capabilities { return Capabilities{} }
func (m *memFS) Close() error               { return nil }

// tree lists the files under dir as rel=content, folders as rel/.
func (m *memFS) tree(dir string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for p, f := range m.files {
		if p == dir || !Within(p, dir) {
			continue
		}
		rel := relTo(p, dir)
		if f.dir {
			out = append(out, rel+"/")
		} else {
			out = append(out, rel+"="+string(f.data))
		}
	}
	slices.Sort(out)
	return out
}

var t0 = time.Date(2026, 11, 4, 3, 0, 0, 0, time.UTC)

func source() *memFS {
	src := newMem(t0)
	src.write("/data/a.txt", "aaa", t0.Add(-time.Hour))
	src.write("/data/sub/b.txt", "bb", t0.Add(-time.Hour))
	src.write("/data/sub/skip.log", "log", t0.Add(-time.Hour))
	src.write("/data/node_modules/x/y.js", "y", t0.Add(-time.Hour))
	return src
}

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestSyncUpdate(t *testing.T) {
	ctx := context.Background()
	src, dst := source(), newMem(t0)
	dst.write("/backup/old.txt", "keep", t0)
	o := SyncOptions{Mode: SyncUpdate, Excludes: []string{"*.log", "node_modules"}}
	res, err := Sync(ctx, src, "/data", dst, "/backup", o, &Progress{})
	if err != nil {
		t.Fatal(err)
	}
	eq(t, dst.tree("/backup"), []string{"a.txt=aaa", "old.txt=keep", "sub/", "sub/b.txt=bb"})
	if res.Copied != 2 || res.Bytes != 5 || res.Skipped != 0 || res.Deleted != 0 {
		t.Fatalf("first run: %+v", res)
	}

	// Nothing changed: nothing copied.
	res, err = Sync(ctx, src, "/data", dst, "/backup", o, &Progress{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Copied != 0 || res.Skipped != 2 {
		t.Fatalf("second run: %+v", res)
	}

	// A changed file is copied again.
	src.write("/data/a.txt", "AAAA", t0.Add(time.Hour))
	res, err = Sync(ctx, src, "/data", dst, "/backup", o, &Progress{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Copied != 1 || res.Skipped != 1 {
		t.Fatalf("third run: %+v", res)
	}
	eq(t, dst.tree("/backup"), []string{"a.txt=AAAA", "old.txt=keep", "sub/", "sub/b.txt=bb"})
}

func TestSyncMirror(t *testing.T) {
	ctx := context.Background()
	src, dst := source(), newMem(t0)
	dst.write("/backup/old.txt", "gone", t0)
	dst.write("/backup/olddir/z.txt", "gone", t0)
	dst.write("/backup/keep.log", "excluded, so kept", t0)
	dst.write("/backup/sub", "a file where a folder goes", t0)
	o := SyncOptions{Mode: SyncMirror, Excludes: []string{"*.log", "node_modules"}}
	res, err := Sync(ctx, src, "/data", dst, "/backup", o, &Progress{})
	if err != nil {
		t.Fatal(err)
	}
	eq(t, dst.tree("/backup"), []string{"a.txt=aaa", "keep.log=excluded, so kept", "sub/", "sub/b.txt=bb"})
	if res.Deleted != 2 || res.Copied != 2 {
		t.Fatalf("%+v", res)
	}
}

func TestSyncMirrorRefusesEmptySource(t *testing.T) {
	ctx := context.Background()
	src, dst := newMem(t0), newMem(t0)
	_ = src.Mkdir(ctx, "/data")
	dst.write("/backup/a.txt", "precious", t0)
	_, err := Sync(ctx, src, "/data", dst, "/backup", SyncOptions{Mode: SyncMirror}, nil)
	if !errors.Is(err, ErrEmptySource) {
		t.Fatalf("err = %v", err)
	}
	eq(t, dst.tree("/backup"), []string{"a.txt=precious"})
}

func TestSyncUpdateKeepsTypeClash(t *testing.T) {
	ctx := context.Background()
	src, dst := source(), newMem(t0)
	dst.write("/backup/sub", "a file", t0)
	res, err := Sync(ctx, src, "/data", dst, "/backup", SyncOptions{Mode: SyncUpdate, Excludes: []string{"node_modules"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Failed != 1 || res.Copied != 1 {
		t.Fatalf("%+v", res)
	}
	eq(t, dst.tree("/backup"), []string{"a.txt=aaa", "sub=a file"})
}

func TestSyncFile(t *testing.T) {
	ctx := context.Background()
	src, dst := source(), newMem(t0)
	res, err := Sync(ctx, src, "/data/a.txt", dst, "/in", SyncOptions{Mode: SyncMirror}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Copied != 1 {
		t.Fatalf("%+v", res)
	}
	eq(t, dst.tree("/in"), []string{"a.txt=aaa"})
}

func TestSyncDryRun(t *testing.T) {
	ctx := context.Background()
	src, dst := source(), newMem(t0)
	dst.write("/backup/old.txt", "x", t0)
	var planned int
	o := SyncOptions{Mode: SyncMirror, DryRun: true, Plan: func(files int, _ int64) { planned = files }}
	res, err := Sync(ctx, src, "/data", dst, "/backup", o, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Copied != 4 || res.Deleted != 1 || planned != 4 {
		t.Fatalf("%+v planned %d", res, planned)
	}
	eq(t, dst.tree("/backup"), []string{"old.txt=x"})
}

func TestSyncSnapshot(t *testing.T) {
	ctx := context.Background()
	src, dst := source(), newMem(t0)
	dst.write("/snaps/notes.txt", "not a snapshot", t0)
	dst.write("/snaps/manual/a", "not a snapshot", t0)
	o := SyncOptions{Mode: SyncSnapshot, Keep: 2, Excludes: []string{"node_modules"}}
	for i := range 3 {
		o.Now = t0.Add(time.Duration(i) * time.Hour)
		res, err := Sync(ctx, src, "/data", dst, "/snaps", o, nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.Copied != 3 {
			t.Fatalf("run %d: %+v", i, res)
		}
		if i == 2 && res.Deleted != 1 {
			t.Fatalf("run %d should prune one: %+v", i, res)
		}
	}
	var top []string
	for _, e := range dst.tree("/snaps") {
		if !strings.Contains(strings.TrimSuffix(e, "/"), "/") {
			top = append(top, e)
		}
	}
	eq(t, top, []string{"2026-11-04_04-00-00/", "2026-11-04_05-00-00/", "manual/", "notes.txt=not a snapshot"})
	eq(t, dst.tree("/snaps/2026-11-04_05-00-00"), []string{"a.txt=aaa", "sub/", "sub/b.txt=bb", "sub/skip.log=log"})
}

func TestMatcher(t *testing.T) {
	m, err := NewMatcher([]string{"*.tmp", "/cache/", "logs/*.gz", " "})
	if err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]bool{
		"a.tmp": true, "x/y/a.tmp": true, "cache": true, "cache/a": true, "x/cache/a": true,
		"logs/a.gz": true, "x/logs/a.gz": false, "logs/a.txt": false, "a.txt": false,
	} {
		if got := m.Excluded(rel); got != want {
			t.Errorf("%s: got %v", rel, got)
		}
	}
	if _, err := NewMatcher([]string{"[oops"}); err == nil {
		t.Error("a broken pattern should be refused")
	}
}

func TestSame(t *testing.T) {
	src := Entry{Size: 1, Modified: t0}
	if !same(src, Entry{Size: 1, Modified: t0.Add(time.Second)}) {
		t.Error("a newer copy is up to date")
	}
	if same(src, Entry{Size: 2, Modified: t0.Add(time.Hour)}) {
		t.Error("a different size isn't")
	}
	if same(Entry{Size: 1, Modified: t0.Add(time.Hour)}, Entry{Size: 1, Modified: t0.Add(time.Second)}) {
		t.Error("a source changed after the copy isn't")
	}
	// FTP: whole minutes.
	if !same(Entry{Size: 1, Modified: t0.Add(30 * time.Second)}, Entry{Size: 1, Modified: t0}) {
		t.Error("minute precision should be allowed for")
	}
}
