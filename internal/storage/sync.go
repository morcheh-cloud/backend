package storage

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Sync modes.
const (
	// SyncUpdate copies new and changed files and deletes nothing.
	SyncUpdate = "update"
	// SyncMirror also deletes what the source no longer has, so the
	// destination ends up the same as the source.
	SyncMirror = "mirror"
	// SyncSnapshot copies everything into a new dated folder each time and
	// keeps the newest few.
	SyncSnapshot = "snapshot"
)

// SnapshotLayout names snapshot folders; only folders named like it are ever
// pruned.
const SnapshotLayout = "2006-01-02_15-04-05"

var snapshotName = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$`)

// ErrEmptySource stops a mirror whose source has nothing in it: deleting
// everything in the destination is far more likely a mistake (a mount that
// went away) than what anyone wants.
var ErrEmptySource = errors.New("the source folder is empty, so nothing was deleted from the destination")

type SyncOptions struct {
	Mode string
	// Glob patterns (path.Match). One without a slash matches a name at any
	// depth; one with a slash matches the path from the source folder.
	// Whatever a folder pattern matches is skipped with all it holds.
	Excludes []string
	// Snapshots to keep, 0 = all of them.
	Keep int
	// Names the snapshot folder.
	Now time.Time
	// Count what would happen without changing anything.
	DryRun bool
	// Plan, when set, hears what's to copy before copying starts.
	Plan func(files int, bytes int64)
}

type SyncResult struct {
	Copied  int   `json:"copied" doc:"Files written"`
	Bytes   int64 `json:"bytes" doc:"Bytes written"`
	Skipped int   `json:"skipped" doc:"Files already up to date"`
	Deleted int   `json:"deleted" doc:"Files and folders removed (mirror), or old snapshots"`
	Failed  int   `json:"failed" doc:"Files that couldn't be copied"`
	// The first few problems with single files.
	Problems []string `json:"problems,omitempty"`
	// The folder a snapshot went into.
	Folder string `json:"folder,omitempty"`
}

const maxProblems = 20

func (r *SyncResult) problem(p string, err error) {
	r.Failed++
	if len(r.Problems) < maxProblems {
		r.Problems = append(r.Problems, p+": "+Message(err))
	}
}

// fileError says an error is about one file (gone, or not readable) rather
// than the connection: the sync goes on with the next one.
func fileError(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) || errors.Is(err, fs.ErrExist)
}

// Matcher says which paths the excludes leave out.
type Matcher struct{ patterns []string }

// NewMatcher checks the patterns.
func NewMatcher(patterns []string) (Matcher, error) {
	var m Matcher
	for _, p := range patterns {
		p = strings.Trim(strings.TrimSpace(p), "/")
		if p == "" {
			continue
		}
		if _, err := path.Match(p, ""); err != nil {
			return m, fmt.Errorf("%q isn't a valid pattern", p)
		}
		m.patterns = append(m.patterns, p)
	}
	return m, nil
}

// Excluded reports whether rel (relative to the source folder, no leading
// slash) or a folder it's in is left out.
func (m Matcher) Excluded(rel string) bool {
	if len(m.patterns) == 0 {
		return false
	}
	parts := strings.Split(rel, "/")
	for i := range parts {
		prefix := strings.Join(parts[:i+1], "/")
		for _, p := range m.patterns {
			target := parts[i]
			if strings.Contains(p, "/") {
				target = prefix
			}
			if ok, _ := path.Match(p, target); ok {
				return true
			}
		}
	}
	return false
}

// Sync makes the folder dstDir on dst hold what src has at srcPath: the
// contents of a folder, or the file itself. Problems with single files are
// counted in the result and the rest goes on; anything else stops it.
func Sync(ctx context.Context, src FS, srcPath string, dst FS, dstDir string, o SyncOptions, p *Progress) (SyncResult, error) {
	var res SyncResult
	m, err := NewMatcher(o.Excludes)
	if err != nil {
		return res, err
	}
	root, err := src.Stat(ctx, srcPath)
	if err != nil {
		return res, fmt.Errorf("source %s: %w", srcPath, err)
	}
	if o.Mode == SyncSnapshot {
		return snapshot(ctx, src, root, dst, dstDir, o, m, p)
	}

	// What the source has, relative to srcPath.
	want := map[string]Entry{}
	if root.Dir {
		err = Walk(ctx, src, root.Path, func(e Entry) error {
			rel := relTo(e.Path, root.Path)
			if rel == "" || m.Excluded(rel) {
				return nil
			}
			want[rel] = e
			return nil
		})
		if err != nil {
			return res, fmt.Errorf("source %s: %w", srcPath, err)
		}
	} else {
		want[root.Name] = root
	}

	// What the destination has.
	have := map[string]Entry{}
	if e, err := dst.Stat(ctx, dstDir); err == nil {
		if !e.Dir {
			return res, fmt.Errorf("destination %s is a file, not a folder", dstDir)
		}
		err = Walk(ctx, dst, dstDir, func(e Entry) error {
			if rel := relTo(e.Path, dstDir); rel != "" {
				have[rel] = e
			}
			return nil
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return res, fmt.Errorf("destination %s: %w", dstDir, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return res, fmt.Errorf("destination %s: %w", dstDir, err)
	}

	if o.Mode == SyncMirror && root.Dir && len(want) == 0 && len(have) > 0 {
		return res, ErrEmptySource
	}

	// Decide. In update mode a name that's a file on one side and a folder on
	// the other is left alone, with whatever the source has under it.
	var mkdirs, copies, replace []string
	blocked := map[string]bool{}
	var files int
	var bytes int64
	for _, rel := range sortedKeys(want) {
		if under(rel, blocked) {
			continue
		}
		s := want[rel]
		d, ok := have[rel]
		if ok && d.Dir != s.Dir {
			if o.Mode != SyncMirror {
				what := "file"
				if d.Dir {
					what = "folder"
				}
				res.problem(rel, fmt.Errorf("a %s in the destination has this name: %w", what, fs.ErrExist))
				blocked[rel] = true
				continue
			}
			replace = append(replace, rel)
			ok = false
		}
		if s.Dir {
			if !ok {
				mkdirs = append(mkdirs, rel)
			}
			continue
		}
		if ok && same(s, d) {
			res.Skipped++
			continue
		}
		copies = append(copies, rel)
		files++
		bytes += s.Size
	}
	var removes []string
	if o.Mode == SyncMirror {
		gone := map[string]bool{}
		for _, rel := range replace {
			gone[rel] = true
		}
		for _, rel := range sortedKeys(have) {
			if _, ok := want[rel]; ok || m.Excluded(rel) || under(rel, gone) {
				continue
			}
			// A folder goes as a whole.
			gone[rel] = true
			removes = append(removes, rel)
		}
	}
	if o.Plan != nil {
		o.Plan(files, bytes)
	}
	if o.DryRun {
		res.Copied, res.Bytes, res.Deleted = files, bytes, len(removes)
		return res, nil
	}

	// Do.
	if err := dst.Mkdir(ctx, dstDir); err != nil {
		return res, fmt.Errorf("destination %s: %w", dstDir, err)
	}
	for _, rel := range replace {
		if err := dst.Remove(ctx, path.Join(dstDir, rel)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			if !fileError(err) {
				return res, err
			}
			res.problem(rel, err)
		}
	}
	for _, rel := range mkdirs {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if err := dst.Mkdir(ctx, path.Join(dstDir, rel)); err != nil {
			if !fileError(err) {
				return res, err
			}
			res.problem(rel, err)
		}
	}
	for _, rel := range copies {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		before := progressBytes(p)
		err := copyFile(ctx, src, want[rel], dst, path.Join(dstDir, rel), p)
		if err != nil {
			if !fileError(err) {
				return res, err
			}
			res.problem(rel, err)
			continue
		}
		res.Copied++
		res.Bytes += progressBytes(p) - before
	}
	for _, rel := range removes {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if err := dst.Remove(ctx, path.Join(dstDir, rel)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			if !fileError(err) {
				return res, err
			}
			res.problem(rel, err)
			continue
		}
		res.Deleted++
	}
	return res, nil
}

// snapshot copies everything into dstDir/<now>, then prunes old snapshots.
// A snapshot that didn't finish is removed again, so it never counts as one
// of the kept ones.
func snapshot(ctx context.Context, src FS, root Entry, dst FS, dstDir string, o SyncOptions, m Matcher, p *Progress) (SyncResult, error) {
	var res SyncResult
	name := o.Now.Format(SnapshotLayout)
	folder := path.Join(dstDir, name)
	res.Folder = folder

	var list []Entry
	var bytes int64
	if root.Dir {
		err := Walk(ctx, src, root.Path, func(e Entry) error {
			rel := relTo(e.Path, root.Path)
			if rel == "" || m.Excluded(rel) {
				return nil
			}
			list = append(list, e)
			if !e.Dir {
				bytes += e.Size
			}
			return nil
		})
		if err != nil {
			return res, fmt.Errorf("source %s: %w", root.Path, err)
		}
	} else {
		list, bytes = []Entry{root}, root.Size
	}
	slices.SortFunc(list, func(a, b Entry) int { return strings.Compare(a.Path, b.Path) })
	files := 0
	for _, e := range list {
		if !e.Dir {
			files++
		}
	}
	if _, err := dst.Stat(ctx, folder); err == nil {
		return res, fmt.Errorf("%s already exists: %w", folder, fs.ErrExist)
	}
	old, err := snapshots(ctx, dst, dstDir)
	if err != nil {
		return res, err
	}
	prune := 0
	if o.Keep > 0 && len(old)+1 > o.Keep {
		prune = len(old) + 1 - o.Keep
	}
	if o.Plan != nil {
		o.Plan(files, bytes)
	}
	if o.DryRun {
		res.Copied, res.Bytes, res.Deleted = files, bytes, prune
		return res, nil
	}

	fail := func(err error) (SyncResult, error) {
		// Best effort, on a context that isn't canceled.
		_ = dst.Remove(context.WithoutCancel(ctx), folder)
		return res, err
	}
	if err := dst.Mkdir(ctx, folder); err != nil {
		return res, fmt.Errorf("destination %s: %w", folder, err)
	}
	for _, e := range list {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		target := path.Join(folder, e.Name)
		if root.Dir {
			target = path.Join(folder, relTo(e.Path, root.Path))
		}
		if e.Dir {
			if err := dst.Mkdir(ctx, target); err != nil {
				return fail(err)
			}
			continue
		}
		before := progressBytes(p)
		if err := copyFile(ctx, src, e, dst, target, p); err != nil {
			if !fileError(err) {
				return fail(err)
			}
			res.problem(relTo(e.Path, root.Path), err)
			continue
		}
		res.Copied++
		res.Bytes += progressBytes(p) - before
	}
	for _, s := range old[:prune] {
		if err := dst.Remove(ctx, s); err != nil && !errors.Is(err, fs.ErrNotExist) {
			res.problem(path.Base(s), err)
			continue
		}
		res.Deleted++
	}
	return res, nil
}

// snapshots lists the snapshot folders in dir, oldest first.
func snapshots(ctx context.Context, f FS, dir string) ([]string, error) {
	entries, err := f.List(ctx, dir, walkPage)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("destination %s: %w", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.Dir && snapshotName.MatchString(e.Name) {
			out = append(out, e.Path)
		}
	}
	slices.Sort(out)
	return out, nil
}

// same says the destination's copy is up to date: same size and not older
// than the source. Copies get the time they were written, so "not older" is
// what "unchanged since the last copy" looks like. FTP shows whole minutes.
func same(s, d Entry) bool {
	if s.Size != d.Size {
		return false
	}
	if s.Modified.IsZero() || d.Modified.IsZero() {
		return true
	}
	slack := 2 * time.Second
	if d.Modified.Second() == 0 && d.Modified.Nanosecond() == 0 {
		slack = time.Minute
	}
	return !s.Modified.After(d.Modified.Add(slack))
}

func relTo(p, base string) string {
	if base == "/" {
		return strings.TrimPrefix(p, "/")
	}
	return strings.TrimPrefix(strings.TrimPrefix(p, base), "/")
}

// under says a folder that holds rel (not rel itself) is in set.
func under(rel string, set map[string]bool) bool {
	if len(set) == 0 {
		return false
	}
	for i := len(rel) - 1; i > 0; i-- {
		if rel[i] == '/' && set[rel[:i]] {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]Entry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func progressBytes(p *Progress) int64 {
	if p == nil {
		return 0
	}
	return p.Bytes
}
