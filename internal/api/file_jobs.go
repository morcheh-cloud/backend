package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/pkg/sftp"

	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/terminal"
)

// File operations on a server that can take minutes: each request is checked
// at once, then runs as a background job.

type compressParams struct {
	ServerID string   `json:"server_id"`
	Dir      string   `json:"dir"`
	Names    []string `json:"names"`
	Dest     string   `json:"dest"`
	Format   string   `json:"format"`
	Excludes []string `json:"excludes,omitempty"` // tar only
}

type extractParams struct {
	ServerID string `json:"server_id"`
	Path     string `json:"path"`
	Dest     string `json:"dest"`
}

type fetchParams struct {
	ServerID  string `json:"server_id"`
	URL       string `json:"url"`
	Dir       string `json:"dir"`
	Name      string `json:"name"`
	Overwrite bool   `json:"overwrite"`
	// MakeDir creates a missing folder first (cron jobs; the file manager
	// downloads into a folder that's open, so it exists).
	MakeDir bool `json:"make_dir,omitempty"`
}

// transferParams is a copy or move inside one server. The names are planned
// again when the job runs: things may have changed while it waited.
type transferParams struct {
	ServerID    string   `json:"server_id"`
	Paths       []string `json:"paths"`
	Destination string   `json:"destination"`
}

// TransferFilesBody is what to copy or move, and where to.
type TransferFilesBody struct {
	FilePathsBody
	Destination string `json:"destination" minLength:"1"`
}

// FetchBody asks a server to download a file from the web itself.
type FetchBody struct {
	URL       string `json:"url" minLength:"1" maxLength:"4096" example:"https://example.com/release.tar.gz"`
	Path      string `json:"path" doc:"Folder to save into" example:"/tmp"`
	Name      string `json:"name,omitempty" maxLength:"255" doc:"File name; default is the last part of the URL"`
	Overwrite bool   `json:"overwrite,omitempty" doc:"Replace a file with that name"`
}

func registerFileJobs(api huma.API, h *serverHandler, tags []string) {
	huma.Register(api, huma.Operation{
		OperationID: "compress-files",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/files/compress",
		Summary:     "Pack files into an archive",
		Description: "All paths must be in one folder. The archive goes next to them unless destination is given; an existing name gets a number. " +
			"Runs as a background job (kind `compress`, result FileEntry of the archive).",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body struct {
			FilePathsBody
			Format      string `json:"format" enum:"tar.gz,zip" default:"tar.gz"`
			Destination string `json:"destination,omitempty" doc:"Archive path; default is next to the files"`
		}
	}) (*JobOutput, error) {
		b := in.Body
		var p compressParams
		err := h.withSFTP(ctx, in.ID, func(_ *sshpool.Conn, s *sftp.Client) error {
			paths, err := resolvePaths(s, b.Paths)
			if err != nil {
				return err
			}
			dir := path.Dir(paths[0])
			names := make([]string, len(paths))
			for i, p := range paths {
				if path.Dir(p) != dir || p == "/" {
					return huma.Error422UnprocessableEntity("Pick files from one folder")
				}
				names[i] = path.Base(p)
			}
			dest := b.Destination
			if dest == "" {
				base := "archive"
				if len(paths) == 1 {
					base = names[0]
				}
				dest = freeName(s, path.Join(dir, base+"."+b.Format), "")
			} else if _, dest, err = resolvePath(s, dest); err != nil {
				return err
			} else if _, err := s.Lstat(dest); err == nil {
				return huma.Error409Conflict(path.Base(dest) + " already exists")
			}
			p = compressParams{ServerID: in.ID, Dir: dir, Names: names, Dest: dest, Format: b.Format}
			return nil
		})
		if err != nil {
			return nil, toProblem(err)
		}
		return h.submitFileJob(ctx, in.ID, "compress", "Compress "+what(p.Names)+" into "+path.Base(p.Dest), path.Dir(p.Dest), p)
	})
	h.jobs.Handle("compress", h.runCompress)

	huma.Register(api, huma.Operation{
		OperationID: "extract-archive",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/files/extract",
		Summary:     "Unpack an archive",
		Description: "Handles .tar, .tar.gz/.tgz, .tar.bz2, .tar.xz, .zip and .gz with the server's tar, unzip and gzip. Existing files are overwritten. " +
			"Runs as a background job (kind `extract`, result ExtractResult).",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body struct {
			Path        string `json:"path" minLength:"1"`
			Destination string `json:"destination,omitempty" doc:"Folder to unpack into; default is the archive's folder"`
		}
	}) (*JobOutput, error) {
		b := in.Body
		var p extractParams
		err := h.withSFTP(ctx, in.ID, func(_ *sshpool.Conn, s *sftp.Client) error {
			_, abs, err := resolvePath(s, b.Path)
			if err != nil {
				return err
			}
			if _, err := s.Stat(abs); err != nil {
				return fsError(abs, err)
			}
			dest := path.Dir(abs)
			if b.Destination != "" {
				if _, dest, err = resolvePath(s, b.Destination); err != nil {
					return err
				}
			}
			if _, _, err := extractCmd(abs, dest); err != nil {
				return err
			}
			p = extractParams{ServerID: in.ID, Path: abs, Dest: dest}
			return nil
		})
		if err != nil {
			return nil, toProblem(err)
		}
		return h.submitFileJob(ctx, in.ID, "extract", "Extract "+path.Base(p.Path)+" into "+p.Dest, p.Dest, p)
	})
	h.jobs.Handle("extract", h.runExtract)

	huma.Register(api, huma.Operation{
		OperationID: "fetch-url",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/files/fetch",
		Summary:     "Download a file from the web onto the server",
		Description: "The server downloads it itself with curl (or wget), so it never passes through Morcheh or the browser. " +
			"Only http and https. It's written to a hidden .part file and renamed when complete. " +
			"Runs as a background job (kind `fetch`, result FileEntry); 409 when the name is taken and overwrite isn't set.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body FetchBody
	}) (*JobOutput, error) {
		b := in.Body
		u, err := url.Parse(strings.TrimSpace(b.URL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fieldError("body.url", "Enter a full http:// or https:// address", b.URL)
		}
		name := strings.TrimSpace(b.Name)
		if name == "" {
			name = urlName(u)
		}
		if name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
			return nil, fieldError("body.name", "Not a valid file name", name)
		}
		var p fetchParams
		err = h.withSFTP(ctx, in.ID, func(_ *sshpool.Conn, s *sftp.Client) error {
			_, dir, err := resolvePath(s, b.Path)
			if err != nil {
				return err
			}
			if fi, err := s.Stat(dir); err != nil {
				return fsError(dir, err)
			} else if !fi.IsDir() {
				return huma.Error422UnprocessableEntity("Not a folder: " + dir)
			}
			if _, err := s.Lstat(path.Join(dir, name)); err == nil && !b.Overwrite {
				return huma.Error409Conflict(name + " already exists in " + dir)
			}
			p = fetchParams{ServerID: in.ID, URL: u.String(), Dir: dir, Name: name, Overwrite: b.Overwrite}
			return nil
		})
		if err != nil {
			return nil, toProblem(err)
		}
		return h.submitFileJob(ctx, in.ID, "fetch", "Download "+name+" from "+u.Host, p.Dir, p)
	})
	h.jobs.Handle("fetch", h.runFetch)

	huma.Register(api, huma.Operation{
		OperationID: "move-files",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/files/move",
		Summary:     "Move files into a folder",
		Description: "Nothing moves if any name already exists in the destination (409); 422 when they're already there. " +
			"Runs as a background job (kind `move`) that starts at once: a rename takes no time. Between filesystems it's `mv`, which can take long.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body TransferFilesBody
	}) (*JobOutput, error) {
		return h.submitTransfer(ctx, in.ID, "move", in.Body)
	})
	h.jobs.Handle("move", h.runMove)

	huma.Register(api, huma.Operation{
		OperationID: "copy-files",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/files/copy",
		Summary:     "Copy files into a folder",
		Description: "Copies with `cp -a` (keeps permissions and times). Copying into the same folder makes \"name copy\", \"name copy 2\"…; elsewhere an existing name is 409. " +
			"Runs as a background job (kind `copy`, result StorageTransferResult).",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body TransferFilesBody
	}) (*JobOutput, error) {
		return h.submitTransfer(ctx, in.ID, "copy", in.Body)
	})
	h.jobs.Handle("copy", h.runCopy)
}

func (h *serverHandler) submitFileJob(ctx context.Context, id, kind, title, dir string, params any) (*JobOutput, error) {
	s, err := h.get(ctx, id)
	if err != nil {
		return nil, err
	}
	return submit(ctx, h.jobs, jobs.Spec{
		Kind: kind, Title: title, Params: params, Refs: placeRefs(id),
		Target: &JobPlace{ServerID: id, Path: dir, Name: s.Name},
	})
}

// what names a selection for a title: the file, or "3 items".
func what(names []string) string {
	if len(names) == 1 {
		return names[0]
	}
	return strconv.Itoa(len(names)) + " items"
}

// urlName is the file name a URL points at: its last path segment.
func urlName(u *url.URL) string {
	name := path.Base(u.Path)
	if name == "/" || name == "." || name == "" {
		return "download"
	}
	return name
}

// jobError turns what a job's work returned into a message for the user,
// keeping the cause when it isn't one we know (toProblem would hide it).
func jobError(err error) error {
	if err == nil {
		return nil
	}
	p := toProblem(err)
	if se, ok := p.(huma.StatusError); ok && se.GetStatus() == http.StatusInternalServerError {
		return err
	}
	return p
}

// ---- Compress ----

func (h *serverHandler) runCompress(ctx context.Context, t *jobs.Task) (any, error) {
	var p compressParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	out, err := h.compress(ctx, t, p)
	return out, jobError(err)
}

// compress packs p.Names in p.Dir into p.Dest on the server, in the job t.
func (h *serverHandler) compress(ctx context.Context, t *jobs.Task, p compressParams) (FileEntry, error) {
	var out FileEntry
	err := h.withSFTP(ctx, p.ServerID, func(c *sshpool.Conn, s *sftp.Client) error {
		if _, err := s.Lstat(p.Dest); err == nil {
			return huma.Error409Conflict(path.Base(p.Dest) + " already exists")
		}
		rel := make([]string, len(p.Names))
		for i, n := range p.Names {
			rel[i] = "./" + n
		}
		cd := "cd -- " + terminal.ShellQuote(p.Dir) + " && "
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Counting files" })
		if n, err := run(ctx, c, cd+"find "+quoteAll(rel)+" 2>/dev/null | wc -l"); err == nil {
			total, _ := strconv.Atoi(strings.TrimSpace(n))
			t.Update(func(pr *jobs.Progress) { pr.ItemsTotal = total })
		}
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Packing" })
		qd := terminal.ShellQuote(p.Dest)
		cmd := "tar -czvf " + qd
		for _, x := range p.Excludes {
			cmd += " --exclude=" + terminal.ShellQuote(x)
		}
		cmd += " -- " + quoteAll(p.Names)
		if p.Format == "zip" {
			cmd = "zip -ry -- " + qd + " " + quoteAll(p.Names)
		}
		stop := every(ctx, func() {
			if fi, err := s.Stat(p.Dest); err == nil {
				t.Update(func(pr *jobs.Progress) { pr.Done = fi.Size() })
			}
		})
		err := runStream(ctx, c, cd+cmd, func(line string) {
			name := strings.TrimSpace(line)
			if p.Format == "zip" {
				name, _, _ = strings.Cut(strings.TrimPrefix(name, "adding: "), " (")
			}
			t.Update(func(pr *jobs.Progress) { pr.Items++; pr.Current = name })
		}, nil)
		stop()
		if err != nil {
			_ = s.Remove(p.Dest) // a partial archive is worse than none
			return err
		}
		out, err = stat(c, s, p.Dest)
		if err == nil {
			t.Logf("Wrote %s (%s)", p.Dest, humanBytes(out.Size))
		}
		return err
	})
	return out, err
}

// ---- Extract ----

// extractCmd is the command that unpacks archive p into dest, and whether it
// lists each file it writes.
func extractCmd(p, dest string) (cmd string, zip bool, err error) {
	qp, qd := terminal.ShellQuote(p), terminal.ShellQuote(dest)
	switch name := strings.ToLower(path.Base(p)); {
	case strings.HasSuffix(name, ".tar.gz"), strings.HasSuffix(name, ".tgz"):
		return "tar -xzvf " + qp + " -C " + qd, false, nil
	case strings.HasSuffix(name, ".tar.bz2"), strings.HasSuffix(name, ".tbz2"):
		return "tar -xjvf " + qp + " -C " + qd, false, nil
	case strings.HasSuffix(name, ".tar.xz"), strings.HasSuffix(name, ".txz"):
		return "tar -xJvf " + qp + " -C " + qd, false, nil
	case strings.HasSuffix(name, ".tar"):
		return "tar -xvf " + qp + " -C " + qd, false, nil
	case strings.HasSuffix(name, ".zip"):
		return "unzip -o " + qp + " -d " + qd, true, nil
	case strings.HasSuffix(name, ".gz"):
		target := path.Join(dest, strings.TrimSuffix(path.Base(p), path.Ext(p)))
		return "gzip -dc -- " + qp + " > " + terminal.ShellQuote(target), false, nil
	}
	return "", false, huma.Error422UnprocessableEntity("Not an archive Morcheh can unpack (tar, tar.gz, tar.bz2, tar.xz, zip, gz)")
}

func (h *serverHandler) runExtract(ctx context.Context, t *jobs.Task) (any, error) {
	var p extractParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	cmd, zip, err := extractCmd(p.Path, p.Dest)
	if err != nil {
		return nil, err
	}
	err = h.withConn(ctx, p.ServerID, func(c *sshpool.Conn) error {
		if zip {
			// The zip's directory is at its end: listing it is cheap.
			if n, err := run(ctx, c, "unzip -Z1 -- "+terminal.ShellQuote(p.Path)+" 2>/dev/null | wc -l"); err == nil {
				total, _ := strconv.Atoi(strings.TrimSpace(n))
				t.Update(func(pr *jobs.Progress) { pr.ItemsTotal = total })
			}
		}
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Unpacking" })
		return runStream(ctx, c, "mkdir -p -- "+terminal.ShellQuote(p.Dest)+" && "+cmd, func(line string) {
			name := strings.TrimSpace(line)
			if zip {
				// "  inflating: dest/file", "   creating: dest/dir/"; skip "Archive: x".
				label, rest, ok := strings.Cut(name, ": ")
				if !ok || label == "Archive" {
					return
				}
				name = strings.TrimPrefix(strings.TrimSpace(rest), strings.TrimSuffix(p.Dest, "/")+"/")
			}
			t.Update(func(pr *jobs.Progress) { pr.Items++; pr.Current = name })
		}, nil)
	})
	if err != nil {
		if ctx.Err() != nil {
			t.Logf("Stopped part way: some files may already be in %s", p.Dest)
		}
		return nil, jobError(err)
	}
	t.Logf("Unpacked %s into %s", path.Base(p.Path), p.Dest)
	return ExtractResult{Destination: p.Dest}, nil
}

// ---- Copy & move ----

// submitTransfer checks a copy or move at once and queues it.
func (h *serverHandler) submitTransfer(ctx context.Context, id, kind string, b TransferFilesBody) (*JobOutput, error) {
	copying := kind == "copy"
	var dest string
	var names []string
	err := h.withSFTP(ctx, id, func(_ *sshpool.Conn, s *sftp.Client) error {
		pairs, err := planTransfer(s, b.Paths, b.Destination, copying)
		if err != nil {
			return err
		}
		if len(pairs) == 0 {
			return huma.Error422UnprocessableEntity("Already in that folder")
		}
		dest = path.Dir(pairs[0][1])
		names = names[:0]
		for _, pr := range pairs {
			names = append(names, path.Base(pr[0]))
		}
		return nil
	})
	if err != nil {
		return nil, toProblem(err)
	}
	s, err := h.get(ctx, id)
	if err != nil {
		return nil, err
	}
	verb := "Move "
	if copying {
		verb = "Copy "
	}
	return submit(ctx, h.jobs, jobs.Spec{
		Kind: kind, Title: verb + what(names) + " to " + dest, Refs: placeRefs(id),
		Params: transferParams{ServerID: id, Paths: b.Paths, Destination: dest},
		Target: &JobPlace{ServerID: id, Path: dest, Name: s.Name},
		Quick:  !copying,
	})
}

// errLostPartWay stops withSFTP's retry once work has begun: run again, the
// job would find its own half-done files and call them a clash.
var errLostPartWay = errors.New("The connection to the server was lost part way through")

func (h *serverHandler) runMove(ctx context.Context, t *jobs.Task) (any, error) {
	var p transferParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	var started bool
	err := h.withSFTP(ctx, p.ServerID, func(c *sshpool.Conn, s *sftp.Client) error {
		if started {
			return errLostPartWay
		}
		pairs, err := planTransfer(s, p.Paths, p.Destination, false)
		if err != nil {
			return err
		}
		t.Update(func(pr *jobs.Progress) { pr.Phase, pr.ItemsTotal = "Moving", len(pairs) })
		started = true
		for _, pair := range pairs {
			if err := ctx.Err(); err != nil {
				return err
			}
			t.Update(func(pr *jobs.Progress) { pr.Current = path.Base(pair[0]) })
			if err := move(ctx, c, s, pair[0], pair[1]); err != nil {
				// mv between filesystems copies, then deletes: stopped half way
				// its target may be all that's left of a file, so it stays.
				var failed *cmdError
				if ctx.Err() != nil || errors.As(err, &failed) {
					t.Logf("Stopped moving %s: some of it may be in both places", pair[0])
				}
				return err
			}
			t.Logf("%s → %s", pair[0], pair[1])
			t.Update(func(pr *jobs.Progress) { pr.Items++ })
		}
		return nil
	})
	return nil, jobError(err)
}

func (h *serverHandler) runCopy(ctx context.Context, t *jobs.Task) (any, error) {
	var p transferParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	var out StorageTransferResult
	var started bool
	err := h.withSFTP(ctx, p.ServerID, func(c *sshpool.Conn, s *sftp.Client) error {
		if started {
			return errLostPartWay
		}
		pairs, err := planTransfer(s, p.Paths, p.Destination, true)
		if err != nil {
			return err
		}
		sources := make([]string, len(pairs))
		for i, pair := range pairs {
			sources[i] = pair[0]
		}
		t.Update(func(pr *jobs.Progress) { pr.Phase, pr.ItemsTotal = "Measuring", len(pairs) })
		files, bytes := measure(ctx, c, sources)
		t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Total = "Copying", bytes })
		if bytes > 0 {
			t.Logf("Copying %d files (%s) to %s", files, humanBytes(bytes), p.Destination)
		}
		started = true

		var mu sync.Mutex
		var targets []string
		stop := everyAdaptive(ctx, func() {
			mu.Lock()
			list := slices.Clone(targets)
			mu.Unlock()
			if len(list) == 0 {
				return
			}
			if _, done := measure(ctx, c, list); done > 0 {
				t.Update(func(pr *jobs.Progress) {
					if pr.Total > 0 {
						done = min(done, pr.Total)
					}
					pr.Done = max(pr.Done, done)
				})
			}
		})
		defer stop()
		for _, pair := range pairs {
			from, to := pair[0], pair[1]
			// cp would put it inside an existing folder, and the clean-up below
			// must only ever remove what this copy made.
			if _, err := s.Lstat(to); err == nil {
				return huma.Error409Conflict(path.Base(to) + " already exists")
			} else if !errors.Is(err, os.ErrNotExist) {
				return fsError(to, err)
			}
			t.Update(func(pr *jobs.Progress) { pr.Current = path.Base(from) })
			mu.Lock()
			targets = append(targets, to)
			mu.Unlock()
			err := runStream(ctx, c, "cp -a -- "+terminal.ShellQuote(from)+" "+terminal.ShellQuote(to), nil, nil)
			if err != nil {
				stop()
				removeUnfinished(ctx, t, c, to)
				return err
			}
			t.Logf("%s → %s", from, to)
			t.Update(func(pr *jobs.Progress) { pr.Items++ })
		}
		out = StorageTransferResult{Files: files, Bytes: bytes}
		return nil
	})
	if err != nil {
		return nil, jobError(err)
	}
	return out, nil
}

// removeUnfinished cleans up after a copy that stopped, even when it was
// canceled. It must only be given a path the copy itself created.
func removeUnfinished(ctx context.Context, t *jobs.Task, c *sshpool.Conn, target string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	if _, err := run(ctx, c, "rm -rf -- "+terminal.ShellQuote(target)); err != nil {
		t.Logf("Couldn't remove the unfinished %s: %v", target, err)
		return
	}
	t.Logf("Removed the unfinished %s", target)
}

// measure counts the files under paths and their bytes for a progress bar;
// zeros when it can't within the time (a slow disk shouldn't hold up the copy).
func measure(ctx context.Context, c *sshpool.Conn, paths []string) (files int, bytes int64) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	q := quoteAll(paths)
	out, err := run(ctx, c, "du -sk -- "+q+" 2>/dev/null; echo @files; find "+q+" ! -type d 2>/dev/null | wc -l")
	if err != nil {
		return 0, 0
	}
	sizes, count, _ := strings.Cut(out, "@files")
	for line := range strings.SplitSeq(sizes, "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			if kb, err := strconv.ParseInt(f[0], 10, 64); err == nil {
				bytes += kb * 1024
			}
		}
	}
	files, _ = strconv.Atoi(strings.TrimSpace(count))
	return files, bytes
}

// everyAdaptive is every for work that loads the server: it runs fn no more
// than a tenth of the time, and at most every 3 seconds.
func everyAdaptive(ctx context.Context, fn func()) (stop func()) {
	var next time.Time
	return every(ctx, func() {
		if time.Now().Before(next) {
			return
		}
		start := time.Now()
		fn()
		next = time.Now().Add(max(3*time.Second, 10*time.Since(start)))
	})
}

// ---- Fetch ----

func (h *serverHandler) runFetch(ctx context.Context, t *jobs.Task) (any, error) {
	var p fetchParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	out, err := h.fetch(ctx, t, p)
	if err != nil {
		return nil, jobError(err)
	}
	return out, nil
}

// fetch has the server download p.URL into p.Dir/p.Name, in the job t.
func (h *serverHandler) fetch(ctx context.Context, t *jobs.Task, p fetchParams) (FileEntry, error) {
	part := "." + p.Name + ".part"
	partPath := path.Join(p.Dir, part)
	qu, qpart, qname := terminal.ShellQuote(p.URL), terminal.ShellQuote(part), terminal.ShellQuote(p.Name)
	keep := "[ ! -e " + qname + " ] || { rm -f -- " + qpart + "; echo " + terminal.ShellQuote(p.Name+" already exists") + " >&2; exit 1; }; "
	if p.Overwrite {
		keep = ""
	}
	cd := "cd -- " + terminal.ShellQuote(p.Dir) + " || exit 1; "
	if p.MakeDir {
		cd = "mkdir -p -- " + terminal.ShellQuote(p.Dir) + " && " + cd
	}
	script := cd +
		"if command -v curl >/dev/null 2>&1; then " +
		"curl -fL -sS --proto =http,https --proto-redir =http,https -D /dev/stderr -o " + qpart + " " + qu + "; " +
		"elif command -v wget >/dev/null 2>&1; then wget -nv -S -O " + qpart + " " + qu + "; " +
		"else echo 'curl: not found' >&2; exit 127; fi " +
		"|| { rc=$?; rm -f -- " + qpart + "; exit $rc; }; " +
		keep + "mv -f -- " + qpart + " " + qname

	var out FileEntry
	err := h.withSFTP(ctx, p.ServerID, func(c *sshpool.Conn, s *sftp.Client) error {
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Connecting"; pr.Current = p.Name })
		t.Logf("GET %s", p.URL)
		stop := every(ctx, func() {
			if fi, err := s.Stat(partPath); err == nil {
				t.Update(func(pr *jobs.Progress) { pr.Done = fi.Size(); pr.Phase = "Downloading" })
			}
		})
		var headers bool
		err := runStream(ctx, c, script, nil, func(line string) bool {
			// curl -D and wget -S print each response's headers: note the
			// status and size, keep the rest out of the error message.
			l := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(l, "HTTP/"):
				// curl's block ends with a blank line; wget indents its lines.
				headers = !strings.HasPrefix(line, " ")
				t.Logf("%s", l)
				return false
			case headers && l == "":
				headers = false
				return false
			case headers || strings.HasPrefix(line, "  "):
				if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(k, "content-length") {
					if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
						t.Update(func(pr *jobs.Progress) { pr.Total = n })
					}
				}
				return false
			}
			t.Logf("%s", l)
			return true
		})
		stop()
		if err != nil {
			if ctx.Err() != nil {
				rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				_, _ = run(rctx, c, "rm -f -- "+terminal.ShellQuote(partPath))
				cancel()
			}
			return err
		}
		out, err = stat(c, s, path.Join(p.Dir, p.Name))
		if err == nil {
			t.Logf("Saved %s (%s)", out.Path, humanBytes(out.Size))
		}
		return err
	})
	return out, err
}
