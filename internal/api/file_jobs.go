package api

import (
	"context"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
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
		cmd := "tar -czvf " + qd + " -- " + quoteAll(p.Names)
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
	return out, jobError(err)
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

// ---- Fetch ----

func (h *serverHandler) runFetch(ctx context.Context, t *jobs.Task) (any, error) {
	var p fetchParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	part := "." + p.Name + ".part"
	partPath := path.Join(p.Dir, part)
	qu, qpart, qname := terminal.ShellQuote(p.URL), terminal.ShellQuote(part), terminal.ShellQuote(p.Name)
	keep := "[ ! -e " + qname + " ] || { rm -f -- " + qpart + "; echo " + terminal.ShellQuote(p.Name+" already exists") + " >&2; exit 1; }; "
	if p.Overwrite {
		keep = ""
	}
	script := "cd -- " + terminal.ShellQuote(p.Dir) + " || exit 1; " +
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
	if err != nil {
		return nil, jobError(err)
	}
	return out, nil
}
