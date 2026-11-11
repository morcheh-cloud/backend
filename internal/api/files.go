package api

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/sshprobe"
	"github.com/morcheh/backend/internal/terminal"
)

// ---- Types ----

type FileEntry struct {
	Name       string    `json:"name" example:"nginx.conf"`
	Path       string    `json:"path" example:"/etc/nginx/nginx.conf"`
	Type       string    `json:"type" enum:"file,dir,symlink,other"`
	Size       int64     `json:"size" doc:"Bytes"`
	Mode       string    `json:"mode" doc:"As ls shows it" example:"-rw-r--r--"`
	Perm       string    `json:"perm" doc:"Octal, with setuid/setgid/sticky" example:"0644"`
	Modified   time.Time `json:"modified"`
	Owner      string    `json:"owner" doc:"User name, or the uid if the server doesn't list it" example:"root"`
	Group      string    `json:"group" example:"root"`
	UID        uint32    `json:"uid"`
	GID        uint32    `json:"gid"`
	LinkTarget string    `json:"link_target" doc:"Where a symlink points; empty otherwise"`
	TargetType string    `json:"target_type" enum:"none,file,dir,other,missing" doc:"What a symlink resolves to; none for other entries"`
}

type DirListing struct {
	Path    string      `json:"path" example:"/etc/nginx"`
	Parent  string      `json:"parent" doc:"Empty at /" example:"/etc"`
	Home    string      `json:"home" doc:"The login user's home directory" example:"/root"`
	Entries []FileEntry `json:"entries"`
}

type FileContent struct {
	Path     string    `json:"path"`
	Content  string    `json:"content"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified" doc:"Send it back as expected_modified when saving, to detect edits made meanwhile"`
}

type FolderSize struct {
	Path string `json:"path"`
	Size int64  `json:"size" doc:"Bytes on disk"`
}

type ExtractResult struct {
	Destination string `json:"destination"`
}

type SearchResult struct {
	Items     []FileEntry `json:"items"`
	Truncated bool        `json:"truncated" doc:"More matched than were returned"`
}

type FilePathQuery struct {
	ServerIDPath
	Path string `query:"path" doc:"Absolute path; empty, ~ or a relative path are taken from the home directory"`
}

type FilePathsBody struct {
	Paths []string `json:"paths" minItems:"1" maxItems:"1000"`
}

type FileEntryOutput struct{ Body FileEntry }

const (
	// Bigger files are downloaded, not opened in the editor.
	maxEditable = 5 << 20
	maxSearch   = 200
	execTimeout = 2 * time.Minute
)

// ---- Handlers ----

func registerFiles(api huma.API, h *serverHandler) {
	tags := []string{"Files"}

	huma.Register(api, huma.Operation{
		OperationID: "list-files",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/files",
		Summary:     "List a folder",
		Description: "Over SFTP, as the server's login user. Symlinks report what they point to.",
		Tags:        tags,
	}, func(ctx context.Context, in *FilePathQuery) (*struct{ Body DirListing }, error) {
		out := &struct{ Body DirListing }{}
		err := h.withSFTP(ctx, in.ID, func(c *sshpool.Conn, s *sftp.Client) error {
			home, p, err := resolvePath(s, in.Path)
			if err != nil {
				return err
			}
			fi, err := s.Stat(p)
			if err != nil {
				return fsError(p, err)
			}
			if !fi.IsDir() {
				return huma.Error422UnprocessableEntity("Not a folder: " + p)
			}
			infos, err := s.ReadDir(p)
			if err != nil {
				return fsError(p, err)
			}
			out.Body = DirListing{Path: p, Home: home, Entries: entries(c, s, p, infos)}
			if p != "/" {
				out.Body.Parent = path.Dir(p)
			}
			return nil
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "stat-file",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/files/stat",
		Summary:     "Details of one file or folder",
		Tags:        tags,
	}, func(ctx context.Context, in *FilePathQuery) (*FileEntryOutput, error) {
		out := &FileEntryOutput{}
		err := h.withSFTP(ctx, in.ID, func(c *sshpool.Conn, s *sftp.Client) error {
			_, p, err := resolvePath(s, in.Path)
			if err != nil {
				return err
			}
			out.Body, err = stat(c, s, p)
			return err
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "folder-size",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/files/size",
		Summary:     "Total size of a folder",
		Description: "Runs `du` on the server; unreadable subfolders are left out of the total.",
		Tags:        tags,
	}, func(ctx context.Context, in *FilePathQuery) (*struct{ Body FolderSize }, error) {
		out := &struct{ Body FolderSize }{}
		err := h.withSFTP(ctx, in.ID, func(c *sshpool.Conn, s *sftp.Client) error {
			_, p, err := resolvePath(s, in.Path)
			if err != nil {
				return err
			}
			stdout, err := run(ctx, c, "du -sk -- "+terminal.ShellQuote(p))
			// du exits 1 when some subfolder is unreadable but still totals the rest.
			fields := strings.Fields(stdout)
			if len(fields) == 0 {
				if err == nil {
					err = errors.New("du printed nothing")
				}
				return err
			}
			kb, perr := strconv.ParseInt(fields[0], 10, 64)
			if perr != nil {
				return fmt.Errorf("du: %w", perr)
			}
			out.Body.Path, out.Body.Size = p, kb*1024
			return nil
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "download-files",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/files/download",
		Summary:     "Download files",
		Description: "One file streams as itself (with Range support). Several paths, or a folder, stream as one zip. " +
			"`inline` shows images, media, PDFs and plain text in the browser instead of saving them.",
		Tags: tags,
		Responses: map[string]*huma.Response{
			"200": {
				Description: "The file, or a zip of everything asked for",
				Content:     map[string]*huma.MediaType{"application/octet-stream": {Schema: &huma.Schema{Type: "string", Format: "binary"}}},
			},
		},
	}, h.download)

	huma.Register(api, huma.Operation{
		OperationID: "read-file",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/files/content",
		Summary:     "Read a text file",
		Description: "For the editor: UTF-8 text up to 5 MB. Bigger files are 413, binary ones 415.",
		Tags:        tags,
	}, func(ctx context.Context, in *FilePathQuery) (*struct{ Body FileContent }, error) {
		out := &struct{ Body FileContent }{}
		err := h.withSFTP(ctx, in.ID, func(_ *sshpool.Conn, s *sftp.Client) error {
			_, p, err := resolvePath(s, in.Path)
			if err != nil {
				return err
			}
			f, err := s.Open(p)
			if err != nil {
				return fsError(p, err)
			}
			defer f.Close()
			fi, err := f.Stat()
			if err != nil {
				return fsError(p, err)
			}
			if fi.IsDir() {
				return huma.Error422UnprocessableEntity("That's a folder: " + p)
			}
			if fi.Size() > maxEditable {
				return huma.NewError(http.StatusRequestEntityTooLarge, "Files over 5 MB can't be opened in the editor. Download it instead.")
			}
			var buf bytes.Buffer
			if _, err := f.WriteTo(&buf); err != nil {
				return fsError(p, err)
			}
			data := buf.Bytes()
			if !isText(data) {
				return huma.NewError(http.StatusUnsupportedMediaType, "This looks like a binary file. Download it instead.")
			}
			out.Body = FileContent{Path: p, Content: string(data), Size: int64(len(data)), Modified: fi.ModTime()}
			return nil
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID:  "write-file",
		Method:       http.MethodPut,
		Path:         "/servers/{id}/files/content",
		Summary:      "Save a text file",
		Description:  "Overwrites the file in place, keeping its owner and permissions. With expected_modified, refuses (409) if the file changed since it was read. With create, makes a new file and refuses if one exists.",
		Tags:         tags,
		MaxBodyBytes: maxEditable + 1<<20,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body struct {
			Path             string     `json:"path" minLength:"1"`
			Content          string     `json:"content"`
			ExpectedModified *time.Time `json:"expected_modified,omitempty"`
			Create           bool       `json:"create,omitempty"`
		}
	}) (*FileEntryOutput, error) {
		out := &FileEntryOutput{}
		b := in.Body
		err := h.withSFTP(ctx, in.ID, func(c *sshpool.Conn, s *sftp.Client) error {
			_, p, err := resolvePath(s, b.Path)
			if err != nil {
				return err
			}
			flags := os.O_WRONLY | os.O_TRUNC
			if b.Create {
				flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
				if _, err := s.Lstat(p); err == nil {
					return huma.Error409Conflict(path.Base(p) + " already exists")
				}
			} else {
				fi, err := s.Stat(p)
				if err != nil {
					return fsError(p, err)
				}
				if fi.IsDir() {
					return huma.Error422UnprocessableEntity("That's a folder: " + p)
				}
				if b.ExpectedModified != nil && fi.ModTime().Unix() != b.ExpectedModified.Unix() {
					return huma.Error409Conflict("The file changed on the server since you opened it.")
				}
			}
			f, err := s.OpenFile(p, flags)
			if err != nil {
				return fsError(p, err)
			}
			if _, err := f.ReadFrom(strings.NewReader(b.Content)); err != nil {
				f.Close()
				return fsError(p, err)
			}
			if err := f.Close(); err != nil {
				return fsError(p, err)
			}
			out.Body, err = stat(c, s, p)
			return err
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "upload-file",
		Method:      http.MethodPut,
		Path:        "/servers/{id}/files/upload",
		Summary:     "Upload a file",
		Description: "The raw body is the file. It is written next to the destination first and renamed into place once complete, so a broken upload never leaves half a file. " +
			"Missing parent folders are created (for folder uploads). An existing file is 409 unless overwrite is set.",
		Tags: tags,
		RequestBody: &huma.RequestBody{
			Required: true,
			Content:  map[string]*huma.MediaType{"application/octet-stream": {Schema: &huma.Schema{Type: "string", Format: "binary"}}},
		},
	}, h.upload)

	huma.Register(api, huma.Operation{
		OperationID: "make-folder",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/files/mkdir",
		Summary:     "Create a folder",
		Description: "Creates missing parents too.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body struct {
			Path string `json:"path" minLength:"1"`
		}
	}) (*FileEntryOutput, error) {
		out := &FileEntryOutput{}
		err := h.withSFTP(ctx, in.ID, func(c *sshpool.Conn, s *sftp.Client) error {
			_, p, err := resolvePath(s, in.Body.Path)
			if err != nil {
				return err
			}
			if _, err := s.Lstat(p); err == nil {
				return huma.Error409Conflict(path.Base(p) + " already exists")
			}
			if err := s.MkdirAll(p); err != nil {
				return fsError(p, err)
			}
			out.Body, err = stat(c, s, p)
			return err
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "rename-file",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/files/rename",
		Summary:     "Rename or move one file or folder",
		Description: "Refuses to replace an existing entry.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body struct {
			From string `json:"from" minLength:"1"`
			To   string `json:"to" minLength:"1"`
		}
	}) (*FileEntryOutput, error) {
		out := &FileEntryOutput{}
		err := h.withSFTP(ctx, in.ID, func(c *sshpool.Conn, s *sftp.Client) error {
			_, from, err := resolvePath(s, in.Body.From)
			if err != nil {
				return err
			}
			_, to, err := resolvePath(s, in.Body.To)
			if err != nil {
				return err
			}
			if from == to {
				out.Body, err = stat(c, s, to)
				return err
			}
			if err := move(ctx, c, s, from, to); err != nil {
				return err
			}
			out.Body, err = stat(c, s, to)
			return err
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-files",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/files/delete",
		Summary:     "Delete files and folders",
		Description: "Folders are deleted with everything in them. `/` is refused.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body FilePathsBody
	}) (*AffectedOutput, error) {
		var n int64
		err := h.withSFTP(ctx, in.ID, func(c *sshpool.Conn, s *sftp.Client) error {
			paths, err := resolvePaths(s, in.Body.Paths)
			if err != nil {
				return err
			}
			for _, p := range paths {
				if p == "/" {
					return huma.Error422UnprocessableEntity("Refusing to delete /")
				}
			}
			// One rm is far faster than SFTP's file-by-file removal; fall back
			// to it when the account can't run commands.
			_, err = run(ctx, c, "rm -rf -- "+quoteAll(paths))
			var ce *cmdError
			if err != nil && !errors.As(err, &ce) {
				for _, p := range paths {
					if err := s.RemoveAll(p); err != nil {
						return fsError(p, err)
					}
				}
				err = nil
			}
			if err != nil {
				return err
			}
			n = int64(len(paths))
			return nil
		})
		return affected(n), toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "chmod-files",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/files/chmod",
		Summary:     "Change permissions",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body struct {
			FilePathsBody
			Mode      string `json:"mode" pattern:"^[0-7]{3,4}$" example:"0644"`
			Recursive bool   `json:"recursive,omitempty" doc:"Apply to everything inside folders too"`
		}
	}) (*AffectedOutput, error) {
		var n int64
		b := in.Body
		err := h.withSFTP(ctx, in.ID, func(c *sshpool.Conn, s *sftp.Client) error {
			paths, err := resolvePaths(s, b.Paths)
			if err != nil {
				return err
			}
			if b.Recursive {
				if _, err := run(ctx, c, "chmod -R "+b.Mode+" -- "+quoteAll(paths)); err != nil {
					return err
				}
			} else {
				bits, _ := strconv.ParseUint(b.Mode, 8, 32)
				for _, p := range paths {
					if err := s.Chmod(p, fromUnixMode(uint32(bits))); err != nil {
						return fsError(p, err)
					}
				}
			}
			n = int64(len(paths))
			return nil
		})
		return affected(n), toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "chown-files",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/files/chown",
		Summary:     "Change owner and group",
		Description: "Runs `chown`, so it usually needs a root login.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body struct {
			FilePathsBody
			Owner     string `json:"owner,omitempty" doc:"User name or uid; empty keeps it"`
			Group     string `json:"group,omitempty" doc:"Group name or gid; empty keeps it"`
			Recursive bool   `json:"recursive,omitempty"`
		}
	}) (*AffectedOutput, error) {
		var n int64
		b := in.Body
		if b.Owner == "" && b.Group == "" {
			return nil, fieldError("body.owner", "Choose an owner or a group", b.Owner)
		}
		for loc, v := range map[string]string{"body.owner": b.Owner, "body.group": b.Group} {
			if v != "" && !accountRe.MatchString(v) {
				return nil, fieldError(loc, "Not a valid user or group name", v)
			}
		}
		err := h.withSFTP(ctx, in.ID, func(c *sshpool.Conn, s *sftp.Client) error {
			paths, err := resolvePaths(s, b.Paths)
			if err != nil {
				return err
			}
			spec := b.Owner
			if b.Group != "" {
				spec += ":" + b.Group
			}
			flags := ""
			if b.Recursive {
				flags = "-R "
			}
			if _, err := run(ctx, c, "chown "+flags+"-- "+terminal.ShellQuote(spec)+" "+quoteAll(paths)); err != nil {
				return err
			}
			n = int64(len(paths))
			return nil
		})
		return affected(n), toProblem(err)
	})

	registerFileJobs(api, h, tags)

	huma.Register(api, huma.Operation{
		OperationID: "search-files",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/files/search",
		Summary:     "Find files by name",
		Description: "Case-insensitive name match anywhere under path (skipping /proc, /sys, /dev and /run), up to 200 results.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		FilePathQuery
		Query string `query:"q" minLength:"1" maxLength:"200" doc:"Part of the name; * and ? work as wildcards"`
	}) (*struct{ Body SearchResult }, error) {
		out := &struct{ Body SearchResult }{}
		err := h.withSFTP(ctx, in.ID, func(c *sshpool.Conn, s *sftp.Client) error {
			_, p, err := resolvePath(s, in.Path)
			if err != nil {
				return err
			}
			pattern := in.Query
			if !strings.ContainsAny(pattern, "*?") {
				pattern = "*" + escapeGlob(pattern) + "*"
			}
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			cmd := "find " + terminal.ShellQuote(p) + ` \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -iname ` +
				terminal.ShellQuote(pattern) + " -print 2>/dev/null | head -n " + strconv.Itoa(maxSearch+1)
			stdout, err := run(ctx, c, cmd)
			if err != nil && ctx.Err() == nil {
				return err
			}
			var found []string
			for line := range strings.SplitSeq(stdout, "\n") {
				if line != "" && line != p {
					found = append(found, line)
				}
			}
			if len(found) > maxSearch {
				found, out.Body.Truncated = found[:maxSearch], true
			}
			if ctx.Err() != nil {
				out.Body.Truncated = true
			}
			out.Body.Items = statMany(c, s, found)
			return nil
		})
		return out, toProblem(err)
	})
}

// ---- Download & upload ----

type DownloadInput struct {
	ServerIDPath
	Paths  []string `query:"path,explode" required:"true" minItems:"1" doc:"Repeat for several files"`
	Inline bool     `query:"inline" doc:"Show in the browser instead of saving (images, media, PDF, plain text only)"`
	Name   string   `query:"name" doc:"File name for a zip of several paths"`
}

func (h *serverHandler) download(ctx context.Context, in *DownloadInput) (*huma.StreamResponse, error) {
	var (
		sc    *sftp.Client
		paths []string
		file  *sftp.File
		info  os.FileInfo
	)
	err := h.withSFTP(ctx, in.ID, func(_ *sshpool.Conn, s *sftp.Client) error {
		var err error
		if paths, err = resolvePaths(s, in.Paths); err != nil {
			return err
		}
		sc = s
		if len(paths) > 1 {
			return nil
		}
		fi, err := s.Stat(paths[0])
		if err != nil {
			return fsError(paths[0], err)
		}
		if fi.IsDir() {
			return nil
		}
		if file, err = s.Open(paths[0]); err != nil {
			return fsError(paths[0], err)
		}
		info = fi
		return nil
	})
	if err != nil {
		return nil, toProblem(err)
	}

	return &huma.StreamResponse{Body: func(hctx huma.Context) {
		r, w := humachi.Unwrap(hctx)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if file != nil {
			defer file.Close()
			serveFile(w, r, file, info, in.Inline)
			return
		}
		name := in.Name
		if name == "" {
			if len(paths) == 1 {
				name = path.Base(paths[0])
			} else {
				name = path.Base(path.Dir(paths[0]))
			}
			if name == "/" || name == "." {
				name = "files"
			}
		}
		if !strings.HasSuffix(strings.ToLower(name), ".zip") {
			name += ".zip"
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", disposition("attachment", name))
		writeZip(w, sc, paths)
	}}, nil
}

// Types the browser may show inline. Anything else (HTML, SVG with
// scripts…) is always a download; the sandbox CSP is a second fence.
var inlineTypes = []string{"image/", "video/", "audio/", "application/pdf", "text/plain"}

func serveFile(w http.ResponseWriter, r *http.Request, f *sftp.File, fi os.FileInfo, inline bool) {
	ctype := mime.TypeByExtension(path.Ext(fi.Name()))
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	kind := "attachment"
	if inline && slices.ContainsFunc(inlineTypes, func(t string) bool { return strings.HasPrefix(ctype, t) }) {
		kind = "inline"
		w.Header().Set("Content-Security-Policy", "sandbox")
		if strings.HasPrefix(ctype, "image/svg") {
			ctype = "image/svg+xml"
		}
	} else if inline {
		ctype = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", disposition(kind, fi.Name()))

	// Ranges (resume, media seeking) go through ServeContent; a plain GET
	// streams with SFTP's concurrent reads, which is much faster.
	if r.Header.Get("Range") != "" {
		http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
		return
	}
	w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	w.Header().Set("Last-Modified", fi.ModTime().UTC().Format(http.TimeFormat))
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = f.WriteTo(w)
	}
}

func disposition(kind, name string) string {
	if d := mime.FormatMediaType(kind, map[string]string{"filename": name}); d != "" {
		return d
	}
	return kind
}

// Already compressed: deflating them again only costs time.
var storedExts = []string{".zip", ".gz", ".tgz", ".bz2", ".xz", ".zst", ".7z", ".rar", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp4", ".mkv", ".mp3", ".deb", ".rpm", ".jar"}

// writeZip streams the paths (folders recursively) as a zip. Names are
// relative to each path's parent; entries that can't be read are skipped,
// since the response has already started.
func writeZip(w io.Writer, s *sftp.Client, paths []string) {
	zw := zip.NewWriter(w)
	defer zw.Close()
	for _, root := range paths {
		parent := path.Dir(root)
		walker := s.Walk(root)
		for walker.Step() {
			if walker.Err() != nil {
				continue
			}
			fi := walker.Stat()
			name := strings.TrimPrefix(strings.TrimPrefix(walker.Path(), parent), "/")
			hdr, err := zip.FileInfoHeader(fi)
			if err != nil {
				continue
			}
			hdr.Name = name
			switch {
			case fi.IsDir():
				hdr.Name += "/"
				hdr.Method = zip.Store
				_, _ = zw.CreateHeader(hdr)
			case fi.Mode().IsRegular():
				if slices.Contains(storedExts, strings.ToLower(path.Ext(name))) {
					hdr.Method = zip.Store
				} else {
					hdr.Method = zip.Deflate
				}
				f, err := s.Open(walker.Path())
				if err != nil {
					continue
				}
				dst, err := zw.CreateHeader(hdr)
				if err == nil {
					_, err = f.WriteTo(dst)
				}
				f.Close()
				if err != nil && isClientGone(err) {
					return
				}
			case fi.Mode()&os.ModeSymlink != 0:
				target, err := s.ReadLink(walker.Path())
				if err != nil {
					continue
				}
				if dst, err := zw.CreateHeader(hdr); err == nil {
					_, _ = io.WriteString(dst, target)
				}
			}
		}
	}
}

func isClientGone(err error) bool {
	var se *sftp.StatusError
	return !errors.As(err, &se) && !errors.Is(err, os.ErrPermission)
}

type UploadInput struct {
	ServerIDPath
	Path      string `query:"path" required:"true" doc:"Destination, including the file name"`
	Overwrite bool   `query:"overwrite" doc:"Replace an existing file"`
	body      io.Reader
	length    int64
}

// Resolve grabs the raw body: Huma doesn't read it (there is no Body
// field), so a large upload streams straight to the server.
func (in *UploadInput) Resolve(ctx huma.Context) []error {
	in.body = ctx.BodyReader()
	in.length, _ = strconv.ParseInt(ctx.Header("Content-Length"), 10, 64)
	return nil
}

func (h *serverHandler) upload(ctx context.Context, in *UploadInput) (*FileEntryOutput, error) {
	out := &FileEntryOutput{}
	started := false
	err := h.withSFTP(ctx, in.ID, func(c *sshpool.Conn, s *sftp.Client) error {
		if started {
			// The body is half read; a retry can't send it again.
			return huma.Error502BadGateway("Lost the connection to the server during the upload")
		}
		_, p, err := resolvePath(s, in.Path)
		if err != nil {
			return err
		}
		if p == "/" {
			return huma.Error422UnprocessableEntity("Give the file a name")
		}
		dir := path.Dir(p)
		perm := os.FileMode(0)
		if fi, err := s.Lstat(p); err == nil {
			if fi.IsDir() {
				return huma.Error409Conflict("A folder named " + path.Base(p) + " is already there")
			}
			if !in.Overwrite {
				return huma.Error409Conflict(path.Base(p)+" already exists", &huma.ErrorDetail{Location: "query.path", Message: "exists", Value: p})
			}
			perm = fi.Mode().Perm()
		} else if err := s.MkdirAll(dir); err != nil {
			return fsError(dir, err)
		}

		tmp := path.Join(dir, "."+path.Base(p)+".morcheh-"+randomSuffix())
		f, err := s.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
		if err != nil {
			return fsError(dir, err)
		}
		started = true
		var body io.Reader = in.body
		if in.length > 0 {
			body = io.LimitReader(in.body, in.length)
		}
		_, err = f.ReadFrom(body)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil && in.length > 0 {
			if fi, serr := s.Stat(tmp); serr == nil && fi.Size() != in.length {
				err = errors.New("the upload was cut short")
			}
		}
		if err != nil {
			_ = s.Remove(tmp)
			if ctx.Err() != nil {
				return huma.NewError(499, "Upload cancelled")
			}
			return huma.Error502BadGateway("Upload failed: " + err.Error())
		}
		if perm != 0 {
			_ = s.Chmod(tmp, perm)
		}
		if err := s.PosixRename(tmp, p); err != nil {
			// Servers without the posix-rename extension can't replace.
			_ = s.Remove(p)
			if err := s.Rename(tmp, p); err != nil {
				_ = s.Remove(tmp)
				return fsError(p, err)
			}
		}
		out.Body, err = stat(c, s, p)
		return err
	})
	return out, toProblem(err)
}

func randomSuffix() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- Helpers ----

// resolvePath makes p absolute and clean: empty or ~ is home, and relative
// paths (or ~/x) are taken from home, like ssh does.
func resolvePath(s *sftp.Client, p string) (home, abs string, err error) {
	p = strings.TrimSpace(p)
	if strings.ContainsRune(p, 0) {
		return "", "", huma.Error422UnprocessableEntity("Invalid path")
	}
	home, err = s.Getwd()
	if err != nil {
		return "", "", err
	}
	switch {
	case p == "" || p == "~":
		p = home
	case strings.HasPrefix(p, "~/"):
		p = path.Join(home, p[2:])
	case !strings.HasPrefix(p, "/"):
		p = path.Join(home, p)
	}
	return home, path.Clean(p), nil
}

func resolvePaths(s *sftp.Client, raw []string) ([]string, error) {
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		_, abs, err := resolvePath(s, p)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(out, abs) {
			out = append(out, abs)
		}
	}
	return out, nil
}

// planTransfer pairs each path with its place in dest. Copies into their
// own folder get a free "copy" name; any other clash stops everything.
func planTransfer(s *sftp.Client, raw []string, rawDest string, copying bool) ([][2]string, error) {
	paths, err := resolvePaths(s, raw)
	if err != nil {
		return nil, err
	}
	_, dest, err := resolvePath(s, rawDest)
	if err != nil {
		return nil, err
	}
	fi, err := s.Stat(dest)
	if err != nil {
		return nil, fsError(dest, err)
	}
	if !fi.IsDir() {
		return nil, huma.Error422UnprocessableEntity("Not a folder: " + dest)
	}
	var pairs [][2]string
	var clashes []string
	for _, p := range paths {
		if p == "/" || dest == p || strings.HasPrefix(dest, p+"/") {
			return nil, huma.Error422UnprocessableEntity("Can't put " + path.Base(p) + " inside itself")
		}
		target := path.Join(dest, path.Base(p))
		if target == p {
			if !copying {
				continue // already there
			}
			target = freeName(s, target, " copy")
		} else if _, err := s.Lstat(target); err == nil {
			clashes = append(clashes, path.Base(p))
			continue
		}
		pairs = append(pairs, [2]string{p, target})
	}
	if len(clashes) > 0 {
		return nil, huma.Error409Conflict("Already in " + dest + ": " + strings.Join(clashes, ", "))
	}
	return pairs, nil
}

// freeName finds an unused name: "a.txt" → "a copy.txt", "a copy 2.txt"…
// (with tag "") "a.txt" → "a 2.txt".
func freeName(s *sftp.Client, p, tag string) string {
	dir, base := path.Split(p)
	stem, ext := splitExt(base)
	for i := 1; ; i++ {
		candidate := stem + tag
		if i > 1 {
			candidate += " " + strconv.Itoa(i)
		}
		next := dir + candidate + ext
		if _, err := s.Lstat(next); err != nil {
			return next
		}
	}
}

// splitExt keeps double extensions together: "x.tar.gz" → "x", ".tar.gz".
func splitExt(name string) (string, string) {
	lower := strings.ToLower(name)
	for _, ext := range []string{".tar.gz", ".tar.bz2", ".tar.xz"} {
		if strings.HasSuffix(lower, ext) && len(name) > len(ext) {
			return name[:len(name)-len(ext)], name[len(name)-len(ext):]
		}
	}
	ext := path.Ext(name)
	if ext == name {
		return name, "" // dotfile
	}
	return strings.TrimSuffix(name, ext), ext
}

// move renames, falling back to mv for moves across filesystems.
func move(ctx context.Context, c *sshpool.Conn, s *sftp.Client, from, to string) error {
	if _, err := s.Lstat(to); err == nil {
		return huma.Error409Conflict(path.Base(to) + " already exists")
	}
	err := s.Rename(from, to)
	if err == nil {
		return nil
	}
	var se *sftp.StatusError
	if !errors.As(err, &se) {
		return fsError(from, err)
	}
	return runStream(ctx, c, "mv -- "+terminal.ShellQuote(from)+" "+terminal.ShellQuote(to), nil, nil)
}

func stat(c *sshpool.Conn, s *sftp.Client, p string) (FileEntry, error) {
	fi, err := s.Lstat(p)
	if err != nil {
		return FileEntry{}, fsError(p, err)
	}
	return entries(c, s, path.Dir(p), []os.FileInfo{fi})[0], nil
}

// statMany looks up paths concurrently, leaving out ones that vanished.
func statMany(c *sshpool.Conn, s *sftp.Client, paths []string) []FileEntry {
	infos := make([]os.FileInfo, len(paths))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for i, p := range paths {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			infos[i], _ = s.Lstat(p)
		})
	}
	wg.Wait()
	out := []FileEntry{}
	for i, fi := range infos {
		if fi != nil {
			out = append(out, entries(c, s, path.Dir(paths[i]), []os.FileInfo{fi})[0])
		}
	}
	return out
}

// entries converts SFTP infos, resolving symlinks concurrently.
func entries(c *sshpool.Conn, s *sftp.Client, dir string, infos []os.FileInfo) []FileEntry {
	users, groups := c.Names()
	out := make([]FileEntry, len(infos))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for i, fi := range infos {
		e := FileEntry{
			Name:       fi.Name(),
			Path:       path.Join(dir, fi.Name()),
			Size:       fi.Size(),
			Modified:   fi.ModTime(),
			Mode:       modeString(fi.Mode()),
			Perm:       fmt.Sprintf("%04o", unixMode(fi.Mode())),
			TargetType: "none",
		}
		switch m := fi.Mode(); {
		case m.IsDir():
			e.Type = "dir"
		case m.IsRegular():
			e.Type = "file"
		case m&os.ModeSymlink != 0:
			e.Type = "symlink"
		default:
			e.Type = "other"
		}
		if st, ok := fi.Sys().(*sftp.FileStat); ok {
			e.UID, e.GID = st.UID, st.GID
		}
		e.Owner = nameOr(users, e.UID)
		e.Group = nameOr(groups, e.GID)
		out[i] = e
		if e.Type == "symlink" {
			wg.Go(func() {
				sem <- struct{}{}
				defer func() { <-sem }()
				out[i].LinkTarget, _ = s.ReadLink(out[i].Path)
				switch t, err := s.Stat(out[i].Path); {
				case err != nil:
					out[i].TargetType = "missing"
				case t.IsDir():
					out[i].TargetType = "dir"
				case t.Mode().IsRegular():
					out[i].TargetType = "file"
				default:
					out[i].TargetType = "other"
				}
			})
		}
	}
	wg.Wait()
	slices.SortFunc(out, func(a, b FileEntry) int { return strings.Compare(a.Name, b.Name) })
	return out
}

func nameOr(names map[uint32]string, id uint32) string {
	if n, ok := names[id]; ok {
		return n
	}
	return strconv.FormatUint(uint64(id), 10)
}

func unixMode(m os.FileMode) uint32 {
	bits := uint32(m.Perm())
	if m&os.ModeSetuid != 0 {
		bits |= 0o4000
	}
	if m&os.ModeSetgid != 0 {
		bits |= 0o2000
	}
	if m&os.ModeSticky != 0 {
		bits |= 0o1000
	}
	return bits
}

func fromUnixMode(bits uint32) os.FileMode {
	m := os.FileMode(bits & 0o777)
	if bits&0o4000 != 0 {
		m |= os.ModeSetuid
	}
	if bits&0o2000 != 0 {
		m |= os.ModeSetgid
	}
	if bits&0o1000 != 0 {
		m |= os.ModeSticky
	}
	return m
}

// modeString is ls -l style ("drwxr-sr-x"), unlike Go's FileMode.String.
func modeString(m os.FileMode) string {
	b := []byte("----------")
	switch {
	case m.IsDir():
		b[0] = 'd'
	case m&os.ModeSymlink != 0:
		b[0] = 'l'
	case m&os.ModeNamedPipe != 0:
		b[0] = 'p'
	case m&os.ModeSocket != 0:
		b[0] = 's'
	case m&os.ModeCharDevice != 0:
		b[0] = 'c'
	case m&os.ModeDevice != 0:
		b[0] = 'b'
	}
	const rwx = "rwxrwxrwx"
	for i := range 9 {
		if m&(1<<uint(8-i)) != 0 {
			b[i+1] = rwx[i]
		}
	}
	special := func(i int, set bool, on, off byte) {
		if !set {
			return
		}
		if b[i] == 'x' {
			b[i] = on
		} else {
			b[i] = off
		}
	}
	special(3, m&os.ModeSetuid != 0, 's', 'S')
	special(6, m&os.ModeSetgid != 0, 's', 'S')
	special(9, m&os.ModeSticky != 0, 't', 'T')
	return string(b)
}

// isText: valid UTF-8 with no NUL bytes in the first 8 KB.
func isText(data []byte) bool {
	head := data[:min(len(data), 8000)]
	return bytes.IndexByte(head, 0) < 0 && utf8.Valid(data)
}

var accountRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}\$?$`)

func quoteAll(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = terminal.ShellQuote(s)
	}
	return strings.Join(q, " ")
}

func escapeGlob(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `[`, `\[`, `]`, `\]`)
	return r.Replace(s)
}

// cmdError is a command that ran and failed; its message is what it printed
// on stderr.
type cmdError struct {
	code int
	msg  string
}

func (e *cmdError) Error() string { return e.msg }

// run executes a shell command as the login user and returns its stdout.
func run(ctx context.Context, c *sshpool.Conn, cmd string) (string, error) {
	return runInput(ctx, c, cmd, "", execTimeout)
}

// runInput is run with text on stdin (empty for none) and its own timeout.
func runInput(ctx context.Context, c *sshpool.Conn, cmd, stdin string, timeout time.Duration) (string, error) {
	return runLogged(ctx, c, cmd, stdin, timeout, logAs{})
}

// logAs is how a command shows in the command log (see sshpool.Session).
type logAs struct {
	script  string
	asRoot  bool
	secrets []string
}

func (l logAs) apply(s *sshpool.Session) {
	s.Script, s.AsRoot, s.Secrets = l.script, l.asRoot, l.secrets
}

// runLogged is runInput logging the command as l says.
func runLogged(ctx context.Context, c *sshpool.Conn, cmd, stdin string, timeout time.Duration, l logAs) (string, error) {
	sess, err := c.Session(ctx)
	if err != nil {
		return "", err
	}
	l.apply(sess)
	defer sess.Close()
	var stdout, stderr bytes.Buffer
	sess.Stdout, sess.Stderr = &stdout, &stderr
	if stdin != "" {
		sess.Stdin = strings.NewReader(stdin)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { sess.Close() })
	defer stop()

	err = sess.Run(cmd)
	if err == nil {
		return stdout.String(), nil
	}
	if ctx.Err() != nil {
		return stdout.String(), huma.Error504GatewayTimeout("The server took too long")
	}
	var exit *ssh.ExitError
	if errors.As(err, &exit) {
		msg := lastLines(stderr.String(), 3)
		switch {
		case exit.ExitStatus() == 127:
			msg = "A command this needs isn't installed on the server"
			if m := notFoundRe.FindStringSubmatch(stderr.String()); m != nil {
				msg = m[1] + " isn't installed on the server"
			}
		case msg == "":
			msg = fmt.Sprintf("The command failed (exit %d)", exit.ExitStatus())
		}
		return stdout.String(), &cmdError{exit.ExitStatus(), msg}
	}
	return stdout.String(), err
}

var notFoundRe = regexp.MustCompile(`([\w.+-]+): (?:command )?not found`)

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}

// fileError carries the path an SFTP error is about, for the message.
type fileError struct {
	path string
	err  error
}

func (e *fileError) Error() string { return e.path + ": " + e.err.Error() }
func (e *fileError) Unwrap() error { return e.err }

func fsError(p string, err error) error {
	return &fileError{p, err}
}

// toProblem turns what a file operation returned into a problem response.
func toProblem(err error) error {
	if err == nil {
		return nil
	}
	var se huma.StatusError
	if errors.As(err, &se) {
		return err
	}
	var be *boxError
	if errors.As(err, &be) {
		return boxProblem(be)
	}
	var ce *cmdError
	if errors.As(err, &ce) {
		return huma.Error422UnprocessableEntity(ce.msg)
	}
	if sshprobe.SessionClosed(err) { // still failing on a fresh connection
		return huma.Error502BadGateway(sshprobe.SessionClosedMessage)
	}
	if sshpool.Lost(err) {
		return huma.Error502BadGateway("Lost the connection to the server")
	}
	var fe *fileError
	if errors.As(err, &fe) {
		switch {
		case errors.Is(fe.err, os.ErrNotExist):
			return huma.Error404NotFound("No such file or folder: " + fe.path)
		case errors.Is(fe.err, os.ErrPermission):
			return huma.Error403Forbidden("Permission denied: " + fe.path)
		case errors.Is(fe.err, os.ErrExist):
			return huma.Error409Conflict(path.Base(fe.path) + " already exists")
		}
		var st *sftp.StatusError
		if errors.As(fe.err, &st) {
			return huma.Error422UnprocessableEntity(fmt.Sprintf("The server refused (%s): %s", fe.path, sftpMessage(st)))
		}
		return huma.Error422UnprocessableEntity(fe.Error())
	}
	return internalError(err)
}

// sftpMessage pulls the server's text out of `sftp: "msg" (CODE)`.
func sftpMessage(st *sftp.StatusError) string {
	msg := st.Error()
	if i, j := strings.Index(msg, `"`), strings.LastIndex(msg, `"`); i >= 0 && j > i {
		if m := msg[i+1 : j]; m != "" {
			return m
		}
	}
	return msg
}
