package api

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/pkg/sftp"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/storage"
)

// ---- Types ----

type StorageEntry struct {
	Name         string     `json:"name" example:"report.csv"`
	Path         string     `json:"path" doc:"From the storage's top (\"/\")" example:"/2026/report.csv"`
	Type         string     `json:"type" enum:"file,dir"`
	Size         int64      `json:"size" doc:"Bytes; 0 for folders"`
	Modified     *time.Time `json:"modified" nullable:"true" doc:"Unknown for S3 prefixes"`
	ContentType  string     `json:"content_type"`
	ETag         string     `json:"etag"`
	StorageClass string     `json:"storage_class" doc:"S3 storage class (STANDARD, GLACIER…)"`
	Bucket       bool       `json:"bucket" doc:"A top-level folder that is an S3 bucket"`
}

func toEntry(e storage.Entry) StorageEntry {
	out := StorageEntry{
		Name: e.Name, Path: e.Path, Type: "file", Size: e.Size, ContentType: e.ContentType,
		ETag: e.ETag, StorageClass: e.StorageClass, Bucket: e.Bucket,
	}
	if e.Dir {
		out.Type = "dir"
	}
	if !e.Modified.IsZero() {
		t := e.Modified
		out.Modified = &t
	}
	return out
}

type StorageListing struct {
	Path      string         `json:"path"`
	Parent    string         `json:"parent" doc:"Empty at the top"`
	Entries   []StorageEntry `json:"entries"`
	Truncated bool           `json:"truncated" doc:"The folder has more entries than limit"`
}

type StoragePathQuery struct {
	StorageIDPath
	Path string `query:"path" doc:"From the storage's top; empty = \"/\""`
}

type StorageEntryOutput struct{ Body StorageEntry }

type StorageAffectedOutput struct {
	Body struct {
		Affected int `json:"affected"`
	}
}

// StorageMoveBody is what to copy or move inside one storage, and where to.
type StorageMoveBody struct {
	Paths       []string `json:"paths" minItems:"1" maxItems:"1000"`
	Destination string   `json:"destination" doc:"Folder to put them in"`
}

// sameStorageParams is a copy or move inside one storage. The names are
// planned again when the job runs.
type sameStorageParams struct {
	StorageID string `json:"storage_id"`
	StorageMoveBody
}

type StorageTransferResult struct {
	Files int   `json:"files" doc:"Files copied"`
	Bytes int64 `json:"bytes" doc:"Bytes streamed through Morcheh (0 when the storage copied by itself)"`
}

const (
	storageListDefault = 5000
	storageWalkTimeout = time.Minute
)

// cleanPath checks a path from a request and makes it absolute.
func cleanPath(p string) (string, error) {
	if strings.ContainsRune(p, 0) {
		return "", huma.Error422UnprocessableEntity("Invalid path")
	}
	return storage.Clean(strings.TrimSpace(p)), nil
}

func cleanPaths(raw []string) ([]string, error) {
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		c, err := cleanPath(p)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out, nil
}

// storageProblem turns a storage error about p into a problem response.
func storageProblem(p string, err error) error {
	var se huma.StatusError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &se):
		return err
	case errors.Is(err, fs.ErrNotExist):
		return huma.Error404NotFound("Not found: " + p)
	case errors.Is(err, fs.ErrPermission):
		return huma.Error403Forbidden("Permission denied: " + p)
	case errors.Is(err, fs.ErrExist):
		return huma.Error409Conflict(path.Base(p) + " already exists")
	case errors.Is(err, storage.ErrNotEmpty):
		return huma.Error409Conflict(path.Base(p) + " is not empty")
	case errors.Is(err, storage.ErrUnsupported):
		return huma.Error422UnprocessableEntity("This storage can't do that")
	case errors.Is(err, fs.ErrInvalid):
		return huma.Error422UnprocessableEntity(p + ": " + err.Error())
	case errors.Is(err, context.Canceled):
		return huma.NewError(499, "Cancelled")
	case errors.Is(err, context.DeadlineExceeded):
		return huma.Error504GatewayTimeout("The storage took too long")
	case storage.IsConnLost(err):
		return huma.Error502BadGateway("Lost the connection to the storage")
	}
	return huma.Error502BadGateway("The storage refused: " + err.Error())
}

func writable(row sqlc.Storage) error {
	if row.ReadOnly {
		return huma.Error403Forbidden("This storage is read-only in Morcheh. Turn that off in its settings to make changes.")
	}
	return nil
}

func exists(ctx context.Context, f storage.FS, p string) (storage.Entry, bool, error) {
	e, err := f.Stat(ctx, p)
	if errors.Is(err, fs.ErrNotExist) {
		return e, false, nil
	}
	return e, err == nil, err
}

// storageFreeName finds an unused name: "a.txt" → "a copy.txt", "a copy 2.txt"…
func storageFreeName(ctx context.Context, f storage.FS, p, tag string) (string, error) {
	dir, base := path.Split(p)
	stem, ext := splitExt(base)
	for i := 1; i < 1000; i++ {
		candidate := stem + tag
		if i > 1 {
			candidate += " " + strconv.Itoa(i)
		}
		next := dir + candidate + ext
		_, ok, err := exists(ctx, f, next)
		if err != nil {
			return "", err
		}
		if !ok {
			return next, nil
		}
	}
	return "", huma.Error409Conflict("Too many copies of " + base)
}

// planStorageTransfer pairs each path with its place in dest. Copies into
// their own folder get a free "copy" name; any other clash stops everything.
func planStorageTransfer(ctx context.Context, f storage.FS, raw []string, rawDest string, copying bool) ([][2]string, error) {
	paths, err := cleanPaths(raw)
	if err != nil {
		return nil, err
	}
	dest, err := cleanPath(rawDest)
	if err != nil {
		return nil, err
	}
	if e, err := f.Stat(ctx, dest); err != nil {
		return nil, storageProblem(dest, err)
	} else if !e.Dir {
		return nil, huma.Error422UnprocessableEntity("Not a folder: " + dest)
	}
	var pairs [][2]string
	var clashes []string
	for _, p := range paths {
		if p == "/" || storage.Within(dest, p) && dest != path.Dir(p) {
			return nil, huma.Error422UnprocessableEntity("Can't put " + path.Base(p) + " inside itself")
		}
		target := path.Join(dest, path.Base(p))
		if target == p {
			if !copying {
				continue // already there
			}
			if target, err = storageFreeName(ctx, f, target, " copy"); err != nil {
				return nil, storageProblem(p, err)
			}
		} else if _, ok, err := exists(ctx, f, target); err != nil {
			return nil, storageProblem(target, err)
		} else if ok {
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

// ---- Handlers ----

func registerStorageFiles(api huma.API, h *storageHandler) {
	tags := []string{"Storage files"}

	huma.Register(api, huma.Operation{
		OperationID: "list-storage-files",
		Method:      http.MethodGet,
		Path:        "/storages/{id}/files",
		Summary:     "List a storage folder",
		Description: "Direct children of a folder. On S3 without a fixed bucket, \"/\" lists the buckets.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		StoragePathQuery
		Limit int `query:"limit" minimum:"1" maximum:"20000" default:"5000"`
	}) (*struct{ Body StorageListing }, error) {
		p, err := cleanPath(in.Path)
		if err != nil {
			return nil, err
		}
		limit := in.Limit
		if limit == 0 {
			limit = storageListDefault
		}
		out := &struct{ Body StorageListing }{}
		err = h.withFS(ctx, in.ID, func(_ sqlc.Storage, f storage.FS) error {
			list, err := f.List(ctx, p, limit+1)
			if err != nil {
				return storageProblem(p, err)
			}
			out.Body = StorageListing{Path: p, Entries: make([]StorageEntry, 0, len(list))}
			if p != "/" {
				out.Body.Parent = path.Dir(p)
			}
			if len(list) > limit {
				list, out.Body.Truncated = list[:limit], true
			}
			for _, e := range list {
				out.Body.Entries = append(out.Body.Entries, toEntry(e))
			}
			return nil
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "stat-storage-file",
		Method:      http.MethodGet,
		Path:        "/storages/{id}/files/stat",
		Summary:     "Details of one file or folder",
		Tags:        tags,
	}, func(ctx context.Context, in *StoragePathQuery) (*StorageEntryOutput, error) {
		p, err := cleanPath(in.Path)
		if err != nil {
			return nil, err
		}
		out := &StorageEntryOutput{}
		err = h.withFS(ctx, in.ID, func(_ sqlc.Storage, f storage.FS) error {
			e, err := f.Stat(ctx, p)
			out.Body = toEntry(e)
			return storageProblem(p, err)
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "storage-folder-size",
		Method:      http.MethodGet,
		Path:        "/storages/{id}/files/size",
		Summary:     "Total size of a folder",
		Description: "Walks the folder. Stops after a minute and reports what it counted so far (partial).",
		Tags:        tags,
	}, func(ctx context.Context, in *StoragePathQuery) (*struct {
		Body struct {
			Path    string `json:"path"`
			Size    int64  `json:"size"`
			Files   int    `json:"files"`
			Folders int    `json:"folders"`
			Partial bool   `json:"partial" doc:"Stopped before the end (too big to count in time)"`
		}
	}, error) {
		p, err := cleanPath(in.Path)
		if err != nil {
			return nil, err
		}
		out := &struct {
			Body struct {
				Path    string `json:"path"`
				Size    int64  `json:"size"`
				Files   int    `json:"files"`
				Folders int    `json:"folders"`
				Partial bool   `json:"partial" doc:"Stopped before the end (too big to count in time)"`
			}
		}{}
		out.Body.Path = p
		err = h.withFS(ctx, in.ID, func(_ sqlc.Storage, f storage.FS) error {
			wctx, cancel := context.WithTimeout(ctx, storageWalkTimeout)
			defer cancel()
			err := storage.Walk(wctx, f, p, func(e storage.Entry) error {
				if e.Dir {
					out.Body.Folders++
				} else {
					out.Body.Files++
					out.Body.Size += e.Size
				}
				return nil
			})
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				out.Body.Partial = true
				return nil
			}
			return storageProblem(p, err)
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "search-storage-files",
		Method:      http.MethodGet,
		Path:        "/storages/{id}/files/search",
		Summary:     "Find files by name",
		Description: "Case-insensitive name match under path (recursive). At most 200 results; stops after a minute.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		StoragePathQuery
		Q string `query:"q" required:"true" minLength:"1" maxLength:"200"`
	}) (*struct {
		Body struct {
			Items     []StorageEntry `json:"items"`
			Truncated bool           `json:"truncated"`
		}
	}, error) {
		p, err := cleanPath(in.Path)
		if err != nil {
			return nil, err
		}
		needle := strings.ToLower(strings.TrimSpace(in.Q))
		out := &struct {
			Body struct {
				Items     []StorageEntry `json:"items"`
				Truncated bool           `json:"truncated"`
			}
		}{}
		out.Body.Items = []StorageEntry{}
		err = h.withFS(ctx, in.ID, func(_ sqlc.Storage, f storage.FS) error {
			out.Body.Items = out.Body.Items[:0]
			wctx, cancel := context.WithTimeout(ctx, storageWalkTimeout)
			defer cancel()
			err := storage.Walk(wctx, f, p, func(e storage.Entry) error {
				if !strings.Contains(strings.ToLower(e.Name), needle) {
					return nil
				}
				if len(out.Body.Items) == maxSearch {
					out.Body.Truncated = true
					return storage.ErrSkip
				}
				out.Body.Items = append(out.Body.Items, toEntry(e))
				return nil
			})
			switch {
			case errors.Is(err, storage.ErrSkip):
				return nil
			case errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil:
				out.Body.Truncated = true
				return nil
			}
			return storageProblem(p, err)
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "download-storage-files",
		Method:      http.MethodGet,
		Path:        "/storages/{id}/files/download",
		Summary:     "Download files",
		Description: "One file streams as itself (Range support on S3 and SFTP). Several paths, or a folder, stream as one zip.",
		Tags:        tags,
		Responses: map[string]*huma.Response{
			"200": {
				Description: "The file, or a zip of everything asked for",
				Content:     map[string]*huma.MediaType{"application/octet-stream": {Schema: &huma.Schema{Type: "string", Format: "binary"}}},
			},
		},
	}, h.download)

	huma.Register(api, huma.Operation{
		OperationID: "read-storage-file",
		Method:      http.MethodGet,
		Path:        "/storages/{id}/files/content",
		Summary:     "Read a text file",
		Description: "For the editor: UTF-8 text up to 5 MB. Bigger files are 413, binary ones 415.",
		Tags:        tags,
	}, func(ctx context.Context, in *StoragePathQuery) (*struct{ Body FileContent }, error) {
		p, err := cleanPath(in.Path)
		if err != nil {
			return nil, err
		}
		out := &struct{ Body FileContent }{}
		err = h.withFS(ctx, in.ID, func(_ sqlc.Storage, f storage.FS) error {
			e, err := f.Stat(ctx, p)
			if err != nil {
				return storageProblem(p, err)
			}
			if e.Dir {
				return huma.Error422UnprocessableEntity("That's a folder: " + p)
			}
			if e.Size > maxEditable {
				return huma.NewError(http.StatusRequestEntityTooLarge, "Files over 5 MB can't be opened in the editor. Download it instead.")
			}
			r, err := f.Open(ctx, p)
			if err != nil {
				return storageProblem(p, err)
			}
			defer r.Close()
			var buf bytes.Buffer
			if _, err := io.Copy(&buf, io.LimitReader(r, maxEditable+1)); err != nil {
				return storageProblem(p, err)
			}
			if buf.Len() > maxEditable {
				return huma.NewError(http.StatusRequestEntityTooLarge, "Files over 5 MB can't be opened in the editor. Download it instead.")
			}
			if !isText(buf.Bytes()) {
				return huma.NewError(http.StatusUnsupportedMediaType, "This looks like a binary file. Download it instead.")
			}
			out.Body = FileContent{Path: p, Content: buf.String(), Size: int64(buf.Len()), Modified: e.Modified}
			return nil
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID:  "write-storage-file",
		Method:       http.MethodPut,
		Path:         "/storages/{id}/files/content",
		Summary:      "Save a text file",
		Description:  "Replaces the file. With expected_modified, refuses (409) if it changed since it was read. With create, makes a new file and refuses if one exists.",
		Tags:         tags,
		MaxBodyBytes: maxEditable + 1<<20,
	}, func(ctx context.Context, in *struct {
		StorageIDPath
		Body struct {
			Path             string     `json:"path" minLength:"1"`
			Content          string     `json:"content"`
			ExpectedModified *time.Time `json:"expected_modified,omitempty"`
			Create           bool       `json:"create,omitempty"`
		}
	}) (*StorageEntryOutput, error) {
		b := in.Body
		p, err := cleanPath(b.Path)
		if err != nil {
			return nil, err
		}
		out := &StorageEntryOutput{}
		err = h.withFS(ctx, in.ID, func(row sqlc.Storage, f storage.FS) error {
			if err := writable(row); err != nil {
				return err
			}
			e, ok, err := exists(ctx, f, p)
			switch {
			case err != nil:
				return storageProblem(p, err)
			case b.Create && ok:
				return huma.Error409Conflict(path.Base(p) + " already exists")
			case !b.Create && !ok:
				return huma.Error404NotFound("Not found: " + p)
			case e.Dir:
				return huma.Error422UnprocessableEntity("That's a folder: " + p)
			case !b.Create && b.ExpectedModified != nil && !e.Modified.IsZero() && e.Modified.Unix() != b.ExpectedModified.Unix():
				return huma.Error409Conflict("The file changed on the storage since you opened it.")
			}
			if err := f.Put(ctx, p, strings.NewReader(b.Content), int64(len(b.Content))); err != nil {
				return storageProblem(p, err)
			}
			e, err = f.Stat(ctx, p)
			out.Body = toEntry(e)
			return storageProblem(p, err)
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "upload-storage-file",
		Method:      http.MethodPut,
		Path:        "/storages/{id}/files/upload",
		Summary:     "Upload a file",
		Description: "The raw body is the file. Missing parent folders are created. An existing file is 409 unless overwrite is set.",
		Tags:        tags,
		RequestBody: &huma.RequestBody{
			Required: true,
			Content:  map[string]*huma.MediaType{"application/octet-stream": {Schema: &huma.Schema{Type: "string", Format: "binary"}}},
		},
	}, h.upload)

	huma.Register(api, huma.Operation{
		OperationID:   "storage-mkdir",
		Method:        http.MethodPost,
		Path:          "/storages/{id}/files/mkdir",
		Summary:       "Create a folder",
		Description:   "On S3 without a fixed bucket, a folder at the top creates a bucket.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		StorageIDPath
		Body struct {
			Path string `json:"path" minLength:"1"`
		}
	}) (*StorageEntryOutput, error) {
		p, err := cleanPath(in.Body.Path)
		if err != nil {
			return nil, err
		}
		if p == "/" {
			return nil, huma.Error422UnprocessableEntity("Give the folder a name")
		}
		out := &StorageEntryOutput{}
		err = h.withFS(ctx, in.ID, func(row sqlc.Storage, f storage.FS) error {
			if err := writable(row); err != nil {
				return err
			}
			if _, ok, err := exists(ctx, f, p); err != nil {
				return storageProblem(p, err)
			} else if ok {
				return huma.Error409Conflict(path.Base(p) + " already exists")
			}
			if err := f.Mkdir(ctx, p); err != nil {
				return storageProblem(p, err)
			}
			e, err := f.Stat(ctx, p)
			out.Body = toEntry(e)
			return storageProblem(p, err)
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "storage-rename",
		Method:      http.MethodPost,
		Path:        "/storages/{id}/files/rename",
		Summary:     "Rename a file or folder",
		Description: "On S3 a rename copies every object and deletes the old ones, so big folders take a while. Buckets can't be renamed.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		StorageIDPath
		Body struct {
			Path string `json:"path" minLength:"1"`
			Name string `json:"name" minLength:"1" maxLength:"255"`
		}
	}) (*StorageEntryOutput, error) {
		p, err := cleanPath(in.Body.Path)
		if err != nil {
			return nil, err
		}
		name := strings.TrimSpace(in.Body.Name)
		if strings.ContainsAny(name, "/\x00") || name == "." || name == ".." {
			return nil, fieldError("body.name", "Names can't contain /", name)
		}
		if p == "/" {
			return nil, huma.Error422UnprocessableEntity("Can't rename the top folder")
		}
		to := path.Join(path.Dir(p), name)
		out := &StorageEntryOutput{}
		err = h.withFS(ctx, in.ID, func(row sqlc.Storage, f storage.FS) error {
			if err := writable(row); err != nil {
				return err
			}
			if to != p {
				if _, ok, err := exists(ctx, f, to); err != nil {
					return storageProblem(to, err)
				} else if ok {
					return huma.Error409Conflict(name + " already exists")
				}
				if err := f.Rename(ctx, p, to); err != nil {
					return storageProblem(p, err)
				}
			}
			e, err := f.Stat(ctx, to)
			out.Body = toEntry(e)
			return storageProblem(to, err)
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "storage-move",
		Method:      http.MethodPost,
		Path:        "/storages/{id}/files/move",
		Summary:     "Move files into a folder",
		Description: "A name already in the destination is 409 and nothing moves; 422 when they're already there. " +
			"Runs as a background job (kind `storage-move`) that starts at once.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		StorageIDPath
		Body StorageMoveBody
	}) (*JobOutput, error) {
		return h.submitSameStorage(ctx, in.ID, "storage-move", in.Body)
	})
	h.servers.jobs.Handle("storage-move", h.runStorageMove)

	huma.Register(api, huma.Operation{
		OperationID: "storage-copy",
		Method:      http.MethodPost,
		Path:        "/storages/{id}/files/copy",
		Summary:     "Copy files into a folder",
		Description: "Copies into their own folder get a free \"copy\" name; any other clash is 409. " +
			"Runs as a background job (kind `storage-copy`, result StorageTransferResult).",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		StorageIDPath
		Body StorageMoveBody
	}) (*JobOutput, error) {
		return h.submitSameStorage(ctx, in.ID, "storage-copy", in.Body)
	})
	h.servers.jobs.Handle("storage-copy", h.runStorageCopy)

	huma.Register(api, huma.Operation{
		OperationID: "storage-delete",
		Method:      http.MethodPost,
		Path:        "/storages/{id}/files/delete",
		Summary:     "Delete files and folders",
		Description: "Folders go with everything in them. On S3, deleting a top-level bucket folder deletes the bucket.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		StorageIDPath
		Body struct {
			Paths []string `json:"paths" minItems:"1" maxItems:"1000"`
		}
	}) (*StorageAffectedOutput, error) {
		paths, err := cleanPaths(in.Body.Paths)
		if err != nil {
			return nil, err
		}
		out := &StorageAffectedOutput{}
		err = h.withFS(ctx, in.ID, func(row sqlc.Storage, f storage.FS) error {
			if err := writable(row); err != nil {
				return err
			}
			for _, p := range paths {
				if p == "/" {
					return huma.Error422UnprocessableEntity("Can't delete the top folder")
				}
				if err := f.Remove(ctx, p); err != nil && !errors.Is(err, fs.ErrNotExist) {
					return storageProblem(p, err)
				}
				out.Body.Affected++
			}
			return nil
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "share-storage-file",
		Method:      http.MethodPost,
		Path:        "/storages/{id}/files/share",
		Summary:     "Make a public download link",
		Description: "A pre-signed link anyone can open until it expires (S3 only; at most 7 days). It can't be revoked early except by rotating the access key.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		StorageIDPath
		Body struct {
			Path      string `json:"path" minLength:"1"`
			ExpiresIn int    `json:"expires_in,omitempty" minimum:"60" maximum:"604800" default:"86400" doc:"Seconds"`
		}
	}) (*struct {
		Body struct {
			URL       string    `json:"url"`
			ExpiresAt time.Time `json:"expires_at"`
		}
	}, error) {
		p, err := cleanPath(in.Body.Path)
		if err != nil {
			return nil, err
		}
		expiry := time.Duration(in.Body.ExpiresIn) * time.Second
		if expiry == 0 {
			expiry = 24 * time.Hour
		}
		out := &struct {
			Body struct {
				URL       string    `json:"url"`
				ExpiresAt time.Time `json:"expires_at"`
			}
		}{}
		err = h.withFS(ctx, in.ID, func(_ sqlc.Storage, f storage.FS) error {
			e, err := f.Stat(ctx, p)
			if err != nil {
				return storageProblem(p, err)
			}
			if e.Dir {
				return huma.Error422UnprocessableEntity("Only files can be shared")
			}
			url, err := f.Share(ctx, p, expiry, e.Name)
			if err != nil {
				return storageProblem(p, err)
			}
			out.Body.URL, out.Body.ExpiresAt = url, time.Now().Add(expiry).UTC()
			return nil
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "transfer-files",
		Method:      http.MethodPost,
		Path:        "/storages/transfer",
		Summary:     "Copy or move files between storages and servers",
		Description: "Each end is a storage or a server (over SFTP). Files stream through Morcheh; two places on one storage copy on the storage itself when it can. " +
			"Server paths are absolute or relative to the login user's home. A name already in the destination is 409 unless overwrite is set. " +
			"The request is checked at once, then the copy runs as a background job (kind `transfer`, result StorageTransferResult); follow it on /jobs/stream.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, h.transfer)
	h.servers.jobs.Handle("transfer", h.runTransfer)
}

// ---- Download & upload ----

type StorageDownloadInput struct {
	StorageIDPath
	Paths  []string `query:"path,explode" required:"true" minItems:"1" doc:"Repeat for several files"`
	Inline bool     `query:"inline" doc:"Show in the browser instead of saving (images, media, PDF, plain text only)"`
	Name   string   `query:"name" doc:"File name for a zip of several paths"`
}

func (h *storageHandler) download(ctx context.Context, in *StorageDownloadInput) (*huma.StreamResponse, error) {
	paths, err := cleanPaths(in.Paths)
	if err != nil {
		return nil, err
	}
	row, err := h.get(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	c, err := h.acquire(ctx, row)
	if err != nil {
		return nil, err
	}
	f := c.fs
	var file storage.File
	if len(paths) == 1 {
		e, err := f.Stat(ctx, paths[0])
		if err != nil {
			h.release(c)
			return nil, storageProblem(paths[0], err)
		}
		if !e.Dir {
			if file, err = f.Open(ctx, paths[0]); err != nil {
				h.release(c)
				return nil, storageProblem(paths[0], err)
			}
		}
	}

	return &huma.StreamResponse{Body: func(hctx huma.Context) {
		defer h.release(c)
		r, w := humachi.Unwrap(hctx)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if file != nil {
			defer file.Close()
			serveStorageFile(w, r, file, in.Inline, f.Capabilities().Ranges)
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
		writeStorageZip(r.Context(), w, f, paths)
	}}, nil
}

func serveStorageFile(w http.ResponseWriter, r *http.Request, file storage.File, inline, ranges bool) {
	e := file.Entry()
	ctype := mime.TypeByExtension(path.Ext(e.Name))
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	kind := "attachment"
	if inline && slices.ContainsFunc(inlineTypes, func(t string) bool { return strings.HasPrefix(ctype, t) }) {
		kind = "inline"
		w.Header().Set("Content-Security-Policy", "sandbox")
	} else if inline {
		ctype = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", disposition(kind, e.Name))

	if rs, ok := file.(io.ReadSeeker); ok && ranges && r.Header.Get("Range") != "" {
		http.ServeContent(w, r, e.Name, e.Modified, rs)
		return
	}
	w.Header().Set("Content-Length", strconv.FormatInt(e.Size, 10))
	if !e.Modified.IsZero() {
		w.Header().Set("Last-Modified", e.Modified.UTC().Format(http.TimeFormat))
	}
	if ranges {
		w.Header().Set("Accept-Ranges", "bytes")
	}
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.Copy(w, file)
	}
}

// writeStorageZip streams the paths (folders recursively) as a zip. Names
// are relative to each path's parent; unreadable entries are skipped, since
// the response has already started.
func writeStorageZip(ctx context.Context, w io.Writer, f storage.FS, paths []string) {
	zw := zip.NewWriter(w)
	defer zw.Close()
	add := func(parent string, e storage.Entry) error {
		hdr := &zip.FileHeader{Name: strings.TrimPrefix(strings.TrimPrefix(e.Path, parent), "/"), Modified: e.Modified}
		if e.Dir {
			hdr.Name += "/"
			_, _ = zw.CreateHeader(hdr)
			return nil
		}
		hdr.Method = zip.Deflate
		if slices.Contains(storedExts, strings.ToLower(path.Ext(e.Name))) {
			hdr.Method = zip.Store
		}
		hdr.UncompressedSize64 = uint64(e.Size)
		r, err := f.Open(ctx, e.Path)
		if err != nil {
			return nil
		}
		defer r.Close()
		dst, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		if _, err := io.Copy(dst, r); err != nil && ctx.Err() != nil {
			return err // the client went away
		}
		return nil
	}
	for _, root := range paths {
		parent := path.Dir(root)
		e, err := f.Stat(ctx, root)
		if err != nil {
			continue
		}
		if err := add(parent, e); err != nil {
			return
		}
		if !e.Dir {
			continue
		}
		if err := storage.Walk(ctx, f, root, func(e storage.Entry) error { return add(parent, e) }); err != nil && ctx.Err() != nil {
			return
		}
	}
}

type StorageUploadInput struct {
	StorageIDPath
	Path      string `query:"path" required:"true" doc:"Destination, including the file name"`
	Overwrite bool   `query:"overwrite" doc:"Replace an existing file"`
	body      io.Reader
	length    int64
}

// Resolve grabs the raw body, so a large upload streams straight through.
func (in *StorageUploadInput) Resolve(ctx huma.Context) []error {
	in.body = ctx.BodyReader()
	in.length = -1
	if n, err := strconv.ParseInt(ctx.Header("Content-Length"), 10, 64); err == nil {
		in.length = n
	}
	return nil
}

func (h *storageHandler) upload(ctx context.Context, in *StorageUploadInput) (*StorageEntryOutput, error) {
	p, err := cleanPath(in.Path)
	if err != nil {
		return nil, err
	}
	if p == "/" {
		return nil, huma.Error422UnprocessableEntity("Give the file a name")
	}
	out := &StorageEntryOutput{}
	started := false
	err = h.withFS(ctx, in.ID, func(row sqlc.Storage, f storage.FS) error {
		if started {
			// The body is half read; a retry can't send it again.
			return huma.Error502BadGateway("Lost the connection to the storage during the upload")
		}
		if err := writable(row); err != nil {
			return err
		}
		e, ok, err := exists(ctx, f, p)
		if err != nil {
			return storageProblem(p, err)
		}
		if ok && e.Dir {
			return huma.Error409Conflict("A folder named " + path.Base(p) + " is already there")
		}
		if ok && !in.Overwrite {
			return huma.Error409Conflict(path.Base(p)+" already exists", &huma.ErrorDetail{Location: "query.path", Message: "exists", Value: p})
		}
		started = true
		body := in.body
		if in.length >= 0 {
			body = io.LimitReader(in.body, in.length)
		}
		if err := f.Put(ctx, p, body, in.length); err != nil {
			if ctx.Err() != nil {
				return huma.NewError(499, "Upload cancelled")
			}
			return storageProblem(p, err)
		}
		e, err = f.Stat(ctx, p)
		if err == nil && in.length >= 0 && e.Size != in.length {
			_ = f.Remove(context.WithoutCancel(ctx), p)
			return huma.Error502BadGateway("The upload was cut short")
		}
		out.Body = toEntry(e)
		return storageProblem(p, err)
	})
	return out, err
}

// ---- Transfers between storages and servers ----

type StorageTransferEnd struct {
	StorageID *string `json:"storage_id,omitempty" format:"uuid"`
	ServerID  *string `json:"server_id,omitempty" format:"uuid"`
}

type StorageTransferBody struct {
	Source struct {
		StorageTransferEnd
		Paths []string `json:"paths" minItems:"1" maxItems:"1000"`
	} `json:"source"`
	Destination struct {
		StorageTransferEnd
		Path string `json:"path" doc:"Folder to put them in"`
	} `json:"destination"`
	Move      bool `json:"move,omitempty" doc:"Delete each source once it's copied"`
	Overwrite bool `json:"overwrite,omitempty" doc:"Replace what's already in the destination"`
}

// place is one end of a transfer, opened.
type place struct {
	fs       storage.FS
	readOnly bool
	name     string
	// resolve turns a request path into one fs understands.
	resolve func(string) (string, error)
}

// with opens one end of a transfer for the duration of fn.
func (h *storageHandler) with(ctx context.Context, end StorageTransferEnd, fn func(place) error) error {
	switch {
	case end.StorageID != nil && *end.StorageID != "" && (end.ServerID == nil || *end.ServerID == ""):
		return h.withFS(ctx, *end.StorageID, func(row sqlc.Storage, f storage.FS) error {
			return fn(place{fs: f, readOnly: row.ReadOnly, name: row.Name, resolve: cleanPath})
		})
	case end.ServerID != nil && *end.ServerID != "" && (end.StorageID == nil || *end.StorageID == ""):
		s, err := h.servers.get(ctx, *end.ServerID)
		if err != nil {
			return err
		}
		return h.servers.withSFTP(ctx, *end.ServerID, func(_ *sshpool.Conn, sc *sftp.Client) error {
			return fn(place{fs: storage.NewSFTP(sc), name: s.Name, resolve: func(p string) (string, error) {
				_, abs, err := resolvePath(sc, p)
				return abs, err
			}})
		})
	}
	return huma.Error422UnprocessableEntity("Each end needs exactly one of storage_id or server_id")
}

// transferPlan is a checked transfer with both ends open.
type transferPlan struct {
	src, dst place
	dest     string
	mkdir    bool        // dest doesn't exist yet
	pairs    [][2]string // source path → path in dest
}

func (p transferPlan) title(move bool) string {
	verb := "Copy"
	if move {
		verb = "Move"
	}
	what := path.Base(p.pairs[0][0])
	if len(p.pairs) > 1 {
		what = strconv.Itoa(len(p.pairs)) + " items"
	}
	return fmt.Sprintf("%s %s from %s to %s", verb, what, p.src.name, p.dst.name)
}

// plan opens both ends, checks the request and calls fn while they're open.
// It changes nothing.
func (h *storageHandler) plan(ctx context.Context, b StorageTransferBody, fn func(transferPlan) error) error {
	return h.with(ctx, b.Source.StorageTransferEnd, func(src place) error {
		if b.Move && src.readOnly {
			return huma.Error403Forbidden(src.name + " is read-only, so files can't be moved out of it. Copy them instead.")
		}
		return h.with(ctx, b.Destination.StorageTransferEnd, func(dst place) error {
			if dst.readOnly {
				return huma.Error403Forbidden(dst.name + " is read-only in Morcheh")
			}
			dest, err := dst.resolve(b.Destination.Path)
			if err != nil {
				return err
			}
			p := transferPlan{src: src, dst: dst, dest: dest}
			if e, ok, err := exists(ctx, dst.fs, dest); err != nil {
				return storageProblem(dest, err)
			} else if !ok {
				p.mkdir = true
			} else if !e.Dir {
				return huma.Error422UnprocessableEntity("Not a folder: " + dest)
			}
			var clashes []string
			for _, raw := range b.Source.Paths {
				sp, err := src.resolve(raw)
				if err != nil {
					return err
				}
				if sp == "/" {
					return huma.Error422UnprocessableEntity("Pick files or folders, not the top folder")
				}
				target := path.Join(dest, path.Base(sp))
				if src.fs == dst.fs && storage.Within(target, sp) {
					return huma.Error422UnprocessableEntity("Can't put " + path.Base(sp) + " inside itself")
				}
				if !p.mkdir {
					if _, ok, err := exists(ctx, dst.fs, target); err != nil {
						return storageProblem(target, err)
					} else if ok && !b.Overwrite {
						clashes = append(clashes, path.Base(sp))
					}
				}
				p.pairs = append(p.pairs, [2]string{sp, target})
			}
			if len(clashes) > 0 {
				return huma.Error409Conflict("Already in " + dest + ": " + strings.Join(clashes, ", "))
			}
			return fn(p)
		})
	})
}

// transfer checks the request and queues it as a job, so the copy goes on
// after the browser leaves and shows its progress.
func (h *storageHandler) transfer(ctx context.Context, in *struct{ Body StorageTransferBody }) (*JobOutput, error) {
	b := in.Body
	var spec jobs.Spec
	err := h.plan(ctx, b, func(p transferPlan) error {
		target := &JobPlace{Path: p.dest, Name: p.dst.name}
		if id := b.Destination.ServerID; id != nil && *id != "" {
			target.ServerID = *id
		} else {
			target.StorageID = *b.Destination.StorageID
		}
		spec = jobs.Spec{
			Kind: "transfer", Title: p.title(b.Move), Params: b, Target: target,
			Refs: placeRefs(deref(b.Source.ServerID), deref(b.Source.StorageID),
				deref(b.Destination.ServerID), deref(b.Destination.StorageID)),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return submit(ctx, h.servers.jobs, spec)
}

// runTransfer is the transfer job: it checks again (things may have changed
// while it was queued), counts what's to copy, then copies it.
func (h *storageHandler) runTransfer(ctx context.Context, t *jobs.Task) (any, error) {
	var b StorageTransferBody
	if err := t.Decode(&b); err != nil {
		return nil, err
	}
	var out StorageTransferResult
	err := h.plan(ctx, b, func(p transferPlan) error {
		src, dst := p.src, p.dst
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Counting files" })
		var files int
		var bytes int64
		for _, pr := range p.pairs {
			n, size, err := storage.Measure(ctx, src.fs, pr[0])
			if err != nil {
				return storageProblem(pr[0], err)
			}
			files, bytes = files+n, bytes+size
		}
		phase := "Copying"
		if b.Move {
			phase = "Moving"
		}
		t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Total, pr.ItemsTotal = phase, bytes, files })
		t.Logf("%s %d files (%s) from %s to %s:%s", phase, files, humanBytes(bytes), src.name, dst.name, p.dest)

		if p.mkdir {
			if err := dst.fs.Mkdir(ctx, p.dest); err != nil {
				return storageProblem(p.dest, err)
			}
		}
		var prog storage.Progress
		prog.OnBytes = t.Add
		for _, pr := range p.pairs {
			base := path.Dir(pr[0])
			prog.OnFile = func(f string) {
				done := prog.Files
				t.Update(func(p *jobs.Progress) {
					p.Current = strings.TrimPrefix(strings.TrimPrefix(f, base), "/")
					p.Items = done
				})
			}
			if b.Overwrite {
				if e, ok, _ := exists(ctx, dst.fs, pr[1]); ok && e.Dir {
					if err := dst.fs.Remove(ctx, pr[1]); err != nil {
						return storageProblem(pr[1], err)
					}
				}
			}
			if err := storage.CopyTree(ctx, src.fs, pr[0], dst.fs, pr[1], &prog); err != nil {
				return storageProblem(pr[0], fmt.Errorf("%s → %s: %w", src.name, dst.name, err))
			}
			t.Logf("%s → %s", pr[0], pr[1])
			if b.Move {
				if err := src.fs.Remove(ctx, pr[0]); err != nil {
					return storageProblem(pr[0], err)
				}
				t.Logf("Removed %s from %s", pr[0], src.name)
			}
		}
		t.Update(func(p *jobs.Progress) { p.Items = prog.Files })
		out = StorageTransferResult{Files: prog.Files, Bytes: prog.Bytes}
		return nil
	})
	return out, err
}

// ---- Copy & move inside one storage ----

// submitSameStorage checks a copy or move at once and queues it.
func (h *storageHandler) submitSameStorage(ctx context.Context, id, kind string, b StorageMoveBody) (*JobOutput, error) {
	copying := kind == "storage-copy"
	var name, dest string
	var names []string
	err := h.withFS(ctx, id, func(row sqlc.Storage, f storage.FS) error {
		if err := writable(row); err != nil {
			return err
		}
		pairs, err := planStorageTransfer(ctx, f, b.Paths, b.Destination, copying)
		if err != nil {
			return err
		}
		if len(pairs) == 0 {
			return huma.Error422UnprocessableEntity("Already in that folder")
		}
		name, dest = row.Name, path.Dir(pairs[0][1])
		names = names[:0]
		for _, pr := range pairs {
			names = append(names, path.Base(pr[0]))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	verb := "Move "
	if copying {
		verb = "Copy "
	}
	b.Destination = dest
	return submit(ctx, h.servers.jobs, jobs.Spec{
		Kind: kind, Title: verb + what(names) + " to " + dest, Refs: placeRefs(id),
		Params: sameStorageParams{id, b},
		Target: &JobPlace{StorageID: id, Path: dest, Name: name},
		Quick:  !copying,
	})
}

func (h *storageHandler) runStorageMove(ctx context.Context, t *jobs.Task) (any, error) {
	var p sameStorageParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	var started bool
	return nil, h.withFS(ctx, p.StorageID, func(row sqlc.Storage, f storage.FS) error {
		if started {
			return errLostPartWay
		}
		if err := writable(row); err != nil {
			return err
		}
		pairs, err := planStorageTransfer(ctx, f, p.Paths, p.Destination, false)
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
			if err := f.Rename(ctx, pair[0], pair[1]); err != nil {
				return storageProblem(pair[0], err)
			}
			t.Logf("%s → %s", pair[0], pair[1])
			t.Update(func(pr *jobs.Progress) { pr.Items++ })
		}
		return nil
	})
}

func (h *storageHandler) runStorageCopy(ctx context.Context, t *jobs.Task) (any, error) {
	var p sameStorageParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	var out StorageTransferResult
	var started bool
	err := h.withFS(ctx, p.StorageID, func(row sqlc.Storage, f storage.FS) error {
		if started {
			return errLostPartWay
		}
		if err := writable(row); err != nil {
			return err
		}
		pairs, err := planStorageTransfer(ctx, f, p.Paths, p.Destination, true)
		if err != nil {
			return err
		}
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Counting files" })
		var files int
		var bytes int64
		for _, pair := range pairs {
			n, size, err := storage.Measure(ctx, f, pair[0])
			if err != nil {
				return storageProblem(pair[0], err)
			}
			files, bytes = files+n, bytes+size
		}
		t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Total, pr.ItemsTotal = "Copying", bytes, files })
		t.Logf("Copying %d files (%s) to %s", files, humanBytes(bytes), p.Destination)
		started = true
		var prog storage.Progress
		prog.OnBytes = t.Add
		for _, pair := range pairs {
			// The clean-up below must only ever remove what this copy made.
			if _, ok, err := exists(ctx, f, pair[1]); err != nil {
				return storageProblem(pair[1], err)
			} else if ok {
				return huma.Error409Conflict(path.Base(pair[1]) + " already exists")
			}
			base := path.Dir(pair[0])
			prog.OnFile = func(file string) {
				done := prog.Files
				t.Update(func(pr *jobs.Progress) {
					pr.Current = strings.TrimPrefix(strings.TrimPrefix(file, base), "/")
					pr.Items = done
				})
			}
			if err := storage.CopyTree(ctx, f, pair[0], f, pair[1], &prog); err != nil {
				rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
				defer cancel()
				if rerr := f.Remove(rctx, pair[1]); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
					t.Logf("Couldn't remove the unfinished %s: %v", pair[1], rerr)
				} else {
					t.Logf("Removed the unfinished %s", pair[1])
				}
				return storageProblem(pair[0], err)
			}
			t.Logf("%s → %s", pair[0], pair[1])
		}
		t.Update(func(pr *jobs.Progress) { pr.Items = prog.Files })
		out = StorageTransferResult{Files: prog.Files, Bytes: prog.Bytes}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
