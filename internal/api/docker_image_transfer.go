package api

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/docker"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/storage"
)

// Moving images without a registry: `docker save` streamed (gzip) into a
// Storage, a saved file streamed back into `docker load`, or one server's
// save piped straight into another's load. Nothing touches either server's
// disk on the way.

const (
	dockerImageExportKind = "docker-image-export"
	dockerImageImportKind = "docker-image-import"
	dockerImageCopyKind   = "docker-image-copy"
	defaultImageFolder    = "/backups/docker-images"
)

type DockerImageExportBody struct {
	StorageID string `json:"storage_id" format:"uuid"`
	Folder    string `json:"folder,omitempty" maxLength:"500" doc:"Folder on the storage; the file goes in <folder>/<server>/. Default /backups/docker-images"`
}

type DockerImageImportBody struct {
	StorageID string `json:"storage_id" format:"uuid"`
	Path      string `json:"path" minLength:"1" maxLength:"4096" doc:"A file made by docker save (.tar, or .tar.gz)"`
}

type DockerImageCopyBody struct {
	ServerIDs []string `json:"server_ids" minItems:"1" maxItems:"20" doc:"Servers to copy it to"`
}

type imageExportParams struct {
	ServerID  string `json:"server_id"`
	Image     string `json:"image"`
	StorageID string `json:"storage_id"`
	Folder    string `json:"folder"`
}

type imageImportParams struct {
	ServerID  string `json:"server_id"`
	StorageID string `json:"storage_id"`
	Path      string `json:"path"`
}

type imageCopyParams struct {
	ServerID  string   `json:"server_id"`
	Image     string   `json:"image"`
	ServerIDs []string `json:"server_ids"`
}

type DockerImageExportResult struct {
	StorageID string   `json:"storage_id"`
	Path      string   `json:"path"`
	Size      int64    `json:"size" doc:"Bytes, compressed"`
	SHA256    string   `json:"sha256"`
	Tags      []string `json:"tags"`
}

type DockerImageCopyResult struct {
	Server string `json:"server"`
	Name   string `json:"name"`
	Error  string `json:"error,omitempty"`
}

// imageNames is what to save: every tag (so a load brings them back), or the
// id when the image has none.
func imageNames(im docker.ImageInspect) []string {
	var names []string
	for _, t := range im.RepoTags {
		if t != "" && t != "<none>:<none>" {
			names = append(names, t)
		}
	}
	if len(names) == 0 {
		return []string{im.ID}
	}
	return names
}

func imageFile(folder, server string, im docker.ImageInspect, at time.Time) string {
	folder = storage.Clean(cmpOr(strings.TrimSpace(folder), defaultImageFolder))
	name := strings.TrimPrefix(im.ID, "sha256:")
	if len(name) > 12 {
		name = name[:12]
	}
	if names := imageNames(im); names[0] != im.ID {
		name = slugPart(strings.NewReplacer("/", "-", ":", "-").Replace(names[0]))
	}
	return path.Join(folder, slugPart(server), name+"-"+at.UTC().Format("20060102-150405")+".tar.gz")
}

// withEngine runs fn on the server's engine over one held connection, never
// retried: a stream can't be replayed.
func (h *serverHandler) withEngine(ctx context.Context, id string, fn func(e *dockerEngine) error) error {
	c, err := h.conn(ctx, id)
	if err != nil {
		return err
	}
	return dockerProblem(hold(c, func() error {
		e, err := h.engine(ctx, id, c)
		if err != nil {
			return err
		}
		return fn(e)
	}))
}

func (st *storageHandler) exportImage(ctx context.Context, t *jobs.Task, p imageExportParams) (any, error) {
	h := st.servers
	srv, err := h.get(ctx, p.ServerID)
	if err != nil {
		return nil, err
	}
	stID, err := uuid.Parse(p.StorageID)
	if err != nil {
		return nil, err
	}
	row, err := st.q.GetStorage(ctx, stID)
	if err != nil {
		if isNotFound(err) {
			return nil, errors.New("The storage was removed.")
		}
		return nil, err
	}
	var res DockerImageExportResult
	err = h.withEngine(ctx, p.ServerID, func(e *dockerEngine) error {
		im, err := e.client.InspectImage(ctx, p.Image)
		if err != nil {
			return err
		}
		names := imageNames(im)
		file := imageFile(p.Folder, srv.Name, im, time.Now())
		c, err := st.acquire(ctx, row)
		if err != nil {
			return fmt.Errorf("%s: %s", row.Name, problemText(err))
		}
		defer st.release(c)
		if err := c.fs.Mkdir(ctx, path.Dir(file)); err != nil {
			return fmt.Errorf("%s: %s", row.Name, problemText(err))
		}
		t.Update(func(pg *jobs.Progress) { pg.Phase, pg.Current, pg.Total = "Saving "+names[0], file, im.Size })
		end := h.dockerLog(ctx, p.ServerID, e, "docker save "+strings.Join(names, " ")+" | gzip > "+row.Name+":"+file)
		r, err := e.client.Save(ctx, names...)
		if err != nil {
			end(err)
			return err
		}
		defer r.Close()

		run, cancel := context.WithCancel(ctx)
		defer cancel()
		pr, pw := io.Pipe()
		done := make(chan error, 1)
		go func() {
			err := c.fs.Put(run, file, pr, -1)
			_ = pr.CloseWithError(errors.New("the storage stopped reading"))
			done <- err
		}()
		out := &sink{w: pw, hash: sha256.New(), t: nil}
		zw, _ := gzip.NewWriterLevel(countWriter{out}, gzip.BestSpeed)
		_, copyErr := io.Copy(zw, &readCounter{r: r, t: t})
		if copyErr == nil {
			copyErr = zw.Close()
		}
		if copyErr != nil {
			_ = pw.CloseWithError(copyErr)
		} else {
			_ = pw.Close()
		}
		putErr := <-done
		if copyErr == nil && putErr != nil {
			copyErr = fmt.Errorf("%s: %s", row.Name, problemText(putErr))
		}
		if copyErr == nil {
			if fe, err := c.fs.Stat(ctx, file); err != nil {
				copyErr = fmt.Errorf("%s: %s", row.Name, problemText(err))
			} else if fe.Size != out.n {
				copyErr = fmt.Errorf("%s holds %d bytes of the %d sent.", row.Name, fe.Size, out.n)
			}
		}
		end(copyErr)
		if copyErr != nil {
			removeQuietly(context.WithoutCancel(ctx), c.fs, file)
			return copyErr
		}
		res = DockerImageExportResult{StorageID: row.ID.String(), Path: file, Size: out.n, SHA256: hex.EncodeToString(out.hash.Sum(nil)), Tags: names}
		t.Logf("Saved %s to %s on %s (%s).", strings.Join(names, ", "), file, row.Name, humanBytes(out.n))
		return nil
	})
	if err != nil {
		return nil, jobError(err)
	}
	return res, nil
}

// countWriter hides the sink's job progress: the export counts what it
// reads from the engine, not the compressed bytes.
type countWriter struct{ s *sink }

func (w countWriter) Write(p []byte) (int, error) {
	n, err := w.s.w.Write(p)
	w.s.hash.Write(p[:n])
	w.s.n += int64(n)
	return n, err
}

func (st *storageHandler) importImage(ctx context.Context, t *jobs.Task, p imageImportParams) (any, error) {
	h := st.servers
	stID, err := uuid.Parse(p.StorageID)
	if err != nil {
		return nil, err
	}
	row, err := st.q.GetStorage(ctx, stID)
	if err != nil {
		if isNotFound(err) {
			return nil, errors.New("The storage was removed.")
		}
		return nil, err
	}
	c, err := st.acquire(ctx, row)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", row.Name, problemText(err))
	}
	defer st.release(c)
	f, err := c.fs.Open(ctx, p.Path)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", row.Name, problemText(err))
	}
	defer f.Close()
	t.Update(func(pg *jobs.Progress) { pg.Phase, pg.Current, pg.Total = "Loading", p.Path, f.Entry().Size })
	var loaded []string
	err = h.withEngine(ctx, p.ServerID, func(e *dockerEngine) error {
		end := h.dockerLog(ctx, p.ServerID, e, "docker load < "+row.Name+":"+p.Path)
		var err error
		loaded, err = e.client.Load(ctx, &readCounter{r: f, t: t})
		end(err)
		return err
	})
	if err != nil {
		return nil, jobError(err)
	}
	for _, l := range loaded {
		t.Logf("%s", l)
	}
	if len(loaded) == 0 {
		t.Logf("Docker loaded the file but named no image.")
	}
	return map[string]any{"loaded": nonNil(loaded)}, nil
}

func (h *serverHandler) copyImage(ctx context.Context, t *jobs.Task, p imageCopyParams) (any, error) {
	var im docker.ImageInspect
	if err := h.withDocker(ctx, p.ServerID, func(e *dockerEngine) error {
		var err error
		im, err = e.client.InspectImage(ctx, p.Image)
		return err
	}); err != nil {
		return nil, jobError(err)
	}
	names := imageNames(im)
	t.Update(func(pg *jobs.Progress) {
		pg.Total, pg.ItemsTotal = im.Size*int64(len(p.ServerIDs)), len(p.ServerIDs)
	})
	results := make([]DockerImageCopyResult, 0, len(p.ServerIDs))
	failed := 0
	for i, target := range p.ServerIDs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		dst, err := h.get(ctx, target)
		name := target
		if err == nil {
			name = dst.Name
		}
		t.Update(func(pg *jobs.Progress) { pg.Phase, pg.Current, pg.Items = "Copying to "+name, names[0], i })
		if err == nil {
			err = h.copyImageTo(ctx, t, p.ServerID, target, names)
		}
		r := DockerImageCopyResult{Server: target, Name: name}
		if err != nil {
			failed++
			r.Error = problemText(err)
			t.Logf("%s: %s", name, r.Error)
		} else {
			t.Logf("%s: copied %s.", name, strings.Join(names, ", "))
		}
		results = append(results, r)
	}
	t.Update(func(pg *jobs.Progress) { pg.Items = len(p.ServerIDs) })
	if failed == len(results) {
		return nil, errors.New(results[0].Error)
	}
	if failed > 0 {
		t.Logf("%d of %d servers didn't get it.", failed, len(results))
	}
	return map[string]any{"servers": results}, nil
}

// copyImageTo pipes the source's save into the target's load.
func (h *serverHandler) copyImageTo(ctx context.Context, t *jobs.Task, from, to string, names []string) error {
	return h.withEngine(ctx, from, func(src *dockerEngine) error {
		r, err := src.client.Save(ctx, names...)
		if err != nil {
			return err
		}
		defer r.Close()
		return h.withEngine(ctx, to, func(dst *dockerEngine) error {
			end := h.dockerLog(ctx, to, dst, "docker load (from another server: "+strings.Join(names, " ")+")")
			_, err := dst.client.Load(ctx, &readCounter{r: r, t: t})
			end(err)
			return err
		})
	})
}

func registerDockerImageTransfer(api huma.API, st *storageHandler) {
	h := st.servers
	tags := []string{"Containers"}

	huma.Register(api, huma.Operation{
		OperationID:   "export-docker-image",
		Method:        http.MethodPost,
		Path:          "/servers/{id}/docker/images/{image}/export",
		Summary:       "Save an image to a storage",
		Description:   "Streams `docker save` (with every tag of the image), gzip-compressed, into <folder>/<server>/ on the storage, as a job (kind `docker-image-export`). Needs Engineer on the storage too.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		DockerImagePath
		Body DockerImageExportBody
	}) (*JobOutput, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		im, err := h.imageIdentity(ctx, in.ID, in.Image)
		if err != nil {
			return nil, err
		}
		row, err := st.writableStorage(ctx, s.WorkspaceID, in.Body.StorageID, "body.storage_id")
		if err != nil {
			return nil, err
		}
		folder := strings.TrimSpace(in.Body.Folder)
		if strings.ContainsRune(folder, 0) {
			return nil, fieldError("body.folder", "Not a folder.", folder)
		}
		dir := path.Join(storage.Clean(cmpOr(folder, defaultImageFolder)), slugPart(s.Name))
		return submit(ctx, h.jobs, jobs.Spec{
			Kind: dockerImageExportKind, Title: "Save " + imageNames(im)[0] + " from " + s.Name + " to " + row.Name,
			Params: imageExportParams{ServerID: in.ID, Image: im.ID, StorageID: row.ID.String(), Folder: folder},
			Refs:   placeRefs(in.ID, row.ID.String()), Target: &JobPlace{StorageID: row.ID.String(), Path: dir, Name: row.Name},
		})
	})
	h.jobs.Handle(dockerImageExportKind, func(ctx context.Context, t *jobs.Task) (any, error) {
		var p imageExportParams
		if err := t.Decode(&p); err != nil {
			return nil, err
		}
		return st.exportImage(ctx, t, p)
	})

	huma.Register(api, huma.Operation{
		OperationID:   "import-docker-image",
		Method:        http.MethodPost,
		Path:          "/servers/{id}/docker/images/import",
		Summary:       "Load an image from a file on a storage",
		Description:   "Streams a file made by `docker save` (.tar or .tar.gz) into `docker load`, as a job (kind `docker-image-import`). Needs Operator on the storage.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body DockerImageImportBody
	}) (*JobOutput, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		id, err := uuid.Parse(in.Body.StorageID)
		if err != nil {
			return nil, fieldError("body.storage_id", "Choose a storage.", in.Body.StorageID)
		}
		switch lvl, err := h.authz.storageLevel(ctx, principalOf(ctx).Access, id); {
		case err != nil:
			return nil, internalError(err)
		case lvl == auth.None:
			return nil, fieldError("body.storage_id", "There's no such storage.", in.Body.StorageID)
		case lvl < auth.Operator:
			return nil, forbidden(auth.Operator)
		}
		file := storage.Clean(in.Body.Path)
		if file == "/" || strings.ContainsRune(file, 0) {
			return nil, fieldError("body.path", "Choose a file.", in.Body.Path)
		}
		return submit(ctx, h.jobs, jobs.Spec{
			Kind: dockerImageImportKind, Title: "Load " + path.Base(file) + " on " + s.Name,
			Params: imageImportParams{ServerID: in.ID, StorageID: id.String(), Path: file},
			Refs:   placeRefs(in.ID, id.String()), Target: &JobPlace{ServerID: in.ID, Name: s.Name},
		})
	})
	h.jobs.Handle(dockerImageImportKind, func(ctx context.Context, t *jobs.Task) (any, error) {
		var p imageImportParams
		if err := t.Decode(&p); err != nil {
			return nil, err
		}
		return st.importImage(ctx, t, p)
	})

	huma.Register(api, huma.Operation{
		OperationID:   "copy-docker-image",
		Method:        http.MethodPost,
		Path:          "/servers/{id}/docker/images/{image}/copy",
		Summary:       "Copy an image to other servers",
		Description:   "Pipes `docker save` on this server into `docker load` on each server in turn, no registry needed, as a job (kind `docker-image-copy`). Needs Engineer on every server.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		DockerImagePath
		Body DockerImageCopyBody
	}) (*JobOutput, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		var ids []uuid.UUID
		var targets []string
		for i, raw := range in.Body.ServerIDs {
			id, err := uuid.Parse(raw)
			if err != nil {
				return nil, fieldError(fmt.Sprintf("body.server_ids[%d]", i), "Not a server.", raw)
			}
			if id == s.ID {
				return nil, fieldError(fmt.Sprintf("body.server_ids[%d]", i), "It's already on this server.", raw)
			}
			if !containsUUID(ids, id) {
				ids, targets = append(ids, id), append(targets, id.String())
			}
		}
		if _, err := h.authz.requireServers(ctx, ids, auth.Engineer); err != nil {
			return nil, err
		}
		im, err := h.imageIdentity(ctx, in.ID, in.Image)
		if err != nil {
			return nil, err
		}
		title := "Copy " + imageNames(im)[0] + " from " + s.Name + " to "
		if len(targets) == 1 {
			if d, err := h.get(ctx, targets[0]); err == nil {
				title += d.Name
			}
		} else {
			title += plural(len(targets), "server")
		}
		return submit(ctx, h.jobs, jobs.Spec{
			Kind: dockerImageCopyKind, Title: title,
			Params: imageCopyParams{ServerID: in.ID, Image: im.ID, ServerIDs: targets},
			Refs:   placeRefs(append([]string{in.ID}, targets...)...), Target: &JobPlace{ServerID: in.ID, Name: s.Name},
		})
	})
	h.jobs.Handle(dockerImageCopyKind, func(ctx context.Context, t *jobs.Task) (any, error) {
		var p imageCopyParams
		if err := t.Decode(&p); err != nil {
			return nil, err
		}
		return h.copyImage(ctx, t, p)
	})
}

func containsUUID(list []uuid.UUID, id uuid.UUID) bool {
	for _, x := range list {
		if x == id {
			return true
		}
	}
	return false
}
