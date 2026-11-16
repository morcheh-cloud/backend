package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morche/backend/internal/docker"
)

// Layer explorer: the image is read with `docker save` (streamed, nothing
// written to the server's disk), every layer's file list kept in memory for
// a while, and the panel browses what each layer added, changed or removed,
// and what space the hidden copies waste.

const (
	layerScanTTL  = 15 * time.Minute
	layerScanKeep = 6
	layerTopPaths = 40
	layerMaxItems = 3000
)

type layerScan struct {
	mu      sync.Mutex
	state   string // reading, ready, failed
	read    int64
	total   int64
	err     string
	img     *docker.SavedImage
	sum     docker.Summary
	started time.Time
	used    time.Time
}

func (s *layerScan) Write(p []byte) (int, error) {
	s.mu.Lock()
	s.read += int64(len(p))
	s.mu.Unlock()
	return len(p), nil
}

var layerScans = struct {
	sync.Mutex
	m map[string]*layerScan
}{m: map[string]*layerScan{}}

// layerScanFor finds or starts the scan of one image.
func (h *serverHandler) layerScanFor(serverID, imageID string, size int64, refresh bool) *layerScan {
	key := serverID + "/" + imageID
	layerScans.Lock()
	defer layerScans.Unlock()
	now := time.Now()
	for k, s := range layerScans.m {
		s.mu.Lock()
		stale := s.state != "reading" && now.Sub(s.used) > layerScanTTL
		s.mu.Unlock()
		if stale {
			delete(layerScans.m, k)
		}
	}
	if s, ok := layerScans.m[key]; ok {
		s.mu.Lock()
		again := refresh && s.state != "reading" || s.state == "failed" && now.Sub(s.used) > 30*time.Second
		s.used = now
		s.mu.Unlock()
		if !again {
			return s
		}
	}
	// Keep the newest few: file lists of big images take real memory.
	if len(layerScans.m) >= layerScanKeep {
		var oldest string
		var at time.Time
		for k, s := range layerScans.m {
			s.mu.Lock()
			if s.state != "reading" && (oldest == "" || s.used.Before(at)) {
				oldest, at = k, s.used
			}
			s.mu.Unlock()
		}
		if oldest != "" {
			delete(layerScans.m, oldest)
		}
	}
	s := &layerScan{state: "reading", total: size, started: now, used: now}
	layerScans.m[key] = s
	go h.runLayerScan(s, serverID, imageID)
	return s
}

func (h *serverHandler) runLayerScan(s *layerScan, serverID, imageID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	var img *docker.SavedImage
	err := func() error {
		c, err := h.conn(ctx, serverID)
		if err != nil {
			return err
		}
		return hold(c, func() error {
			e, err := h.engine(ctx, serverID, c)
			if err != nil {
				return err
			}
			r, err := e.client.Save(ctx, imageID)
			if err != nil {
				return err
			}
			defer r.Close()
			img, err = docker.ReadSaved(io.TeeReader(r, s))
			if err == nil {
				_, _ = io.Copy(io.Discard, r)
			}
			return err
		})
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.state, s.err = "failed", problemText(dockerProblem(err))
		slog.Info("docker: layer scan", "server", serverID, "image", imageID, "error", err)
		return
	}
	s.img, s.sum, s.state = img, img.Summarize(layerTopPaths), "ready"
}

type DockerScanLayer struct {
	Index     int    `json:"index"`
	DiffID    string `json:"diff_id"`
	CreatedBy string `json:"created_by" doc:"The build step that made it"`
	Created   string `json:"created,omitempty"`
	Comment   string `json:"comment,omitempty"`
	Size      int64  `json:"size" doc:"Bytes of its files"`
	Files     int    `json:"files"`
	Added     int    `json:"added"`
	Modified  int    `json:"modified" doc:"Files that replace a copy from a lower layer"`
	Removed   int    `json:"removed" doc:"Files it deletes"`
	Wasted    int64  `json:"wasted" doc:"Bytes of lower copies it replaces or deletes"`
}

type DockerWastedPath struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes" doc:"Bytes of the copies later layers hide"`
	Copies int    `json:"copies"`
	Layers []int  `json:"layers" doc:"Layers holding a copy, oldest first"`
}

type DockerLayerScan struct {
	State      string             `json:"state" enum:"reading,ready,failed"`
	Read       int64              `json:"read" doc:"Bytes of the saved image read so far"`
	Expected   int64              `json:"expected" doc:"About how many bytes it will read (the image's size)"`
	Error      string             `json:"error,omitempty"`
	ImageID    string             `json:"image_id"`
	Seconds    float64            `json:"seconds" doc:"How long reading took (so far)"`
	Layers     []DockerScanLayer  `json:"layers"`
	Steps      int                `json:"steps" doc:"Build steps, the ones that changed no file included"`
	Total      int64              `json:"total" doc:"Bytes of every layer's files"`
	Final      int64              `json:"final" doc:"Bytes a container sees"`
	Wasted     int64              `json:"wasted"`
	Efficiency float64            `json:"efficiency" doc:"final / total, 0–1"`
	Files      int                `json:"files" doc:"Files a container sees"`
	Truncated  bool               `json:"truncated" doc:"The image has more files than are listed"`
	Top        []DockerWastedPath `json:"top"`
}

type DockerLayerEntry struct {
	Name    string `json:"name"`
	Kind    string `json:"kind" enum:"file,dir,link,hardlink"`
	Size    int64  `json:"size" doc:"A folder: everything under it"`
	Files   int    `json:"files"`
	Layer   int    `json:"layer" doc:"The layer it last changed in"`
	Change  string `json:"change,omitempty" enum:"added,modified,removed" doc:"What the chosen layer did to it"`
	Changed int    `json:"changed" doc:"A folder: paths under it the chosen layer changed"`
}

type DockerLayerFiles struct {
	Layer     int                `json:"layer"`
	Path      string             `json:"path"`
	Items     []DockerLayerEntry `json:"items"`
	Truncated bool               `json:"truncated"`
}

func (s *layerScan) view(imageID string) DockerLayerScan {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := DockerLayerScan{
		State: s.state, Read: s.read, Expected: s.total, Error: s.err, ImageID: imageID,
		Layers: []DockerScanLayer{}, Top: []DockerWastedPath{},
	}
	v.Seconds = time.Since(s.started).Seconds()
	if s.img == nil {
		return v
	}
	for i, l := range s.img.Layers {
		st := s.sum.Layers[i]
		v.Layers = append(v.Layers, DockerScanLayer{
			Index: i, DiffID: l.DiffID, CreatedBy: l.CreatedBy, Created: l.Created, Comment: l.Comment,
			Size: l.Size, Files: st.Files, Added: st.Added, Modified: st.Modified, Removed: st.Removed, Wasted: st.Wasted,
		})
	}
	v.Steps, v.Total, v.Final, v.Wasted = s.img.Steps, s.sum.Total, s.sum.Final, s.sum.Wasted
	v.Efficiency, v.Files, v.Truncated = s.sum.Efficiency, s.sum.Files, s.img.Truncated
	for _, w := range s.sum.Top {
		v.Top = append(v.Top, DockerWastedPath{Path: w.Path, Bytes: w.Bytes, Copies: w.Copies, Layers: w.Layers})
	}
	return v
}

var layerKinds = map[byte]string{
	docker.KindFile: "file", docker.KindDir: "dir", docker.KindLink: "link", docker.KindHard: "hardlink",
}

var layerChanges = map[byte]string{'a': "added", 'm': "modified", 'r': "removed"}

// imageIdentity resolves an id or reference to the image's id and size.
func (h *serverHandler) imageIdentity(ctx context.Context, serverID, image string) (docker.ImageInspect, error) {
	var im docker.ImageInspect
	err := h.withDocker(ctx, serverID, func(e *dockerEngine) error {
		var err error
		im, err = e.client.InspectImage(ctx, image)
		return err
	})
	return im, err
}

func registerDockerImageLayers(api huma.API, h *serverHandler) {
	tags := []string{"Containers"}
	base := "/servers/{id}/docker/images/{image}/layers"

	huma.Register(api, huma.Operation{
		OperationID: "get-docker-image-layers",
		Method:      http.MethodGet,
		Path:        base,
		Summary:     "What each layer of an image holds, and the space it wastes",
		Description: "The first call starts reading the image (`docker save`, streamed) and answers `reading` with how far it got; ask again until `ready`. Results are kept 15 minutes; `refresh` reads it again.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerImagePath
		Refresh bool `query:"refresh"`
	}) (*struct{ Body DockerLayerScan }, error) {
		if _, err := h.get(ctx, in.ID); err != nil {
			return nil, err
		}
		im, err := h.imageIdentity(ctx, in.ID, in.Image)
		if err != nil {
			return nil, err
		}
		s := h.layerScanFor(in.ID, im.ID, im.Size, in.Refresh)
		return &struct{ Body DockerLayerScan }{Body: s.view(im.ID)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-docker-image-layer-files",
		Method:      http.MethodGet,
		Path:        base + "/files",
		Summary:     "One folder of an image as it looks after a layer",
		Description: "Marks what that layer added, changed or removed; `changes` lists only those. 409 while the image is still being read.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerImagePath
		Layer   int    `query:"layer" minimum:"0"`
		Path    string `query:"path" maxLength:"4096" doc:"Folder; empty = the root"`
		Changes bool   `query:"changes"`
	}) (*struct{ Body DockerLayerFiles }, error) {
		if _, err := h.get(ctx, in.ID); err != nil {
			return nil, err
		}
		im, err := h.imageIdentity(ctx, in.ID, in.Image)
		if err != nil {
			return nil, err
		}
		layerScans.Lock()
		s := layerScans.m[in.ID+"/"+im.ID]
		layerScans.Unlock()
		if s == nil {
			return nil, huma.Error409Conflict("Read the image's layers first.")
		}
		s.mu.Lock()
		img, state := s.img, s.state
		s.used = time.Now()
		s.mu.Unlock()
		if state != "ready" || img == nil {
			return nil, huma.Error409Conflict("The image is still being read.")
		}
		if in.Layer >= len(img.Layers) {
			return nil, fieldError("query.layer", "The image has no such layer.", in.Layer)
		}
		list := img.Tree(in.Layer, in.Path, in.Changes)
		out := &struct{ Body DockerLayerFiles }{}
		out.Body = DockerLayerFiles{Layer: in.Layer, Path: in.Path, Items: make([]DockerLayerEntry, 0, min(len(list), layerMaxItems))}
		if len(list) > layerMaxItems {
			// Keep the biggest when a folder is huge.
			slices.SortStableFunc(list, func(a, b docker.TreeEntry) int { return compareSize(b.Size, a.Size) })
			list, out.Body.Truncated = list[:layerMaxItems], true
		}
		for _, e := range list {
			out.Body.Items = append(out.Body.Items, DockerLayerEntry{
				Name: e.Name, Kind: layerKinds[e.Kind], Size: e.Size, Files: e.Files, Layer: e.Layer,
				Change: layerChanges[e.Change], Changed: e.Changed,
			})
		}
		return out, nil
	})
}

func compareSize(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
