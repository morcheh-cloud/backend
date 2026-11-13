package docker

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// File kinds in a layer.
const (
	KindFile     byte = 'f'
	KindDir      byte = 'd'
	KindLink     byte = 'l' // symbolic link
	KindHard     byte = 'h' // hard link
	KindWhiteout byte = 'w' // the path is removed by this layer
	KindOpaque   byte = 'o' // the folder's lower contents are hidden by this layer
)

// MaxLayerFiles caps how many entries a saved image may hold before the
// reader stops collecting (memory stays bounded on huge images).
const MaxLayerFiles = 600_000

// LayerFile is one entry of a layer's tar, path without a leading "/".
type LayerFile struct {
	Path string
	Size int64
	Kind byte
}

// SavedLayer is one filesystem layer with the build step that made it.
type SavedLayer struct {
	DiffID    string
	CreatedBy string
	Created   string
	Comment   string
	Size      int64 // bytes of regular files
	Files     []LayerFile
}

// SavedImage is what a `docker save` tar holds about one image.
type SavedImage struct {
	Layers    []SavedLayer
	Steps     int  // build steps, layers and the ones that changed no file
	Truncated bool // MaxLayerFiles was reached
}

type savedManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type savedConfig struct {
	History []struct {
		Created    string `json:"created"`
		CreatedBy  string `json:"created_by"`
		Comment    string `json:"comment"`
		EmptyLayer bool   `json:"empty_layer"`
	} `json:"history"`
	RootFS struct {
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

// ReadSaved reads a `docker save` tar (legacy or OCI layout, layers plain,
// gzip or zstd) in one pass and lists every layer's files.
func ReadSaved(r io.Reader) (*SavedImage, error) {
	outer := tar.NewReader(r)
	jsons := map[string][]byte{}
	layers := map[string][]LayerFile{}
	links := map[string]string{}
	count := 0
	truncated := false
	for {
		h, err := outer.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading the saved image: %w", err)
		}
		name := strings.TrimPrefix(path.Clean(h.Name), "./")
		switch h.Typeflag {
		case tar.TypeSymlink:
			links[name] = path.Join(path.Dir(name), h.Linkname)
			continue
		case tar.TypeReg:
		default:
			continue
		}
		br := bufio.NewReaderSize(outer, 64<<10)
		head, _ := br.Peek(512)
		switch {
		case len(head) == 0:
		case looksJSON(head) && h.Size < 16<<20:
			b, err := io.ReadAll(br)
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", name, err)
			}
			jsons[name] = b
		default:
			files, n, cut, err := readLayer(br, head, MaxLayerFiles-count)
			if err != nil {
				return nil, fmt.Errorf("reading layer %s: %w", name, err)
			}
			if files != nil {
				layers[name] = files
				count += n
				truncated = truncated || cut
			}
		}
	}
	raw, ok := jsons["manifest.json"]
	if !ok {
		return nil, errors.New("the saved image has no manifest.json")
	}
	var ms []savedManifest
	if err := json.Unmarshal(raw, &ms); err != nil || len(ms) == 0 {
		return nil, errors.New("the saved image's manifest.json can't be read")
	}
	m := ms[0]
	var cfg savedConfig
	if b, ok := jsons[resolve(links, m.Config)]; ok {
		_ = json.Unmarshal(b, &cfg)
	}
	img := &SavedImage{Steps: len(cfg.History), Truncated: truncated}
	var steps []int // history entries that made a layer
	for i, s := range cfg.History {
		if !s.EmptyLayer {
			steps = append(steps, i)
		}
	}
	for i, name := range m.Layers {
		l := SavedLayer{Files: layers[resolve(links, name)]}
		if i < len(cfg.RootFS.DiffIDs) {
			l.DiffID = cfg.RootFS.DiffIDs[i]
		}
		if i < len(steps) {
			s := cfg.History[steps[i]]
			l.CreatedBy, l.Created, l.Comment = s.CreatedBy, s.Created, s.Comment
		}
		for _, f := range l.Files {
			if f.Kind == KindFile {
				l.Size += f.Size
			}
		}
		img.Layers = append(img.Layers, l)
	}
	return img, nil
}

func resolve(links map[string]string, name string) string {
	name = strings.TrimPrefix(path.Clean(name), "./")
	for range 8 {
		t, ok := links[name]
		if !ok {
			break
		}
		name = t
	}
	return name
}

func looksJSON(b []byte) bool {
	b = bytes.TrimLeft(b, " \t\r\n")
	return len(b) > 0 && (b[0] == '{' || b[0] == '[')
}

func isTar(b []byte) bool {
	if len(b) >= 262 && string(b[257:262]) == "ustar" {
		return true
	}
	return len(b) == 512 && !slices.ContainsFunc(b, func(c byte) bool { return c != 0 })
}

// readLayer lists a layer tar (plain, gzip or zstd). Not a tar = nil files.
func readLayer(br *bufio.Reader, head []byte, room int) ([]LayerFile, int, bool, error) {
	var in io.Reader = br
	switch {
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, 0, false, err
		}
		defer gz.Close()
		in = gz
	case bytes.HasPrefix(head, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		zr, err := zstd.NewReader(br)
		if err != nil {
			return nil, 0, false, err
		}
		defer zr.Close()
		in = zr
	case isTar(head):
	default:
		return nil, 0, false, nil
	}
	tr := tar.NewReader(in)
	files := []LayerFile{}
	cut := false
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, 0, false, err
		}
		if len(files) >= room {
			cut = true
			continue
		}
		p := strings.Trim(path.Clean("/"+h.Name), "/")
		if p == "" {
			continue
		}
		dir, base := path.Split(p)
		dir = strings.TrimSuffix(dir, "/")
		f := LayerFile{Path: p}
		switch {
		case base == ".wh..wh..opq":
			f.Path, f.Kind = dir, KindOpaque
		case strings.HasPrefix(base, ".wh."):
			f.Path, f.Kind = path.Join(dir, strings.TrimPrefix(base, ".wh.")), KindWhiteout
		case h.Typeflag == tar.TypeDir:
			f.Kind = KindDir
		case h.Typeflag == tar.TypeSymlink:
			f.Kind = KindLink
		case h.Typeflag == tar.TypeLink:
			f.Kind = KindHard
		default:
			f.Kind, f.Size = KindFile, h.Size
		}
		files = append(files, f)
	}
	return files, len(files), cut, nil
}

// LayerStat is one layer's numbers in a Summary.
type LayerStat struct {
	Files    int   // entries that aren't folders
	Added    int   // files new in this layer
	Modified int   // files that replace a lower copy
	Removed  int   // files this layer deletes
	Wasted   int64 // bytes of lower copies this layer replaces or deletes
}

// WastedPath is a path whose lower copies take space no one sees.
type WastedPath struct {
	Path   string
	Bytes  int64 // bytes of the copies hidden by later layers
	Copies int   // copies across the layers (the visible one included)
	Layers []int // layers holding a copy, oldest first
}

// Summary is the image-wide view: what each layer did and what's wasted.
type Summary struct {
	Layers     []LayerStat
	Total      int64 // bytes of every layer's files
	Final      int64 // bytes the running container sees
	Wasted     int64 // Total - Final: copies replaced or deleted later
	Efficiency float64
	Files      int // files the running container sees
	Top        []WastedPath
}

type node struct {
	size  int64
	layer int
	kind  byte
}

// Change says what a layer did to a path.
type Change struct {
	Kind byte // 'a' added, 'm' modified, 'r' removed
	Size int64
}

// replay applies the layers 0..upto. visit (optional) is told about every
// hidden lower copy (removed or replaced) and each layer's changes.
func (img *SavedImage) replay(upto int, visit func(layer int, p string, old node, kind byte)) map[string]node {
	state := map[string]node{}
	remove := func(i int, p string, keep bool) {
		n, ok := state[p]
		if !keep && ok {
			delete(state, p)
			if visit != nil && n.kind != KindDir {
				visit(i, p, n, 'r')
			}
		}
		if ok && n.kind != KindDir {
			return // nothing can sit under a file
		}
		prefix := p + "/"
		if p == "" {
			prefix = ""
		}
		for k, n := range state {
			if strings.HasPrefix(k, prefix) {
				delete(state, k)
				if visit != nil && n.kind != KindDir {
					visit(i, k, n, 'r')
				}
			}
		}
	}
	for i, l := range img.Layers {
		if i > upto {
			break
		}
		// Deletions first: a layer's whiteouts hide only what's below it.
		for _, f := range l.Files {
			switch f.Kind {
			case KindOpaque:
				remove(i, f.Path, true)
			case KindWhiteout:
				remove(i, f.Path, false)
			}
		}
		for _, f := range l.Files {
			if f.Kind == KindOpaque || f.Kind == KindWhiteout {
				continue
			}
			old, had := state[f.Path]
			if f.Kind == KindDir && had && old.kind == KindDir {
				continue
			}
			state[f.Path] = node{size: f.Size, layer: i, kind: f.Kind}
			if visit != nil && f.Kind != KindDir {
				if had && old.kind != KindDir {
					visit(i, f.Path, old, 'm')
				} else {
					visit(i, f.Path, node{}, 'a')
				}
			}
		}
	}
	return state
}

// Summarize replays every layer.
func (img *SavedImage) Summarize(top int) Summary {
	s := Summary{Layers: make([]LayerStat, len(img.Layers))}
	waste := map[string]*WastedPath{}
	state := img.replay(len(img.Layers)-1, func(i int, p string, old node, kind byte) {
		st := &s.Layers[i]
		switch kind {
		case 'a':
			st.Added++
			return
		case 'm':
			st.Modified++
		case 'r':
			st.Removed++
		}
		st.Wasted += old.size
		w := waste[p]
		if w == nil {
			w = &WastedPath{Path: p}
			waste[p] = w
		}
		w.Bytes += old.size
		w.Copies++
		w.Layers = append(w.Layers, old.layer)
	})
	for i, l := range img.Layers {
		s.Total += l.Size
		for _, f := range l.Files {
			if f.Kind != KindDir && f.Kind != KindOpaque && f.Kind != KindWhiteout {
				s.Layers[i].Files++
			}
		}
	}
	for _, n := range state {
		if n.kind != KindDir {
			s.Final += n.size
			s.Files++
		}
	}
	s.Wasted = max(s.Total-s.Final, 0)
	s.Efficiency = 1
	if s.Total > 0 {
		s.Efficiency = float64(s.Final) / float64(s.Total)
	}
	list := make([]WastedPath, 0, len(waste))
	for p, w := range waste {
		if w.Bytes == 0 {
			continue
		}
		if n, ok := state[p]; ok && n.kind != KindDir {
			w.Copies++
			w.Layers = append(w.Layers, n.layer)
		}
		list = append(list, *w)
	}
	slices.SortFunc(list, func(a, b WastedPath) int {
		if a.Bytes != b.Bytes {
			if a.Bytes > b.Bytes {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Path, b.Path)
	})
	if len(list) > top {
		list = list[:top]
	}
	s.Top = list
	return s
}

// TreeEntry is one child of a folder as seen after a layer.
type TreeEntry struct {
	Name    string
	Kind    byte  // KindFile, KindDir, KindLink, KindHard
	Size    int64 // a folder: everything under it
	Files   int   // a folder: files under it
	Layer   int   // the layer it last changed in
	Change  byte  // what the asked layer did to it: 'a', 'm', 'r' or 0
	Changed int   // a folder: paths under it the asked layer changed
	live    bool
}

// Tree lists dir ("" = root) as it looks once layers 0..layer are applied,
// marking what that layer changed. changes = only entries it touched.
func (img *SavedImage) Tree(layer int, dir string, changes bool) []TreeEntry {
	dir = strings.Trim(path.Clean("/"+dir), "/")
	marks := map[string]Change{}
	state := img.replay(layer, func(i int, p string, old node, kind byte) {
		if i != layer {
			return
		}
		if kind == 'r' {
			marks[p] = Change{Kind: 'r', Size: old.size}
			return
		}
		if c, ok := marks[p]; ok && c.Kind == 'r' {
			kind = 'm' // deleted then written again by the same layer
		}
		marks[p] = Change{Kind: kind}
	})
	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}
	byName := map[string]*TreeEntry{}
	child := func(p string) (*TreeEntry, bool) {
		if !strings.HasPrefix(p, prefix) || p == dir {
			return nil, false
		}
		rest := p[len(prefix):]
		name, _, deeper := strings.Cut(rest, "/")
		e := byName[name]
		if e == nil {
			e = &TreeEntry{Name: name, Kind: KindDir, Layer: -1}
			byName[name] = e
		}
		return e, deeper
	}
	for p, n := range state {
		e, deeper := child(p)
		if e == nil {
			continue
		}
		e.live = true
		if !deeper {
			e.Kind = n.kind
			e.Layer = max(e.Layer, n.layer)
			if n.kind != KindDir {
				e.Size, e.Files = n.size, 1
			}
			if c, ok := marks[p]; ok {
				e.Change = c.Kind
			}
			continue
		}
		e.Layer = max(e.Layer, n.layer)
		if n.kind != KindDir {
			e.Size += n.size
			e.Files++
		}
	}
	for p, c := range marks {
		e, deeper := child(p)
		if e == nil {
			continue
		}
		if deeper {
			e.Changed++
		}
		if e.live {
			continue
		}
		// Gone after this layer: show what it removed.
		e.Change, e.Layer = 'r', layer
		if c.Kind == 'r' {
			e.Size += c.Size
			e.Files++
		}
		if !deeper {
			e.Kind = KindFile
		}
	}
	out := make([]TreeEntry, 0, len(byName))
	for _, e := range byName {
		if changes && e.Change == 0 && e.Changed == 0 {
			continue
		}
		e.Layer = max(e.Layer, 0)
		out = append(out, *e)
	}
	slices.SortFunc(out, func(a, b TreeEntry) int {
		if (a.Kind == KindDir) != (b.Kind == KindDir) {
			if a.Kind == KindDir {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out
}
