package docker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"testing"
)

type tf struct {
	name string
	body string
	dir  bool
}

func layerTar(t *testing.T, gz bool, files ...tf) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w = &buf
	var zw *gzip.Writer
	tw := tar.NewWriter(w)
	if gz {
		zw = gzip.NewWriter(w)
		tw = tar.NewWriter(zw)
	}
	for _, f := range files {
		h := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}
		if f.dir {
			h.Typeflag, h.Size, h.Mode = tar.TypeDir, 0, 0o755
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(f.body))
	}
	_ = tw.Close()
	if zw != nil {
		_ = zw.Close()
	}
	return buf.Bytes()
}

func savedTar(t *testing.T, entries map[string][]byte, links map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, b := range entries {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(b)
	}
	for name, target := range links {
		_ = tw.WriteHeader(&tar.Header{Name: name, Linkname: target, Typeflag: tar.TypeSymlink})
	}
	_ = tw.Close()
	return buf.Bytes()
}

func TestReadSavedAndSummarize(t *testing.T) {
	l1 := layerTar(t, false,
		tf{name: "etc/", dir: true},
		tf{name: "etc/app.conf", body: "aaaa"},
		tf{name: "var/cache/big.bin", body: "0123456789"},
		tf{name: "var/cache/small", body: "xy"},
	)
	l2 := layerTar(t, true,
		tf{name: "etc/app.conf", body: "bbbbbb"},
		tf{name: "var/cache/.wh..wh..opq"},
		tf{name: "usr/bin/tool", body: "t"},
	)
	l3 := layerTar(t, false, tf{name: "usr/bin/.wh.tool"})
	cfg, _ := json.Marshal(map[string]any{
		"history": []map[string]any{
			{"created_by": "ADD base"},
			{"created_by": "ENV A=1", "empty_layer": true},
			{"created_by": "RUN change"},
			{"created_by": "RUN rm tool"},
		},
		"rootfs": map[string]any{"diff_ids": []string{"sha256:1", "sha256:2", "sha256:3"}},
	})
	manifest, _ := json.Marshal([]map[string]any{{
		"Config": "blobs/sha256/cfg",
		"Layers": []string{"blobs/sha256/l1", "blobs/sha256/l2", "old/layer.tar"},
	}})
	raw := savedTar(t, map[string][]byte{
		"manifest.json":    manifest,
		"blobs/sha256/cfg": cfg,
		"blobs/sha256/l1":  l1,
		"blobs/sha256/l2":  l2,
		"blobs/sha256/l3":  l3,
	}, map[string]string{"old/layer.tar": "../blobs/sha256/l3"})

	img, err := ReadSaved(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(img.Layers) != 3 || img.Steps != 4 {
		t.Fatalf("layers %d steps %d", len(img.Layers), img.Steps)
	}
	if img.Layers[1].CreatedBy != "RUN change" || img.Layers[2].CreatedBy != "RUN rm tool" {
		t.Fatalf("steps mapped wrong: %+v", img.Layers)
	}
	if img.Layers[0].Size != 16 || img.Layers[1].Size != 7 {
		t.Fatalf("sizes %d %d", img.Layers[0].Size, img.Layers[1].Size)
	}

	s := img.Summarize(10)
	if s.Total != 23 || s.Final != 6 || s.Wasted != 17 {
		t.Fatalf("total %d final %d wasted %d", s.Total, s.Final, s.Wasted)
	}
	if s.Layers[1].Modified != 1 || s.Layers[1].Removed != 2 || s.Layers[1].Added != 1 {
		t.Fatalf("layer 2 stats %+v", s.Layers[1])
	}
	if s.Layers[2].Removed != 1 || s.Files != 1 {
		t.Fatalf("layer 3 stats %+v files %d", s.Layers[2], s.Files)
	}
	if s.Top[0].Path != "var/cache/big.bin" || s.Top[0].Bytes != 10 {
		t.Fatalf("top %+v", s.Top)
	}

	root := img.Tree(1, "", false)
	if len(root) != 3 {
		t.Fatalf("root after layer 2: %+v", root)
	}
	cache := img.Tree(1, "var/cache", true)
	if len(cache) != 2 || cache[0].Change != 'r' {
		t.Fatalf("var/cache changes: %+v", cache)
	}
	etc := img.Tree(1, "etc", false)
	if len(etc) != 1 || etc[0].Change != 'm' || etc[0].Size != 6 {
		t.Fatalf("etc: %+v", etc)
	}
}
