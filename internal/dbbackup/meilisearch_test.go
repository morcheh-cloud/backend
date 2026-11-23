package dbbackup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/morche/backend/internal/dbmon"
)

func TestMeiliCheckUID(t *testing.T) {
	for _, ok := range []string{"movies", "a-b_C9", strings.Repeat("x", 400)} {
		if err := meiliCheckUID(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "has space", "dot.ted", "slash/x", "é", strings.Repeat("x", 401)} {
		if err := meiliCheckUID(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func TestMeiliUnknownField(t *testing.T) {
	err := &dbmon.HTTPError{Status: 400, Code: "bad_request", Message: "Unknown field `vectorStore`: expected one of `displayedAttributes`, `searchableAttributes`"}
	if got := meiliUnknownField(err); got != "vectorStore" {
		t.Errorf("got %q", got)
	}
	if got := meiliUnknownField(errors.New("Unknown field `x`")); got != "" {
		t.Errorf("a non-HTTP error: %q", got)
	}
}

// Dump an index of the compose service test-meilisearch, restore it as a
// new index and over an existing one, and compare.
func TestMeiliLiveRoundTrip(t *testing.T) {
	hc := http.Client{Timeout: 2 * time.Second}
	res, err := hc.Get("http://127.0.0.1:7701/health")
	if err != nil {
		t.Skip("test-meilisearch isn't running (make up in the backend)")
	}
	res.Body.Close()
	cfg := dbmon.Config{Engine: dbmon.Meili, Host: "127.0.0.1", Port: 7701, TLS: dbmon.TLSDisable, Dial: dbmon.DirectDialer(true)}
	target := func(name string) Target {
		return Target{Engine: dbmon.Meili, Password: "colony-master-key-2026", Name: name}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c := cfg
	c.Password = "colony-master-key-2026"
	h, err := dbmon.OpenHTTP(c)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	drop := func(uid string) {
		if t, err := meiliTask(ctx, h, http.MethodDelete, dbmon.Path("indexes", uid), nil, ""); err == nil {
			_ = meiliWaitTask(ctx, h, t)
		}
	}
	for _, uid := range []string{"backup_src", "backup_copy"} {
		drop(uid)
		defer drop(uid)
	}

	// 2,345 documents (more than a page and a batch), a nested field, and
	// settings to carry over.
	src := &NativeIndex{Name: "backup_src", PrimaryKey: "sku", Settings: []byte(`{"filterableAttributes":["kind"],"sortableAttributes":["n"],"stopWords":["the"]}`)}
	if err := meiliCreate(ctx, h, "backup_src", src); err != nil {
		t.Fatal(err)
	}
	var nd bytes.Buffer
	for i := range 2345 {
		fmt.Fprintf(&nd, `{"sku":"s-%d","n":%d,"kind":"k%d","nested":{"a":[1,2,"x\ny"]}}`+"\n", i, i, i%7)
	}
	tu, err := meiliTask(ctx, h, http.MethodPost, "/indexes/backup_src/documents", nd.Bytes(), "application/x-ndjson")
	if err != nil {
		t.Fatal(err)
	}
	if err := meiliWaitTask(ctx, h, tu); err != nil {
		t.Fatal(err)
	}

	var file bytes.Buffer
	if err := Dump(ctx, cfg, target("backup_src"), &file); err != nil {
		t.Fatal(err)
	}
	if s := sniffNative(file.Bytes()[:min(file.Len(), 4096)]); s.Format != MeiliNDJSON || len(s.Databases) != 1 || s.Databases[0] != "backup_src" {
		t.Fatalf("sniff: %+v", s)
	}
	if !nativeEnds(file.Bytes()[max(0, file.Len()-200):]) {
		t.Fatal("no trailer")
	}

	count := func(uid string) int64 {
		var st struct {
			NumberOfDocuments int64 `json:"numberOfDocuments"`
		}
		if err := h.JSON(ctx, http.MethodGet, dbmon.Path("indexes", uid, "stats"), nil, &st); err != nil {
			t.Fatal(err)
		}
		return st.NumberOfDocuments
	}
	settingOf := func(uid string) string {
		raw, err := h.Raw(ctx, http.MethodGet, dbmon.Path("indexes", uid, "settings", "stop-words"), nil, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	load := func(name string, o RestoreOptions) error {
		o.Format = MeiliNDJSON
		return Load(ctx, cfg, target(name), o, bytes.NewReader(file.Bytes()))
	}

	if err := load("backup_copy", RestoreOptions{}); err != nil {
		t.Fatal(err)
	}
	if n := count("backup_copy"); n != 2345 {
		t.Fatalf("copy holds %d documents", n)
	}
	if s := settingOf("backup_copy"); s != `["the"]` {
		t.Fatalf("stop words: %s", s)
	}
	var doc map[string]any
	if err := h.JSON(ctx, http.MethodGet, "/indexes/backup_copy/documents/s-42", nil, &doc); err != nil || fmt.Sprint(doc["nested"]) != "map[a:[1 2 x\ny]]" {
		t.Fatalf("document: %v %v", doc, err)
	}

	// Into an existing index: refused, unless replacing.
	if err := load("backup_copy", RestoreOptions{}); err == nil {
		t.Fatal("restoring over an existing index without Replace should fail")
	}
	tu, err = meiliTask(ctx, h, http.MethodPost, "/indexes/backup_copy/documents", []byte(`[{"sku":"extra"}]`), "")
	if err != nil {
		t.Fatal(err)
	}
	_ = meiliWaitTask(ctx, h, tu)
	if err := load("backup_copy", RestoreOptions{Replace: true}); err != nil {
		t.Fatal(err)
	}
	if n := count("backup_copy"); n != 2345 {
		t.Fatalf("replaced copy holds %d documents", n)
	}
	var list struct {
		Results []struct{ UID string } `json:"results"`
	}
	_ = h.JSON(ctx, http.MethodGet, "/indexes?limit=1000", nil, &list)
	for _, ix := range list.Results {
		if strings.HasPrefix(ix.UID, "morche_restore_") {
			t.Errorf("left behind: %s", ix.UID)
		}
	}

	// A cut file fails, and leaves nothing behind.
	cut := file.Bytes()[:file.Len()/2]
	err = Load(ctx, cfg, target("backup_cut"), RestoreOptions{Format: MeiliNDJSON}, bytes.NewReader(cut))
	if err == nil || !errors.Is(err, io.ErrUnexpectedEOF) && !strings.Contains(err.Error(), "cut") {
		t.Fatalf("cut file: %v", err)
	}
	if ok, _ := meiliExists(ctx, h, "backup_cut"); ok {
		drop("backup_cut")
		t.Error("a failed restore left its index behind")
	}
	if err := load("bad name", RestoreOptions{}); err == nil {
		t.Error("a bad name should be refused")
	}
}
