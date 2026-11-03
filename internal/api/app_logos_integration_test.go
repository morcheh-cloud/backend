package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

var (
	faviconPNG = append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{7}, 64)...)
	uploadPNG  = append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{9}, 64)...)
	logoSVG    = []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><rect width="1" height="1"/></svg>`)
)

// iconServer is a service with a favicon; hits counts every request to it.
func iconServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><link rel="icon" href="/a.png"></head></html>`))
		case "/a.png":
			w.Header().Set("Content-Type", "image/png")
			w.Write(faviconPNG)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func logoPath(a App) string { return "/apps/" + a.ID + "/logo" }

func upload(t *testing.T, c *tclient, a App, ws uuid.UUID, ct string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	return c.raw(t, http.MethodPut, logoPath(a), ct, data, &ws)
}

// waitFor polls until ok or fails after the timeout.
func waitFor(t *testing.T, timeout time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func hasFavicon(t *testing.T, e *env, a App) bool {
	t.Helper()
	var n int
	if err := e.db.QueryRow(context.Background(),
		"SELECT count(*) FROM app_logos WHERE app_id = $1 AND source = 'favicon'", uuid.MustParse(a.ID)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func TestIntegrationLogoBackgroundFetchKeepsUpload(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	srv, _ := iconServer(t)
	a := addApp(t, admin, ws, map[string]any{"name": "Panel", "address": srv.URL})
	waitFor(t, 5*time.Second, "the favicon", func() bool { return hasFavicon(t, e, a) })

	var got App
	expect(t, upload(t, admin, a, ws, "image/png", uploadPNG), http.StatusOK, &got)
	if got.LogoKind != "upload" {
		t.Fatalf("logo_kind = %s", got.LogoKind)
	}
	got = App{}
	expect(t, admin.do(t, http.MethodPost, "/apps/"+a.ID+"/refetch-icon", nil, &ws), http.StatusOK, &got)
	if got.LogoKind != "upload" {
		t.Fatalf("refetch changed logo_kind to %s", got.LogoKind)
	}
	w := admin.do(t, http.MethodGet, logoPath(a), nil, &ws)
	expect(t, w, http.StatusOK, nil)
	if !bytes.Equal(w.Body.Bytes(), uploadPNG) {
		t.Fatal("logo isn't the upload")
	}
}

func TestIntegrationLogoBackgroundFetchKeepsIcon(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	srv, _ := iconServer(t)
	a := addApp(t, admin, ws, map[string]any{"name": "Panel", "address": srv.URL, "logo_kind": "icon", "logo_icon": "database"})
	var got App
	expect(t, admin.do(t, http.MethodPost, "/apps/"+a.ID+"/refetch-icon", nil, &ws), http.StatusOK, &got)
	if got.LogoKind != "icon" || got.LogoIcon != "database" || got.LogoURL != nil {
		t.Fatalf("got %+v", got)
	}
}

func TestIntegrationLogoFetchOnlyWhenAddressChanges(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	first, firstHits := iconServer(t)
	second, secondHits := iconServer(t)
	a := addApp(t, admin, ws, map[string]any{"name": "Panel", "address": first.URL})
	waitFor(t, 5*time.Second, "the first fetch", func() bool { return hasFavicon(t, e, a) })

	before := firstHits.Load()
	expect(t, admin.do(t, http.MethodPatch, "/apps/"+a.ID, map[string]any{"name": "Renamed"}, &ws), http.StatusOK, nil)
	time.Sleep(200 * time.Millisecond)
	if n := firstHits.Load(); n != before {
		t.Fatalf("a rename fetched again (%d → %d)", before, n)
	}
	expect(t, admin.do(t, http.MethodPatch, "/apps/"+a.ID, map[string]any{"address": second.URL}, &ws), http.StatusOK, nil)
	waitFor(t, 5*time.Second, "a fetch from the new address", func() bool { return secondHits.Load() > 0 })
}

func TestIntegrationLogoUploadRejectsNonImage(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	a := addApp(t, admin, ws, map[string]any{"name": "Panel", "address": "panel.local"})
	expect(t, upload(t, admin, a, ws, "image/png", []byte("<html><body>hi</body></html>")), http.StatusUnprocessableEntity, nil)
	big := append(append([]byte{}, uploadPNG...), make([]byte, 1<<20)...)
	if w := upload(t, admin, a, ws, "image/png", big); w.Code != http.StatusRequestEntityTooLarge && w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("big upload = %d", w.Code)
	}
}

func TestIntegrationLogoSVGIsSandboxed(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	a := addApp(t, admin, ws, map[string]any{"name": "Panel", "address": "panel.local"})
	// The declared type is ignored: what's stored comes from the bytes.
	expect(t, upload(t, admin, a, ws, "text/html", logoSVG), http.StatusOK, nil)
	w := admin.do(t, http.MethodGet, logoPath(a), nil, &ws)
	expect(t, w, http.StatusOK, nil)
	h := w.Header()
	if h.Get("Content-Type") != "image/svg+xml" || h.Get("X-Content-Type-Options") != "nosniff" ||
		!strings.Contains(h.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("headers = %v", h)
	}
	if cc := h.Get("Cache-Control"); cc != "private, max-age=86400" {
		t.Fatalf("Cache-Control = %q", cc)
	}
}

func TestIntegrationLogoLevels(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin, viewer, stranger := e.user(t, "admin"), e.user(t, "member"), e.user(t, "member")
	a := addApp(t, admin, ws, map[string]any{"name": "Panel", "address": "panel.local"})
	expect(t, upload(t, admin, a, ws, "image/png", uploadPNG), http.StatusOK, nil)
	id := uuid.MustParse(a.ID)
	e.grant(t, viewer, "viewer", grantTarget{App: &id})

	expect(t, viewer.do(t, http.MethodGet, logoPath(a), nil, &ws), http.StatusOK, nil)
	expect(t, upload(t, viewer, a, ws, "image/png", uploadPNG), http.StatusForbidden, nil)
	expect(t, viewer.do(t, http.MethodPost, "/apps/"+a.ID+"/refetch-icon", nil, &ws), http.StatusForbidden, nil)
	expect(t, stranger.do(t, http.MethodGet, logoPath(a), nil, &ws), http.StatusNotFound, nil)
}

func TestIntegrationLogoRefetchFailure(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	srv, _ := iconServer(t)
	a := addApp(t, admin, ws, map[string]any{"name": "Panel", "address": srv.URL})
	srv.Close()
	w := admin.do(t, http.MethodPost, "/apps/"+a.ID+"/refetch-icon", nil, &ws)
	expect(t, w, http.StatusUnprocessableEntity, nil)
	body := w.Body.String()
	if strings.Contains(body, "127.0.0.1") || strings.Contains(body, "refused") || strings.Contains(body, "dial") {
		t.Fatalf("body leaks details: %s", body)
	}
}

func TestIntegrationLogoURLChangesWithUpload(t *testing.T) {
	e := newEnv(t)
	ws := e.workspace(t)
	admin := e.user(t, "admin")
	a := addApp(t, admin, ws, map[string]any{"name": "Panel", "address": "panel.local"})
	var one, two App
	expect(t, upload(t, admin, a, ws, "image/png", uploadPNG), http.StatusOK, &one)
	expect(t, upload(t, admin, a, ws, "image/svg+xml", logoSVG), http.StatusOK, &two)
	if one.LogoURL == nil || two.LogoURL == nil || *one.LogoURL == *two.LogoURL {
		t.Fatalf("logo_url %v → %v", one.LogoURL, two.LogoURL)
	}
}
