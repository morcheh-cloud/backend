package appicon

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	pngBytes = append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{1}, 32)...)
	icoBytes = append([]byte{0, 0, 1, 0, 1, 0}, bytes.Repeat([]byte{2}, 32)...)
	jpgBytes = append([]byte{0xff, 0xd8, 0xff, 0xe0}, bytes.Repeat([]byte{3}, 32)...)
)

func page(links string) string {
	return "<!doctype html><html><head><title>x</title>" + links + "</head><body>hi</body></html>"
}

func serve(t *testing.T, routes map[string]func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(mux(routes))
	t.Cleanup(srv.Close)
	return srv
}

func mux(routes map[string]func(w http.ResponseWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f, ok := routes[r.URL.Path]; ok {
			f(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

func html(body string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, body)
	}
}

func image(ct string, data []byte) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ct)
		w.Write(data)
	}
}

func fetch(t *testing.T, address string) (*Icon, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return Fetch(ctx, address)
}

func mustFetch(t *testing.T, address string) *Icon {
	t.Helper()
	icon, err := fetch(t, address)
	if err != nil {
		t.Fatal(err)
	}
	return icon
}

func TestFetchLinkIcon(t *testing.T) {
	srv := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/":      html(page(`<link rel="icon" href="/a.png">`)),
		"/a.png": image("image/png", pngBytes),
	})
	icon := mustFetch(t, srv.URL)
	if icon.ContentType != "image/png" || !bytes.Equal(icon.Data, pngBytes) {
		t.Fatalf("icon = %s %d bytes", icon.ContentType, len(icon.Data))
	}
}

func TestFetchPrefersAppleTouch(t *testing.T) {
	srv := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/":          html(page(`<link rel="shortcut icon" href="/small.ico"><link rel="apple-touch-icon" href="/big.png">`)),
		"/small.ico": image("image/x-icon", icoBytes),
		"/big.png":   image("image/png", pngBytes),
	})
	if icon := mustFetch(t, srv.URL); !bytes.Equal(icon.Data, pngBytes) {
		t.Fatalf("got %s", icon.ContentType)
	}
}

func TestFetchFallsBackToFaviconIco(t *testing.T) {
	srv := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/":            html(page("")),
		"/favicon.ico": image("image/vnd.microsoft.icon", icoBytes),
	})
	icon := mustFetch(t, srv.URL)
	if icon.ContentType != "image/x-icon" || !bytes.Equal(icon.Data, icoBytes) {
		t.Fatalf("icon = %s", icon.ContentType)
	}
}

func TestFetchRelativeToFinalURL(t *testing.T) {
	srv := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/":                   func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/app/login/", http.StatusFound) },
		"/app/login/":         html(page(`<link rel="icon" href="icon.png">`)),
		"/app/login/icon.png": image("image/png", pngBytes),
	})
	if icon := mustFetch(t, srv.URL); !bytes.Equal(icon.Data, pngBytes) {
		t.Fatalf("got %s", icon.ContentType)
	}
}

func TestFetchSelfSignedOK(t *testing.T) {
	srv := httptest.NewTLSServer(mux(map[string]func(http.ResponseWriter, *http.Request){
		"/":      html(page(`<link rel="icon" href="/a.png">`)),
		"/a.png": image("image/png", pngBytes),
	}))
	defer srv.Close()
	mustFetch(t, srv.URL)
}

func TestFetchSendsNoCredentials(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	record := func(next func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen = append(seen, r.Method+"|"+r.Header.Get("Cookie")+"|"+r.Header.Get("Authorization"))
			mu.Unlock()
			next(w, r)
		}
	}
	srv := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/": record(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc", Path: "/"})
			html(page(`<link rel="icon" href="/a.png">`))(w, r)
		}),
		"/a.png": record(image("image/png", pngBytes)),
	})
	mustFetch(t, srv.URL)
	if len(seen) != 2 {
		t.Fatalf("seen = %v", seen)
	}
	for _, s := range seen {
		if s != "GET||" {
			t.Fatalf("request = %q", s)
		}
	}
}

func redirects(n int) map[string]func(http.ResponseWriter, *http.Request) {
	routes := map[string]func(http.ResponseWriter, *http.Request){
		"/r/0":   html(page(`<link rel="icon" href="/a.png">`)),
		"/a.png": image("image/png", pngBytes),
	}
	for i := 1; i <= n; i++ {
		to := fmt.Sprintf("/r/%d", i-1)
		routes[fmt.Sprintf("/r/%d", i)] = func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, to, http.StatusFound) }
	}
	return routes
}

func TestFetchRedirectLimit(t *testing.T) {
	srv := serve(t, redirects(4))
	if _, err := fetch(t, srv.URL+"/r/3"); err != nil {
		t.Fatalf("3 redirects: %v", err)
	}
	if _, err := fetch(t, srv.URL+"/r/4"); err == nil {
		t.Fatal("4 redirects worked")
	}
}

func TestFetchRefusesNonHTTPRedirect(t *testing.T) {
	srv := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
		},
	})
	if _, err := fetch(t, srv.URL); err == nil {
		t.Fatal("followed a file:// redirect")
	}
}

func TestFetchSizeLimit(t *testing.T) {
	big := append(append([]byte{}, pngBytes...), bytes.Repeat([]byte{0}, MaxSize)...)
	srv := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/":      html(page(`<link rel="icon" href="/a.png">`)),
		"/a.png": image("image/png", big),
	})
	if _, err := fetch(t, srv.URL); err == nil {
		t.Fatal("took an image over the limit")
	}
}

func TestFetchTimeout(t *testing.T) {
	srv := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/": func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := Fetch(ctx, srv.URL); err == nil {
		t.Fatal("no error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("took %s", time.Since(start))
	}
}

func TestFetchRejectsNonImage(t *testing.T) {
	for name, icon := range map[string]func(http.ResponseWriter, *http.Request){
		"declared html": html("<html>nope</html>"),
		"html as png":   image("image/png", []byte("<html><body>not an image</body></html>")),
	} {
		t.Run(name, func(t *testing.T) {
			srv := serve(t, map[string]func(http.ResponseWriter, *http.Request){
				"/":      html(page(`<link rel="icon" href="/a.png">`)),
				"/a.png": icon,
			})
			if _, err := fetch(t, srv.URL); err == nil {
				t.Fatal("accepted a non-image")
			}
		})
	}
}

func TestFetchIgnoresDataHref(t *testing.T) {
	srv := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/":            html(page(`<link rel="icon" href="data:image/png;base64,iVBORw0KGgo=">`)),
		"/favicon.ico": image("image/x-icon", icoBytes),
	})
	if icon := mustFetch(t, srv.URL); !bytes.Equal(icon.Data, icoBytes) {
		t.Fatalf("got %s", icon.ContentType)
	}
}

func TestFetchErrorsCarryNoAddress(t *testing.T) {
	srv := serve(t, nil)
	srv.Close()
	_, err := fetch(t, srv.URL)
	if err == nil || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("err = %v", err)
	}
}

func TestSniff(t *testing.T) {
	ok := map[string][]byte{
		"image/png":     pngBytes,
		"image/jpeg":    jpgBytes,
		"image/gif":     []byte("GIF89a\x01\x00\x01\x00"),
		"image/webp":    []byte("RIFF\x10\x00\x00\x00WEBPVP8 "),
		"image/x-icon":  icoBytes,
		"image/svg+xml": []byte(`  <svg xmlns="http://www.w3.org/2000/svg"></svg>`),
	}
	for want, data := range ok {
		if got, ok := Sniff(data); !ok || got != want {
			t.Errorf("Sniff(%s) = %q %v", want, got, ok)
		}
	}
	if got, ok := Sniff([]byte("<?xml version=\"1.0\"?>\n<!-- x -->\n<svg viewBox=\"0 0 1 1\"></svg>")); !ok || got != "image/svg+xml" {
		t.Errorf("xml svg = %q %v", got, ok)
	}
	for name, data := range map[string][]byte{
		"html":   []byte("<!doctype html><html><body><svg></svg></body></html>"),
		"xml":    []byte("<?xml version=\"1.0\"?><rss></rss>"),
		"random": []byte{9, 8, 7, 6, 5, 4, 3, 2, 1},
		"empty":  nil,
	} {
		if got, ok := Sniff(data); ok {
			t.Errorf("Sniff(%s) = %q", name, got)
		}
	}
}
