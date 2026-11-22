// Command fakearvan serves a fake ArvanCloud API for development (plain
// HTTP): IaaS v3 at /<region>/v3/… and CDN 4.0 at /cdn/4.0/…. Point the
// backend at it with ARVAN_FAKE_URL=http://127.0.0.1:8091/%s/v3; cloud
// accounts and DNS connections whose key starts with "fake-" then talk to it.
// The key it accepts is fake.Key.
package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	cdnfake "github.com/morche/backend/internal/arvancdn/fake"
	"github.com/morche/backend/internal/cloud/arvan/fake"
)

func main() {
	addr := os.Getenv("FAKEARVAN_ADDR")
	if addr == "" {
		addr = ":8091"
	}
	iaas, cdn := fake.New(), cdnfake.New()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/cdn/") {
			cdn.ServeHTTP(w, r)
			return
		}
		iaas.ServeHTTP(w, r)
	})
	log.Printf("fake ArvanCloud on %s (key %s)", addr, fake.Key)
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
