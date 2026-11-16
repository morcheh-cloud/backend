// Command fakearvan serves a fake ArvanCloud IaaS v3 API for development
// (plain HTTP, paths /<region>/v3/…). Point the backend at it with
// ARVAN_FAKE_URL=http://127.0.0.1:8091/%s/v3; accounts whose key starts with
// "fake-" then talk to it. The key it accepts is fake.Key.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/morche/backend/internal/cloud/arvan/fake"
)

func main() {
	addr := os.Getenv("FAKEARVAN_ADDR")
	if addr == "" {
		addr = ":8091"
	}
	log.Printf("fake ArvanCloud on %s (key %s)", addr, fake.Key)
	srv := &http.Server{Addr: addr, Handler: fake.New(), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
