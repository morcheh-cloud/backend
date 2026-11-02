//go:build smoke

package dbmon

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestSmoke looks at the test databases from docker-compose.yml (make up):
//
//	go test -tags smoke ./internal/dbmon -run Smoke -v
//
// SMOKE_DUMP=1 prints each snapshot as JSON.
func TestSmoke(t *testing.T) {
	cases := []struct {
		name  string
		cfg   Config
		query string
		db    string
	}{
		{"postgres", Config{Engine: Postgres, Port: 5434, Username: "ant", Password: "colony", Database: "shop"}, "SELECT * FROM pg_class WHERE relname = 'x'", "shop"},
		{"mysql", Config{Engine: MySQL, Port: 3307, Username: "root", Password: "colony"}, "SELECT * FROM mysql.user WHERE User = 'x'", "mysql"},
		{"mariadb", Config{Engine: MySQL, Port: 3308, Username: "root", Password: "colony"}, "SELECT * FROM mysql.user WHERE User = 'x'", "mysql"},
		{"mssql", Config{Engine: MSSQL, Port: 14330, Username: "sa", Password: "Colony-2026!", TLS: TLSRequire}, "SELECT * FROM sys.objects WHERE name = 'x'", "master"},
		{"mongo", Config{Engine: Mongo, Port: 27018, Username: "ant", Password: "colony"}, `{"collection": "system.version", "filter": {"x": 1}}`, "admin"},
		{"redis", Config{Engine: Redis, Port: 6381, Password: "colony"}, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.cfg.Host = "127.0.0.1"
			if c.cfg.TLS == "" {
				c.cfg.TLS = TLSDisable
			}
			c.cfg.Dial = DirectDialer(true)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			conn, err := Open(ctx, c.cfg)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer conn.Close()
			if _, err := conn.Collect(ctx, true); err != nil {
				t.Fatalf("collect: %v", err)
			}
			time.Sleep(time.Second)
			s, err := conn.Collect(ctx, false)
			if err != nil {
				t.Fatalf("collect 2: %v", err)
			}
			t.Logf("%s %s role=%s conns=%d/%v dbs=%d tables=%d queries=%d (%s) users=%d settings=%d sessions=%d clients=%d rates=%v cache=%v",
				s.Flavor, s.Version, s.Role, s.Connections.Total, deref(s.Connections.Max),
				len(s.Databases), len(s.Tables), len(s.Queries), s.QueriesSource,
				len(s.Users), len(s.Settings), len(s.Sessions), len(s.Clients), s.Rates != nil, deref(s.CacheHit))
			for _, n := range s.Notes {
				t.Logf("note %s: %s", n.Area, n.Message)
			}
			if os.Getenv("SMOKE_DUMP") != "" {
				b, _ := json.MarshalIndent(s, "", "  ")
				t.Log(string(b))
			}
			for _, ch := range Evaluate(EvalInput{Engine: c.cfg.Engine, Snapshot: s, Now: time.Now()}) {
				if ch.Level != LevelOK {
					t.Logf("check %s %s: %s", ch.ID, ch.Level, ch.Reason)
				}
			}
			d := Diagnose(ctx, c.cfg)
			for _, st := range d.Steps {
				t.Logf("step %s %s (%d ms): %s", st.ID, st.Status, st.Ms, st.Message)
			}
			if d.Status != StatusOnline {
				t.Errorf("diagnose: %s %s", d.Status, d.Message)
			}
			if c.query != "" {
				p, err := conn.Explain(ctx, c.db, c.query)
				if err != nil {
					t.Errorf("explain: %v", err)
				} else {
					t.Logf("plan (%s) cost=%v warnings=%v\n%.400s", p.Format, deref(p.Cost), p.Warnings, p.Plan)
				}
			}
		})
	}
}
