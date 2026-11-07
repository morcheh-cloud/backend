//go:build dbbackuplive

package dbbackup

import (
	"bytes"
	"compress/gzip"
	"os/exec"
	"strings"
	"testing"
)

// Runs each script inside the compose test containers:
// go test -tags dbbackuplive ./internal/dbbackup
func TestLive(t *testing.T) {
	cases := []struct {
		name, container string
		target          Target
	}{
		{"pg one", "morcheh-test-postgres-1", Target{Engine: "postgres", Username: "ant", Password: "colony", Name: "shop", Local: true}},
		{"pg all", "morcheh-test-postgres-1", Target{Engine: "postgres", Username: "ant", Password: "colony", Local: true}},
		{"mysql one", "morcheh-test-mysql-1", Target{Engine: "mysql", Username: "root", Password: "colony", Name: "shop", Local: true}},
		{"mysql all", "morcheh-test-mysql-1", Target{Engine: "mysql", Username: "root", Password: "colony", Local: true}},
		{"maria one", "morcheh-test-mariadb-1", Target{Engine: "mysql", Username: "root", Password: "colony", Name: "shop", Local: true}},
		{"mongo", "morcheh-test-mongo-1", Target{Engine: "mongodb", Username: "ant", Password: "colony", Local: true}},
		{"redis", "morcheh-test-redis-1", Target{Engine: "redis", Password: "colony", Local: true}},
		{"mssql", "morcheh-test-mssql-1", Target{Engine: "mssql", Username: "sa", Password: "Colony-2026!", Name: "master", Local: true, ID: "live-test"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, err := Build(c.target)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("docker", "exec", "-i", c.container, "sh", "-s")
			cmd.Stdin = strings.NewReader(spec.Script)
			var out, errb bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &errb
			runErr := cmd.Run()
			t.Logf("stdout %d bytes, stderr: %.400s", out.Len(), errb.String())
			if runErr != nil {
				t.Fatalf("%v", runErr)
			}
			file := out.Bytes()
			if spec.Gzip {
				var z bytes.Buffer
				w := gzip.NewWriter(&z)
				w.Write(file)
				w.Close()
				file = z.Bytes()
			}
			res, err := Verify(spec.Format, bytes.NewReader(file))
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			t.Logf("verified %d bytes %s", res.Bytes, res.SHA256[:12])
		})
	}
}
