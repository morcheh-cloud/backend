//go:build dbbackuplive

package dbbackup

import (
	"bytes"
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
		{"pg one", "morche-test-postgres-1", Target{Engine: "postgres", Username: "ant", Password: "colony", Name: "shop", Local: true}},
		{"pg one zstd", "morche-test-postgres-1", Target{Engine: "postgres", Username: "ant", Password: "colony", Name: "shop", Local: true, Compression: Zstd}},
		{"pg one parallel", "morche-test-postgres-1", Target{Engine: "postgres", Username: "ant", Password: "colony", Name: "shop", Local: true, Compression: Zstd, Workers: 4}},
		{"pg one parallel temp dir", "morche-test-postgres-1", Target{Engine: "postgres", Username: "ant", Password: "colony", Name: "shop", Local: true, Workers: 2, TempDir: "/var/tmp"}},
		{"pg all zstd", "morche-test-postgres-1", Target{Engine: "postgres", Username: "ant", Password: "colony", Local: true, Compression: Zstd}},
		{"maria one zstd", "morche-test-mariadb-1", Target{Engine: "mysql", Username: "root", Password: "colony", Name: "shop", Local: true, Compression: Zstd, Level: LevelSmall}},
		{"pg all", "morche-test-postgres-1", Target{Engine: "postgres", Username: "ant", Password: "colony", Local: true}},
		{"mysql one", "morche-test-mysql-1", Target{Engine: "mysql", Username: "root", Password: "colony", Name: "shop", Local: true}},
		{"mysql all", "morche-test-mysql-1", Target{Engine: "mysql", Username: "root", Password: "colony", Local: true}},
		{"maria one", "morche-test-mariadb-1", Target{Engine: "mysql", Username: "root", Password: "colony", Name: "shop", Local: true}},
		{"mongo", "morche-test-mongo-1", Target{Engine: "mongodb", Username: "ant", Password: "colony", Local: true}},
		{"redis", "morche-test-redis-1", Target{Engine: "redis", Password: "colony", Local: true}},
		{"mssql", "morche-test-mssql-1", Target{Engine: "mssql", Username: "sa", Password: "Colony-2026!", Name: "master", Local: true, ID: "live-test"}},
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
			file = packed(t, spec, file)
			res, err := Verify(spec.Format, bytes.NewReader(file))
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			t.Logf("verified %d bytes %s", res.Bytes, res.SHA256[:12])
		})
	}
}

// A temporary folder that isn't there stops the dump before it starts, saying so.
func TestLiveMissingTempDir(t *testing.T) {
	spec, err := Build(Target{Engine: "postgres", Username: "ant", Password: "colony", Name: "shop", Local: true, Workers: 2, TempDir: "/no/such dir"})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("docker", "exec", "-i", "morche-test-postgres-1", "sh", "-s")
	cmd.Stdin = strings.NewReader(spec.Script)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if cmd.Run() == nil {
		t.Fatal("it ran")
	}
	if !strings.Contains(errb.String(), "The temporary folder /no/such dir doesn't exist") || out.Len() != 0 {
		t.Fatalf("stdout %d bytes, stderr %q", out.Len(), errb.String())
	}
}
