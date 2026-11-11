package sshpool

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every command goes through Conn.Session, so it reaches the command log.
// sshprobe uses its own short-lived client for checks and stays outside.
func TestNoRawSessions(t *testing.T) {
	root := filepath.Join("..", "..")
	allowed := map[string]bool{
		filepath.Join("internal", "sshpool", "session.go"): true,
		filepath.Join("internal", "sshprobe", "probe.go"):  true,
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == ".git" || d.Name() == "vendor") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if allowed[rel] {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), ".NewSession(") {
			t.Errorf("%s opens an SSH session directly: use Conn.Session so the command is logged", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
