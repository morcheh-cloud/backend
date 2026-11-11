package packages

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDumpScripts writes the scripts to $PKG_DUMP, to make fixtures.
func TestDumpScripts(t *testing.T) {
	dir := os.Getenv("PKG_DUMP")
	if dir == "" {
		t.Skip("PKG_DUMP not set")
	}
	w := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("overview.sh", OverviewScript())
	w("info-installed.sh", InfoScript(os.Getenv("PKG_INSTALLED")))
	w("info-remote.sh", InfoScript(os.Getenv("PKG_REMOTE")))
	w("search.sh", SearchScript("htop"))
	w("history.sh", HistoryScript())
	p, _ := PreviewScript(ActInstall, "", []string{os.Getenv("PKG_REMOTE")}, "")
	w("preview-install.sh", p)
	p, _ = PreviewScript(ActRemove, "", []string{os.Getenv("PKG_INSTALLED")}, "")
	w("preview-remove.sh", p)
	p, _ = PreviewScript(ActUpgradeAll, ModeAll, nil, "")
	w("preview-upgrade.sh", p)
}
