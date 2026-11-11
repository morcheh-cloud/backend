package api

import (
	"testing"

	"github.com/morcheh/backend/internal/packages"
)

func TestUpgradeNote(t *testing.T) {
	pkg := func(name, version string) packages.InstalledPackage {
		return packages.InstalledPackage{Name: name, Version: version, Arch: "amd64", State: "installed"}
	}
	before := &packages.PackagesOverview{Packages: []packages.InstalledPackage{
		pkg("curl", "8.5.0-1"), pkg("openssl", "3.0.13-1"), pkg("linux-image-6.8.0-40", "6.8.0-40.40"), pkg("vim", "9.1"),
	}}
	after := &packages.PackagesOverview{Updates: 2, Packages: []packages.InstalledPackage{
		pkg("curl", "8.5.0-2"), pkg("openssl", "3.0.13-2"), pkg("linux-image-6.8.0-41", "6.8.0-41.41"), pkg("vim", "9.1"),
	}}
	cases := []struct {
		name          string
		before, after *packages.PackagesOverview
		mode, want    string
	}{
		{"changes", before, after, packages.ModeFull, "2 packages upgraded, 1 new, 1 removed. 2 updates left (held or kept back)."},
		{"nothing", before, &packages.PackagesOverview{Packages: before.Packages}, packages.ModeAll, "Already up to date."},
		{"security left", before, &packages.PackagesOverview{Updates: 5, SecurityCount: 1, Packages: before.Packages}, packages.ModeSecurity, "Already up to date. 1 security update left (held or kept back)."},
	}
	for _, c := range cases {
		if got := upgradeNote(c.before, c.after, c.mode); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
