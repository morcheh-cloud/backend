package packages

import (
	"os"
	"slices"
	"testing"
)

// The fixtures in testdata/<pm>/ are real outputs of the scripts, taken
// in containers (see dump_test.go for how to make them again).

func fixture(t *testing.T, pm, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + pm + "/" + name + ".out")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseOverview(t *testing.T) {
	cases := []struct {
		pm                   string
		min, updates, secure int
	}{
		{APT, 80, -1, 1},
		{DNF, 100, 17, 5},
		{Zypper, 100, 0, 0},
		{APK, 10, 9, 0},
		{Pacman, 100, 26, 0},
	}
	for _, c := range cases {
		t.Run(c.pm, func(t *testing.T) {
			o := ParseOverview(fixture(t, c.pm, "overview"))
			if o.Manager != c.pm {
				t.Fatalf("manager = %q", o.Manager)
			}
			if len(o.Packages) < c.min {
				t.Fatalf("%d packages, want at least %d", len(o.Packages), c.min)
			}
			if c.updates >= 0 && o.Updates != c.updates {
				t.Errorf("updates = %d, want %d", o.Updates, c.updates)
			}
			if o.SecurityCount < c.secure {
				t.Errorf("security = %d, want at least %d", o.SecurityCount, c.secure)
			}
			n := 0
			for _, p := range o.Packages {
				if p.Name == "" || p.Version == "" {
					t.Fatalf("empty package %+v", p)
				}
				if p.Latest != "" {
					n++
				}
			}
			if n != o.Updates {
				t.Errorf("%d packages with a newer version, overview says %d", n, o.Updates)
			}
			if o.Warnings == nil || o.RebootPackages == nil {
				t.Error("nil list")
			}
		})
	}
}

func TestParseInfo(t *testing.T) {
	cases := []struct{ pm, installed string }{
		{APT, "less"}, {DNF, "less"}, {Zypper, "less"}, {APK, "busybox"}, {Pacman, "sed"},
	}
	for _, c := range cases {
		t.Run(c.pm, func(t *testing.T) {
			i, ok := ParseInfo(c.installed, fixture(t, c.pm, "info-installed"))
			if !ok || !i.Installed || i.Version == "" || i.Summary == "" {
				t.Fatalf("installed: ok=%v %+v", ok, i)
			}
			if len(i.Files) == 0 {
				t.Error("no files")
			}
			if len(i.Depends) == 0 {
				t.Error("no dependencies")
			}
			if len(i.Versions) > 0 && !slices.ContainsFunc(i.Versions, func(v PackageVersion) bool { return v.Installed && v.Version == i.Version }) {
				t.Errorf("installed version %s not marked in %+v", i.Version, i.Versions)
			}
			r, ok := ParseInfo("htop", fixture(t, c.pm, "info-remote"))
			if !ok || r.Installed || r.Latest == "" || r.Summary == "" {
				t.Fatalf("remote: ok=%v %+v", ok, r)
			}
			if len(r.Files) != 0 {
				t.Error("files for a package that isn't installed")
			}
		})
	}
	if _, ok := ParseInfo("nope", "@@ meta\npm apt\n"); ok {
		t.Error("found a package in empty output")
	}
}

func TestParseSearch(t *testing.T) {
	for _, pm := range []string{APT, DNF, Zypper, APK, Pacman} {
		t.Run(pm, func(t *testing.T) {
			m := ParseSearch(fixture(t, pm, "search"), "htop", 10)
			if len(m) == 0 || m[0].Name != "htop" {
				t.Fatalf("htop isn't first: %+v", m)
			}
			for _, x := range m {
				if x.Installed == "?" {
					t.Error("placeholder left")
				}
			}
		})
	}
}

func TestApplyCandidates(t *testing.T) {
	m := []PackageMatch{{Name: "less"}, {Name: "htop", Installed: "?"}}
	ApplyCandidates(m, "@@ policy\nless:\n  Installed: 590-2ubuntu2.1\n  Candidate: 590-2ubuntu2.1\n  Version table:\n *** 590-2ubuntu2.1 500\n        500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages\nhtop:\n  Installed: (none)\n  Candidate: 3.3.0-4build1\n  Version table:\n     3.3.0-4build1 500\n        500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages\n")
	if m[0].Installed != "590-2ubuntu2.1" || m[0].Version != "590-2ubuntu2.1" {
		t.Errorf("less: %+v", m[0])
	}
	if m[1].Installed != "" || m[1].Version != "3.3.0-4build1" || m[1].Repo == "" {
		t.Errorf("htop: %+v", m[1])
	}
}

func TestParseHistory(t *testing.T) {
	for _, pm := range []string{APT, DNF, Zypper, Pacman} {
		t.Run(pm, func(t *testing.T) {
			h := ParseHistory(fixture(t, pm, "history"))
			if len(h) == 0 {
				t.Fatal("no history")
			}
			for i, e := range h {
				if e.At.IsZero() || len(e.Changes) == 0 && e.Error == "" {
					t.Fatalf("entry %d: %+v", i, e)
				}
				if i > 0 && e.At.After(h[i-1].At) {
					t.Fatal("not newest first")
				}
				for _, c := range e.Changes {
					if c.Name == "" || c.Action == "" {
						t.Fatalf("change %+v", c)
					}
				}
			}
			found := slices.ContainsFunc(h, func(e PackageHistoryEntry) bool {
				return slices.ContainsFunc(e.Changes, func(c PackageChange) bool { return c.Name == "less" || c.Name == "filesystem" })
			})
			if !found {
				t.Error("the test install isn't in the history")
			}
		})
	}
	if h := ParseHistory(fixture(t, APK, "history")); h == nil || len(h) != 0 {
		t.Errorf("apk: %+v", h)
	}
}

func TestDNFHistoryUpgrade(t *testing.T) {
	h := ParseHistory(fixture(t, DNF, "history"))
	i := slices.IndexFunc(h[0].Changes, func(c PackageChange) bool { return c.Name == "glibc" })
	if i < 0 {
		t.Fatalf("no glibc in %+v", h[0])
	}
	if c := h[0].Changes[i]; c.Action != "upgrade" || c.From == "" || c.To == "" || c.From == c.To {
		t.Errorf("glibc: %+v", c)
	}
	if h[0].User != "root" || h[0].Command == "" {
		t.Errorf("entry: %+v", h[0])
	}
}

func TestParsePreview(t *testing.T) {
	for _, pm := range []string{APT, DNF, Zypper, APK, Pacman} {
		t.Run(pm, func(t *testing.T) {
			p := ParsePreview(ActInstall, fixture(t, pm, "preview-install"))
			if !slices.ContainsFunc(p.Changes, func(c PackageChange) bool { return c.Name == "htop" && c.Action == "install" }) {
				t.Errorf("install: %+v", p)
			}
			p = ParsePreview(ActRemove, fixture(t, pm, "preview-remove"))
			if len(p.Changes) == 0 && len(p.Problems) == 0 {
				t.Errorf("remove says nothing: %+v", p)
			}
			p = ParsePreview(ActUpgradeAll, fixture(t, pm, "preview-upgrade"))
			if p.Changes == nil || p.Problems == nil {
				t.Error("nil list")
			}
			for _, c := range p.Changes {
				if c.Action == "upgrade" && (c.From == "" && pm != Zypper || c.To == "" && pm != Zypper) {
					t.Errorf("upgrade without versions: %+v", c)
				}
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.10", "1.9", 1},
		{"1.0~rc1", "1.0", -1},
		{"1:1.0", "2.0", 1},
		{"2.41-16.fc42", "2.41-18.fc42", -1},
		{"590-2ubuntu2.1", "590-2ubuntu2", 1},
		{"1.0a", "1.0", 1},
		{"6.5_p20251123-r0", "6.5-r0", 1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareVersions(c.b, c.a); got != -c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestValid(t *testing.T) {
	for _, n := range []string{"less", "libc6:amd64", "g++", "python3.12", "xorg-x11-server-Xorg"} {
		if !ValidName(n) {
			t.Errorf("%q refused", n)
		}
	}
	for _, n := range []string{"", "-rf", "a b", "a;b", "$(x)", "a/b"} {
		if ValidName(n) {
			t.Errorf("%q let through", n)
		}
	}
}

func TestAptDeferred(t *testing.T) {
	out := "@@ meta\npm apt\n@@ out\nCalculating upgrade...\nThe following upgrades have been deferred due to phasing:\n  distro-info python3-distro-info\n  software-properties-common\nThe following packages have been kept back:\n  linux-generic\nThe following packages will be upgraded:\n  snapd\nInst snapd [2.76] (2.78 Ubuntu [amd64])\n"
	p := ParsePreview(ActUpgradeAll, out)
	if !slices.Equal(p.Deferred, []string{"distro-info", "python3-distro-info", "software-properties-common"}) || !slices.Equal(p.KeptBack, []string{"linux-generic"}) || len(p.Changes) != 1 {
		t.Errorf("%+v", p)
	}
}
