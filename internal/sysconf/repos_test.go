package sysconf

import (
	"slices"
	"strings"
	"testing"
)

const aptList = `deb http://archive.ubuntu.com/ubuntu noble main restricted
# deb-src http://archive.ubuntu.com/ubuntu noble main restricted
deb [arch=amd64 signed-by=/usr/share/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable
## Plain comment line
deb http://security.ubuntu.com/ubuntu noble-security main
`

const aptDeb822 = `Types: deb
URIs: http://archive.ubuntu.com/ubuntu/
Suites: noble noble-updates
Components: main restricted
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

## Security
Types: deb deb-src
URIs: http://security.ubuntu.com/ubuntu/
Suites: noble-security
Components: main
Enabled: no
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
`

const yumRepo = `[baseos]
name=Rocky Linux $releasever - BaseOS
mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&repo=BaseOS-$releasever
#baseurl=http://dl.rockylinux.org/$contentdir/$releasever/BaseOS/$basearch/os/
gpgcheck=1
enabled=1

[docker-ce-stable]
name=Docker CE Stable - $basearch
baseurl=https://download.docker.com/linux/rhel/$releasever/$basearch/stable
enabled=0
gpgcheck=1
`

func TestAptSources(t *testing.T) {
	rs := ParseAptLine("/etc/apt/sources.list", aptList)
	if len(rs) != 4 {
		t.Fatalf("%+v", rs)
	}
	if r := rs[0]; r.ID != "/etc/apt/sources.list#1" || !r.Enabled || !r.Main || r.Format != "line" ||
		!slices.Equal(r.Types, []string{"deb"}) || !slices.Equal(r.Suites, []string{"noble"}) || !slices.Equal(r.Components, []string{"main", "restricted"}) {
		t.Fatalf("main: %+v", r)
	}
	if r := rs[1]; r.Enabled || r.Types[0] != "deb-src" || r.ID != "/etc/apt/sources.list#2" {
		t.Fatalf("src: %+v", r)
	}
	if r := rs[2]; r.Main || r.Options["arch"] != "amd64" || r.Options["signed-by"] != "/usr/share/keyrings/docker.gpg" || r.URIs[0] != "https://download.docker.com/linux/ubuntu" {
		t.Fatalf("docker: %+v", r)
	}
	if r := rs[3]; !r.Main || r.ID != "/etc/apt/sources.list#5" {
		t.Fatalf("security: %+v", r)
	}

	ds := ParseDeb822("/etc/apt/sources.list.d/ubuntu.sources", aptDeb822)
	if len(ds) != 2 {
		t.Fatalf("%+v", ds)
	}
	if d := ds[0]; !d.Enabled || !d.Main || d.ID != "/etc/apt/sources.list.d/ubuntu.sources#1" || !slices.Equal(d.Suites, []string{"noble", "noble-updates"}) || d.Options["Signed-By"] == "" {
		t.Fatalf("deb822 main: %+v", d)
	}
	if d := ds[1]; d.Enabled || !slices.Equal(d.Types, []string{"deb", "deb-src"}) {
		t.Fatalf("deb822 security: %+v", d)
	}
	if m := ParseDeb822("/etc/apt/sources.list.d/morche-tools.sources", "Types: deb\nURIs: https://x\nSuites: ./\n"); !m[0].Morche {
		t.Fatal("morche file not marked")
	}
	if CurrentMirror(append(rs, ds...)) != "http://archive.ubuntu.com/ubuntu" {
		t.Fatal(CurrentMirror(rs))
	}
}

func TestYumRepo(t *testing.T) {
	rs := ParseYumRepo("/etc/yum.repos.d/rocky.repo", yumRepo)
	if len(rs) != 2 {
		t.Fatalf("%+v", rs)
	}
	if r := rs[0]; r.Name != "baseos" || !r.Enabled || r.Options["name"] != "Rocky Linux $releasever - BaseOS" || len(r.URIs) != 1 || !strings.HasPrefix(r.URIs[0], "https://mirrors.rockylinux.org") || r.ID != "/etc/yum.repos.d/rocky.repo#1" {
		t.Fatalf("%+v", r)
	}
	if r := rs[1]; r.Enabled || r.URIs[0] != "https://download.docker.com/linux/rhel/$releasever/$basearch/stable" {
		t.Fatalf("%+v", r)
	}
}

func TestSetRepoEnabled(t *testing.T) {
	off := SetRepoEnabled("line", aptList, 1, false)
	if !strings.HasPrefix(off, "# deb http://archive.ubuntu.com/ubuntu noble main restricted\n") {
		t.Fatalf("line off:\n%s", off)
	}
	if SetRepoEnabled("line", off, 1, true) != aptList {
		t.Fatal("line on did not give the text back")
	}
	on := SetRepoEnabled("line", aptList, 2, true)
	if !strings.Contains(on, "\ndeb-src http://archive") {
		t.Fatalf("line on:\n%s", on)
	}

	d := SetRepoEnabled("deb822", aptDeb822, 2, true)
	if strings.Contains(d, "Enabled") {
		t.Fatalf("deb822 on:\n%s", d)
	}
	d = SetRepoEnabled("deb822", d, 1, false)
	if rs := ParseDeb822("f", d); rs[0].Enabled || !rs[1].Enabled {
		t.Fatalf("deb822 off:\n%s", d)
	}

	y := SetRepoEnabled("repo", yumRepo, 2, true)
	if rs := ParseYumRepo("f", y); !rs[1].Enabled || !rs[0].Enabled {
		t.Fatalf("repo on:\n%s", y)
	}
	y = SetRepoEnabled("repo", "[a]\nname=A\nbaseurl=x\n", 1, false)
	if y != "[a]\nenabled=0\nname=A\nbaseurl=x\n" {
		t.Fatalf("repo off added:\n%q", y)
	}
}

func TestSetMirror(t *testing.T) {
	got := SetMirror("line", aptList, "https://mirror.example.ir/ubuntu")
	want := strings.NewReplacer(
		"deb http://archive.ubuntu.com/ubuntu noble", "deb https://mirror.example.ir/ubuntu noble",
		"deb-src http://archive.ubuntu.com/ubuntu", "deb-src https://mirror.example.ir/ubuntu",
		"deb http://security.ubuntu.com/ubuntu", "deb https://mirror.example.ir/ubuntu",
	).Replace(aptList)
	if got != want {
		t.Fatalf("line:\n%s", got)
	}
	d := SetMirror("deb822", aptDeb822, "https://mirror.example.ir/ubuntu")
	if strings.Count(d, "URIs: https://mirror.example.ir/ubuntu\n") != 2 {
		t.Fatalf("deb822:\n%s", d)
	}
	deb := "deb http://deb.debian.org/debian bookworm main\ndeb http://security.debian.org/debian-security bookworm-security main\n"
	if got := SetMirror("line", deb, "https://m.example/debian/"); got != "deb https://m.example/debian bookworm main\ndeb https://m.example/debian-security bookworm-security main\n" {
		t.Fatalf("debian:\n%s", got)
	}
}

func TestPrintNewRepos(t *testing.T) {
	r := Repo{Types: []string{"deb"}, URIs: []string{"https://pkg.example.com/apt"}, Suites: []string{"stable"}, Components: []string{"main"}, Options: map[string]string{"Signed-By": "/etc/apt/keyrings/example.asc"}}
	got := PrintDeb822(r)
	back := ParseDeb822("/etc/apt/sources.list.d/morche-example.sources", got)
	if len(back) != 1 || back[0].URIs[0] != "https://pkg.example.com/apt" || back[0].Options["Signed-By"] != "/etc/apt/keyrings/example.asc" || !back[0].Enabled {
		t.Fatalf("%s\n%+v", got, back)
	}
	y := PrintYumRepo(Repo{Name: "example", URIs: []string{"https://pkg.example.com/rpm"}, Options: map[string]string{"name": "Example", "gpgcheck": "1"}})
	yb := ParseYumRepo("f", y)
	if len(yb) != 1 || yb[0].Name != "example" || yb[0].Options["gpgcheck"] != "1" || !yb[0].Enabled {
		t.Fatalf("%s", y)
	}
}

func TestRemoveRepo(t *testing.T) {
	if got := RemoveRepo("line", aptList, 3); strings.Contains(got, "docker") || !strings.Contains(got, "## Plain comment line") {
		t.Fatalf("line:\n%s", got)
	}
	got := RemoveRepo("deb822", aptDeb822, 2)
	if rs := ParseDeb822("f", got); len(rs) != 1 || strings.Contains(got, "security") {
		t.Fatalf("deb822:\n%s", got)
	}
	got = RemoveRepo("repo", yumRepo, 2)
	if rs := ParseYumRepo("f", got); len(rs) != 1 || rs[0].Name != "baseos" || strings.Contains(got, "docker") {
		t.Fatalf("repo:\n%s", got)
	}
}
