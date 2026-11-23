package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morche/backend/internal/sshpool"
	"github.com/morche/backend/internal/sysconf"
	"github.com/morche/backend/internal/terminal"
)

type RepoMirror struct {
	Current  string `json:"current" doc:"Where the distribution's own packages come from now" example:"http://archive.ubuntu.com/ubuntu"`
	Distro   string `json:"distro" doc:"os-release ID" example:"ubuntu"`
	Codename string `json:"codename" example:"noble"`
	CanSet   bool   `json:"can_set" doc:"Morche can switch the mirror here (apt on Ubuntu or Debian)"`
}

type ReposOverview struct {
	Revision string         `json:"revision"`
	Manager  string         `json:"manager" enum:"apt,dnf,yum,other"`
	Editable bool           `json:"editable"`
	Note     string         `json:"note"`
	Repos    []sysconf.Repo `json:"repos"`
	Mirror   RepoMirror     `json:"mirror"`
	Writable bool           `json:"writable"`
}

type RepoToggleBody struct {
	Revision string `json:"revision"`
	ID       string `json:"id" doc:"The repo's id from the list"`
	Enabled  bool   `json:"enabled"`
}

type RepoToggleInput struct {
	ID   string `path:"id" format:"uuid"`
	Body RepoToggleBody
}

type RepoAddBody struct {
	Revision   string   `json:"revision"`
	Name       string   `json:"name" doc:"Short name: the file is morche-<name>.sources or .repo" example:"docker"`
	Title      string   `json:"title,omitempty" required:"false" doc:".repo only: the name shown by dnf"`
	URIs       []string `json:"uris" minItems:"1" maxItems:"4" example:"[\"https://download.docker.com/linux/ubuntu\"]"`
	Suites     []string `json:"suites,omitempty" required:"false" maxItems:"6" doc:"apt only" example:"[\"noble\"]"`
	Components []string `json:"components,omitempty" required:"false" maxItems:"10" doc:"apt only" example:"[\"stable\"]"`
	SignedBy   string   `json:"signed_by,omitempty" required:"false" doc:"apt only: the key file that signs it" example:"/etc/apt/keyrings/docker.asc"`
	Source     bool     `json:"source,omitempty" required:"false" doc:"apt only: also source packages (deb-src)"`
	GPGCheck   bool     `json:"gpgcheck,omitempty" required:"false" doc:".repo only"`
	GPGKey     string   `json:"gpgkey,omitempty" required:"false" doc:".repo only: URL or file of the signing key"`
}

type RepoAddInput struct {
	ID   string `path:"id" format:"uuid"`
	Body RepoAddBody
}

type RepoRemoveBody struct {
	Revision string `json:"revision"`
	ID       string `json:"id"`
}

type RepoRemoveInput struct {
	ID   string `path:"id" format:"uuid"`
	Body RepoRemoveBody
}

type MirrorBody struct {
	Revision string `json:"revision"`
	URL      string `json:"url" example:"https://mirror.arvancloud.ir/ubuntu"`
}

type MirrorInput struct {
	ID   string `path:"id" format:"uuid"`
	Body MirrorBody
}

type MirrorTestBody struct {
	URL string `json:"url"`
}

type MirrorTestInput struct {
	ID   string `path:"id" format:"uuid"`
	Body MirrorTestBody
}

type MirrorTestResult struct {
	OK     bool   `json:"ok"`
	TookMS int64  `json:"took_ms"`
	Error  string `json:"error"`
	Tried  string `json:"tried" doc:"The address it fetched"`
}

const repoScript = `printf '\036M\n'; if command -v apt-get >/dev/null 2>&1; then echo apt; elif command -v dnf >/dev/null 2>&1; then echo dnf; elif command -v yum >/dev/null 2>&1; then echo yum; else echo other; fi
printf '\036O\n'; cat /etc/os-release 2>/dev/null
true`

type repoState struct {
	o     ReposOverview
	files []configFile
	paths []string
}

func osRelease(text string) (id, codename string) {
	for _, l := range strings.Split(text, "\n") {
		k, v, _ := strings.Cut(l, "=")
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			id = v
		case "VERSION_CODENAME":
			codename = v
		}
	}
	return id, codename
}

func parseRepoFile(f configFile) []sysconf.Repo {
	switch {
	case strings.HasSuffix(f.Path, ".sources"):
		return sysconf.ParseDeb822(f.Path, f.Text)
	case strings.HasSuffix(f.Path, ".repo"):
		return sysconf.ParseYumRepo(f.Path, f.Text)
	}
	return sysconf.ParseAptLine(f.Path, f.Text)
}

func repoFormat(p string) string {
	switch {
	case strings.HasSuffix(p, ".sources"):
		return "deb822"
	case strings.HasSuffix(p, ".repo"):
		return "repo"
	}
	return "line"
}

func (h *serverHandler) readRepos(ctx context.Context, sh *rootShell) (*repoState, error) {
	out, err := sh.run(ctx, repoScript)
	if err != nil {
		return nil, err
	}
	sec := netSections(out)
	st := &repoState{}
	o := &st.o
	o.Manager = strings.TrimSpace(sec["M"])
	o.Writable = sh.priv != privUser
	o.Mirror.Distro, o.Mirror.Codename = osRelease(sec["O"])
	switch o.Manager {
	case "apt":
		st.paths, err = listFiles(ctx, sh, "/etc/apt/sources.list", "/etc/apt/sources.list.d/*.list", "/etc/apt/sources.list.d/*.sources")
	case "dnf", "yum":
		st.paths, err = listFiles(ctx, sh, "/etc/yum.repos.d/*.repo")
	default:
		o.Note = "Package sources can be managed for apt, dnf and yum."
	}
	if err != nil {
		return nil, err
	}
	st.files, o.Revision, err = readConfigFiles(ctx, sh, st.paths...)
	if err != nil {
		return nil, err
	}
	o.Repos = []sysconf.Repo{}
	for _, f := range st.files {
		for _, r := range parseRepoFile(f) {
			o.Repos = append(o.Repos, r.Filled())
		}
	}
	o.Editable = o.Writable && o.Manager != "other"
	if o.Manager == "apt" {
		o.Mirror.Current = sysconf.CurrentMirror(o.Repos)
		o.Mirror.CanSet = o.Editable && (o.Mirror.Distro == "ubuntu" || o.Mirror.Distro == "debian")
	}
	return st, nil
}

func (st *repoState) find(id string) (sysconf.Repo, int, string, error) {
	file, n, ok := strings.Cut(id, "#")
	idx, err := strconv.Atoi(n)
	if !ok || err != nil {
		return sysconf.Repo{}, 0, "", fieldError("body.id", "Not a repository id", id)
	}
	for _, r := range st.o.Repos {
		if r.ID == id {
			text, _ := fileText(st.files, file)
			return r, idx, text, nil
		}
	}
	return sysconf.Repo{}, 0, "", huma.Error404NotFound("No such repository: the list changed, load it again")
}

func (st *repoState) check() string {
	switch st.o.Manager {
	case "apt":
		return "apt-cache policy >/dev/null"
	case "dnf":
		return "dnf -q -C repolist --all >/dev/null"
	case "yum":
		return "yum -q -C repolist all >/dev/null"
	}
	return ""
}

func (st *repoState) plan(summary string, writes ...configWrite) configPlan {
	read := append([]string{}, st.paths...)
	for _, w := range writes {
		if _, ok := fileText(st.files, w.Path); !ok && !slices.Contains(read, w.Path) {
			read = append(read, w.Path)
		}
	}
	return configPlan{Area: "repos", Summary: summary, Read: read, Writes: writes, Check: st.check()}
}

func repoLabel(r sysconf.Repo) string {
	if r.Name != "" {
		return r.Name
	}
	if len(r.URIs) > 0 {
		s := r.URIs[0]
		if len(r.Suites) > 0 {
			s += " " + r.Suites[0]
		}
		return s
	}
	return r.ID
}

var (
	repoName  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)
	repoWord  = regexp.MustCompile(`^[A-Za-z0-9._/~+-]{1,64}$`)
	repoPath  = regexp.MustCompile(`^/[A-Za-z0-9._/+-]{1,200}$`)
	plainText = regexp.MustCompile(`^[^\x00-\x1f]{0,100}$`)
)

func checkRepoURL(loc, u string) error {
	p, err := url.Parse(u)
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" || strings.ContainsAny(u, " \t\n\r\"'`$\\") || p.User != nil {
		return fieldError(loc, "Give an http:// or https:// address", u)
	}
	return nil
}

func checkRepoAdd(b RepoAddBody, manager string) error {
	if !repoName.MatchString(b.Name) {
		return fieldError("body.name", "Use lowercase letters, digits and hyphens", b.Name)
	}
	for i, u := range b.URIs {
		if err := checkRepoURL(fmt.Sprintf("body.uris[%d]", i), u); err != nil {
			return err
		}
	}
	if manager == "apt" {
		if len(b.Suites) == 0 {
			return fieldError("body.suites", "Give the suite (the release name, or ./ for a flat repository)", b.Suites)
		}
		for i, s := range append(append([]string{}, b.Suites...), b.Components...) {
			if !repoWord.MatchString(s) {
				return fieldError(fmt.Sprintf("body.suites[%d]", i), "One word: letters, digits, dots, slashes and hyphens", s)
			}
		}
		if b.SignedBy != "" && !repoPath.MatchString(b.SignedBy) {
			return fieldError("body.signed_by", "Give the full path of the key file", b.SignedBy)
		}
	} else {
		if !plainText.MatchString(b.Title) {
			return fieldError("body.title", "Keep it to plain text", b.Title)
		}
		if b.GPGKey != "" {
			if strings.HasPrefix(b.GPGKey, "/") || strings.HasPrefix(b.GPGKey, "file://") {
				if !repoPath.MatchString(strings.TrimPrefix(b.GPGKey, "file://")) {
					return fieldError("body.gpgkey", "Not a file path", b.GPGKey)
				}
			} else if err := checkRepoURL("body.gpgkey", b.GPGKey); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *serverHandler) reposOverview(ctx context.Context, id string) (*ReposOverview, error) {
	var o ReposOverview
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.rootShell(ctx, id, c)
		if err != nil {
			return err
		}
		st, err := h.readRepos(ctx, sh)
		if err == nil {
			o = st.o
		}
		return err
	})
	return &o, toProblem(err)
}

// reposChange runs one change built from the fresh state and answers the
// list after it.
func (h *serverHandler) reposChange(ctx context.Context, id, revision string, build func(st *repoState) (configPlan, error)) (*struct{ Body ReposOverview }, error) {
	_, err := h.configChange(ctx, id, revision, func(sh *rootShell) (configPlan, error) {
		st, err := h.readRepos(ctx, sh)
		if err != nil {
			return configPlan{}, err
		}
		if !st.o.Editable {
			return configPlan{}, huma.Error422UnprocessableEntity(strings.TrimSpace("Package sources can't be changed here. " + st.o.Note))
		}
		return build(st)
	})
	if err != nil {
		return nil, err
	}
	o, err := h.reposOverview(ctx, id)
	if err != nil {
		return nil, err
	}
	return &struct{ Body ReposOverview }{*o}, nil
}

func registerConfigRepos(api huma.API, h *serverHandler) {
	tags := []string{"Server config"}

	huma.Register(api, huma.Operation{
		OperationID: "get-server-repositories",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/repositories",
		Summary:     "Where the server gets its packages",
		Description: "Every apt source (one-line and deb822) or yum/dnf .repo section, and the mirror the distribution's own repositories use.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body ReposOverview }, error) {
		o, err := h.reposOverview(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body ReposOverview }{*o}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-server-repository",
		Method:      http.MethodPut,
		Path:        "/servers/{id}/repositories",
		Summary:     "Turn a repository on or off",
		Tags:        tags,
	}, func(ctx context.Context, in *RepoToggleInput) (*struct{ Body ReposOverview }, error) {
		return h.reposChange(ctx, in.ID, in.Body.Revision, func(st *repoState) (configPlan, error) {
			r, n, text, err := st.find(in.Body.ID)
			if err != nil {
				return configPlan{}, err
			}
			verb := "Turn off "
			if in.Body.Enabled {
				verb = "Turn on "
			}
			return st.plan(verb+repoLabel(r), configWrite{Path: r.File, Text: sysconf.SetRepoEnabled(r.Format, text, n, in.Body.Enabled)}), nil
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "add-server-repository",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/repositories",
		Summary:     "Add a repository",
		Description: "Writes /etc/apt/sources.list.d/morche-<name>.sources (deb822) or /etc/yum.repos.d/morche-<name>.repo. Refresh the package lists afterwards to use it.",
		Tags:        tags,
	}, func(ctx context.Context, in *RepoAddInput) (*struct{ Body ReposOverview }, error) {
		b := in.Body
		return h.reposChange(ctx, in.ID, b.Revision, func(st *repoState) (configPlan, error) {
			if err := checkRepoAdd(b, st.o.Manager); err != nil {
				return configPlan{}, err
			}
			var w configWrite
			if st.o.Manager == "apt" {
				r := sysconf.Repo{Types: []string{"deb"}, URIs: b.URIs, Suites: b.Suites, Components: b.Components, Options: map[string]string{}}
				if b.Source {
					r.Types = append(r.Types, "deb-src")
				}
				if b.SignedBy != "" {
					r.Options["Signed-By"] = b.SignedBy
				}
				w = configWrite{Path: "/etc/apt/sources.list.d/morche-" + b.Name + ".sources", Text: sysconf.PrintDeb822(r)}
			} else {
				opts := map[string]string{"gpgcheck": "0"}
				if b.Title != "" {
					opts["name"] = b.Title
				}
				if b.GPGCheck {
					opts["gpgcheck"] = "1"
				}
				if b.GPGKey != "" {
					opts["gpgkey"] = b.GPGKey
				}
				w = configWrite{Path: "/etc/yum.repos.d/morche-" + b.Name + ".repo", Text: sysconf.PrintYumRepo(sysconf.Repo{Name: b.Name, URIs: b.URIs[:1], Options: opts})}
			}
			if _, ok := fileText(st.files, w.Path); ok {
				return configPlan{}, fieldError("body.name", "A repository Morche added already has this name", b.Name)
			}
			return st.plan("Add "+b.Name+" ("+b.URIs[0]+")", w), nil
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-server-repository",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/repositories/delete",
		Summary:     "Remove a repository",
		Description: "Takes the entry out of its file (the file goes when nothing is left). The distribution's own repositories can only be turned off.",
		Tags:        tags,
	}, func(ctx context.Context, in *RepoRemoveInput) (*struct{ Body ReposOverview }, error) {
		return h.reposChange(ctx, in.ID, in.Body.Revision, func(st *repoState) (configPlan, error) {
			r, n, text, err := st.find(in.Body.ID)
			if err != nil {
				return configPlan{}, err
			}
			if r.Main {
				return configPlan{}, huma.Error422UnprocessableEntity("This is one of the distribution's own repositories: turn it off instead of removing it")
			}
			rest := sysconf.RemoveRepo(r.Format, text, n)
			w := configWrite{Path: r.File, Text: rest}
			left := 0
			for _, x := range st.o.Repos {
				if x.File == r.File {
					left++
				}
			}
			if left <= 1 {
				w = configWrite{Path: r.File, Remove: true}
			}
			return st.plan("Remove "+repoLabel(r), w), nil
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-server-mirror",
		Method:      http.MethodPut,
		Path:        "/servers/{id}/repositories/mirror",
		Summary:     "Get the distribution's packages from another mirror",
		Description: "Points every main Ubuntu or Debian repository (security too) at the mirror: give its base, ending in /ubuntu or /debian. Test it first.",
		Tags:        tags,
	}, func(ctx context.Context, in *MirrorInput) (*struct{ Body ReposOverview }, error) {
		u := strings.TrimRight(in.Body.URL, "/")
		if err := checkRepoURL("body.url", u); err != nil {
			return nil, err
		}
		return h.reposChange(ctx, in.ID, in.Body.Revision, func(st *repoState) (configPlan, error) {
			if !st.o.Mirror.CanSet {
				return configPlan{}, huma.Error422UnprocessableEntity("Switching the mirror works for apt on Ubuntu and Debian")
			}
			if want := st.o.Mirror.Distro; path.Base(u) != want {
				return configPlan{}, fieldError("body.url", "The mirror's address should end in /"+want, in.Body.URL)
			}
			var writes []configWrite
			for _, f := range st.files {
				fresh := sysconf.SetMirror(repoFormat(f.Path), f.Text, u)
				if fresh != f.Text {
					writes = append(writes, configWrite{Path: f.Path, Text: fresh})
				}
			}
			if len(writes) == 0 {
				return configPlan{}, huma.Error422UnprocessableEntity("No main repository to point at the mirror")
			}
			return st.plan("Mirror "+u, writes...), nil
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "test-server-mirror",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/repositories/mirror/test",
		Summary:     "Try a mirror from the server",
		Description: "Fetches the release file of this server's release from the mirror, from the server itself.",
		Tags:        tags,
	}, func(ctx context.Context, in *MirrorTestInput) (*struct{ Body MirrorTestResult }, error) {
		u := strings.TrimRight(in.Body.URL, "/")
		if err := checkRepoURL("body.url", u); err != nil {
			return nil, err
		}
		res := MirrorTestResult{}
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.rootShell(ctx, in.ID, c)
			if err != nil {
				return err
			}
			st, err := h.readRepos(ctx, sh)
			if err != nil {
				return err
			}
			if st.o.Mirror.Codename == "" {
				return huma.Error422UnprocessableEntity("This server's release name is unknown, so the mirror can't be tried")
			}
			res.Tried = u + "/dists/" + st.o.Mirror.Codename + "/Release"
			q := terminal.ShellQuote(res.Tried)
			script := "if command -v curl >/dev/null 2>&1; then curl -fsS -o /dev/null -m 15 " + q + "; " +
				"elif command -v wget >/dev/null 2>&1; then wget -q -T 15 -O /dev/null " + q + "; else echo 'Neither curl nor wget is installed'; exit 2; fi"
			start := time.Now()
			r, err := sh.exec(ctx, script, 25*time.Second, 4<<10)
			if err != nil {
				return err
			}
			res.TookMS = time.Since(start).Milliseconds()
			res.OK = r.code == 0
			if !res.OK {
				res.Error = configMessage(r.output, "The mirror didn't answer, or it doesn't have this release")
			}
			return nil
		})
		if err != nil {
			return nil, toProblem(err)
		}
		return &struct{ Body MirrorTestResult }{res}, nil
	})

	configRestorers["repos"] = func(ctx context.Context, h *serverHandler, _ string, sh *rootShell, _ []ConfigChangeFile) (configPlan, error) {
		st, err := h.readRepos(ctx, sh)
		if err != nil {
			return configPlan{}, err
		}
		return configPlan{Read: st.paths, Check: st.check()}, nil
	}
}
