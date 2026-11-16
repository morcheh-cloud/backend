package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/cmdlog"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/sshpool"
	"github.com/morche/backend/internal/terminal"
)

// Compose projects outside the workspace's projects folder: found by a scan
// of the server's disk, added by path, or seen once through their
// containers. They are kept in docker_project_places so they stay listed
// (and editable) whether or not anything runs.

// ---- API shapes ----

type DockerProjectFound struct {
	Name     string   `json:"name" doc:"The project name compose would use for it"`
	Dir      string   `json:"dir"`
	Files    []string `json:"files" doc:"The compose file, then any override beside it"`
	Services []string `json:"services"`
	Problem  string   `json:"problem,omitempty" doc:"Why it can't be added as it is (unreadable file, no usable name…)"`
	State    string   `json:"state" enum:"new,listed,forgotten,clash" doc:"new = not listed yet; listed = already a project; forgotten = someone chose to forget it; clash = another project already has its name"`
	Project  string   `json:"project,omitempty" doc:"listed: the project it is; clash: the project holding its name"`
}

type DockerProjectScanResult struct {
	ScannedAt *time.Time           `json:"scanned_at,omitempty" doc:"Empty = never looked"`
	Running   bool                 `json:"running" doc:"A look is going on now"`
	TookMs    int                  `json:"took_ms"`
	Truncated bool                 `json:"truncated" doc:"It stopped early (too slow or too many files); what it found is listed"`
	Error     string               `json:"error,omitempty"`
	Items     []DockerProjectFound `json:"items"`
	New       int                  `json:"new" doc:"Items in state new without a problem"`
}

type DockerProjectScanBody struct {
	Paths []string `json:"paths,omitempty" maxItems:"10" doc:"Folders to look in; empty = the whole disk (system folders skipped)"`
	Depth int      `json:"depth,omitempty" minimum:"1" maximum:"12" doc:"How many folders deep; default 7"`
}

type DockerProjectAddItem struct {
	Path string `json:"path" minLength:"1" maxLength:"1024" doc:"A compose file, or the folder holding one"`
	Name string `json:"name,omitempty" maxLength:"63" doc:"Empty = the name compose would use"`
}

type DockerProjectAddBody struct {
	Items []DockerProjectAddItem `json:"items" minItems:"1" maxItems:"100"`
}

type DockerProjectAddProblem struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

type DockerProjectAddResult struct {
	Added    []string                  `json:"added" doc:"Names of the projects now listed"`
	Problems []DockerProjectAddProblem `json:"problems"`
}

// ---- Merging into the list ----

// mergePlaces adds the server's kept places to byName and returns where
// each listed project came from. Projects its containers name but that
// aren't kept yet are remembered, so a `down` doesn't make them vanish.
func (h *serverHandler) mergePlaces(ctx context.Context, id, root string, byName map[string]*DockerProject, get func(string) *DockerProject) map[string]string {
	sources := map[string]string{}
	sid, err := uuid.Parse(id)
	if err != nil {
		return sources
	}
	rows, err := h.q.DockerProjectPlaces(ctx, sid)
	if err != nil {
		slog.Warn("docker: project places", "server", id, "error", err)
		return sources
	}
	kept := map[string]bool{}
	for _, r := range rows {
		kept[r.Project] = true
		if p := byName[r.Project]; p != nil {
			if p.Dir == "" || path.Clean(p.Dir) == path.Clean(r.Dir) {
				sources[r.Project] = r.Source
				if p.Dir == "" {
					p.Dir = r.Dir
				}
				if len(p.Files) == 0 {
					p.Files = append([]string{}, r.Files...)
				}
			}
			continue // a project of the same name lives elsewhere
		}
		if r.Hidden {
			continue
		}
		p := get(r.Project)
		p.Dir, p.Files = r.Dir, append([]string{}, r.Files...)
		sources[r.Project] = r.Source
	}
	for name, p := range byName {
		if kept[name] || p.Total == 0 || p.Dir == "" || len(p.Files) == 0 || path.Dir(path.Clean(p.Dir)) == root {
			continue
		}
		if err := h.q.RememberDockerProjectPlace(ctx, sqlc.RememberDockerProjectPlaceParams{
			ServerID: sid, Project: name, Dir: p.Dir, Files: p.Files,
		}); err != nil {
			slog.Warn("docker: remembering a project", "server", id, "project", name, "error", err)
		}
	}
	return sources
}

// ---- Looking for compose files ----

var composeOverrideNames = []string{"compose.override.yaml", "compose.override.yml", "docker-compose.override.yaml", "docker-compose.override.yml"}

// Folders a scan of / never goes into.
var scanSkipPaths = []string{
	"/proc", "/sys", "/dev", "/run", "/boot", "/tmp", "/var/tmp", "/var/cache", "/var/log",
	"/var/lib/docker", "/var/lib/containers", "/var/lib/containerd", "/var/lib/apt", "/var/lib/dpkg",
	"/var/lib/snapd", "/snap", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/usr/bin", "/usr/sbin",
	"/usr/lib", "/usr/lib32", "/usr/lib64", "/usr/libexec", "/usr/include", "/usr/share", "/usr/src",
	"/nix", "/lost+found",
}

// Folder names skipped anywhere: dependency and build trees full of
// example compose files.
var scanSkipNames = []string{"node_modules", ".git", ".cache", ".npm", ".cargo", ".rustup", "site-packages", "vendor", ".venv", "venv", ".gradle", ".m2", ".pnpm-store", ".yarn", ".Trash"}

const (
	scanMaxFiles    = 3000
	scanMaxProjects = 300
	scanTimeout     = 60 // seconds, for find itself
)

var projectScans = struct {
	sync.Mutex
	running map[string]bool
	done    map[string]bool // a scan row exists (saves a query per list)
}{running: map[string]bool{}, done: map[string]bool{}}

// maybeAutoScan looks for compose files once per server, in the background,
// the first time its projects are listed.
func (h *serverHandler) maybeAutoScan(id string) {
	projectScans.Lock()
	if projectScans.running[id] || projectScans.done[id] {
		projectScans.Unlock()
		return
	}
	projectScans.running[id] = true
	projectScans.Unlock()
	go func() {
		ctx := cmdlog.Background(context.Background(), "Looking for compose projects")
		finish := func(done bool) {
			projectScans.Lock()
			delete(projectScans.running, id)
			if done {
				projectScans.done[id] = true
			}
			projectScans.Unlock()
		}
		sid, err := uuid.Parse(id)
		if err != nil {
			finish(true)
			return
		}
		if _, err := h.q.DockerProjectScan(ctx, sid); err == nil {
			finish(true)
			return
		} else if !isNotFound(err) {
			finish(false)
			return
		}
		c, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		h.scanProjects(c, id, nil, 0)
		finish(true)
	}()
}

func scanRunning(id string) bool {
	projectScans.Lock()
	defer projectScans.Unlock()
	return projectScans.running[id]
}

// scanProjects looks for compose files on the server and keeps what it
// found as the server's last scan.
func (h *serverHandler) scanProjects(ctx context.Context, id string, paths []string, depth int) error {
	sid, err := uuid.Parse(id)
	if err != nil {
		return huma.Error404NotFound("server not found")
	}
	if depth <= 0 {
		depth = 7
	}
	if len(paths) == 0 {
		paths = []string{"/"}
	}
	started := time.Now()
	var items []DockerProjectFound
	truncated := false
	err = h.withShell(ctx, id, func(_ *sshpool.Conn, sh *rootShell) error {
		files, cut, err := findComposeFiles(ctx, sh, paths, depth)
		if err != nil {
			return err
		}
		truncated = cut
		groups := groupComposeFiles(files)
		if len(groups) > scanMaxProjects {
			groups, truncated = groups[:scanMaxProjects], true
		}
		items, err = describeComposeDirs(ctx, sh, groups)
		return err
	})
	row := sqlc.SaveDockerProjectScanParams{ServerID: sid, TookMs: int32(time.Since(started).Milliseconds()), Truncated: truncated}
	if err != nil {
		row.Error = dockerProblemText(err)
	}
	if items == nil {
		items = []DockerProjectFound{}
	}
	row.Items, _ = json.Marshal(items)
	if serr := h.q.SaveDockerProjectScan(ctx, row); serr != nil {
		slog.Warn("docker: keeping a project scan", "server", id, "error", serr)
	}
	projectScans.Lock()
	projectScans.done[id] = true
	projectScans.Unlock()
	return err
}

// findComposeFiles lists compose files (and overrides) under paths.
func findComposeFiles(ctx context.Context, sh *rootShell, paths []string, depth int) ([]string, bool, error) {
	q := terminal.ShellQuote
	var prune []string
	for _, p := range scanSkipPaths {
		prune = append(prune, "-path "+q(p))
	}
	for _, n := range scanSkipNames {
		prune = append(prune, "-name "+q(n))
	}
	prune = append(prune, "-path '*/go/pkg'")
	var names []string
	for _, n := range append(slices.Clone(composeFileNames), composeOverrideNames...) {
		names = append(names, "-name "+q(n))
	}
	var roots []string
	for _, p := range paths {
		roots = append(roots, q(p))
	}
	script := `T=; command -v timeout >/dev/null 2>&1 && T="timeout ` + strconv.Itoa(scanTimeout) + `"
out=$($T find ` + strings.Join(roots, " ") + ` -maxdepth ` + strconv.Itoa(depth) +
		` \( ` + strings.Join(prune, " -o ") + ` \) -prune -o -type f \( ` + strings.Join(names, " -o ") +
		` \) -size -1024k -print 2>/dev/null); code=$?
printf '%s\n' "$out" | head -n ` + strconv.Itoa(scanMaxFiles+1) + `
echo "#code $code"`
	res, err := sh.exec(ctx, script, (scanTimeout+20)*time.Second, 4<<20)
	if err != nil {
		return nil, false, err
	}
	var files []string
	truncated := res.truncated || res.timedOut
	for l := range strings.SplitSeq(string(res.output), "\n") {
		if code, ok := strings.CutPrefix(l, "#code "); ok {
			if code == "124" {
				truncated = true
			}
			continue
		}
		if l == "" || strings.ContainsAny(l, "\t\r") || !path.IsAbs(l) {
			continue
		}
		files = append(files, l)
	}
	if len(files) > scanMaxFiles {
		files, truncated = files[:scanMaxFiles], true
	}
	return files, truncated, nil
}

type composeGroup struct {
	dir   string
	files []string // main file first, then overrides
}

// groupComposeFiles picks, per folder, the file compose itself would read
// (compose.yaml before docker-compose.yml) and the overrides beside it.
func groupComposeFiles(files []string) []composeGroup {
	byDir := map[string][]string{}
	for _, f := range files {
		d := path.Dir(f)
		byDir[d] = append(byDir[d], path.Base(f))
	}
	var out []composeGroup
	for d, names := range byDir {
		main := ""
		for _, n := range composeFileNames {
			if slices.Contains(names, n) {
				main = n
				break
			}
		}
		if main == "" {
			continue // only an override
		}
		g := composeGroup{dir: d, files: []string{path.Join(d, main)}}
		for _, n := range composeOverrideNames {
			if slices.Contains(names, n) {
				g.files = append(g.files, path.Join(d, n))
			}
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].dir < out[j].dir })
	return out
}

// describeComposeDirs reads each main file (its first 64 KiB) and the
// COMPOSE_PROJECT_NAME of the .env beside it, for the name and services.
// The contents stay out of the command log.
func describeComposeDirs(ctx context.Context, sh *rootShell, groups []composeGroup) ([]DockerProjectFound, error) {
	if len(groups) == 0 {
		return []DockerProjectFound{}, nil
	}
	q := terminal.ShellQuote
	var b strings.Builder
	for i, g := range groups {
		b.WriteString("f=" + q(g.files[0]) + "; printf '%s\\t' " + strconv.Itoa(i) + "\n")
		b.WriteString(`if [ -r "$f" ]; then head -c 65536 "$f" | base64 | tr -d '\n'; else printf '!'; fi; printf '\t'` + "\n")
		b.WriteString("e=" + q(path.Join(g.dir, ".env")) + `; [ -r "$e" ] && grep -m1 '^COMPOSE_PROJECT_NAME=' "$e" | cut -d= -f2- | tr -d "\"'\r"; echo` + "\n")
	}
	out, err := sh.hiding(true).run(ctx, b.String())
	if err != nil {
		return nil, err
	}
	found := make([]DockerProjectFound, len(groups))
	for i, g := range groups {
		found[i] = DockerProjectFound{Dir: g.dir, Files: g.files, Services: []string{}, Problem: "Couldn't read it"}
	}
	for l := range strings.SplitSeq(out, "\n") {
		parts := strings.SplitN(l, "\t", 3)
		if len(parts) < 3 {
			continue
		}
		i, err := strconv.Atoi(parts[0])
		if err != nil || i < 0 || i >= len(groups) {
			continue
		}
		f := &found[i]
		f.Problem = ""
		envName := strings.TrimSpace(parts[2])
		if parts[1] == "!" {
			f.Problem = "The server's login can't read this file (give it sudo)"
			f.Name = composeNameFor(f.Dir, "", envName)
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			f.Problem = "Couldn't read it"
			continue
		}
		var doc struct {
			Name     string         `yaml:"name"`
			Services map[string]any `yaml:"services"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil && len(raw) < 65536 {
			f.Problem = "It isn't valid YAML: " + firstLine(err.Error())
		}
		for s := range doc.Services {
			f.Services = append(f.Services, s)
		}
		sort.Strings(f.Services)
		if f.Problem == "" && len(doc.Services) == 0 && len(raw) < 65536 {
			f.Problem = "It has no services"
		}
		f.Name = composeNameFor(f.Dir, doc.Name, envName)
		if f.Problem == "" && !projectNameRe.MatchString(f.Name) {
			f.Problem = "Compose can't make a project name from its folder: give it one"
		}
	}
	return found, nil
}

// composeNameFor is the project name `docker compose` uses: the file's
// `name:`, else COMPOSE_PROJECT_NAME from .env, else the folder's name,
// lowercased with anything but a-z 0-9 _ - dropped.
func composeNameFor(dir, fileName, envName string) string {
	for _, n := range []string{fileName, envName} {
		if n != "" && !strings.Contains(n, "$") {
			return normalizeComposeName(n)
		}
	}
	return normalizeComposeName(path.Base(dir))
}

func normalizeComposeName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	return strings.TrimLeft(b.String(), "_-")
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}

// scanResult is the last scan, each item's state worked out against what's
// listed now.
func (h *serverHandler) scanResult(ctx context.Context, id string) (DockerProjectScanResult, error) {
	res := DockerProjectScanResult{Running: scanRunning(id), Items: []DockerProjectFound{}}
	sid, err := uuid.Parse(id)
	if err != nil {
		return res, huma.Error404NotFound("server not found")
	}
	row, err := h.q.DockerProjectScan(ctx, sid)
	if isNotFound(err) {
		return res, nil
	}
	if err != nil {
		return res, internalError(err)
	}
	at := row.ScannedAt
	res.ScannedAt, res.TookMs, res.Truncated, res.Error = &at, int(row.TookMs), row.Truncated, row.Error
	if err := json.Unmarshal(row.Items, &res.Items); err != nil {
		return res, internalError(err)
	}
	ps, _, err := h.dockerProjects(ctx, id)
	if err != nil {
		return res, err
	}
	hidden := map[string]bool{} // dirs
	if rows, err := h.q.DockerProjectPlaces(ctx, sid); err == nil {
		for _, r := range rows {
			if r.Hidden {
				hidden[path.Clean(r.Dir)] = true
			}
		}
	}
	byDir, byName := map[string]string{}, map[string]string{}
	for _, p := range ps {
		if p.Dir != "" {
			byDir[path.Clean(p.Dir)] = p.Name
		}
		byName[p.Name] = p.Dir
	}
	for i := range res.Items {
		f := &res.Items[i]
		dir := path.Clean(f.Dir)
		switch {
		case byDir[dir] != "":
			f.State, f.Project = "listed", byDir[dir]
		case hidden[dir]:
			f.State = "forgotten"
		case f.Name != "" && byName[f.Name] != "" || (f.Name != "" && hasName(ps, f.Name)):
			f.State, f.Project = "clash", f.Name
		default:
			f.State = "new"
			if f.Problem == "" {
				res.New++
			}
		}
	}
	return res, nil
}

func hasName(ps []DockerProject, name string) bool {
	return slices.ContainsFunc(ps, func(p DockerProject) bool { return p.Name == name })
}

// ---- Adding ----

// addProjects keeps each path as a project, checking that its compose file
// is there and its name is free.
func (h *serverHandler) addProjects(ctx context.Context, id string, items []DockerProjectAddItem) (DockerProjectAddResult, error) {
	res := DockerProjectAddResult{Added: []string{}, Problems: []DockerProjectAddProblem{}}
	sid, err := uuid.Parse(id)
	if err != nil {
		return res, huma.Error404NotFound("server not found")
	}
	for i := range items {
		p := strings.TrimSpace(items[i].Path)
		if !path.IsAbs(p) {
			return res, fieldError("body.items["+strconv.Itoa(i)+"].path", "Give the full path, starting with /", p)
		}
		items[i].Path = path.Clean(p)
	}
	ps, root, err := h.dockerProjects(ctx, id)
	if err != nil {
		return res, err
	}

	// Which files each path stands for.
	q := terminal.ShellQuote
	var b strings.Builder
	for i, it := range items {
		n := strconv.Itoa(i)
		b.WriteString("p=" + q(it.Path) + "\nif [ -d \"$p\" ]; then d=\"$p\"; for f in " + strings.Join(composeFileNames, " ") + " " + strings.Join(composeOverrideNames, " ") +
			"; do [ -f \"$d/$f\" ] && printf '%s\\t%s\\n' " + n + " \"$d/$f\"; done\n" +
			"elif [ -f \"$p\" ]; then printf '%s\\tmain\\t%s\\n' " + n + " \"$p\"; d=$(dirname \"$p\"); for f in " + strings.Join(composeOverrideNames, " ") +
			"; do [ -f \"$d/$f\" ] && printf '%s\\t%s\\n' " + n + " \"$d/$f\"; done\nelse printf '%s\\tnone\\n' " + n + "; fi\n")
	}
	b.WriteString("true\n")
	var found []DockerProjectFound
	groups := make([]composeGroup, len(items))
	err = h.withShell(ctx, id, func(_ *sshpool.Conn, sh *rootShell) error {
		out, err := sh.run(ctx, b.String())
		if err != nil {
			return err
		}
		mains := map[int]string{}
		files := map[int][]string{}
		for l := range strings.SplitSeq(out, "\n") {
			parts := strings.Split(l, "\t")
			i, err := strconv.Atoi(parts[0])
			if err != nil || i < 0 || i >= len(items) || len(parts) < 2 {
				continue
			}
			switch {
			case parts[1] == "main" && len(parts) == 3:
				mains[i] = parts[2]
			case parts[1] != "none":
				files[i] = append(files[i], parts[1])
			}
		}
		var todo []composeGroup
		var index []int
		for i, it := range items {
			var g composeGroup
			if m := mains[i]; m != "" {
				g = composeGroup{dir: path.Dir(m), files: []string{m}}
				for _, f := range files[i] {
					if f != m {
						g.files = append(g.files, f)
					}
				}
			} else if gs := groupComposeFiles(files[i]); len(gs) > 0 {
				g = gs[0]
			} else {
				res.Problems = append(res.Problems, DockerProjectAddProblem{Path: it.Path, Message: "No compose file there (compose.yaml, docker-compose.yml…)"})
				continue
			}
			groups[i] = g
			todo = append(todo, g)
			index = append(index, i)
		}
		described, err := describeComposeDirs(ctx, sh, todo)
		if err != nil {
			return err
		}
		found = make([]DockerProjectFound, len(items))
		for k, i := range index {
			found[i] = described[k]
		}
		return nil
	})
	if err != nil {
		return res, shellFailure(err, "")
	}

	byDir := map[string]string{}
	for _, p := range ps {
		if p.Dir != "" {
			byDir[path.Clean(p.Dir)] = p.Name
		}
	}
	taken := map[string]bool{}
	for _, p := range ps {
		taken[p.Name] = true
	}
	who := ""
	if pr := principalOf(ctx); pr != nil {
		who = cmpOr(pr.User.FullName, pr.User.Username)
	}
	for i, it := range items {
		g := groups[i]
		if len(g.files) == 0 {
			continue
		}
		f := found[i]
		problem := func(msg string) {
			res.Problems = append(res.Problems, DockerProjectAddProblem{Path: it.Path, Message: msg})
		}
		if path.Dir(g.dir) == root {
			if name := byDir[g.dir]; name != "" {
				res.Added = append(res.Added, name) // already in the projects folder
				continue
			}
		}
		if name := byDir[g.dir]; name != "" {
			if it.Name == "" || it.Name == name {
				// Already listed (maybe through its containers): keep it.
				if err := h.q.UpsertDockerProjectPlace(ctx, sqlc.UpsertDockerProjectPlaceParams{
					ServerID: sid, Project: name, Dir: g.dir, Files: g.files, Source: "added", AddedByName: who,
				}); err != nil {
					return res, internalError(err)
				}
				res.Added = append(res.Added, name)
				continue
			}
			problem("It's already the project " + name)
			continue
		}
		if f.Problem != "" && it.Name == "" {
			problem(f.Problem)
			continue
		}
		name := it.Name
		if name == "" {
			name = f.Name
		}
		if !projectNameRe.MatchString(name) {
			problem("Use lowercase letters, digits, - and _ for the name (starting with a letter or digit)")
			continue
		}
		if taken[name] {
			problem("This server already has a project called " + name + ": give this one another name")
			continue
		}
		if err := h.q.UpsertDockerProjectPlace(ctx, sqlc.UpsertDockerProjectPlaceParams{
			ServerID: sid, Project: name, Dir: g.dir, Files: g.files, Source: "added", AddedByName: who,
		}); err != nil {
			return res, internalError(err)
		}
		taken[name] = true
		byDir[g.dir] = name
		res.Added = append(res.Added, name)
	}
	return res, nil
}

// ---- Handlers ----

func registerDockerProjectPlaces(api huma.API, h *serverHandler) {
	tags := []string{"Containers"}
	base := "/servers/{id}/docker"

	huma.Register(api, huma.Operation{
		OperationID: "get-docker-project-scan",
		Method:      http.MethodGet,
		Path:        base + "/project-scan",
		Summary:     "The last look for compose projects on a server's disk",
		Description: "What it found, each with its state against the projects listed now. The first listing of a server's projects starts a look by itself. Engineer.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body DockerProjectScanResult }, error) {
		if principalOf(ctx).Level < auth.Engineer {
			return nil, forbidden(auth.Engineer)
		}
		r, err := h.scanResult(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body DockerProjectScanResult }{r}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "scan-docker-projects",
		Method:      http.MethodPost,
		Path:        base + "/project-scan",
		Summary:     "Look for compose projects on a server's disk",
		Description: "Finds compose files (system folders and dependency trees skipped, about a minute at most) and answers what it found. Nothing is added: send the ones to keep to add-docker-projects. Engineer.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body DockerProjectScanBody
	}) (*struct{ Body DockerProjectScanResult }, error) {
		if principalOf(ctx).Level < auth.Engineer {
			return nil, forbidden(auth.Engineer)
		}
		var paths []string
		for i, p := range in.Body.Paths {
			p = strings.TrimSpace(p)
			if !path.IsAbs(p) {
				return nil, fieldError("body.paths["+strconv.Itoa(i)+"]", "Give the full path, starting with /", p)
			}
			paths = append(paths, path.Clean(p))
		}
		projectScans.Lock()
		if projectScans.running[in.ID] {
			projectScans.Unlock()
			return nil, huma.Error409Conflict("Morche is already looking on this server; try again in a minute")
		}
		projectScans.running[in.ID] = true
		projectScans.Unlock()
		err := h.scanProjects(ctx, in.ID, paths, in.Body.Depth)
		projectScans.Lock()
		delete(projectScans.running, in.ID)
		projectScans.Unlock()
		if err != nil {
			return nil, shellFailure(err, "")
		}
		r, err := h.scanResult(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body DockerProjectScanResult }{r}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "add-docker-projects",
		Method:      http.MethodPost,
		Path:        base + "/project-places",
		Summary:     "List compose projects that are already on a server",
		Description: "Each path is a compose file or the folder holding one, anywhere on the server. They are listed from then on (even with nothing running), and can be edited, deployed and taken down like any project; their folder is never deleted. Engineer.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body DockerProjectAddBody
	}) (*struct{ Body DockerProjectAddResult }, error) {
		if principalOf(ctx).Level < auth.Engineer {
			return nil, forbidden(auth.Engineer)
		}
		r, err := h.addProjects(ctx, in.ID, in.Body.Items)
		if err != nil {
			return nil, err
		}
		return &struct{ Body DockerProjectAddResult }{r}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "forget-docker-project",
		Method:        http.MethodDelete,
		Path:          base + "/projects/{project}/place",
		Summary:       "Stop listing a compose project",
		Description:   "For a project outside the projects folder with no containers: Morche stops listing it and a later look leaves it out. Its files stay on the server. Engineer.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *DockerProjectPath) (*struct{}, error) {
		if principalOf(ctx).Level < auth.Engineer {
			return nil, forbidden(auth.Engineer)
		}
		p, _, err := h.dockerProject(ctx, in.ID, in.Project)
		if err != nil {
			return nil, err
		}
		if p.Managed {
			return nil, huma.Error422UnprocessableEntity("It's in the projects folder: Destroy removes it")
		}
		if p.Total > 0 {
			return nil, huma.Error422UnprocessableEntity("It still has containers: take it down first")
		}
		sid := uuid.MustParse(in.ID)
		n, err := h.q.HideDockerProjectPlace(ctx, sqlc.HideDockerProjectPlaceParams{ServerID: sid, Project: p.Name})
		if err != nil {
			return nil, internalError(err)
		}
		if n == 0 {
			if err := h.q.HideDockerProjectPlaceAt(ctx, sqlc.HideDockerProjectPlaceAtParams{
				ServerID: sid, Project: p.Name, Dir: p.Dir, Files: p.Files,
			}); err != nil {
				return nil, internalError(err)
			}
		}
		return &struct{}{}, nil
	})
}
