package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/docker"
	"github.com/morche/backend/internal/jobs"
	"github.com/morche/backend/internal/sshpool"
	"github.com/morche/backend/internal/terminal"
)

// ---- API shapes ----

type DockerProject struct {
	Name       string      `json:"name"`
	Dir        string      `json:"dir" doc:"Its folder on the server; empty when the containers don't say"`
	Files      []string    `json:"files" doc:"Its compose files (full paths)"`
	Managed    bool        `json:"managed" doc:"In the workspace's projects folder"`
	Source     string      `json:"source" enum:"folder,containers,scan,added" doc:"How Morche knows it: folder = in the projects folder; containers = its containers name it; scan = found on the disk; added = someone gave its path"`
	State      string      `json:"state" enum:"running,partial,stopped,not-deployed"`
	Running    int         `json:"running"`
	Total      int         `json:"total"`
	Services   []string    `json:"services" doc:"Services that have a container"`
	Images     []string    `json:"images"`
	Containers []DockerRef `json:"containers"`
	Created    *time.Time  `json:"created,omitempty" doc:"When its oldest container was made"`
	Title      string      `json:"title" doc:"A display name set in Morche; empty = use the name"`
	Note       string      `json:"note" doc:"A description set in Morche"`
}

type DockerProjectDetails struct {
	DockerProject
	Compose  string `json:"compose" doc:"The first compose file (Engineer)"`
	Env      string `json:"env" doc:"The .env file next to it (Engineer)"`
	HasEnv   bool   `json:"has_env"`
	Readable bool   `json:"readable" doc:"The files were read: false without Engineer access or when they aren't on the server"`
	Missing  bool   `json:"missing" doc:"The compose file isn't on the server (any more)"`
	Revision string `json:"revision" doc:"Send back when saving; a change in between answers 409"`
}

type DockerProjectFilesBody struct {
	Compose  string `json:"compose" minLength:"1" maxLength:"500000"`
	Env      string `json:"env,omitempty" maxLength:"200000"`
	Revision string `json:"revision,omitempty" doc:"From the details; empty = overwrite"`
	Note     string `json:"note,omitempty" maxLength:"300" doc:"What changed, kept with this version in the history"`
}

type DockerProjectCreateBody struct {
	Name    string `json:"name" minLength:"1" maxLength:"63" pattern:"^[a-z0-9][a-z0-9_-]*$" doc:"Lowercase letters, digits, - and _"`
	Compose string `json:"compose" minLength:"1" maxLength:"500000"`
	Env     string `json:"env,omitempty" maxLength:"200000"`
	Start   bool   `json:"start,omitempty" doc:"Run docker compose up -d once it's saved"`
}

type DockerProjectCreated struct {
	Project DockerProjectDetails `json:"project"`
	Job     *Job                 `json:"job,omitempty" doc:"The up job, when start was asked"`
}

type DockerProjectPath struct {
	ServerIDPath
	Project string `path:"project" maxLength:"63"`
}

type DockerProjectActionPath struct {
	DockerProjectPath
	Action string `path:"action" enum:"up,down,start,stop,restart,pull,redeploy,destroy"`
}

type dockerComposeParams struct {
	ServerID string   `json:"server_id"`
	Project  string   `json:"project"`
	Action   string   `json:"action"`
	Dir      string   `json:"dir"`
	Files    []string `json:"files"`
	Managed  bool     `json:"managed"`
	Root     string   `json:"root"`
}

const dockerComposeKind = "docker-compose"

var projectNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

var composeFileNames = []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}

// composeDetect sets $C to the compose command the server has.
const composeDetect = `if docker compose version >/dev/null 2>&1; then C="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then C=docker-compose
elif command -v podman-compose >/dev/null 2>&1; then C=podman-compose
else echo "Docker Compose isn't installed on the server (install the docker-compose-plugin package)" >&2; exit 69; fi
`

// composeArgs is "-p name --project-directory dir -f a -f b", quoted.
func composeArgs(name, dir string, files []string) string {
	q := terminal.ShellQuote
	s := "-p " + q(name)
	if dir != "" {
		s += " --project-directory " + q(dir)
	}
	for _, f := range files {
		s += " -f " + q(f)
	}
	return s
}

// shellFailure turns a failed script into a 422 with what it printed.
func shellFailure(err error, location string) error {
	var ce *cmdError
	if errors.As(err, &ce) {
		if strings.Contains(ce.msg, "Permission denied") {
			return huma.Error422UnprocessableEntity(ce.msg + ". The server's login can't write there: give it sudo, or pick a projects folder it can write in the workspace's container settings.")
		}
		if location != "" && ce.code == 65 {
			return fieldError(location, ce.msg, "")
		}
		return huma.Error422UnprocessableEntity(ce.msg)
	}
	return err
}

func projectState(running, total int) string {
	switch {
	case total == 0:
		return "not-deployed"
	case running == total:
		return "running"
	case running == 0:
		return "stopped"
	}
	return "partial"
}

// ---- Finding projects ----

// dockerProjects lists the compose projects on a server: those its
// containers name, plus folders in the projects folder holding a compose
// file but nothing running yet.
func (h *serverHandler) dockerProjects(ctx context.Context, id string) ([]DockerProject, string, error) {
	s, err := h.get(ctx, id)
	if err != nil {
		return nil, "", err
	}
	set, err := h.serverDockerSettings(ctx, s)
	if err != nil {
		return nil, "", err
	}
	root := path.Clean(set.ProjectsDir)

	var cs []docker.ContainerSummary
	if err := h.withDocker(ctx, id, func(e *dockerEngine) error {
		cs, err = e.client.Containers(ctx)
		return err
	}); err != nil {
		return nil, "", err
	}

	byName := map[string]*DockerProject{}
	get := func(name string) *DockerProject {
		p := byName[name]
		if p == nil {
			p = &DockerProject{Name: name, Files: []string{}, Services: []string{}, Images: []string{}, Containers: []DockerRef{}}
			byName[name] = p
		}
		return p
	}
	for _, c := range cs {
		name := c.Labels["com.docker.compose.project"]
		if name == "" {
			continue
		}
		p := get(name)
		if dir := c.Labels["com.docker.compose.project.working_dir"]; dir != "" && p.Dir == "" {
			p.Dir = dir
		}
		if files := c.Labels["com.docker.compose.project.config_files"]; files != "" && len(p.Files) == 0 {
			for f := range strings.SplitSeq(files, ",") {
				if f = strings.TrimSpace(f); f != "" {
					if !path.IsAbs(f) && p.Dir != "" {
						f = path.Join(p.Dir, f)
					}
					p.Files = append(p.Files, f)
				}
			}
		}
		p.Total++
		if c.State == "running" {
			p.Running++
		}
		if svc := c.Labels["com.docker.compose.service"]; svc != "" && !slices.Contains(p.Services, svc) {
			p.Services = append(p.Services, svc)
		}
		if !slices.Contains(p.Images, c.Image) {
			p.Images = append(p.Images, c.Image)
		}
		p.Containers = append(p.Containers, DockerRef{ID: c.ID, Name: containerName(c.Names), State: c.State})
		created := time.Unix(c.Created, 0).UTC()
		if p.Created == nil || created.Before(*p.Created) {
			p.Created = &created
		}
	}

	// Folders in the projects folder (a failure here only hides them).
	script := "d=" + terminal.ShellQuote(root) + `; [ -d "$d" ] || exit 0
for p in "$d"/*/; do [ -d "$p" ] || continue
  for f in compose.yaml compose.yml docker-compose.yaml docker-compose.yml; do
    if [ -f "$p$f" ]; then printf '%s\t%s\n' "$(basename "$p")" "$f"; break; fi
  done
done`
	_ = h.withShell(ctx, id, func(_ *sshpool.Conn, sh *rootShell) error {
		out, err := sh.run(ctx, script)
		if err != nil {
			return err
		}
		for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
			name, file, ok := strings.Cut(line, "\t")
			if !ok || !projectNameRe.MatchString(name) {
				continue
			}
			dir := path.Join(root, name)
			p := byName[name]
			if p != nil && p.Dir != "" && p.Dir != dir {
				continue // another project of the same name lives elsewhere
			}
			p = get(name)
			if p.Dir == "" {
				p.Dir = dir
			}
			if len(p.Files) == 0 {
				p.Files = []string{path.Join(dir, file)}
			}
		}
		return nil
	})

	sources := h.mergePlaces(ctx, id, root, byName, get)

	metas := map[string]sqlc.DockerProjectMetum{}
	if sid, err := uuid.Parse(id); err == nil {
		if rows, err := h.q.DockerProjectMetas(ctx, sid); err == nil {
			for _, m := range rows {
				metas[m.Project] = m
			}
		}
	}
	out := make([]DockerProject, 0, len(byName))
	for _, p := range byName {
		if m, ok := metas[p.Name]; ok {
			p.Title, p.Note = m.Title, m.Note
		}
		p.Managed = p.Dir != "" && path.Dir(path.Clean(p.Dir)) == root
		switch {
		case p.Managed:
			p.Source = "folder"
		case sources[p.Name] != "":
			p.Source = sources[p.Name]
		default:
			p.Source = "containers"
		}
		p.State = projectState(p.Running, p.Total)
		sort.Strings(p.Services)
		sort.Strings(p.Images)
		sort.Slice(p.Containers, func(i, j int) bool { return p.Containers[i].Name < p.Containers[j].Name })
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, root, nil
}

func (h *serverHandler) dockerProject(ctx context.Context, id, name string) (DockerProject, string, error) {
	ps, root, err := h.dockerProjects(ctx, id)
	if err != nil {
		return DockerProject{}, "", err
	}
	for _, p := range ps {
		if p.Name == name {
			return p, root, nil
		}
	}
	return DockerProject{}, "", huma.Error404NotFound("No compose project " + name + " on this server")
}

func projectRevision(compose, env string, hasEnv bool) string {
	sum := sha256.New()
	sum.Write([]byte(compose))
	sum.Write([]byte{0})
	if hasEnv {
		sum.Write([]byte(env))
	}
	return hex.EncodeToString(sum.Sum(nil))[:16]
}

// readProjectFiles reads the first compose file and the .env beside it.
// Their contents never reach the command log.
func (h *serverHandler) readProjectFiles(ctx context.Context, id string, p DockerProject) (d DockerProjectDetails, err error) {
	d.DockerProject = p
	if len(p.Files) == 0 || p.Dir == "" {
		d.Missing = true
		return d, nil
	}
	q := terminal.ShellQuote
	script := "cd " + q(p.Dir) + " 2>/dev/null || exit 0\nf=" + q(p.Files[0]) + `
[ -f "$f" ] || exit 0
echo ok
base64 < "$f" | tr -d '\n'; echo
if [ -f .env ]; then echo y; base64 < .env | tr -d '\n'; echo; else echo n; fi`
	err = h.withShell(ctx, id, func(_ *sshpool.Conn, sh *rootShell) error {
		out, err := sh.hiding(true).run(ctx, script)
		if err != nil {
			return err
		}
		lines := strings.Split(out, "\n")
		if len(lines) < 3 || lines[0] != "ok" {
			d.Missing = true
			return nil
		}
		compose, err := base64.StdEncoding.DecodeString(lines[1])
		if err != nil {
			return fmt.Errorf("reading the compose file: %w", err)
		}
		d.Compose = string(compose)
		if lines[2] == "y" && len(lines) > 3 {
			env, err := base64.StdEncoding.DecodeString(lines[3])
			if err != nil {
				return fmt.Errorf("reading .env: %w", err)
			}
			d.Env, d.HasEnv = string(env), true
		}
		d.Readable = true
		return nil
	})
	if err != nil {
		return d, shellFailure(err, "")
	}
	d.Revision = projectRevision(d.Compose, d.Env, d.HasEnv)
	return d, nil
}

// writeFilesScript writes compose (and .env) through base64, checks them
// with `compose config`, and puts the old ones back if that fails (exit 65).
func writeFilesScript(name, dir, file string, files []string, compose, env, b64c, b64e string) string {
	q := terminal.ShellQuote
	var b strings.Builder
	b.WriteString("set -e\nmkdir -p " + q(dir) + "\ncd " + q(dir) + "\nF=" + q(file) + "\n")
	b.WriteString(`[ -f "$F" ] && cp -p "$F" "$F.morche-old" || true` + "\n")
	b.WriteString("if [ -f .env ]; then cp -p .env .env.morche-old; fi\n")
	b.WriteString("printf '%s' " + q(b64c) + ` | base64 -d > "$F.morche-new"; mv "$F.morche-new" "$F"` + "\n")
	if env != "" {
		b.WriteString("umask 077; printf '%s' " + q(b64e) + " | base64 -d > .env.morche-new; chmod 600 .env.morche-new; mv .env.morche-new .env\n")
	} else {
		b.WriteString("rm -f .env\n")
	}
	b.WriteString(composeDetect)
	b.WriteString("set +e\nout=$($C " + composeArgs(name, dir, files) + " config -q 2>&1); code=$?\n")
	b.WriteString(`if [ $code -ne 0 ]; then
  if [ -f "$F.morche-old" ]; then mv "$F.morche-old" "$F"; else rm -f "$F"; fi
  if [ -f .env.morche-old ]; then mv .env.morche-old .env; else rm -f .env; fi
  printf '%s\n' "$out" | tail -n 5 >&2; exit 65
fi
rm -f "$F.morche-old" .env.morche-old
`)
	_ = compose
	return b.String()
}

// ---- Handlers ----

func registerDockerProjects(api huma.API, h *serverHandler) {
	tags := []string{"Containers"}
	base := "/servers/{id}/docker/projects"

	huma.Register(api, huma.Operation{
		OperationID: "list-docker-projects",
		Method:      http.MethodGet,
		Path:        base,
		Summary:     "Compose projects on a server",
		Description: "Projects its containers belong to, folders in the workspace's projects folder that hold a compose file, and compose projects elsewhere on the disk that were found or added. The first listing starts a look for compose files in the background.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body []DockerProject }, error) {
		ps, _, err := h.dockerProjects(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		h.maybeAutoScan(in.ID)
		return &struct{ Body []DockerProject }{ps}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-docker-project",
		Method:      http.MethodGet,
		Path:        base + "/{project}",
		Summary:     "A compose project",
		Description: "Its containers, and (Engineer) its compose and .env files.",
		Tags:        tags,
	}, func(ctx context.Context, in *DockerProjectPath) (*struct{ Body DockerProjectDetails }, error) {
		p, _, err := h.dockerProject(ctx, in.ID, in.Project)
		if err != nil {
			return nil, err
		}
		if principalOf(ctx).Level < auth.Engineer {
			return &struct{ Body DockerProjectDetails }{DockerProjectDetails{DockerProject: p}}, nil
		}
		d, err := h.readProjectFiles(ctx, in.ID, p)
		if err != nil {
			return nil, err
		}
		return &struct{ Body DockerProjectDetails }{d}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "save-docker-project-files",
		Method:      http.MethodPut,
		Path:        base + "/{project}/files",
		Summary:     "Save a project's compose and .env files",
		Description: "Checked with `docker compose config` on the server first; a file it refuses is put back and answers 422. Doesn't redeploy: run `up` or `redeploy` after. 409 when the files changed since `revision`.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerProjectPath
		Body DockerProjectFilesBody
	}) (*struct{ Body DockerProjectDetails }, error) {
		b := in.Body
		if err := checkComposeText(b.Compose); err != nil {
			return nil, err
		}
		p, _, err := h.dockerProject(ctx, in.ID, in.Project)
		if err != nil {
			return nil, err
		}
		cur, err := h.readProjectFiles(ctx, in.ID, p)
		if err != nil {
			return nil, err
		}
		if cur.Missing {
			return nil, huma.Error422UnprocessableEntity("This project's compose file isn't on the server, so there's nothing to edit")
		}
		if b.Revision != "" && b.Revision != cur.Revision {
			return nil, huma.Error409Conflict("Someone changed these files since you opened them")
		}
		h.keepFoundVersion(ctx, in.ID, cur)
		if err := h.writeProjectFiles(ctx, in.ID, p, b.Compose, b.Env); err != nil {
			return nil, err
		}
		h.recordProjectVersion(ctx, in.ID, p.Name, b.Compose, b.Env, b.Env != "", "save", strings.TrimSpace(b.Note))
		d, err := h.readProjectFiles(ctx, in.ID, p)
		if err != nil {
			return nil, err
		}
		return &struct{ Body DockerProjectDetails }{d}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-docker-project",
		Method:        http.MethodPost,
		Path:          base,
		Summary:       "Make a compose project",
		Description:   "Writes compose.yaml (and .env) in a new folder under the workspace's projects folder, checked with `docker compose config`. With `start`, also runs `up -d` as a job (kind `docker-compose`).",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body DockerProjectCreateBody
	}) (*struct{ Body DockerProjectCreated }, error) {
		b := in.Body
		if !projectNameRe.MatchString(b.Name) {
			return nil, fieldError("body.name", "Use lowercase letters, digits, - and _ (starting with a letter or digit)", b.Name)
		}
		if err := checkComposeText(b.Compose); err != nil {
			return nil, err
		}
		ps, root, err := h.dockerProjects(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		for _, p := range ps {
			if p.Name == b.Name {
				return nil, fieldError("body.name", "This server already has a project called "+b.Name, b.Name)
			}
		}
		dir := path.Join(root, b.Name)
		file := path.Join(dir, "compose.yaml")
		b64c := base64.StdEncoding.EncodeToString([]byte(b.Compose))
		b64e := base64.StdEncoding.EncodeToString([]byte(b.Env))
		q := terminal.ShellQuote
		guard := "for f in " + strings.Join(composeFileNames, " ") + "; do if [ -e " + q(dir) + `/"$f" ]; then echo "` + dir + ` already holds a compose file" >&2; exit 66; fi; done` + "\n"
		script := guard + writeFilesScript(b.Name, dir, file, []string{file}, b.Compose, b.Env, b64c, b64e) +
			"\n[ \"$(ls -A " + q(dir) + " 2>/dev/null)\" ] || rmdir " + q(dir) + " 2>/dev/null || true\n"
		// On a refused file the folder is left empty: remove it.
		script = strings.Replace(script, "printf '%s\\n' \"$out\" | tail -n 5 >&2; exit 65",
			"rmdir "+q(dir)+" 2>/dev/null; printf '%s\\n' \"$out\" | tail -n 5 >&2; exit 65", 1)
		err = h.withShell(ctx, in.ID, func(_ *sshpool.Conn, sh *rootShell) error {
			_, err := sh.hiding(false, b64c, b64e).run(ctx, script)
			return err
		})
		if err != nil {
			var ce *cmdError
			if errors.As(err, &ce) && ce.code == 66 {
				return nil, fieldError("body.name", ce.msg, b.Name)
			}
			return nil, shellFailure(err, "body.compose")
		}
		h.recordProjectVersion(ctx, in.ID, b.Name, b.Compose, b.Env, b.Env != "", "create", "")
		p := DockerProject{
			Name: b.Name, Dir: dir, Files: []string{file}, Managed: true, State: "not-deployed",
			Services: []string{}, Images: []string{}, Containers: []DockerRef{},
		}
		out := &struct{ Body DockerProjectCreated }{DockerProjectCreated{Project: DockerProjectDetails{
			DockerProject: p, Compose: b.Compose, Env: b.Env, HasEnv: b.Env != "", Readable: true,
			Revision: projectRevision(b.Compose, b.Env, b.Env != ""),
		}}}
		if b.Start {
			j, err := h.submitCompose(ctx, in.ID, p, root, "up")
			if err != nil {
				return nil, err
			}
			out.Body.Job = &j.Body
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "docker-project-action",
		Method:        http.MethodPost,
		Path:          base + "/{project}/actions/{action}",
		Summary:       "Run a compose command on a project",
		Description:   "up, down, start, stop, restart, pull, redeploy (pull + up) or destroy (down with its volumes; a project in the projects folder also loses its folder). Runs as a job (kind `docker-compose`). Operator may start, stop and restart; the rest needs Engineer.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *DockerProjectActionPath) (*JobOutput, error) {
		switch in.Action {
		case "start", "stop", "restart":
		default:
			if principalOf(ctx).Level < auth.Engineer {
				return nil, forbidden(auth.Engineer)
			}
		}
		p, root, err := h.dockerProject(ctx, in.ID, in.Project)
		if err != nil {
			return nil, err
		}
		if len(p.Files) == 0 && in.Action != "start" && in.Action != "stop" && in.Action != "restart" && in.Action != "down" {
			return nil, huma.Error422UnprocessableEntity("Its containers don't say where the compose file is, so only start, stop, restart and down work")
		}
		return h.submitCompose(ctx, in.ID, p, root, in.Action)
	})
	h.jobs.Handle(dockerComposeKind, h.runDockerCompose)
	registerDockerProjectCheck(api, h)
	registerDockerProjectPlaces(api, h)
}

var composeVerbs = map[string]string{
	"up": "Deploy", "down": "Take down", "start": "Start", "stop": "Stop", "restart": "Restart",
	"pull": "Pull images of", "redeploy": "Redeploy", "destroy": "Destroy",
}

var composePhases = map[string]string{
	"up": "Deploying", "redeploy": "Redeploying", "down": "Taking down", "destroy": "Destroying",
	"start": "Starting", "stop": "Stopping", "restart": "Restarting",
}

func (h *serverHandler) submitCompose(ctx context.Context, id string, p DockerProject, root, action string) (*JobOutput, error) {
	s, err := h.get(ctx, id)
	if err != nil {
		return nil, err
	}
	return submit(ctx, h.jobs, jobs.Spec{
		Kind: dockerComposeKind, Title: composeVerbs[action] + " " + p.Name + " on " + s.Name,
		Params: dockerComposeParams{ServerID: id, Project: p.Name, Action: action, Dir: p.Dir, Files: p.Files, Managed: p.Managed, Root: root},
		Refs:   placeRefs(id), Target: &JobPlace{ServerID: id, Name: s.Name, Path: p.Dir},
	})
}

// ---- Job ----

// composeImages lists the images a project's file names.
func composeImages(ctx context.Context, sh *rootShell, p dockerComposeParams) ([]string, error) {
	out, err := sh.run(ctx, composeDetect+"cd "+terminal.ShellQuote(p.Dir)+" && $C "+composeArgs(p.Project, p.Dir, p.Files)+" config --images")
	if err != nil {
		return nil, err
	}
	var images []string
	for l := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if l = strings.TrimSpace(l); l != "" && !slices.Contains(images, l) {
			images = append(images, l)
		}
	}
	return images, nil
}

// pullWithAuth pulls images through the engine with the workspace's
// registry logins (so no password ever goes through a shell). With
// missingOnly, images the server already has are skipped.
func (h *serverHandler) pullWithAuth(ctx context.Context, t *jobs.Task, serverID string, images []string, missingOnly bool) error {
	have := map[string]bool{}
	if missingOnly {
		err := h.withDocker(ctx, serverID, func(e *dockerEngine) error {
			ims, err := e.client.Images(ctx)
			for _, im := range ims {
				for _, tag := range im.RepoTags {
					have[tag] = true
				}
			}
			return err
		})
		if err != nil {
			return err
		}
	}
	// Bytes of the images pulled so far; Done grows across images so the
	// job's rate stays right. Current = "image · 12 MB of 40 MB".
	var pulled int64
	for i, image := range images {
		if missingOnly && (have[image] || have[image+":latest"] || have["docker.io/library/"+image]) {
			t.Logf("Using %s (already on the server)", image)
			continue
		}
		t.Update(func(pr *jobs.Progress) {
			pr.Phase, pr.Current, pr.Items, pr.ItemsTotal = "Pulling images", image, i, len(images)
		})
		t.Logf("Pulling %s", image)
		auth := h.serverRegistryAuth(ctx, serverID, image)
		layers := map[string]*[2]int64{} // id → done, total
		var last time.Time
		size := func() (done, total int64) {
			for _, l := range layers {
				done += l[0]
				total += l[1]
			}
			return done, total
		}
		err := h.dockerDo(ctx, serverID, "docker pull "+image, func(e *dockerEngine) error {
			return e.client.Pull(ctx, image, "", auth, func(ev docker.PullEvent) {
				if ev.ID == "" {
					return
				}
				l := layers[ev.ID]
				if l == nil {
					l = &[2]int64{}
					layers[ev.ID] = l
				}
				switch ev.Status {
				case "Downloading":
					l[0], l[1] = ev.Progress.Current, ev.Progress.Total
				case "Download complete", "Pull complete", "Already exists":
					l[0] = l[1]
				default:
					return
				}
				if time.Since(last) < 300*time.Millisecond {
					return
				}
				last = time.Now()
				done, total := size()
				t.Update(func(pr *jobs.Progress) {
					pr.Done = pulled + done
					if total > 0 {
						pr.Current = image + " · " + humanBytes(done) + " of " + humanBytes(total)
					}
				})
			})
		})
		if err != nil {
			return fmt.Errorf("pulling %s: %s", image, dockerProblemText(err))
		}
		done, _ := size()
		pulled += done
		t.Update(func(pr *jobs.Progress) { pr.Done, pr.Items = pulled, i+1 })
		if done > 0 {
			t.Logf("Pulled %s (%s)", image, humanBytes(done))
		} else {
			t.Logf("Pulled %s", image)
		}
	}
	return nil
}

func (h *serverHandler) composeRun(ctx context.Context, t *jobs.Task, sh *rootShell, p dockerComposeParams, args string) error {
	q := terminal.ShellQuote
	cd := ""
	if p.Dir != "" {
		cd = "cd " + q(p.Dir) + " && "
	}
	files := p.Files
	script := composeDetect + cd + "$C " + composeArgs(p.Project, p.Dir, files) + " " + args
	var mu sync.Mutex
	var tail []string
	last := ""
	w := &lineWriter{fn: func(s string) {
		mu.Lock()
		defer mu.Unlock()
		// Compose prints each progress state twice without a TTY.
		if s == last {
			return
		}
		last = s
		t.Logf("%s", s)
		tail = append(tail, s)
		if len(tail) > 5 {
			tail = tail[1:]
		}
	}}
	res, err := sh.execTo(ctx, script, 30*time.Minute, w)
	w.flush()
	if err != nil {
		return err
	}
	if res.timedOut {
		return errors.New("docker compose took longer than 30 minutes")
	}
	if res.code != 0 {
		mu.Lock()
		defer mu.Unlock()
		msg := strings.Join(tail, "\n")
		if res.code == 69 || msg == "" {
			if msg == "" {
				msg = fmt.Sprintf("docker compose failed (exit %d)", res.code)
			}
		}
		return errors.New(msg)
	}
	return nil
}

// composeUpArgs is `compose up` as the server's workspace wants it: with
// --remove-orphans unless its settings turned that off.
func (h *serverHandler) composeUpArgs(ctx context.Context, serverID string) string {
	if srv, err := h.get(ctx, serverID); err == nil {
		if set, err := h.serverDockerSettings(ctx, srv); err == nil && !set.RemoveOrphans {
			return "up -d"
		}
	}
	return "up -d --remove-orphans"
}

func (h *serverHandler) runDockerCompose(ctx context.Context, t *jobs.Task) (any, error) {
	var p dockerComposeParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	// The project page shows the containers as they come; don't let it
	// answer from a measurement taken before this job changed them.
	defer forgetProjectStats(p.ServerID)
	// "==> " lines mark the steps, so the project page can tell how far a
	// deploy got (the progress is cleared when a job ends).
	var images []string
	if (p.Action == "pull" || p.Action == "redeploy" || p.Action == "up") && len(p.Files) > 0 {
		t.Logf("==> Reading the compose file")
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Reading the compose file" })
		err := h.withShell(ctx, p.ServerID, func(_ *sshpool.Conn, sh *rootShell) error {
			var err error
			images, err = composeImages(ctx, sh, p)
			return err
		})
		if err != nil {
			return nil, jobError(shellFailure(err, ""))
		}
		t.Logf("==> Pulling images")
		if err := h.pullWithAuth(ctx, t, p.ServerID, images, p.Action == "up"); err != nil {
			return nil, jobError(err)
		}
	}
	up := h.composeUpArgs(ctx, p.ServerID)
	steps := map[string]string{
		"up": up, "redeploy": up,
		"down": "down --remove-orphans", "destroy": "down --volumes --remove-orphans",
		"start": "start", "stop": "stop", "restart": "restart",
	}
	if args, ok := steps[p.Action]; ok {
		t.Update(func(pr *jobs.Progress) {
			pr.Phase, pr.Current = composePhases[p.Action], p.Project
			pr.Done, pr.Items, pr.ItemsTotal = 0, 0, 0
		})
		t.Logf("==> docker compose %s", args)
		err := h.withShell(ctx, p.ServerID, func(_ *sshpool.Conn, sh *rootShell) error {
			return h.composeRun(ctx, t, sh, p, args)
		})
		if err != nil {
			return nil, jobError(err)
		}
	}
	removed := false
	if p.Action == "destroy" && p.Managed && p.Dir != "" && path.Dir(path.Clean(p.Dir)) == path.Clean(p.Root) && p.Root != "/" {
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Removing the folder" })
		err := h.withShell(ctx, p.ServerID, func(_ *sshpool.Conn, sh *rootShell) error {
			_, err := sh.run(ctx, "rm -rf -- "+terminal.ShellQuote(path.Clean(p.Dir)))
			return err
		})
		if err != nil {
			return nil, jobError(shellFailure(err, ""))
		}
		removed = true
		t.Logf("Removed %s", p.Dir)
	}
	t.Logf("==> Done")
	t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Items, pr.ItemsTotal = "Done", len(images), len(images) })
	return map[string]any{"project": p.Project, "action": p.Action, "images": images, "folder_removed": removed}, nil
}
