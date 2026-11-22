package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/cmdlog"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/docker"
	"github.com/morche/backend/internal/jobs"
)

type DockerUpdateUser struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	State   string `json:"state"`
	Project string `json:"project,omitempty"`
	Service string `json:"service,omitempty"`
}

type DockerImageUpdate struct {
	Image        string             `json:"image" doc:"The reference containers were made from"`
	State        string             `json:"state" enum:"current,available,local,pinned,error,unchecked" doc:"available = the registry has a newer image; local = built here, nothing to compare; pinned = by digest"`
	LocalDigest  string             `json:"local_digest,omitempty"`
	RemoteDigest string             `json:"remote_digest,omitempty"`
	Error        string             `json:"error,omitempty"`
	CheckedAt    *time.Time         `json:"checked_at,omitempty"`
	Containers   []DockerUpdateUser `json:"containers"`
}

type DockerUpdates struct {
	Items     []DockerImageUpdate `json:"items" doc:"Images in use: available first"`
	CheckedAt *time.Time          `json:"checked_at,omitempty" doc:"Last check; empty = never"`
	Available int                 `json:"available"`
}

type DockerUpdateApplyBody struct {
	Containers []string `json:"containers" minItems:"1" maxItems:"200" doc:"Container ids (or names) to bring onto their image's newest version"`
}

type dockerUpdateCheckParams struct {
	ServerID string `json:"server_id"`
}

type dockerUpdateApplyParams struct {
	ServerID   string   `json:"server_id"`
	Containers []string `json:"containers"`
}

const (
	dockerUpdateCheckKind = "docker-update-check"
	dockerUpdateKind      = "docker-update"
)

// pinnedRef says whether a reference can't move (a digest or an image id).
func pinnedRef(ref string) bool {
	return strings.Contains(ref, "@sha256:") || strings.HasPrefix(ref, "sha256:") || hexID.MatchString(ref)
}

// sameRepo says whether repoDigest ("repo@sha256:…") is of ref's repository.
func sameRepo(ref, repoDigest string) bool {
	repo, _, _ := strings.Cut(repoDigest, "@")
	name := ref
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name = name[:i]
	}
	norm := func(s string) string {
		s = strings.TrimPrefix(s, "docker.io/")
		s = strings.TrimPrefix(s, "index.docker.io/")
		return strings.TrimPrefix(s, "library/")
	}
	return norm(repo) == norm(name)
}

// checkDockerUpdates asks the registries about every image a container on
// the server uses and stores the answers.
func (h *serverHandler) checkDockerUpdates(ctx context.Context, id string, progress func(i, n int, image string)) (int, error) {
	sid, err := uuid.Parse(id)
	if err != nil {
		return 0, err
	}
	var cs []docker.ContainerSummary
	var ims []docker.ImageSummary
	if err := h.withDocker(ctx, id, func(e *dockerEngine) error {
		if cs, err = e.client.Containers(ctx); err != nil {
			return err
		}
		ims, err = e.client.Images(ctx)
		return err
	}); err != nil {
		return 0, err
	}
	digests := map[string][]string{}
	tagged := map[string]string{} // tag → the image id it points to here
	for _, im := range ims {
		digests[im.ID] = im.RepoDigests
		for _, t := range im.RepoTags {
			tagged[t] = im.ID
		}
	}
	// reference → the image id its containers use. When some still run an
	// older image than the tag now points to (pulled, never recreated), that
	// one counts: those containers are the ones with an update waiting.
	imageOf := map[string]string{}
	var refs []string
	for _, c := range cs {
		old, ok := imageOf[c.Image]
		if !ok {
			refs = append(refs, c.Image)
		}
		if !ok || old == tagged[withTag(c.Image)] {
			imageOf[c.Image] = c.ImageID
		}
	}
	sort.Strings(refs)
	before := map[string]sqlc.DockerImageUpdate{}
	if rows, err := h.q.ListDockerImageUpdates(ctx, sid); err == nil {
		for _, r := range rows {
			before[r.Image] = r
		}
	}
	var fresh []string // images that newly have a version waiting
	available := 0
	for i, ref := range refs {
		if progress != nil {
			progress(i, len(refs), ref)
		}
		if ctx.Err() != nil {
			return available, ctx.Err()
		}
		row := h.registryState(ctx, id, sid, ref, digests[imageOf[ref]])
		if row.State == "available" {
			available++
			if b, ok := before[ref]; !ok || b.State != "available" || b.RemoteDigest != row.RemoteDigest {
				fresh = append(fresh, ref)
			}
		}
		if err := h.q.UpsertDockerImageUpdate(ctx, row); err != nil {
			return available, err
		}
	}
	if refs == nil {
		refs = []string{}
	}
	if err := h.q.DeleteDockerImageUpdatesExcept(ctx, sqlc.DeleteDockerImageUpdatesExceptParams{ServerID: sid, Images: refs}); err != nil {
		return available, err
	}
	if len(fresh) > 0 {
		if s, err := h.q.GetServer(ctx, sid); err == nil {
			h.notifyDockerUpdates(ctx, s, fresh)
		}
	}
	return available, nil
}

// registryState compares one image reference with its registry. local is
// the repo digests of the image the containers use now.
func (h *serverHandler) registryState(ctx context.Context, id string, sid uuid.UUID, ref string, local []string) sqlc.UpsertDockerImageUpdateParams {
	row := sqlc.UpsertDockerImageUpdateParams{ServerID: sid, Image: ref}
	for _, d := range local {
		if sameRepo(ref, d) {
			_, row.LocalDigest, _ = strings.Cut(d, "@")
			break
		}
	}
	switch {
	case pinnedRef(ref):
		row.State = "pinned"
	case row.LocalDigest == "":
		row.State = "local"
	default:
		auth := h.serverRegistryAuth(ctx, id, ref)
		var remote string
		err := h.withDocker(ctx, id, func(e *dockerEngine) error {
			var err error
			remote, err = e.client.RemoteDigest(ctx, ref, auth)
			return err
		})
		switch {
		case err != nil:
			row.State, row.Error = "error", dockerProblemText(err)
		case remote == "":
			row.State, row.Error = "error", "The registry didn't say"
		default:
			row.RemoteDigest = remote
			row.State = "available"
			for _, d := range local {
				if strings.HasSuffix(d, "@"+remote) {
					row.State = "current"
					break
				}
			}
		}
	}
	return row
}

func registerDockerUpdates(api huma.API, h *serverHandler) {
	tags := []string{"Containers"}

	huma.Register(api, huma.Operation{
		OperationID: "list-docker-updates",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/docker/updates",
		Summary:     "Image updates on a server",
		Description: "Each image its containers use, with whether the registry has a newer one (from the last check).",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body DockerUpdates }, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		var cs []docker.ContainerSummary
		if err := h.withDocker(ctx, in.ID, func(e *dockerEngine) error {
			cs, err = e.client.Containers(ctx)
			return err
		}); err != nil {
			return nil, err
		}
		rows, err := h.q.ListDockerImageUpdates(ctx, s.ID)
		if err != nil {
			return nil, internalError(err)
		}
		known := map[string]sqlc.DockerImageUpdate{}
		out := DockerUpdates{Items: []DockerImageUpdate{}}
		for _, r := range rows {
			known[r.Image] = r
			if out.CheckedAt == nil || r.CheckedAt.After(*out.CheckedAt) {
				at := r.CheckedAt
				out.CheckedAt = &at
			}
		}
		byImage := map[string]*DockerImageUpdate{}
		var order []string
		for _, c := range cs {
			u := byImage[c.Image]
			if u == nil {
				u = &DockerImageUpdate{Image: c.Image, State: "unchecked", Containers: []DockerUpdateUser{}}
				if r, ok := known[c.Image]; ok {
					at := r.CheckedAt
					u.State, u.LocalDigest, u.RemoteDigest, u.Error, u.CheckedAt = r.State, r.LocalDigest, r.RemoteDigest, r.Error, &at
				} else if pinnedRef(c.Image) {
					u.State = "pinned"
				}
				byImage[c.Image] = u
				order = append(order, c.Image)
			}
			u.Containers = append(u.Containers, DockerUpdateUser{
				ID: c.ID, Name: containerName(c.Names), State: c.State,
				Project: c.Labels["com.docker.compose.project"], Service: c.Labels["com.docker.compose.service"],
			})
		}
		rank := map[string]int{"available": 0, "error": 1, "unchecked": 2, "current": 3, "local": 4, "pinned": 5}
		for _, img := range order {
			u := byImage[img]
			sort.Slice(u.Containers, func(i, j int) bool { return u.Containers[i].Name < u.Containers[j].Name })
			if u.State == "available" {
				out.Available++
			}
			out.Items = append(out.Items, *u)
		}
		sort.SliceStable(out.Items, func(i, j int) bool {
			a, b := out.Items[i], out.Items[j]
			if rank[a.State] != rank[b.State] {
				return rank[a.State] < rank[b.State]
			}
			return a.Image < b.Image
		})
		return &struct{ Body DockerUpdates }{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "check-docker-updates",
		Method:        http.MethodPost,
		Path:          "/servers/{id}/docker/updates/check",
		Summary:       "Ask the registries for newer images",
		Description:   "Compares each image in use with what its registry has now (using the workspace's registry logins). Runs as a job (kind `docker-update-check`); after a first check the server is re-checked daily unless turned off in the workspace's container settings.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *ServerIDPath) (*JobOutput, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return submit(ctx, h.jobs, jobs.Spec{
			Kind: dockerUpdateCheckKind, Title: "Check image updates on " + s.Name,
			Params: dockerUpdateCheckParams{ServerID: in.ID},
			Refs:   placeRefs(in.ID), Target: &JobPlace{ServerID: in.ID, Name: s.Name},
		})
	})

	huma.Register(api, huma.Operation{
		OperationID:   "apply-docker-updates",
		Method:        http.MethodPost,
		Path:          "/servers/{id}/docker/updates/apply",
		Summary:       "Update containers to their newest image",
		Description:   "Pulls each container's image again, then recreates it with the same settings: a compose service through `docker compose up -d --no-deps <service>`, any other container by copying its settings (the old one is kept until the new one runs). Runs as a job (kind `docker-update`).",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body DockerUpdateApplyBody
	}) (*JobOutput, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		title := "Update " + plural(len(in.Body.Containers), "container") + " on " + s.Name
		return submit(ctx, h.jobs, jobs.Spec{
			Kind: dockerUpdateKind, Title: title,
			Params: dockerUpdateApplyParams{ServerID: in.ID, Containers: in.Body.Containers},
			Refs:   placeRefs(in.ID), Target: &JobPlace{ServerID: in.ID, Name: s.Name},
		})
	})

	h.jobs.Handle(dockerUpdateCheckKind, func(ctx context.Context, t *jobs.Task) (any, error) {
		var p dockerUpdateCheckParams
		if err := t.Decode(&p); err != nil {
			return nil, err
		}
		n, err := h.checkDockerUpdates(ctx, p.ServerID, func(i, total int, image string) {
			t.Update(func(pr *jobs.Progress) {
				pr.Phase, pr.Current, pr.Items, pr.ItemsTotal = "Asking the registries", image, i, total
			})
		})
		if err != nil {
			return nil, jobError(err)
		}
		t.Logf("%s", plural(n, "image")+" can be updated")
		return map[string]int{"available": n}, nil
	})
	h.jobs.Handle(dockerUpdateKind, h.runDockerUpdate)
}

func (h *serverHandler) runDockerUpdate(ctx context.Context, t *jobs.Task) (any, error) {
	var p dockerUpdateApplyParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	sid, err := uuid.Parse(p.ServerID)
	if err != nil {
		return nil, err
	}
	var cs []docker.ContainerSummary
	if err := h.withDocker(ctx, p.ServerID, func(e *dockerEngine) error {
		cs, err = e.client.Containers(ctx)
		return err
	}); err != nil {
		return nil, jobError(err)
	}
	var picked []docker.ContainerSummary
	for _, want := range p.Containers {
		found := false
		for _, c := range cs {
			if c.ID == want || strings.HasPrefix(c.ID, want) && len(want) >= 12 || containerName(c.Names) == want {
				if !slices.ContainsFunc(picked, func(x docker.ContainerSummary) bool { return x.ID == c.ID }) {
					picked = append(picked, c)
				}
				found = true
				break
			}
		}
		if !found {
			t.Logf("Skipped %s: no such container any more", want)
		}
	}
	// Pull each image once.
	var images []string
	for _, c := range picked {
		if pinnedRef(c.Image) {
			continue
		}
		if !slices.Contains(images, c.Image) {
			images = append(images, c.Image)
		}
	}
	if err := h.pullWithAuth(ctx, t, p.ServerID, images, false); err != nil {
		return nil, jobError(err)
	}
	var failed []string
	updated := 0
	for i, c := range picked {
		name := containerName(c.Names)
		t.Update(func(pr *jobs.Progress) {
			pr.Phase, pr.Current, pr.Items, pr.ItemsTotal = "Recreating", name, i, len(picked)
		})
		if pinnedRef(c.Image) {
			t.Logf("Skipped %s: its image is pinned (%s)", name, c.Image)
			continue
		}
		err := h.recreateContainer(ctx, t, p.ServerID, c)
		if err != nil {
			msg := dockerProblemText(err)
			t.Logf("Couldn't update %s: %s", name, msg)
			failed = append(failed, name)
			continue
		}
		updated++
		_ = h.q.MarkDockerImageCurrent(ctx, sqlc.MarkDockerImageCurrentParams{ServerID: sid, Image: c.Image})
	}
	t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Items, pr.ItemsTotal = "Done", len(picked), len(picked) })
	if len(failed) > 0 {
		return nil, jobError(errors.New("Couldn't update " + strings.Join(failed, ", ") + " (see the output)"))
	}
	return map[string]int{"updated": updated}, nil
}

// recreateContainer puts a new container in place of c on the image its
// reference points to now: a compose service through compose up, anything
// else by copying its settings.
func (h *serverHandler) recreateContainer(ctx context.Context, t *jobs.Task, serverID string, c docker.ContainerSummary) error {
	name := containerName(c.Names)
	project := c.Labels["com.docker.compose.project"]
	service := c.Labels["com.docker.compose.service"]
	dir := c.Labels["com.docker.compose.project.working_dir"]
	files := c.Labels["com.docker.compose.project.config_files"]
	if project != "" && service != "" && dir != "" && files != "" {
		cp := dockerComposeParams{ServerID: serverID, Project: project, Dir: dir}
		for f := range strings.SplitSeq(files, ",") {
			if f = strings.TrimSpace(f); f != "" {
				if !path.IsAbs(f) {
					f = path.Join(dir, f)
				}
				cp.Files = append(cp.Files, f)
			}
		}
		t.Logf("Recreating %s (service %s of %s)", name, service, project)
		return h.updateService(ctx, t, cp, service, "", -1)
	}
	t.Logf("Recreating %s", name)
	return h.dockerDo(ctx, serverID, "docker recreate "+name+" ("+c.Image+")", func(e *dockerEngine) error {
		_, err := e.client.Recreate(ctx, c.ID)
		return err
	})
}

// startDockerUpdateLoop re-checks image updates on servers that were checked
// before, as often as their workspace's settings say (so servers without Docker are never asked).
func startDockerUpdateLoop(h *serverHandler) {
	go func() {
		running := map[uuid.UUID]bool{}
		done := make(chan uuid.UUID, 64)
		for range time.Tick(time.Hour) {
		drain:
			for {
				select {
				case id := <-done:
					delete(running, id)
				default:
					break drain
				}
			}
			ids, err := h.q.StaleDockerUpdateServers(context.Background())
			if err != nil {
				slog.Warn("list servers for image update checks", "error", err)
				continue
			}
			for _, id := range ids {
				if running[id] || len(running) >= 3 {
					continue
				}
				running[id] = true
				go func(id uuid.UUID) {
					defer func() { done <- id }()
					ctx, cancel := context.WithTimeout(cmdlog.Background(context.Background(), "Docker"), 15*time.Minute)
					defer cancel()
					if _, err := h.checkDockerUpdates(ctx, id.String(), nil); err != nil {
						slog.Warn("daily image update check", "server", id, "error", err)
					}
				}(id)
			}
		}
	}()
}

// withTag adds the ":latest" Docker assumes to a reference without a tag or
// digest.
func withTag(ref string) string {
	if strings.Contains(ref, "@") {
		return ref
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		return ref
	}
	return ref + ":latest"
}
