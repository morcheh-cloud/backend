package api

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/sshpool"
)

// A compose project's history: every version of its files Morche wrote (or
// found before its first change), so a change can be compared and undone.

type DockerProjectVersion struct {
	ID          uuid.UUID `json:"id"`
	Revision    string    `json:"revision" doc:"Same as the project's revision when these are the files on the server now"`
	Reason      string    `json:"reason" enum:"found,save,create,restore,git" doc:"found = the files as they were before Morche first changed them"`
	Note        string    `json:"note"`
	By          string    `json:"by" doc:"Who made it; empty for Morche itself"`
	CreatedAt   time.Time `json:"created_at"`
	ComposeSize int       `json:"compose_size"`
	HasEnv      bool      `json:"has_env"`
	Current     bool      `json:"current" doc:"These are the files on the server now"`
}

type DockerProjectVersionFiles struct {
	DockerProjectVersion
	Compose string `json:"compose"`
	Env     string `json:"env"`
}

type DockerProjectVersions struct {
	Items    []DockerProjectVersion `json:"items"`
	Revision string                 `json:"revision" doc:"The revision of the files on the server now (empty when they couldn't be read)"`
}

type DockerProjectVersionPath struct {
	DockerProjectPath
	Version string `path:"version" format:"uuid"`
}

type DockerProjectRestoreBody struct {
	Revision string `json:"revision,omitempty" doc:"The project's revision when the person decided; a change in between answers 409"`
	Deploy   bool   `json:"deploy,omitempty" doc:"Run compose up after writing the files (a job)"`
}

const maxProjectNote = 300

// recordProjectVersion keeps a version unless it's the same as the newest
// one. Failures are logged, never returned: history must not block a save.
func (h *serverHandler) recordProjectVersion(ctx context.Context, serverID, project, compose, env string, hasEnv bool, reason, note string) {
	sid, err := uuid.Parse(serverID)
	if err != nil {
		return
	}
	rev := projectRevision(compose, env, hasEnv)
	if last, err := h.q.LatestDockerProjectVersion(ctx, sqlc.LatestDockerProjectVersionParams{ServerID: sid, Project: project}); err == nil && last.Revision == rev && reason != "restore" {
		return
	}
	var envEnc []byte
	if hasEnv {
		envEnc = h.box.Seal(env)
	}
	by := ""
	if pr := principalOf(ctx); pr != nil {
		by = cmpOr(pr.User.FullName, pr.User.Username)
	}
	if len(note) > maxProjectNote {
		note = note[:maxProjectNote]
	}
	if _, err := h.q.CreateDockerProjectVersion(ctx, sqlc.CreateDockerProjectVersionParams{
		ServerID: sid, Project: project, Revision: rev, Compose: compose, EnvEnc: envEnc,
		Reason: reason, Note: note, CreatedByName: by,
	}); err != nil {
		slog.Warn("docker: keeping a project version", "project", project, "error", err)
		return
	}
	keep := int32(defaultVersionsKeep)
	if srv, err := h.get(ctx, serverID); err == nil {
		if set, err := h.serverDockerSettings(ctx, srv); err == nil {
			keep = int32(set.VersionsKeep)
		}
	}
	_ = h.q.PruneDockerProjectVersions(ctx, sqlc.PruneDockerProjectVersionsParams{ServerID: sid, Project: project, Keep: keep})
}

// keepFoundVersion stores the files as they are before Morche first changes
// them, so the very first edit can be undone too.
func (h *serverHandler) keepFoundVersion(ctx context.Context, serverID string, cur DockerProjectDetails) {
	sid, err := uuid.Parse(serverID)
	if err != nil || !cur.Readable || cur.Missing {
		return
	}
	if _, err := h.q.LatestDockerProjectVersion(ctx, sqlc.LatestDockerProjectVersionParams{ServerID: sid, Project: cur.Name}); err == nil || !isNotFound(err) {
		return
	}
	h.recordProjectVersion(context.WithoutCancel(ctx), serverID, cur.Name, cur.Compose, cur.Env, cur.HasEnv, "found", "")
}

// writeProjectFiles writes and checks a project's files (see
// writeFilesScript). An empty env removes the .env.
func (h *serverHandler) writeProjectFiles(ctx context.Context, serverID string, p DockerProject, compose, env string) error {
	b64c := base64.StdEncoding.EncodeToString([]byte(compose))
	b64e := base64.StdEncoding.EncodeToString([]byte(env))
	script := writeFilesScript(p.Name, p.Dir, p.Files[0], p.Files, compose, env, b64c, b64e)
	err := h.withShell(ctx, serverID, func(_ *sshpool.Conn, sh *rootShell) error {
		_, err := sh.hiding(false, b64c, b64e).run(ctx, script)
		return err
	})
	if err != nil {
		return shellFailure(err, "body.compose")
	}
	return nil
}

func versionOut(r sqlc.ListDockerProjectVersionsRow, current string) DockerProjectVersion {
	return DockerProjectVersion{
		ID: r.ID, Revision: r.Revision, Reason: r.Reason, Note: r.Note, By: r.CreatedByName,
		CreatedAt: r.CreatedAt, ComposeSize: int(r.ComposeSize), HasEnv: r.HasEnv,
		Current: current != "" && r.Revision == current,
	}
}

func (h *serverHandler) projectVersion(ctx context.Context, in *DockerProjectVersionPath) (sqlc.DockerProjectVersion, error) {
	sid, err := uuid.Parse(in.ID)
	vid, err2 := uuid.Parse(in.Version)
	if err != nil || err2 != nil {
		return sqlc.DockerProjectVersion{}, huma.Error404NotFound("version not found")
	}
	v, err := h.q.GetDockerProjectVersion(ctx, sqlc.GetDockerProjectVersionParams{ID: vid, ServerID: sid, Project: in.Project})
	if err != nil {
		if isNotFound(err) {
			return v, huma.Error404NotFound("This version isn't kept any more")
		}
		return v, internalError(err)
	}
	return v, nil
}

func (h *serverHandler) versionFiles(v sqlc.DockerProjectVersion) (DockerProjectVersionFiles, error) {
	env := ""
	if v.EnvEnc != nil {
		var err error
		if env, err = h.box.Open(v.EnvEnc); err != nil {
			return DockerProjectVersionFiles{}, internalError(err)
		}
	}
	return DockerProjectVersionFiles{
		DockerProjectVersion: DockerProjectVersion{
			ID: v.ID, Revision: v.Revision, Reason: v.Reason, Note: v.Note, By: v.CreatedByName,
			CreatedAt: v.CreatedAt, ComposeSize: len(v.Compose), HasEnv: v.EnvEnc != nil,
		},
		Compose: v.Compose, Env: env,
	}, nil
}

func registerDockerProjectVersions(api huma.API, h *serverHandler) {
	tags := []string{"Containers"}
	base := "/servers/{id}/docker/projects/{project}/versions"

	huma.Register(api, huma.Operation{
		OperationID: "list-docker-project-versions",
		Method:      http.MethodGet,
		Path:        base,
		Summary:     "A project's file history",
		Description: "Versions of the compose and .env files Morche wrote, newest first (the last 50 are kept), with the one on the server now marked.",
		Tags:        tags,
	}, func(ctx context.Context, in *DockerProjectPath) (*struct{ Body DockerProjectVersions }, error) {
		p, _, err := h.dockerProject(ctx, in.ID, in.Project)
		if err != nil {
			return nil, err
		}
		sid, _ := uuid.Parse(in.ID)
		rows, err := h.q.ListDockerProjectVersions(ctx, sqlc.ListDockerProjectVersionsParams{ServerID: sid, Project: p.Name})
		if err != nil {
			return nil, internalError(err)
		}
		cur := ""
		if len(p.Files) > 0 {
			if d, err := h.readProjectFiles(ctx, in.ID, p); err == nil && d.Readable && !d.Missing {
				cur = d.Revision
			}
		}
		out := DockerProjectVersions{Items: make([]DockerProjectVersion, 0, len(rows)), Revision: cur}
		for _, r := range rows {
			out.Items = append(out.Items, versionOut(r, cur))
		}
		return &struct{ Body DockerProjectVersions }{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-docker-project-version",
		Method:      http.MethodGet,
		Path:        base + "/{version}",
		Summary:     "One version of a project's files",
		Tags:        tags,
	}, func(ctx context.Context, in *DockerProjectVersionPath) (*struct{ Body DockerProjectVersionFiles }, error) {
		v, err := h.projectVersion(ctx, in)
		if err != nil {
			return nil, err
		}
		f, err := h.versionFiles(v)
		if err != nil {
			return nil, err
		}
		return &struct{ Body DockerProjectVersionFiles }{f}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "restore-docker-project-version",
		Method:      http.MethodPost,
		Path:        base + "/{version}/restore",
		Summary:     "Put an older version of a project's files back",
		Description: "Writes that version's compose and .env (checked with `docker compose config` like a save) and keeps it as a new version. With `deploy`, runs compose up as a job. 409 when the files changed since `revision`.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerProjectVersionPath
		Body DockerProjectRestoreBody
	}) (*struct{ Body DockerProjectCreated }, error) {
		v, err := h.projectVersion(ctx, &in.DockerProjectVersionPath)
		if err != nil {
			return nil, err
		}
		f, err := h.versionFiles(v)
		if err != nil {
			return nil, err
		}
		p, root, err := h.dockerProject(ctx, in.ID, in.Project)
		if err != nil {
			return nil, err
		}
		if len(p.Files) == 0 {
			return nil, huma.Error422UnprocessableEntity("Its containers don't say where the compose file is, so the files can't be written")
		}
		cur, err := h.readProjectFiles(ctx, in.ID, p)
		if err != nil {
			return nil, err
		}
		if in.Body.Revision != "" && !cur.Missing && in.Body.Revision != cur.Revision {
			return nil, huma.Error409Conflict("Someone changed these files since you looked")
		}
		h.keepFoundVersion(ctx, in.ID, cur)
		if err := h.writeProjectFiles(ctx, in.ID, p, f.Compose, f.Env); err != nil {
			return nil, err
		}
		note := "Back to the version of " + v.CreatedAt.UTC().Format("2 Jan 2006 15:04") + " UTC"
		h.recordProjectVersion(ctx, in.ID, p.Name, f.Compose, f.Env, f.HasEnv, "restore", note)
		d, err := h.readProjectFiles(ctx, in.ID, p)
		if err != nil {
			return nil, err
		}
		out := &struct{ Body DockerProjectCreated }{DockerProjectCreated{Project: d}}
		if in.Body.Deploy {
			j, err := h.submitCompose(ctx, in.ID, p, root, "up")
			if err != nil {
				return nil, err
			}
			out.Body.Job = &j.Body
		}
		return out, nil
	})
}
