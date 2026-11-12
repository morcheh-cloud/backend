package api

import (
	"context"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/docker"
	"github.com/morcheh/backend/internal/sshpool"
)

// ---- Settings ----

const (
	defaultProjectsDir  = "/opt/morcheh/projects"
	defaultScannerImage = "aquasec/trivy:latest"
	defaultEventsHours  = 24
)

type DockerSettings struct {
	ProjectsDir  string    `json:"projects_dir" doc:"Folder on each server where new compose projects are created, one folder per project"`
	UpdateCheck  bool      `json:"update_check" doc:"Check once a day whether running images have a newer version"`
	ScannerImage string    `json:"scanner_image" doc:"Image used to scan for vulnerabilities when Trivy isn't installed on the server"`
	EventsHours  int       `json:"events_hours" minimum:"1" maximum:"720" doc:"How far back the event log reads by default"`
	UpdatedAt    time.Time `json:"updated_at,omitzero"`
}

type DockerSettingsBody struct {
	ProjectsDir  string `json:"projects_dir" minLength:"2" maxLength:"500"`
	UpdateCheck  bool   `json:"update_check"`
	ScannerImage string `json:"scanner_image" minLength:"1" maxLength:"300"`
	EventsHours  int    `json:"events_hours" minimum:"1" maximum:"720"`
}

func toDockerSettings(s sqlc.DockerSetting) DockerSettings {
	return DockerSettings{ProjectsDir: s.ProjectsDir, UpdateCheck: s.UpdateCheck, ScannerImage: s.ScannerImage, EventsHours: int(s.EventsHours), UpdatedAt: s.UpdatedAt}
}

// dockerSettings returns the workspace's settings, or the defaults.
func (h *serverHandler) dockerSettings(ctx context.Context, ws uuid.UUID) (DockerSettings, error) {
	s, err := h.q.GetDockerSettings(ctx, ws)
	if isNotFound(err) {
		return DockerSettings{ProjectsDir: defaultProjectsDir, UpdateCheck: true, ScannerImage: defaultScannerImage, EventsHours: defaultEventsHours}, nil
	}
	if err != nil {
		return DockerSettings{}, internalError(err)
	}
	return toDockerSettings(s), nil
}

// ---- Registries ----

type DockerRegistry struct {
	ID          string    `json:"id" format:"uuid"`
	Name        string    `json:"name"`
	Address     string    `json:"address" doc:"Registry host, like docker.io, ghcr.io or registry.example.com:5000"`
	Username    string    `json:"username"`
	HasPassword bool      `json:"has_password" doc:"A password or token is saved (it never comes back)"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type DockerRegistryBody struct {
	Name     string `json:"name" minLength:"1" maxLength:"100"`
	Address  string `json:"address" minLength:"1" maxLength:"300"`
	Username string `json:"username" maxLength:"200"`
	Password string `json:"password,omitempty" required:"false" maxLength:"4000" doc:"Password or access token. Blank keeps the saved one when editing"`
}

type DockerRegistryTestBody struct {
	ServerID   string `json:"server_id" format:"uuid" doc:"Server whose engine tries the login"`
	Address    string `json:"address" minLength:"1" maxLength:"300"`
	Username   string `json:"username" maxLength:"200"`
	Password   string `json:"password,omitempty" required:"false" maxLength:"4000"`
	RegistryID string `json:"registry_id,omitempty" required:"false" format:"uuid" doc:"Saved registry whose password to use when password is blank"`
}

type DockerRegistryTest struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func toDockerRegistry(r sqlc.DockerRegistry) DockerRegistry {
	return DockerRegistry{ID: r.ID.String(), Name: r.Name, Address: r.Address, Username: r.Username, HasPassword: len(r.PasswordEnc) > 0, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}

// registryHost tidies what someone typed into a registry host:
// "https://index.docker.io/v1/" → "docker.io".
func registryHost(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	switch s {
	case "", "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com", "hub.docker.com":
		return "docker.io"
	}
	return s
}

// imageRegistry is the registry an image reference is pulled from.
func imageRegistry(ref string) string {
	i := strings.IndexByte(ref, '/')
	if i < 0 {
		return "docker.io"
	}
	first := ref[:i]
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return registryHost(first)
	}
	return "docker.io"
}

// registryServer is the address the engine's auth wants for a host.
func registryServer(host string) string {
	if host == "docker.io" {
		return "https://index.docker.io/v1/"
	}
	return host
}

// registryAuthFor returns the X-Registry-Auth value for pulling image on a
// server of workspace ws, or "" when the workspace keeps no login for its
// registry.
func (h *serverHandler) registryAuthFor(ctx context.Context, ws uuid.UUID, image string) string {
	host := imageRegistry(image)
	rows, err := h.q.ListDockerRegistries(ctx, ws)
	if err != nil {
		return ""
	}
	for _, r := range rows {
		if r.Address != host {
			continue
		}
		pass := ""
		if len(r.PasswordEnc) > 0 {
			b, err := h.box.Open(r.PasswordEnc)
			if err != nil {
				return ""
			}
			pass = string(b)
		}
		return docker.RegistryAuth(registryServer(host), r.Username, pass)
	}
	return ""
}

// serverRegistryAuth is registryAuthFor for the workspace a server is in.
func (h *serverHandler) serverRegistryAuth(ctx context.Context, serverID, image string) string {
	id, err := uuid.Parse(serverID)
	if err != nil {
		return ""
	}
	s, err := h.q.GetServer(ctx, id)
	if err != nil {
		return ""
	}
	return h.registryAuthFor(ctx, s.WorkspaceID, image)
}

// ---- Templates ----

type DockerTemplate struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Category    string    `json:"category"`
	Compose     string    `json:"compose"`
	Env         string    `json:"env"`
	Builtin     bool      `json:"builtin" doc:"Comes with Morche; can't be changed (copy it instead)"`
	Logo        string    `json:"logo,omitempty" doc:"Logo slug, for built-in templates"`
	CreatedBy   string    `json:"created_by,omitempty"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitzero"`
}

type DockerTemplateBody struct {
	Name        string `json:"name" minLength:"1" maxLength:"100"`
	Description string `json:"description" maxLength:"1000"`
	Category    string `json:"category" maxLength:"50"`
	Compose     string `json:"compose" minLength:"1" maxLength:"200000"`
	Env         string `json:"env" maxLength:"100000"`
}

type DockerTemplates struct {
	Builtin []DockerTemplate `json:"builtin"`
	Custom  []DockerTemplate `json:"custom"`
}

func toDockerTemplate(t sqlc.DockerTemplate) DockerTemplate {
	return DockerTemplate{
		ID: t.ID.String(), Name: t.Name, Description: t.Description, Category: t.Category,
		Compose: t.Compose, Env: t.Env, CreatedBy: t.CreatedByName, UpdatedBy: t.UpdatedByName, UpdatedAt: t.UpdatedAt,
	}
}

// findTemplate returns a built-in template ("builtin:<slug>") or one of the
// workspace's own.
func (h *serverHandler) findTemplate(ctx context.Context, ws uuid.UUID, id string) (DockerTemplate, error) {
	if slug, ok := strings.CutPrefix(id, "builtin:"); ok {
		for _, t := range builtinTemplates {
			if t.ID == "builtin:"+slug {
				return t, nil
			}
		}
		return DockerTemplate{}, huma.Error404NotFound("No such template")
	}
	tid, err := uuid.Parse(id)
	if err != nil {
		return DockerTemplate{}, huma.Error404NotFound("No such template")
	}
	t, err := h.q.GetDockerTemplate(ctx, sqlc.GetDockerTemplateParams{ID: tid, WorkspaceID: ws})
	if isNotFound(err) {
		return DockerTemplate{}, huma.Error404NotFound("No such template")
	}
	if err != nil {
		return DockerTemplate{}, internalError(err)
	}
	return toDockerTemplate(t), nil
}

// ---- Handlers ----

type dockerRegistryPath struct {
	WorkspacePath
	Registry string `path:"registry" format:"uuid"`
}

type dockerTemplatePath struct {
	WorkspacePath
	Template string `path:"template" format:"uuid"`
}

func registerDockerSettings(api huma.API, h *serverHandler) {
	tags := []string{"Containers"}
	base := "/workspaces/{id}/docker"

	huma.Register(api, huma.Operation{
		OperationID: "get-docker-settings",
		Method:      http.MethodGet,
		Path:        base + "/settings",
		Summary:     "Container settings of a workspace",
		Tags:        tags,
	}, func(ctx context.Context, in *WorkspacePath) (*struct{ Body DockerSettings }, error) {
		s, err := h.dockerSettings(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, err
		}
		return &struct{ Body DockerSettings }{s}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-docker-settings",
		Method:      http.MethodPut,
		Path:        base + "/settings",
		Summary:     "Change a workspace's container settings",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body DockerSettingsBody
	}) (*struct{ Body DockerSettings }, error) {
		b := in.Body
		dir := path.Clean(strings.TrimSpace(b.ProjectsDir))
		if !strings.HasPrefix(dir, "/") || dir == "/" || strings.ContainsAny(dir, "\n\r\x00") {
			return nil, fieldError("body.projects_dir", "Use a full folder path like /opt/projects", dir)
		}
		img := strings.TrimSpace(b.ScannerImage)
		if strings.ContainsAny(img, " \t\n") {
			return nil, fieldError("body.scanner_image", "An image name has no spaces", img)
		}
		s, err := h.q.UpsertDockerSettings(ctx, sqlc.UpsertDockerSettingsParams{
			WorkspaceID: uuid.MustParse(in.ID), ProjectsDir: dir, UpdateCheck: b.UpdateCheck, ScannerImage: img, EventsHours: int32(b.EventsHours),
		})
		if err != nil {
			return nil, internalError(err)
		}
		return &struct{ Body DockerSettings }{toDockerSettings(s)}, nil
	})

	// -- Registries --

	huma.Register(api, huma.Operation{
		OperationID: "list-docker-registries",
		Method:      http.MethodGet,
		Path:        base + "/registries",
		Summary:     "Registry logins of a workspace",
		Description: "Used for every pull on the workspace's servers (pulls, updates, compose projects). Passwords never come back.",
		Tags:        tags,
	}, func(ctx context.Context, in *WorkspacePath) (*struct {
		Body struct {
			Items []DockerRegistry `json:"items"`
		}
	}, error) {
		rows, err := h.q.ListDockerRegistries(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []DockerRegistry `json:"items"`
			}
		}{}
		out.Body.Items = make([]DockerRegistry, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = toDockerRegistry(r)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-docker-registry",
		Method:        http.MethodPost,
		Path:          base + "/registries",
		Summary:       "Save a registry login",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body DockerRegistryBody
	}) (*struct{ Body DockerRegistry }, error) {
		b := in.Body
		host := registryHost(b.Address)
		if strings.ContainsAny(host, " \t") {
			return nil, fieldError("body.address", "A registry address has no spaces", b.Address)
		}
		r, err := h.q.CreateDockerRegistry(ctx, sqlc.CreateDockerRegistryParams{
			WorkspaceID: uuid.MustParse(in.ID), Name: strings.TrimSpace(b.Name), Address: host,
			Username: strings.TrimSpace(b.Username), PasswordEnc: h.box.Seal(b.Password),
		})
		if isUniqueViolation(err) {
			return nil, fieldError("body.address", "This workspace already has a login for "+host, b.Address)
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &struct{ Body DockerRegistry }{toDockerRegistry(r)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-docker-registry",
		Method:      http.MethodPut,
		Path:        base + "/registries/{registry}",
		Summary:     "Change a registry login",
		Description: "A blank password keeps the saved one.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		dockerRegistryPath
		Body DockerRegistryBody
	}) (*struct{ Body DockerRegistry }, error) {
		b := in.Body
		host := registryHost(b.Address)
		var pass []byte
		if b.Password != "" {
			pass = h.box.Seal(b.Password)
		}
		r, err := h.q.UpdateDockerRegistry(ctx, sqlc.UpdateDockerRegistryParams{
			ID: uuid.MustParse(in.Registry), WorkspaceID: uuid.MustParse(in.ID),
			Name: strings.TrimSpace(b.Name), Address: host, Username: strings.TrimSpace(b.Username), PasswordEnc: pass,
		})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("No such registry")
		}
		if isUniqueViolation(err) {
			return nil, fieldError("body.address", "This workspace already has a login for "+host, b.Address)
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &struct{ Body DockerRegistry }{toDockerRegistry(r)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-docker-registry",
		Method:      http.MethodDelete,
		Path:        base + "/registries/{registry}",
		Summary:     "Forget a registry login",
		Tags:        tags,
	}, func(ctx context.Context, in *dockerRegistryPath) (*struct{}, error) {
		n, err := h.q.DeleteDockerRegistry(ctx, sqlc.DeleteDockerRegistryParams{ID: uuid.MustParse(in.Registry), WorkspaceID: uuid.MustParse(in.ID)})
		if err != nil {
			return nil, internalError(err)
		}
		if n == 0 {
			return nil, huma.Error404NotFound("No such registry")
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "test-docker-registry",
		Method:      http.MethodPost,
		Path:        base + "/registries/test",
		Summary:     "Try a registry login",
		Description: "Asks a server's engine to log in with these values (nothing is saved). Needs Engineer on that server.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body DockerRegistryTestBody
	}) (*struct{ Body DockerRegistryTest }, error) {
		b := in.Body
		sid, err := uuid.Parse(b.ServerID)
		if err != nil {
			return nil, fieldError("body.server_id", "Pick a server", b.ServerID)
		}
		if _, err := h.authz.requireServers(ctx, []uuid.UUID{sid}, auth.Engineer); err != nil {
			return nil, err
		}
		pass := b.Password
		if pass == "" && b.RegistryID != "" {
			r, err := h.q.GetDockerRegistry(ctx, sqlc.GetDockerRegistryParams{ID: uuid.MustParse(b.RegistryID), WorkspaceID: uuid.MustParse(in.ID)})
			if err == nil && len(r.PasswordEnc) > 0 {
				if p, err := h.box.Open(r.PasswordEnc); err == nil {
					pass = string(p)
				}
			}
		}
		host := registryHost(b.Address)
		out := &struct{ Body DockerRegistryTest }{}
		err = h.withDocker(ctx, b.ServerID, func(e *dockerEngine) error {
			status, err := e.client.Login(ctx, registryServer(host), strings.TrimSpace(b.Username), pass)
			if err != nil {
				out.Body = DockerRegistryTest{Message: dockerProblemText(dockerProblem(err))}
				return nil
			}
			if status == "" {
				status = "Login Succeeded"
			}
			out.Body = DockerRegistryTest{OK: true, Message: status}
			return nil
		})
		if err != nil {
			return nil, dockerProblem(err)
		}
		return out, nil
	})

	// -- Templates --

	huma.Register(api, huma.Operation{
		OperationID: "list-docker-templates",
		Method:      http.MethodGet,
		Path:        base + "/templates",
		Summary:     "Compose templates",
		Description: "The built-in ones and the workspace's own.",
		Tags:        tags,
	}, func(ctx context.Context, in *WorkspacePath) (*struct{ Body DockerTemplates }, error) {
		rows, err := h.q.ListDockerTemplates(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct{ Body DockerTemplates }{DockerTemplates{Builtin: builtinTemplates, Custom: make([]DockerTemplate, len(rows))}}
		for i, r := range rows {
			out.Body.Custom[i] = toDockerTemplate(r)
		}
		return out, nil
	})

	saveTemplate := func(ctx context.Context, ws uuid.UUID, id *uuid.UUID, b DockerTemplateBody) (*struct{ Body DockerTemplate }, error) {
		if err := checkComposeText(b.Compose); err != nil {
			return nil, err
		}
		who := ""
		if p := principalOf(ctx); p != nil {
			who = displayName(p.User)
		}
		var t sqlc.DockerTemplate
		var err error
		name, cat := strings.TrimSpace(b.Name), strings.TrimSpace(b.Category)
		if id == nil {
			t, err = h.q.CreateDockerTemplate(ctx, sqlc.CreateDockerTemplateParams{
				WorkspaceID: ws, Name: name, Description: strings.TrimSpace(b.Description), Category: cat,
				Compose: b.Compose, Env: b.Env, CreatedByName: who,
			})
		} else {
			t, err = h.q.UpdateDockerTemplate(ctx, sqlc.UpdateDockerTemplateParams{
				ID: *id, WorkspaceID: ws, Name: name, Description: strings.TrimSpace(b.Description), Category: cat,
				Compose: b.Compose, Env: b.Env, UpdatedByName: who,
			})
		}
		if isNotFound(err) {
			return nil, huma.Error404NotFound("No such template")
		}
		if isUniqueViolation(err) {
			return nil, fieldError("body.name", "A template with this name already exists", name)
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &struct{ Body DockerTemplate }{toDockerTemplate(t)}, nil
	}

	huma.Register(api, huma.Operation{
		OperationID:   "create-docker-template",
		Method:        http.MethodPost,
		Path:          base + "/templates",
		Summary:       "Save a compose template",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body DockerTemplateBody
	}) (*struct{ Body DockerTemplate }, error) {
		return saveTemplate(ctx, uuid.MustParse(in.ID), nil, in.Body)
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-docker-template",
		Method:      http.MethodPut,
		Path:        base + "/templates/{template}",
		Summary:     "Change a compose template",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		dockerTemplatePath
		Body DockerTemplateBody
	}) (*struct{ Body DockerTemplate }, error) {
		id := uuid.MustParse(in.Template)
		return saveTemplate(ctx, uuid.MustParse(in.ID), &id, in.Body)
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-docker-template",
		Method:      http.MethodDelete,
		Path:        base + "/templates/{template}",
		Summary:     "Delete a compose template",
		Tags:        tags,
	}, func(ctx context.Context, in *dockerTemplatePath) (*struct{}, error) {
		n, err := h.q.DeleteDockerTemplate(ctx, sqlc.DeleteDockerTemplateParams{ID: uuid.MustParse(in.Template), WorkspaceID: uuid.MustParse(in.ID)})
		if err != nil {
			return nil, internalError(err)
		}
		if n == 0 {
			return nil, huma.Error404NotFound("No such template")
		}
		return nil, nil
	})
}

// checkComposeText is a cheap first look at a compose file; the server's
// `docker compose config` has the last word.
func checkComposeText(s string) error {
	if !strings.Contains(s, "services:") {
		return fieldError("body.compose", "A compose file needs a services: section", "")
	}
	if strings.Contains(s, "\t") {
		return fieldError("body.compose", "YAML can't be indented with tabs: use spaces", "")
	}
	return nil
}

// withConnShell runs fn with the server's connection and root shell.
func (h *serverHandler) withShell(ctx context.Context, id string, fn func(c *sshpool.Conn, sh *rootShell) error) error {
	return h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.rootShell(ctx, id, c)
		if err != nil {
			return err
		}
		return fn(c, sh)
	})
}
