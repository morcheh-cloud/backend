package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/software"
	"github.com/morcheh/backend/internal/sshpool"
)

// Applications: a catalog of software (packages like Docker, Docker Compose
// apps like Grafana) installed, updated and removed on servers from the
// panel, plus what a scan finds already installed. Named "software" in code
// because "apps" are the team's web services (/services).

const (
	softwareRunKind  = "software-run"
	softwareScanKind = "software-scan"
)

// ---- API types ----

type SoftwareImage struct {
	Service string `json:"service"`
	Image   string `json:"image"`
	Version string `json:"version,omitempty"`
	State   string `json:"state" doc:"The container's state: running, exited, restarting…"`
	Update  bool   `json:"update,omitempty" doc:"The registry has a newer image under the same tag"`
}

type SoftwarePackage struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Latest   string `json:"latest"`
	Security bool   `json:"security,omitempty"`
}

type SoftwareInstall struct {
	ID              string            `json:"id" format:"uuid"`
	WorkspaceID     string            `json:"workspace_id" format:"uuid"`
	ServerID        string            `json:"server_id" format:"uuid"`
	ServerName      string            `json:"server_name"`
	ServerStatus    string            `json:"server_status"`
	RecipeID        string            `json:"recipe_id"`
	Name            string            `json:"name"`
	Kind            string            `json:"kind" enum:"package,docker,script"`
	Origin          string            `json:"origin" enum:"morcheh,found" doc:"morcheh = installed from the panel; found = a scan found it"`
	Status          string            `json:"status" enum:"installing,installed,updating,failed,removing,missing"`
	Version         string            `json:"version"`
	Latest          string            `json:"latest"`
	UpdateAvailable bool              `json:"update_available"`
	State           string            `json:"state" doc:"Docker apps: running, stopped or partial"`
	Params          map[string]string `json:"params" doc:"The values it was installed with, without the secret ones"`
	SecretParams    []string          `json:"secret_params" doc:"Names of the secret values kept for it (Owners can reveal them)"`
	Dir             string            `json:"dir,omitempty"`
	Project         string            `json:"project,omitempty"`
	Images          []SoftwareImage   `json:"images"`
	CanRollback     bool              `json:"can_rollback"`
	Pinned          bool              `json:"pinned" doc:"Runs the version before its last update (rolled back)"`
	Error           string            `json:"error"`
	CheckedAt       *time.Time        `json:"checked_at"`
	InstalledAt     *time.Time        `json:"installed_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

type SoftwareHost struct {
	ServerID       string            `json:"server_id" format:"uuid"`
	ServerName     string            `json:"server_name"`
	ServerStatus   string            `json:"server_status"`
	PM             string            `json:"pm" doc:"Package manager: apt, dnf, yum, zypper, apk or pacman"`
	Docker         string            `json:"docker" doc:"Docker's version; empty when it isn't installed or running"`
	Compose        string            `json:"compose"`
	Upgradable     int32             `json:"upgradable" doc:"System packages with a newer version"`
	Security       int32             `json:"security" doc:"Of which security updates"`
	RebootRequired bool              `json:"reboot_required"`
	Packages       []SoftwarePackage `json:"packages"`
	Error          string            `json:"error" doc:"Why the last scan failed"`
	CheckedAt      time.Time         `json:"checked_at"`
}

type SoftwareRunOptions struct {
	Parallel      int   `json:"parallel,omitempty" minimum:"0" maximum:"20" doc:"Servers at a time; 0 = 5 for install and uninstall, 1 for the rest"`
	StopOnFailure *bool `json:"stop_on_failure,omitempty" doc:"Skip the servers not started yet once one fails. Default: on for updates, off for installs"`
	Fresh         bool  `json:"fresh,omitempty" doc:"Install of a Docker app: delete data an earlier install left first"`
	RemoveData    bool  `json:"remove_data,omitempty" doc:"Uninstall of a Docker app: delete its volumes and folder too"`
	SecurityOnly  bool  `json:"security_only,omitempty" doc:"System upgrade: security updates only (apt, dnf, yum, zypper)"`
	Full          bool  `json:"full,omitempty" doc:"System upgrade: apt full-upgrade / dist-upgrade, which may remove packages"`
}

type SoftwareRun struct {
	ID            string     `json:"id" format:"uuid"`
	WorkspaceID   string     `json:"workspace_id" format:"uuid"`
	Action        string     `json:"action" enum:"install,update,uninstall,rollback,upgrade-system"`
	Name          string     `json:"name"`
	State         string     `json:"state" enum:"queued,running,succeeded,failed,canceled,interrupted"`
	Error         string     `json:"error"`
	JobID         string     `json:"job_id,omitempty" format:"uuid"`
	CreatedByName string     `json:"created_by_name"`
	CreatedAt     time.Time  `json:"created_at"`
	StartedAt     *time.Time `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at"`
	Targets       int32      `json:"targets"`
	Succeeded     int32      `json:"succeeded"`
	Failed        int32      `json:"failed"`
	ServerNames   []string   `json:"server_names"`
	ServerIDs     []string   `json:"server_ids"`
}

type SoftwareRunTarget struct {
	Position      int32      `json:"position"`
	ServerID      string     `json:"server_id,omitempty" format:"uuid"`
	ServerName    string     `json:"server_name"`
	RecipeID      string     `json:"recipe_id"`
	RecipeName    string     `json:"recipe_name"`
	State         string     `json:"state" enum:"queued,running,succeeded,failed,canceled,interrupted,skipped"`
	Error         string     `json:"error"`
	Output        string     `json:"output"`
	Truncated     bool       `json:"truncated"`
	VersionBefore string     `json:"version_before"`
	VersionAfter  string     `json:"version_after"`
	StartedAt     *time.Time `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at"`
}

type SoftwareRunDetail struct {
	SoftwareRun
	Options SoftwareRunOptions  `json:"options"`
	Params  map[string]string   `json:"params" doc:"The values given, without the secret ones"`
	Steps   []SoftwareRunTarget `json:"steps" doc:"One per server and application, in the order they run on each server"`
}

type startSoftwareRunBody struct {
	Action    string             `json:"action" enum:"install,update,uninstall,rollback,upgrade-system"`
	ServerIDs []string           `json:"server_ids" minItems:"1" maxItems:"500"`
	Recipes   []string           `json:"recipes,omitempty" maxItems:"100" doc:"Install: exactly one. Update, uninstall, rollback: the applications (\"system\" = the server's packages); empty for update = every one with an update. Ignored by upgrade-system"`
	Params    map[string]string  `json:"params,omitempty" doc:"Install: the recipe's parameters. Empty generated ones are made for each server"`
	Options   SoftwareRunOptions `json:"options,omitempty"`
}

type SoftwarePreflight struct {
	ServerID   string   `json:"server_id" format:"uuid"`
	ServerName string   `json:"server_name"`
	OK         bool     `json:"ok" doc:"Nothing stops the install"`
	Problems   []string `json:"problems" doc:"What would make it fail"`
	Warnings   []string `json:"warnings"`
	First      []string `json:"first" doc:"Applications installed before it on this server (what it requires)"`
	Installed  bool     `json:"installed" doc:"Already on this server"`
	Version    string   `json:"version,omitempty"`
	PM         string   `json:"pm,omitempty"`
	Docker     string   `json:"docker,omitempty"`
	Arch       string   `json:"arch,omitempty"`
	FreeMB     int64    `json:"free_mb,omitempty"`
}

// ---- Handler ----

type softwareHandler struct {
	q        *sqlc.Queries
	servers  *serverHandler
	authz    *authz
	runner   *jobs.Runner
	scripts  *scriptHandler
	registry *software.Registry
}

func newSoftwareHandler(servers *serverHandler, a *authz, scripts *scriptHandler) *softwareHandler {
	h := &softwareHandler{
		q: servers.q, servers: servers, authz: a, runner: servers.jobs, scripts: scripts,
		registry: software.NewRegistry(),
	}
	ctx := context.Background()
	if err := h.q.InterruptSoftwareRuns(ctx); err != nil {
		slog.Warn("end software runs left running", "error", err)
	}
	if err := h.q.ResetStuckSoftwareInstalls(ctx); err != nil {
		slog.Warn("reset software left changing", "error", err)
	}
	go func() {
		for {
			if err := h.q.DeleteOldSoftwareRuns(ctx); err != nil {
				slog.Warn("delete old software runs", "error", err)
			}
			time.Sleep(6 * time.Hour)
		}
	}()
	return h
}

// The answer to installing a built-in recipe taken out of the catalog.
const retiredText = "This application is no longer in the catalog. Earlier installs can still be updated and removed."

// catalog is every recipe a workspace's servers can install: the built-in
// ones and the workspace's own.
func (h *softwareHandler) catalog(ctx context.Context, ws uuid.UUID) ([]software.Recipe, error) {
	list := software.Builtins()
	rows, err := h.q.ListSoftwareRecipes(ctx, ws)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		r, ok := recipeOf(row)
		if ok {
			list = append(list, r)
		}
	}
	sort.SliceStable(list, func(i, j int) bool { return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name) })
	return list, nil
}

func recipeOf(row sqlc.SoftwareRecipe) (software.Recipe, bool) {
	var r software.Recipe
	if err := json.Unmarshal(row.Spec, &r); err != nil {
		slog.Warn("a saved software recipe doesn't read", "id", row.ID, "error", err)
		return r, false
	}
	r.ID, r.Builtin, r.RecordID = row.Slug, false, row.ID.String()
	return r, true
}

// ---- Conversions ----

func softwareImages(raw []byte) []SoftwareImage {
	var imgs []software.Image
	decodeInto(raw, &imgs)
	out := make([]SoftwareImage, len(imgs))
	for i, img := range imgs {
		out[i] = SoftwareImage{Service: img.Service, Image: img.Image, Version: img.Version, State: img.State, Update: img.Update}
	}
	return out
}

func (h *softwareHandler) toInstall(r sqlc.GetSoftwareInstallRow) SoftwareInstall {
	params := map[string]string{}
	decodeInto(r.Params, &params)
	secrets := []string{}
	for name := range h.openSecrets(r.Secrets) {
		secrets = append(secrets, name)
	}
	sort.Strings(secrets)
	return SoftwareInstall{
		ID: r.ID.String(), WorkspaceID: r.WorkspaceID.String(), ServerID: r.ServerID.String(),
		ServerName: r.ServerName, ServerStatus: r.ServerStatus, RecipeID: r.RecipeID, Name: r.Name,
		Kind: r.Kind, Origin: r.Origin, Status: r.Status, Version: r.Version, Latest: r.Latest,
		UpdateAvailable: r.UpdateAvailable, State: r.State, Params: params, SecretParams: secrets,
		Dir: r.Dir, Project: r.Project, Images: softwareImages(r.Images), CanRollback: r.CanRollback,
		Pinned: r.Pinned, Error: r.Error, CheckedAt: r.CheckedAt, InstalledAt: r.InstalledAt, UpdatedAt: r.UpdatedAt,
	}
}

func toSoftwareHost(r sqlc.ListSoftwareHostsRow) SoftwareHost {
	var pkgs []software.Package
	decodeInto(r.Packages, &pkgs)
	out := SoftwareHost{
		ServerID: r.ServerID.String(), ServerName: r.ServerName, ServerStatus: r.ServerStatus,
		PM: r.Pm, Docker: r.Docker, Compose: r.Compose, Upgradable: r.Upgradable, Security: r.Security,
		RebootRequired: r.RebootRequired, Packages: make([]SoftwarePackage, len(pkgs)), Error: r.Error,
		CheckedAt: r.CheckedAt,
	}
	for i, p := range pkgs {
		out.Packages[i] = SoftwarePackage{Name: p.Name, Version: p.Version, Latest: p.Latest, Security: p.Security}
	}
	return out
}

func toSoftwareRunRow(r sqlc.ListSoftwareRunsRow) SoftwareRun {
	ids := make([]string, len(r.ServerIds))
	for i, id := range r.ServerIds {
		ids[i] = id.String()
	}
	return SoftwareRun{
		ID: r.ID.String(), WorkspaceID: r.WorkspaceID.String(), Action: r.Action, Name: r.Name, State: r.State,
		Error: r.Error, JobID: optionalIDValue(r.JobID), CreatedByName: r.CreatedByName, CreatedAt: r.CreatedAt,
		StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, Targets: r.Targets, Succeeded: r.Succeeded,
		Failed: r.Failed, ServerNames: r.ServerNames, ServerIDs: ids,
	}
}

func toSoftwareRunDetail(r sqlc.SoftwareRun, targets []sqlc.SoftwareRunTarget) SoftwareRunDetail {
	out := SoftwareRunDetail{
		SoftwareRun: SoftwareRun{
			ID: r.ID.String(), WorkspaceID: r.WorkspaceID.String(), Action: r.Action, Name: r.Name, State: r.State,
			Error: r.Error, JobID: optionalIDValue(r.JobID), CreatedByName: r.CreatedByName, CreatedAt: r.CreatedAt,
			StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, Targets: int32(len(targets)),
			ServerNames: []string{}, ServerIDs: []string{},
		},
		Params: map[string]string{},
		Steps:  make([]SoftwareRunTarget, len(targets)),
	}
	decodeInto(r.Options, &out.Options)
	decodeInto(r.Params, &out.Params)
	for i, t := range targets {
		out.Steps[i] = SoftwareRunTarget{
			Position: t.Position, ServerID: optionalIDValue(t.ServerID), ServerName: t.ServerName,
			RecipeID: t.RecipeID, RecipeName: t.RecipeName, State: t.State, Error: t.Error, Output: t.Output,
			Truncated: t.Truncated, VersionBefore: t.VersionBefore, VersionAfter: t.VersionAfter,
			StartedAt: t.StartedAt, FinishedAt: t.FinishedAt,
		}
		switch t.State {
		case jobs.Succeeded:
			out.Succeeded++
		case jobs.Failed, jobs.Interrupted:
			out.Failed++
		}
		if !slices.Contains(out.ServerNames, t.ServerName) {
			out.ServerNames = append(out.ServerNames, t.ServerName)
		}
		if t.ServerID != nil && !slices.Contains(out.ServerIDs, t.ServerID.String()) {
			out.ServerIDs = append(out.ServerIDs, t.ServerID.String())
		}
	}
	return out
}

// sealSecrets keeps values as one sealed JSON object; nil when empty.
func (h *softwareHandler) sealSecrets(values map[string]string) []byte {
	if len(values) == 0 {
		return nil
	}
	raw, _ := json.Marshal(values)
	return h.servers.box.Seal(string(raw))
}

func (h *softwareHandler) openSecrets(sealed []byte) map[string]string {
	out := map[string]string{}
	if len(sealed) == 0 {
		return out
	}
	plain, err := h.servers.box.Open(sealed)
	if err != nil {
		slog.Warn("open sealed software values", "error", err)
		return out
	}
	_ = json.Unmarshal([]byte(plain), &out)
	return out
}

// splitSecret splits values into what may be shown and what is sealed.
func splitSecret(r software.Recipe, values map[string]string) (plain, secret map[string]string) {
	plain, secret = map[string]string{}, map[string]string{}
	for name, v := range values {
		i := slices.IndexFunc(r.Params, func(p software.RecipeParam) bool { return p.Name == name })
		if i >= 0 && r.Params[i].Secret() {
			secret[name] = v
		} else {
			plain[name] = v
		}
	}
	return plain, secret
}

// ---- Access ----

// softwareRunLevel is the caller's level on a run: the lowest on its servers.
func softwareRunLevel(acc *auth.Access, r sqlc.SoftwareRun, targets []sqlc.SoftwareRunTarget) auth.Level {
	level := auth.Owner + 1
	for _, t := range targets {
		if t.ServerID != nil {
			level = min(level, acc.ServerLevel(r.WorkspaceID, *t.ServerID))
		}
	}
	if level > auth.Owner {
		return acc.WorkspaceLevel(r.WorkspaceID)
	}
	return max(level, acc.WorkspaceLevel(r.WorkspaceID))
}

func (h *softwareHandler) loadRun(ctx context.Context, rawID string, need auth.Level) (sqlc.SoftwareRun, []sqlc.SoftwareRunTarget, error) {
	id, err := uuid.Parse(rawID)
	if err != nil {
		return sqlc.SoftwareRun{}, nil, huma.Error404NotFound("run not found")
	}
	r, err := h.q.GetSoftwareRun(ctx, id)
	if isNotFound(err) {
		return r, nil, huma.Error404NotFound("run not found")
	}
	if err != nil {
		return r, nil, internalError(err)
	}
	targets, err := h.q.ListSoftwareRunTargets(ctx, id)
	if err != nil {
		return r, nil, internalError(err)
	}
	switch level := softwareRunLevel(principalOf(ctx).Access, r, targets); {
	case level == auth.None:
		return r, nil, huma.Error404NotFound("run not found")
	case level < need:
		return r, nil, forbidden(need)
	}
	if h.syncRun(ctx, r.ID, r.State, r.JobID, r.CreatedAt) {
		if r, err = h.q.GetSoftwareRun(ctx, id); err != nil {
			return r, nil, internalError(err)
		}
		if targets, err = h.q.ListSoftwareRunTargets(ctx, id); err != nil {
			return r, nil, internalError(err)
		}
	}
	return r, targets, nil
}

// syncRun ends a stored run whose job ended without it.
func (h *softwareHandler) syncRun(ctx context.Context, id uuid.UUID, state string, job *uuid.UUID, created time.Time) bool {
	if !jobs.Active(state) {
		return false
	}
	end := func(state, msg string) bool {
		if err := h.q.EndSoftwareRun(ctx, sqlc.EndSoftwareRunParams{ID: id, State: state, Error: msg}); err != nil {
			slog.Warn("end a software run", "run", id, "error", err)
			return false
		}
		return true
	}
	const lost = "Morcheh restarted before it finished."
	if job == nil {
		if time.Since(created) < time.Minute {
			return false
		}
		return end(jobs.Interrupted, lost)
	}
	j, err := h.runner.Get(ctx, *job)
	switch {
	case errors.Is(err, jobs.ErrNotFound):
		return end(jobs.Interrupted, lost)
	case err != nil, jobs.Active(j.State):
		return false
	case j.State == jobs.Canceled:
		return end(jobs.Canceled, "")
	case j.State == jobs.Failed:
		return end(jobs.Failed, j.Error)
	}
	return end(jobs.Interrupted, cmpOr(j.Error, lost))
}

// loadInstall reads an install record the caller has need on (its server).
func (h *softwareHandler) loadInstall(ctx context.Context, rawID string) (sqlc.GetSoftwareInstallRow, error) {
	id, err := uuid.Parse(rawID)
	if err != nil {
		return sqlc.GetSoftwareInstallRow{}, huma.Error404NotFound("application not found")
	}
	r, err := h.q.GetSoftwareInstall(ctx, id)
	if isNotFound(err) {
		return r, huma.Error404NotFound("application not found")
	}
	if err != nil {
		return r, internalError(err)
	}
	return r, nil
}

// ---- Routes ----

var composeServiceRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)

func registerSoftware(api huma.API, h *softwareHandler) {
	h.runner.Handle(softwareRunKind, h.runJob)
	h.runner.Handle(softwareScanKind, h.scanJob)
	tags := []string{"Applications"}

	type installPath struct {
		ID string `path:"id" format:"uuid"`
	}
	type installOutput struct{ Body SoftwareInstall }

	// ---- Catalog ----

	type catalogOutput struct {
		Body struct {
			Items      []software.Recipe `json:"items"`
			Categories []string          `json:"categories"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "list-software-catalog",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/software/catalog",
		Summary:     "The applications a workspace's servers can install",
		Description: "The built-in recipes and the workspace's own, by name.",
		Tags:        tags,
	}, func(ctx context.Context, in *WorkspacePath) (*catalogOutput, error) {
		list, err := h.catalog(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		out := &catalogOutput{}
		out.Body.Items = list
		out.Body.Categories = []string{}
		for _, r := range list {
			if r.Category != "" && !slices.Contains(out.Body.Categories, r.Category) {
				out.Body.Categories = append(out.Body.Categories, r.Category)
			}
		}
		sort.Strings(out.Body.Categories)
		return out, nil
	})

	type recipeOutput struct{ Body software.Recipe }
	checkRecipe := func(r *software.Recipe) error {
		r.Normalize()
		if err := r.Check(); err != nil {
			var fe *software.FieldError
			if errors.As(err, &fe) {
				return fieldError("body."+fe.Field, fe.Msg, nil)
			}
			return huma.Error422UnprocessableEntity(err.Error())
		}
		return nil
	}

	huma.Register(api, huma.Operation{
		OperationID:   "create-software-recipe",
		Method:        http.MethodPost,
		Path:          "/workspaces/{id}/software/recipes",
		Summary:       "Add an application of the workspace's own to the catalog",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body software.Recipe
	}) (*recipeOutput, error) {
		r := in.Body
		if err := checkRecipe(&r); err != nil {
			return nil, err
		}
		if software.IsBuiltin(r.ID) || r.ID == software.System {
			return nil, fieldError("body.id", "A built-in application has this id. Choose another.", r.ID)
		}
		r.Builtin, r.RecordID = false, ""
		spec, _ := json.Marshal(r)
		row, err := h.q.CreateSoftwareRecipe(ctx, sqlc.CreateSoftwareRecipeParams{
			WorkspaceID: uuid.MustParse(in.ID), Slug: r.ID, Spec: spec, CreatedBy: principalOf(ctx).ID(),
		})
		if isUniqueViolation(err) {
			return nil, fieldError("body.id", "This workspace already has an application with this id.", r.ID)
		}
		if err != nil {
			return nil, internalError(err)
		}
		out, _ := recipeOf(row)
		return &recipeOutput{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-software-recipe",
		Method:      http.MethodPut,
		Path:        "/software-recipes/{id}",
		Summary:     "Change one of the workspace's own applications",
		Description: "Its id stays. What is installed already changes on its next update.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		installPath
		Body software.Recipe
	}) (*recipeOutput, error) {
		id := uuid.MustParse(in.ID)
		row, err := h.q.GetSoftwareRecipe(ctx, id)
		if isNotFound(err) {
			return nil, huma.Error404NotFound("recipe not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		r := in.Body
		r.ID = row.Slug
		if err := checkRecipe(&r); err != nil {
			return nil, err
		}
		r.Builtin, r.RecordID = false, ""
		spec, _ := json.Marshal(r)
		row, err = h.q.UpdateSoftwareRecipe(ctx, sqlc.UpdateSoftwareRecipeParams{ID: id, Spec: spec, UpdatedBy: principalOf(ctx).ID()})
		if err != nil {
			return nil, internalError(err)
		}
		out, _ := recipeOf(row)
		return &recipeOutput{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-software-recipe",
		Method:        http.MethodDelete,
		Path:          "/software-recipes/{id}",
		Summary:       "Remove one of the workspace's own applications from the catalog",
		Description:   "Servers keep what is installed; it can no longer be updated or removed from the panel.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *installPath) (*struct{}, error) {
		if err := h.q.DeleteSoftwareRecipe(ctx, uuid.MustParse(in.ID)); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})

	// ---- What is installed ----

	type installsOutput struct {
		Body struct {
			Items []SoftwareInstall `json:"items"`
			Hosts []SoftwareHost    `json:"hosts"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "list-software-installs",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/software/installs",
		Summary:     "Applications on a workspace's servers, and each server's system updates",
		Description: "Only servers the caller can see. Refreshed by a scan every SOFTWARE_CHECK_INTERVAL and after every run.",
		Tags:        tags,
	}, func(ctx context.Context, in *WorkspacePath) (*installsOutput, error) {
		ws := uuid.MustParse(in.ID)
		acc := principalOf(ctx).Access
		rows, err := h.q.ListSoftwareInstalls(ctx, ws)
		if err != nil {
			return nil, internalError(err)
		}
		hosts, err := h.q.ListSoftwareHosts(ctx, ws)
		if err != nil {
			return nil, internalError(err)
		}
		out := &installsOutput{}
		out.Body.Items = []SoftwareInstall{}
		for _, r := range rows {
			if acc.ServerLevel(ws, r.ServerID) >= auth.Viewer {
				out.Body.Items = append(out.Body.Items, h.toInstall(sqlc.GetSoftwareInstallRow(r)))
			}
		}
		out.Body.Hosts = []SoftwareHost{}
		for _, r := range hosts {
			if acc.ServerLevel(ws, r.ServerID) >= auth.Viewer {
				out.Body.Hosts = append(out.Body.Hosts, toSoftwareHost(r))
			}
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-server-software",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/software",
		Summary:     "Applications on a server and its system updates",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct {
		Body struct {
			Items []SoftwareInstall `json:"items"`
			Host  *SoftwareHost     `json:"host" doc:"Null until its first scan"`
		}
	}, error) {
		sid := uuid.MustParse(in.ID)
		rows, err := h.q.ListServerSoftwareInstalls(ctx, sid)
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []SoftwareInstall `json:"items"`
				Host  *SoftwareHost     `json:"host" doc:"Null until its first scan"`
			}
		}{}
		out.Body.Items = make([]SoftwareInstall, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = h.toInstall(sqlc.GetSoftwareInstallRow(r))
		}
		host, err := h.q.GetSoftwareHost(ctx, sid)
		switch {
		case isNotFound(err):
		case err != nil:
			return nil, internalError(err)
		default:
			s, err := h.servers.get(ctx, in.ID)
			if err != nil {
				return nil, err
			}
			v := toSoftwareHost(sqlc.ListSoftwareHostsRow{
				ServerID: host.ServerID, Pm: host.Pm, Docker: host.Docker, Compose: host.Compose,
				Upgradable: host.Upgradable, Security: host.Security, RebootRequired: host.RebootRequired,
				Packages: host.Packages, Error: host.Error, CheckedAt: host.CheckedAt,
				ServerName: s.Name, ServerStatus: s.Status,
			})
			out.Body.Host = &v
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-software-install",
		Method:      http.MethodGet,
		Path:        "/software-installs/{id}",
		Summary:     "One application on one server",
		Tags:        tags,
	}, func(ctx context.Context, in *installPath) (*installOutput, error) {
		r, err := h.loadInstall(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &installOutput{h.toInstall(r)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "reveal-software-secrets",
		Method:      http.MethodPost,
		Path:        "/software-installs/{id}/reveal",
		Summary:     "Show the secret values an application was installed with",
		Description: "Passwords Morcheh made or was given at install time. Owner of the server.",
		Tags:        tags,
	}, func(ctx context.Context, in *installPath) (*struct {
		Body struct {
			Values map[string]string `json:"values"`
		}
	}, error) {
		r, err := h.loadInstall(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		out := &struct {
			Body struct {
				Values map[string]string `json:"values"`
			}
		}{}
		out.Body.Values = h.openSecrets(r.Secrets)
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "forget-software-install",
		Method:        http.MethodDelete,
		Path:          "/software-installs/{id}",
		Summary:       "Forget an application record",
		Description:   "Nothing changes on the server. A scan finds it again if it is still there.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *installPath) (*struct{}, error) {
		r, err := h.loadInstall(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if r.Status == "installing" || r.Status == "updating" || r.Status == "removing" {
			return nil, huma.Error409Conflict("It is being changed right now. Wait for the run to end.")
		}
		if err := h.q.DeleteSoftwareInstall(ctx, r.ID); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})

	// ---- Docker apps ----

	composeOf := func(r sqlc.GetSoftwareInstallRow) error {
		if r.Kind != software.KindDocker {
			return huma.Error422UnprocessableEntity("Only Docker apps can do this. Use the server's Services tab for the rest.")
		}
		if r.Project == "" {
			return huma.Error422UnprocessableEntity("Morcheh doesn't know this app's compose project.")
		}
		return nil
	}

	huma.Register(api, huma.Operation{
		OperationID: "software-install-action",
		Method:      http.MethodPost,
		Path:        "/software-installs/{id}/action",
		Summary:     "Start, stop or restart a Docker app",
		Description: "Operator. Answers the record after a fresh look at the app.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		installPath
		Body struct {
			Action string `json:"action" enum:"start,stop,restart"`
		}
	}) (*installOutput, error) {
		r, err := h.loadInstall(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if err := composeOf(r); err != nil {
			return nil, err
		}
		args := in.Body.Action
		if args == "start" && r.Origin == "morcheh" {
			// up, not start: containers removed by hand come back too.
			args = "up -d --remove-orphans"
		}
		script := software.ComposeAt(r.Dir, r.Project, args)
		err = h.servers.withConn(ctx, r.ServerID.String(), func(c *sshConn) error {
			sh, err := h.servers.rootShell(ctx, r.ServerID.String(), c)
			if err != nil {
				return err
			}
			_, err = runInput(ctx, c, wrapStdin(sh), stdinFor(sh, script), 3*time.Minute)
			return err
		})
		if err != nil {
			return nil, toProblem(err)
		}
		h.scanApp(ctx, r.ServerID, r.WorkspaceID, r.RecipeID, r.Origin)
		if r, err = h.loadInstall(ctx, in.ID); err != nil {
			return nil, err
		}
		return &installOutput{h.toInstall(r)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "software-install-logs",
		Method:      http.MethodGet,
		Path:        "/software-installs/{id}/logs",
		Summary:     "The last lines a Docker app's containers wrote",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		installPath
		Lines   int    `query:"lines" minimum:"10" maximum:"5000" default:"300"`
		Service string `query:"service" doc:"One compose service; empty = all"`
	}) (*struct {
		Body struct {
			Text string `json:"text"`
		}
	}, error) {
		r, err := h.loadInstall(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if err := composeOf(r); err != nil {
			return nil, err
		}
		args := fmt.Sprintf("logs --no-color --timestamps --tail %d", in.Lines)
		if in.Service != "" {
			if !composeServiceRe.MatchString(in.Service) {
				return nil, fieldError("query.service", "Not a service name.", in.Service)
			}
			args += " " + in.Service
		}
		script := software.ComposeAt(r.Dir, r.Project, args+" 2>&1")
		var text string
		err = h.servers.withConn(ctx, r.ServerID.String(), func(c *sshConn) error {
			sh, err := h.servers.rootShell(ctx, r.ServerID.String(), c)
			if err != nil {
				return err
			}
			text, err = runInput(ctx, c, wrapStdin(sh), stdinFor(sh, script), time.Minute)
			return err
		})
		if err != nil {
			return nil, toProblem(err)
		}
		out := &struct {
			Body struct {
				Text string `json:"text"`
			}
		}{}
		out.Body.Text = cleanOutput(text)
		return out, nil
	})

	type composeOutput struct {
		Body struct {
			Content  string `json:"content"`
			Revision string `json:"revision" doc:"Send it back when saving: a change made since is refused (409)"`
		}
	}
	morchehApp := func(r sqlc.GetSoftwareInstallRow) error {
		if err := composeOf(r); err != nil {
			return err
		}
		if r.Origin != "morcheh" {
			return huma.Error422UnprocessableEntity("Only apps installed from Morcheh can be edited here.")
		}
		return nil
	}
	readCompose := func(ctx context.Context, r sqlc.GetSoftwareInstallRow) (string, error) {
		var text string
		err := h.servers.withConn(ctx, r.ServerID.String(), func(c *sshConn) error {
			sh, err := h.servers.rootShell(ctx, r.ServerID.String(), c)
			if err != nil {
				return err
			}
			text, err = runInput(ctx, c, wrapStdin(sh), stdinFor(sh, software.ReadComposeScript(r.RecipeID)), time.Minute)
			return err
		})
		return text, toProblem(err)
	}
	revisionOf := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])
	}

	huma.Register(api, huma.Operation{
		OperationID: "get-software-compose",
		Method:      http.MethodGet,
		Path:        "/software-installs/{id}/compose",
		Summary:     "A Docker app's compose file",
		Tags:        tags,
	}, func(ctx context.Context, in *installPath) (*composeOutput, error) {
		r, err := h.loadInstall(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if err := morchehApp(r); err != nil {
			return nil, err
		}
		text, err := readCompose(ctx, r)
		if err != nil {
			return nil, err
		}
		out := &composeOutput{}
		out.Body.Content, out.Body.Revision = text, revisionOf(text)
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "save-software-compose",
		Method:      http.MethodPut,
		Path:        "/software-installs/{id}/compose",
		Summary:     "Change a Docker app's compose file and apply it",
		Description: "Checked with docker compose config first (422 with its words when wrong); the old file stays as compose.yml.previous.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		installPath
		Body struct {
			Content  string `json:"content" minLength:"1" maxLength:"262144"`
			Revision string `json:"revision"`
		}
	}) (*composeOutput, error) {
		r, err := h.loadInstall(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if err := morchehApp(r); err != nil {
			return nil, err
		}
		current, err := readCompose(ctx, r)
		if err != nil {
			return nil, err
		}
		if revisionOf(current) != in.Body.Revision {
			return nil, huma.Error409Conflict("The compose file changed on the server since you opened it.")
		}
		out := &liveOutput{limit: 64 << 10}
		var res *scriptResult
		err = h.servers.withConn(ctx, r.ServerID.String(), func(c *sshConn) error {
			sh, err := h.servers.rootShell(ctx, r.ServerID.String(), c)
			if err != nil {
				return err
			}
			if sh.priv == privUser {
				return errors.New(noRootMessage)
			}
			res, _, err = execScript(ctx, sh, software.SaveComposeScript(r.RecipeID, in.Body.Content), 5*time.Minute, out)
			return err
		})
		if err != nil {
			return nil, toProblem(err)
		}
		raw, _, _ := out.snapshot()
		text := strings.TrimSpace(cleanOutput(raw))
		code := int32(-1)
		if res.code != nil {
			code = *res.code
		}
		switch {
		case res.stopped:
			return nil, huma.Error504GatewayTimeout("The server took too long")
		case code == 3:
			return nil, fieldError("body.content", "Docker Compose refused it: "+lastLines(text, 6), nil)
		case code != 0:
			return nil, huma.Error422UnprocessableEntity("It was saved, but the app didn't start: " + lastLines(text, 6))
		}
		h.scanApp(ctx, r.ServerID, r.WorkspaceID, r.RecipeID, r.Origin)
		answer := &composeOutput{}
		answer.Body.Content, answer.Body.Revision = in.Body.Content, revisionOf(in.Body.Content)
		return answer, nil
	})

	// ---- Before an install ----

	huma.Register(api, huma.Operation{
		OperationID: "software-preflight",
		Method:      http.MethodPost,
		Path:        "/software/preflight",
		Summary:     "Check servers before installing an application on them",
		Description: "Package manager, root, Docker, free space, busy ports and leftovers from an earlier install. Engineer on every server.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		Body struct {
			RecipeID  string            `json:"recipe_id"`
			ServerIDs []string          `json:"server_ids" minItems:"1" maxItems:"500"`
			Params    map[string]string `json:"params,omitempty"`
		}
	}) (*struct {
		Body struct {
			Items []SoftwarePreflight `json:"items"`
		}
	}, error) {
		servers, ws, err := h.pickServers(ctx, in.Body.ServerIDs, auth.Engineer)
		if err != nil {
			return nil, err
		}
		list, err := h.catalog(ctx, ws)
		if err != nil {
			return nil, internalError(err)
		}
		r, ok := software.Find(list, in.Body.RecipeID)
		if !ok {
			return nil, fieldError("body.recipe_id", "There is no such application in this workspace's catalog.", in.Body.RecipeID)
		}
		if r.Retired {
			return nil, fieldError("body.recipe_id", retiredText, in.Body.RecipeID)
		}
		out := &struct {
			Body struct {
				Items []SoftwarePreflight `json:"items"`
			}
		}{}
		out.Body.Items = h.preflight(ctx, r, list, servers, in.Body.Params)
		return out, nil
	})

	// ---- Runs ----

	type runOutput struct{ Body SoftwareRunDetail }
	type startOutput struct {
		Body struct {
			Run SoftwareRunDetail `json:"run"`
			Job Job               `json:"job"`
		}
	}

	huma.Register(api, huma.Operation{
		OperationID:   "start-software-run",
		Method:        http.MethodPost,
		Path:          "/software-runs",
		Summary:       "Install, update, roll back or remove applications on servers",
		Description:   "Queues a background job. Install, update, rollback and system upgrades need Engineer on every server, uninstall needs Owner. All servers must be in one workspace.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct{ Body startSoftwareRunBody }) (*startOutput, error) {
		plan, err := h.plan(ctx, in.Body, uuid.Nil)
		if err != nil {
			return nil, err
		}
		if len(plan.steps) == 0 {
			return nil, huma.Error422UnprocessableEntity(plan.nothing)
		}
		run, err := h.create(ctx, plan)
		if err != nil {
			return nil, err
		}
		j, err := h.submitRun(ctx, run, plan)
		if err != nil {
			return nil, err
		}
		targets, err := h.q.ListSoftwareRunTargets(ctx, run.ID)
		if err != nil {
			return nil, internalError(err)
		}
		out := &startOutput{}
		out.Body.Run, out.Body.Job = toSoftwareRunDetail(run, targets), j.Body
		return out, nil
	})

	type runList struct {
		Body struct {
			Items []SoftwareRun `json:"items"`
			Total int64         `json:"total"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "list-software-runs",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/software-runs",
		Summary:     "A workspace's application runs, newest first",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		ServerID string `query:"server_id" format:"uuid"`
		RecipeID string `query:"recipe_id"`
		State    string `query:"state" enum:"queued,running,succeeded,failed,canceled,interrupted"`
		Q        string `query:"q" doc:"In the run's name or who started it"`
		Limit    int32  `query:"limit" minimum:"1" maximum:"200" default:"50"`
		Offset   int32  `query:"offset" minimum:"0"`
	}) (*runList, error) {
		params := sqlc.ListSoftwareRunsParams{WorkspaceID: uuid.MustParse(in.ID), Lim: in.Limit, Off: in.Offset}
		count := sqlc.CountSoftwareRunsParams{WorkspaceID: params.WorkspaceID}
		if in.ServerID != "" {
			id := uuid.MustParse(in.ServerID)
			params.ServerID, count.ServerID = &id, &id
		}
		if in.RecipeID != "" {
			params.RecipeID, count.RecipeID = &in.RecipeID, &in.RecipeID
		}
		if in.State != "" {
			params.State, count.State = &in.State, &in.State
		}
		if q := strings.TrimSpace(in.Q); q != "" {
			params.Q, count.Q = &q, &q
		}
		rows, err := h.q.ListSoftwareRuns(ctx, params)
		if err != nil {
			return nil, internalError(err)
		}
		changed := false
		for _, r := range rows {
			if h.syncRun(ctx, r.ID, r.State, r.JobID, r.CreatedAt) {
				changed = true
			}
		}
		if changed {
			if rows, err = h.q.ListSoftwareRuns(ctx, params); err != nil {
				return nil, internalError(err)
			}
		}
		total, err := h.q.CountSoftwareRuns(ctx, count)
		if err != nil {
			return nil, internalError(err)
		}
		out := &runList{}
		out.Body.Total = total
		out.Body.Items = make([]SoftwareRun, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = toSoftwareRunRow(r)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-software-run",
		Method:      http.MethodGet,
		Path:        "/software-runs/{id}",
		Summary:     "A run with its output on each server",
		Description: "Needs Operator on every server it touched. While it runs, the output is saved about every second: poll this.",
		Tags:        tags,
	}, func(ctx context.Context, in *installPath) (*runOutput, error) {
		r, targets, err := h.loadRun(ctx, in.ID, auth.Operator)
		if err != nil {
			return nil, err
		}
		return &runOutput{toSoftwareRunDetail(r, targets)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "cancel-software-run",
		Method:      http.MethodPost,
		Path:        "/software-runs/{id}/cancel",
		Summary:     "Stop a run",
		Description: "Steps not started are skipped; a running one gets SIGTERM, which can leave a half-done install. Engineer on every server it touched.",
		Tags:        tags,
	}, func(ctx context.Context, in *installPath) (*runOutput, error) {
		r, _, err := h.loadRun(ctx, in.ID, auth.Engineer)
		if err != nil {
			return nil, err
		}
		if !jobs.Active(r.State) || r.JobID == nil {
			return nil, huma.Error409Conflict("The run has already finished.")
		}
		if _, err := h.runner.Cancel(ctx, *r.JobID); err != nil {
			return nil, jobProblem(err)
		}
		r, targets, err := h.loadRun(ctx, in.ID, auth.Engineer)
		if err != nil {
			return nil, err
		}
		return &runOutput{toSoftwareRunDetail(r, targets)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-software-run",
		Method:        http.MethodDelete,
		Path:          "/software-runs/{id}",
		Summary:       "Delete a finished run",
		Description:   "Needs Engineer on every server it touched.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *installPath) (*struct{}, error) {
		r, _, err := h.loadRun(ctx, in.ID, auth.Engineer)
		if err != nil {
			return nil, err
		}
		n, err := h.q.DeleteSoftwareRun(ctx, r.ID)
		if err != nil {
			return nil, internalError(err)
		}
		if n == 0 {
			return nil, huma.Error409Conflict("Stop the run before deleting it.")
		}
		return nil, nil
	})

	// ---- Scans ----

	scan := func(ctx context.Context, ids []uuid.UUID, name string, target *JobPlace) (*JobOutput, error) {
		title := "Look for applications on " + name
		spec := jobs.Spec{
			Kind: softwareScanKind, Title: title, Refs: ids,
			Params: softwareScanParams{ServerIDs: ids}, Quick: true,
		}
		if target != nil {
			spec.Target = *target
		}
		return submit(ctx, h.runner, spec)
	}

	huma.Register(api, huma.Operation{
		OperationID:   "scan-server-software",
		Method:        http.MethodPost,
		Path:          "/servers/{id}/software/scan",
		Summary:       "Look again at what is installed on a server and what has updates",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *ServerIDPath) (*JobOutput, error) {
		s, err := h.servers.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return scan(ctx, []uuid.UUID{s.ID}, s.Name, &JobPlace{ServerID: s.ID.String(), Name: s.Name})
	})

	huma.Register(api, huma.Operation{
		OperationID:   "scan-workspace-software",
		Method:        http.MethodPost,
		Path:          "/workspaces/{id}/software/scan",
		Summary:       "Look again at every reachable server of a workspace",
		Description:   "Only servers the caller has Operator on.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *WorkspacePath) (*JobOutput, error) {
		ws := uuid.MustParse(in.ID)
		all, err := h.q.WorkspaceServersToScan(ctx, ws)
		if err != nil {
			return nil, internalError(err)
		}
		acc := principalOf(ctx).Access
		ids := slices.DeleteFunc(all, func(id uuid.UUID) bool { return acc.ServerLevel(ws, id) < auth.Operator })
		if len(ids) == 0 {
			return nil, huma.Error422UnprocessableEntity("No server you can scan is online.")
		}
		return scan(ctx, ids, countServers(len(ids)), nil)
	})
}

// ---- Shared bits ----

// sshConn is the pool's connection, named here for the handlers' closures.
type sshConn = sshpool.Conn

const noRootMessage = "Its login user can't become root (no sudo, and the stored password didn't work). Give that user sudo."

// wrapStdin is the command that runs a script fed on stdin, as root when the
// shell can be (and as the login user otherwise). The script follows sudo's
// password on stdin; see stdinFor.
func wrapStdin(sh *rootShell) string {
	switch sh.priv {
	case privSudo:
		return "sudo -n sh -s"
	case privSudoPassword:
		return "sudo -S -p '' sh -s"
	}
	return "sh -s"
}

// pickServers checks a list of server ids as the caller with need on each,
// all in one workspace, sorted by name.
func (h *softwareHandler) pickServers(ctx context.Context, raw []string, need auth.Level) ([]sqlc.Server, uuid.UUID, error) {
	ids := make([]uuid.UUID, 0, len(raw))
	for _, s := range raw {
		id, err := uuid.Parse(s)
		if err != nil {
			return nil, uuid.Nil, fieldError("body.server_ids", "Not a server id.", s)
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, uuid.Nil, fieldError("body.server_ids", "Choose at least one server.", nil)
	}
	where, err := h.authz.requireServers(ctx, ids, need)
	if err != nil {
		return nil, uuid.Nil, err
	}
	ws := uuid.Nil
	servers := make([]sqlc.Server, 0, len(ids))
	for _, id := range ids {
		w, ok := where[id]
		if !ok {
			return nil, uuid.Nil, fieldError("body.server_ids", "A chosen server doesn't exist.", id.String())
		}
		if ws == uuid.Nil {
			ws = w
		} else if w != ws {
			return nil, uuid.Nil, fieldError("body.server_ids", "The servers must all be in one workspace.", id.String())
		}
		s, err := h.servers.get(ctx, id.String())
		if err != nil {
			return nil, uuid.Nil, err
		}
		servers = append(servers, s)
	}
	sort.SliceStable(servers, func(i, j int) bool { return strings.ToLower(servers[i].Name) < strings.ToLower(servers[j].Name) })
	return servers, ws, nil
}

// preflight checks each server for installing r, five at a time.
func (h *softwareHandler) preflight(ctx context.Context, r software.Recipe, list []software.Recipe, servers []sqlc.Server, given map[string]string) []SoftwarePreflight {
	values, _, _ := r.Values(given)
	ports := r.Ports(values)
	out := make([]SoftwarePreflight, len(servers))
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = h.preflightOne(ctx, r, list, s, ports)
		}()
	}
	wg.Wait()
	return out
}

func (h *softwareHandler) preflightOne(ctx context.Context, r software.Recipe, list []software.Recipe, s sqlc.Server, ports []int) SoftwarePreflight {
	p := SoftwarePreflight{ServerID: s.ID.String(), ServerName: s.Name, Problems: []string{}, Warnings: []string{}, First: []string{}}
	installs, _ := h.q.ListServerSoftwareInstalls(ctx, s.ID)
	has := func(id string) (sqlc.ListServerSoftwareInstallsRow, bool) {
		i := slices.IndexFunc(installs, func(x sqlc.ListServerSoftwareInstallsRow) bool {
			return x.RecipeID == id && x.Status != "missing"
		})
		if i < 0 {
			return sqlc.ListServerSoftwareInstallsRow{}, false
		}
		return installs[i], true
	}
	if row, ok := has(r.ID); ok {
		p.Installed, p.Version = true, row.Version
		switch {
		case row.Status == "installing" || row.Status == "updating" || row.Status == "removing":
			p.Problems = append(p.Problems, "It is being changed right now by another run.")
		case row.Origin == "found" && r.Kind == software.KindDocker:
			p.Warnings = append(p.Warnings, "It already runs here in containers Morcheh didn't start. Installing it again starts a second copy.")
		case row.Status == "installed":
			p.Warnings = append(p.Warnings, "It's already installed. Installing again keeps its data and applies the values you give now.")
		}
	}
	if s.Status == "offline" || s.Status == "unreachable" {
		p.Problems = append(p.Problems, "The server isn't reachable.")
		return p
	}

	var kv map[string]string
	var busy []string
	err := h.servers.withConn(ctx, s.ID.String(), func(c *sshConn) error {
		sh, err := h.servers.rootShell(ctx, s.ID.String(), c)
		if err != nil {
			return err
		}
		if sh.priv == privUser {
			p.Problems = append(p.Problems, noRootMessage)
		}
		text, err := runInput(ctx, c, wrapStdin(sh), stdinFor(sh, software.PreflightScript(r, ports)), time.Minute)
		if err != nil {
			return err
		}
		kv = map[string]string{}
		for line := range strings.SplitSeq(text, "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok {
				continue
			}
			if k == "busy" {
				busy = append(busy, v)
				continue
			}
			kv[k] = v
		}
		return nil
	})
	if err != nil {
		p.Problems = append(p.Problems, problemText(toProblem(err)))
		return p
	}
	p.PM, p.Docker, p.Arch = kv["pm"], kv["docker"], kv["arch"]
	var free int64
	_, _ = fmt.Sscan(kv["free_kb"], &free)
	p.FreeMB = free / 1024

	if !r.Supports(p.PM) {
		pm := cmpOr(p.PM, "an unknown one")
		p.Problems = append(p.Problems, fmt.Sprintf("%s works only with %s (this server uses %s).", r.Name, strings.Join(r.OS, ", "), pm))
	}
	// What it requires, installed first when missing.
	for _, need := range r.Requires {
		missing := false
		if need == "docker" {
			missing = p.Docker == "" || kv["compose"] == ""
		} else if _, ok := has(need); !ok {
			missing = true
		}
		if !missing {
			continue
		}
		dep, ok := software.Find(list, need)
		if !ok {
			p.Problems = append(p.Problems, fmt.Sprintf("It needs %s, which isn't in the catalog.", need))
			continue
		}
		if !dep.Supports(p.PM) {
			p.Problems = append(p.Problems, fmt.Sprintf("It needs %s, which can't be installed with %s.", dep.Name, cmpOr(p.PM, "this package manager")))
			continue
		}
		p.First = append(p.First, dep.Name)
	}
	if len(p.First) > 0 {
		p.Warnings = append(p.Warnings, strings.Join(p.First, " and ")+" will be installed first.")
	}
	if !(kv["here"] == "1") {
		for _, port := range busy {
			p.Problems = append(p.Problems, "Port "+port+" is already in use on the server. Choose another one.")
		}
	}
	if kv["old_data"] == "1" && kv["here"] != "1" {
		p.Warnings = append(p.Warnings, "Data from an earlier install is still on the server and will be used again (tick Start fresh to delete it).")
	}
	if p.FreeMB > 0 && p.FreeMB < 1024 {
		p.Warnings = append(p.Warnings, fmt.Sprintf("Only %d MB free on the disk.", p.FreeMB))
	}
	p.OK = len(p.Problems) == 0
	return p
}

// stdinFor is what to feed a command from wrapStdin: sudo's password first
// when it asks for one, then the script.
func stdinFor(sh *rootShell, script string) string {
	if sh.priv == privSudoPassword {
		return sh.password + "\n" + script
	}
	return script
}
