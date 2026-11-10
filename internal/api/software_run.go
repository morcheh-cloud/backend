package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/software"
)

// ---- Planning ----

// systemRecipe stands for "the server's own packages" in runs and records.
var systemRecipe = software.Recipe{ID: software.System, Name: "System packages", Kind: software.KindPackage}

type softwareStep struct {
	server sqlc.Server
	recipe software.Recipe
	before string
	// install: the values for this server (generated ones included).
	values map[string]string
}

type softwarePlan struct {
	ws      uuid.UUID
	action  string
	name    string
	options SoftwareRunOptions
	params  map[string]string
	secrets map[string]string
	steps   []softwareStep
	// nothing is why there are no steps.
	nothing string
}

func softwareActionVerb(action string) string {
	switch action {
	case "install":
		return "Install"
	case "uninstall":
		return "Remove"
	case "rollback":
		return "Roll back"
	case "upgrade-system":
		return "Upgrade the system packages"
	}
	return "Update"
}

// plan checks a start request as the caller and lists what runs where. ws is
// the workspace it must be in, or uuid.Nil for any one.
func (h *softwareHandler) plan(ctx context.Context, b startSoftwareRunBody, ws uuid.UUID) (softwarePlan, error) {
	p := softwarePlan{action: b.Action, options: b.Options, params: map[string]string{}, secrets: map[string]string{}}
	need := auth.Engineer
	if b.Action == "uninstall" {
		need = auth.Owner
	}
	servers, where, err := h.pickServers(ctx, b.ServerIDs, need)
	if err != nil {
		return p, err
	}
	if ws != uuid.Nil && where != ws {
		return p, fieldError("body.server_ids", "The servers must be in this cron job's workspace.", nil)
	}
	p.ws = where
	list, err := h.catalog(ctx, p.ws)
	if err != nil {
		return p, internalError(err)
	}
	recipes := slices.Compact(slices.Sorted(slices.Values(b.Recipes)))

	type serverState struct {
		host     *sqlc.SoftwareHost
		installs []sqlc.ListServerSoftwareInstallsRow
	}
	stateOf := func(s sqlc.Server) (serverState, error) {
		var st serverState
		rows, err := h.q.ListServerSoftwareInstalls(ctx, s.ID)
		if err != nil {
			return st, internalError(err)
		}
		st.installs = rows
		host, err := h.q.GetSoftwareHost(ctx, s.ID)
		if err == nil {
			st.host = &host
		} else if !isNotFound(err) {
			return st, internalError(err)
		}
		return st, nil
	}
	rowOf := func(st serverState, id string) (sqlc.ListServerSoftwareInstallsRow, bool) {
		i := slices.IndexFunc(st.installs, func(r sqlc.ListServerSoftwareInstallsRow) bool { return r.RecipeID == id })
		if i < 0 {
			return sqlc.ListServerSoftwareInstallsRow{}, false
		}
		return st.installs[i], true
	}
	// recipeFor is the recipe of an install record; a Docker app found on
	// the server without a recipe still gets one, to update it.
	recipeFor := func(row sqlc.ListServerSoftwareInstallsRow) (software.Recipe, bool) {
		if r, ok := software.Find(list, row.RecipeID); ok {
			return r, true
		}
		if row.Kind == software.KindDocker {
			return software.Recipe{ID: row.RecipeID, Name: row.Name, Kind: software.KindDocker}, true
		}
		return software.Recipe{}, false
	}
	add := func(s sqlc.Server, r software.Recipe, before string, values map[string]string) {
		p.steps = append(p.steps, softwareStep{server: s, recipe: r, before: before, values: values})
	}

	var main software.Recipe
	switch b.Action {
	case "install":
		if len(recipes) != 1 {
			return p, fieldError("body.recipes", "Choose one application to install.", nil)
		}
		r, ok := software.Find(list, recipes[0])
		if !ok || r.ID == software.System {
			return p, fieldError("body.recipes", "There is no such application in this workspace's catalog.", recipes[0])
		}
		if r.Retired {
			return p, fieldError("body.recipes", retiredText, recipes[0])
		}
		main = r
		if err := r.CheckGiven(b.Params); err != nil {
			return p, recipeError(err)
		}
		given, _, _ := r.Values(b.Params)
		for name, v := range given {
			if _, typed := b.Params[name]; !typed {
				continue
			}
			p.params[name] = v
		}
		p.params, p.secrets = splitSecret(r, p.params)
		for _, s := range servers {
			st, err := stateOf(s)
			if err != nil {
				return p, err
			}
			for _, needID := range r.Requires {
				missing := false
				if needID == "docker" {
					// Docker apps need the engine and its compose plugin; the
					// docker recipe adds only the plugin when the engine is there.
					if st.host != nil {
						missing = st.host.Docker == "" || st.host.Compose == ""
					} else {
						row, ok := rowOf(st, "docker")
						missing = !ok || row.Status != "installed"
					}
				} else if row, ok := rowOf(st, needID); !ok || row.Status != "installed" {
					missing = true
				}
				if !missing {
					continue
				}
				dep, ok := software.Find(list, needID)
				if !ok {
					return p, huma.Error422UnprocessableEntity(fmt.Sprintf("%s needs %s, which isn't in the catalog.", r.Name, needID))
				}
				values, _, err := dep.Values(nil)
				if err != nil {
					return p, huma.Error422UnprocessableEntity(fmt.Sprintf("%s needs %s, which needs settings of its own: install it first.", r.Name, dep.Name))
				}
				add(s, dep, "", values)
			}
			values, _, err := r.Values(b.Params)
			if err != nil {
				return p, recipeError(err)
			}
			before := ""
			if row, ok := rowOf(st, r.ID); ok {
				before = row.Version
			}
			add(s, r, before, values)
		}
		p.nothing = "Nothing to install."

	case "upgrade-system":
		main = systemRecipe
		for _, s := range servers {
			add(s, systemRecipe, "", nil)
		}

	case "update", "uninstall", "rollback":
		if b.Action != "update" && len(recipes) == 0 {
			return p, fieldError("body.recipes", "Choose the applications.", nil)
		}
		skipped := []string{}
		for _, s := range servers {
			st, err := stateOf(s)
			if err != nil {
				return p, err
			}
			// "*" (or nothing) = every application with an update.
			ids := slices.DeleteFunc(slices.Clone(recipes), func(id string) bool { return id == "*" })
			if len(recipes) == 0 || slices.Contains(recipes, "*") {
				for _, row := range st.installs {
					if row.UpdateAvailable && row.Status == "installed" {
						if !slices.Contains(ids, row.RecipeID) {
							ids = append(ids, row.RecipeID)
						}
					}
				}
			}
			for _, id := range ids {
				if id == software.System {
					if b.Action != "update" {
						return p, fieldError("body.recipes", "The system packages can only be updated.", id)
					}
					add(s, systemRecipe, "", nil)
					continue
				}
				row, ok := rowOf(st, id)
				if !ok || row.Status == "missing" {
					continue
				}
				r, ok := recipeFor(row)
				if !ok {
					skipped = append(skipped, row.Name)
					continue
				}
				docker, found := row.Kind == software.KindDocker, row.Origin == "found"
				switch b.Action {
				case "update":
					if docker && found && (row.Dir == "" || row.Project == "") {
						skipped = append(skipped, row.Name+" on "+s.Name)
						continue
					}
				case "uninstall":
					if docker && found {
						return p, fieldError("body.recipes", fmt.Sprintf("Morcheh didn't install %s on %s, so it doesn't remove it. Stop or remove it on the server.", row.Name, s.Name), id)
					}
				case "rollback":
					if !docker || found || !row.CanRollback {
						skipped = append(skipped, row.Name+" on "+s.Name)
						continue
					}
				}
				add(s, r, row.Version, nil)
			}
		}
		switch b.Action {
		case "update":
			p.nothing = "Nothing to update: the chosen applications are up to date or not on these servers."
			if len(skipped) > 0 {
				p.nothing = "Nothing Morcheh can update: " + strings.Join(skipped, ", ") + " (Morcheh doesn't know their compose folder or recipe)."
			}
		case "uninstall":
			p.nothing = "None of the chosen applications is on these servers."
		case "rollback":
			p.nothing = "Nothing to roll back: only Docker apps installed from Morcheh go back, after an update."
		}
		if len(p.steps) > 0 {
			main = p.steps[0].recipe
		}
	default:
		return p, fieldError("body.action", "Unknown action.", b.Action)
	}

	// Busy: another run is changing the same thing on the same server.
	ids := make([]uuid.UUID, len(servers))
	for i, s := range servers {
		ids[i] = s.ID
	}
	active, err := h.q.ActiveSoftwareRunsOn(ctx, ids)
	if err != nil {
		return p, internalError(err)
	}
	for _, st := range p.steps {
		if slices.ContainsFunc(active, func(a sqlc.ActiveSoftwareRunsOnRow) bool {
			return a.ServerID == st.server.ID && a.RecipeID == st.recipe.ID
		}) {
			return p, huma.Error409Conflict(fmt.Sprintf("%s is already being changed on %s by another run.", st.recipe.Name, st.server.Name))
		}
	}

	// The name: "Install Grafana on web-1", "Update 3 applications on 2 servers".
	names := []string{}
	onServers := []string{}
	for _, st := range p.steps {
		if !slices.Contains(names, st.recipe.Name) {
			names = append(names, st.recipe.Name)
		}
		if !slices.Contains(onServers, st.server.Name) {
			onServers = append(onServers, st.server.Name)
		}
	}
	what := main.Name
	switch {
	case b.Action == "upgrade-system":
		what = ""
	case b.Action == "install":
	case len(names) == 1:
		what = names[0]
	case len(names) > 1:
		what = fmt.Sprintf("%d applications", len(names))
	}
	where2 := ""
	switch len(onServers) {
	case 0:
	case 1:
		where2 = " on " + onServers[0]
	default:
		where2 = " on " + countServers(len(onServers))
	}
	p.name = strings.TrimSpace(softwareActionVerb(b.Action) + " " + what + where2)
	return p, nil
}

func recipeError(err error) error {
	var fe *software.FieldError
	if errors.As(err, &fe) {
		return fieldError("body."+fe.Field, fe.Msg, nil)
	}
	return huma.Error422UnprocessableEntity(err.Error())
}

// create stores a planned run with its steps, and marks installs as
// installing.
func (h *softwareHandler) create(ctx context.Context, plan softwarePlan) (sqlc.SoftwareRun, error) {
	p := principalOf(ctx)
	opts, _ := json.Marshal(plan.options)
	params, _ := json.Marshal(plan.params)
	run, err := h.q.CreateSoftwareRun(ctx, sqlc.CreateSoftwareRunParams{
		WorkspaceID: plan.ws, Action: plan.action, Name: plan.name, Options: opts, Params: params,
		Secrets: h.sealSecrets(plan.secrets), CreatedBy: p.ID(), CreatedByName: cmpOr(p.User.FullName, p.User.Username),
	})
	if err != nil {
		return run, internalError(err)
	}
	bg := context.WithoutCancel(ctx)
	fail := func(err error) (sqlc.SoftwareRun, error) {
		_ = h.q.EndSoftwareRun(bg, sqlc.EndSoftwareRunParams{ID: run.ID, State: jobs.Failed, Error: "It couldn't be saved."})
		h.failInstalls(bg, plan, "It couldn't be saved.")
		return run, internalError(err)
	}
	for i, st := range plan.steps {
		id := st.server.ID
		if err := h.q.CreateSoftwareRunTarget(ctx, sqlc.CreateSoftwareRunTargetParams{
			RunID: run.ID, Position: int32(i), ServerID: &id, ServerName: st.server.Name,
			RecipeID: st.recipe.ID, RecipeName: st.recipe.Name, VersionBefore: st.before,
		}); err != nil {
			return fail(err)
		}
		if plan.action != "install" {
			continue
		}
		plain, secret := splitSecret(st.recipe, st.values)
		raw, _ := json.Marshal(plain)
		dir, project := "", ""
		if st.recipe.Kind == software.KindDocker {
			dir, project = software.Dir(st.recipe.ID), software.Project(st.recipe.ID)
		}
		if _, err := h.q.BeginSoftwareInstall(ctx, sqlc.BeginSoftwareInstallParams{
			WorkspaceID: plan.ws, ServerID: id, RecipeID: st.recipe.ID, Name: st.recipe.Name, Kind: st.recipe.Kind,
			Params: raw, Secrets: h.sealSecrets(secret), Dir: dir, Project: project,
		}); err != nil {
			return fail(err)
		}
	}
	return run, nil
}

// failInstalls marks the records an install run began as failed.
func (h *softwareHandler) failInstalls(ctx context.Context, plan softwarePlan, msg string) {
	if plan.action != "install" {
		return
	}
	for _, st := range plan.steps {
		row, err := h.q.GetSoftwareInstallByRecipe(ctx, sqlc.GetSoftwareInstallByRecipeParams{ServerID: st.server.ID, RecipeID: st.recipe.ID})
		if err == nil && row.Status == "installing" {
			_ = h.q.SetSoftwareInstallStatus(ctx, sqlc.SetSoftwareInstallStatusParams{ID: row.ID, Status: "failed", Error: msg})
		}
	}
}

type softwareRunParams struct {
	RunID uuid.UUID `json:"run_id"`
}

// submitRun queues a stored run as its own job.
func (h *softwareHandler) submitRun(ctx context.Context, run sqlc.SoftwareRun, plan softwarePlan) (*JobOutput, error) {
	refs := []uuid.UUID{}
	for _, st := range plan.steps {
		if !slices.Contains(refs, st.server.ID) {
			refs = append(refs, st.server.ID)
		}
	}
	target := JobPlace{RunID: run.ID.String(), Name: plan.name}
	if len(refs) == 1 {
		target.ServerID = refs[0].String()
	}
	j, err := submit(ctx, h.runner, jobs.Spec{
		Kind: softwareRunKind, Title: plan.name, Params: softwareRunParams{RunID: run.ID}, Refs: refs, Target: target,
	})
	bg := context.WithoutCancel(ctx)
	if err != nil {
		_ = h.q.EndSoftwareRun(bg, sqlc.EndSoftwareRunParams{ID: run.ID, State: jobs.Failed, Error: "It couldn't be queued."})
		h.failInstalls(bg, plan, "It couldn't be queued.")
		return nil, err
	}
	jobID := uuid.MustParse(j.Body.ID)
	if err := h.q.SetSoftwareRunJob(ctx, sqlc.SetSoftwareRunJobParams{JobID: &jobID, ID: run.ID}); err != nil {
		slog.Warn("link a software run to its job", "run", run.ID, "error", err)
	}
	return j, nil
}

// ---- Running ----

func (h *softwareHandler) runJob(ctx context.Context, t *jobs.Task) (any, error) {
	var params softwareRunParams
	if err := t.Decode(&params); err != nil {
		return nil, err
	}
	return h.execute(ctx, t, params.RunID)
}

func softwareTimeout(action string) time.Duration {
	switch action {
	case "upgrade-system":
		return time.Hour
	case "uninstall":
		return 15 * time.Minute
	case "rollback":
		return 10 * time.Minute
	}
	return 30 * time.Minute
}

// execute runs a stored run in the job t (its own, or a cron job's). The
// servers run side by side; each server's steps run in order, and a failed
// step skips the rest on that server.
func (h *softwareHandler) execute(ctx context.Context, t *jobs.Task, runID uuid.UUID) (any, error) {
	bg := context.WithoutCancel(ctx)
	run, err := h.q.GetSoftwareRun(ctx, runID)
	if isNotFound(err) {
		return nil, errors.New("The run was deleted before it started.")
	}
	if err != nil {
		return nil, err
	}
	if !jobs.Active(run.State) {
		return nil, nil
	}
	targets, err := h.q.ListSoftwareRunTargets(ctx, run.ID)
	if err != nil {
		return nil, err
	}
	var opts SoftwareRunOptions
	decodeInto(run.Options, &opts)
	list, err := h.catalog(ctx, run.WorkspaceID)
	if err != nil {
		return nil, err
	}
	if err := h.q.StartSoftwareRun(ctx, run.ID); err != nil {
		return nil, err
	}

	// Lanes: one per server, in the order the steps were planned.
	type lane struct {
		name  string
		steps []sqlc.SoftwareRunTarget
	}
	var lanes []*lane
	for _, tg := range targets {
		i := slices.IndexFunc(lanes, func(l *lane) bool {
			return l.steps[0].ServerID != nil && tg.ServerID != nil && *l.steps[0].ServerID == *tg.ServerID
		})
		if i < 0 {
			lanes = append(lanes, &lane{name: tg.ServerName})
			i = len(lanes) - 1
		}
		lanes[i].steps = append(lanes[i].steps, tg)
	}
	parallel := opts.Parallel
	if parallel <= 0 {
		parallel = 1
		if run.Action == "install" || run.Action == "uninstall" {
			parallel = 5
		}
	}
	stopOnFailure := run.Action != "install" && run.Action != "uninstall"
	if opts.StopOnFailure != nil {
		stopOnFailure = *opts.StopOnFailure
	}

	var mu sync.Mutex
	running := []string{}
	done, failed, badLanes := 0, 0, 0
	tripped := false
	report := func() {
		t.Update(func(p *jobs.Progress) {
			p.Phase, p.Items, p.ItemsTotal = "Running", done, len(targets)
			p.Current = strings.Join(running, ", ")
		})
	}
	report()
	skip := func(tg sqlc.SoftwareRunTarget, why string) {
		if err := h.q.FinishSoftwareTarget(bg, sqlc.FinishSoftwareTargetParams{
			RunID: run.ID, Position: tg.Position, State: "skipped", Error: why,
		}); err != nil {
			slog.Warn("skip a software step", "run", run.ID, "error", err)
		}
		mu.Lock()
		done++
		report()
		mu.Unlock()
	}

	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for _, l := range lanes {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
		mu.Lock()
		stop := tripped
		mu.Unlock()
		if stop {
			<-sem
			for _, tg := range l.steps {
				skip(tg, "Skipped: a server before it failed.")
			}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			broken := ""
			for _, tg := range l.steps {
				if ctx.Err() != nil {
					break
				}
				if broken != "" {
					skip(tg, "Skipped: "+broken+" failed on this server first.")
					continue
				}
				label := tg.RecipeName + " on " + tg.ServerName
				mu.Lock()
				running = append(running, label)
				report()
				mu.Unlock()

				state := h.runStep(ctx, t, run, opts, list, tg)

				mu.Lock()
				running = slices.DeleteFunc(running, func(n string) bool { return n == label })
				done++
				if state != jobs.Succeeded {
					failed++
					if stopOnFailure && state == jobs.Failed {
						tripped = true
					}
				}
				report()
				mu.Unlock()
				t.Logf("%s: %s", label, state)
				if state != jobs.Succeeded {
					broken = tg.RecipeName
				}
			}
			if broken != "" {
				mu.Lock()
				badLanes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	state, msg := jobs.Succeeded, ""
	switch {
	case ctx.Err() != nil && t.Canceled():
		state = jobs.Canceled
	case ctx.Err() != nil:
		state, msg = jobs.Interrupted, "Morcheh stopped before it finished."
	case failed > 0:
		state = jobs.Failed
		if len(lanes) == 1 {
			msg = "It failed on " + lanes[0].name + "."
		} else {
			msg = fmt.Sprintf("It failed on %d of %s.", max(badLanes, 1), countServers(len(lanes)))
		}
	}
	if state == jobs.Canceled || state == jobs.Interrupted {
		_ = h.q.EndSoftwareRun(bg, sqlc.EndSoftwareRunParams{ID: run.ID, State: state, Error: msg})
		h.settleInstalls(bg, run, targets)
	} else if err := h.q.FinishSoftwareRun(bg, sqlc.FinishSoftwareRunParams{ID: run.ID, State: state, Error: msg}); err != nil {
		slog.Error("finish a software run", "run", run.ID, "error", err)
	}
	switch state {
	case jobs.Succeeded:
		return map[string]any{"run_id": run.ID.String()}, nil
	case jobs.Failed:
		return nil, errors.New(msg)
	}
	return nil, ctx.Err()
}

// settleInstalls puts back records left mid-change by a stopped run.
func (h *softwareHandler) settleInstalls(ctx context.Context, run sqlc.SoftwareRun, targets []sqlc.SoftwareRunTarget) {
	for _, tg := range targets {
		if tg.ServerID == nil || tg.RecipeID == software.System {
			continue
		}
		row, err := h.q.GetSoftwareInstallByRecipe(ctx, sqlc.GetSoftwareInstallByRecipeParams{ServerID: *tg.ServerID, RecipeID: tg.RecipeID})
		if err != nil {
			continue
		}
		switch row.Status {
		case "installing":
			_ = h.q.SetSoftwareInstallStatus(ctx, sqlc.SetSoftwareInstallStatusParams{ID: row.ID, Status: "failed", Error: "The install was stopped before it finished."})
		case "updating", "removing":
			_ = h.q.SetSoftwareInstallStatus(ctx, sqlc.SetSoftwareInstallStatusParams{ID: row.ID, Status: "installed", Error: "The last change was stopped before it finished."})
		}
	}
}

// runStep runs one application's script on one server and stores what
// happened, on the run and on the install record.
func (h *softwareHandler) runStep(ctx context.Context, t *jobs.Task, run sqlc.SoftwareRun, opts SoftwareRunOptions, list []software.Recipe, tg sqlc.SoftwareRunTarget) string {
	bg := context.WithoutCancel(ctx)
	finish := func(p sqlc.FinishSoftwareTargetParams) string {
		p.RunID, p.Position = run.ID, tg.Position
		p.Output = cleanOutput(p.Output)
		if err := h.q.FinishSoftwareTarget(bg, p); err != nil {
			slog.Error("finish a software step", "run", run.ID, "server", tg.ServerName, "error", err)
		}
		return p.State
	}
	stopped := func() string {
		if t.Canceled() {
			return jobs.Canceled
		}
		return jobs.Interrupted
	}
	if ctx.Err() != nil {
		return finish(sqlc.FinishSoftwareTargetParams{State: stopped()})
	}
	if tg.ServerID == nil {
		return finish(sqlc.FinishSoftwareTargetParams{State: jobs.Failed, Error: "The server was deleted."})
	}
	sid := *tg.ServerID

	// The recipe and the record it changes.
	var row sqlc.SoftwareInstall
	r := systemRecipe
	if tg.RecipeID != software.System {
		var err error
		row, err = h.q.GetSoftwareInstallByRecipe(ctx, sqlc.GetSoftwareInstallByRecipeParams{ServerID: sid, RecipeID: tg.RecipeID})
		if err != nil {
			return finish(sqlc.FinishSoftwareTargetParams{State: jobs.Failed, Error: "Morcheh no longer has a record of it on this server."})
		}
		var ok bool
		if r, ok = software.Find(list, tg.RecipeID); !ok {
			if row.Kind != software.KindDocker || run.Action != "update" {
				return finish(sqlc.FinishSoftwareTargetParams{State: jobs.Failed, Error: "Its recipe was removed from the catalog."})
			}
			r = software.Recipe{ID: row.RecipeID, Name: row.Name, Kind: software.KindDocker}
		}
	}
	values := map[string]string{}
	decodeInto(row.Params, &values)
	for k, v := range h.openSecrets(row.Secrets) {
		values[k] = v
	}
	docker := r.Kind == software.KindDocker

	var script string
	switch run.Action {
	case "install":
		script = software.InstallScript(r, values, software.InstallOptions{Fresh: opts.Fresh})
	case "update":
		switch {
		case r.ID == software.System:
			script = software.SystemUpgradeScript(software.SystemOptions{SecurityOnly: opts.SecurityOnly, Full: opts.Full})
		case docker && row.Origin == "found":
			script = software.UpdateFoundScript(row.Dir, row.Project)
		default:
			script = software.UpdateScript(r)
		}
	case "upgrade-system":
		script = software.SystemUpgradeScript(software.SystemOptions{SecurityOnly: opts.SecurityOnly, Full: opts.Full})
	case "rollback":
		script = software.RollbackScript(r)
	case "uninstall":
		script = software.UninstallScript(r, software.UninstallOptions{RemoveData: opts.RemoveData})
	}
	env := values
	if docker {
		env = nil
	}
	wrapped, err := wrapScript("sh", script, env)
	if err != nil {
		return finish(sqlc.FinishSoftwareTargetParams{State: jobs.Failed, Error: err.Error()})
	}

	setStatus := func(status, msg string) {
		if row.ID == uuid.Nil {
			return
		}
		if err := h.q.SetSoftwareInstallStatus(bg, sqlc.SetSoftwareInstallStatusParams{ID: row.ID, Status: status, Error: msg}); err != nil {
			slog.Warn("set an application's status", "id", row.ID, "error", err)
		}
	}
	switch run.Action {
	case "update", "rollback":
		setStatus("updating", "")
	case "uninstall":
		setStatus("removing", "")
	}
	if err := h.q.StartSoftwareTarget(ctx, sqlc.StartSoftwareTargetParams{RunID: run.ID, Position: tg.Position}); err != nil {
		return finish(sqlc.FinishSoftwareTargetParams{State: jobs.Failed, Error: err.Error()})
	}

	out := &liveOutput{limit: scriptOutputCap}
	saveStop, saveDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(saveDone)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		seen := 0
		for {
			select {
			case <-saveStop:
				return
			case <-tick.C:
				text, truncated, version := out.snapshot()
				if version == seen {
					continue
				}
				seen = version
				if err := h.q.SaveSoftwareTargetOutput(bg, sqlc.SaveSoftwareTargetOutputParams{
					RunID: run.ID, Position: tg.Position, Output: cleanOutput(text), Truncated: truncated,
				}); err != nil {
					slog.Warn("save a software step's output", "run", run.ID, "error", err)
				}
			}
		}
	}()
	timeout := softwareTimeout(run.Action)
	res, err := h.scripts.execOn(ctx, sid.String(), "root", wrapped, timeout, out)
	close(saveStop)
	<-saveDone

	text, truncated, _ := out.snapshot()
	p := sqlc.FinishSoftwareTargetParams{Output: text, Truncated: truncated}
	switch {
	case err != nil && ctx.Err() != nil:
		p.State = stopped()
	case err != nil:
		p.State, p.Error = jobs.Failed, err.Error()
	case res.stopped && ctx.Err() != nil:
		p.State = stopped()
	case res.stopped:
		p.State, p.Error = jobs.Failed, fmt.Sprintf("It ran past its time limit (%s) and was stopped.", timeout)
	case res.code == nil || *res.code != 0:
		p.State = jobs.Failed
		p.Error = lastLines(strings.TrimSpace(cleanOutput(text)), 1)
		if p.Error == "" && res.code != nil {
			p.Error = fmt.Sprintf("It exited with code %d.", *res.code)
		}
	default:
		p.State = jobs.Succeeded
	}

	if p.State != jobs.Succeeded {
		why := cmpOr(p.Error, "It was stopped before it finished.")
		switch run.Action {
		case "install":
			setStatus("failed", why)
		case "update", "rollback":
			setStatus("installed", "The last update failed: "+why)
		case "uninstall":
			setStatus("installed", "Removing it failed: "+why)
		}
		return finish(p)
	}

	// It worked: look again at what is there now.
	if run.Action == "uninstall" {
		if row.ID != uuid.Nil {
			_ = h.q.DeleteSoftwareInstall(bg, row.ID)
		}
		if r.ID == "docker" {
			_, _ = h.scanServer(bg, sid, software.ScanOptions{Full: true})
		}
		return finish(p)
	}
	opt := software.ScanOptions{Full: r.ID == software.System || r.ID == "docker"}
	if docker {
		opt.Apps = []string{r.ID}
	}
	scan, err := h.scanServer(bg, sid, opt)
	if err != nil {
		t.Logf("%s on %s: the look afterwards failed: %s", r.Name, tg.ServerName, problemText(err))
	}
	if r.ID == software.System {
		return finish(p)
	}
	if f, ok := foundOf(scan, r.ID); ok {
		p.VersionAfter = f.Version
		imgs, _ := json.Marshal(f.Images)
		if err := h.q.FinishSoftwareInstall(bg, sqlc.FinishSoftwareInstallParams{
			ID: row.ID, Status: "installed", Version: f.Version, Latest: f.Latest, UpdateAvailable: f.UpdateAvailable,
			State: f.State, Images: imgs, CanRollback: f.CanRollback, Pinned: f.Pinned, Installed: run.Action == "install",
		}); err != nil {
			slog.Warn("finish an application's record", "id", row.ID, "error", err)
		}
	} else {
		imgs := row.Images
		if len(imgs) == 0 {
			imgs = []byte("[]")
		}
		_ = h.q.FinishSoftwareInstall(bg, sqlc.FinishSoftwareInstallParams{
			ID: row.ID, Status: "installed", Version: row.Version, Latest: row.Latest, State: row.State, Images: imgs,
			CanRollback: row.CanRollback, Pinned: row.Pinned, Installed: run.Action == "install",
		})
	}
	return finish(p)
}

func foundOf(scan software.Scan, id string) (software.Found, bool) {
	i := slices.IndexFunc(scan.Software, func(f software.Found) bool { return f.RecipeID == id })
	if i < 0 {
		return software.Found{}, false
	}
	return scan.Software[i], true
}

// ---- Scanning ----

const softwareScanTimeout = 6 * time.Minute

// scanServer looks at what is installed on a server and stores it. It runs
// as root when it can (to refresh the package lists), else as the login
// user.
func (h *softwareHandler) scanServer(ctx context.Context, id uuid.UUID, opt software.ScanOptions) (software.Scan, error) {
	var scan software.Scan
	s, err := h.servers.get(ctx, id.String())
	if err != nil {
		return scan, err
	}
	list, err := h.catalog(ctx, s.WorkspaceID)
	if err != nil {
		return scan, err
	}
	// A package or script taken out of the catalog is only looked for where
	// it was installed before, so it isn't newly "found" anywhere else.
	if before, err := h.q.ListServerSoftwareInstalls(ctx, id); err == nil {
		list = slices.DeleteFunc(list, func(r software.Recipe) bool {
			return r.Retired && r.Kind != software.KindDocker &&
				!slices.ContainsFunc(before, func(row sqlc.ListServerSoftwareInstallsRow) bool { return row.RecipeID == r.ID })
		})
	}
	var text string
	err = h.servers.withConn(ctx, id.String(), func(c *sshConn) error {
		sh, err := h.servers.rootShell(ctx, id.String(), c)
		if err != nil {
			return err
		}
		text, err = runInput(ctx, c, wrapStdin(sh), stdinFor(sh, software.ScanScript(list, opt)), softwareScanTimeout)
		return err
	})
	if err != nil {
		if opt.Full {
			_ = h.q.SaveSoftwareHostError(ctx, sqlc.SaveSoftwareHostErrorParams{ServerID: id, Error: problemText(toProblem(err))})
		}
		return scan, err
	}
	scan = software.ParseScan(text, list, opt)

	for i := range scan.Software {
		f := &scan.Software[i]
		if f.Kind == software.KindDocker && len(f.Images) > 0 && h.registry.CheckImages(ctx, f.Images) {
			f.UpdateAvailable = true
		}
	}
	if opt.Full {
		hs := scan.Host
		if err := h.q.SaveSoftwareHost(ctx, sqlc.SaveSoftwareHostParams{
			ServerID: id, Pm: hs.PM, Docker: hs.Docker, Compose: hs.Compose, Upgradable: int32(hs.Upgradable),
			Security: int32(hs.Security), RebootRequired: hs.RebootRequired, Packages: software.MarshalPackages(hs.Packages),
		}); err != nil {
			slog.Warn("save a software scan", "server", id, "error", err)
		}
	}
	present := []string{}
	for _, f := range scan.Software {
		present = append(present, f.RecipeID)
		if err := h.q.SaveScannedSoftware(ctx, sqlc.SaveScannedSoftwareParams{
			WorkspaceID: s.WorkspaceID, ServerID: id, RecipeID: f.RecipeID, Name: f.Name, Kind: f.Kind,
			Origin: f.Origin, Version: f.Version, Latest: f.Latest, UpdateAvailable: f.UpdateAvailable, State: f.State,
			Images: software.MarshalImages(f.Images), Dir: f.Dir, Project: f.Project, CanRollback: f.CanRollback,
			Pinned: f.Pinned,
		}); err != nil {
			slog.Warn("save a found application", "server", id, "recipe", f.RecipeID, "error", err)
		}
	}
	// What it didn't look for stays as it was.
	rows, err := h.q.ListServerSoftwareInstalls(ctx, id)
	if err == nil {
		for _, row := range rows {
			if !slices.Contains(scan.Looked, row.RecipeID) && !slices.Contains(present, row.RecipeID) {
				present = append(present, row.RecipeID)
			}
		}
		_ = h.q.DeleteGoneFoundSoftware(ctx, sqlc.DeleteGoneFoundSoftwareParams{ServerID: id, Present: present})
		_ = h.q.MarkMissingSoftware(ctx, sqlc.MarkMissingSoftwareParams{ServerID: id, Present: present})
	}
	return scan, nil
}

// scanApp refreshes one app's record after a change made from the panel.
func (h *softwareHandler) scanApp(ctx context.Context, server, _ uuid.UUID, recipeID, _ string) {
	if _, err := h.scanServer(context.WithoutCancel(ctx), server, software.ScanOptions{Apps: []string{recipeID}}); err != nil {
		slog.Warn("look at an application again", "server", server, "recipe", recipeID, "error", err)
	}
}

type softwareScanParams struct {
	ServerIDs []uuid.UUID `json:"server_ids"`
}

// scanJob scans servers fully, three at a time.
func (h *softwareHandler) scanJob(ctx context.Context, t *jobs.Task) (any, error) {
	var params softwareScanParams
	if err := t.Decode(&params); err != nil {
		return nil, err
	}
	total := len(params.ServerIDs)
	var mu sync.Mutex
	done, failed := 0, 0
	var last error
	report := func() {
		t.Update(func(p *jobs.Progress) { p.Phase, p.Items, p.ItemsTotal = "Looking", done, total })
	}
	report()
	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup
	for _, id := range params.ServerIDs {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			_, err := h.scanServer(ctx, id, software.ScanOptions{Full: true})
			mu.Lock()
			done++
			if err != nil {
				failed++
				last = err
				t.Logf("%s: %s", id, problemText(toProblem(err)))
			}
			report()
			mu.Unlock()
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if failed > 0 {
		if total == 1 {
			return nil, errors.New(problemText(toProblem(last)))
		}
		return nil, fmt.Errorf("It failed on %d of %s.", failed, countServers(total))
	}
	return map[string]any{"servers": total}, nil
}

// ---- Checker ----

// startSoftwareChecker scans every online server once per interval.
func startSoftwareChecker(h *softwareHandler, every time.Duration) {
	if every <= 0 {
		return
	}
	var mu sync.Mutex
	running := map[uuid.UUID]bool{}
	sem := make(chan struct{}, 3)
	go func() {
		time.Sleep(30 * time.Second)
		for ; ; time.Sleep(time.Minute) {
			due, err := h.q.ServersToScanSoftware(context.Background(), every.Seconds())
			if err != nil {
				slog.Warn("list servers to scan for software", "error", err)
				continue
			}
			for _, id := range due {
				mu.Lock()
				busy := running[id]
				running[id] = true
				mu.Unlock()
				if busy {
					continue
				}
				sem <- struct{}{}
				go func() {
					defer func() {
						<-sem
						mu.Lock()
						delete(running, id)
						mu.Unlock()
					}()
					ctx, cancel := context.WithTimeout(context.Background(), softwareScanTimeout+time.Minute)
					defer cancel()
					if _, err := h.scanServer(ctx, id, software.ScanOptions{Full: true}); err != nil {
						slog.Debug("software scan", "server", id, "error", err)
					}
				}()
			}
		}
	}()
}
