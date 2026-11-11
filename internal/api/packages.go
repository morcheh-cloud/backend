package api

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/packages"
	"github.com/morcheh/backend/internal/sshpool"
)

// System packages on a server: what's installed, what can be upgraded, and
// installing, upgrading or removing them. Reads answer at once; changes run
// as background jobs.

const (
	packageActionKind  = "package-action"
	packageRefreshKind = "package-refresh"
	// How long one action may take; upgrading everything takes longer.
	packageActionTimeout  = 30 * time.Minute
	packageUpgradeTimeout = 60 * time.Minute
)

// ---- Types ----

type PackageNameInput struct {
	ServerIDPath
	Name string `query:"name" required:"true" maxLength:"128" doc:"The package's name" example:"nginx"`
}

type PackageSearchInput struct {
	ServerIDPath
	Q     string `query:"q" required:"true" maxLength:"64" doc:"Part of a name (or a description, where the manager searches those)" example:"htop"`
	Limit int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
}

type PackageSearchResult struct {
	Manager string                  `json:"manager"`
	Matches []packages.PackageMatch `json:"matches" doc:"Exact names first, then names starting with the search, then the rest"`
}

type PackageHistory struct {
	Manager   string                         `json:"manager"`
	Supported bool                           `json:"supported" doc:"The manager keeps a history (apk doesn't)"`
	Entries   []packages.PackageHistoryEntry `json:"entries" doc:"Newest first, at most 200"`
}

type PackageActionBody struct {
	Action  string   `json:"action" enum:"install,remove,purge,upgrade,reinstall,upgrade-all,autoremove,clean" doc:"upgrade-all: every package (see mode); autoremove: packages nothing needs any more; clean: empty the download cache"`
	Names   []string `json:"names,omitempty" required:"false" maxItems:"200" doc:"The packages, for install, remove, purge, upgrade and reinstall"`
	Version string   `json:"version,omitempty" required:"false" maxLength:"128" doc:"Install this version (also an older one); one package only"`
	Mode    string   `json:"mode,omitempty" required:"false" enum:"all,security,full" doc:"For upgrade-all: all = a normal upgrade, security = only security updates, full = may also add or remove packages (apt full-upgrade)"`
}

type PackageMarkBody struct {
	Mark  string   `json:"mark" enum:"hold,unhold,auto,manual" doc:"hold: keep at this version; auto: installed as a dependency (autoremove may take it); manual: installed by hand"`
	Names []string `json:"names" minItems:"1" maxItems:"200"`
}

type PackageAutoUpdatesBody struct {
	Enabled bool `json:"enabled"`
}

type packageJobParams struct {
	ServerID string   `json:"server_id"`
	Action   string   `json:"action,omitempty"`
	Names    []string `json:"names,omitempty"`
	Version  string   `json:"version,omitempty"`
	Mode     string   `json:"mode,omitempty"`
}

// ---- Routes ----

func registerPackages(api huma.API, h *serverHandler) {
	tags := []string{"Packages"}
	base := "/servers/{id}/packages"

	huma.Register(api, huma.Operation{
		OperationID: "get-packages",
		Method:      http.MethodGet,
		Path:        base,
		Summary:     "Installed packages and updates",
		Description: "Every installed package with its version, size, whether it was installed by hand, held or no longer needed, " +
			"and the newer version the repositories have (security updates marked). Read from the package lists the server already has: " +
			"refresh them for fresh updates.",
		Tags: tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body packages.PackagesOverview }, error) {
		return h.packagesOverview(ctx, in.ID)
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-package",
		Method:      http.MethodGet,
		Path:        base + "/info",
		Summary:     "One package",
		Description: "Its description, dependencies, what needs it, its files (when installed) and the versions the server could install. 404 when no repository has it.",
		Tags:        tags,
	}, func(ctx context.Context, in *PackageNameInput) (*struct{ Body packages.PackageInfo }, error) {
		if !packages.ValidName(in.Name) {
			return nil, fieldError("query.name", "Not a package name", in.Name)
		}
		out := &struct{ Body packages.PackageInfo }{}
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.rootShell(ctx, in.ID, c)
			if err != nil {
				return err
			}
			text, err := pkgRun(ctx, sh, packages.InfoScript(in.Name), 3*time.Minute)
			if err != nil {
				return err
			}
			info, ok := packages.ParseInfo(in.Name, text)
			if !ok {
				return huma.Error404NotFound("No package called " + in.Name + " on this server or in its repositories")
			}
			out.Body = info
			return nil
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "search-packages",
		Method:      http.MethodGet,
		Path:        base + "/search",
		Summary:     "Search the repositories",
		Description: "Packages the server could install, with the version on offer and the installed one. Reads the lists the server has, downloads nothing.",
		Tags:        tags,
	}, func(ctx context.Context, in *PackageSearchInput) (*struct{ Body PackageSearchResult }, error) {
		q := strings.TrimSpace(in.Q)
		if !packages.ValidQuery(q) {
			return nil, fieldError("query.q", "Letters, digits and + . _ - only", in.Q)
		}
		out := &struct{ Body PackageSearchResult }{}
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.rootShell(ctx, in.ID, c)
			if err != nil {
				return err
			}
			text, err := pkgRun(ctx, sh, packages.SearchScript(q), 3*time.Minute)
			if err != nil {
				return err
			}
			pm := metaOf(text)
			m := packages.ParseSearch(text, q, in.Limit)
			if len(m) > 0 && packages.NeedsCandidates(pm) {
				names := make([]string, len(m))
				for i, x := range m {
					names[i] = x.Name
				}
				cand, err := pkgRun(ctx, sh, packages.CandidatesScript(names), 2*time.Minute)
				if err != nil {
					return err
				}
				packages.ApplyCandidates(m, cand)
			}
			out.Body = PackageSearchResult{Manager: pm, Matches: m}
			return nil
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "package-history",
		Method:      http.MethodGet,
		Path:        base + "/history",
		Summary:     "What the package manager did before",
		Description: "Past installs, upgrades and removals from the manager's own log, with who ran them and the command.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body PackageHistory }, error) {
		out := &struct{ Body PackageHistory }{}
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.rootShell(ctx, in.ID, c)
			if err != nil {
				return err
			}
			text, err := pkgRun(ctx, sh, packages.HistoryScript(), 2*time.Minute)
			if err != nil {
				return err
			}
			pm := metaOf(text)
			out.Body = PackageHistory{Manager: pm, Supported: packages.CapabilitiesOf(pm).History, Entries: packages.ParseHistory(text)}
			return nil
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "preview-packages",
		Method:      http.MethodPost,
		Path:        base + "/preview",
		Summary:     "What an action would change",
		Description: "Asks the package manager to simulate it: the packages it would install, upgrade or remove (dependencies too), " +
			"or why it can't. Nothing changes. Needs root or sudo.",
		Tags: tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body PackageActionBody
	}) (*struct{ Body packages.PackagePreview }, error) {
		b, err := checkPackageAction(in.Body)
		if err != nil {
			return nil, err
		}
		if b.Action == packages.ActClean {
			return nil, fieldError("body.action", "Emptying the cache has no preview", b.Action)
		}
		script, err := packages.PreviewScript(b.Action, b.Mode, b.Names, b.Version)
		if err != nil {
			return nil, fieldError("body.action", err.Error(), b.Action)
		}
		out := &struct{ Body packages.PackagePreview }{}
		err = h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.pkgRoot(ctx, in.ID, c)
			if err != nil {
				return err
			}
			res, err := sh.exec(ctx, script, 3*time.Minute, 4<<20)
			if err != nil {
				return err
			}
			if res.timedOut {
				return huma.Error504GatewayTimeout("The package manager took too long to answer")
			}
			out.Body = packages.ParsePreview(b.Action, string(res.output))
			return nil
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "run-package-action",
		Method:      http.MethodPost,
		Path:        base + "/actions",
		Summary:     "Install, upgrade or remove packages",
		Description: "Checked at once, then runs as a background job (kind `package-action`); it can't be canceled once the package manager is running. " +
			"Waits for another package manager on the server to finish first. 409 when Morcheh is already changing packages there.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body PackageActionBody
	}) (*JobOutput, error) {
		b, err := checkPackageAction(in.Body)
		if err != nil {
			return nil, err
		}
		if _, err := packages.ActionScript(b.Action, b.Mode, b.Names, b.Version); err != nil {
			return nil, fieldError("body.action", err.Error(), b.Action)
		}
		p := packageJobParams{ServerID: in.ID, Action: b.Action, Names: b.Names, Version: b.Version, Mode: b.Mode}
		return h.submitPackageJob(ctx, in.ID, packageActionKind, p, func(pm string) error {
			caps := packages.CapabilitiesOf(pm)
			switch {
			case b.Action == packages.ActPurge && !caps.Purge:
				return fieldError("body.action", "Only apt keeps configuration files apart: remove the package instead", b.Action)
			case b.Version != "" && !caps.Versions:
				return fieldError("body.version", "Installing a chosen version isn't supported with "+pm, b.Version)
			case b.Mode == packages.ModeSecurity && !caps.Security:
				return fieldError("body.mode", "Security-only updates aren't supported with "+pm, b.Mode)
			}
			return nil
		})
	})
	h.jobs.Handle(packageActionKind, h.runPackageJob)

	huma.Register(api, huma.Operation{
		OperationID:   "refresh-package-lists",
		Method:        http.MethodPost,
		Path:          base + "/refresh",
		Summary:       "Download fresh package lists",
		Description:   "apt update, dnf makecache and the like, so the updates shown are current. Runs as a background job (kind `package-refresh`).",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *ServerIDPath) (*JobOutput, error) {
		return h.submitPackageJob(ctx, in.ID, packageRefreshKind, packageJobParams{ServerID: in.ID}, nil)
	})
	h.jobs.Handle(packageRefreshKind, h.runPackageJob)

	huma.Register(api, huma.Operation{
		OperationID: "mark-packages",
		Method:      http.MethodPost,
		Path:        base + "/mark",
		Summary:     "Hold packages, or mark them as installed by hand or as dependencies",
		Description: "Answers the fresh overview. 422 when the server's package manager can't do it.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body PackageMarkBody
	}) (*struct{ Body packages.PackagesOverview }, error) {
		names, err := checkNames(in.Body.Names)
		if err != nil {
			return nil, err
		}
		script, err := packages.MarkScript(in.Body.Mark, names)
		if err != nil {
			return nil, fieldError("body.mark", err.Error(), in.Body.Mark)
		}
		return h.packageChange(ctx, in.ID, script)
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-auto-updates",
		Method:      http.MethodPost,
		Path:        base + "/auto-updates",
		Summary:     "Turn automatic updates on or off",
		Description: "unattended-upgrades on apt, dnf-automatic on dnf; the tool has to be installed first. Answers the fresh overview.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body PackageAutoUpdatesBody
	}) (*struct{ Body packages.PackagesOverview }, error) {
		return h.packageChange(ctx, in.ID, packages.AutoUpdatesScript(in.Body.Enabled))
	})
}

// ---- Reading ----

func (h *serverHandler) packagesOverview(ctx context.Context, id string) (*struct{ Body packages.PackagesOverview }, error) {
	out := &struct{ Body packages.PackagesOverview }{}
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.rootShell(ctx, id, c)
		if err != nil {
			return err
		}
		o, err := readPackages(ctx, sh)
		if err == nil {
			out.Body = *o
		}
		return err
	})
	return out, toProblem(err)
}

func readPackages(ctx context.Context, sh *rootShell) (*packages.PackagesOverview, error) {
	text, err := pkgRun(ctx, sh, packages.OverviewScript(), 3*time.Minute)
	if err != nil {
		return nil, err
	}
	o := packages.ParseOverview(text)
	o.Access = sh.priv.access()
	return &o, nil
}

// pkgRun runs a read-only script; they always exit 0, so anything else is
// a real failure.
func pkgRun(ctx context.Context, sh *rootShell, script string, timeout time.Duration) (string, error) {
	res, err := sh.exec(ctx, script, timeout, 64<<20)
	switch {
	case err != nil:
		return "", err
	case res.timedOut:
		return "", huma.Error504GatewayTimeout("The package manager took too long to answer")
	case res.truncated:
		return "", huma.Error422UnprocessableEntity("The package manager's answer was too long to read")
	case res.code != 0:
		return "", huma.Error422UnprocessableEntity(fmt.Sprintf("Couldn't read the packages (exit %d): %s", res.code, lastLines(string(res.output), 3)))
	}
	return string(res.output), nil
}

// metaOf reads the manager from a script's "@@ meta" block.
func metaOf(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if pm, ok := strings.CutPrefix(strings.TrimSpace(l), "pm "); ok {
			return pm
		}
	}
	return packages.None
}

// ---- Changing ----

func (h *serverHandler) pkgRoot(ctx context.Context, id string, c *sshpool.Conn) (*rootShell, error) {
	sh, err := h.rootShell(ctx, id, c)
	if err != nil {
		return nil, err
	}
	if sh.priv == privUser {
		return nil, huma.Error403Forbidden("Changing packages needs root or sudo on this server")
	}
	return sh, nil
}

// packageChange runs a quick change (exit 3 = the manager can't) and
// answers the fresh overview.
func (h *serverHandler) packageChange(ctx context.Context, id, script string) (*struct{ Body packages.PackagesOverview }, error) {
	if err := h.packageJobRunning(ctx, id); err != nil {
		return nil, err
	}
	out := &struct{ Body packages.PackagesOverview }{}
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.pkgRoot(ctx, id, c)
		if err != nil {
			return err
		}
		res, err := sh.exec(ctx, script, 3*time.Minute, 256<<10)
		if err != nil {
			return err
		}
		switch {
		case res.timedOut:
			return huma.Error504GatewayTimeout("The package manager took too long to answer")
		case res.code != 0:
			return huma.Error422UnprocessableEntity(lastLines(string(res.output), 3))
		}
		o, err := readPackages(ctx, sh)
		if err == nil {
			out.Body = *o
		}
		return err
	})
	return out, toProblem(err)
}

// checkPackageAction tidies and checks an action before anything runs.
func checkPackageAction(b PackageActionBody) (PackageActionBody, error) {
	b.Version = strings.TrimSpace(b.Version)
	switch b.Action {
	case packages.ActInstall, packages.ActRemove, packages.ActPurge, packages.ActUpgrade, packages.ActReinstall:
		names, err := checkNames(b.Names)
		if err != nil {
			return b, err
		}
		b.Names = names
	default:
		b.Names = nil
	}
	if b.Version != "" {
		if b.Action != packages.ActInstall || len(b.Names) != 1 {
			return b, fieldError("body.version", "A version goes with installing one package", b.Version)
		}
		if !packages.ValidVersion(b.Version) {
			return b, fieldError("body.version", "Not a package version", b.Version)
		}
	}
	if b.Action != packages.ActUpgradeAll {
		b.Mode = ""
	} else if b.Mode == "" {
		b.Mode = packages.ModeAll
	}
	return b, nil
}

func checkNames(names []string) ([]string, error) {
	var out []string
	for i, n := range names {
		n = strings.TrimSpace(n)
		if !packages.ValidName(n) {
			return nil, fieldError("body.names["+strconv.Itoa(i)+"]", "Not a package name", n)
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, fieldError("body.names", "Pick at least one package", names)
	}
	if len(out) > packages.MaxNames {
		return nil, fieldError("body.names", fmt.Sprintf("At most %d packages at a time", packages.MaxNames), len(out))
	}
	return out, nil
}

// packageJobRunning refuses while Morcheh is changing packages on the
// server already (here or from fail2ban).
func (h *serverHandler) packageJobRunning(ctx context.Context, id string) error {
	refs := placeRefs(id)
	if len(refs) == 0 {
		return huma.Error404NotFound("server not found")
	}
	active := true
	list, err := h.jobs.List(ctx, sqlc.ListJobsParams{Ref: &refs[0], Active: &active, Lim: 200})
	if err != nil {
		return internalError(err)
	}
	busy := []string{packageActionKind, packageRefreshKind, f2bInstallKind, f2bRemoveKind}
	if slices.ContainsFunc(list, func(j sqlc.Job) bool { return slices.Contains(busy, j.Kind) }) {
		return huma.Error409Conflict("Morcheh is already changing packages on this server: wait for that to finish")
	}
	return nil
}

// submitPackageJob checks what it can at once (root, a known manager, what
// it supports), then queues the job.
func (h *serverHandler) submitPackageJob(ctx context.Context, id, kind string, p packageJobParams, check func(pm string) error) (*JobOutput, error) {
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.pkgRoot(ctx, id, c)
		if err != nil {
			return err
		}
		facts, err := sh.run(ctx, hostScript)
		if err != nil {
			return err
		}
		pm := parseHost(facts).pm
		if pm == "" {
			return huma.Error422UnprocessableEntity("This server has no package manager Morcheh knows (apt, dnf, yum, zypper, apk or pacman)")
		}
		if pm == "apt-get" {
			pm = packages.APT
		}
		if check != nil {
			return check(pm)
		}
		return nil
	})
	if err != nil {
		return nil, toProblem(err)
	}
	if err := h.packageJobRunning(ctx, id); err != nil {
		return nil, err
	}
	s, err := h.get(ctx, id)
	if err != nil {
		return nil, err
	}
	return submit(ctx, h.jobs, jobs.Spec{Kind: kind, Title: packageJobTitle(kind, p) + " on " + s.Name, Params: p, Refs: placeRefs(id)})
}

func packageJobTitle(kind string, p packageJobParams) string {
	if kind == packageRefreshKind {
		return "Refresh the package lists"
	}
	what := ""
	switch {
	case len(p.Names) == 1:
		what = p.Names[0]
		if p.Version != "" {
			what += " " + p.Version
		}
	case len(p.Names) > 1:
		what = strconv.Itoa(len(p.Names)) + " packages"
	}
	switch p.Action {
	case packages.ActInstall:
		return "Install " + what
	case packages.ActRemove:
		return "Remove " + what
	case packages.ActPurge:
		return "Purge " + what
	case packages.ActUpgrade:
		return "Upgrade " + what
	case packages.ActReinstall:
		return "Reinstall " + what
	case packages.ActUpgradeAll:
		switch p.Mode {
		case packages.ModeSecurity:
			return "Install security updates"
		case packages.ModeFull:
			return "Full upgrade"
		}
		return "Upgrade all packages"
	case packages.ActAutoremove:
		return "Remove unneeded packages"
	case packages.ActClean:
		return "Empty the package cache"
	}
	return "Change packages"
}

// runPackageJob runs the package manager. Stopping it half way can leave
// the server's packages broken, and a process under sudo isn't ours to
// kill, so the job can't be canceled once it's running.
func (h *serverHandler) runPackageJob(ctx context.Context, t *jobs.Task) (any, error) {
	var p packageJobParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	script, timeout, phase := packages.RefreshScript(), packageTimeout, "Refreshing"
	if p.Action != "" {
		var err error
		if script, err = packages.ActionScript(p.Action, p.Mode, p.Names, p.Version); err != nil {
			return nil, err
		}
		timeout, phase = packageActionTimeout, "Working"
		if p.Action == packages.ActUpgradeAll {
			timeout, phase = packageUpgradeTimeout, "Upgrading"
		}
	}
	reboot := false
	err := h.withConn(ctx, p.ServerID, func(c *sshpool.Conn) error {
		sh, err := h.pkgRoot(ctx, p.ServerID, c)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Locked = phase, true })
		var last string
		lines := &lineWriter{fn: func(l string) {
			last = l
			if strings.Contains(l, "needs a restart") || strings.Contains(l, "*** System restart required ***") {
				reboot = true
			}
			t.Logf("%s", l)
			t.Update(func(pr *jobs.Progress) { pr.Current = l })
		}}
		res, err := sh.execTo(ctx, script, timeout, lines)
		lines.flush()
		switch {
		case err != nil:
			return err
		case ctx.Err() != nil:
			return ctx.Err()
		case res.timedOut:
			return fmt.Errorf("It took longer than %d minutes, so Morcheh stopped waiting", int(timeout.Minutes()))
		case res.code != 0:
			return fmt.Errorf("The package manager failed (exit %d): %s", res.code, last)
		}
		return nil
	})
	if err != nil {
		return nil, jobError(err)
	}
	return map[string]any{"server_id": p.ServerID, "reboot_required": reboot}, nil
}
