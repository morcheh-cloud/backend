package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/dbbackup"
	"github.com/morcheh/backend/internal/dbmon"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/storage"
)

// Database backups: a plan says what to dump, from where, to which Storages and
// when. The dump runs on a server, never inside Morcheh (on the database's own
// server, or the one the plan names for a direct database); Morcheh streams
// what it prints to every Storage at once, gzipping and hashing on the way.
// A plan over several databases makes one backup per database. MySQL/MariaDB
// (binary log) and SQL Server (differential) can take incrementals that build
// on the full before them. Restores run the same way in reverse
// (database_restores.go).
const (
	backupKind       = "database-backup"
	backupVerifyKind = "database-backup-verify"
	// How many runs that left no file a plan keeps on record.
	backupFailedRows = 200
	// How much of what a dump printed on stderr is kept.
	backupStderrTail = 4 << 10
	// A failed run's half-written file gets this long to be removed.
	backupCleanup = 30 * time.Second
	// How many storages one plan writes to.
	backupMaxStorages = 10
)

const backupLost = "Morcheh restarted before it finished."

// BackupPlanBody is what a person sets on a plan.
type BackupPlanBody struct {
	Name           string   `json:"name" minLength:"1" maxLength:"100" example:"Nightly"`
	StorageIDs     []string `json:"storage_ids" minItems:"1" maxItems:"10" doc:"Where it's uploaded: the database is dumped once and sent to each of them"`
	Folder         string   `json:"folder" minLength:"1" maxLength:"1024" doc:"Folder on the Storages; {year}, {month} and {day} are filled in at each run. Each database gets a folder of its own inside it" example:"/backups/{year}-{month}-{day}"`
	Selection      string   `json:"selection" enum:"all,selected,pattern" doc:"Which databases: all of them, the ones named in targets, or the ones matching pattern"`
	Targets        []string `json:"targets,omitempty" maxItems:"200" doc:"The databases, for selection=selected"`
	Pattern        string   `json:"pattern,omitempty" maxLength:"256" doc:"A regular expression, for selection=pattern" example:"^shop_"`
	Method         string   `json:"method" enum:"full,incremental" doc:"incremental: only what changed since the backup before (MySQL/MariaDB, SQL Server)"`
	FullEveryDays  int32    `json:"full_every_days" minimum:"1" maximum:"365" doc:"An incremental plan starts over with a full backup this often"`
	Retention      string   `json:"retention" enum:"days,gfs,forever" doc:"How old backups are deleted"`
	KeepDays       int32    `json:"keep_days" minimum:"1" maximum:"3650" doc:"For retention=days"`
	GFSDaily       int32    `json:"gfs_daily" minimum:"0" maximum:"1000" doc:"For retention=gfs: the newest backup of this many days"`
	GFSWeekly      int32    `json:"gfs_weekly" minimum:"0" maximum:"1000" doc:"… of this many weeks"`
	GFSMonthly     int32    `json:"gfs_monthly" minimum:"0" maximum:"1000" doc:"… of this many months"`
	RunnerServerID *string  `json:"runner_server_id,omitempty" format:"uuid" doc:"For a direct database: the server that runs the dump; empty = the machine Morcheh runs on. Ignored otherwise"`
	Username       string   `json:"username,omitempty" maxLength:"255" doc:"A login just for backups; empty = the database's own"`
	Password       string   `json:"password,omitempty" maxLength:"1024" doc:"Blank keeps the saved one"`
	Cron           string   `json:"cron,omitempty" maxLength:"128" doc:"When it runs; empty = only when started by hand" example:"0 3 * * *"`
	Timezone       string   `json:"timezone,omitempty" maxLength:"64" example:"Asia/Tehran"`
	Enabled        bool     `json:"enabled"`
}

// BackupRunBrief is a plan's newest finished run.
type BackupRunBrief struct {
	ID    string    `json:"id" format:"uuid"`
	State string    `json:"state"`
	Error string    `json:"error"`
	At    time.Time `json:"at"`
	Bytes int64     `json:"bytes"`
}

// BackupPlanStorage is one place a plan writes to.
type BackupPlanStorage struct {
	ID       string `json:"id" format:"uuid"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
}

// BackupPlan is a saved way of backing up a database.
type BackupPlan struct {
	ID             string              `json:"id" format:"uuid"`
	DatabaseID     string              `json:"database_id" format:"uuid"`
	Name           string              `json:"name"`
	Storages       []BackupPlanStorage `json:"storages"`
	Folder         string              `json:"folder"`
	Selection      string              `json:"selection" enum:"all,selected,pattern"`
	Targets        []string            `json:"targets"`
	Pattern        string              `json:"pattern"`
	Method         string              `json:"method" enum:"full,incremental"`
	FullEveryDays  int32               `json:"full_every_days"`
	Retention      string              `json:"retention" enum:"days,gfs,forever"`
	KeepDays       int32               `json:"keep_days"`
	GFSDaily       int32               `json:"gfs_daily"`
	GFSWeekly      int32               `json:"gfs_weekly"`
	GFSMonthly     int32               `json:"gfs_monthly"`
	RunnerServerID *string             `json:"runner_server_id" format:"uuid" nullable:"true"`
	RunnerName     string              `json:"runner_name" doc:"The server the dump runs on (\"This Morcheh server\" for Morcheh's own machine)"`
	Username       string              `json:"username"`
	HasPassword    bool                `json:"has_password"`
	Cron           string              `json:"cron"`
	Timezone       string              `json:"timezone"`
	Enabled        bool                `json:"enabled"`
	NextRunAt      *time.Time          `json:"next_run_at" nullable:"true"`
	RunsAs         string              `json:"runs_as" doc:"The person whose access it runs with: whoever saved it last"`
	Problem        string              `json:"problem" doc:"Why it can't run right now; empty when it can"`
	Running        bool                `json:"running"`
	Last           *BackupRunBrief     `json:"last,omitempty"`
	LastGoodAt     *time.Time          `json:"last_good_at" nullable:"true"`
	CreatedAt      time.Time           `json:"created_at"`
	UpdatedAt      time.Time           `json:"updated_at"`
}

// BackupCopy is a backup's file on one Storage.
type BackupCopy struct {
	StorageID   *string `json:"storage_id" format:"uuid" nullable:"true" doc:"Null when the storage was removed"`
	StorageName string  `json:"storage_name"`
	State       string  `json:"state" enum:"pending,stored,failed"`
	Error       string  `json:"error"`
}

// Backup is one database's run of a plan and, when it worked, the file it left.
type Backup struct {
	ID             string       `json:"id" format:"uuid"`
	DatabaseID     string       `json:"database_id" format:"uuid"`
	PlanID         *string      `json:"plan_id" format:"uuid" nullable:"true"`
	PlanName       string       `json:"plan_name"`
	Path           string       `json:"path" doc:"The same on every storage it was written to"`
	Engine         string       `json:"engine"`
	Target         string       `json:"target" doc:"The database it holds; empty = all of them"`
	Format         string       `json:"format"`
	Kind           string       `json:"kind" enum:"full,incremental"`
	ParentID       *string      `json:"parent_id" format:"uuid" nullable:"true" doc:"What an incremental builds on"`
	Dependents     int64        `json:"dependents" doc:"Incrementals that build on it directly"`
	Trigger        string       `json:"trigger" enum:"schedule,manual,restore"`
	State          string       `json:"state" enum:"queued,running,succeeded,failed,canceled,interrupted,skipped"`
	Error          string       `json:"error" doc:"Why it failed; on a backup that worked, a storage that didn't get its copy"`
	Bytes          int64        `json:"bytes"`
	SHA256         string       `json:"sha256"`
	Copies         []BackupCopy `json:"copies"`
	VerifiedAt     *time.Time   `json:"verified_at" nullable:"true" doc:"When the stored file was last read back"`
	VerifyError    string       `json:"verify_error" doc:"What that check found wrong; empty = it passed"`
	JobID          *string      `json:"job_id" format:"uuid" nullable:"true"`
	CreatedByName  string       `json:"created_by_name"`
	Restorable     bool         `json:"restorable" doc:"Morcheh can restore it from the panel"`
	RestoreProblem string       `json:"restore_problem" doc:"Why it can't be restored from the panel; empty when it can"`
	Restore        string       `json:"restore" doc:"The commands that bring it back by hand, for copying"`
	CreatedAt      time.Time    `json:"created_at"`
	StartedAt      *time.Time   `json:"started_at" nullable:"true"`
	FinishedAt     *time.Time   `json:"finished_at" nullable:"true"`
}

// BackupProblem is a plan whose newest run failed.
type BackupProblem struct {
	PlanID       string    `json:"plan_id" format:"uuid"`
	PlanName     string    `json:"plan_name"`
	DatabaseID   string    `json:"database_id" format:"uuid"`
	DatabaseName string    `json:"database_name"`
	Error        string    `json:"error"`
	At           time.Time `json:"at"`
}

// BackupIncremental says whether an engine can take incrementals.
type BackupIncremental struct {
	Supported bool   `json:"supported"`
	Note      string `json:"note" doc:"How it works, or why not"`
}

// BackupOptions is what a plan for this database can choose from.
type BackupOptions struct {
	Databases      []string          `json:"databases" doc:"The databases on it, without the system ones"`
	DatabasesError string            `json:"databases_error" doc:"Why they couldn't be listed; empty when they could"`
	Selections     []string          `json:"selections" doc:"Which ways of choosing databases work here"`
	SelectionNote  string            `json:"selection_note" doc:"Why some don't"`
	Incremental    BackupIncremental `json:"incremental"`
	Local          LocalTools        `json:"local" doc:"Whether the machine Morcheh runs on can run its backups and restores"`
}

// toBackups adds each backup's copies and how many incrementals build on it.
func (h *backupHandler) toBackups(ctx context.Context, rows []sqlc.DatabaseBackup) ([]Backup, error) {
	ids := make([]uuid.UUID, len(rows))
	for i, b := range rows {
		ids[i] = b.ID
	}
	copies, err := h.q.ListBackupCopies(ctx, ids)
	if err != nil {
		return nil, internalError(err)
	}
	children, err := h.q.CountBackupChildren(ctx, ids)
	if err != nil {
		return nil, internalError(err)
	}
	copiesOf := map[uuid.UUID][]BackupCopy{}
	for _, c := range copies {
		copiesOf[c.BackupID] = append(copiesOf[c.BackupID], BackupCopy{
			StorageID: optionalIDString(c.StorageID), StorageName: c.StorageName, State: c.State, Error: c.Error,
		})
	}
	childrenOf := map[uuid.UUID]int64{}
	for _, c := range children {
		if c.ParentID != nil {
			childrenOf[*c.ParentID] = c.Total
		}
	}
	out := make([]Backup, len(rows))
	for i, b := range rows {
		v := Backup{
			ID: b.ID.String(), DatabaseID: b.DatabaseID.String(), PlanID: optionalIDString(b.PlanID),
			PlanName: b.PlanName, Path: b.Path, Engine: b.Engine, Target: b.Target, Format: b.Format,
			Kind: b.Kind, ParentID: optionalIDString(b.ParentID), Dependents: childrenOf[b.ID],
			Trigger: b.Trigger, State: b.State, Error: b.Error, Bytes: b.Bytes, SHA256: b.Sha256,
			Copies: copiesOf[b.ID], VerifiedAt: b.VerifiedAt, VerifyError: b.VerifyError,
			JobID: optionalIDString(b.JobID), CreatedByName: b.CreatedByName,
			CreatedAt: b.CreatedAt, StartedAt: b.StartedAt, FinishedAt: b.FinishedAt,
		}
		if v.Copies == nil {
			v.Copies = []BackupCopy{}
		}
		if b.State == jobs.Succeeded {
			v.Restore = dbbackup.Restore(b.Format, b.Target, path.Base(b.Path))
			v.RestoreProblem = dbbackup.Restorable(b.Format, b.Target)
			if v.RestoreProblem == "" && !slices.ContainsFunc(v.Copies, func(c BackupCopy) bool {
				return c.State == "stored" && c.StorageID != nil
			}) {
				v.RestoreProblem = "None of its storages hold the file any more."
			}
			v.Restorable = v.RestoreProblem == ""
		}
		out[i] = v
	}
	return out, nil
}

func (h *backupHandler) toBackup(ctx context.Context, b sqlc.DatabaseBackup) (Backup, error) {
	items, err := h.toBackups(ctx, []sqlc.DatabaseBackup{b})
	if err != nil {
		return Backup{}, err
	}
	return items[0], nil
}

// ---- Handler ----

type backupHandler struct {
	q      *sqlc.Queries
	db     *databaseHandler
	st     *storageHandler
	authz  *authz
	runner *jobs.Runner
}

func newBackupHandler(db *databaseHandler, st *storageHandler, a *authz) *backupHandler {
	return &backupHandler{q: st.q, db: db, st: st, authz: a, runner: st.servers.jobs}
}

func (h *backupHandler) plan(ctx context.Context, rawID string) (sqlc.DatabaseBackupPlan, error) {
	p, err := h.q.GetBackupPlan(ctx, uuid.MustParse(rawID))
	if isNotFound(err) {
		return p, huma.Error404NotFound("backup plan not found")
	}
	if err != nil {
		return p, internalError(err)
	}
	return p, nil
}

func (h *backupHandler) backup(ctx context.Context, rawID string) (sqlc.DatabaseBackup, error) {
	b, err := h.q.GetBackup(ctx, uuid.MustParse(rawID))
	if isNotFound(err) {
		return b, huma.Error404NotFound("backup not found")
	}
	if err != nil {
		return b, internalError(err)
	}
	if h.syncRun(ctx, b) {
		if b, err = h.q.GetBackup(ctx, b.ID); err != nil {
			return b, internalError(err)
		}
	}
	return b, nil
}

// runAs is the person a plan acts as, with their access now.
func (h *backupHandler) runAs(ctx context.Context, p sqlc.DatabaseBackupPlan) (string, *auth.Access, error) {
	const removed = "The person who saved this plan was removed. Someone with access should open it and save it again."
	if p.UpdatedBy == nil {
		return "", nil, errors.New(removed)
	}
	u, err := h.q.GetUser(ctx, *p.UpdatedBy)
	if isNotFound(err) {
		return "", nil, errors.New(removed)
	}
	if err != nil {
		return "", nil, err
	}
	name := cmpOr(u.FullName, u.Username)
	if u.Status != "active" {
		return name, nil, fmt.Errorf("%s's account isn't active, so their backup plans don't run. Someone with access should open it and save it again.", name)
	}
	acc, err := h.authz.accessOf(ctx, u)
	return name, acc, err
}

// backupPlace is where a run happens.
type backupPlace struct {
	who      string
	server   sqlc.Server
	storages []sqlc.Storage
}

// ready finds what a run needs, with what it found so far when something is
// missing: the error says why the plan can't run.
func (h *backupHandler) ready(ctx context.Context, d sqlc.Database, p sqlc.DatabaseBackupPlan) (backupPlace, error) {
	var out backupPlace
	var problem error
	note := func(err error) {
		if problem == nil {
			problem = err
		}
	}
	who, acc, err := h.runAs(ctx, p)
	out.who = who
	note(err)

	ids, err := h.q.ListBackupPlanStorages(ctx, p.ID)
	if err != nil {
		note(err)
	}
	for _, id := range ids {
		s, err := h.q.GetStorage(ctx, id)
		if isNotFound(err) {
			continue
		}
		if err != nil {
			note(err)
			continue
		}
		out.storages = append(out.storages, s)
		switch {
		case s.ReadOnly:
			note(fmt.Errorf("%s is read-only in Morcheh, so nothing can be written to it.", s.Name))
		case acc != nil && acc.StorageLevel(d.WorkspaceID, s.ID) < auth.Engineer:
			note(fmt.Errorf("%s no longer has %s access to %s.", who, auth.Engineer, s.Name))
		}
	}
	if len(out.storages) == 0 && err == nil {
		note(errors.New("Its storages were removed. Choose another one."))
	}

	serverID := backupServer(d, p)
	switch {
	case serverID == nil && d.Mode == "direct":
		out.server.Name = LocalRunnerName
	case serverID == nil:
		note(errors.New("The server this database is reached through was removed."))
	default:
		if s, err := h.q.GetServer(ctx, *serverID); isNotFound(err) {
			note(errors.New("The server that runs it was removed. Choose another one."))
		} else if err != nil {
			note(err)
		} else {
			out.server = s
			if acc != nil && acc.ServerLevel(d.WorkspaceID, s.ID) < auth.Engineer {
				note(fmt.Errorf("%s no longer has %s access to %s.", who, auth.Engineer, s.Name))
			}
		}
	}

	if acc != nil && databaseLevelOf(acc, d) < auth.Owner {
		note(fmt.Errorf("%s no longer has %s access to %s.", who, auth.Owner, d.Name))
	}
	if problem == nil && p.Method == "incremental" && !dbbackup.Incremental(d.Engine).Supported {
		note(errors.New("This database can't take incremental backups. Change the plan to full."))
	}
	return out, problem
}

// backupServer is the server a plan's dump runs on; nil for a direct
// database = the machine Morcheh runs on.
func backupServer(d sqlc.Database, p sqlc.DatabaseBackupPlan) *uuid.UUID {
	if d.Mode == "direct" {
		return p.RunnerServerID
	}
	return d.ServerID
}

// views adds what a plan's list shows: last runs, problems, names.
func (h *backupHandler) views(ctx context.Context, d sqlc.Database, plans []sqlc.DatabaseBackupPlan) ([]BackupPlan, error) {
	ids := make([]uuid.UUID, len(plans))
	for i, p := range plans {
		ids[i] = p.ID
	}
	last, err := h.q.LastBackups(ctx, ids)
	if err != nil {
		return nil, internalError(err)
	}
	good, err := h.q.LastGoodBackupTimes(ctx, ids)
	if err != nil {
		return nil, internalError(err)
	}
	lastOf := map[uuid.UUID]sqlc.LastBackupsRow{}
	for _, l := range last {
		if l.PlanID != nil {
			lastOf[*l.PlanID] = l
		}
	}
	goodOf := map[uuid.UUID]time.Time{}
	for _, g := range good {
		if g.PlanID != nil {
			goodOf[*g.PlanID] = g.At
		}
	}

	owner := databaseLevelOf(principalOf(ctx).Access, d) >= auth.Owner
	out := make([]BackupPlan, len(plans))
	for i, p := range plans {
		place, problem := h.ready(ctx, d, p)
		v := BackupPlan{
			ID: p.ID.String(), DatabaseID: p.DatabaseID.String(), Name: p.Name,
			Storages: make([]BackupPlanStorage, len(place.storages)), Folder: p.Folder,
			Selection: p.Selection, Targets: p.Targets, Pattern: p.Pattern, Method: p.Method,
			FullEveryDays: p.FullEveryDays, Retention: p.Retention, KeepDays: p.KeepDays,
			GFSDaily: p.GfsDaily, GFSWeekly: p.GfsWeekly, GFSMonthly: p.GfsMonthly,
			RunnerServerID: optionalIDString(p.RunnerServerID), RunnerName: place.server.Name,
			Username: p.Username, HasPassword: len(p.PasswordEnc) > 0, Cron: p.Cron,
			Timezone: p.Timezone, Enabled: p.Enabled, NextRunAt: p.NextRunAt, RunsAs: place.who,
			CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
		}
		for j, s := range place.storages {
			v.Storages[j] = BackupPlanStorage{ID: s.ID.String(), Name: s.Name, Protocol: s.Protocol}
		}
		if v.Targets == nil {
			v.Targets = []string{}
		}
		if !owner {
			v.Username = ""
		}
		if problem != nil {
			v.Problem = problemText(problem)
		}
		if v.Running, err = h.busy(ctx, p.ID); err != nil {
			return nil, internalError(err)
		}
		if l, ok := lastOf[p.ID]; ok {
			at := l.CreatedAt
			if l.FinishedAt != nil {
				at = *l.FinishedAt
			}
			v.Last = &BackupRunBrief{ID: l.ID.String(), State: l.State, Error: l.Error, At: at, Bytes: l.Bytes}
		}
		if at, ok := goodOf[p.ID]; ok {
			v.LastGoodAt = &at
		}
		out[i] = v
	}
	return out, nil
}

func (h *backupHandler) view(ctx context.Context, d sqlc.Database, p sqlc.DatabaseBackupPlan) (BackupPlan, error) {
	items, err := h.views(ctx, d, []sqlc.DatabaseBackupPlan{p})
	if err != nil {
		return BackupPlan{}, err
	}
	return items[0], nil
}

// ---- Saving a plan ----

type checkedPlan struct {
	storages []uuid.UUID
	folder   string
	targets  []string
	pattern  string
	runner   *uuid.UUID
	cron     string
	timezone string
	next     *time.Time
}

func (h *backupHandler) check(ctx context.Context, d sqlc.Database, b BackupPlanBody) (checkedPlan, error) {
	out := checkedPlan{
		cron:     strings.TrimSpace(b.Cron),
		timezone: cmpOr(strings.TrimSpace(b.Timezone), "UTC"),
		pattern:  strings.TrimSpace(b.Pattern),
	}
	acc := principalOf(ctx).Access

	folder := strings.TrimSpace(b.Folder)
	if err := backupFolderProblem(folder); err != "" {
		return out, fieldError("body.folder", err, b.Folder)
	}
	out.folder = storage.Clean(folder)

	for i, raw := range b.StorageIDs {
		loc := fmt.Sprintf("body.storage_ids[%d]", i)
		id, err := uuid.Parse(raw)
		if err != nil {
			return out, fieldError(loc, "Choose a storage.", raw)
		}
		if slices.Contains(out.storages, id) {
			continue
		}
		s, err := h.q.GetStorage(ctx, id)
		if isNotFound(err) || (err == nil && s.WorkspaceID != d.WorkspaceID) {
			return out, fieldError(loc, "This storage isn't in this workspace.", raw)
		}
		if err != nil {
			return out, internalError(err)
		}
		if s.ReadOnly {
			return out, fieldError(loc, s.Name+" is read-only in Morcheh, so nothing can be written to it.", raw)
		}
		if acc.StorageLevel(d.WorkspaceID, s.ID) < auth.Engineer {
			return out, fieldError(loc, fmt.Sprintf("You need %s access to %s.", auth.Engineer, s.Name), raw)
		}
		if s.Protocol == storage.ProtoS3 && s.Bucket == "" && strings.Count(strings.Trim(out.folder, "/"), "/") == 0 && !strings.Contains(out.folder, "{") && out.folder == "/" {
			return out, fieldError("body.folder", "Files on "+s.Name+" go inside a bucket: start the path with one.", b.Folder)
		}
		if s.Protocol == storage.ProtoS3 && s.Bucket == "" && strings.HasPrefix(out.folder, "/{") {
			return out, fieldError("body.folder", "Files on "+s.Name+" go inside a bucket: start the path with its name, not a date.", b.Folder)
		}
		out.storages = append(out.storages, s.ID)
	}
	if len(out.storages) == 0 {
		return out, fieldError("body.storage_ids", "Choose a storage.", "")
	}
	if len(out.storages) > backupMaxStorages {
		return out, fieldError("body.storage_ids", fmt.Sprintf("Choose at most %d storages.", backupMaxStorages), "")
	}

	for _, t := range b.Targets {
		if t = strings.TrimSpace(t); t != "" && !slices.Contains(out.targets, t) {
			out.targets = append(out.targets, t)
		}
	}
	if b.Selection != "selected" {
		out.targets = nil
	}
	if b.Selection != "pattern" {
		out.pattern = ""
	}
	if field, msg := backupSelectionProblem(d, b.Selection, out.targets, out.pattern); msg != "" {
		return out, fieldError("body."+field, msg, "")
	}
	if b.Method == "incremental" {
		if inc := dbbackup.Incremental(d.Engine); !inc.Supported {
			return out, fieldError("body.method", inc.Note, b.Method)
		}
	}

	if d.Mode == "direct" {
		// None = the machine Morcheh runs on.
		runner := parseOptionalID(b.RunnerServerID)
		if runner == nil {
			if lt := localTools(d); !lt.Supported {
				return out, fieldError("body.runner_server_id", lt.Note, "")
			}
		} else {
			srv, err := h.q.GetServer(ctx, *runner)
			if isNotFound(err) || (err == nil && srv.WorkspaceID != d.WorkspaceID) {
				return out, fieldError("body.runner_server_id", "This server isn't in this workspace.", *b.RunnerServerID)
			}
			if err != nil {
				return out, internalError(err)
			}
			if acc.ServerLevel(d.WorkspaceID, srv.ID) < auth.Engineer {
				return out, fieldError("body.runner_server_id", fmt.Sprintf("You need %s access to %s.", auth.Engineer, srv.Name), *b.RunnerServerID)
			}
		}
		out.runner = runner
	} else if d.ServerID == nil {
		return out, huma.Error422UnprocessableEntity("The server this database is reached through was removed.")
	}

	if _, err := time.LoadLocation(out.timezone); err != nil {
		return out, fieldError("body.timezone", "Unknown time zone.", b.Timezone)
	}
	if out.cron != "" {
		if _, _, err := parseCron(out.cron, out.timezone); err != nil {
			return out, err
		}
		if b.Enabled {
			out.next = nextRun(out.cron, out.timezone, time.Now())
		}
	}
	return out, nil
}

// backupFolderPlaces are what a plan's folder may hold, filled in at each run.
var backupFolderPlaces = strings.NewReplacer("{year}", "2006", "{month}", "01", "{day}", "02")

// backupFolder fills in a plan's folder for a run at this time.
func backupFolder(folder string, at time.Time) string {
	return storage.Clean(strings.NewReplacer(
		"{year}", at.Format("2006"), "{month}", at.Format("01"), "{day}", at.Format("02"),
	).Replace(folder))
}

// backupFolderProblem says what's wrong with a plan's folder.
func backupFolderProblem(folder string) string {
	if !strings.HasPrefix(folder, "/") || strings.ContainsRune(folder, 0) {
		return "Use a full path, starting with /."
	}
	if strings.ContainsAny(backupFolderPlaces.Replace(folder), "{}") {
		return "Only {year}, {month} and {day} can be filled in."
	}
	return ""
}

// backupSelectionProblem says why a plan's "what to back up" can't work, and
// which field is wrong.
func backupSelectionProblem(d sqlc.Database, selection string, targets []string, pattern string) (string, string) {
	switch d.Engine {
	case dbmon.Redis:
		if selection != "all" {
			return "selection", "Redis backs up everything at once."
		}
	case dbmon.MSSQL:
		if !local(d) {
			return "selection", "SQL Server writes its backup to its own disk, so it has to be reached on its own server (or in a container there)."
		}
	}
	switch selection {
	case "selected":
		if len(targets) == 0 {
			return "targets", "Choose at least one database."
		}
		for _, t := range targets {
			if err := dbbackup.CheckName(t); err != nil {
				return "targets", err.Error()
			}
		}
	case "pattern":
		if pattern == "" {
			return "pattern", "Write a pattern that matches the databases' names."
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return "pattern", "This pattern doesn't work: " + strings.TrimPrefix(err.Error(), "error parsing regexp: ")
		}
	}
	return "", ""
}

// systemDatabases are left out of "all" and patterns: the engine's own.
var systemDatabases = map[string][]string{
	dbmon.Postgres: {"postgres", "template0", "template1", "rdsadmin", "azure_maintenance", "azure_sys", "cloudsqladmin"},
	dbmon.MySQL:    {"mysql", "sys", "performance_schema", "information_schema"},
	dbmon.Mongo:    {"admin", "local", "config"},
	dbmon.MSSQL:    {"master", "model", "msdb", "tempdb", "rdsadmin"},
}

// listDatabases is what a database server holds, without its own.
func (h *backupHandler) listDatabases(ctx context.Context, d sqlc.Database) ([]string, error) {
	live := h.db.live(ctx, d)
	s := live.Snapshot
	if s == nil {
		return nil, fmt.Errorf("Couldn't reach the database to list what it holds: %s", cmpOr(live.Message, "it didn't answer"))
	}
	if len(s.Databases) == 0 {
		heavy, err := h.db.collect(ctx, d, true)
		if err != nil {
			return nil, fmt.Errorf("Couldn't list what the database holds: %s", problemText(err))
		}
		s = heavy
	}
	var out []string
	for _, db := range s.Databases {
		if slices.Contains(systemDatabases[d.Engine], db.Name) {
			continue
		}
		// SQL Server can only back up a database that's online.
		if d.Engine == dbmon.MSSQL && db.State != "" && !strings.EqualFold(db.State, "ONLINE") {
			continue
		}
		out = append(out, db.Name)
	}
	slices.Sort(out)
	return out, nil
}

// targetsOf is the databases a run of the plan backs up, each a backup of its
// own. Redis has one, the whole server ("").
func (h *backupHandler) targetsOf(ctx context.Context, d sqlc.Database, p sqlc.DatabaseBackupPlan) ([]string, error) {
	if d.Engine == dbmon.Redis {
		return []string{""}, nil
	}
	if p.Selection == "selected" {
		return p.Targets, nil
	}
	names, err := h.listDatabases(ctx, d)
	if err != nil {
		return nil, err
	}
	if p.Selection == "pattern" {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil, fmt.Errorf("Its pattern doesn't work: %w", err)
		}
		names = slices.DeleteFunc(names, func(n string) bool { return !re.MatchString(n) })
		if len(names) == 0 {
			return nil, fmt.Errorf("No database matches %s.", p.Pattern)
		}
	}
	if len(names) == 0 {
		return nil, errors.New("The database server holds no databases of its own to back up.")
	}
	// A name dbbackup won't quote stays out, with the reason in the log.
	return slices.DeleteFunc(names, func(n string) bool { return dbbackup.CheckName(n) != nil }), nil
}

// sealLogin is what a plan stores as its login: none, the new password, or
// what's saved when the password was left blank.
func (h *backupHandler) sealLogin(b BackupPlanBody, prev []byte) (string, []byte) {
	user := strings.TrimSpace(b.Username)
	switch {
	case user == "":
		return "", nil
	case b.Password != "":
		return user, h.db.box.Seal(b.Password)
	}
	return user, prev
}

func uniquePlanName(err error) error {
	if isUniqueViolation(err) {
		return fieldError("body.name", "This database already has a plan with that name.", "")
	}
	return internalError(err)
}

func optionalIDValue(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// backupSlug makes a database's name safe as a folder.
func backupSlug(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		if r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(r)
			dash = false
			continue
		}
		dash = true
	}
	return cmpOr(b.String(), "database")
}

// backupPath is where a run's file goes:
// {folder}/{database}/{target}_{time}_{id}.{ext}. The end of the run's id keeps
// two runs in one second from sharing a file, which retention would then
// delete from under the other.
func backupPath(folder, database, target string, at time.Time, id uuid.UUID, ext string) string {
	sum := id.String()
	return path.Join(storage.Clean(folder), backupSlug(database),
		cmpOr(backupSlugOf(target), "all")+"_"+at.Format("2006-01-02_15-04-05")+"_"+sum[len(sum)-6:]+"."+ext)
}

// backupSlugOf is backupSlug for what may be empty.
func backupSlugOf(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return backupSlug(s)
}

// ---- API ----

type BackupPlanIDPath struct {
	ID string `path:"id" format:"uuid"`
}

type BackupIDPath struct {
	ID string `path:"id" format:"uuid"`
}

type BackupPlanOutput struct {
	Body BackupPlan
}

type BackupOutput struct {
	Body Backup
}

type BackupOptionsOutput struct {
	Body BackupOptions
}

func registerDatabaseBackups(api huma.API, h *backupHandler) {
	tags := []string{"Database backups"}
	h.runner.Handle(backupKind, h.runJob)
	h.runner.Handle(backupVerifyKind, h.runVerify)
	h.runner.Handle(restoreKind, h.runRestore)

	type planList struct {
		Body struct {
			Items []BackupPlan `json:"items"`
		}
	}

	huma.Register(api, huma.Operation{
		OperationID: "get-database-backup-options",
		Method:      http.MethodGet,
		Path:        "/databases/{id}/backup-options",
		Summary:     "What a backup plan for this database can choose from",
		Description: "Lists its databases (it connects to do so) and says which ways of choosing them, and whether incrementals, work here.",
		Tags:        tags,
	}, func(ctx context.Context, in *DatabaseIDPath) (*BackupOptionsOutput, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		inc := dbbackup.Incremental(d.Engine)
		out := BackupOptions{
			Databases:   []string{},
			Selections:  []string{"all", "selected", "pattern"},
			Incremental: BackupIncremental{Supported: inc.Supported, Note: inc.Note},
			Local:       localTools(d),
		}
		if d.Engine == dbmon.Redis {
			out.Selections = []string{"all"}
			out.SelectionNote = "Redis backs up everything at once."
			return &BackupOptionsOutput{Body: out}, nil
		}
		if names, err := h.listDatabases(ctx, d); err != nil {
			out.DatabasesError = problemText(err)
		} else if names != nil {
			out.Databases = names
		}
		return &BackupOptionsOutput{Body: out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-database-backup-plans",
		Method:      http.MethodGet,
		Path:        "/databases/{id}/backup-plans",
		Summary:     "List a database's backup plans",
		Tags:        tags,
	}, func(ctx context.Context, in *DatabaseIDPath) (*planList, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		rows, err := h.q.ListBackupPlans(ctx, d.ID)
		if err != nil {
			return nil, internalError(err)
		}
		out := &planList{}
		out.Body.Items, err = h.views(ctx, d, rows)
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-database-backup-plan",
		Method:      http.MethodGet,
		Path:        "/database-backup-plans/{id}",
		Summary:     "Get a backup plan",
		Tags:        tags,
	}, func(ctx context.Context, in *BackupPlanIDPath) (*BackupPlanOutput, error) {
		p, err := h.plan(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		d, err := h.q.GetDatabase(ctx, p.DatabaseID)
		if err != nil {
			return nil, internalError(err)
		}
		v, err := h.view(ctx, d, p)
		return &BackupPlanOutput{Body: v}, err
	})

	save := func(ctx context.Context, d sqlc.Database, prev *sqlc.DatabaseBackupPlan, body BackupPlanBody) (*BackupPlanOutput, error) {
		c, err := h.check(ctx, d, body)
		if err != nil {
			return nil, err
		}
		var sealedPrev []byte
		if prev != nil {
			sealedPrev = prev.PasswordEnc
		}
		user, sealed := h.sealLogin(body, sealedPrev)
		name := strings.TrimSpace(body.Name)
		targets := c.targets
		if targets == nil {
			targets = []string{}
		}
		var p sqlc.DatabaseBackupPlan
		tx, err := h.st.servers.db.Begin(ctx)
		if err != nil {
			return nil, internalError(err)
		}
		defer tx.Rollback(ctx)
		q := h.q.WithTx(tx)
		if prev == nil {
			p, err = q.CreateBackupPlan(ctx, sqlc.CreateBackupPlanParams{
				WorkspaceID: d.WorkspaceID, DatabaseID: d.ID, Name: name, Folder: c.folder,
				Selection: body.Selection, Targets: targets, Pattern: c.pattern, Method: body.Method,
				FullEveryDays: body.FullEveryDays, Retention: body.Retention, KeepDays: body.KeepDays,
				GfsDaily: body.GFSDaily, GfsWeekly: body.GFSWeekly, GfsMonthly: body.GFSMonthly,
				RunnerServerID: c.runner, Username: user, PasswordEnc: sealed, Cron: c.cron,
				Timezone: c.timezone, Enabled: body.Enabled, NextRunAt: c.next,
				CreatedBy: principalOf(ctx).ID(),
			})
		} else {
			p, err = q.UpdateBackupPlan(ctx, sqlc.UpdateBackupPlanParams{
				ID: prev.ID, Name: name, Folder: c.folder, Selection: body.Selection, Targets: targets,
				Pattern: c.pattern, Method: body.Method, FullEveryDays: body.FullEveryDays,
				Retention: body.Retention, KeepDays: body.KeepDays, GfsDaily: body.GFSDaily,
				GfsWeekly: body.GFSWeekly, GfsMonthly: body.GFSMonthly, RunnerServerID: c.runner,
				Username: user, PasswordEnc: sealed, Cron: c.cron, Timezone: c.timezone,
				Enabled: body.Enabled, NextRunAt: c.next, UpdatedBy: principalOf(ctx).ID(),
			})
		}
		if err != nil {
			return nil, uniquePlanName(err)
		}
		if err := q.SetBackupPlanStorages(ctx, sqlc.SetBackupPlanStoragesParams{PlanID: p.ID, StorageIds: c.storages}); err != nil {
			return nil, internalError(err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, internalError(err)
		}
		v, err := h.view(ctx, d, p)
		return &BackupPlanOutput{Body: v}, err
	}

	huma.Register(api, huma.Operation{
		OperationID:   "create-database-backup-plan",
		Method:        http.MethodPost,
		Path:          "/databases/{id}/backup-plans",
		Summary:       "Add a backup plan",
		DefaultStatus: http.StatusCreated,
		Tags:          tags,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Body BackupPlanBody
	}) (*BackupPlanOutput, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return save(ctx, d, nil, in.Body)
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-database-backup-plan",
		Method:      http.MethodPut,
		Path:        "/database-backup-plans/{id}",
		Summary:     "Change a backup plan",
		Description: "It runs with the access of whoever saves it last.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		BackupPlanIDPath
		Body BackupPlanBody
	}) (*BackupPlanOutput, error) {
		prev, err := h.plan(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		d, err := h.q.GetDatabase(ctx, prev.DatabaseID)
		if err != nil {
			return nil, internalError(err)
		}
		return save(ctx, d, &prev, in.Body)
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-database-backup-plan",
		Method:        http.MethodDelete,
		Path:          "/database-backup-plans/{id}",
		Summary:       "Delete a backup plan",
		Description:   "Its backups stay, in the list and on the Storages.",
		DefaultStatus: http.StatusNoContent,
		Tags:          tags,
	}, func(ctx context.Context, in *BackupPlanIDPath) (*struct{}, error) {
		p, err := h.plan(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		busy, err := h.busy(ctx, p.ID)
		if err != nil {
			return nil, internalError(err)
		}
		if busy {
			return nil, huma.Error409Conflict("It's running now. Wait for it to finish, or stop it first.")
		}
		if _, err := h.q.DeleteBackupPlan(ctx, p.ID); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "run-database-backup-plan",
		Method:        http.MethodPost,
		Path:          "/database-backup-plans/{id}/run",
		Summary:       "Back up now",
		DefaultStatus: http.StatusAccepted,
		Tags:          tags,
	}, func(ctx context.Context, in *BackupPlanIDPath) (*JobOutput, error) {
		p, err := h.plan(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		job, err := h.start(ctx, p, principalOf(ctx))
		if err != nil {
			return nil, err
		}
		return &JobOutput{Body: toJob(*job, false)}, nil
	})

	type backupList struct {
		Body struct {
			Items []Backup `json:"items"`
			Total int64    `json:"total"`
		}
	}

	huma.Register(api, huma.Operation{
		OperationID: "list-database-backups",
		Method:      http.MethodGet,
		Path:        "/databases/{id}/backups",
		Summary:     "List a database's backups, newest first",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Limit  int32 `query:"limit" minimum:"1" maximum:"200" default:"50"`
		Offset int32 `query:"offset" minimum:"0"`
	}) (*backupList, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		params := sqlc.ListBackupsParams{DatabaseID: d.ID, Lim: in.Limit, Off: in.Offset}
		rows, err := h.q.ListBackups(ctx, params)
		if err != nil {
			return nil, internalError(err)
		}
		synced := false
		for _, r := range rows {
			synced = h.syncRun(ctx, r) || synced
		}
		if synced {
			if rows, err = h.q.ListBackups(ctx, params); err != nil {
				return nil, internalError(err)
			}
		}
		total, err := h.q.CountBackups(ctx, d.ID)
		if err != nil {
			return nil, internalError(err)
		}
		out := &backupList{}
		out.Body.Total = total
		out.Body.Items, err = h.toBackups(ctx, rows)
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-database-backup",
		Method:      http.MethodGet,
		Path:        "/database-backups/{id}",
		Summary:     "Get a backup",
		Tags:        tags,
	}, func(ctx context.Context, in *BackupIDPath) (*BackupOutput, error) {
		b, err := h.backup(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		v, err := h.toBackup(ctx, b)
		return &BackupOutput{Body: v}, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "cancel-database-backup",
		Method:      http.MethodPost,
		Path:        "/database-backups/{id}/cancel",
		Summary:     "Stop a backup that's running",
		Description: "Stops the whole run: other databases of it that haven't finished stop too.",
		Tags:        tags,
	}, func(ctx context.Context, in *BackupIDPath) (*BackupOutput, error) {
		b, err := h.backup(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if !jobs.Active(b.State) {
			return nil, huma.Error409Conflict("It has finished already.")
		}
		if b.JobID == nil {
			return nil, huma.Error409Conflict("It's only just starting. Try again in a moment.")
		}
		if _, err := h.runner.Cancel(ctx, *b.JobID); err != nil && !errors.Is(err, jobs.ErrNotFound) && !errors.Is(err, jobs.ErrFinished) {
			return nil, jobProblem(err)
		}
		if b, err = h.backup(ctx, in.ID); err != nil {
			return nil, err
		}
		v, err := h.toBackup(ctx, b)
		return &BackupOutput{Body: v}, err
	})

	huma.Register(api, huma.Operation{
		OperationID:   "verify-database-backup",
		Method:        http.MethodPost,
		Path:          "/database-backups/{id}/verify",
		Summary:       "Read a backup back and check it",
		Description:   "Reads every stored copy and compares its size and checksum with what was sent, and looks at its format. It doesn't restore anything.",
		DefaultStatus: http.StatusAccepted,
		Tags:          tags,
	}, func(ctx context.Context, in *BackupIDPath) (*JobOutput, error) {
		b, err := h.backup(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if b.State != jobs.Succeeded {
			return nil, huma.Error409Conflict("Only a backup that finished can be checked.")
		}
		stored, err := h.storedCopies(ctx, b.ID)
		if err != nil {
			return nil, internalError(err)
		}
		if len(stored) == 0 {
			return nil, huma.Error409Conflict("None of its storages hold the file any more.")
		}
		refs := make([]uuid.UUID, len(stored))
		for i, c := range stored {
			refs[i] = *c.StorageID
		}
		return submit(ctx, h.runner, jobs.Spec{
			Kind:   backupVerifyKind,
			Title:  "Check backup " + path.Base(b.Path),
			Params: backupParams{Backup: b.ID.String()},
			Refs:   refs,
			Target: JobPlace{StorageID: stored[0].StorageID.String(), Path: path.Dir(b.Path), Name: stored[0].StorageName, DatabaseID: b.DatabaseID.String()},
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "download-database-backup",
		Method:      http.MethodGet,
		Path:        "/database-backups/{id}/download",
		Summary:     "Download a backup's file",
		Description: "From the storage named, or else the first one holding it that the caller can read.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		BackupIDPath
		Storage string `query:"storage" format:"uuid" required:"false" doc:"Which copy"`
	}) (*huma.StreamResponse, error) {
		b, err := h.backup(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if b.State != jobs.Succeeded {
			return nil, huma.Error409Conflict("This run didn't leave a file.")
		}
		stored, err := h.storedCopies(ctx, b.ID)
		if err != nil {
			return nil, internalError(err)
		}
		acc := principalOf(ctx).Access
		var row sqlc.Storage
		var refused error = huma.Error409Conflict("None of its storages hold the file any more.")
		for _, c := range stored {
			if in.Storage != "" && c.StorageID.String() != in.Storage {
				continue
			}
			s, err := h.q.GetStorage(ctx, *c.StorageID)
			if err != nil {
				continue
			}
			if acc.StorageLevel(s.WorkspaceID, s.ID) < auth.Operator {
				refused = huma.Error403Forbidden(fmt.Sprintf("You need %s access to %s.", auth.Operator, s.Name))
				continue
			}
			row = s
			break
		}
		if row.ID == uuid.Nil {
			return nil, refused
		}
		c, err := h.st.acquire(ctx, row)
		if err != nil {
			return nil, err
		}
		file, err := c.fs.Open(ctx, b.Path)
		if err != nil {
			h.st.release(c)
			return nil, storageProblem(b.Path, err)
		}
		return &huma.StreamResponse{Body: func(hctx huma.Context) {
			defer h.st.release(c)
			defer file.Close()
			r, w := humachi.Unwrap(hctx)
			w.Header().Set("X-Content-Type-Options", "nosniff")
			serveStorageFile(w, r, file, false, c.fs.Capabilities().Ranges)
		}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-database-backup",
		Method:        http.MethodDelete,
		Path:          "/database-backups/{id}",
		Summary:       "Delete a backup and its files",
		Description:   "Deletes its file from every storage, and the incrementals that build on it with theirs.",
		DefaultStatus: http.StatusNoContent,
		Tags:          tags,
	}, func(ctx context.Context, in *BackupIDPath) (*struct{}, error) {
		b, err := h.backup(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if jobs.Active(b.State) {
			return nil, huma.Error409Conflict("It's running now. Stop it first.")
		}
		dependents, err := h.q.BackupDependents(ctx, &b.ID)
		if err != nil {
			return nil, internalError(err)
		}
		acc := principalOf(ctx).Access
		for _, id := range append(dependents, b.ID) {
			stored, err := h.storedCopies(ctx, id)
			if err != nil {
				return nil, internalError(err)
			}
			for _, c := range stored {
				row, err := h.q.GetStorage(ctx, *c.StorageID)
				switch {
				case isNotFound(err):
				case err != nil:
					return nil, internalError(err)
				case row.ReadOnly:
					return nil, huma.Error409Conflict(row.Name + " is read-only in Morcheh, so the file can't be deleted.")
				case acc.StorageLevel(row.WorkspaceID, row.ID) < auth.Engineer:
					return nil, huma.Error403Forbidden(fmt.Sprintf("You need %s access to %s.", auth.Engineer, row.Name))
				}
			}
		}
		if err := h.deleteWithDependents(ctx, b, nil); err != nil {
			return nil, storageProblem(b.Path, err)
		}
		return nil, nil
	})

	type problemList struct {
		Body struct {
			Items []BackupProblem `json:"items"`
		}
	}

	huma.Register(api, huma.Operation{
		OperationID: "list-database-backup-problems",
		Method:      http.MethodGet,
		Path:        "/database-backup-problems",
		Summary:     "Backup plans whose newest run failed",
		Tags:        tags,
	}, func(ctx context.Context, _ *struct{}) (*problemList, error) {
		s := principalOf(ctx).scope()
		rows, err := h.q.ListBackupProblems(ctx, sqlc.ListBackupProblemsParams{
			SeeAll: s.seeAll, WorkspaceIds: s.workspaces, ServerIds: s.servers, WorkspaceID: s.current,
		})
		if err != nil {
			return nil, internalError(err)
		}
		out := &problemList{}
		out.Body.Items = make([]BackupProblem, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = BackupProblem{
				PlanID: r.PlanID.String(), PlanName: r.PlanName, DatabaseID: r.DatabaseID.String(),
				DatabaseName: r.DatabaseName, Error: r.Error, At: r.CreatedAt,
			}
		}
		return out, nil
	})

	registerDatabaseRestores(api, h, tags)
}

// storedCopies are a backup's copies that hold its file on a storage that's
// still there.
func (h *backupHandler) storedCopies(ctx context.Context, id uuid.UUID) ([]sqlc.DatabaseBackupCopy, error) {
	copies, err := h.q.ListBackupCopies(ctx, []uuid.UUID{id})
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(copies, func(c sqlc.DatabaseBackupCopy) bool {
		return c.State != "stored" || c.StorageID == nil
	}), nil
}

// keep slog in use for files that only log through it here.
var _ = slog.Warn
