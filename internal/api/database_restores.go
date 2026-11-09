package api

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/dbbackup"
	"github.com/morcheh/backend/internal/dbmon"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/storage"
)

// restoreKind loads a backup (and what it builds on) back into a database.
const restoreKind = "database-backup-restore"

// RestoreBody is what to restore into and how.
type RestoreBody struct {
	TargetName     string `json:"target_name" minLength:"1" maxLength:"128" doc:"The database to load it into"`
	Mode           string `json:"mode" enum:"replace,new" doc:"replace = overwrite a database that exists; new = create one"`
	Confirm        string `json:"confirm,omitempty" maxLength:"128" doc:"For replace: the target's name typed again"`
	SafetyBackup   bool   `json:"safety_backup,omitempty" doc:"For replace: back the target up first, to the same storage"`
	StorageID      string `json:"storage_id,omitempty" maxLength:"36" doc:"Which storage to read it from; empty = the first that holds all of it"`
	RunnerServerID string `json:"runner_server_id,omitempty" maxLength:"36" doc:"For a direct database: the server the restore runs on, or \"local\" for the machine Morcheh runs on; empty = the plan's (Morcheh's machine when there's no plan)"`
	Username       string `json:"username,omitempty" maxLength:"256" doc:"A login for this restore only; empty = the database's saved one"`
	Password       string `json:"password,omitempty" maxLength:"1024"`
}

// BackupRestore is one restore and how it went.
type BackupRestore struct {
	ID             string     `json:"id" format:"uuid"`
	DatabaseID     string     `json:"database_id" format:"uuid"`
	BackupID       *string    `json:"backup_id" format:"uuid" nullable:"true" doc:"Null when the backup was deleted since"`
	Source         string     `json:"source" doc:"The backup's file"`
	TargetName     string     `json:"target_name"`
	Mode           string     `json:"mode" enum:"replace,new"`
	StorageName    string     `json:"storage_name"`
	WantSafety     bool       `json:"want_safety"`
	SafetyBackupID *string    `json:"safety_backup_id" format:"uuid" nullable:"true" doc:"The backup taken just before"`
	State          string     `json:"state" enum:"queued,running,succeeded,failed,canceled,interrupted"`
	Error          string     `json:"error"`
	JobID          *string    `json:"job_id" format:"uuid" nullable:"true"`
	CreatedByName  string     `json:"created_by_name"`
	CreatedAt      time.Time  `json:"created_at"`
	StartedAt      *time.Time `json:"started_at" nullable:"true"`
	FinishedAt     *time.Time `json:"finished_at" nullable:"true"`
}

type restoreParams struct {
	Restore string `json:"restore"`
}

// restoreChain is a backup and everything it builds on, oldest first, once
// it's known it can be restored from the panel.
func (h *backupHandler) restoreChain(ctx context.Context, b sqlc.DatabaseBackup) ([]sqlc.DatabaseBackup, error) {
	if b.State != jobs.Succeeded {
		return nil, huma.Error409Conflict("Only a backup that finished can be restored.")
	}
	chain, err := h.q.BackupChain(ctx, b.ID)
	if err != nil {
		return nil, internalError(err)
	}
	if len(chain) == 0 || chain[0].Kind != "full" {
		return nil, huma.Error409Conflict("The full backup this one builds on is gone, so it can't be restored.")
	}
	for _, m := range chain {
		if m.State != jobs.Succeeded {
			return nil, huma.Error409Conflict("A backup this one builds on didn't finish, so it can't be restored.")
		}
		if why := dbbackup.Restorable(m.Format, m.Target); why != "" {
			return nil, huma.Error422UnprocessableEntity(why)
		}
	}
	return chain, nil
}

// chainStorages are the storages holding every file of the chain, in the
// order the newest backup lists them.
func (h *backupHandler) chainStorages(ctx context.Context, chain []sqlc.DatabaseBackup) ([]sqlc.DatabaseBackupCopy, error) {
	ids := make([]uuid.UUID, len(chain))
	for i, b := range chain {
		ids[i] = b.ID
	}
	copies, err := h.q.ListBackupCopies(ctx, ids)
	if err != nil {
		return nil, err
	}
	last := chain[len(chain)-1].ID
	var out []sqlc.DatabaseBackupCopy
	for _, c := range copies {
		if c.BackupID != last || c.State != "stored" || c.StorageID == nil {
			continue
		}
		whole := true
		for _, b := range chain {
			if !slices.ContainsFunc(copies, func(o sqlc.DatabaseBackupCopy) bool {
				return o.BackupID == b.ID && o.State == "stored" && o.StorageID != nil && *o.StorageID == *c.StorageID
			}) {
				whole = false
				break
			}
		}
		if whole {
			out = append(out, c)
		}
	}
	return out, nil
}

// databaseNames lists every database on the server, system ones too, so a
// restore knows what it would overwrite.
func (h *backupHandler) databaseNames(ctx context.Context, d sqlc.Database) ([]string, error) {
	live := h.db.live(ctx, d)
	s := live.Snapshot
	if s == nil || len(s.Databases) == 0 {
		heavy, err := h.db.collect(ctx, d, true)
		if err != nil {
			return nil, fmt.Errorf("Couldn't reach the database to see what it holds: %s", problemText(err))
		}
		s = heavy
	}
	out := make([]string, len(s.Databases))
	for i, db := range s.Databases {
		out[i] = db.Name
	}
	return out, nil
}

// syncRestore ends a stored restore whose job ended without it.
func (h *backupHandler) syncRestore(ctx context.Context, r sqlc.DatabaseRestore) bool {
	if !jobs.Active(r.State) {
		return false
	}
	end := func(state, msg string) bool {
		return h.q.EndRestore(ctx, sqlc.EndRestoreParams{ID: r.ID, State: state, Error: msg}) == nil
	}
	if r.JobID == nil {
		if time.Since(r.CreatedAt) < time.Minute {
			return false
		}
		return end(jobs.Interrupted, backupLost)
	}
	j, err := h.runner.Get(ctx, *r.JobID)
	switch {
	case errors.Is(err, jobs.ErrNotFound):
		return end(jobs.Interrupted, backupLost)
	case err != nil, jobs.Active(j.State):
		return false
	case j.State == jobs.Canceled:
		return end(jobs.Canceled, "")
	case j.State == jobs.Failed:
		return end(jobs.Failed, j.Error)
	}
	return end(jobs.Interrupted, cmpOr(j.Error, backupLost))
}

func (h *backupHandler) toRestore(ctx context.Context, r sqlc.DatabaseRestore) BackupRestore {
	out := BackupRestore{
		ID: r.ID.String(), DatabaseID: r.DatabaseID.String(), Source: r.Source, TargetName: r.TargetName,
		Mode: r.Mode, WantSafety: r.WantSafety, State: r.State, Error: r.Error, CreatedByName: r.CreatedByName,
		CreatedAt: r.CreatedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
		BackupID: optionalID(r.BackupID), SafetyBackupID: optionalID(r.SafetyBackupID), JobID: optionalID(r.JobID),
	}
	if r.StorageID != nil {
		if s, err := h.q.GetStorage(ctx, *r.StorageID); err == nil {
			out.StorageName = s.Name
		}
	}
	return out
}

// optionalID is an id for a response, or nil.
func optionalID(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	s := id.String()
	return &s
}

type restoreList struct {
	Body struct {
		Items []BackupRestore `json:"items"`
		Total int64           `json:"total"`
	}
}

func registerDatabaseRestores(api huma.API, h *backupHandler, tags []string) {
	huma.Register(api, huma.Operation{
		OperationID:   "restore-database-backup",
		Method:        http.MethodPost,
		Path:          "/database-backups/{id}/restore",
		Summary:       "Restore a backup into a database",
		Description:   "Loads the backup, and the full one an incremental builds on, into a database that exists (replace, with its name typed again, optionally backed up first) or a new one. Every file is read back and checked before the database is touched.",
		DefaultStatus: http.StatusAccepted,
		Tags:          tags,
	}, func(ctx context.Context, in *struct {
		BackupIDPath
		Body RestoreBody
	}) (*JobOutput, error) {
		b, err := h.backup(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		body := in.Body
		name := strings.TrimSpace(body.TargetName)
		if err := dbbackup.CheckName(name); err != nil {
			return nil, fieldError("body.target_name", problemText(err), nil)
		}
		if body.Mode == "replace" && body.Confirm != name {
			return nil, fieldError("body.confirm", "Type the database's name to confirm.", nil)
		}
		d, err := h.q.GetDatabase(ctx, b.DatabaseID)
		if err != nil {
			return nil, internalError(err)
		}
		chain, err := h.restoreChain(ctx, b)
		if err != nil {
			return nil, err
		}
		if why := dbbackup.RestoreInto(b.Format, b.Target, name, len(chain) > 1); why != "" {
			return nil, fieldError("body.target_name", why, nil)
		}
		if slices.Contains(systemDatabases[d.Engine], name) {
			return nil, fieldError("body.target_name", name+" is a system database; Morcheh won't restore over it.", nil)
		}
		if d.Engine == dbmon.MSSQL && !backupTarget(d, "", "", name, "").Local {
			return nil, huma.Error422UnprocessableEntity("SQL Server reads a backup from its own disk, so it can only be restored when Morcheh reaches it through the server it runs on.")
		}
		acc := principalOf(ctx).Access

		// Where to read it from.
		holders, err := h.chainStorages(ctx, chain)
		if err != nil {
			return nil, internalError(err)
		}
		var src sqlc.Storage
		var refused error = huma.Error409Conflict("No storage holds every file this restore needs any more.")
		for _, c := range holders {
			if body.StorageID != "" && c.StorageID.String() != body.StorageID {
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
			src = s
			break
		}
		if src.ID == uuid.Nil {
			return nil, refused
		}
		safety := body.SafetyBackup && body.Mode == "replace"
		if safety {
			switch {
			case src.ReadOnly:
				return nil, fieldError("body.safety_backup", src.Name+" is read-only in Morcheh, so the backup before can't be written to it. Turn it off, or restore from another storage.", nil)
			case acc.StorageLevel(src.WorkspaceID, src.ID) < auth.Engineer:
				return nil, fieldError("body.safety_backup", fmt.Sprintf("The backup before needs %s access to %s.", auth.Engineer, src.Name), nil)
			}
		}

		// Where it runs: nil for a direct database = the machine Morcheh
		// runs on.
		var serverID *uuid.UUID
		switch {
		case d.Mode != "direct":
			serverID = d.ServerID
			if serverID == nil {
				return nil, huma.Error422UnprocessableEntity("The server this database is reached through was removed.")
			}
		case body.RunnerServerID == localRunner:
		case body.RunnerServerID != "":
			id, err := uuid.Parse(body.RunnerServerID)
			if err != nil {
				return nil, fieldError("body.runner_server_id", "Choose a server.", nil)
			}
			serverID = &id
		case b.PlanID != nil:
			if p, err := h.q.GetBackupPlan(ctx, *b.PlanID); err == nil {
				serverID = p.RunnerServerID
			}
		}
		if serverID == nil {
			if lt := localTools(d); !lt.Supported {
				return nil, fieldError("body.runner_server_id", lt.Note, nil)
			}
		} else {
			server, err := h.q.GetServer(ctx, *serverID)
			if isNotFound(err) {
				return nil, fieldError("body.runner_server_id", "That server was removed. Choose another one.", nil)
			}
			if err != nil {
				return nil, internalError(err)
			}
			if acc.ServerLevel(d.WorkspaceID, server.ID) < auth.Engineer {
				return nil, huma.Error403Forbidden(fmt.Sprintf("You need %s access to %s.", auth.Engineer, server.Name))
			}
		}

		// What's there now.
		names, err := h.databaseNames(ctx, d)
		if err != nil {
			return nil, huma.Error422UnprocessableEntity(problemText(err))
		}
		exists := slices.Contains(names, name)
		switch {
		case body.Mode == "replace" && !exists:
			return nil, fieldError("body.target_name", "There's no database called "+name+". Restore it as a new one instead.", nil)
		case body.Mode == "new" && exists:
			return nil, fieldError("body.target_name", name+" exists already. Choose another name, or replace it.", nil)
		}
		if n, err := h.q.CountActiveRestores(ctx, d.ID); err != nil {
			return nil, internalError(err)
		} else if n > 0 {
			return nil, huma.Error409Conflict("A restore into this database is running. Wait for it to finish.")
		}

		user, sealed := strings.TrimSpace(body.Username), []byte(nil)
		if user != "" && body.Password != "" {
			sealed = h.db.box.Seal(body.Password)
		}
		by := principalOf(ctx)
		r, err := h.q.CreateRestore(ctx, sqlc.CreateRestoreParams{
			WorkspaceID: d.WorkspaceID, DatabaseID: d.ID, BackupID: &b.ID, Source: b.Path, TargetName: name,
			Mode: body.Mode, RunnerServerID: serverID, StorageID: &src.ID, WantSafety: safety,
			Username: user, PasswordEnc: sealed, CreatedBy: by.ID(), CreatedByName: cmpOr(by.User.FullName, by.User.Username),
		})
		if err != nil {
			return nil, internalError(err)
		}
		verb := "Restore"
		if body.Mode == "new" {
			verb = "Restore as new"
		}
		// uuid.Nil stands for Morcheh's own machine.
		refs := []uuid.UUID{src.ID, runnerOf(serverID)}
		out, err := submit(ctx, h.runner, jobs.Spec{
			Kind:   restoreKind,
			Title:  fmt.Sprintf("%s %s on %s", verb, name, d.Name),
			Params: restoreParams{Restore: r.ID.String()},
			Refs:   refs,
			Target: JobPlace{StorageID: src.ID.String(), Name: src.Name, Path: path.Dir(b.Path), DatabaseID: d.ID.String()},
		})
		if err != nil {
			_ = h.q.EndRestore(ctx, sqlc.EndRestoreParams{ID: r.ID, State: jobs.Failed, Error: "It couldn't be queued."})
			return nil, err
		}
		if id, err := uuid.Parse(out.Body.ID); err == nil {
			_ = h.q.SetRestoreJob(ctx, sqlc.SetRestoreJobParams{ID: r.ID, JobID: &id})
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-database-restores",
		Method:      http.MethodGet,
		Path:        "/databases/{id}/restores",
		Summary:     "A database's restores, newest first",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ID     string `path:"id" format:"uuid"`
		Limit  int32  `query:"limit" minimum:"1" maximum:"200" default:"50"`
		Offset int32  `query:"offset" minimum:"0"`
	}) (*restoreList, error) {
		id := uuid.MustParse(in.ID)
		rows, err := h.q.ListRestores(ctx, sqlc.ListRestoresParams{DatabaseID: id, Lim: in.Limit, Off: in.Offset})
		if err != nil {
			return nil, internalError(err)
		}
		total, err := h.q.CountRestores(ctx, id)
		if err != nil {
			return nil, internalError(err)
		}
		out := &restoreList{}
		out.Body.Total = total
		out.Body.Items = make([]BackupRestore, len(rows))
		for i, r := range rows {
			if h.syncRestore(ctx, r) {
				if fresh, err := h.q.GetRestore(ctx, r.ID); err == nil {
					r = fresh
				}
			}
			out.Body.Items[i] = h.toRestore(ctx, r)
		}
		return out, nil
	})
}

// runRestore is the database-backup-restore job: check every file, back the
// target up when asked, then load the files oldest first.
func (h *backupHandler) runRestore(ctx context.Context, t *jobs.Task) (any, error) {
	var params restoreParams
	if err := t.Decode(&params); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(params.Restore)
	if err != nil {
		return nil, err
	}
	bg := context.WithoutCancel(ctx)
	r, err := h.q.GetRestore(bg, id)
	if err != nil {
		return nil, err
	}
	if !jobs.Active(r.State) {
		return nil, nil
	}
	fail := func(err error) (any, error) {
		state, msg := jobs.Failed, problemText(err)
		switch {
		case t.Canceled():
			state, msg = jobs.Canceled, ""
		case ctx.Err() != nil:
			state, msg = jobs.Interrupted, backupLost
		}
		_ = h.q.EndRestore(bg, sqlc.EndRestoreParams{ID: r.ID, State: state, Error: msg})
		return nil, err
	}
	if err := h.q.StartRestore(bg, r.ID); err != nil {
		return fail(err)
	}
	if r.BackupID == nil || r.StorageID == nil {
		return fail(errors.New("The backup or its storage was removed."))
	}
	b, err := h.q.GetBackup(bg, *r.BackupID)
	if err != nil {
		return fail(errors.New("The backup was deleted."))
	}
	chain, err := h.restoreChain(bg, b)
	if err != nil {
		return fail(errors.New(problemText(err)))
	}
	d, err := h.q.GetDatabase(bg, r.DatabaseID)
	if err != nil {
		return fail(err)
	}
	// Only a direct database runs on Morcheh's own machine; for the others
	// no server means it was removed.
	if r.RunnerServerID == nil && d.Mode != "direct" {
		return fail(errors.New("The server it runs on was removed."))
	}
	src, err := h.q.GetStorage(bg, *r.StorageID)
	if err != nil {
		return fail(errors.New("The storage was removed."))
	}
	user, sealed := d.Username, d.PasswordEnc
	if r.Username != "" {
		user, sealed = r.Username, r.PasswordEnc
	}
	password, err := h.db.box.Open(sealed)
	if err != nil {
		return fail(err)
	}
	var total int64
	for _, m := range chain {
		total += m.Bytes
	}

	// 1. Every file is read back first: a bad one is found before anything
	// is overwritten.
	t.Update(func(p *jobs.Progress) {
		p.Phase, p.Done, p.Total, p.ItemsTotal = "Checking the files", 0, total, len(chain)
	})
	for i, m := range chain {
		t.Update(func(p *jobs.Progress) { p.Items, p.Current = i, path.Base(m.Path) })
		problem, err := h.checkCopy(ctx, t, m, src.ID)
		if err == nil && problem != "" {
			err = errors.New(path.Base(m.Path) + ": " + problem)
		}
		if err != nil {
			return fail(err)
		}
	}
	t.Logf("Checked %d file(s) on %s", len(chain), src.Name)

	// 2. What's there now, kept in case the backup isn't what was wanted.
	if r.WantSafety {
		t.Update(func(p *jobs.Progress) {
			p.Phase, p.Done, p.Total, p.Current, p.Items, p.ItemsTotal = "Backing up "+r.TargetName+" first", 0, 0, r.TargetName, 0, 0
		})
		safetyID, err := h.safetyBackup(ctx, t, r, d, src, user, password, path.Dir(path.Dir(b.Path)))
		if safetyID != uuid.Nil {
			_ = h.q.SetRestoreSafety(bg, sqlc.SetRestoreSafetyParams{ID: r.ID, SafetyBackupID: &safetyID})
		}
		if err != nil {
			return fail(fmt.Errorf("The backup before restoring failed, so nothing was changed: %s", problemText(err)))
		}
		t.Logf("Backed up %s first", r.TargetName)
	}

	// 3. The files, oldest first.
	t.Update(func(p *jobs.Progress) { p.Phase, p.Done, p.Total, p.ItemsTotal = "Restoring", 0, total, len(chain) })
	script := dumpScript{
		server: runnerOf(r.RunnerServerID), secrets: []string{password},
		root: d.Container != "" || d.Engine == dbmon.MSSQL,
	}
	if d.Mode == "server" {
		script.container = d.Container
	}
	target := backupTarget(d, user, password, r.TargetName, r.ID.String())
	for i, m := range chain {
		t.Update(func(p *jobs.Progress) { p.Items, p.Current = i, path.Base(m.Path) })
		s, err := dbbackup.BuildRestore(target, dbbackup.RestoreOptions{
			Format: m.Format, Source: m.Target, Replace: r.Mode == "replace", First: i == 0, Last: i == len(chain)-1,
		})
		if err != nil {
			return fail(err)
		}
		script.script = s
		if err := h.loadFile(ctx, t, script, src, m); err != nil {
			if i > 0 {
				err = fmt.Errorf("%s (after %d of %d files)", problemText(err), i, len(chain))
			}
			return fail(err)
		}
		t.Logf("Loaded %s", path.Base(m.Path))
	}
	t.Update(func(p *jobs.Progress) { p.Items = len(chain) })
	if err := h.q.EndRestore(bg, sqlc.EndRestoreParams{ID: r.ID, State: jobs.Succeeded}); err != nil {
		return nil, err
	}
	return map[string]any{"database": r.TargetName, "files": len(chain)}, nil
}

// loadFile streams one backup file from the storage into the restore script,
// unzipping Morcheh's own gzip on the way.
func (h *backupHandler) loadFile(ctx context.Context, t *jobs.Task, s dumpScript, src sqlc.Storage, b sqlc.DatabaseBackup) error {
	return h.st.withFS(ctx, src.ID.String(), func(_ sqlc.Storage, f storage.FS) error {
		file, err := f.Open(ctx, b.Path)
		if err != nil {
			return err
		}
		defer file.Close()
		var data io.Reader = &countingReader{r: file, t: t}
		if dbbackup.Gzipped(b.Format) {
			gz, err := gzip.NewReader(data)
			if err != nil {
				return fmt.Errorf("The file isn't gzip: %w", err)
			}
			defer gz.Close()
			data = gz
		}
		s.data = data
		if _, err := h.runDump(ctx, t, s, nil); err != nil {
			return err
		}
		return nil
	})
}

// safetyBackup takes a full backup of the restore's target, beside the backup
// being restored. It has no plan, so retention never deletes it.
func (h *backupHandler) safetyBackup(ctx context.Context, t *jobs.Task, r sqlc.DatabaseRestore, d sqlc.Database,
	dest sqlc.Storage, user, password, folder string) (uuid.UUID, error) {
	bg := context.WithoutCancel(ctx)
	b, err := h.q.CreateBackup(bg, sqlc.CreateBackupParams{
		WorkspaceID: d.WorkspaceID, DatabaseID: d.ID, PlanName: "Before restore", Engine: d.Engine,
		Target: r.TargetName, Trigger: "restore", State: jobs.Queued, CreatedBy: r.CreatedBy, CreatedByName: r.CreatedByName,
	})
	if err != nil {
		return uuid.Nil, err
	}
	end := func(err error) (uuid.UUID, error) {
		_ = h.q.EndBackup(bg, sqlc.EndBackupParams{ID: b.ID, State: jobs.Failed, Error: problemText(err)})
		_ = h.q.FailBackupCopies(bg, b.ID)
		return b.ID, err
	}
	if err := h.q.SetBackupJob(bg, sqlc.SetBackupJobParams{ID: b.ID, JobID: &t.ID}); err != nil {
		return end(err)
	}
	if err := h.q.CreateBackupCopy(bg, sqlc.CreateBackupCopyParams{BackupID: b.ID, StorageID: &dest.ID, StorageName: dest.Name}); err != nil {
		return end(err)
	}
	spec, err := dbbackup.Build(backupTarget(d, user, password, r.TargetName, b.ID.String()))
	if err != nil {
		return end(err)
	}
	now := time.Now()
	file := backupPath(folder, d.Name, r.TargetName, now, b.ID, spec.Ext)
	if err := h.q.StartBackup(bg, sqlc.StartBackupParams{ID: b.ID, Path: file, Format: spec.Format, Kind: "full"}); err != nil {
		return end(err)
	}
	script := dumpScript{
		server: runnerOf(r.RunnerServerID), secrets: []string{password}, script: spec.Script,
		root: d.Container != "" || d.Engine == dbmon.MSSQL,
	}
	if d.Mode == "server" {
		script.container = d.Container
	}
	res, err := h.stream(ctx, t, script, spec, []sqlc.Storage{dest}, b.ID, file)
	if err != nil {
		return end(err)
	}
	if err := h.q.FinishBackup(bg, sqlc.FinishBackupParams{ID: b.ID, Bytes: res.bytes, Sha256: res.sum, Error: res.warning}); err != nil {
		return b.ID, err
	}
	return b.ID, nil
}

// runnerOf is the server a restore runs on; uuid.Nil = Morcheh's own machine.
func runnerOf(id *uuid.UUID) uuid.UUID {
	if id == nil {
		return uuid.Nil
	}
	return *id
}
