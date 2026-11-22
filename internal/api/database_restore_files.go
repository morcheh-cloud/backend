package api

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/dbbackup"
	"github.com/morche/backend/internal/dbmon"
	"github.com/morche/backend/internal/jobs"
)

// A restore from a file Morche didn't take: a dump brought from elsewhere,
// on a storage or a server. The file is read to tell what it is (never
// trusted by its name), checked whole before anything changes, and loaded
// with the same scripts as Morche's own backups.

// RestoreFileSource is the file to restore: on a storage or a server.
type RestoreFileSource struct {
	StorageTransferEnd
	Path string `json:"path" minLength:"1" maxLength:"4096" doc:"The file's path on the storage or server"`
}

// RestoreFileInfo is what a file turned out to be.
type RestoreFileInfo struct {
	Path      string     `json:"path" doc:"The file's full path"`
	Name      string     `json:"name"`
	Size      int64      `json:"size"`
	Modified  *time.Time `json:"modified" nullable:"true"`
	Format    string     `json:"format" doc:"Empty = not a backup Morche knows"`
	Engine    string     `json:"engine" doc:"The database engine it is for; empty when unknown"`
	Label     string     `json:"label" doc:"What it is, in words"`
	Gzip      bool       `json:"gzip"`
	Packed    string     `json:"compression" doc:"gzip or zstd around the file; empty = neither"`
	Databases []string   `json:"databases" doc:"The databases the file names (a MySQL dump's USE, a mongodump archive's); empty = it holds one, unnamed"`
	Named     bool       `json:"named" doc:"The file names its database and can only go back under that name (a MySQL dump made with --databases)"`
	Problem   string     `json:"problem" doc:"Why it can't be restored into this database; empty = it can"`
}

// RestoreFileBody is a restore from a file.
type RestoreFileBody struct {
	Source          RestoreFileSource `json:"source"`
	SourceName      string            `json:"source_name,omitempty" maxLength:"128" doc:"When the file holds several databases: the one to take"`
	TargetName      string            `json:"target_name" minLength:"1" maxLength:"128" doc:"The database to load it into"`
	Mode            string            `json:"mode" enum:"replace,new" doc:"replace = overwrite a database that exists; new = create one"`
	Confirm         string            `json:"confirm,omitempty" maxLength:"128" doc:"For replace: the target's name typed again"`
	SafetyBackup    bool              `json:"safety_backup,omitempty" doc:"For replace: back the target up first"`
	SafetyStorageID string            `json:"safety_storage_id,omitempty" maxLength:"36" doc:"Where the backup before goes; empty = the file's storage"`
	SafetyFolder    string            `json:"safety_folder,omitempty" maxLength:"1024" doc:"The folder on it; empty = beside the file (or the top when it's another storage)"`
	RunnerServerID  string            `json:"runner_server_id,omitempty" maxLength:"36" doc:"For a direct database: the server the restore runs on, or \"local\" (also empty) for the machine Morche runs on"`
	Username        string            `json:"username,omitempty" maxLength:"256" doc:"A login for this restore only; empty = the database's saved one"`
	Password        string            `json:"password,omitempty" maxLength:"1024"`
	Workers         int               `json:"workers,omitempty" minimum:"0" maximum:"16" doc:"For a parallel PostgreSQL archive (format pg_dir): jobs for the restore; 0 = 4. More than one isn't a single transaction"`
	TempDir         string            `json:"temp_dir,omitempty" maxLength:"512" doc:"For a parallel PostgreSQL archive (format pg_dir), or a ClickHouse dump (ch_tar) when the runner's tar can't stream it: where it's unpacked first, on the machine the restore runs on; empty = its temporary folder"`
}

// restoreRunner is where a restore runs: nil = the machine Morche runs on.
// asked is the request's runner_server_id; planned the plan's, when asked
// is empty.
func (h *backupHandler) restoreRunner(ctx context.Context, d sqlc.Database, asked string, planned *uuid.UUID) (*uuid.UUID, error) {
	var serverID *uuid.UUID
	switch {
	case d.Mode != "direct":
		serverID = d.ServerID
		if serverID == nil {
			return nil, huma.Error422UnprocessableEntity("The server this database is reached through was removed.")
		}
	case asked == localRunner:
	case asked != "":
		id, err := uuid.Parse(asked)
		if err != nil {
			return nil, fieldError("body.runner_server_id", "Choose a server.", nil)
		}
		serverID = &id
	default:
		serverID = planned
	}
	if serverID == nil {
		if lt := localTools(d); !lt.Supported {
			return nil, fieldError("body.runner_server_id", lt.Note, nil)
		}
		return nil, nil
	}
	server, err := h.q.GetServer(ctx, *serverID)
	if isNotFound(err) {
		return nil, fieldError("body.runner_server_id", "That server was removed. Choose another one.", nil)
	}
	if err != nil {
		return nil, internalError(err)
	}
	if principalOf(ctx).Access.ServerLevel(d.WorkspaceID, server.ID) < auth.Engineer {
		return nil, huma.Error403Forbidden(fmt.Sprintf("You need %s access to %s.", auth.Engineer, server.Name))
	}
	return serverID, nil
}

// checkRestoreTarget checks the target agrees with the mode, and that no
// other restore into the database is running.
func (h *backupHandler) checkRestoreTarget(ctx context.Context, d sqlc.Database, mode, name string) error {
	names, err := h.databaseNames(ctx, d)
	if err != nil {
		return huma.Error422UnprocessableEntity(problemText(err))
	}
	exists := slices.Contains(names, name)
	switch {
	case mode == "replace" && !exists:
		return fieldError("body.target_name", "There's no database called "+name+". Restore it as a new one instead.", nil)
	case mode == "new" && exists:
		return fieldError("body.target_name", name+" exists already. Choose another name, or replace it.", nil)
	}
	if n, err := h.q.CountActiveRestores(ctx, d.ID); err != nil {
		return internalError(err)
	} else if n > 0 {
		return huma.Error409Conflict("A restore into this database is running. Wait for it to finish.")
	}
	return nil
}

// fileRestoreWorkers is how many jobs restore a parallel archive from a file
// when the request doesn't say.
const fileRestoreWorkers = 4

// fileRestoreOptions is how a file of what s says goes into target. why says
// why it can't.
func fileRestoreOptions(s dbbackup.Sniffed, sourceName, target, mode string) (dbbackup.RestoreOptions, string, string) {
	o := dbbackup.RestoreOptions{
		Format: s.Format, Source: target, Replace: mode == "replace", First: true, Last: true,
		MongoPlain: !s.MongoGzip, CreateNamed: true,
	}
	switch s.Format {
	case dbbackup.MongoArchive, dbbackup.ClickHouseTar:
		switch {
		case len(s.Databases) == 0:
			return o, "body.source", "The archive holds no databases."
		case sourceName == "" && len(s.Databases) == 1:
			sourceName = s.Databases[0]
		case sourceName == "":
			return o, "body.source_name", "The archive holds several databases. Choose the one to restore."
		case !slices.Contains(s.Databases, sourceName):
			return o, "body.source_name", "The archive doesn't hold a database called " + sourceName + "."
		}
		o.Source = sourceName
	case dbbackup.MySQLSQL:
		// The file says USE <name>, so it only goes back there.
		o.Source = s.Databases[0]
		if why := dbbackup.RestoreInto(s.Format, o.Source, target, false); why != "" {
			return o, "body.target_name", why
		}
	case dbbackup.MSSQLBak:
		// The database it was taken from isn't known: its files always go
		// under new names, so they never clash with another database's.
		o.Source = ""
	}
	return o, "", ""
}

// fileEnd is the end of a stored restore that holds its file.
func fileEnd(r sqlc.DatabaseRestore) (StorageTransferEnd, bool) {
	switch {
	case r.StorageID != nil:
		id := r.StorageID.String()
		return StorageTransferEnd{StorageID: &id}, true
	case r.SourceServerID != nil:
		id := r.SourceServerID.String()
		return StorageTransferEnd{ServerID: &id}, true
	}
	return StorageTransferEnd{}, false
}

// inspectFile opens a file on a storage or server and reads enough of it to
// tell what it is.
func (h *backupHandler) inspectFile(ctx context.Context, src RestoreFileSource, engine string) (RestoreFileInfo, error) {
	var out RestoreFileInfo
	err := h.st.with(ctx, src.StorageTransferEnd, func(p place) error {
		file, err := p.resolve(src.Path)
		if err != nil {
			return err
		}
		e, err := p.fs.Stat(ctx, file)
		if err != nil {
			return storageProblem(file, err)
		}
		if e.Dir {
			return fieldError("body.source.path", "That's a folder. Choose a file.", nil)
		}
		out.Path, out.Name, out.Size = file, path.Base(file), e.Size
		if !e.Modified.IsZero() {
			m := e.Modified
			out.Modified = &m
		}
		f, err := p.fs.Open(ctx, file)
		if err != nil {
			return storageProblem(file, err)
		}
		defer f.Close()
		s, err := dbbackup.Sniff(f, engine)
		if err != nil {
			return huma.Error422UnprocessableEntity("Couldn't read the file: " + problemText(err))
		}
		out.Format, out.Engine, out.Label, out.Gzip, out.Packed = s.Format, s.Engine, s.Label, s.Gzip, s.Pack
		out.Databases = append([]string{}, s.Databases...)
		out.Named = s.Format == dbbackup.MySQLSQL
		out.Problem = s.ForEngine(engine)
		return nil
	})
	return out, err
}

type restoreFileInfoOutput struct {
	Body RestoreFileInfo
}

func registerDatabaseRestoreFiles(api huma.API, h *backupHandler, tags []string) {
	huma.Register(api, huma.Operation{
		OperationID: "inspect-database-restore-file",
		Method:      http.MethodPost,
		Path:        "/databases/{id}/restore-file/inspect",
		Summary:     "Tell what a backup file is",
		Description: "Reads the start of a file on a storage or a server and says what kind of backup it is, which databases it names, and whether it can be restored into this database. It changes nothing.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ID   string `path:"id" format:"uuid"`
		Body struct {
			Source RestoreFileSource `json:"source"`
		}
	}) (*restoreFileInfoOutput, error) {
		d, err := h.q.GetDatabase(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		if err := h.st.mayReach(ctx, in.Body.Source.StorageTransferEnd, auth.Operator); err != nil {
			return nil, err
		}
		info, err := h.inspectFile(ctx, in.Body.Source, d.Engine)
		if err != nil {
			return nil, err
		}
		return &restoreFileInfoOutput{Body: info}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "restore-database-file",
		Method:        http.MethodPost,
		Path:          "/databases/{id}/restore-file",
		Summary:       "Restore a backup file from a storage or server",
		Description:   "Loads a dump Morche didn't take (pg_dump plain or custom, mysqldump, mongodump --archive, SQL Server .bak, a ClickHouse dump Morche made; gzip/zstd or not) from a storage or a server into a database that exists (replace, with its name typed again, optionally backed up first) or a new one. The whole file is read and checked before the database is touched.",
		DefaultStatus: http.StatusAccepted,
		Tags:          tags,
	}, func(ctx context.Context, in *struct {
		ID   string `path:"id" format:"uuid"`
		Body RestoreFileBody
	}) (*JobOutput, error) {
		body := in.Body
		name := strings.TrimSpace(body.TargetName)
		if err := dbbackup.CheckName(name); err != nil {
			return nil, fieldError("body.target_name", problemText(err), nil)
		}
		if body.Mode == "replace" && body.Confirm != name {
			return nil, fieldError("body.confirm", "Type the database's name to confirm.", nil)
		}
		tempDir, err := restoreTempDir(body.TempDir, nil, false)
		if err != nil {
			return nil, err
		}
		d, err := h.q.GetDatabase(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		if slices.Contains(systemDatabases[d.Engine], name) {
			return nil, fieldError("body.target_name", name+" is a system database; Morche won't restore over it.", nil)
		}
		if d.Engine == dbmon.MSSQL && !backupTarget(d, "", "", name, "").Local {
			return nil, huma.Error422UnprocessableEntity("SQL Server reads a backup from its own disk, so it can only be restored when Morche reaches it through the server it runs on.")
		}
		end := body.Source.StorageTransferEnd
		if err := h.st.mayReach(ctx, end, auth.Operator); err != nil {
			return nil, err
		}
		info, err := h.inspectFile(ctx, body.Source, d.Engine)
		if err != nil {
			return nil, err
		}
		if info.Problem != "" {
			return nil, fieldError("body.source.path", info.Problem, nil)
		}
		s := dbbackup.Sniffed{Format: info.Format, Databases: info.Databases}
		if _, at, why := fileRestoreOptions(s, strings.TrimSpace(body.SourceName), name, body.Mode); why != "" {
			return nil, fieldError(at, why, nil)
		}
		acc := principalOf(ctx).Access
		srcStorage, srcServer := parseOptionalID(end.StorageID), parseOptionalID(end.ServerID)
		srcName := ""
		if srcStorage != nil {
			st, err := h.q.GetStorage(ctx, *srcStorage)
			if err != nil {
				return nil, internalError(err)
			}
			srcName = st.Name
		} else if srcServer != nil {
			sv, err := h.q.GetServer(ctx, *srcServer)
			if err != nil {
				return nil, internalError(err)
			}
			srcName = sv.Name
		}

		// The backup before: to the file's storage unless another is chosen.
		safety := body.SafetyBackup && body.Mode == "replace"
		var safetyStorage *uuid.UUID
		safetyFolder := strings.TrimSpace(body.SafetyFolder)
		if safety {
			id := parseOptionalID(&body.SafetyStorageID)
			if id == nil {
				id = srcStorage
				if safetyFolder == "" {
					safetyFolder = path.Dir(info.Path)
				}
			}
			if id == nil {
				return nil, fieldError("body.safety_storage_id", "Choose a storage for the backup before.", nil)
			}
			st, err := h.q.GetStorage(ctx, *id)
			switch {
			case isNotFound(err):
				return nil, fieldError("body.safety_storage_id", "That storage was removed. Choose another one.", nil)
			case err != nil:
				return nil, internalError(err)
			case st.ReadOnly:
				return nil, fieldError("body.safety_storage_id", st.Name+" is read-only in Morche, so the backup before can't be written to it. Choose another storage.", nil)
			case acc.StorageLevel(st.WorkspaceID, st.ID) < auth.Engineer:
				return nil, fieldError("body.safety_storage_id", fmt.Sprintf("The backup before needs %s access to %s.", auth.Engineer, st.Name), nil)
			}
			safetyStorage = &st.ID
			if safetyFolder, err = cleanPath(safetyFolder); err != nil {
				return nil, err
			}
		}

		serverID, err := h.restoreRunner(ctx, d, body.RunnerServerID, nil)
		if err != nil {
			return nil, err
		}
		if err := h.checkRestoreTarget(ctx, d, body.Mode, name); err != nil {
			return nil, err
		}

		user, sealed := strings.TrimSpace(body.Username), []byte(nil)
		if user != "" && body.Password != "" {
			sealed = h.db.box.Seal(body.Password)
		}
		by := principalOf(ctx)
		r, err := h.q.CreateRestore(ctx, sqlc.CreateRestoreParams{
			WorkspaceID: d.WorkspaceID, DatabaseID: d.ID, Source: info.Path, TargetName: name,
			Mode: body.Mode, RunnerServerID: serverID, StorageID: srcStorage, WantSafety: safety,
			Username: user, PasswordEnc: sealed, CreatedBy: by.ID(), CreatedByName: cmpOr(by.User.FullName, by.User.Username),
			SourceServerID: srcServer, Format: info.Format, SourceName: strings.TrimSpace(body.SourceName),
			SafetyStorageID: safetyStorage, SafetyFolder: safetyFolder,
		})
		if err != nil {
			return nil, internalError(err)
		}
		verb := "Restore"
		if body.Mode == "new" {
			verb = "Restore as new"
		}
		refs := []uuid.UUID{runnerOf(serverID)}
		place := JobPlace{Name: srcName, Path: path.Dir(info.Path), DatabaseID: d.ID.String()}
		if srcStorage != nil {
			refs = append(refs, *srcStorage)
			place.StorageID = srcStorage.String()
		} else {
			refs = append(refs, *srcServer)
			place.ServerID = srcServer.String()
		}
		if safetyStorage != nil && !slices.Contains(refs, *safetyStorage) {
			refs = append(refs, *safetyStorage)
		}
		out, err := submit(ctx, h.runner, jobs.Spec{
			Kind:   restoreKind,
			Title:  fmt.Sprintf("%s %s on %s from %s", verb, name, d.Name, info.Name),
			Params: restoreParams{Restore: r.ID.String(), Workers: body.Workers, TempDir: tempDir},
			Refs:   refs,
			Target: place,
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
}

// runFileRestore is the restore job for a file Morche didn't take: read it
// whole and check it again, back the target up when asked, then load it.
func (h *backupHandler) runFileRestore(ctx context.Context, t *jobs.Task, r sqlc.DatabaseRestore, params restoreParams, fail func(error) (any, error)) (any, error) {
	bg := context.WithoutCancel(ctx)
	end, ok := fileEnd(r)
	if !ok {
		return fail(errors.New("The storage or server holding the file was removed."))
	}
	d, err := h.q.GetDatabase(bg, r.DatabaseID)
	if err != nil {
		return fail(err)
	}
	if r.RunnerServerID == nil && d.Mode != "direct" {
		return fail(errors.New("The server it runs on was removed."))
	}
	user, sealed := d.Username, d.PasswordEnc
	if r.Username != "" {
		user, sealed = r.Username, r.PasswordEnc
	}
	password, err := h.db.box.Open(sealed)
	if err != nil {
		return fail(err)
	}
	name := path.Base(r.Source)

	// 1. The whole file is read first: a bad one is found before anything
	// is overwritten.
	var check dbbackup.FileCheck
	var from string
	err = h.st.with(ctx, end, func(p place) error {
		from = p.name
		e, err := p.fs.Stat(ctx, r.Source)
		if err != nil {
			return err
		}
		t.Update(func(pr *jobs.Progress) {
			pr.Phase, pr.Done, pr.Total, pr.Current, pr.Items, pr.ItemsTotal = "Checking the file", 0, e.Size, name, 0, 1
		})
		f, err := p.fs.Open(ctx, r.Source)
		if err != nil {
			return err
		}
		defer f.Close()
		check, err = dbbackup.CheckFile(&countingReader{r: f, t: t}, d.Engine)
		return err
	})
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fail(errors.New("The file is gone: " + r.Source))
	case err != nil:
		return fail(err)
	}
	if why := check.ForEngine(d.Engine); why != "" {
		return fail(errors.New(why))
	}
	mysql := func(f string) bool { return f == dbbackup.MySQLDB || f == dbbackup.MySQLSQL }
	// A USE line further in than the first look read turns a MySQL dump
	// into one that names its database; the options below check that.
	if check.Format != r.Format && !(mysql(check.Format) && mysql(r.Format)) {
		return fail(errors.New("The file changed since it was chosen: it's a " + cmpOr(check.Label, "different file") + " now. Start the restore again."))
	}
	opts, _, why := fileRestoreOptions(check.Sniffed, r.SourceName, r.TargetName, r.Mode)
	if why != "" {
		return fail(errors.New(why))
	}
	opts.Workers, opts.TempDir = cmp.Or(params.Workers, fileRestoreWorkers), params.TempDir
	t.Logf("Checked %s on %s (%s, %d bytes)", name, from, check.Label, check.Bytes)

	// 2. What's there now, kept in case the file isn't what was wanted.
	if r.WantSafety {
		if r.SafetyStorageID == nil {
			return fail(errors.New("The storage for the backup before was removed, so nothing was changed."))
		}
		dest, err := h.q.GetStorage(bg, *r.SafetyStorageID)
		if err != nil {
			return fail(errors.New("The storage for the backup before was removed, so nothing was changed."))
		}
		t.Update(func(p *jobs.Progress) {
			p.Phase, p.Done, p.Total, p.Current, p.Items, p.ItemsTotal = "Backing up "+r.TargetName+" first", 0, 0, r.TargetName, 0, 0
		})
		safetyID, err := h.safetyBackup(ctx, t, r, d, dest, user, password, r.SafetyFolder)
		if safetyID != uuid.Nil {
			_ = h.q.SetRestoreSafety(bg, sqlc.SetRestoreSafetyParams{ID: r.ID, SafetyBackupID: &safetyID})
		}
		if err != nil {
			return fail(fmt.Errorf("The backup before restoring failed, so nothing was changed: %s", problemText(err)))
		}
		t.Logf("Backed up %s first, to %s", r.TargetName, dest.Name)
	}

	// 3. The file.
	t.Update(func(p *jobs.Progress) {
		p.Phase, p.Done, p.Total, p.Current, p.Items, p.ItemsTotal = "Restoring", 0, check.Bytes, name, 0, 1
	})
	script := dumpScript{
		server: runnerOf(r.RunnerServerID), secrets: []string{password},
		root: d.Container != "" || d.Engine == dbmon.MSSQL,
	}
	if d.Mode == "server" {
		script.container = d.Container
	}
	s, err := dbbackup.BuildRestore(backupTarget(d, user, password, r.TargetName, r.ID.String()), opts)
	if err != nil {
		return fail(err)
	}
	script.script = s
	err = h.st.with(ctx, end, func(p place) error {
		f, err := p.fs.Open(ctx, r.Source)
		if err != nil {
			return err
		}
		defer f.Close()
		var data io.Reader = &countingReader{r: f, t: t}
		if check.Pack != "" {
			zr, err := dbbackup.Unpack(data, check.Pack)
			if err != nil {
				return err
			}
			defer zr.Close()
			data = zr
		}
		if check.Format == dbbackup.PgSQL {
			// psql runs the file in restricted mode under a key the file
			// can't know, so it can't end it.
			key := make([]byte, 16)
			if _, err := rand.Read(key); err != nil {
				return err
			}
			data = dbbackup.PlainSQL(data, hex.EncodeToString(key))
		}
		script.data = data
		_, err = h.runDump(ctx, t, script, nil)
		return err
	})
	if err != nil {
		return fail(err)
	}
	t.Update(func(p *jobs.Progress) { p.Items = 1 })
	t.Logf("Loaded %s into %s", name, r.TargetName)
	if err := h.q.EndRestore(bg, sqlc.EndRestoreParams{ID: r.ID, State: jobs.Succeeded}); err != nil {
		return nil, err
	}
	return map[string]any{"database": r.TargetName, "files": 1}, nil
}
