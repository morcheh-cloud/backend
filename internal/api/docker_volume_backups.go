package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/docker"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/storage"
	"github.com/morcheh/backend/internal/terminal"
)

// Docker volume backups: the volume's folder on the server is packed with
// tar + gzip (as root) and streamed over SSH straight into a Storage; a
// restore streams it back. The containers using the volume can be stopped
// around it, so a database's files are copied at rest.

const (
	dockerVolumeBackupKind  = "docker-volume-backup"
	dockerVolumeRestoreKind = "docker-volume-restore"
	defaultVolumeFolder     = "/backups/docker-volumes"
)

type DockerVolumeBackup struct {
	ID          uuid.UUID  `json:"id"`
	Volume      string     `json:"volume"`
	StorageID   *uuid.UUID `json:"storage_id,omitempty" doc:"Missing when the storage was removed"`
	StorageName string     `json:"storage_name"`
	Path        string     `json:"path" doc:"The file on the storage"`
	Size        int64      `json:"size" doc:"Bytes, compressed"`
	SHA256      string     `json:"sha256"`
	State       string     `json:"state" enum:"running,stored,failed"`
	Error       string     `json:"error,omitempty"`
	Note        string     `json:"note,omitempty" doc:"Warnings from tar, such as files that changed while it read them"`
	Stopped     int        `json:"stopped" doc:"Containers stopped while it was made"`
	ScheduleID  *uuid.UUID `json:"schedule_id,omitempty" doc:"The cron job that made it"`
	JobID       *uuid.UUID `json:"job_id,omitempty"`
	By          string     `json:"by"`
	CreatedAt   time.Time  `json:"created_at"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
}

func toVolumeBackup(b sqlc.DockerVolumeBackup) DockerVolumeBackup {
	return DockerVolumeBackup{
		ID: b.ID, Volume: b.Volume, StorageID: b.StorageID, StorageName: b.StorageName, Path: b.Path,
		Size: b.Size, SHA256: b.Sha256, State: b.State, Error: b.Error, Note: b.Note, Stopped: int(b.Stopped),
		ScheduleID: b.ScheduleID, JobID: b.JobID, By: b.CreatedByName, CreatedAt: b.CreatedAt, FinishedAt: b.FinishedAt,
	}
}

type DockerVolumeBackupBody struct {
	StorageID string `json:"storage_id" format:"uuid"`
	Folder    string `json:"folder,omitempty" maxLength:"500" doc:"Folder on the storage; the file goes in <folder>/<server>/<volume>/. Default /backups/docker-volumes"`
	Stop      bool   `json:"stop,omitempty" doc:"Stop the running containers using the volume while it is packed, then start them again"`
}

type DockerVolumeRestoreBody struct {
	Volume  string `json:"volume,omitempty" maxLength:"255" doc:"Volume to restore into; default the one it came from. Created when missing"`
	Replace bool   `json:"replace,omitempty" doc:"Empty the volume first; else the files are written over what is there"`
	Stop    bool   `json:"stop,omitempty" doc:"Stop the running containers using the volume during the restore, then start them again"`
}

type DockerVolumeBackupPath struct {
	ServerIDPath
	Backup string `path:"backup" format:"uuid"`
}

type DockerVolumeBackupsInput struct {
	ServerIDPath
	Volume string `query:"volume" doc:"Only this volume's copies"`
}

type volumeBackupParams struct {
	ServerID   string `json:"server_id"`
	Volume     string `json:"volume"`
	StorageID  string `json:"storage_id"`
	Folder     string `json:"folder"`
	Stop       bool   `json:"stop"`
	By         string `json:"by"`
	ScheduleID string `json:"schedule_id,omitempty"`
}

type volumeRestoreParams struct {
	ServerID string `json:"server_id"`
	BackupID string `json:"backup_id"`
	Volume   string `json:"volume"`
	Replace  bool   `json:"replace"`
	Stop     bool   `json:"stop"`
}

var volumeNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)

// slugPart makes a name safe as one folder name.
func slugPart(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return cmpOr(strings.Trim(b.String(), "-."), "server")
}

func volumeFile(folder, server, volume string, at time.Time) string {
	folder = storage.Clean(cmpOr(strings.TrimSpace(folder), defaultVolumeFolder))
	return path.Join(folder, slugPart(server), volume, volume+"-"+at.UTC().Format("20060102-150405")+".tar.gz")
}

// volumeShell runs script as root with the volume's folder as its working
// directory, with the containers using it stopped around it (stop). create
// makes the volume when it's missing (a restore into a new one).
func (h *serverHandler) volumeShell(ctx context.Context, t *jobs.Task, serverID, volume string, stop, create bool,
	script string, in io.Reader, out io.Writer) (stopped int, warning string, err error) {
	c, err := h.conn(ctx, serverID)
	if err != nil {
		return 0, "", err
	}
	err = hold(c, func() error {
		e, err := h.engine(ctx, serverID, c)
		if err != nil {
			return err
		}
		vols, err := e.client.Volumes(ctx)
		if err != nil {
			return err
		}
		var v *docker.Volume
		for i := range vols {
			if vols[i].Name == volume {
				v = &vols[i]
			}
		}
		if v == nil {
			if !create {
				return fmt.Errorf("There's no volume %s on this server any more.", volume)
			}
			nv, err := e.client.CreateVolume(ctx, docker.VolumeCreate{Name: volume})
			if err != nil {
				return err
			}
			t.Logf("Created the volume %s.", volume)
			v = &nv
		}
		if v.Mountpoint == "" || (v.Driver != "" && v.Driver != "local") {
			return fmt.Errorf("The %s driver keeps this volume's files elsewhere, so they can't be packed from the server.", cmpOr(v.Driver, "volume"))
		}
		sh, err := h.rootShell(ctx, serverID, c)
		if err != nil {
			return err
		}
		if sh.priv == privUser {
			return errors.New("Reading a volume's files needs root: give the login user sudo, or sign in as root.")
		}

		if stop {
			cs, err := e.client.Containers(ctx)
			if err != nil {
				return err
			}
			var ids, names []string
			for _, ct := range cs {
				if ct.State != "running" || !slices.ContainsFunc(ct.Mounts, func(m docker.Mount) bool { return m.Type == "volume" && m.Name == volume }) {
					continue
				}
				t.Update(func(p *jobs.Progress) { p.Phase = "Stopping " + containerName(ct.Names) })
				if err := e.client.Act(ctx, ct.ID, "stop", 30, ""); err != nil {
					return fmt.Errorf("Couldn't stop %s: %w", containerName(ct.Names), err)
				}
				ids, names = append(ids, ct.ID), append(names, containerName(ct.Names))
			}
			stopped = len(ids)
			if stopped > 0 {
				t.Logf("Stopped %s while it works.", strings.Join(names, ", "))
				defer func() {
					bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
					defer cancel()
					for i, id := range ids {
						if err := e.client.Act(bg, id, "start", -1, ""); err != nil {
							warning = strings.TrimSpace(warning + " Couldn't start " + names[i] + " again: start it by hand.")
						}
					}
					if warning == "" {
						t.Logf("Started %s again.", strings.Join(names, ", "))
					}
				}()
			}
		}

		full := "cd -- " + terminal.ShellQuote(v.Mountpoint) + " || exit 3\n" + script
		cmd, prefix := sh.command(full)
		sess, err := c.Session(ctx)
		if err != nil {
			return err
		}
		defer sess.Close()
		sh.logAs(full).apply(sess)
		sess.Secrets = append(sess.Secrets, sh.password)
		var stderr tailWriter
		sess.Stdout, sess.Stderr = out, &stderr
		sess.NoStdout = out != nil
		if out == nil {
			sess.Stdout = &stderr
		}
		switch {
		case in != nil:
			sess.Stdin = io.MultiReader(strings.NewReader(prefix), in)
		case prefix != "":
			sess.Stdin = strings.NewReader(prefix)
		}
		if err := sess.Start(cmd); err != nil {
			return err
		}
		wait := make(chan error, 1)
		go func() { wait <- sess.Wait() }()
		select {
		case err = <-wait:
		case <-ctx.Done():
			_ = sess.Signal(ssh.SIGTERM)
			select {
			case <-wait:
			case <-time.After(scriptGrace):
				_ = sess.Close()
				<-wait
			}
			return ctx.Err()
		}
		text := scrub(string(stderr.b), sh.password)
		var exit *ssh.ExitError
		switch {
		case err == nil:
			if text != "" {
				warning = text
			}
			return nil
		case errors.As(err, &exit) && text != "":
			return errors.New(text)
		case errors.As(err, &exit):
			return fmt.Errorf("It stopped with code %d.", exit.ExitStatus())
		}
		return err
	})
	return stopped, warning, err
}

// backupVolume packs a volume into a storage and records the copy.
func (st *storageHandler) backupVolume(ctx context.Context, t *jobs.Task, p volumeBackupParams) (sqlc.DockerVolumeBackup, error) {
	h := st.servers
	sid, err := uuid.Parse(p.ServerID)
	if err != nil {
		return sqlc.DockerVolumeBackup{}, err
	}
	srv, err := h.q.GetServer(ctx, sid)
	if err != nil {
		return sqlc.DockerVolumeBackup{}, err
	}
	stID, err := uuid.Parse(p.StorageID)
	if err != nil {
		return sqlc.DockerVolumeBackup{}, err
	}
	row, err := st.q.GetStorage(ctx, stID)
	if err != nil {
		if isNotFound(err) {
			return sqlc.DockerVolumeBackup{}, errors.New("The storage was removed.")
		}
		return sqlc.DockerVolumeBackup{}, err
	}
	file := volumeFile(p.Folder, srv.Name, p.Volume, time.Now())
	var sched *uuid.UUID
	if id, err := uuid.Parse(p.ScheduleID); err == nil {
		sched = &id
	}
	jobID := t.ID
	b, err := st.q.CreateDockerVolumeBackup(ctx, sqlc.CreateDockerVolumeBackupParams{
		ServerID: sid, Volume: p.Volume, StorageID: &row.ID, StorageName: row.Name, Path: file,
		ScheduleID: sched, JobID: &jobID, CreatedByName: p.By,
	})
	if err != nil {
		return b, err
	}
	finish := func(state string, size int64, sum, msg, note string, stopped int) {
		if e := st.q.FinishDockerVolumeBackup(context.WithoutCancel(ctx), sqlc.FinishDockerVolumeBackupParams{
			ID: b.ID, State: state, Size: size, Sha256: sum, Error: msg, Note: note, Stopped: int32(stopped),
		}); e != nil {
			slog.Warn("docker: record a volume backup", "id", b.ID, "error", e)
		}
		b.State, b.Size, b.Sha256, b.Error, b.Note, b.Stopped = state, size, sum, msg, note, int32(stopped)
	}

	c, err := st.acquire(ctx, row)
	if err == nil {
		if err = c.fs.Mkdir(ctx, path.Dir(file)); err != nil {
			st.release(c)
		}
	}
	if err != nil {
		finish("failed", 0, "", problemText(err), "", 0)
		return b, fmt.Errorf("%s: %s", row.Name, problemText(err))
	}
	defer st.release(c)

	run, cancel := context.WithCancel(ctx)
	defer cancel()
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := c.fs.Put(run, file, pr, -1)
		_ = pr.CloseWithError(errors.New("the storage stopped reading"))
		done <- err
	}()
	t.Update(func(pg *jobs.Progress) { pg.Phase, pg.Current = "Packing "+p.Volume, file })
	out := &sink{w: pw, hash: sha256.New(), t: t}
	script := "tar -czf - . ; rc=$?\n[ \"$rc\" -le 1 ] || exit \"$rc\"\n"
	stopped, warning, runErr := h.volumeShell(run, t, p.ServerID, p.Volume, p.Stop, false, script, nil, out)
	if runErr != nil {
		_ = pw.CloseWithError(runErr)
	} else {
		_ = pw.Close()
	}
	putErr := <-done
	if runErr == nil && putErr != nil {
		runErr = fmt.Errorf("%s: %s", row.Name, problemText(putErr))
	}
	if runErr == nil && out.n == 0 {
		runErr = errors.New("The copy came out empty.")
	}
	if runErr == nil {
		if e, err := c.fs.Stat(ctx, file); err != nil {
			runErr = fmt.Errorf("%s: %s", row.Name, problemText(err))
		} else if e.Size != out.n {
			runErr = fmt.Errorf("%s holds %d bytes of the %d sent.", row.Name, e.Size, out.n)
		}
	}
	if runErr != nil {
		removeQuietly(ctx, c.fs, file)
		if ctx.Err() != nil {
			finish("failed", 0, "", "It was stopped.", "", stopped)
		} else {
			finish("failed", 0, "", problemText(jobError(runErr)), "", stopped)
		}
		return b, runErr
	}
	if warning != "" {
		t.Logf("%s", warning)
	}
	finish("stored", out.n, hex.EncodeToString(out.hash.Sum(nil)), "", warning, stopped)
	t.Logf("Stored %s on %s (%s).", file, row.Name, humanBytes(out.n))
	return b, nil
}

// readCounter reports bytes read as the job's progress.
type readCounter struct {
	r io.Reader
	t *jobs.Task
}

func (c *readCounter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.t.Add(int64(n))
	return n, err
}

func (st *storageHandler) restoreVolume(ctx context.Context, t *jobs.Task, p volumeRestoreParams) (any, error) {
	h := st.servers
	sid, err := uuid.Parse(p.ServerID)
	bid, err2 := uuid.Parse(p.BackupID)
	if err != nil || err2 != nil {
		return nil, errors.New("Not a backup.")
	}
	b, err := st.q.GetDockerVolumeBackup(ctx, sqlc.GetDockerVolumeBackupParams{ID: bid, ServerID: sid})
	if err != nil {
		if isNotFound(err) {
			return nil, errors.New("This copy isn't kept any more.")
		}
		return nil, err
	}
	if b.StorageID == nil {
		return nil, fmt.Errorf("%s was removed, and the copy with it.", cmpOr(b.StorageName, "Its storage"))
	}
	row, err := st.q.GetStorage(ctx, *b.StorageID)
	if err != nil {
		return nil, err
	}
	c, err := st.acquire(ctx, row)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", row.Name, problemText(err))
	}
	defer st.release(c)
	f, err := c.fs.Open(ctx, b.Path)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", row.Name, problemText(err))
	}
	defer f.Close()
	size := f.Entry().Size
	t.Update(func(pg *jobs.Progress) {
		pg.Phase, pg.Current, pg.Total = "Restoring "+p.Volume, b.Path, size
	})
	script := ""
	if p.Replace {
		script += "find . -mindepth 1 -maxdepth 1 -exec rm -rf -- {} \\; || exit 3\n"
	}
	script += "no=; tar --help 2>&1 | grep -q -- --numeric-owner && no=--numeric-owner\ntar -xzf - $no\n"
	stopped, warning, err := h.volumeShell(ctx, t, p.ServerID, p.Volume, p.Stop, true, script, &readCounter{r: f, t: t}, nil)
	if err != nil {
		return nil, err
	}
	if warning != "" {
		t.Logf("%s", warning)
	}
	t.Logf("Put %s back into %s.", b.CreatedAt.UTC().Format("2 Jan 2006 15:04")+" UTC", p.Volume)
	return map[string]any{"volume": p.Volume, "stopped": stopped}, nil
}

// pruneVolumeBackups removes a cron job's copies of a volume beyond keep;
// a nil schedule means the copies made by hand.
func (st *storageHandler) pruneVolumeBackups(ctx context.Context, t *jobs.Task, server uuid.UUID, volume string, schedule *uuid.UUID, keep int) {
	if keep <= 0 {
		return
	}
	old, err := st.q.OldDockerVolumeBackups(ctx, sqlc.OldDockerVolumeBackupsParams{ServerID: server, Volume: volume, ScheduleID: schedule, Keep: int32(keep)})
	if err != nil {
		slog.Warn("docker: old volume backups", "error", err)
		return
	}
	for _, b := range old {
		if err := st.removeVolumeBackup(ctx, b); err != nil {
			t.Logf("Couldn't remove the old copy %s: %s", b.Path, problemText(err))
			continue
		}
		t.Logf("Removed the old copy %s.", b.Path)
	}
}

func (st *storageHandler) removeVolumeBackup(ctx context.Context, b sqlc.DockerVolumeBackup) error {
	if b.StorageID != nil && b.State == "stored" {
		row, err := st.q.GetStorage(ctx, *b.StorageID)
		if err == nil {
			c, err := st.acquire(ctx, row)
			if err != nil {
				return err
			}
			err = c.fs.Remove(ctx, b.Path)
			st.release(c)
			if err != nil && !isMissingFile(err) {
				return err
			}
		} else if !isNotFound(err) {
			return err
		}
	}
	return st.q.DeleteDockerVolumeBackup(ctx, b.ID)
}

func isMissingFile(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}

func registerDockerVolumeBackups(api huma.API, st *storageHandler) {
	h := st.servers
	tags := []string{"Containers"}
	if err := st.q.FailStaleDockerVolumeBackups(context.Background()); err != nil {
		slog.Warn("docker: closing cut-off volume backups", "error", err)
	}

	huma.Register(api, huma.Operation{
		OperationID: "list-docker-volume-backups",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/docker/volume-backups",
		Summary:     "Copies of a server's volumes kept on storages",
		Description: "Newest first, at most 500.",
		Tags:        tags,
	}, func(ctx context.Context, in *DockerVolumeBackupsInput) (*struct {
		Body struct {
			Items []DockerVolumeBackup `json:"items"`
		}
	}, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		var vol *string
		if v := strings.TrimSpace(in.Volume); v != "" {
			vol = &v
		}
		rows, err := st.q.ListDockerVolumeBackups(ctx, sqlc.ListDockerVolumeBackupsParams{ServerID: s.ID, Volume: vol})
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []DockerVolumeBackup `json:"items"`
			}
		}{}
		out.Body.Items = make([]DockerVolumeBackup, 0, len(rows))
		for _, r := range rows {
			out.Body.Items = append(out.Body.Items, toVolumeBackup(r))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "backup-docker-volume",
		Method:        http.MethodPost,
		Path:          "/servers/{id}/docker/volumes/{volume}/backup",
		Summary:       "Copy a volume to a storage",
		Description:   "Packs the volume's folder (tar.gz, as root) and streams it to the storage, as a job (kind `docker-volume-backup`). Needs Engineer on the storage too.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		DockerVolumePath
		Body DockerVolumeBackupBody
	}) (*JobOutput, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if !volumeNamePattern.MatchString(in.Volume) {
			return nil, huma.Error422UnprocessableEntity("Not a volume name")
		}
		row, err := st.writableStorage(ctx, s.WorkspaceID, in.Body.StorageID, "body.storage_id")
		if err != nil {
			return nil, err
		}
		folder := strings.TrimSpace(in.Body.Folder)
		if folder != "" && strings.ContainsRune(folder, 0) {
			return nil, fieldError("body.folder", "Not a folder.", folder)
		}
		by := ""
		if pr := principalOf(ctx); pr != nil {
			by = cmpOr(pr.User.FullName, pr.User.Username)
		}
		return submit(ctx, h.jobs, jobs.Spec{
			Kind: dockerVolumeBackupKind, Title: "Back up the volume " + in.Volume + " on " + s.Name + " to " + row.Name,
			Params: volumeBackupParams{ServerID: in.ID, Volume: in.Volume, StorageID: row.ID.String(), Folder: folder, Stop: in.Body.Stop, By: by},
			Refs:   placeRefs(in.ID, row.ID.String()), Target: &JobPlace{ServerID: in.ID, Name: s.Name},
		})
	})
	h.jobs.Handle(dockerVolumeBackupKind, func(ctx context.Context, t *jobs.Task) (any, error) {
		var p volumeBackupParams
		if err := t.Decode(&p); err != nil {
			return nil, err
		}
		b, err := st.backupVolume(ctx, t, p)
		if err != nil {
			return nil, err
		}
		// Copies made by hand are kept as the container settings say.
		if p.ScheduleID == "" {
			if srv, err := h.get(ctx, p.ServerID); err == nil {
				if set, err := h.serverDockerSettings(ctx, srv); err == nil && set.BackupKeep > 0 {
					st.pruneVolumeBackups(ctx, t, srv.ID, p.Volume, nil, set.BackupKeep)
				}
			}
		}
		return toVolumeBackup(b), nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "restore-docker-volume-backup",
		Method:        http.MethodPost,
		Path:          "/servers/{id}/docker/volume-backups/{backup}/restore",
		Summary:       "Put a volume's copy back",
		Description:   "Streams the copy from its storage into the volume (created when missing), as a job (kind `docker-volume-restore`). Needs Operator on the storage too.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		DockerVolumeBackupPath
		Body DockerVolumeRestoreBody
	}) (*JobOutput, error) {
		s, b, err := st.volumeBackup(ctx, in.ID, in.Backup)
		if err != nil {
			return nil, err
		}
		if b.State != "stored" {
			return nil, huma.Error409Conflict("This copy wasn't stored, so there is nothing to put back.")
		}
		if b.StorageID == nil {
			return nil, huma.Error409Conflict("Its storage was removed, and the copy with it.")
		}
		if lvl, err := h.authz.storageLevel(ctx, principalOf(ctx).Access, *b.StorageID); err != nil {
			return nil, err
		} else if lvl < auth.Operator {
			return nil, forbidden(auth.Operator)
		}
		vol := cmpOr(strings.TrimSpace(in.Body.Volume), b.Volume)
		if !volumeNamePattern.MatchString(vol) {
			return nil, fieldError("body.volume", "Use letters, digits, _ . and -, starting with a letter or digit.", vol)
		}
		return submit(ctx, h.jobs, jobs.Spec{
			Kind: dockerVolumeRestoreKind, Title: "Restore the volume " + vol + " on " + s.Name,
			Params: volumeRestoreParams{ServerID: in.ID, BackupID: b.ID.String(), Volume: vol, Replace: in.Body.Replace, Stop: in.Body.Stop},
			Refs:   placeRefs(in.ID, b.StorageID.String()), Target: &JobPlace{ServerID: in.ID, Name: s.Name},
		})
	})
	h.jobs.Handle(dockerVolumeRestoreKind, func(ctx context.Context, t *jobs.Task) (any, error) {
		var p volumeRestoreParams
		if err := t.Decode(&p); err != nil {
			return nil, err
		}
		return st.restoreVolume(ctx, t, p)
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-docker-volume-backup",
		Method:      http.MethodDelete,
		Path:        "/servers/{id}/docker/volume-backups/{backup}",
		Summary:     "Remove a volume's copy, with its file on the storage",
		Tags:        tags,
	}, func(ctx context.Context, in *DockerVolumeBackupPath) (*struct{}, error) {
		_, b, err := st.volumeBackup(ctx, in.ID, in.Backup)
		if err != nil {
			return nil, err
		}
		if b.State == "running" {
			return nil, huma.Error409Conflict("It's being made now. Stop its task first.")
		}
		if b.StorageID != nil && b.State == "stored" {
			if lvl, err := h.authz.storageLevel(ctx, principalOf(ctx).Access, *b.StorageID); err != nil {
				return nil, err
			} else if lvl > auth.None && lvl < auth.Engineer {
				return nil, forbidden(auth.Engineer)
			}
		}
		if err := st.removeVolumeBackup(ctx, b); err != nil {
			return nil, huma.Error502BadGateway("Couldn't remove the file: " + problemText(err))
		}
		return nil, nil
	})
}

func (st *storageHandler) volumeBackup(ctx context.Context, serverID, backupID string) (sqlc.Server, sqlc.DockerVolumeBackup, error) {
	s, err := st.servers.get(ctx, serverID)
	if err != nil {
		return s, sqlc.DockerVolumeBackup{}, err
	}
	bid, err := uuid.Parse(backupID)
	if err != nil {
		return s, sqlc.DockerVolumeBackup{}, huma.Error404NotFound("backup not found")
	}
	b, err := st.q.GetDockerVolumeBackup(ctx, sqlc.GetDockerVolumeBackupParams{ID: bid, ServerID: s.ID})
	if err != nil {
		if isNotFound(err) {
			return s, b, huma.Error404NotFound("This copy isn't kept any more")
		}
		return s, b, internalError(err)
	}
	return s, b, nil
}

// writableStorage checks a storage the caller writes a file to.
func (st *storageHandler) writableStorage(ctx context.Context, ws uuid.UUID, raw, loc string) (sqlc.Storage, error) {
	id, err := uuid.Parse(raw)
	if err != nil {
		return sqlc.Storage{}, fieldError(loc, "Choose a storage.", raw)
	}
	row, err := st.q.GetStorage(ctx, id)
	if isNotFound(err) || (err == nil && row.WorkspaceID != ws) {
		return row, fieldError(loc, "This storage isn't in this workspace.", raw)
	}
	if err != nil {
		return row, internalError(err)
	}
	if row.ReadOnly {
		return row, fieldError(loc, row.Name+" is read-only in Morche, so nothing can be written to it.", raw)
	}
	lvl := principalOf(ctx).Access.StorageLevel(ws, id)
	if lvl == auth.None {
		return row, fieldError(loc, "This storage isn't in this workspace.", raw)
	}
	if lvl < auth.Engineer {
		return row, forbidden(auth.Engineer)
	}
	return row, nil
}
