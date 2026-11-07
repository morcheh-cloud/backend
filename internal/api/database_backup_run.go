package api

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"log/slog"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/dbbackup"
	"github.com/morcheh/backend/internal/dbmon"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/storage"
	"github.com/morcheh/backend/internal/terminal"
)

// How much of a dump's start is kept to find the binary log position in.
const backupHeadBytes = 64 << 10

// errChainBroken: an incremental can't build on the backup before it, so a
// full one is needed.
var errChainBroken = errors.New("the chain can't be continued")

// ---- Runs ----

// syncRun ends a stored run whose job ended without it (Morcheh stopped
// halfway) and says whether it did.
func (h *backupHandler) syncRun(ctx context.Context, b sqlc.DatabaseBackup) bool {
	if !jobs.Active(b.State) {
		return false
	}
	end := func(state, msg string) bool {
		if err := h.q.EndBackup(ctx, sqlc.EndBackupParams{ID: b.ID, State: state, Error: msg}); err != nil {
			slog.Warn("end a database backup", "backup", b.ID, "error", err)
			return false
		}
		if err := h.q.FailBackupCopies(ctx, b.ID); err != nil {
			slog.Warn("fail a database backup's copies", "backup", b.ID, "error", err)
		}
		return true
	}
	if b.JobID == nil {
		if time.Since(b.CreatedAt) < time.Minute {
			return false
		}
		return end(jobs.Interrupted, backupLost)
	}
	j, err := h.runner.Get(ctx, *b.JobID)
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

// busy says a run of the plan is still queued or running.
func (h *backupHandler) busy(ctx context.Context, id uuid.UUID) (bool, error) {
	runs, err := h.q.ListActiveBackups(ctx, &id)
	if err != nil {
		return false, err
	}
	for _, r := range runs {
		if !h.syncRun(ctx, r) {
			return true, nil
		}
	}
	return false, nil
}

// backupParams are a backup job's (Backups) or a check's (Backup). A backup job
// queued before plans covered several databases has only Backup.
type backupParams struct {
	Backups []string `json:"backups,omitempty"`
	Backup  string   `json:"backup,omitempty"`
}

// start runs a plan: by a person, or by the clock when by is nil. A person is
// told why it can't run; the clock writes it down as a failed (or, when the
// run before is still going, skipped) run.
func (h *backupHandler) start(ctx context.Context, p sqlc.DatabaseBackupPlan, by *principal) (*sqlc.Job, error) {
	d, err := h.q.GetDatabase(ctx, p.DatabaseID)
	if err != nil {
		return nil, internalError(err)
	}
	busy, err := h.busy(ctx, p.ID)
	if err != nil {
		return nil, internalError(err)
	}
	if busy && by != nil {
		return nil, huma.Error409Conflict("It's running now. Wait for it to finish, or stop it first.")
	}
	base := sqlc.CreateBackupParams{
		WorkspaceID: p.WorkspaceID, DatabaseID: p.DatabaseID, PlanID: &p.ID, PlanName: p.Name,
		Engine: d.Engine, Trigger: "schedule", State: jobs.Queued,
	}
	if by != nil {
		base.Trigger = "manual"
		base.CreatedBy = by.ID()
		base.CreatedByName = cmpOr(by.User.FullName, by.User.Username)
	}
	// A run that can't start leaves one row saying why.
	refuse := func(state string, why error) (*sqlc.Job, error) {
		if by != nil {
			return nil, huma.Error422UnprocessableEntity(problemText(why))
		}
		now := time.Now()
		row := base
		row.State, row.Error, row.FinishedAt = state, problemText(why), &now
		_, err := h.q.CreateBackup(ctx, row)
		return nil, err
	}
	if busy {
		return refuse("skipped", errors.New("The run before was still going."))
	}
	place, problem := h.ready(ctx, d, p)
	if problem != nil {
		return refuse(jobs.Failed, problem)
	}
	targets, err := h.targetsOf(ctx, d, p)
	if err != nil {
		return refuse(jobs.Failed, err)
	}

	rows := make([]sqlc.DatabaseBackup, 0, len(targets))
	ids := make([]string, 0, len(targets))
	fail := func(err error) (*sqlc.Job, error) {
		for _, b := range rows {
			_ = h.q.EndBackup(ctx, sqlc.EndBackupParams{ID: b.ID, State: jobs.Failed, Error: "It couldn't be queued."})
			_ = h.q.FailBackupCopies(ctx, b.ID)
		}
		return nil, internalError(err)
	}
	for _, target := range targets {
		row := base
		row.Target = target
		b, err := h.q.CreateBackup(ctx, row)
		if err != nil {
			return fail(err)
		}
		rows = append(rows, b)
		ids = append(ids, b.ID.String())
		for _, s := range place.storages {
			if err := h.q.CreateBackupCopy(ctx, sqlc.CreateBackupCopyParams{BackupID: b.ID, StorageID: &s.ID, StorageName: s.Name}); err != nil {
				return fail(err)
			}
		}
	}

	// uuid.Nil stands for Morcheh's own machine, so its runs queue together.
	refs := []uuid.UUID{place.server.ID}
	names := make([]string, len(place.storages))
	for i, s := range place.storages {
		refs = append(refs, s.ID)
		names[i] = s.Name
	}
	what := d.Name
	if len(targets) == 1 && targets[0] != "" && targets[0] != d.Name {
		what = targets[0] + " on " + d.Name
	} else if len(targets) > 1 {
		what = fmt.Sprintf("%d databases on %s", len(targets), d.Name)
	}
	first := place.storages[0]
	spec := jobs.Spec{
		Kind:   backupKind,
		Title:  fmt.Sprintf("Back up %s to %s", what, strings.Join(names, ", ")),
		Params: backupParams{Backups: ids},
		Refs:   refs,
		Target: JobPlace{
			StorageID: first.ID.String(), Name: first.Name, DatabaseID: d.ID.String(),
			Path: path.Join(backupFolder(p.Folder, time.Now().In(scheduleLoc(p.Timezone))), backupSlug(d.Name)),
		},
	}
	if by != nil {
		spec.CreatedBy = by.ID()
	}
	job, err := h.runner.Submit(ctx, spec)
	if err != nil {
		return fail(err)
	}
	for _, b := range rows {
		if err := h.q.SetBackupJob(ctx, sqlc.SetBackupJobParams{ID: b.ID, JobID: &job.ID}); err != nil {
			slog.Warn("link a database backup to its job", "backup", b.ID, "error", err)
		}
	}
	return &job, nil
}

// runJob is the database-backup job: one dump per database of the run, one
// after another, then the plan's retention.
func (h *backupHandler) runJob(ctx context.Context, t *jobs.Task) (any, error) {
	var params backupParams
	if err := t.Decode(&params); err != nil {
		return nil, err
	}
	ids := params.Backups
	if len(ids) == 0 && params.Backup != "" {
		ids = []string{params.Backup}
	}
	bg := context.WithoutCancel(ctx)
	var rows []sqlc.DatabaseBackup
	for _, raw := range ids {
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, err
		}
		b, err := h.q.GetBackup(bg, id)
		if isNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if jobs.Active(b.State) {
			rows = append(rows, b)
		}
	}
	if len(rows) == 0 {
		return nil, nil
	}
	end := func(b sqlc.DatabaseBackup, err error) {
		state, msg := jobs.Failed, problemText(err)
		switch {
		case t.Canceled():
			state, msg = jobs.Canceled, ""
		case ctx.Err() != nil:
			state, msg = jobs.Interrupted, backupLost
		}
		if e := h.q.EndBackup(bg, sqlc.EndBackupParams{ID: b.ID, State: state, Error: msg}); e != nil {
			slog.Warn("end a database backup", "backup", b.ID, "error", e)
		}
		if e := h.q.FailBackupCopies(bg, b.ID); e != nil {
			slog.Warn("fail a database backup's copies", "backup", b.ID, "error", e)
		}
	}
	failAll := func(err error) (any, error) {
		for _, b := range rows {
			end(b, err)
		}
		return nil, err
	}

	if rows[0].PlanID == nil {
		return failAll(errors.New("Its plan was deleted."))
	}
	p, err := h.q.GetBackupPlan(bg, *rows[0].PlanID)
	if isNotFound(err) {
		return failAll(errors.New("Its plan was deleted."))
	}
	if err != nil {
		return failAll(err)
	}
	d, err := h.q.GetDatabase(bg, p.DatabaseID)
	if err != nil {
		return failAll(err)
	}
	place, err := h.ready(ctx, d, p)
	if err != nil {
		return failAll(err)
	}
	user, sealed := d.Username, d.PasswordEnc
	if p.Username != "" {
		user, sealed = p.Username, p.PasswordEnc
	}
	password, err := h.db.box.Open(sealed)
	if err != nil {
		return failAll(err)
	}

	var failed []string
	var total int64
	for i, b := range rows {
		if ctx.Err() != nil {
			end(b, ctx.Err())
			continue
		}
		label := cmpOr(b.Target, d.Name)
		t.Update(func(pr *jobs.Progress) {
			pr.Items, pr.ItemsTotal, pr.Current, pr.Phase, pr.Done = i, len(rows), label, "Dumping", 0
		})
		res, err := h.dumpOne(ctx, t, b, p, d, place, user, password)
		if err != nil {
			end(b, err)
			if ctx.Err() == nil {
				failed = append(failed, label+": "+problemText(err))
				t.Logf("%s failed: %s", label, problemText(err))
			}
			continue
		}
		total += res.bytes
		t.Logf("Stored %s (%s)", label, humanBytes(res.bytes))
	}
	t.Update(func(pr *jobs.Progress) { pr.Items = len(rows) })
	h.prune(bg, t, p)

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch {
	case len(failed) == 0:
		return map[string]any{"backups": len(rows), "bytes": total}, nil
	case len(rows) == 1:
		_, why, _ := strings.Cut(failed[0], ": ")
		return nil, errors.New(why)
	}
	return nil, fmt.Errorf("%d of %d databases failed. %s", len(failed), len(rows), strings.Join(failed, "; "))
}

// dumpOne takes one database's backup: an incremental when the plan asks for
// one and there's a chain to build on, a full one otherwise.
func (h *backupHandler) dumpOne(ctx context.Context, t *jobs.Task, b sqlc.DatabaseBackup, p sqlc.DatabaseBackupPlan,
	d sqlc.Database, place backupPlace, user, password string) (backupResult, error) {
	now := time.Now().In(scheduleLoc(p.Timezone))
	target := backupTarget(d, user, password, b.Target, b.ID.String())
	kind, parent := "full", (*uuid.UUID)(nil)
	if p.Method == "incremental" && dbbackup.Incremental(d.Engine).Supported {
		base, why, err := h.incrementalBase(ctx, p, d, b.Target, place.storages)
		switch {
		case err != nil:
			return backupResult{}, err
		case base != nil:
			kind, parent = "incremental", &base.ID
			target.Incremental, target.Position = true, base.Position
			t.Logf("%s: incremental on top of the backup of %s", cmpOr(b.Target, d.Name), base.CreatedAt.In(now.Location()).Format("2006-01-02 15:04"))
		default:
			target.Chain = true
			if why != "" {
				t.Logf("%s: a full backup, since %s", cmpOr(b.Target, d.Name), why)
			}
		}
	}
	script := dumpScript{
		server: place.server.ID, secrets: []string{password},
		// A container takes docker, SQL Server's file belongs to its own user.
		root: d.Container != "" || d.Engine == dbmon.MSSQL,
	}
	if d.Mode == "server" {
		script.container = d.Container
	}

	for attempt := 0; ; attempt++ {
		spec, err := dbbackup.Build(target)
		if err != nil {
			return backupResult{}, err
		}
		file := backupPath(backupFolder(p.Folder, now), d.Name, b.Target, now, b.ID, spec.Ext)
		if err := h.q.StartBackup(ctx, sqlc.StartBackupParams{ID: b.ID, Path: file, Format: spec.Format, Kind: kind, ParentID: parent}); err != nil {
			return backupResult{}, err
		}
		script.script = spec.Script
		res, err := h.stream(ctx, t, script, spec, place.storages, b.ID, file)
		if errors.Is(err, errChainBroken) && target.Incremental && attempt == 0 {
			t.Logf("%s: the backup it builds on no longer fits the database (another backup or a restore moved it on); taking a full one instead.", cmpOr(b.Target, d.Name))
			target.Incremental, target.Chain, target.Position = false, true, ""
			kind, parent = "full", nil
			for _, s := range place.storages {
				_ = h.q.SetBackupCopy(ctx, sqlc.SetBackupCopyParams{State: "pending", BackupID: b.ID, StorageID: &s.ID})
			}
			continue
		}
		if errors.Is(err, errChainBroken) {
			return res, errors.New("The binary log the backup needs is gone from the server.")
		}
		if err != nil {
			return res, err
		}
		position := res.marks.position
		if position == "" && spec.HeadPosition {
			position = dbbackup.PositionIn(res.head)
		}
		if target.Chain && position == "" {
			t.Logf("%s: couldn't read where the binary log stood, so the next backup will be a full one too.", cmpOr(b.Target, d.Name))
		}
		if err := h.q.FinishBackup(context.WithoutCancel(ctx), sqlc.FinishBackupParams{
			ID: b.ID, Bytes: res.bytes, Sha256: res.sum, Position: position, Error: res.warning,
		}); err != nil {
			return res, err
		}
		return res, nil
	}
}

// incrementalBase is what an incremental of target builds on, or nil (and
// why, when there's something to say) when it has to be a full one.
func (h *backupHandler) incrementalBase(ctx context.Context, p sqlc.DatabaseBackupPlan, d sqlc.Database,
	target string, storages []sqlc.Storage) (*sqlc.DatabaseBackup, string, error) {
	last, err := h.q.LastPlanBackup(ctx, sqlc.LastPlanBackupParams{PlanID: &p.ID, Target: target})
	if isNotFound(err) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	if last.Position == "" {
		return nil, "the backup before didn't record where it stopped", nil
	}
	chain, err := h.q.BackupChain(ctx, last.ID)
	if err != nil {
		return nil, "", err
	}
	root := chain[0]
	if root.Kind != "full" || slices.ContainsFunc(chain, func(b sqlc.DatabaseBackup) bool { return b.State != jobs.Succeeded }) {
		return nil, "the backups before it are incomplete", nil
	}
	if age := time.Since(root.CreatedAt); age >= time.Duration(p.FullEveryDays)*24*time.Hour {
		return nil, fmt.Sprintf("the last full one is %d days old", int(age.Hours()/24)), nil
	}
	restored, err := h.q.LastRestoreAt(ctx, sqlc.LastRestoreAtParams{DatabaseID: d.ID, TargetName: cmpOr(target, d.Name)})
	if err != nil {
		return nil, "", err
	}
	if restored.After(last.CreatedAt) {
		return nil, "the database was restored after the last backup", nil
	}
	ids := make([]uuid.UUID, len(chain))
	for i, b := range chain {
		ids[i] = b.ID
	}
	copies, err := h.q.ListBackupCopies(ctx, ids)
	if err != nil {
		return nil, "", err
	}
	for _, s := range storages {
		for _, b := range chain {
			if !slices.ContainsFunc(copies, func(c sqlc.DatabaseBackupCopy) bool {
				return c.BackupID == b.ID && c.State == "stored" && c.StorageID != nil && *c.StorageID == s.ID
			}) {
				return nil, s.Name + " doesn't hold the backups it would build on", nil
			}
		}
	}
	if d.Engine == dbmon.MSSQL {
		// A differential holds everything since the full one.
		return &root, "", nil
	}
	return &last, "", nil
}

// backupTarget says what to dump as the script will see it.
func backupTarget(d sqlc.Database, user, password, name, id string) dbbackup.Target {
	t := dbbackup.Target{
		Engine: d.Engine, Host: d.Host, Port: int(d.Port), Username: user, Password: password,
		AuthDatabase: d.Dbname, Name: name, TLS: d.Tls, CACert: d.CaCert, Local: local(d), ID: id,
	}
	if d.Mode == "server" && d.Container != "" {
		// Inside the container it's on localhost. A set host means the port is
		// the one published on the server, not the one inside.
		t.Host, t.TLS, t.CACert, t.Local = "127.0.0.1", dbmon.TLSDisable, "", true
		if d.Host != "" {
			t.Port = 0
		}
	}
	return t
}

// ---- Running a script on a server ----

// wrapCommand runs shell as root when asked, inside a container when there is
// one. prefix goes on stdin first: sudo -S reads its password a byte at a time,
// so the rest of stdin reaches the shell.
func wrapCommand(priv privilege, sudoPassword, container, shell string) (cmd, prefix string) {
	cmd = shell
	if container != "" {
		cmd = "docker exec -i -- " + terminal.ShellQuote(container) + " " + shell
	}
	switch priv {
	case privSudo:
		cmd = "sudo -n " + cmd
	case privSudoPassword:
		cmd, prefix = "sudo -S -p '' "+cmd, sudoPassword+"\n"
	}
	return cmd, prefix
}

// dumpCommand is what to run over SSH and what to feed it. The script goes in
// on stdin (never a command line, where it'd show in `ps`).
func dumpCommand(priv privilege, sudoPassword, container, script string) (cmd, stdin string) {
	cmd, prefix := wrapCommand(priv, sudoPassword, container, "sh -s")
	return cmd, prefix + script
}

// feedCommand runs a script of n bytes read from stdin, leaving the rest of
// stdin (the data) to the script.
func feedCommand(n int) string {
	return fmt.Sprintf(`sh -c 's=$(dd bs=1 count=%d 2>/dev/null) && eval "$s"'`, n)
}

// scrub takes secrets out of what a tool printed.
func scrub(s string, secrets ...string) string {
	for _, v := range secrets {
		if v != "" {
			s = strings.ReplaceAll(s, v, "•••")
		}
	}
	return strings.TrimSpace(s)
}

// tailWriter keeps the last bytes written.
type tailWriter struct {
	b []byte
}

func (t *tailWriter) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > backupStderrTail {
		t.b = t.b[len(t.b)-backupStderrTail:]
	}
	return len(p), nil
}

// headWriter keeps the first bytes written.
type headWriter struct {
	b []byte
}

func (h *headWriter) Write(p []byte) (int, error) {
	if room := backupHeadBytes - len(h.b); room > 0 {
		h.b = append(h.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

// sink counts and hashes what reaches the Storages.
type sink struct {
	w    io.Writer
	hash hash.Hash
	n    int64
	t    *jobs.Task
}

func (s *sink) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	s.hash.Write(p[:n])
	s.n += int64(n)
	s.t.Add(int64(n))
	return n, err
}

// dumpScript is a script and how to run it. With data, the script reads it on
// stdin (a restore); without, its stdout is the backup. No server = on the
// machine Morcheh runs on.
type dumpScript struct {
	server    uuid.UUID
	container string
	root      bool
	script    string
	secrets   []string
	data      io.Reader
}

// dumpMarks are what a script said on stderr for Morcheh.
type dumpMarks struct {
	position string
	broken   bool
}

// readMarks takes Morcheh's lines out of what a script printed.
func readMarks(s string) (dumpMarks, string) {
	var m dumpMarks
	var rest []string
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(l, dbbackup.PositionMark):
			m.position = strings.TrimPrefix(l, dbbackup.PositionMark)
		case l == dbbackup.BrokenMark:
			m.broken = true
		default:
			rest = append(rest, line)
		}
	}
	return m, strings.Join(rest, "\n")
}

// runDump runs the script on its server, its stdout going to out. It
// reconnects once when the connection turns out to be stale.
func (h *backupHandler) runDump(ctx context.Context, t *jobs.Task, s dumpScript, out io.Writer) (dumpMarks, error) {
	if s.runsLocally() {
		return h.runLocal(ctx, t, s, out)
	}
	id := s.server.String()
	servers := h.st.servers
	for attempt := 0; ; attempt++ {
		c, err := servers.conn(ctx, id)
		if err != nil {
			return dumpMarks{}, err
		}
		started := false
		var marks dumpMarks
		err = hold(c, func() error {
			priv, password := privUser, ""
			if s.root {
				sh, err := servers.rootShell(ctx, id, c)
				if err != nil {
					return err
				}
				priv, password = sh.priv, sh.password
			}
			shell := "sh -s"
			if s.data != nil {
				shell = feedCommand(len(s.script))
			}
			cmd, prefix := wrapCommand(priv, password, s.container, shell)
			var stdin io.Reader = strings.NewReader(prefix + s.script)
			if s.data != nil {
				stdin = io.MultiReader(stdin, s.data)
			}
			var err error
			started, marks, err = execDump(ctx, t, c, cmd, stdin, out, append(s.secrets, password))
			return err
		})
		// Nothing was read from stdin yet, so it can go again as it is.
		if err != nil && !started && attempt == 0 && sshpool.Lost(err) {
			servers.pool.Drop(id)
			continue
		}
		return marks, err
	}
}

// execDump waits for the command. When ctx ends it asks the command to stop,
// then closes the session.
func execDump(ctx context.Context, t *jobs.Task, c *sshpool.Conn, cmd string, stdin io.Reader, out io.Writer, secrets []string) (bool, dumpMarks, error) {
	sess, err := c.Client.NewSession()
	if err != nil {
		return false, dumpMarks{}, err
	}
	defer sess.Close()
	var stderr tailWriter
	sess.Stdout, sess.Stderr, sess.Stdin = out, &stderr, stdin
	if out == nil {
		sess.Stdout = &stderr
	}
	if err := sess.Start(cmd); err != nil {
		return false, dumpMarks{}, err
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
		return true, dumpMarks{}, ctx.Err()
	}
	marks, text := readMarks(string(stderr.b))
	text = scrub(text, secrets...)
	var exit *ssh.ExitError
	var missing *ssh.ExitMissingError
	switch {
	case err == nil:
		if text != "" {
			t.Logf("%s", text)
		}
		return true, marks, nil
	case marks.broken:
		return true, marks, errChainBroken
	case errors.As(err, &exit):
		if text != "" {
			return true, marks, errors.New(text)
		}
		if exit.Signal() != "" {
			return true, marks, errors.New("It was killed by signal " + exit.Signal() + ".")
		}
		return true, marks, fmt.Errorf("It stopped with code %d.", exit.ExitStatus())
	case errors.As(err, &missing):
		return true, marks, errors.New("The connection closed before it finished.")
	}
	return true, marks, err
}

// ---- Streaming to the Storages ----

type backupResult struct {
	bytes   int64
	sum     string
	marks   dumpMarks
	head    []byte
	warning string
}

// backupDest is one Storage a dump goes to.
type backupDest struct {
	row  sqlc.Storage
	conn *storageConn
	pw   *io.PipeWriter
	done chan error
	dead error
}

// fanWriter writes to every Storage still taking the file. One failing drops
// out; when none is left the dump is stopped.
type fanWriter struct {
	dests  []*backupDest
	cancel context.CancelFunc
}

var errNoStorageLeft = errors.New("no storage is taking the file")

func (f *fanWriter) Write(p []byte) (int, error) {
	alive := 0
	for _, d := range f.dests {
		if d.dead != nil {
			continue
		}
		if _, err := d.pw.Write(p); err != nil {
			d.dead = err
			continue
		}
		alive++
	}
	if alive == 0 {
		f.cancel()
		return 0, errNoStorageLeft
	}
	return len(p), nil
}

// stream pipes the dump into every Storage at once: SSH → gzip (when asked) →
// hash → each Storage's Put. It works when at least one Storage got the whole
// file; the others are marked failed on the backup.
func (h *backupHandler) stream(ctx context.Context, t *jobs.Task, s dumpScript, spec dbbackup.Spec,
	storages []sqlc.Storage, id uuid.UUID, file string) (backupResult, error) {
	run, cancel := context.WithCancel(ctx)
	defer cancel()
	bg := context.WithoutCancel(ctx)
	setCopy := func(row sqlc.Storage, err error) {
		state, msg := "stored", ""
		if err != nil {
			state, msg = "failed", problemText(err)
		}
		if e := h.q.SetBackupCopy(bg, sqlc.SetBackupCopyParams{State: state, Error: msg, BackupID: id, StorageID: &row.ID}); e != nil {
			slog.Warn("record a backup copy", "backup", id, "error", e)
		}
	}

	var dests []*backupDest
	var problems []string
	for _, row := range storages {
		c, err := h.st.acquire(ctx, row)
		if err == nil {
			if err = c.fs.Mkdir(ctx, path.Dir(file)); err != nil {
				h.st.release(c)
			}
		}
		if err != nil {
			setCopy(row, err)
			problems = append(problems, row.Name+": "+problemText(err))
			continue
		}
		pr, pw := io.Pipe()
		d := &backupDest{row: row, conn: c, pw: pw, done: make(chan error, 1)}
		go func() {
			err := c.fs.Put(run, file, pr, -1)
			_ = pr.CloseWithError(errors.New("the storage stopped reading"))
			d.done <- err
		}()
		dests = append(dests, d)
	}
	defer func() {
		for _, d := range dests {
			h.st.release(d.conn)
		}
	}()
	if len(dests) == 0 {
		return backupResult{}, errors.New(strings.Join(problems, "; "))
	}

	out := &sink{w: &fanWriter{dests: dests, cancel: cancel}, hash: sha256.New(), t: t}
	var w io.Writer = out
	var gz *gzip.Writer
	if spec.Gzip {
		gz = gzip.NewWriter(out)
		w = gz
	}
	var head headWriter
	if spec.HeadPosition {
		w = io.MultiWriter(&head, w)
	}
	marks, dumpErr := h.runDump(run, t, s, w)
	if dumpErr == nil && gz != nil {
		dumpErr = gz.Close()
	}
	for _, d := range dests {
		if dumpErr != nil {
			_ = d.pw.CloseWithError(dumpErr)
		} else {
			_ = d.pw.Close()
		}
	}
	for _, d := range dests {
		if err := <-d.done; err != nil {
			d.dead = err
		}
	}
	if dumpErr == nil && out.n == 0 {
		dumpErr = errors.New("The backup came out empty.")
	}
	if dumpErr != nil {
		var dests_ []string
		for _, d := range dests {
			removeQuietly(ctx, d.conn.fs, file)
			setCopy(d.row, cmpErr(d.dead, dumpErr))
			if d.dead != nil {
				dests_ = append(dests_, d.row.Name+": "+problemText(d.dead))
			}
		}
		// Every storage failing is what stopped the dump.
		if ctx.Err() == nil && (errors.Is(dumpErr, context.Canceled) || errors.Is(dumpErr, errNoStorageLeft)) && len(dests_) > 0 {
			return backupResult{}, errors.New(strings.Join(append(problems, dests_...), "; "))
		}
		return backupResult{}, dumpErr
	}

	stored := 0
	for _, d := range dests {
		if d.dead == nil {
			if e, err := d.conn.fs.Stat(ctx, file); err != nil {
				d.dead = err
			} else if e.Size != out.n {
				d.dead = fmt.Errorf("It holds %d bytes of the %d sent.", e.Size, out.n)
			}
		}
		if d.dead != nil {
			removeQuietly(ctx, d.conn.fs, file)
			problems = append(problems, d.row.Name+": "+problemText(d.dead))
		} else {
			stored++
		}
		setCopy(d.row, d.dead)
	}
	if stored == 0 {
		return backupResult{}, errors.New(strings.Join(problems, "; "))
	}
	res := backupResult{bytes: out.n, sum: hex.EncodeToString(out.hash.Sum(nil)), marks: marks, head: head.b}
	if len(problems) > 0 {
		res.warning = "Not stored on " + strings.Join(problems, "; ")
		t.Logf("%s", res.warning)
	}
	return res, nil
}

// removeQuietly deletes a half-written file; the run has failed already.
func removeQuietly(ctx context.Context, f storage.FS, file string) {
	clean, cancel := context.WithTimeout(context.WithoutCancel(ctx), backupCleanup)
	defer cancel()
	if err := f.Remove(clean, file); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Warn("remove a partial backup", "path", file, "error", err)
	}
}

// ---- Checking a stored file ----

// runVerify is the database-backup-verify job: it reads every stored copy back
// and compares it with what was sent. A bad file is written on the backup; a
// storage that can't be read says nothing about the file, so it isn't.
func (h *backupHandler) runVerify(ctx context.Context, t *jobs.Task) (any, error) {
	var params backupParams
	if err := t.Decode(&params); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(params.Backup)
	if err != nil {
		return nil, err
	}
	bg := context.WithoutCancel(ctx)
	b, err := h.q.GetBackup(bg, id)
	if err != nil {
		return nil, err
	}
	stored, err := h.storedCopies(bg, b.ID)
	if err != nil {
		return nil, err
	}
	if len(stored) == 0 {
		return nil, errors.New("None of its storages hold the file any more.")
	}
	t.Update(func(p *jobs.Progress) { p.ItemsTotal, p.Total = len(stored), b.Bytes*int64(len(stored)) })
	var bad, unreadable []string
	for i, c := range stored {
		t.Update(func(p *jobs.Progress) { p.Phase, p.Current, p.Items = "Reading", c.StorageName, i })
		problem, err := h.checkCopy(ctx, t, b, *c.StorageID)
		switch {
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case err != nil:
			unreadable = append(unreadable, c.StorageName+": "+problemText(err))
		case problem != "":
			bad = append(bad, c.StorageName+": "+problem)
		default:
			t.Logf("%s: the file is intact", c.StorageName)
		}
	}
	if len(bad) == 0 && len(unreadable) == len(stored) {
		return nil, errors.New(strings.Join(unreadable, "; "))
	}
	problem := strings.Join(bad, "; ")
	if err := h.q.SetBackupVerified(bg, sqlc.SetBackupVerifiedParams{ID: b.ID, VerifyError: problem}); err != nil {
		return nil, err
	}
	if problem != "" {
		return nil, errors.New(problem)
	}
	if len(unreadable) > 0 {
		t.Logf("Couldn't read: %s", strings.Join(unreadable, "; "))
	}
	return map[string]any{"bytes": b.Bytes, "copies": len(stored) - len(unreadable)}, nil
}

// checkCopy reads one stored copy back. problem = the file is wrong; err = it
// couldn't be read.
func (h *backupHandler) checkCopy(ctx context.Context, t *jobs.Task, b sqlc.DatabaseBackup, storageID uuid.UUID) (string, error) {
	var res dbbackup.Result
	var bad error
	err := h.st.withFS(ctx, storageID.String(), func(_ sqlc.Storage, f storage.FS) error {
		file, err := f.Open(ctx, b.Path)
		if err != nil {
			return err
		}
		defer file.Close()
		res, bad = dbbackup.Verify(b.Format, &countingReader{r: file, t: t})
		if bad != nil && res.SHA256 == "" {
			return bad
		}
		return nil
	})
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "The file is gone from the storage.", nil
	case err != nil:
		return "", err
	case res.Bytes != b.Bytes:
		return fmt.Sprintf("The file is %d bytes; %d were stored.", res.Bytes, b.Bytes), nil
	case res.SHA256 != b.Sha256:
		return "The file isn't what was stored: its checksum is different.", nil
	case bad != nil:
		return bad.Error(), nil
	}
	return "", nil
}

type countingReader struct {
	r io.Reader
	t *jobs.Task
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.t.Add(int64(n))
	return n, err
}

// ---- Scheduler ----

// startBackupScheduler runs plans when they're due. A run missed while
// Morcheh was down happens once, when it's back.
func startBackupScheduler(h *backupHandler, every time.Duration) {
	if every <= 0 {
		return
	}
	go func() {
		ctx := context.Background()
		h.fixNext(ctx)
		for range time.Tick(every) {
			h.fire(ctx)
		}
	}()
}

func (h *backupHandler) fixNext(ctx context.Context) {
	plans, err := h.q.ListBackupPlansWithoutNext(ctx)
	if err != nil {
		slog.Warn("list backup plans without a next run", "error", err)
		return
	}
	for _, p := range plans {
		next := nextRun(p.Cron, p.Timezone, time.Now())
		if err := h.q.SetBackupPlanNext(ctx, sqlc.SetBackupPlanNextParams{ID: p.ID, NextRunAt: next}); err != nil {
			slog.Warn("set a backup plan's next run", "plan", p.ID, "error", err)
		}
	}
}

func (h *backupHandler) fire(ctx context.Context) {
	now := time.Now()
	due, err := h.q.ListDueBackupPlans(ctx, &now)
	if err != nil {
		slog.Warn("list due backup plans", "error", err)
		return
	}
	for _, p := range due {
		n, err := h.q.ClaimBackupPlan(ctx, sqlc.ClaimBackupPlanParams{
			ID: p.ID, Due: p.NextRunAt, NextRunAt: nextRun(p.Cron, p.Timezone, now),
		})
		if err != nil {
			slog.Warn("claim a backup plan", "plan", p.ID, "error", err)
			continue
		}
		if n == 0 {
			continue
		}
		if _, err := h.start(ctx, p, nil); err != nil {
			slog.Warn("start a backup plan", "plan", p.ID, "error", err)
		}
	}
}
