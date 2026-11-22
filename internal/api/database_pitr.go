package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/dbmon"
	"github.com/morche/backend/internal/jobs"
	"github.com/morche/backend/internal/pitr"
	"github.com/morche/backend/internal/storage"
)

// Continuous backup (point-in-time recovery) of PostgreSQL with pgBackRest:
// internal/pitr writes the scripts, this runs them on the database's server
// as root and keeps the state. One per database (a PostgreSQL instance):
// archive_command sends every WAL file to the Storage, Morche's scheduler
// takes full/diff/incr backups, and a restore goes to a new instance beside
// the server's own (safe) or over it (replace).

const pitrKind = "database-pitr"

// pitrCheckEvery is how often each repository's state is read.
const pitrCheckEvery = 5 * time.Minute

// pitrCopyPorts is where restored copies listen, on the server's localhost.
const (
	pitrCopyPortFirst = 15432
	pitrCopyPortLast  = 15531
)

// ---- Types ----

// PitrSettingsBody is what a person picks.
type PitrSettingsBody struct {
	StorageID      string `json:"storage_id" format:"uuid" doc:"An S3 storage reached over HTTPS, or an SFTP storage signing in with a key"`
	Folder         string `json:"folder" minLength:"1" maxLength:"1024" doc:"Folder for the repository; for an S3 storage without a fixed bucket, its first part is the bucket" example:"/pgbackrest/shop"`
	FullCron       string `json:"full_cron" minLength:"1" maxLength:"100" doc:"When full backups are taken" example:"0 1 * * 0"`
	DiffCron       string `json:"diff_cron,omitempty" maxLength:"100" doc:"Differential backups (changes since the last full); empty = none" example:"0 1 * * 1-6"`
	IncrCron       string `json:"incr_cron,omitempty" maxLength:"100" doc:"Incremental backups (changes since the last backup of any type); empty = none"`
	Timezone       string `json:"timezone,omitempty" maxLength:"64" example:"Asia/Tehran"`
	RetentionFull  int32  `json:"retention_full" minimum:"1" maximum:"100" doc:"Full backups kept; older ones, their diff/incr and the WAL only they need are deleted"`
	CompressLevel  int32  `json:"compress_level,omitempty" minimum:"1" maximum:"19" default:"3" doc:"zstd level"`
	ProcessMax     int32  `json:"process_max,omitempty" minimum:"1" maximum:"32" default:"2" doc:"Parallel processes for backup, restore and archiving"`
	ArchiveTimeout int32  `json:"archive_timeout" minimum:"0" maximum:"3600" doc:"Seconds after which a WAL file is archived even if it isn't full: the most a quiet database can lose. 0 = only when full (16 MB)"`
	Encrypt        bool   `json:"encrypt" doc:"Encrypt the repository (AES-256); Morche keeps the passphrase. Fixed once the repository exists"`
	ReplaceArchive bool   `json:"replace_archive_command,omitempty" doc:"PostgreSQL already sends its WAL somewhere else: take archive_command over"`
	Enabled        bool   `json:"enabled" doc:"Scheduled backups run (archiving goes on regardless)"`
}

// PitrSettings are the saved choices.
type PitrSettings struct {
	StorageID      string     `json:"storage_id" format:"uuid"`
	StorageName    string     `json:"storage_name"`
	StorageKind    string     `json:"storage_kind" doc:"s3 or sftp"`
	Folder         string     `json:"folder"`
	FullCron       string     `json:"full_cron"`
	DiffCron       string     `json:"diff_cron"`
	IncrCron       string     `json:"incr_cron"`
	Timezone       string     `json:"timezone"`
	RetentionFull  int32      `json:"retention_full"`
	CompressLevel  int32      `json:"compress_level"`
	ProcessMax     int32      `json:"process_max"`
	ArchiveTimeout int32      `json:"archive_timeout"`
	Encrypted      bool       `json:"encrypted"`
	Enabled        bool       `json:"enabled"`
	NextFullAt     *time.Time `json:"next_full_at" nullable:"true"`
	NextDiffAt     *time.Time `json:"next_diff_at" nullable:"true"`
	NextIncrAt     *time.Time `json:"next_incr_at" nullable:"true"`
}

// PitrRun is one thing done for it.
type PitrRun struct {
	ID            string     `json:"id" format:"uuid"`
	Kind          string     `json:"kind" enum:"setup,restart,backup,check,restore,teardown,remove"`
	Variant       string     `json:"variant" doc:"backup: full, diff or incr; restore: new or replace"`
	Trigger       string     `json:"trigger" enum:"manual,schedule"`
	TargetTime    *time.Time `json:"target_time" nullable:"true" doc:"restore: the point in time; null = the newest"`
	State         string     `json:"state" enum:"queued,running,succeeded,failed,canceled,interrupted,skipped"`
	Error         string     `json:"error"`
	JobID         *string    `json:"job_id" format:"uuid" nullable:"true"`
	RestoreDir    string     `json:"restore_dir"`
	RestorePort   *int32     `json:"restore_port" nullable:"true"`
	CopyID        *string    `json:"copy_database_id" format:"uuid" nullable:"true" doc:"The temporary database Morche added for a restored copy"`
	Removed       bool       `json:"removed" doc:"A restored copy that's been taken down"`
	CreatedByName string     `json:"created_by_name"`
	CreatedAt     time.Time  `json:"created_at"`
	StartedAt     *time.Time `json:"started_at" nullable:"true"`
	FinishedAt    *time.Time `json:"finished_at" nullable:"true"`
}

// PitrProblem is something that needs a look.
type PitrProblem struct {
	Kind    string `json:"kind" enum:"archive_failing,archive_stale,no_backup,backup_old,unreachable,restart,repo"`
	Message string `json:"message"`
}

// PitrStatus is everything the page shows.
type PitrStatus struct {
	Supported  bool              `json:"supported"`
	Note       string            `json:"note" doc:"Why it can't be set up, when it can't"`
	Configured bool              `json:"configured"`
	State      string            `json:"state" enum:"none,new,setting_up,needs_restart,ready,broken,removing"`
	Problem    string            `json:"problem"`
	Problems   []PitrProblem     `json:"problems"`
	Settings   *PitrSettings     `json:"settings,omitempty"`
	Cluster    *pitr.PitrCluster `json:"cluster,omitempty"`
	Backups    []pitr.PitrBackup `json:"backups"`
	// How far back it can go.
	WindowFrom *time.Time         `json:"window_from" nullable:"true"`
	WindowTo   *time.Time         `json:"window_to" nullable:"true"`
	Archiver   *pitr.PitrArchiver `json:"archiver,omitempty"`
	WALMin     string             `json:"wal_min"`
	WALMax     string             `json:"wal_max"`
	RepoBytes  int64              `json:"repo_bytes" doc:"What the backups take in the storage (WAL aside)"`
	RepoStatus string             `json:"repo_status" doc:"pgBackRest's word on the repository"`
	CheckedAt  *time.Time         `json:"checked_at" nullable:"true"`
	RestartAt  *time.Time         `json:"restart_at" nullable:"true"`
	Copies     []PitrRun          `json:"copies" doc:"Restored copies still running on the server"`
	Active     *PitrRun           `json:"active,omitempty" doc:"What's running or waiting now"`
	SharedWith *PitrShared        `json:"shared_with,omitempty" doc:"Another database in Morche for the same PostgreSQL that already has it: set up there"`
	ServerName string             `json:"server_name"`
}

// PitrShared names the database a PostgreSQL's continuous backup is set up
// through.
type PitrShared struct {
	ID   string `json:"id" format:"uuid"`
	Name string `json:"name"`
}

type pitrParams struct {
	Run string `json:"run"`
	// backup: full|diff|incr. restore: new|replace + the time (empty = newest).
	Variant string `json:"variant,omitempty"`
	Target  string `json:"target,omitempty"`
	// remove: delete the repository too.
	Purge bool `json:"purge,omitempty"`
	// setup: take archive_command over from whatever set it.
	Replace bool `json:"replace,omitempty"`
	// teardown: the restore run whose copy goes.
	Copy string `json:"copy,omitempty"`
}

// ---- Reading and checking ----

// pitrSupport says whether d can have continuous backup, and why not.
func pitrSupport(d sqlc.Database) (bool, string) {
	switch {
	case d.Engine != dbmon.Postgres:
		return false, "Continuous backup is for PostgreSQL."
	case d.Mode != "server" || d.ServerID == nil:
		return false, "Continuous backup runs on the database's own server: add it through its server (SSH), not by address."
	case d.Container != "":
		return false, "PostgreSQL in a container isn't supported yet: archive_command runs inside the container, so pgBackRest would have to be in its image."
	}
	return true, ""
}

// pitrRepo turns a Storage into pgBackRest's repository settings.
func (h *backupHandler) pitrRepo(s sqlc.Storage, folder string) (pitr.Repo, error) {
	cfg, err := h.st.config(s)
	if err != nil {
		return pitr.Repo{}, internalError(err)
	}
	folder = "/" + strings.Trim(storage.Clean(folder), "/")
	r := pitr.Repo{Type: s.Protocol}
	switch s.Protocol {
	case "s3":
		raw := strings.TrimSpace(cfg.Host)
		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return r, fieldError("body.storage_id", "The storage's address can't be read.", nil)
		}
		if u.Scheme != "https" {
			return r, fieldError("body.storage_id", "pgBackRest talks to S3 only over HTTPS: give "+s.Name+" an https:// address (a self-signed certificate is fine with \"Skip TLS check\" on).", nil)
		}
		r.Endpoint = u.Hostname()
		if p := u.Port(); p != "" {
			r.Port, _ = strconv.Atoi(p)
		} else if cfg.Port > 0 {
			r.Port = cfg.Port
		}
		r.Region, r.Key, r.Secret, r.PathStyle, r.VerifyTLS = cfg.Region, cfg.Username, cfg.Secret, cfg.PathStyle, !cfg.InsecureTLS
		r.Bucket = cfg.Bucket
		inside := path.Join("/", strings.Trim(cfg.Root, "/"), folder)
		if r.Bucket == "" {
			// The folder's first part is the bucket.
			parts := strings.SplitN(strings.TrimPrefix(folder, "/"), "/", 2)
			if parts[0] == "" {
				return r, fieldError("body.folder", "Start the folder with a bucket: /bucket/folder.", nil)
			}
			r.Bucket, inside = parts[0], "/"
			if len(parts) == 2 {
				inside = "/" + parts[1]
			}
		}
		r.Path = inside
	case "sftp":
		if s.AuthMethod != "private_key" || cfg.PrivateKey == "" {
			return r, fieldError("body.storage_id", "pgBackRest signs in to SFTP with a key only: give "+s.Name+" a private key.", nil)
		}
		if cfg.HostKey == "" {
			return r, fieldError("body.storage_id", "Morche doesn't know "+s.Name+"'s host key yet: check the storage once to trust it.", nil)
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.HostKey))
		if err != nil {
			return r, fieldError("body.storage_id", "The storage's saved host key can't be read.", nil)
		}
		r.HostKey = pub.Type() + " " + base64.StdEncoding.EncodeToString(pub.Marshal())
		r.Host, r.Port, r.User, r.PrivateKey, r.Passphrase = cfg.Host, cfg.Port, cfg.Username, cfg.PrivateKey, cfg.Passphrase
		r.Path = path.Join("/", strings.Trim(cfg.Root, "/"), folder)
	default:
		return r, fieldError("body.storage_id", "pgBackRest can use an S3 storage (over HTTPS) or an SFTP one, not "+strings.ToUpper(s.Protocol)+".", nil)
	}
	return r, nil
}

// pitrSettings builds pitr.Settings from a saved row.
func (h *backupHandler) pitrSettings(ctx context.Context, p sqlc.DatabasePitr) (pitr.Settings, sqlc.Storage, error) {
	var out pitr.Settings
	if p.StorageID == nil {
		return out, sqlc.Storage{}, errors.New("Its storage was removed: pick another one in the settings.")
	}
	s, err := h.q.GetStorage(ctx, *p.StorageID)
	if err != nil {
		return out, s, errors.New("Its storage can't be read: " + problemText(err))
	}
	if out.Repo, err = h.pitrRepo(s, p.Folder); err != nil {
		return out, s, errors.New(problemText(err))
	}
	out.RetentionFull, out.CompressLevel, out.ProcessMax, out.ArchiveTimeout =
		int(p.RetentionFull), int(p.CompressLevel), int(p.ProcessMax), int(p.ArchiveTimeout)
	if len(p.CipherPassEnc) > 0 {
		if out.CipherPass, err = h.db.box.Open(p.CipherPassEnc); err != nil {
			return out, s, err
		}
	}
	return out, s, out.Check()
}

// pitrSecrets are what a script's messages must never show. Very short
// values are left out: scrubbing them would blank ordinary words (a dev
// MinIO whose access key is "morche").
func pitrSecrets(s pitr.Settings) []string {
	var out []string
	for _, v := range []string{s.Repo.Secret, s.Repo.Key, s.Repo.Passphrase, s.CipherPass} {
		if len(v) >= 8 {
			out = append(out, v)
		}
	}
	return out
}

// pitrScript runs a script as root on d's server and returns what it
// printed. t may be nil for a quick read outside a job.
func (h *backupHandler) pitrScript(ctx context.Context, t *jobs.Task, d sqlc.Database, script string, secrets []string) (string, error) {
	var out strings.Builder
	s := dumpScript{server: *d.ServerID, root: true, script: script, secrets: secrets}
	_, err := h.runDump(ctx, t, s, &out)
	return out.String(), err
}

// pitrCluster reads the PostgreSQL on d's server.
func (h *backupHandler) pitrCluster(ctx context.Context, t *jobs.Task, d sqlc.Database) (pitr.PitrCluster, error) {
	out, err := h.pitrScript(ctx, t, d, pitr.DetectScript(pitrPort(d)), nil)
	if err != nil {
		return pitr.PitrCluster{}, err
	}
	return pitr.ParseDetect(out, pitrPort(d))
}

// pitrPort is the port PostgreSQL listens on, as its server sees it.
func pitrPort(d sqlc.Database) int {
	if d.Port > 0 {
		return int(d.Port)
	}
	return 5432
}

// storedCluster is what the last detection found.
func storedCluster(p sqlc.DatabasePitr) pitr.PitrCluster {
	var c pitr.PitrCluster
	_ = json.Unmarshal(p.Cluster, &c)
	return c
}

// refreshInfo reads the repository and the archiver, and keeps them.
func (h *backupHandler) refreshInfo(ctx context.Context, t *jobs.Task, d sqlc.Database, p sqlc.DatabasePitr) (pitr.Info, error) {
	s, _, err := h.pitrSettings(ctx, p)
	if err != nil {
		return pitr.Info{}, err
	}
	out, err := h.pitrScript(ctx, t, d, pitr.InfoScript(storedCluster(p)), pitrSecrets(s))
	if err != nil {
		return pitr.Info{}, err
	}
	info, err := pitr.ParseInfo(out)
	if err != nil {
		return info, err
	}
	raw, _ := json.Marshal(info)
	if err := h.q.SetPitrInfo(context.WithoutCancel(ctx), sqlc.SetPitrInfoParams{DatabaseID: d.ID, Info: raw}); err != nil {
		return info, err
	}
	return info, nil
}

// pitrProblems are what the page and the nav count warn about.
func pitrProblems(p sqlc.DatabasePitr, info *pitr.Info, now time.Time) []PitrProblem {
	var out []PitrProblem
	add := func(kind, msg string) { out = append(out, PitrProblem{Kind: kind, Message: msg}) }
	switch p.State {
	case "needs_restart":
		add("restart", "PostgreSQL needs a restart before WAL archiving starts. Until then nothing can be restored.")
	case "broken":
		add("repo", cmpOr(p.Problem, "The last setup or run failed."))
	}
	if p.State != "ready" || info == nil {
		if p.State == "ready" && p.Problem != "" {
			add("unreachable", p.Problem)
		}
		return out
	}
	if p.Problem != "" {
		add("unreachable", "The last check failed: "+p.Problem)
	}
	if info.Archiver.Failing() {
		add("archive_failing", "WAL can't reach the storage ("+info.Archiver.LastFailedWAL+" failed). Until it does, recent changes can't be restored and WAL piles up on the server.")
	}
	if a := info.Archiver.LastArchivedTime; a != nil && p.ArchiveTimeout > 0 &&
		now.Sub(*a) > time.Duration(p.ArchiveTimeout)*time.Second*10+15*time.Minute && info.Archiver.Failing() {
		add("archive_stale", "Nothing has been archived since "+a.UTC().Format("2006-01-02 15:04")+" UTC.")
	}
	if len(info.Backups) == 0 {
		add("no_backup", "There's no backup yet: take a full one to start the window.")
	} else if l := info.Latest(""); l != nil && now.Sub(l.Stop) > 8*24*time.Hour {
		add("backup_old", "The newest backup is "+strconv.Itoa(int(now.Sub(l.Stop).Hours()/24))+" days old.")
	}
	return out
}

func toPitrRun(r sqlc.DatabasePitrRun) PitrRun {
	return PitrRun{
		ID: r.ID.String(), Kind: r.Kind, Variant: r.Variant, Trigger: r.Trigger, TargetTime: r.TargetTime,
		State: r.State, Error: r.Error, JobID: optionalIDString(r.JobID), RestoreDir: r.RestoreDir,
		RestorePort: r.RestorePort, CopyID: optionalIDString(r.RestoreDatabaseID), Removed: r.RemovedAt != nil,
		CreatedByName: r.CreatedByName, CreatedAt: r.CreatedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
	}
}

// status puts the page together from what's stored (no SSH).
func (h *backupHandler) pitrStatus(ctx context.Context, d sqlc.Database) (PitrStatus, error) {
	out := PitrStatus{State: "none", Backups: []pitr.PitrBackup{}, Copies: []PitrRun{}, Problems: []PitrProblem{}}
	out.Supported, out.Note = pitrSupport(d)
	if d.ServerID != nil {
		if srv, err := h.q.GetServer(ctx, *d.ServerID); err == nil {
			out.ServerName = srv.Name
		}
	}
	p, err := h.q.GetPitr(ctx, d.ID)
	if isNotFound(err) {
		if sib := h.pitrSibling(ctx, d); sib != nil {
			out.SharedWith = sib
		}
		return out, nil
	}
	if err != nil {
		return out, internalError(err)
	}
	out.Configured, out.State, out.Problem, out.CheckedAt, out.RestartAt = true, p.State, p.Problem, p.CheckedAt, p.RestartAt
	set := &PitrSettings{
		Folder: p.Folder, FullCron: p.FullCron, DiffCron: p.DiffCron, IncrCron: p.IncrCron, Timezone: p.Timezone,
		RetentionFull: p.RetentionFull, CompressLevel: p.CompressLevel, ProcessMax: p.ProcessMax,
		ArchiveTimeout: p.ArchiveTimeout, Encrypted: len(p.CipherPassEnc) > 0, Enabled: p.Enabled,
		NextFullAt: p.NextFullAt, NextDiffAt: p.NextDiffAt, NextIncrAt: p.NextIncrAt,
	}
	if p.StorageID != nil {
		set.StorageID = p.StorageID.String()
		if s, err := h.q.GetStorage(ctx, *p.StorageID); err == nil {
			set.StorageName, set.StorageKind = s.Name, s.Protocol
		}
	}
	out.Settings = set
	if c := storedCluster(p); c.Version > 0 {
		out.Cluster = &c
	}
	var info *pitr.Info
	if len(p.Info) > 0 {
		var i pitr.Info
		if json.Unmarshal(p.Info, &i) == nil {
			info = &i
			out.Backups = i.Backups
			if out.Backups == nil {
				out.Backups = []pitr.PitrBackup{}
			}
			if from, to := i.Window(); !from.IsZero() {
				out.WindowFrom, out.WindowTo = &from, &to
			}
			out.Archiver, out.WALMin, out.WALMax, out.RepoBytes, out.RepoStatus = &i.Archiver, i.WALMin, i.WALMax, i.RepoSize(), i.Status
		}
	}
	out.Problems = pitrProblems(p, info, time.Now())
	if out.Problems == nil {
		out.Problems = []PitrProblem{}
	}
	copies, err := h.q.ListPitrCopies(ctx, d.ID)
	if err != nil {
		return out, internalError(err)
	}
	for _, r := range copies {
		out.Copies = append(out.Copies, toPitrRun(r))
	}
	if r, err := h.q.ActivePitrRunRow(ctx, d.ID); err == nil {
		v := toPitrRun(r)
		out.Active = &v
	}
	return out, nil
}

// pitrSibling is another row of the same PostgreSQL that has it set up.
func (h *backupHandler) pitrSibling(ctx context.Context, d sqlc.Database) *PitrShared {
	if d.ServerID == nil {
		return nil
	}
	row, err := h.q.PitrSibling(ctx, sqlc.PitrSiblingParams{ServerID: d.ServerID, Port: int32(pitrPort(d)), DatabaseID: d.ID})
	if err != nil {
		return nil
	}
	return &PitrShared{ID: row.ID.String(), Name: row.Name}
}

// pitrRank orders problems, worst first.
var pitrRank = map[string]int{
	"archive_failing": 0, "repo": 1, "archive_stale": 2, "unreachable": 3,
	"restart": 4, "no_backup": 5, "backup_old": 6,
}

// pitrProblemsFor are the continuous backups in scope that need a look,
// for the nav count and Home (from what's stored: no SSH). A failing
// archive matters most: WAL piles up on the server until it works.
func (h *backupHandler) pitrProblemsFor(ctx context.Context, s scope) []BackupProblem {
	rows, err := h.q.ListPitrs(ctx)
	if err != nil {
		return nil
	}
	acc := principalOf(ctx).Access
	now := time.Now()
	var out []BackupProblem
	for _, p := range rows {
		if s.current != nil && p.WorkspaceID != *s.current {
			continue
		}
		d, err := h.q.GetDatabase(ctx, p.DatabaseID)
		if err != nil || databaseLevelOf(acc, d) < auth.Viewer {
			continue
		}
		var info *pitr.Info
		if len(p.Info) > 0 {
			var i pitr.Info
			if json.Unmarshal(p.Info, &i) == nil {
				info = &i
			}
		}
		// One row per database: its worst problem.
		var worst *PitrProblem
		for _, pr := range pitrProblems(p, info, now) {
			if worst == nil || pitrRank[pr.Kind] < pitrRank[worst.Kind] {
				worst = &pr
			}
		}
		if worst == nil {
			continue
		}
		at := now
		if p.CheckedAt != nil {
			at = *p.CheckedAt
		}
		out = append(out, BackupProblem{
			Kind: "pitr", PlanName: "Point in time", DatabaseID: d.ID.String(), DatabaseName: d.Name,
			Error: worst.Message, At: at,
		})
	}
	return out
}

// pitrAccess checks the caller may change continuous backup on d: Owner on
// the database and Engineer on its server (it runs as root there).
func (h *backupHandler) pitrAccess(ctx context.Context, d sqlc.Database) error {
	acc := principalOf(ctx).Access
	if databaseLevelOf(acc, d) < auth.Owner {
		return huma.Error403Forbidden(fmt.Sprintf("You need %s access to %s.", auth.Owner, d.Name))
	}
	if d.ServerID != nil && acc.ServerLevel(d.WorkspaceID, *d.ServerID) < auth.Engineer {
		return huma.Error403Forbidden(fmt.Sprintf("You need %s access to its server.", auth.Engineer))
	}
	return nil
}

// ---- Starting runs ----

// startPitr records a run and queues its job. by is nil for the scheduler.
func (h *backupHandler) startPitr(ctx context.Context, d sqlc.Database, kind, variant string, target *time.Time, params pitrParams, by *principal) (*JobOutput, error) {
	if n, err := h.q.ActivePitrRun(ctx, d.ID); err != nil {
		return nil, internalError(err)
	} else if n > 0 {
		if by == nil {
			// The scheduler's turn passed while something else ran: say so.
			if r, err := h.q.CreatePitrRun(ctx, sqlc.CreatePitrRunParams{DatabaseID: d.ID, Kind: kind, Variant: variant, Trigger: "schedule", TargetTime: target}); err == nil {
				_ = h.q.EndPitrRun(ctx, sqlc.EndPitrRunParams{ID: r.ID, State: "skipped", Error: "Something else was running for this database."})
			}
			return nil, nil
		}
		return nil, huma.Error409Conflict("Something else is running for this database now. Wait for it to finish.")
	}
	row := sqlc.CreatePitrRunParams{DatabaseID: d.ID, Kind: kind, Variant: variant, Trigger: "schedule", TargetTime: target}
	if by != nil {
		row.Trigger, row.CreatedBy, row.CreatedByName = "manual", by.ID(), cmpOr(by.User.FullName, by.User.Username)
	}
	r, err := h.q.CreatePitrRun(ctx, row)
	if err != nil {
		return nil, internalError(err)
	}
	params.Run = r.ID.String()
	titles := map[string]string{
		"setup": "Set up continuous backup of %s", "restart": "Restart PostgreSQL for %s",
		"backup": "Back up %s (" + variant + ")", "check": "Check continuous backup of %s",
		"restore": "Restore %s to a point in time", "teardown": "Take down a restored copy of %s",
		"remove": "Turn off continuous backup of %s",
	}
	// Runs for one database queue behind each other.
	spec := jobs.Spec{
		Kind: pitrKind, Title: fmt.Sprintf(titles[kind], d.Name), Params: params, Refs: []uuid.UUID{d.ID},
		Target: JobPlace{DatabaseID: d.ID.String(), ServerID: d.ServerID.String(), Name: d.Name},
	}
	if by != nil {
		spec.CreatedBy = by.ID()
	}
	out, err := submit(ctx, h.runner, spec)
	if err != nil {
		_ = h.q.EndPitrRun(ctx, sqlc.EndPitrRunParams{ID: r.ID, State: "failed", Error: "It couldn't be queued."})
		return nil, err
	}
	if id, err := uuid.Parse(out.Body.ID); err == nil {
		_ = h.q.SetPitrRunJob(ctx, sqlc.SetPitrRunJobParams{ID: r.ID, JobID: &id})
	}
	return out, nil
}

// newCipherPass makes a repository passphrase.
func newCipherPass() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// checkPitrBody checks the settings and works out the next runs.
func (h *backupHandler) checkPitrBody(ctx context.Context, d sqlc.Database, b PitrSettingsBody, prev *sqlc.DatabasePitr) (sqlc.UpsertPitrParams, error) {
	out := sqlc.UpsertPitrParams{
		DatabaseID: d.ID, WorkspaceID: d.WorkspaceID, Timezone: cmpOr(strings.TrimSpace(b.Timezone), "UTC"),
		RetentionFull: b.RetentionFull, CompressLevel: max(1, b.CompressLevel), ProcessMax: max(1, b.ProcessMax),
		ArchiveTimeout: b.ArchiveTimeout, Enabled: b.Enabled, UpdatedBy: principalOf(ctx).ID(),
		FullCron: strings.TrimSpace(b.FullCron), DiffCron: strings.TrimSpace(b.DiffCron), IncrCron: strings.TrimSpace(b.IncrCron),
	}
	if out.CompressLevel == 0 {
		out.CompressLevel = 3
	}
	sid, err := uuid.Parse(b.StorageID)
	if err != nil {
		return out, fieldError("body.storage_id", "Pick a storage.", nil)
	}
	s, err := h.q.GetStorage(ctx, sid)
	if isNotFound(err) || (err == nil && s.WorkspaceID != d.WorkspaceID) {
		return out, fieldError("body.storage_id", "This storage isn't in this workspace.", nil)
	}
	if err != nil {
		return out, internalError(err)
	}
	acc := principalOf(ctx).Access
	if acc.StorageLevel(s.WorkspaceID, s.ID) < auth.Engineer {
		return out, fieldError("body.storage_id", fmt.Sprintf("You need %s access to %s.", auth.Engineer, s.Name), nil)
	}
	if s.ReadOnly {
		return out, fieldError("body.storage_id", s.Name+" is read-only in Morche.", nil)
	}
	folder := "/" + strings.Trim(storage.Clean(b.Folder), "/")
	if folder == "/" {
		return out, fieldError("body.folder", "Pick a folder of its own, not the top.", nil)
	}
	if _, err := h.pitrRepo(s, folder); err != nil {
		return out, err
	}
	out.StorageID, out.Folder = &s.ID, folder
	now := time.Now()
	for _, c := range []struct {
		expr, field string
		next        **time.Time
	}{{out.FullCron, "full_cron", &out.NextFullAt}, {out.DiffCron, "diff_cron", &out.NextDiffAt}, {out.IncrCron, "incr_cron", &out.NextIncrAt}} {
		if c.expr == "" {
			continue
		}
		if _, _, err := parseCron(c.expr, out.Timezone); err != nil {
			var se huma.StatusError
			if errors.As(err, &se) && strings.Contains(err.Error(), "time zone") {
				return out, err
			}
			return out, fieldError("body."+c.field, problemText(err), c.expr)
		}
		*c.next = nextRun(c.expr, out.Timezone, now)
	}
	// The repository's encryption is fixed when it's made.
	sameRepo := prev != nil && prev.StorageID != nil && *prev.StorageID == s.ID && prev.Folder == folder
	switch {
	case sameRepo && b.Encrypt != (len(prev.CipherPassEnc) > 0):
		return out, fieldError("body.encrypt", "Encryption can't change for a repository that exists: pick a new folder to start one with it "+map[bool]string{true: "on", false: "off"}[b.Encrypt]+".", nil)
	case sameRepo:
		out.CipherPassEnc = prev.CipherPassEnc
	case b.Encrypt && prev != nil && len(prev.CipherPassEnc) > 0:
		// A new repository keeps the passphrase: the old one stays readable
		// with the same one.
		out.CipherPassEnc = prev.CipherPassEnc
	case b.Encrypt:
		out.CipherPassEnc = h.db.box.Seal(newCipherPass())
	}
	return out, nil
}

// ---- Jobs ----

func (h *backupHandler) runPitr(ctx context.Context, t *jobs.Task) (any, error) {
	var params pitrParams
	if err := t.Decode(&params); err != nil {
		return nil, err
	}
	bg := context.WithoutCancel(ctx)
	r, err := h.q.GetPitrRun(bg, uuid.MustParse(params.Run))
	if err != nil {
		return nil, err
	}
	end := func(err error) (any, error) {
		state, msg := "succeeded", ""
		switch {
		case err == nil:
		case t.Canceled():
			state, msg = "canceled", ""
		case ctx.Err() != nil:
			state, msg = "interrupted", backupLost
		default:
			state, msg = "failed", problemText(err)
		}
		_ = h.q.EndPitrRun(bg, sqlc.EndPitrRunParams{ID: r.ID, State: state, Error: msg})
		return nil, err
	}
	if err := h.q.StartPitrRun(bg, r.ID); err != nil {
		return end(err)
	}
	d, err := h.q.GetDatabase(bg, r.DatabaseID)
	if err != nil {
		return end(err)
	}
	if ok, why := pitrSupport(d); !ok {
		return end(errors.New(why))
	}
	p, err := h.q.GetPitr(bg, d.ID)
	if err != nil {
		return end(errors.New("Continuous backup isn't set up for it any more."))
	}
	setState := func(state, problem string) {
		_ = h.q.SetPitrState(bg, sqlc.SetPitrStateParams{DatabaseID: d.ID, State: state, Problem: problem})
	}
	settings, _, err := h.pitrSettings(bg, p)
	if err != nil && r.Kind != "teardown" && r.Kind != "remove" {
		return end(err)
	}
	secrets := pitrSecrets(settings)

	// A restart, a setup or a replace stopped half way can leave PostgreSQL
	// down or half configured: no cancel once they start.
	if r.Kind == "setup" || r.Kind == "restart" || r.Kind == "remove" || (r.Kind == "restore" && r.Variant == "replace") {
		t.Update(func(pr *jobs.Progress) { pr.Locked = true })
	}

	switch r.Kind {
	case "setup":
		setState("setting_up", "")
		c, err := h.pitrCluster(ctx, t, d)
		if err != nil {
			setState("broken", problemText(err))
			return end(err)
		}
		raw, _ := json.Marshal(c)
		_ = h.q.SetPitrCluster(bg, sqlc.SetPitrClusterParams{DatabaseID: d.ID, Cluster: raw})
		if c.InRecovery {
			err := errors.New("This PostgreSQL is a standby. Set continuous backup up on the primary.")
			setState("broken", problemText(err))
			return end(err)
		}
		t.Logf("PostgreSQL %d, data in %s", c.Version, c.DataDir)
		out, err := h.pitrScript(ctx, t, d, pitr.SetupScript(c, settings, params.Replace), secrets)
		if err != nil {
			setState("broken", problemText(err))
			return end(err)
		}
		m := pitr.Marks(out)
		if v := m["pgbackrest"]; v != "" {
			c.PgBackRest = v
			raw, _ := json.Marshal(c)
			_ = h.q.SetPitrCluster(bg, sqlc.SetPitrClusterParams{DatabaseID: d.ID, Cluster: raw})
			t.Logf("pgBackRest %s", v)
		}
		if m["RESTART"] == "1" {
			setState("needs_restart", "")
			t.Logf("PostgreSQL needs a restart before archiving starts.")
			return end(nil)
		}
		setState("ready", "")
		h.afterReady(ctx, t, d)
	case "restart":
		out, err := h.pitrScript(ctx, t, d, pitr.RestartScript(storedCluster(p)), secrets)
		if err != nil {
			return end(err)
		}
		if pitr.Marks(out)["READY"] != "1" {
			return end(errors.New("The restart didn't finish."))
		}
		_ = h.q.SetPitrRestartAt(bg, sqlc.SetPitrRestartAtParams{DatabaseID: d.ID})
		setState("ready", "")
		t.Logf("PostgreSQL is back and WAL reaches the storage.")
		h.afterReady(ctx, t, d)
	case "backup":
		if p.State != "ready" && p.State != "broken" {
			return end(errors.New("It isn't ready to back up yet."))
		}
		if _, err := h.pitrScript(ctx, t, d, pitr.BackupScript(storedCluster(p), params.Variant), secrets); err != nil {
			return end(err)
		}
		if _, err := h.refreshInfo(ctx, t, d, p); err != nil {
			t.Logf("Couldn't read the repository afterwards: %s", problemText(err))
		}
	case "check":
		if _, err := h.pitrScript(ctx, t, d, pitr.CheckScript(storedCluster(p)), secrets); err != nil {
			return end(err)
		}
		_, _ = h.refreshInfo(ctx, t, d, p)
	case "restore":
		return end(h.runPitrRestore(ctx, t, d, p, r, params, secrets))
	case "teardown":
		cr, err := h.q.GetPitrRun(bg, uuid.MustParse(params.Copy))
		if err != nil || cr.DatabaseID != d.ID || cr.RestoreDir == "" {
			return end(errors.New("That copy isn't there any more."))
		}
		if _, err := h.pitrScript(ctx, t, d, pitr.TeardownScript(storedCluster(p), cr.RestoreDir), nil); err != nil {
			return end(err)
		}
		_ = h.q.SetPitrRunRemoved(bg, cr.ID)
		if cr.RestoreDatabaseID != nil {
			_, _ = h.q.DeleteDatabase(bg, *cr.RestoreDatabaseID)
		}
		t.Logf("Removed %s", cr.RestoreDir)
	case "remove":
		setState("removing", "")
		c := storedCluster(p)
		if c.Version > 0 {
			if _, err := h.pitrScript(ctx, t, d, pitr.RemoveScript(c, params.Purge), secrets); err != nil {
				setState("broken", problemText(err))
				return end(err)
			}
		}
		if err := h.q.DeletePitr(bg, d.ID); err != nil {
			return end(err)
		}
		t.Logf("Archiving is off. PostgreSQL turns archive_mode off at its next restart; until then WAL is let go as usual.")
	}
	return end(nil)
}

// afterReady reads the repository and, when there's no backup yet, takes
// the first full one.
func (h *backupHandler) afterReady(ctx context.Context, t *jobs.Task, d sqlc.Database) {
	bg := context.WithoutCancel(ctx)
	p, err := h.q.GetPitr(bg, d.ID)
	if err != nil {
		return
	}
	info, err := h.refreshInfo(ctx, t, d, p)
	if err != nil {
		t.Logf("Couldn't read the repository: %s", problemText(err))
		return
	}
	if len(info.Backups) > 0 {
		return
	}
	s, _, err := h.pitrSettings(bg, p)
	if err != nil {
		return
	}
	t.Logf("Taking the first full backup")
	if _, err := h.pitrScript(ctx, t, d, pitr.BackupScript(storedCluster(p), pitr.Full), pitrSecrets(s)); err != nil {
		t.Logf("The first full backup failed: %s", problemText(err))
		return
	}
	_, _ = h.refreshInfo(ctx, t, d, p)
}

// runPitrRestore restores to a new instance (and adds it to Morche as a
// temporary database) or over the server's own.
func (h *backupHandler) runPitrRestore(ctx context.Context, t *jobs.Task, d sqlc.Database, p sqlc.DatabasePitr, r sqlc.DatabasePitrRun, params pitrParams, secrets []string) error {
	bg := context.WithoutCancel(ctx)
	c := storedCluster(p)
	var at time.Time
	if r.TargetTime != nil {
		at = *r.TargetTime
	}
	if r.Variant == "replace" {
		out, err := h.pitrScript(ctx, t, d, pitr.ReplaceScript(c, at), secrets)
		if err != nil {
			return err
		}
		if pitr.Marks(out)["READY"] != "1" {
			return errors.New("PostgreSQL didn't come back.")
		}
		t.Logf("PostgreSQL is back, at the point asked for. Archiving goes on from there.")
		_, _ = h.refreshInfo(ctx, t, d, p)
		return nil
	}
	// A copy beside it: a port no other copy uses.
	used := map[int32]bool{}
	if copies, err := h.q.ListPitrCopies(bg, d.ID); err == nil {
		for _, cr := range copies {
			if cr.RestorePort != nil {
				used[*cr.RestorePort] = true
			}
		}
	}
	port := int32(0)
	for p := int32(pitrCopyPortFirst); p <= pitrCopyPortLast; p++ {
		if !used[p] {
			port = p
			break
		}
	}
	if port == 0 {
		return errors.New("Too many restored copies are running: take one down first.")
	}
	var need int64
	var info pitr.Info
	if len(p.Info) > 0 && json.Unmarshal(p.Info, &info) == nil {
		if l := info.Latest(""); l != nil {
			need = l.Size + l.Size/10
		}
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	out, err := h.pitrScript(ctx, t, d, pitr.RestoreNewScript(c, at, stamp, int(port), need), secrets)
	if err != nil {
		// Cancelled or cut off half way: don't leave a half copy running.
		dir := path.Join(path.Dir(c.DataDir), pitr.RestorePrefix+stamp)
		if _, e := h.pitrScript(bg, nil, d, pitr.TeardownScript(c, dir), nil); e != nil {
			t.Logf("Couldn't clean %s up: %s", dir, problemText(e))
		}
		return err
	}
	dir := pitr.Marks(out)["RESTORED"]
	if dir == "" {
		return errors.New("The copy didn't start.")
	}
	when := "the newest point"
	if !at.IsZero() {
		when = at.UTC().Format("2006-01-02 15:04:05") + " UTC"
	}
	// The copy, as a database in Morche: same server, same login.
	copyRow, err := h.q.CreateDatabase(bg, sqlc.CreateDatabaseParams{
		WorkspaceID: d.WorkspaceID, Name: cutRunes(d.Name+" · restored "+stamp, 100), Engine: d.Engine, Mode: "server",
		ServerID: d.ServerID, Host: "127.0.0.1", Port: port, Username: d.Username, PasswordEnc: d.PasswordEnc,
		Dbname: d.Dbname, Tls: dbmon.TLSDisable, CaCert: "", AllowInternal: d.AllowInternal,
		Description:     "A copy of " + d.Name + " restored to " + when + " on port " + strconv.Itoa(int(port)) + " of its server. Take it down from " + d.Name + "'s Point in time tab when you're done.",
		IntervalSeconds: d.IntervalSeconds,
	})
	var copyID *uuid.UUID
	if err == nil {
		copyID = &copyRow.ID
	} else {
		t.Logf("Couldn't add the copy to Morche: %s", problemText(err))
	}
	_ = h.q.SetPitrRunRestore(bg, sqlc.SetPitrRunRestoreParams{ID: r.ID, RestoreDir: dir, RestorePort: &port, RestoreDatabaseID: copyID})
	t.Logf("The copy runs in %s on port %d (localhost only), restored to %s.", dir, port, when)
	return nil
}

// cutRunes keeps the first n characters (never half of one).
func cutRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// ---- Scheduler and checks ----

// startPitrScheduler takes due backups and restarts, and reads every
// repository's state now and then (the page shows the last read).
func startPitrScheduler(h *backupHandler, every, check time.Duration) {
	ctx := context.Background()
	if err := h.q.InterruptPitrRuns(ctx); err != nil {
		slog.Warn("interrupt continuous backup runs", "error", err)
	}
	if err := h.q.ResetStuckPitrs(ctx); err != nil {
		slog.Warn("reset continuous backups cut off", "error", err)
	}
	if every > 0 {
		go func() {
			for range time.Tick(every) {
				h.firePitr(ctx)
			}
		}()
	}
	if check > 0 {
		go func() {
			for range time.Tick(check) {
				h.checkPitrs(ctx)
			}
		}()
	}
}

func (h *backupHandler) firePitr(ctx context.Context) {
	now := time.Now()
	due, err := h.q.ListDuePitrBackups(ctx, &now)
	if err != nil {
		slog.Warn("list due continuous backups", "error", err)
		return
	}
	for _, p := range due {
		was := sqlc.ClaimPitrBackupsParams{DatabaseID: p.DatabaseID, WasFull: p.NextFullAt, WasDiff: p.NextDiffAt, WasIncr: p.NextIncrAt}
		claim := was
		claim.NextFullAt, claim.NextDiffAt, claim.NextIncrAt = p.NextFullAt, p.NextDiffAt, p.NextIncrAt
		// The biggest due type runs; every due one moves on.
		kind := ""
		for _, c := range []struct {
			name string
			at   *time.Time
			expr string
			next **time.Time
		}{{pitr.Full, p.NextFullAt, p.FullCron, &claim.NextFullAt}, {pitr.Diff, p.NextDiffAt, p.DiffCron, &claim.NextDiffAt}, {pitr.Incr, p.NextIncrAt, p.IncrCron, &claim.NextIncrAt}} {
			if c.at == nil || c.at.After(now) {
				continue
			}
			*c.next = nextRun(c.expr, p.Timezone, now)
			if kind == "" {
				kind = c.name
			}
		}
		n, err := h.q.ClaimPitrBackups(ctx, claim)
		if err != nil || n == 0 || kind == "" {
			continue
		}
		d, err := h.q.GetDatabase(ctx, p.DatabaseID)
		if err != nil {
			continue
		}
		if _, err := h.startPitr(ctx, d, "backup", kind, nil, pitrParams{Variant: kind}, nil); err != nil {
			slog.Warn("start a continuous backup", "error", err)
		}
	}
	restarts, err := h.q.ListDuePitrRestarts(ctx, &now)
	if err != nil {
		return
	}
	for _, p := range restarts {
		_ = h.q.SetPitrRestartAt(ctx, sqlc.SetPitrRestartAtParams{DatabaseID: p.DatabaseID})
		if d, err := h.q.GetDatabase(ctx, p.DatabaseID); err == nil {
			if _, err := h.startPitr(ctx, d, "restart", "", nil, pitrParams{}, nil); err != nil {
				slog.Warn("start a scheduled PostgreSQL restart", "error", err)
			}
		}
	}
}

// checkPitrs reads each set-up repository; a failure to reach it is kept as
// the problem until a read works again.
func (h *backupHandler) checkPitrs(ctx context.Context) {
	rows, err := h.q.ListReadyPitrs(ctx)
	if err != nil {
		return
	}
	for _, p := range rows {
		d, err := h.q.GetDatabase(ctx, p.DatabaseID)
		if err != nil {
			continue
		}
		if n, _ := h.q.ActivePitrRun(ctx, d.ID); n > 0 {
			continue
		}
		c, cancel := context.WithTimeout(ctx, time.Minute)
		_, err = h.refreshInfo(c, nil, d, p)
		cancel()
		problem := ""
		if err != nil {
			problem = problemText(err)
		}
		if p.State == "ready" && problem != p.Problem {
			_ = h.q.SetPitrState(ctx, sqlc.SetPitrStateParams{DatabaseID: d.ID, State: "ready", Problem: problem})
		}
	}
}

// ---- API ----

type PitrStatusOutput struct{ Body PitrStatus }

type PitrDetectOutput struct {
	Body struct {
		Cluster  pitr.PitrCluster `json:"cluster"`
		Warnings []string         `json:"warnings"`
		Foreign  bool             `json:"foreign_archive_command" doc:"archive_command is set to something else; saving needs replace_archive_command"`
		Restart  bool             `json:"needs_restart" doc:"archive_mode or wal_level only change with a restart"`
	}
}

// PitrChangeOutput is the state after a change, and the job it started
// when it needed one.
type PitrChangeOutput struct {
	Body struct {
		Job    *Job       `json:"job,omitempty"`
		Status PitrStatus `json:"status"`
	}
}

type PitrRunsOutput struct {
	Body struct {
		Items []PitrRun `json:"items"`
		Total int64     `json:"total"`
	}
}

type PitrRestartBody struct {
	Confirm string     `json:"confirm" doc:"The database's name, typed again"`
	At      *time.Time `json:"at,omitempty" doc:"Restart at this time instead of now"`
}

type PitrBackupBody struct {
	Type string `json:"type" enum:"full,diff,incr"`
}

type PitrRestoreBody struct {
	Mode    string     `json:"mode" enum:"new,replace" doc:"new = a copy beside it on the server (safe); replace = the server's own PostgreSQL goes back in time"`
	At      *time.Time `json:"at,omitempty" doc:"The point in time; empty = as far as the WAL goes"`
	Confirm string     `json:"confirm,omitempty" doc:"replace: the database's name, typed again"`
}

type PitrRemoveBody struct {
	Purge   bool   `json:"purge,omitempty" doc:"Delete the backups and WAL from the storage too"`
	Confirm string `json:"confirm" doc:"The database's name, typed again"`
}

type PitrCipherOutput struct {
	Body struct {
		Passphrase string `json:"passphrase"`
	}
}

type PitrCopyPath struct {
	ID  string `path:"id" format:"uuid"`
	Run string `path:"run" format:"uuid"`
}

func registerDatabasePitr(api huma.API, h *backupHandler) {
	tags := []string{"Point-in-time recovery"}
	h.runner.Handle(pitrKind, h.runPitr)

	load := func(ctx context.Context, id string, write bool) (sqlc.Database, error) {
		d, err := h.db.get(ctx, id)
		if err != nil {
			return d, err
		}
		if write {
			if ok, why := pitrSupport(d); !ok {
				return d, huma.Error422UnprocessableEntity(why)
			}
			if err := h.pitrAccess(ctx, d); err != nil {
				return d, err
			}
			// One PostgreSQL, one setup: a second would overwrite the first's.
			if sib := h.pitrSibling(ctx, d); sib != nil {
				return d, huma.Error409Conflict("This PostgreSQL already has continuous backup, set up through " + sib.Name + " in Morche. Use that one.")
			}
		}
		return d, nil
	}
	saved := func(ctx context.Context, d sqlc.Database) (sqlc.DatabasePitr, error) {
		p, err := h.q.GetPitr(ctx, d.ID)
		if isNotFound(err) {
			return p, huma.Error404NotFound("Continuous backup isn't set up for this database.")
		}
		if err != nil {
			return p, internalError(err)
		}
		return p, nil
	}
	changed := func(ctx context.Context, d sqlc.Database, job *JobOutput, err error) (*PitrChangeOutput, error) {
		if err != nil {
			return nil, err
		}
		out := &PitrChangeOutput{}
		if job != nil {
			out.Body.Job = &job.Body
		}
		out.Body.Status, err = h.pitrStatus(ctx, d)
		return out, err
	}
	confirm := func(d sqlc.Database, typed string) error {
		if strings.TrimSpace(typed) != d.Name {
			return fieldError("body.confirm", "Type the database's name to confirm.", nil)
		}
		return nil
	}

	huma.Register(api, huma.Operation{
		OperationID: "get-database-pitr", Method: http.MethodGet, Path: "/databases/{id}/pitr",
		Summary: "Continuous backup (point-in-time recovery) of a PostgreSQL database", Tags: tags,
	}, func(ctx context.Context, in *DatabaseIDPath) (*PitrStatusOutput, error) {
		d, err := load(ctx, in.ID, false)
		if err != nil {
			return nil, err
		}
		s, err := h.pitrStatus(ctx, d)
		return &PitrStatusOutput{Body: s}, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "refresh-database-pitr", Method: http.MethodPost, Path: "/databases/{id}/pitr/refresh",
		Summary: "Read the repository and the archiver again", Tags: tags,
	}, func(ctx context.Context, in *DatabaseIDPath) (*PitrStatusOutput, error) {
		d, err := load(ctx, in.ID, false)
		if err != nil {
			return nil, err
		}
		p, err := saved(ctx, d)
		if err != nil {
			return nil, err
		}
		if p.State == "ready" || p.State == "broken" {
			problem := ""
			if _, err := h.refreshInfo(ctx, nil, d, p); err != nil {
				problem = problemText(err)
			}
			if p.State == "ready" {
				_ = h.q.SetPitrState(ctx, sqlc.SetPitrStateParams{DatabaseID: d.ID, State: "ready", Problem: problem})
			}
		}
		s, err := h.pitrStatus(ctx, d)
		return &PitrStatusOutput{Body: s}, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "detect-database-pitr", Method: http.MethodPost, Path: "/databases/{id}/pitr/detect",
		Summary: "Look at the PostgreSQL on the server before setting continuous backup up", Tags: tags,
	}, func(ctx context.Context, in *DatabaseIDPath) (*PitrDetectOutput, error) {
		d, err := load(ctx, in.ID, true)
		if err != nil {
			return nil, err
		}
		c, err := h.pitrCluster(ctx, nil, d)
		if err != nil {
			return nil, huma.Error422UnprocessableEntity(problemText(err))
		}
		out := &PitrDetectOutput{}
		out.Body.Cluster, out.Body.Foreign, out.Body.Restart = c, !c.Ours(), c.NeedsRestart()
		w := []string{}
		if c.InRecovery {
			w = append(w, "This PostgreSQL is a standby: set continuous backup up on the primary.")
		}
		if c.PgBackRest == "" {
			if c.Package == "" {
				w = append(w, "pgBackRest isn't installed and Morche can't find a package manager to install it with: install it by hand first.")
			} else {
				w = append(w, "pgBackRest isn't installed: Morche installs it with "+c.Package+".")
			}
		}
		if !c.Ours() {
			w = append(w, "PostgreSQL already sends its WAL somewhere: archive_command = "+c.ArchiveCommand+".")
		}
		if c.NeedsRestart() {
			w = append(w, "archive_mode is off: PostgreSQL needs one restart before archiving starts.")
		}
		out.Body.Warnings = w
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "save-database-pitr", Method: http.MethodPut, Path: "/databases/{id}/pitr",
		Summary: "Set continuous backup up, or change its settings (installs pgBackRest and writes its config on the server)", Tags: tags,
	}, func(ctx context.Context, in *struct {
		ID   string `path:"id" format:"uuid"`
		Body PitrSettingsBody
	}) (*PitrChangeOutput, error) {
		d, err := load(ctx, in.ID, true)
		if err != nil {
			return nil, err
		}
		var prev *sqlc.DatabasePitr
		if p, err := h.q.GetPitr(ctx, d.ID); err == nil {
			prev = &p
		} else if !isNotFound(err) {
			return nil, internalError(err)
		}
		row, err := h.checkPitrBody(ctx, d, in.Body, prev)
		if err != nil {
			return nil, err
		}
		if _, err := h.q.UpsertPitr(ctx, row); err != nil {
			return nil, internalError(err)
		}
		// A schedule-only change needs nothing on the server.
		if prev != nil && (prev.State == "ready" || prev.State == "needs_restart") && sameRepoSettings(*prev, row) {
			return changed(ctx, d, nil, nil)
		}
		job, err := h.startPitr(ctx, d, "setup", "", nil, pitrParams{Replace: in.Body.ReplaceArchive}, principalOf(ctx))
		return changed(ctx, d, job, err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "resetup-database-pitr", Method: http.MethodPost, Path: "/databases/{id}/pitr/setup",
		Summary: "Run the setup again with the saved settings (rewrites pgBackRest's config and archive_command on the server)", Tags: tags,
	}, func(ctx context.Context, in *struct {
		ID   string `path:"id" format:"uuid"`
		Body struct {
			ReplaceArchive bool `json:"replace_archive_command,omitempty" doc:"Take archive_command over from whatever set it"`
		}
	}) (*PitrChangeOutput, error) {
		d, err := load(ctx, in.ID, true)
		if err != nil {
			return nil, err
		}
		if _, err := saved(ctx, d); err != nil {
			return nil, err
		}
		job, err := h.startPitr(ctx, d, "setup", "", nil, pitrParams{Replace: in.Body.ReplaceArchive}, principalOf(ctx))
		return changed(ctx, d, job, err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "restart-database-pitr", Method: http.MethodPost, Path: "/databases/{id}/pitr/restart",
		Summary: "Restart PostgreSQL so archive_mode takes effect, now or at a set time", Tags: tags,
	}, func(ctx context.Context, in *struct {
		ID   string `path:"id" format:"uuid"`
		Body PitrRestartBody
	}) (*PitrChangeOutput, error) {
		d, err := load(ctx, in.ID, true)
		if err != nil {
			return nil, err
		}
		p, err := saved(ctx, d)
		if err != nil {
			return nil, err
		}
		if p.State != "needs_restart" {
			return nil, huma.Error409Conflict("It doesn't need a restart.")
		}
		if err := confirm(d, in.Body.Confirm); err != nil {
			return nil, err
		}
		if in.Body.At != nil && in.Body.At.After(time.Now().Add(time.Minute)) {
			if err := h.q.SetPitrRestartAt(ctx, sqlc.SetPitrRestartAtParams{DatabaseID: d.ID, RestartAt: in.Body.At}); err != nil {
				return nil, internalError(err)
			}
			return changed(ctx, d, nil, nil)
		}
		job, err := h.startPitr(ctx, d, "restart", "", nil, pitrParams{}, principalOf(ctx))
		return changed(ctx, d, job, err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "cancel-database-pitr-restart", Method: http.MethodDelete, Path: "/databases/{id}/pitr/restart",
		Summary: "Call off a restart set for later", Tags: tags, DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *DatabaseIDPath) (*struct{}, error) {
		d, err := load(ctx, in.ID, true)
		if err != nil {
			return nil, err
		}
		return nil, h.q.SetPitrRestartAt(ctx, sqlc.SetPitrRestartAtParams{DatabaseID: d.ID})
	})

	huma.Register(api, huma.Operation{
		OperationID: "backup-database-pitr", Method: http.MethodPost, Path: "/databases/{id}/pitr/backup",
		Summary: "Take a backup now", Tags: tags,
	}, func(ctx context.Context, in *struct {
		ID   string `path:"id" format:"uuid"`
		Body PitrBackupBody
	}) (*JobOutput, error) {
		d, err := load(ctx, in.ID, false)
		if err != nil {
			return nil, err
		}
		p, err := saved(ctx, d)
		if err != nil {
			return nil, err
		}
		if p.State != "ready" && p.State != "broken" {
			return nil, huma.Error409Conflict("It isn't ready to back up yet.")
		}
		return h.startPitr(ctx, d, "backup", in.Body.Type, nil, pitrParams{Variant: in.Body.Type}, principalOf(ctx))
	})

	huma.Register(api, huma.Operation{
		OperationID: "check-database-pitr", Method: http.MethodPost, Path: "/databases/{id}/pitr/check",
		Summary: "Make PostgreSQL archive its current WAL and check it reached the storage", Tags: tags,
	}, func(ctx context.Context, in *DatabaseIDPath) (*JobOutput, error) {
		d, err := load(ctx, in.ID, false)
		if err != nil {
			return nil, err
		}
		if _, err := saved(ctx, d); err != nil {
			return nil, err
		}
		return h.startPitr(ctx, d, "check", "", nil, pitrParams{}, principalOf(ctx))
	})

	huma.Register(api, huma.Operation{
		OperationID: "restore-database-pitr", Method: http.MethodPost, Path: "/databases/{id}/pitr/restore",
		Summary: "Restore to a point in time: a new copy beside it, or the server's own PostgreSQL", Tags: tags,
	}, func(ctx context.Context, in *struct {
		ID   string `path:"id" format:"uuid"`
		Body PitrRestoreBody
	}) (*JobOutput, error) {
		d, err := load(ctx, in.ID, true)
		if err != nil {
			return nil, err
		}
		p, err := saved(ctx, d)
		if err != nil {
			return nil, err
		}
		if p.State != "ready" && p.State != "broken" {
			return nil, huma.Error409Conflict("There's nothing to restore yet.")
		}
		if in.Body.Mode == "replace" {
			if err := confirm(d, in.Body.Confirm); err != nil {
				return nil, err
			}
		}
		if at := in.Body.At; at != nil {
			var info pitr.Info
			if len(p.Info) > 0 && json.Unmarshal(p.Info, &info) == nil {
				if from, _ := info.Window(); from.IsZero() {
					return nil, fieldError("body.at", "There's no backup to start from yet.", nil)
				} else if at.Before(from) {
					return nil, fieldError("body.at", "That's before the oldest backup ("+from.UTC().Format("2006-01-02 15:04:05")+" UTC).", nil)
				}
			}
			if at.After(time.Now()) {
				return nil, fieldError("body.at", "That's in the future.", nil)
			}
		}
		return h.startPitr(ctx, d, "restore", in.Body.Mode, in.Body.At, pitrParams{Variant: in.Body.Mode}, principalOf(ctx))
	})

	huma.Register(api, huma.Operation{
		OperationID: "teardown-database-pitr-copy", Method: http.MethodDelete, Path: "/databases/{id}/pitr/copies/{run}",
		Summary: "Stop a restored copy and delete its folder", Tags: tags,
	}, func(ctx context.Context, in *PitrCopyPath) (*JobOutput, error) {
		d, err := load(ctx, in.ID, true)
		if err != nil {
			return nil, err
		}
		cr, err := h.q.GetPitrRun(ctx, uuid.MustParse(in.Run))
		if err != nil || cr.DatabaseID != d.ID || cr.RestoreDir == "" || cr.RemovedAt != nil {
			return nil, huma.Error404NotFound("That copy isn't there.")
		}
		return h.startPitr(ctx, d, "teardown", "", nil, pitrParams{Copy: cr.ID.String()}, principalOf(ctx))
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-database-pitr-runs", Method: http.MethodGet, Path: "/databases/{id}/pitr/runs",
		Summary: "What's been done for continuous backup", Tags: tags,
	}, func(ctx context.Context, in *struct {
		ID     string `path:"id" format:"uuid"`
		Limit  int32  `query:"limit" minimum:"1" maximum:"200" default:"50"`
		Offset int32  `query:"offset" minimum:"0" default:"0"`
	}) (*PitrRunsOutput, error) {
		d, err := load(ctx, in.ID, false)
		if err != nil {
			return nil, err
		}
		rows, err := h.q.ListPitrRuns(ctx, sqlc.ListPitrRunsParams{DatabaseID: d.ID, Lim: in.Limit, Off: in.Offset})
		if err != nil {
			return nil, internalError(err)
		}
		total, _ := h.q.CountPitrRuns(ctx, d.ID)
		out := &PitrRunsOutput{}
		out.Body.Items, out.Body.Total = make([]PitrRun, len(rows)), total
		for i, r := range rows {
			out.Body.Items[i] = toPitrRun(r)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "reveal-database-pitr-passphrase", Method: http.MethodPost, Path: "/databases/{id}/pitr/passphrase",
		Summary: "The repository's encryption passphrase (keep a copy: without it the backups can't be read)", Tags: tags,
	}, func(ctx context.Context, in *DatabaseIDPath) (*PitrCipherOutput, error) {
		d, err := load(ctx, in.ID, true)
		if err != nil {
			return nil, err
		}
		p, err := saved(ctx, d)
		if err != nil {
			return nil, err
		}
		if len(p.CipherPassEnc) == 0 {
			return nil, huma.Error404NotFound("The repository isn't encrypted.")
		}
		pass, err := h.db.box.Open(p.CipherPassEnc)
		if err != nil {
			return nil, internalError(err)
		}
		out := &PitrCipherOutput{}
		out.Body.Passphrase = pass
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "remove-database-pitr", Method: http.MethodPost, Path: "/databases/{id}/pitr/remove",
		Summary: "Turn continuous backup off (archiving stops; the backups stay unless purge)", Tags: tags,
	}, func(ctx context.Context, in *struct {
		ID   string `path:"id" format:"uuid"`
		Body PitrRemoveBody
	}) (*JobOutput, error) {
		d, err := load(ctx, in.ID, true)
		if err != nil {
			return nil, err
		}
		if _, err := saved(ctx, d); err != nil {
			return nil, err
		}
		if err := confirm(d, in.Body.Confirm); err != nil {
			return nil, err
		}
		return h.startPitr(ctx, d, "remove", "", nil, pitrParams{Purge: in.Body.Purge}, principalOf(ctx))
	})
}

// sameRepoSettings says only the schedule (or enabled) changed: nothing
// to write on the server.
func sameRepoSettings(prev sqlc.DatabasePitr, row sqlc.UpsertPitrParams) bool {
	return prev.StorageID != nil && row.StorageID != nil && *prev.StorageID == *row.StorageID &&
		prev.Folder == row.Folder && prev.RetentionFull == row.RetentionFull &&
		prev.CompressLevel == row.CompressLevel && prev.ProcessMax == row.ProcessMax &&
		prev.ArchiveTimeout == row.ArchiveTimeout
}
