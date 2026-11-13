package api

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/jobs"
)

// The docker-volume-backup cron action: copies a server's Docker volumes to
// a storage (as the Volumes page's Back up does), one after another, then
// removes this job's copies beyond keep.

// ScheduleVolumes backs up Docker volumes to a storage.
type ScheduleVolumes struct {
	ServerID  string   `json:"server_id" format:"uuid"`
	Volumes   []string `json:"volumes,omitempty" maxItems:"100" doc:"Volume names (* and ? work); empty = every volume"`
	StorageID string   `json:"storage_id" format:"uuid"`
	Folder    string   `json:"folder,omitempty" maxLength:"500" doc:"Folder on the storage; default /backups/docker-volumes"`
	Stop      bool     `json:"stop,omitempty" doc:"Stop the running containers using each volume while it's copied"`
	Keep      int      `json:"keep,omitempty" minimum:"0" maximum:"1000" doc:"Copies of each volume this job keeps; older ones are removed. 0 = keep all"`
	KeepGoing bool     `json:"keep_going,omitempty" doc:"Carry on with the other volumes after one fails"`
}

func (k *scheduleChecker) volumes(b ScheduleBody) error {
	t := b.Task.Volumes
	if t == nil {
		return fieldError("body.task.volumes.server_id", "Choose a server.", nil)
	}
	ids, err := k.servers("body.task.volumes.server_id", []string{t.ServerID}, auth.Engineer)
	if err != nil {
		return err
	}
	folder := storageFolder(t.Folder)
	if _, err := k.end("body.task.volumes", ScheduleEnd{StorageID: &t.StorageID, Path: folder}, auth.Engineer, true, false); err != nil {
		return err
	}
	out := *t
	out.ServerID = ids[0]
	out.Folder = folder
	out.Volumes = nil
	for i, raw := range t.Volumes {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		if len(p) > 255 {
			return fieldError(fmt.Sprintf("body.task.volumes.volumes[%d]", i), "Keep it under 255 characters.", raw)
		}
		if !slices.Contains(out.Volumes, p) {
			out.Volumes = append(out.Volumes, p)
		}
	}
	k.c.task.Volumes = &out
	return nil
}

func storageFolder(f string) string {
	f = strings.TrimSpace(f)
	if f == "" {
		return defaultVolumeFolder
	}
	if !strings.HasPrefix(f, "/") {
		f = "/" + f
	}
	return f
}

func (r *taskRun) volumeBackups(ctx context.Context) (any, error) {
	t := r.plan.Task.Volumes
	if t == nil || len(r.plan.Destinations) == 0 {
		return r.finish(ctx, "It has no server.")
	}
	st := r.h.st
	server := r.plan.Destinations[0]
	if err := mayUse(r.acc, r.ws, server, auth.Engineer, r.who); err != nil {
		r.rows([]ScheduleEndView{server})
		r.end(ctx, 0, errors.New(r.asWho(err)), "")
		return r.finish(ctx, "")
	}
	storeID, err := uuid.Parse(t.StorageID)
	if err != nil {
		return r.finish(ctx, "Its storage is missing.")
	}
	row, err := st.q.GetStorage(ctx, storeID)
	if err != nil {
		return r.finish(ctx, "Its storage was removed: choose another one.")
	}
	if lvl := r.acc.StorageLevel(r.ws, storeID); lvl < auth.Engineer {
		return r.finish(ctx, r.asWho(forbidden(auth.Engineer)))
	}
	if row.ReadOnly {
		return r.finish(ctx, row.Name+" is read-only in Morche, so nothing can be written to it.")
	}

	r.t.Update(func(p *jobs.Progress) { p.Phase = "Listing the volumes on " + server.Name })
	var names []string
	if err := st.servers.withDocker(ctx, *server.ServerID, func(e *dockerEngine) error {
		vols, err := e.client.Volumes(ctx)
		for _, v := range vols {
			if volumeMatches(t.Volumes, v.Name) {
				names = append(names, v.Name)
			}
		}
		return err
	}); err != nil {
		r.rows([]ScheduleEndView{server})
		r.end(ctx, 0, jobError(err), "")
		return r.finish(ctx, "")
	}
	if len(names) == 0 {
		r.rows([]ScheduleEndView{server})
		r.skip(0, "No volume on it matches.")
		return r.finish(ctx, "")
	}
	slices.Sort(names)
	rows := make([]ScheduleEndView, len(names))
	for i, n := range names {
		sid := *server.ServerID
		rows[i] = ScheduleEndView{ScheduleEnd: ScheduleEnd{ServerID: &sid, Path: n}, Name: server.Name + " · " + n}
	}
	r.rows(rows)
	sid := uuid.MustParse(*server.ServerID)
	stoppedBy := ""
	for i, n := range names {
		if ctx.Err() != nil {
			break
		}
		if stoppedBy != "" {
			r.mu.Lock()
			r.results[i].State, r.results[i].Note = "canceled", "Not copied: "+stoppedBy+" failed first."
			r.save()
			r.mu.Unlock()
			continue
		}
		r.begin(i, "Copying")
		b, err := st.backupVolume(ctx, r.t, volumeBackupParams{
			ServerID: *server.ServerID, Volume: n, StorageID: t.StorageID, Folder: t.Folder, Stop: t.Stop,
			By: r.who, ScheduleID: r.sched.String(),
		})
		note := ""
		if err == nil {
			note = fmt.Sprintf("%s on %s", humanBytes(b.Size), row.Name)
			r.bytes += b.Size
			r.files++
			st.pruneVolumeBackups(ctx, r.t, sid, n, &r.sched, t.Keep)
		}
		r.end(ctx, i, err, note)
		if err != nil && !t.KeepGoing {
			stoppedBy = n
		}
	}
	return r.finish(ctx, "")
}

func volumeMatches(patterns []string, name string) bool {
	if len(patterns) == 0 {
		return true
	}
	return slices.ContainsFunc(patterns, func(p string) bool { return globMatch(p, name) })
}
