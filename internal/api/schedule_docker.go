package api

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/docker"
	"github.com/morcheh/backend/internal/jobs"
)

// The docker-update cron action: on each server, the running containers
// whose image has a newer version are pulled and recreated (as Updates »
// Update does). With rollback, each one is watched for a while and put back
// on its old image when it stops or turns unhealthy.

// ScheduleDocker updates containers to their newest image.
type ScheduleDocker struct {
	ServerIDs   []string `json:"server_ids" minItems:"1" maxItems:"50" format:"uuid"`
	Only        []string `json:"only,omitempty" maxItems:"50" doc:"Projects or containers to update (* and ? work); empty = every running container with a newer image"`
	Check       bool     `json:"check,omitempty" doc:"Ask the registries for newer images first; else the last daily check decides"`
	Rollback    bool     `json:"rollback,omitempty" doc:"Watch each updated container and put its old image back when it stops or turns unhealthy"`
	WaitSeconds int      `json:"wait_seconds,omitempty" minimum:"0" maximum:"600" doc:"How long to watch it (rollback); default 60"`
	KeepGoing   bool     `json:"keep_going,omitempty" doc:"Carry on with the other servers after one fails"`
}

func (k *scheduleChecker) docker(b ScheduleBody) error {
	t := b.Task.Docker
	if t == nil {
		return fieldError("body.task.docker.server_ids", "Choose at least one server.", nil)
	}
	// Recreating containers needs Engineer, as on the Updates page.
	ids, err := k.servers("body.task.docker.server_ids", t.ServerIDs, auth.Engineer)
	if err != nil {
		return err
	}
	out := *t
	out.ServerIDs = ids
	out.Only = nil
	for i, raw := range t.Only {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		if len(p) > 128 {
			return fieldError(fmt.Sprintf("body.task.docker.only[%d]", i), "Keep it under 128 characters.", raw)
		}
		if !slices.Contains(out.Only, p) {
			out.Only = append(out.Only, p)
		}
	}
	if out.Rollback {
		if out.WaitSeconds == 0 {
			out.WaitSeconds = 60
		}
		out.WaitSeconds = min(max(out.WaitSeconds, 10), 600)
	} else {
		out.WaitSeconds = 0
	}
	k.c.task.Docker = &out
	return nil
}

func (r *taskRun) dockerUpdate(ctx context.Context) (any, error) {
	t := r.plan.Task.Docker
	if t == nil {
		return r.finish(ctx, "It has no servers.")
	}
	r.rows(r.plan.Destinations)
	stoppedBy := ""
	for i, d := range r.plan.Destinations {
		if ctx.Err() != nil {
			break
		}
		if stoppedBy != "" {
			r.mu.Lock()
			r.results[i].State, r.results[i].Note = "canceled", "Not updated: "+stoppedBy+" failed first."
			r.save()
			r.mu.Unlock()
			continue
		}
		r.begin(i, "Updating containers on")
		err := mayUse(r.acc, r.ws, d, auth.Engineer, r.who)
		note := ""
		skip := ""
		if err == nil {
			note, skip, err = r.dockerOne(ctx, t, *d.ServerID, d.Name)
		}
		switch {
		case skip != "":
			r.skip(i, skip)
		default:
			r.end(ctx, i, err, note)
			if err != nil && !t.KeepGoing {
				stoppedBy = d.Name
			}
		}
	}
	return r.finish(ctx, "")
}

// updatePick is one container to update and the image it ran before.
type updatePick struct {
	c       docker.ContainerSummary
	oldID   string
	name    string
	project string
}

func (u updatePick) matches(patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if globMatch(p, u.name) || u.project != "" && globMatch(p, u.project) {
			return true
		}
	}
	return false
}

// dockerOne updates one server. skip = nothing to do (and why).
func (r *taskRun) dockerOne(ctx context.Context, t *ScheduleDocker, serverID, serverName string) (note, skip string, err error) {
	h := r.h.st.servers
	task := r.t
	sid, err := uuid.Parse(serverID)
	if err != nil {
		return "", "", err
	}
	prefix := ""
	if len(r.results) > 1 {
		prefix = serverName + ": "
	}
	if t.Check {
		task.Logf("%sAsking the registries for newer images", prefix)
		if _, err := h.checkDockerUpdates(ctx, serverID, func(i, n int, image string) {
			task.Update(func(p *jobs.Progress) { p.Current = prefix + image })
		}); err != nil {
			return "", "", jobError(err)
		}
	}
	rows, err := h.q.ListDockerImageUpdates(ctx, sid)
	if err != nil {
		return "", "", err
	}
	newer := map[string]bool{}
	for _, row := range rows {
		if row.State == "update" {
			newer[row.Image] = true
		}
	}
	if len(newer) == 0 {
		if !t.Check && len(rows) == 0 {
			return "", "No image has been checked for updates here yet: tick Check for new images first.", nil
		}
		return "", "Every image is up to date.", nil
	}
	var cs []docker.ContainerSummary
	if err := h.withDocker(ctx, serverID, func(e *dockerEngine) error {
		var err error
		cs, err = e.client.Containers(ctx)
		return err
	}); err != nil {
		return "", "", jobError(err)
	}
	var picks []updatePick
	var images []string
	for _, c := range cs {
		if c.State != "running" || !newer[c.Image] || pinnedRef(c.Image) {
			continue
		}
		u := updatePick{c: c, oldID: c.ImageID, name: containerName(c.Names), project: c.Labels["com.docker.compose.project"]}
		if !u.matches(t.Only) {
			continue
		}
		picks = append(picks, u)
		if !slices.Contains(images, c.Image) {
			images = append(images, c.Image)
		}
	}
	if len(picks) == 0 {
		return "", "No running container it may update has a newer image.", nil
	}
	if err := h.pullWithAuth(ctx, task, serverID, images, false); err != nil {
		return "", "", jobError(err)
	}

	var updated, rolled, failed []string
	keepOld := map[string]bool{} // images that went back: still "update"
	for i, u := range picks {
		if ctx.Err() != nil {
			return "", "", ctx.Err()
		}
		task.Update(func(p *jobs.Progress) {
			p.Current = fmt.Sprintf("%s%s (%d of %d)", prefix, u.name, i+1, len(picks))
		})
		if err := h.recreateContainer(ctx, task, serverID, u.c); err != nil {
			task.Logf("%sCouldn't update %s: %s", prefix, u.name, dockerProblemText(err))
			failed = append(failed, u.name)
			keepOld[u.c.Image] = true
			continue
		}
		if !t.Rollback {
			updated = append(updated, u.name)
			continue
		}
		why := h.watchUpdated(ctx, task, serverID, u.name, time.Duration(t.WaitSeconds)*time.Second, prefix)
		if why == "" {
			task.Logf("%s%s is running fine on the new image", prefix, u.name)
			updated = append(updated, u.name)
			continue
		}
		task.Logf("%s%s %s: putting its old image back", prefix, u.name, why)
		keepOld[u.c.Image] = true
		if err := h.rollbackContainer(ctx, task, serverID, u); err != nil {
			task.Logf("%sCouldn't put %s back: %s", prefix, u.name, dockerProblemText(err))
			failed = append(failed, u.name+" ("+why+"; going back failed too)")
			continue
		}
		rolled = append(rolled, u.name+" ("+why+")")
	}
	for _, img := range images {
		if !keepOld[img] {
			_ = h.q.MarkDockerImageCurrent(ctx, sqlc.MarkDockerImageCurrentParams{ServerID: sid, Image: img})
		}
	}

	var parts []string
	if len(updated) > 0 {
		parts = append(parts, "Updated "+strings.Join(updated, ", ")+".")
	}
	if len(rolled) > 0 {
		parts = append(parts, "Back on the old image: "+strings.Join(rolled, ", ")+".")
	}
	if len(failed) > 0 {
		parts = append(parts, "Couldn't update "+strings.Join(failed, ", ")+".")
	}
	note = strings.Join(parts, " ")
	if len(rolled) > 0 || len(failed) > 0 {
		return "", "", errors.New(note)
	}
	return note, "", nil
}

// watchUpdated watches a freshly recreated container; "" = it's fine, else
// what went wrong. A container with a health check must turn healthy within
// the wait; one without must still be running at its end.
func (h *serverHandler) watchUpdated(ctx context.Context, t *jobs.Task, serverID, name string, wait time.Duration, prefix string) string {
	t.Logf("%sWatching %s for %d seconds", prefix, name, int(wait.Seconds()))
	deadline := time.Now().Add(wait)
	last := ""
	for {
		var ins docker.ContainerInspect
		err := h.withDocker(ctx, serverID, func(e *dockerEngine) error {
			var err error
			ins, _, err = e.client.Inspect(ctx, name, false)
			return err
		})
		switch {
		case ctx.Err() != nil:
			return ""
		case err != nil:
			last = "couldn't be read after the update"
		case !ins.State.Running && !ins.State.Restarting:
			return fmt.Sprintf("stopped after the update (exit code %d)", ins.State.ExitCode)
		case ins.State.Restarting:
			last = "kept restarting after the update"
		case ins.State.Health != nil && ins.State.Health.Status == "unhealthy":
			return "turned unhealthy after the update"
		case ins.State.Health != nil && ins.State.Health.Status == "healthy":
			return ""
		case ins.State.Health != nil:
			last = "wasn't healthy yet after " + plural(int(wait.Seconds()), "second")
		default:
			last = ""
		}
		if time.Now().After(deadline) {
			return last
		}
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(5 * time.Second):
		}
	}
}

// rollbackContainer points the image reference at the image the container
// ran before and recreates it on that.
func (h *serverHandler) rollbackContainer(ctx context.Context, t *jobs.Task, serverID string, u updatePick) error {
	repo, tag := splitImageRef(u.c.Image)
	var now docker.ContainerSummary
	err := h.withDocker(ctx, serverID, func(e *dockerEngine) error {
		if err := e.client.TagImage(ctx, u.oldID, repo, tag); err != nil {
			return err
		}
		cs, err := e.client.Containers(ctx)
		if err != nil {
			return err
		}
		for _, c := range cs {
			if containerName(c.Names) == u.name {
				now = c
				return nil
			}
		}
		return errors.New("the container is gone")
	})
	if err != nil {
		return err
	}
	return h.recreateContainer(ctx, t, serverID, now)
}

// splitImageRef splits "registry:5000/app:1.2" into repository and tag
// (latest when there's none).
func splitImageRef(ref string) (repo, tag string) {
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		return ref[:i], ref[i+1:]
	}
	return ref, "latest"
}
