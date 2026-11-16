package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/morche/backend/internal/auth"
)

// The docker-prune cron action: on each server, removes what Docker no longer
// uses (as the Images page's Clean up does), optionally only what is older
// than some hours, so a fresh build or a container stopped a moment ago stays.

// ScheduleDockerPrune cleans up Docker on servers.
type ScheduleDockerPrune struct {
	ServerIDs  []string `json:"server_ids" minItems:"1" maxItems:"50" format:"uuid"`
	Containers bool     `json:"containers,omitempty" doc:"Stopped containers"`
	Images     string   `json:"images,omitempty" enum:"none,dangling,all," doc:"dangling = untagged ones; all = every image no container uses"`
	Volumes    string   `json:"volumes,omitempty" enum:"none,anonymous,all," doc:"Volumes no container uses; anonymous = only unnamed ones"`
	Networks   bool     `json:"networks,omitempty" doc:"Networks no container uses"`
	BuildCache bool     `json:"build_cache,omitempty"`
	OlderThan  int      `json:"older_than_hours,omitempty" minimum:"0" maximum:"8760" doc:"Only what was made more than this many hours ago (not volumes: Docker keeps no age for them). 0 = all of it"`
	KeepGoing  bool     `json:"keep_going,omitempty" doc:"Carry on with the other servers after one fails"`
}

func (p ScheduleDockerPrune) body() DockerPruneBody {
	return DockerPruneBody{
		Containers: p.Containers, Images: p.Images, Volumes: p.Volumes,
		Networks: p.Networks, BuildCache: p.BuildCache,
	}
}

func (k *scheduleChecker) dockerPrune(b ScheduleBody) error {
	t := b.Task.Prune
	if t == nil {
		return fieldError("body.task.prune.server_ids", "Choose at least one server.", nil)
	}
	ids, err := k.servers("body.task.prune.server_ids", t.ServerIDs, auth.Engineer)
	if err != nil {
		return err
	}
	out := *t
	out.ServerIDs = ids
	if out.Images == "none" {
		out.Images = ""
	}
	if out.Volumes == "none" {
		out.Volumes = ""
	}
	if !out.Containers && !out.Networks && !out.BuildCache && out.Images == "" && out.Volumes == "" {
		return fieldError("body.task.prune.containers", "Pick something to remove.", nil)
	}
	k.c.task.Prune = &out
	return nil
}

func (r *taskRun) dockerPrune(ctx context.Context) (any, error) {
	t := r.plan.Task.Prune
	if t == nil {
		return r.finish(ctx, "It has no servers.")
	}
	h := r.h.st.servers
	r.rows(r.plan.Destinations)
	stoppedBy := ""
	for i, d := range r.plan.Destinations {
		if ctx.Err() != nil {
			break
		}
		if stoppedBy != "" {
			r.mu.Lock()
			r.results[i].State, r.results[i].Note = "canceled", "Not cleaned: "+stoppedBy+" failed first."
			r.save()
			r.mu.Unlock()
			continue
		}
		r.begin(i, "Cleaning up Docker on")
		err := mayUse(r.acc, r.ws, d, auth.Engineer, r.who)
		note := ""
		if err == nil {
			prefix := ""
			if len(r.plan.Destinations) > 1 {
				prefix = d.Name + ": "
			}
			var res DockerPruneResult
			res, err = h.pruneDocker(ctx, r.t, *d.ServerID, t.body(), t.OlderThan, prefix)
			if err == nil {
				note = pruneNote(res)
				r.bytes += res.Space
			} else {
				err = jobError(err)
			}
		}
		r.end(ctx, i, err, note)
		if err != nil && !t.KeepGoing {
			stoppedBy = d.Name
		}
	}
	return r.finish(ctx, "")
}

// pruneNote: "Freed 1.2 GB: 3 images, 2 containers."
func pruneNote(res DockerPruneResult) string {
	var parts []string
	add := func(n int, one string) {
		if n > 0 {
			parts = append(parts, plural(n, one))
		}
	}
	add(res.Images, "image")
	add(res.Containers, "container")
	add(res.Volumes, "volume")
	add(res.Networks, "network")
	add(res.Caches, "cache item")
	if len(parts) == 0 && res.Space == 0 {
		return "Nothing to remove."
	}
	note := "Freed " + humanBytes(res.Space)
	if len(parts) > 0 {
		note += ": " + strings.Join(parts, ", ")
	}
	return fmt.Sprintf("%s.", note)
}
