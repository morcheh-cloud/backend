package api

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morche/backend/internal/docker"
)

// DockerEvent is one thing the engine did. Only harmless attributes are
// kept: never a command line (exec events carry them) or labels.
type DockerEvent struct {
	Time     time.Time `json:"time"`
	Type     string    `json:"type" enum:"container,image,volume,network,daemon,plugin,node,service,secret,config,builder" doc:"What it happened to"`
	Action   string    `json:"action" example:"die" doc:"What happened, e.g. start, die, oom, pull, destroy, health_status"`
	Detail   string    `json:"detail,omitempty" example:"unhealthy" doc:"The health status for health_status"`
	ID       string    `json:"id"`
	Name     string    `json:"name,omitempty"`
	Image    string    `json:"image,omitempty"`
	Project  string    `json:"project,omitempty" doc:"Compose project, for containers"`
	ExitCode string    `json:"exit_code,omitempty" doc:"For die"`
	Signal   string    `json:"signal,omitempty" doc:"For kill"`
}

type DockerEvents struct {
	Items []DockerEvent `json:"items" doc:"Newest first"`
	Since time.Time     `json:"since"`
	Note  string        `json:"note,omitempty" doc:"Docker keeps only its last ~1000 events in memory (and none from before it restarted)"`
}

type dockerEventsQuery struct {
	ServerIDPath
	Hours int    `query:"hours" minimum:"1" maximum:"720" doc:"How far back; 0 = the workspace's setting"`
	Type  string `query:"type" enum:"container,image,volume,network," doc:"Only this kind"`
	Exec  bool   `query:"exec" doc:"Also exec_* events (every health check makes three)"`
}

const maxDockerEvents = 1000

func toDockerEvent(ev docker.Event) DockerEvent {
	a := ev.Actor.Attributes
	action, detail, _ := strings.Cut(ev.Action, ":")
	out := DockerEvent{
		Time: time.Unix(0, ev.TimeNano).UTC(), Type: ev.Type, Action: strings.TrimSpace(action),
		ID: ev.Actor.ID, Name: a["name"], Image: a["image"], Project: a["com.docker.compose.project"],
		ExitCode: a["exitCode"], Signal: a["signal"],
	}
	if out.Action == "health_status" {
		out.Detail = strings.TrimSpace(detail)
	}
	if ev.Type == "image" && out.Name == "" {
		out.Name = ev.Actor.ID
	}
	return out
}

func registerDockerEvents(api huma.API, h *serverHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "list-docker-events",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/docker/events",
		Summary:     "What the engine did lately",
		Description: "Starts, stops, crashes, pulls, removals… as the engine remembers them (newest first, at most 1000).",
		Tags:        []string{"Containers"},
	}, func(ctx context.Context, in *dockerEventsQuery) (*struct{ Body DockerEvents }, error) {
		hours := in.Hours
		if hours == 0 {
			s, err := h.get(ctx, in.ID)
			if err != nil {
				return nil, err
			}
			set, err := h.serverDockerSettings(ctx, s)
			if err != nil {
				return nil, err
			}
			hours = set.EventsHours
		}
		until := time.Now()
		since := until.Add(-time.Duration(hours) * time.Hour)
		filters := map[string][]string{}
		if in.Type != "" {
			filters["type"] = []string{in.Type}
		}
		out := &struct{ Body DockerEvents }{DockerEvents{Items: []DockerEvent{}, Since: since.UTC()}}
		err := h.withDocker(ctx, in.ID, func(e *dockerEngine) error {
			evs, err := e.client.Events(ctx, since, until, filters, maxDockerEvents*4)
			if err != nil {
				return err
			}
			for _, ev := range evs {
				if !in.Exec && strings.HasPrefix(ev.Action, "exec_") {
					continue
				}
				out.Body.Items = append(out.Body.Items, toDockerEvent(ev))
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		items := out.Body.Items
		sort.SliceStable(items, func(i, j int) bool { return items[i].Time.After(items[j].Time) })
		if len(items) > maxDockerEvents {
			items = items[:maxDockerEvents]
		}
		out.Body.Items = items
		if len(items) > 0 && hours > 1 && items[len(items)-1].Time.After(since.Add(time.Hour)) {
			out.Body.Note = "Docker only remembers its recent events (and none from before it last restarted), so older ones may be missing."
		}
		return out, nil
	})
}
