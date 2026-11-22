package api

// Container auto-update (like Watchtower): policies per workspace that look
// for newer images of the containers they pick, on a schedule, by webhook or
// by hand, and pull + recreate them (or only report, in monitor mode).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/cmdlog"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/docker"
	"github.com/morche/backend/internal/jobs"
	"github.com/morche/backend/internal/notify"
	"github.com/morche/backend/internal/sshpool"
	"github.com/morche/backend/internal/terminal"
)

const dockerAutoUpdateKind = "docker-auto-update"

// ---- Types ----

type DockerAutoUpdateRules struct {
	Servers        []string `json:"servers" minItems:"1" maxItems:"100" doc:"Server ids in the workspace"`
	Pick           string   `json:"pick" enum:"all,labeled,chosen" doc:"all = every container (but excluded ones); labeled = only containers labelled morche.auto-update.enable=true or com.centurylinklabs.watchtower.enable=true; chosen = containers, compose projects or images named in include (or labelled)"`
	Include        []string `json:"include,omitempty" maxItems:"200" doc:"Names, compose projects or images (* and ? allowed), for pick = chosen"`
	Exclude        []string `json:"exclude,omitempty" maxItems:"200" doc:"Names, compose projects or images (* and ?) never touched"`
	IncludeStopped bool     `json:"include_stopped" doc:"Also update containers that aren't running (they stay stopped unless revive_stopped)"`
	Mode           string   `json:"mode" enum:"update,monitor" doc:"monitor = only report new images, never pull or recreate"`
}

type DockerAutoUpdateBody struct {
	DockerAutoUpdateRules
	Name          string   `json:"name" minLength:"1" maxLength:"80"`
	Enabled       bool     `json:"enabled"`
	ReviveStopped bool     `json:"revive_stopped" doc:"Start a stopped container after updating it"`
	Cron          string   `json:"cron,omitempty" maxLength:"100" doc:"When it runs (5-field cron); empty = only by hand or webhook"`
	Timezone      string   `json:"timezone,omitempty" maxLength:"64"`
	NoPull        bool     `json:"no_pull" doc:"Never pull: only recreate containers whose image was replaced on the server some other way (built or pulled there)"`
	Cleanup       bool     `json:"cleanup" doc:"Remove the old image once nothing uses it"`
	Rollback      bool     `json:"rollback" doc:"Watch each updated container and put the old image back if it stops or turns unhealthy"`
	WaitSeconds   int      `json:"wait_seconds" minimum:"10" maximum:"600" doc:"How long to watch for rollback"`
	RestartLinked bool     `json:"restart_linked" doc:"Restart containers that depend on an updated one (depends-on label or network_mode container:)"`
	StopTimeout   int      `json:"stop_timeout" minimum:"0" maximum:"600" doc:"Seconds a container gets to stop before it is killed"`
	MinAgeHours   int      `json:"min_age_hours" minimum:"0" maximum:"720" doc:"Only take a new image once the registry has had it this long (0 = at once)"`
	Hooks         bool     `json:"hooks" doc:"Run the containers' lifecycle hook labels (pre-check, pre-update, post-update, post-check)"`
	HookTimeout   int      `json:"hook_timeout" minimum:"5" maximum:"1800" doc:"Seconds a hook may run (a -timeout label, in minutes, wins)"`
	Notify        string   `json:"notify" enum:"never,changes,failures,always"`
	Channels      []string `json:"channels,omitempty" maxItems:"20" doc:"Notification channel ids"`
}

type DockerAutoUpdateServer struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Missing bool   `json:"missing,omitempty" doc:"Deleted or moved out of the workspace"`
}

type DockerAutoUpdateCounts struct {
	Updated    int `json:"updated"`
	Available  int `json:"available"`
	RolledBack int `json:"rolled_back"`
	Failed     int `json:"failed"`
}

type DockerAutoUpdate struct {
	ID             string                   `json:"id"`
	WorkspaceID    string                   `json:"workspace_id"`
	Name           string                   `json:"name"`
	Enabled        bool                     `json:"enabled"`
	Servers        []DockerAutoUpdateServer `json:"servers"`
	Pick           string                   `json:"pick" enum:"all,labeled,chosen"`
	Include        []string                 `json:"include"`
	Exclude        []string                 `json:"exclude"`
	IncludeStopped bool                     `json:"include_stopped"`
	ReviveStopped  bool                     `json:"revive_stopped"`
	Cron           string                   `json:"cron"`
	Timezone       string                   `json:"timezone"`
	Mode           string                   `json:"mode" enum:"update,monitor"`
	NoPull         bool                     `json:"no_pull"`
	Cleanup        bool                     `json:"cleanup"`
	Rollback       bool                     `json:"rollback"`
	WaitSeconds    int                      `json:"wait_seconds"`
	RestartLinked  bool                     `json:"restart_linked"`
	StopTimeout    int                      `json:"stop_timeout"`
	MinAgeHours    int                      `json:"min_age_hours"`
	Hooks          bool                     `json:"hooks"`
	HookTimeout    int                      `json:"hook_timeout"`
	Notify         string                   `json:"notify" enum:"never,changes,failures,always"`
	Channels       []string                 `json:"channels"`
	NextRunAt      *time.Time               `json:"next_run_at,omitempty"`
	LastRunAt      *time.Time               `json:"last_run_at,omitempty"`
	LastState      string                   `json:"last_state" doc:"'' = never ran; running, ok, updated, available, failed"`
	LastNote       string                   `json:"last_note"`
	LastJobID      string                   `json:"last_job_id,omitempty"`
	Running        bool                     `json:"running"`
	RunsAs         string                   `json:"runs_as" doc:"Whose access runs use: the person who saved it last"`
	WebhookToken   string                   `json:"webhook_token,omitempty" doc:"Only for Engineers: POST /hooks/docker-update/{token} runs it"`
	Last30Days     DockerAutoUpdateCounts   `json:"last_30_days"`
	CreatedAt      time.Time                `json:"created_at"`
	UpdatedAt      time.Time                `json:"updated_at"`
}

type DockerAutoUpdates struct {
	Items []DockerAutoUpdate `json:"items"`
}

type DockerAutoUpdateEvent struct {
	ID         string    `json:"id"`
	PolicyID   string    `json:"policy_id"`
	PolicyName string    `json:"policy_name"`
	ServerID   string    `json:"server_id"`
	ServerName string    `json:"server_name"`
	JobID      string    `json:"job_id,omitempty"`
	Container  string    `json:"container"`
	Image      string    `json:"image"`
	OldImage   string    `json:"old_image"`
	NewImage   string    `json:"new_image"`
	Result     string    `json:"result" enum:"updated,available,rolled_back,failed,skipped"`
	Message    string    `json:"message"`
	At         time.Time `json:"at"`
}

type DockerAutoUpdateEvents struct {
	Items []DockerAutoUpdateEvent `json:"items"`
	Next  string                  `json:"next,omitempty" doc:"Pass as before for older ones"`
}

type DockerAutoUpdateCandidate struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Image       string   `json:"image"`
	Project     string   `json:"project,omitempty"`
	Service     string   `json:"service,omitempty"`
	State       string   `json:"state"`
	Included    bool     `json:"included"`
	Why         string   `json:"why" doc:"Why it is in or out, in plain words"`
	Update      string   `json:"update" enum:"available,current,local,pinned,error,unchecked" doc:"From the server's last registry check"`
	MonitorOnly bool     `json:"monitor_only,omitempty" doc:"Its label says report only"`
	NoPull      bool     `json:"no_pull,omitempty" doc:"Its label says never pull"`
	Hooks       []string `json:"hooks,omitempty" doc:"Lifecycle hooks its labels define"`
}

type DockerAutoUpdatePreviewServer struct {
	ID         string                      `json:"id"`
	Name       string                      `json:"name"`
	Error      string                      `json:"error,omitempty"`
	Containers []DockerAutoUpdateCandidate `json:"containers"`
}

type DockerAutoUpdatePreview struct {
	Servers  []DockerAutoUpdatePreviewServer `json:"servers"`
	Included int                             `json:"included"`
	Waiting  int                             `json:"waiting" doc:"Included containers whose image has a newer version (last check)"`
}

type DockerAutoUpdateRunBody struct {
	CheckOnly bool   `json:"check_only,omitempty" doc:"Only look and report, as in monitor mode"`
	Server    string `json:"server,omitempty" format:"uuid" doc:"Only this one of its servers"`
}

type DockerServerAutoUpdateCover struct {
	Container string   `json:"container"`
	Policies  []string `json:"policies"`
	Monitor   bool     `json:"monitor" doc:"Every policy that takes it only reports"`
}

type DockerServerAutoUpdate struct {
	Policies   []DockerAutoUpdate            `json:"policies"`
	Containers []DockerServerAutoUpdateCover `json:"containers"`
}

type DockerAutoUpdatePath struct {
	ID     string `path:"id" format:"uuid"`
	Policy string `path:"policy" format:"uuid"`
}

type dockerAutoUpdateParams struct {
	PolicyID  string `json:"policy_id"`
	Trigger   string `json:"trigger"`
	Image     string `json:"image,omitempty"`
	Server    string `json:"server,omitempty"`
	CheckOnly bool   `json:"check_only,omitempty"`
}

type DockerAutoUpdateHookInput struct {
	Token   string `path:"token" maxLength:"100"`
	Image   string `query:"image" maxLength:"300" doc:"Only containers of this image (or repository; * allowed)"`
	RawBody []byte `required:"false"`
}

type DockerAutoUpdateHookOutput struct {
	Status int
	Body   struct {
		OK      bool    `json:"ok"`
		JobID   *string `json:"job_id,omitempty"`
		Message string  `json:"message"`
	}
}

// autoUpdateBusy keeps one run per policy at a time.
var autoUpdateBusy sync.Map

// ---- Labels ----

var autoLabelPrefixes = []string{"morche.auto-update.", "com.centurylinklabs.watchtower."}

// autoLabel reads one of our labels, or Watchtower's of the same name.
func autoLabel(c docker.ContainerSummary, key string) (string, bool) {
	for _, p := range autoLabelPrefixes {
		if v, ok := c.Labels[p+key]; ok {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}

func labelTrue(v string) bool {
	switch strings.ToLower(v) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

var hookNames = []string{"pre-check", "pre-update", "post-update", "post-check"}

// ---- Picking ----

// autoMatches says whether a pattern names the container, its compose
// project or service, or its image.
func autoMatches(patterns []string, c docker.ContainerSummary) string {
	name := containerName(c.Names)
	project := c.Labels["com.docker.compose.project"]
	service := c.Labels["com.docker.compose.service"]
	repo, _ := splitImageRef(c.Image)
	for _, p := range patterns {
		if globMatch(p, name) || project != "" && (globMatch(p, project) || globMatch(p, project+"/"+service)) ||
			globMatch(p, c.Image) || globMatch(p, repo) || globMatch(p, strings.TrimPrefix(repo, "docker.io/library/")) {
			return p
		}
	}
	return ""
}

// autoPick says whether rules take a container in, and why (or why not).
func autoPick(r DockerAutoUpdateRules, c docker.ContainerSummary) (bool, string) {
	name := containerName(c.Names)
	switch {
	case strings.Contains(name, "-morche-old-"):
		return false, "A copy kept during an update"
	case pinnedRef(c.Image):
		return false, "Its image is pinned to a digest or an id, so there is nothing newer"
	case c.State == "paused":
		return false, "Paused"
	case c.State != "running" && !r.IncludeStopped:
		return false, "Not running (tick Stopped containers too to take it)"
	}
	enable, labelled := autoLabel(c, "enable")
	if labelled && !labelTrue(enable) {
		return false, "Its enable label is false"
	}
	if p := autoMatches(r.Exclude, c); p != "" {
		return false, "Left out by “" + p + "”"
	}
	switch r.Pick {
	case "all":
		return true, "Every container"
	case "labeled":
		if labelled {
			return true, "Its enable label is true"
		}
		return false, "No enable label"
	}
	if p := autoMatches(r.Include, c); p != "" {
		return true, "Matches “" + p + "”"
	}
	if labelled {
		return true, "Its enable label is true"
	}
	return false, "Not chosen"
}

func toAutoCandidate(r DockerAutoUpdateRules, c docker.ContainerSummary, state map[string]string) DockerAutoUpdateCandidate {
	in, why := autoPick(r, c)
	out := DockerAutoUpdateCandidate{
		ID: c.ID, Name: containerName(c.Names), Image: c.Image, State: c.State, Included: in, Why: why,
		Project: c.Labels["com.docker.compose.project"], Service: c.Labels["com.docker.compose.service"],
		Update: cmpOr(state[c.Image], "unchecked"),
	}
	if pinnedRef(c.Image) {
		out.Update = "pinned"
	}
	if v, ok := autoLabel(c, "monitor-only"); ok {
		out.MonitorOnly = labelTrue(v)
	}
	if v, ok := autoLabel(c, "no-pull"); ok {
		out.NoPull = labelTrue(v)
	}
	for _, k := range hookNames {
		if v, ok := autoLabel(c, "lifecycle."+k); ok && v != "" {
			out.Hooks = append(out.Hooks, k)
		}
	}
	return out
}

// ---- Output ----

func (h *serverHandler) autoUpdateOut(ctx context.Context, p sqlc.DockerAutoUpdate, showHook bool, counts map[uuid.UUID]*DockerAutoUpdateCounts) DockerAutoUpdate {
	_, busy := autoUpdateBusy.Load(p.ID)
	out := DockerAutoUpdate{
		ID: p.ID.String(), WorkspaceID: p.WorkspaceID.String(), Name: p.Name, Enabled: p.Enabled,
		Servers: []DockerAutoUpdateServer{}, Pick: p.Pick, Include: nonNil(p.Include), Exclude: nonNil(p.Exclude),
		IncludeStopped: p.IncludeStopped, ReviveStopped: p.ReviveStopped, Cron: p.Cron, Timezone: p.Timezone,
		Mode: p.Mode, NoPull: p.NoPull, Cleanup: p.Cleanup, Rollback: p.Rollback, WaitSeconds: int(p.WaitSeconds),
		RestartLinked: p.RestartLinked, StopTimeout: int(p.StopTimeout), MinAgeHours: int(p.MinAgeHours),
		Hooks: p.Hooks, HookTimeout: int(p.HookTimeout), Notify: p.Notify, Channels: []string{},
		LastRunAt: p.LastRunAt, LastState: p.LastState, LastNote: p.LastNote,
		Running: busy, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
	if p.Enabled {
		out.NextRunAt = p.NextRunAt
	}
	if p.LastJobID != nil {
		out.LastJobID = p.LastJobID.String()
	}
	if busy {
		out.LastState = "running"
	}
	for _, c := range p.Channels {
		out.Channels = append(out.Channels, c.String())
	}
	for _, id := range p.ServerIds {
		s, err := h.q.GetServer(ctx, id)
		if err != nil || s.WorkspaceID != p.WorkspaceID {
			out.Servers = append(out.Servers, DockerAutoUpdateServer{ID: id.String(), Name: "Removed server", Missing: true})
			continue
		}
		out.Servers = append(out.Servers, DockerAutoUpdateServer{ID: id.String(), Name: s.Name})
	}
	if p.UpdatedBy != nil {
		if u, err := h.q.GetUser(ctx, *p.UpdatedBy); err == nil {
			out.RunsAs = displayName(u)
		}
	}
	if showHook {
		if t, err := h.box.Open(p.WebhookEnc); err == nil {
			out.WebhookToken = t
		}
	}
	if c := counts[p.ID]; c != nil {
		out.Last30Days = *c
	}
	return out
}

func (h *serverHandler) autoUpdateCounts(ctx context.Context, ws uuid.UUID) map[uuid.UUID]*DockerAutoUpdateCounts {
	out := map[uuid.UUID]*DockerAutoUpdateCounts{}
	rows, err := h.q.CountDockerAutoUpdateEvents(ctx, ws)
	if err != nil {
		return out
	}
	for _, r := range rows {
		c := out[r.PolicyID]
		if c == nil {
			c = &DockerAutoUpdateCounts{}
			out[r.PolicyID] = c
		}
		switch r.Result {
		case "updated":
			c.Updated += int(r.N)
		case "available":
			c.Available += int(r.N)
		case "rolled_back":
			c.RolledBack += int(r.N)
		case "failed":
			c.Failed += int(r.N)
		}
	}
	return out
}

// callerWorkspaceLevel is the caller's level on the workspace (Owner for
// internal calls).
func callerWorkspaceLevel(ctx context.Context, ws uuid.UUID) auth.Level {
	if p := principalOf(ctx); p != nil {
		return p.Access.WorkspaceLevel(ws)
	}
	return auth.Owner
}

// ---- Checking a body ----

func tidyPatterns(field string, in []string) ([]string, error) {
	out := []string{}
	for i, p := range in {
		p = strings.TrimSpace(p)
		if p == "" || slices.Contains(out, p) {
			continue
		}
		if len(p) > 200 {
			return nil, fieldError(fmt.Sprintf("body.%s[%d]", field, i), "Too long", p)
		}
		if _, err := path.Match(strings.ToLower(p), ""); err != nil {
			return nil, fieldError(fmt.Sprintf("body.%s[%d]", field, i), "Not a valid pattern", p)
		}
		out = append(out, p)
	}
	return out, nil
}

// checkAutoRules tidies the rules and checks the servers are in the
// workspace and the caller may do this much on each.
func (h *serverHandler) checkAutoRules(ctx context.Context, ws uuid.UUID, r *DockerAutoUpdateRules, need auth.Level) ([]uuid.UUID, []sqlc.Server, error) {
	var err error
	if r.Include, err = tidyPatterns("include", r.Include); err != nil {
		return nil, nil, err
	}
	if r.Exclude, err = tidyPatterns("exclude", r.Exclude); err != nil {
		return nil, nil, err
	}
	p := principalOf(ctx)
	var ids []uuid.UUID
	var servers []sqlc.Server
	for i, raw := range r.Servers {
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, nil, fieldError(fmt.Sprintf("body.servers[%d]", i), "Not a server id", raw)
		}
		if slices.Contains(ids, id) {
			continue
		}
		s, err := h.q.GetServer(ctx, id)
		if err != nil || s.WorkspaceID != ws {
			return nil, nil, fieldError(fmt.Sprintf("body.servers[%d]", i), "This server isn't in the workspace", raw)
		}
		if p != nil && p.Access.ServerLevel(ws, id) < need {
			return nil, nil, fieldError(fmt.Sprintf("body.servers[%d]", i), fmt.Sprintf("You need %s access to %s", need, s.Name), raw)
		}
		ids = append(ids, id)
		servers = append(servers, s)
	}
	if len(ids) == 0 {
		return nil, nil, fieldError("body.servers", "Pick at least one server", nil)
	}
	return ids, servers, nil
}

func autoNeed(mode string) auth.Level {
	if mode == "monitor" {
		return auth.Operator
	}
	return auth.Engineer
}

func (h *serverHandler) checkAutoBody(ctx context.Context, ws uuid.UUID, b *DockerAutoUpdateBody) ([]uuid.UUID, []uuid.UUID, *time.Time, error) {
	b.Name = strings.TrimSpace(b.Name)
	if b.Name == "" {
		return nil, nil, nil, fieldError("body.name", "Give it a name", "")
	}
	ids, _, err := h.checkAutoRules(ctx, ws, &b.DockerAutoUpdateRules, autoNeed(b.Mode))
	if err != nil {
		return nil, nil, nil, err
	}
	if b.Pick == "chosen" && len(b.Include) == 0 {
		return nil, nil, nil, fieldError("body.include", "Name at least one container, compose project or image", nil)
	}
	if !b.IncludeStopped {
		b.ReviveStopped = false
	}
	b.Cron = strings.TrimSpace(b.Cron)
	b.Timezone = cmpOr(strings.TrimSpace(b.Timezone), "UTC")
	var next *time.Time
	if b.Cron != "" {
		if _, _, err := parseCron(b.Cron, b.Timezone); err != nil {
			return nil, nil, nil, err
		}
		next = nextRun(b.Cron, b.Timezone, time.Now())
	} else if _, err := time.LoadLocation(b.Timezone); err != nil {
		return nil, nil, nil, fieldError("body.timezone", "Unknown time zone.", b.Timezone)
	}
	var channels []uuid.UUID
	for i, raw := range b.Channels {
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, nil, nil, fieldError(fmt.Sprintf("body.channels[%d]", i), "Not a channel id", raw)
		}
		cw, err := h.q.GetNotificationChannelWorkspace(ctx, id)
		if err != nil || cw != ws {
			return nil, nil, nil, fieldError(fmt.Sprintf("body.channels[%d]", i), "No such channel in this workspace", raw)
		}
		if !slices.Contains(channels, id) {
			channels = append(channels, id)
		}
	}
	if b.Notify != "never" && len(channels) == 0 {
		b.Notify = "never"
	}
	if channels == nil {
		channels = []uuid.UUID{}
	}
	return ids, channels, next, nil
}

// ---- Routes ----

func registerDockerAutoUpdates(api huma.API, h *serverHandler) {
	tags := []string{"Containers"}
	base := "/workspaces/{id}/docker/auto-updates"

	load := func(ctx context.Context, in *DockerAutoUpdatePath) (sqlc.DockerAutoUpdate, error) {
		p, err := h.q.GetDockerAutoUpdate(ctx, uuid.MustParse(in.Policy))
		if isNotFound(err) || err == nil && p.WorkspaceID.String() != in.ID {
			return p, huma.Error404NotFound("No such auto-update")
		}
		if err != nil {
			return p, internalError(err)
		}
		return p, nil
	}
	showHook := func(ctx context.Context, ws uuid.UUID) bool {
		return callerWorkspaceLevel(ctx, ws) >= auth.Engineer
	}

	huma.Register(api, huma.Operation{
		OperationID: "list-docker-auto-updates", Method: http.MethodGet, Path: base,
		Summary: "Container auto-updates", Description: "The workspace's auto-update policies with their last run and what the last 30 days held.",
		Tags: tags,
	}, func(ctx context.Context, in *WorkspacePath) (*struct{ Body DockerAutoUpdates }, error) {
		ws := uuid.MustParse(in.ID)
		rows, err := h.q.ListDockerAutoUpdates(ctx, ws)
		if err != nil {
			return nil, internalError(err)
		}
		counts := h.autoUpdateCounts(ctx, ws)
		out := DockerAutoUpdates{Items: make([]DockerAutoUpdate, len(rows))}
		hook := showHook(ctx, ws)
		for i, r := range rows {
			out.Items[i] = h.autoUpdateOut(ctx, r, hook, counts)
		}
		return &struct{ Body DockerAutoUpdates }{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-docker-auto-update", Method: http.MethodGet, Path: base + "/{policy}",
		Summary: "One container auto-update", Tags: tags,
	}, func(ctx context.Context, in *DockerAutoUpdatePath) (*struct{ Body DockerAutoUpdate }, error) {
		p, err := load(ctx, in)
		if err != nil {
			return nil, err
		}
		return &struct{ Body DockerAutoUpdate }{h.autoUpdateOut(ctx, p, showHook(ctx, p.WorkspaceID), h.autoUpdateCounts(ctx, p.WorkspaceID))}, nil
	})

	save := func(ctx context.Context, ws uuid.UUID, prev *sqlc.DockerAutoUpdate, b DockerAutoUpdateBody) (*struct{ Body DockerAutoUpdate }, error) {
		ids, channels, next, err := h.checkAutoBody(ctx, ws, &b)
		if err != nil {
			return nil, err
		}
		var by *uuid.UUID
		if p := principalOf(ctx); p != nil {
			by = p.ID()
		}
		var row sqlc.DockerAutoUpdate
		if prev == nil {
			token := pushToken()
			row, err = h.q.CreateDockerAutoUpdate(ctx, sqlc.CreateDockerAutoUpdateParams{
				WorkspaceID: ws, Name: b.Name, Enabled: b.Enabled, ServerIds: ids, Pick: b.Pick,
				Include: b.Include, Exclude: b.Exclude, IncludeStopped: b.IncludeStopped, ReviveStopped: b.ReviveStopped,
				Cron: b.Cron, Timezone: b.Timezone, Mode: b.Mode, NoPull: b.NoPull, Cleanup: b.Cleanup,
				Rollback: b.Rollback, WaitSeconds: int32(b.WaitSeconds), RestartLinked: b.RestartLinked,
				StopTimeout: int32(b.StopTimeout), MinAgeHours: int32(b.MinAgeHours), Hooks: b.Hooks,
				HookTimeout: int32(b.HookTimeout), Notify: b.Notify, Channels: channels,
				WebhookEnc: h.box.Seal(token), WebhookHash: hookHash(token), NextRunAt: next, UpdatedBy: by,
			})
		} else {
			row, err = h.q.UpdateDockerAutoUpdate(ctx, sqlc.UpdateDockerAutoUpdateParams{
				ID: prev.ID, Name: b.Name, Enabled: b.Enabled, ServerIds: ids, Pick: b.Pick,
				Include: b.Include, Exclude: b.Exclude, IncludeStopped: b.IncludeStopped, ReviveStopped: b.ReviveStopped,
				Cron: b.Cron, Timezone: b.Timezone, Mode: b.Mode, NoPull: b.NoPull, Cleanup: b.Cleanup,
				Rollback: b.Rollback, WaitSeconds: int32(b.WaitSeconds), RestartLinked: b.RestartLinked,
				StopTimeout: int32(b.StopTimeout), MinAgeHours: int32(b.MinAgeHours), Hooks: b.Hooks,
				HookTimeout: int32(b.HookTimeout), Notify: b.Notify, Channels: channels,
				NextRunAt: next, UpdatedBy: by,
			})
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &struct{ Body DockerAutoUpdate }{h.autoUpdateOut(ctx, row, true, h.autoUpdateCounts(ctx, ws))}, nil
	}

	huma.Register(api, huma.Operation{
		OperationID: "create-docker-auto-update", Method: http.MethodPost, Path: base,
		Summary: "Add a container auto-update",
		Description: "Saving needs Engineer access to every server it updates (Operator in monitor mode). " +
			"Runs act with the access of whoever saved it last.",
		Tags: tags, DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body DockerAutoUpdateBody
	}) (*struct{ Body DockerAutoUpdate }, error) {
		return save(ctx, uuid.MustParse(in.ID), nil, in.Body)
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-docker-auto-update", Method: http.MethodPut, Path: base + "/{policy}",
		Summary: "Change a container auto-update", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DockerAutoUpdatePath
		Body DockerAutoUpdateBody
	}) (*struct{ Body DockerAutoUpdate }, error) {
		p, err := load(ctx, &in.DockerAutoUpdatePath)
		if err != nil {
			return nil, err
		}
		return save(ctx, p.WorkspaceID, &p, in.Body)
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-docker-auto-update-enabled", Method: http.MethodPost, Path: base + "/{policy}/enabled",
		Summary: "Turn a container auto-update on or off", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DockerAutoUpdatePath
		Body struct {
			Enabled bool `json:"enabled"`
		}
	}) (*struct{ Body DockerAutoUpdate }, error) {
		p, err := load(ctx, &in.DockerAutoUpdatePath)
		if err != nil {
			return nil, err
		}
		var next *time.Time
		if in.Body.Enabled && p.Cron != "" {
			next = nextRun(p.Cron, p.Timezone, time.Now())
		}
		row, err := h.q.SetDockerAutoUpdateEnabled(ctx, sqlc.SetDockerAutoUpdateEnabledParams{
			ID: p.ID, Enabled: in.Body.Enabled, NextRunAt: next, UpdatedBy: p.UpdatedBy,
		})
		if err != nil {
			return nil, internalError(err)
		}
		return &struct{ Body DockerAutoUpdate }{h.autoUpdateOut(ctx, row, true, h.autoUpdateCounts(ctx, p.WorkspaceID))}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "reset-docker-auto-update-webhook", Method: http.MethodPost, Path: base + "/{policy}/webhook",
		Summary: "Make a new webhook address", Description: "The old address stops working.", Tags: tags,
	}, func(ctx context.Context, in *DockerAutoUpdatePath) (*struct{ Body DockerAutoUpdate }, error) {
		p, err := load(ctx, in)
		if err != nil {
			return nil, err
		}
		token := pushToken()
		row, err := h.q.SetDockerAutoUpdateWebhook(ctx, sqlc.SetDockerAutoUpdateWebhookParams{
			ID: p.ID, WebhookEnc: h.box.Seal(token), WebhookHash: hookHash(token),
		})
		if err != nil {
			return nil, internalError(err)
		}
		return &struct{ Body DockerAutoUpdate }{h.autoUpdateOut(ctx, row, true, h.autoUpdateCounts(ctx, p.WorkspaceID))}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-docker-auto-update", Method: http.MethodDelete, Path: base + "/{policy}",
		Summary: "Delete a container auto-update", Description: "Its history goes with it.", Tags: tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *DockerAutoUpdatePath) (*struct{}, error) {
		n, err := h.q.DeleteDockerAutoUpdate(ctx, sqlc.DeleteDockerAutoUpdateParams{ID: uuid.MustParse(in.Policy), WorkspaceID: uuid.MustParse(in.ID)})
		if err != nil {
			return nil, internalError(err)
		}
		if n == 0 {
			return nil, huma.Error404NotFound("No such auto-update")
		}
		return &struct{}{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "run-docker-auto-update", Method: http.MethodPost, Path: base + "/{policy}/run",
		Summary:     "Run a container auto-update now",
		Description: "Runs as a job (kind `docker-auto-update`) with the access of whoever saved it last. check_only = only look and report.",
		Tags:        tags, DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		DockerAutoUpdatePath
		Body *DockerAutoUpdateRunBody `required:"false"`
	}) (*JobOutput, error) {
		p, err := load(ctx, &in.DockerAutoUpdatePath)
		if err != nil {
			return nil, err
		}
		var b DockerAutoUpdateRunBody
		if in.Body != nil {
			b = *in.Body
		}
		if b.Server != "" && !slices.ContainsFunc(p.ServerIds, func(id uuid.UUID) bool { return id.String() == b.Server }) {
			return nil, fieldError("body.server", "This auto-update doesn't cover that server", b.Server)
		}
		return h.submitAutoUpdate(ctx, p, dockerAutoUpdateParams{Trigger: "manual", Server: b.Server, CheckOnly: b.CheckOnly}, nil)
	})

	huma.Register(api, huma.Operation{
		OperationID: "preview-docker-auto-update", Method: http.MethodPost, Path: base + "/preview",
		Summary:     "What an auto-update would take",
		Description: "Lists each server's containers with whether the rules take them in and why, and what the last registry check said about their image. Nothing is changed.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body DockerAutoUpdateRules
	}) (*struct{ Body DockerAutoUpdatePreview }, error) {
		ws := uuid.MustParse(in.ID)
		r := in.Body
		_, servers, err := h.checkAutoRules(ctx, ws, &r, auth.Viewer)
		if err != nil {
			return nil, err
		}
		out := DockerAutoUpdatePreview{Servers: make([]DockerAutoUpdatePreviewServer, len(servers))}
		var wg sync.WaitGroup
		for i, s := range servers {
			wg.Go(func() {
				out.Servers[i] = h.previewAutoServer(ctx, r, s)
			})
		}
		wg.Wait()
		for _, s := range out.Servers {
			for _, c := range s.Containers {
				if c.Included {
					out.Included++
					if c.Update == "available" {
						out.Waiting++
					}
				}
			}
		}
		return &struct{ Body DockerAutoUpdatePreview }{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-docker-auto-update-events", Method: http.MethodGet, Path: base + "-events",
		Summary: "What auto-updates did", Description: "Newest first, 50 at a time.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Policy string `query:"policy" format:"uuid" required:"false"`
		Server string `query:"server" format:"uuid" required:"false"`
		Result string `query:"result" enum:"updated,available,rolled_back,failed,skipped" required:"false"`
		Before string `query:"before" required:"false" doc:"The next value of the page before"`
	}) (*struct{ Body DockerAutoUpdateEvents }, error) {
		arg := sqlc.ListDockerAutoUpdateEventsParams{WorkspaceID: uuid.MustParse(in.ID), Lim: 51}
		if in.Policy != "" {
			id := uuid.MustParse(in.Policy)
			arg.PolicyID = &id
		}
		if in.Server != "" {
			id := uuid.MustParse(in.Server)
			arg.ServerID = &id
		}
		if in.Result != "" {
			arg.Result = &in.Result
		}
		if in.Before != "" {
			t, err := time.Parse(time.RFC3339Nano, in.Before)
			if err != nil {
				return nil, fieldError("query.before", "Not a time", in.Before)
			}
			arg.Before = &t
		}
		rows, err := h.q.ListDockerAutoUpdateEvents(ctx, arg)
		if err != nil {
			return nil, internalError(err)
		}
		out := DockerAutoUpdateEvents{Items: []DockerAutoUpdateEvent{}}
		p := principalOf(ctx)
		for i, r := range rows {
			if i == 50 {
				out.Next = rows[49].At.Format(time.RFC3339Nano)
				break
			}
			if p != nil && p.Access.ServerLevel(r.WorkspaceID, r.ServerID) < auth.Viewer {
				continue
			}
			e := DockerAutoUpdateEvent{
				ID: r.ID.String(), PolicyID: r.PolicyID.String(), PolicyName: r.PolicyName,
				ServerID: r.ServerID.String(), ServerName: r.ServerName, Container: r.Container, Image: r.Image,
				OldImage: r.OldImage, NewImage: r.NewImage, Result: r.Result, Message: r.Message, At: r.At,
			}
			if r.JobID != nil {
				e.JobID = r.JobID.String()
			}
			out.Items = append(out.Items, e)
		}
		return &struct{ Body DockerAutoUpdateEvents }{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-server-docker-auto-update", Method: http.MethodGet, Path: "/servers/{id}/docker/auto-update",
		Summary:     "Auto-updates covering a server",
		Description: "The auto-updates that name this server, and which of its containers each one takes.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body DockerServerAutoUpdate }, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		rows, err := h.q.ListDockerAutoUpdatesForServer(ctx, s.ID)
		if err != nil {
			return nil, internalError(err)
		}
		out := DockerServerAutoUpdate{Policies: []DockerAutoUpdate{}, Containers: []DockerServerAutoUpdateCover{}}
		var mine []sqlc.DockerAutoUpdate
		for _, r := range rows {
			if r.WorkspaceID == s.WorkspaceID {
				mine = append(mine, r)
			}
		}
		if len(mine) == 0 {
			return &struct{ Body DockerServerAutoUpdate }{out}, nil
		}
		counts := h.autoUpdateCounts(ctx, s.WorkspaceID)
		for _, r := range mine {
			out.Policies = append(out.Policies, h.autoUpdateOut(ctx, r, false, counts))
		}
		var cs []docker.ContainerSummary
		if err := h.withDocker(ctx, in.ID, func(e *dockerEngine) error {
			cs, err = e.client.Containers(ctx)
			return err
		}); err != nil {
			return &struct{ Body DockerServerAutoUpdate }{out}, nil
		}
		for _, c := range cs {
			cover := DockerServerAutoUpdateCover{Container: containerName(c.Names), Policies: []string{}, Monitor: true}
			for _, r := range mine {
				if !r.Enabled {
					continue
				}
				if ok, _ := autoPick(rulesOf(r), c); ok {
					cover.Policies = append(cover.Policies, r.ID.String())
					if r.Mode == "update" {
						if v, _ := autoLabel(c, "monitor-only"); !labelTrue(v) {
							cover.Monitor = false
						}
					}
				}
			}
			if len(cover.Policies) > 0 {
				out.Containers = append(out.Containers, cover)
			}
		}
		return &struct{ Body DockerServerAutoUpdate }{out}, nil
	})

	hook := func(ctx context.Context, in *DockerAutoUpdateHookInput) (*DockerAutoUpdateHookOutput, error) {
		p, err := h.q.GetDockerAutoUpdateByHook(ctx, hookHash(in.Token))
		if isNotFound(err) {
			return nil, huma.Error404NotFound("No auto-update has this webhook address")
		}
		if err != nil {
			return nil, internalError(err)
		}
		out := &DockerAutoUpdateHookOutput{Status: http.StatusAccepted}
		out.Body.OK = true
		if !p.Enabled {
			out.Status = http.StatusOK
			out.Body.Message = "Ignored: this auto-update is turned off"
			return out, nil
		}
		if _, busy := autoUpdateBusy.Load(p.ID); busy {
			out.Status = http.StatusOK
			out.Body.Message = "A run is already going"
			return out, nil
		}
		j, err := h.submitAutoUpdate(context.WithoutCancel(ctx), p, dockerAutoUpdateParams{Trigger: "webhook", Image: strings.TrimSpace(in.Image)}, p.UpdatedBy)
		if err != nil {
			return nil, err
		}
		out.Body.JobID = &j.Body.ID
		out.Body.Message = "Running"
		return out, nil
	}
	hookPath := "/hooks/docker-update/{token}"
	huma.Register(api, huma.Operation{
		OperationID: "docker-auto-update-webhook", Method: http.MethodPost, Path: hookPath,
		Summary:      "Run a container auto-update (webhook)",
		Description:  "Call it from CI after pushing an image, or from a registry's webhook. No sign-in; the token is the secret. ?image= limits the run to containers of that image.",
		Tags:         tags,
		MaxBodyBytes: 1 << 20,
	}, hook)
	if op := api.OpenAPI().Paths[hookPath]; op != nil && op.Post != nil && op.Post.RequestBody != nil {
		op.Post.RequestBody.Required = false
	}

	h.jobs.Handle(dockerAutoUpdateKind, h.runAutoUpdate)
}

func rulesOf(p sqlc.DockerAutoUpdate) DockerAutoUpdateRules {
	return DockerAutoUpdateRules{Pick: p.Pick, Include: p.Include, Exclude: p.Exclude, IncludeStopped: p.IncludeStopped, Mode: p.Mode}
}

func (h *serverHandler) previewAutoServer(ctx context.Context, r DockerAutoUpdateRules, s sqlc.Server) DockerAutoUpdatePreviewServer {
	out := DockerAutoUpdatePreviewServer{ID: s.ID.String(), Name: s.Name, Containers: []DockerAutoUpdateCandidate{}}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var cs []docker.ContainerSummary
	if err := h.withDocker(ctx, s.ID.String(), func(e *dockerEngine) error {
		var err error
		cs, err = e.client.Containers(ctx)
		return err
	}); err != nil {
		out.Error = dockerProblemText(err)
		return out
	}
	state := map[string]string{}
	if rows, err := h.q.ListDockerImageUpdates(ctx, s.ID); err == nil {
		for _, row := range rows {
			state[row.Image] = row.State
		}
	}
	for _, c := range cs {
		if strings.Contains(containerName(c.Names), "-morche-old-") {
			continue
		}
		out.Containers = append(out.Containers, toAutoCandidate(r, c, state))
	}
	sort.SliceStable(out.Containers, func(i, j int) bool {
		a, b := out.Containers[i], out.Containers[j]
		if a.Included != b.Included {
			return a.Included
		}
		return a.Name < b.Name
	})
	return out
}

// submitAutoUpdate starts a run. by = whose job it is when nobody is
// signed in (schedule, webhook).
func (h *serverHandler) submitAutoUpdate(ctx context.Context, p sqlc.DockerAutoUpdate, params dockerAutoUpdateParams, by *uuid.UUID) (*JobOutput, error) {
	if _, busy := autoUpdateBusy.Load(p.ID); busy {
		return nil, huma.Error409Conflict("This auto-update is already running")
	}
	params.PolicyID = p.ID.String()
	title := "Auto-update: " + p.Name
	if p.Mode == "monitor" || params.CheckOnly {
		title = "Look for new images: " + p.Name
	}
	ids := make([]string, len(p.ServerIds))
	for i, id := range p.ServerIds {
		ids[i] = id.String()
	}
	place := &JobPlace{AutoUpdate: p.ID.String(), Name: p.Name}
	if params.Server != "" {
		place.ServerID = params.Server
	}
	spec := jobs.Spec{
		Kind: dockerAutoUpdateKind, Title: title, Params: params, Refs: placeRefs(ids...),
		Target: place,
	}
	var out *JobOutput
	if principalOf(ctx) == nil {
		spec.CreatedBy = by
		j, err := h.jobs.Submit(ctx, spec)
		if err != nil {
			return nil, internalError(err)
		}
		out = &JobOutput{toJob(j, false)}
	} else {
		var err error
		if out, err = submit(ctx, h.jobs, spec); err != nil {
			return nil, err
		}
	}
	if id, err := uuid.Parse(out.Body.ID); err == nil {
		_ = h.q.StartDockerAutoUpdateRun(context.WithoutCancel(ctx), sqlc.StartDockerAutoUpdateRunParams{ID: p.ID, JobID: &id})
	}
	return out, nil
}

// ---- Running ----

// autoRun is one run of a policy.
type autoRun struct {
	h       *serverHandler
	t       *jobs.Task
	p       sqlc.DockerAutoUpdate
	monitor bool
	image   string
	acc     *auth.Access
	multi   bool

	updated, available, rolled, failed, skipped []string
	problems                                    []string
}

func (h *serverHandler) runAutoUpdate(ctx context.Context, t *jobs.Task) (any, error) {
	var params dockerAutoUpdateParams
	if err := t.Decode(&params); err != nil {
		return nil, err
	}
	pid, err := uuid.Parse(params.PolicyID)
	if err != nil {
		return nil, err
	}
	bg := context.WithoutCancel(ctx)
	p, err := h.q.GetDockerAutoUpdate(ctx, pid)
	if err != nil {
		return nil, errors.New("The auto-update was deleted before this run started.")
	}
	if _, busy := autoUpdateBusy.LoadOrStore(pid, struct{}{}); busy {
		return nil, errors.New("Another run of this auto-update is going.")
	}
	defer autoUpdateBusy.Delete(pid)
	_ = h.q.StartDockerAutoUpdateRun(bg, sqlc.StartDockerAutoUpdateRunParams{ID: pid, JobID: &t.ID})
	end := func(state, note string) {
		_ = h.q.EndDockerAutoUpdateRun(bg, sqlc.EndDockerAutoUpdateRunParams{ID: pid, LastState: state, LastNote: truncate(note, 1000)})
	}

	u, acc, err := h.autoRunUser(ctx, p)
	if err != nil {
		end("failed", problemText(err))
		h.notifyAutoUpdate(p, nil, err.Error())
		return nil, err
	}
	ctx = context.WithValue(ctx, principalKey{}, &principal{User: u, Access: acc})
	r := &autoRun{h: h, t: t, p: p, monitor: p.Mode == "monitor" || params.CheckOnly, image: params.Image, acc: acc}
	if r.image != "" {
		t.Logf("Only containers of %s", r.image)
	}
	var servers []sqlc.Server
	for _, id := range p.ServerIds {
		if params.Server != "" && id.String() != params.Server {
			continue
		}
		s, err := h.q.GetServer(ctx, id)
		if err != nil || s.WorkspaceID != p.WorkspaceID {
			r.problems = append(r.problems, "a server was removed from the workspace")
			continue
		}
		servers = append(servers, s)
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].Name < servers[j].Name })
	r.multi = len(servers) > 1
	for i, s := range servers {
		if ctx.Err() != nil {
			break
		}
		t.Update(func(pr *jobs.Progress) {
			pr.Phase, pr.Current, pr.Items, pr.ItemsTotal = "Server "+s.Name, "", i, len(servers)
		})
		need := auth.Engineer
		if r.monitor {
			need = auth.Operator
		}
		if acc.ServerLevel(p.WorkspaceID, s.ID) < need {
			msg := fmt.Sprintf("%s no longer has %s access to %s", displayName(u), need, s.Name)
			t.Logf("%s: skipped", msg)
			r.problems = append(r.problems, msg)
			continue
		}
		if err := r.server(ctx, s); err != nil {
			msg := s.Name + ": " + dockerProblemText(err)
			t.Logf("%s", msg)
			r.problems = append(r.problems, msg)
		}
	}
	t.Update(func(pr *jobs.Progress) {
		pr.Phase, pr.Current, pr.Items, pr.ItemsTotal = "Done", "", len(servers), len(servers)
	})

	note := r.summary()
	state := "ok"
	switch {
	case len(r.failed) > 0 || len(r.rolled) > 0 || len(r.problems) > 0:
		state = "failed"
	case len(r.updated) > 0:
		state = "updated"
	case len(r.available) > 0:
		state = "available"
	}
	end(state, note)
	h.notifyAutoUpdate(p, r, "")
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	t.Logf("%s", note)
	result := map[string]int{"updated": len(r.updated), "available": len(r.available), "rolled_back": len(r.rolled), "failed": len(r.failed)}
	if state == "failed" {
		return nil, jobError(errors.New(note))
	}
	return result, nil
}

// autoRunUser is whose access a run uses.
func (h *serverHandler) autoRunUser(ctx context.Context, p sqlc.DockerAutoUpdate) (sqlc.User, *auth.Access, error) {
	gone := errors.New("The person who saved this auto-update was removed. Someone with access should open it and save it again.")
	if p.UpdatedBy == nil {
		return sqlc.User{}, nil, gone
	}
	u, err := h.q.GetUser(ctx, *p.UpdatedBy)
	if isNotFound(err) {
		return u, nil, gone
	}
	if err != nil {
		return u, nil, err
	}
	if u.Status != "active" {
		return u, nil, fmt.Errorf("%s's account isn't active, so this auto-update doesn't run. Someone with access should open it and save it again.", displayName(u))
	}
	acc, err := h.authz.accessOf(ctx, u)
	return u, acc, err
}

func (r *autoRun) summary() string {
	var parts []string
	if len(r.updated) > 0 {
		parts = append(parts, "Updated "+listText(r.updated, 8)+".")
	}
	if len(r.available) > 0 {
		parts = append(parts, "New image for "+listText(r.available, 8)+".")
	}
	if len(r.rolled) > 0 {
		parts = append(parts, "Back on the old image: "+listText(r.rolled, 5)+".")
	}
	if len(r.failed) > 0 {
		parts = append(parts, "Couldn't update "+listText(r.failed, 5)+".")
	}
	if len(r.problems) > 0 {
		parts = append(parts, "Problems: "+listText(r.problems, 3)+".")
	}
	if len(parts) == 0 {
		if r.monitor {
			return "Every image is up to date."
		}
		return "Nothing to update: every image is up to date."
	}
	return strings.Join(parts, " ")
}

func (r *autoRun) prefix(s sqlc.Server) string {
	if r.multi {
		return s.Name + ": "
	}
	return ""
}

func (r *autoRun) event(ctx context.Context, s sqlc.Server, c docker.ContainerSummary, result, oldImg, newImg, msg string) {
	err := r.h.q.AddDockerAutoUpdateEvent(context.WithoutCancel(ctx), sqlc.AddDockerAutoUpdateEventParams{
		PolicyID: r.p.ID, WorkspaceID: r.p.WorkspaceID, ServerID: s.ID, JobID: &r.t.ID,
		Container: containerName(c.Names), Image: c.Image, OldImage: shortImageID(oldImg), NewImage: newImg,
		Result: result, Message: truncate(msg, 500),
	})
	if err != nil {
		slog.Warn("record auto-update event", "error", err)
	}
}

func shortImageID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 && !strings.Contains(id, ":") {
		return id[:12]
	}
	return id
}

// pick is one container this run looks at.
type autoPickItem struct {
	c       docker.ContainerSummary
	name    string
	monitor bool
	noPull  bool
}

// server runs the policy on one server.
func (r *autoRun) server(ctx context.Context, s sqlc.Server) error {
	h, t, p := r.h, r.t, r.p
	id := s.ID.String()
	pre := r.prefix(s)
	var cs []docker.ContainerSummary
	var ims []docker.ImageSummary
	if err := h.withDocker(ctx, id, func(e *dockerEngine) error {
		var err error
		if cs, err = e.client.Containers(ctx); err != nil {
			return err
		}
		ims, err = e.client.Images(ctx)
		return err
	}); err != nil {
		return err
	}
	digests := map[string][]string{}
	for _, im := range ims {
		digests[im.ID] = im.RepoDigests
	}
	rules := rulesOf(p)
	var picks []autoPickItem
	for _, c := range cs {
		if ok, _ := autoPick(rules, c); !ok {
			continue
		}
		if r.image != "" {
			repo, _ := splitImageRef(c.Image)
			if !globMatch(r.image, c.Image) && !globMatch(r.image, repo) && !sameRepo(r.image, repo+"@x") {
				continue
			}
		}
		it := autoPickItem{c: c, name: containerName(c.Names), monitor: r.monitor}
		if v, ok := autoLabel(c, "monitor-only"); ok && labelTrue(v) {
			it.monitor = true
		}
		if v, ok := autoLabel(c, "no-pull"); ok && labelTrue(v) {
			it.noPull = true
		}
		picks = append(picks, it)
	}
	if len(picks) == 0 {
		t.Logf("%sNo container to look at", pre)
		return nil
	}
	t.Logf("%sLooking at %s", pre, plural(len(picks), "container"))

	// Hooks before anything else.
	if p.Hooks && !r.monitor {
		for _, it := range picks {
			if it.c.State == "running" {
				r.hook(ctx, s, it.c, "pre-check")
			}
		}
	}

	// Ask the registries (once per image reference).
	refs := map[string]sqlc.UpsertDockerImageUpdateParams{}
	if !p.NoPull || r.monitor {
		var order []string
		for _, it := range picks {
			if _, ok := refs[it.c.Image]; !ok {
				refs[it.c.Image] = sqlc.UpsertDockerImageUpdateParams{}
				order = append(order, it.c.Image)
			}
		}
		for i, ref := range order {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			t.Update(func(pr *jobs.Progress) {
				pr.Current = fmt.Sprintf("%sasking about %s (%d of %d)", pre, ref, i+1, len(order))
			})
			var local []string
			for _, it := range picks {
				if it.c.Image == ref {
					local = digests[it.c.ImageID]
					break
				}
			}
			row := h.registryState(ctx, id, s.ID, ref, local)
			refs[ref] = row
			if err := h.q.UpsertDockerImageUpdate(ctx, row); err != nil {
				return err
			}
			if row.State == "error" {
				t.Logf("%sCouldn't ask about %s: %s", pre, ref, row.Error)
			}
		}
	}
	seen := map[string]time.Time{}
	if rows, err := h.q.ListDockerImageUpdates(ctx, s.ID); err == nil {
		for _, row := range rows {
			seen[row.Image] = row.SeenAt
		}
	}

	// Which images to pull.
	var pull []string
	young := map[string]bool{}
	for ref, row := range refs {
		if row.State != "available" {
			continue
		}
		if p.MinAgeHours > 0 {
			ready := seen[ref].Add(time.Duration(p.MinAgeHours) * time.Hour)
			if time.Now().Before(ready) {
				young[ref] = true
				t.Logf("%sA new %s is out; waiting until %s (minimum age)", pre, ref, ready.Format("2006-01-02 15:04 MST"))
				continue
			}
		}
		for _, it := range picks {
			if it.c.Image == ref && !it.monitor && !it.noPull && !p.NoPull {
				pull = append(pull, ref)
				break
			}
		}
	}
	sort.Strings(pull)
	if len(pull) > 0 {
		if err := h.pullWithAuth(ctx, t, id, pull, false); err != nil {
			return err
		}
	}

	// What each reference points to now.
	current := map[string]string{}
	if err := h.withDocker(ctx, id, func(e *dockerEngine) error {
		for _, it := range picks {
			if _, ok := current[it.c.Image]; ok {
				continue
			}
			im, err := e.client.InspectImage(ctx, it.c.Image)
			if err == nil {
				current[it.c.Image] = im.ID
			} else {
				current[it.c.Image] = ""
			}
		}
		return nil
	}); err != nil {
		return err
	}

	var done []autoDone
	for i, it := range picks {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		row := refs[it.c.Image]
		now := current[it.c.Image]
		stale := now != "" && now != it.c.ImageID
		label := pre + it.name
		if it.monitor {
			newImg := ""
			switch {
			case row.State == "available":
				newImg = row.RemoteDigest
			case stale:
				newImg = now
			}
			if newImg == "" {
				continue
			}
			r.available = append(r.available, label)
			already, _ := h.q.SeenDockerAutoUpdateAvailable(ctx, sqlc.SeenDockerAutoUpdateAvailableParams{
				PolicyID: p.ID, ServerID: s.ID, Container: it.name, NewImage: shortImageID(newImg),
			})
			t.Logf("%s: a newer image is waiting (%s)", label, it.c.Image)
			if !already {
				r.event(ctx, s, it.c, "available", it.c.ImageID, shortImageID(newImg), "A newer image is waiting")
			}
			continue
		}
		if !stale {
			if young[it.c.Image] {
				r.skipped = append(r.skipped, label)
			}
			continue
		}
		t.Update(func(pr *jobs.Progress) { pr.Current = fmt.Sprintf("%s (%d of %d)", label, i+1, len(picks)) })
		d, ok := r.update(ctx, s, it, now)
		if ok {
			done = append(done, d)
		}
	}

	// Restart what depends on the updated ones.
	if p.RestartLinked && len(done) > 0 {
		r.restartLinked(ctx, s, done)
	}
	if p.Hooks {
		for _, it := range picks {
			if it.c.State == "running" && !slices.ContainsFunc(done, func(d autoDone) bool { return d.name == it.name }) {
				r.hook(ctx, s, it.c, "post-check")
			}
		}
	}
	// Clean up and mark images current.
	var after []docker.ContainerSummary
	_ = h.withDocker(ctx, id, func(e *dockerEngine) error {
		var err error
		after, err = e.client.Containers(ctx)
		return err
	})
	if len(done) > 0 && after != nil {
		inUse := map[string]bool{}
		onOld := map[string]bool{}
		for _, c := range after {
			inUse[c.ImageID] = true
			if cur, ok := current[c.Image]; ok && cur != "" && c.ImageID != cur {
				onOld[c.Image] = true
			}
		}
		marked := map[string]bool{}
		for _, d := range done {
			if !d.back && !onOld[d.ref] && !marked[d.ref] {
				marked[d.ref] = true
				_ = h.q.MarkDockerImageCurrent(ctx, sqlc.MarkDockerImageCurrentParams{ServerID: s.ID, Image: d.ref})
			}
		}
		if p.Cleanup {
			removed := map[string]bool{}
			for _, d := range done {
				if d.back || inUse[d.oldID] || removed[d.oldID] || d.oldID == "" {
					continue
				}
				removed[d.oldID] = true
				err := h.withDocker(ctx, id, func(e *dockerEngine) error { return e.client.RemoveImage(ctx, d.oldID, false) })
				if err != nil {
					t.Logf("%sKept the old image %s: %s", pre, shortImageID(d.oldID), dockerProblemText(err))
				} else {
					t.Logf("%sRemoved the old image %s", pre, shortImageID(d.oldID))
				}
			}
		}
	}
	return nil
}

// autoDone is a container this run recreated.
type autoDone struct {
	name, id, ref, oldID string
	back                 bool
}

// update recreates one container on its image's new version.
func (r *autoRun) update(ctx context.Context, s sqlc.Server, it autoPickItem, newID string) (autoDone, bool) {
	h, t, p := r.h, r.t, r.p
	id := s.ID.String()
	label := r.prefix(s) + it.name
	c := it.c
	d := autoDone{name: it.name, ref: c.Image, oldID: c.ImageID}
	if p.Hooks && c.State == "running" {
		code, ran := r.hook(ctx, s, c, "pre-update")
		if ran && code == 75 {
			t.Logf("%s: its pre-update hook asked to skip this time", label)
			r.skipped = append(r.skipped, label)
			r.event(ctx, s, c, "skipped", c.ImageID, shortImageID(newID), "Its pre-update hook asked to skip (exit code 75)")
			return d, false
		}
		if ran && code != 0 {
			msg := fmt.Sprintf("its pre-update hook failed (exit code %d)", code)
			t.Logf("%s: not updated, %s", label, msg)
			r.failed = append(r.failed, label)
			r.event(ctx, s, c, "failed", c.ImageID, shortImageID(newID), "Not updated: "+msg)
			return d, false
		}
	}
	running := c.State == "running"
	start := running || p.ReviveStopped
	if err := h.recreateAuto(ctx, t, id, c, int(p.StopTimeout), start); err != nil {
		msg := dockerProblemText(err)
		t.Logf("%s: couldn't update: %s", label, msg)
		r.failed = append(r.failed, label)
		r.event(ctx, s, c, "failed", c.ImageID, shortImageID(newID), msg)
		return d, false
	}
	if start && p.Rollback {
		u := updatePick{c: c, oldID: c.ImageID, name: it.name, project: c.Labels["com.docker.compose.project"]}
		why := h.watchUpdated(ctx, t, id, it.name, time.Duration(p.WaitSeconds)*time.Second, r.prefix(s))
		if why != "" {
			t.Logf("%s %s: putting its old image back", label, why)
			d.back = true
			if err := h.rollbackContainer(ctx, t, id, u); err != nil {
				r.failed = append(r.failed, label)
				r.event(ctx, s, c, "failed", c.ImageID, shortImageID(newID), "It "+why+", and going back failed too: "+dockerProblemText(err))
				return d, true
			}
			r.rolled = append(r.rolled, label)
			r.event(ctx, s, c, "rolled_back", c.ImageID, shortImageID(newID), "It "+why+", so the old image was put back")
			return d, true
		}
	}
	t.Logf("%s: updated to %s", label, shortImageID(newID))
	r.updated = append(r.updated, label)
	r.event(ctx, s, c, "updated", c.ImageID, shortImageID(newID), "")
	if p.Hooks && start {
		if now, ok := r.findContainer(ctx, id, it.name); ok {
			if code, ran := r.hook(ctx, s, now, "post-update"); ran && code != 0 {
				t.Logf("%s: its post-update hook ended with exit code %d", label, code)
			}
		}
	}
	return d, true
}

func (r *autoRun) findContainer(ctx context.Context, serverID, name string) (docker.ContainerSummary, bool) {
	var out docker.ContainerSummary
	found := false
	_ = r.h.withDocker(ctx, serverID, func(e *dockerEngine) error {
		cs, err := e.client.Containers(ctx)
		if err != nil {
			return err
		}
		for _, c := range cs {
			if containerName(c.Names) == name {
				out, found = c, true
				return nil
			}
		}
		return nil
	})
	return out, found
}

// recreateAuto is recreateContainer with a stop timeout, keeping a stopped
// container stopped unless start.
func (h *serverHandler) recreateAuto(ctx context.Context, t *jobs.Task, serverID string, c docker.ContainerSummary, stop int, start bool) error {
	name := containerName(c.Names)
	project := c.Labels["com.docker.compose.project"]
	service := c.Labels["com.docker.compose.service"]
	dir := c.Labels["com.docker.compose.project.working_dir"]
	files := c.Labels["com.docker.compose.project.config_files"]
	if project != "" && service != "" && dir != "" && files != "" {
		cp := dockerComposeParams{ServerID: serverID, Project: project, Dir: dir}
		for f := range strings.SplitSeq(files, ",") {
			if f = strings.TrimSpace(f); f != "" {
				if !path.IsAbs(f) {
					f = path.Join(dir, f)
				}
				cp.Files = append(cp.Files, f)
			}
		}
		svc := terminal.ShellQuote(service)
		// The project's files may not be on this host (made elsewhere, moved,
		// or an engine reached remotely): then compose can't recreate it, and
		// the Engine API does it with the container's own settings instead.
		check := "test -d " + terminal.ShellQuote(dir)
		for _, f := range cp.Files {
			check += " && test -f " + terminal.ShellQuote(f)
		}
		missing := false
		err := h.withShell(ctx, serverID, func(_ *sshpool.Conn, sh *rootShell) error {
			res, err := sh.exec(ctx, check, execTimeout, 1024)
			if err != nil {
				return err
			}
			if res.code != 0 {
				missing = true
				return nil
			}
			t.Logf("Recreating %s (service %s of %s)", name, service, project)
			if !start {
				return h.composeRun(ctx, t, sh, cp, "up --no-start --no-deps "+svc)
			}
			return errRollLater
		})
		if errors.Is(err, errRollLater) {
			return h.updateService(ctx, t, cp, service, "--timeout "+strconv.Itoa(stop), stop)
		}
		if !missing {
			return err
		}
		t.Logf("The files of project %s aren't in %s on this server; recreating %s with its own settings instead", project, dir, name)
	}
	t.Logf("Recreating %s", name)
	return h.dockerDo(ctx, serverID, "docker recreate "+name+" ("+c.Image+")", func(e *dockerEngine) error {
		newID, err := e.client.RecreateWait(ctx, c.ID, stop)
		if err != nil {
			return err
		}
		if start && c.State != "running" && newID != "" {
			return e.client.Act(ctx, newID, "start", 0, "")
		}
		return nil
	})
}

// hook runs a lifecycle hook label inside a container. ran = it has one.
func (r *autoRun) hook(ctx context.Context, s sqlc.Server, c docker.ContainerSummary, which string) (int, bool) {
	cmd, ok := autoLabel(c, "lifecycle."+which)
	if !ok || cmd == "" {
		return 0, false
	}
	label := r.prefix(s) + containerName(c.Names)
	timeout := time.Duration(r.p.HookTimeout) * time.Second
	if v, ok := autoLabel(c, "lifecycle."+which+"-timeout"); ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			timeout = time.Duration(min(n, 60)) * time.Minute
		}
	}
	r.t.Logf("%s: running its %s hook", label, which)
	hctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var res docker.ExecResult
	err := r.h.withDocker(hctx, s.ID.String(), func(e *dockerEngine) error {
		var err error
		res, err = e.client.Exec(hctx, c.ID, []string{"sh", "-c", cmd}, "")
		return err
	})
	if out := strings.TrimSpace(res.Output); out != "" {
		lines := strings.Split(out, "\n")
		if len(lines) > 20 {
			lines = lines[len(lines)-20:]
		}
		for _, l := range lines {
			r.t.Logf("  %s", l)
		}
	}
	if err != nil {
		if hctx.Err() != nil && ctx.Err() == nil {
			r.t.Logf("%s: its %s hook took longer than %s", label, which, timeout)
		} else {
			r.t.Logf("%s: its %s hook couldn't run: %s", label, which, dockerProblemText(err))
		}
		return 1, true
	}
	return res.ExitCode, true
}

// restartLinked restarts containers that depend on the updated ones.
func (r *autoRun) restartLinked(ctx context.Context, s sqlc.Server, done []autoDone) {
	id := s.ID.String()
	var cs []docker.ContainerSummary
	if err := r.h.withDocker(ctx, id, func(e *dockerEngine) error {
		var err error
		cs, err = e.client.Containers(ctx)
		return err
	}); err != nil {
		return
	}
	names := map[string]bool{}
	for _, d := range done {
		names[d.name] = true
	}
	for _, c := range cs {
		name := containerName(c.Names)
		if names[name] || c.State != "running" || strings.Contains(name, "-morche-old-") {
			continue
		}
		var on []string
		if v, ok := autoLabel(c, "depends-on"); ok {
			for dep := range strings.SplitSeq(v, ",") {
				if dep = strings.TrimPrefix(strings.TrimSpace(dep), "/"); names[dep] {
					on = append(on, dep)
				}
			}
		}
		netTo := ""
		if m, ok := strings.CutPrefix(c.HostConfig.NetworkMode, "container:"); ok {
			for _, d := range done {
				if m == d.name || strings.HasPrefix(d.id, m) {
					netTo = d.name
				}
			}
			// The old container's id is gone: Docker shows the id, which no
			// longer exists, so any container: mode pointing nowhere counts.
			if netTo == "" && !slices.ContainsFunc(cs, func(x docker.ContainerSummary) bool {
				return strings.HasPrefix(x.ID, m) || containerName(x.Names) == m
			}) {
				netTo = "an updated container"
			}
		}
		if len(on) == 0 && netTo == "" {
			continue
		}
		label := r.prefix(s) + name
		var err error
		if netTo != "" {
			r.t.Logf("%s: recreating it, it shares the network of %s", label, netTo)
			err = r.h.recreateAuto(ctx, r.t, id, c, int(r.p.StopTimeout), true)
		} else {
			r.t.Logf("%s: restarting it, it depends on %s", label, strings.Join(on, ", "))
			err = r.h.withDocker(ctx, id, func(e *dockerEngine) error {
				return e.client.Act(ctx, c.ID, "restart", int(r.p.StopTimeout), "")
			})
		}
		if err != nil {
			r.t.Logf("%s: couldn't restart: %s", label, dockerProblemText(err))
			r.problems = append(r.problems, "couldn't restart "+label)
		}
	}
}

// ---- Telling people ----

func (h *serverHandler) notifyAutoUpdate(p sqlc.DockerAutoUpdate, r *autoRun, fail string) {
	if p.Notify == "never" || len(p.Channels) == 0 {
		return
	}
	bad := fail != "" || r != nil && (len(r.failed) > 0 || len(r.rolled) > 0 || len(r.problems) > 0)
	changed := r != nil && (len(r.updated) > 0 || len(r.available) > 0)
	switch p.Notify {
	case "failures":
		if !bad {
			return
		}
	case "changes":
		if !bad && !changed {
			return
		}
	}
	channels := make([]string, len(p.Channels))
	for i, c := range p.Channels {
		channels[i] = c.String()
	}
	msg := notify.Message{Event: "docker_auto_update", Data: map[string]any{"auto_update_id": p.ID.String()}}
	switch {
	case fail != "":
		msg.Title = "Auto-update " + p.Name + " couldn't run"
		msg.Text = fail
	case bad:
		msg.Title = "Auto-update " + p.Name + " ran into problems"
		msg.Text = r.summary()
	case len(r.updated) > 0:
		msg.Title = fmt.Sprintf("Auto-update %s updated %s", p.Name, plural(len(r.updated), "container"))
		msg.Text = r.summary()
	case len(r.available) > 0:
		msg.Title = fmt.Sprintf("New images for %s (%s)", plural(len(r.available), "container"), p.Name)
		msg.Text = r.summary()
	default:
		msg.Title = "Auto-update " + p.Name + ": nothing to do"
		msg.Text = r.summary()
	}
	if r != nil {
		msg.Fields = []notify.Field{
			{Name: "Updated", Value: strconv.Itoa(len(r.updated))},
			{Name: "Rolled back", Value: strconv.Itoa(len(r.rolled))},
			{Name: "Failed", Value: strconv.Itoa(len(r.failed))},
		}
		if len(r.available) > 0 {
			msg.Fields = append(msg.Fields, notify.Field{Name: "Waiting", Value: strconv.Itoa(len(r.available))})
		}
	}
	if h.alerts != nil && h.alerts.up != nil && h.alerts.up.panelURL != "" {
		msg.URL = h.alerts.up.panelURL + "/containers/auto-update/" + p.ID.String()
	}
	h.dockerNotify(sqlc.Server{WorkspaceID: p.WorkspaceID}, channels, msg)
}

// ---- Schedule ----

// startDockerAutoUpdateLoop starts policies when their schedule comes round.
func startDockerAutoUpdateLoop(h *serverHandler) {
	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		lastPrune := time.Time{}
		for range tick.C {
			ctx := cmdlog.Background(context.Background(), "Docker")
			if fix, err := h.q.EnabledDockerAutoUpdatesWithoutNext(ctx); err == nil {
				for _, p := range fix {
					if p.Cron != "" {
						_ = h.q.SetDockerAutoUpdateNext(ctx, sqlc.SetDockerAutoUpdateNextParams{ID: p.ID, NextRunAt: nextRun(p.Cron, p.Timezone, time.Now())})
					}
				}
			}
			due, err := h.q.DueDockerAutoUpdates(ctx)
			if err != nil {
				slog.Warn("docker auto-update: list due", "error", err)
				continue
			}
			for _, p := range due {
				var next *time.Time
				if p.Cron != "" {
					next = nextRun(p.Cron, p.Timezone, time.Now())
				}
				n, err := h.q.ClaimDockerAutoUpdate(ctx, sqlc.ClaimDockerAutoUpdateParams{ID: p.ID, Due: p.NextRunAt, NextRunAt: next})
				if err != nil || n == 0 {
					continue
				}
				if _, busy := autoUpdateBusy.Load(p.ID); busy {
					continue
				}
				if _, err := h.submitAutoUpdate(ctx, p, dockerAutoUpdateParams{Trigger: "schedule"}, p.UpdatedBy); err != nil {
					slog.Warn("docker auto-update: start a run", "policy", p.ID, "error", err)
				}
			}
			if time.Since(lastPrune) > 24*time.Hour {
				lastPrune = time.Now()
				if !logOwned("docker-auto-update-events") {
					_ = h.q.PruneDockerAutoUpdateEvents(ctx)
				}
			}
		}
	}()
}
