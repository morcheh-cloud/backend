package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/docker"
	"github.com/morche/backend/internal/sshpool"
)

// ---- Settings ----

const (
	defaultProjectsDir  = "/opt/morche/projects"
	defaultScannerImage = "aquasec/trivy:latest"
	defaultEventsHours  = 24
	defaultStatsDays    = 30
	defaultUpdateHours  = 24
	defaultVersionsKeep = 50
)

type DockerSettings struct {
	ProjectsDir       string `json:"projects_dir" doc:"Folder on each server where new compose projects are created, one folder per project"`
	UpdateCheck       bool   `json:"update_check" doc:"Check once a day whether running images have a newer version"`
	ScannerImage      string `json:"scanner_image" doc:"Image used to scan for vulnerabilities when Trivy isn't installed on the server"`
	EventsHours       int    `json:"events_hours" minimum:"1" maximum:"720" doc:"How far back the event log reads by default"`
	StatsDays         int    `json:"stats_days" minimum:"0" maximum:"90" doc:"Days projects' CPU, memory and network are kept (a point every 5 minutes); 0 = not recorded"`
	UpdateCheckHours  int    `json:"update_check_hours" enum:"6,12,24,72,168" doc:"Hours between automatic image update checks"`
	ScanIgnoreUnfixed bool   `json:"scan_ignore_unfixed" doc:"Vulnerability scans leave out findings that have no fixed version yet"`
	RemoveOrphans     bool   `json:"remove_orphans" doc:"Deploying a project removes containers of services no longer in its compose file"`
	VersionsKeep      int    `json:"versions_keep" minimum:"5" maximum:"200" doc:"Compose file versions kept per project"`

	DefaultRestart  string  `json:"default_restart" enum:",no,always,unless-stopped,on-failure" doc:"Restart policy added to services of a new project that don't set one; empty = add none"`
	DefaultMemoryMB int     `json:"default_memory_mb" minimum:"0" maximum:"1048576" doc:"Memory limit (MiB) added to services of a new project that don't set one; 0 = none"`
	DefaultCPUs     float64 `json:"default_cpus" minimum:"0" maximum:"512" doc:"CPU limit (cores) added to services of a new project that don't set one; 0 = none"`
	DefaultLogMaxMB int     `json:"default_log_max_mb" minimum:"0" maximum:"10240" doc:"Log rotation added to services of a new project that don't set logging: size of one file (MiB); 0 = none"`
	DefaultLogFiles int     `json:"default_log_files" minimum:"0" maximum:"100" doc:"Log files kept by that rotation"`

	PruneAuto       bool   `json:"prune_auto" doc:"Clean up unused things on every server by itself"`
	PruneHours      int    `json:"prune_hours" enum:"24,72,168,720" doc:"Hours between automatic clean-ups"`
	PruneImages     string `json:"prune_images" enum:"none,dangling,all" doc:"Images it removes: none, untagged only, or every image no container uses"`
	PruneContainers bool   `json:"prune_containers" doc:"Also remove stopped containers"`
	PruneNetworks   bool   `json:"prune_networks" doc:"Also remove networks no container uses"`
	PruneBuildCache bool   `json:"prune_build_cache" doc:"Also remove the build cache"`
	PruneOlderHours int    `json:"prune_older_hours" enum:"0,24,72,168,720" doc:"Only remove things older than this many hours; 0 = any age"`

	NotifyUpdates  bool     `json:"notify_updates" doc:"Send a message when a running image gets a new version"`
	NotifyVulns    string   `json:"notify_vulns" enum:"off,critical,high" doc:"Send a message when a scan finds more vulnerabilities at this severity (high = high and critical)"`
	NotifyChannels []string `json:"notify_channels" doc:"Notification channels those messages go to"`

	BackupStorageID string `json:"backup_storage_id" doc:"Storage volume backups go to unless another is picked; empty = ask"`
	BackupFolder    string `json:"backup_folder" doc:"Folder on that storage; empty = /backups/docker-volumes"`
	BackupStop      bool   `json:"backup_stop" doc:"Stop the containers using a volume while it is backed up"`
	BackupKeep      int    `json:"backup_keep" minimum:"0" maximum:"1000" doc:"Copies of a volume kept from backups made by hand; older ones are removed; 0 = keep all"`

	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

type DockerSettingsBody struct {
	ProjectsDir       string `json:"projects_dir" minLength:"2" maxLength:"500"`
	UpdateCheck       bool   `json:"update_check"`
	ScannerImage      string `json:"scanner_image" minLength:"1" maxLength:"300"`
	EventsHours       int    `json:"events_hours" minimum:"1" maximum:"720"`
	StatsDays         int    `json:"stats_days" minimum:"0" maximum:"90"`
	UpdateCheckHours  int    `json:"update_check_hours" enum:"6,12,24,72,168"`
	ScanIgnoreUnfixed bool   `json:"scan_ignore_unfixed"`
	RemoveOrphans     bool   `json:"remove_orphans"`
	VersionsKeep      int    `json:"versions_keep" minimum:"5" maximum:"200"`

	DefaultRestart  string  `json:"default_restart,omitempty" required:"false" enum:",no,always,unless-stopped,on-failure"`
	DefaultMemoryMB int     `json:"default_memory_mb,omitempty" required:"false" minimum:"0" maximum:"1048576"`
	DefaultCPUs     float64 `json:"default_cpus,omitempty" required:"false" minimum:"0" maximum:"512"`
	DefaultLogMaxMB int     `json:"default_log_max_mb,omitempty" required:"false" minimum:"0" maximum:"10240"`
	DefaultLogFiles int     `json:"default_log_files,omitempty" required:"false" minimum:"0" maximum:"100"`

	PruneAuto       bool   `json:"prune_auto,omitempty" required:"false"`
	PruneHours      int    `json:"prune_hours,omitempty" required:"false" enum:"24,72,168,720"`
	PruneImages     string `json:"prune_images,omitempty" required:"false" enum:"none,dangling,all"`
	PruneContainers bool   `json:"prune_containers,omitempty" required:"false"`
	PruneNetworks   bool   `json:"prune_networks,omitempty" required:"false"`
	PruneBuildCache bool   `json:"prune_build_cache,omitempty" required:"false"`
	PruneOlderHours int    `json:"prune_older_hours,omitempty" required:"false" enum:"0,24,72,168,720"`

	NotifyUpdates  bool     `json:"notify_updates,omitempty" required:"false"`
	NotifyVulns    string   `json:"notify_vulns,omitempty" required:"false" enum:"off,critical,high"`
	NotifyChannels []string `json:"notify_channels,omitempty" required:"false" maxItems:"20"`

	BackupStorageID string `json:"backup_storage_id,omitempty" required:"false"`
	BackupFolder    string `json:"backup_folder,omitempty" required:"false" maxLength:"500"`
	BackupStop      bool   `json:"backup_stop,omitempty" required:"false"`
	BackupKeep      int    `json:"backup_keep,omitempty" required:"false" minimum:"0" maximum:"1000"`
}

// DockerSettingsOverrides are the settings one server sets for itself; a
// missing key follows the workspace. The keys are DockerSettings' own.
type DockerSettingsOverrides struct {
	ProjectsDir       *string   `json:"projects_dir,omitempty" required:"false" minLength:"2" maxLength:"500"`
	UpdateCheck       *bool     `json:"update_check,omitempty" required:"false"`
	ScannerImage      *string   `json:"scanner_image,omitempty" required:"false" minLength:"1" maxLength:"300"`
	EventsHours       *int      `json:"events_hours,omitempty" required:"false" minimum:"1" maximum:"720"`
	StatsDays         *int      `json:"stats_days,omitempty" required:"false" minimum:"0" maximum:"90"`
	UpdateCheckHours  *int      `json:"update_check_hours,omitempty" required:"false" enum:"6,12,24,72,168"`
	ScanIgnoreUnfixed *bool     `json:"scan_ignore_unfixed,omitempty" required:"false"`
	RemoveOrphans     *bool     `json:"remove_orphans,omitempty" required:"false"`
	VersionsKeep      *int      `json:"versions_keep,omitempty" required:"false" minimum:"5" maximum:"200"`
	DefaultRestart    *string   `json:"default_restart,omitempty" required:"false" enum:",no,always,unless-stopped,on-failure"`
	DefaultMemoryMB   *int      `json:"default_memory_mb,omitempty" required:"false" minimum:"0" maximum:"1048576"`
	DefaultCPUs       *float64  `json:"default_cpus,omitempty" required:"false" minimum:"0" maximum:"512"`
	DefaultLogMaxMB   *int      `json:"default_log_max_mb,omitempty" required:"false" minimum:"0" maximum:"10240"`
	DefaultLogFiles   *int      `json:"default_log_files,omitempty" required:"false" minimum:"0" maximum:"100"`
	PruneAuto         *bool     `json:"prune_auto,omitempty" required:"false"`
	PruneHours        *int      `json:"prune_hours,omitempty" required:"false" enum:"24,72,168,720"`
	PruneImages       *string   `json:"prune_images,omitempty" required:"false" enum:"none,dangling,all"`
	PruneContainers   *bool     `json:"prune_containers,omitempty" required:"false"`
	PruneNetworks     *bool     `json:"prune_networks,omitempty" required:"false"`
	PruneBuildCache   *bool     `json:"prune_build_cache,omitempty" required:"false"`
	PruneOlderHours   *int      `json:"prune_older_hours,omitempty" required:"false" enum:"0,24,72,168,720"`
	NotifyUpdates     *bool     `json:"notify_updates,omitempty" required:"false"`
	NotifyVulns       *string   `json:"notify_vulns,omitempty" required:"false" enum:"off,critical,high"`
	NotifyChannels    *[]string `json:"notify_channels,omitempty" required:"false" maxItems:"20"`
	BackupStorageID   *string   `json:"backup_storage_id,omitempty" required:"false"`
	BackupFolder      *string   `json:"backup_folder,omitempty" required:"false" maxLength:"500"`
	BackupStop        *bool     `json:"backup_stop,omitempty" required:"false"`
	BackupKeep        *int      `json:"backup_keep,omitempty" required:"false" minimum:"0" maximum:"1000"`
}

// DockerServerSettings is one server's own settings and last clean-up.
type DockerServerSettings struct {
	ServerID   string                  `json:"server_id" format:"uuid"`
	ServerName string                  `json:"server_name"`
	Overrides  DockerSettingsOverrides `json:"overrides"`
	UpdatedAt  *time.Time              `json:"updated_at,omitempty"`
	Prune      *DockerAutoPrune        `json:"prune,omitempty" doc:"The last automatic clean-up"`
}

type DockerAutoPrune struct {
	At      time.Time `json:"at"`
	Space   int64     `json:"space" doc:"Bytes freed"`
	Removed int       `json:"removed" doc:"Things removed"`
	Error   string    `json:"error,omitempty"`
}

// DockerEffectiveSettings is what applies on one server.
type DockerEffectiveSettings struct {
	DockerSettings
	Overridden []string `json:"overridden" doc:"Keys this server sets for itself"`
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

func toDockerSettings(s sqlc.DockerSetting) DockerSettings {
	storage := ""
	if s.BackupStorageID != nil {
		storage = s.BackupStorageID.String()
	}
	return DockerSettings{ProjectsDir: s.ProjectsDir, UpdateCheck: s.UpdateCheck, ScannerImage: s.ScannerImage, EventsHours: int(s.EventsHours), StatsDays: int(s.StatsDays),
		UpdateCheckHours: int(s.UpdateCheckHours), ScanIgnoreUnfixed: s.ScanIgnoreUnfixed, RemoveOrphans: s.RemoveOrphans, VersionsKeep: int(s.VersionsKeep),
		DefaultRestart: s.DefaultRestart, DefaultMemoryMB: int(s.DefaultMemoryMb), DefaultCPUs: s.DefaultCpus, DefaultLogMaxMB: int(s.DefaultLogMaxMb), DefaultLogFiles: int(s.DefaultLogFiles),
		PruneAuto: s.PruneAuto, PruneHours: int(s.PruneHours), PruneImages: s.PruneImages, PruneContainers: s.PruneContainers, PruneNetworks: s.PruneNetworks,
		PruneBuildCache: s.PruneBuildCache, PruneOlderHours: int(s.PruneOlderHours),
		NotifyUpdates: s.NotifyUpdates, NotifyVulns: s.NotifyVulns, NotifyChannels: uuidStrings(s.NotifyChannels),
		BackupStorageID: storage, BackupFolder: s.BackupFolder, BackupStop: s.BackupStop, BackupKeep: int(s.BackupKeep),
		UpdatedAt: s.UpdatedAt}
}

func defaultDockerSettings() DockerSettings {
	return DockerSettings{ProjectsDir: defaultProjectsDir, UpdateCheck: true, ScannerImage: defaultScannerImage, EventsHours: defaultEventsHours, StatsDays: defaultStatsDays,
		UpdateCheckHours: defaultUpdateHours, RemoveOrphans: true, VersionsKeep: defaultVersionsKeep,
		PruneHours: 168, PruneImages: "dangling", PruneNetworks: true, PruneBuildCache: true, PruneOlderHours: 24,
		NotifyVulns: "off", NotifyChannels: []string{}}
}

// dockerSettings returns the workspace's settings, or the defaults.
func (h *serverHandler) dockerSettings(ctx context.Context, ws uuid.UUID) (DockerSettings, error) {
	s, err := h.q.GetDockerSettings(ctx, ws)
	if isNotFound(err) {
		return defaultDockerSettings(), nil
	}
	if err != nil {
		return DockerSettings{}, internalError(err)
	}
	return toDockerSettings(s), nil
}

// serverDockerSettings is what applies on a server: the workspace's settings
// with the server's own laid over them.
func (h *serverHandler) serverDockerSettings(ctx context.Context, s sqlc.Server) (DockerSettings, error) {
	set, _, err := h.effectiveDockerSettings(ctx, s)
	return set, err
}

func (h *serverHandler) effectiveDockerSettings(ctx context.Context, s sqlc.Server) (DockerSettings, []string, error) {
	set, err := h.dockerSettings(ctx, s.WorkspaceID)
	if err != nil {
		return set, nil, err
	}
	o, err := h.q.GetDockerServerSettings(ctx, s.ID)
	if isNotFound(err) {
		return set, []string{}, nil
	}
	if err != nil {
		return set, nil, internalError(err)
	}
	return overlayDockerSettings(set, o.Overrides)
}

// overlayDockerSettings lays a server's stored overrides over set and returns
// the keys it changed.
func overlayDockerSettings(set DockerSettings, raw []byte) (DockerSettings, []string, error) {
	keys := map[string]json.RawMessage{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &keys); err != nil {
			return set, nil, internalError(err)
		}
	}
	at := set.UpdatedAt
	if err := json.Unmarshal(raw, &set); err != nil && len(raw) > 0 {
		return set, nil, internalError(err)
	}
	set.UpdatedAt = at
	out := make([]string, 0, len(keys))
	for k := range keys {
		out = append(out, k)
	}
	slices.Sort(out)
	return set, out, nil
}

func dockerBodyOf(s DockerSettings) DockerSettingsBody {
	return DockerSettingsBody{ProjectsDir: s.ProjectsDir, UpdateCheck: s.UpdateCheck, ScannerImage: s.ScannerImage, EventsHours: s.EventsHours, StatsDays: s.StatsDays,
		UpdateCheckHours: s.UpdateCheckHours, ScanIgnoreUnfixed: s.ScanIgnoreUnfixed, RemoveOrphans: s.RemoveOrphans, VersionsKeep: s.VersionsKeep,
		DefaultRestart: s.DefaultRestart, DefaultMemoryMB: s.DefaultMemoryMB, DefaultCPUs: s.DefaultCPUs, DefaultLogMaxMB: s.DefaultLogMaxMB, DefaultLogFiles: s.DefaultLogFiles,
		PruneAuto: s.PruneAuto, PruneHours: s.PruneHours, PruneImages: s.PruneImages, PruneContainers: s.PruneContainers, PruneNetworks: s.PruneNetworks,
		PruneBuildCache: s.PruneBuildCache, PruneOlderHours: s.PruneOlderHours,
		NotifyUpdates: s.NotifyUpdates, NotifyVulns: s.NotifyVulns, NotifyChannels: s.NotifyChannels,
		BackupStorageID: s.BackupStorageID, BackupFolder: s.BackupFolder, BackupStop: s.BackupStop, BackupKeep: s.BackupKeep}
}

// checkDockerSettings tidies b and refuses what can't work: a relative
// folder, a channel or storage of another workspace.
func (h *serverHandler) checkDockerSettings(ctx context.Context, ws uuid.UUID, b *DockerSettingsBody) (sqlc.UpsertDockerSettingsParams, error) {
	p := sqlc.UpsertDockerSettingsParams{WorkspaceID: ws}
	dir := path.Clean(strings.TrimSpace(b.ProjectsDir))
	if !strings.HasPrefix(dir, "/") || dir == "/" || strings.ContainsAny(dir, "\n\r\x00") {
		return p, fieldError("body.projects_dir", "Use a full folder path like /opt/projects", dir)
	}
	b.ProjectsDir = dir
	img := strings.TrimSpace(b.ScannerImage)
	if img == "" || strings.ContainsAny(img, " \t\n") {
		return p, fieldError("body.scanner_image", "An image name has no spaces", img)
	}
	b.ScannerImage = img
	if b.PruneHours == 0 {
		b.PruneHours = 168
	}
	if b.PruneImages == "" {
		b.PruneImages = "dangling"
	}
	if b.NotifyVulns == "" {
		b.NotifyVulns = "off"
	}
	if (b.DefaultLogMaxMB > 0) != (b.DefaultLogFiles > 0) {
		if b.DefaultLogMaxMB > 0 {
			b.DefaultLogFiles = 3
		} else {
			b.DefaultLogMaxMB = 0
			b.DefaultLogFiles = 0
		}
	}
	channels := []uuid.UUID{}
	for i, raw := range b.NotifyChannels {
		id, err := uuid.Parse(raw)
		if err != nil {
			return p, fieldError(fmt.Sprintf("body.notify_channels[%d]", i), "No such channel", raw)
		}
		cw, err := h.q.GetNotificationChannelWorkspace(ctx, id)
		if isNotFound(err) || (err == nil && cw != ws) {
			return p, fieldError(fmt.Sprintf("body.notify_channels[%d]", i), "That channel isn't in this workspace", raw)
		}
		if err != nil {
			return p, internalError(err)
		}
		if !slices.Contains(channels, id) {
			channels = append(channels, id)
		}
	}
	b.NotifyChannels = uuidStrings(channels)
	if (b.NotifyUpdates || b.NotifyVulns != "off") && len(channels) == 0 {
		return p, fieldError("body.notify_channels", "Pick a channel for these messages", nil)
	}
	var storage *uuid.UUID
	if raw := strings.TrimSpace(b.BackupStorageID); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return p, fieldError("body.backup_storage_id", "No such storage", raw)
		}
		st, err := h.q.GetStorage(ctx, id)
		if isNotFound(err) || (err == nil && st.WorkspaceID != ws) {
			return p, fieldError("body.backup_storage_id", "That storage isn't in this workspace", raw)
		}
		if err != nil {
			return p, internalError(err)
		}
		if st.ReadOnly {
			return p, fieldError("body.backup_storage_id", "That storage is read-only", raw)
		}
		storage = &id
	}
	b.BackupStorageID = ""
	if storage != nil {
		b.BackupStorageID = storage.String()
	}
	folder := strings.TrimSpace(b.BackupFolder)
	if folder != "" {
		if strings.ContainsAny(folder, "\n\r\x00") {
			return p, fieldError("body.backup_folder", "Use a plain folder path", folder)
		}
		folder = path.Clean("/" + folder)
		if folder == "/" {
			folder = ""
		}
	}
	b.BackupFolder = folder
	p = sqlc.UpsertDockerSettingsParams{
		WorkspaceID: ws, ProjectsDir: b.ProjectsDir, UpdateCheck: b.UpdateCheck, ScannerImage: b.ScannerImage, EventsHours: int32(b.EventsHours),
		StatsDays: int32(b.StatsDays), UpdateCheckHours: int32(b.UpdateCheckHours), ScanIgnoreUnfixed: b.ScanIgnoreUnfixed,
		RemoveOrphans: b.RemoveOrphans, VersionsKeep: int32(b.VersionsKeep),
		DefaultRestart: b.DefaultRestart, DefaultMemoryMb: int32(b.DefaultMemoryMB), DefaultCpus: b.DefaultCPUs,
		DefaultLogMaxMb: int32(b.DefaultLogMaxMB), DefaultLogFiles: int32(b.DefaultLogFiles),
		PruneAuto: b.PruneAuto, PruneHours: int32(b.PruneHours), PruneImages: b.PruneImages, PruneContainers: b.PruneContainers,
		PruneNetworks: b.PruneNetworks, PruneBuildCache: b.PruneBuildCache, PruneOlderHours: int32(b.PruneOlderHours),
		NotifyUpdates: b.NotifyUpdates, NotifyVulns: b.NotifyVulns, NotifyChannels: channels,
		BackupStorageID: storage, BackupFolder: b.BackupFolder, BackupStop: b.BackupStop, BackupKeep: int32(b.BackupKeep),
	}
	return p, nil
}

// checkDockerOverrides checks a server's own settings by laying them over the
// workspace's and checking the whole; only the keys it sets are kept, tidied.
func (h *serverHandler) checkDockerOverrides(ctx context.Context, ws uuid.UUID, o DockerSettingsOverrides) ([]byte, error) {
	raw, err := json.Marshal(o)
	if err != nil {
		return nil, internalError(err)
	}
	keys := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, internalError(err)
	}
	base, err := h.dockerSettings(ctx, ws)
	if err != nil {
		return nil, err
	}
	merged, _, err := overlayDockerSettings(base, raw)
	if err != nil {
		return nil, err
	}
	b := dockerBodyOf(merged)
	if _, err := h.checkDockerSettings(ctx, ws, &b); err != nil {
		return nil, err
	}
	tidy, err := json.Marshal(DockerSettings{ProjectsDir: b.ProjectsDir, UpdateCheck: b.UpdateCheck, ScannerImage: b.ScannerImage, EventsHours: b.EventsHours, StatsDays: b.StatsDays,
		UpdateCheckHours: b.UpdateCheckHours, ScanIgnoreUnfixed: b.ScanIgnoreUnfixed, RemoveOrphans: b.RemoveOrphans, VersionsKeep: b.VersionsKeep,
		DefaultRestart: b.DefaultRestart, DefaultMemoryMB: b.DefaultMemoryMB, DefaultCPUs: b.DefaultCPUs, DefaultLogMaxMB: b.DefaultLogMaxMB, DefaultLogFiles: b.DefaultLogFiles,
		PruneAuto: b.PruneAuto, PruneHours: b.PruneHours, PruneImages: b.PruneImages, PruneContainers: b.PruneContainers, PruneNetworks: b.PruneNetworks,
		PruneBuildCache: b.PruneBuildCache, PruneOlderHours: b.PruneOlderHours,
		NotifyUpdates: b.NotifyUpdates, NotifyVulns: b.NotifyVulns, NotifyChannels: b.NotifyChannels,
		BackupStorageID: b.BackupStorageID, BackupFolder: b.BackupFolder, BackupStop: b.BackupStop, BackupKeep: b.BackupKeep})
	if err != nil {
		return nil, internalError(err)
	}
	all := map[string]json.RawMessage{}
	if err := json.Unmarshal(tidy, &all); err != nil {
		return nil, internalError(err)
	}
	// A log size and its file count are tidied as a pair, so one sent alone
	// keeps the other's tidied value too.
	pairs := map[string]string{"default_log_max_mb": "default_log_files", "default_log_files": "default_log_max_mb"}
	for k := range keys {
		if p, ok := pairs[k]; ok {
			if _, sent := keys[p]; !sent && string(all[p]) != "0" {
				keys[p] = nil
			}
		}
	}
	out := map[string]json.RawMessage{}
	for k := range keys {
		if v, ok := all[k]; ok {
			out[k] = v
		}
	}
	return json.Marshal(out)
}

func toDockerServerSettings(r sqlc.ListDockerServerSettingsRow) DockerServerSettings {
	out := DockerServerSettings{ServerID: r.ServerID.String(), ServerName: r.ServerName, UpdatedAt: r.UpdatedAt}
	if len(r.Overrides) > 0 {
		_ = json.Unmarshal(r.Overrides, &out.Overrides)
	}
	if r.PrunedAt != nil {
		out.Prune = &DockerAutoPrune{At: *r.PrunedAt, Space: r.PrunedSpace, Removed: int(r.PrunedRemoved), Error: r.PruneError}
	}
	return out
}

// ---- Registries ----

type DockerRegistry struct {
	ID          string                `json:"id" format:"uuid"`
	Name        string                `json:"name"`
	Address     string                `json:"address" doc:"Registry host, like docker.io, ghcr.io or registry.example.com:5000"`
	Username    string                `json:"username"`
	HasPassword bool                  `json:"has_password" doc:"A password or token is saved (it never comes back)"`
	Servers     string                `json:"servers" enum:"all,chosen" doc:"Which servers it's for: every server of the workspace, or server_ids"`
	ServerIDs   []string              `json:"server_ids" doc:"The chosen servers (servers = chosen)"`
	SignIn      bool                  `json:"sign_in_on_servers" doc:"Also sign each server's own Docker in (docker login), not only Morche's pulls"`
	Logins      []DockerRegistryLogin `json:"logins" doc:"Where Morche signed Docker in (or tried to), last time"`
	CreatedAt   time.Time             `json:"created_at"`
	UpdatedAt   time.Time             `json:"updated_at"`
}

type DockerRegistryLogin struct {
	ServerID string    `json:"server_id" format:"uuid"`
	OK       bool      `json:"ok"`
	Message  string    `json:"message,omitempty"`
	AsUser   string    `json:"as_user,omitempty" doc:"Whose Docker config holds it: root, or the login user"`
	At       time.Time `json:"at"`
}

type DockerRegistryBody struct {
	Name      string   `json:"name" minLength:"1" maxLength:"100"`
	Address   string   `json:"address" minLength:"1" maxLength:"300"`
	Username  string   `json:"username" maxLength:"200"`
	Password  string   `json:"password,omitempty" required:"false" maxLength:"4000" doc:"Password or access token. Blank keeps the saved one when editing"`
	Servers   string   `json:"servers,omitempty" required:"false" enum:"all,chosen" doc:"Default all"`
	ServerIDs []string `json:"server_ids,omitempty" required:"false" maxItems:"1000"`
	SignIn    bool     `json:"sign_in_on_servers,omitempty" required:"false" doc:"Also docker login on the servers (start it with the sign-in action)"`
}

type DockerRegistryTestBody struct {
	ServerID   string `json:"server_id" format:"uuid" doc:"Server whose engine tries the login"`
	Address    string `json:"address" minLength:"1" maxLength:"300"`
	Username   string `json:"username" maxLength:"200"`
	Password   string `json:"password,omitempty" required:"false" maxLength:"4000"`
	RegistryID string `json:"registry_id,omitempty" required:"false" format:"uuid" doc:"Saved registry whose password to use when password is blank"`
}

type DockerRegistryTest struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func toDockerRegistry(r sqlc.DockerRegistry, logins []sqlc.DockerRegistryLogin) DockerRegistry {
	out := DockerRegistry{
		ID: r.ID.String(), Name: r.Name, Address: r.Address, Username: r.Username, HasPassword: len(r.PasswordEnc) > 0,
		Servers: r.Servers, ServerIDs: make([]string, len(r.ServerIds)), SignIn: r.SignInOnServers,
		Logins: []DockerRegistryLogin{}, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
	for i, id := range r.ServerIds {
		out.ServerIDs[i] = id.String()
	}
	for _, l := range logins {
		if l.RegistryID == r.ID {
			out.Logins = append(out.Logins, DockerRegistryLogin{ServerID: l.ServerID.String(), OK: l.Ok, Message: l.Message, AsUser: l.AsUser, At: l.At})
		}
	}
	return out
}

// registryCovers says whether a registry login is for a server.
func registryCovers(r sqlc.DockerRegistry, server uuid.UUID) bool {
	return r.Servers != "chosen" || slices.Contains(r.ServerIds, server)
}

// registryServers checks the body's servers: chosen ones must be in the
// workspace.
func (h *serverHandler) registryServers(ctx context.Context, ws uuid.UUID, b DockerRegistryBody) (string, []uuid.UUID, error) {
	mode := b.Servers
	if mode == "" {
		mode = "all"
	}
	if mode == "all" {
		return mode, []uuid.UUID{}, nil
	}
	rows, err := h.q.ListWorkspaceServers(ctx, ws)
	if err != nil {
		return "", nil, internalError(err)
	}
	ids := []uuid.UUID{}
	for i, raw := range b.ServerIDs {
		id, err := uuid.Parse(raw)
		if err != nil || !slices.ContainsFunc(rows, func(r sqlc.ListWorkspaceServersRow) bool { return r.ID == id }) {
			return "", nil, fieldError(fmt.Sprintf("body.server_ids[%d]", i), "That server isn't in this workspace", raw)
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return "", nil, fieldError("body.server_ids", "Pick at least one server", b.ServerIDs)
	}
	return mode, ids, nil
}

// registryOut is a saved registry with where it's signed in.
func (h *serverHandler) registryOut(ctx context.Context, r sqlc.DockerRegistry) DockerRegistry {
	logins, _ := h.q.ListDockerRegistryLogins(ctx, r.WorkspaceID)
	return toDockerRegistry(r, logins)
}

// registryHost tidies what someone typed into a registry host:
// "https://index.docker.io/v1/" → "docker.io".
func registryHost(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	switch s {
	case "", "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com", "hub.docker.com":
		return "docker.io"
	}
	return s
}

// imageRegistry is the registry an image reference is pulled from.
func imageRegistry(ref string) string {
	i := strings.IndexByte(ref, '/')
	if i < 0 {
		return "docker.io"
	}
	first := ref[:i]
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return registryHost(first)
	}
	return "docker.io"
}

// registryServer is the address the engine's auth wants for a host.
func registryServer(host string) string {
	if host == "docker.io" {
		return "https://index.docker.io/v1/"
	}
	return host
}

// registryAuthFor returns the X-Registry-Auth value for pulling image on a
// server of workspace ws, or "" when the workspace keeps no login for its
// registry that covers the server.
func (h *serverHandler) registryAuthFor(ctx context.Context, ws, server uuid.UUID, image string) string {
	host := imageRegistry(image)
	rows, err := h.q.ListDockerRegistries(ctx, ws)
	if err != nil {
		return ""
	}
	for _, r := range rows {
		if r.Address != host || !registryCovers(r, server) {
			continue
		}
		pass := ""
		if len(r.PasswordEnc) > 0 {
			b, err := h.box.Open(r.PasswordEnc)
			if err != nil {
				return ""
			}
			pass = string(b)
		}
		return docker.RegistryAuth(registryServer(host), r.Username, pass)
	}
	return ""
}

// serverRegistryAuth is registryAuthFor for the workspace a server is in.
func (h *serverHandler) serverRegistryAuth(ctx context.Context, serverID, image string) string {
	id, err := uuid.Parse(serverID)
	if err != nil {
		return ""
	}
	s, err := h.q.GetServer(ctx, id)
	if err != nil {
		return ""
	}
	return h.registryAuthFor(ctx, s.WorkspaceID, s.ID, image)
}

// ---- Templates ----

type DockerTemplate struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Category    string    `json:"category"`
	Compose     string    `json:"compose"`
	Env         string    `json:"env"`
	Builtin     bool      `json:"builtin" doc:"Comes with Morche; can't be changed (copy it instead)"`
	Logo        string    `json:"logo,omitempty" doc:"Logo file under /apps/, for built-in templates (e.g. nginx or templates/ghost.svg)"`
	Website     string    `json:"website,omitempty" doc:"The app's own site, for built-in templates"`
	Tags        []string  `json:"tags,omitempty" doc:"Search words, for built-in templates"`
	Featured    bool      `json:"featured,omitempty" doc:"A popular built-in template, listed first"`
	CreatedBy   string    `json:"created_by,omitempty"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitzero"`
}

type DockerTemplateBody struct {
	Name        string `json:"name" minLength:"1" maxLength:"100"`
	Description string `json:"description" maxLength:"1000"`
	Category    string `json:"category" maxLength:"50"`
	Compose     string `json:"compose" minLength:"1" maxLength:"200000"`
	Env         string `json:"env" maxLength:"100000"`
}

type DockerTemplates struct {
	Builtin []DockerTemplate `json:"builtin"`
	Custom  []DockerTemplate `json:"custom"`
}

func toDockerTemplate(t sqlc.DockerTemplate) DockerTemplate {
	return DockerTemplate{
		ID: t.ID.String(), Name: t.Name, Description: t.Description, Category: t.Category,
		Compose: t.Compose, Env: t.Env, CreatedBy: t.CreatedByName, UpdatedBy: t.UpdatedByName, UpdatedAt: t.UpdatedAt,
	}
}

// findTemplate returns a built-in template ("builtin:<slug>") or one of the
// workspace's own.
func (h *serverHandler) findTemplate(ctx context.Context, ws uuid.UUID, id string) (DockerTemplate, error) {
	if slug, ok := strings.CutPrefix(id, "builtin:"); ok {
		for _, t := range builtinTemplates {
			if t.ID == "builtin:"+slug {
				return t, nil
			}
		}
		return DockerTemplate{}, huma.Error404NotFound("No such template")
	}
	tid, err := uuid.Parse(id)
	if err != nil {
		return DockerTemplate{}, huma.Error404NotFound("No such template")
	}
	t, err := h.q.GetDockerTemplate(ctx, sqlc.GetDockerTemplateParams{ID: tid, WorkspaceID: ws})
	if isNotFound(err) {
		return DockerTemplate{}, huma.Error404NotFound("No such template")
	}
	if err != nil {
		return DockerTemplate{}, internalError(err)
	}
	return toDockerTemplate(t), nil
}

// ---- Handlers ----

type DockerRegistryPath struct {
	WorkspacePath
	Registry string `path:"registry" format:"uuid"`
}

type DockerServerSettingsPath struct {
	WorkspacePath
	Server string `path:"server" format:"uuid"`
}

type dockerTemplatePath struct {
	WorkspacePath
	Template string `path:"template" format:"uuid"`
}

func registerDockerSettings(api huma.API, h *serverHandler) {
	tags := []string{"Containers"}
	base := "/workspaces/{id}/docker"

	huma.Register(api, huma.Operation{
		OperationID: "get-docker-settings",
		Method:      http.MethodGet,
		Path:        base + "/settings",
		Summary:     "Container settings of a workspace",
		Tags:        tags,
	}, func(ctx context.Context, in *WorkspacePath) (*struct{ Body DockerSettings }, error) {
		s, err := h.dockerSettings(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, err
		}
		return &struct{ Body DockerSettings }{s}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-docker-settings",
		Method:      http.MethodPut,
		Path:        base + "/settings",
		Summary:     "Change a workspace's container settings",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body DockerSettingsBody
	}) (*struct{ Body DockerSettings }, error) {
		b := in.Body
		p, err := h.checkDockerSettings(ctx, uuid.MustParse(in.ID), &b)
		if err != nil {
			return nil, err
		}
		s, err := h.q.UpsertDockerSettings(ctx, p)
		if err != nil {
			return nil, internalError(err)
		}
		return &struct{ Body DockerSettings }{toDockerSettings(s)}, nil
	})

	// serverOf returns the server when it's in the workspace of the path.
	serverOf := func(ctx context.Context, in DockerServerSettingsPath) (sqlc.Server, error) {
		s, err := h.q.GetServer(ctx, uuid.MustParse(in.Server))
		if isNotFound(err) || (err == nil && s.WorkspaceID != uuid.MustParse(in.ID)) {
			return s, huma.Error404NotFound("No such server in this workspace")
		}
		if err != nil {
			return s, internalError(err)
		}
		return s, nil
	}

	huma.Register(api, huma.Operation{
		OperationID: "list-docker-server-settings",
		Method:      http.MethodGet,
		Path:        base + "/settings/servers",
		Summary:     "Servers with their own container settings",
		Description: "Every server of the workspace that sets some container settings for itself, or had an automatic clean-up.",
		Tags:        tags,
	}, func(ctx context.Context, in *WorkspacePath) (*struct {
		Body struct {
			Items []DockerServerSettings `json:"items"`
		}
	}, error) {
		rows, err := h.q.ListDockerServerSettings(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []DockerServerSettings `json:"items"`
			}
		}{}
		out.Body.Items = make([]DockerServerSettings, 0, len(rows))
		for _, r := range rows {
			out.Body.Items = append(out.Body.Items, toDockerServerSettings(r))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-docker-server-settings",
		Method:      http.MethodPut,
		Path:        base + "/settings/servers/{server}",
		Summary:     "Set a server's own container settings",
		Description: "Only the keys sent are the server's own; the rest follow the workspace. Sending none = follow the workspace in everything.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerServerSettingsPath
		Body DockerSettingsOverrides
	}) (*struct{ Body DockerServerSettings }, error) {
		s, err := serverOf(ctx, in.DockerServerSettingsPath)
		if err != nil {
			return nil, err
		}
		raw, err := h.checkDockerOverrides(ctx, s.WorkspaceID, in.Body)
		if err != nil {
			return nil, err
		}
		out := DockerServerSettings{ServerID: s.ID.String(), ServerName: s.Name}
		if string(raw) == "{}" {
			if err := h.q.DeleteDockerServerSettings(ctx, s.ID); err != nil {
				return nil, internalError(err)
			}
			return &struct{ Body DockerServerSettings }{out}, nil
		}
		row, err := h.q.UpsertDockerServerSettings(ctx, sqlc.UpsertDockerServerSettingsParams{ServerID: s.ID, Overrides: raw})
		if err != nil {
			return nil, internalError(err)
		}
		_ = json.Unmarshal(row.Overrides, &out.Overrides)
		out.UpdatedAt = &row.UpdatedAt
		return &struct{ Body DockerServerSettings }{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-docker-server-settings",
		Method:        http.MethodDelete,
		Path:          base + "/settings/servers/{server}",
		Summary:       "A server follows the workspace's container settings again",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *DockerServerSettingsPath) (*struct{}, error) {
		s, err := serverOf(ctx, *in)
		if err != nil {
			return nil, err
		}
		if err := h.q.DeleteDockerServerSettings(ctx, s.ID); err != nil {
			return nil, internalError(err)
		}
		return &struct{}{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-server-docker-settings",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/docker/settings",
		Summary:     "Container settings that apply on a server",
		Description: "The workspace's settings with the server's own laid over them.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body DockerEffectiveSettings }, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		set, keys, err := h.effectiveDockerSettings(ctx, s)
		if err != nil {
			return nil, err
		}
		return &struct{ Body DockerEffectiveSettings }{DockerEffectiveSettings{DockerSettings: set, Overridden: keys}}, nil
	})

	// -- Registries --

	huma.Register(api, huma.Operation{
		OperationID: "list-docker-registries",
		Method:      http.MethodGet,
		Path:        base + "/registries",
		Summary:     "Registry logins of a workspace",
		Description: "Used for every pull on the workspace's servers (pulls, updates, compose projects). Passwords never come back.",
		Tags:        tags,
	}, func(ctx context.Context, in *WorkspacePath) (*struct {
		Body struct {
			Items []DockerRegistry `json:"items"`
		}
	}, error) {
		rows, err := h.q.ListDockerRegistries(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []DockerRegistry `json:"items"`
			}
		}{}
		logins, err := h.q.ListDockerRegistryLogins(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		out.Body.Items = make([]DockerRegistry, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = toDockerRegistry(r, logins)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-docker-registry",
		Method:        http.MethodPost,
		Path:          base + "/registries",
		Summary:       "Save a registry login",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body DockerRegistryBody
	}) (*struct{ Body DockerRegistry }, error) {
		b := in.Body
		host := registryHost(b.Address)
		if strings.ContainsAny(host, " \t") {
			return nil, fieldError("body.address", "A registry address has no spaces", b.Address)
		}
		mode, ids, err := h.registryServers(ctx, uuid.MustParse(in.ID), b)
		if err != nil {
			return nil, err
		}
		r, err := h.q.CreateDockerRegistry(ctx, sqlc.CreateDockerRegistryParams{
			WorkspaceID: uuid.MustParse(in.ID), Name: strings.TrimSpace(b.Name), Address: host,
			Username: strings.TrimSpace(b.Username), PasswordEnc: h.box.Seal(b.Password),
			Servers: mode, ServerIds: ids, SignInOnServers: b.SignIn,
		})
		if isUniqueViolation(err) {
			return nil, fieldError("body.address", "This workspace already has a login for "+host, b.Address)
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &struct{ Body DockerRegistry }{h.registryOut(ctx, r)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-docker-registry",
		Method:      http.MethodPut,
		Path:        base + "/registries/{registry}",
		Summary:     "Change a registry login",
		Description: "A blank password keeps the saved one.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerRegistryPath
		Body DockerRegistryBody
	}) (*struct{ Body DockerRegistry }, error) {
		b := in.Body
		host := registryHost(b.Address)
		var pass []byte
		if b.Password != "" {
			pass = h.box.Seal(b.Password)
		}
		mode, ids, err := h.registryServers(ctx, uuid.MustParse(in.ID), b)
		if err != nil {
			return nil, err
		}
		r, err := h.q.UpdateDockerRegistry(ctx, sqlc.UpdateDockerRegistryParams{
			ID: uuid.MustParse(in.Registry), WorkspaceID: uuid.MustParse(in.ID),
			Name: strings.TrimSpace(b.Name), Address: host, Username: strings.TrimSpace(b.Username), PasswordEnc: pass,
			Servers: mode, ServerIds: ids, SignInOnServers: b.SignIn,
		})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("No such registry")
		}
		if isUniqueViolation(err) {
			return nil, fieldError("body.address", "This workspace already has a login for "+host, b.Address)
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &struct{ Body DockerRegistry }{h.registryOut(ctx, r)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-docker-registry",
		Method:      http.MethodDelete,
		Path:        base + "/registries/{registry}",
		Summary:     "Forget a registry login",
		Tags:        tags,
	}, func(ctx context.Context, in *DockerRegistryPath) (*struct{}, error) {
		n, err := h.q.DeleteDockerRegistry(ctx, sqlc.DeleteDockerRegistryParams{ID: uuid.MustParse(in.Registry), WorkspaceID: uuid.MustParse(in.ID)})
		if err != nil {
			return nil, internalError(err)
		}
		if n == 0 {
			return nil, huma.Error404NotFound("No such registry")
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "test-docker-registry",
		Method:      http.MethodPost,
		Path:        base + "/registries/test",
		Summary:     "Try a registry login",
		Description: "Asks a server's engine to log in with these values (nothing is saved). Needs Engineer on that server.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body DockerRegistryTestBody
	}) (*struct{ Body DockerRegistryTest }, error) {
		b := in.Body
		sid, err := uuid.Parse(b.ServerID)
		if err != nil {
			return nil, fieldError("body.server_id", "Pick a server", b.ServerID)
		}
		if _, err := h.authz.requireServers(ctx, []uuid.UUID{sid}, auth.Engineer); err != nil {
			return nil, err
		}
		pass := b.Password
		if pass == "" && b.RegistryID != "" {
			r, err := h.q.GetDockerRegistry(ctx, sqlc.GetDockerRegistryParams{ID: uuid.MustParse(b.RegistryID), WorkspaceID: uuid.MustParse(in.ID)})
			if err == nil && len(r.PasswordEnc) > 0 {
				if p, err := h.box.Open(r.PasswordEnc); err == nil {
					pass = string(p)
				}
			}
		}
		host := registryHost(b.Address)
		out := &struct{ Body DockerRegistryTest }{}
		err = h.withDocker(ctx, b.ServerID, func(e *dockerEngine) error {
			status, err := e.client.Login(ctx, registryServer(host), strings.TrimSpace(b.Username), pass)
			if err != nil {
				out.Body = DockerRegistryTest{Message: dockerProblemText(dockerProblem(err))}
				return nil
			}
			if status == "" {
				status = "Login Succeeded"
			}
			out.Body = DockerRegistryTest{OK: true, Message: status}
			return nil
		})
		if err != nil {
			return nil, dockerProblem(err)
		}
		return out, nil
	})

	// -- Templates --

	huma.Register(api, huma.Operation{
		OperationID: "list-docker-templates",
		Method:      http.MethodGet,
		Path:        base + "/templates",
		Summary:     "Compose templates",
		Description: "The built-in ones and the workspace's own.",
		Tags:        tags,
	}, func(ctx context.Context, in *WorkspacePath) (*struct{ Body DockerTemplates }, error) {
		rows, err := h.q.ListDockerTemplates(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct{ Body DockerTemplates }{DockerTemplates{Builtin: builtinTemplates, Custom: make([]DockerTemplate, len(rows))}}
		for i, r := range rows {
			out.Body.Custom[i] = toDockerTemplate(r)
		}
		return out, nil
	})

	saveTemplate := func(ctx context.Context, ws uuid.UUID, id *uuid.UUID, b DockerTemplateBody) (*struct{ Body DockerTemplate }, error) {
		if err := checkComposeText(b.Compose); err != nil {
			return nil, err
		}
		who := ""
		if p := principalOf(ctx); p != nil {
			who = displayName(p.User)
		}
		var t sqlc.DockerTemplate
		var err error
		name, cat := strings.TrimSpace(b.Name), strings.TrimSpace(b.Category)
		if id == nil {
			t, err = h.q.CreateDockerTemplate(ctx, sqlc.CreateDockerTemplateParams{
				WorkspaceID: ws, Name: name, Description: strings.TrimSpace(b.Description), Category: cat,
				Compose: b.Compose, Env: b.Env, CreatedByName: who,
			})
		} else {
			t, err = h.q.UpdateDockerTemplate(ctx, sqlc.UpdateDockerTemplateParams{
				ID: *id, WorkspaceID: ws, Name: name, Description: strings.TrimSpace(b.Description), Category: cat,
				Compose: b.Compose, Env: b.Env, UpdatedByName: who,
			})
		}
		if isNotFound(err) {
			return nil, huma.Error404NotFound("No such template")
		}
		if isUniqueViolation(err) {
			return nil, fieldError("body.name", "A template with this name already exists", name)
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &struct{ Body DockerTemplate }{toDockerTemplate(t)}, nil
	}

	huma.Register(api, huma.Operation{
		OperationID:   "create-docker-template",
		Method:        http.MethodPost,
		Path:          base + "/templates",
		Summary:       "Save a compose template",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body DockerTemplateBody
	}) (*struct{ Body DockerTemplate }, error) {
		return saveTemplate(ctx, uuid.MustParse(in.ID), nil, in.Body)
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-docker-template",
		Method:      http.MethodPut,
		Path:        base + "/templates/{template}",
		Summary:     "Change a compose template",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		dockerTemplatePath
		Body DockerTemplateBody
	}) (*struct{ Body DockerTemplate }, error) {
		id := uuid.MustParse(in.Template)
		return saveTemplate(ctx, uuid.MustParse(in.ID), &id, in.Body)
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-docker-template",
		Method:      http.MethodDelete,
		Path:        base + "/templates/{template}",
		Summary:     "Delete a compose template",
		Tags:        tags,
	}, func(ctx context.Context, in *dockerTemplatePath) (*struct{}, error) {
		n, err := h.q.DeleteDockerTemplate(ctx, sqlc.DeleteDockerTemplateParams{ID: uuid.MustParse(in.Template), WorkspaceID: uuid.MustParse(in.ID)})
		if err != nil {
			return nil, internalError(err)
		}
		if n == 0 {
			return nil, huma.Error404NotFound("No such template")
		}
		return nil, nil
	})
}

// checkComposeText is a cheap first look at a compose file; the server's
// `docker compose config` has the last word.
func checkComposeText(s string) error {
	if !strings.Contains(s, "services:") {
		return fieldError("body.compose", "A compose file needs a services: section", "")
	}
	if strings.Contains(s, "\t") {
		return fieldError("body.compose", "YAML can't be indented with tabs: use spaces", "")
	}
	return nil
}

// withConnShell runs fn with the server's connection and root shell.
func (h *serverHandler) withShell(ctx context.Context, id string, fn func(c *sshpool.Conn, sh *rootShell) error) error {
	return h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.rootShell(ctx, id, c)
		if err != nil {
			return err
		}
		return fn(c, sh)
	})
}
