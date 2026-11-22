package events

import (
	"time"

	"github.com/google/uuid"
)

// Event types. Each one is published where the thing already happens; see
// Catalog for what each carries.
const (
	AlertFired       = "alert.fired"
	AlertResolved    = "alert.resolved"
	MonitorDown      = "monitor.down"
	MonitorUp        = "monitor.up"
	MonitorDegraded  = "monitor.degraded"
	ServerOffline    = "server.offline"
	ServerOnline     = "server.online"
	CronjobFailed    = "cronjob.failed"
	CronjobSucceeded = "cronjob.succeeded"
	BackupFailed     = "backup.failed"
	BackupSucceeded  = "backup.succeeded"
	DeployFailed     = "deploy.failed"
	DeploySucceeded  = "deploy.succeeded"
	AutomationFailed = "automation.failed"
	WebhookReceived  = "webhook.received"
	TestPing         = "test.ping"
)

// Type describes one event type, for pickers and docs.
type Type struct {
	Name        string `json:"name" doc:"The event's type, e.g. alert.fired"`
	Group       string `json:"group" doc:"For grouping in a picker: Alerts, Monitoring, Servers, Cron jobs, Backups, Containers, Automations, Webhooks"`
	Label       string `json:"label"`
	Description string `json:"description"`
	// Severity is the usual one; some types (alert.fired) take the rule's.
	Severity    string `json:"severity"`
	SubjectKind string `json:"subject_kind" doc:"What subject.kind is (several, comma separated, when it varies)"`
	// ServerScoped: the event usually carries server_id.
	ServerScoped bool `json:"server_scoped"`
	// Internal types are never sent to automations (test.ping, automation.failed
	// can't trigger automations).
	Internal bool  `json:"internal,omitempty"`
	Sample   Event `json:"sample"`
}

var (
	sampleWorkspace = uuid.MustParse("00000000-0000-4000-8000-000000000001")
	sampleServer    = uuid.MustParse("00000000-0000-4000-8000-000000000002")
	sampleAt        = time.Date(2026, 11, 22, 9, 30, 0, 0, time.UTC)
)

func sample(typ, severity, title, text, url string, subj Subject, server bool, data map[string]any) Event {
	e := Event{
		ID:   uuid.MustParse("00000000-0000-4000-8000-0000000000ff"),
		Type: typ, WorkspaceID: sampleWorkspace, At: sampleAt,
		Severity: severity, Title: title, Text: text, URL: url, Subject: subj, Data: data,
	}
	if server {
		s := sampleServer
		e.ServerID = &s
	}
	return e
}

var sampleServerSubject = Subject{Kind: SubjectServer, ID: sampleServer.String(), Name: "web-1"}

// Catalog lists every event type, in the order a picker shows them.
var Catalog = []Type{
	{
		Name: AlertFired, Group: "Alerts", Label: "Alert fired",
		Description: "An alert rule's condition held for its time (servers, containers, databases, Proxmox clusters). Published even while a mute covers it, with data.muted = true.",
		Severity:    Warning, SubjectKind: "server,database,cluster", ServerScoped: true,
		Sample: sample(AlertFired, Warning, "High CPU on web-1", "CPU is 93% (above 90%).", "https://panel.example.com/servers/"+sampleServer.String()+"/metrics",
			sampleServerSubject, true, map[string]any{
				"rule_id": "00000000-0000-4000-8000-000000000003", "rule_name": "High CPU", "metric": "cpu",
				"value": 93.4, "threshold": 90, "op": "above", "detail": "", "severity": "warning", "muted": false,
			}),
	},
	{
		Name: AlertResolved, Group: "Alerts", Label: "Alert resolved",
		Description: "A firing alert rule's condition no longer holds.",
		Severity:    Info, SubjectKind: "server,database,cluster", ServerScoped: true,
		Sample: sample(AlertResolved, Info, "Resolved: High CPU on web-1", "CPU is back to 41%.", "",
			sampleServerSubject, true, map[string]any{
				"rule_id": "00000000-0000-4000-8000-000000000003", "rule_name": "High CPU", "metric": "cpu",
				"value": 41.0, "threshold": 90, "lasted_seconds": 840, "severity": "warning", "muted": false,
			}),
	},
	{
		Name: MonitorDown, Group: "Monitoring", Label: "Monitor down",
		Description: "An uptime monitor turned down (after its retries).",
		Severity:    Critical, SubjectKind: SubjectMonitor,
		Sample: sample(MonitorDown, Critical, "Shop website is down", "connection refused", "",
			Subject{Kind: SubjectMonitor, ID: "00000000-0000-4000-8000-000000000004", Name: "Shop website"}, false,
			map[string]any{"kind": "http", "target": "https://shop.example.com", "status": "down", "code": "", "latency_ms": nil}),
	},
	{
		Name: MonitorUp, Group: "Monitoring", Label: "Monitor up again",
		Description: "A down or degraded monitor is back up.",
		Severity:    Info, SubjectKind: SubjectMonitor,
		Sample: sample(MonitorUp, Info, "Shop website is back up", "", "",
			Subject{Kind: SubjectMonitor, ID: "00000000-0000-4000-8000-000000000004", Name: "Shop website"}, false,
			map[string]any{"kind": "http", "target": "https://shop.example.com", "status": "up", "previous": "down", "lasted_seconds": 300, "latency_ms": 120}),
	},
	{
		Name: MonitorDegraded, Group: "Monitoring", Label: "Monitor degraded",
		Description: "A monitor answers, but slowly or with a warning.",
		Severity:    Warning, SubjectKind: SubjectMonitor,
		Sample: sample(MonitorDegraded, Warning, "Shop website is degraded", "slower than 2000 ms", "",
			Subject{Kind: SubjectMonitor, ID: "00000000-0000-4000-8000-000000000004", Name: "Shop website"}, false,
			map[string]any{"kind": "http", "target": "https://shop.example.com", "status": "degraded", "latency_ms": 2400}),
	},
	{
		Name: ServerOffline, Group: "Servers", Label: "Server offline",
		Description: "A server that was online can't be reached or signed in to any more.",
		Severity:    Critical, SubjectKind: SubjectServer, ServerScoped: true,
		Sample: sample(ServerOffline, Critical, "web-1 is offline", "dial tcp 10.0.0.5:22: i/o timeout", "",
			sampleServerSubject, true, map[string]any{"status": "unreachable", "previous": "online", "host": "10.0.0.5"}),
	},
	{
		Name: ServerOnline, Group: "Servers", Label: "Server online again",
		Description: "A server that couldn't be reached is online again.",
		Severity:    Info, SubjectKind: SubjectServer, ServerScoped: true,
		Sample: sample(ServerOnline, Info, "web-1 is online again", "", "",
			sampleServerSubject, true, map[string]any{"status": "online", "previous": "unreachable", "host": "10.0.0.5", "latency_ms": 12}),
	},
	{
		Name: CronjobFailed, Group: "Cron jobs", Label: "Cron job failed",
		Description: "A cron job's run failed, or only partly worked (data.partial).",
		Severity:    Warning, SubjectKind: SubjectCronjob,
		Sample: sample(CronjobFailed, Warning, "Nightly sync failed", "web-1:/var/www: permission denied", "",
			Subject{Kind: SubjectCronjob, ID: "00000000-0000-4000-8000-000000000005", Name: "Nightly sync"}, false,
			map[string]any{"run_id": "00000000-0000-4000-8000-000000000006", "action": "sync", "trigger": "schedule", "state": "failed", "partial": false, "error": "web-1:/var/www: permission denied"}),
	},
	{
		Name: CronjobSucceeded, Group: "Cron jobs", Label: "Cron job succeeded",
		Description: "A cron job's run finished without problems.",
		Severity:    Info, SubjectKind: SubjectCronjob,
		Sample: sample(CronjobSucceeded, Info, "Nightly sync finished", "", "",
			Subject{Kind: SubjectCronjob, ID: "00000000-0000-4000-8000-000000000005", Name: "Nightly sync"}, false,
			map[string]any{"run_id": "00000000-0000-4000-8000-000000000006", "action": "sync", "trigger": "schedule", "state": "succeeded", "files": 120, "bytes": 52428800}),
	},
	{
		Name: BackupFailed, Group: "Backups", Label: "Database backup failed",
		Description: "A database backup run failed for at least one database.",
		Severity:    Critical, SubjectKind: SubjectDatabase,
		Sample: sample(BackupFailed, Critical, "Backup of Shop DB failed", "pg_dump: connection refused", "",
			Subject{Kind: SubjectDatabase, ID: "00000000-0000-4000-8000-000000000007", Name: "Shop DB"}, true,
			map[string]any{"plan_id": "00000000-0000-4000-8000-000000000008", "plan_name": "Nightly", "trigger": "schedule", "backups": 1, "failed": 1, "error": "pg_dump: connection refused"}),
	},
	{
		Name: BackupSucceeded, Group: "Backups", Label: "Database backup succeeded",
		Description: "Every database of a backup run was stored.",
		Severity:    Info, SubjectKind: SubjectDatabase,
		Sample: sample(BackupSucceeded, Info, "Backup of Shop DB finished", "", "",
			Subject{Kind: SubjectDatabase, ID: "00000000-0000-4000-8000-000000000007", Name: "Shop DB"}, true,
			map[string]any{"plan_id": "00000000-0000-4000-8000-000000000008", "plan_name": "Nightly", "trigger": "schedule", "backups": 1, "failed": 0, "bytes": 10485760}),
	},
	{
		Name: DeployFailed, Group: "Containers", Label: "Deploy failed",
		Description: "A compose project's deploy (Deploy / Redeploy, or a git deploy) failed.",
		Severity:    Critical, SubjectKind: SubjectProject, ServerScoped: true,
		Sample: sample(DeployFailed, Critical, "Deploy of shop on web-1 failed", "pull access denied for shop-api", "",
			Subject{Kind: SubjectProject, ID: sampleServer.String() + "/shop", Name: "shop"}, true,
			map[string]any{"project": "shop", "action": "redeploy", "job_id": "00000000-0000-4000-8000-000000000009", "error": "pull access denied for shop-api"}),
	},
	{
		Name: DeploySucceeded, Group: "Containers", Label: "Deploy succeeded",
		Description: "A compose project was deployed (git deploys only when something new was deployed).",
		Severity:    Info, SubjectKind: SubjectProject, ServerScoped: true,
		Sample: sample(DeploySucceeded, Info, "shop deployed on web-1", "", "",
			Subject{Kind: SubjectProject, ID: sampleServer.String() + "/shop", Name: "shop"}, true,
			map[string]any{"project": "shop", "action": "git", "job_id": "00000000-0000-4000-8000-000000000009", "commit": "3f2a9c1"}),
	},
	{
		Name: AutomationFailed, Group: "Automations", Label: "Automation failed",
		Description: "An automation's run failed. Never triggers automations.",
		Severity:    Warning, SubjectKind: SubjectAutomation, Internal: true,
		Sample: sample(AutomationFailed, Warning, "Automation Restart nginx failed", "step 1 (service): unit not found", "",
			Subject{Kind: SubjectAutomation, ID: "00000000-0000-4000-8000-00000000000a", Name: "Restart nginx"}, false,
			map[string]any{"run_id": "00000000-0000-4000-8000-00000000000b", "error": "step 1 (service): unit not found"}),
	},
	{
		Name: WebhookReceived, Group: "Automations", Label: "Incoming hook called",
		Description: "Someone called an automation's incoming URL (POST /automation-hooks/{token}); the JSON body is data. Only that automation runs: it's never published to other automations or webhooks.",
		Severity:    Info, SubjectKind: SubjectAutomation, Internal: true,
		Sample: sample(WebhookReceived, Info, "Deploy finished in CI", "", "",
			Subject{Kind: SubjectAutomation, ID: "00000000-0000-4000-8000-00000000000a", Name: "Restart nginx"}, false,
			map[string]any{"title": "Deploy finished in CI", "branch": "main", "commit": "3f2a9c1"}),
	},
	{
		Name: TestPing, Group: "Webhooks", Label: "Test ping",
		Description: "Sent only by a webhook's Send a test.",
		Severity:    Info, SubjectKind: SubjectWebhook, Internal: true,
		Sample: sample(TestPing, Info, "Test from Morche", "If you can read this, the webhook works.", "",
			Subject{Kind: SubjectWebhook, ID: "00000000-0000-4000-8000-00000000000c", Name: "Ops webhook"}, false, nil),
	},
}

// Lookup finds a type in the catalog.
func Lookup(name string) (Type, bool) {
	for _, t := range Catalog {
		if t.Name == name {
			return t, true
		}
	}
	return Type{}, false
}

// Known says whether name is a type in the catalog.
func Known(name string) bool {
	_, ok := Lookup(name)
	return ok
}
