package api

import "github.com/morche/backend/internal/auth"

type policyKind int

const (
	// Anyone, signed in or not.
	kindPublic policyKind = iota
	// Any valid session, even a pending user or one who must change password.
	kindSession
	// An active user. The handler decides the rest (usually filtering a list).
	kindActive
	// A system admin.
	kindAdmin
	// A level on the server, storage, workspace, database or app (web service)
	// in the path's {id}.
	kindServer
	kindStorage
	kindWorkspace
	kindDatabase
	kindApp
	// A level on the database of the backup plan or backup in {id}.
	kindBackupPlan
	kindBackup
	// A workspace level, on the workspace of the playbook or run in {id}.
	kindPlaybook
	kindAnsibleRun
	// A workspace level, on the workspace of the cron job or run in {id}.
	kindSchedule
	kindScheduleRun
	// A workspace level, on the workspace of the storage sync or run in {id}.
	kindStorageSync
	kindStorageSyncRun
	// The lower of the two databases' levels, for the database sync or run
	// in {id}.
	kindDatabaseSync
	kindDatabaseSyncRun
	// A workspace level, on the workspace of the DNS server in {id}.
	kindDNSServer
	// A workspace level, on the workspace of the saved script in {id}.
	kindScript
	// The server level on the server the proxy in {id} runs on.
	kindProxy
	// A workspace level, on the workspace of the custom application recipe
	// in {id}.
	kindSoftwareRecipe
	// The server level on the server of the installed application in {id}.
	kindSoftwareInstall
	// A workspace level, on the workspace of the uptime monitor, notification
	// channel or monitor incident in {id}.
	kindMonitor
	kindNotificationChannel
	kindMonitorIncident
	// A workspace level, on the workspace of the alert rule in {id}.
	kindAlertRule
	// A workspace level, on the workspace of the Proxmox cluster in {id}.
	kindPVECluster
	// A workspace level, on the workspace of the cloud account in {id}.
	kindCloudAccount
	// A workspace level, on the workspace of the asset in {id}.
	kindAsset
	// A workspace level, on the workspace of the outgoing webhook or webhook
	// delivery in {id}.
	kindWebhook
	kindWebhookDelivery
	// A workspace level, on the workspace of the automation or automation
	// run in {id}.
	kindAutomation
	kindAutomationRun
	// The server level on the server the package registry in {id} runs on.
	kindPackageRegistry
	// A workspace level, on the workspace of the tunnel in {id}.
	kindTunnel
)

type policy struct {
	kind  policyKind
	level auth.Level
}

func onServer(l auth.Level) policy      { return policy{kindServer, l} }
func onStorage(l auth.Level) policy     { return policy{kindStorage, l} }
func onWorkspace(l auth.Level) policy   { return policy{kindWorkspace, l} }
func onDatabase(l auth.Level) policy    { return policy{kindDatabase, l} }
func onApp(l auth.Level) policy         { return policy{kindApp, l} }
func onBackupPlan(l auth.Level) policy  { return policy{kindBackupPlan, l} }
func onBackup(l auth.Level) policy      { return policy{kindBackup, l} }
func onPlaybook(l auth.Level) policy    { return policy{kindPlaybook, l} }
func onAnsibleRun(l auth.Level) policy  { return policy{kindAnsibleRun, l} }
func onSchedule(l auth.Level) policy    { return policy{kindSchedule, l} }
func onScheduleRun(l auth.Level) policy { return policy{kindScheduleRun, l} }
func onStorageSync(l auth.Level) policy { return policy{kindStorageSync, l} }
func onStorageSyncRun(l auth.Level) policy {
	return policy{kindStorageSyncRun, l}
}
func onDatabaseSync(l auth.Level) policy {
	return policy{kindDatabaseSync, l}
}
func onDatabaseSyncRun(l auth.Level) policy {
	return policy{kindDatabaseSyncRun, l}
}
func onDNSServer(l auth.Level) policy    { return policy{kindDNSServer, l} }
func onPVECluster(l auth.Level) policy   { return policy{kindPVECluster, l} }
func onCloudAccount(l auth.Level) policy { return policy{kindCloudAccount, l} }
func onTunnel(l auth.Level) policy       { return policy{kindTunnel, l} }
func onScript(l auth.Level) policy       { return policy{kindScript, l} }
func onProxy(l auth.Level) policy        { return policy{kindProxy, l} }
func onPackageRegistry(l auth.Level) policy {
	return policy{kindPackageRegistry, l}
}
func onSoftwareRecipe(l auth.Level) policy {
	return policy{kindSoftwareRecipe, l}
}
func onSoftwareInstall(l auth.Level) policy {
	return policy{kindSoftwareInstall, l}
}
func onMonitor(l auth.Level) policy { return policy{kindMonitor, l} }
func onNotificationChannel(l auth.Level) policy {
	return policy{kindNotificationChannel, l}
}
func onMonitorIncident(l auth.Level) policy {
	return policy{kindMonitorIncident, l}
}
func onAlertRule(l auth.Level) policy { return policy{kindAlertRule, l} }
func onAsset(l auth.Level) policy     { return policy{kindAsset, l} }
func onWebhook(l auth.Level) policy   { return policy{kindWebhook, l} }
func onWebhookDelivery(l auth.Level) policy {
	return policy{kindWebhookDelivery, l}
}
func onAutomation(l auth.Level) policy { return policy{kindAutomation, l} }
func onAutomationRun(l auth.Level) policy {
	return policy{kindAutomationRun, l}
}

var (
	public  = policy{kind: kindPublic}
	session = policy{kind: kindSession}
	active  = policy{kind: kindActive}
	admin   = policy{kind: kindAdmin}
)

// policies says who may call each operation. The middleware refuses any
// operation missing from here, and a test checks the two stay in step.
var policies = map[string]policy{
	"get-health": public,

	// Asset inventory. Ownership grants nothing; the workspace level decides.
	"list-assets":               onWorkspace(auth.Viewer),
	"create-asset":              onWorkspace(auth.Engineer),
	"import-assets":             onWorkspace(auth.Engineer),
	"bulk-update-assets":        onWorkspace(auth.Engineer),
	"list-asset-relations":      onWorkspace(auth.Viewer),
	"list-asset-people":         onWorkspace(auth.Viewer),
	"get-asset-owner-rules":     onWorkspace(auth.Viewer),
	"set-asset-owner-rules":     onWorkspace(auth.Owner),
	"get-asset-settings":        onWorkspace(auth.Viewer),
	"set-asset-settings":        onWorkspace(auth.Owner),
	"list-asset-discoveries":    onWorkspace(auth.Viewer),
	"run-asset-discovery":       onWorkspace(auth.Engineer),
	"set-asset-discovery-state": onWorkspace(auth.Engineer),
	"track-asset-discovery":     onWorkspace(auth.Engineer),
	"get-asset":                 onAsset(auth.Viewer),
	"update-asset":              onAsset(auth.Engineer),
	"delete-asset":              onAsset(auth.Engineer),
	"review-asset":              onAsset(auth.Viewer),
	"get-asset-license-key":     onAsset(auth.Owner),
	"add-asset-relation":        onAsset(auth.Engineer),
	"delete-asset-relation":     onAsset(auth.Engineer),
	// Notes: the handler also lets the asset's owner, deputy or owning group
	// write (else Operator).
	"list-asset-notes":  onAsset(auth.Viewer),
	"create-asset-note": onAsset(auth.Viewer),
	"update-asset-note": onAsset(auth.Viewer),
	"pin-asset-note":    onAsset(auth.Viewer),
	"delete-asset-note": onAsset(auth.Viewer),

	// Signing in.
	"get-auth-state":  public,
	"auth-setup":      public,
	"auth-register":   public,
	"auth-login":      public,
	"auth-demo":       public,
	"auth-logout":     session,
	"auth-logout-all": session,
	"get-me":          session,
	"change-password": session,
	"update-me":       active,
	"get-my-access":   active,

	// API tokens: your own; admins see and revoke anyone's. A token can't
	// call any of these (tokenRefused).
	"list-api-tokens":        active,
	"create-api-token":       active,
	"delete-api-token":       active,
	"admin-list-user-tokens": admin,
	"admin-delete-api-token": admin,

	// The event bus: what event types exist (for pickers).
	"get-event-catalog": active,
	// Outgoing webhooks: the workspace's Owner.
	"list-webhooks":              onWorkspace(auth.Owner),
	"create-webhook":             onWorkspace(auth.Owner),
	"get-webhook":                onWebhook(auth.Owner),
	"update-webhook":             onWebhook(auth.Owner),
	"delete-webhook":             onWebhook(auth.Owner),
	"test-webhook":               onWebhook(auth.Owner),
	"rotate-webhook-secret":      onWebhook(auth.Owner),
	"list-webhook-deliveries":    onWebhook(auth.Owner),
	"get-webhook-delivery":       onWebhookDelivery(auth.Owner),
	"redeliver-webhook-delivery": onWebhookDelivery(auth.Owner),
	// Automations: Viewer reads, Operator runs and stops, Engineer edits.
	// Steps that run commands also need Engineer on each server, checked in
	// the handler (as the person it runs as, again at run time).
	"list-automations":               onWorkspace(auth.Viewer),
	"create-automation":              onWorkspace(auth.Engineer),
	"preview-automation":             onWorkspace(auth.Engineer),
	"get-automation":                 onAutomation(auth.Viewer),
	"update-automation":              onAutomation(auth.Engineer),
	"delete-automation":              onAutomation(auth.Engineer),
	"run-automation":                 onAutomation(auth.Operator),
	"test-automation":                onAutomation(auth.Operator),
	"create-automation-hook":         onAutomation(auth.Engineer),
	"delete-automation-hook":         onAutomation(auth.Engineer),
	"list-automation-runs":           onAutomation(auth.Viewer),
	"list-workspace-automation-runs": onWorkspace(auth.Viewer),
	"get-automation-run":             onAutomationRun(auth.Viewer),
	"cancel-automation-run":          onAutomationRun(auth.Operator),

	// Sessions and the sign-in log.
	"list-my-sessions":         active,
	"end-my-session":           active,
	"end-my-other-sessions":    active,
	"list-sign-in-alerts":      active,
	"answer-sign-in-alert":     active,
	"list-sign-ins":            active,
	"admin-list-user-sessions": admin,
	"admin-end-user-session":   admin,
	"admin-get-security":       admin,
	"admin-update-security":    admin,

	// Log retention and archives.
	"list-log-datasets":        admin,
	"list-log-dataset-periods": admin,
	"preview-log-policy":       admin,
	"save-log-policy":          admin,
	"reset-log-policy":         admin,
	"run-log-policy":           admin,
	"export-log-dataset":       admin,
	"compact-log-dataset":      admin,
	"list-log-archives":        admin,
	"get-log-archive":          admin,
	"download-log-archive":     admin,
	"restore-log-archive":      admin,
	"put-away-log-archive":     admin,
	"set-log-archive-hold":     admin,
	"delete-log-archive":       admin,

	// Panel people and settings.
	"admin-list-users":        admin,
	"admin-get-user":          admin,
	"admin-create-user":       admin,
	"admin-update-user":       admin,
	"admin-set-password":      admin,
	"admin-approve-user":      admin,
	"admin-reject-user":       admin,
	"admin-block-user":        admin,
	"admin-unblock-user":      admin,
	"admin-delete-user":       admin,
	"admin-revoke-sessions":   admin,
	"admin-list-groups":       admin,
	"admin-create-group":      admin,
	"admin-update-group":      admin,
	"admin-delete-group":      admin,
	"admin-set-group-members": admin,
	"admin-get-settings":      admin,
	"admin-update-settings":   admin,

	// Workspaces and who can reach what. Grant handlers check the resource.
	"list-workspaces":  active,
	"get-workspace":    onWorkspace(auth.Viewer),
	"create-workspace": admin,
	"update-workspace": admin,
	"delete-workspace": admin,
	"assign-workspace": admin,
	// The logo shows to anyone who sees the workspace; checked inside.
	"get-workspace-logo": active,
	"put-workspace-logo": admin,
	"list-grants":        active,
	"set-grant":          active,
	"delete-grant":       active,
	"list-principals":    active,

	// Servers. Lists filter themselves, bulk actions check every id.
	"list-servers":              active,
	"server-insights":           active,
	"get-server-facets":         active,
	"create-server":             active,
	"test-server-connection":    active,
	"bulk-check-servers":        active,
	"bulk-move-servers":         active,
	"bulk-tag-servers":          active,
	"bulk-delete-servers":       active,
	"get-server":                onServer(auth.Viewer),
	"update-server":             onServer(auth.Owner),
	"sign-in-server":            onServer(auth.Owner),
	"get-morche-host":           active,
	"add-morche-host":           admin,
	"delete-server":             onServer(auth.Owner),
	"duplicate-server":          onServer(auth.Owner),
	"set-server-favorite":       onServer(auth.Operator),
	"check-server":              onServer(auth.Operator),
	"reveal-server-credentials": onServer(auth.Owner),

	// Folders: writes need Owner of the folder's workspace, checked inside.
	"list-folders":  active,
	"create-folder": active,
	"update-folder": active,
	"delete-folder": active,

	// Terminals: a root shell. Everyone only sees their own.
	"list-terminals":  onServer(auth.Engineer),
	"rename-terminal": onServer(auth.Engineer),
	"close-terminal":  onServer(auth.Engineer),

	// Files on a server.
	"list-files":      onServer(auth.Operator),
	"stat-file":       onServer(auth.Operator),
	"folder-size":     onServer(auth.Operator),
	"download-files":  onServer(auth.Operator),
	"read-file":       onServer(auth.Operator),
	"search-files":    onServer(auth.Operator),
	"disk-usage":      onServer(auth.Operator),
	"write-file":      onServer(auth.Engineer),
	"upload-file":     onServer(auth.Engineer),
	"make-folder":     onServer(auth.Engineer),
	"rename-file":     onServer(auth.Engineer),
	"delete-files":    onServer(auth.Engineer),
	"chmod-files":     onServer(auth.Engineer),
	"chown-files":     onServer(auth.Engineer),
	"compress-files":  onServer(auth.Engineer),
	"extract-archive": onServer(auth.Engineer),
	"fetch-url":       onServer(auth.Engineer),
	"move-files":      onServer(auth.Engineer),
	"copy-files":      onServer(auth.Engineer),

	// Cron. run-cron-command runs any command in a root shell, so it's no
	// lighter than the terminal.
	"get-cron":          onServer(auth.Viewer),
	"cron-history":      onServer(auth.Operator),
	"add-cron-job":      onServer(auth.Engineer),
	"update-cron-job":   onServer(auth.Engineer),
	"delete-cron-jobs":  onServer(auth.Engineer),
	"enable-cron-jobs":  onServer(auth.Engineer),
	"save-crontab":      onServer(auth.Engineer),
	"run-cron-command":  onServer(auth.Engineer),
	"cron-timer-action": onServer(auth.Engineer),

	"list-ports":      onServer(auth.Viewer),
	"get-network-map": active,

	"get-server-stats":    onServer(auth.Viewer),
	"get-server-metrics":  onServer(auth.Viewer),
	"stream-server-stats": onServer(auth.Viewer),

	// Fail2ban.
	"get-fail2ban":             onServer(auth.Viewer),
	"get-fail2ban-filter":      onServer(auth.Viewer),
	"fail2ban-log":             onServer(auth.Operator),
	"install-fail2ban":         onServer(auth.Engineer),
	"uninstall-fail2ban":       onServer(auth.Engineer),
	"fail2ban-service":         onServer(auth.Engineer),
	"update-fail2ban-defaults": onServer(auth.Engineer),
	"update-fail2ban-jail":     onServer(auth.Engineer),
	"delete-fail2ban-jail":     onServer(auth.Engineer),
	"save-fail2ban-config":     onServer(auth.Engineer),
	"fail2ban-ban":             onServer(auth.Engineer),
	"fail2ban-unban":           onServer(auth.Engineer),
	"save-fail2ban-filter":     onServer(auth.Engineer),
	"test-fail2ban-filter":     onServer(auth.Engineer),

	// System packages.
	"get-packages":          onServer(auth.Viewer),
	"get-package":           onServer(auth.Viewer),
	"search-packages":       onServer(auth.Viewer),
	"package-history":       onServer(auth.Viewer),
	"refresh-package-lists": onServer(auth.Operator),
	"preview-packages":      onServer(auth.Engineer),
	"run-package-action":    onServer(auth.Engineer),
	"mark-packages":         onServer(auth.Engineer),
	"set-auto-updates":      onServer(auth.Engineer),

	// The firewall on a server.
	"get-firewall":             onServer(auth.Viewer),
	"firewall-raw":             onServer(auth.Operator),
	"firewall-log":             onServer(auth.Operator),
	"install-firewall":         onServer(auth.Engineer),
	"enable-firewall":          onServer(auth.Engineer),
	"disable-firewall":         onServer(auth.Engineer),
	"add-firewall-rule":        onServer(auth.Engineer),
	"update-firewall-rule":     onServer(auth.Engineer),
	"delete-firewall-rules":    onServer(auth.Engineer),
	"update-firewall-settings": onServer(auth.Engineer),
	"reset-firewall":           onServer(auth.Engineer),
	"keep-firewall-change":     onServer(auth.Engineer),
	"undo-firewall-change":     onServer(auth.Engineer),
	"move-firewall-rule":       onServer(auth.Engineer),
	"add-firewall-forward":     onServer(auth.Engineer),
	"update-firewall-forward":  onServer(auth.Engineer),
	"delete-firewall-forwards": onServer(auth.Engineer),
	"get-container-access":     onServer(auth.Viewer),
	"set-container-access":     onServer(auth.Engineer),
	"firewall-history":         onServer(auth.Operator),
	"firewall-change":          onServer(auth.Operator),
	"restore-firewall-change":  onServer(auth.Engineer),
	"apply-firewall-rules":     active, // Engineer on every server: checked in the handler

	// Linux users on a server.
	"get-users":         onServer(auth.Viewer),
	"create-user":       onServer(auth.Engineer),
	"update-user":       onServer(auth.Engineer),
	"delete-user":       onServer(auth.Engineer),
	"set-user-password": onServer(auth.Engineer),
	"lock-user":         onServer(auth.Engineer),
	"logout-user":       onServer(auth.Engineer),
	"create-group":      onServer(auth.Engineer),
	"update-group":      onServer(auth.Engineer),
	"delete-group":      onServer(auth.Engineer),

	// Services. A service's details include its environment, which often holds
	// secrets. service-action lets Operators start/stop/restart/reload; the
	// handler wants Engineer for the rest.
	"list-services":         onServer(auth.Viewer),
	"get-service":           onServer(auth.Operator),
	"get-service-logs":      onServer(auth.Operator),
	"stream-service-logs":   onServer(auth.Operator),
	"service-action":        onServer(auth.Operator),
	"save-service-override": onServer(auth.Engineer),
	"save-service-file":     onServer(auth.Engineer),
	"create-service":        onServer(auth.Engineer),
	"delete-service":        onServer(auth.Engineer),
	"reload-services":       onServer(auth.Engineer),

	// Processes. Viewers get the list without command lines (they can carry
	// passwords); details need Operator (environment only for Engineers).
	"list-processes": onServer(auth.Viewer),
	// Containers (Docker / Podman engine over SSH)
	"get-docker-engine":             onServer(auth.Viewer),
	"list-docker-containers":        onServer(auth.Viewer),
	"get-docker-container":          onServer(auth.Viewer),
	"inspect-docker-container":      onServer(auth.Engineer),
	"docker-container-logs":         onServer(auth.Operator),
	"stream-docker-container-logs":  onServer(auth.Operator),
	"stream-docker-container-stats": onServer(auth.Viewer),
	"docker-container-action":       onServer(auth.Operator),
	"kill-docker-container":         onServer(auth.Engineer),
	"remove-docker-container":       onServer(auth.Engineer),
	"rename-docker-container":       onServer(auth.Engineer),
	"list-docker-images":            onServer(auth.Viewer),
	"get-docker-image":              onServer(auth.Viewer),
	"pull-docker-image":             onServer(auth.Engineer),
	"remove-docker-image":           onServer(auth.Engineer),
	"tag-docker-image":              onServer(auth.Engineer),
	"list-docker-volumes":           onServer(auth.Viewer),
	"create-docker-volume":          onServer(auth.Engineer),
	"remove-docker-volume":          onServer(auth.Engineer),
	// A volume's files are read and written as root.
	"list-docker-volume-files":       onServer(auth.Engineer),
	"stat-docker-volume-file":        onServer(auth.Engineer),
	"docker-volume-folder-size":      onServer(auth.Engineer),
	"docker-volume-disk-usage":       onServer(auth.Engineer),
	"read-docker-volume-file":        onServer(auth.Engineer),
	"write-docker-volume-file":       onServer(auth.Engineer),
	"download-docker-volume-files":   onServer(auth.Engineer),
	"upload-docker-volume-file":      onServer(auth.Engineer),
	"make-docker-volume-folder":      onServer(auth.Engineer),
	"rename-docker-volume-file":      onServer(auth.Engineer),
	"delete-docker-volume-files":     onServer(auth.Engineer),
	"chmod-docker-volume-files":      onServer(auth.Engineer),
	"chown-docker-volume-files":      onServer(auth.Engineer),
	"search-docker-volume-files":     onServer(auth.Engineer),
	"move-docker-volume-files":       onServer(auth.Engineer),
	"copy-docker-volume-files":       onServer(auth.Engineer),
	"list-docker-networks":           onServer(auth.Viewer),
	"create-docker-network":          onServer(auth.Engineer),
	"remove-docker-network":          onServer(auth.Engineer),
	"connect-docker-network":         onServer(auth.Engineer),
	"disconnect-docker-network":      onServer(auth.Engineer),
	"docker-disk-usage":              onServer(auth.Viewer),
	"prune-docker":                   onServer(auth.Engineer),
	"get-docker-image-layers":        onServer(auth.Engineer),
	"list-docker-image-layer-files":  onServer(auth.Engineer),
	"export-docker-image":            onServer(auth.Engineer),
	"import-docker-image":            onServer(auth.Engineer),
	"copy-docker-image":              onServer(auth.Engineer),
	"run-docker-container":           onServer(auth.Engineer),
	"list-docker-fleet":              active,
	"list-docker-events":             onServer(auth.Viewer),
	"list-docker-projects":           onServer(auth.Viewer),
	"get-docker-project":             onServer(auth.Viewer),
	"docker-project-stats":           onServer(auth.Viewer),
	"docker-report":                  onServer(auth.Viewer),
	"docker-project-history":         onServer(auth.Viewer),
	"list-docker-volume-backups":     onServer(auth.Viewer),
	"backup-docker-volume":           onServer(auth.Engineer),
	"restore-docker-volume-backup":   onServer(auth.Owner),
	"delete-docker-volume-backup":    onServer(auth.Engineer),
	"docker-project-logs":            onServer(auth.Operator),
	"stream-docker-project-logs":     onServer(auth.Operator),
	"stream-docker-project-stats":    onServer(auth.Viewer),
	"set-docker-project-meta":        onServer(auth.Engineer),
	"save-docker-project-files":      onServer(auth.Engineer),
	"list-docker-project-versions":   onServer(auth.Engineer),
	"get-docker-project-version":     onServer(auth.Engineer),
	"restore-docker-project-version": onServer(auth.Engineer),
	"create-docker-project":          onServer(auth.Engineer),
	"check-docker-project":           onServer(auth.Engineer),
	"get-docker-project-scan":        onServer(auth.Engineer),
	"scan-docker-projects":           onServer(auth.Engineer),
	"add-docker-projects":            onServer(auth.Engineer),
	"forget-docker-project":          onServer(auth.Engineer),
	"get-docker-project-git":         onServer(auth.Viewer),
	"save-docker-project-git":        onServer(auth.Engineer),
	"delete-docker-project-git":      onServer(auth.Engineer),
	"deploy-docker-project-git":      onServer(auth.Engineer),
	"reset-docker-project-webhook":   onServer(auth.Engineer),
	"create-docker-project-git":      onServer(auth.Engineer),
	"docker-project-action":          onServer(auth.Operator),
	"list-docker-updates":            onServer(auth.Viewer),
	"get-server-docker-auto-update":  onServer(auth.Viewer),
	"check-docker-updates":           onServer(auth.Operator),
	"apply-docker-updates":           onServer(auth.Engineer),
	"list-docker-scans":              onServer(auth.Viewer),
	"get-docker-scan":                onServer(auth.Viewer),
	"scan-docker-images":             onServer(auth.Engineer),
	// Container settings per workspace: registry logins are the Owner's.
	"get-docker-settings":              onWorkspace(auth.Viewer),
	"update-docker-settings":           onWorkspace(auth.Owner),
	"list-docker-server-settings":      onWorkspace(auth.Viewer),
	"update-docker-server-settings":    onWorkspace(auth.Owner),
	"delete-docker-server-settings":    onWorkspace(auth.Owner),
	"get-server-docker-settings":       onServer(auth.Viewer),
	"get-docker-daemon-config":         onServer(auth.Engineer),
	"save-docker-daemon-config":        onServer(auth.Owner),
	"apply-docker-daemon-config":       onServer(auth.Owner),
	"list-docker-registries":           onWorkspace(auth.Viewer),
	"create-docker-registry":           onWorkspace(auth.Owner),
	"update-docker-registry":           onWorkspace(auth.Owner),
	"delete-docker-registry":           onWorkspace(auth.Owner),
	"test-docker-registry":             onWorkspace(auth.Owner),
	"sign-in-docker-registry":          onWorkspace(auth.Owner),
	"list-docker-templates":            onWorkspace(auth.Viewer),
	"list-docker-auto-updates":         onWorkspace(auth.Viewer),
	"get-docker-auto-update":           onWorkspace(auth.Viewer),
	"create-docker-auto-update":        onWorkspace(auth.Engineer),
	"update-docker-auto-update":        onWorkspace(auth.Engineer),
	"set-docker-auto-update-enabled":   onWorkspace(auth.Engineer),
	"reset-docker-auto-update-webhook": onWorkspace(auth.Engineer),
	"delete-docker-auto-update":        onWorkspace(auth.Engineer),
	"run-docker-auto-update":           onWorkspace(auth.Operator),
	"preview-docker-auto-update":       onWorkspace(auth.Viewer),
	"list-docker-auto-update-events":   onWorkspace(auth.Viewer),
	"create-docker-template":           onWorkspace(auth.Engineer),
	"update-docker-template":           onWorkspace(auth.Engineer),
	"delete-docker-template":           onWorkspace(auth.Engineer),
	"get-process":                      onServer(auth.Operator),
	"signal-processes":                 onServer(auth.Engineer),
	"renice-processes":                 onServer(auth.Engineer),

	// Notes on a server: anyone who sees it reads them, Operators write.
	"list-server-notes":  onServer(auth.Viewer),
	"create-server-note": onServer(auth.Operator),
	"update-server-note": onServer(auth.Operator),
	"pin-server-note":    onServer(auth.Operator),
	"delete-server-note": onServer(auth.Operator),

	// Saved scripts. Running one needs Engineer on every server (checked
	// inside, like the terminal); a run is read with Operator and stopped or
	// deleted with Engineer on every server it touched.
	"list-scripts":            onWorkspace(auth.Viewer),
	"create-script":           onWorkspace(auth.Engineer),
	"get-script":              onScript(auth.Viewer),
	"update-script":           onScript(auth.Engineer),
	"delete-script":           onScript(auth.Engineer),
	"list-server-scripts":     onServer(auth.Viewer),
	"start-script-run":        active,
	"list-script-runs":        onWorkspace(auth.Operator),
	"list-server-script-runs": onServer(auth.Operator),
	"get-script-run":          active,
	"cancel-script-run":       active,
	"delete-script-run":       active,

	// Applications. Workspace lists filter by server; a run is checked
	// against every server it touches (Engineer to start, Owner to remove
	// software; Operator to read it).
	"list-software-catalog":   onWorkspace(auth.Viewer),
	"create-software-recipe":  onWorkspace(auth.Engineer),
	"update-software-recipe":  onSoftwareRecipe(auth.Engineer),
	"delete-software-recipe":  onSoftwareRecipe(auth.Engineer),
	"list-software-installs":  active,
	"list-server-software":    onServer(auth.Viewer),
	"get-software-install":    onSoftwareInstall(auth.Viewer),
	"reveal-software-secrets": onSoftwareInstall(auth.Owner),
	"forget-software-install": onSoftwareInstall(auth.Engineer),
	"software-preflight":      active,
	"start-software-run":      active,
	"list-software-runs":      onWorkspace(auth.Operator),
	"get-software-run":        active,
	"cancel-software-run":     active,
	"delete-software-run":     active,
	"scan-server-software":    onServer(auth.Operator),
	"scan-workspace-software": active,

	// Terminal recordings. Lists filter to the caller's own below Owner; one
	// recording is the caller's own or an Owner's (checked inside).
	"get-recording-settings":    onWorkspace(auth.Viewer),
	"set-recording-settings":    onWorkspace(auth.Owner),
	"list-workspace-recordings": active,
	"list-server-recordings":    onServer(auth.Viewer),
	"get-recording":             active,
	"get-recording-cast":        active,
	"delete-recording":          active,

	// The command log. Lists filter to the caller's own below Owner; one
	// entry is the caller's own or an Owner's (checked inside).
	"get-command-log-settings":     onWorkspace(auth.Viewer),
	"set-command-log-settings":     onWorkspace(auth.Owner),
	"list-workspace-command-log":   active,
	"workspace-command-log-facets": active,
	"export-workspace-command-log": active,
	"list-server-command-log":      onServer(auth.Viewer),
	"server-command-log-facets":    onServer(auth.Viewer),
	"export-server-command-log":    onServer(auth.Viewer),
	"get-command-log":              active,

	"get-power":    onServer(auth.Viewer),
	"power-action": onServer(auth.Operator),
	"cancel-power": onServer(auth.Operator),

	// Storages.
	"list-apps":                  active,
	"create-app":                 active,
	"get-app":                    onApp(auth.Viewer),
	"update-app":                 onApp(auth.Engineer),
	"delete-app":                 onApp(auth.Owner),
	"reveal-app-account":         onApp(auth.Operator),
	"list-app-activity":          onApp(auth.Owner),
	"get-app-logo":               onApp(auth.Viewer),
	"put-app-logo":               onApp(auth.Engineer),
	"refetch-app-icon":           onApp(auth.Engineer),
	"create-app-category":        onWorkspace(auth.Engineer),
	"update-app-category":        onWorkspace(auth.Engineer),
	"delete-app-category":        onWorkspace(auth.Engineer),
	"set-apps-layout":            onWorkspace(auth.Engineer),
	"list-storages":              active,
	"create-storage":             active,
	"test-storage-connection":    active,
	"get-storage":                onStorage(auth.Viewer),
	"update-storage":             onStorage(auth.Owner),
	"delete-storage":             onStorage(auth.Owner),
	"reveal-storage-credentials": onStorage(auth.Owner),
	"set-storage-favorite":       onStorage(auth.Operator),
	"check-storage":              onStorage(auth.Operator),
	"storage-insights":           active,
	"measure-storage-usage":      onStorage(auth.Operator),

	// Files on a storage.
	"list-storage-files":     onStorage(auth.Viewer),
	"stat-storage-file":      onStorage(auth.Viewer),
	"storage-folder-size":    onStorage(auth.Viewer),
	"search-storage-files":   onStorage(auth.Viewer),
	"download-storage-files": onStorage(auth.Operator),
	"read-storage-file":      onStorage(auth.Operator),
	"write-storage-file":     onStorage(auth.Engineer),
	"upload-storage-file":    onStorage(auth.Engineer),
	"storage-mkdir":          onStorage(auth.Engineer),
	"storage-rename":         onStorage(auth.Engineer),
	"storage-move":           onStorage(auth.Engineer),
	"storage-copy":           onStorage(auth.Engineer),
	"storage-delete":         onStorage(auth.Engineer),
	"share-storage-file":     onStorage(auth.Engineer),
	// Bucket settings (S3): who can read it, encryption and retention are
	// Owner's; the rest Engineer's.
	"get-storage-bucket":            onStorage(auth.Viewer),
	"create-storage-bucket":         onStorage(auth.Engineer),
	"empty-storage-bucket":          onStorage(auth.Engineer),
	"set-storage-bucket-versioning": onStorage(auth.Engineer),
	"set-storage-bucket-lifecycle":  onStorage(auth.Engineer),
	"set-storage-bucket-tags":       onStorage(auth.Engineer),
	"set-storage-bucket-cors":       onStorage(auth.Engineer),
	"set-storage-bucket-access":     onStorage(auth.Owner),
	"set-storage-bucket-encryption": onStorage(auth.Owner),
	"set-storage-bucket-retention":  onStorage(auth.Owner),
	"transfer-files":                active,

	// DNS: a DNS server's level is its workspace's.
	"list-dns-servers":          active,
	"create-dns-server":         active,
	"test-dns-connection":       active,
	"list-dns-zones-everywhere": active,
	"get-dns-server":            onDNSServer(auth.Viewer),
	"list-dns-zones":            onDNSServer(auth.Viewer),
	"list-dns-records":          onDNSServer(auth.Viewer),
	"set-dns-server-favorite":   onDNSServer(auth.Operator),
	"check-dns-server":          onDNSServer(auth.Operator),
	"create-dns-zone":           onDNSServer(auth.Engineer),
	"delete-dns-zone":           onDNSServer(auth.Engineer),
	"get-dns-zone-options":      onDNSServer(auth.Viewer),
	"set-dns-zone-options":      onDNSServer(auth.Engineer),
	"resync-dns-zone":           onDNSServer(auth.Operator),
	"set-dns-zone-enabled":      onDNSServer(auth.Engineer),
	"add-dns-record":            onDNSServer(auth.Engineer),
	"update-dns-record":         onDNSServer(auth.Engineer),
	"delete-dns-record":         onDNSServer(auth.Engineer),
	"update-dns-server":         onDNSServer(auth.Owner),
	"delete-dns-server":         onDNSServer(auth.Owner),
	// ArvanCloud domains (CDN): writes also need the connection to allow changes.
	"list-cdn-records":                onDNSServer(auth.Viewer),
	"export-cdn-records":              onDNSServer(auth.Viewer),
	"get-cdn-ssl":                     onDNSServer(auth.Viewer),
	"get-cdn-caching":                 onDNSServer(auth.Viewer),
	"get-cdn-redirect":                onDNSServer(auth.Viewer),
	"get-cdn-acceleration":            onDNSServer(auth.Viewer),
	"get-cdn-report":                  onDNSServer(auth.Viewer),
	"check-cdn-domain":                onDNSServer(auth.Operator),
	"purge-cdn-cache":                 onDNSServer(auth.Operator),
	"add-cdn-record":                  onDNSServer(auth.Engineer),
	"update-cdn-record":               onDNSServer(auth.Engineer),
	"delete-cdn-record":               onDNSServer(auth.Engineer),
	"set-cdn-record-cloud":            onDNSServer(auth.Engineer),
	"import-cdn-records":              onDNSServer(auth.Engineer),
	"set-cdn-dnssec":                  onDNSServer(auth.Engineer),
	"update-cdn-ssl":                  onDNSServer(auth.Engineer),
	"issue-cdn-certificate":           onDNSServer(auth.Engineer),
	"update-cdn-caching":              onDNSServer(auth.Engineer),
	"update-cdn-redirect":             onDNSServer(auth.Engineer),
	"update-cdn-acceleration":         onDNSServer(auth.Engineer),
	"get-cdn-firewall":                onDNSServer(auth.Viewer),
	"get-cdn-rate-limit":              onDNSServer(auth.Viewer),
	"get-cdn-waf":                     onDNSServer(auth.Viewer),
	"update-cdn-firewall-settings":    onDNSServer(auth.Engineer),
	"add-cdn-firewall-rule":           onDNSServer(auth.Engineer),
	"update-cdn-firewall-rule":        onDNSServer(auth.Engineer),
	"delete-cdn-firewall-rule":        onDNSServer(auth.Engineer),
	"set-cdn-firewall-rule-enabled":   onDNSServer(auth.Engineer),
	"move-cdn-firewall-rule":          onDNSServer(auth.Engineer),
	"update-cdn-rate-limit-settings":  onDNSServer(auth.Engineer),
	"add-cdn-rate-limit-rule":         onDNSServer(auth.Engineer),
	"update-cdn-rate-limit-rule":      onDNSServer(auth.Engineer),
	"delete-cdn-rate-limit-rule":      onDNSServer(auth.Engineer),
	"set-cdn-rate-limit-rule-enabled": onDNSServer(auth.Engineer),
	"move-cdn-rate-limit-rule":        onDNSServer(auth.Engineer),
	"update-cdn-waf-mode":             onDNSServer(auth.Engineer),
	"add-cdn-waf-package":             onDNSServer(auth.Engineer),
	"set-cdn-waf-package":             onDNSServer(auth.Engineer),
	"delete-cdn-waf-package":          onDNSServer(auth.Engineer),
	"add-cdn-waf-rule":                onDNSServer(auth.Engineer),
	"update-cdn-waf-rule":             onDNSServer(auth.Engineer),
	"delete-cdn-waf-rule":             onDNSServer(auth.Engineer),
	"set-cdn-waf-rule-enabled":        onDNSServer(auth.Engineer),
	"move-cdn-waf-rule":               onDNSServer(auth.Engineer),
	// Names across every DNS connection (the reverse proxy's domains).
	"find-dns-names":   active,
	"point-dns-name":   onDNSServer(auth.Engineer),
	"get-arvan-ranges": active,

	// Proxmox: a cluster's level is its workspace's.
	"list-pve-clusters":              active,
	"create-pve-cluster":             active,
	"test-pve-connection":            active,
	"list-pve-guests-everywhere":     active,
	"list-pve-infrastructure":        active,
	"list-tunnels":                   active,
	"create-tunnel":                  active,
	"test-tunnel":                    active,
	"get-tunnel":                     onTunnel(auth.Viewer),
	"list-tunnel-servers":            onTunnel(auth.Viewer),
	"list-tunnel-users":              onTunnel(auth.Viewer),
	"get-tunnel-log":                 onTunnel(auth.Operator),
	"connect-tunnel":                 onTunnel(auth.Operator),
	"disconnect-tunnel":              onTunnel(auth.Operator),
	"update-tunnel":                  onTunnel(auth.Owner),
	"delete-tunnel":                  onTunnel(auth.Owner),
	"list-cloud-accounts":            active,
	"create-cloud-account":           active,
	"test-cloud-account":             active,
	"list-cloud-servers":             active,
	"get-cloud-account":              onCloudAccount(auth.Viewer),
	"set-cloud-account-favorite":     onCloudAccount(auth.Viewer),
	"get-cloud-server":               onCloudAccount(auth.Viewer),
	"get-cloud-account-resources":    onCloudAccount(auth.Viewer),
	"check-cloud-account":            onCloudAccount(auth.Operator),
	"power-cloud-server":             onCloudAccount(auth.Operator),
	"rename-cloud-server":            onCloudAccount(auth.Engineer),
	"update-cloud-account":           onCloudAccount(auth.Owner),
	"delete-cloud-account":           onCloudAccount(auth.Owner),
	"get-pve-cluster":                onPVECluster(auth.Viewer),
	"list-pve-guests":                onPVECluster(auth.Viewer),
	"get-pve-guest":                  onPVECluster(auth.Viewer),
	"get-pve-guest-rrd":              onPVECluster(auth.Viewer),
	"list-pve-snapshots":             onPVECluster(auth.Viewer),
	"list-pve-guest-tasks":           onPVECluster(auth.Viewer),
	"list-pve-guest-backups":         onPVECluster(auth.Viewer),
	"get-pve-cloud-init":             onPVECluster(auth.Viewer),
	"get-pve-guest-firewall":         onPVECluster(auth.Viewer),
	"check-pve-migration":            onPVECluster(auth.Viewer),
	"get-pve-node":                   onPVECluster(auth.Viewer),
	"get-pve-node-rrd":               onPVECluster(auth.Viewer),
	"list-pve-storage-content":       onPVECluster(auth.Viewer),
	"list-pve-cluster-tasks":         onPVECluster(auth.Viewer),
	"get-pve-task-log":               onPVECluster(auth.Viewer),
	"list-pve-ha":                    onPVECluster(auth.Viewer),
	"get-pve-create-options":         onPVECluster(auth.Viewer),
	"set-pve-cluster-favorite":       onPVECluster(auth.Viewer),
	"check-pve-cluster":              onPVECluster(auth.Operator),
	"power-pve-guest":                onPVECluster(auth.Operator),
	"set-pve-guest-config":           onPVECluster(auth.Engineer),
	"resize-pve-guest-disk":          onPVECluster(auth.Engineer),
	"create-pve-snapshot":            onPVECluster(auth.Engineer),
	"rollback-pve-snapshot":          onPVECluster(auth.Engineer),
	"delete-pve-snapshot":            onPVECluster(auth.Engineer),
	"clone-pve-guest":                onPVECluster(auth.Engineer),
	"convert-pve-guest-to-template":  onPVECluster(auth.Engineer),
	"migrate-pve-guest":              onPVECluster(auth.Engineer),
	"backup-pve-guest":               onPVECluster(auth.Engineer),
	"restore-pve-guest":              onPVECluster(auth.Engineer),
	"set-pve-cloud-init":             onPVECluster(auth.Engineer),
	"set-pve-guest-firewall-options": onPVECluster(auth.Engineer),
	"add-pve-guest-firewall-rule":    onPVECluster(auth.Engineer),
	"update-pve-guest-firewall-rule": onPVECluster(auth.Engineer),
	"move-pve-guest-firewall-rule":   onPVECluster(auth.Engineer),
	"delete-pve-guest-firewall-rule": onPVECluster(auth.Engineer),
	"set-pve-guest-ha":               onPVECluster(auth.Engineer),
	"remove-pve-guest-ha":            onPVECluster(auth.Engineer),
	"link-pve-guest":                 onPVECluster(auth.Engineer),
	"unlink-pve-guest":               onPVECluster(auth.Engineer),
	"download-pve-storage-url":       onPVECluster(auth.Engineer),
	"upload-pve-storage-file":        onPVECluster(auth.Engineer),
	"create-pve-guest":               onPVECluster(auth.Engineer),
	"open-pve-console":               onPVECluster(auth.Engineer),
	"update-pve-cluster":             onPVECluster(auth.Owner),
	"delete-pve-cluster":             onPVECluster(auth.Owner),
	"delete-pve-guest":               onPVECluster(auth.Owner),
	"delete-pve-volume":              onPVECluster(auth.Owner),
	"get-server-pve-link":            onServer(auth.Viewer),

	// Reverse proxies
	"list-proxy-kinds":                   active,
	"list-package-registry-kinds":        active,
	"list-package-registries":            active,
	"create-package-registry":            active, // Engineer on the server, checked in the handler
	"package-registry-preflight":         onServer(auth.Engineer),
	"get-package-registry":               onPackageRegistry(auth.Viewer),
	"update-package-registry":            onPackageRegistry(auth.Engineer),
	"delete-package-registry":            onPackageRegistry(auth.Owner),
	"redeploy-package-registry":          onPackageRegistry(auth.Engineer),
	"secure-package-registry":            onPackageRegistry(auth.Engineer),
	"check-package-registry":             onPackageRegistry(auth.Operator),
	"package-registry-action":            onPackageRegistry(auth.Engineer),
	"get-package-registry-credentials":   onPackageRegistry(auth.Owner),
	"list-package-registry-items":        onPackageRegistry(auth.Viewer),
	"get-package-registry-item":          onPackageRegistry(auth.Viewer),
	"delete-package-registry-item":       onPackageRegistry(auth.Engineer),
	"list-package-registry-accounts":     onPackageRegistry(auth.Operator),
	"create-package-registry-account":    onPackageRegistry(auth.Engineer),
	"reset-package-registry-account":     onPackageRegistry(auth.Engineer),
	"delete-package-registry-account":    onPackageRegistry(auth.Engineer),
	"list-proxies":                       active,
	"list-proxy-hosts-everywhere":        active,
	"get-proxy-traffic":                  active,
	"create-proxy":                       active, // Engineer on the server, checked by the handler
	"detect-proxy":                       onServer(auth.Engineer),
	"get-proxy":                          onProxy(auth.Viewer),
	"inspect-proxy":                      onProxy(auth.Viewer),
	"delete-proxy":                       onProxy(auth.Owner),
	"setup-proxy":                        onProxy(auth.Engineer),
	"setup-proxy-geo":                    onProxy(auth.Engineer),
	"setup-proxy-module":                 onProxy(auth.Engineer),
	"list-proxy-host-waf-events":         onProxy(auth.Operator),
	"proxy-action":                       onProxy(auth.Operator), // stop needs Engineer
	"preview-proxy-host":                 onProxy(auth.Viewer),
	"create-proxy-host":                  onProxy(auth.Engineer),
	"test-proxy-host":                    onProxy(auth.Engineer),
	"test-proxy-upstream":                onProxy(auth.Engineer),
	"update-proxy-host":                  onProxy(auth.Engineer),
	"set-proxy-host-enabled":             onProxy(auth.Engineer),
	"delete-proxy-host":                  onProxy(auth.Engineer),
	"get-proxy-logs":                     onProxy(auth.Operator),
	"list-proxy-host-requests":           onProxy(auth.Operator),
	"get-proxy-host-report":              onProxy(auth.Operator),
	"get-proxy-host-redirect-stats":      onProxy(auth.Operator),
	"check-proxy-redirect-targets":       onProxy(auth.Engineer),
	"fetch-proxy-redirect-source":        onProxy(auth.Engineer),
	"purge-proxy-host-cache":             onProxy(auth.Operator),
	"list-proxy-host-kept-pages":         onProxy(auth.Operator),
	"list-proxy-history":                 onProxy(auth.Viewer),
	"get-proxy-change":                   onProxy(auth.Viewer),
	"restore-proxy-change":               onProxy(auth.Engineer),
	"list-proxy-certificate-authorities": onProxy(auth.Viewer),
	"create-proxy-certificate":           onProxy(auth.Engineer),

	// Databases: a database's level is its workspace's, or that of the
	// server it's reached through when higher.
	"list-databases":              active,
	"database-insights":           active,
	"create-database":             active,
	"test-database-connection":    active,
	"get-database-outbound-ip":    active,
	"list-database-checks":        active,
	"get-database":                onDatabase(auth.Viewer),
	"get-database-live":           onDatabase(auth.Viewer),
	"list-database-events":        onDatabase(auth.Viewer),
	"get-database-history":        onDatabase(auth.Viewer),
	"set-database-favorite":       onDatabase(auth.Operator),
	"check-database":              onDatabase(auth.Operator),
	"set-database-paused":         onDatabase(auth.Engineer),
	"update-database-monitoring":  onDatabase(auth.Engineer),
	"kill-database-session":       onDatabase(auth.Engineer),
	"explain-database-query":      onDatabase(auth.Engineer),
	"update-database":             onDatabase(auth.Owner),
	"delete-database":             onDatabase(auth.Owner),
	"reveal-database-credentials": onDatabase(auth.Owner),

	// Data explorer: the data itself, so Engineer to read (like Explain);
	// a run that may write is an Owner's. Saved queries: your own, or a
	// shared one as Owner (inside).
	"get-database-explorer":       onDatabase(auth.Engineer),
	"describe-database-object":    onDatabase(auth.Engineer),
	"list-database-rows":          onDatabase(auth.Engineer),
	"get-database-key":            onDatabase(auth.Engineer),
	"run-database-query":          onDatabase(auth.Engineer),
	"run-database-change":         onDatabase(auth.Owner),
	"list-database-query-runs":    onDatabase(auth.Engineer),
	"list-database-saved-queries": onDatabase(auth.Engineer),
	"create-database-saved-query": onDatabase(auth.Engineer),
	"update-database-saved-query": onDatabase(auth.Engineer),
	"delete-database-saved-query": onDatabase(auth.Engineer),
	"edit-database-rows":          onDatabase(auth.Owner),
	"list-database-saved-views":   onDatabase(auth.Engineer),
	"create-database-saved-view":  onDatabase(auth.Engineer),
	"update-database-saved-view":  onDatabase(auth.Engineer),
	"delete-database-saved-view":  onDatabase(auth.Engineer),

	// Backups: a plan and its login are an Owner's; starting and checking one
	// an Operator's. A backup is the whole database, so downloading or
	// deleting one is an Owner's too (and the storage is checked inside).
	// Restoring writes over a database, so it's an Owner's, with Engineer on
	// the server it runs on and Operator on the storage it reads (checked inside).
	"list-database-backup-problems": active,
	"get-database-backup-options":   onDatabase(auth.Owner),
	"list-database-backup-plans":    onDatabase(auth.Viewer),
	"get-database-backup-plan":      onBackupPlan(auth.Viewer),
	"list-database-backups":         onDatabase(auth.Viewer),
	"list-database-restores":        onDatabase(auth.Viewer),
	"inspect-database-restore-file": onDatabase(auth.Owner),
	"restore-database-file":         onDatabase(auth.Owner),
	"create-database-backup-plan":   onDatabase(auth.Owner),
	"update-database-backup-plan":   onBackupPlan(auth.Owner),
	"delete-database-backup-plan":   onBackupPlan(auth.Owner),
	"run-database-backup-plan":      onBackupPlan(auth.Operator),
	"get-database-backup":           onBackup(auth.Viewer),
	"cancel-database-backup":        onBackup(auth.Operator),
	"verify-database-backup":        onBackup(auth.Operator),
	"download-database-backup":      onBackup(auth.Owner),
	"delete-database-backup":        onBackup(auth.Owner),
	"restore-database-backup":       onBackup(auth.Owner),
	// Continuous backup: changes also need Engineer on the server (the
	// handler checks); backups and checks are Operator, like a plan's run.
	"get-database-pitr":               onDatabase(auth.Viewer),
	"refresh-database-pitr":           onDatabase(auth.Viewer),
	"list-database-pitr-runs":         onDatabase(auth.Viewer),
	"backup-database-pitr":            onDatabase(auth.Operator),
	"check-database-pitr":             onDatabase(auth.Operator),
	"detect-database-pitr":            onDatabase(auth.Owner),
	"save-database-pitr":              onDatabase(auth.Owner),
	"resetup-database-pitr":           onDatabase(auth.Owner),
	"restart-database-pitr":           onDatabase(auth.Owner),
	"cancel-database-pitr-restart":    onDatabase(auth.Owner),
	"restore-database-pitr":           onDatabase(auth.Owner),
	"teardown-database-pitr-copy":     onDatabase(auth.Owner),
	"reveal-database-pitr-passphrase": onDatabase(auth.Owner),
	"remove-database-pitr":            onDatabase(auth.Owner),

	// Database syncs: the lower of the two databases' levels counts. Seeing
	// one = Viewer, running or comparing = Operator, saving = Owner (it
	// writes over the target). A server runner needs Engineer (inside).
	"list-database-syncs":       onWorkspace(auth.Viewer),
	"create-database-sync":      onWorkspace(auth.Viewer),
	"list-database-sync-plans":  onDatabase(auth.Viewer),
	"list-database-sync-tables": onDatabase(auth.Operator),
	"get-database-sync":         onDatabaseSync(auth.Viewer),
	"update-database-sync":      onDatabaseSync(auth.Operator),
	"pause-database-sync":       onDatabaseSync(auth.Operator),
	"delete-database-sync":      onDatabaseSync(auth.Operator),
	"run-database-sync":         onDatabaseSync(auth.Operator),
	"list-database-sync-runs":   onDatabaseSync(auth.Viewer),
	"get-database-sync-run":     onDatabaseSyncRun(auth.Viewer),
	"cancel-database-sync-run":  onDatabaseSyncRun(auth.Operator),

	// Jobs: everyone sees their own, admins all.
	"list-jobs": active,
	// Ansible. Starting a run also needs Owner on every chosen server, checked
	// in the handler: a playbook can do anything on them.
	"get-ansible-status":      active,
	"list-ansible-modules":    active,
	"get-ansible-module":      active,
	"list-playbooks":          onWorkspace(auth.Viewer),
	"create-playbook":         onWorkspace(auth.Engineer),
	"get-playbook":            onPlaybook(auth.Viewer),
	"update-playbook":         onPlaybook(auth.Engineer),
	"delete-playbook":         onPlaybook(auth.Engineer),
	"preview-ansible-targets": onWorkspace(auth.Viewer),
	"start-ansible-run":       onWorkspace(auth.Viewer),
	"list-ansible-runs":       onWorkspace(auth.Operator),
	"get-ansible-run":         onAnsibleRun(auth.Operator),
	"stream-ansible-run":      onAnsibleRun(auth.Operator),
	"cancel-ansible-run":      onAnsibleRun(auth.Engineer),
	"delete-ansible-run":      onAnsibleRun(auth.Engineer),
	// Cron jobs (Morche's own schedules). Saving one also needs Operator on
	// the source and Engineer on every destination, checked in the handler.
	"list-schedules":       onWorkspace(auth.Viewer),
	"preview-schedule":     active,
	"create-schedule":      onWorkspace(auth.Engineer),
	"get-schedule":         onSchedule(auth.Viewer),
	"update-schedule":      onSchedule(auth.Engineer),
	"set-schedule-enabled": onSchedule(auth.Engineer),
	"delete-schedule":      onSchedule(auth.Engineer),
	"run-schedule":         onSchedule(auth.Operator),
	"list-schedule-runs":   onSchedule(auth.Viewer),
	"get-schedule-run":     onScheduleRun(auth.Viewer),
	"cancel-schedule-run":  onScheduleRun(auth.Operator),
	"delete-schedule-run":  onScheduleRun(auth.Engineer),

	// Storage migrations and syncs. Saving one also needs Operator on the
	// source and Engineer on the destination (Owner on both for MinIO
	// replication), checked in the handler.
	"list-storage-syncs":              onWorkspace(auth.Viewer),
	"create-storage-sync":             onWorkspace(auth.Engineer),
	"get-storage-sync":                onStorageSync(auth.Viewer),
	"update-storage-sync":             onStorageSync(auth.Engineer),
	"pause-storage-sync":              onStorageSync(auth.Engineer),
	"delete-storage-sync":             onStorageSync(auth.Engineer),
	"run-storage-sync":                onStorageSync(auth.Operator),
	"list-storage-sync-runs":          onStorageSync(auth.Viewer),
	"get-storage-sync-replication":    onStorageSync(auth.Viewer),
	"resync-storage-sync-replication": onStorageSync(auth.Operator),
	"get-storage-sync-run":            onStorageSyncRun(auth.Viewer),
	"cancel-storage-sync-run":         onStorageSyncRun(auth.Operator),
	"restart-storage-sync-watch":      onStorageSync(auth.Operator),
	"raise-storage-sync-watch-limit":  onStorageSync(auth.Engineer),

	"get-job":     active,
	"cancel-job":  active,
	"retry-job":   active,
	"delete-job":  active,
	"clear-jobs":  active,
	"stream-jobs": active,

	// Uptime monitors.
	"list-monitors":                active,
	"create-monitor":               active,
	"test-monitor-settings":        active,
	"get-monitor":                  onMonitor(auth.Viewer),
	"update-monitor":               onMonitor(auth.Engineer),
	"delete-monitor":               onMonitor(auth.Owner),
	"check-monitor":                onMonitor(auth.Operator),
	"pause-monitor":                onMonitor(auth.Operator),
	"get-monitor-report":           onMonitor(auth.Viewer),
	"list-monitor-checks":          onMonitor(auth.Viewer),
	"list-monitor-events":          onMonitor(auth.Viewer),
	"list-monitor-incidents":       onMonitor(auth.Viewer),
	"list-incidents":               active,
	"acknowledge-monitor-incident": onMonitorIncident(auth.Operator),
	"push-heartbeat":               public,
	"push-heartbeat-post":          public,
	"docker-git-webhook":           public,
	"automation-hook":              public,
	"docker-auto-update-webhook":   public,

	// Notification channels.
	"list-notification-channels":  active,
	"create-notification-channel": active,
	"test-notification-settings":  active,
	"get-notification-channel":    onNotificationChannel(auth.Viewer),
	"update-notification-channel": onNotificationChannel(auth.Owner),
	"delete-notification-channel": onNotificationChannel(auth.Owner),
	"test-notification-channel":   onNotificationChannel(auth.Owner),
	"list-notification-log":       onNotificationChannel(auth.Viewer),
	"list-alert-rules":            active,
	"create-alert-rule":           active,
	"preview-alert-rule":          active,
	"list-alert-events":           active,
	"get-alert-rule":              onAlertRule(auth.Viewer),
	"update-alert-rule":           onAlertRule(auth.Engineer),
	"set-alert-rule-enabled":      onAlertRule(auth.Engineer),
	"delete-alert-rule":           onAlertRule(auth.Engineer),
	"list-alert-mutes":            active,
	"create-alert-mute":           active,
	"delete-alert-mute":           active,
}
