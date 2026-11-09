package api

import "github.com/morcheh/backend/internal/auth"

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
	// A workspace level, on the workspace of the DNS server in {id}.
	kindDNSServer
	// A workspace level, on the workspace of the saved script in {id}.
	kindScript
	// The server level on the server the proxy in {id} runs on.
	kindProxy
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
func onDNSServer(l auth.Level) policy   { return policy{kindDNSServer, l} }
func onScript(l auth.Level) policy      { return policy{kindScript, l} }
func onProxy(l auth.Level) policy       { return policy{kindProxy, l} }

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

	// Signing in.
	"get-auth-state":  public,
	"auth-setup":      public,
	"auth-register":   public,
	"auth-login":      public,
	"auth-logout":     session,
	"auth-logout-all": session,
	"get-me":          session,
	"change-password": session,
	"update-me":       active,
	"get-my-access":   active,

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

	// Terminal recordings. Lists filter to the caller's own below Owner; one
	// recording is the caller's own or an Owner's (checked inside).
	"get-recording-settings":    onWorkspace(auth.Viewer),
	"set-recording-settings":    onWorkspace(auth.Owner),
	"list-workspace-recordings": active,
	"list-server-recordings":    onServer(auth.Viewer),
	"get-recording":             active,
	"get-recording-cast":        active,
	"delete-recording":          active,

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

	// Reverse proxies
	"list-proxy-kinds":                   active,
	"list-proxies":                       active,
	"list-proxy-hosts-everywhere":        active,
	"get-proxy-traffic":                  active,
	"create-proxy":                       active, // Engineer on the server, checked by the handler
	"get-proxy":                          onProxy(auth.Viewer),
	"inspect-proxy":                      onProxy(auth.Viewer),
	"delete-proxy":                       onProxy(auth.Owner),
	"setup-proxy":                        onProxy(auth.Engineer),
	"setup-proxy-geo":                    onProxy(auth.Engineer),
	"proxy-action":                       onProxy(auth.Operator), // stop needs Engineer
	"preview-proxy-host":                 onProxy(auth.Viewer),
	"create-proxy-host":                  onProxy(auth.Engineer),
	"test-proxy-host":                    onProxy(auth.Engineer),
	"test-proxy-upstream":                onProxy(auth.Engineer),
	"update-proxy-host":                  onProxy(auth.Engineer),
	"set-proxy-host-enabled":             onProxy(auth.Engineer),
	"delete-proxy-host":                  onProxy(auth.Engineer),
	"get-proxy-logs":                     onProxy(auth.Operator),
	"purge-proxy-host-cache":             onProxy(auth.Operator),
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
	// Cron jobs (Morcheh's own schedules). Saving one also needs Operator on
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

	"get-job":     active,
	"cancel-job":  active,
	"retry-job":   active,
	"delete-job":  active,
	"clear-jobs":  active,
	"stream-jobs": active,
}
