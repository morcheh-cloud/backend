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
	// A level on the server, storage, workspace or database in the path's {id}.
	kindServer
	kindStorage
	kindWorkspace
	kindDatabase
)

type policy struct {
	kind  policyKind
	level auth.Level
}

func onServer(l auth.Level) policy    { return policy{kindServer, l} }
func onStorage(l auth.Level) policy   { return policy{kindStorage, l} }
func onWorkspace(l auth.Level) policy { return policy{kindWorkspace, l} }
func onDatabase(l auth.Level) policy  { return policy{kindDatabase, l} }

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
	"list-grants":      active,
	"set-grant":        active,
	"delete-grant":     active,
	"list-principals":  active,

	// Servers. Lists filter themselves, bulk actions check every id.
	"list-servers":              active,
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

	"get-power":    onServer(auth.Viewer),
	"power-action": onServer(auth.Operator),
	"cancel-power": onServer(auth.Operator),

	// Storages.
	"list-storages":              active,
	"create-storage":             active,
	"test-storage-connection":    active,
	"get-storage":                onStorage(auth.Viewer),
	"update-storage":             onStorage(auth.Owner),
	"delete-storage":             onStorage(auth.Owner),
	"reveal-storage-credentials": onStorage(auth.Owner),
	"set-storage-favorite":       onStorage(auth.Operator),
	"check-storage":              onStorage(auth.Operator),

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
	"transfer-files":         active,

	// Databases: a database's level is its workspace's, or that of the
	// server it's reached through when higher.
	"list-databases":              active,
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

	// Jobs: everyone sees their own, admins all.
	"list-jobs":   active,
	"get-job":     active,
	"cancel-job":  active,
	"retry-job":   active,
	"delete-job":  active,
	"clear-jobs":  active,
	"stream-jobs": active,
}
