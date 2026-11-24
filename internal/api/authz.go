package api

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/cache"
	"github.com/morche/backend/internal/cmdlog"
	"github.com/morche/backend/internal/config"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/events"
	"github.com/morche/backend/internal/jobs"
	"github.com/morche/backend/internal/terminal"
)

const (
	sessionCookie   = "morche_session"
	workspaceHeader = "X-Workspace-Id"

	sessionTTL  = 12 * time.Hour
	rememberTTL = 30 * 24 * time.Hour
)

// principal is who is making a request and what they can reach.
type principal struct {
	User      sqlc.User
	SessionID uuid.UUID
	// TokenID is the API token the request came with (uuid.Nil = a session
	// cookie); TokenName is that token's name, for the command log.
	TokenID   uuid.UUID
	TokenName string
	Access    *auth.Access
	// Workspace is the one open in the panel (X-Workspace-Id): it narrows lists
	// and says where new servers go. It grants nothing.
	Workspace *uuid.UUID
	// Level is what they have on the server, storage or workspace in the path.
	Level auth.Level
}

func (p *principal) ID() *uuid.UUID { return &p.User.ID }

type principalKey struct{}

// principalOf returns the caller. Every operation except the public ones has
// one, because the middleware put it there; nil means an internal call.
func principalOf(ctx context.Context) *principal {
	p, _ := ctx.Value(principalKey{}).(*principal)
	return p
}

// client is where a request came from, for sessions and rate limits.
type client struct{ ip, userAgent string }

type clientKey struct{}

func clientOf(ctx context.Context) client {
	c, _ := ctx.Value(clientKey{}).(client)
	return c
}

// authz decides who gets in. Everything that changes what someone may do calls
// invalidate, which re-checks open streams and terminals.
type authz struct {
	cfg    *config.Config
	db     *pgxpool.Pool
	q      *sqlc.Queries
	rdb    *cache.Cache
	runner *jobs.Runner
	terms  *terminal.Manager

	mu       sync.Mutex
	watchers map[*watcher]struct{}
	dirty    chan struct{}

	// allow is the address allowlist in force (nil until first read).
	allow atomic.Pointer[allowlist]
	// up sends security alerts through the notification channels. Set by build.
	up *uptimeHandler
	// pruned is when old sign-ins were last deleted (only the sweep touches it).
	pruned time.Time
	// events is the panel's event bus (internal/events): every handler reaches
	// it as <handler>.authz.events. Set by build; nil drops events.
	events *events.Bus
	// panelURL is where the panel is served ("" = unknown), for links in events.
	panelURL string
}

func newAuthz(cfg *config.Config, db *pgxpool.Pool, rdb *cache.Cache, runner *jobs.Runner, terms *terminal.Manager) *authz {
	a := &authz{
		cfg: cfg, db: db, q: sqlc.New(db), rdb: rdb, runner: runner, terms: terms,
		watchers: map[*watcher]struct{}{},
		dirty:    make(chan struct{}, 1),
	}
	go a.watch()
	return a
}

// denied is why a request can't go on.
type denied struct {
	status  int
	message string
}

func (d *denied) Error() string { return d.message }

func errUnauthenticated() *denied {
	return &denied{http.StatusUnauthorized, "Sign in to continue."}
}

// middleware is the one gate every operation passes. An operation without a
// policy is refused, so a new endpoint can't be left open by forgetting.
func (a *authz) middleware(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		base := context.WithValue(ctx.Context(), clientKey{}, client{
			ip: hostOf(ctx.RemoteAddr()), userAgent: truncate(ctx.Header("User-Agent"), 256),
		})
		op := ctx.Operation().OperationID
		pol, ok := policies[op]
		if !ok {
			slog.Error("operation has no access policy", "operation", op)
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "This action isn't available.")
			return
		}
		token, bearer := "", ""
		if c, err := huma.ReadCookie(ctx, sessionCookie); err == nil {
			token = c.Value
		}
		// An API token counts only without a session cookie, so a browser
		// session is never mixed with a token.
		if token == "" {
			bearer = bearerToken(ctx.Header("Authorization"))
		}
		// Without a session there's nothing to reach, whatever the address:
		// answer that first, so the address check never waits on the database.
		if pol.kind != kindPublic && token == "" && bearer == "" {
			d := errUnauthenticated()
			_ = huma.WriteErr(api, ctx, d.status, d.message)
			return
		}
		if !allowlistExempt[op] {
			if d := a.addressRefused(base, clientOf(base).ip); d != nil {
				if op == "auth-login" && d.status == http.StatusForbidden {
					a.noteRefusedSignIn(base)
				}
				writeAddressRefused(api, ctx, d)
				return
			}
		}
		if pol.kind == kindPublic {
			if a.demoRefuses(op, nil) {
				_ = huma.WriteErr(api, ctx, http.StatusForbidden, demoRefusal)
				return
			}
			next(huma.WithContext(ctx, base))
			return
		}
		var p *principal
		var d *denied
		if token != "" {
			p, d = a.authorize(base, token, pol, ctx.Param("id"), ctx.Header(workspaceHeader))
		} else {
			p, d = a.authorizeToken(base, bearer, op, ctx.Operation().Method, pol, ctx.Param("id"), ctx.Header(workspaceHeader))
		}
		if d != nil {
			_ = huma.WriteErr(api, ctx, d.status, d.message)
			return
		}
		if a.demoRefuses(op, p) {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, demoRefusal)
			return
		}
		withP := context.WithValue(base, principalKey{}, p)
		withP = cmdlog.With(withP, requestOrigin(ctx, p, a.loggedIP(p, hostOf(ctx.RemoteAddr()))))
		watched, stop := a.track(withP, p, pol, ctx.Param("id"))
		defer stop()
		next(huma.WithContext(ctx, watched))
	}
}

// requestOrigin says, for the command log, that commands run while handling
// this request are for p: a read on GET, otherwise a change.
func requestOrigin(ctx huma.Context, p *principal, ip string) cmdlog.Origin {
	op := ctx.Operation()
	kind := cmdlog.Change
	if op.Method == http.MethodGet || op.Method == http.MethodHead {
		kind = cmdlog.Read
	}
	source := cmpOr(op.Summary, op.OperationID)
	if p.TokenID != uuid.Nil {
		source = "API token " + p.TokenName + ": " + source
	}
	return cmdlog.Origin{
		Kind: kind, Source: source,
		UserID: &p.User.ID, ClientIP: ip,
	}
}

// authorize is the whole check, shared with the terminal WebSocket.
func (a *authz) authorize(ctx context.Context, token string, pol policy, rawID, workspace string) (*principal, *denied) {
	if token == "" {
		return nil, errUnauthenticated()
	}
	row, err := a.q.GetSessionByHash(ctx, auth.HashToken(token))
	if isNotFound(err) {
		return nil, errUnauthenticated()
	}
	if err != nil {
		slog.Error("load session", "error", err)
		return nil, &denied{http.StatusInternalServerError, "internal error"}
	}
	u := row.User
	if u.Status == "blocked" {
		return nil, errUnauthenticated()
	}
	if time.Since(row.Session.LastSeenAt) > time.Minute {
		if err := a.q.TouchSession(ctx, row.Session.ID); err != nil {
			slog.Warn("touch session", "error", err)
		}
	}
	p := &principal{User: u, SessionID: row.Session.ID}
	if id, err := uuid.Parse(workspace); err == nil {
		p.Workspace = &id
	}
	return a.authorizeAs(ctx, p, pol, rawID)
}

// authorizeAs is the part of the check shared by sessions and API tokens:
// p's user is known and not blocked.
func (a *authz) authorizeAs(ctx context.Context, p *principal, pol policy, rawID string) (*principal, *denied) {
	u := p.User
	if pol.kind == kindSession {
		return p, nil
	}
	if u.Status != "active" {
		return nil, &denied{http.StatusForbidden, "Your account is waiting for approval."}
	}
	if u.MustChangePassword {
		return nil, &denied{http.StatusForbidden, "Change your password to continue."}
	}
	var err error
	if p.Access, err = a.accessOf(ctx, u); err != nil {
		slog.Error("load access", "error", err)
		return nil, &denied{http.StatusInternalServerError, "internal error"}
	}
	if p.Level, err = a.check(ctx, pol, p.Access, rawID); err != nil {
		d, ok := err.(*denied)
		if !ok {
			slog.Error("check access", "error", err)
			return nil, &denied{http.StatusInternalServerError, "internal error"}
		}
		return nil, d
	}
	return p, nil
}

func (a *authz) accessOf(ctx context.Context, u sqlc.User) (*auth.Access, error) {
	grants, err := a.q.ListUserGrants(ctx, &u.ID)
	if err != nil {
		return nil, err
	}
	return auth.NewAccess(u.Role == "admin", grants), nil
}

// check applies a policy to someone's access. A resource they have no access
// to answers 404, not 403: they shouldn't learn it exists.
func (a *authz) check(ctx context.Context, pol policy, acc *auth.Access, rawID string) (auth.Level, error) {
	switch pol.kind {
	case kindActive:
		return auth.None, nil
	case kindAdmin:
		if !acc.Admin {
			return auth.None, &denied{http.StatusForbidden, "Only a system admin can do this."}
		}
		return auth.Owner, nil
	}

	noun := map[policyKind]string{kindServer: "server", kindStorage: "storage", kindWorkspace: "workspace", kindDatabase: "database", kindBackupPlan: "backup plan", kindBackup: "backup", kindApp: "service", kindPlaybook: "playbook", kindAnsibleRun: "run", kindSchedule: "cron job", kindScheduleRun: "run", kindStorageSync: "sync", kindStorageSyncRun: "run", kindDatabaseSync: "sync", kindDatabaseSyncRun: "run", kindDNSServer: "DNS server", kindScript: "script", kindProxy: "proxy", kindSoftwareRecipe: "application", kindSoftwareInstall: "application", kindMonitor: "monitor", kindNotificationChannel: "channel", kindMonitorIncident: "incident", kindAlertRule: "alert rule", kindPVECluster: "cluster", kindCloudAccount: "cloud account", kindAsset: "asset", kindWebhook: "webhook", kindWebhookDelivery: "delivery", kindAutomation: "automation", kindAutomationRun: "run", kindPackageRegistry: "registry", kindTunnel: "tunnel"}[pol.kind]
	missing := &denied{http.StatusNotFound, noun + " not found"}
	id, err := uuid.Parse(rawID)
	if err != nil {
		return auth.None, missing
	}
	var level auth.Level
	switch pol.kind {
	case kindServer:
		ws, err := a.q.GetServerWorkspace(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.ServerLevel(ws, id)
	case kindStorage:
		ws, err := a.q.GetStorageWorkspace(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.StorageLevel(ws, id)
	case kindWorkspace:
		if _, err := a.q.GetWorkspace(ctx, id); isNotFound(err) {
			return auth.None, missing
		} else if err != nil {
			return auth.None, err
		}
		level = acc.WorkspaceLevel(id)
	case kindDatabase:
		d, err := a.q.GetDatabaseWorkspace(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = databaseLevel(acc, d.WorkspaceID, d.ServerID)
	case kindBackupPlan, kindBackup:
		var dbID uuid.UUID
		if pol.kind == kindBackupPlan {
			dbID, err = a.q.GetBackupPlanDatabase(ctx, id)
		} else {
			dbID, err = a.q.GetBackupDatabase(ctx, id)
		}
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		d, err := a.q.GetDatabaseWorkspace(ctx, dbID)
		if err != nil {
			return auth.None, err
		}
		level = databaseLevel(acc, d.WorkspaceID, d.ServerID)
	case kindApp:
		ws, err := a.q.GetAppWorkspace(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.AppLevel(ws, id)
	case kindDNSServer:
		ws, err := a.q.GetDNSServerWorkspace(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.WorkspaceLevel(ws)
	case kindTunnel:
		ws, err := a.q.GetTunnelWorkspace(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.WorkspaceLevel(ws)
	case kindCloudAccount:
		ws, err := a.q.GetCloudAccountWorkspace(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.WorkspaceLevel(ws)
	case kindPVECluster:
		ws, err := a.q.GetPVEClusterWorkspace(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.WorkspaceLevel(ws)
	case kindProxy:
		r, err := a.q.GetProxyServer(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.ServerLevel(r.WorkspaceID, r.ID)
	case kindPackageRegistry:
		r, err := a.q.GetPackageRegistryServer(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.ServerLevel(r.WorkspaceID, r.ID)
	case kindSoftwareRecipe:
		ws, err := a.q.GetSoftwareRecipeWorkspace(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.WorkspaceLevel(ws)
	case kindSoftwareInstall:
		r, err := a.q.GetSoftwareInstallServer(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.ServerLevel(r.WorkspaceID, r.ServerID)
	case kindMonitor, kindNotificationChannel, kindMonitorIncident, kindAlertRule:
		var ws uuid.UUID
		switch pol.kind {
		case kindAlertRule:
			ws, err = a.q.GetAlertRuleWorkspace(ctx, id)
		case kindMonitor:
			ws, err = a.q.GetMonitorWorkspace(ctx, id)
		case kindNotificationChannel:
			ws, err = a.q.GetNotificationChannelWorkspace(ctx, id)
		default:
			var inc sqlc.MonitorIncident
			inc, err = a.q.GetMonitorIncident(ctx, id)
			if err == nil {
				ws, err = a.q.GetMonitorWorkspace(ctx, inc.MonitorID)
			}
		}
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.WorkspaceLevel(ws)
	case kindAutomation, kindAutomationRun:
		get := a.q.GetAutomationWorkspace
		if pol.kind == kindAutomationRun {
			get = a.q.GetAutomationRunWorkspace
		}
		ws, err := get(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.WorkspaceLevel(ws)
	case kindWebhook, kindWebhookDelivery:
		get := a.q.GetWebhookWorkspace
		if pol.kind == kindWebhookDelivery {
			get = a.q.GetWebhookDeliveryWorkspace
		}
		ws, err := get(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.WorkspaceLevel(ws)
	case kindAsset:
		ws, err := a.q.GetAssetWorkspace(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.WorkspaceLevel(ws)
	case kindScript:
		ws, err := a.q.GetScriptWorkspace(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.WorkspaceLevel(ws)
	case kindPlaybook:
		ws, err := a.q.GetPlaybookWorkspace(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.WorkspaceLevel(ws)
	case kindAnsibleRun:
		ws, err := a.q.GetAnsibleRunWorkspace(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.WorkspaceLevel(ws)
	case kindSchedule, kindScheduleRun:
		get := a.q.GetScheduleWorkspace
		if pol.kind == kindScheduleRun {
			get = a.q.GetScheduleRunWorkspace
		}
		ws, err := get(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.WorkspaceLevel(ws)
	case kindStorageSync, kindStorageSyncRun:
		get := a.q.GetStorageSyncWorkspace
		if pol.kind == kindStorageSyncRun {
			get = a.q.GetStorageSyncRunWorkspace
		}
		ws, err := get(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = acc.WorkspaceLevel(ws)
	case kindDatabaseSync, kindDatabaseSyncRun:
		get := a.q.GetDatabaseSyncEnds
		if pol.kind == kindDatabaseSyncRun {
			get = func(ctx context.Context, id uuid.UUID) (sqlc.GetDatabaseSyncEndsRow, error) {
				e, err := a.q.GetDatabaseSyncRunEnds(ctx, id)
				return sqlc.GetDatabaseSyncEndsRow(e), err
			}
		}
		e, err := get(ctx, id)
		if isNotFound(err) {
			return auth.None, missing
		}
		if err != nil {
			return auth.None, err
		}
		level = syncLevel(acc, e)
	default:
		return auth.None, &denied{http.StatusForbidden, "This action isn't available."}
	}
	if level == auth.None {
		return level, missing
	}
	if level < pol.level {
		return level, needLevel(pol.level)
	}
	return level, nil
}

func needLevel(l auth.Level) *denied {
	return &denied{http.StatusForbidden, "You need " + l.String() + " access for this."}
}

// forbidden is needLevel as a handler's error.
func forbidden(l auth.Level) error {
	return huma.Error403Forbidden("You need " + l.String() + " access for this.")
}

// serverLevel is the caller's level on one server (0 when it doesn't exist).
func (a *authz) serverLevel(ctx context.Context, acc *auth.Access, id uuid.UUID) (auth.Level, error) {
	ws, err := a.q.GetServerWorkspace(ctx, id)
	if isNotFound(err) {
		return auth.None, nil
	}
	if err != nil {
		return auth.None, err
	}
	return acc.ServerLevel(ws, id), nil
}

// databaseLevel is what someone has on a database: its workspace's level, or
// the level on the server it goes through when that's higher (whoever runs the
// server may watch what runs on it).
func databaseLevel(acc *auth.Access, workspace uuid.UUID, server *uuid.UUID) auth.Level {
	l := acc.WorkspaceLevel(workspace)
	if server != nil {
		l = max(l, acc.ServerLevel(workspace, *server))
	}
	return l
}

// syncLevel is the lower of the levels on a database sync's two ends.
func syncLevel(acc *auth.Access, e sqlc.GetDatabaseSyncEndsRow) auth.Level {
	return min(databaseLevel(acc, e.SourceWorkspaceID, e.SourceServerID), databaseLevel(acc, e.TargetWorkspaceID, e.TargetServerID))
}

// storageLevel is the caller's level on one storage (0 when it doesn't exist).
func (a *authz) storageLevel(ctx context.Context, acc *auth.Access, id uuid.UUID) (auth.Level, error) {
	ws, err := a.q.GetStorageWorkspace(ctx, id)
	if isNotFound(err) {
		return auth.None, nil
	}
	if err != nil {
		return auth.None, err
	}
	return acc.StorageLevel(ws, id), nil
}

// ---- What a list may show ----

// scope is the part of the tables someone may see.
type scope struct {
	seeAll     bool
	workspaces []uuid.UUID
	servers    []uuid.UUID
	storages   []uuid.UUID
	apps       []uuid.UUID
	current    *uuid.UUID
}

func (p *principal) scope() scope {
	s := scope{
		seeAll:     p.Access.Admin,
		workspaces: []uuid.UUID{},
		servers:    []uuid.UUID{},
		storages:   []uuid.UUID{},
		apps:       []uuid.UUID{},
		current:    p.Workspace,
	}
	for id := range p.Access.Workspaces {
		s.workspaces = append(s.workspaces, id)
	}
	for id := range p.Access.Servers {
		s.servers = append(s.servers, id)
	}
	for id := range p.Access.Storages {
		s.storages = append(s.storages, id)
	}
	for id := range p.Access.Apps {
		s.apps = append(s.apps, id)
	}
	return s
}

// createTarget is the workspace new things go in: the one open in the panel, or
// the only one they can add to. They must be allowed to add there.
func (a *authz) createTarget(ctx context.Context, p *principal) (uuid.UUID, error) {
	if p.Workspace != nil {
		if _, err := a.q.GetWorkspace(ctx, *p.Workspace); isNotFound(err) {
			return uuid.Nil, huma.Error404NotFound("workspace not found")
		} else if err != nil {
			return uuid.Nil, internalError(err)
		}
		if !p.Access.CanCreateIn(*p.Workspace) {
			return uuid.Nil, huma.Error403Forbidden("You can't add servers, storage or services to this workspace.")
		}
		return *p.Workspace, nil
	}
	var can []uuid.UUID
	if p.Access.Admin {
		list, err := a.q.ListWorkspaces(ctx)
		if err != nil {
			return uuid.Nil, internalError(err)
		}
		for _, w := range list {
			can = append(can, w.ID)
		}
	} else {
		for id, w := range p.Access.Workspaces {
			if w.CanCreate {
				can = append(can, id)
			}
		}
	}
	switch len(can) {
	case 0:
		return uuid.Nil, huma.Error403Forbidden("You can't add servers, storage or services.")
	case 1:
		return can[0], nil
	}
	return uuid.Nil, huma.Error422UnprocessableEntity("Choose a workspace first (" + workspaceHeader + " header).")
}

// requireServers checks a bulk action: they need the level on every server, and
// get back where each one lives. Ids that don't exist are ignored for admins and
// look like any other server they can't reach for everyone else.
func (a *authz) requireServers(ctx context.Context, ids []uuid.UUID, need auth.Level) (map[uuid.UUID]uuid.UUID, error) {
	acc := principalOf(ctx).Access
	rows, err := a.q.ListServerWorkspaces(ctx, ids)
	if err != nil {
		return nil, internalError(err)
	}
	where := make(map[uuid.UUID]uuid.UUID, len(rows))
	for _, r := range rows {
		where[r.ID] = r.WorkspaceID
	}
	for _, id := range ids {
		ws, ok := where[id]
		if !ok {
			if acc.Admin {
				continue
			}
			return nil, huma.Error404NotFound("server not found")
		}
		switch level := acc.ServerLevel(ws, id); {
		case level == auth.None:
			return nil, huma.Error404NotFound("server not found")
		case level < need:
			return nil, forbidden(need)
		}
	}
	return where, nil
}

// grantCreator keeps whoever adds a server, storage or app able to manage it,
// when their workspace level alone wouldn't let them.
func grantCreator(ctx context.Context, q *sqlc.Queries, p *principal, ws uuid.UUID, server, storage, app *uuid.UUID) error {
	if p.Access.Admin || p.Access.WorkspaceLevel(ws) >= auth.Owner {
		return nil
	}
	_, err := q.UpsertGrant(ctx, sqlc.UpsertGrantParams{
		UserID: p.ID(), ServerID: server, StorageID: storage, AppID: app, Level: auth.Owner.String(),
	})
	return err
}

// ---- Cutting off what's already open ----

// watcher is one request in flight. A stream or terminal outlives the check it
// passed, so these are re-checked whenever access changes.
type watcher struct {
	p      *principal
	pol    policy
	rawID  string
	ip     string
	cancel context.CancelFunc
}

// track makes ctx end as soon as this request isn't allowed any more.
func (a *authz) track(ctx context.Context, p *principal, pol policy, rawID string) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	w := &watcher{p: p, pol: pol, rawID: rawID, ip: clientOf(ctx).ip, cancel: cancel}
	a.mu.Lock()
	a.watchers[w] = struct{}{}
	a.mu.Unlock()
	return ctx, func() {
		a.mu.Lock()
		delete(a.watchers, w)
		a.mu.Unlock()
		cancel()
	}
}

// invalidate re-checks everything open, soon. Call it after any change to who
// can do what.
func (a *authz) invalidate() {
	select {
	case a.dirty <- struct{}{}:
	default:
	}
}

func (a *authz) watch() {
	// The tick catches sessions that simply expired.
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-a.dirty:
		case <-t.C:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		a.sweep(ctx)
		cancel()
	}
}

// sweep re-checks every open request and terminal. A failed lookup leaves
// things as they are: the next one tries again, and a database hiccup shouldn't
// close everyone's terminals.
func (a *authz) sweep(ctx context.Context) {
	if err := a.q.DeleteExpiredSessions(ctx); err != nil {
		slog.Warn("delete expired sessions", "error", err)
	}
	if time.Since(a.pruned) > time.Hour {
		if !logOwned("sign-ins") {
			if err := a.q.DeleteOldSignIns(ctx, signInKeepDays); err != nil {
				slog.Warn("delete old sign-ins", "error", err)
			} else {
				a.pruned = time.Now()
			}
		}
	}
	// Picks up a change made from the command line, and cuts off streams
	// from an address that's no longer allowed.
	allow, err := a.reloadAllowlist(ctx)
	if err != nil {
		slog.Warn("reload the allowlist", "error", err)
		allow = a.allow.Load()
	}

	a.mu.Lock()
	open := make([]*watcher, 0, len(a.watchers))
	for w := range a.watchers {
		open = append(open, w)
	}
	a.mu.Unlock()

	access := map[uuid.UUID]*auth.Access{}
	accessOf := func(u sqlc.User) (*auth.Access, error) {
		if acc, ok := access[u.ID]; ok {
			return acc, nil
		}
		acc, err := a.accessOf(ctx, u)
		if err == nil {
			access[u.ID] = acc
		}
		return acc, err
	}

	for _, w := range open {
		if allow != nil && !allow.allows(w.ip) {
			w.cancel()
			continue
		}
		var u sqlc.User
		if w.p.TokenID != uuid.Nil {
			// Revoked or expired since it was opened: the stream ends.
			row, err := a.q.GetApiTokenUser(ctx, w.p.TokenID)
			if isNotFound(err) {
				w.cancel()
				continue
			}
			if err != nil {
				slog.Warn("re-check api token", "error", err)
				continue
			}
			u = row.User
		} else {
			row, err := a.q.GetSessionUser(ctx, w.p.SessionID)
			if isNotFound(err) {
				w.cancel()
				continue
			}
			if err != nil {
				slog.Warn("re-check session", "error", err)
				continue
			}
			u = row.User
		}
		if u.Status == "blocked" {
			w.cancel()
			continue
		}
		if w.pol.kind == kindSession {
			continue
		}
		if u.Status != "active" || u.MustChangePassword {
			w.cancel()
			continue
		}
		acc, err := accessOf(u)
		if err != nil {
			slog.Warn("re-check access", "error", err)
			continue
		}
		// The jobs stream filters by this, so losing it ends the stream.
		if w.p.Access.Admin && !acc.Admin {
			w.cancel()
			continue
		}
		if _, err := a.check(ctx, w.pol, acc, w.rawID); err != nil {
			if _, ok := err.(*denied); ok {
				w.cancel()
			} else {
				slog.Warn("re-check access", "error", err)
			}
		}
	}

	for _, s := range a.terms.All() {
		user, _, _ := strings.Cut(s.Owner, "/")
		owner, err := uuid.Parse(user)
		if err != nil {
			s.Kill()
			continue
		}
		u, err := a.q.GetUser(ctx, owner)
		if isNotFound(err) {
			s.Kill()
			continue
		}
		if err != nil {
			slog.Warn("re-check terminal", "error", err)
			continue
		}
		if u.Status != "active" {
			s.Kill()
			continue
		}
		acc, err := accessOf(u)
		if err != nil {
			slog.Warn("re-check terminal", "error", err)
			continue
		}
		if _, err := a.check(ctx, policy{kindServer, auth.Engineer}, acc, s.ServerID); err != nil {
			if _, ok := err.(*denied); ok {
				s.Kill()
			} else {
				slog.Warn("re-check terminal", "error", err)
			}
		}
	}
}

// runningJobs lists someone's unfinished jobs. Read it before deleting them:
// the delete clears who started each job.
func (a *authz) runningJobs(ctx context.Context, id uuid.UUID) []uuid.UUID {
	running, err := a.q.ListActiveJobsBy(ctx, &id)
	if err != nil {
		slog.Warn("list a user's jobs", "error", err)
	}
	return running
}

// dropUser ends what someone left running, when they are blocked or deleted.
func (a *authz) dropUser(ctx context.Context, id uuid.UUID, running []uuid.UUID) {
	a.terms.KillOwner(id.String())
	for _, j := range running {
		// A job in a step that can't be stopped says so; it ends by itself.
		if _, err := a.runner.Cancel(ctx, j); err != nil {
			slog.Warn("cancel a user's job", "job", j, "error", err)
		}
	}
	a.invalidate()
}

// ---- Rate limits ----

// over says whether a counter is already at its limit. Redis being down opens
// the limit rather than locking every admin out of the panel; password hashing
// still throttles guessing.
func (a *authz) over(ctx context.Context, key string, limit int64) bool {
	n, err := a.rdb.Client.Get(ctx, "ratelimit:"+key).Int64()
	if err != nil {
		return false
	}
	return n >= limit
}

// hit counts one attempt and returns the count so far (0 if Redis is down).
func (a *authz) hit(ctx context.Context, key string, window time.Duration) int64 {
	key = "ratelimit:" + key
	n, err := a.rdb.Client.Incr(ctx, key).Result()
	if err != nil {
		slog.Warn("rate limit", "error", err)
		return 0
	}
	if n == 1 {
		a.rdb.Client.Expire(ctx, key, window)
	}
	return n
}

func (a *authz) forget(ctx context.Context, key string) {
	a.rdb.Client.Del(ctx, "ratelimit:"+key)
}

// ForgetLoginLimits clears the sign-in and password counters of one account.
// A counter per address is left alone: it covers everyone behind that address.
func ForgetLoginLimits(ctx context.Context, rdb *cache.Cache, id uuid.UUID, username string) error {
	name := strings.ToLower(username)
	keys := []string{"ratelimit:login:name:" + name, "ratelimit:password:" + id.String()}
	it := rdb.Client.Scan(ctx, 0, "ratelimit:login:pair:"+name+":*", 100).Iterator()
	for it.Next(ctx) {
		keys = append(keys, it.Val())
	}
	if err := it.Err(); err != nil {
		return err
	}
	return rdb.Client.Del(ctx, keys...).Err()
}

func errTooMany() error {
	return huma.NewError(http.StatusTooManyRequests, "Too many attempts. Wait a few minutes and try again.")
}

// ---- CSRF ----

// originGuard refuses state-changing requests from other sites. SameSite=Lax
// already keeps the cookie off them; this is the second lock. Requests without
// an Origin aren't from a browser page, so they carry no ambient cookie.
func originGuard(origins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}
			if o := r.Header.Get("Origin"); o != "" && !originAllowed(o, r.Host, origins) {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func originAllowed(origin, host string, allowed []string) bool {
	if slices.Contains(allowed, "*") || slices.Contains(allowed, origin) {
		return true
	}
	// Same origin: the browser wrote this, and it matches where the request went.
	if _, rest, ok := strings.Cut(origin, "://"); ok && rest == host {
		return true
	}
	for _, a := range allowed {
		if pre, post, ok := strings.Cut(a, "*"); ok && strings.HasPrefix(origin, pre) && strings.HasSuffix(origin, post) {
			return true
		}
	}
	return false
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// baseHeaders go on every answer: the browser never guesses a type from the
// bytes, and no address of the API (ids, paths in query strings) is sent on
// to a site a file or page links to. Framing stays allowed, since the panel
// shows file previews (sandboxed by their own CSP) in an iframe.
func baseHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
