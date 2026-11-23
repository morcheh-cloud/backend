package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/morche/backend/internal/cache"
	"github.com/morche/backend/internal/config"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/events"
	"github.com/morche/backend/internal/jobs"
	_ "github.com/morche/backend/internal/proxy/nginx" // registers the nginx driver
	"github.com/morche/backend/internal/secrets"
	"github.com/morche/backend/internal/sshpool"
	"github.com/morche/backend/internal/terminal"
)

const (
	title   = "Morche API"
	version = "0.1.0"
)

// NewRouter builds the HTTP handler. OpenAPI spec is served at /openapi.json
// and Swagger UI at /docs. It registers the job handlers on runner; start
// the runner after this.
func NewRouter(cfg *config.Config, db *pgxpool.Pool, rdb *cache.Cache, box *secrets.Box, runner *jobs.Runner) http.Handler {
	r, _ := build(cfg, db, rdb, box, runner)
	return r
}

// build is NewRouter with the parts a test inspects.
func build(cfg *config.Config, db *pgxpool.Pool, rdb *cache.Cache, box *secrets.Box, runner *jobs.Runner) (*chi.Mux, huma.API) {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	// Off by default: without a proxy in front, anyone could fake their address
	// with these headers and walk around the login limits.
	if cfg.TrustProxy {
		r.Use(proxiedIP)
	}
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.CORSOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", workspaceHeader},
		AllowCredentials: true,
		MaxAge:           300,
	}))
	r.Use(originGuard(cfg.CORSOrigins))
	r.Use(baseHeaders)

	// Our handlers never return null arrays; keep them non-nullable in the
	// spec so the generated client types them as plain arrays.
	huma.DefaultArrayNullable = false

	hc := huma.DefaultConfig(title, version)
	hc.DocsRenderer = huma.DocsRendererSwaggerUI
	// The API's map stays out of production; these routes skip the middleware.
	if !cfg.Development() {
		hc.DocsPath, hc.OpenAPIPath, hc.SchemasPath = "", "", ""
		hc.CreateHooks = nil
	}
	api := humachi.New(r, hc)

	// Before any clean-up loop starts: a log policy may own those rows, and
	// every kind of logs has one (its default until an admin changes it).
	seedLogPolicies(context.Background(), sqlc.New(db))
	loadLogOwners(context.Background(), sqlc.New(db))

	terms := terminal.NewManager(cfg.TerminalDetachedTimeout)
	a := newAuthz(cfg, db, rdb, runner, terms)
	a.events = events.New()
	// Before any Register: an operation takes the middlewares in place then.
	api.UseMiddleware(a.middleware(api))

	registerHealth(api, db, rdb)
	registerAuth(api, a)
	registerDemo(api, a)
	registerAPITokens(api, a)
	registerEvents(api)
	registerAdmin(api, a)
	registerSignIns(api, a)
	registerWorkspaces(api, a)
	registerWorkspaceLogos(api, a)
	registerFolders(api, a)
	cmdLog := newCommandLog(sqlc.New(db))
	pool := sshpool.New()
	pool.Log = cmdLog
	servers := &serverHandler{
		db: db, q: sqlc.New(db), box: box,
		pool:  pool,
		cmds:  cmdLog,
		terms: terms,
		jobs:  runner,
		authz: a,
	}
	servers.stats = newStatsHub(servers)
	servers.recs = newRecordings(sqlc.New(db), servers)
	startRecordingJanitor(servers.recs)
	startServerMonitor(servers, cfg.ServerCheckInterval)
	startServerSampler(servers, cfg.ServerSampleInterval, cfg.ServerHistory)
	registerServers(api, servers)
	morcheHost := &morcheHostHandler{cfg: cfg, s: servers}
	registerMorcheHost(api, morcheHost)
	startMorcheHost(morcheHost)
	registerServerInsights(api, servers, cfg.ServerSampleInterval)
	registerServerMetrics(api, servers, cfg.ServerSampleInterval)
	registerTerminals(api, r, servers, cfg.CORSOrigins)
	registerRecordings(api, servers.recs)
	registerCommandLog(api, servers)
	registerFiles(api, servers)
	registerDiskUsage(api, servers)
	registerCron(api, servers)
	registerPorts(api, servers)
	registerProcesses(api, servers)
	registerDocker(api, servers)
	startDockerUpdateLoop(servers)
	startDockerAutoUpdateLoop(servers)
	startDockerAutoPruneLoop(servers)
	startDockerAlertLoop(servers)
	startDockerGitLoop(servers)
	startProjectStatsLoop(servers)
	startProjectHistoryLoop(servers)
	registerNetwork(api, servers)
	registerStats(api, servers)
	registerFail2ban(api, servers)
	registerFirewall(api, servers)
	registerUsers(api, servers)
	registerConfigHistory(api, servers)
	registerServices(api, servers)
	registerPackages(api, servers)
	registerPower(api, servers)
	registerServerNotes(api, servers)
	proxies := newProxyHandler(servers)
	startProxyMonitor(proxies, cfg.ProxyCheckInterval)
	registerProxies(api, proxies)
	scripts := newScriptHandler(servers, a)
	registerScripts(api, scripts)
	software := newSoftwareHandler(servers, a, scripts)
	registerSoftware(api, software)
	startSoftwareChecker(software, cfg.SoftwareCheckInterval)
	st := newStorageHandler(sqlc.New(db), box, servers)
	startStorageMonitor(st, cfg.StorageCheckInterval)
	startStorageScanner(st, cfg.StorageScanInterval, cfg.StorageHistory)
	registerStorages(api, st)
	registerStorageCredentials(api, st)
	registerStorageFiles(api, st)
	registerStorageBuckets(api, st)
	registerStorageInsights(api, st)
	registerDockerVolumeBackups(api, st)
	registerDockerImageTransfer(api, st)
	databases := newDatabaseHandler(sqlc.New(db), box, servers)
	registerDatabases(api, databases)
	registerDatabaseInsights(api, databases)
	dns := &dnsHandler{q: sqlc.New(db), box: box, authz: a, arvanFake: cfg.ArvanFakeURL}
	startDNSMonitor(dns, cfg.DNSCheckInterval)
	registerDNS(api, dns)
	registerDNSCDN(api, dns)
	registerDNSCDNSecurity(api, dns)
	registerDNSNames(api, dns)
	registerCDNRanges(api)
	panelURL := cfg.PanelURL
	if panelURL == "" && len(cfg.CORSOrigins) > 0 && cfg.CORSOrigins[0] != "*" {
		panelURL = cfg.CORSOrigins[0]
	}
	a.panelURL = strings.TrimRight(panelURL, "/")
	up := newUptimeHandler(sqlc.New(db), box, a, servers, panelURL, cfg.MonitorHistory)
	a.up = up
	startUptimeMonitor(up)
	registerMonitors(api, up)
	registerNotifications(api, up)
	servers.alerts = newAlertEngine(sqlc.New(db), up, cfg.ServerSampleInterval)
	alertRules := &alertRuleHandler{q: sqlc.New(db), authz: a, engine: servers.alerts}
	registerAlertRules(api, alertRules)
	registerAlertMutes(api, alertRules)
	pve := &pveHandler{q: sqlc.New(db), box: box, authz: a, servers: servers, runner: runner}
	pve.registerJobs()
	registerPVEClusters(api, pve)
	registerPVEGuests(api, pve)
	registerPVEInfra(api, pve)
	registerPVEConsole(api, r, pve, cfg.CORSOrigins)
	startPVEMonitor(pve, cfg.PVECheckInterval)
	cloudH := &cloudHandler{q: sqlc.New(db), box: box, authz: a, fakeURL: cfg.ArvanFakeURL, cache: map[uuid.UUID]cloudCached{}, res: map[uuid.UUID]cloudResCached{}}
	registerCloudAccounts(api, cloudH)
	registerCloudServers(api, cloudH)
	registerCloudResources(api, cloudH)
	startCloudMonitor(cloudH, cfg.CloudCheckInterval)
	alertRules.pve = pve
	assets := newAssetHandler(servers, a)
	assets.pve, assets.cloud, assets.dns, assets.up = pve, cloudH, dns, up
	registerAssets(api, assets)
	startAssetLoops(assets)
	apps := newAppHandler(sqlc.New(db), db, box, a)
	registerApps(api, apps)
	registerAppCategories(api, apps)
	registerAppSecrets(api, apps)
	registerAppLogos(api, apps)
	playbooks := newAnsibleHandler(servers, a)
	registerAnsible(api, playbooks)
	backups := newBackupHandler(databases, st, a)
	registerDatabaseBackups(api, backups)
	registerDatabasePitr(api, backups)
	explorer := newExplorerHandler(databases)
	registerDatabaseExplorer(api, explorer)
	registerDatabaseExplorerEdit(api, explorer)
	dbSyncs := newDatabaseSyncHandler(backups, a)
	registerDatabaseSyncs(api, dbSyncs)
	schedules := newScheduleHandler(st, a, scripts, playbooks, backups, software)
	schedules.pve = pve
	registerSchedules(api, schedules)
	startBackupScheduler(backups, cfg.ScheduleTick)
	startPitrScheduler(backups, cfg.ScheduleTick, pitrCheckEvery)
	startDatabaseSyncScheduler(dbSyncs, cfg.ScheduleTick)
	startScheduler(schedules, cfg.ScheduleTick)
	storageSyncs := newStorageSyncHandler(st, a)
	registerStorageSyncs(api, storageSyncs)
	startStorageSyncScheduler(storageSyncs, cfg.ScheduleTick)
	logs := newLogArchiveHandler(sqlc.New(db), db, st, runner, cfg.LogArchiveDir)
	registerLogArchives(api, logs)
	startLogArchiveScheduler(logs, cfg.ScheduleTick)
	runner.SkipCleanup = func() bool { return logOwned("jobs") }
	registerJobs(api, a)
	registerJobEvents(runner, servers)
	hooks := newWebhookDispatcher(sqlc.New(db), box)
	hooks.start(a.events)
	registerWebhooks(api, &webhookHandler{q: sqlc.New(db), box: box, authz: a, d: hooks})
	autos := newAutomationHandler(sqlc.New(db), box, a, servers, scripts, schedules, up)
	registerAutomations(api, autos)
	autos.start(a.events)

	return r, api
}
