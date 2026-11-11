package api

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/morcheh/backend/internal/cache"
	"github.com/morcheh/backend/internal/config"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
	_ "github.com/morcheh/backend/internal/proxy/nginx" // registers the nginx driver
	"github.com/morcheh/backend/internal/secrets"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/terminal"
)

const (
	title   = "Morcheh API"
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
		r.Use(middleware.RealIP)
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

	terms := terminal.NewManager(cfg.TerminalDetachedTimeout)
	a := newAuthz(cfg, db, rdb, runner, terms)
	// Before any Register: an operation takes the middlewares in place then.
	api.UseMiddleware(a.middleware(api))

	registerHealth(api, db, rdb)
	registerAuth(api, a)
	registerAdmin(api, a)
	registerWorkspaces(api, a)
	registerWorkspaceLogos(api, a)
	registerFolders(api, a)
	servers := &serverHandler{
		db: db, q: sqlc.New(db), box: box,
		pool:  sshpool.New(),
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
	registerServerInsights(api, servers, cfg.ServerSampleInterval)
	registerTerminals(api, r, servers, cfg.CORSOrigins)
	registerRecordings(api, servers.recs)
	registerFiles(api, servers)
	registerDiskUsage(api, servers)
	registerCron(api, servers)
	registerPorts(api, servers)
	registerNetwork(api, servers)
	registerStats(api, servers)
	registerFail2ban(api, servers)
	registerFirewall(api, servers)
	registerUsers(api, servers)
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
	databases := newDatabaseHandler(sqlc.New(db), box, servers)
	registerDatabases(api, databases)
	registerDatabaseInsights(api, databases)
	dns := &dnsHandler{q: sqlc.New(db), box: box, authz: a}
	startDNSMonitor(dns, cfg.DNSCheckInterval)
	registerDNS(api, dns)
	panelURL := cfg.PanelURL
	if panelURL == "" && len(cfg.CORSOrigins) > 0 && cfg.CORSOrigins[0] != "*" {
		panelURL = cfg.CORSOrigins[0]
	}
	up := newUptimeHandler(sqlc.New(db), box, a, servers, panelURL, cfg.MonitorHistory)
	startUptimeMonitor(up)
	registerMonitors(api, up)
	registerNotifications(api, up)
	apps := newAppHandler(sqlc.New(db), db, box, a)
	registerApps(api, apps)
	registerAppCategories(api, apps)
	registerAppSecrets(api, apps)
	registerAppLogos(api, apps)
	playbooks := newAnsibleHandler(servers, a)
	registerAnsible(api, playbooks)
	backups := newBackupHandler(databases, st, a)
	registerDatabaseBackups(api, backups)
	schedules := newScheduleHandler(st, a, scripts, playbooks, backups, software)
	registerSchedules(api, schedules)
	startBackupScheduler(backups, cfg.ScheduleTick)
	startScheduler(schedules, cfg.ScheduleTick)
	registerJobs(api, a)

	return r, api
}
