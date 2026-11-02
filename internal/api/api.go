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
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.CORSOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Our handlers never return null arrays; keep them non-nullable in the
	// spec so the generated client types them as plain arrays.
	huma.DefaultArrayNullable = false

	hc := huma.DefaultConfig(title, version)
	hc.DocsRenderer = huma.DocsRendererSwaggerUI
	api := humachi.New(r, hc)

	registerHealth(api, db, rdb)
	registerFolders(api, db)
	servers := &serverHandler{
		db: db, q: sqlc.New(db), box: box,
		pool:  sshpool.New(),
		terms: terminal.NewManager(cfg.TerminalDetachedTimeout),
		jobs:  runner,
	}
	servers.stats = newStatsHub(servers)
	registerServers(api, servers)
	registerTerminals(api, r, servers, cfg.CORSOrigins)
	registerFiles(api, servers)
	registerDiskUsage(api, servers)
	registerCron(api, servers)
	registerPorts(api, servers)
	registerNetwork(api, servers)
	registerStats(api, servers)
	registerFail2ban(api, servers)
	registerUsers(api, servers)
	registerServices(api, servers)
	registerPower(api, servers)
	st := newStorageHandler(sqlc.New(db), box, servers)
	registerStorages(api, st)
	registerStorageCredentials(api, st)
	registerStorageFiles(api, st)
	registerJobs(api, runner)

	return r
}
