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
)

const (
	title   = "Morcheh API"
	version = "0.1.0"
)

// NewRouter builds the HTTP handler. OpenAPI spec is served at /openapi.json
// and Swagger UI at /docs.
func NewRouter(cfg *config.Config, db *pgxpool.Pool, rdb *cache.Cache) http.Handler {
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

	hc := huma.DefaultConfig(title, version)
	hc.DocsRenderer = huma.DocsRendererSwaggerUI
	api := humachi.New(r, hc)

	registerHealth(api, db, rdb)

	return r
}
