package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/morcheh/backend/internal/cache"
)

type HealthOutput struct {
	Body struct {
		Status string `json:"status" example:"ok" doc:"Overall service status"`
	}
}

func registerHealth(api huma.API, db *pgxpool.Pool, rdb *cache.Cache) {
	huma.Register(api, huma.Operation{
		OperationID: "get-health",
		Method:      http.MethodGet,
		Path:        "/health",
		Summary:     "Health check",
		Tags:        []string{"System"},
	}, func(ctx context.Context, _ *struct{}) (*HealthOutput, error) {
		if err := db.Ping(ctx); err != nil {
			return nil, huma.Error503ServiceUnavailable("database unreachable")
		}
		if err := rdb.Ping(ctx); err != nil {
			return nil, huma.Error503ServiceUnavailable("redis unreachable")
		}
		out := &HealthOutput{}
		out.Body.Status = "ok"
		return out, nil
	})
}
