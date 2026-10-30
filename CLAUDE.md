# Morcheh — Backend

## Maintaining this file (standing instruction from the user)

- This file is the project's memory. Whenever the user says something should be remembered, write it here — compactly (one line where possible), in the most relevant section.
- Also decide on your own: after any change to the project that a future session must know about (new convention, dependency, structure, decision, gotcha), update this file in the same turn. Don't log routine edits or anything already obvious from the code.
- Keep it short: edit or replace outdated lines instead of appending duplicates.
- Do not use the auto-memory directory for project facts; they go here.

Go 1.27 · Chi router · Huma v2 (OpenAPI 3.1 + Swagger UI) · PostgreSQL 18 via pgx/v5 · sqlc (data access) · goose migrations · Redis 8 via go-redis/v9 (cache). Module: `github.com/morcheh/backend`.

## Product

- Morcheh ("ant"): SSH-based server management + monitoring for small/medium orgs — add servers over SSH, discover services/files, configure servers, run Ansible playbooks, password vault, uptime checks.
- Frontend is `../frontend` (Next.js, client-side only, calls this API via `NEXT_PUBLIC_API_URL`; CORS origin `http://localhost:3200`).
- Planned direction (not built yet): SSH via `golang.org/x/crypto/ssh`, Ansible run as a subprocess with streamed output, job queue (River or Asynq), WebSocket for web terminal, SSE for live logs, RBAC + audit log, encrypted secrets.

## Commands

```bash
cp .env.example .env    # first time
make up                 # Postgres + Redis in docker compose (waits for healthy); `make down` stops
make run                # API on :8080 — Swagger UI /docs, spec /openapi.json
make psql / make redis-cli
make sqlc               # regenerate internal/database/sqlc after changing migrations/ or queries/
make build              # → bin/server
make migrate-new name=create_servers
make migrate-up / migrate-down
go vet ./... && go build ./...   # run before declaring work done
```

## Structure & conventions

- `cmd/server/main.go` — wiring + graceful shutdown. `internal/config` — env config (`caarlos0/env`, `.env` loaded by godotenv). `internal/database` — pgx pool. `internal/api` — router (`api.go`) and one file per resource with Huma operations.
- New endpoints: `huma.Register` with `OperationID`, `Summary`, `Tags`; register them from `NewRouter`. Request/response types are Go structs (`Body` field, `doc`/`example` tags) so the OpenAPI spec stays complete — the frontend relies on it.
- Errors: return `huma.ErrorXXX(...)` (RFC 9457 problem JSON), not raw `http.Error`.
- Schema changes only through goose SQL files in `migrations/`.
- Data access: sqlc (chosen over GORM/Ent: no runtime reflection, reads goose migrations as schema, native pgx/v5). Write SQL in `queries/*.sql` with `-- name: X :one|:many|:exec`, run `make sqlc`, use `sqlc.New(pool)`; never edit generated code. uuid → `google/uuid.UUID`, nullable → pointers (see `sqlc.yaml`).
- Cache: `internal/cache` — `cache.Get/Set/Delete` (JSON) and generic `cache.Remember(ctx, c, key, ttl, load)`; `cache.ErrMiss` on miss; raw client at `c.Client`.
- Logging: `log/slog` for app logs; chi `middleware.Logger` for access logs.

## Gotchas

- goose is a `tool` in go.mod (`go tool goose`), which pulls many DB drivers into go.mod as indirect deps — they are not compiled into the server binary.
- `make migrate-up` errors with "no migration files found" until the first migration exists.
- Postgres 18 image: volume mounts at `/var/lib/postgresql` (not `/var/lib/postgresql/data`).
- Server refuses to start if `DATABASE_URL`/`REDIS_URL` is missing or Postgres/Redis is unreachable; `/health` checks both.
- Compose ports bind to `127.0.0.1` only; local creds are `morcheh`/`morcheh` (Redis password `morcheh`). `make sqlc` fails with "no queries" until `queries/` has a .sql file.
