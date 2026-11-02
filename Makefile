-include .env
export

.PHONY: run stop build reset-admin tidy up down db-up db-down psql redis-cli migrate-up migrate-down migrate-new sqlc

# Port from HTTP_ADDR (":8080", "127.0.0.1:8080"…), 8080 when unset.
PORT := $(or $(lastword $(subst :, ,$(HTTP_ADDR))),8080)

# Stops an earlier server first, so the new one can take the port.
run: stop
	go run ./cmd/server

# Stops our server listening on PORT (from another `make run` or bin/server):
# SIGTERM for a clean shutdown, SIGKILL if it still holds the port after 15 s.
# Anything else on the port is left alone.
stop:
	@pids=$$(for p in $$(lsof -ti tcp:$(PORT) -sTCP:LISTEN); do \
		[ "$$(ps -o comm= -p $$p)" = server ] && echo $$p; done); \
	[ -z "$$pids" ] && exit 0; \
	echo "stopping the running server (pid $$pids) on :$(PORT)"; \
	kill $$pids 2>/dev/null; \
	for i in $$(seq 30); do \
		kill -0 $$pids 2>/dev/null || exit 0; sleep 0.5; \
	done; \
	echo "still running after 15 s, killing it"; kill -9 $$pids 2>/dev/null; true

build:
	go build -o bin/server ./cmd/server

# usage: make reset-admin  (or args="-user alice -rename bob")
reset-admin:
	go run ./cmd/server reset-admin $(args)

tidy:
	go mod tidy

# Postgres + Redis + the SSH, S3, FTP and WebDAV test servers; waits until they are up.
up:
	docker compose up -d --wait

down:
	docker compose down

db-up: up

db-down: down

psql:
	docker compose exec postgres psql -U morcheh -d morcheh

redis-cli:
	docker compose exec redis redis-cli -a morcheh --no-auth-warning

migrate-up:
	go tool goose -dir migrations postgres "$(DATABASE_URL)" up

migrate-down:
	go tool goose -dir migrations postgres "$(DATABASE_URL)" down

# usage: make migrate-new name=create_servers
migrate-new:
	go tool goose -dir migrations create $(name) sql

# Generates type-safe Go code in internal/database/sqlc from migrations/ + queries/.
sqlc:
	go tool sqlc generate
