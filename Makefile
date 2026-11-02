-include .env
export

.PHONY: run build reset-admin tidy up down db-up db-down psql redis-cli migrate-up migrate-down migrate-new sqlc

run:
	go run ./cmd/server

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
