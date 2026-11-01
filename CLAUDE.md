# Morcheh — Backend

## Maintaining this file (standing instruction from the user)

- This file is the project's memory. Whenever the user says something should be remembered, write it here — compactly (one line where possible), in the most relevant section.
- Also decide on your own: after any change to the project that a future session must know about (new convention, dependency, structure, decision, gotcha), update this file in the same turn. Don't log routine edits or anything already obvious from the code.
- Keep it short: edit or replace outdated lines instead of appending duplicates.
- Do not use the auto-memory directory for project facts; they go here.

## Working style (from the user)

- On every task, think beyond the literal request: propose related options and features the user didn't mention (as suggestions, not silently built).

Go 1.27 · Chi router · Huma v2 (OpenAPI 3.1 + Swagger UI) · PostgreSQL 18 via pgx/v5 · sqlc (data access) · goose migrations · Redis 8 via go-redis/v9 (cache). Module: `github.com/morcheh/backend`.

## Product

- Morcheh ("ant"): SSH-based server management + monitoring for small/medium orgs — add servers over SSH, discover services/files, configure servers, run Ansible playbooks, password vault, uptime checks.
- Frontend is `../frontend` (Next.js, client-side only, calls this API via `NEXT_PUBLIC_API_URL`; CORS origin `http://localhost:3200`).
- Built: servers + folders (SSH only). `internal/api/servers.go`: list (`q` matches name/host/hostname/description/tags, filters folder|`unfiled`/favorites/os/status/tag/auth, sort, offset paging), `/servers/facets` (counts for filters), CRUD, favorite, duplicate, `/servers/{id}/check`, `/servers/test-connection` (unsaved form), `/servers/bulk/{check,move,tags,delete}`. `internal/api/folders.go`: nested folders (CRUD; delete moves servers/subfolders up).
- `internal/sshprobe` connects with password or private key (+passphrase), reports status (`online`/`unreachable`/`auth_failed`/`host_key_mismatch`/`error`), latency and detected OS (os-release / sw_vers / `ver`). Host keys are TOFU: first successful check stores the key; a different key → `host_key_mismatch` until `?trust_new_host_key=true`; changing host/port forgets it.
- Terminal + files over SSH: `internal/sshpool` keeps one shared SSH connection per server (keepalive, idle close after 5 min, lazy SFTP client, uid/gid name cache, replaced when credentials/host key change — `connVersion` in `api/ssh.go`). Get it via `h.conn(ctx, id)` / `h.withSFTP(...)` (retries once on a dead pooled conn). `internal/terminal`: shells live on the backend (PTY `xterm-256color`, 512 KB scrollback replayed on attach, max 10 per server, killed after `TERMINAL_DETACHED_TIMEOUT` (15m) detached). WebSocket `GET /servers/{id}/terminals/connect` (raw chi route, not in the spec; origin checked against `CORS_ORIGINS`): `?session=` reattaches, else new shell with `cols`/`rows`/`cwd`; binary frames = terminal bytes both ways; text JSON: client `resize`, server `session`/`title`/`exit`/`error`; failures close with code 4000+HTTP status. REST: list/rename/close terminals. `api/files.go` (tag Files, `/servers/{id}/files/...`): list, stat, size (du), download (one file with Range, else streamed zip; `inline` only for safe types + CSP sandbox), content read/write (≤5 MB text, mtime conflict 409), upload (raw body PUT, temp file + rename, 409 unless `overwrite`), mkdir, rename, move, copy, delete, chmod, chown, compress (tar.gz/zip), extract, search (find). Mutations needing commands run them over exec (`run()`), so the remote needs a POSIX shell + coreutils (zip/unzip optional).
- Live stats: `GET /servers/{id}/stats` (`api/stats.go`) runs `internal/sysstats.Script` over exec (`h.withConn`, retries once on a dead conn) and parses /proc (uptime, loadavg, stat, net/dev sampled 1 s apart, meminfo) + `df -PkT`; ~1.2 s per call. Linux only (422 otherwise). Disks drop pseudo filesystems (overlay kept only at `/`) and dedupe mounts with identical size numbers (bind mounts). Realtime: `GET /servers/{id}/stats/stream` (Huma `sse`, events `stats` / `problem` = `StatsProblem{status, detail, retrying}`, ping comment every 20 s). `statsHub` runs ONE `sysstats.StreamScript` per watched server (loop: a frame per second ending `@end`, df every 10th frame under `timeout 5`), holds the conn with `Acquire`/`Release`, fans out to all subscribers (newest event only, the last one replayed on join), stops 10 s after the last subscriber leaves, restarts the script if no frame for 20 s, retries failures with 2→30 s backoff (404/422 final).
- Open ports: `GET /servers/{id}/ports` (`api/ports.go`, tag Network) runs `internal/ports.Script` (POSIX sh, busybox-safe) over exec: `ss -tulpn` else `netstat`, via `sudo -n` when passwordless (else only the login user's processes are named, `privileged:false`), /proc comm/cmdline/cgroup, systemd unit, and `docker`/`podman inspect`. `ports.Parse` maps published bindings to containers whatever holds the host socket (docker-proxy, rootlesskit, conmon), host-network containers via cgroup id, merges IPv4/IPv6 per owner, labels the service (container image → process/interpreter table in `known.go` → well-known port guess) and flags `sensitive` (DBs/caches). Fixture tests in `internal/ports/testdata`.
- Cron: `api/cron.go` (tag Cron, `/servers/{id}/cron…`): one collect script reads every user crontab, /etc/crontab, /etc/cron.d, periodic run-parts dirs and systemd timers (+ daemon detection, server tz); `history` greps journal/syslog/cron log for last runs (empty with a `note` when none). Edits (add/update/delete/enable jobs, save a whole table as text) carry the table `revision` (hash) → 409 when stale; a bad raw line → 422 at `body.content` with `value` = line number. `run` executes a command once as the job's user (timeout, output capped keeping the start, `truncated`); `timers/action` = start/enable/disable a systemd timer. Root access via `api/privilege.go`: `rootShell` detects root / `sudo -n` / sudo with the stored login password (`runInput` feeds stdin), cached 10 min (`privilegeTTL`) since failed sudo gets logged.
- `internal/secrets`: AES-256-GCM sealing of passwords/keys/passphrases at rest; API never returns secrets (only `has_password`/`has_private_key`).
- Planned direction (not built yet): Ansible run as a subprocess with streamed output, job queue (River or Asynq), SSE for live logs, RBAC + audit log, encrypted secrets.

- Fail2ban: `api/fail2ban.go` (tag Security, `/servers/{id}/security/fail2ban…`): overview (one collect script: installed/running/version, files, jails with status + timed bans), install/uninstall, service actions, `[DEFAULT]`/jail edits, raw jail.local, filters (`.conf` read-only, edits go to `.local`), ban/unban, log events, `test` (fail2ban-regex). `internal/fail2ban` only parses/edits text (line-preserving `Doc`, status/ban/log parsers, tests); it runs nothing. Writes go through `writeChecked`: backup, write, `fail2ban-client -t`, reload, restore on failure → 422 with fail2ban's message; stale `revision` → 409. Tasks answer `{ok, exit_code (-1 = timeout), output, truncated, duration_ms}`. `api/host.go` is the shared layer for modules that install a package and run a service (package manager + init detection, `packageScript`, `serviceScript`; servers without init run the daemon directly): reuse it for the next security modules (firewall, SSH hardening…).
- Users & groups: `api/users.go` (`/servers/{id}/users[/{user}[/password|lock|logout]]`, `/servers/{id}/groups[/{group}]`): one collect script reads passwd/shadow/group/login.defs/sudoers/lastlog/who; `internal/users` only parses. Every mutation runs as root (`rootShell`) and answers the fresh overview. `protect()` refuses lock/remove/rename/sudo changes on root and the login user. Sudo levels: `none` = leave every sudo-granting group, `password` = join `sudo_group` (else a rule), `nopasswd` = rule in `/etc/sudoers.d/morcheh-<name>` (dots → `_`); single-user rules elsewhere get commented `# (disabled by Morcheh) `, multi-user rules → 422; checked with `visudo`, restored on failure. Lock = `usermod -L -e 1970-01-02`. Passwords hashed server-side with `GehirnInc/crypt` (sha512_crypt); BusyBox (Alpine) gets fallbacks for missing shadow tools.

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
- Errors: return `huma.ErrorXXX(...)` (RFC 9457 problem JSON), not raw `http.Error`. File ops wrap SFTP errors with `fsError(path, err)` and return through `toProblem` (404/403/409/422/502).
- Huma: an input struct without `Body` isn't read, so streaming uploads grab `ctx.BodyReader()` in a `Resolve` method; repeated query params need `query:"x,explode"`; raise `MaxBodyBytes` (default 1 MB) for big JSON bodies.
- Schema changes only through goose SQL files in `migrations/`.
- Data access: sqlc (chosen over GORM/Ent: no runtime reflection, reads goose migrations as schema, native pgx/v5). Write SQL in `queries/*.sql` with `-- name: X :one|:many|:exec`, run `make sqlc`, use `sqlc.New(pool)`; never edit generated code. uuid → `google/uuid.UUID`, nullable → pointers (see `sqlc.yaml`).
- Cache: `internal/cache` — `cache.Get/Set/Delete` (JSON) and generic `cache.Remember(ctx, c, key, ttl, load)`; `cache.ErrMiss` on miss; raw client at `c.Client`.
- Logging: `log/slog` for app logs; chi `middleware.Logger` for access logs.

## Gotchas

- goose is a `tool` in go.mod (`go tool goose`), which pulls many DB drivers into go.mod as indirect deps — they are not compiled into the server binary.
- `make migrate-up` errors with "no migration files found" until the first migration exists.
- Postgres 18 image: volume mounts at `/var/lib/postgresql` (not `/var/lib/postgresql/data`).
- `SECRETS_KEY` (base64 32 bytes, `openssl rand -base64 32`) is required; changing it makes every stored credential unreadable.
- Local SSH target for testing: `docker run -d --name morcheh-test-ssh -p 127.0.0.1:2222:2222 -e USER_NAME=ant -e USER_PASSWORD=colony -e PASSWORD_ACCESS=true lscr.io/linuxserver/openssh-server` (user `ant` / `colony`). Alpine/busybox crond (no syslog → cron history empty); for cron testing we added `ant ALL=(ALL) NOPASSWD: ALL` in its sudoers and seeded root/ant crontabs + `/etc/cron.d/app` (lost if the container is recreated).
- Server refuses to start if `DATABASE_URL`/`REDIS_URL` is missing or Postgres/Redis is unreachable; `/health` checks both.
- Compose ports bind to `127.0.0.1` only (host ports: Postgres 5433, Redis 6380; no `restart` policy); local creds are `morcheh`/`morcheh` (Redis password `morcheh`). `make sqlc` fails with "no queries" until `queries/` has a .sql file.
