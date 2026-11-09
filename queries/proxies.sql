-- name: ListProxies :many
SELECT sqlc.embed(p), s.name AS server_name, s.host AS server_host, s.workspace_id, s.status AS server_status,
       (SELECT count(*) FROM proxy_hosts h WHERE h.proxy_id = p.id)::int AS host_count
FROM proxies p
JOIN servers s ON s.id = p.server_id
WHERE (@see_all::bool OR s.workspace_id = ANY (@workspace_ids::uuid[]) OR s.id = ANY (@server_ids::uuid[]))
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR s.workspace_id = sqlc.narg('workspace_id')::uuid)
  AND (sqlc.narg('server_id')::uuid IS NULL OR p.server_id = sqlc.narg('server_id')::uuid)
ORDER BY lower(s.name), p.kind, p.container;

-- name: GetProxy :one
SELECT sqlc.embed(p), s.name AS server_name, s.host AS server_host, s.workspace_id, s.status AS server_status,
       (SELECT count(*) FROM proxy_hosts h WHERE h.proxy_id = p.id)::int AS host_count
FROM proxies p
JOIN servers s ON s.id = p.server_id
WHERE p.id = $1;

-- name: GetProxyServer :one
SELECT s.id, s.workspace_id
FROM proxies p
JOIN servers s ON s.id = p.server_id
WHERE p.id = $1;

-- name: CreateProxy :one
INSERT INTO proxies (server_id, kind, runtime, container) VALUES (@server_id, @kind, @runtime, @container) RETURNING *;

-- name: DeleteProxy :exec
DELETE FROM proxies WHERE id = $1;

-- name: RecordProxyCheck :exec
-- The version keeps its last known value while the server is away.
UPDATE proxies SET
    status = @status,
    status_message = @status_message,
    version = CASE WHEN @version::text = '' THEN version ELSE @version::text END,
    host_problems = @host_problems,
    last_checked_at = now()
WHERE id = @id;

-- name: ListProxiesDueForCheck :many
SELECT p.* FROM proxies p
JOIN servers s ON s.id = p.server_id
WHERE p.last_checked_at IS NULL OR p.last_checked_at < @before::timestamptz
ORDER BY p.last_checked_at NULLS FIRST;

-- name: ListProxyHosts :many
SELECT * FROM proxy_hosts WHERE proxy_id = $1 ORDER BY lower(domains[1]), id;

-- name: ListProxyHostsEverywhere :many
-- Every host of every proxy the caller can see, for the fleet view.
SELECT sqlc.embed(h), p.kind, p.server_id, p.container, p.status AS proxy_status, s.name AS server_name, s.workspace_id
FROM proxy_hosts h
JOIN proxies p ON p.id = h.proxy_id
JOIN servers s ON s.id = p.server_id
WHERE (@see_all::bool OR s.workspace_id = ANY (@workspace_ids::uuid[]) OR s.id = ANY (@server_ids::uuid[]))
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR s.workspace_id = sqlc.narg('workspace_id')::uuid)
ORDER BY lower(h.domains[1]), h.id;

-- name: GetProxyHost :one
SELECT * FROM proxy_hosts WHERE id = @id AND proxy_id = @proxy_id;

-- name: CreateProxyHost :one
INSERT INTO proxy_hosts (proxy_id, domains, enabled, config, note, created_by_name, updated_by_name)
VALUES (@proxy_id, @domains, @enabled, @config, @note, @by_name, @by_name)
RETURNING *;

-- name: UpdateProxyHost :one
UPDATE proxy_hosts SET
    domains = @domains,
    enabled = @enabled,
    config = @config,
    note = @note,
    updated_by_name = @by_name,
    updated_at = now()
WHERE id = @id AND proxy_id = @proxy_id
RETURNING *;

-- name: RestoreProxyHost :exec
-- Puts back a host from a history snapshot, with its old id.
INSERT INTO proxy_hosts (id, proxy_id, domains, enabled, config, note, created_by_name, updated_by_name, created_at, updated_at)
VALUES (@id, @proxy_id, @domains, @enabled, @config, @note, @created_by_name, @updated_by_name, @created_at, now());

-- name: DeleteProxyHost :exec
DELETE FROM proxy_hosts WHERE id = @id AND proxy_id = @proxy_id;

-- name: DeleteProxyHosts :exec
DELETE FROM proxy_hosts WHERE proxy_id = $1;

-- name: AddProxyChange :exec
INSERT INTO proxy_changes (proxy_id, user_id, user_name, summary, hosts)
VALUES (@proxy_id, @user_id, @user_name, @summary, @hosts);

-- name: ListProxyChanges :many
SELECT id, user_name, summary, jsonb_array_length(hosts)::int AS host_count, created_at
FROM proxy_changes
WHERE proxy_id = $1
ORDER BY created_at DESC, id DESC;

-- name: GetProxyChange :one
SELECT * FROM proxy_changes WHERE id = @id AND proxy_id = @proxy_id;

-- name: PruneProxyChanges :exec
DELETE FROM proxy_changes AS old
WHERE old.proxy_id = @proxy_id AND old.id NOT IN (
    SELECT recent.id FROM proxy_changes AS recent
    WHERE recent.proxy_id = @proxy_id
    ORDER BY recent.created_at DESC, recent.id DESC
    LIMIT @keep
);
