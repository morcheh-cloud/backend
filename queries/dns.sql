-- name: ListDNSServers :many
SELECT * FROM dns_servers
WHERE (@see_all::bool OR workspace_id = ANY (@workspace_ids::uuid[]))
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR workspace_id = sqlc.narg('workspace_id')::uuid)
ORDER BY favorite DESC, lower(name);

-- name: GetDNSServer :one
SELECT * FROM dns_servers WHERE id = $1;

-- name: GetDNSServerWorkspace :one
SELECT workspace_id FROM dns_servers WHERE id = $1;

-- name: ListDNSServersDueForCheck :many
-- Servers whose last check is older than @before (or that were never
-- checked), the longest waiting first.
SELECT * FROM dns_servers
WHERE last_checked_at IS NULL OR last_checked_at < @before::timestamptz
ORDER BY last_checked_at NULLS FIRST;

-- name: CreateDNSServer :one
INSERT INTO dns_servers (workspace_id, name, url, token_enc, tls_skip_verify, allow_internal, description)
VALUES (@workspace_id, @name, @url, @token_enc, @tls_skip_verify, @allow_internal, @description)
RETURNING *;

-- name: UpdateDNSServer :one
-- Full replace of the editable fields; the handler resolves the token first.
UPDATE dns_servers SET
    name = @name,
    url = @url,
    token_enc = @token_enc,
    tls_skip_verify = @tls_skip_verify,
    allow_internal = @allow_internal,
    description = @description,
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteDNSServer :exec
DELETE FROM dns_servers WHERE id = $1;

-- name: SetDNSServerFavorite :one
UPDATE dns_servers SET favorite = @favorite, updated_at = now() WHERE id = @id RETURNING *;

-- name: RecordDNSServerCheck :one
-- Version and domain keep their last known value while a server is away.
UPDATE dns_servers SET
    status = @status,
    status_message = @status_message,
    version = CASE WHEN @status = 'online' THEN @version ELSE version END,
    server_domain = CASE WHEN @status = 'online' THEN @server_domain ELSE server_domain END,
    zone_count = CASE WHEN @status = 'online' THEN @zone_count ELSE zone_count END,
    latency_ms = sqlc.narg('latency_ms'),
    last_checked_at = now(),
    last_online_at = CASE WHEN @status = 'online' THEN now() ELSE last_online_at END
WHERE id = @id
RETURNING *;
