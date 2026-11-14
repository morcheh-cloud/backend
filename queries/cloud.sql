-- name: ListCloudAccounts :many
SELECT * FROM cloud_accounts
WHERE (@see_all::bool OR workspace_id = ANY (@workspace_ids::uuid[]))
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR workspace_id = sqlc.narg('workspace_id')::uuid)
ORDER BY favorite DESC, lower(name);

-- name: GetCloudAccount :one
SELECT * FROM cloud_accounts WHERE id = $1;

-- name: GetCloudAccountWorkspace :one
SELECT workspace_id FROM cloud_accounts WHERE id = $1;

-- name: ListCloudAccountsDueForCheck :many
-- Accounts whose last check is older than @before (or never checked), the
-- longest waiting first.
SELECT * FROM cloud_accounts
WHERE last_checked_at IS NULL OR last_checked_at < @before::timestamptz
ORDER BY last_checked_at NULLS FIRST;

-- name: CreateCloudAccount :one
INSERT INTO cloud_accounts (workspace_id, provider, name, api_key_enc, key_hint, description, allow_changes)
VALUES (@workspace_id, @provider, @name, @api_key_enc, @key_hint, @description, @allow_changes)
RETURNING *;

-- name: UpdateCloudAccount :one
-- Full replace of the editable fields; the handler resolves the key first.
UPDATE cloud_accounts SET
    name = @name,
    api_key_enc = @api_key_enc,
    key_hint = @key_hint,
    description = @description,
    allow_changes = @allow_changes,
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteCloudAccount :exec
DELETE FROM cloud_accounts WHERE id = $1;

-- name: SetCloudAccountFavorite :one
UPDATE cloud_accounts SET favorite = @favorite, updated_at = now() WHERE id = @id RETURNING *;

-- name: RecordCloudAccountCheck :one
-- The counts keep their last value while an account can't be read.
UPDATE cloud_accounts SET
    status = @status,
    status_message = @status_message,
    server_count = CASE WHEN @status = 'online' THEN @server_count ELSE server_count END,
    running_count = CASE WHEN @status = 'online' THEN @running_count ELSE running_count END,
    latency_ms = sqlc.narg('latency_ms'),
    last_checked_at = now(),
    last_online_at = CASE WHEN @status = 'online' THEN now() ELSE last_online_at END
WHERE id = @id
RETURNING *;

-- name: ListServersByHost :many
-- Panel servers at any of @hosts that the caller can see, to show which
-- cloud servers are already in Morche.
SELECT id, name, host, status FROM servers
WHERE host = ANY (@hosts::text[])
  AND (@see_all::bool OR workspace_id = ANY (@workspace_ids::uuid[]) OR id = ANY (@server_ids::uuid[]))
ORDER BY created_at;
