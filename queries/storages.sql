-- name: ListStorages :many
SELECT * FROM storages s
WHERE (@see_all::bool OR s.workspace_id = ANY (@workspace_ids::uuid[]) OR s.id = ANY (@storage_ids::uuid[]))
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR s.workspace_id = sqlc.narg('workspace_id')::uuid)
ORDER BY s.favorite DESC, lower(s.name);

-- name: GetStorage :one
SELECT * FROM storages WHERE id = $1;

-- name: CreateStorage :one
INSERT INTO storages (
    workspace_id, name, protocol, provider, host, port, username, auth_method,
    secret_enc, private_key_enc, passphrase_enc, bucket, region, path_style,
    tls, insecure_tls, host_key, root_path, read_only, description, favorite
) VALUES (
    @workspace_id, @name, @protocol, @provider, @host, @port, @username, @auth_method,
    sqlc.narg('secret_enc'), sqlc.narg('private_key_enc'), sqlc.narg('passphrase_enc'),
    @bucket, @region, @path_style, @tls, @insecure_tls, @host_key, @root_path,
    @read_only, @description, @favorite
)
RETURNING *;

-- name: UpdateStorage :one
-- Full replace of the editable fields; the handler resolves secrets first.
UPDATE storages SET
    name = @name,
    protocol = @protocol,
    provider = @provider,
    host = @host,
    port = @port,
    username = @username,
    auth_method = @auth_method,
    secret_enc = sqlc.narg('secret_enc'),
    private_key_enc = sqlc.narg('private_key_enc'),
    passphrase_enc = sqlc.narg('passphrase_enc'),
    bucket = @bucket,
    region = @region,
    path_style = @path_style,
    tls = @tls,
    insecure_tls = @insecure_tls,
    host_key = @host_key,
    root_path = @root_path,
    read_only = @read_only,
    description = @description,
    favorite = @favorite,
    status = @status,
    status_message = @status_message,
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: SetStorageFavorite :one
UPDATE storages SET favorite = @favorite, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: RecordStorageCheck :one
-- host_key is only stored when the check saw one (SFTP).
UPDATE storages SET
    status = @status,
    status_message = @status_message,
    detail = CASE WHEN @status = 'online' THEN @detail::text ELSE detail END,
    latency_ms = sqlc.narg('latency_ms'),
    host_key = CASE WHEN @host_key::text <> '' THEN @host_key::text ELSE host_key END,
    last_checked_at = now()
WHERE id = @id
RETURNING *;

-- name: ResetStorageHostKey :exec
UPDATE storages SET host_key = '', updated_at = now() WHERE id = $1;

-- name: DeleteStorage :execrows
DELETE FROM storages WHERE id = $1;
