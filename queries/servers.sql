-- name: ListServers :many
-- Filters combine with AND; values inside one filter (os, status, tags)
-- combine with OR. A folder filter includes its subfolders. total is the
-- match count before LIMIT/OFFSET.
WITH RECURSIVE subtree AS (
    SELECT id FROM folders WHERE folders.id = sqlc.narg('folder_id')::uuid
    UNION ALL
    SELECT f.id FROM folders f JOIN subtree t ON f.parent_id = t.id
)
SELECT sqlc.embed(s), count(*) OVER ()::int AS total
FROM servers s
WHERE (sqlc.narg('folder_id')::uuid IS NULL OR s.folder_id IN (SELECT id FROM subtree))
  AND (NOT @unfiled::bool OR s.folder_id IS NULL)
  AND (NOT @favorites_only::bool OR s.favorite)
  AND (sqlc.narg('q')::text IS NULL
       OR s.name ILIKE '%' || sqlc.narg('q')::text || '%'
       OR s.host ILIKE '%' || sqlc.narg('q')::text || '%'
       OR s.hostname ILIKE '%' || sqlc.narg('q')::text || '%'
       OR s.description ILIKE '%' || sqlc.narg('q')::text || '%'
       OR sqlc.narg('q')::text = ANY (s.tags))
  AND (cardinality(@os_ids::text[]) = 0 OR coalesce(nullif(s.os_id, ''), 'unknown') = ANY (@os_ids::text[]))
  AND (cardinality(@statuses::text[]) = 0 OR s.status = ANY (@statuses::text[]))
  AND (cardinality(@tags::text[]) = 0 OR s.tags && @tags::text[])
  AND (cardinality(@auth_methods::text[]) = 0 OR s.auth_method = ANY (@auth_methods::text[]))
ORDER BY
    CASE WHEN @sort::text = 'name' AND NOT @descending::bool THEN lower(s.name) END,
    CASE WHEN @sort::text = 'name' AND @descending::bool THEN lower(s.name) END DESC,
    CASE WHEN @sort::text = 'host' AND NOT @descending::bool THEN s.host END,
    CASE WHEN @sort::text = 'host' AND @descending::bool THEN s.host END DESC,
    CASE WHEN @sort::text = 'os' AND NOT @descending::bool THEN nullif(s.os_name || ' ' || s.os_version, ' ') END NULLS LAST,
    CASE WHEN @sort::text = 'os' AND @descending::bool THEN nullif(s.os_name || ' ' || s.os_version, ' ') END DESC NULLS LAST,
    CASE WHEN @sort::text = 'status' AND NOT @descending::bool THEN s.status END,
    CASE WHEN @sort::text = 'status' AND @descending::bool THEN s.status END DESC,
    CASE WHEN @sort::text = 'last_checked' AND NOT @descending::bool THEN s.last_checked_at END NULLS LAST,
    CASE WHEN @sort::text = 'last_checked' AND @descending::bool THEN s.last_checked_at END DESC NULLS LAST,
    CASE WHEN @sort::text = 'created' AND NOT @descending::bool THEN s.created_at END,
    CASE WHEN @sort::text = 'created' AND @descending::bool THEN s.created_at END DESC,
    lower(s.name), s.id
LIMIT @lim OFFSET @off;

-- name: GetServer :one
SELECT * FROM servers WHERE id = $1;

-- name: GetServers :many
SELECT * FROM servers WHERE id = ANY (@ids::uuid[]) ORDER BY lower(name);

-- name: CreateServer :one
INSERT INTO servers (
    folder_id, name, host, port, username, auth_method,
    password_enc, private_key_enc, passphrase_enc, description, tags, favorite
) VALUES (
    sqlc.narg('folder_id'), @name, @host, @port, @username, @auth_method,
    sqlc.narg('password_enc'), sqlc.narg('private_key_enc'), sqlc.narg('passphrase_enc'),
    @description, @tags, @favorite
)
RETURNING *;

-- name: UpdateServer :one
-- Full replace of the editable fields. The handler resolves secrets first:
-- it passes the stored ones back unchanged when the request leaves them out.
UPDATE servers SET
    folder_id = sqlc.narg('folder_id'),
    name = @name,
    host = @host,
    port = @port,
    username = @username,
    auth_method = @auth_method,
    password_enc = sqlc.narg('password_enc'),
    private_key_enc = sqlc.narg('private_key_enc'),
    passphrase_enc = sqlc.narg('passphrase_enc'),
    host_key = @host_key,
    status = @status,
    status_message = @status_message,
    description = @description,
    tags = @tags,
    favorite = @favorite,
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: SetServerFavorite :one
UPDATE servers SET favorite = @favorite, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: RecordServerCheck :one
-- Stores a connection check. OS fields are only overwritten when the check
-- got far enough to read them (detected = true).
UPDATE servers SET
    status = @status,
    status_message = @status_message,
    latency_ms = sqlc.narg('latency_ms'),
    host_key = CASE WHEN @host_key::text <> '' THEN @host_key::text ELSE host_key END,
    os_family = CASE WHEN @detected::bool THEN @os_family ELSE os_family END,
    os_id = CASE WHEN @detected::bool THEN @os_id ELSE os_id END,
    os_name = CASE WHEN @detected::bool THEN @os_name ELSE os_name END,
    os_version = CASE WHEN @detected::bool THEN @os_version ELSE os_version END,
    kernel = CASE WHEN @detected::bool THEN @kernel ELSE kernel END,
    arch = CASE WHEN @detected::bool THEN @arch ELSE arch END,
    hostname = CASE WHEN @detected::bool THEN @hostname ELSE hostname END,
    last_checked_at = now(),
    last_seen_at = CASE WHEN @status = 'online' THEN now() ELSE last_seen_at END
WHERE id = @id
RETURNING *;

-- name: ResetServerHostKey :exec
UPDATE servers SET host_key = '', updated_at = now() WHERE id = $1;

-- name: MoveServers :execrows
UPDATE servers SET folder_id = sqlc.narg('folder_id'), updated_at = now()
WHERE id = ANY (@ids::uuid[]);

-- name: AddServerTags :execrows
UPDATE servers
SET tags = ARRAY(SELECT DISTINCT t FROM unnest(tags || @tags::text[]) AS t ORDER BY t),
    updated_at = now()
WHERE id = ANY (@ids::uuid[]);

-- name: RemoveServerTags :execrows
UPDATE servers
SET tags = ARRAY(SELECT t FROM unnest(tags) AS t WHERE t <> ALL (@tags::text[])),
    updated_at = now()
WHERE id = ANY (@ids::uuid[]);

-- name: DeleteServers :execrows
DELETE FROM servers WHERE id = ANY (@ids::uuid[]);

-- name: CountServers :one
SELECT count(*)::int AS total,
       count(*) FILTER (WHERE favorite)::int AS favorites,
       count(*) FILTER (WHERE folder_id IS NULL)::int AS unfiled
FROM servers;

-- name: ServerOSFacets :many
SELECT coalesce(nullif(os_id, ''), 'unknown')::text AS value,
       max(os_name)::text AS label,
       max(os_family)::text AS family,
       count(*)::int AS count
FROM servers
GROUP BY 1
ORDER BY count(*) DESC, 1;

-- name: ServerStatusFacets :many
SELECT status AS value, count(*)::int AS count
FROM servers
GROUP BY status
ORDER BY count(*) DESC;

-- name: ServerTagFacets :many
SELECT t::text AS value, count(*)::int AS count
FROM servers, unnest(tags) AS t
GROUP BY t
ORDER BY count(*) DESC, t;
