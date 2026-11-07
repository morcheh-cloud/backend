-- name: ListServerNotes :many
-- Pinned first, then the most recently changed.
SELECT * FROM server_notes WHERE server_id = $1
ORDER BY pinned DESC, updated_at DESC, id DESC;

-- name: CountServerNotes :one
SELECT count(*)::int FROM server_notes WHERE server_id = $1;

-- name: GetServerNote :one
SELECT * FROM server_notes WHERE id = @id AND server_id = @server_id;

-- name: CreateServerNote :one
INSERT INTO server_notes (server_id, title, body, pinned, created_by, created_by_name, updated_by_name)
VALUES (@server_id, @title, @body, @pinned, sqlc.narg('created_by'), @created_by_name, @created_by_name)
RETURNING *;

-- name: UpdateServerNote :one
UPDATE server_notes SET
    title = @title,
    body = @body,
    pinned = @pinned,
    updated_by_name = @updated_by_name,
    updated_at = now()
WHERE id = @id AND server_id = @server_id
RETURNING *;

-- name: SetServerNotePinned :one
-- Pinning isn't an edit: it keeps who changed it last and when.
UPDATE server_notes SET pinned = @pinned
WHERE id = @id AND server_id = @server_id
RETURNING *;

-- name: DeleteServerNote :execrows
DELETE FROM server_notes WHERE id = @id AND server_id = @server_id;
