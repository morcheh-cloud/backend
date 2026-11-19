-- name: ListAssetNotes :many
-- Pinned first, then the most recently changed.
SELECT * FROM asset_notes WHERE asset_id = $1
ORDER BY pinned DESC, updated_at DESC, id DESC;

-- name: CountAssetNotes :one
SELECT count(*)::int FROM asset_notes WHERE asset_id = $1;

-- name: CountAssetNotesByWorkspace :many
SELECT n.asset_id, count(*)::int AS notes
FROM asset_notes n JOIN assets a ON a.id = n.asset_id
WHERE a.workspace_id = @workspace_id
GROUP BY n.asset_id;

-- name: GetAssetNote :one
SELECT * FROM asset_notes WHERE id = @id AND asset_id = @asset_id;

-- name: CreateAssetNote :one
INSERT INTO asset_notes (asset_id, title, body, pinned, created_by, created_by_name, updated_by_name)
VALUES (@asset_id, @title, @body, @pinned, sqlc.narg('created_by'), @created_by_name, @created_by_name)
RETURNING *;

-- name: UpdateAssetNote :one
UPDATE asset_notes SET
    title = @title,
    body = @body,
    pinned = @pinned,
    updated_by_name = @updated_by_name,
    updated_at = now()
WHERE id = @id AND asset_id = @asset_id
RETURNING *;

-- name: SetAssetNotePinned :one
-- Pinning isn't an edit: it keeps who changed it last and when.
UPDATE asset_notes SET pinned = @pinned
WHERE id = @id AND asset_id = @asset_id
RETURNING *;

-- name: DeleteAssetNote :execrows
DELETE FROM asset_notes WHERE id = @id AND asset_id = @asset_id;
