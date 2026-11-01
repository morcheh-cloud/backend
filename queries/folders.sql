-- name: ListFolders :many
-- server_count counts only the folder's own servers; the client sums subtrees.
SELECT f.*, count(s.id)::int AS server_count
FROM folders f
LEFT JOIN servers s ON s.folder_id = f.id
GROUP BY f.id
ORDER BY lower(f.name);

-- name: GetFolder :one
SELECT * FROM folders WHERE id = $1;

-- name: CreateFolder :one
INSERT INTO folders (name, parent_id)
VALUES (@name, sqlc.narg('parent_id'))
RETURNING *;

-- name: UpdateFolder :one
UPDATE folders
SET name = @name, parent_id = sqlc.narg('parent_id'), updated_at = now()
WHERE id = @id
RETURNING *;

-- name: FolderSubtreeContains :one
-- Whether candidate is folder_id itself or one of its descendants; moving a
-- folder under such a candidate would make a cycle.
WITH RECURSIVE subtree AS (
    SELECT id FROM folders WHERE folders.id = @folder_id
    UNION ALL
    SELECT f.id FROM folders f JOIN subtree t ON f.parent_id = t.id
)
SELECT (@candidate::uuid IN (SELECT id FROM subtree))::bool AS contains;

-- name: ReparentFolderChildren :exec
UPDATE folders SET parent_id = sqlc.narg('new_parent_id'), updated_at = now()
WHERE parent_id = @folder_id;

-- name: MoveFolderServers :exec
UPDATE servers SET folder_id = sqlc.narg('new_folder_id'), updated_at = now()
WHERE folder_id = @folder_id;

-- name: DeleteFolder :execrows
DELETE FROM folders WHERE id = $1;
