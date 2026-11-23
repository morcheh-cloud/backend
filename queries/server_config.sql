-- name: AddConfigChange :one
INSERT INTO server_config_changes (server_id, user_id, user_name, area, summary, status, files)
VALUES (@server_id, @user_id, @user_name, @area, @summary, @status, @files)
RETURNING id;

-- name: ListConfigChanges :many
SELECT id, user_name, area, summary, status, files, created_at
FROM server_config_changes
WHERE server_id = @server_id AND (sqlc.narg(area)::text IS NULL OR area = sqlc.narg(area))
ORDER BY created_at DESC, id DESC
LIMIT 100;

-- name: GetConfigChange :one
SELECT * FROM server_config_changes WHERE id = @id AND server_id = @server_id;

-- name: SettleConfigChanges :exec
UPDATE server_config_changes SET status = @status
WHERE server_id = @server_id AND area = @area AND status = 'pending';

-- name: PruneConfigChanges :exec
DELETE FROM server_config_changes AS old
WHERE old.server_id = @server_id AND old.area = @area AND old.id NOT IN (
    SELECT recent.id FROM server_config_changes AS recent
    WHERE recent.server_id = @server_id AND recent.area = @area
    ORDER BY recent.created_at DESC, recent.id DESC
    LIMIT 50
);
