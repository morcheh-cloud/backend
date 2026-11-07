-- name: GetTerminalRecordingSettings :one
SELECT * FROM terminal_recording_settings WHERE workspace_id = $1;

-- name: SetTerminalRecordingSettings :one
INSERT INTO terminal_recording_settings (workspace_id, enabled, keep_days, updated_by_name)
VALUES (@workspace_id, @enabled, @keep_days, @updated_by_name)
ON CONFLICT (workspace_id) DO UPDATE SET
    enabled = excluded.enabled,
    keep_days = excluded.keep_days,
    updated_by_name = excluded.updated_by_name,
    updated_at = now()
RETURNING *;

-- name: CreateTerminalRecording :one
INSERT INTO terminal_recordings (workspace_id, server_id, server_name, user_id, user_name, title, cols, rows, started_at)
VALUES (@workspace_id, @server_id, @server_name, sqlc.narg('user_id'), @user_name, @title, @cols, @rows, @started_at)
RETURNING id;

-- name: SaveTerminalRecording :exec
UPDATE terminal_recordings SET
    title = @title,
    duration_ms = @duration_ms,
    size = @size,
    truncated = @truncated,
    data = @data
WHERE id = @id;

-- name: EndTerminalRecording :exec
UPDATE terminal_recordings SET
    title = @title,
    duration_ms = @duration_ms,
    size = @size,
    truncated = @truncated,
    data = @data,
    exit_code = sqlc.narg('exit_code'),
    ended_at = now()
WHERE id = @id;

-- name: InterruptTerminalRecordings :execrows
-- At start-up: shells recorded by a previous run of Morcheh are gone.
UPDATE terminal_recordings SET
    ended_at = started_at + duration_ms * interval '1 millisecond',
    interrupted = true
WHERE ended_at IS NULL;

-- name: ListTerminalRecordings :many
-- Without the data. user_id narrows to one person's sessions.
SELECT id, workspace_id, server_id, server_name, user_id, user_name, title, cols, rows,
       started_at, ended_at, exit_code, interrupted, duration_ms, size, truncated
FROM terminal_recordings
WHERE (sqlc.narg('workspace_id')::uuid IS NULL OR workspace_id = sqlc.narg('workspace_id'))
  AND (sqlc.narg('server_id')::uuid IS NULL OR server_id = sqlc.narg('server_id'))
  AND (sqlc.narg('user_id')::uuid IS NULL OR user_id = sqlc.narg('user_id'))
  AND (sqlc.narg('q')::text IS NULL
       OR title ILIKE '%' || sqlc.narg('q') || '%'
       OR server_name ILIKE '%' || sqlc.narg('q') || '%'
       OR user_name ILIKE '%' || sqlc.narg('q') || '%')
ORDER BY started_at DESC, id DESC
LIMIT @lim OFFSET @off;

-- name: CountTerminalRecordings :one
SELECT count(*)::int FROM terminal_recordings
WHERE (sqlc.narg('workspace_id')::uuid IS NULL OR workspace_id = sqlc.narg('workspace_id'))
  AND (sqlc.narg('server_id')::uuid IS NULL OR server_id = sqlc.narg('server_id'))
  AND (sqlc.narg('user_id')::uuid IS NULL OR user_id = sqlc.narg('user_id'))
  AND (sqlc.narg('q')::text IS NULL
       OR title ILIKE '%' || sqlc.narg('q') || '%'
       OR server_name ILIKE '%' || sqlc.narg('q') || '%'
       OR user_name ILIKE '%' || sqlc.narg('q') || '%');

-- name: GetTerminalRecordingInfo :one
SELECT id, workspace_id, server_id, server_name, user_id, user_name, title, cols, rows,
       started_at, ended_at, exit_code, interrupted, duration_ms, size, truncated
FROM terminal_recordings WHERE id = $1;

-- name: GetTerminalRecordingData :one
SELECT data, ended_at, interrupted FROM terminal_recordings WHERE id = $1;

-- name: DeleteTerminalRecording :execrows
DELETE FROM terminal_recordings WHERE id = $1;

-- name: PruneTerminalRecordings :execrows
-- Past each workspace's keep_days (90 without settings). Live ones stay.
DELETE FROM terminal_recordings r
WHERE r.ended_at IS NOT NULL
  AND r.started_at < now() - make_interval(days => coalesce(
      (SELECT s.keep_days FROM terminal_recording_settings s WHERE s.workspace_id = r.workspace_id), 90));
