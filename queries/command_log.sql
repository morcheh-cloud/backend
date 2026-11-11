-- name: GetCommandLogSettings :one
SELECT * FROM command_log_settings WHERE workspace_id = $1;

-- name: SetCommandLogSettings :one
INSERT INTO command_log_settings (workspace_id, enabled, keep_days, log_reads, log_automatic, log_output, updated_by_name)
VALUES (@workspace_id, @enabled, @keep_days, @log_reads, @log_automatic, @log_output, @updated_by_name)
ON CONFLICT (workspace_id) DO UPDATE SET
    enabled = excluded.enabled,
    keep_days = excluded.keep_days,
    log_reads = excluded.log_reads,
    log_automatic = excluded.log_automatic,
    log_output = excluded.log_output,
    updated_by_name = excluded.updated_by_name,
    updated_at = now()
RETURNING *;

-- name: SaveCommandLog :batchexec
-- Writes a row's whole state; called again as it ends or repeats.
INSERT INTO command_log (
    id, workspace_id, server_id, server_name, user_id, user_name, kind, entry,
    source, ref, recording_id, recording_ms, command, truncated, cwd, as_root,
    started_at, ended_at, exit_code, error, note, interrupted, repeats, last_at, client_ip
) VALUES (
    @id, @workspace_id, sqlc.narg('server_id'), @server_name, sqlc.narg('user_id'), @user_name, @kind, @entry,
    @source, @ref, sqlc.narg('recording_id'), sqlc.narg('recording_ms'), @command, @truncated, @cwd, @as_root,
    @started_at, sqlc.narg('ended_at'), sqlc.narg('exit_code'), @error, @note, @interrupted, @repeats, @last_at, @client_ip
)
ON CONFLICT (id) DO UPDATE SET
    ended_at = excluded.ended_at,
    exit_code = excluded.exit_code,
    error = excluded.error,
    note = excluded.note,
    interrupted = excluded.interrupted,
    repeats = excluded.repeats,
    last_at = excluded.last_at,
    as_root = excluded.as_root;

-- name: InterruptCommandLog :execrows
-- At start-up: commands a previous run of Morcheh was waiting on.
UPDATE command_log SET ended_at = last_at, interrupted = true
WHERE ended_at IS NULL;

-- name: ListCommandLog :many
-- Newest first, a page after the (before_at, before_id) cursor.
SELECT * FROM command_log
WHERE (sqlc.narg('workspace_id')::uuid IS NULL OR workspace_id = sqlc.narg('workspace_id'))
  AND (sqlc.narg('server_id')::uuid IS NULL OR server_id = sqlc.narg('server_id'))
  AND (sqlc.narg('user_id')::uuid IS NULL OR user_id = sqlc.narg('user_id'))
  AND (sqlc.narg('only_user')::uuid IS NULL OR user_id = sqlc.narg('only_user'))
  AND (sqlc.narg('kinds')::text[] IS NULL OR kind = ANY (sqlc.narg('kinds')::text[]))
  AND (sqlc.narg('entry')::text IS NULL OR entry = sqlc.narg('entry'))
  AND (sqlc.narg('ref')::text IS NULL OR ref = sqlc.narg('ref'))
  AND (sqlc.narg('recording_id')::uuid IS NULL OR recording_id = sqlc.narg('recording_id'))
  AND (sqlc.narg('as_root')::boolean IS NULL OR as_root = sqlc.narg('as_root'))
  AND (sqlc.narg('status')::text IS NULL
       OR (sqlc.narg('status') = 'ok' AND exit_code = 0)
       OR (sqlc.narg('status') = 'failed' AND ((exit_code IS NOT NULL AND exit_code <> 0) OR error <> '') AND NOT interrupted)
       OR (sqlc.narg('status') = 'running' AND ended_at IS NULL)
       OR (sqlc.narg('status') = 'interrupted' AND interrupted))
  AND (sqlc.narg('q')::text IS NULL
       OR command ILIKE '%' || sqlc.narg('q') || '%'
       OR source ILIKE '%' || sqlc.narg('q') || '%'
       OR cwd ILIKE '%' || sqlc.narg('q') || '%')
  AND (sqlc.narg('since')::timestamptz IS NULL OR started_at >= sqlc.narg('since'))
  AND (sqlc.narg('until')::timestamptz IS NULL OR started_at < sqlc.narg('until'))
  AND (sqlc.narg('before_at')::timestamptz IS NULL
       OR (started_at, id) < (sqlc.narg('before_at')::timestamptz, sqlc.narg('before_id')::uuid))
ORDER BY started_at DESC, id DESC
LIMIT @lim;

-- name: GetCommandLog :one
SELECT * FROM command_log WHERE id = $1;

-- name: CommandLogPeople :many
-- Who ran commands in the window, for the filter.
SELECT user_id, max(user_name)::text AS user_name, count(*)::int AS n
FROM command_log
WHERE (sqlc.narg('workspace_id')::uuid IS NULL OR workspace_id = sqlc.narg('workspace_id'))
  AND (sqlc.narg('server_id')::uuid IS NULL OR server_id = sqlc.narg('server_id'))
  AND (sqlc.narg('only_user')::uuid IS NULL OR user_id = sqlc.narg('only_user'))
  AND started_at >= @since
GROUP BY user_id
ORDER BY n DESC
LIMIT 100;

-- name: CommandLogServers :many
-- Which servers commands ran on in the window, for the filter.
SELECT server_id, max(server_name)::text AS server_name, count(*)::int AS n
FROM command_log
WHERE workspace_id = @workspace_id
  AND (sqlc.narg('only_user')::uuid IS NULL OR user_id = sqlc.narg('only_user'))
  AND started_at >= @since
  AND server_id IS NOT NULL
GROUP BY server_id
ORDER BY n DESC
LIMIT 200;

-- name: PruneCommandLog :execrows
-- Past each workspace's keep_days (90 without settings).
DELETE FROM command_log c
WHERE c.started_at < now() - make_interval(days => coalesce(
      (SELECT s.keep_days FROM command_log_settings s WHERE s.workspace_id = c.workspace_id), 90));

-- name: SaveCommandLogOutput :batchexec
INSERT INTO command_log_output (id, output, size, truncated, note)
VALUES (@id, @output, @size, @truncated, @note)
ON CONFLICT (id) DO UPDATE SET
    output = excluded.output, size = excluded.size,
    truncated = excluded.truncated, note = excluded.note;

-- name: GetCommandLogOutput :one
SELECT * FROM command_log_output WHERE id = $1;
