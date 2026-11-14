-- name: ListStorageSyncs :many
-- With each one's newest run (skipped ones aside), for the list.
SELECT s.*,
    r.id AS last_run_id, r.state AS last_run_state, r.created_at AS last_run_at,
    r.finished_at AS last_run_finished_at, r.error AS last_run_error,
    r.dry_run AS last_run_dry_run
FROM storage_syncs s
LEFT JOIN storage_sync_runs r ON r.id = (
    SELECT x.id FROM storage_sync_runs x
    WHERE x.sync_id = s.id AND x.state <> 'skipped'
    ORDER BY x.created_at DESC, x.id DESC LIMIT 1
)
WHERE s.workspace_id = @workspace_id
  AND (sqlc.narg('storage_id')::uuid IS NULL OR s.source_storage_id = sqlc.narg('storage_id')::uuid OR s.dest_storage_id = sqlc.narg('storage_id')::uuid)
ORDER BY s.kind, lower(s.name);

-- name: GetStorageSync :one
SELECT * FROM storage_syncs WHERE id = $1;

-- name: GetStorageSyncWorkspace :one
SELECT workspace_id FROM storage_syncs WHERE id = $1;

-- name: CreateStorageSync :one
INSERT INTO storage_syncs (
    workspace_id, kind, name, source_storage_id, source_path, dest_storage_id, dest_path,
    engine, mode, trigger, cron, timezone, interval_minutes, options, next_run_at,
    created_by, updated_by
) VALUES (
    @workspace_id, @kind, @name, @source_storage_id, @source_path, @dest_storage_id, @dest_path,
    @engine, @mode, @trigger, @cron, @timezone, @interval_minutes, @options, sqlc.narg('next_run_at'),
    sqlc.narg('created_by'), sqlc.narg('created_by')
)
RETURNING *;

-- name: UpdateStorageSync :one
UPDATE storage_syncs SET
    name = @name,
    source_storage_id = @source_storage_id,
    source_path = @source_path,
    dest_storage_id = @dest_storage_id,
    dest_path = @dest_path,
    engine = @engine,
    mode = @mode,
    trigger = @trigger,
    cron = @cron,
    timezone = @timezone,
    interval_minutes = @interval_minutes,
    options = @options,
    next_run_at = sqlc.narg('next_run_at'),
    updated_by = sqlc.narg('updated_by'),
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: SetStorageSyncPaused :one
-- Pausing and resuming don't change whose access it runs with.
UPDATE storage_syncs SET paused = @paused, next_run_at = sqlc.narg('next_run_at'), updated_at = now()
WHERE id = @id
RETURNING *;

-- name: SetStorageSyncNative :exec
UPDATE storage_syncs SET native = @native, problem = @problem WHERE id = @id;

-- name: SetStorageSyncHeld :exec
UPDATE storage_syncs SET held = @held WHERE id = @id;

-- name: DeleteStorageSync :execrows
DELETE FROM storage_syncs WHERE id = $1;

-- name: ListDueStorageSyncs :many
SELECT * FROM storage_syncs
WHERE NOT paused AND trigger <> 'manual' AND next_run_at IS NOT NULL AND next_run_at <= @now
ORDER BY next_run_at
LIMIT 100;

-- name: ClaimStorageSync :execrows
-- Moves next_run_at on, only if nobody else did first.
UPDATE storage_syncs SET next_run_at = sqlc.narg('next_run_at')
WHERE id = @id AND next_run_at = @due;

-- name: SetStorageSyncNext :exec
UPDATE storage_syncs SET next_run_at = sqlc.narg('next_run_at') WHERE id = @id;

-- name: CreateStorageSyncRun :one
INSERT INTO storage_sync_runs (
    sync_id, workspace_id, trigger, dry_run, state, error, created_by, created_by_name, finished_at
) VALUES (
    @sync_id, @workspace_id, @trigger, @dry_run, @state, @error,
    sqlc.narg('created_by'), @created_by_name, sqlc.narg('finished_at')
)
RETURNING *;

-- name: SetStorageSyncRunJob :exec
UPDATE storage_sync_runs SET job_id = @job_id WHERE id = @id;

-- name: StartStorageSyncRun :exec
UPDATE storage_sync_runs SET state = 'running', started_at = now() WHERE id = $1 AND state = 'queued';

-- name: SaveStorageSyncRun :exec
-- While it runs, so the page shows where it is.
UPDATE storage_sync_runs SET phase = @phase, result = @result, files = @files, bytes = @bytes WHERE id = @id;

-- name: FinishStorageSyncRun :exec
UPDATE storage_sync_runs SET
    state = @state, error = @error, phase = '', result = @result, files = @files, bytes = @bytes,
    finished_at = now()
WHERE id = @id;

-- name: EndStorageSyncRun :exec
-- Ends a run that's still queued or running, keeping what it recorded.
UPDATE storage_sync_runs SET state = @state, error = @error, phase = '', finished_at = now()
WHERE id = @id AND state IN ('queued', 'running');

-- name: GetStorageSyncRun :one
SELECT * FROM storage_sync_runs WHERE id = $1;

-- name: GetStorageSyncRunWorkspace :one
SELECT workspace_id FROM storage_sync_runs WHERE id = $1;

-- name: ListStorageSyncRuns :many
SELECT * FROM storage_sync_runs
WHERE sync_id = @sync_id
ORDER BY created_at DESC, id DESC
LIMIT @lim;

-- name: ListActiveStorageSyncRuns :many
SELECT * FROM storage_sync_runs WHERE sync_id = $1 AND state IN ('queued', 'running');

-- name: PruneStorageSyncRuns :exec
DELETE FROM storage_sync_runs d
WHERE d.sync_id = @sync_id::uuid AND d.id NOT IN (
    SELECT x.id FROM storage_sync_runs x WHERE x.sync_id = @sync_id::uuid ORDER BY x.created_at DESC, x.id DESC LIMIT @keep
);
