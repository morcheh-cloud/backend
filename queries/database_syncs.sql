-- name: ListDatabaseSyncs :many
-- With each one's newest run (skipped ones aside), for the list.
SELECT s.*,
    r.id AS last_run_id, r.state AS last_run_state, r.created_at AS last_run_at,
    r.finished_at AS last_run_finished_at, r.error AS last_run_error,
    r.dry_run AS last_run_dry_run
FROM database_syncs s
LEFT JOIN database_sync_runs r ON r.id = (
    SELECT x.id FROM database_sync_runs x
    WHERE x.sync_id = s.id AND x.state <> 'skipped'
    ORDER BY x.created_at DESC, x.id DESC LIMIT 1
)
WHERE (sqlc.narg('workspace_id')::uuid IS NULL OR s.workspace_id = sqlc.narg('workspace_id')::uuid)
  AND (sqlc.narg('database_id')::uuid IS NULL OR s.source_db_id = sqlc.narg('database_id')::uuid OR s.target_db_id = sqlc.narg('database_id')::uuid)
ORDER BY lower(s.name);

-- name: GetDatabaseSync :one
SELECT * FROM database_syncs WHERE id = $1;

-- name: CreateDatabaseSync :one
INSERT INTO database_syncs (
    workspace_id, name, mode, source_db_id, source_name, target_db_id, target_name,
    trigger, cron, timezone, interval_minutes, options, next_run_at, paused,
    created_by, updated_by
) VALUES (
    @workspace_id, @name, @mode, @source_db_id, @source_name, @target_db_id, @target_name,
    @trigger, @cron, @timezone, @interval_minutes, @options, sqlc.narg('next_run_at'), @paused,
    sqlc.narg('created_by'), sqlc.narg('created_by')
)
RETURNING *;

-- name: UpdateDatabaseSync :one
UPDATE database_syncs SET
    name = @name,
    mode = @mode,
    source_db_id = @source_db_id,
    source_name = @source_name,
    target_db_id = @target_db_id,
    target_name = @target_name,
    trigger = @trigger,
    cron = @cron,
    timezone = @timezone,
    interval_minutes = @interval_minutes,
    options = @options,
    marks = @marks,
    next_run_at = sqlc.narg('next_run_at'),
    paused = @paused,
    problem = '',
    updated_by = sqlc.narg('updated_by'),
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: SetDatabaseSyncPaused :one
UPDATE database_syncs SET paused = @paused, next_run_at = sqlc.narg('next_run_at'), updated_at = now()
WHERE id = @id
RETURNING *;

-- name: SetDatabaseSyncMarks :exec
UPDATE database_syncs SET marks = @marks, full_at = sqlc.narg('full_at') WHERE id = @id;

-- name: SetDatabaseSyncProblem :exec
UPDATE database_syncs SET problem = @problem WHERE id = @id;

-- name: DeleteDatabaseSync :execrows
DELETE FROM database_syncs WHERE id = $1;

-- name: ListDueDatabaseSyncs :many
SELECT * FROM database_syncs
WHERE NOT paused AND trigger <> 'manual' AND next_run_at IS NOT NULL AND next_run_at <= @now
ORDER BY next_run_at
LIMIT 100;

-- name: ClaimDatabaseSync :execrows
UPDATE database_syncs SET next_run_at = sqlc.narg('next_run_at')
WHERE id = @id AND next_run_at = @due;

-- name: CreateDatabaseSyncRun :one
INSERT INTO database_sync_runs (
    sync_id, workspace_id, trigger, dry_run, state, error, created_by, created_by_name, finished_at
) VALUES (
    @sync_id, @workspace_id, @trigger, @dry_run, @state, @error,
    sqlc.narg('created_by'), @created_by_name, sqlc.narg('finished_at')
)
RETURNING *;

-- name: SetDatabaseSyncRunJob :exec
UPDATE database_sync_runs SET job_id = @job_id WHERE id = @id;

-- name: StartDatabaseSyncRun :exec
UPDATE database_sync_runs SET state = 'running', started_at = now() WHERE id = $1 AND state = 'queued';

-- name: SaveDatabaseSyncRun :exec
UPDATE database_sync_runs SET phase = @phase, result = @result, rows_written = @rows_written WHERE id = @id;

-- name: FinishDatabaseSyncRun :exec
UPDATE database_sync_runs SET
    state = @state, error = @error, phase = '', result = @result, rows_written = @rows_written,
    finished_at = now()
WHERE id = @id;

-- name: EndDatabaseSyncRun :exec
UPDATE database_sync_runs SET state = @state, error = @error, phase = '', finished_at = now()
WHERE id = @id AND state IN ('queued', 'running');

-- name: GetDatabaseSyncRun :one
SELECT * FROM database_sync_runs WHERE id = $1;

-- name: ListDatabaseSyncRuns :many
SELECT * FROM database_sync_runs
WHERE sync_id = @sync_id
ORDER BY created_at DESC, id DESC
LIMIT @lim;

-- name: ListActiveDatabaseSyncRuns :many
SELECT * FROM database_sync_runs WHERE sync_id = $1 AND state IN ('queued', 'running');

-- name: CountActiveDatabaseSyncRunsTo :one
-- Runs writing into a database now, from any sync.
SELECT count(*) FROM database_sync_runs r
JOIN database_syncs s ON s.id = r.sync_id
WHERE s.target_db_id = @target_db_id AND s.target_name = @target_name AND r.state IN ('queued', 'running') AND NOT r.dry_run;

-- name: PruneDatabaseSyncRuns :exec
DELETE FROM database_sync_runs d
WHERE d.sync_id = @sync_id::uuid AND d.id NOT IN (
    SELECT x.id FROM database_sync_runs x WHERE x.sync_id = @sync_id::uuid ORDER BY x.created_at DESC, x.id DESC LIMIT @keep
);

-- name: GetDatabaseSyncEnds :one
-- What access to a sync follows: both databases' workspaces and servers.
SELECT src.workspace_id AS source_workspace_id, src.server_id AS source_server_id,
    dst.workspace_id AS target_workspace_id, dst.server_id AS target_server_id
FROM database_syncs s
JOIN databases src ON src.id = s.source_db_id
JOIN databases dst ON dst.id = s.target_db_id
WHERE s.id = $1;

-- name: GetDatabaseSyncRunEnds :one
SELECT src.workspace_id AS source_workspace_id, src.server_id AS source_server_id,
    dst.workspace_id AS target_workspace_id, dst.server_id AS target_server_id
FROM database_sync_runs r
JOIN database_syncs s ON s.id = r.sync_id
JOIN databases src ON src.id = s.source_db_id
JOIN databases dst ON dst.id = s.target_db_id
WHERE r.id = $1;
