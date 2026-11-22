-- name: GetPitr :one
SELECT * FROM database_pitr WHERE database_id = $1;

-- name: UpsertPitr :one
INSERT INTO database_pitr (
    database_id, workspace_id, storage_id, folder, full_cron, diff_cron, incr_cron, timezone,
    next_full_at, next_diff_at, next_incr_at, retention_full, compress_level, process_max,
    archive_timeout, cipher_pass_enc, enabled, created_by, updated_by
) VALUES (
    @database_id, @workspace_id, @storage_id, @folder, @full_cron, @diff_cron, @incr_cron, @timezone,
    sqlc.narg('next_full_at'), sqlc.narg('next_diff_at'), sqlc.narg('next_incr_at'), @retention_full,
    @compress_level, @process_max, @archive_timeout, sqlc.narg('cipher_pass_enc'), @enabled,
    sqlc.narg('updated_by'), sqlc.narg('updated_by')
)
ON CONFLICT (database_id) DO UPDATE SET
    storage_id = EXCLUDED.storage_id, folder = EXCLUDED.folder,
    full_cron = EXCLUDED.full_cron, diff_cron = EXCLUDED.diff_cron, incr_cron = EXCLUDED.incr_cron,
    timezone = EXCLUDED.timezone, next_full_at = EXCLUDED.next_full_at,
    next_diff_at = EXCLUDED.next_diff_at, next_incr_at = EXCLUDED.next_incr_at,
    retention_full = EXCLUDED.retention_full, compress_level = EXCLUDED.compress_level,
    process_max = EXCLUDED.process_max, archive_timeout = EXCLUDED.archive_timeout,
    cipher_pass_enc = EXCLUDED.cipher_pass_enc, enabled = EXCLUDED.enabled,
    updated_by = EXCLUDED.updated_by, updated_at = now()
RETURNING *;

-- name: SetPitrState :exec
UPDATE database_pitr SET state = @state, problem = @problem, updated_at = now()
WHERE database_id = @database_id;

-- name: SetPitrCluster :exec
UPDATE database_pitr SET cluster = @cluster WHERE database_id = @database_id;

-- name: SetPitrInfo :exec
UPDATE database_pitr SET info = @info, checked_at = now() WHERE database_id = @database_id;

-- name: SetPitrRestartAt :exec
UPDATE database_pitr SET restart_at = sqlc.narg('restart_at') WHERE database_id = @database_id;

-- name: DeletePitr :exec
DELETE FROM database_pitr WHERE database_id = $1;

-- name: ListPitrs :many
SELECT * FROM database_pitr ORDER BY database_id;

-- name: ListDuePitrBackups :many
SELECT * FROM database_pitr
WHERE enabled AND state = 'ready'
  AND (next_full_at <= @now OR next_diff_at <= @now OR next_incr_at <= @now);

-- name: ClaimPitrBackups :execrows
UPDATE database_pitr SET next_full_at = sqlc.narg('next_full_at'), next_diff_at = sqlc.narg('next_diff_at'),
    next_incr_at = sqlc.narg('next_incr_at')
WHERE database_id = @database_id
  AND next_full_at IS NOT DISTINCT FROM sqlc.narg('was_full')
  AND next_diff_at IS NOT DISTINCT FROM sqlc.narg('was_diff')
  AND next_incr_at IS NOT DISTINCT FROM sqlc.narg('was_incr');

-- name: ListDuePitrRestarts :many
SELECT * FROM database_pitr WHERE state = 'needs_restart' AND restart_at <= @now;

-- name: CreatePitrRun :one
INSERT INTO database_pitr_runs (database_id, kind, variant, trigger, target_time, created_by, created_by_name)
VALUES (@database_id, @kind, @variant, @trigger, sqlc.narg('target_time'), sqlc.narg('created_by'), @created_by_name)
RETURNING *;

-- name: SetPitrRunJob :exec
UPDATE database_pitr_runs SET job_id = @job_id WHERE id = @id;

-- name: StartPitrRun :exec
UPDATE database_pitr_runs SET state = 'running', started_at = now() WHERE id = $1;

-- name: EndPitrRun :exec
UPDATE database_pitr_runs SET state = @state, error = @error, finished_at = now() WHERE id = @id;

-- name: SetPitrRunRestore :exec
UPDATE database_pitr_runs SET restore_dir = @restore_dir, restore_port = @restore_port,
    restore_database_id = sqlc.narg('restore_database_id')
WHERE id = @id;

-- name: SetPitrRunRemoved :exec
UPDATE database_pitr_runs SET removed_at = now() WHERE id = $1;

-- name: GetPitrRun :one
SELECT * FROM database_pitr_runs WHERE id = $1;

-- name: ListPitrRuns :many
SELECT * FROM database_pitr_runs WHERE database_id = @database_id
ORDER BY created_at DESC LIMIT @lim OFFSET @off;

-- name: CountPitrRuns :one
SELECT count(*) FROM database_pitr_runs WHERE database_id = $1;

-- name: ListPitrCopies :many
SELECT * FROM database_pitr_runs
WHERE database_id = $1 AND kind = 'restore' AND variant = 'new' AND restore_dir <> '' AND removed_at IS NULL
ORDER BY created_at DESC;

-- name: ActivePitrRun :one
SELECT count(*) FROM database_pitr_runs WHERE database_id = $1 AND state IN ('queued', 'running');

-- name: InterruptPitrRuns :exec
-- At start: nothing is running any more.
UPDATE database_pitr_runs SET state = 'interrupted', error = 'Morche restarted before it finished.', finished_at = now()
WHERE state IN ('queued', 'running');

-- name: ListReadyPitrs :many
SELECT * FROM database_pitr WHERE state IN ('ready', 'broken');

-- name: ActivePitrRunRow :one
SELECT * FROM database_pitr_runs WHERE database_id = $1 AND state IN ('queued', 'running')
ORDER BY created_at DESC LIMIT 1;

-- name: PitrSibling :one
-- Another database row for the same PostgreSQL (server and port) that
-- already has continuous backup: a second setup would overwrite its config.
SELECT d.id, d.name FROM database_pitr p JOIN databases d ON d.id = p.database_id
WHERE d.server_id = @server_id AND d.port = @port AND d.id <> @database_id
LIMIT 1;

-- name: ResetStuckPitrs :exec
-- At start: a setup or removal cut off by a restart needs a look.
UPDATE database_pitr SET state = 'broken', problem = 'Morche restarted before it finished: set it up again.'
WHERE state IN ('setting_up', 'removing');
