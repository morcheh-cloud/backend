-- name: ListLogArchivePolicies :many
SELECT * FROM log_archive_policies ORDER BY dataset;

-- name: GetLogArchivePolicy :one
SELECT * FROM log_archive_policies WHERE dataset = $1;

-- name: SaveLogArchivePolicy :one
INSERT INTO log_archive_policies (
    dataset, enabled, mode, after_days, max_mb, period, keep_local, storage_ids, folder,
    keep_days, cron, timezone, next_run_at, updated_by, updated_at)
VALUES (
    @dataset, @enabled, @mode, @after_days, @max_mb, @period, @keep_local, @storage_ids, @folder,
    @keep_days, @cron, @timezone, sqlc.narg('next_run_at'), sqlc.narg('updated_by'), now())
ON CONFLICT (dataset) DO UPDATE SET
    enabled = EXCLUDED.enabled, mode = EXCLUDED.mode, after_days = EXCLUDED.after_days,
    max_mb = EXCLUDED.max_mb, period = EXCLUDED.period, keep_local = EXCLUDED.keep_local,
    storage_ids = EXCLUDED.storage_ids, folder = EXCLUDED.folder, keep_days = EXCLUDED.keep_days,
    cron = EXCLUDED.cron, timezone = EXCLUDED.timezone, next_run_at = EXCLUDED.next_run_at,
    updated_by = EXCLUDED.updated_by, updated_at = now()
RETURNING *;

-- name: SeedLogArchivePolicy :exec
-- A kind of logs' default policy, unless it already has one.
INSERT INTO log_archive_policies (
    dataset, enabled, mode, after_days, max_mb, period, keep_local, storage_ids, folder,
    keep_days, cron, timezone, next_run_at, updated_at)
VALUES (
    @dataset, @enabled, @mode, @after_days, @max_mb, @period, @keep_local, @storage_ids, @folder,
    @keep_days, @cron, @timezone, sqlc.narg('next_run_at'), now())
ON CONFLICT (dataset) DO NOTHING;

-- name: DueLogArchivePolicies :many
SELECT * FROM log_archive_policies
WHERE enabled AND next_run_at IS NOT NULL AND next_run_at <= now()
ORDER BY next_run_at;

-- name: LogArchivePoliciesWithoutNext :many
SELECT * FROM log_archive_policies WHERE enabled AND next_run_at IS NULL;

-- name: SetLogArchivePolicyNext :exec
UPDATE log_archive_policies SET next_run_at = sqlc.narg('next_run_at') WHERE dataset = @dataset;

-- name: ClaimLogArchivePolicy :execrows
-- Moves next_run_at on, only if nobody else did first.
UPDATE log_archive_policies SET next_run_at = sqlc.narg('next_run_at')
WHERE dataset = @dataset AND next_run_at = @due;

-- name: SetLogArchivePolicyRun :exec
UPDATE log_archive_policies SET last_run_at = now(), last_state = @last_state,
    last_note = @last_note, last_job_id = sqlc.narg('last_job_id')
WHERE dataset = @dataset;

-- name: CreateLogArchive :one
INSERT INTO log_archives (dataset, mode, period_from, period_to, file_name, note, job_id, created_by, created_by_name)
VALUES (@dataset, @mode, @period_from, @period_to, @file_name, @note, sqlc.narg('job_id'),
    sqlc.narg('created_by'), @created_by_name)
RETURNING *;

-- name: FinishLogArchive :one
UPDATE log_archives SET state = @state, error = @error, rows = @rows, tables = @tables,
    bytes = @bytes, sha256 = @sha256, finished_at = now()
WHERE id = @id
RETURNING *;

-- name: GetLogArchive :one
SELECT * FROM log_archives WHERE id = $1;

-- name: ListLogArchives :many
SELECT * FROM log_archives
WHERE (sqlc.narg('dataset')::text IS NULL OR dataset = sqlc.narg('dataset'))
  AND (sqlc.narg('state')::text IS NULL OR state = sqlc.narg('state'))
  AND (NOT @held_only::boolean OR restore_state = 'held')
ORDER BY period_from DESC, created_at DESC
LIMIT @lim OFFSET @off;

-- name: CountLogArchives :one
SELECT count(*) FROM log_archives
WHERE (sqlc.narg('dataset')::text IS NULL OR dataset = sqlc.narg('dataset'))
  AND (sqlc.narg('state')::text IS NULL OR state = sqlc.narg('state'))
  AND (NOT @held_only::boolean OR restore_state = 'held');

-- name: LogArchiveTotals :many
SELECT dataset, count(*)::bigint AS files, coalesce(sum(bytes), 0)::bigint AS bytes,
    coalesce(sum(rows), 0)::bigint AS rows, min(period_from)::timestamptz AS oldest,
    count(*) FILTER (WHERE restore_state = 'held')::bigint AS held
FROM log_archives WHERE state = 'stored'
GROUP BY dataset;

-- name: StoredLogArchiveWindows :many
-- Periods already kept in a file, so a copy policy doesn't export them twice.
SELECT period_from, period_to, mode FROM log_archives
WHERE dataset = @dataset AND state IN ('stored', 'running');

-- name: HeldLogArchives :many
-- Restored rows that are back in the database for now: a policy must not
-- archive them again while held.
SELECT * FROM log_archives WHERE dataset = @dataset AND restore_state IN ('held', 'running');

-- name: ExpiredLogArchiveHolds :many
SELECT * FROM log_archives WHERE restore_state = 'held' AND hold_until <= now();

-- name: SetLogArchiveRestore :one
UPDATE log_archives SET restore_state = @restore_state, restored_at = sqlc.narg('restored_at'),
    restored_rows = @restored_rows, restored_by_name = @restored_by_name,
    restore_error = @restore_error, hold_until = sqlc.narg('hold_until')
WHERE id = @id
RETURNING *;

-- name: ClaimLogArchiveRestore :execrows
UPDATE log_archives SET restore_state = 'running', restore_error = ''
WHERE id = @id AND restore_state <> 'running';

-- name: SetLogArchiveHold :one
UPDATE log_archives SET hold_until = sqlc.narg('hold_until') WHERE id = @id AND restore_state = 'held'
RETURNING *;

-- name: ExpiredLogArchives :many
-- Files older than their policy keeps them (never one whose rows are back).
SELECT a.* FROM log_archives a
JOIN log_archive_policies p ON p.dataset = a.dataset
WHERE p.keep_days > 0 AND a.state = 'stored' AND a.restore_state NOT IN ('held', 'running')
  AND a.created_at < now() - make_interval(days => p.keep_days);

-- name: DeleteLogArchive :exec
DELETE FROM log_archives WHERE id = $1;

-- name: InterruptLogArchives :exec
-- At start: nothing is running any more.
UPDATE log_archives SET state = 'interrupted', error = 'Morche stopped while it was being written.',
    finished_at = now()
WHERE state = 'running';

-- name: ResetLogArchiveRestores :exec
UPDATE log_archives SET restore_state = '', restore_error = 'Morche stopped while it was being put back.'
WHERE restore_state = 'running';

-- name: AddLogArchiveCopy :one
INSERT INTO log_archive_copies (archive_id, local, storage_id, storage_name, path)
VALUES (@archive_id, @local, sqlc.narg('storage_id'), @storage_name, @path)
RETURNING *;

-- name: SetLogArchiveCopy :exec
UPDATE log_archive_copies SET state = @state, error = @error WHERE id = @id;

-- name: ListLogArchiveCopies :many
SELECT * FROM log_archive_copies WHERE archive_id = ANY(@archive_ids::uuid[]) ORDER BY local DESC, storage_name;

-- name: DeleteLogArchiveCopy :exec
DELETE FROM log_archive_copies WHERE id = $1;
