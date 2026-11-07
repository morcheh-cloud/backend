-- name: ListBackupPlans :many
SELECT * FROM database_backup_plans WHERE database_id = $1 ORDER BY lower(name);

-- name: GetBackupPlan :one
SELECT * FROM database_backup_plans WHERE id = $1;

-- name: GetBackupPlanDatabase :one
SELECT database_id FROM database_backup_plans WHERE id = $1;

-- name: CreateBackupPlan :one
INSERT INTO database_backup_plans (
    workspace_id, database_id, name, folder, selection, targets, pattern, method,
    full_every_days, retention, keep_days, gfs_daily, gfs_weekly, gfs_monthly, runner_server_id,
    username, password_enc, cron, timezone, enabled, next_run_at, created_by, updated_by
) VALUES (
    @workspace_id, @database_id, @name, @folder, @selection, @targets::text[], @pattern, @method,
    @full_every_days, @retention, @keep_days, @gfs_daily, @gfs_weekly, @gfs_monthly,
    sqlc.narg('runner_server_id'), @username, sqlc.narg('password_enc'), @cron, @timezone,
    @enabled, sqlc.narg('next_run_at'), sqlc.narg('created_by'), sqlc.narg('created_by')
)
RETURNING *;

-- name: UpdateBackupPlan :one
UPDATE database_backup_plans SET
    name = @name, folder = @folder, selection = @selection, targets = @targets::text[],
    pattern = @pattern, method = @method, full_every_days = @full_every_days,
    retention = @retention, keep_days = @keep_days, gfs_daily = @gfs_daily,
    gfs_weekly = @gfs_weekly, gfs_monthly = @gfs_monthly,
    runner_server_id = sqlc.narg('runner_server_id'), username = @username,
    password_enc = sqlc.narg('password_enc'), cron = @cron, timezone = @timezone,
    enabled = @enabled, next_run_at = sqlc.narg('next_run_at'),
    updated_by = sqlc.narg('updated_by'), updated_at = now()
WHERE id = @id
RETURNING *;

-- name: SetBackupPlanStorages :exec
WITH gone AS (
    DELETE FROM database_backup_plan_storages
    WHERE plan_id = @plan_id AND NOT (storage_id = ANY (@storage_ids::uuid[]))
)
INSERT INTO database_backup_plan_storages (plan_id, storage_id, position)
SELECT @plan_id, s.id, s.ord::integer
FROM unnest(@storage_ids::uuid[]) WITH ORDINALITY AS s (id, ord)
ON CONFLICT (plan_id, storage_id) DO UPDATE SET position = EXCLUDED.position;

-- name: ListBackupPlanStorages :many
SELECT storage_id FROM database_backup_plan_storages WHERE plan_id = $1 ORDER BY position;

-- name: DeleteBackupPlan :execrows
DELETE FROM database_backup_plans WHERE id = $1;

-- name: ListDueBackupPlans :many
SELECT * FROM database_backup_plans
WHERE enabled AND next_run_at IS NOT NULL AND next_run_at <= sqlc.narg('now')::timestamptz
ORDER BY next_run_at;

-- name: ClaimBackupPlan :execrows
-- Moves a due plan on; 0 rows means something else already did.
UPDATE database_backup_plans SET next_run_at = sqlc.narg('next_run_at')
WHERE id = @id AND next_run_at = sqlc.narg('due')::timestamptz;

-- name: AnyBackupPlanEnabled :one
SELECT EXISTS (SELECT 1 FROM database_backup_plans WHERE database_id = $1 AND enabled);

-- name: LastGoodBackup :one
SELECT * FROM database_backups
WHERE database_id = $1 AND state = 'succeeded'
ORDER BY id DESC LIMIT 1;

-- name: ListBackupPlansWithoutNext :many
SELECT * FROM database_backup_plans WHERE enabled AND cron <> '' AND next_run_at IS NULL;

-- name: SetBackupPlanNext :exec
UPDATE database_backup_plans SET next_run_at = sqlc.narg('next_run_at') WHERE id = @id;

-- name: CreateBackup :one
INSERT INTO database_backups (
    workspace_id, database_id, plan_id, plan_name, engine, target, trigger, state, error,
    created_by, created_by_name, finished_at
) VALUES (
    @workspace_id, @database_id, sqlc.narg('plan_id'), @plan_name, @engine, @target, @trigger,
    @state, @error, sqlc.narg('created_by'), @created_by_name, sqlc.narg('finished_at')
)
RETURNING *;

-- name: CreateBackupCopy :exec
INSERT INTO database_backup_copies (backup_id, storage_id, storage_name)
VALUES (@backup_id, sqlc.narg('storage_id'), @storage_name);

-- name: SetBackupCopy :exec
UPDATE database_backup_copies SET state = @state, error = @error
WHERE backup_id = @backup_id AND storage_id = @storage_id;

-- name: FailBackupCopies :exec
-- Copies of a run that ended without storing them.
UPDATE database_backup_copies SET state = 'failed' WHERE backup_id = @backup_id AND state = 'pending';

-- name: ListBackupCopies :many
SELECT * FROM database_backup_copies WHERE backup_id = ANY (@backup_ids::uuid[]) ORDER BY id;

-- name: SetBackupJob :exec
UPDATE database_backups SET job_id = @job_id WHERE id = @id;

-- name: GetBackup :one
SELECT * FROM database_backups WHERE id = $1;

-- name: GetBackupDatabase :one
SELECT database_id FROM database_backups WHERE id = $1;

-- name: ListBackups :many
SELECT * FROM database_backups WHERE database_id = @database_id
ORDER BY id DESC LIMIT @lim OFFSET @off;

-- name: CountBackups :one
SELECT count(*) FROM database_backups WHERE database_id = $1;

-- name: ListActiveBackups :many
SELECT * FROM database_backups WHERE plan_id = $1 AND state IN ('queued', 'running');

-- name: StartBackup :exec
UPDATE database_backups SET state = 'running', started_at = coalesce(started_at, now()), path = @path,
    format = @format, kind = @kind, parent_id = sqlc.narg('parent_id')
WHERE id = @id;

-- name: FinishBackup :exec
-- error is a warning here: a copy that failed while another worked.
UPDATE database_backups SET state = 'succeeded', bytes = @bytes, sha256 = @sha256, position = @position,
    error = @error, finished_at = now()
WHERE id = @id;

-- name: EndBackup :exec
-- Only a run still going: a run that finished keeps its outcome.
UPDATE database_backups SET state = @state, error = @error, finished_at = now()
WHERE id = @id AND state IN ('queued', 'running');

-- name: SetBackupVerified :exec
UPDATE database_backups SET verified_at = now(), verify_error = @verify_error WHERE id = @id;

-- name: DeleteBackup :execrows
DELETE FROM database_backups WHERE id = $1;

-- name: LastBackups :many
-- Each plan's newest finished run; of a run over several databases, the one
-- that failed if any did.
SELECT DISTINCT ON (b.plan_id) b.plan_id, b.id, b.state, b.error, b.created_at, b.finished_at, b.bytes
FROM database_backups b
WHERE b.plan_id = ANY (@plan_ids::uuid[]) AND b.state NOT IN ('queued', 'running', 'skipped')
ORDER BY b.plan_id, coalesce(b.job_id, b.id) DESC, b.state IN ('failed', 'interrupted') DESC, b.id DESC;

-- name: LastGoodBackupTimes :many
SELECT b.plan_id, max(b.finished_at)::timestamptz AS at FROM database_backups b
WHERE b.plan_id = ANY (@plan_ids::uuid[]) AND b.state = 'succeeded'
GROUP BY b.plan_id;

-- name: ListPlanBackups :many
-- Every good backup of a plan, newest first: what retention looks at.
SELECT * FROM database_backups
WHERE plan_id = @plan_id AND state = 'succeeded'
ORDER BY id DESC;

-- name: LastPlanBackup :one
-- The newest good backup of one database in a plan: an incremental builds on it.
SELECT * FROM database_backups
WHERE plan_id = @plan_id AND target = @target AND state = 'succeeded'
ORDER BY id DESC LIMIT 1;

-- name: BackupChain :many
-- A backup and all it builds on, oldest first.
WITH RECURSIVE chain AS (
    SELECT c.id, c.parent_id, 0 AS depth FROM database_backups c WHERE c.id = $1
    UNION ALL
    SELECT p.id, p.parent_id, chain.depth + 1
    FROM database_backups p JOIN chain ON p.id = chain.parent_id
)
SELECT b.* FROM database_backups b JOIN chain ON chain.id = b.id ORDER BY chain.depth DESC;

-- name: BackupDependents :many
-- What builds on a backup, directly or not, newest first.
WITH RECURSIVE dep AS (
    SELECT b.id FROM database_backups b WHERE b.parent_id = $1
    UNION ALL
    SELECT c.id FROM database_backups c JOIN dep ON c.parent_id = dep.id
)
SELECT d.id FROM database_backups d WHERE d.id IN (SELECT id FROM dep) ORDER BY d.id DESC;

-- name: CountBackupChildren :many
SELECT parent_id, count(*)::bigint AS total FROM database_backups
WHERE parent_id = ANY (@ids::uuid[]) GROUP BY parent_id;

-- name: PruneBackupRecords :exec
-- Rows of runs that left no backup, past the newest @keep of a plan.
DELETE FROM database_backups
WHERE id IN (
    SELECT o.id FROM database_backups o
    WHERE o.plan_id = @plan_id AND o.state IN ('failed', 'canceled', 'interrupted', 'skipped')
    ORDER BY o.id DESC OFFSET @keep
);

-- name: ListBackupProblems :many
-- Enabled plans whose newest run failed for at least one of its databases, in
-- what the caller reaches.
SELECT p.id AS plan_id, p.name AS plan_name, p.database_id, d.name AS database_name,
       b.state, b.error, b.created_at
FROM database_backup_plans p
JOIN databases d ON d.id = p.database_id
JOIN LATERAL (
    SELECT state, error, created_at FROM database_backups
    WHERE plan_id = p.id AND state NOT IN ('queued', 'running', 'skipped')
    ORDER BY coalesce(job_id, id) DESC, state IN ('failed', 'interrupted') DESC, id DESC LIMIT 1
) b ON true
WHERE p.enabled AND b.state IN ('failed', 'interrupted')
  AND (@see_all::bool OR d.workspace_id = ANY (@workspace_ids::uuid[])
       OR d.server_id = ANY (@server_ids::uuid[]))
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR d.workspace_id = sqlc.narg('workspace_id')::uuid)
ORDER BY b.created_at DESC;

-- name: CreateRestore :one
INSERT INTO database_restores (
    workspace_id, database_id, backup_id, source, target_name, mode, runner_server_id, storage_id,
    want_safety, username, password_enc, created_by, created_by_name
) VALUES (
    @workspace_id, @database_id, @backup_id, @source, @target_name, @mode,
    sqlc.narg('runner_server_id'), sqlc.narg('storage_id'), @want_safety, @username,
    sqlc.narg('password_enc'), sqlc.narg('created_by'), @created_by_name
)
RETURNING *;

-- name: SetRestoreJob :exec
UPDATE database_restores SET job_id = @job_id WHERE id = @id;

-- name: GetRestore :one
SELECT * FROM database_restores WHERE id = $1;

-- name: ListRestores :many
SELECT * FROM database_restores WHERE database_id = @database_id
ORDER BY id DESC LIMIT @lim OFFSET @off;

-- name: CountRestores :one
SELECT count(*) FROM database_restores WHERE database_id = $1;

-- name: CountActiveRestores :one
SELECT count(*) FROM database_restores WHERE database_id = $1 AND state IN ('queued', 'running');

-- name: StartRestore :exec
UPDATE database_restores SET state = 'running', started_at = now() WHERE id = @id;

-- name: SetRestoreSafety :exec
UPDATE database_restores SET safety_backup_id = @safety_backup_id WHERE id = @id;

-- name: EndRestore :exec
-- Only a restore still going. The login it was given goes with it.
UPDATE database_restores SET state = @state, error = @error, finished_at = now(),
    username = '', password_enc = NULL
WHERE id = @id AND state IN ('queued', 'running');

-- name: LastRestoreAt :one
-- When a restore last rewrote a database: the chain up to then no longer fits.
SELECT coalesce(max(finished_at), 'epoch'::timestamptz)::timestamptz AS at
FROM database_restores
WHERE database_id = @database_id AND target_name = @target_name AND state <> 'canceled';
