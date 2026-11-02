-- name: ListDatabases :many
SELECT * FROM databases d
WHERE (@see_all::bool OR d.workspace_id = ANY (@workspace_ids::uuid[])
       OR d.server_id = ANY (@server_ids::uuid[]))
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR d.workspace_id = sqlc.narg('workspace_id')::uuid)
  AND (sqlc.narg('server_id')::uuid IS NULL OR d.server_id = sqlc.narg('server_id')::uuid)
ORDER BY CASE d.health WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 WHEN 'unknown' THEN 2 ELSE 3 END,
    d.favorite DESC, lower(d.name);

-- name: GetDatabase :one
SELECT * FROM databases WHERE id = $1;

-- name: GetDatabaseWorkspace :one
-- What access to a database follows: its workspace, and the server it goes
-- through.
SELECT workspace_id, server_id FROM databases WHERE id = $1;

-- name: ListDatabasesDue :many
-- What the monitor should look at now.
SELECT * FROM databases
WHERE NOT paused
  AND (last_checked_at IS NULL OR last_checked_at + make_interval(secs => interval_seconds) <= now())
ORDER BY last_checked_at NULLS FIRST;

-- name: CreateDatabase :one
INSERT INTO databases (
    workspace_id, name, engine, mode, server_id, host, port, username, password_enc,
    dbname, tls, ca_cert, allow_internal, container, description, favorite, interval_seconds
) VALUES (
    @workspace_id, @name, @engine, @mode, sqlc.narg('server_id'), @host, @port, @username,
    sqlc.narg('password_enc'), @dbname, @tls, @ca_cert, @allow_internal, @container,
    @description, @favorite, @interval_seconds
)
RETURNING *;

-- name: UpdateDatabase :one
-- Full replace of the editable fields; the handler resolves the password first.
UPDATE databases SET
    name = @name,
    engine = @engine,
    mode = @mode,
    server_id = sqlc.narg('server_id'),
    host = @host,
    port = @port,
    username = @username,
    password_enc = sqlc.narg('password_enc'),
    dbname = @dbname,
    tls = @tls,
    ca_cert = @ca_cert,
    allow_internal = @allow_internal,
    container = @container,
    description = @description,
    favorite = @favorite,
    interval_seconds = @interval_seconds,
    status = @status,
    status_message = @status_message,
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteDatabase :execrows
DELETE FROM databases WHERE id = $1;

-- name: SetDatabaseFavorite :one
UPDATE databases SET favorite = @favorite WHERE id = @id RETURNING *;

-- name: SetDatabasePaused :one
UPDATE databases SET paused = @paused, updated_at = now() WHERE id = @id RETURNING *;

-- name: SetDatabaseMonitoring :one
UPDATE databases SET
    thresholds = @thresholds,
    muted_checks = @muted_checks,
    alerts_enabled = @alerts_enabled
WHERE id = @id
RETURNING *;

-- name: RecordDatabaseCheck :one
UPDATE databases SET
    status = @status,
    status_message = @status_message,
    version = CASE WHEN @version::text <> '' THEN @version::text ELSE version END,
    flavor = CASE WHEN @flavor::text <> '' THEN @flavor::text ELSE flavor END,
    role = CASE WHEN @status = 'online' THEN @role::text ELSE role END,
    latency_ms = sqlc.narg('latency_ms'),
    size_bytes = COALESCE(sqlc.narg('size_bytes'), size_bytes),
    connections = sqlc.narg('connections'),
    max_connections = COALESCE(sqlc.narg('max_connections'), max_connections),
    last_checked_at = now(),
    last_online_at = CASE WHEN @status = 'online' THEN now() ELSE last_online_at END,
    health = @health,
    checks = @checks,
    baseline = @baseline
WHERE id = @id
RETURNING *;

-- name: InsertDatabaseSample :exec
INSERT INTO database_samples (
    database_id, at, online, latency_ms, connections, active, max_connections, qps, tps,
    cache_hit, size_bytes, disk_free_bytes, disk_total_bytes, replication_lag, blocked,
    deadlocks, memory_bytes
) VALUES (
    @database_id, @at, @online, sqlc.narg('latency_ms'), sqlc.narg('connections'), sqlc.narg('active'),
    sqlc.narg('max_connections'), sqlc.narg('qps'), sqlc.narg('tps'), sqlc.narg('cache_hit'),
    sqlc.narg('size_bytes'), sqlc.narg('disk_free_bytes'), sqlc.narg('disk_total_bytes'),
    sqlc.narg('replication_lag'), sqlc.narg('blocked'), sqlc.narg('deadlocks'), sqlc.narg('memory_bytes')
)
ON CONFLICT DO NOTHING;

-- name: PruneDatabaseSamples :exec
DELETE FROM database_samples WHERE at < @before;

-- name: PruneDatabaseEvents :exec
DELETE FROM database_events WHERE at < @before;

-- name: DatabaseHistory :many
-- Averages per bucket; peaks where an average would hide the problem. NaN =
-- nothing measured in the bucket (sqlc can't type a nullable aggregate).
SELECT
    date_bin(make_interval(secs => @bucket_seconds::int), at, timestamptz '2000-01-01')::timestamptz AS bucket,
    count(*)::int AS samples,
    count(*) FILTER (WHERE online)::int AS online_samples,
    coalesce(avg(latency_ms)::float8, 'NaN')::float8 AS latency_ms,
    coalesce(max(connections)::float8, 'NaN')::float8 AS connections,
    coalesce(avg(active)::float8, 'NaN')::float8 AS active,
    coalesce(max(max_connections)::float8, 'NaN')::float8 AS max_connections,
    coalesce(avg(qps)::float8, 'NaN')::float8 AS qps,
    coalesce(avg(tps)::float8, 'NaN')::float8 AS tps,
    coalesce(avg(cache_hit)::float8, 'NaN')::float8 AS cache_hit,
    coalesce(max(size_bytes)::float8, 'NaN')::float8 AS size_bytes,
    coalesce(min(disk_free_bytes)::float8, 'NaN')::float8 AS disk_free_bytes,
    coalesce(max(disk_total_bytes)::float8, 'NaN')::float8 AS disk_total_bytes,
    coalesce(max(replication_lag)::float8, 'NaN')::float8 AS replication_lag,
    coalesce(max(blocked)::float8, 'NaN')::float8 AS blocked,
    coalesce(sum(deadlocks)::float8, 'NaN')::float8 AS deadlocks,
    coalesce(max(memory_bytes)::float8, 'NaN')::float8 AS memory_bytes
FROM database_samples
WHERE database_id = @database_id AND at >= @since AND at <= @until
GROUP BY bucket
ORDER BY bucket;

-- name: DatabaseSizeTrend :many
-- Oldest first: what the "fills up in N days" estimates fit a line through.
SELECT at, size_bytes, disk_free_bytes FROM database_samples
WHERE database_id = @database_id AND at >= @since AND online
  AND (size_bytes IS NOT NULL OR disk_free_bytes IS NOT NULL)
ORDER BY at;

-- name: DatabaseAverages :one
-- What this hour normally looks like: the same hour on earlier days.
SELECT
    count(*)::int AS samples,
    coalesce(avg(qps)::float8, 'NaN')::float8 AS qps,
    coalesce(avg(latency_ms)::float8, 'NaN')::float8 AS latency_ms,
    coalesce(avg(connections)::float8, 'NaN')::float8 AS connections,
    coalesce(avg(active)::float8, 'NaN')::float8 AS active
FROM database_samples
WHERE database_id = @database_id AND online AND at >= @since AND at < @until
  AND extract(hour FROM at) = extract(hour FROM @now::timestamptz);

-- name: InsertDatabaseEvent :one
INSERT INTO database_events (database_id, kind, severity, check_id, title, detail)
VALUES (@database_id, @kind, @severity, @check_id, @title, @detail)
RETURNING *;

-- name: ListDatabaseEvents :many
SELECT * FROM database_events
WHERE database_id = @database_id
  AND (sqlc.narg('before')::timestamptz IS NULL OR at < sqlc.narg('before')::timestamptz)
ORDER BY at DESC
LIMIT @lim;

-- name: ListAlertChannels :many
SELECT * FROM alert_channels WHERE workspace_id = $1 ORDER BY lower(name);

-- name: GetAlertChannel :one
SELECT * FROM alert_channels WHERE id = $1;

-- name: CreateAlertChannel :one
INSERT INTO alert_channels (workspace_id, name, kind, config_enc, target, min_severity, enabled)
VALUES (@workspace_id, @name, @kind, @config_enc, @target, @min_severity, @enabled)
RETURNING *;

-- name: UpdateAlertChannel :one
UPDATE alert_channels SET
    name = @name,
    kind = @kind,
    config_enc = @config_enc,
    target = @target,
    min_severity = @min_severity,
    enabled = @enabled,
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteAlertChannel :execrows
DELETE FROM alert_channels WHERE id = @id AND workspace_id = @workspace_id;

-- name: RecordAlertDelivery :exec
UPDATE alert_channels SET
    last_sent_at = CASE WHEN @error::text = '' THEN now() ELSE last_sent_at END,
    last_error = @error::text
WHERE id = @id;

-- name: GetDatabaseBackupPlan :one
SELECT * FROM database_backup_plans WHERE database_id = $1;

-- name: UpsertDatabaseBackupPlan :one
INSERT INTO database_backup_plans (
    database_id, enabled, storage_id, folder, runner_server_id, dbnames, frequency,
    hour, weekday, keep, next_run_at, created_by
) VALUES (
    @database_id, @enabled, @storage_id, @folder, sqlc.narg('runner_server_id'), @dbnames,
    @frequency, @hour, @weekday, @keep, @next_run_at, sqlc.narg('created_by')
)
ON CONFLICT (database_id) DO UPDATE SET
    enabled = EXCLUDED.enabled,
    storage_id = EXCLUDED.storage_id,
    folder = EXCLUDED.folder,
    runner_server_id = EXCLUDED.runner_server_id,
    dbnames = EXCLUDED.dbnames,
    frequency = EXCLUDED.frequency,
    hour = EXCLUDED.hour,
    weekday = EXCLUDED.weekday,
    keep = EXCLUDED.keep,
    next_run_at = EXCLUDED.next_run_at,
    created_by = EXCLUDED.created_by,
    updated_at = now()
RETURNING *;

-- name: DeleteDatabaseBackupPlan :execrows
DELETE FROM database_backup_plans WHERE database_id = $1;

-- name: ListDueBackupPlans :many
SELECT * FROM database_backup_plans WHERE enabled AND next_run_at <= now();

-- name: SetBackupPlanNextRun :exec
UPDATE database_backup_plans SET next_run_at = @next_run_at WHERE database_id = @database_id;

-- name: CreateDatabaseBackup :one
INSERT INTO database_backups (database_id, job_id, trigger, storage_id, path, dbname)
VALUES (@database_id, sqlc.narg('job_id'), @trigger, sqlc.narg('storage_id'), @path, @dbname)
RETURNING *;

-- name: FinishDatabaseBackup :one
UPDATE database_backups SET
    status = @status,
    path = @path,
    size_bytes = @size_bytes,
    error = @error,
    finished_at = now()
WHERE id = @id
RETURNING *;

-- name: VerifyDatabaseBackup :one
UPDATE database_backups SET
    verify_status = @verify_status,
    verify_detail = @verify_detail,
    verified_at = now()
WHERE id = @id
RETURNING *;

-- name: GetDatabaseBackup :one
SELECT * FROM database_backups WHERE id = $1;

-- name: ListDatabaseBackups :many
SELECT * FROM database_backups WHERE database_id = $1 ORDER BY started_at DESC LIMIT $2;

-- name: DeleteDatabaseBackup :execrows
DELETE FROM database_backups WHERE id = $1;

-- name: LastGoodDatabaseBackup :one
SELECT * FROM database_backups
WHERE database_id = $1 AND status = 'ok'
ORDER BY started_at DESC
LIMIT 1;

-- name: FailStaleDatabaseBackups :exec
-- Whatever a restart cut off never ends by itself.
UPDATE database_backups SET status = 'failed', error = 'Interrupted by a restart', finished_at = now()
WHERE status = 'running' AND started_at < now() - interval '12 hours';
