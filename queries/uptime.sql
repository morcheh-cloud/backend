-- ---- Notification channels ----

-- name: ListNotificationChannels :many
SELECT * FROM notification_channels
WHERE (@see_all::bool OR workspace_id = ANY (@workspace_ids::uuid[]))
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR workspace_id = sqlc.narg('workspace_id')::uuid)
ORDER BY lower(name);

-- name: GetNotificationChannel :one
SELECT * FROM notification_channels WHERE id = $1;

-- name: GetNotificationChannelWorkspace :one
SELECT workspace_id FROM notification_channels WHERE id = $1;

-- name: CreateNotificationChannel :one
INSERT INTO notification_channels (
    workspace_id, name, kind, config, secrets_enc, enabled, is_default,
    allow_internal, created_by_name, updated_by_name
) VALUES (
    @workspace_id, @name, @kind, @config, @secrets_enc, @enabled, @is_default,
    @allow_internal, @created_by_name, @created_by_name
)
RETURNING *;

-- name: UpdateNotificationChannel :one
UPDATE notification_channels SET
    name = @name,
    config = @config,
    secrets_enc = @secrets_enc,
    enabled = @enabled,
    is_default = @is_default,
    allow_internal = @allow_internal,
    updated_by_name = @updated_by_name,
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteNotificationChannel :exec
DELETE FROM notification_channels WHERE id = $1;

-- name: RecordChannelSend :exec
UPDATE notification_channels SET
    last_sent_at = CASE WHEN @ok::bool THEN now() ELSE last_sent_at END,
    last_error = CASE WHEN @ok::bool THEN last_error ELSE @error::text END,
    last_error_at = CASE WHEN @ok::bool THEN last_error_at ELSE now() END
WHERE id = @id;

-- name: LogNotification :exec
INSERT INTO notification_log (channel_id, monitor_id, title, ok, error)
VALUES (@channel_id, sqlc.narg('monitor_id'), @title, @ok, @error);

-- name: ListNotificationLog :many
SELECT l.*, coalesce(m.name, '')::text AS monitor_name
FROM notification_log l
LEFT JOIN monitors m ON m.id = l.monitor_id
WHERE l.channel_id = @channel_id
ORDER BY l.at DESC
LIMIT @lim;

-- name: CountChannelMonitors :many
SELECT channel_id, count(*)::int AS monitors
FROM monitor_channels
WHERE channel_id = ANY (@ids::uuid[])
GROUP BY channel_id;

-- name: DefaultChannels :many
SELECT id FROM notification_channels
WHERE workspace_id = @workspace_id AND is_default;

-- ---- Monitors ----

-- name: ListMonitors :many
SELECT * FROM monitors
WHERE (@see_all::bool OR workspace_id = ANY (@workspace_ids::uuid[]))
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR workspace_id = sqlc.narg('workspace_id')::uuid)
  AND (sqlc.narg('server_id')::uuid IS NULL OR server_id = sqlc.narg('server_id')::uuid
       OR via_server_id = sqlc.narg('server_id')::uuid)
ORDER BY lower(name);

-- name: GetMonitor :one
SELECT * FROM monitors WHERE id = $1;

-- name: GetMonitorWorkspace :one
SELECT workspace_id FROM monitors WHERE id = $1;

-- name: GetMonitorByPushToken :one
SELECT * FROM monitors WHERE push_token = $1;

-- name: CreateMonitor :one
INSERT INTO monitors (
    workspace_id, name, kind, config, secrets_enc, description, tags,
    via_server_id, server_id, interval_seconds, retry_seconds, timeout_seconds,
    retries, resend_every, notify_degraded, allow_internal, paused, push_token,
    created_by_name, updated_by_name
) VALUES (
    @workspace_id, @name, @kind, @config, @secrets_enc, @description, @tags,
    sqlc.narg('via_server_id'), sqlc.narg('server_id'), @interval_seconds,
    @retry_seconds, @timeout_seconds, @retries, @resend_every, @notify_degraded,
    @allow_internal, @paused, sqlc.narg('push_token'), @created_by_name,
    @created_by_name
)
RETURNING *;

-- name: UpdateMonitor :one
-- A changed monitor is checked again at once.
UPDATE monitors SET
    name = @name,
    config = @config,
    secrets_enc = @secrets_enc,
    description = @description,
    tags = @tags,
    via_server_id = sqlc.narg('via_server_id'),
    server_id = sqlc.narg('server_id'),
    interval_seconds = @interval_seconds,
    retry_seconds = @retry_seconds,
    timeout_seconds = @timeout_seconds,
    retries = @retries,
    resend_every = @resend_every,
    notify_degraded = @notify_degraded,
    allow_internal = @allow_internal,
    push_token = sqlc.narg('push_token'),
    updated_by_name = @updated_by_name,
    next_check_at = now(),
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteMonitor :exec
DELETE FROM monitors WHERE id = $1;

-- name: SetMonitorPaused :one
-- Resuming starts over: pending until the next check says otherwise.
UPDATE monitors SET
    paused = @paused,
    status = CASE WHEN @paused::bool THEN status ELSE 'pending' END,
    status_since = CASE WHEN @paused::bool THEN status_since ELSE now() END,
    status_message = CASE WHEN @paused::bool THEN status_message ELSE '' END,
    fail_count = 0,
    down_checks = 0,
    next_check_at = now(),
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: ListDueMonitors :many
SELECT * FROM monitors
WHERE NOT paused AND next_check_at <= now()
ORDER BY next_check_at
LIMIT @lim;

-- name: SaveMonitorState :one
UPDATE monitors SET
    status = @status,
    status_message = @status_message,
    status_since = @status_since,
    fail_count = @fail_count,
    down_checks = @down_checks,
    last_latency_ms = sqlc.narg('last_latency_ms'),
    last_checked_at = @last_checked_at,
    next_check_at = @next_check_at,
    cert_expires_at = coalesce(sqlc.narg('cert_expires_at'), cert_expires_at)
WHERE id = @id
RETURNING *;

-- name: DelayMonitor :exec
UPDATE monitors SET next_check_at = @next_check_at WHERE id = @id;

-- name: ListMonitorChannels :many
SELECT channel_id FROM monitor_channels WHERE monitor_id = $1;

-- name: ListMonitorChannelsFor :many
SELECT monitor_id, channel_id FROM monitor_channels
WHERE monitor_id = ANY (@ids::uuid[]);

-- name: ClearMonitorChannels :exec
DELETE FROM monitor_channels WHERE monitor_id = $1;

-- name: AddMonitorChannel :exec
INSERT INTO monitor_channels (monitor_id, channel_id) VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: ChannelsToNotify :many
SELECT c.* FROM notification_channels c
JOIN monitor_channels mc ON mc.channel_id = c.id
WHERE mc.monitor_id = $1 AND c.enabled;

-- ---- Checks and history ----

-- name: InsertMonitorCheck :exec
INSERT INTO monitor_checks (monitor_id, at, status, latency_ms, code, message)
VALUES (@monitor_id, @at, @status, sqlc.narg('latency_ms'), @code, @message);

-- name: AddMonitorDay :exec
INSERT INTO monitor_days (
    monitor_id, day, checks, up, degraded, down, latency_sum, latency_count, latency_max
) VALUES (
    @monitor_id, @day, 1,
    (@status::text = 'up')::int, (@status::text = 'degraded')::int, (@status::text = 'down')::int,
    coalesce(sqlc.narg('latency_ms')::int, 0), (sqlc.narg('latency_ms')::int IS NOT NULL)::int,
    coalesce(sqlc.narg('latency_ms')::int, 0)
)
ON CONFLICT (monitor_id, day) DO UPDATE SET
    checks = monitor_days.checks + 1,
    up = monitor_days.up + excluded.up,
    degraded = monitor_days.degraded + excluded.degraded,
    down = monitor_days.down + excluded.down,
    latency_sum = monitor_days.latency_sum + excluded.latency_sum,
    latency_count = monitor_days.latency_count + excluded.latency_count,
    latency_max = greatest(monitor_days.latency_max, excluded.latency_max);

-- name: PruneMonitorChecks :execrows
DELETE FROM monitor_checks WHERE at < @before;

-- name: RecentMonitorChecks :many
-- Each monitor's newest checks, newest first, for the list's bars.
SELECT c.monitor_id, c.at, c.status, c.latency_ms, c.message
FROM monitors m
CROSS JOIN LATERAL (
    SELECT x.monitor_id, x.at, x.status, x.latency_ms, x.message
    FROM monitor_checks x
    WHERE x.monitor_id = m.id
    ORDER BY x.at DESC
    LIMIT @per::int
) c
WHERE m.id = ANY (@ids::uuid[]);

-- name: MonitorUptimeSince :many
-- Counts per monitor since a time, from the raw checks.
SELECT monitor_id,
    count(*)::int AS checks,
    count(*) FILTER (WHERE status = 'up')::int AS up,
    count(*) FILTER (WHERE status = 'degraded')::int AS degraded,
    count(*) FILTER (WHERE status = 'down')::int AS down,
    coalesce(avg(latency_ms), 0)::float8 AS latency_avg
FROM monitor_checks
WHERE monitor_id = ANY (@ids::uuid[]) AND at >= @since
GROUP BY monitor_id;

-- name: MonitorDaysSince :many
SELECT * FROM monitor_days
WHERE monitor_id = ANY (@ids::uuid[]) AND day >= @since::date
ORDER BY day;

-- name: MonitorChecksBetween :many
SELECT at, status, latency_ms, code, message
FROM monitor_checks
WHERE monitor_id = @monitor_id AND at >= @since AND at < @until
ORDER BY at DESC
LIMIT @lim;

-- name: MonitorBuckets :many
-- Checks grouped into buckets of @step seconds.
SELECT date_bin(make_interval(secs => @step::int), at, @origin::timestamptz)::timestamptz AS bucket,
    count(*)::int AS checks,
    count(*) FILTER (WHERE status = 'up')::int AS up,
    count(*) FILTER (WHERE status = 'degraded')::int AS degraded,
    count(*) FILTER (WHERE status = 'down')::int AS down,
    coalesce(avg(latency_ms), 0)::float8 AS latency_avg,
    coalesce(max(latency_ms), 0)::int AS latency_max,
    coalesce(percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms), 0)::float8 AS latency_p95
FROM monitor_checks
WHERE monitor_id = @monitor_id AND at >= @origin
GROUP BY bucket
ORDER BY bucket;

-- name: InsertMonitorEvent :exec
INSERT INTO monitor_events (monitor_id, at, from_status, to_status, message)
VALUES (@monitor_id, @at, @from_status, @to_status, @message);

-- name: ListMonitorEvents :many
SELECT * FROM monitor_events
WHERE monitor_id = @monitor_id
ORDER BY at DESC
LIMIT @lim;

-- ---- Incidents ----

-- name: OpenMonitorIncident :exec
INSERT INTO monitor_incidents (monitor_id, started_at, cause)
VALUES (@monitor_id, @started_at, @cause)
ON CONFLICT (monitor_id) WHERE resolved_at IS NULL DO NOTHING;

-- name: ResolveMonitorIncident :exec
UPDATE monitor_incidents SET resolved_at = @resolved_at
WHERE monitor_id = @monitor_id AND resolved_at IS NULL;

-- name: GetMonitorIncident :one
SELECT * FROM monitor_incidents WHERE id = $1;

-- name: AcknowledgeMonitorIncident :one
UPDATE monitor_incidents SET
    acknowledged_at = coalesce(acknowledged_at, now()),
    acknowledged_by_name = CASE WHEN acknowledged_at IS NULL THEN @name ELSE acknowledged_by_name END,
    note = @note
WHERE id = @id
RETURNING *;

-- name: ListMonitorIncidents :many
SELECT * FROM monitor_incidents
WHERE monitor_id = @monitor_id
ORDER BY started_at DESC
LIMIT @lim;

-- name: ListWorkspaceIncidents :many
-- Incidents of every monitor in scope, open ones first.
SELECT i.*, m.name AS monitor_name, m.kind AS monitor_kind, m.workspace_id
FROM monitor_incidents i
JOIN monitors m ON m.id = i.monitor_id
WHERE (@see_all::bool OR m.workspace_id = ANY (@workspace_ids::uuid[]))
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR m.workspace_id = sqlc.narg('workspace_id')::uuid)
  AND (NOT @open_only::bool OR i.resolved_at IS NULL)
ORDER BY (i.resolved_at IS NULL) DESC, i.started_at DESC
LIMIT @lim;

-- name: MonitorDowntimeSince :many
-- Seconds each monitor spent in incidents since a time (open ones up to now).
SELECT monitor_id,
    count(*)::int AS incidents,
    coalesce(sum(extract(epoch FROM (coalesce(resolved_at, now()) - greatest(started_at, @since::timestamptz)))), 0)::float8 AS seconds
FROM monitor_incidents
WHERE monitor_id = ANY (@ids::uuid[]) AND coalesce(resolved_at, now()) >= @since::timestamptz
GROUP BY monitor_id;
