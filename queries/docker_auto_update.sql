-- name: ListDockerAutoUpdates :many
SELECT * FROM docker_auto_updates WHERE workspace_id = $1 ORDER BY lower(name), created_at;

-- name: GetDockerAutoUpdate :one
SELECT * FROM docker_auto_updates WHERE id = $1;

-- name: GetDockerAutoUpdateByHook :one
SELECT * FROM docker_auto_updates WHERE webhook_hash = $1;

-- name: ListDockerAutoUpdatesForServer :many
SELECT * FROM docker_auto_updates WHERE @server_id::uuid = ANY(server_ids) ORDER BY lower(name);

-- name: CreateDockerAutoUpdate :one
INSERT INTO docker_auto_updates (
    workspace_id, name, enabled, server_ids, pick, include, exclude, include_stopped, revive_stopped,
    cron, timezone, mode, no_pull, cleanup, rollback, wait_seconds, restart_linked, stop_timeout,
    min_age_hours, hooks, hook_timeout, notify, channels, webhook_enc, webhook_hash, next_run_at,
    created_by, updated_by)
VALUES (
    @workspace_id, @name, @enabled, @server_ids, @pick, @include, @exclude, @include_stopped, @revive_stopped,
    @cron, @timezone, @mode, @no_pull, @cleanup, @rollback, @wait_seconds, @restart_linked, @stop_timeout,
    @min_age_hours, @hooks, @hook_timeout, @notify, @channels, @webhook_enc, @webhook_hash, sqlc.narg('next_run_at'),
    @updated_by, @updated_by)
RETURNING *;

-- name: UpdateDockerAutoUpdate :one
UPDATE docker_auto_updates SET
    name = @name, enabled = @enabled, server_ids = @server_ids, pick = @pick, include = @include,
    exclude = @exclude, include_stopped = @include_stopped, revive_stopped = @revive_stopped,
    cron = @cron, timezone = @timezone, mode = @mode, no_pull = @no_pull, cleanup = @cleanup,
    rollback = @rollback, wait_seconds = @wait_seconds, restart_linked = @restart_linked,
    stop_timeout = @stop_timeout, min_age_hours = @min_age_hours, hooks = @hooks,
    hook_timeout = @hook_timeout, notify = @notify, channels = @channels,
    next_run_at = sqlc.narg('next_run_at'), updated_by = @updated_by, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: SetDockerAutoUpdateEnabled :one
UPDATE docker_auto_updates SET enabled = @enabled, next_run_at = sqlc.narg('next_run_at'),
    updated_by = @updated_by, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: SetDockerAutoUpdateWebhook :one
UPDATE docker_auto_updates SET webhook_enc = @webhook_enc, webhook_hash = @webhook_hash, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteDockerAutoUpdate :execrows
DELETE FROM docker_auto_updates WHERE id = @id AND workspace_id = @workspace_id;

-- name: DueDockerAutoUpdates :many
SELECT * FROM docker_auto_updates
WHERE enabled AND next_run_at IS NOT NULL AND next_run_at <= now()
ORDER BY next_run_at
LIMIT 50;

-- name: ClaimDockerAutoUpdate :execrows
-- Moves next_run_at on, only if nobody else did first.
UPDATE docker_auto_updates SET next_run_at = sqlc.narg('next_run_at')
WHERE id = @id AND next_run_at = @due;

-- name: EnabledDockerAutoUpdatesWithoutNext :many
SELECT * FROM docker_auto_updates WHERE enabled AND next_run_at IS NULL;

-- name: SetDockerAutoUpdateNext :exec
UPDATE docker_auto_updates SET next_run_at = sqlc.narg('next_run_at') WHERE id = @id;

-- name: StartDockerAutoUpdateRun :exec
UPDATE docker_auto_updates SET last_run_at = now(), last_state = 'running', last_note = '', last_job_id = @job_id
WHERE id = @id;

-- name: EndDockerAutoUpdateRun :exec
UPDATE docker_auto_updates SET last_state = @last_state, last_note = @last_note WHERE id = @id;

-- name: AddDockerAutoUpdateEvent :exec
INSERT INTO docker_auto_update_events (policy_id, workspace_id, server_id, job_id, container, image, old_image, new_image, result, message)
VALUES (@policy_id, @workspace_id, @server_id, sqlc.narg('job_id'), @container, @image, @old_image, @new_image, @result, @message);

-- name: SeenDockerAutoUpdateAvailable :one
-- Whether this policy already said a container's image has this version.
SELECT EXISTS (
    SELECT 1 FROM docker_auto_update_events
    WHERE policy_id = @policy_id AND server_id = @server_id AND container = @container
      AND result = 'available' AND new_image = @new_image
);

-- name: ListDockerAutoUpdateEvents :many
SELECT e.*, s.name AS server_name, p.name AS policy_name
FROM docker_auto_update_events e
JOIN servers s ON s.id = e.server_id
JOIN docker_auto_updates p ON p.id = e.policy_id
WHERE e.workspace_id = @workspace_id
  AND (sqlc.narg('policy_id')::uuid IS NULL OR e.policy_id = sqlc.narg('policy_id'))
  AND (sqlc.narg('server_id')::uuid IS NULL OR e.server_id = sqlc.narg('server_id'))
  AND (sqlc.narg('result')::text IS NULL OR e.result = sqlc.narg('result'))
  AND (sqlc.narg('before')::timestamptz IS NULL OR e.at < sqlc.narg('before'))
ORDER BY e.at DESC
LIMIT @lim;

-- name: CountDockerAutoUpdateEvents :many
-- Per policy, what the last 30 days held.
SELECT policy_id, result, count(*)::int AS n
FROM docker_auto_update_events
WHERE workspace_id = $1 AND at > now() - interval '30 days'
GROUP BY policy_id, result;

-- name: PruneDockerAutoUpdateEvents :exec
DELETE FROM docker_auto_update_events WHERE at < now() - interval '180 days';
