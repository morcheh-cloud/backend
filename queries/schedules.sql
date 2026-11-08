-- name: ListSchedules :many
-- With each schedule's newest run (skipped ones aside), for the list.
SELECT s.*,
    r.id AS last_run_id, r.state AS last_run_state, r.created_at AS last_run_at,
    r.finished_at AS last_run_finished_at, r.error AS last_run_error
FROM schedules s
LEFT JOIN schedule_runs r ON r.id = (
    SELECT x.id FROM schedule_runs x
    WHERE x.schedule_id = s.id AND x.state <> 'skipped'
    ORDER BY x.created_at DESC, x.id DESC LIMIT 1
)
WHERE s.workspace_id = @workspace_id
  AND (sqlc.narg('server_id')::uuid IS NULL OR sqlc.narg('server_id')::uuid = ANY (s.server_ids))
  AND (sqlc.narg('storage_id')::uuid IS NULL OR sqlc.narg('storage_id')::uuid = ANY (s.storage_ids))
ORDER BY lower(s.name);

-- name: GetSchedule :one
SELECT * FROM schedules WHERE id = $1;

-- name: GetScheduleWorkspace :one
SELECT workspace_id FROM schedules WHERE id = $1;

-- name: CreateSchedule :one
INSERT INTO schedules (
    workspace_id, name, description, action, cron, timezone, enabled, source,
    destinations, options, task, server_ids, storage_ids, next_run_at, created_by, updated_by
) VALUES (
    @workspace_id, @name, @description, @action, @cron, @timezone, @enabled, @source,
    @destinations, @options, @task, @server_ids, @storage_ids, sqlc.narg('next_run_at'),
    sqlc.narg('created_by'), sqlc.narg('created_by')
)
RETURNING *;

-- name: UpdateSchedule :one
UPDATE schedules SET
    name = @name,
    description = @description,
    action = @action,
    task = @task,
    cron = @cron,
    timezone = @timezone,
    enabled = @enabled,
    source = @source,
    destinations = @destinations,
    options = @options,
    server_ids = @server_ids,
    storage_ids = @storage_ids,
    next_run_at = sqlc.narg('next_run_at'),
    updated_by = sqlc.narg('updated_by'),
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: SetScheduleEnabled :one
-- Pausing and resuming don't change whose access it runs with.
UPDATE schedules SET enabled = @enabled, next_run_at = sqlc.narg('next_run_at'), updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteSchedule :execrows
DELETE FROM schedules WHERE id = $1;

-- name: ListDueSchedules :many
SELECT * FROM schedules
WHERE enabled AND next_run_at IS NOT NULL AND next_run_at <= @now
ORDER BY next_run_at
LIMIT 100;

-- name: ClaimSchedule :execrows
-- Moves next_run_at on, only if nobody else did first.
UPDATE schedules SET next_run_at = sqlc.narg('next_run_at')
WHERE id = @id AND next_run_at = @due;

-- name: ListEnabledSchedulesWithoutNext :many
SELECT * FROM schedules WHERE enabled AND next_run_at IS NULL;

-- name: SetScheduleNext :exec
UPDATE schedules SET next_run_at = sqlc.narg('next_run_at') WHERE id = @id;

-- name: CreateScheduleRun :one
INSERT INTO schedule_runs (
    schedule_id, workspace_id, trigger, dry_run, plan, state, error, created_by, created_by_name, finished_at
) VALUES (
    @schedule_id, @workspace_id, @trigger, @dry_run, @plan, @state, @error,
    sqlc.narg('created_by'), @created_by_name, sqlc.narg('finished_at')
)
RETURNING *;

-- name: SetScheduleRunJob :exec
UPDATE schedule_runs SET job_id = @job_id WHERE id = @id;

-- name: StartScheduleRun :exec
UPDATE schedule_runs SET state = 'running', started_at = now() WHERE id = $1 AND state = 'queued';

-- name: SaveScheduleRunResults :exec
-- While it runs, so the page shows each finished destination.
UPDATE schedule_runs SET results = @results, files = @files, bytes = @bytes WHERE id = @id;

-- name: SetScheduleRunLink :exec
UPDATE schedule_runs SET link = @link WHERE id = @id;

-- name: FinishScheduleRun :exec
UPDATE schedule_runs SET
    state = @state, error = @error, results = @results, files = @files, bytes = @bytes,
    finished_at = now()
WHERE id = @id;

-- name: EndScheduleRun :exec
-- Ends a run that's still queued or running, keeping what it recorded.
UPDATE schedule_runs SET state = @state, error = @error, finished_at = now()
WHERE id = @id AND state IN ('queued', 'running');

-- name: GetScheduleRun :one
SELECT * FROM schedule_runs WHERE id = $1;

-- name: GetScheduleRunWorkspace :one
SELECT workspace_id FROM schedule_runs WHERE id = $1;

-- name: ListScheduleRuns :many
SELECT * FROM schedule_runs
WHERE schedule_id = @schedule_id
  AND (sqlc.narg('state')::text IS NULL OR state = sqlc.narg('state')::text)
ORDER BY created_at DESC, id DESC
LIMIT @lim OFFSET @off;

-- name: CountScheduleRuns :one
SELECT count(*) FROM schedule_runs
WHERE schedule_id = @schedule_id
  AND (sqlc.narg('state')::text IS NULL OR state = sqlc.narg('state')::text);

-- name: ListActiveScheduleRuns :many
SELECT * FROM schedule_runs
WHERE state IN ('queued', 'running')
  AND (sqlc.narg('schedule_id')::uuid IS NULL OR schedule_id = sqlc.narg('schedule_id')::uuid);

-- name: DeleteScheduleRun :execrows
DELETE FROM schedule_runs WHERE id = $1 AND state NOT IN ('queued', 'running');

-- name: PruneScheduleRuns :exec
-- Keeps a schedule's newest runs, and every one still going.
DELETE FROM schedule_runs d
WHERE d.schedule_id = @schedule_id
  AND d.state NOT IN ('queued', 'running')
  AND d.id NOT IN (
      SELECT k.id FROM schedule_runs k WHERE k.schedule_id = @schedule_id
      ORDER BY k.created_at DESC, k.id DESC LIMIT @keep
  );

-- name: ListScheduleEndNames :many
-- Names of the servers, storages, scripts, playbooks and databases schedules
-- point at.
SELECT id, name, workspace_id, 'server'::text AS kind FROM servers WHERE id = ANY (@ids::uuid[])
UNION ALL
SELECT id, name, workspace_id, 'storage'::text AS kind FROM storages WHERE id = ANY (@ids::uuid[])
UNION ALL
SELECT id, name, workspace_id, 'script'::text AS kind FROM scripts WHERE id = ANY (@ids::uuid[])
UNION ALL
SELECT id, name, workspace_id, 'playbook'::text AS kind FROM ansible_playbooks WHERE id = ANY (@ids::uuid[])
UNION ALL
SELECT id, name, workspace_id, 'database'::text AS kind FROM databases WHERE id = ANY (@ids::uuid[]);

-- name: ListUserNames :many
SELECT id, username, full_name, status FROM users WHERE id = ANY (@ids::uuid[]);
