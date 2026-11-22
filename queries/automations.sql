-- ---- Automations ----

-- name: CreateAutomation :one
INSERT INTO automations (workspace_id, name, description, enabled, trigger, actions,
    cooldown_seconds, max_runs_per_hour, updated_by, created_by)
VALUES (@workspace_id, @name, @description, @enabled, @trigger, @actions,
    @cooldown_seconds, @max_runs_per_hour, sqlc.narg('created_by'), sqlc.narg('created_by'))
RETURNING *;

-- name: UpdateAutomation :one
-- Saving clears the problem: it runs as whoever saved it now.
UPDATE automations SET name = @name, description = @description, enabled = @enabled,
    trigger = @trigger, actions = @actions, cooldown_seconds = @cooldown_seconds,
    max_runs_per_hour = @max_runs_per_hour, updated_by = sqlc.narg('updated_by'),
    problem = '', updated_at = now()
WHERE id = @id
RETURNING *;

-- name: GetAutomation :one
SELECT * FROM automations WHERE id = $1;

-- name: GetAutomationWorkspace :one
SELECT workspace_id FROM automations WHERE id = $1;

-- name: GetAutomationByHook :one
SELECT * FROM automations WHERE hook_token_hash = $1;

-- name: ListAutomations :many
SELECT * FROM automations WHERE workspace_id = $1 ORDER BY lower(name), created_at;

-- name: ListEventAutomations :many
-- The workspace's automations an event may start.
SELECT * FROM automations
WHERE workspace_id = $1 AND enabled AND trigger->>'kind' = 'event';

-- name: DeleteAutomation :exec
DELETE FROM automations WHERE id = $1;

-- name: SetAutomationHook :one
UPDATE automations SET hook_token_hash = sqlc.narg('hash'), updated_at = now()
WHERE id = @id
RETURNING *;

-- name: SetAutomationProblem :exec
UPDATE automations SET problem = @problem WHERE id = @id;

-- name: NoteAutomationRun :exec
-- How its latest run (not a skipped one) ended.
UPDATE automations SET last_run_at = now(), last_status = @status WHERE id = @id;

-- ---- Runs ----

-- name: CreateAutomationRun :one
INSERT INTO automation_runs (automation_id, workspace_id, trigger_kind, event, subject_id,
    status, steps, reason, started_by, started_by_name, finished_at)
VALUES (@automation_id, @workspace_id, @trigger_kind, @event, @subject_id,
    @status, @steps, @reason, sqlc.narg('started_by'), @started_by_name, sqlc.narg('finished_at'))
RETURNING *;

-- name: GetAutomationRun :one
SELECT * FROM automation_runs WHERE id = $1;

-- name: GetAutomationRunWorkspace :one
SELECT workspace_id FROM automation_runs WHERE id = $1;

-- name: SetAutomationRunJob :exec
UPDATE automation_runs SET job_id = @job_id WHERE id = @id;

-- name: StartAutomationRun :exec
UPDATE automation_runs SET status = 'running', started_at = now()
WHERE id = $1 AND status = 'queued';

-- name: SaveAutomationRunSteps :exec
UPDATE automation_runs SET steps = @steps WHERE id = @id;

-- name: EndAutomationRun :exec
UPDATE automation_runs SET status = @status, reason = @reason, finished_at = now()
WHERE id = @id AND status IN ('queued', 'running');

-- name: ListAutomationRuns :many
-- Newest first, of one automation or (automation_id NULL) the whole workspace.
SELECT r.*, a.name AS automation_name FROM automation_runs r
JOIN automations a ON a.id = r.automation_id
WHERE r.workspace_id = @workspace_id
  AND (sqlc.narg('automation_id')::uuid IS NULL OR r.automation_id = sqlc.narg('automation_id'))
  AND (sqlc.narg('status')::text IS NULL OR r.status = sqlc.narg('status'))
ORDER BY r.created_at DESC, r.id DESC
LIMIT @lim OFFSET @off;

-- name: CountAutomationRuns :one
SELECT count(*) FROM automation_runs r
WHERE r.workspace_id = @workspace_id
  AND (sqlc.narg('automation_id')::uuid IS NULL OR r.automation_id = sqlc.narg('automation_id'))
  AND (sqlc.narg('status')::text IS NULL OR r.status = sqlc.narg('status'));

-- name: RecentAutomationRuns :many
-- The last 10 runs of every automation in a workspace, for the list.
SELECT automation_id, id, status, trigger_kind, created_at FROM (
    SELECT r.automation_id, r.id, r.status, r.trigger_kind, r.created_at,
        row_number() OVER (PARTITION BY r.automation_id ORDER BY r.created_at DESC, r.id DESC) AS n
    FROM automation_runs r WHERE r.workspace_id = $1
) x WHERE n <= 10
ORDER BY automation_id, created_at DESC;

-- name: CountAutomationRunsSince :one
-- Runs that weren't skipped, for max_runs_per_hour.
SELECT count(*) FROM automation_runs
WHERE automation_id = @automation_id AND status <> 'skipped' AND created_at >= @since;

-- name: CountActiveAutomationRuns :one
SELECT count(*) FROM automation_runs
WHERE automation_id = $1 AND status IN ('queued', 'running');

-- name: LastAutomationRunFor :one
-- When it last ran (not skipped) for a subject, for the cooldown.
SELECT coalesce(max(created_at), '1970-01-01T00:00:00Z'::timestamptz)::timestamptz FROM automation_runs
WHERE automation_id = @automation_id AND subject_id = @subject_id AND status <> 'skipped';

-- name: LastSkippedAutomationRun :one
SELECT coalesce(max(created_at), '1970-01-01T00:00:00Z'::timestamptz)::timestamptz FROM automation_runs
WHERE automation_id = $1 AND status = 'skipped';

-- name: InterruptAutomationRuns :exec
-- Runs left going when Morche stopped.
UPDATE automation_runs SET status = 'failed', reason = 'Morche stopped before it finished.', finished_at = now()
WHERE status IN ('queued', 'running');

-- name: DeleteAutomationRun :exec
DELETE FROM automation_runs WHERE id = $1 AND status NOT IN ('queued', 'running');

-- name: PruneAutomationRuns :execrows
-- Keeps each automation's newest runs within the days, and every one still going.
DELETE FROM automation_runs d
WHERE d.status NOT IN ('queued', 'running')
  AND (d.created_at < @before OR d.id NOT IN (
      SELECT k.id FROM automation_runs k WHERE k.automation_id = d.automation_id
      ORDER BY k.created_at DESC, k.id DESC LIMIT @keep
  ));

-- name: CountActiveAutomationRunsFor :one
-- Runs going for one subject (an event about another subject may still run).
SELECT count(*) FROM automation_runs
WHERE automation_id = @automation_id AND subject_id = @subject_id AND status IN ('queued', 'running');
