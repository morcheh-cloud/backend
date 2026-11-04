-- name: ListScripts :many
SELECT * FROM scripts WHERE workspace_id = $1 ORDER BY lower(name);

-- name: GetScript :one
SELECT * FROM scripts WHERE id = $1;

-- name: CreateScript :one
INSERT INTO scripts (
    workspace_id, name, description, interpreter, content, run_as,
    timeout_seconds, params, created_by, updated_by
) VALUES (
    @workspace_id, @name, @description, @interpreter, @content, @run_as,
    @timeout_seconds, @params, sqlc.narg('created_by'), sqlc.narg('created_by')
)
RETURNING *;

-- name: UpdateScript :one
UPDATE scripts SET
    name = @name,
    description = @description,
    interpreter = @interpreter,
    content = @content,
    run_as = @run_as,
    timeout_seconds = @timeout_seconds,
    params = @params,
    updated_by = sqlc.narg('updated_by'),
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteScript :exec
DELETE FROM scripts WHERE id = $1;

-- name: LastScriptRuns :many
-- Each script's latest run on one server.
SELECT DISTINCT ON (r.script_id)
    r.script_id, r.id AS run_id, r.created_at, t.state, t.exit_code
FROM script_runs r
JOIN script_run_targets t ON t.run_id = r.id
WHERE t.server_id = $1 AND r.script_id IS NOT NULL
ORDER BY r.script_id, r.id DESC;

-- name: CreateScriptRun :one
INSERT INTO script_runs (
    script_id, name, interpreter, content, run_as, timeout_seconds, env,
    created_by, created_by_name
) VALUES (
    sqlc.narg('script_id'), @name, @interpreter, @content, @run_as,
    @timeout_seconds, @env, sqlc.narg('created_by'), @created_by_name
)
RETURNING *;

-- name: CreateScriptRunTarget :exec
INSERT INTO script_run_targets (run_id, server_id, server_name, position)
VALUES (@run_id, @server_id, @server_name, @position);

-- name: SetScriptRunJob :exec
UPDATE script_runs SET job_id = @job_id WHERE id = @id;

-- name: GetScriptRun :one
SELECT * FROM script_runs WHERE id = $1;

-- name: ListScriptRunTargets :many
SELECT * FROM script_run_targets WHERE run_id = $1 ORDER BY position;

-- name: StartScriptRun :exec
UPDATE script_runs SET state = 'running', started_at = now() WHERE id = $1;

-- name: FinishScriptRun :exec
UPDATE script_runs SET state = @state, finished_at = now() WHERE id = @id;

-- name: StartScriptTarget :exec
UPDATE script_run_targets SET state = 'running', started_at = now()
WHERE run_id = @run_id AND position = @position;

-- name: SaveScriptTargetOutput :exec
UPDATE script_run_targets SET output = @output, truncated = @truncated
WHERE run_id = @run_id AND position = @position;

-- name: FinishScriptTarget :exec
UPDATE script_run_targets SET
    state = @state,
    exit_code = sqlc.narg('exit_code'),
    timed_out = @timed_out,
    error = @error,
    output = @output,
    truncated = @truncated,
    finished_at = now()
WHERE run_id = @run_id AND position = @position;

-- name: ListServerScriptRuns :many
-- Runs that touched one server, newest first, with what they did there.
-- script_id narrows to one script; pattern (ILIKE) matches the run's name.
SELECT
    r.id, r.script_id, r.name, r.interpreter, r.run_as, r.state AS run_state,
    r.job_id, r.created_by, r.created_by_name, r.created_at,
    t.position, t.state, t.exit_code, t.timed_out, t.error,
    t.started_at, t.finished_at,
    (SELECT count(*) FROM script_run_targets x WHERE x.run_id = r.id)::int AS servers
FROM script_run_targets t
JOIN script_runs r ON r.id = t.run_id
WHERE t.server_id = @server_id
  AND (sqlc.narg('script_id')::uuid IS NULL OR r.script_id = sqlc.narg('script_id')::uuid)
  AND (@pattern::text = '' OR r.name ILIKE @pattern)
ORDER BY r.id DESC
LIMIT @lim OFFSET @off;

-- name: InterruptScriptRuns :exec
-- What the last process left running can't go on after a restart.
WITH runs AS (
    UPDATE script_runs SET state = 'interrupted', finished_at = now()
    WHERE state = 'running'
    RETURNING id
)
UPDATE script_run_targets SET state = 'interrupted', finished_at = now()
WHERE run_id IN (SELECT id FROM runs) AND state IN ('queued', 'running');

-- name: DeleteOldScriptRuns :exec
DELETE FROM script_runs
WHERE created_at < now() - interval '90 days' AND state NOT IN ('queued', 'running');
