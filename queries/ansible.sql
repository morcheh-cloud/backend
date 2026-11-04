-- name: ListPlaybooks :many
-- With each playbook's newest run, for the list.
SELECT p.id, p.workspace_id, p.name, p.description, p.created_at, p.updated_at,
    length(p.content)::int AS size,
    r.id AS last_run_id, r.state AS last_run_state, r.created_at AS last_run_at
FROM ansible_playbooks p
LEFT JOIN ansible_runs r ON r.id = (
    SELECT x.id FROM ansible_runs x
    WHERE x.playbook_id = p.id ORDER BY x.created_at DESC, x.id DESC LIMIT 1
)
WHERE p.workspace_id = @workspace_id
ORDER BY lower(p.name);

-- name: GetPlaybook :one
SELECT * FROM ansible_playbooks WHERE id = $1;

-- name: GetPlaybookWorkspace :one
SELECT workspace_id FROM ansible_playbooks WHERE id = $1;

-- name: CreatePlaybook :one
INSERT INTO ansible_playbooks (workspace_id, name, description, content, variables, created_by, updated_by)
VALUES (@workspace_id, @name, @description, @content, @variables, sqlc.narg('created_by'), sqlc.narg('created_by'))
RETURNING *;

-- name: UpdatePlaybook :one
UPDATE ansible_playbooks SET
    name = @name,
    description = @description,
    content = @content,
    variables = @variables,
    updated_by = sqlc.narg('updated_by'),
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeletePlaybook :execrows
DELETE FROM ansible_playbooks WHERE id = $1;

-- name: ListAnsibleServers :many
-- With the sealed credentials: only for building a run's inventory.
SELECT * FROM servers WHERE workspace_id = $1 ORDER BY lower(name);

-- name: ListAnsibleFolders :many
SELECT id, parent_id FROM folders WHERE workspace_id = $1;

-- name: CreateAnsibleRun :one
INSERT INTO ansible_runs (
    workspace_id, playbook_id, playbook_name, content, selection, hosts, server_ids,
    options, created_by, created_by_name
) VALUES (
    @workspace_id, sqlc.narg('playbook_id'), @playbook_name, @content, @selection, @hosts, @server_ids,
    @options, sqlc.narg('created_by'), @created_by_name
)
RETURNING *;

-- name: SetAnsibleRunJob :exec
UPDATE ansible_runs SET job_id = @job_id WHERE id = @id;

-- name: GetAnsibleRun :one
SELECT * FROM ansible_runs WHERE id = $1;

-- name: GetAnsibleRunWorkspace :one
SELECT workspace_id FROM ansible_runs WHERE id = $1;

-- name: ListAnsibleRuns :many
-- Newest first, without the heavy columns.
SELECT id, workspace_id, playbook_id, playbook_name, hosts, options, state, error,
    exit_code, recap, job_id, created_by, created_by_name, created_at, started_at, finished_at
FROM ansible_runs
WHERE workspace_id = @workspace_id
  AND (sqlc.narg('playbook_id')::uuid IS NULL OR playbook_id = sqlc.narg('playbook_id')::uuid)
  AND (sqlc.narg('server_id')::uuid IS NULL OR sqlc.narg('server_id')::uuid = ANY (server_ids))
  AND (sqlc.narg('state')::text IS NULL OR state = sqlc.narg('state')::text)
  AND (sqlc.narg('q')::text IS NULL OR playbook_name ILIKE '%' || sqlc.narg('q')::text || '%'
       OR created_by_name ILIKE '%' || sqlc.narg('q')::text || '%')
ORDER BY created_at DESC, id DESC
LIMIT @lim OFFSET @off;

-- name: CountAnsibleRuns :one
SELECT count(*) FROM ansible_runs
WHERE workspace_id = @workspace_id
  AND (sqlc.narg('playbook_id')::uuid IS NULL OR playbook_id = sqlc.narg('playbook_id')::uuid)
  AND (sqlc.narg('server_id')::uuid IS NULL OR sqlc.narg('server_id')::uuid = ANY (server_ids))
  AND (sqlc.narg('state')::text IS NULL OR state = sqlc.narg('state')::text)
  AND (sqlc.narg('q')::text IS NULL OR playbook_name ILIKE '%' || sqlc.narg('q')::text || '%'
       OR created_by_name ILIKE '%' || sqlc.narg('q')::text || '%');

-- name: StartAnsibleRun :exec
UPDATE ansible_runs SET state = 'running', started_at = now() WHERE id = $1;

-- name: SaveAnsibleRunProgress :exec
UPDATE ansible_runs SET output = @output, output_truncated = @output_truncated, plays = @plays
WHERE id = @id;

-- name: FinishAnsibleRun :exec
UPDATE ansible_runs SET
    state = @state,
    error = @error,
    exit_code = sqlc.narg('exit_code'),
    output = @output,
    output_truncated = @output_truncated,
    plays = @plays,
    recap = @recap,
    finished_at = now()
WHERE id = @id;

-- name: EndAnsibleRun :exec
-- A run whose job ended without it (canceled while queued, Morcheh restarted).
UPDATE ansible_runs SET state = @state, error = @error, finished_at = coalesce(finished_at, now())
WHERE id = @id AND state IN ('queued', 'running');

-- name: DeleteAnsibleRun :execrows
DELETE FROM ansible_runs WHERE id = $1 AND state NOT IN ('queued', 'running');
