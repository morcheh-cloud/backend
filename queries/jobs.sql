-- name: CreateJob :one
INSERT INTO jobs (kind, title, params, refs, target, retry_of, created_by)
VALUES (@kind, @title, @params, @refs, sqlc.narg('target'), sqlc.narg('retry_of'), sqlc.narg('created_by'))
RETURNING *;

-- name: GetJob :one
SELECT * FROM jobs WHERE id = $1;

-- name: ListJobs :many
-- Newest first. ref narrows to one server or storage; active to queued and
-- running jobs, finished to the rest; created_by to one person's.
SELECT * FROM jobs
WHERE (sqlc.narg('created_by')::uuid IS NULL OR created_by = sqlc.narg('created_by')::uuid)
  AND (sqlc.narg('ref')::uuid IS NULL OR sqlc.narg('ref')::uuid = ANY(refs))
  AND (sqlc.narg('kind')::text IS NULL OR kind = sqlc.narg('kind')::text)
  AND (sqlc.narg('active')::boolean IS NULL
       OR (state IN ('queued', 'running')) = sqlc.narg('active')::boolean)
ORDER BY created_at DESC, id DESC
LIMIT @lim;

-- name: ListQueuedJobs :many
SELECT * FROM jobs WHERE state = 'queued' ORDER BY created_at, id;

-- name: StartJob :exec
UPDATE jobs SET state = 'running', started_at = now() WHERE id = $1;

-- name: SaveJobProgress :exec
UPDATE jobs SET progress = @progress, log = @log WHERE id = @id;

-- name: FinishJob :exec
UPDATE jobs SET
    state = @state,
    progress = @progress,
    result = sqlc.narg('result'),
    error = @error,
    log = @log,
    finished_at = now()
WHERE id = @id;

-- name: CancelQueuedJob :execrows
UPDATE jobs SET state = 'canceled', finished_at = now()
WHERE id = $1 AND state = 'queued';

-- name: InterruptRunningJobs :execrows
-- At startup: whatever was running died with the last process.
UPDATE jobs SET state = 'interrupted', finished_at = now(),
    error = 'Morcheh restarted while this was running'
WHERE state = 'running';

-- name: DeleteJob :execrows
DELETE FROM jobs WHERE id = $1 AND state NOT IN ('queued', 'running');

-- name: DeleteFinishedJobs :execrows
DELETE FROM jobs
WHERE state NOT IN ('queued', 'running')
  AND (sqlc.narg('created_by')::uuid IS NULL OR created_by = sqlc.narg('created_by')::uuid)
  AND (sqlc.narg('ref')::uuid IS NULL OR sqlc.narg('ref')::uuid = ANY(refs))
  AND (sqlc.narg('before')::timestamptz IS NULL OR finished_at < sqlc.narg('before')::timestamptz);

-- name: ListActiveJobsBy :many
SELECT id FROM jobs WHERE created_by = $1 AND state IN ('queued', 'running');
