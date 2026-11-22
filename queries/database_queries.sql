-- name: ListDatabaseSavedQueries :many
-- Shared ones and the caller's own; pinned first, then by title.
SELECT * FROM database_saved_queries
WHERE database_id = @database_id AND (shared OR created_by = @user_id)
ORDER BY pinned DESC, lower(title), id;

-- name: GetDatabaseSavedQuery :one
SELECT * FROM database_saved_queries WHERE id = @id AND database_id = @database_id;

-- name: CountDatabaseSavedQueries :one
SELECT count(*)::int FROM database_saved_queries WHERE database_id = $1;

-- name: CreateDatabaseSavedQuery :one
INSERT INTO database_saved_queries (database_id, title, description, dbname, query, shared, pinned, created_by, created_by_name, updated_by_name)
VALUES (@database_id, @title, @description, @dbname, @query, @shared, @pinned, sqlc.narg('created_by'), @created_by_name, @created_by_name)
RETURNING *;

-- name: UpdateDatabaseSavedQuery :one
UPDATE database_saved_queries SET
    title = @title,
    description = @description,
    dbname = @dbname,
    query = @query,
    shared = @shared,
    pinned = @pinned,
    updated_by_name = @updated_by_name,
    updated_at = now()
WHERE id = @id AND database_id = @database_id
RETURNING *;

-- name: MarkDatabaseSavedQueryRun :exec
UPDATE database_saved_queries SET run_count = run_count + 1, last_run_at = now()
WHERE id = @id AND database_id = @database_id;

-- name: DeleteDatabaseSavedQuery :execrows
DELETE FROM database_saved_queries WHERE id = @id AND database_id = @database_id;

-- name: CreateDatabaseQueryRun :one
INSERT INTO database_query_runs (database_id, user_id, user_name, dbname, query, mode, ok, error, rows, ms)
VALUES (@database_id, sqlc.narg('user_id'), @user_name, @dbname, @query, @mode, @ok, @error, @rows, @ms)
RETURNING *;

-- name: ListDatabaseQueryRuns :many
-- Newest first; only one person's when user_id is given.
SELECT * FROM database_query_runs
WHERE database_id = @database_id
  AND (sqlc.narg('user_id')::uuid IS NULL OR user_id = sqlc.narg('user_id'))
  AND (sqlc.narg('before')::timestamptz IS NULL OR at < sqlc.narg('before'))
ORDER BY at DESC
LIMIT @lim;

-- name: PruneDatabaseQueryRuns :exec
DELETE FROM database_query_runs WHERE at < now() - interval '90 days';

-- name: ListDatabaseSavedViews :many
-- One table's: shared ones and the caller's own, by title.
SELECT * FROM database_saved_views
WHERE database_id = @database_id AND dbname = @dbname AND schema_name = @schema_name AND table_name = @table_name
  AND (shared OR created_by = @user_id)
ORDER BY lower(title), id;

-- name: GetDatabaseSavedView :one
SELECT * FROM database_saved_views WHERE id = @id AND database_id = @database_id;

-- name: CountDatabaseSavedViews :one
SELECT count(*)::int FROM database_saved_views WHERE database_id = $1;

-- name: CreateDatabaseSavedView :one
INSERT INTO database_saved_views (database_id, dbname, schema_name, table_name, title, state, shared, created_by, created_by_name, updated_by_name)
VALUES (@database_id, @dbname, @schema_name, @table_name, @title, @state, @shared, sqlc.narg('created_by'), @created_by_name, @created_by_name)
RETURNING *;

-- name: UpdateDatabaseSavedView :one
UPDATE database_saved_views SET
    title = @title,
    state = @state,
    shared = @shared,
    updated_by_name = @updated_by_name,
    updated_at = now()
WHERE id = @id AND database_id = @database_id
RETURNING *;

-- name: DeleteDatabaseSavedView :execrows
DELETE FROM database_saved_views WHERE id = @id AND database_id = @database_id;
