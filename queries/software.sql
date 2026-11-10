-- name: ListSoftwareRecipes :many
SELECT * FROM software_recipes WHERE workspace_id = $1 ORDER BY slug;

-- name: GetSoftwareRecipe :one
SELECT * FROM software_recipes WHERE id = $1;

-- name: GetSoftwareRecipeBySlug :one
SELECT * FROM software_recipes WHERE workspace_id = @workspace_id AND slug = @slug;

-- name: GetSoftwareRecipeWorkspace :one
SELECT workspace_id FROM software_recipes WHERE id = $1;

-- name: CreateSoftwareRecipe :one
INSERT INTO software_recipes (workspace_id, slug, spec, created_by, updated_by)
VALUES (@workspace_id, @slug, @spec, sqlc.narg('created_by'), sqlc.narg('created_by'))
RETURNING *;

-- name: UpdateSoftwareRecipe :one
UPDATE software_recipes SET spec = @spec, updated_by = sqlc.narg('updated_by'), updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteSoftwareRecipe :exec
DELETE FROM software_recipes WHERE id = $1;

-- name: ListSoftwareInstalls :many
-- Everything installed in a workspace, with the server's name.
SELECT i.*, s.name AS server_name, s.status AS server_status
FROM software_installs i
JOIN servers s ON s.id = i.server_id
WHERE i.workspace_id = $1
ORDER BY i.name, s.name;

-- name: ListServerSoftwareInstalls :many
SELECT i.*, s.name AS server_name, s.status AS server_status
FROM software_installs i
JOIN servers s ON s.id = i.server_id
WHERE i.server_id = $1
ORDER BY i.name;

-- name: GetSoftwareInstall :one
SELECT i.*, s.name AS server_name, s.status AS server_status
FROM software_installs i
JOIN servers s ON s.id = i.server_id
WHERE i.id = $1;

-- name: GetSoftwareInstallServer :one
SELECT server_id, workspace_id FROM software_installs WHERE id = $1;

-- name: GetSoftwareInstallByRecipe :one
SELECT * FROM software_installs WHERE server_id = @server_id AND recipe_id = @recipe_id;

-- name: BeginSoftwareInstall :one
-- A run starts installing an app on a server: a new row, or the old one again.
INSERT INTO software_installs (
    workspace_id, server_id, recipe_id, name, kind, origin, status, params, secrets,
    dir, project, error
) VALUES (
    @workspace_id, @server_id, @recipe_id, @name, @kind, 'morcheh', 'installing', @params,
    @secrets, @dir, @project, ''
)
ON CONFLICT (server_id, recipe_id) DO UPDATE SET
    name = excluded.name,
    kind = excluded.kind,
    origin = 'morcheh',
    status = 'installing',
    params = excluded.params,
    secrets = excluded.secrets,
    dir = excluded.dir,
    project = excluded.project,
    error = '',
    updated_at = now()
RETURNING *;

-- name: SetSoftwareInstallStatus :exec
UPDATE software_installs SET status = @status, error = @error, updated_at = now() WHERE id = @id;

-- name: FinishSoftwareInstall :exec
-- What a finished install or update found on the server.
UPDATE software_installs SET
    status = @status,
    error = @error,
    version = @version,
    latest = @latest,
    update_available = @update_available,
    state = @state,
    images = @images,
    can_rollback = @can_rollback,
    pinned = @pinned,
    checked_at = now(),
    installed_at = CASE WHEN @installed::boolean THEN now() ELSE installed_at END,
    updated_at = now()
WHERE id = @id;

-- name: DeleteSoftwareInstall :exec
DELETE FROM software_installs WHERE id = $1;

-- name: SaveScannedSoftware :exec
-- What a scan found installed. A run in progress keeps its status.
INSERT INTO software_installs (
    workspace_id, server_id, recipe_id, name, kind, origin, status, version, latest,
    update_available, state, images, dir, project, can_rollback, pinned, checked_at, installed_at
) VALUES (
    @workspace_id, @server_id, @recipe_id, @name, @kind, @origin, 'installed', @version,
    @latest, @update_available, @state, @images, @dir, @project, @can_rollback, @pinned, now(), NULL
)
ON CONFLICT (server_id, recipe_id) DO UPDATE SET
    version = excluded.version,
    latest = excluded.latest,
    update_available = excluded.update_available,
    state = excluded.state,
    can_rollback = excluded.can_rollback,
    pinned = excluded.pinned,
    images = CASE WHEN excluded.images = '[]'::jsonb THEN software_installs.images ELSE excluded.images END,
    dir = CASE WHEN excluded.dir = '' THEN software_installs.dir ELSE excluded.dir END,
    project = CASE WHEN excluded.project = '' THEN software_installs.project ELSE excluded.project END,
    status = CASE WHEN software_installs.status IN ('installing', 'updating', 'removing')
        THEN software_installs.status ELSE 'installed' END,
    error = CASE WHEN software_installs.status IN ('installing', 'updating', 'removing')
        THEN software_installs.error ELSE '' END,
    checked_at = now(),
    updated_at = now();

-- name: DeleteGoneFoundSoftware :exec
-- A scan no longer found an app it had found before: forget it.
DELETE FROM software_installs
WHERE server_id = @server_id AND origin = 'found' AND NOT (recipe_id = ANY(@present::text[]))
  AND status NOT IN ('installing', 'updating', 'removing');

-- name: MarkMissingSoftware :exec
-- A scan no longer finds an app Morcheh installed.
UPDATE software_installs SET status = 'missing', state = '', checked_at = now(), updated_at = now()
WHERE server_id = @server_id AND origin = 'morcheh' AND NOT (recipe_id = ANY(@present::text[]))
  AND status = 'installed';

-- name: SaveSoftwareHost :exec
INSERT INTO software_hosts (
    server_id, pm, docker, compose, upgradable, security, reboot_required, packages, error, checked_at
) VALUES (
    @server_id, @pm, @docker, @compose, @upgradable, @security, @reboot_required, @packages, @error, now()
)
ON CONFLICT (server_id) DO UPDATE SET
    pm = excluded.pm,
    docker = excluded.docker,
    compose = excluded.compose,
    upgradable = excluded.upgradable,
    security = excluded.security,
    reboot_required = excluded.reboot_required,
    packages = excluded.packages,
    error = excluded.error,
    checked_at = now();

-- name: SaveSoftwareHostError :exec
INSERT INTO software_hosts (server_id, error, checked_at) VALUES (@server_id, @error, now())
ON CONFLICT (server_id) DO UPDATE SET error = excluded.error, checked_at = now();

-- name: GetSoftwareHost :one
SELECT * FROM software_hosts WHERE server_id = $1;

-- name: ListSoftwareHosts :many
SELECT h.*, s.name AS server_name, s.status AS server_status
FROM software_hosts h
JOIN servers s ON s.id = h.server_id
WHERE s.workspace_id = $1
ORDER BY s.name;

-- name: ServersToScanSoftware :many
-- Online servers whose last scan is older than the interval (or never ran).
SELECT s.id FROM servers s
LEFT JOIN software_hosts h ON h.server_id = s.id
WHERE s.status = 'online'
  AND (h.checked_at IS NULL OR h.checked_at < now() - make_interval(secs => @seconds::float8))
ORDER BY h.checked_at NULLS FIRST
LIMIT 50;

-- name: CreateSoftwareRun :one
INSERT INTO software_runs (
    workspace_id, action, name, options, params, secrets, created_by, created_by_name
) VALUES (
    @workspace_id, @action, @name, @options, @params, @secrets, sqlc.narg('created_by'), @created_by_name
)
RETURNING *;

-- name: CreateSoftwareRunTarget :exec
INSERT INTO software_run_targets (run_id, position, server_id, server_name, recipe_id, recipe_name, version_before)
VALUES (@run_id, @position, @server_id, @server_name, @recipe_id, @recipe_name, @version_before);

-- name: SetSoftwareRunJob :exec
UPDATE software_runs SET job_id = @job_id WHERE id = @id;

-- name: GetSoftwareRun :one
SELECT * FROM software_runs WHERE id = $1;

-- name: ListSoftwareRunTargets :many
SELECT * FROM software_run_targets WHERE run_id = $1 ORDER BY position;

-- name: StartSoftwareRun :exec
UPDATE software_runs SET state = 'running', started_at = now() WHERE id = $1;

-- name: FinishSoftwareRun :exec
UPDATE software_runs SET state = @state, error = @error, finished_at = now() WHERE id = @id;

-- name: EndSoftwareRun :exec
WITH run AS (
    UPDATE software_runs SET state = @state, error = @error, finished_at = coalesce(finished_at, now())
    WHERE id = @id AND state IN ('queued', 'running')
    RETURNING id
)
UPDATE software_run_targets SET state = @state, finished_at = coalesce(finished_at, now())
WHERE run_id IN (SELECT id FROM run) AND state IN ('queued', 'running');

-- name: StartSoftwareTarget :exec
UPDATE software_run_targets SET state = 'running', started_at = now()
WHERE run_id = @run_id AND position = @position;

-- name: SaveSoftwareTargetOutput :exec
UPDATE software_run_targets SET output = @output, truncated = @truncated
WHERE run_id = @run_id AND position = @position;

-- name: FinishSoftwareTarget :exec
UPDATE software_run_targets SET
    state = @state,
    error = @error,
    output = @output,
    truncated = @truncated,
    version_after = @version_after,
    started_at = CASE WHEN @state::text = 'skipped' THEN started_at ELSE coalesce(started_at, now()) END,
    finished_at = now()
WHERE run_id = @run_id AND position = @position;

-- name: ListSoftwareRuns :many
SELECT r.id, r.workspace_id, r.action, r.name, r.state, r.error, r.job_id, r.created_by,
    r.created_by_name, r.created_at, r.started_at, r.finished_at,
    (SELECT count(*) FROM software_run_targets t WHERE t.run_id = r.id)::int AS targets,
    (SELECT count(*) FROM software_run_targets t WHERE t.run_id = r.id AND t.state = 'succeeded')::int AS succeeded,
    (SELECT count(*) FROM software_run_targets t WHERE t.run_id = r.id AND t.state IN ('failed', 'interrupted'))::int AS failed,
    (SELECT coalesce(array_agg(DISTINCT t.server_name), '{}')
     FROM software_run_targets t WHERE t.run_id = r.id)::text[] AS server_names,
    (SELECT coalesce(array_agg(DISTINCT t.server_id) FILTER (WHERE t.server_id IS NOT NULL), '{}')
     FROM software_run_targets t WHERE t.run_id = r.id)::uuid[] AS server_ids
FROM software_runs r
WHERE r.workspace_id = @workspace_id
  AND (sqlc.narg('server_id')::uuid IS NULL OR EXISTS (
      SELECT 1 FROM software_run_targets t WHERE t.run_id = r.id AND t.server_id = sqlc.narg('server_id')::uuid))
  AND (sqlc.narg('recipe_id')::text IS NULL OR EXISTS (
      SELECT 1 FROM software_run_targets t WHERE t.run_id = r.id AND t.recipe_id = sqlc.narg('recipe_id')::text))
  AND (sqlc.narg('state')::text IS NULL OR r.state = sqlc.narg('state')::text)
  AND (sqlc.narg('q')::text IS NULL OR r.name ILIKE '%' || sqlc.narg('q')::text || '%'
       OR r.created_by_name ILIKE '%' || sqlc.narg('q')::text || '%')
ORDER BY r.id DESC
LIMIT @lim OFFSET @off;

-- name: CountSoftwareRuns :one
SELECT count(*) FROM software_runs r
WHERE r.workspace_id = @workspace_id
  AND (sqlc.narg('server_id')::uuid IS NULL OR EXISTS (
      SELECT 1 FROM software_run_targets t WHERE t.run_id = r.id AND t.server_id = sqlc.narg('server_id')::uuid))
  AND (sqlc.narg('recipe_id')::text IS NULL OR EXISTS (
      SELECT 1 FROM software_run_targets t WHERE t.run_id = r.id AND t.recipe_id = sqlc.narg('recipe_id')::text))
  AND (sqlc.narg('state')::text IS NULL OR r.state = sqlc.narg('state')::text)
  AND (sqlc.narg('q')::text IS NULL OR r.name ILIKE '%' || sqlc.narg('q')::text || '%'
       OR r.created_by_name ILIKE '%' || sqlc.narg('q')::text || '%');

-- name: ActiveSoftwareRunsOn :many
-- Runs still going that touch these servers.
SELECT DISTINCT t.server_id::uuid AS server_id, t.recipe_id
FROM software_run_targets t
JOIN software_runs r ON r.id = t.run_id
WHERE r.state IN ('queued', 'running') AND t.server_id = ANY(@server_ids::uuid[]);

-- name: DeleteSoftwareRun :execrows
DELETE FROM software_runs WHERE id = $1 AND state NOT IN ('queued', 'running');

-- name: InterruptSoftwareRuns :exec
WITH runs AS (
    UPDATE software_runs SET state = 'interrupted', error = 'Morcheh restarted before it finished.', finished_at = now()
    WHERE state = 'running'
    RETURNING id
)
UPDATE software_run_targets SET state = 'interrupted', finished_at = now()
WHERE run_id IN (SELECT id FROM runs) AND state IN ('queued', 'running');

-- name: ResetStuckSoftwareInstalls :exec
-- Installs left mid-change by a restart.
UPDATE software_installs SET status = 'failed', error = 'Morcheh restarted while this was changing.'
WHERE status IN ('installing', 'updating', 'removing');

-- name: DeleteOldSoftwareRuns :exec
DELETE FROM software_runs
WHERE created_at < now() - interval '90 days' AND state NOT IN ('queued', 'running');

-- name: WorkspaceServersToScan :many
-- A workspace's servers a scan can reach now.
SELECT id FROM servers WHERE workspace_id = $1 AND status IN ('online', 'unknown') ORDER BY name;
