-- name: ListDockerRegistries :many
SELECT * FROM docker_registries WHERE workspace_id = $1 ORDER BY lower(name), id;

-- name: GetDockerRegistry :one
SELECT * FROM docker_registries WHERE id = @id AND workspace_id = @workspace_id;

-- name: CreateDockerRegistry :one
INSERT INTO docker_registries (workspace_id, name, address, username, password_enc)
VALUES (@workspace_id, @name, @address, @username, @password_enc)
RETURNING *;

-- name: UpdateDockerRegistry :one
-- A NULL password keeps the saved one.
UPDATE docker_registries SET
    name = @name,
    address = @address,
    username = @username,
    password_enc = COALESCE(sqlc.narg('password_enc'), password_enc),
    updated_at = now()
WHERE id = @id AND workspace_id = @workspace_id
RETURNING *;

-- name: DeleteDockerRegistry :execrows
DELETE FROM docker_registries WHERE id = @id AND workspace_id = @workspace_id;

-- name: ListDockerTemplates :many
SELECT * FROM docker_templates WHERE workspace_id = $1 ORDER BY lower(name), id;

-- name: GetDockerTemplate :one
SELECT * FROM docker_templates WHERE id = @id AND workspace_id = @workspace_id;

-- name: CreateDockerTemplate :one
INSERT INTO docker_templates (workspace_id, name, description, category, compose, env, created_by_name, updated_by_name)
VALUES (@workspace_id, @name, @description, @category, @compose, @env, @created_by_name, @created_by_name)
RETURNING *;

-- name: UpdateDockerTemplate :one
UPDATE docker_templates SET
    name = @name,
    description = @description,
    category = @category,
    compose = @compose,
    env = @env,
    updated_by_name = @updated_by_name,
    updated_at = now()
WHERE id = @id AND workspace_id = @workspace_id
RETURNING *;

-- name: DeleteDockerTemplate :execrows
DELETE FROM docker_templates WHERE id = @id AND workspace_id = @workspace_id;

-- name: GetDockerSettings :one
SELECT * FROM docker_settings WHERE workspace_id = $1;

-- name: UpsertDockerSettings :one
INSERT INTO docker_settings (workspace_id, projects_dir, update_check, scanner_image, events_hours)
VALUES (@workspace_id, @projects_dir, @update_check, @scanner_image, @events_hours)
ON CONFLICT (workspace_id) DO UPDATE SET
    projects_dir = EXCLUDED.projects_dir,
    update_check = EXCLUDED.update_check,
    scanner_image = EXCLUDED.scanner_image,
    events_hours = EXCLUDED.events_hours,
    updated_at = now()
RETURNING *;

-- name: ListDockerImageUpdates :many
SELECT * FROM docker_image_updates WHERE server_id = $1 ORDER BY image;

-- name: ListDockerImageUpdatesFor :many
SELECT * FROM docker_image_updates WHERE server_id = ANY(@server_ids::uuid[]) ORDER BY server_id, image;

-- name: UpsertDockerImageUpdate :exec
INSERT INTO docker_image_updates (server_id, image, local_digest, remote_digest, state, error, checked_at)
VALUES (@server_id, @image, @local_digest, @remote_digest, @state, @error, now())
ON CONFLICT (server_id, image) DO UPDATE SET
    local_digest = EXCLUDED.local_digest,
    remote_digest = EXCLUDED.remote_digest,
    state = EXCLUDED.state,
    error = EXCLUDED.error,
    checked_at = now();

-- name: DeleteDockerImageUpdatesExcept :exec
-- Forgets images the server no longer runs.
DELETE FROM docker_image_updates WHERE server_id = @server_id AND NOT (image = ANY(@images::text[]));

-- name: MarkDockerImageCurrent :exec
UPDATE docker_image_updates SET state = 'current', local_digest = remote_digest, checked_at = now()
WHERE server_id = @server_id AND image = @image;

-- name: StaleDockerUpdateServers :many
-- Online servers whose image updates were checked before (they have rows)
-- but not since @before, in workspaces that leave the daily check on.
SELECT s.id
FROM servers s
JOIN docker_image_updates u ON u.server_id = s.id
LEFT JOIN docker_settings ds ON ds.workspace_id = s.workspace_id
WHERE s.status = 'online' AND COALESCE(ds.update_check, true)
GROUP BY s.id
HAVING max(u.checked_at) < @before::timestamptz
LIMIT 50;

-- name: ListDockerImageScans :many
SELECT * FROM docker_image_scans WHERE server_id = $1 ORDER BY critical DESC, high DESC, image;

-- name: ListDockerImageScansFor :many
SELECT server_id, image_id, image, critical, high, medium, low, unknown, fixable, scanner, error, scanned_at
FROM docker_image_scans WHERE server_id = ANY(@server_ids::uuid[]);

-- name: GetDockerImageScan :one
SELECT * FROM docker_image_scans WHERE server_id = @server_id AND image_id = @image_id;

-- name: UpsertDockerImageScan :exec
INSERT INTO docker_image_scans (server_id, image_id, image, critical, high, medium, low, unknown, fixable, findings, scanner, error, scanned_at)
VALUES (@server_id, @image_id, @image, @critical, @high, @medium, @low, @unknown, @fixable, @findings, @scanner, @error, now())
ON CONFLICT (server_id, image_id) DO UPDATE SET
    image = EXCLUDED.image,
    critical = EXCLUDED.critical,
    high = EXCLUDED.high,
    medium = EXCLUDED.medium,
    low = EXCLUDED.low,
    unknown = EXCLUDED.unknown,
    fixable = EXCLUDED.fixable,
    findings = EXCLUDED.findings,
    scanner = EXCLUDED.scanner,
    error = EXCLUDED.error,
    scanned_at = now();

-- name: DeleteDockerImageScan :exec
DELETE FROM docker_image_scans WHERE server_id = @server_id AND image_id = @image_id;
