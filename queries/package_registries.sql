-- name: ListPackageRegistries :many
SELECT sqlc.embed(r), s.name AS server_name, s.host AS server_host, s.workspace_id, s.status AS server_status
FROM package_registries r
JOIN servers s ON s.id = r.server_id
WHERE (@see_all::bool OR s.workspace_id = ANY (@workspace_ids::uuid[]) OR s.id = ANY (@server_ids::uuid[]))
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR s.workspace_id = sqlc.narg('workspace_id')::uuid)
  AND (sqlc.narg('server_id')::uuid IS NULL OR r.server_id = sqlc.narg('server_id')::uuid)
ORDER BY lower(r.name), r.id;

-- name: ListAllPackageRegistries :many
SELECT * FROM package_registries WHERE state = 'ready' ORDER BY id;

-- name: GetPackageRegistry :one
SELECT sqlc.embed(r), s.name AS server_name, s.host AS server_host, s.workspace_id, s.status AS server_status
FROM package_registries r
JOIN servers s ON s.id = r.server_id
WHERE r.id = $1;

-- name: GetPackageRegistryServer :one
SELECT s.id, s.workspace_id
FROM package_registries r
JOIN servers s ON s.id = r.server_id
WHERE r.id = $1;

-- name: ListServerPackageRegistryPorts :many
SELECT port FROM package_registries WHERE server_id = $1;

-- name: CreatePackageRegistry :one
INSERT INTO package_registries (server_id, kind, name, note, project, dir, port, domain, https, version, admin_user, admin_secret_enc, settings, created_by_name)
VALUES (@server_id, @kind, @name, @note, @project, @dir, @port, @domain, @https, @version, @admin_user, @admin_secret_enc, @settings, @created_by_name)
RETURNING *;

-- name: SetPackageRegistryJob :exec
UPDATE package_registries SET job_id = @job_id, state = @state, problem = '', updated_at = now() WHERE id = @id;

-- name: SetPackageRegistryState :exec
UPDATE package_registries SET state = @state, problem = @problem, updated_at = now() WHERE id = @id;

-- name: SetPackageRegistryLinks :exec
UPDATE package_registries SET
    proxy_host_id = sqlc.narg('proxy_host_id'),
    docker_registry_id = sqlc.narg('docker_registry_id'),
    https = @https,
    updated_at = now()
WHERE id = @id;

-- name: UpdatePackageRegistry :one
UPDATE package_registries SET name = @name, note = @note, settings = @settings, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: SetPackageRegistryHealth :exec
UPDATE package_registries SET
    health = @health,
    problem = CASE WHEN state = 'ready' THEN @problem ELSE problem END,
    version = CASE WHEN @version::text = '' THEN version ELSE @version::text END,
    usage_bytes = @usage_bytes,
    items = @items,
    checked_at = now()
WHERE id = @id;

-- name: DeletePackageRegistry :exec
DELETE FROM package_registries WHERE id = $1;

-- name: GetProxyHostProxy :one
SELECT proxy_id FROM proxy_hosts WHERE id = $1;
