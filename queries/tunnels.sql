-- name: ListTunnels :many
SELECT t.*, (SELECT count(*) FROM servers s WHERE s.tunnel_id = t.id)::int AS server_count,
    ((SELECT count(*) FROM databases d WHERE d.tunnel_id = t.id) + (SELECT count(*) FROM pve_clusters c WHERE c.tunnel_id = t.id)
     + (SELECT count(*) FROM monitors m WHERE m.tunnel_id = t.id) + (SELECT count(*) FROM storages st WHERE st.tunnel_id = t.id))::int AS other_count
FROM tunnels t
WHERE (@see_all::bool OR t.workspace_id = ANY (@workspace_ids::uuid[]))
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR t.workspace_id = sqlc.narg('workspace_id')::uuid)
ORDER BY lower(t.name);

-- name: GetTunnel :one
SELECT * FROM tunnels WHERE id = $1;

-- name: GetTunnelWorkspace :one
SELECT workspace_id FROM tunnels WHERE id = $1;

-- name: CreateTunnel :one
INSERT INTO tunnels (workspace_id, name, kind, config, secrets_enc, description)
VALUES (@workspace_id, @name, @kind, @config, @secrets_enc, @description)
RETURNING *;

-- name: UpdateTunnel :one
UPDATE tunnels SET
    name = @name,
    config = @config,
    secrets_enc = @secrets_enc,
    description = @description,
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteTunnel :exec
DELETE FROM tunnels WHERE id = $1;

-- name: RecordTunnelState :exec
UPDATE tunnels SET
    status = @status,
    status_message = @status_message,
    address = @address,
    status_at = now(),
    last_connected_at = CASE WHEN @status = 'connected' THEN now() ELSE last_connected_at END
WHERE id = @id;

-- name: ResetTunnelStates :exec
-- On start nothing is open yet.
UPDATE tunnels SET status = 'idle', status_message = '', address = '' WHERE status IN ('connecting', 'connected');

-- name: ListTunnelServers :many
SELECT id, name, host, port, status, workspace_id FROM servers WHERE tunnel_id = @tunnel_id::uuid ORDER BY lower(name);

-- name: SetServerTunnel :one
UPDATE servers SET tunnel_id = sqlc.narg('tunnel_id'), updated_at = now() WHERE id = @id RETURNING *;

-- name: SetDatabaseTunnel :exec
UPDATE databases SET tunnel_id = sqlc.narg('tunnel_id') WHERE id = @id;

-- name: SetPVEClusterTunnel :exec
UPDATE pve_clusters SET tunnel_id = sqlc.narg('tunnel_id') WHERE id = @id;

-- name: SetMonitorTunnel :exec
UPDATE monitors SET tunnel_id = sqlc.narg('tunnel_id') WHERE id = @id;

-- name: SetStorageTunnel :exec
UPDATE storages SET tunnel_id = sqlc.narg('tunnel_id') WHERE id = @id;

-- name: ListTunnelUsers :many
-- Everything reached through a tunnel, servers first.
SELECT 'server'::text AS kind, id, name, workspace_id, status FROM servers WHERE tunnel_id = @tunnel_id::uuid
UNION ALL
SELECT 'database', id, name, workspace_id, status FROM databases WHERE tunnel_id = @tunnel_id::uuid
UNION ALL
SELECT 'cluster', id, name, workspace_id, status FROM pve_clusters WHERE tunnel_id = @tunnel_id::uuid
UNION ALL
SELECT 'monitor', id, name, workspace_id, status FROM monitors WHERE tunnel_id = @tunnel_id::uuid
UNION ALL
SELECT 'storage', id, name, workspace_id, status FROM storages WHERE tunnel_id = @tunnel_id::uuid;
