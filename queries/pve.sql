-- name: ListPVEClusters :many
SELECT * FROM pve_clusters
WHERE (@see_all::bool OR workspace_id = ANY (@workspace_ids::uuid[]))
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR workspace_id = sqlc.narg('workspace_id')::uuid)
ORDER BY favorite DESC, lower(name);

-- name: ListAllPVEClusters :many
SELECT * FROM pve_clusters ORDER BY workspace_id, lower(name);

-- name: GetPVECluster :one
SELECT * FROM pve_clusters WHERE id = $1;

-- name: GetPVEClusterWorkspace :one
SELECT workspace_id FROM pve_clusters WHERE id = $1;

-- name: ListPVEClustersDueForCheck :many
-- Clusters whose last check is older than @before (or that were never
-- checked), the longest waiting first.
SELECT * FROM pve_clusters
WHERE last_checked_at IS NULL OR last_checked_at < @before::timestamptz
ORDER BY last_checked_at NULLS FIRST;

-- name: CreatePVECluster :one
INSERT INTO pve_clusters (workspace_id, name, url, token_id, secret_enc, fingerprint, tls_skip_verify, allow_internal, description)
VALUES (@workspace_id, @name, @url, @token_id, @secret_enc, @fingerprint, @tls_skip_verify, @allow_internal, @description)
RETURNING *;

-- name: UpdatePVECluster :one
-- Full replace of the editable fields; the handler resolves the secret first.
UPDATE pve_clusters SET
    name = @name,
    url = @url,
    token_id = @token_id,
    secret_enc = @secret_enc,
    fingerprint = @fingerprint,
    tls_skip_verify = @tls_skip_verify,
    allow_internal = @allow_internal,
    description = @description,
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeletePVECluster :exec
DELETE FROM pve_clusters WHERE id = $1;

-- name: SetPVEClusterFavorite :one
UPDATE pve_clusters SET favorite = @favorite, updated_at = now() WHERE id = @id RETURNING *;

-- name: RecordPVEClusterCheck :one
-- What was last read keeps its value while a cluster is away.
UPDATE pve_clusters SET
    status = @status,
    status_message = @status_message,
    version = CASE WHEN @status = 'online' THEN @version ELSE version END,
    cluster_name = CASE WHEN @status = 'online' THEN @cluster_name ELSE cluster_name END,
    node_count = CASE WHEN @status = 'online' THEN @node_count ELSE node_count END,
    nodes_online = CASE WHEN @status = 'online' THEN @nodes_online ELSE nodes_online END,
    guest_count = CASE WHEN @status = 'online' THEN @guest_count ELSE guest_count END,
    running_count = CASE WHEN @status = 'online' THEN @running_count ELSE running_count END,
    latency_ms = sqlc.narg('latency_ms'),
    last_checked_at = now(),
    last_online_at = CASE WHEN @status = 'online' THEN now() ELSE last_online_at END
WHERE id = @id
RETURNING *;

-- name: ListPVELinks :many
-- Machines linked to servers, with the server's name, on the given clusters.
SELECT l.cluster_id, l.vmid, l.server_id, s.name AS server_name, s.status AS server_status
FROM pve_vm_links l
JOIN servers s ON s.id = l.server_id
WHERE l.cluster_id = ANY (@cluster_ids::uuid[]);

-- name: GetPVELinkForServer :one
SELECT l.cluster_id, l.vmid, l.server_id, c.name AS cluster_name, c.workspace_id
FROM pve_vm_links l
JOIN pve_clusters c ON c.id = l.cluster_id
WHERE l.server_id = $1;

-- name: GetPVELink :one
SELECT * FROM pve_vm_links WHERE cluster_id = @cluster_id AND vmid = @vmid;

-- name: DeletePVELinkForServer :exec
DELETE FROM pve_vm_links WHERE server_id = $1;

-- name: SetPVELink :one
-- A machine links to one server; run DeletePVELinkForServer first so a
-- server links to one machine too.
INSERT INTO pve_vm_links (cluster_id, vmid, server_id) VALUES (@cluster_id, @vmid, @server_id)
ON CONFLICT (cluster_id, vmid) DO UPDATE SET server_id = excluded.server_id, created_at = now()
RETURNING *;

-- name: DeletePVELink :exec
DELETE FROM pve_vm_links WHERE cluster_id = @cluster_id AND vmid = @vmid;
