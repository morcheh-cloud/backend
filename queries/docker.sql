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
INSERT INTO docker_settings (workspace_id, projects_dir, update_check, scanner_image, events_hours, stats_days, update_check_hours, scan_ignore_unfixed, remove_orphans, versions_keep, default_restart, default_memory_mb, default_cpus, default_log_max_mb, default_log_files, prune_auto, prune_hours, prune_images, prune_containers, prune_networks, prune_build_cache, prune_older_hours, notify_updates, notify_vulns, notify_channels, backup_storage_id, backup_folder, backup_stop, backup_keep)
VALUES (@workspace_id, @projects_dir, @update_check, @scanner_image, @events_hours, @stats_days, @update_check_hours, @scan_ignore_unfixed, @remove_orphans, @versions_keep, @default_restart, @default_memory_mb, @default_cpus, @default_log_max_mb, @default_log_files, @prune_auto, @prune_hours, @prune_images, @prune_containers, @prune_networks, @prune_build_cache, @prune_older_hours, @notify_updates, @notify_vulns, @notify_channels, sqlc.narg(backup_storage_id), @backup_folder, @backup_stop, @backup_keep)
ON CONFLICT (workspace_id) DO UPDATE SET
    projects_dir = EXCLUDED.projects_dir,
    update_check = EXCLUDED.update_check,
    scanner_image = EXCLUDED.scanner_image,
    events_hours = EXCLUDED.events_hours,
    stats_days = EXCLUDED.stats_days,
    update_check_hours = EXCLUDED.update_check_hours,
    scan_ignore_unfixed = EXCLUDED.scan_ignore_unfixed,
    remove_orphans = EXCLUDED.remove_orphans,
    versions_keep = EXCLUDED.versions_keep,
    default_restart = EXCLUDED.default_restart,
    default_memory_mb = EXCLUDED.default_memory_mb,
    default_cpus = EXCLUDED.default_cpus,
    default_log_max_mb = EXCLUDED.default_log_max_mb,
    default_log_files = EXCLUDED.default_log_files,
    prune_auto = EXCLUDED.prune_auto,
    prune_hours = EXCLUDED.prune_hours,
    prune_images = EXCLUDED.prune_images,
    prune_containers = EXCLUDED.prune_containers,
    prune_networks = EXCLUDED.prune_networks,
    prune_build_cache = EXCLUDED.prune_build_cache,
    prune_older_hours = EXCLUDED.prune_older_hours,
    notify_updates = EXCLUDED.notify_updates,
    notify_vulns = EXCLUDED.notify_vulns,
    notify_channels = EXCLUDED.notify_channels,
    backup_storage_id = EXCLUDED.backup_storage_id,
    backup_folder = EXCLUDED.backup_folder,
    backup_stop = EXCLUDED.backup_stop,
    backup_keep = EXCLUDED.backup_keep,
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
    remote_digest = CASE WHEN EXCLUDED.remote_digest = '' THEN docker_image_updates.remote_digest ELSE EXCLUDED.remote_digest END,
    seen_at = CASE WHEN EXCLUDED.remote_digest <> '' AND EXCLUDED.remote_digest <> docker_image_updates.remote_digest
        THEN now() ELSE docker_image_updates.seen_at END,
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
-- but not within their check interval (the server's own, else its
-- workspace's), where the automatic check is on.
SELECT s.id
FROM servers s
JOIN docker_image_updates u ON u.server_id = s.id
LEFT JOIN docker_settings ds ON ds.workspace_id = s.workspace_id
LEFT JOIN docker_server_settings o ON o.server_id = s.id
WHERE s.status = 'online' AND COALESCE((o.overrides->>'update_check')::boolean, ds.update_check, true)
GROUP BY s.id, ds.update_check_hours, o.overrides
HAVING max(u.checked_at) < now() - make_interval(hours => COALESCE((o.overrides->>'update_check_hours')::int, ds.update_check_hours, 24))
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

-- name: DockerProjectMetas :many
SELECT * FROM docker_project_meta WHERE server_id = $1;

-- name: UpsertDockerProjectMeta :one
INSERT INTO docker_project_meta (server_id, project, title, note, updated_by_name, updated_at)
VALUES (@server_id, @project, @title, @note, @updated_by_name, now())
ON CONFLICT (server_id, project) DO UPDATE SET
    title = EXCLUDED.title, note = EXCLUDED.note,
    updated_by_name = EXCLUDED.updated_by_name, updated_at = now()
RETURNING *;

-- name: ListDockerProjectVersions :many
SELECT id, server_id, project, revision, reason, note, created_by_name, created_at,
       length(compose)::int AS compose_size, (env_enc IS NOT NULL)::bool AS has_env
FROM docker_project_versions
WHERE server_id = $1 AND project = $2
ORDER BY created_at DESC, id DESC
LIMIT 200;

-- name: GetDockerProjectVersion :one
SELECT * FROM docker_project_versions WHERE id = $1 AND server_id = $2 AND project = $3;

-- name: LatestDockerProjectVersion :one
SELECT * FROM docker_project_versions
WHERE server_id = $1 AND project = $2
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: CreateDockerProjectVersion :one
INSERT INTO docker_project_versions (server_id, project, revision, compose, env_enc, reason, note, created_by_name)
VALUES (@server_id, @project, @revision, @compose, @env_enc, @reason, @note, @created_by_name)
RETURNING id, created_at;

-- name: PruneDockerProjectVersions :exec
-- Keeps the newest @keep of a project.
DELETE FROM docker_project_versions v
WHERE v.server_id = @server_id AND v.project = @project AND v.id NOT IN (
    SELECT k.id FROM docker_project_versions k
    WHERE k.server_id = @server_id AND k.project = @project
    ORDER BY k.created_at DESC, k.id DESC
    LIMIT sqlc.arg(keep)::int
);

-- name: DockerStatsServers :many
-- Servers whose projects are recorded: the ones measured lately (@ids),
-- those with points from the last week and those known to run Docker (their
-- images are checked for updates), in workspaces that keep history.
SELECT s.id, COALESCE((o.overrides->>'stats_days')::int, ds.stats_days, 30)::int AS stats_days
FROM servers s
LEFT JOIN docker_settings ds ON ds.workspace_id = s.workspace_id
LEFT JOIN docker_server_settings o ON o.server_id = s.id
WHERE s.status = 'online' AND COALESCE((o.overrides->>'stats_days')::int, ds.stats_days, 30) > 0
  AND (s.id = ANY(@ids::uuid[])
    OR EXISTS (SELECT 1 FROM docker_project_stats p WHERE p.server_id = s.id AND p.at > now() - interval '7 days')
    OR EXISTS (SELECT 1 FROM docker_image_updates u WHERE u.server_id = s.id))
LIMIT 200;

-- name: AddDockerProjectStat :exec
INSERT INTO docker_project_stats (server_id, project, at, cpu, cpu_max, memory, memory_max, net_rx, net_tx, running, total, unhealthy)
VALUES (@server_id, @project, @at, @cpu, @cpu_max, @memory, @memory_max, @net_rx, @net_tx, @running, @total, @unhealthy)
ON CONFLICT DO NOTHING;

-- name: PruneDockerProjectStats :execrows
DELETE FROM docker_project_stats p
USING servers s
LEFT JOIN docker_settings ds ON ds.workspace_id = s.workspace_id
LEFT JOIN docker_server_settings o ON o.server_id = s.id
WHERE p.server_id = s.id AND p.at < now() - make_interval(days => COALESCE((o.overrides->>'stats_days')::int, ds.stats_days, 30));

-- name: DockerProjectStatsHistory :many
SELECT date_bin(make_interval(secs => sqlc.arg(step_seconds)::int), at, '2000-01-01T00:00:00Z'::timestamptz)::timestamptz AS bucket,
    avg(cpu)::float8 AS cpu, max(cpu_max)::float8 AS cpu_max,
    avg(memory)::float8 AS memory, max(memory_max)::bigint AS memory_max,
    avg(net_rx)::float8 AS net_rx, avg(net_tx)::float8 AS net_tx,
    min(running)::int AS running, max(total)::int AS total, max(unhealthy)::int AS unhealthy
FROM docker_project_stats
WHERE server_id = @server_id AND project = @project AND at >= @since::timestamptz
GROUP BY 1 ORDER BY 1;

-- name: FirstDockerProjectStat :one
SELECT min(at)::timestamptz FROM docker_project_stats WHERE server_id = @server_id AND project = @project;

-- name: CreateDockerVolumeBackup :one
INSERT INTO docker_volume_backups (server_id, volume, storage_id, storage_name, path, schedule_id, job_id, created_by_name)
VALUES (@server_id, @volume, @storage_id, @storage_name, @path, sqlc.narg(schedule_id), sqlc.narg(job_id), @created_by_name)
RETURNING *;

-- name: FinishDockerVolumeBackup :exec
UPDATE docker_volume_backups
SET state = @state, size = @size, sha256 = @sha256, error = @error, note = @note, stopped = @stopped, finished_at = now()
WHERE id = @id;

-- name: GetDockerVolumeBackup :one
SELECT * FROM docker_volume_backups WHERE id = @id AND server_id = @server_id;

-- name: ListDockerVolumeBackups :many
SELECT * FROM docker_volume_backups
WHERE server_id = @server_id AND (sqlc.narg(volume)::text IS NULL OR volume = sqlc.narg(volume))
ORDER BY created_at DESC
LIMIT 500;

-- Stored copies of a volume beyond the newest @keep made by one cron job.
-- name: OldDockerVolumeBackups :many
SELECT * FROM docker_volume_backups
WHERE server_id = @server_id AND volume = @volume AND schedule_id IS NOT DISTINCT FROM sqlc.narg(schedule_id)::uuid AND state = 'stored'
ORDER BY created_at DESC
OFFSET @keep::int;

-- name: DeleteDockerVolumeBackup :exec
DELETE FROM docker_volume_backups WHERE id = @id;

-- Copies cut off by a restart of Morche.
-- name: FailStaleDockerVolumeBackups :exec
UPDATE docker_volume_backups
SET state = 'failed', error = 'Morche stopped before it finished.', finished_at = now()
WHERE state = 'running';

-- name: GetDockerGitSource :one
SELECT * FROM docker_git_sources WHERE server_id = $1 AND project = $2;

-- name: GetDockerGitSourceByHook :one
SELECT * FROM docker_git_sources WHERE webhook_hash = $1;

-- name: ListDockerGitSources :many
SELECT * FROM docker_git_sources WHERE server_id = $1 ORDER BY project;

-- name: DueDockerGitSources :many
SELECT * FROM docker_git_sources
WHERE auto_deploy AND poll_minutes > 0
  AND (last_checked_at IS NULL OR last_checked_at < now() - make_interval(mins => poll_minutes))
ORDER BY last_checked_at NULLS FIRST
LIMIT 50;

-- name: UpsertDockerGitSource :one
INSERT INTO docker_git_sources (server_id, project, dir, repo_url, branch, compose_path, username, token_enc,
    auto_deploy, poll_minutes, webhook_enc, webhook_hash, created_by, created_by_name)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
ON CONFLICT (server_id, project) DO UPDATE SET
    repo_url = EXCLUDED.repo_url, branch = EXCLUDED.branch, compose_path = EXCLUDED.compose_path,
    username = EXCLUDED.username, token_enc = EXCLUDED.token_enc, auto_deploy = EXCLUDED.auto_deploy,
    poll_minutes = EXCLUDED.poll_minutes, created_by = EXCLUDED.created_by,
    created_by_name = EXCLUDED.created_by_name, last_error = '', updated_at = now()
RETURNING *;

-- name: SetDockerGitWebhook :one
UPDATE docker_git_sources SET webhook_enc = $3, webhook_hash = $4, updated_at = now()
WHERE server_id = $1 AND project = $2
RETURNING *;

-- name: DeleteDockerGitSource :execrows
DELETE FROM docker_git_sources WHERE server_id = $1 AND project = $2;

-- name: DockerGitDeployed :exec
UPDATE docker_git_sources SET last_commit = $3, last_message = $4, last_author = $5,
    last_deployed_at = now(), last_checked_at = now(), last_error = ''
WHERE server_id = $1 AND project = $2;

-- name: DockerGitChecked :exec
UPDATE docker_git_sources SET last_checked_at = now(), last_error = $3
WHERE server_id = $1 AND project = $2;

-- name: DockerServerStatsHistory :many
-- Every compose project of a server added up per recorded point, then
-- averaged per bucket.
WITH t AS (
    SELECT at, sum(cpu) AS cpu, sum(cpu_max) AS cpu_max, sum(memory) AS memory,
        sum(net_rx) AS net_rx, sum(net_tx) AS net_tx, sum(running) AS running, sum(total) AS total
    FROM docker_project_stats
    WHERE server_id = @server_id AND at >= @since::timestamptz
    GROUP BY at
)
SELECT date_bin(make_interval(secs => sqlc.arg(step_seconds)::int), at, '2000-01-01T00:00:00Z'::timestamptz)::timestamptz AS bucket,
    avg(cpu)::float8 AS cpu, max(cpu_max)::float8 AS cpu_max,
    avg(memory)::float8 AS memory, max(memory)::bigint AS memory_max,
    avg(net_rx)::float8 AS net_rx, avg(net_tx)::float8 AS net_tx,
    min(running)::int AS running, max(total)::int AS total
FROM t
GROUP BY 1 ORDER BY 1;

-- name: GetDockerServerSettings :one
SELECT * FROM docker_server_settings WHERE server_id = $1;

-- name: ListDockerServerSettings :many
-- Every server of a workspace with its own settings or an automatic
-- clean-up on record.
SELECT s.id AS server_id, s.name AS server_name,
    COALESCE(o.overrides, '{}'::jsonb)::jsonb AS overrides, o.updated_at,
    p.ran_at AS pruned_at, COALESCE(p.space, 0)::bigint AS pruned_space,
    COALESCE(p.removed, 0)::int AS pruned_removed, COALESCE(p.error, '')::text AS prune_error
FROM servers s
LEFT JOIN docker_server_settings o ON o.server_id = s.id
LEFT JOIN docker_auto_prunes p ON p.server_id = s.id
WHERE s.workspace_id = @workspace_id AND (o.server_id IS NOT NULL OR p.server_id IS NOT NULL)
ORDER BY s.name;

-- name: UpsertDockerServerSettings :one
INSERT INTO docker_server_settings (server_id, overrides)
VALUES (@server_id, @overrides)
ON CONFLICT (server_id) DO UPDATE SET overrides = EXCLUDED.overrides, updated_at = now()
RETURNING *;

-- name: DeleteDockerServerSettings :exec
DELETE FROM docker_server_settings WHERE server_id = $1;

-- name: DockerAutoPruneServers :many
-- Online servers known to run Docker whose automatic clean-up (their own
-- setting, else their workspace's) is due.
SELECT s.id
FROM servers s
LEFT JOIN docker_settings ds ON ds.workspace_id = s.workspace_id
LEFT JOIN docker_server_settings o ON o.server_id = s.id
LEFT JOIN docker_auto_prunes p ON p.server_id = s.id
WHERE s.status = 'online'
  AND COALESCE((o.overrides->>'prune_auto')::boolean, ds.prune_auto, false)
  AND (EXISTS (SELECT 1 FROM docker_image_updates u WHERE u.server_id = s.id)
    OR EXISTS (SELECT 1 FROM docker_project_stats st WHERE st.server_id = s.id AND st.at > now() - interval '7 days'))
  AND (p.ran_at IS NULL OR p.ran_at < now() - make_interval(hours => COALESCE((o.overrides->>'prune_hours')::int, ds.prune_hours, 168)))
LIMIT 20;

-- name: RecordDockerAutoPrune :exec
INSERT INTO docker_auto_prunes (server_id, ran_at, space, removed, error)
VALUES (@server_id, now(), @space, @removed, @error)
ON CONFLICT (server_id) DO UPDATE SET ran_at = now(), space = EXCLUDED.space, removed = EXCLUDED.removed, error = EXCLUDED.error;

-- name: DockerProjectPlaces :many
SELECT * FROM docker_project_places WHERE server_id = $1;

-- name: UpsertDockerProjectPlace :exec
INSERT INTO docker_project_places (server_id, project, dir, files, source, added_by_name)
VALUES (@server_id, @project, @dir, @files, @source, @added_by_name)
ON CONFLICT (server_id, project) DO UPDATE SET
    dir = EXCLUDED.dir, files = EXCLUDED.files, source = EXCLUDED.source,
    hidden = false, added_by_name = EXCLUDED.added_by_name;

-- name: RememberDockerProjectPlace :exec
INSERT INTO docker_project_places (server_id, project, dir, files, source)
VALUES (@server_id, @project, @dir, @files, 'containers')
ON CONFLICT (server_id, project) DO NOTHING;

-- name: HideDockerProjectPlace :execrows
UPDATE docker_project_places SET hidden = true
WHERE server_id = @server_id AND project = @project;

-- name: HideDockerProjectPlaceAt :exec
INSERT INTO docker_project_places (server_id, project, dir, files, source, hidden, added_by_name)
VALUES (@server_id, @project, @dir, @files, 'scan', true, @added_by_name)
ON CONFLICT (server_id, project) DO UPDATE SET hidden = true;

-- name: DockerProjectScan :one
SELECT * FROM docker_project_scans WHERE server_id = $1;

-- name: SaveDockerProjectScan :exec
INSERT INTO docker_project_scans (server_id, scanned_at, took_ms, items, truncated, error)
VALUES (@server_id, now(), @took_ms, @items, @truncated, @error)
ON CONFLICT (server_id) DO UPDATE SET
    scanned_at = now(), took_ms = EXCLUDED.took_ms, items = EXCLUDED.items,
    truncated = EXCLUDED.truncated, error = EXCLUDED.error;
