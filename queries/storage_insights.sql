-- name: InsertStorageCheck :exec
INSERT INTO storage_checks (storage_id, status, latency_ms, message)
VALUES (@storage_id, @status, sqlc.narg('latency_ms'), @message);

-- name: PruneStorageChecks :execrows
DELETE FROM storage_checks WHERE checked_at < @before::timestamptz;

-- name: InsertStorageUsage :one
INSERT INTO storage_usage (storage_id, used_bytes, files, folders, total_bytes, free_bytes, partial, top, duration_ms)
VALUES (@storage_id, @used_bytes, @files, @folders, sqlc.narg('total_bytes'), sqlc.narg('free_bytes'), @partial, @top, @duration_ms)
RETURNING *;

-- name: PruneStorageUsage :execrows
DELETE FROM storage_usage WHERE measured_at < @before::timestamptz;

-- name: ListStoragesDueForScan :many
-- Online storages not measured since @before, the longest waiting first.
SELECT s.* FROM storages s
LEFT JOIN LATERAL (
    SELECT max(u.measured_at) AS last FROM storage_usage u WHERE u.storage_id = s.id
) u ON true
WHERE s.status = 'online' AND (u.last IS NULL OR u.last < @before::timestamptz)
ORDER BY u.last NULLS FIRST;

-- name: LatestStorageUsage :many
SELECT DISTINCT ON (storage_id) * FROM storage_usage
WHERE storage_id = ANY (@ids::uuid[])
ORDER BY storage_id, measured_at DESC;

-- name: StorageUsageHistory :many
-- Measurements since @since, plus the last one before it (the baseline for
-- growth), oldest first.
SELECT storage_id, measured_at, used_bytes, files FROM (
    SELECT u.storage_id, u.measured_at, u.used_bytes, u.files FROM storage_usage u
    WHERE u.storage_id = ANY (@ids::uuid[]) AND u.measured_at >= @since::timestamptz
    UNION ALL
    (SELECT DISTINCT ON (b.storage_id) b.storage_id, b.measured_at, b.used_bytes, b.files FROM storage_usage b
     WHERE b.storage_id = ANY (@ids::uuid[]) AND b.measured_at < @since::timestamptz
     ORDER BY b.storage_id, b.measured_at DESC)
) h
ORDER BY measured_at;

-- name: StorageCheckSummary :many
SELECT storage_id,
       count(*)::bigint AS checks,
       count(*) FILTER (WHERE status <> 'online')::bigint AS failures,
       coalesce(avg(latency_ms) FILTER (WHERE status = 'online'), 0)::float8 AS latency_avg,
       coalesce(percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) FILTER (WHERE status = 'online'), 0)::float8 AS latency_p95,
       min(checked_at)::timestamptz AS first_at
FROM storage_checks
WHERE storage_id = ANY (@ids::uuid[]) AND checked_at >= @since::timestamptz
GROUP BY storage_id;

-- name: StorageCheckSeries :many
SELECT date_bin(make_interval(secs => @bucket_secs::float8), checked_at, @origin::timestamptz)::timestamptz AS t,
       storage_id,
       count(*)::bigint AS checks,
       count(*) FILTER (WHERE status <> 'online')::bigint AS failures,
       coalesce(avg(latency_ms) FILTER (WHERE status = 'online'), 0)::float8 AS latency_avg,
       coalesce(max(latency_ms) FILTER (WHERE status = 'online'), 0)::int AS latency_max
FROM storage_checks
WHERE storage_id = ANY (@ids::uuid[]) AND checked_at >= @since::timestamptz
GROUP BY 1, 2
ORDER BY 1;

-- name: StorageStatusChanges :many
-- Each time a storage's status changed since @since, newest first. Looks a
-- day further back (lookback) so the first change has its previous status.
SELECT storage_id, checked_at, status, prev_status::text AS prev_status, message FROM (
    SELECT c.storage_id, c.checked_at, c.status, c.message,
           lag(c.status) OVER (PARTITION BY c.storage_id ORDER BY c.checked_at) AS prev_status
    FROM storage_checks c
    WHERE c.storage_id = ANY (@ids::uuid[]) AND c.checked_at >= sqlc.arg('lookback')::timestamptz
) changes
WHERE checked_at >= @since::timestamptz AND prev_status IS NOT NULL AND status <> prev_status
ORDER BY checked_at DESC
LIMIT 200;

-- name: StorageActivitySeries :many
-- Finished file transfers, cron job syncs and database backups touching
-- these storages, per time bucket and kind.
SELECT t::timestamptz AS t, kind::text AS kind,
       count(*) FILTER (WHERE ok)::bigint AS ok,
       count(*) FILTER (WHERE NOT ok)::bigint AS failed,
       coalesce(sum(bytes), 0)::bigint AS bytes,
       coalesce(sum(files), 0)::bigint AS files
FROM (
    SELECT date_bin(make_interval(secs => @bucket_secs::float8), j.finished_at, @origin::timestamptz) AS t,
           'transfer' AS kind, j.state = 'succeeded' AS ok,
           CASE WHEN j.state = 'succeeded' THEN coalesce((j.progress->>'done')::bigint, 0) ELSE 0 END AS bytes,
           CASE WHEN j.state = 'succeeded' THEN coalesce((j.progress->>'items')::bigint, 0) ELSE 0 END AS files
    FROM jobs j
    WHERE j.kind IN ('transfer', 'storage-copy', 'storage-move')
      AND j.refs && @ids::uuid[]
      AND j.state IN ('succeeded', 'failed', 'interrupted')
      AND j.finished_at >= @since::timestamptz
    UNION ALL
    SELECT date_bin(make_interval(secs => @bucket_secs::float8), r.finished_at, @origin::timestamptz),
           'sync', r.state = 'succeeded', r.bytes, r.files::bigint
    FROM schedule_runs r JOIN schedules s ON s.id = r.schedule_id
    WHERE s.storage_ids && @ids::uuid[]
      AND NOT r.dry_run
      AND r.state IN ('succeeded', 'partial', 'failed', 'interrupted')
      AND r.finished_at >= @since::timestamptz
    UNION ALL
    SELECT date_bin(make_interval(secs => @bucket_secs::float8), b.finished_at, @origin::timestamptz),
           'backup', b.state = 'succeeded', CASE WHEN b.state = 'succeeded' THEN b.bytes ELSE 0 END, CASE WHEN b.state = 'succeeded' THEN 1 ELSE 0 END::bigint
    FROM database_backup_copies c JOIN database_backups b ON b.id = c.backup_id
    WHERE c.storage_id = ANY (@ids::uuid[])
      AND b.state IN ('succeeded', 'failed', 'interrupted')
      AND b.finished_at >= @since::timestamptz
) a
GROUP BY 1, 2
ORDER BY 1;

-- name: StorageActivityByStorage :many
-- The same activity, totalled per storage (a transfer between two storages
-- counts for both).
SELECT sid::uuid AS storage_id,
       count(*) FILTER (WHERE ok)::bigint AS ok,
       count(*) FILTER (WHERE NOT ok)::bigint AS failed,
       coalesce(sum(bytes), 0)::bigint AS bytes
FROM (
    SELECT unnest(j.refs) AS sid, j.state = 'succeeded' AS ok,
           CASE WHEN j.state = 'succeeded' THEN coalesce((j.progress->>'done')::bigint, 0) ELSE 0 END AS bytes
    FROM jobs j
    WHERE j.kind IN ('transfer', 'storage-copy', 'storage-move')
      AND j.refs && @ids::uuid[]
      AND j.state IN ('succeeded', 'failed', 'interrupted')
      AND j.finished_at >= @since::timestamptz
    UNION ALL
    SELECT unnest(s.storage_ids), r.state = 'succeeded', r.bytes
    FROM schedule_runs r JOIN schedules s ON s.id = r.schedule_id
    WHERE s.storage_ids && @ids::uuid[]
      AND NOT r.dry_run
      AND r.state IN ('succeeded', 'partial', 'failed', 'interrupted')
      AND r.finished_at >= @since::timestamptz
    UNION ALL
    SELECT c.storage_id, b.state = 'succeeded', CASE WHEN b.state = 'succeeded' THEN b.bytes ELSE 0 END
    FROM database_backup_copies c JOIN database_backups b ON b.id = c.backup_id
    WHERE c.storage_id = ANY (@ids::uuid[])
      AND b.state IN ('succeeded', 'failed', 'interrupted')
      AND b.finished_at >= @since::timestamptz
) a
WHERE sid = ANY (@ids::uuid[])
GROUP BY sid;
