-- name: RecordServerCheckBucket :exec
INSERT INTO server_check_buckets (server_id, bucket, checks, failures, latency_sum, latency_max)
VALUES (@server_id, date_bin('5 minutes', now(), timestamptz '2000-01-01'), 1, @failures, @latency_sum, @latency_max)
ON CONFLICT (server_id, bucket) DO UPDATE SET
    checks = server_check_buckets.checks + 1,
    failures = server_check_buckets.failures + excluded.failures,
    latency_sum = server_check_buckets.latency_sum + excluded.latency_sum,
    latency_max = greatest(server_check_buckets.latency_max, excluded.latency_max);

-- name: InsertServerStatusChange :exec
INSERT INTO server_status_changes (server_id, status, prev_status, message)
VALUES (@server_id, @status, @prev_status, @message);

-- name: InsertServerSample :exec
INSERT INTO server_samples (
    server_id, at, cpu_percent, iowait_percent, cores, load1, mem_used_bytes, mem_total_bytes,
    swap_used_bytes, swap_total_bytes, disk_used_bytes, disk_total_bytes, disk_max_percent,
    disk_max_mount, rx_bytes_per_sec, tx_bytes_per_sec
) VALUES (
    @server_id, @at, @cpu_percent, @iowait_percent, @cores, @load1, @mem_used_bytes, @mem_total_bytes,
    @swap_used_bytes, @swap_total_bytes, @disk_used_bytes, @disk_total_bytes, @disk_max_percent,
    @disk_max_mount, @rx_bytes_per_sec, @tx_bytes_per_sec
)
ON CONFLICT DO NOTHING;

-- name: ListServersToSample :many
-- Online servers that aren't known to be something other than Linux.
SELECT * FROM servers
WHERE status = 'online' AND os_family IN ('', 'linux')
ORDER BY id;

-- name: PruneServerCheckBuckets :execrows
DELETE FROM server_check_buckets WHERE bucket < @before::timestamptz;

-- name: PruneServerStatusChanges :execrows
DELETE FROM server_status_changes WHERE at < @before::timestamptz;

-- name: PruneServerSamples :execrows
DELETE FROM server_samples WHERE at < @before::timestamptz;

-- name: ServerCheckSummary :many
SELECT server_id,
       sum(checks)::bigint AS checks,
       sum(failures)::bigint AS failures,
       coalesce(sum(latency_sum)::float8 / nullif(sum(checks - failures), 0), 0)::float8 AS latency_avg,
       coalesce(max(latency_max), 0)::int AS latency_max,
       min(bucket)::timestamptz AS first_at
FROM server_check_buckets
WHERE server_id = ANY (@ids::uuid[]) AND bucket >= @since::timestamptz
GROUP BY server_id;

-- name: ServerCheckSeries :many
SELECT date_bin(make_interval(secs => @bucket_secs::float8), bucket, @origin::timestamptz)::timestamptz AS t,
       server_id,
       sum(checks)::bigint AS checks,
       sum(failures)::bigint AS failures,
       coalesce(sum(latency_sum)::float8 / nullif(sum(checks - failures), 0), 0)::float8 AS latency_avg,
       coalesce(max(latency_max), 0)::int AS latency_max
FROM server_check_buckets
WHERE server_id = ANY (@ids::uuid[]) AND bucket >= @since::timestamptz
GROUP BY 1, 2
ORDER BY 1;

-- name: ServerStatusChanges :many
SELECT * FROM server_status_changes
WHERE server_id = ANY (@ids::uuid[]) AND at >= @since::timestamptz
ORDER BY at DESC
LIMIT 200;

-- name: LatestServerSamples :many
SELECT DISTINCT ON (server_id) * FROM server_samples
WHERE server_id = ANY (@ids::uuid[])
ORDER BY server_id, at DESC;

-- name: ServerSampleSummary :many
-- Averages and peaks over the range, and the root disk at its start and end
-- (for growth and "full in N days").
SELECT server_id,
       count(*)::bigint AS samples,
       avg(cpu_percent)::float8 AS cpu_avg,
       max(cpu_percent)::float8 AS cpu_max,
       coalesce(avg(100.0 * mem_used_bytes / nullif(mem_total_bytes, 0)), 0)::float8 AS mem_avg,
       coalesce(max(100.0 * mem_used_bytes / nullif(mem_total_bytes, 0)), 0)::float8 AS mem_max,
       max(disk_max_percent)::float8 AS disk_max,
       avg(rx_bytes_per_sec)::float8 AS rx_avg,
       avg(tx_bytes_per_sec)::float8 AS tx_avg,
       min(at)::timestamptz AS first_at,
       max(at)::timestamptz AS last_at,
       ((array_agg(disk_used_bytes ORDER BY at))[1])::bigint AS disk_first,
       ((array_agg(disk_used_bytes ORDER BY at DESC))[1])::bigint AS disk_last
FROM server_samples
WHERE server_id = ANY (@ids::uuid[]) AND at >= @since::timestamptz
GROUP BY server_id;

-- name: ServerSampleSeries :many
SELECT date_bin(make_interval(secs => @bucket_secs::float8), at, @origin::timestamptz)::timestamptz AS t,
       server_id,
       count(*)::bigint AS samples,
       avg(cpu_percent)::float8 AS cpu_avg,
       max(cpu_percent)::float8 AS cpu_max,
       coalesce(avg(100.0 * mem_used_bytes / nullif(mem_total_bytes, 0)), 0)::float8 AS mem_avg,
       coalesce(max(100.0 * mem_used_bytes / nullif(mem_total_bytes, 0)), 0)::float8 AS mem_max,
       max(disk_max_percent)::float8 AS disk_max,
       max(disk_used_bytes)::bigint AS disk_used,
       avg(rx_bytes_per_sec)::float8 AS rx_avg,
       avg(tx_bytes_per_sec)::float8 AS tx_avg,
       avg(load1)::float8 AS load_avg
FROM server_samples
WHERE server_id = ANY (@ids::uuid[]) AND at >= @since::timestamptz
GROUP BY 1, 2
ORDER BY 1;
