-- +goose Up

-- Connection checks of each server, counted in 5-minute buckets (a check
-- every 15 s would be 5,760 rows a day per server). Pruned after
-- SERVER_HISTORY.
CREATE TABLE server_check_buckets (
    server_id   uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    bucket      timestamptz NOT NULL,
    checks      integer NOT NULL DEFAULT 0,
    failures    integer NOT NULL DEFAULT 0,
    -- Over the online checks only.
    latency_sum bigint NOT NULL DEFAULT 0,
    latency_max integer NOT NULL DEFAULT 0,
    PRIMARY KEY (server_id, bucket)
);

CREATE INDEX server_check_buckets_time_idx ON server_check_buckets (bucket);

-- Each time a check found a server in another state than the last one.
CREATE TABLE server_status_changes (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    server_id   uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    at          timestamptz NOT NULL DEFAULT now(),
    status      text NOT NULL,
    prev_status text NOT NULL,
    message     text NOT NULL DEFAULT ''
);

CREATE INDEX server_status_changes_server_idx ON server_status_changes (server_id, at DESC);
CREATE INDEX server_status_changes_time_idx ON server_status_changes (at);

-- CPU, memory, disk and network of each online Linux server, read every
-- SERVER_SAMPLE_INTERVAL.
CREATE TABLE server_samples (
    server_id        uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    at               timestamptz NOT NULL DEFAULT now(),
    cpu_percent      double precision NOT NULL,
    iowait_percent   double precision NOT NULL,
    cores            integer NOT NULL,
    load1            double precision NOT NULL,
    mem_used_bytes   bigint NOT NULL,
    mem_total_bytes  bigint NOT NULL,
    swap_used_bytes  bigint NOT NULL,
    swap_total_bytes bigint NOT NULL,
    -- The root filesystem (the largest one when / isn't listed).
    disk_used_bytes  bigint NOT NULL,
    disk_total_bytes bigint NOT NULL,
    -- The fullest real filesystem.
    disk_max_percent double precision NOT NULL,
    disk_max_mount   text NOT NULL DEFAULT '',
    rx_bytes_per_sec double precision NOT NULL,
    tx_bytes_per_sec double precision NOT NULL,
    PRIMARY KEY (server_id, at)
);

CREATE INDEX server_samples_time_idx ON server_samples (at);

-- +goose Down
DROP TABLE server_samples;
DROP TABLE server_status_changes;
DROP TABLE server_check_buckets;
