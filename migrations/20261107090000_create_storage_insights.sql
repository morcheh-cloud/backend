-- +goose Up

-- Every connection check of a storage (background monitor and Check), for
-- uptime and latency charts. Pruned after STORAGE_HISTORY_DAYS.
CREATE TABLE storage_checks (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    storage_id  uuid NOT NULL REFERENCES storages (id) ON DELETE CASCADE,
    checked_at  timestamptz NOT NULL DEFAULT now(),
    status      text NOT NULL,
    latency_ms  integer,
    -- Why it failed; empty when online.
    message     text NOT NULL DEFAULT ''
);

CREATE INDEX storage_checks_storage_idx ON storage_checks (storage_id, checked_at);
CREATE INDEX storage_checks_time_idx ON storage_checks (checked_at);

-- How much a storage holds, measured by walking it (and, on SFTP, the
-- disk's size and free space). One row per measurement.
CREATE TABLE storage_usage (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    storage_id   uuid NOT NULL REFERENCES storages (id) ON DELETE CASCADE,
    measured_at  timestamptz NOT NULL DEFAULT now(),
    used_bytes   bigint NOT NULL DEFAULT 0,
    files        bigint NOT NULL DEFAULT 0,
    folders      bigint NOT NULL DEFAULT 0,
    -- The disk behind it, when the protocol tells (SFTP statvfs).
    total_bytes  bigint,
    free_bytes   bigint,
    -- Stopped before the end (too big to walk in time).
    partial      boolean NOT NULL DEFAULT false,
    -- Biggest top-level folders (or buckets): [{name, bytes, files}].
    top          jsonb NOT NULL DEFAULT '[]',
    duration_ms  integer NOT NULL DEFAULT 0
);

CREATE INDEX storage_usage_storage_idx ON storage_usage (storage_id, measured_at DESC);

-- +goose Down
DROP TABLE storage_usage;
DROP TABLE storage_checks;
