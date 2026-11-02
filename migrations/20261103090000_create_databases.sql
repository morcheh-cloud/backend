-- +goose Up

-- Databases Morcheh watches. mode=server reaches host:port from a panel server
-- over SSH; mode=direct dials it from the backend. The password is AES-GCM
-- sealed by the API (internal/secrets) and never leaves it.
CREATE TABLE databases (
    id               uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id     uuid NOT NULL REFERENCES workspaces (id) ON DELETE RESTRICT,
    name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    engine           text NOT NULL CHECK (engine IN ('postgres', 'mysql', 'mssql', 'redis', 'mongodb')),
    mode             text NOT NULL CHECK (mode IN ('server', 'direct')),
    -- Stays NULL with mode=server when the server is deleted: the database
    -- keeps its history and reports that its way in is gone.
    server_id        uuid REFERENCES servers (id) ON DELETE SET NULL,
    host             text NOT NULL,
    port             integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    username         text NOT NULL DEFAULT '',
    password_enc     bytea,
    dbname           text NOT NULL DEFAULT '',
    tls              text NOT NULL DEFAULT 'require' CHECK (tls IN ('disable', 'require', 'verify')),
    ca_cert          text NOT NULL DEFAULT '',
    -- Direct only, set by a system admin: may dial private addresses.
    allow_internal   boolean NOT NULL DEFAULT false,
    -- Docker container the database runs in, for disk checks and backup tools.
    container        text NOT NULL DEFAULT '',
    description      text NOT NULL DEFAULT '',
    favorite         boolean NOT NULL DEFAULT false,
    paused           boolean NOT NULL DEFAULT false,
    interval_seconds integer NOT NULL DEFAULT 60 CHECK (interval_seconds BETWEEN 15 AND 3600),
    -- Overrides of the default limits, by check id.
    thresholds       jsonb NOT NULL DEFAULT '{}',
    muted_checks     text[] NOT NULL DEFAULT '{}',
    alerts_enabled   boolean NOT NULL DEFAULT true,
    status           text NOT NULL DEFAULT 'unknown'
        CHECK (status IN ('unknown', 'online', 'unreachable', 'auth_failed', 'tls_error', 'blocked', 'error')),
    status_message   text NOT NULL DEFAULT '',
    version          text NOT NULL DEFAULT '',
    flavor           text NOT NULL DEFAULT '',
    role             text NOT NULL DEFAULT '',
    latency_ms       integer,
    size_bytes       bigint,
    connections      integer,
    max_connections  integer,
    last_checked_at  timestamptz,
    last_online_at   timestamptz,
    health           text NOT NULL DEFAULT 'unknown' CHECK (health IN ('unknown', 'ok', 'warning', 'critical')),
    -- The last evaluation, with how long each state has lasted.
    checks           jsonb NOT NULL DEFAULT '[]',
    -- What "normal" looks like: known addresses, users, settings, version.
    baseline         jsonb NOT NULL DEFAULT '{}',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (mode <> 'direct' OR server_id IS NULL)
);

CREATE UNIQUE INDEX databases_name_key ON databases (workspace_id, lower(name));
CREATE INDEX databases_server_idx ON databases (server_id);

-- One row per monitoring pass, kept for 30 days.
CREATE TABLE database_samples (
    database_id     uuid NOT NULL REFERENCES databases (id) ON DELETE CASCADE,
    at              timestamptz NOT NULL,
    online          boolean NOT NULL,
    latency_ms      integer,
    connections     integer,
    active          integer,
    max_connections integer,
    qps             double precision,
    tps             double precision,
    cache_hit       double precision,
    size_bytes      bigint,
    disk_free_bytes bigint,
    disk_total_bytes bigint,
    replication_lag double precision,
    blocked         integer,
    deadlocks       bigint,
    memory_bytes    bigint,
    PRIMARY KEY (database_id, at)
);

-- What happened, in order: checks changing state, restarts, new addresses…
CREATE TABLE database_events (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    database_id uuid NOT NULL REFERENCES databases (id) ON DELETE CASCADE,
    at          timestamptz NOT NULL DEFAULT now(),
    kind        text NOT NULL,
    severity    text NOT NULL CHECK (severity IN ('info', 'ok', 'warning', 'critical')),
    check_id    text NOT NULL DEFAULT '',
    title       text NOT NULL,
    detail      text NOT NULL DEFAULT ''
);

CREATE INDEX database_events_database_idx ON database_events (database_id, at DESC);

-- Where a workspace's alerts go. config is sealed JSON: it holds bot tokens,
-- webhook secrets and SMTP passwords.
CREATE TABLE alert_channels (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    kind         text NOT NULL CHECK (kind IN ('telegram', 'bale', 'webhook', 'email')),
    config_enc   bytea NOT NULL,
    -- What the channel names in the list, without opening config.
    target       text NOT NULL DEFAULT '',
    min_severity text NOT NULL DEFAULT 'warning' CHECK (min_severity IN ('warning', 'critical')),
    enabled      boolean NOT NULL DEFAULT true,
    last_sent_at timestamptz,
    last_error   text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX alert_channels_name_key ON alert_channels (workspace_id, lower(name));

-- A database's backup schedule.
CREATE TABLE database_backup_plans (
    database_id      uuid PRIMARY KEY REFERENCES databases (id) ON DELETE CASCADE,
    enabled          boolean NOT NULL DEFAULT true,
    storage_id       uuid NOT NULL REFERENCES storages (id) ON DELETE CASCADE,
    folder           text NOT NULL DEFAULT '',
    runner_server_id uuid REFERENCES servers (id) ON DELETE SET NULL,
    dbnames          text[] NOT NULL DEFAULT '{}',
    frequency        text NOT NULL CHECK (frequency IN ('hourly', 'every_6h', 'daily', 'weekly')),
    hour             integer NOT NULL DEFAULT 2 CHECK (hour BETWEEN 0 AND 23),
    weekday          integer NOT NULL DEFAULT 0 CHECK (weekday BETWEEN 0 AND 6),
    keep             integer NOT NULL DEFAULT 7 CHECK (keep BETWEEN 1 AND 365),
    next_run_at      timestamptz NOT NULL,
    created_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_at       timestamptz NOT NULL DEFAULT now()
);

-- Every backup taken, and the last test of it.
CREATE TABLE database_backups (
    id             uuid PRIMARY KEY DEFAULT uuidv7(),
    database_id    uuid NOT NULL REFERENCES databases (id) ON DELETE CASCADE,
    job_id         uuid,
    trigger        text NOT NULL CHECK (trigger IN ('manual', 'schedule')),
    storage_id     uuid REFERENCES storages (id) ON DELETE SET NULL,
    path           text NOT NULL DEFAULT '',
    dbname         text NOT NULL DEFAULT '',
    status         text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'ok', 'failed')),
    size_bytes     bigint NOT NULL DEFAULT 0,
    error          text NOT NULL DEFAULT '',
    started_at     timestamptz NOT NULL DEFAULT now(),
    finished_at    timestamptz,
    verify_status  text NOT NULL DEFAULT '' CHECK (verify_status IN ('', 'ok', 'failed')),
    verify_detail  text NOT NULL DEFAULT '',
    verified_at    timestamptz
);

CREATE INDEX database_backups_database_idx ON database_backups (database_id, started_at DESC);

-- +goose Down
DROP TABLE database_backups;
DROP TABLE database_backup_plans;
DROP TABLE alert_channels;
DROP TABLE database_events;
DROP TABLE database_samples;
DROP TABLE databases;
