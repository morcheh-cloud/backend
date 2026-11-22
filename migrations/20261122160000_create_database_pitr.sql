-- +goose Up

-- Continuous backup (point-in-time recovery) of a PostgreSQL cluster with
-- pgBackRest: one per database row (= one PostgreSQL instance), backups and
-- WAL in a Storage, scheduled full/diff/incr backups run by Morche.
CREATE TABLE database_pitr (
    database_id     uuid PRIMARY KEY REFERENCES databases (id) ON DELETE CASCADE,
    workspace_id    uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    storage_id      uuid REFERENCES storages (id) ON DELETE SET NULL,
    -- Folder in the storage (the bucket's first segment when it isn't fixed).
    folder          text NOT NULL CHECK (length(folder) BETWEEN 1 AND 1024),
    -- new → setting_up → needs_restart → ready; broken = needs a look;
    -- removing while archiving is being turned off.
    state           text NOT NULL DEFAULT 'new'
                    CHECK (state IN ('new', 'setting_up', 'needs_restart', 'ready', 'broken', 'removing')),
    problem         text NOT NULL DEFAULT '',
    full_cron       text NOT NULL DEFAULT '0 1 * * 0',
    diff_cron       text NOT NULL DEFAULT '0 1 * * 1-6',
    incr_cron       text NOT NULL DEFAULT '',
    timezone        text NOT NULL DEFAULT 'UTC',
    next_full_at    timestamptz,
    next_diff_at    timestamptz,
    next_incr_at    timestamptz,
    retention_full  integer NOT NULL DEFAULT 2 CHECK (retention_full BETWEEN 1 AND 100),
    compress_level  integer NOT NULL DEFAULT 3 CHECK (compress_level BETWEEN 1 AND 19),
    process_max     integer NOT NULL DEFAULT 2 CHECK (process_max BETWEEN 1 AND 32),
    archive_timeout integer NOT NULL DEFAULT 60 CHECK (archive_timeout BETWEEN 0 AND 3600),
    -- Repository encryption passphrase, sealed; null = not encrypted.
    cipher_pass_enc bytea,
    enabled         boolean NOT NULL DEFAULT true,
    -- A restart asked for at a set time (archive_mode needs one).
    restart_at      timestamptz,
    -- What detection found on the server (pitr.Cluster), and the last read
    -- of the repository (pitr.Info).
    cluster         jsonb NOT NULL DEFAULT '{}',
    info            jsonb,
    checked_at      timestamptz,
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX database_pitr_storage_idx ON database_pitr (storage_id);

-- Everything done for it: setup, restarts, backups, checks, restores,
-- copies torn down, removal.
CREATE TABLE database_pitr_runs (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    database_id     uuid NOT NULL REFERENCES databases (id) ON DELETE CASCADE,
    kind            text NOT NULL CHECK (kind IN ('setup', 'restart', 'backup', 'check', 'restore', 'teardown', 'remove')),
    -- backup: full|diff|incr; restore: new|replace.
    variant         text NOT NULL DEFAULT '',
    trigger         text NOT NULL DEFAULT 'manual' CHECK (trigger IN ('manual', 'schedule')),
    -- restore: the point in time (null = as far as the WAL goes).
    target_time     timestamptz,
    state           text NOT NULL DEFAULT 'queued'
                    CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'canceled', 'interrupted', 'skipped')),
    error           text NOT NULL DEFAULT '',
    job_id          uuid,
    -- restore to a new instance: where it lives while it's kept.
    restore_dir     text NOT NULL DEFAULT '',
    restore_port    integer,
    -- …and the temporary database row Morche made for it.
    restore_database_id uuid REFERENCES databases (id) ON DELETE SET NULL,
    removed_at      timestamptz,
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by_name text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    finished_at     timestamptz
);

CREATE INDEX database_pitr_runs_database_idx ON database_pitr_runs (database_id, created_at DESC);

-- +goose Down
DROP TABLE database_pitr_runs;
DROP TABLE database_pitr;
