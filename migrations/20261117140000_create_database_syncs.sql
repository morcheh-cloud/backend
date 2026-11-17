-- +goose Up

-- Database syncs keep one database's data in step with another's: chosen
-- tables row by row, only new rows, a whole database row by row (mirror), or
-- a fresh copy loaded over the target (replace). Saved in the target's
-- workspace.
CREATE TABLE database_syncs (
    id               uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id     uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    -- tables = chosen tables row by row; incremental = only new or changed
    -- rows by a tracking column; mirror = every table row by row; replace =
    -- dump the source and load it over the target.
    mode             text NOT NULL CHECK (mode IN ('tables', 'incremental', 'mirror', 'replace')),
    source_db_id     uuid NOT NULL REFERENCES databases (id) ON DELETE CASCADE,
    -- The database inside the source connection (Postgres/MySQL schema db).
    source_name      text NOT NULL,
    target_db_id     uuid NOT NULL REFERENCES databases (id) ON DELETE CASCADE,
    target_name      text NOT NULL,
    trigger          text NOT NULL DEFAULT 'manual' CHECK (trigger IN ('manual', 'schedule', 'interval')),
    cron             text NOT NULL DEFAULT '',
    timezone         text NOT NULL DEFAULT 'UTC',
    interval_minutes integer NOT NULL DEFAULT 0,
    -- tables, strategies, replace settings…
    options          jsonb NOT NULL DEFAULT '{}',
    -- Incremental: the last value copied per table {table: {value, key}}.
    marks            jsonb NOT NULL DEFAULT '{}',
    -- When the last full compare ran (incremental with full_every_hours).
    full_at          timestamptz,
    paused           boolean NOT NULL DEFAULT false,
    next_run_at      timestamptz,
    problem          text NOT NULL DEFAULT '',
    created_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    -- Runs act with this person's access, checked each time.
    updated_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX database_syncs_name_key ON database_syncs (workspace_id, lower(name));
CREATE INDEX database_syncs_due_idx ON database_syncs (next_run_at) WHERE NOT paused;
CREATE INDEX database_syncs_source_idx ON database_syncs (source_db_id);
CREATE INDEX database_syncs_target_idx ON database_syncs (target_db_id);

CREATE TABLE database_sync_runs (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    sync_id         uuid NOT NULL REFERENCES database_syncs (id) ON DELETE CASCADE,
    workspace_id    uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    trigger         text NOT NULL DEFAULT 'manual' CHECK (trigger IN ('manual', 'schedule', 'interval')),
    -- A compare: counts the differences and writes nothing.
    dry_run         boolean NOT NULL DEFAULT false,
    state           text NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'running', 'succeeded', 'partial', 'failed', 'canceled', 'interrupted', 'skipped')),
    phase           text NOT NULL DEFAULT '',
    error           text NOT NULL DEFAULT '',
    -- Per table: inserted/updated/deleted/same/conflicts/failed, samples.
    result          jsonb NOT NULL DEFAULT '{}',
    rows_written    bigint NOT NULL DEFAULT 0,
    job_id          uuid REFERENCES jobs (id) ON DELETE SET NULL,
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by_name text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    finished_at     timestamptz
);

CREATE INDEX database_sync_runs_sync_idx ON database_sync_runs (sync_id, created_at DESC);
CREATE INDEX database_sync_runs_active_idx ON database_sync_runs (state) WHERE state IN ('queued', 'running');

-- +goose Down
DROP TABLE database_sync_runs;
DROP TABLE database_syncs;
