-- +goose Up

-- The first sketch of these two tables was never written to.
DROP TABLE database_backups;
DROP TABLE database_backup_plans;

-- What to back up from a database, where to, and when. An empty cron means it
-- only runs when someone presses Run.
CREATE TABLE database_backup_plans (
    id               uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id     uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    database_id      uuid NOT NULL REFERENCES databases (id) ON DELETE CASCADE,
    name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    -- NULL once the storage is deleted: the plan then can't run.
    storage_id       uuid REFERENCES storages (id) ON DELETE SET NULL,
    folder           text NOT NULL DEFAULT '/',
    -- One database's name; empty = everything on the instance.
    target           text NOT NULL DEFAULT '',
    -- Where a direct database's dump tool runs. A database reached through a
    -- server always uses that server.
    runner_server_id uuid REFERENCES servers (id) ON DELETE SET NULL,
    -- Optional login for dumping, when the monitoring one can't read
    -- everything. Empty = the database's own.
    username         text NOT NULL DEFAULT '',
    password_enc     bytea,
    cron             text NOT NULL DEFAULT '',
    timezone         text NOT NULL DEFAULT 'UTC',
    enabled          boolean NOT NULL DEFAULT true,
    -- Good backups kept; older ones are deleted. 0 keeps all.
    keep             integer NOT NULL DEFAULT 7 CHECK (keep BETWEEN 0 AND 1000),
    next_run_at      timestamptz,
    created_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    -- Runs act with this person's access, checked each time.
    updated_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX database_backup_plans_name_key ON database_backup_plans (database_id, lower(name));
CREATE INDEX database_backup_plans_due_idx ON database_backup_plans (next_run_at) WHERE enabled;

-- One run of a plan. A row in state succeeded is what makes a file a backup:
-- a dump cut short leaves no such row, whatever is left on the storage. Rows
-- outlive the plan, because the file does.
CREATE TABLE database_backups (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id    uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    database_id     uuid NOT NULL REFERENCES databases (id) ON DELETE CASCADE,
    plan_id         uuid REFERENCES database_backup_plans (id) ON DELETE SET NULL,
    plan_name       text NOT NULL DEFAULT '',
    storage_id      uuid REFERENCES storages (id) ON DELETE SET NULL,
    storage_name    text NOT NULL DEFAULT '',
    path            text NOT NULL DEFAULT '',
    engine          text NOT NULL,
    target          text NOT NULL DEFAULT '',
    format          text NOT NULL DEFAULT '',
    trigger         text NOT NULL DEFAULT 'schedule' CHECK (trigger IN ('schedule', 'manual')),
    state           text NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'canceled', 'interrupted', 'skipped')),
    error           text NOT NULL DEFAULT '',
    bytes           bigint NOT NULL DEFAULT 0,
    -- Of the file as stored.
    sha256          text NOT NULL DEFAULT '',
    verified_at     timestamptz,
    verify_error    text NOT NULL DEFAULT '',
    job_id          uuid REFERENCES jobs (id) ON DELETE SET NULL,
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by_name text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    finished_at     timestamptz
);

CREATE INDEX database_backups_database_idx ON database_backups (database_id, id DESC);
CREATE INDEX database_backups_plan_idx ON database_backups (plan_id, id DESC);

-- +goose Down
DROP TABLE database_backups;
DROP TABLE database_backup_plans;

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
