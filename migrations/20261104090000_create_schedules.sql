-- +goose Up

-- Cron jobs Morcheh runs itself (not crontab on a server), per workspace. The
-- first action is a file sync from one server or storage to one or more
-- servers and storages.
CREATE TABLE schedules (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    description  text NOT NULL DEFAULT '',
    action       text NOT NULL DEFAULT 'sync' CHECK (action IN ('sync')),
    -- Five-field cron expression, read in timezone (IANA name).
    cron         text NOT NULL,
    timezone     text NOT NULL DEFAULT 'UTC',
    enabled      boolean NOT NULL DEFAULT true,
    -- {server_id | storage_id, path}
    source       jsonb NOT NULL,
    -- [{server_id | storage_id, path}]
    destinations jsonb NOT NULL DEFAULT '[]',
    -- mode (update, mirror, snapshot), excludes, keep.
    options      jsonb NOT NULL DEFAULT '{}',
    -- Every server and storage it touches, for filters and access checks.
    server_ids   uuid[] NOT NULL DEFAULT '{}',
    storage_ids  uuid[] NOT NULL DEFAULT '{}',
    -- NULL while paused.
    next_run_at  timestamptz,
    created_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    -- Runs act with this person's access, checked each time.
    updated_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX schedules_name_key ON schedules (workspace_id, lower(name));
CREATE INDEX schedules_due_idx ON schedules (next_run_at) WHERE enabled;
CREATE INDEX schedules_servers_idx ON schedules USING gin (server_ids);
CREATE INDEX schedules_storages_idx ON schedules USING gin (storage_ids);

-- One run of a schedule. It keeps a copy of what it ran, so the record still
-- reads right after the schedule changes.
CREATE TABLE schedule_runs (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    schedule_id   uuid NOT NULL REFERENCES schedules (id) ON DELETE CASCADE,
    workspace_id  uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    -- schedule = on time, manual = Run now.
    trigger       text NOT NULL DEFAULT 'schedule' CHECK (trigger IN ('schedule', 'manual')),
    dry_run       boolean NOT NULL DEFAULT false,
    -- {source, destinations, options} as they were.
    plan          jsonb NOT NULL DEFAULT '{}',
    state         text NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'running', 'succeeded', 'partial', 'failed', 'canceled', 'interrupted', 'skipped')),
    error         text NOT NULL DEFAULT '',
    -- Per destination: what it copied, skipped, deleted, and its error.
    results       jsonb NOT NULL DEFAULT '[]',
    files         integer NOT NULL DEFAULT 0,
    bytes         bigint NOT NULL DEFAULT 0,
    job_id        uuid REFERENCES jobs (id) ON DELETE SET NULL,
    created_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by_name text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    started_at    timestamptz,
    finished_at   timestamptz
);

CREATE INDEX schedule_runs_schedule_idx ON schedule_runs (schedule_id, created_at DESC);
CREATE INDEX schedule_runs_active_idx ON schedule_runs (state) WHERE state IN ('queued', 'running');

-- +goose Down
DROP TABLE schedule_runs;
DROP TABLE schedules;
