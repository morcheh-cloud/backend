-- +goose Up

-- Storage migrations (copy everything once, optionally moving it) and syncs
-- (keep a destination up to date), between two storages of a workspace.
CREATE TABLE storage_syncs (
    id                uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id      uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    kind              text NOT NULL CHECK (kind IN ('migrate', 'sync')),
    name              text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    source_storage_id uuid NOT NULL REFERENCES storages (id) ON DELETE CASCADE,
    source_path       text NOT NULL DEFAULT '/',
    dest_storage_id   uuid NOT NULL REFERENCES storages (id) ON DELETE CASCADE,
    dest_path         text NOT NULL DEFAULT '/',
    -- morche = Morche's host copies the files; replication = the storages
    -- replicate by themselves (MinIO bucket replication).
    engine            text NOT NULL DEFAULT 'morche' CHECK (engine IN ('morche', 'replication')),
    -- update = copy new and changed files; mirror = also delete what the
    -- source no longer has.
    mode              text NOT NULL DEFAULT 'update' CHECK (mode IN ('update', 'mirror')),
    -- manual, schedule (cron in timezone) or interval (every N minutes).
    trigger           text NOT NULL DEFAULT 'manual' CHECK (trigger IN ('manual', 'schedule', 'interval')),
    cron              text NOT NULL DEFAULT '',
    timezone          text NOT NULL DEFAULT 'UTC',
    interval_minutes  integer NOT NULL DEFAULT 0,
    -- excludes, existing, verify, delete_source, settle_minutes,
    -- delete_delay_hours, replication {...}.
    options           jsonb NOT NULL DEFAULT '{}',
    paused            boolean NOT NULL DEFAULT false,
    next_run_at       timestamptz,
    -- Deletes waiting out delete_delay_hours: {path: first seen missing}.
    held              jsonb NOT NULL DEFAULT '{}',
    -- What Morche set up on the storages for replication (arn, rule id…).
    native            jsonb NOT NULL DEFAULT '{}',
    -- Why it can't run as saved (replication couldn't be set up…).
    problem           text NOT NULL DEFAULT '',
    created_by        uuid REFERENCES users (id) ON DELETE SET NULL,
    -- Runs act with this person's access, checked each time.
    updated_by        uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX storage_syncs_name_key ON storage_syncs (workspace_id, kind, lower(name));
CREATE INDEX storage_syncs_due_idx ON storage_syncs (next_run_at) WHERE NOT paused;
CREATE INDEX storage_syncs_source_idx ON storage_syncs (source_storage_id);
CREATE INDEX storage_syncs_dest_idx ON storage_syncs (dest_storage_id);

CREATE TABLE storage_sync_runs (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    sync_id         uuid NOT NULL REFERENCES storage_syncs (id) ON DELETE CASCADE,
    workspace_id    uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    trigger         text NOT NULL DEFAULT 'manual' CHECK (trigger IN ('manual', 'schedule', 'interval')),
    dry_run         boolean NOT NULL DEFAULT false,
    state           text NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'running', 'succeeded', 'partial', 'failed', 'canceled', 'interrupted', 'skipped')),
    -- What it's doing now: listing, copying, verifying, removing.
    phase           text NOT NULL DEFAULT '',
    error           text NOT NULL DEFAULT '',
    -- Copied/skipped/deleted/failed counts, verify results, problems.
    result          jsonb NOT NULL DEFAULT '{}',
    files           integer NOT NULL DEFAULT 0,
    bytes           bigint NOT NULL DEFAULT 0,
    job_id          uuid REFERENCES jobs (id) ON DELETE SET NULL,
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by_name text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    finished_at     timestamptz
);

CREATE INDEX storage_sync_runs_sync_idx ON storage_sync_runs (sync_id, created_at DESC);
CREATE INDEX storage_sync_runs_active_idx ON storage_sync_runs (state) WHERE state IN ('queued', 'running');

-- +goose Down
DROP TABLE storage_sync_runs;
DROP TABLE storage_syncs;
