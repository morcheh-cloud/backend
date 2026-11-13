-- +goose Up
-- Auto-update policies (Watchtower-like): containers on chosen servers are
-- moved onto their image's newest version on a schedule, from a webhook or
-- by hand.
CREATE TABLE docker_auto_updates (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id     uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name             text NOT NULL,
    enabled          boolean NOT NULL DEFAULT true,
    server_ids       uuid[] NOT NULL DEFAULT '{}',
    pick             text NOT NULL DEFAULT 'chosen' CHECK (pick IN ('all', 'labeled', 'chosen')),
    include          text[] NOT NULL DEFAULT '{}',
    exclude          text[] NOT NULL DEFAULT '{}',
    include_stopped  boolean NOT NULL DEFAULT false,
    revive_stopped   boolean NOT NULL DEFAULT false,
    cron             text NOT NULL DEFAULT '0 4 * * *',
    timezone         text NOT NULL DEFAULT 'UTC',
    mode             text NOT NULL DEFAULT 'update' CHECK (mode IN ('update', 'monitor')),
    no_pull          boolean NOT NULL DEFAULT false,
    cleanup          boolean NOT NULL DEFAULT true,
    rollback         boolean NOT NULL DEFAULT true,
    wait_seconds     int NOT NULL DEFAULT 60,
    restart_linked   boolean NOT NULL DEFAULT true,
    stop_timeout     int NOT NULL DEFAULT 30,
    min_age_hours    int NOT NULL DEFAULT 0,
    hooks            boolean NOT NULL DEFAULT false,
    hook_timeout     int NOT NULL DEFAULT 60,
    notify           text NOT NULL DEFAULT 'changes' CHECK (notify IN ('never', 'changes', 'failures', 'always')),
    channels         uuid[] NOT NULL DEFAULT '{}',
    webhook_enc      bytea NOT NULL,
    webhook_hash     text NOT NULL UNIQUE,
    next_run_at      timestamptz,
    last_run_at      timestamptz,
    last_state       text NOT NULL DEFAULT '',
    last_note        text NOT NULL DEFAULT '',
    last_job_id      uuid,
    created_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX docker_auto_updates_workspace ON docker_auto_updates (workspace_id);
CREATE INDEX docker_auto_updates_due ON docker_auto_updates (next_run_at) WHERE enabled;

-- What each run did to each container.
CREATE TABLE docker_auto_update_events (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id    uuid NOT NULL REFERENCES docker_auto_updates (id) ON DELETE CASCADE,
    workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    server_id    uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    job_id       uuid,
    container    text NOT NULL,
    image        text NOT NULL,
    old_image    text NOT NULL DEFAULT '',
    new_image    text NOT NULL DEFAULT '',
    result       text NOT NULL CHECK (result IN ('updated', 'available', 'rolled_back', 'failed', 'skipped')),
    message      text NOT NULL DEFAULT '',
    at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX docker_auto_update_events_policy ON docker_auto_update_events (policy_id, at DESC);
CREATE INDEX docker_auto_update_events_workspace ON docker_auto_update_events (workspace_id, at DESC);
CREATE INDEX docker_auto_update_events_server ON docker_auto_update_events (server_id, at DESC);

-- When the registry's current digest of an image was first seen (for a
-- policy's "wait before taking a new version").
ALTER TABLE docker_image_updates ADD COLUMN seen_at timestamptz NOT NULL DEFAULT now();

-- +goose Down
ALTER TABLE docker_image_updates DROP COLUMN seen_at;
DROP TABLE docker_auto_update_events;
DROP TABLE docker_auto_updates;
