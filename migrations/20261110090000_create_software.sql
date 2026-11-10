-- +goose Up

-- Applications: a catalog of software installed on servers from the panel
-- (packages like Docker or Git, and Docker Compose apps like Grafana).
-- Built-in recipes ship with Morcheh; these are a workspace's own.
CREATE TABLE software_recipes (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    -- The recipe's id in the catalog ("custom-<slug>" for built-ins' sake).
    slug         text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    -- The whole recipe, as the catalog reads it.
    spec         jsonb NOT NULL,
    created_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, slug)
);

-- What is on each server: installed by Morcheh, or found by a scan.
CREATE TABLE software_installs (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id    uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    server_id       uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    recipe_id       text NOT NULL,
    name            text NOT NULL,
    kind            text NOT NULL CHECK (kind IN ('package', 'docker', 'script')),
    origin          text NOT NULL DEFAULT 'morcheh' CHECK (origin IN ('morcheh', 'found')),
    status          text NOT NULL DEFAULT 'installing'
        CHECK (status IN ('installing', 'installed', 'updating', 'failed', 'removing', 'missing')),
    version         text NOT NULL DEFAULT '',
    latest          text NOT NULL DEFAULT '',
    update_available boolean NOT NULL DEFAULT false,
    -- Docker apps: running | stopped | partial; empty for packages.
    state           text NOT NULL DEFAULT '',
    -- Values it was installed with, without the secret ones: {NAME: value}.
    params          jsonb NOT NULL DEFAULT '{}',
    -- The secret ones, sealed: {NAME: value} as JSON.
    secrets         bytea,
    -- Docker apps: where its compose.yml lives and the compose project name.
    dir             text NOT NULL DEFAULT '',
    project         text NOT NULL DEFAULT '',
    -- [{service, image, digest, latest_digest}].
    images          jsonb NOT NULL DEFAULT '[]',
    -- Docker apps: an update can be undone / it runs the version before one.
    can_rollback    boolean NOT NULL DEFAULT false,
    pinned          boolean NOT NULL DEFAULT false,
    error           text NOT NULL DEFAULT '',
    checked_at      timestamptz,
    installed_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (server_id, recipe_id)
);

CREATE INDEX software_installs_workspace_idx ON software_installs (workspace_id);

-- What the last scan said about a server as a whole.
CREATE TABLE software_hosts (
    server_id       uuid PRIMARY KEY REFERENCES servers (id) ON DELETE CASCADE,
    pm              text NOT NULL DEFAULT '',
    docker          text NOT NULL DEFAULT '',
    compose         text NOT NULL DEFAULT '',
    upgradable      integer NOT NULL DEFAULT 0,
    security        integer NOT NULL DEFAULT 0,
    reboot_required boolean NOT NULL DEFAULT false,
    -- [{name, version, latest}] of the upgradable packages, capped.
    packages        jsonb NOT NULL DEFAULT '[]',
    error           text NOT NULL DEFAULT '',
    checked_at      timestamptz NOT NULL DEFAULT now()
);

-- One install / update / removal across one or more servers.
CREATE TABLE software_runs (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id    uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    action          text NOT NULL
        CHECK (action IN ('install', 'update', 'uninstall', 'rollback', 'upgrade-system')),
    name            text NOT NULL,
    -- {parallel, stop_on_failure, remove_data, …}.
    options         jsonb NOT NULL DEFAULT '{}',
    params          jsonb NOT NULL DEFAULT '{}',
    secrets         bytea,
    state           text NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'canceled', 'interrupted')),
    error           text NOT NULL DEFAULT '',
    job_id          uuid REFERENCES jobs (id) ON DELETE SET NULL,
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by_name text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    finished_at     timestamptz
);

CREATE INDEX software_runs_workspace_idx ON software_runs (workspace_id, id DESC);
CREATE INDEX software_runs_active_idx ON software_runs (state) WHERE state IN ('queued', 'running');

CREATE TABLE software_run_targets (
    run_id         uuid NOT NULL REFERENCES software_runs (id) ON DELETE CASCADE,
    position       integer NOT NULL,
    server_id      uuid REFERENCES servers (id) ON DELETE SET NULL,
    server_name    text NOT NULL,
    recipe_id      text NOT NULL DEFAULT '',
    recipe_name    text NOT NULL DEFAULT '',
    state          text NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'canceled', 'interrupted', 'skipped')),
    error          text NOT NULL DEFAULT '',
    output         text NOT NULL DEFAULT '',
    truncated      boolean NOT NULL DEFAULT false,
    version_before text NOT NULL DEFAULT '',
    version_after  text NOT NULL DEFAULT '',
    started_at     timestamptz,
    finished_at    timestamptz,
    PRIMARY KEY (run_id, position)
);

CREATE INDEX software_run_targets_server_idx ON software_run_targets (server_id, run_id DESC);

-- Cron jobs can update applications and system packages.
ALTER TABLE schedules DROP CONSTRAINT schedules_action_check;
ALTER TABLE schedules ADD CONSTRAINT schedules_action_check
    CHECK (action IN ('sync', 'script', 'ansible', 'service', 'reboot', 'fetch', 'archive', 'verify-backup', 'software-update'));

-- +goose Down
DELETE FROM schedules WHERE action = 'software-update';
ALTER TABLE schedules DROP CONSTRAINT schedules_action_check;
ALTER TABLE schedules ADD CONSTRAINT schedules_action_check
    CHECK (action IN ('sync', 'script', 'ansible', 'service', 'reboot', 'fetch', 'archive', 'verify-backup'));
DROP TABLE software_run_targets;
DROP TABLE software_runs;
DROP TABLE software_hosts;
DROP TABLE software_installs;
DROP TABLE software_recipes;
