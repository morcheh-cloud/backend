-- +goose Up

-- Saved scripts, per workspace: run on one server or many from the panel.
CREATE TABLE scripts (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    description  text NOT NULL DEFAULT '',
    interpreter  text NOT NULL DEFAULT 'bash' CHECK (interpreter IN ('sh', 'bash', 'python3')),
    content      text NOT NULL,
    -- user = the server's login user; root = through sudo when it isn't root.
    run_as       text NOT NULL DEFAULT 'user' CHECK (run_as IN ('user', 'root')),
    timeout_seconds integer NOT NULL DEFAULT 600 CHECK (timeout_seconds BETWEEN 1 AND 86400),
    -- Values asked for at run time, passed as environment variables:
    -- [{name, label, default, required}].
    params       jsonb NOT NULL DEFAULT '[]',
    created_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX scripts_name_key ON scripts (workspace_id, lower(name));

-- One run of a script on one or more servers. It copies what it ran, so the
-- record still reads right after the script changes or goes.
CREATE TABLE script_runs (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    -- NULL for a command run without saving it, or a script deleted since.
    script_id       uuid REFERENCES scripts (id) ON DELETE SET NULL,
    name            text NOT NULL,
    interpreter     text NOT NULL,
    content         text NOT NULL,
    run_as          text NOT NULL,
    timeout_seconds integer NOT NULL,
    -- The values it ran with: {NAME: value}.
    env             jsonb NOT NULL DEFAULT '{}',
    state           text NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'canceled', 'interrupted')),
    job_id          uuid REFERENCES jobs (id) ON DELETE SET NULL,
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by_name text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    finished_at     timestamptz
);

CREATE INDEX script_runs_script_idx ON script_runs (script_id, created_at DESC);
CREATE INDEX script_runs_active_idx ON script_runs (state) WHERE state IN ('queued', 'running');

-- What a run did on each server.
CREATE TABLE script_run_targets (
    run_id      uuid NOT NULL REFERENCES script_runs (id) ON DELETE CASCADE,
    -- NULL once the server is deleted; its name stays.
    server_id   uuid REFERENCES servers (id) ON DELETE SET NULL,
    server_name text NOT NULL,
    position    integer NOT NULL,
    state       text NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'canceled', 'interrupted')),
    exit_code   integer,
    timed_out   boolean NOT NULL DEFAULT false,
    -- Why it couldn't run at all (unreachable, no sudo…).
    error       text NOT NULL DEFAULT '',
    -- stdout and stderr together, capped.
    output      text NOT NULL DEFAULT '',
    truncated   boolean NOT NULL DEFAULT false,
    started_at  timestamptz,
    finished_at timestamptz,
    PRIMARY KEY (run_id, position)
);

CREATE INDEX script_run_targets_server_idx ON script_run_targets (server_id, run_id DESC);

-- +goose Down
DROP TABLE script_run_targets;
DROP TABLE script_runs;
DROP TABLE scripts;
