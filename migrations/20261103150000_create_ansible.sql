-- +goose Up

-- Ansible playbooks kept in Morcheh, per workspace. Runs execute
-- ansible-playbook on the Morcheh host against the workspace's servers.
CREATE TABLE ansible_playbooks (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    description  text NOT NULL DEFAULT '',
    -- The playbook itself (YAML).
    content      text NOT NULL,
    -- Extra variables offered by default when running it (YAML).
    variables    text NOT NULL DEFAULT '',
    created_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ansible_playbooks_name_key ON ansible_playbooks (workspace_id, lower(name));

-- One run of a playbook. It copies what it ran (playbook text, hosts, options)
-- so the record still reads right after the playbook or servers change.
CREATE TABLE ansible_runs (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id  uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    -- NULL for a playbook run without saving it, or one deleted since.
    playbook_id   uuid REFERENCES ansible_playbooks (id) ON DELETE SET NULL,
    playbook_name text NOT NULL,
    content       text NOT NULL,
    -- What was chosen ({server_ids, tags, folder_ids, all}) and the servers it
    -- resolved to ([{server_id, name, host, inventory_name}]).
    selection     jsonb NOT NULL DEFAULT '{}',
    hosts         jsonb NOT NULL DEFAULT '[]',
    server_ids    uuid[] NOT NULL DEFAULT '{}',
    -- check, diff, verbosity, tags, skip_tags, limit, forks, extra_vars.
    options       jsonb NOT NULL DEFAULT '{}',
    state         text NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'canceled', 'interrupted')),
    error         text NOT NULL DEFAULT '',
    exit_code     integer,
    -- What ansible-playbook printed (ANSI colors kept), capped.
    output        text NOT NULL DEFAULT '',
    output_truncated boolean NOT NULL DEFAULT false,
    -- Plays, tasks and each host's result from Morcheh's callback plugin.
    plays         jsonb NOT NULL DEFAULT '[]',
    -- Per host: ok, changed, failed, unreachable, skipped, rescued, ignored.
    recap         jsonb NOT NULL DEFAULT '{}',
    job_id        uuid REFERENCES jobs (id) ON DELETE SET NULL,
    created_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by_name text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    started_at    timestamptz,
    finished_at   timestamptz
);

CREATE INDEX ansible_runs_workspace_idx ON ansible_runs (workspace_id, created_at DESC);
CREATE INDEX ansible_runs_playbook_idx ON ansible_runs (playbook_id, created_at DESC);
CREATE INDEX ansible_runs_servers_idx ON ansible_runs USING gin (server_ids);
CREATE INDEX ansible_runs_active_idx ON ansible_runs (state) WHERE state IN ('queued', 'running');

-- +goose Down
DROP TABLE ansible_runs;
DROP TABLE ansible_playbooks;
