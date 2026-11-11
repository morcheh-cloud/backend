-- +goose Up

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- How a workspace keeps its command log. No row = on, 90 days, reads kept,
-- Morcheh's own upkeep left out.
CREATE TABLE command_log_settings (
    workspace_id    uuid PRIMARY KEY REFERENCES workspaces (id) ON DELETE CASCADE,
    enabled         boolean NOT NULL DEFAULT true,
    keep_days       int NOT NULL DEFAULT 90 CHECK (keep_days BETWEEN 1 AND 3650),
    -- Commands run only to show someone a page (lists, details, logs).
    log_reads       boolean NOT NULL DEFAULT true,
    -- Morcheh's own upkeep: live stats, checks, scans, monitors.
    log_automatic   boolean NOT NULL DEFAULT false,
    updated_by_name text NOT NULL DEFAULT '',
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- Every command Morcheh ran on a server over SSH, every command typed into
-- one of its terminals, and each terminal shell itself (entry = 'shell').
-- Rows are never edited by people: only time (keep_days) removes them.
CREATE TABLE command_log (
    id           uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    server_id    uuid REFERENCES servers (id) ON DELETE SET NULL,
    server_name  text NOT NULL,
    user_id      uuid REFERENCES users (id) ON DELETE SET NULL,
    user_name    text NOT NULL DEFAULT '',
    -- terminal | change | read | job | schedule | automatic
    kind         text NOT NULL,
    -- command | shell
    entry        text NOT NULL DEFAULT 'command',
    -- What it was for, in the panel's words.
    source       text NOT NULL DEFAULT '',
    -- The job or terminal session it belongs to.
    ref          text NOT NULL DEFAULT '',
    recording_id uuid REFERENCES terminal_recordings (id) ON DELETE SET NULL,
    recording_ms bigint,
    command      text NOT NULL,
    truncated    boolean NOT NULL DEFAULT false,
    cwd          text NOT NULL DEFAULT '',
    as_root      boolean NOT NULL DEFAULT false,
    started_at   timestamptz NOT NULL,
    ended_at     timestamptz,
    exit_code    int,
    error        text NOT NULL DEFAULT '',
    -- Extra words about a shell entry (e.g. why its commands aren't captured).
    note         text NOT NULL DEFAULT '',
    -- Morcheh stopped (or lost the server) before it ended.
    interrupted  boolean NOT NULL DEFAULT false,
    -- The same read ran again shortly after: counted here, not as new rows.
    repeats      int NOT NULL DEFAULT 1,
    last_at      timestamptz NOT NULL,
    client_ip    text NOT NULL DEFAULT ''
);

CREATE INDEX command_log_workspace_idx ON command_log (workspace_id, started_at DESC, id DESC);
CREATE INDEX command_log_server_idx ON command_log (server_id, started_at DESC, id DESC);
CREATE INDEX command_log_user_idx ON command_log (user_id, started_at DESC, id DESC);
CREATE INDEX command_log_ref_idx ON command_log (ref) WHERE ref <> '';
CREATE INDEX command_log_command_trgm ON command_log USING gin (command gin_trgm_ops);

-- +goose Down

DROP TABLE command_log;
DROP TABLE command_log_settings;
