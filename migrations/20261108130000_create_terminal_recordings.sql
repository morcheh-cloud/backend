-- +goose Up

-- Whether a workspace records its terminal sessions, and for how long the
-- recordings are kept. No row = off, 90 days.
CREATE TABLE terminal_recording_settings (
    workspace_id    uuid PRIMARY KEY REFERENCES workspaces (id) ON DELETE CASCADE,
    enabled         boolean NOT NULL DEFAULT false,
    keep_days       int NOT NULL DEFAULT 90 CHECK (keep_days BETWEEN 1 AND 3650),
    updated_by_name text NOT NULL DEFAULT '',
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- One terminal session's output as asciicast v2, gzipped. Saved while the
-- shell runs (ended_at is NULL) and once more when it ends. What was typed is
-- never stored, only what the server printed.
CREATE TABLE terminal_recordings (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    server_id   uuid REFERENCES servers (id) ON DELETE SET NULL,
    server_name text NOT NULL,
    user_id     uuid REFERENCES users (id) ON DELETE SET NULL,
    user_name   text NOT NULL,
    title       text NOT NULL DEFAULT '',
    cols        int NOT NULL,
    rows        int NOT NULL,
    started_at  timestamptz NOT NULL DEFAULT now(),
    ended_at    timestamptz,
    exit_code   int,
    -- Morcheh stopped before the shell ended; the data is a gzip without its end.
    interrupted boolean NOT NULL DEFAULT false,
    duration_ms bigint NOT NULL DEFAULT 0,
    -- Output bytes before compression.
    size        bigint NOT NULL DEFAULT 0,
    truncated   boolean NOT NULL DEFAULT false,
    data        bytea NOT NULL DEFAULT ''
);

CREATE INDEX terminal_recordings_workspace_idx ON terminal_recordings (workspace_id, started_at DESC);
CREATE INDEX terminal_recordings_server_idx ON terminal_recordings (server_id, started_at DESC);
CREATE INDEX terminal_recordings_user_idx ON terminal_recordings (user_id, started_at DESC);

-- +goose Down

DROP TABLE terminal_recordings;
DROP TABLE terminal_recording_settings;
