-- +goose Up

-- Notes the team keeps on a server: what it's for, how to deploy, who to call.
-- Markdown. Pinned ones show on the server's overview.
CREATE TABLE server_notes (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    server_id       uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    title           text NOT NULL DEFAULT '' CHECK (length(title) <= 200),
    body            text NOT NULL DEFAULT '' CHECK (length(body) <= 100000),
    pinned          boolean NOT NULL DEFAULT false,
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by_name text NOT NULL DEFAULT '',
    updated_by_name text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX server_notes_server_idx ON server_notes (server_id, pinned DESC, updated_at DESC);

-- +goose Down
DROP TABLE server_notes;
