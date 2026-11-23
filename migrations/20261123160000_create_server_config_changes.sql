-- +goose Up

-- Changes Morche made to a server's config files (hosts, DNS, clock,
-- network, package sources), with the files before and after so a change
-- can be compared and taken back.
CREATE TABLE server_config_changes (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    server_id  uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    user_id    uuid REFERENCES users (id) ON DELETE SET NULL,
    user_name  text NOT NULL DEFAULT '',
    area       text NOT NULL CHECK (area IN ('hosts', 'dns', 'clock', 'network', 'repos')),
    summary    text NOT NULL,
    status     text NOT NULL CHECK (status IN ('applied', 'pending', 'undone')),
    -- [{path, before, after, existed, exists}]
    files      jsonb NOT NULL DEFAULT '[]',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX server_config_changes_server_idx ON server_config_changes (server_id, area, created_at DESC);

-- +goose Down
DROP TABLE server_config_changes;
