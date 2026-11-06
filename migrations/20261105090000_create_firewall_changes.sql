-- +goose Up
CREATE TABLE firewall_changes (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    server_id    uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    user_id      uuid REFERENCES users (id) ON DELETE SET NULL,
    user_name    text NOT NULL DEFAULT '',
    summary      text NOT NULL,
    backend      text NOT NULL,
    status       text NOT NULL CHECK (status IN ('applied', 'pending', 'undone')),
    state_before jsonb NOT NULL,
    added        text[] NOT NULL DEFAULT '{}',
    removed      text[] NOT NULL DEFAULT '{}',
    snapshot     bytea,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX firewall_changes_server_idx ON firewall_changes (server_id, created_at DESC);

-- +goose Down
DROP TABLE firewall_changes;
