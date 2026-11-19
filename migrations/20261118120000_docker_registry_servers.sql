-- +goose Up
-- Which servers a registry login is for, and whether Morche also signs the
-- servers' own Docker in (so docker / compose / Watchtower on the server can
-- pull from it too, not only Morche's pulls).
ALTER TABLE docker_registries
    -- all = every server of the workspace; chosen = server_ids only.
    ADD COLUMN servers            text NOT NULL DEFAULT 'all' CHECK (servers IN ('all', 'chosen')),
    ADD COLUMN server_ids         uuid[] NOT NULL DEFAULT '{}',
    ADD COLUMN sign_in_on_servers boolean NOT NULL DEFAULT false;

-- The login written into a server's Docker (docker login), last time Morche
-- tried. A row means Morche signed in there (or tried to), so it knows where
-- to sign out again.
CREATE TABLE docker_registry_logins (
    registry_id uuid NOT NULL REFERENCES docker_registries (id) ON DELETE CASCADE,
    server_id   uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    ok          boolean NOT NULL,
    message     text NOT NULL DEFAULT '',
    -- Whose config holds it: root, or the login user when there's no root.
    as_user     text NOT NULL DEFAULT '',
    at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (registry_id, server_id)
);

-- +goose Down
DROP TABLE docker_registry_logins;
ALTER TABLE docker_registries
    DROP COLUMN servers,
    DROP COLUMN server_ids,
    DROP COLUMN sign_in_on_servers;
