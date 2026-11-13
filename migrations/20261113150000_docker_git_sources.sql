-- +goose Up
-- A compose project that comes from a git repository: Morche clones it on
-- the server and deploys it again when the branch moves (a webhook, polling
-- or by hand).
CREATE TABLE docker_git_sources (
    server_id        uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    project          text NOT NULL,
    dir              text NOT NULL,
    repo_url         text NOT NULL,
    branch           text NOT NULL DEFAULT 'main',
    compose_path     text NOT NULL DEFAULT '',
    username         text NOT NULL DEFAULT '',
    token_enc        bytea,
    auto_deploy      boolean NOT NULL DEFAULT true,
    poll_minutes     int NOT NULL DEFAULT 0,
    webhook_enc      bytea NOT NULL,
    webhook_hash     text NOT NULL UNIQUE,
    last_commit      text NOT NULL DEFAULT '',
    last_message     text NOT NULL DEFAULT '',
    last_author      text NOT NULL DEFAULT '',
    last_deployed_at timestamptz,
    last_checked_at  timestamptz,
    last_error       text NOT NULL DEFAULT '',
    created_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by_name  text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (server_id, project)
);

-- +goose Down
DROP TABLE docker_git_sources;
