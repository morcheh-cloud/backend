-- +goose Up
-- Every version of a compose project's files Morche wrote or found, so a
-- change can be compared and rolled back. The .env is sealed (it holds
-- passwords); NULL = the project had no .env.
CREATE TABLE docker_project_versions (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    server_id       uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    project         text NOT NULL,
    revision        text NOT NULL,
    compose         text NOT NULL,
    env_enc         bytea,
    reason          text NOT NULL CHECK (reason IN ('found', 'save', 'create', 'restore', 'git')),
    note            text NOT NULL DEFAULT '',
    created_by_name text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX docker_project_versions_project ON docker_project_versions (server_id, project, created_at DESC);

-- +goose Down
DROP TABLE docker_project_versions;
