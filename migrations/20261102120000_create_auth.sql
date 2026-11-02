-- +goose Up

-- People who can log in. The first one is created through /auth/setup and is
-- an admin; pending users can log in but do nothing until approved.
CREATE TABLE users (
    id                   uuid PRIMARY KEY DEFAULT uuidv7(),
    username             text NOT NULL CHECK (length(username) BETWEEN 3 AND 32),
    email                text NOT NULL CHECK (length(email) BETWEEN 3 AND 254),
    first_name           text NOT NULL CHECK (length(first_name) BETWEEN 1 AND 64),
    full_name            text NOT NULL CHECK (length(full_name) BETWEEN 1 AND 128),
    -- Argon2id, in PHC string format.
    password_hash        text NOT NULL,
    role                 text NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
    status               text NOT NULL DEFAULT 'active' CHECK (status IN ('pending', 'active', 'blocked')),
    -- Set when an admin picks the password: the user replaces it at next login.
    must_change_password boolean NOT NULL DEFAULT false,
    last_login_at        timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX users_username_key ON users (lower(username));
CREATE UNIQUE INDEX users_email_key ON users (lower(email));

-- Only the SHA-256 of a session token is stored; the token lives in the
-- browser's HttpOnly cookie.
CREATE TABLE sessions (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash   bytea NOT NULL UNIQUE,
    remember     boolean NOT NULL DEFAULT false,
    user_agent   text NOT NULL DEFAULT '',
    ip           text NOT NULL DEFAULT '',
    expires_at   timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

CREATE TABLE user_groups (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX user_groups_name_key ON user_groups (lower(name));

CREATE TABLE group_members (
    group_id uuid NOT NULL REFERENCES user_groups (id) ON DELETE CASCADE,
    user_id  uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX group_members_user_idx ON group_members (user_id);

CREATE TABLE workspaces (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX workspaces_name_key ON workspaces (lower(name));

-- Everything that exists today moves into one workspace.
INSERT INTO workspaces (name, description) VALUES ('Main workspace', 'Created automatically for existing servers and storages.');

ALTER TABLE folders ADD COLUMN workspace_id uuid REFERENCES workspaces (id) ON DELETE CASCADE;
ALTER TABLE servers ADD COLUMN workspace_id uuid REFERENCES workspaces (id) ON DELETE RESTRICT;
ALTER TABLE storages ADD COLUMN workspace_id uuid REFERENCES workspaces (id) ON DELETE RESTRICT;

UPDATE folders SET workspace_id = (SELECT id FROM workspaces LIMIT 1);
UPDATE servers SET workspace_id = (SELECT id FROM workspaces LIMIT 1);
UPDATE storages SET workspace_id = (SELECT id FROM workspaces LIMIT 1);

ALTER TABLE folders ALTER COLUMN workspace_id SET NOT NULL;
ALTER TABLE servers ALTER COLUMN workspace_id SET NOT NULL;
ALTER TABLE storages ALTER COLUMN workspace_id SET NOT NULL;

CREATE INDEX folders_workspace_idx ON folders (workspace_id);
CREATE INDEX servers_workspace_idx ON servers (workspace_id);
CREATE INDEX storages_workspace_idx ON storages (workspace_id);

-- Names are unique inside a workspace, not across them.
DROP INDEX folders_parent_name_key;
DROP INDEX servers_name_key;
DROP INDEX storages_name_key;
CREATE UNIQUE INDEX folders_parent_name_key ON folders (workspace_id, parent_id, lower(name)) NULLS NOT DISTINCT;
CREATE UNIQUE INDEX servers_name_key ON servers (workspace_id, lower(name));
CREATE UNIQUE INDEX storages_name_key ON storages (workspace_id, lower(name));

-- One row = this user or group has this level on this workspace, server or
-- storage. A workspace grant covers everything in it. Levels add up by taking
-- the highest; can_create (add servers and storages) only means something on a
-- workspace grant.
CREATE TABLE access_grants (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id      uuid REFERENCES users (id) ON DELETE CASCADE,
    group_id     uuid REFERENCES user_groups (id) ON DELETE CASCADE,
    workspace_id uuid REFERENCES workspaces (id) ON DELETE CASCADE,
    server_id    uuid REFERENCES servers (id) ON DELETE CASCADE,
    storage_id   uuid REFERENCES storages (id) ON DELETE CASCADE,
    level        text NOT NULL CHECK (level IN ('viewer', 'operator', 'engineer', 'owner')),
    can_create   boolean NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(user_id, group_id) = 1),
    CHECK (num_nonnulls(workspace_id, server_id, storage_id) = 1),
    CHECK (NOT can_create OR workspace_id IS NOT NULL)
);

CREATE UNIQUE INDEX access_grants_key ON access_grants (user_id, group_id, workspace_id, server_id, storage_id) NULLS NOT DISTINCT;
CREATE INDEX access_grants_user_idx ON access_grants (user_id);
CREATE INDEX access_grants_group_idx ON access_grants (group_id);
CREATE INDEX access_grants_workspace_idx ON access_grants (workspace_id);
CREATE INDEX access_grants_server_idx ON access_grants (server_id);
CREATE INDEX access_grants_storage_idx ON access_grants (storage_id);

-- Panel-wide settings; always exactly one row.
CREATE TABLE app_settings (
    id                boolean PRIMARY KEY DEFAULT true CHECK (id),
    registration_open boolean NOT NULL DEFAULT false,
    updated_at        timestamptz NOT NULL DEFAULT now()
);

INSERT INTO app_settings DEFAULT VALUES;

-- Who started a job. NULL (older jobs, deleted users) = only admins see it.
ALTER TABLE jobs ADD COLUMN created_by uuid REFERENCES users (id) ON DELETE SET NULL;
CREATE INDEX jobs_created_by_idx ON jobs (created_by);

-- +goose Down

DROP INDEX jobs_created_by_idx;
ALTER TABLE jobs DROP COLUMN created_by;
DROP TABLE app_settings;
DROP TABLE access_grants;

DROP INDEX folders_parent_name_key;
DROP INDEX servers_name_key;
DROP INDEX storages_name_key;
ALTER TABLE folders DROP COLUMN workspace_id;
ALTER TABLE servers DROP COLUMN workspace_id;
ALTER TABLE storages DROP COLUMN workspace_id;
CREATE UNIQUE INDEX folders_parent_name_key ON folders (parent_id, lower(name)) NULLS NOT DISTINCT;
CREATE UNIQUE INDEX servers_name_key ON servers (lower(name));
CREATE UNIQUE INDEX storages_name_key ON storages (lower(name));

DROP TABLE workspaces;
DROP TABLE group_members;
DROP TABLE user_groups;
DROP TABLE sessions;
DROP TABLE users;
