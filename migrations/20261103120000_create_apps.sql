-- +goose Up

-- Web services the team signs in to (Portainer, MinIO…): the panel's
-- "Services" page. Named "apps" here because "services" already means
-- systemd units.
CREATE TABLE app_categories (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    color        text NOT NULL,
    position     integer NOT NULL DEFAULT 0,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX app_categories_name_key ON app_categories (workspace_id, lower(name));

CREATE TABLE apps (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    -- Removing a category leaves its services uncategorized.
    category_id  uuid REFERENCES app_categories (id) ON DELETE SET NULL,
    name         text NOT NULL,
    address      text NOT NULL,
    note         text NOT NULL DEFAULT '',
    color        text NOT NULL,
    critical     boolean NOT NULL DEFAULT false,
    position     integer NOT NULL DEFAULT 0,
    -- auto = fetched favicon, else the first letter; upload = app_logos
    -- 'upload' row; icon = a lucide icon name.
    logo_kind    text NOT NULL DEFAULT 'auto' CHECK (logo_kind IN ('auto', 'upload', 'icon')),
    logo_icon    text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX apps_workspace_idx ON apps (workspace_id);
CREATE INDEX apps_category_idx ON apps (category_id);

-- Kept apart from apps so listing stays light and the background favicon
-- fetch can never overwrite an uploaded logo.
CREATE TABLE app_logos (
    app_id       uuid NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    source       text NOT NULL CHECK (source IN ('favicon', 'upload')),
    content_type text NOT NULL,
    data         bytea NOT NULL,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (app_id, source)
);

CREATE TABLE app_accounts (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    app_id       uuid NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    label        text NOT NULL DEFAULT '',
    username     text NOT NULL DEFAULT '',
    -- Sealed with internal/secrets; NULL = no password saved.
    password_enc bytea,
    position     integer NOT NULL DEFAULT 0
);

CREATE INDEX app_accounts_app_idx ON app_accounts (app_id);

-- Every password reveal. Names are copied so the row still reads right after
-- the account or the person is gone.
CREATE TABLE app_secret_views (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    app_id        uuid NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    account_id    uuid REFERENCES app_accounts (id) ON DELETE SET NULL,
    account_label text NOT NULL,
    user_id       uuid REFERENCES users (id) ON DELETE SET NULL,
    user_name     text NOT NULL,
    ip            text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX app_secret_views_app_idx ON app_secret_views (app_id, created_at DESC);

ALTER TABLE access_grants ADD COLUMN app_id uuid REFERENCES apps (id) ON DELETE CASCADE;
ALTER TABLE access_grants DROP CONSTRAINT access_grants_check1;
ALTER TABLE access_grants ADD CONSTRAINT access_grants_target_check
    CHECK (num_nonnulls(workspace_id, server_id, storage_id, app_id) = 1);
DROP INDEX access_grants_key;
CREATE UNIQUE INDEX access_grants_key ON access_grants (user_id, group_id, workspace_id, server_id, storage_id, app_id) NULLS NOT DISTINCT;
CREATE INDEX access_grants_app_idx ON access_grants (app_id);

-- +goose Down

DELETE FROM access_grants WHERE app_id IS NOT NULL;
DROP INDEX access_grants_app_idx;
DROP INDEX access_grants_key;
CREATE UNIQUE INDEX access_grants_key ON access_grants (user_id, group_id, workspace_id, server_id, storage_id) NULLS NOT DISTINCT;
ALTER TABLE access_grants DROP CONSTRAINT access_grants_target_check;
ALTER TABLE access_grants DROP COLUMN app_id;
ALTER TABLE access_grants ADD CONSTRAINT access_grants_check1
    CHECK (num_nonnulls(workspace_id, server_id, storage_id) = 1);

DROP TABLE app_secret_views;
DROP TABLE app_accounts;
DROP TABLE app_logos;
DROP TABLE apps;
DROP TABLE app_categories;
