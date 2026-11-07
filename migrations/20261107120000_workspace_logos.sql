-- +goose Up

-- How a workspace shows in the panel's switcher: its first letter or a Lucide
-- icon on one of the palette colors (the panel owns the actual colors), or an
-- uploaded picture in workspace_logos.
ALTER TABLE workspaces
    ADD COLUMN color     text NOT NULL DEFAULT 'indigo',
    ADD COLUMN logo_kind text NOT NULL DEFAULT 'letter' CHECK (logo_kind IN ('letter', 'icon', 'upload')),
    ADD COLUMN logo_icon text NOT NULL DEFAULT '';

CREATE TABLE workspace_logos (
    workspace_id uuid PRIMARY KEY REFERENCES workspaces (id) ON DELETE CASCADE,
    content_type text NOT NULL,
    data         bytea NOT NULL,
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- +goose Down

DROP TABLE workspace_logos;

ALTER TABLE workspaces
    DROP COLUMN color,
    DROP COLUMN logo_kind,
    DROP COLUMN logo_icon;
