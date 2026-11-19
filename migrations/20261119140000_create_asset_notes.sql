-- +goose Up

-- Notes the team keeps on an asset: what it's for, who to call, what went
-- wrong last time. Markdown. Pinned ones show on the asset's overview.
CREATE TABLE asset_notes (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    asset_id        uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    title           text NOT NULL DEFAULT '' CHECK (length(title) <= 200),
    body            text NOT NULL DEFAULT '' CHECK (length(body) <= 100000),
    pinned          boolean NOT NULL DEFAULT false,
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by_name text NOT NULL DEFAULT '',
    updated_by_name text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX asset_notes_asset_idx ON asset_notes (asset_id, pinned DESC, updated_at DESC);

-- The single notes field becomes the first note.
INSERT INTO asset_notes (asset_id, body, created_by_name, updated_by_name, created_at, updated_at)
SELECT id, notes, updated_by_name, updated_by_name, updated_at, updated_at FROM assets WHERE notes <> '';
UPDATE assets SET notes = '' WHERE notes <> '';

-- +goose Down
DROP TABLE asset_notes;
