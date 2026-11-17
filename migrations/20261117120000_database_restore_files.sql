-- +goose Up
-- A restore from a file Morche didn't take: on a storage (storage_id) or a
-- server (source_server_id), at source.
ALTER TABLE database_restores
    ADD COLUMN source_server_id  uuid REFERENCES servers (id) ON DELETE SET NULL,
    -- What the file was found to be; empty = one of Morche's own backups.
    ADD COLUMN format            text NOT NULL DEFAULT '',
    -- The database inside the file to take, when it holds several.
    ADD COLUMN source_name       text NOT NULL DEFAULT '',
    -- Where the backup before goes (Morche's own backups use storage_id).
    ADD COLUMN safety_storage_id uuid REFERENCES storages (id) ON DELETE SET NULL,
    ADD COLUMN safety_folder     text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE database_restores
    DROP COLUMN source_server_id,
    DROP COLUMN format,
    DROP COLUMN source_name,
    DROP COLUMN safety_storage_id,
    DROP COLUMN safety_folder;
