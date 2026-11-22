-- +goose Up
-- How a plan compresses its files and how many jobs its dumps use.
ALTER TABLE database_backup_plans
    ADD COLUMN compression text NOT NULL DEFAULT 'gzip',
    ADD COLUMN compression_level text NOT NULL DEFAULT 'balanced',
    ADD COLUMN workers integer NOT NULL DEFAULT 1;

-- What a backup was taken with ("zstd:fast"; empty = before this, gzip).
ALTER TABLE database_backups
    ADD COLUMN compression text NOT NULL DEFAULT '',
    ADD COLUMN workers integer NOT NULL DEFAULT 1;

-- +goose Down
ALTER TABLE database_backups DROP COLUMN compression, DROP COLUMN workers;
ALTER TABLE database_backup_plans DROP COLUMN compression, DROP COLUMN compression_level, DROP COLUMN workers;
