-- +goose Up
-- Where a parallel PostgreSQL dump is written before it's sent ('' = the
-- runner's own temporary folder).
ALTER TABLE database_backup_plans ADD COLUMN temp_dir text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE database_backup_plans DROP COLUMN temp_dir;
