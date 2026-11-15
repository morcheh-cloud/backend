-- +goose Up

-- A sync can read from a server's folder (over SSH) instead of a storage, and
-- a server folder can be watched: changes are pushed as soon as they happen.
ALTER TABLE storage_syncs
    ALTER COLUMN source_storage_id DROP NOT NULL,
    ADD COLUMN source_server_id uuid REFERENCES servers (id) ON DELETE CASCADE,
    ADD CONSTRAINT storage_syncs_one_source CHECK ((source_storage_id IS NULL) <> (source_server_id IS NULL));
CREATE INDEX storage_syncs_source_server_idx ON storage_syncs (source_server_id);

-- watch = follow the source folder's changes; interval_minutes is then how
-- often a full check runs besides (0 = only after reconnecting).
ALTER TABLE storage_syncs DROP CONSTRAINT storage_syncs_trigger_check;
ALTER TABLE storage_syncs ADD CONSTRAINT storage_syncs_trigger_check
    CHECK (trigger IN ('manual', 'schedule', 'interval', 'watch'));
ALTER TABLE storage_sync_runs DROP CONSTRAINT storage_sync_runs_trigger_check;
ALTER TABLE storage_sync_runs ADD CONSTRAINT storage_sync_runs_trigger_check
    CHECK (trigger IN ('manual', 'schedule', 'interval', 'watch'));

-- +goose Down
DELETE FROM storage_syncs WHERE source_server_id IS NOT NULL;
UPDATE storage_syncs SET trigger = 'manual' WHERE trigger = 'watch';
UPDATE storage_sync_runs SET trigger = 'manual' WHERE trigger = 'watch';
ALTER TABLE storage_sync_runs DROP CONSTRAINT storage_sync_runs_trigger_check;
ALTER TABLE storage_sync_runs ADD CONSTRAINT storage_sync_runs_trigger_check
    CHECK (trigger IN ('manual', 'schedule', 'interval'));
ALTER TABLE storage_syncs DROP CONSTRAINT storage_syncs_trigger_check;
ALTER TABLE storage_syncs ADD CONSTRAINT storage_syncs_trigger_check
    CHECK (trigger IN ('manual', 'schedule', 'interval'));
DROP INDEX storage_syncs_source_server_idx;
ALTER TABLE storage_syncs
    DROP CONSTRAINT storage_syncs_one_source,
    DROP COLUMN source_server_id,
    ALTER COLUMN source_storage_id SET NOT NULL;
