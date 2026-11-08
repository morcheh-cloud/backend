-- +goose Up

-- Cron jobs do more than sync files: run a script, a playbook, a service
-- action, a reboot, a download, an archive, or check a database backup. What
-- each needs beyond source/destinations is in task.
ALTER TABLE schedules DROP CONSTRAINT schedules_action_check;
ALTER TABLE schedules ADD CONSTRAINT schedules_action_check
    CHECK (action IN ('sync', 'script', 'ansible', 'service', 'reboot', 'fetch', 'archive', 'verify-backup'));
ALTER TABLE schedules ADD COLUMN task jsonb NOT NULL DEFAULT '{}';

-- What a run started elsewhere: {kind: script-run | ansible-run | database-backup, id}.
ALTER TABLE schedule_runs ADD COLUMN link jsonb NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE schedule_runs DROP COLUMN link;
DELETE FROM schedules WHERE action <> 'sync';
ALTER TABLE schedules DROP COLUMN task;
ALTER TABLE schedules DROP CONSTRAINT schedules_action_check;
ALTER TABLE schedules ADD CONSTRAINT schedules_action_check CHECK (action IN ('sync'));
