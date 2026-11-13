-- +goose Up
-- Cron jobs can update containers to their newest image, with rollback.
ALTER TABLE schedules DROP CONSTRAINT schedules_action_check;
ALTER TABLE schedules ADD CONSTRAINT schedules_action_check
    CHECK (action IN ('sync', 'script', 'ansible', 'service', 'reboot', 'fetch', 'archive', 'verify-backup', 'software-update', 'package-upgrade', 'docker-update'));

-- +goose Down
DELETE FROM schedules WHERE action = 'docker-update';
ALTER TABLE schedules DROP CONSTRAINT schedules_action_check;
ALTER TABLE schedules ADD CONSTRAINT schedules_action_check
    CHECK (action IN ('sync', 'script', 'ansible', 'service', 'reboot', 'fetch', 'archive', 'verify-backup', 'software-update', 'package-upgrade'));
