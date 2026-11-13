-- +goose Up
ALTER TABLE schedules DROP CONSTRAINT schedules_action_check;
ALTER TABLE schedules ADD CONSTRAINT schedules_action_check
    CHECK (action IN ('sync', 'script', 'ansible', 'service', 'reboot', 'fetch', 'archive', 'verify-backup', 'software-update', 'package-upgrade', 'docker-update', 'docker-volume-backup', 'docker-prune'));

-- +goose Down
DELETE FROM schedules WHERE action = 'docker-prune';
ALTER TABLE schedules DROP CONSTRAINT schedules_action_check;
ALTER TABLE schedules ADD CONSTRAINT schedules_action_check
    CHECK (action IN ('sync', 'script', 'ansible', 'service', 'reboot', 'fetch', 'archive', 'verify-backup', 'software-update', 'package-upgrade', 'docker-update', 'docker-volume-backup'));
