-- +goose Up
-- Copies of Docker volumes kept on a Storage (a .tar.gz of the volume's
-- folder), made by hand or by a cron job, and put back from there.
CREATE TABLE docker_volume_backups (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    server_id       uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    volume          text NOT NULL,
    storage_id      uuid REFERENCES storages (id) ON DELETE SET NULL,
    storage_name    text NOT NULL DEFAULT '',
    path            text NOT NULL,
    size            bigint NOT NULL DEFAULT 0,
    sha256          text NOT NULL DEFAULT '',
    state           text NOT NULL DEFAULT 'running' CHECK (state IN ('running', 'stored', 'failed')),
    error           text NOT NULL DEFAULT '',
    note            text NOT NULL DEFAULT '',
    stopped         int NOT NULL DEFAULT 0,
    schedule_id     uuid REFERENCES schedules (id) ON DELETE SET NULL,
    job_id          uuid,
    created_by_name text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz
);
CREATE INDEX docker_volume_backups_volume ON docker_volume_backups (server_id, volume, created_at DESC);

ALTER TABLE schedules DROP CONSTRAINT schedules_action_check;
ALTER TABLE schedules ADD CONSTRAINT schedules_action_check
    CHECK (action IN ('sync', 'script', 'ansible', 'service', 'reboot', 'fetch', 'archive', 'verify-backup', 'software-update', 'package-upgrade', 'docker-update', 'docker-volume-backup'));

-- +goose Down
DELETE FROM schedules WHERE action = 'docker-volume-backup';
ALTER TABLE schedules DROP CONSTRAINT schedules_action_check;
ALTER TABLE schedules ADD CONSTRAINT schedules_action_check
    CHECK (action IN ('sync', 'script', 'ansible', 'service', 'reboot', 'fetch', 'archive', 'verify-backup', 'software-update', 'package-upgrade', 'docker-update'));
DROP TABLE docker_volume_backups;
