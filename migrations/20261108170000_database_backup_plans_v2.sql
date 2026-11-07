-- +goose Up

-- A plan can pick several databases, write to several storages, take
-- incrementals and keep by age or by tiers.
ALTER TABLE database_backup_plans
    ADD COLUMN selection       text NOT NULL DEFAULT 'all' CHECK (selection IN ('all', 'selected', 'pattern')),
    ADD COLUMN targets         text[] NOT NULL DEFAULT '{}',
    ADD COLUMN pattern         text NOT NULL DEFAULT '',
    ADD COLUMN method          text NOT NULL DEFAULT 'full' CHECK (method IN ('full', 'incremental')),
    -- An incremental plan starts over with a full one this often.
    ADD COLUMN full_every_days integer NOT NULL DEFAULT 7 CHECK (full_every_days BETWEEN 1 AND 365),
    ADD COLUMN retention       text NOT NULL DEFAULT 'days' CHECK (retention IN ('days', 'gfs', 'forever')),
    ADD COLUMN keep_days       integer NOT NULL DEFAULT 7 CHECK (keep_days BETWEEN 1 AND 3650),
    ADD COLUMN gfs_daily       integer NOT NULL DEFAULT 3 CHECK (gfs_daily BETWEEN 0 AND 1000),
    ADD COLUMN gfs_weekly      integer NOT NULL DEFAULT 4 CHECK (gfs_weekly BETWEEN 0 AND 1000),
    ADD COLUMN gfs_monthly     integer NOT NULL DEFAULT 12 CHECK (gfs_monthly BETWEEN 0 AND 1000);

UPDATE database_backup_plans SET selection = 'selected', targets = ARRAY[target] WHERE target <> '';
UPDATE database_backup_plans SET retention = 'forever' WHERE keep = 0;
UPDATE database_backup_plans SET keep_days = least(keep, 3650) WHERE keep > 0;

-- Where a plan's dump is uploaded: once dumped, to each of these.
CREATE TABLE database_backup_plan_storages (
    plan_id    uuid NOT NULL REFERENCES database_backup_plans (id) ON DELETE CASCADE,
    storage_id uuid NOT NULL REFERENCES storages (id) ON DELETE CASCADE,
    position   integer NOT NULL DEFAULT 0,
    PRIMARY KEY (plan_id, storage_id)
);

CREATE INDEX database_backup_plan_storages_storage_idx ON database_backup_plan_storages (storage_id);

INSERT INTO database_backup_plan_storages (plan_id, storage_id)
SELECT id, storage_id FROM database_backup_plans WHERE storage_id IS NOT NULL;

ALTER TABLE database_backup_plans DROP COLUMN target, DROP COLUMN storage_id, DROP COLUMN keep;

ALTER TABLE database_backups
    ADD COLUMN kind      text NOT NULL DEFAULT 'full' CHECK (kind IN ('full', 'incremental')),
    -- What an incremental builds on: nothing can be restored without it.
    ADD COLUMN parent_id uuid REFERENCES database_backups (id),
    -- Where the next incremental continues from: a binary log file and offset,
    -- or SQL Server's differential base.
    ADD COLUMN position  text NOT NULL DEFAULT '';

ALTER TABLE database_backups DROP CONSTRAINT database_backups_trigger_check;
ALTER TABLE database_backups ADD CONSTRAINT database_backups_trigger_check
    CHECK (trigger IN ('schedule', 'manual', 'restore'));

CREATE INDEX database_backups_parent_idx ON database_backups (parent_id);

-- Each storage a run writes to. The file has the same path on all of them.
CREATE TABLE database_backup_copies (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    backup_id    uuid NOT NULL REFERENCES database_backups (id) ON DELETE CASCADE,
    storage_id   uuid REFERENCES storages (id) ON DELETE SET NULL,
    storage_name text NOT NULL DEFAULT '',
    state        text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'stored', 'failed')),
    error        text NOT NULL DEFAULT ''
);

CREATE INDEX database_backup_copies_backup_idx ON database_backup_copies (backup_id);
CREATE INDEX database_backup_copies_storage_idx ON database_backup_copies (storage_id);

INSERT INTO database_backup_copies (backup_id, storage_id, storage_name, state)
SELECT id, storage_id, storage_name, CASE WHEN state = 'succeeded' THEN 'stored' WHEN state IN ('queued', 'running') THEN 'pending' ELSE 'failed' END
FROM database_backups
WHERE storage_id IS NOT NULL OR storage_name <> '';

ALTER TABLE database_backups DROP COLUMN storage_id, DROP COLUMN storage_name;

-- A backup brought back into a database.
CREATE TABLE database_restores (
    id               uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id     uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    database_id      uuid NOT NULL REFERENCES databases (id) ON DELETE CASCADE,
    backup_id        uuid REFERENCES database_backups (id) ON DELETE SET NULL,
    -- What was restored, for when the backup is gone.
    source           text NOT NULL DEFAULT '',
    target_name      text NOT NULL DEFAULT '',
    mode             text NOT NULL CHECK (mode IN ('replace', 'new')),
    runner_server_id uuid REFERENCES servers (id) ON DELETE SET NULL,
    storage_id       uuid REFERENCES storages (id) ON DELETE SET NULL,
    want_safety      boolean NOT NULL DEFAULT false,
    safety_backup_id uuid REFERENCES database_backups (id) ON DELETE SET NULL,
    -- A login typed for this restore only, wiped when it ends.
    username         text NOT NULL DEFAULT '',
    password_enc     bytea,
    state            text NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'canceled', 'interrupted')),
    error            text NOT NULL DEFAULT '',
    job_id           uuid REFERENCES jobs (id) ON DELETE SET NULL,
    created_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by_name  text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    started_at       timestamptz,
    finished_at      timestamptz
);

CREATE INDEX database_restores_database_idx ON database_restores (database_id, id DESC);

-- +goose Down
DROP TABLE database_restores;

ALTER TABLE database_backups
    ADD COLUMN storage_id   uuid REFERENCES storages (id) ON DELETE SET NULL,
    ADD COLUMN storage_name text NOT NULL DEFAULT '';

UPDATE database_backups b SET storage_id = c.storage_id, storage_name = c.storage_name
FROM (SELECT DISTINCT ON (backup_id) * FROM database_backup_copies ORDER BY backup_id, state = 'stored' DESC, id) c
WHERE c.backup_id = b.id;

DROP TABLE database_backup_copies;

DELETE FROM database_backups WHERE trigger = 'restore';
ALTER TABLE database_backups DROP CONSTRAINT database_backups_trigger_check;
ALTER TABLE database_backups ADD CONSTRAINT database_backups_trigger_check
    CHECK (trigger IN ('schedule', 'manual'));

DROP INDEX database_backups_parent_idx;
ALTER TABLE database_backups DROP COLUMN kind, DROP COLUMN parent_id, DROP COLUMN position;

ALTER TABLE database_backup_plans
    ADD COLUMN target     text NOT NULL DEFAULT '',
    ADD COLUMN storage_id uuid REFERENCES storages (id) ON DELETE SET NULL,
    ADD COLUMN keep       integer NOT NULL DEFAULT 7 CHECK (keep BETWEEN 0 AND 1000);

UPDATE database_backup_plans p SET storage_id = s.storage_id
FROM (SELECT DISTINCT ON (plan_id) plan_id, storage_id FROM database_backup_plan_storages ORDER BY plan_id, position) s
WHERE s.plan_id = p.id;
UPDATE database_backup_plans SET target = targets[1] WHERE selection = 'selected' AND cardinality(targets) > 0;
UPDATE database_backup_plans SET keep = CASE WHEN retention = 'forever' THEN 0 ELSE least(keep_days, 1000) END;

DROP TABLE database_backup_plan_storages;

ALTER TABLE database_backup_plans
    DROP COLUMN selection, DROP COLUMN targets, DROP COLUMN pattern, DROP COLUMN method,
    DROP COLUMN full_every_days, DROP COLUMN retention, DROP COLUMN keep_days,
    DROP COLUMN gfs_daily, DROP COLUMN gfs_weekly, DROP COLUMN gfs_monthly;
