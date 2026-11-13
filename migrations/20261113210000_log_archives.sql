-- +goose Up
-- Retention and archiving for Morche's own log and event tables. One policy
-- per dataset (command log, sign-ins, samples…); while a policy is on, it
-- owns that dataset's clean-up and the built-in pruning leaves it alone.
CREATE TABLE log_archive_policies (
    dataset      text PRIMARY KEY,
    enabled      boolean NOT NULL DEFAULT false,
    -- archive = zip the rows then delete them; copy = zip them and keep them
    -- (for reports); delete = drop them without a file.
    mode         text NOT NULL DEFAULT 'archive' CHECK (mode IN ('archive', 'copy', 'delete')),
    after_days   int NOT NULL DEFAULT 90 CHECK (after_days >= 1),
    -- Above this size (MB) older periods go too, oldest first; 0 = no limit.
    max_mb       int NOT NULL DEFAULT 0 CHECK (max_mb >= 0),
    period       text NOT NULL DEFAULT 'month' CHECK (period IN ('day', 'week', 'month')),
    keep_local   boolean NOT NULL DEFAULT true,
    storage_ids  uuid[] NOT NULL DEFAULT '{}',
    folder       text NOT NULL DEFAULT '/morcheh-archives',
    -- Archive files are deleted after this many days; 0 = kept for good.
    keep_days    int NOT NULL DEFAULT 0 CHECK (keep_days >= 0),
    cron         text NOT NULL DEFAULT '30 3 * * *',
    timezone     text NOT NULL DEFAULT 'UTC',
    next_run_at  timestamptz,
    last_run_at  timestamptz,
    last_state   text NOT NULL DEFAULT '',
    last_note    text NOT NULL DEFAULT '',
    last_job_id  uuid,
    updated_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX log_archive_policies_due ON log_archive_policies (next_run_at) WHERE enabled;

-- One zip file: a dataset's rows from one period.
CREATE TABLE log_archives (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    dataset          text NOT NULL,
    mode             text NOT NULL CHECK (mode IN ('archive', 'copy')),
    period_from      timestamptz NOT NULL,
    period_to        timestamptz NOT NULL,
    state            text NOT NULL DEFAULT 'running' CHECK (state IN ('running', 'stored', 'failed', 'interrupted')),
    error            text NOT NULL DEFAULT '',
    file_name        text NOT NULL,
    rows             bigint NOT NULL DEFAULT 0,
    tables           jsonb NOT NULL DEFAULT '{}',
    bytes            bigint NOT NULL DEFAULT 0,
    sha256           text NOT NULL DEFAULT '',
    note             text NOT NULL DEFAULT '',
    job_id           uuid,
    created_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by_name  text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    finished_at      timestamptz,
    -- Bringing it back: '' = never, running, held = its rows are in the
    -- database until hold_until (null = until put away), done = put
    -- back for good (a copy's rows only fill gaps).
    restore_state    text NOT NULL DEFAULT '' CHECK (restore_state IN ('', 'running', 'held', 'done')),
    restored_at      timestamptz,
    restored_rows    bigint NOT NULL DEFAULT 0,
    restored_by_name text NOT NULL DEFAULT '',
    restore_error    text NOT NULL DEFAULT '',
    hold_until       timestamptz
);
CREATE INDEX log_archives_dataset ON log_archives (dataset, period_from DESC);
CREATE INDEX log_archives_held ON log_archives (hold_until) WHERE restore_state = 'held';

-- Where each archive's file is: on Morche's own disk or on a Storage.
CREATE TABLE log_archive_copies (
    id           bigserial PRIMARY KEY,
    archive_id   uuid NOT NULL REFERENCES log_archives (id) ON DELETE CASCADE,
    local        boolean NOT NULL DEFAULT false,
    storage_id   uuid REFERENCES storages (id) ON DELETE SET NULL,
    storage_name text NOT NULL DEFAULT '',
    path         text NOT NULL,
    state        text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'stored', 'failed')),
    error        text NOT NULL DEFAULT ''
);
CREATE INDEX log_archive_copies_archive ON log_archive_copies (archive_id);

-- +goose Down
DROP TABLE log_archive_copies;
DROP TABLE log_archives;
DROP TABLE log_archive_policies;
