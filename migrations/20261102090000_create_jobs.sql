-- +goose Up

-- Background jobs (internal/jobs): long operations that outlive the request
-- that started them — transfers, archives, downloads onto a server.
CREATE TABLE jobs (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    -- What runs it: a handler registered under this name.
    kind        text NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
    title       text NOT NULL,
    -- Everything the handler needs to run (or rerun) the job.
    params      jsonb NOT NULL DEFAULT '{}',
    -- Servers and storages the job touches, for filtering and limits.
    refs        uuid[] NOT NULL DEFAULT '{}',
    -- Where its output lands ({server_id|storage_id, path}), for links.
    target      jsonb,
    state       text NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'canceled', 'interrupted')),
    progress    jsonb NOT NULL DEFAULT '{}',
    result      jsonb,
    error       text NOT NULL DEFAULT '',
    -- Tail of what the job printed, capped by the runner.
    log         text NOT NULL DEFAULT '',
    -- The job this one is a retry of.
    retry_of    uuid,
    created_at  timestamptz NOT NULL DEFAULT now(),
    started_at  timestamptz,
    finished_at timestamptz
);

CREATE INDEX jobs_created_idx ON jobs (created_at DESC);
CREATE INDEX jobs_active_idx ON jobs (state) WHERE state IN ('queued', 'running');

-- +goose Down
DROP TABLE jobs;
