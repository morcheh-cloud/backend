-- +goose Up

-- Queries people keep on a database: run again later, alone (private) or by
-- everyone who can query it (shared).
CREATE TABLE database_saved_queries (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    database_id     uuid NOT NULL REFERENCES databases (id) ON DELETE CASCADE,
    title           text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
    description     text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    -- The database inside the connection it runs in ('' = the connection's).
    dbname          text NOT NULL DEFAULT '' CHECK (length(dbname) <= 128),
    query           text NOT NULL CHECK (length(query) BETWEEN 1 AND 100000),
    shared          boolean NOT NULL DEFAULT false,
    pinned          boolean NOT NULL DEFAULT false,
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by_name text NOT NULL DEFAULT '',
    updated_by_name text NOT NULL DEFAULT '',
    run_count       integer NOT NULL DEFAULT 0,
    last_run_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX database_saved_queries_db_idx ON database_saved_queries (database_id, pinned DESC, lower(title));

-- Every query someone ran from the panel: their history and the audit trail.
-- Kept 90 days.
CREATE TABLE database_query_runs (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    database_id uuid NOT NULL REFERENCES databases (id) ON DELETE CASCADE,
    user_id     uuid REFERENCES users (id) ON DELETE SET NULL,
    user_name   text NOT NULL DEFAULT '',
    dbname      text NOT NULL DEFAULT '',
    query       text NOT NULL,
    -- read = read only; change = may write.
    mode        text NOT NULL CHECK (mode IN ('read', 'change')),
    ok          boolean NOT NULL,
    error       text NOT NULL DEFAULT '',
    rows        bigint NOT NULL DEFAULT 0,
    ms          bigint NOT NULL DEFAULT 0,
    at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX database_query_runs_db_idx ON database_query_runs (database_id, at DESC);
CREATE INDEX database_query_runs_user_idx ON database_query_runs (database_id, user_id, at DESC);

-- +goose Down
DROP TABLE database_query_runs;
DROP TABLE database_saved_queries;
