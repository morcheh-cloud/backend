-- +goose Up

-- Filters people keep on a table of the data explorer (search, filters,
-- condition, sort): alone or shared with everyone who can browse it.
CREATE TABLE database_saved_views (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    database_id     uuid NOT NULL REFERENCES databases (id) ON DELETE CASCADE,
    dbname          text NOT NULL DEFAULT '' CHECK (length(dbname) <= 128),
    schema_name     text NOT NULL DEFAULT '' CHECK (length(schema_name) <= 128),
    table_name      text NOT NULL CHECK (length(table_name) BETWEEN 1 AND 256),
    title           text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
    -- {search, filters, match, where, sort, page_size}
    state           jsonb NOT NULL DEFAULT '{}',
    shared          boolean NOT NULL DEFAULT false,
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by_name text NOT NULL DEFAULT '',
    updated_by_name text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX database_saved_views_table_idx ON database_saved_views (database_id, dbname, schema_name, table_name);

-- +goose Down
DROP TABLE database_saved_views;
