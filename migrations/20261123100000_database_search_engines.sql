-- +goose Up
-- Elasticsearch (also OpenSearch) and Meilisearch join the engines a
-- database connection can be.
ALTER TABLE databases DROP CONSTRAINT databases_engine_check;
ALTER TABLE databases ADD CONSTRAINT databases_engine_check
    CHECK (engine IN ('postgres', 'mysql', 'mssql', 'redis', 'mongodb', 'clickhouse', 'elasticsearch', 'meilisearch'));

-- +goose Down
DELETE FROM databases WHERE engine IN ('elasticsearch', 'meilisearch');
ALTER TABLE databases DROP CONSTRAINT databases_engine_check;
ALTER TABLE databases ADD CONSTRAINT databases_engine_check
    CHECK (engine IN ('postgres', 'mysql', 'mssql', 'redis', 'mongodb', 'clickhouse'));
