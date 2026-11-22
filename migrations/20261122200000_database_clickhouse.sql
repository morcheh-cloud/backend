-- +goose Up
-- ClickHouse joins the engines a database connection can be.
ALTER TABLE databases DROP CONSTRAINT databases_engine_check;
ALTER TABLE databases ADD CONSTRAINT databases_engine_check
    CHECK (engine IN ('postgres', 'mysql', 'mssql', 'redis', 'mongodb', 'clickhouse'));

-- +goose Down
DELETE FROM databases WHERE engine = 'clickhouse';
ALTER TABLE databases DROP CONSTRAINT databases_engine_check;
ALTER TABLE databases ADD CONSTRAINT databases_engine_check
    CHECK (engine IN ('postgres', 'mysql', 'mssql', 'redis', 'mongodb'));
