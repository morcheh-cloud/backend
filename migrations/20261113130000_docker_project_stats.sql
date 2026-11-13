-- +goose Up
-- Compose projects' numbers kept over time: one point every 5 minutes per
-- project, kept as long as the workspace's Docker settings say.
ALTER TABLE docker_settings
    ADD COLUMN stats_days int NOT NULL DEFAULT 30 CHECK (stats_days BETWEEN 0 AND 90);

CREATE TABLE docker_project_stats (
    server_id  uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    project    text NOT NULL,
    at         timestamptz NOT NULL,
    -- Averages over the 5 minutes, and the highest sample in them.
    cpu        double precision NOT NULL,
    cpu_max    double precision NOT NULL,
    memory     bigint NOT NULL,
    memory_max bigint NOT NULL,
    net_rx     double precision NOT NULL,
    net_tx     double precision NOT NULL,
    running    int NOT NULL,
    total      int NOT NULL,
    unhealthy  int NOT NULL,
    PRIMARY KEY (server_id, project, at)
);
CREATE INDEX docker_project_stats_at ON docker_project_stats (at);

-- +goose Down
DROP TABLE docker_project_stats;
ALTER TABLE docker_settings DROP COLUMN stats_days;
