-- +goose Up
-- Where a monitor is checked from: Morcheh itself (server_id NULL) and/or
-- panel servers over SSH. Each round checks every location; the monitor's
-- rule turns their answers into one status. The row keeps the location's
-- own latest answer.
CREATE TABLE monitor_locations (
    id             uuid PRIMARY KEY DEFAULT uuidv7(),
    monitor_id     uuid NOT NULL REFERENCES monitors (id) ON DELETE CASCADE,
    server_id      uuid REFERENCES servers (id) ON DELETE CASCADE,
    status         text NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending', 'up', 'degraded', 'down', 'unknown')),
    status_message text NOT NULL DEFAULT '',
    status_since   timestamptz NOT NULL DEFAULT now(),
    latency_ms     int,
    code           text NOT NULL DEFAULT '',
    checked_at     timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE NULLS NOT DISTINCT (monitor_id, server_id)
);

CREATE INDEX monitor_locations_server_idx ON monitor_locations (server_id);

INSERT INTO monitor_locations (monitor_id, server_id)
SELECT id, via_server_id FROM monitors WHERE kind <> 'push';

-- The rule. down: when the monitor counts as down (any = one location
-- failing is enough, majority, all, count = at least down_count).
-- degraded: when failures below that make it degraded instead of up.
-- Locations that couldn't check at all (the server was unreachable) don't vote.
ALTER TABLE monitors
    DROP COLUMN via_server_id,
    ADD COLUMN rule_down text NOT NULL DEFAULT 'majority'
        CHECK (rule_down IN ('any', 'majority', 'all', 'count')),
    ADD COLUMN rule_down_count int NOT NULL DEFAULT 2
        CHECK (rule_down_count BETWEEN 1 AND 50),
    ADD COLUMN rule_degraded text NOT NULL DEFAULT 'any'
        CHECK (rule_degraded IN ('any', 'majority', 'count', 'never')),
    ADD COLUMN rule_degraded_count int NOT NULL DEFAULT 1
        CHECK (rule_degraded_count BETWEEN 1 AND 50);

-- Every location's answer for a check, when there's more than one:
-- [{"loc": "morcheh" | server id, "status", "latency_ms", "code", "message"}].
ALTER TABLE monitor_checks ADD COLUMN results jsonb NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE monitor_checks DROP COLUMN results;
ALTER TABLE monitors
    DROP COLUMN rule_down,
    DROP COLUMN rule_down_count,
    DROP COLUMN rule_degraded,
    DROP COLUMN rule_degraded_count,
    ADD COLUMN via_server_id uuid REFERENCES servers (id) ON DELETE SET NULL;
UPDATE monitors m SET via_server_id = (
    SELECT l.server_id FROM monitor_locations l
    WHERE l.monitor_id = m.id AND l.server_id IS NOT NULL
    ORDER BY l.created_at LIMIT 1
);
DROP TABLE monitor_locations;
