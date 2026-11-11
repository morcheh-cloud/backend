-- +goose Up
ALTER TABLE command_log_settings ADD COLUMN log_output boolean NOT NULL DEFAULT true;

-- What a command printed (kept apart so lists never read it).
CREATE TABLE command_log_output (
    id         uuid PRIMARY KEY REFERENCES command_log (id) ON DELETE CASCADE,
    output     text NOT NULL DEFAULT '',
    size       bigint NOT NULL DEFAULT 0,
    truncated  boolean NOT NULL DEFAULT false,
    note       text NOT NULL DEFAULT ''
);

-- +goose Down
DROP TABLE command_log_output;
ALTER TABLE command_log_settings DROP COLUMN log_output;
