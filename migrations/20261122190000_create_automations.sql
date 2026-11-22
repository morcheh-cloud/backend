-- +goose Up
-- Automations: when an event happens (or an incoming hook is called, or
-- someone presses Run), do a list of steps.
CREATE TABLE automations (
    id                uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id      uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name              text NOT NULL,
    description       text NOT NULL DEFAULT '',
    enabled           boolean NOT NULL DEFAULT true,
    -- {kind, events, filter, include_muted}
    trigger           jsonb NOT NULL DEFAULT '{}',
    -- Ordered steps; a webhook step's header values are sealed in it.
    actions           jsonb NOT NULL DEFAULT '[]',
    cooldown_seconds  integer NOT NULL DEFAULT 300,
    max_runs_per_hour integer NOT NULL DEFAULT 20,
    -- SHA-256 of the incoming hook's token (NULL = no incoming URL).
    hook_token_hash   text,
    -- Who it runs as: whoever saved it last.
    updated_by        uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by        uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    last_run_at       timestamptz,
    -- How the last run that wasn't skipped ended ('' = never ran).
    last_status       text NOT NULL DEFAULT '',
    -- Why it can't run (lost access…); cleared when it's saved.
    problem           text NOT NULL DEFAULT ''
);

CREATE INDEX automations_workspace_idx ON automations (workspace_id);
CREATE UNIQUE INDEX automations_hook_idx ON automations (hook_token_hash) WHERE hook_token_hash IS NOT NULL;

CREATE TABLE automation_runs (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    automation_id   uuid NOT NULL REFERENCES automations (id) ON DELETE CASCADE,
    workspace_id    uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    trigger_kind    text NOT NULL CHECK (trigger_kind IN ('event', 'webhook', 'manual', 'test')),
    -- The event it ran for (PanelEvent JSON).
    event           jsonb NOT NULL DEFAULT '{}',
    -- What the cooldown counts per: the event's subject id.
    subject_id      text NOT NULL DEFAULT '',
    status          text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'skipped', 'canceled')),
    -- One entry per step, saved as the run goes.
    steps           jsonb NOT NULL DEFAULT '[]',
    -- Why it was skipped, or why it failed.
    reason          text NOT NULL DEFAULT '',
    job_id          uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    finished_at     timestamptz,
    started_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    started_by_name text NOT NULL DEFAULT ''
);

CREATE INDEX automation_runs_automation_idx ON automation_runs (automation_id, created_at DESC);
CREATE INDEX automation_runs_workspace_idx ON automation_runs (workspace_id, created_at DESC);

-- +goose Down
DROP TABLE automation_runs;
DROP TABLE automations;
