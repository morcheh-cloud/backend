-- +goose Up

-- Runs belong to a workspace, like Ansible runs: lists and access go by it.
ALTER TABLE script_runs ADD COLUMN workspace_id uuid REFERENCES workspaces (id) ON DELETE CASCADE;
UPDATE script_runs r SET workspace_id = s.workspace_id FROM scripts s WHERE s.id = r.script_id;
UPDATE script_runs r SET workspace_id = v.workspace_id
FROM script_run_targets t JOIN servers v ON v.id = t.server_id
WHERE t.run_id = r.id AND r.workspace_id IS NULL;
DELETE FROM script_runs WHERE workspace_id IS NULL;
ALTER TABLE script_runs ALTER COLUMN workspace_id SET NOT NULL;
CREATE INDEX script_runs_workspace_idx ON script_runs (workspace_id, id DESC);

-- Why a whole run couldn't go on (it was deleted, Morcheh restarted…).
ALTER TABLE script_runs ADD COLUMN error text NOT NULL DEFAULT '';

-- +goose Down
DROP INDEX script_runs_workspace_idx;
ALTER TABLE script_runs DROP COLUMN error;
ALTER TABLE script_runs DROP COLUMN workspace_id;
