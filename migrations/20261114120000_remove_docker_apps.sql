-- +goose Up

-- Container apps left Applications: they are Containers templates now,
-- deployed as compose projects. A workspace's own Docker recipes become its
-- own templates (a name already taken gets " (Applications)"), and the
-- records of Docker apps go: the apps keep running and show in Containers ›
-- Projects.
INSERT INTO docker_templates (workspace_id, name, description, category, compose, env, created_by_name, updated_by_name)
SELECT r.workspace_id,
       CASE WHEN EXISTS (
           SELECT 1 FROM docker_templates t
           WHERE t.workspace_id = r.workspace_id AND lower(t.name) = lower(left(r.spec->>'name', 100))
       ) THEN left(r.spec->>'name', 85) || ' (Applications)' ELSE left(r.spec->>'name', 100) END,
       left(coalesce(r.spec->>'summary', ''), 500),
       left(coalesce(r.spec->>'category', ''), 50),
       r.spec->>'compose',
       left(coalesce((
           SELECT string_agg((p->>'name') || '=' || coalesce(p->>'default', ''), E'\n')
           FROM jsonb_array_elements(coalesce(r.spec->'params', '[]'::jsonb)) AS p
       ), ''), 50000),
       'Applications',
       'Applications'
FROM software_recipes r
WHERE r.spec->>'kind' = 'docker'
  AND coalesce(r.spec->>'name', '') <> ''
  AND length(coalesce(r.spec->>'compose', '')) BETWEEN 1 AND 200000
ON CONFLICT DO NOTHING;

DELETE FROM software_recipes WHERE spec->>'kind' = 'docker';
DELETE FROM software_installs WHERE kind = 'docker';
DELETE FROM software_runs WHERE action = 'rollback';

ALTER TABLE software_installs DROP CONSTRAINT software_installs_kind_check;
ALTER TABLE software_installs ADD CONSTRAINT software_installs_kind_check
    CHECK (kind IN ('package', 'script'));
ALTER TABLE software_runs DROP CONSTRAINT software_runs_action_check;
ALTER TABLE software_runs ADD CONSTRAINT software_runs_action_check
    CHECK (action IN ('install', 'update', 'uninstall', 'upgrade-system'));

ALTER TABLE software_installs
    DROP COLUMN state,
    DROP COLUMN dir,
    DROP COLUMN project,
    DROP COLUMN images,
    DROP COLUMN can_rollback,
    DROP COLUMN pinned;

-- +goose Down
ALTER TABLE software_installs
    ADD COLUMN state text NOT NULL DEFAULT '',
    ADD COLUMN dir text NOT NULL DEFAULT '',
    ADD COLUMN project text NOT NULL DEFAULT '',
    ADD COLUMN images jsonb NOT NULL DEFAULT '[]',
    ADD COLUMN can_rollback boolean NOT NULL DEFAULT false,
    ADD COLUMN pinned boolean NOT NULL DEFAULT false;

ALTER TABLE software_runs DROP CONSTRAINT software_runs_action_check;
ALTER TABLE software_runs ADD CONSTRAINT software_runs_action_check
    CHECK (action IN ('install', 'update', 'uninstall', 'rollback', 'upgrade-system'));
ALTER TABLE software_installs DROP CONSTRAINT software_installs_kind_check;
ALTER TABLE software_installs ADD CONSTRAINT software_installs_kind_check
    CHECK (kind IN ('package', 'docker', 'script'));
