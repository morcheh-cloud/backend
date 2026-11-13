-- +goose Up
-- More container settings per workspace.
ALTER TABLE docker_settings
    -- Hours between automatic image update checks (needs update_check).
    ADD COLUMN update_check_hours int NOT NULL DEFAULT 24 CHECK (update_check_hours IN (6, 12, 24, 72, 168)),
    -- Leave out vulnerabilities that have no fixed version yet.
    ADD COLUMN scan_ignore_unfixed boolean NOT NULL DEFAULT false,
    -- Deploys remove containers of services no longer in the compose file.
    ADD COLUMN remove_orphans boolean NOT NULL DEFAULT true,
    -- Compose file versions kept per project.
    ADD COLUMN versions_keep int NOT NULL DEFAULT 50 CHECK (versions_keep BETWEEN 5 AND 200);

-- +goose Down
ALTER TABLE docker_settings
    DROP COLUMN update_check_hours,
    DROP COLUMN scan_ignore_unfixed,
    DROP COLUMN remove_orphans,
    DROP COLUMN versions_keep;
