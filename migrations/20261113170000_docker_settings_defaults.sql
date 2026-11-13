-- +goose Up
-- Container settings: defaults for new projects, automatic clean-up,
-- notifications, volume backup defaults, and per-server overrides.
ALTER TABLE docker_settings
    -- Written into services of a new project that don't set them ('' / 0 = leave out).
    ADD COLUMN default_restart text NOT NULL DEFAULT '' CHECK (default_restart IN ('', 'no', 'always', 'unless-stopped', 'on-failure')),
    ADD COLUMN default_memory_mb int NOT NULL DEFAULT 0 CHECK (default_memory_mb BETWEEN 0 AND 1048576),
    ADD COLUMN default_cpus double precision NOT NULL DEFAULT 0 CHECK (default_cpus BETWEEN 0 AND 512),
    ADD COLUMN default_log_max_mb int NOT NULL DEFAULT 0 CHECK (default_log_max_mb BETWEEN 0 AND 10240),
    ADD COLUMN default_log_files int NOT NULL DEFAULT 0 CHECK (default_log_files BETWEEN 0 AND 100),
    -- Automatic clean-up of what isn't used (never volumes).
    ADD COLUMN prune_auto boolean NOT NULL DEFAULT false,
    ADD COLUMN prune_hours int NOT NULL DEFAULT 168 CHECK (prune_hours IN (24, 72, 168, 720)),
    ADD COLUMN prune_images text NOT NULL DEFAULT 'dangling' CHECK (prune_images IN ('none', 'dangling', 'all')),
    ADD COLUMN prune_containers boolean NOT NULL DEFAULT false,
    ADD COLUMN prune_networks boolean NOT NULL DEFAULT true,
    ADD COLUMN prune_build_cache boolean NOT NULL DEFAULT true,
    ADD COLUMN prune_older_hours int NOT NULL DEFAULT 24 CHECK (prune_older_hours IN (0, 24, 72, 168, 720)),
    -- Notifications to the workspace's alert channels.
    ADD COLUMN notify_updates boolean NOT NULL DEFAULT false,
    ADD COLUMN notify_vulns text NOT NULL DEFAULT 'off' CHECK (notify_vulns IN ('off', 'critical', 'high')),
    ADD COLUMN notify_channels uuid[] NOT NULL DEFAULT '{}',
    -- What the volume backup dialog starts with; keep = manual copies kept per volume (0 = all).
    ADD COLUMN backup_storage_id uuid REFERENCES storages(id) ON DELETE SET NULL,
    ADD COLUMN backup_folder text NOT NULL DEFAULT '',
    ADD COLUMN backup_stop boolean NOT NULL DEFAULT false,
    ADD COLUMN backup_keep int NOT NULL DEFAULT 0 CHECK (backup_keep BETWEEN 0 AND 1000);

-- One server's own values for some settings; the rest come from its workspace.
CREATE TABLE docker_server_settings (
    server_id uuid PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    overrides jsonb NOT NULL DEFAULT '{}',
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- The last automatic clean-up of each server.
CREATE TABLE docker_auto_prunes (
    server_id uuid PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    ran_at timestamptz NOT NULL DEFAULT now(),
    space bigint NOT NULL DEFAULT 0,
    removed int NOT NULL DEFAULT 0,
    error text NOT NULL DEFAULT ''
);

-- +goose Down
DROP TABLE docker_auto_prunes;
DROP TABLE docker_server_settings;
ALTER TABLE docker_settings
    DROP COLUMN default_restart,
    DROP COLUMN default_memory_mb,
    DROP COLUMN default_cpus,
    DROP COLUMN default_log_max_mb,
    DROP COLUMN default_log_files,
    DROP COLUMN prune_auto,
    DROP COLUMN prune_hours,
    DROP COLUMN prune_images,
    DROP COLUMN prune_containers,
    DROP COLUMN prune_networks,
    DROP COLUMN prune_build_cache,
    DROP COLUMN prune_older_hours,
    DROP COLUMN notify_updates,
    DROP COLUMN notify_vulns,
    DROP COLUMN notify_channels,
    DROP COLUMN backup_storage_id,
    DROP COLUMN backup_folder,
    DROP COLUMN backup_stop,
    DROP COLUMN backup_keep;
