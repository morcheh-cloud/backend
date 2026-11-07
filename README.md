# Morcheh — Backend

API for Morcheh (SSH-based server management and monitoring). Development setup and commands are in `CLAUDE.md` (`make up`, `make run`).

## Running with Docker

The `Dockerfile` builds the server together with every tool it drives from its own machine: ssh/sshpass and Ansible (with bubblewrap) for playbooks, and the database clients for backups that run on the Morcheh server (`pg_dump` 18, `mariadb-dump`/`mariadb-binlog`, `mongodump`, `redis-cli`). Migrations are applied on start (`MIGRATE_ON_START=false` to skip).

The whole stack (Postgres, Redis, backend, panel) is in `deploy/`. It expects the frontend repository next to this one (`../frontend`):

```bash
cd deploy
cp .env.example .env      # PANEL_URL, API_URL, passwords, SECRETS_KEY, SETUP_TOKEN
docker compose up -d --build
```

- The panel calls the backend from the browser, so `API_URL` must be the address people's browsers reach the backend at. It's baked into the panel image: run `docker compose build frontend` after changing it.
- Behind https set `COOKIE_INSECURE=false`; on plain http it must be `true`, or signing in doesn't stick.
- Keep a copy of `SECRETS_KEY`: every saved password and key is sealed with it.
- Ansible's sandbox (bubblewrap) needs user namespaces, which Docker's default profiles refuse. Without the `security_opt` lines in `compose.yml` playbooks still run, but only system admins can start them.

## Locked out of the admin account

`reset-admin` sets a new password on an admin account, unblocks it and signs it out everywhere. It talks to the database directly, so it works when nobody can sign in to the panel. The server can stay running.

### In production (Docker)

Run it inside the running backend container:

```bash
docker compose exec backend server reset-admin        # deploy/compose.yml
docker exec -it <container> server reset-admin        # any other setup
```

- `server` is on the image's PATH. With an image of your own where the server is the container's main process, `/proc/1/exe reset-admin` reaches it without knowing its path.
- It uses the container's own environment (`DATABASE_URL`, `REDIS_URL`, `SECRETS_KEY`), so there is nothing to configure.
- Keep a terminal (`-it`, Compose gives one): the new password is asked for twice. Without one, give it on one line of stdin: `printf '%s\n' "$NEW_PASSWORD" | docker compose exec -T backend server reset-admin`. The password is never a flag, so it stays out of the shell history and the process list.

Flags:

| Flag | |
|---|---|
| `-user alice` | which admin, needed only when there are several (the error lists them) |
| `-rename bob` | also change the username |
| `-temporary` | make them choose a new password at next sign-in |

```bash
docker compose exec backend server reset-admin -user alice -temporary
```

The password must be at least 12 characters. Open terminals and streams of that account end within a minute. If Redis can't be reached, the password still changes but a recent sign-in lockout can last up to 15 minutes.

### On a dev machine

```bash
make reset-admin                     # or: make reset-admin args="-user alice -temporary"
bin/server reset-admin -h            # all flags
```
