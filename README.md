# Morcheh — Backend

API for Morcheh (SSH-based server management and monitoring). Development setup and commands are in `CLAUDE.md` (`make up`, `make run`).

## Locked out of the admin account

`reset-admin` sets a new password on an admin account, unblocks it and signs it out everywhere. It talks to the database directly, so it works when nobody can sign in to the panel. The server can stay running.

### In production (Docker)

Run it inside the running backend container:

```bash
docker exec -it <container> /proc/1/exe reset-admin
```

- `<container>` is the backend container's name or id (`docker ps`). With Compose: `docker compose exec backend /proc/1/exe reset-admin` (use your service name).
- `/proc/1/exe` is the binary the container is running, so you don't need to know where the image put it. This works when the server is the container's main process (`ENTRYPOINT ["/path/to/server"]`). If PID 1 is a shell or an init such as tini, use the binary's real path instead: `docker exec -it <container> /path/to/server reset-admin`.
- It uses the container's own environment (`DATABASE_URL`, `REDIS_URL`, `SECRETS_KEY`), so there is nothing to configure.
- Keep `-it`: the new password is asked for twice. Without a terminal, give it on one line of stdin: `printf '%s\n' "$NEW_PASSWORD" | docker exec -i <container> /proc/1/exe reset-admin`. The password is never a flag, so it stays out of the shell history and the process list.

Flags:

| Flag | |
|---|---|
| `-user alice` | which admin, needed only when there are several (the error lists them) |
| `-rename bob` | also change the username |
| `-temporary` | make them choose a new password at next sign-in |

```bash
docker exec -it <container> /proc/1/exe reset-admin -user alice -temporary
```

The password must be at least 12 characters. Open terminals and streams of that account end within a minute. If Redis can't be reached, the password still changes but a recent sign-in lockout can last up to 15 minutes.

### On a dev machine

```bash
make reset-admin                     # or: make reset-admin args="-user alice -temporary"
bin/server reset-admin -h            # all flags
```
