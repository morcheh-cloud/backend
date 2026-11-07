#!/bin/sh
# Applies the schema, then hands over to the server. Anything other than the
# server (a shell, `server reset-admin`) runs as given.
set -eu

case "${1:-server}" in
  server)
    shift || true
    # A subcommand (reset-admin…) talks to an existing schema: no migration.
    if [ "$#" -eq 0 ] && [ "${MIGRATE_ON_START:-true}" != "false" ]; then
      echo "applying database migrations"
      goose -dir /app/migrations postgres "$DATABASE_URL" up
    fi
    exec server "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
