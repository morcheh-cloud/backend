#!/bin/sh
set -e
v=$(ls /etc/postgresql | sort -n | tail -1)
if [ ! -f /var/lib/postgresql/.morche-init ]; then
  pg_ctlcluster "$v" main start
  su postgres -c "psql -q" <<'SQL'
CREATE ROLE ant LOGIN SUPERUSER PASSWORD 'colony';
CREATE DATABASE shop OWNER ant;
\c shop
CREATE TABLE orders (id serial PRIMARY KEY, item text NOT NULL, at timestamptz NOT NULL DEFAULT now());
INSERT INTO orders (item) SELECT 'item ' || g FROM generate_series(1, 1000) g;
SQL
  pg_ctlcluster "$v" main stop
  touch /var/lib/postgresql/.morche-init
fi
socat TCP-LISTEN:9120,bind=127.0.0.1,reuseaddr,fork TCP:test-minio-tls:9000 &
# Its own sshd at the address Morche uses for it (127.0.0.1:2225), so an
# SFTP storage pointing here works from Morche and from this server alike.
socat TCP-LISTEN:2225,bind=127.0.0.1,reuseaddr,fork TCP:127.0.0.1:22 &
# Started once, like a server at boot; nothing starts it again behind a
# restore's back.
pg_ctlcluster "$v" main start || true
exec /usr/sbin/sshd -D
