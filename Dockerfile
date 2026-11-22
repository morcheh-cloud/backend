# syntax=docker/dockerfile:1
#
# Morche backend: the API server plus every tool the panel drives from this
# machine. Build: docker build -t morche-backend .
#
#   ssh, sshpass ........ Ansible runs (key and password logins)
#   ansible ............. playbooks, the module catalogue (ansible-doc) and the
#                         usual collections (community.general, ansible.posix…)
#   bubblewrap .......... sandbox around playbook runs (needs user namespaces,
#                         see deploy/compose.yml)
#   postgresql-client-18  backups/restores of PostgreSQL run here by default
#   mariadb-client ...... MySQL/MariaDB: mariadb-dump, mariadb, mariadb-binlog
#   mongodb tools ....... mongodump, mongorestore
#   redis-tools ......... redis-cli (RDB snapshots)
#   clickhouse .......... clickhouse-client (ClickHouse backups/restores); the
#                         official server image's single binary, ~700 MB
#                         unpacked (most of the image's size)
#   goose + migrations .. the schema, applied on start (MIGRATE_ON_START)

ARG GO_VERSION=1.27
ARG UBUNTU_VERSION=24.04
# An LTS line; the client reads any server version near it.
ARG CLICKHOUSE_VERSION=25.8

# ---- ClickHouse client --------------------------------------------------------
# The one binary is the server, client and tools; only the client is used.
FROM clickhouse/clickhouse-server:${CLICKHOUSE_VERSION} AS clickhouse

# ---- build ------------------------------------------------------------------
FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags="-s -w" -o /out/server ./cmd/server && \
    go build -ldflags="-s -w" -o /out/goose github.com/pressly/goose/v3/cmd/goose

# ---- runtime ----------------------------------------------------------------
FROM ubuntu:${UBUNTU_VERSION}
LABEL org.opencontainers.image.source=https://github.com/morcheh-cloud/backend \
      org.opencontainers.image.title="Morche backend" \
      org.opencontainers.image.description="API for Morche: SSH-based server management and monitoring"
ARG UBUNTU_VERSION
ARG PG_CLIENT=18
ARG MONGO_SERIES=8.0
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 LC_ALL=C.UTF-8

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg postgresql-common; \
    . /etc/os-release; \
    install -d -m 0755 /etc/apt/keyrings; \
    # PostgreSQL's own repository: pg_dump must be as new as the server. Its
    # key ships with Ubuntu's postgresql-common (no download that can flake).
    gpg --dearmor -o /etc/apt/keyrings/pgdg.gpg \
      /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc; \
    echo "deb [signed-by=/etc/apt/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" \
      > /etc/apt/sources.list.d/pgdg.list; \
    # MongoDB's repository, for mongodump/mongorestore.
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 3 \
      -o /tmp/mongodb.asc "https://pgp.mongodb.com/server-${MONGO_SERIES}.asc"; \
    gpg --dearmor -o /etc/apt/keyrings/mongodb.gpg /tmp/mongodb.asc; \
    rm /tmp/mongodb.asc; \
    echo "deb [signed-by=/etc/apt/keyrings/mongodb.gpg] https://repo.mongodb.org/apt/ubuntu ${VERSION_CODENAME}/mongodb-org/${MONGO_SERIES} multiverse" \
      > /etc/apt/sources.list.d/mongodb.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      tini tzdata openssh-client sshpass bubblewrap \
      ansible python3-jmespath python3-netaddr \
      "postgresql-client-${PG_CLIENT}" \
      mariadb-client \
      mongodb-database-tools \
      redis-tools \
      gzip coreutils findutils procps less iputils-ping netcat-openbsd; \
    apt-get purge -y --auto-remove gnupg postgresql-common; \
    rm -rf /var/lib/apt/lists/*; \
    # Every tool the panel looks for has to be there.
    for t in ssh sshpass bwrap ansible-playbook ansible-doc pg_dump pg_dumpall \
      pg_restore psql mariadb-dump mariadb mariadb-binlog mongodump mongorestore \
      redis-cli tar; do command -v "$t" >/dev/null || { echo "missing: $t"; exit 1; }; done

COPY --from=build /out/server /out/goose /usr/local/bin/
COPY --from=clickhouse /usr/bin/clickhouse /usr/local/bin/clickhouse
RUN ln -s clickhouse /usr/local/bin/clickhouse-client && \
    clickhouse-client --version
COPY migrations /app/migrations
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# A plain user: nothing the server or its tools run needs root here.
RUN useradd --create-home --uid 10001 --user-group --shell /bin/sh morche && \
    install -d -o morche -g morche /home/morche/log-archives && \
    chmod 0755 /usr/local/bin/docker-entrypoint.sh
USER morche
WORKDIR /home/morche

ENV APP_ENV=production \
    HTTP_ADDR=:8080 \
    MIGRATE_ON_START=true \
    ANSIBLE_PLAYBOOK=ansible-playbook \
    ANSIBLE_SANDBOX=auto
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS http://127.0.0.1:${HTTP_ADDR##*:}/health >/dev/null || exit 1

# tini reaps what ansible and ssh leave behind (ssh's ControlPersist masters).
ENTRYPOINT ["tini", "--", "docker-entrypoint.sh"]
CMD ["server"]
