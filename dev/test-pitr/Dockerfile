# Dev target for PostgreSQL continuous backup (PITR): Debian's own
# PostgreSQL (pg_ctlcluster, /etc/postgresql, a dedicated config like a real
# server), sshd, and a sudo user. pgBackRest isn't installed: Morche's setup
# installs it, as it would on a real server.
#   ops / colony — passwordless sudo (Morche's SSH login)
#   PostgreSQL 17 on 5432 inside; database shop, login ant / colony
# 127.0.0.1:9120 inside forwards to test-minio-tls:9000, so the storage
# address https://127.0.0.1:9120 works from Morche and from this server;
# 127.0.0.1:2225 inside is its own sshd, for an SFTP storage the same way.
FROM debian:trixie
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      postgresql postgresql-contrib openssh-server sudo procps iproute2 socat ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /bin/bash ops && echo 'ops:colony' | chpasswd \
 && echo 'ops ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/ops \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/; s/^#\?AllowTcpForwarding.*/AllowTcpForwarding yes/' /etc/ssh/sshd_config \
 && mkdir -p /run/sshd
COPY entrypoint.sh /usr/local/bin/test-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/test-entrypoint.sh"]
