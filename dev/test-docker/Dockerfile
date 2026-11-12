# Dev target for the Containers section: Docker in Docker reached over SSH.
#   ant / colony  — in the docker group (Morche talks to the socket directly)
#   ops / colony  — not in the group, passwordless sudo (the dial-stdio path)
FROM docker:29-dind
RUN apk add --no-cache openssh-server sudo bash \
 && addgroup -S docker 2>/dev/null; \
    adduser -D -s /bin/bash ant && echo 'ant:colony' | chpasswd && addgroup ant docker \
 && adduser -D -s /bin/bash ops && echo 'ops:colony' | chpasswd \
 && echo 'ops ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/ops \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/; s/^#\?AllowTcpForwarding.*/AllowTcpForwarding yes/' /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/bin/test-entrypoint.sh
ENV DOCKER_TLS_CERTDIR=
ENTRYPOINT ["/usr/local/bin/test-entrypoint.sh"]
