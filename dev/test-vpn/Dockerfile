# Dev fixture for Settings › VPN & tunnels: one gateway with every kind of
# way in, in front of a private network (10.77.0.0/24) that only it reaches.
#   WireGuard ...... udp 51820   client config: /out/wireguard.conf
#   OpenVPN ........ udp 1194, tcp 1195 (certificates)  /out/openvpn-udp.ovpn, /out/openvpn-tcp.ovpn
#   AnyConnect ..... ocserv on tcp/udp 4443, ant / colony (self-signed cert)
#   SOCKS5 ......... tcp 1080, ant / colony
#   HTTP proxy ..... tcp 3128, ant / colony
# The target behind it: 10.77.0.10:22, ant / colony (image mode "target").
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openvpn easy-rsa wireguard-tools \
      ocserv gnutls-bin dante-server tinyproxy iptables iproute2 openssl openssh-server procps \
 && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd \
 && useradd -m -s /bin/bash ant && echo 'ant:colony' | chpasswd \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
# Certificates are made once, at build time.
RUN set -eux; cd /etc/openvpn; cp -r /usr/share/easy-rsa pki-tool; cd pki-tool; \
    ./easyrsa --batch init-pki; ./easyrsa --batch --req-cn=morche-test build-ca nopass; \
    ./easyrsa --batch build-server-full server nopass; ./easyrsa --batch build-client-full client nopass; \
    openvpn --genkey secret /etc/openvpn/ta.key; \
    mkdir -p /etc/ocserv/certs; cd /etc/ocserv/certs; \
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=test-vpn" -keyout key.pem -out cert.pem; \
    printf 'colony\ncolony\n' | ocpasswd -c /etc/ocserv/passwd ant
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
