#!/bin/bash
set -e
if [ "$1" = "target" ]; then
  ssh-keygen -A >/dev/null
  exec /usr/sbin/sshd -D -e
fi
mkdir -p /out /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
LAN=10.77.0.0/24
iptables -t nat -A POSTROUTING -d $LAN -j MASQUERADE

# ---- WireGuard ----
umask 077
if [ ! -f /out/server.key ]; then
  wg genkey > /out/server.key; wg pubkey < /out/server.key > /out/server.pub
  wg genkey > /out/client.key; wg pubkey < /out/client.key > /out/client.pub
fi
ip link add wg0 type wireguard
# (wg can't fopen key files in a container: pass the config on stdin)
printf "[Interface]\nPrivateKey = %s\nListenPort = 51820\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.66.0.2/32\n" \
  "$(cat /out/server.key)" "$(cat /out/client.pub)" | wg setconf wg0 /dev/stdin
umask 022
ip addr add 10.66.0.1/24 dev wg0 && ip link set wg0 up
cat > /out/wireguard.conf <<WG
[Interface]
PrivateKey = $(cat /out/client.key)
Address = 10.66.0.2/32

[Peer]
PublicKey = $(cat /out/server.pub)
Endpoint = 127.0.0.1:51820
AllowedIPs = 10.77.0.0/24, 10.66.0.0/24
WG

# ---- OpenVPN ----
P=/etc/openvpn/pki-tool/pki
for proto in udp tcp; do
  port=1194; dev=tun1; net=10.88.0.0; [ $proto = tcp ] && port=1195 dev=tun2 net=10.89.0.0
  openvpn --daemon --proto $proto --port $port --dev $dev --server $net 255.255.255.0 \
    --ca $P/ca.crt --cert $P/issued/server.crt --key $P/private/server.key --dh none \
    --tls-auth /etc/openvpn/ta.key 0 --push "route 10.77.0.0 255.255.255.0" \
    --push "dhcp-option DNS 10.77.0.2" --keepalive 10 60 --verb 3 --log /var/log/openvpn-$proto.log
  { echo client; echo dev tun; echo "proto $proto"; echo "remote 127.0.0.1 $port"; echo nobind
    echo remote-cert-tls server; echo key-direction 1; echo verb 3
    echo "<ca>"; cat $P/ca.crt; echo "</ca>"; echo "<cert>"; openssl x509 -in $P/issued/client.crt; echo "</cert>"
    echo "<key>"; cat $P/private/client.key; echo "</key>"; echo "<tls-auth>"; cat /etc/openvpn/ta.key; echo "</tls-auth>"
  } > /out/openvpn-$proto.ovpn
done

# ---- ocserv (AnyConnect) ----
cat > /etc/ocserv/ocserv.conf <<OC
auth = "plain[passwd=/etc/ocserv/passwd]"
tcp-port = 4443
udp-port = 4443
socket-file = /run/ocserv.socket
server-cert = /etc/ocserv/certs/cert.pem
server-key = /etc/ocserv/certs/key.pem
max-clients = 16
device = vpns
ipv4-network = 10.99.0.0
ipv4-netmask = 255.255.255.0
route = 10.77.0.0/255.255.255.0
dns = 10.77.0.2
isolate-workers = false
cookie-timeout = 300
OC
ocserv -c /etc/ocserv/ocserv.conf

# ---- SOCKS5 (dante) ----
OUT=$(ip -4 route get 10.77.0.10 | grep -o 'dev [^ ]*' | cut -d' ' -f2)
cat > /etc/danted.conf <<SD
logoutput: stderr
internal: 0.0.0.0 port = 1080
external: $OUT
socksmethod: username
user.privileged: root
user.notprivileged: nobody
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }
SD
danted -D -f /etc/danted.conf

# ---- HTTP proxy ----
cat > /etc/tinyproxy/tinyproxy.conf <<TP
Port 3128
Listen 0.0.0.0
Timeout 600
BasicAuth ant colony
Allow 0.0.0.0/0
TP
tinyproxy -c /etc/tinyproxy/tinyproxy.conf

echo "test-vpn ready"
exec tail -F /var/log/openvpn-udp.log /var/log/openvpn-tcp.log
