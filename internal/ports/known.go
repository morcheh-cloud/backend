package ports

import (
	"path"
	"regexp"
	"strings"
)

type known struct {
	name string
	// Shouldn't be reachable from the internet (databases, caches, remote
	// desktops, unauthenticated APIs…).
	sensitive bool
	// Says little about what actually runs there (8080 is "HTTP" for
	// anything); a container's own name is more useful.
	generic bool
}

// programs maps process names (as /proc/<pid>/comm shows them, so cut at
// 15 characters) and image names to the product they are.
var programs = map[string]known{
	"sshd":              {name: "SSH"},
	"dropbear":          {name: "SSH (Dropbear)"},
	"openssh-server":    {name: "SSH"},
	"nginx":             {name: "Nginx"},
	"apache2":           {name: "Apache"},
	"httpd":             {name: "Apache"},
	"caddy":             {name: "Caddy"},
	"traefik":           {name: "Traefik"},
	"haproxy":           {name: "HAProxy"},
	"envoy":             {name: "Envoy"},
	"lighttpd":          {name: "lighttpd"},
	"varnishd":          {name: "Varnish"},
	"squid":             {name: "Squid proxy"},
	"postgres":          {name: "PostgreSQL", sensitive: true},
	"postgresql":        {name: "PostgreSQL", sensitive: true},
	"postgis":           {name: "PostgreSQL (PostGIS)", sensitive: true},
	"timescaledb":       {name: "TimescaleDB", sensitive: true},
	"pgbouncer":         {name: "PgBouncer", sensitive: true},
	"mysqld":            {name: "MySQL", sensitive: true},
	"mysql":             {name: "MySQL", sensitive: true},
	"mariadbd":          {name: "MariaDB", sensitive: true},
	"mariadb":           {name: "MariaDB", sensitive: true},
	"redis-server":      {name: "Redis", sensitive: true},
	"redis":             {name: "Redis", sensitive: true},
	"redis-stack":       {name: "Redis", sensitive: true},
	"valkey-server":     {name: "Valkey", sensitive: true},
	"valkey":            {name: "Valkey", sensitive: true},
	"keydb-server":      {name: "KeyDB", sensitive: true},
	"mongod":            {name: "MongoDB", sensitive: true},
	"mongo":             {name: "MongoDB", sensitive: true},
	"mongodb":           {name: "MongoDB", sensitive: true},
	"memcached":         {name: "Memcached", sensitive: true},
	"elasticsearch":     {name: "Elasticsearch", sensitive: true},
	"opensearch":        {name: "OpenSearch", sensitive: true},
	"kibana":            {name: "Kibana"},
	"clickhouse-serv":   {name: "ClickHouse", sensitive: true},
	"clickhouse":        {name: "ClickHouse", sensitive: true},
	"clickhouse-server": {name: "ClickHouse", sensitive: true},
	"influxd":           {name: "InfluxDB", sensitive: true},
	"influxdb":          {name: "InfluxDB", sensitive: true},
	"couchdb":           {name: "CouchDB", sensitive: true},
	"cassandra":         {name: "Cassandra", sensitive: true},
	"rabbitmq":          {name: "RabbitMQ", sensitive: true},
	"rabbitmq-server":   {name: "RabbitMQ", sensitive: true},
	"kafka":             {name: "Kafka", sensitive: true},
	"zookeeper":         {name: "ZooKeeper", sensitive: true},
	"nats-server":       {name: "NATS"},
	"nats":              {name: "NATS"},
	"mosquitto":         {name: "MQTT (Mosquitto)"},
	"eclipse-mosquitto": {name: "MQTT (Mosquitto)"},
	"minio":             {name: "MinIO"},
	"etcd":              {name: "etcd", sensitive: true},
	"consul":            {name: "Consul"},
	"vault":             {name: "Vault"},
	"nomad":             {name: "Nomad"},
	"grafana":           {name: "Grafana"},
	"grafana-server":    {name: "Grafana"},
	"prometheus":        {name: "Prometheus"},
	"alertmanager":      {name: "Alertmanager"},
	"node_exporter":     {name: "Node exporter"},
	"node-exporter":     {name: "Node exporter"},
	"cadvisor":          {name: "cAdvisor"},
	"loki":              {name: "Loki"},
	"promtail":          {name: "Promtail"},
	"jaeger":            {name: "Jaeger"},
	"zabbix_agentd":     {name: "Zabbix agent"},
	"zabbix_server":     {name: "Zabbix server"},
	"netdata":           {name: "Netdata"},
	"dockerd":           {name: "Docker daemon", sensitive: true},
	"containerd":        {name: "containerd"},
	"kubelet":           {name: "Kubelet", sensitive: true},
	"kube-apiserver":    {name: "Kubernetes API"},
	"kube-proxy":        {name: "kube-proxy"},
	"k3s":               {name: "k3s"},
	"k3s-server":        {name: "k3s"},
	"systemd-resolve":   {name: "DNS resolver (systemd-resolved)"},
	"systemd-resolved":  {name: "DNS resolver (systemd-resolved)"},
	"dnsmasq":           {name: "dnsmasq (DNS/DHCP)"},
	"named":             {name: "BIND DNS"},
	"unbound":           {name: "Unbound DNS"},
	"coredns":           {name: "CoreDNS"},
	"pihole-ftl":        {name: "Pi-hole"},
	"adguardhome":       {name: "AdGuard Home"},
	"chronyd":           {name: "NTP (chrony)"},
	"ntpd":              {name: "NTP"},
	"systemd-timesyn":   {name: "NTP (systemd-timesyncd)"},
	"cupsd":             {name: "CUPS printing"},
	"avahi-daemon":      {name: "mDNS (Avahi)"},
	"rpcbind":           {name: "RPC portmapper", sensitive: true},
	"rpc.statd":         {name: "NFS status", sensitive: true},
	"rpc.mountd":        {name: "NFS mount", sensitive: true},
	"smbd":              {name: "Samba (SMB)", sensitive: true},
	"nmbd":              {name: "Samba NetBIOS", sensitive: true},
	"exim4":             {name: "Exim (SMTP)"},
	"exim":              {name: "Exim (SMTP)"},
	"dovecot":           {name: "Dovecot (IMAP/POP3)"},
	"vsftpd":            {name: "FTP (vsftpd)", sensitive: true},
	"proftpd":           {name: "FTP (ProFTPD)", sensitive: true},
	"pure-ftpd":         {name: "FTP (Pure-FTPd)", sensitive: true},
	"openvpn":           {name: "OpenVPN"},
	"tailscaled":        {name: "Tailscale"},
	"zerotier-one":      {name: "ZeroTier"},
	"cockpit-ws":        {name: "Cockpit"},
	"miniserv.pl":       {name: "Webmin"},
	"xrdp":              {name: "Remote desktop (xrdp)", sensitive: true},
	"x11vnc":            {name: "VNC", sensitive: true},
	"Xvnc":              {name: "VNC", sensitive: true},
	"php-fpm":           {name: "PHP-FPM"},
	"gunicorn":          {name: "Gunicorn"},
	"uvicorn":           {name: "Uvicorn"},
	"puma":              {name: "Puma"},
	"unicorn":           {name: "Unicorn"},
	"uwsgi":             {name: "uWSGI"},
	"gitea":             {name: "Gitea"},
	"forgejo":           {name: "Forgejo"},
	"code-server":       {name: "code-server"},
	"jupyter-lab":       {name: "JupyterLab"},
	"portainer":         {name: "Portainer"},
	"wordpress":         {name: "WordPress"},
	"nextcloud":         {name: "Nextcloud"},
	"sonarqube":         {name: "SonarQube"},
	"jenkins":           {name: "Jenkins"},
	"registry":          {name: "Docker registry"},
	"n8n":               {name: "n8n"},
	"keycloak":          {name: "Keycloak"},
	"mailhog":           {name: "MailHog"},
	"mailpit":           {name: "Mailpit"},
	"adminer":           {name: "Adminer"},
	"phpmyadmin":        {name: "phpMyAdmin"},
	"pgadmin4":          {name: "pgAdmin"},
}

// interpreters run someone else's program; the script they run (or the
// unit that starts them) says more than "node".
var interpreters = map[string]string{
	"node":     "Node.js",
	"nodejs":   "Node.js",
	"bun":      "Bun",
	"deno":     "Deno",
	"python":   "Python",
	"java":     "Java",
	"ruby":     "Ruby",
	"php":      "PHP",
	"perl":     "Perl",
	"dotnet":   ".NET",
	"beam.smp": "Erlang",
}

// wellKnown is what a port usually carries, for sockets whose process we
// can't see (and containers whose image we don't recognise).
var wellKnown = map[string]known{
	"tcp/20":    {name: "FTP data", sensitive: true},
	"tcp/21":    {name: "FTP", sensitive: true},
	"tcp/22":    {name: "SSH"},
	"tcp/23":    {name: "Telnet", sensitive: true},
	"tcp/25":    {name: "SMTP"},
	"tcp/53":    {name: "DNS"},
	"udp/53":    {name: "DNS"},
	"udp/67":    {name: "DHCP server"},
	"udp/68":    {name: "DHCP client"},
	"udp/69":    {name: "TFTP", sensitive: true},
	"tcp/80":    {name: "HTTP", generic: true},
	"tcp/110":   {name: "POP3"},
	"tcp/111":   {name: "RPC portmapper", sensitive: true},
	"udp/111":   {name: "RPC portmapper", sensitive: true},
	"udp/123":   {name: "NTP"},
	"udp/137":   {name: "NetBIOS name", sensitive: true},
	"udp/138":   {name: "NetBIOS datagram", sensitive: true},
	"tcp/139":   {name: "NetBIOS session", sensitive: true},
	"tcp/143":   {name: "IMAP"},
	"udp/161":   {name: "SNMP", sensitive: true},
	"tcp/389":   {name: "LDAP", sensitive: true},
	"tcp/443":   {name: "HTTPS", generic: true},
	"udp/443":   {name: "HTTP/3 (QUIC)", generic: true},
	"tcp/445":   {name: "SMB", sensitive: true},
	"tcp/465":   {name: "SMTP over TLS"},
	"udp/514":   {name: "Syslog"},
	"tcp/587":   {name: "SMTP submission"},
	"tcp/631":   {name: "CUPS printing"},
	"tcp/636":   {name: "LDAP over TLS"},
	"tcp/853":   {name: "DNS over TLS"},
	"tcp/873":   {name: "rsync", sensitive: true},
	"tcp/993":   {name: "IMAP over TLS"},
	"tcp/995":   {name: "POP3 over TLS"},
	"udp/1194":  {name: "OpenVPN"},
	"tcp/1433":  {name: "SQL Server", sensitive: true},
	"tcp/1521":  {name: "Oracle DB", sensitive: true},
	"tcp/1883":  {name: "MQTT"},
	"tcp/2049":  {name: "NFS", sensitive: true},
	"tcp/2375":  {name: "Docker API (no TLS)", sensitive: true},
	"tcp/2376":  {name: "Docker API", sensitive: true},
	"tcp/2379":  {name: "etcd", sensitive: true},
	"tcp/2380":  {name: "etcd peers", sensitive: true},
	"tcp/3000":  {name: "Web app", generic: true},
	"tcp/3306":  {name: "MySQL", sensitive: true},
	"tcp/3389":  {name: "Remote desktop (RDP)", sensitive: true},
	"udp/3478":  {name: "STUN/TURN"},
	"tcp/4222":  {name: "NATS"},
	"tcp/5000":  {name: "Web app", generic: true},
	"udp/5353":  {name: "mDNS"},
	"tcp/5432":  {name: "PostgreSQL", sensitive: true},
	"tcp/5601":  {name: "Kibana"},
	"tcp/5672":  {name: "RabbitMQ", sensitive: true},
	"tcp/5900":  {name: "VNC", sensitive: true},
	"tcp/5984":  {name: "CouchDB", sensitive: true},
	"tcp/6379":  {name: "Redis", sensitive: true},
	"tcp/6443":  {name: "Kubernetes API"},
	"tcp/8000":  {name: "Web app", generic: true},
	"tcp/8080":  {name: "HTTP (alternate)", generic: true},
	"tcp/8086":  {name: "InfluxDB", sensitive: true},
	"tcp/8443":  {name: "HTTPS (alternate)", generic: true},
	"tcp/8888":  {name: "Web app", generic: true},
	"tcp/9000":  {name: "Web app", generic: true},
	"tcp/9042":  {name: "Cassandra", sensitive: true},
	"tcp/9090":  {name: "Prometheus"},
	"tcp/9092":  {name: "Kafka", sensitive: true},
	"tcp/9093":  {name: "Alertmanager"},
	"tcp/9100":  {name: "Node exporter"},
	"tcp/9200":  {name: "Elasticsearch", sensitive: true},
	"tcp/9300":  {name: "Elasticsearch nodes", sensitive: true},
	"tcp/10250": {name: "Kubelet", sensitive: true},
	"tcp/11211": {name: "Memcached", sensitive: true},
	"udp/11211": {name: "Memcached", sensitive: true},
	"tcp/15672": {name: "RabbitMQ management"},
	"tcp/27017": {name: "MongoDB", sensitive: true},
	"udp/51820": {name: "WireGuard"},
}

var versionSuffix = regexp.MustCompile(`[\d.]+$`)

// program looks a process or image name up, ignoring a version suffix
// (php-fpm8.2, python3.12) or a build suffix (sshd.pam).
func program(name string) (known, bool) {
	if k, ok := programs[name]; ok {
		return k, true
	}
	name = strings.ToLower(versionSuffix.ReplaceAllString(name, ""))
	if k, ok := programs[name]; ok {
		return k, true
	}
	if base, _, ok := strings.Cut(name, "."); ok {
		k, ok := programs[base]
		return k, ok
	}
	return known{}, false
}

func interpreter(name string) (string, bool) {
	label, ok := interpreters[strings.ToLower(versionSuffix.ReplaceAllString(name, ""))]
	return label, ok
}

// imageName is the bare name of an image reference:
// registry.example.com/library/postgres:18 → postgres.
func imageName(ref string) string {
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	ref = path.Base(ref)
	if i := strings.IndexByte(ref, ':'); i >= 0 {
		ref = ref[:i]
	}
	return ref
}
