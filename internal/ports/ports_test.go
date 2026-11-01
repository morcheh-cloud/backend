package ports

import (
	"os"
	"testing"
	"time"
)

func find(t *testing.T, r PortsReport, proto string, port int) OpenPort {
	t.Helper()
	for _, p := range r.Ports {
		if p.Protocol == proto && p.Port == port {
			return p
		}
	}
	t.Fatalf("%s/%d not found", proto, port)
	return OpenPort{}
}

// Rootless Docker on a desktop: rootlesskit holds the published ports.
func TestHostSS(t *testing.T) {
	data, err := os.ReadFile("testdata/host-ss.txt")
	if err != nil {
		t.Fatal(err)
	}
	r := Parse(string(data), time.Now())
	if r.Tool != "ss" || r.Privileged || r.Docker.Status != "ok" || r.Docker.Containers == 0 {
		t.Fatalf("header: %+v %+v", r.Tool, r.Docker)
	}

	pg := find(t, r, "tcp", 5432)
	if pg.Container == nil || pg.Container.Name != "gereft_pg" || pg.Container.ComposeService != "pg" {
		t.Fatalf("5432 container: %+v", pg.Container)
	}
	if pg.Service != "PostgreSQL" || !pg.Sensitive || pg.Exposure != "public" || len(pg.Addresses) != 2 {
		t.Fatalf("5432: %+v", pg)
	}

	chrome := find(t, r, "tcp", 3010)
	if chrome.Service != "browserless_chrome" || chrome.Container.TargetPort != 3000 {
		t.Fatalf("3010: %+v %+v", chrome, chrome.Container)
	}
	if local := find(t, r, "tcp", 5433); local.Exposure != "local" {
		t.Fatalf("5433 exposure: %s", local.Exposure)
	}
	// Owner hidden without root: only the port's usual service.
	if dns := find(t, r, "udp", 53); dns.Service != "DNS" || dns.ServiceSource != "port" || dns.Process != nil {
		t.Fatalf("53: %+v", dns)
	}
	if node := find(t, r, "tcp", 1337); node.Service != "Node.js · main" {
		t.Fatalf("1337: %q", node.Service)
	}
	if next := find(t, r, "tcp", 3200); next.Service != "next-server" {
		t.Fatalf("3200: %q", next.Service)
	}
}

// A root login with systemd, the classic docker-proxy and a host-network
// container.
const rootSS = `@priv 1
@tool ss
@sockets
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      511    0.0.0.0:80         0.0.0.0:*    users:(("nginx",pid=812,fd=6),("nginx",pid=811,fd=6))
tcp   LISTEN 0      511    [::]:80            [::]:*       users:(("nginx",pid=812,fd=7),("nginx",pid=811,fd=7))
tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=700,fd=3))
tcp   LISTEN 0      4096   0.0.0.0:6379       0.0.0.0:*    users:(("docker-proxy",pid=950,fd=4))
tcp   LISTEN 0      4096   10.0.0.5:9100      0.0.0.0:*    users:(("node_exporter",pid=1200,fd=3))
tcp   LISTEN 0      511    127.0.0.1:3000     0.0.0.0:*    users:(("node",pid=1300,fd=20))
@pid 700	sshd	root	sshd: /usr/sbin/sshd -D [listener]	0::/system.slice/ssh.service 
@pid 811	nginx	root	nginx: master process /usr/sbin/nginx	0::/system.slice/nginx.service 
@pid 812	nginx	www-data	nginx: worker process	0::/system.slice/nginx.service 
@pid 950	docker-proxy	root	/usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 6379	0::/system.slice/docker.service 
@pid 1200	node_exporter	nobody	/bin/node_exporter	0::/system.slice/docker-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.scope 
@pid 1300	node	app	node /srv/app/server.js	0::/system.slice/myapp.service 
@units
Id=nginx.service
Description=A high performance web server

Id=myapp.service
Description=My app
@docker ok docker
{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"/monitoring-node-exporter-1","image":"prom/node-exporter:v1.8.0","state":"running","network":"host","labels":{"com.docker.compose.project":"monitoring","com.docker.compose.service":"node-exporter"},"ports":{}}
{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","name":"/cache","image":"redis:7","state":"running","network":"bridge","labels":{},"ports":{"6379/tcp":[{"HostIp":"0.0.0.0","HostPort":"6379"}]}}
{"id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","name":"/api","image":"ghcr.io/acme/api:1.2","state":"running","network":"bridge","labels":{},"ports":{"8080/tcp":[{"HostIp":"","HostPort":"8081"}],"9999/tcp":null}}
`

func TestRootSS(t *testing.T) {
	r := Parse(rootSS, time.Now())
	if !r.Privileged || r.Docker.Containers != 3 {
		t.Fatalf("header: %+v", r)
	}

	web := find(t, r, "tcp", 80)
	if web.Service != "Nginx" || web.Unit == nil || web.Unit.Description != "A high performance web server" {
		t.Fatalf("80: %+v %+v", web, web.Unit)
	}
	if web.Process.PID != 811 || len(web.Process.PIDs) != 2 || web.Process.User != "root" || len(web.Addresses) != 2 {
		t.Fatalf("80 process: %+v %v", web.Process, web.Addresses)
	}

	redis := find(t, r, "tcp", 6379)
	if redis.Container == nil || redis.Container.Name != "cache" || redis.Unit != nil || redis.Service != "Redis" || !redis.Sensitive {
		t.Fatalf("6379: %+v", redis)
	}

	exp := find(t, r, "tcp", 9100)
	if exp.Container == nil || exp.Container.Network != "host" || exp.Service != "Node exporter" || exp.Exposure != "private" {
		t.Fatalf("9100: %+v %+v", exp, exp.Container)
	}

	app := find(t, r, "tcp", 3000)
	if app.Service != "myapp" || app.Exposure != "local" {
		t.Fatalf("3000: %+v", app)
	}

	// No socket on the host (userland proxy off): still listed.
	api := find(t, r, "tcp", 8081)
	if api.Container == nil || api.Container.TargetPort != 8080 || api.Exposure != "public" || api.Service != "api" {
		t.Fatalf("8081: %+v %+v", api, api.Container)
	}
	for _, p := range r.Ports {
		if p.Port == 9999 {
			t.Fatal("unpublished container port listed")
		}
	}
}

// Busybox netstat as a non-root user, docker installed but not allowed.
const busybox = `@priv 0
@tool netstat
@sockets
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:2222            0.0.0.0:*               LISTEN      194/sshd.pam
tcp        0      0 :::2222                 :::*                    LISTEN      194/sshd.pam
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      412/python3
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
@pid 194	sshd.pam	ant	sshd.pam: /usr/sbin/sshd.pam -D -e [listener]	0::/ 
@pid 412	python3	ant	python3 -m http.server --bind 127.0.0.1	0::/ 
@docker error docker permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock
`

func TestBusyboxNetstat(t *testing.T) {
	r := Parse(busybox, time.Now())
	if r.Tool != "netstat" || r.Docker.Status != "denied" || r.Docker.Runtime != "docker" {
		t.Fatalf("header: %+v", r)
	}
	ssh := find(t, r, "tcp", 2222)
	if len(ssh.Addresses) != 2 || ssh.Exposure != "public" || ssh.Service != "SSH" {
		t.Fatalf("2222: %+v", ssh)
	}
	if py := find(t, r, "tcp", 8000); py.Service != "Python · http.server" || py.Process.User != "ant" {
		t.Fatalf("8000: %+v", py)
	}
	if dhcp := find(t, r, "udp", 68); dhcp.Service != "DHCP client" {
		t.Fatalf("68: %+v", dhcp)
	}
}
