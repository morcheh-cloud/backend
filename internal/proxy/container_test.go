package proxy

import (
	"strings"
	"testing"
)

const edgeInspect = `[{
  "Id": "0123456789abcdef0123",
  "Name": "/edge",
  "State": {"Status": "running", "Running": true, "Pid": 4242},
  "Config": {"Image": "nginx:1.29", "Labels": {"com.docker.compose.project": "web", "com.docker.compose.service": "edge"}},
  "HostConfig": {"NetworkMode": "apps", "RestartPolicy": {"Name": "unless-stopped"}},
  "NetworkSettings": {
    "Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8081"}, {"HostIp": "::", "HostPort": "8081"}], "443/udp": [{"HostIp": "0.0.0.0", "HostPort": "8444"}]},
    "Networks": {"apps": {"IPAddress": "172.20.0.3", "Gateway": "172.20.0.1", "Aliases": ["edge", "0123456789ab"]}}
  },
  "Mounts": [{"Type": "bind", "Source": "/srv/www", "Destination": "/usr/share/nginx/html", "RW": false}]
}, {
  "Id": "fedcba9876543210",
  "Name": "/npm",
  "State": {"Status": "exited", "Running": false, "Pid": 0},
  "Config": {"Image": "jc21/nginx-proxy-manager:latest"},
  "HostConfig": {"NetworkMode": "default", "PortBindings": {"80/tcp": [{"HostPort": "80"}]}},
  "NetworkSettings": {"Ports": {}, "Networks": {}}
}]`

func TestParseDetect(t *testing.T) {
	out := "native 1.24.0\nnative_running\ndown podman\nruntime docker\n@@inspect docker\n" + edgeInspect + "\n@@end\n"
	d := ParseDetect(out)
	if !d.Native.Installed || !d.Native.Running || d.Native.Version != "1.24.0" {
		t.Fatalf("native = %+v", d.Native)
	}
	if len(d.Runtimes) != 1 || d.Runtimes[0] != "docker" || len(d.Down) != 1 || d.Down[0] != "podman" {
		t.Fatalf("runtimes = %v, down = %v", d.Runtimes, d.Down)
	}
	if len(d.Containers) != 2 {
		t.Fatalf("containers = %d", len(d.Containers))
	}
	edge, npm := d.Containers[0], d.Containers[1]
	if edge.Name != "edge" || !edge.Running || edge.Pid != 4242 || edge.ID != "0123456789ab" || edge.Compose != "web" {
		t.Fatalf("edge = %+v", edge)
	}
	if !edge.Published(80, "tcp") || edge.Published(443, "tcp") || !edge.Published(443, "udp") || len(edge.Ports) != 2 {
		t.Fatalf("edge ports = %+v", edge.Ports)
	}
	if got := edge.InsidePath("/srv/www/site"); got != "/usr/share/nginx/html/site" {
		t.Fatalf("InsidePath = %q", got)
	}
	if edge.InsidePath("/srv/other") != "" {
		t.Fatal("a folder outside every mount maps to nothing")
	}
	if len(edge.Networks) != 1 || edge.Networks[0].Gateway != "172.20.0.1" || len(edge.Networks[0].Aliases) != 1 {
		t.Fatalf("edge networks = %+v", edge.Networks)
	}
	if npm.Managed != "Nginx Proxy Manager" || npm.Running || npm.NetworkMode != "bridge" || !npm.Published(80, "tcp") {
		t.Fatalf("npm = %+v", npm)
	}
}

func TestParseDetectNothing(t *testing.T) {
	d := ParseDetect("")
	if d.Native.Installed || len(d.Runtimes) != 0 || len(d.Containers) != 0 {
		t.Fatalf("d = %+v", d)
	}
}

func TestContainerScripts(t *testing.T) {
	c := Container{Runtime: RuntimeDocker, Name: "edge"}
	run := c.Run("nginx -t\n")
	if !strings.Contains(run, "docker exec") || !strings.Contains(run, "nginx -t") {
		t.Fatalf("Run = %s", run)
	}
	if !strings.Contains(c.Host("restart @"), "restart 'edge'") && !strings.Contains(c.Host("restart @"), "restart edge") {
		t.Fatalf("Host = %s", c.Host("restart @"))
	}
	if !ValidContainerName("edge_1.a-b") || ValidContainerName("a b") || ValidContainerName("-x") || ValidContainerName("") {
		t.Fatal("ValidContainerName")
	}
}
