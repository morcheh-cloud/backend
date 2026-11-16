package api

import (
	"testing"

	"github.com/morche/backend/internal/proxy"
)

func TestManagedLogs(t *testing.T) {
	sites := []proxy.Site{
		{File: "/data/nginx/proxy_host/1.conf", Line: 1, Text: "server {\n  access_log /data/logs/proxy-host-1_access.log proxy;\n}"},
		{File: "/data/nginx/proxy_host/2.conf", Line: 1, Text: "server {\n  access_log /data/logs/shared.log;\n}"},
		{File: "/data/nginx/proxy_host/3.conf", Line: 1, Text: "server {\n  access_log /data/logs/shared.log;\n}"},
		{File: "/etc/nginx/conf.d/x.conf", Line: 1, Text: "server {\n  access_log /dev/stdout;\n}"},
		{File: "/etc/nginx/conf.d/y.conf", Line: 1, Text: "server {\n  access_log off;\n}"},
		{File: "/etc/nginx/morche/a.conf", Line: 1, Managed: true, Text: "access_log /var/log/a.log;"},
	}
	got := managedLogs(sites)
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	for _, l := range got {
		if l.path != "/data/logs/proxy-host-1_access.log" || l.file != "/data/nginx/proxy_host/1.conf" {
			t.Fatalf("got %+v", l)
		}
	}
}
