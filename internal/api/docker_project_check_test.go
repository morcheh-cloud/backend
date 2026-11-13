package api

import "testing"

func TestReadComposeJSON(t *testing.T) {
	text := `{"name":"x","services":{"web":{"image":"nginx","ports":[{"mode":"ingress","target":80,"published":"8080","protocol":"tcp"}]},"db":{"build":{"context":"."},"ports":[{"target":53,"published":"5300-5301","protocol":"udp"}]}}}`
	svcs, ports := readComposeJSON(text)
	if len(svcs) != 2 || svcs[0].Name != "db" || !svcs[0].Build || svcs[1].Image != "nginx" {
		t.Fatalf("services = %+v", svcs)
	}
	if len(ports) != 2 || ports[1].Published != "8080" || ports[1].Target != "80" || ports[0].Published != "5300-5301" || ports[0].Protocol != "udp" {
		t.Fatalf("ports = %+v", ports)
	}
}

func TestListeningPorts(t *testing.T) {
	m := listeningPorts("tcp 0.0.0.0:22\ntcp [::]:8080\nudp 127.0.0.53%lo:53\n")
	for _, k := range []string{"tcp/22", "tcp/8080", "udp/53"} {
		if !m[k] {
			t.Errorf("missing %s in %v", k, m)
		}
	}
	if got := portRange("8000-8002"); len(got) != 3 || got[2] != 8002 {
		t.Errorf("portRange = %v", got)
	}
}
