package tunnel

import (
	"strings"
	"testing"
)

func TestParseOpenVPN(t *testing.T) {
	base := "client\ndev tun\nremote vpn.example.com 1194\n<ca>\nup /bin/sh\n</ca>\n"
	f, err := ParseOpenVPN(base)
	if err != nil {
		t.Fatalf("inline block content isn't a directive: %v", err)
	}
	if len(f.Remotes) != 1 || f.Remotes[0] != "vpn.example.com" {
		t.Fatalf("remotes %v", f.Remotes)
	}
	refused := []string{
		"up /bin/sh", "--down x", "plugin /lib/x.so", "management 127.0.0.1 7505",
		"management-client-auth", "log /tmp/x", "ca /etc/shadow", "tls-auth /root/ta.key 1",
		"config other.ovpn", "daemon",
	}
	for _, line := range refused {
		if _, err := ParseOpenVPN(base + line + "\n"); err == nil {
			t.Errorf("%q was allowed", line)
		}
	}
	f, err = ParseOpenVPN(base + "auth-user-pass /etc/passwd\nsocks-proxy 1.2.3.4 1080\n")
	if err != nil || !f.NeedsLogin || strings.Contains(f.Text, "\nauth-user-pass") || strings.Contains(f.Text, "\nsocks-proxy") {
		t.Fatalf("dropped lines kept or login missed: %v %v", err, f.NeedsLogin)
	}
	if _, err := ParseOpenVPN("client\n"); err == nil {
		t.Error("a file without remote was allowed")
	}
	if _, err := ParseOpenVPN(base + "<key>\nx\n"); err == nil {
		t.Error("an unclosed block was allowed")
	}
}
