package tunnel

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Against the dev fixture (docker compose up test-vpn test-vpn-target):
// MORCHE_VPN_FIXTURE=1 MORCHE_TUNNEL_EXE=<built cmd/server> go test ./internal/tunnel -run Fixture -v
func fixture(t *testing.T) *Manager {
	if os.Getenv("MORCHE_VPN_FIXTURE") == "" {
		t.Skip("set MORCHE_VPN_FIXTURE=1 with the test-vpn containers up")
	}
	return New(Options{Executable: os.Getenv("MORCHE_TUNNEL_EXE")})
}

func fixtureFile(t *testing.T, name string) string {
	out, err := exec.Command("docker", "compose", "exec", "-T", "test-vpn", "cat", "/out/"+name).Output()
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(out)
}

const target = "10.77.0.10:22"

func reachSSH(t *testing.T, m *Manager, s Spec) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res := m.Test(ctx, s, target)
	for _, l := range res.Log {
		t.Log(l.Text)
	}
	if !res.Reached {
		t.Fatalf("test: %s", res.Message)
	}
	c, err := m.Dial(ctx, s, "tcp", target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "SSH-") {
		t.Fatalf("banner %q %v", line, err)
	}
	st, _ := m.State(s.ID)
	t.Logf("banner %q state %+v", strings.TrimSpace(line), st)
	m.Close(s.ID)
}

func TestFixtureSOCKS(t *testing.T) {
	m := fixture(t)
	reachSSH(t, m, Spec{ID: "socks", Kind: KindSOCKS5, Config: Config{Host: "127.0.0.1", Port: 1080, Username: "ant"}, Secrets: Secrets{Password: "colony"}})
}

func TestFixtureHTTP(t *testing.T) {
	m := fixture(t)
	reachSSH(t, m, Spec{ID: "http", Kind: KindHTTP, Config: Config{Host: "127.0.0.1", Port: 3128, Username: "ant"}, Secrets: Secrets{Password: "colony"}})
}

func TestFixtureWireGuard(t *testing.T) {
	m := fixture(t)
	conf := fixtureFile(t, "wireguard.conf")
	get := func(k string) string {
		for _, l := range strings.Split(conf, "\n") {
			if v, ok := strings.CutPrefix(l, k+" = "); ok {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}
	reachSSH(t, m, Spec{ID: "wg", Kind: KindWireGuard, Config: Config{
		Addresses: []string{get("Address")}, PeerPublicKey: get("PublicKey"), Endpoint: get("Endpoint"),
		AllowedIPs: strings.Split(get("AllowedIPs"), ", "),
	}, Secrets: Secrets{PrivateKey: get("PrivateKey")}})
}

func TestFixtureOpenVPNUDP(t *testing.T) {
	m := fixture(t)
	reachSSH(t, m, Spec{ID: "ovpn-udp", Kind: KindOpenVPN, Secrets: Secrets{ConfigFile: fixtureFile(t, "openvpn-udp.ovpn")}})
}

func TestFixtureOpenVPNTCP(t *testing.T) {
	m := fixture(t)
	reachSSH(t, m, Spec{ID: "ovpn-tcp", Kind: KindOpenVPN, Secrets: Secrets{ConfigFile: fixtureFile(t, "openvpn-tcp.ovpn")}})
}

func TestFixtureOpenConnect(t *testing.T) {
	m := fixture(t)
	s := Spec{ID: "oc", Kind: KindOpenConnect, Config: Config{Protocol: "anyconnect", Host: "127.0.0.1", Port: 4443, Username: "ant"}, Secrets: Secrets{Password: "colony"}}
	ctx := context.Background()
	res := m.Test(ctx, s, "")
	if res.Pin == "" {
		t.Fatalf("expected an untrusted certificate, got %+v", res.Message)
	}
	t.Logf("pin %s", res.Pin)
	s.Config.ServerCert = res.Pin
	reachSSH(t, m, s)
}
