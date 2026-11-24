package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// An .ovpn file is trusted no further than its connection settings: every
// directive that runs a program, writes a file, reads one from Morche's disk
// or changes how Morche drives OpenVPN is refused.

var ovpnRefused = map[string]string{
	"up": "runs a program", "down": "runs a program", "route-up": "runs a program",
	"route-pre-down": "runs a program", "ipchange": "runs a program", "client-connect": "runs a program",
	"client-disconnect": "runs a program", "learn-address": "runs a program",
	"auth-user-pass-verify": "runs a program", "tls-verify": "runs a program", "plugin": "loads a library",
	"iproute": "runs a program", "management": "opens a control port", "daemon": "leaves Morche's control",
	"log": "writes a file", "log-append": "writes a file", "writepid": "writes a file", "status": "writes a file",
	"cd": "changes folder", "chroot": "changes folder", "config": "reads a file", "tmp-dir": "writes files",
	"user": "changes user", "group": "changes group", "dev-node": "opens a device",
	"tls-export-cert": "writes files", "client-config-dir": "reads files", "ifconfig-pool-persist": "writes a file",
	"replay-persist": "writes a file", "remap-usr1": "changes signals", "mlock": "locks memory",
}

// Directives whose argument is a file: only inline content is allowed.
var ovpnFileArgs = map[string]bool{
	"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true,
	"pkcs12": true, "dh": true, "crl-verify": true, "extra-certs": true, "secret": true,
	"http-proxy-user-pass": true,
}

// Directives Morche sets itself; the file's copy is left out.
var ovpnDropped = map[string]bool{
	"auth-user-pass": true, "askpass": true, "socks-proxy": true, "http-proxy": true,
	"http-proxy-option": true, "script-security": true, "verb": true, "auth-nocache": true,
}

// Inline blocks that hold data, not directives.
var ovpnDataBlocks = map[string]bool{
	"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true,
	"pkcs12": true, "dh": true, "extra-certs": true, "secret": true, "http-proxy-user-pass": true,
	"auth-user-pass": true, "crl-verify": true, "peer-fingerprint": true,
}

// OpenVPNFile is what Morche learned from an .ovpn file.
type OpenVPNFile struct {
	// Text is the file with the directives Morche sets itself left out.
	Text string
	// Remotes are the servers' names or addresses.
	Remotes []string
	// NeedsLogin: the file asks for a username and password.
	NeedsLogin bool
	// NeedsPassphrase: the private key is encrypted.
	NeedsPassphrase bool
}

// ParseOpenVPN checks an .ovpn file.
func ParseOpenVPN(text string) (OpenVPNFile, error) {
	var f OpenVPNFile
	if strings.TrimSpace(text) == "" {
		return f, errors.New("paste the .ovpn file")
	}
	var out strings.Builder
	block := ""
	for i, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if block != "" {
			if strings.EqualFold(line, "</"+block+">") {
				block = ""
			} else if strings.Contains(line, "ENCRYPTED") && strings.Contains(line, "PRIVATE KEY") {
				f.NeedsPassphrase = true
			}
			out.WriteString(raw + "\n")
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && !strings.HasPrefix(line, "</") {
			name := strings.ToLower(strings.Trim(line, "<>"))
			if ovpnDataBlocks[name] {
				block = name
				if name == "auth-user-pass" {
					f.NeedsLogin = true
				}
			}
			out.WriteString(raw + "\n")
			continue
		}
		if line == "" || line[0] == '#' || line[0] == ';' || strings.HasPrefix(line, "</") {
			out.WriteString(raw + "\n")
			continue
		}
		fields := strings.Fields(line)
		name := strings.ToLower(strings.TrimPrefix(fields[0], "--"))
		if why, bad := ovpnRefused[name]; bad || strings.HasPrefix(name, "management-") {
			if !bad {
				why = "opens a control port"
			}
			return f, fmt.Errorf("line %d: %q isn't allowed (it %s)", i+1, name, why)
		}
		if ovpnFileArgs[name] && len(fields) > 1 && fields[1] != "[inline]" {
			return f, fmt.Errorf("line %d: %s points at a file on disk; paste its content inline instead (<%s>…</%s>)", i+1, name, name, name)
		}
		if ovpnDropped[name] {
			if name == "auth-user-pass" {
				f.NeedsLogin = true
			}
			out.WriteString("# (set by Morche) " + raw + "\n")
			continue
		}
		if name == "remote" && len(fields) > 1 {
			f.Remotes = append(f.Remotes, fields[1])
		}
		out.WriteString(raw + "\n")
	}
	if block != "" {
		return f, fmt.Errorf("<%s> isn't closed", block)
	}
	if len(f.Remotes) == 0 {
		return f, errors.New("the file has no remote line (the VPN server)")
	}
	f.Text = out.String()
	return f, nil
}

var (
	ovpnHelpOnce sync.Once
	ovpnHelp     string
)

// openvpnHas says whether this machine's openvpn knows an option.
func openvpnHas(option string) bool {
	ovpnHelpOnce.Do(func() {
		out, _ := exec.Command("openvpn", "--help").CombinedOutput()
		ovpnHelp = string(out)
	})
	return strings.Contains(ovpnHelp, option+" ")
}

// lookups resolves names outside the namespace, which has no DNS of its own.
func lookups(ctx context.Context, names []string) (map[string]string, error) {
	hosts := map[string]string{}
	for _, n := range names {
		if _, err := netip.ParseAddr(n); err == nil {
			continue
		}
		if _, ok := hosts[n]; ok {
			continue
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", n)
		if err != nil || len(ips) == 0 {
			ips, err = net.DefaultResolver.LookupNetIP(ctx, "ip", n)
		}
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("couldn't look up the VPN server %s", n)
		}
		hosts[n] = ips[0].Unmap().String()
	}
	return hosts, nil
}

func namespacedConfig(ctx context.Context, s Spec) (helperConfig, error) {
	c := s.Config
	switch s.Kind {
	case KindOpenVPN:
		f, err := ParseOpenVPN(s.Secrets.ConfigFile)
		if err != nil {
			return helperConfig{}, err
		}
		hosts, err := lookups(ctx, f.Remotes)
		if err != nil {
			return helperConfig{}, err
		}
		cfg := helperConfig{
			Program: "openvpn",
			Files:   map[string]string{"client.ovpn": f.Text},
			Hosts:   hosts,
			Args: []string{
				"--config", "client.ovpn", "--socks-proxy", "127.0.0.1", "{egress}",
				"--verb", "3", "--auth-nocache", "--script-security", "1",
				"--connect-retry-max", "2", "--resolv-retry", "0",
				"--pull-filter", "ignore", "block-outside-dns",
			},
		}
		if openvpnHas("--dns-updown") {
			// 2.7+ would set the VPN's DNS on the machine (resolvectl): never.
			cfg.Args = append(cfg.Args, "--dns-updown", "disable")
		}
		if c.Username != "" || s.Secrets.Password != "" {
			cfg.Files["auth.txt"] = c.Username + "\n" + s.Secrets.Password + "\n"
			cfg.Args = append(cfg.Args, "--auth-user-pass", "auth.txt")
		} else if f.NeedsLogin {
			return helperConfig{}, errors.New("this VPN asks for a username and password")
		}
		if s.Secrets.Passphrase != "" {
			cfg.Files["pass.txt"] = s.Secrets.Passphrase + "\n"
			cfg.Args = append(cfg.Args, "--askpass", "pass.txt")
		}
		return cfg, nil
	case KindSSTP:
		hosts, err := lookups(ctx, []string{c.Host})
		if err != nil {
			return helperConfig{}, err
		}
		server := c.Host
		if c.Port != 0 && c.Port != 443 {
			server = net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
		}
		args := []string{"--log-stderr", "--log-level", "2", "--proxy", "http://127.0.0.1:{egress}"}
		if c.IgnoreCert {
			args = append(args, "--cert-warn")
		}
		args = append(args, "--user", c.Username, "--password", s.Secrets.Password, server,
			"require-mschap-v2", "noauth", "noipdefault", "usepeerdns", "defaultroute",
			"refuse-eap", "noccp", "nodeflate", "nobsdcomp", "nodetach", "logfd", "2")
		return helperConfig{Program: "sstpc", Args: args, Hosts: hosts}, nil
	}
	return helperConfig{}, fmt.Errorf("%s doesn't run in a namespace", s.Kind)
}
