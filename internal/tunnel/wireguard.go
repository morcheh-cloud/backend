package tunnel

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// WireGuardKey checks a base64 key (private, public or preshared) and
// returns it as hex, the way wireguard-go's settings want it.
func WireGuardKey(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != 32 {
		return "", errors.New("a WireGuard key is 44 characters of base64")
	}
	return hex.EncodeToString(raw), nil
}

// Prefixes parses addresses written with or without a /bits suffix.
func Prefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("%q isn't an IP address", s)
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%q isn't an address range", s)
		}
		out = append(out, p)
	}
	return out, nil
}

// Addrs parses a list of plain IP addresses.
func Addrs(list []string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q isn't an IP address", s)
		}
		out = append(out, a)
	}
	return out, nil
}

type wgLink struct {
	dev  *device.Device
	tnet *netstack.Net
	once sync.Once
}

func (w *wgLink) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := w.tnet.DialContext(ctx, network, addr)
	if err != nil {
		return nil, wgMessage(err)
	}
	return c, nil
}

func wgMessage(err error) error {
	msg := err.Error()
	if strings.Contains(msg, "no route") || strings.Contains(msg, "host is unreachable") {
		return fmt.Errorf("%w (is the address inside the tunnel's Allowed IPs?)", err)
	}
	return err
}

func (w *wgLink) done() <-chan struct{} { return nil }
func (w *wgLink) failure() error        { return nil }
func (w *wgLink) close()                { w.once.Do(w.dev.Close) }

func openWireGuard(ctx context.Context, s Spec, log func(string)) (link, opened, error) {
	c := s.Config
	prefixes, err := Prefixes(c.Addresses)
	if err != nil {
		return nil, opened{}, err
	}
	if len(prefixes) == 0 {
		return nil, opened{}, errors.New("set the tunnel's address (Interface › Address)")
	}
	var local []netip.Addr
	for _, p := range prefixes {
		local = append(local, p.Addr())
	}
	dns, err := Addrs(c.DNS)
	if err != nil {
		return nil, opened{}, err
	}
	priv, err := WireGuardKey(s.Secrets.PrivateKey)
	if err != nil {
		return nil, opened{}, fmt.Errorf("private key: %w", err)
	}
	pub, err := WireGuardKey(c.PeerPublicKey)
	if err != nil {
		return nil, opened{}, fmt.Errorf("peer's public key: %w", err)
	}
	host, port, err := net.SplitHostPort(c.Endpoint)
	if err != nil {
		return nil, opened{}, errors.New("the endpoint is host:port, like vpn.example.com:51820")
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, opened{}, fmt.Errorf("couldn't look up the endpoint %s", host)
	}
	endpoint := netip.AddrPortFrom(ips[0].Unmap(), parsePort(port))
	mtu := c.MTU
	if mtu == 0 {
		mtu = 1420
	}
	keepalive := c.Keepalive
	if keepalive == 0 {
		keepalive = 25
	}
	allowed := c.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	allowedP, err := Prefixes(allowed)
	if err != nil {
		return nil, opened{}, err
	}

	tdev, tnet, err := netstack.CreateNetTUN(local, dns, mtu)
	if err != nil {
		return nil, opened{}, err
	}
	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(f string, a ...any) { log(fmt.Sprintf(f, a...)) },
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=%d\n",
		priv, pub, endpoint, keepalive)
	if s.Secrets.PresharedKey != "" {
		psk, err := WireGuardKey(s.Secrets.PresharedKey)
		if err != nil {
			dev.Close()
			return nil, opened{}, fmt.Errorf("preshared key: %w", err)
		}
		fmt.Fprintf(&uapi, "preshared_key=%s\n", psk)
	}
	for _, p := range allowedP {
		fmt.Fprintf(&uapi, "allowed_ip=%s\n", p.Masked())
	}
	if err := dev.IpcSet(uapi.String()); err != nil {
		dev.Close()
		return nil, opened{}, fmt.Errorf("the settings were refused: %w", err)
	}
	log(fmt.Sprintf("Talking to %s (%s) from %s", c.Endpoint, endpoint, strings.Join(c.Addresses, ", ")))
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, opened{}, err
	}
	// The keepalive starts a handshake; wait for its answer.
	deadline := time.Now().Add(15 * time.Second)
	for {
		if wgHandshake(dev) {
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			dev.Close()
			return nil, opened{}, errors.New("no answer from the WireGuard server: check the endpoint, both keys and that its UDP port is open")
		}
		time.Sleep(250 * time.Millisecond)
	}
	log("Handshake done")
	var addrs []string
	for _, a := range local {
		addrs = append(addrs, a.String())
	}
	return &wgLink{dev: dev, tnet: tnet}, opened{address: strings.Join(addrs, ", "), dns: c.DNS}, nil
}

func parsePort(s string) uint16 {
	n, _ := strconv.Atoi(s)
	return uint16(n)
}

func wgHandshake(dev *device.Device) bool {
	out, err := dev.IpcGet()
	if err != nil {
		return false
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "last_handshake_time_sec="); ok && v != "0" {
			return true
		}
	}
	return false
}
