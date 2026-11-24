package tunnel

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// openconnect runs with --script-tun: instead of a tun device it hands its
// packets to a script over a socket. The script is this program
// (`tunnel-script`), which passes that socket back to Morche, where the
// packets go into an in-process network stack. No root, no tun device, and
// nothing changes on the machine's network.

// scriptHello is what tunnel-script sends with the packet socket.
type scriptHello struct {
	Token string `json:"token"`
	IP4   string `json:"ip4"`
	IP6   string `json:"ip6"`
	MTU   int    `json:"mtu"`
	DNS   string `json:"dns"`
}

var pinRe = regexp.MustCompile(`--servercert\s+(pin-sha256:[A-Za-z0-9+/=]+)`)

// ProtocolLabel names an openconnect protocol.
func ProtocolLabel(p string) string {
	switch p {
	case "anyconnect":
		return "Cisco AnyConnect"
	case "fortinet":
		return "Fortinet"
	case "gp":
		return "Palo Alto GlobalProtect"
	case "pulse":
		return "Pulse / Ivanti Connect Secure"
	case "nc":
		return "Juniper Network Connect"
	case "f5":
		return "F5 BIG-IP"
	case "array":
		return "Array Networks"
	}
	return p
}

type ocLink struct {
	cmd    *exec.Cmd
	pkt    net.Conn
	tdev   tun.Device
	tnet   *netstack.Net
	dead   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	reason error
	keep   *net.UnixConn
	dir    string
	hasDNS bool
}

func (o *ocLink) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	addr, err := outsideName(ctx, addr, o.hasDNS)
	if err != nil {
		return nil, err
	}
	return o.tnet.DialContext(ctx, network, addr)
}

func (o *ocLink) done() <-chan struct{} { return o.dead }

func (o *ocLink) failure() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.reason
}

func (o *ocLink) fail(err error) {
	o.mu.Lock()
	if o.reason == nil {
		o.reason = err
	}
	o.mu.Unlock()
	o.once.Do(func() { close(o.dead) })
}

func (o *ocLink) close() {
	if o.cmd.Process != nil {
		// SIGINT logs out of the VPN before leaving.
		_ = o.cmd.Process.Signal(os.Interrupt)
		go func() {
			time.Sleep(5 * time.Second)
			_ = o.cmd.Process.Kill()
		}()
	}
	o.fail(errors.New("closed"))
	if o.pkt != nil {
		o.pkt.Close()
	}
	if o.tdev != nil {
		o.tdev.Close()
	}
	if o.keep != nil {
		o.keep.Close()
	}
	os.RemoveAll(o.dir)
}

func randomToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func openOpenConnect(ctx context.Context, s Spec, exe string, log func(string)) (link, opened, error) {
	bin, err := exec.LookPath("openconnect")
	if err != nil {
		return nil, opened{}, errors.New("openconnect isn't installed on the machine Morche runs on")
	}
	c := s.Config
	dir, err := os.MkdirTemp("", "morche-oc-")
	if err != nil {
		return nil, opened{}, err
	}
	sock := filepath.Join(dir, "s")
	ln, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: sock, Net: "unixpacket"})
	if err != nil {
		os.RemoveAll(dir)
		return nil, opened{}, err
	}
	token := randomToken()

	server := c.Host
	if c.Port != 0 && c.Port != 443 && !strings.Contains(server, "/") {
		server = hostPort(c.Host, c.Port)
	}
	args := []string{
		"--protocol=" + c.Protocol, "--non-inter", "--passwd-on-stdin",
		"--script-tun", "--script", shellQuote(exe) + " tunnel-script",
		"--reconnect-timeout", "60",
	}
	if c.Username != "" {
		args = append(args, "--user="+c.Username)
	}
	if c.Group != "" {
		args = append(args, "--authgroup="+c.Group)
	}
	if c.ServerCert != "" {
		args = append(args, "--servercert="+c.ServerCert)
	}
	args = append(args, "--", server)

	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "MORCHE_TUNNEL_SOCK="+sock, "MORCHE_TUNNEL_TOKEN="+token)
	cmd.Stdin = strings.NewReader(s.Secrets.Password + "\n")
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
	out, err := cmd.StdoutPipe()
	if err != nil {
		os.RemoveAll(dir)
		return nil, opened{}, err
	}
	cmd.Stderr = cmd.Stdout
	l := &ocLink{cmd: cmd, dead: make(chan struct{}), dir: dir}
	var pinMu sync.Mutex
	var pin, last string
	if err := cmd.Start(); err != nil {
		ln.Close()
		os.RemoveAll(dir)
		return nil, opened{}, err
	}
	log(fmt.Sprintf("Started openconnect (%s) to %s", ProtocolLabel(c.Protocol), server))
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if m := pinRe.FindStringSubmatch(line); m != nil {
				pinMu.Lock()
				pin = m[1]
				pinMu.Unlock()
			}
			if strings.TrimSpace(line) != "" {
				pinMu.Lock()
				last = strings.TrimSpace(line)
				pinMu.Unlock()
			}
			log(line)
		}
	}()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	type got struct {
		hello scriptHello
		conn  *net.UnixConn
		f     *os.File
		err   error
	}
	hello := make(chan got, 1)
	go func() {
		for {
			uc, err := ln.AcceptUnix()
			if err != nil {
				hello <- got{err: err}
				return
			}
			var h scriptHello
			f, err := recvMsg(uc, &h)
			if err != nil || h.Token != token || f == nil {
				uc.Close()
				if f != nil {
					f.Close()
				}
				continue
			}
			hello <- got{hello: h, conn: uc, f: f}
			return
		}
	}()

	failWith := func(err error) (link, opened, error) {
		ln.Close()
		l.close()
		return nil, opened{}, err
	}
	var g got
	select {
	case g = <-hello:
		ln.Close()
		if g.err != nil {
			return failWith(g.err)
		}
	case err := <-exited:
		time.Sleep(100 * time.Millisecond)
		pinMu.Lock()
		p, msg := pin, last
		pinMu.Unlock()
		if p != "" {
			return failWith(&CertError{Pin: p, Message: "The VPN server's certificate isn't trusted. Check its fingerprint, then trust it: " + p})
		}
		return failWith(ocMessage(msg, err))
	case <-ctx.Done():
		return failWith(errors.New("the VPN didn't connect in time"))
	}
	l.keep = g.conn
	go func() {
		err := <-exited
		pinMu.Lock()
		msg := last
		pinMu.Unlock()
		l.fail(ocMessage(msg, err))
	}()

	pkt, err := fileConn(g.f)
	if err != nil {
		return failWith(err)
	}
	l.pkt = pkt
	var local []netip.Addr
	if a, err := netip.ParseAddr(g.hello.IP4); err == nil {
		local = append(local, a)
	}
	if g.hello.IP6 != "" {
		v := g.hello.IP6
		if i := strings.IndexByte(v, '/'); i >= 0 {
			v = v[:i]
		}
		if a, err := netip.ParseAddr(v); err == nil {
			local = append(local, a)
		}
	}
	if len(local) == 0 {
		return failWith(errors.New("the VPN didn't give Morche an address"))
	}
	dnsList := c.DNS
	if len(dnsList) == 0 {
		dnsList = strings.Fields(g.hello.DNS)
	}
	dns, _ := Addrs(dnsList)
	mtu := g.hello.MTU
	if mtu <= 0 {
		mtu = 1300
	}
	tdev, tnet, err := netstack.CreateNetTUN(local, dns, mtu)
	if err != nil {
		return failWith(err)
	}
	l.tdev, l.tnet, l.hasDNS = tdev, tnet, len(dns) > 0
	go pump(pkt, tdev, mtu, l.fail)
	var addrs []string
	for _, a := range local {
		addrs = append(addrs, a.String())
	}
	log("Got address " + strings.Join(addrs, ", "))
	return l, opened{address: strings.Join(addrs, ", "), dns: dnsList}, nil
}

func ocMessage(last string, err error) error {
	low := strings.ToLower(last)
	switch {
	case strings.Contains(low, "failed to complete authentication") || strings.Contains(low, "login failed") || strings.Contains(low, "authentication failed") ||
		strings.Contains(low, "invalid username or password") || strings.Contains(low, "auth-failed"):
		return errors.New("the VPN refused the username or password")
	case strings.Contains(low, "failed to connect") || strings.Contains(low, "connection refused") ||
		strings.Contains(low, "no route to host"):
		return errors.New("couldn't reach the VPN server: " + last)
	case strings.Contains(low, "two-factor") || strings.Contains(low, "token") && strings.Contains(low, "code"):
		return errors.New("the VPN asks for a one-time code, which Morche can't type in")
	}
	if last != "" {
		return errors.New(last)
	}
	if err != nil {
		return fmt.Errorf("openconnect stopped: %w", err)
	}
	return errors.New("openconnect stopped")
}

// pump moves IP packets between the socket (one datagram per packet) and
// the network stack.
func pump(pkt net.Conn, dev tun.Device, mtu int, fail func(error)) {
	go func() {
		buf := make([]byte, mtu+128)
		for {
			n, err := pkt.Read(buf)
			if err != nil {
				fail(errors.New("the VPN closed"))
				return
			}
			if n == 0 {
				continue
			}
			p := make([]byte, n)
			copy(p, buf[:n])
			if _, err := dev.Write([][]byte{p}, 0); err != nil && !errors.Is(err, io.ErrShortWrite) {
				continue
			}
		}
	}()
	batch := dev.BatchSize()
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, mtu+128)
	}
	sizes := make([]int, batch)
	for {
		n, err := dev.Read(bufs, sizes, 0)
		if err != nil {
			fail(errors.New("the VPN closed"))
			return
		}
		for i := range n {
			if _, err := pkt.Write(bufs[i][:sizes[i]]); err != nil {
				fail(errors.New("the VPN closed"))
				return
			}
		}
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// RunScript is `tunnel-script`, run by openconnect: it hands the packet
// socket and the addresses to Morche, then waits until Morche lets go.
func RunScript() error {
	fdText := os.Getenv("VPNFD")
	if fdText == "" {
		// Called for another reason (disconnect…): nothing to do.
		return nil
	}
	fd, err := strconv.Atoi(fdText)
	if err != nil {
		return err
	}
	c, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: os.Getenv("MORCHE_TUNNEL_SOCK"), Net: "unixpacket"})
	if err != nil {
		return err
	}
	ip6 := os.Getenv("INTERNAL_IP6_ADDRESS")
	if ip6 == "" {
		ip6 = os.Getenv("INTERNAL_IP6_NETMASK")
	}
	mtu, _ := strconv.Atoi(os.Getenv("INTERNAL_IP4_MTU"))
	h := scriptHello{
		Token: os.Getenv("MORCHE_TUNNEL_TOKEN"),
		IP4:   os.Getenv("INTERNAL_IP4_ADDRESS"),
		IP6:   ip6,
		MTU:   mtu,
		DNS:   strings.TrimSpace(os.Getenv("INTERNAL_IP4_DNS") + " " + os.Getenv("INTERNAL_IP6_DNS")),
	}
	f := os.NewFile(uintptr(fd), "vpn")
	if err := sendMsg(c, h, f); err != nil {
		return err
	}
	f.Close()
	// Stay until Morche closes its end.
	buf := make([]byte, 16)
	for {
		if _, err := c.Read(buf); err != nil {
			return nil
		}
	}
}
