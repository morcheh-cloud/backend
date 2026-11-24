package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// OpenVPN and SSTP need a real tun (or ppp) device. They run in a network
// namespace of their own (a user namespace too when Morche isn't root),
// next to a helper (`tunnel-helper`, this program). The VPN reaches its
// server through a small proxy in that namespace whose connections the
// helper asks Morche to open outside; Morche's own connections into the VPN
// are opened by the helper inside and handed back as sockets. So the VPN's
// routes and DNS never touch the machine's network, and two VPNs with the
// same address ranges don't clash.

// helperConfig is the first message to the helper.
type helperConfig struct {
	Program string            `json:"program"`
	Args    []string          `json:"args"`
	Files   map[string]string `json:"files"`
	// Hosts are names the VPN program looks up (its servers), already
	// resolved outside: the namespace has no DNS until the VPN is up.
	Hosts map[string]string `json:"hosts"`
}

// helperMsg is every other message, both ways.
type helperMsg struct {
	Op      string   `json:"op"`
	ID      uint64   `json:"id,omitempty"`
	Network string   `json:"network,omitempty"`
	Addr    string   `json:"addr,omitempty"`
	DNS     []string `json:"dns,omitempty"`
	Error   string   `json:"error,omitempty"`
	Line    string   `json:"line,omitempty"`
	Iface   string   `json:"iface,omitempty"`
}

type nsLink struct {
	cmd   *exec.Cmd
	ctl   *net.UnixConn
	wmu   sync.Mutex
	next  atomic.Uint64
	mu    sync.Mutex
	wait  map[uint64]chan dialed
	dns   []string
	dead  chan struct{}
	once  sync.Once
	cause error
}

type dialed struct {
	f   *os.File
	err error
}

func (n *nsLink) send(m helperMsg, f *os.File) error {
	n.wmu.Lock()
	defer n.wmu.Unlock()
	return sendMsg(n.ctl, m, f)
}

func (n *nsLink) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	dns := n.dns
	n.mu.Unlock()
	if _, err := netip.ParseAddr(host); err != nil && len(dns) == 0 {
		// The VPN gave no DNS: look the name up outside.
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("couldn't look up %s (set the VPN's DNS servers to look up names inside it)", host)
		}
		addr = net.JoinHostPort(ips[0].Unmap().String(), port)
	}
	id := n.next.Add(1)
	ch := make(chan dialed, 1)
	n.mu.Lock()
	n.wait[id] = ch
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		delete(n.wait, id)
		n.mu.Unlock()
	}()
	if err := n.send(helperMsg{Op: "dial", ID: id, Network: network, Addr: addr, DNS: dns}, nil); err != nil {
		return nil, errors.New("the VPN closed")
	}
	select {
	case d := <-ch:
		if d.err != nil {
			return nil, d.err
		}
		return fileConn(d.f)
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-n.dead:
		return nil, errors.New("the VPN closed")
	}
}

func (n *nsLink) done() <-chan struct{} { return n.dead }

func (n *nsLink) failure() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.cause
}

func (n *nsLink) fail(err error) {
	n.mu.Lock()
	if n.cause == nil {
		n.cause = err
	}
	n.mu.Unlock()
	n.once.Do(func() { close(n.dead) })
}

func (n *nsLink) close() {
	n.fail(errors.New("closed"))
	_ = n.send(helperMsg{Op: "stop"}, nil)
	go func() {
		time.Sleep(5 * time.Second)
		if n.cmd.Process != nil {
			_ = n.cmd.Process.Kill()
		}
	}()
	n.ctl.Close()
}

var (
	dnsPushRe = regexp.MustCompile(`dhcp-option DNS6? ([0-9a-fA-F.:]+)`)
	pppDNSRe  = regexp.MustCompile(`(?:primary|secondary)\s+DNS address\s+([0-9a-fA-F.:]+)`)
)

func openNamespaced(ctx context.Context, s Spec, exe string, log func(string)) (link, opened, error) {
	cfg, err := namespacedConfig(ctx, s)
	if err != nil {
		return nil, opened{}, err
	}
	if _, err := exec.LookPath(cfg.Program); err != nil {
		return nil, opened{}, fmt.Errorf("%s isn't installed on the machine Morche runs on", cfg.Program)
	}
	ctl, theirs, err := socketpair()
	if err != nil {
		return nil, opened{}, err
	}
	cmd := exec.Command(exe, "tunnel-helper")
	cmd.ExtraFiles = []*os.File{theirs}
	attr := &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWNS}
	if os.Geteuid() != 0 {
		attr.Cloneflags |= syscall.CLONE_NEWUSER
		attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
		attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
		attr.GidMappingsEnableSetgroups = false
	}
	cmd.SysProcAttr = attr
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		theirs.Close()
		ctl.Close()
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EINVAL) {
			return nil, opened{}, errors.New("Morche couldn't make a private network for the VPN: user namespaces aren't allowed here. In Docker, run the backend with the VPN settings from compose.yml")
		}
		return nil, opened{}, err
	}
	theirs.Close()
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			log(sc.Text())
		}
	}()
	n := &nsLink{cmd: cmd, ctl: ctl, wait: map[uint64]chan dialed{}, dead: make(chan struct{})}
	if err := sendMsg(ctl, cfg, nil); err != nil {
		n.close()
		return nil, opened{}, err
	}
	log("Started " + cfg.Program + " in its own network")

	up := make(chan opened, 1)
	exited := make(chan string, 1)
	var completed atomic.Bool
	var iface atomic.Value
	var dnsSeen []string
	var dnsMu sync.Mutex
	isUp := func() {
		if s.Kind == KindOpenVPN && !completed.Load() {
			return
		}
		a, _ := iface.Load().(string)
		if a == "" {
			return
		}
		dnsMu.Lock()
		dns := append([]string{}, s.Config.DNS...)
		if len(dns) == 0 {
			dns = append(dns, dnsSeen...)
		}
		dnsMu.Unlock()
		n.mu.Lock()
		n.dns = dns
		n.mu.Unlock()
		select {
		case up <- opened{address: a, dns: dns}:
		default:
		}
	}
	go func() {
		var last string
		for {
			var m helperMsg
			f, err := recvMsg(ctl, &m)
			if err != nil {
				if last == "" {
					last = "the VPN program stopped"
				}
				n.fail(errors.New(last))
				select {
				case exited <- last:
				default:
				}
				return
			}
			switch m.Op {
			case "log":
				log(m.Line)
				line := strings.TrimSpace(m.Line)
				if line != "" {
					last = line
				}
				if found := append(dnsPushRe.FindAllStringSubmatch(line, -1), pppDNSRe.FindAllStringSubmatch(line, -1)...); len(found) > 0 {
					dnsMu.Lock()
					for _, f := range found {
						if !contains(dnsSeen, f[1]) {
							dnsSeen = append(dnsSeen, f[1])
						}
					}
					dnsMu.Unlock()
				}
				if strings.Contains(line, "Initialization Sequence Completed") {
					completed.Store(true)
					isUp()
				}
			case "up":
				iface.Store(m.Addr)
				isUp()
			case "exit":
				msg := vpnMessage(s.Kind, last, m.Error)
				n.fail(errors.New(msg))
				select {
				case exited <- msg:
				default:
				}
			case "egress":
				go n.egress(m)
			case "dialed":
				n.mu.Lock()
				ch := n.wait[m.ID]
				n.mu.Unlock()
				var d dialed
				if m.Error != "" {
					d.err = errors.New(m.Error)
					if f != nil {
						f.Close()
					}
				} else if f == nil {
					d.err = errors.New("no connection came back")
				} else {
					d.f = f
				}
				if ch != nil {
					ch <- d
				} else if d.f != nil {
					d.f.Close()
				}
				continue
			}
			if f != nil {
				f.Close()
			}
		}
	}()
	go func() { _ = cmd.Wait() }()

	select {
	case o := <-up:
		log("Got address " + o.address)
		return n, o, nil
	case msg := <-exited:
		n.close()
		return nil, opened{}, errors.New(msg)
	case <-ctx.Done():
		n.close()
		return nil, opened{}, errors.New("the VPN didn't connect in time")
	}
}

// egress opens, outside, a connection the VPN program asked for.
func (n *nsLink) egress(m helperMsg) {
	reply := helperMsg{Op: "egressed", ID: m.ID}
	var f *os.File
	switch m.Network {
	case "udp":
		c, err := net.ListenUDP("udp", nil)
		if err != nil {
			reply.Error = err.Error()
			break
		}
		f, err = c.File()
		c.Close()
		if err != nil {
			reply.Error = err.Error()
		}
	default:
		c, err := (&net.Dialer{Timeout: dialTimeout}).Dial("tcp", m.Addr)
		if err != nil {
			reply.Error = err.Error()
			break
		}
		f, err = c.(*net.TCPConn).File()
		c.Close()
		if err != nil {
			reply.Error = err.Error()
		}
	}
	_ = n.send(reply, f)
	if f != nil {
		f.Close()
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func vpnMessage(kind, last, exitErr string) string {
	low := strings.ToLower(last)
	switch {
	case strings.Contains(low, "auth_failed") || strings.Contains(low, "authentication failed") ||
		strings.Contains(low, "auth: received control message: auth_failed"):
		return "the VPN refused the username or password"
	case strings.Contains(low, "cannot open tun") || strings.Contains(low, "/dev/net/tun"):
		return "the VPN couldn't make its tun device: the machine Morche runs on needs /dev/net/tun (in Docker: devices: [/dev/net/tun])"
	case strings.Contains(low, "/dev/ppp") || strings.Contains(low, "couldn't open the /dev/ppp"):
		return "SSTP needs /dev/ppp and a backend running as root (in Docker: user: root, devices: [/dev/ppp], cap_add: [NET_ADMIN])"
	case strings.Contains(low, "tls error") || strings.Contains(low, "certificate verify failed"):
		return "the TLS handshake with the VPN server failed: " + last
	}
	if last != "" {
		return last
	}
	if exitErr != "" {
		return kind + " stopped: " + exitErr
	}
	return kind + " stopped"
}
