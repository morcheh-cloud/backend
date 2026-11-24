package tunnel

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// RunHelper is `tunnel-helper`: it runs inside the VPN's own network
// namespace, started by openNamespaced with the control socket on fd 3.
func RunHelper() error {
	f := os.NewFile(3, "control")
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return err
	}
	h := &helper{ctl: c.(*net.UnixConn), wait: map[uint64]chan dialed{}}
	var cfg helperConfig
	if _, err := recvMsg(h.ctl, &cfg); err != nil {
		return err
	}
	return h.run(cfg)
}

type helper struct {
	ctl  *net.UnixConn
	wmu  sync.Mutex
	next atomic.Uint64
	mu   sync.Mutex
	wait map[uint64]chan dialed
}

func (h *helper) send(m helperMsg, f *os.File) {
	h.wmu.Lock()
	defer h.wmu.Unlock()
	_ = sendMsg(h.ctl, m, f)
}

func (h *helper) log(format string, a ...any) {
	h.send(helperMsg{Op: "log", Line: fmt.Sprintf(format, a...)}, nil)
}

func (h *helper) run(cfg helperConfig) error {
	dir, err := os.MkdirTemp("", "morche-vpn-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := loopbackUp(); err != nil {
		h.log("Couldn't bring up the loopback: %v", err)
	}
	h.hosts(dir, cfg.Hosts)
	for name, text := range cfg.Files {
		if strings.ContainsAny(name, "/\\") {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			return err
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	go h.serveEgress(ln)

	args := make([]string, len(cfg.Args))
	for i, a := range cfg.Args {
		args[i] = strings.ReplaceAll(a, "{egress}", port)
	}
	cmd := exec.Command(cfg.Program, args...)
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		h.send(helperMsg{Op: "exit", Error: err.Error()}, nil)
		return err
	}
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			h.send(helperMsg{Op: "log", Line: sc.Text()}, nil)
		}
	}()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	go h.watchInterfaces()

	stop := make(chan struct{})
	go func() {
		defer close(stop)
		for {
			var m helperMsg
			f, err := recvMsg(h.ctl, &m)
			if err != nil {
				return
			}
			switch m.Op {
			case "stop":
				return
			case "dial":
				go h.dial(m)
			case "egressed":
				h.mu.Lock()
				ch := h.wait[m.ID]
				h.mu.Unlock()
				d := dialed{f: f}
				if m.Error != "" {
					d.err = errors.New(m.Error)
				}
				if ch != nil {
					ch <- d
				} else if f != nil {
					f.Close()
				}
				continue
			}
			if f != nil {
				f.Close()
			}
		}
	}()
	select {
	case err := <-exited:
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		time.Sleep(200 * time.Millisecond) // let the last lines through
		h.send(helperMsg{Op: "exit", Error: msg}, nil)
		return nil
	case <-stop:
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
		}
		select {
		case <-exited:
		case <-time.After(4 * time.Second):
			_ = cmd.Process.Kill()
		}
		return nil
	}
}

// hosts puts the VPN servers' addresses in this namespace's /etc/hosts.
func (h *helper) hosts(dir string, entries map[string]string) {
	if len(entries) == 0 {
		return
	}
	var b strings.Builder
	b.WriteString("127.0.0.1 localhost\n::1 localhost\n")
	for name, ip := range entries {
		fmt.Fprintf(&b, "%s %s\n", ip, name)
	}
	path := filepath.Join(dir, "hosts")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return
	}
	_ = unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "")
	if err := unix.Mount(path, "/etc/hosts", "", unix.MS_BIND, ""); err != nil {
		h.log("Couldn't set the VPN server's address (%v); it may not be found", err)
	}
}

func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// watchInterfaces reports the VPN's interface once it has an address, and
// sends everything else through it.
func (h *helper) watchInterfaces() {
	for {
		time.Sleep(400 * time.Millisecond)
		list, err := net.Interfaces()
		if err != nil {
			continue
		}
		for _, i := range list {
			if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, _ := i.Addrs()
			var ips []string
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok && !n.IP.IsLinkLocalUnicast() {
					ips = append(ips, n.IP.String())
				}
			}
			if len(ips) == 0 {
				continue
			}
			// Only this namespace's connections use it, so a default route
			// through the VPN is safe and reaches what its pushed routes
			// leave out.
			if ip, err := exec.LookPath("ip"); err == nil {
				_ = exec.Command(ip, "route", "add", "default", "dev", i.Name).Run()
			}
			h.send(helperMsg{Op: "up", Iface: i.Name, Addr: strings.Join(ips, ", ")}, nil)
			return
		}
	}
}

// dial opens a connection inside the VPN and hands it to Morche.
func (h *helper) dial(m helperMsg) {
	reply := helperMsg{Op: "dialed", ID: m.ID}
	d := &net.Dialer{Timeout: dialTimeout}
	if len(m.DNS) > 0 {
		servers := m.DNS
		d.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var last error
			for _, s := range servers {
				c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(s, "53"))
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, last
		}}
	}
	network := m.Network
	if network == "" {
		network = "tcp"
	}
	c, err := d.Dial(network, m.Addr)
	if err != nil {
		reply.Error = err.Error()
		h.send(reply, nil)
		return
	}
	var f *os.File
	switch t := c.(type) {
	case *net.TCPConn:
		f, err = t.File()
	case *net.UDPConn:
		f, err = t.File()
	default:
		err = errors.New("unsupported connection")
	}
	c.Close()
	if err != nil {
		reply.Error = err.Error()
		h.send(reply, nil)
		return
	}
	h.send(reply, f)
	f.Close()
}

// outside asks Morche to open a connection outside the namespace.
func (h *helper) outside(network, addr string) (*os.File, error) {
	id := h.next.Add(1)
	ch := make(chan dialed, 1)
	h.mu.Lock()
	h.wait[id] = ch
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.wait, id)
		h.mu.Unlock()
	}()
	h.send(helperMsg{Op: "egress", ID: id, Network: network, Addr: addr}, nil)
	select {
	case d := <-ch:
		if d.err != nil {
			if d.f != nil {
				d.f.Close()
			}
			return nil, d.err
		}
		if d.f == nil {
			return nil, errors.New("no connection came back")
		}
		return d.f, nil
	case <-time.After(30 * time.Second):
		return nil, errors.New("timed out")
	}
}

// serveEgress is the proxy the VPN program reaches its server through:
// SOCKS5 (CONNECT and UDP ASSOCIATE) or HTTP CONNECT.
func (h *helper) serveEgress(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			br := bufio.NewReader(c)
			first, err := br.Peek(1)
			if err != nil {
				c.Close()
				return
			}
			if first[0] == 5 {
				h.socks(c, br)
			} else {
				h.httpConnect(c, br)
			}
		}()
	}
}

func (h *helper) httpConnect(c net.Conn, br *bufio.Reader) {
	defer c.Close()
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		_, _ = io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		return
	}
	f, err := h.outside("tcp", req.Host)
	if err != nil {
		h.log("Couldn't reach %s: %v", req.Host, err)
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	up, err := fileConn(f)
	if err != nil {
		return
	}
	defer up.Close()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	splice(&readerConn{Conn: c, r: br}, up)
}

type readerConn struct {
	net.Conn
	r io.Reader
}

func (r *readerConn) Read(p []byte) (int, error) { return r.r.Read(p) }

func (r *readerConn) CloseWrite() error {
	if cw, ok := r.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

func (h *helper) socks(c net.Conn, br *bufio.Reader) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	req := make([]byte, 3)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	addr, err := readSocksAddr(br)
	if err != nil {
		return
	}
	switch req[1] {
	case 1: // CONNECT
		f, err := h.outside("tcp", addr)
		if err != nil {
			h.log("Couldn't reach %s: %v", addr, err)
			_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		up, err := fileConn(f)
		if err != nil {
			return
		}
		defer up.Close()
		_ = c.SetDeadline(time.Time{})
		if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
		splice(&readerConn{Conn: c, r: br}, up)
	case 3: // UDP ASSOCIATE
		h.udpAssociate(c)
	default:
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
	}
}

func readSocksAddr(r io.Reader) (string, error) {
	t := make([]byte, 1)
	if _, err := io.ReadFull(r, t); err != nil {
		return "", err
	}
	var host string
	switch t[0] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", errors.New("bad address type")
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(r, p); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p)))), nil
}

// udpAssociate relays the VPN program's datagrams through a UDP socket that
// Morche opened outside, until the SOCKS connection closes.
func (h *helper) udpAssociate(c net.Conn) {
	f, err := h.outside("udp", "")
	if err != nil {
		_, _ = c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	pc, err := net.FilePacketConn(f)
	f.Close()
	if err != nil {
		return
	}
	defer pc.Close()
	out := pc.(*net.UDPConn)
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	defer local.Close()
	la := local.LocalAddr().(*net.UDPAddr)
	reply := []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(reply[8:], uint16(la.Port))
	_ = c.SetDeadline(time.Time{})
	if _, err := c.Write(reply); err != nil {
		return
	}
	var client atomic.Pointer[net.UDPAddr]
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := local.ReadFromUDP(buf)
			if err != nil {
				return
			}
			client.Store(from)
			if n < 4 || buf[2] != 0 { // fragments aren't supported
				continue
			}
			r := &sliceReader{b: buf[3:n]}
			addr, err := readSocksAddr(r)
			if err != nil {
				continue
			}
			ua, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				continue
			}
			_, _ = out.WriteToUDP(r.b, ua)
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := out.ReadFromUDP(buf)
			if err != nil {
				return
			}
			to := client.Load()
			if to == nil {
				continue
			}
			var head []byte
			if ip4 := from.IP.To4(); ip4 != nil {
				head = append([]byte{0, 0, 0, 1}, ip4...)
			} else {
				head = append([]byte{0, 0, 0, 4}, from.IP.To16()...)
			}
			head = binary.BigEndian.AppendUint16(head, uint16(from.Port))
			_, _ = local.WriteToUDP(append(head, buf[:n]...), to)
		}
	}()
	// The association lasts as long as its TCP connection.
	_, _ = io.Copy(io.Discard, c)
}

type sliceReader struct{ b []byte }

func (s *sliceReader) Read(p []byte) (int, error) {
	if len(s.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.b)
	s.b = s.b[n:]
	return n, nil
}
