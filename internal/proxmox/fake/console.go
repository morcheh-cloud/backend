package fake

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
)

// errSocket tells route that a websocket took the request over.
var errSocket = errors.New("websocket")

type consoleTicket struct {
	port, ticket, password string
	vmid                   int
	kind                   string // vnc | term
	expires                time.Time
	task                   *task
}

// consoleTicket answers vncproxy/termproxy: a ticket for one websocket.
func (s *Server) consoleTicket(r *http.Request, n *node, g *guest, kind string) (any, error) {
	if !g.running() {
		if g.kind == "lxc" {
			return nil, fail(http.StatusInternalServerError, "CT %d not running", g.vmid)
		}
		return nil, fail(http.StatusInternalServerError, "VM %d not running", g.vmid)
	}
	if kind == "term" && g.kind == "qemu" {
		serial := form(r, "serial")
		if serial == "" {
			serial = "serial0"
		}
		if !strings.HasPrefix(serial, "serial") || g.conf[serial] == "" {
			return nil, fail(http.StatusInternalServerError, "VM %d: %s is not configured", g.vmid, serial)
		}
	}
	for k, t := range s.tickets {
		if time.Now().After(t.expires) {
			delete(s.tickets, k)
			if !t.task.done() {
				t.task.timer.Stop()
				s.finish(t.task, errors.New("connection timed out"))
			}
		}
	}
	port := 5900 + len(s.tickets) + s.pid%50
	t := &consoleTicket{
		port: strconv.Itoa(port), ticket: "PVEVNC:" + strings.ToUpper(randHex(4)) + "::" + randHex(32),
		vmid: g.vmid, kind: kind, expires: time.Now().Add(10 * time.Second),
	}
	if kind == "vnc" && formBool(r, "generate-password") {
		t.password = randHex(4)
	}
	typ := "vncproxy"
	if kind == "term" {
		typ = "vncshell"
	}
	t.task = s.runTask(n.name, typ, strconv.Itoa(g.vmid), 24*time.Hour, []string{"connection timed out waiting for the websocket"}, nil)
	t.task.lines = nil
	s.tickets[t.ticket] = t
	user := strings.SplitN(s.opt.TokenID, "!", 2)[0]
	out := map[string]any{"user": user, "ticket": t.ticket, "port": t.port, "upid": t.task.upid}
	if t.password != "" {
		out["password"] = t.password
	}
	if kind == "vnc" {
		out["cert"] = "-----BEGIN CERTIFICATE-----\nMIIFAKE\n-----END CERTIFICATE-----\n"
	}
	return out, nil
}

// socket serves GET …/{qemu|lxc}/{vmid}/vncwebsocket?port=&vncticket=.
func (s *Server) socket(w http.ResponseWriter, r *http.Request, p []string) {
	q := r.URL.Query()
	s.mu.Lock()
	t := s.tickets[q.Get("vncticket")]
	var g *guest
	if len(p) == 5 {
		id, _ := strconv.Atoi(p[3])
		g = s.guests[id]
		if t != nil && (t.vmid != id || t.port != q.Get("port") || g == nil || g.node != p[1] || g.kind != p[2]) {
			t = nil
		}
	}
	if t != nil {
		delete(s.tickets, t.ticket) // one connection per ticket
	}
	if t == nil || time.Now().After(t.expires) {
		s.mu.Unlock()
		reply(w, nil, fail(http.StatusUnauthorized, "permission denied - invalid vncticket"))
		return
	}
	info := screenInfo{name: g.name(), kind: g.kind, vmid: g.vmid, node: g.node}
	info.ip, info.prefix = s.addrOf(g, g.conf["ipconfig0"]+","+g.conf["net0"])
	info.cores, info.mem, info.started = g.cpus(), g.maxMem(), g.startedAt
	info.os = g.conf["ostype"]
	s.mu.Unlock()

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"binary"}})
	if err != nil {
		return
	}
	c.SetReadLimit(1 << 20)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	// The machine stopping ends its console, like on a real host.
	go func() {
		tk := time.NewTicker(time.Second)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				s.mu.Lock()
				gone := s.guests[info.vmid] != g || !g.running()
				s.mu.Unlock()
				if gone {
					cancel()
					return
				}
			}
		}
	}()
	if t.kind == "vnc" {
		err = serveVNC(ctx, websocket.NetConn(ctx, c, websocket.MessageBinary), t.password, t.ticket, info)
	} else {
		err = serveTerm(ctx, c, t.ticket, info)
	}
	s.mu.Lock()
	if !t.task.done() {
		t.task.timer.Stop()
		s.finish(t.task, nil)
	}
	s.mu.Unlock()
	if err != nil {
		_ = c.Close(websocket.StatusPolicyViolation, err.Error())
		return
	}
	_ = c.Close(websocket.StatusNormalClosure, "")
}

type screenInfo struct {
	name, kind, node, ip, os string
	vmid, prefix, cores      int
	mem                      int64
	started                  time.Time
}

// serveTerm speaks termproxy: "user:ticket\n" → "OK", then framed input.
func serveTerm(ctx context.Context, c *websocket.Conn, ticket string, info screenInfo) error {
	_, first, err := c.Read(ctx)
	if err != nil {
		return nil
	}
	user, tk, ok := strings.Cut(strings.TrimSuffix(string(first), "\n"), ":")
	if !ok || tk != ticket || user == "" {
		return errors.New("invalid ticket")
	}
	sh := newShell(info)
	out := "OK" + sh.banner() + sh.prompt()
	if err := c.Write(ctx, websocket.MessageBinary, []byte(out)); err != nil {
		return nil
	}
	for {
		_, msg, err := c.Read(ctx)
		if err != nil {
			return nil
		}
		m := string(msg)
		switch {
		case m == "2":
			continue
		case strings.HasPrefix(m, "1:"):
			parts := strings.Split(m, ":")
			if len(parts) >= 3 {
				sh.cols, _ = strconv.Atoi(parts[1])
			}
			continue
		case strings.HasPrefix(m, "0:"):
			rest := m[2:]
			i := strings.IndexByte(rest, ':')
			if i < 0 {
				continue
			}
			reply, exit := sh.input(rest[i+1:])
			if reply != "" {
				if err := c.Write(ctx, websocket.MessageBinary, []byte(reply)); err != nil {
					return nil
				}
			}
			if exit {
				return nil
			}
		}
	}
}

// shell is a tiny line-based shell shared by the text console and the VNC
// screen: it echoes, edits the line and knows a handful of commands.
type shell struct {
	info  screenInfo
	line  []rune
	cols  int
	login int // VNC only: 0 = asks the user name, 1 = the password, 2 = signed in
	user  string
}

func newShell(info screenInfo) *shell { return &shell{info: info, cols: 80, login: 2, user: "root"} }

func (sh *shell) host() string {
	if sh.info.name == "" {
		return fmt.Sprintf("guest%d", sh.info.vmid)
	}
	return sh.info.name
}

func (sh *shell) distro() string {
	switch sh.info.os {
	case "ubuntu":
		return "Ubuntu 24.04.1 LTS"
	case "alpine":
		return "Alpine Linux v3.20"
	case "win11", "win10", "win2k22", "win2k19":
		return "Microsoft Windows Server (fake)"
	}
	return "Debian GNU/Linux 12 (bookworm)"
}

func (sh *shell) banner() string {
	return "\r\n" + sh.distro() + " " + sh.host() + "\r\n\r\nThis is Morche's fake Proxmox console: try help.\r\n\r\n"
}

func (sh *shell) prompt() string {
	switch sh.login {
	case 0:
		return sh.host() + " login: "
	case 1:
		return "Password: "
	}
	sign := "#"
	if sh.user != "root" {
		sign = "$"
	}
	return sh.user + "@" + sh.host() + ":~" + sign + " "
}

// input takes typed bytes and answers what the terminal shows.
func (sh *shell) input(data string) (out string, exit bool) {
	var b strings.Builder
	for _, r := range data {
		switch r {
		case '\r', '\n':
			cmd := strings.TrimSpace(string(sh.line))
			sh.line = sh.line[:0]
			b.WriteString("\r\n")
			res, bye := sh.run(cmd)
			if bye {
				b.WriteString("logout\r\n")
				return b.String(), true
			}
			b.WriteString(res)
			b.WriteString(sh.prompt())
		case 0x7f, '\b':
			if len(sh.line) > 0 {
				sh.line = sh.line[:len(sh.line)-1]
				if sh.login != 1 {
					b.WriteString("\b \b")
				}
			}
		case 0x03: // Ctrl+C
			sh.line = sh.line[:0]
			b.WriteString("^C\r\n" + sh.prompt())
		case 0x04: // Ctrl+D
			if len(sh.line) == 0 {
				return b.String() + "logout\r\n", true
			}
		case 0x0c: // Ctrl+L
			b.WriteString("\x1b[H\x1b[2J" + sh.prompt() + string(sh.line))
		case '\t', 0x1b:
		default:
			if r >= 0x20 {
				sh.line = append(sh.line, r)
				if sh.login != 1 {
					b.WriteRune(r)
				}
			}
		}
	}
	return b.String(), false
}

func (sh *shell) run(cmd string) (string, bool) {
	switch sh.login {
	case 0:
		if cmd == "" {
			return "", false
		}
		sh.user, sh.login = cmd, 1
		return "", false
	case 1:
		sh.login = 2
		return "Linux " + sh.host() + " 6.1.0-28-amd64 #1 SMP PREEMPT_DYNAMIC x86_64\r\n\r\n", false
	}
	name, args, _ := strings.Cut(cmd, " ")
	nl := func(lines ...string) string { return strings.Join(lines, "\r\n") + "\r\n" }
	up := time.Since(sh.info.started).Round(time.Minute)
	switch name {
	case "":
		return "", false
	case "help":
		return nl("Commands: help, hostname, whoami, uptime, uname -a, ip a, free -h, ls, date, echo, clear, exit"), false
	case "hostname":
		return nl(sh.host()), false
	case "whoami":
		return nl(sh.user), false
	case "uptime":
		return nl(fmt.Sprintf(" %s up %s,  1 user,  load average: 0.08, 0.05, 0.01", time.Now().Format("15:04:05"), strings.TrimSuffix(up.String(), "0s"))), false
	case "uname":
		if args == "-a" {
			return nl("Linux " + sh.host() + " 6.1.0-28-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.119-1 (2024-11-22) x86_64 GNU/Linux"), false
		}
		return nl("Linux"), false
	case "ip":
		dev := "ens18"
		if sh.info.kind == "lxc" {
			dev = "eth0@if12"
		}
		return nl("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN", "    inet 127.0.0.1/8 scope host lo",
			"2: "+dev+": <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP",
			fmt.Sprintf("    inet %s/%d brd + scope global %s", sh.info.ip, sh.info.prefix, strings.Split(dev, "@")[0])), false
	case "free":
		total := sh.info.mem / mib
		return nl("               total        used        free", fmt.Sprintf("Mem:     %10dMi %10dMi %10dMi", total, total*38/100, total*62/100)), false
	case "ls":
		return nl("notes.txt  backups  app"), false
	case "date":
		return nl(time.Now().UTC().Format("Mon Jan  2 15:04:05 UTC 2006")), false
	case "echo":
		return nl(args), false
	case "clear":
		return "\x1b[H\x1b[2J", false
	case "exit", "logout":
		return "", true
	}
	return nl("-bash: " + name + ": command not found"), false
}
