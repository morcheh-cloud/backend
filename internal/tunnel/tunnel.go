// Package tunnel opens the ways Morche reaches servers it can't reach
// directly: an SSH jump host, a SOCKS5 or HTTP proxy, or a VPN (WireGuard,
// OpenVPN, the openconnect family, SSTP).
//
// Every tunnel is private to Morche: nothing changes on the machine's own
// network. WireGuard and openconnect run on an in-process network stack
// (gVisor netstack); OpenVPN and SSTP run in their own network namespace
// with a helper that hands connected sockets back. A tunnel opens on first
// use and closes once it has been idle for a while.
package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Kinds.
const (
	KindJump        = "jump"
	KindSOCKS5      = "socks5"
	KindHTTP        = "http"
	KindWireGuard   = "wireguard"
	KindOpenVPN     = "openvpn"
	KindOpenConnect = "openconnect"
	KindSSTP        = "sstp"
)

// Kinds lists every kind, in the order the panel shows them.
var Kinds = []string{KindJump, KindSOCKS5, KindHTTP, KindWireGuard, KindOpenVPN, KindOpenConnect, KindSSTP}

// Protocols openconnect speaks (its --protocol values).
var Protocols = []string{"anyconnect", "fortinet", "gp", "pulse", "nc", "f5", "array"}

// Statuses of a tunnel.
const (
	StatusIdle       = "idle"       // not open; opens on first use
	StatusConnecting = "connecting" // opening
	StatusConnected  = "connected"  // open
	StatusFailed     = "failed"     // the last try failed
)

// DialFunc opens a connection the way net.Dialer.DialContext does.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Config is a tunnel's settings without its secrets (stored as JSON).
type Config struct {
	// jump: the Morche server to hop through.
	ServerID string `json:"server_id,omitempty"`
	// socks5, http: the proxy. openconnect, sstp: the VPN server.
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	// socks5, http, openvpn, openconnect, sstp.
	Username string `json:"username,omitempty"`
	// http: talk to the proxy over TLS.
	TLS bool `json:"tls,omitempty"`

	// wireguard: this side's addresses (CIDR), the peer.
	Addresses     []string `json:"addresses,omitempty"`
	PeerPublicKey string   `json:"peer_public_key,omitempty"`
	Endpoint      string   `json:"endpoint,omitempty"`
	AllowedIPs    []string `json:"allowed_ips,omitempty"`
	Keepalive     int      `json:"keepalive,omitempty"`
	MTU           int      `json:"mtu,omitempty"`

	// openconnect: which protocol, the login group, the server's pinned
	// certificate (pin-sha256:…), empty = the system's CAs.
	Protocol   string `json:"protocol,omitempty"`
	Group      string `json:"group,omitempty"`
	ServerCert string `json:"server_cert,omitempty"`
	// sstp: accept a certificate the system doesn't trust.
	IgnoreCert bool `json:"ignore_cert,omitempty"`

	// VPNs: name servers inside the VPN; empty = what the VPN hands out.
	DNS []string `json:"dns,omitempty"`
}

// Secrets are sealed at rest and never leave the backend.
type Secrets struct {
	Password     string `json:"password,omitempty"`
	PrivateKey   string `json:"private_key,omitempty"`   // wireguard
	PresharedKey string `json:"preshared_key,omitempty"` // wireguard
	ConfigFile   string `json:"config_file,omitempty"`   // openvpn (.ovpn)
	Passphrase   string `json:"passphrase,omitempty"`    // openvpn private key
}

// Spec is everything needed to open one tunnel.
type Spec struct {
	ID      string
	Name    string
	Kind    string
	Config  Config
	Secrets Secrets
}

// Version changes whenever anything that affects the connection changes.
func (s Spec) Version() string {
	sum := sha256.New()
	_ = json.NewEncoder(sum).Encode([]any{s.Kind, s.Config, s.Secrets})
	return hex.EncodeToString(sum.Sum(nil))[:16]
}

// State is what a tunnel is doing now.
type State struct {
	Status  string    `json:"status"`
	Message string    `json:"message"`
	Since   time.Time `json:"since"`
	// Address is the address the VPN gave Morche, when there is one.
	Address string `json:"address,omitempty"`
	// DNS the VPN handed out.
	DNS []string `json:"dns,omitempty"`
	// Conns is how many connections are open through it.
	Conns int `json:"conns"`
}

// CertError: the VPN server's certificate isn't trusted. Pin is what to
// trust (openconnect's pin-sha256:…).
type CertError struct {
	Pin     string
	Message string
}

func (e *CertError) Error() string { return e.Message }

// link is one open tunnel.
type link interface {
	dial(ctx context.Context, network, addr string) (net.Conn, error)
	// done closes when the tunnel dies by itself.
	done() <-chan struct{}
	// failure is why it died.
	failure() error
	close()
}

// stateless links (jump, proxies) never die by themselves.
type stateless struct {
	dialFn DialFunc
}

func (s stateless) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return s.dialFn(ctx, network, addr)
}
func (stateless) done() <-chan struct{} { return nil }
func (stateless) failure() error        { return nil }
func (stateless) close()                {}

// Options configure a Manager.
type Options struct {
	// Jump returns how to dial through the Morche server with this id (its
	// pooled SSH connection).
	Jump func(ctx context.Context, serverID string) (DialFunc, error)
	// OnState is told every change, to store it.
	OnState func(id string, st State)
	// Idle closes a tunnel nobody used for this long (default 10 min).
	Idle time.Duration
	// Executable runs the helpers (default: this program).
	Executable string
}

// Manager keeps the open tunnels.
type Manager struct {
	opt  Options
	mu   sync.Mutex
	live map[string]*entry
	logs map[string]*ring
}

type entry struct {
	spec    Spec
	version string
	link    link
	ready   chan struct{} // closed once opening ended
	err     error
	state   State
	conns   int
	lastUse time.Time
}

func New(opt Options) *Manager {
	if opt.Idle <= 0 {
		opt.Idle = 10 * time.Minute
	}
	m := &Manager{opt: opt, live: map[string]*entry{}, logs: map[string]*ring{}}
	go m.reap()
	return m
}

func (m *Manager) reap() {
	for range time.Tick(30 * time.Second) {
		m.mu.Lock()
		var idle []*entry
		for id, e := range m.live {
			select {
			case <-e.ready:
			default:
				continue
			}
			if e.conns == 0 && time.Since(e.lastUse) > m.opt.Idle {
				delete(m.live, id)
				idle = append(idle, e)
			}
		}
		m.mu.Unlock()
		for _, e := range idle {
			if e.link != nil {
				e.link.close()
			}
			m.log(e.spec.ID, "Closed after being idle")
			m.setState(e.spec.ID, State{Status: StatusIdle, Since: time.Now()})
		}
	}
}

func (m *Manager) ringOf(id string) *ring {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.logs[id]
	if r == nil {
		r = newRing(400)
		m.logs[id] = r
	}
	return r
}

func (m *Manager) log(id, line string) {
	m.ringOf(id).add(line)
}

// Log returns the last lines a tunnel wrote, oldest first.
func (m *Manager) Log(id string) []LogLine {
	return m.ringOf(id).lines()
}

// Sentence starts a message with a capital letter.
func Sentence(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

func (m *Manager) setState(id string, st State) {
	st.Message = Sentence(st.Message)
	m.mu.Lock()
	if e := m.live[id]; e != nil {
		st.Conns = e.conns
		if st.Address == "" {
			st.Address = e.state.Address
		}
		if st.DNS == nil {
			st.DNS = e.state.DNS
		}
		e.state = st
	}
	m.mu.Unlock()
	if m.opt.OnState != nil {
		m.opt.OnState(id, st)
	}
}

// State is the tunnel's state now; ok = false when it isn't open.
func (m *Manager) State(id string) (State, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.live[id]
	if e == nil {
		return State{}, false
	}
	st := e.state
	st.Conns = e.conns
	return st, true
}

// Close closes the tunnel if it's open.
func (m *Manager) Close(id string) {
	m.mu.Lock()
	e := m.live[id]
	delete(m.live, id)
	m.mu.Unlock()
	if e == nil {
		return
	}
	<-e.ready
	if e.link != nil {
		e.link.close()
		m.log(id, "Disconnected")
	}
	m.setState(id, State{Status: StatusIdle, Since: time.Now()})
}

// Open opens the tunnel (or returns the open one) and waits for it.
func (m *Manager) Open(ctx context.Context, spec Spec) error {
	_, err := m.get(ctx, spec)
	return err
}

func (m *Manager) get(ctx context.Context, spec Spec) (*entry, error) {
	version := spec.Version()
	m.mu.Lock()
	e := m.live[spec.ID]
	if e != nil {
		stale := e.version != version
		select {
		case <-e.ready:
			if e.err != nil {
				stale = true
			} else if d := e.link.done(); d != nil {
				select {
				case <-d:
					stale = true
				default:
				}
			}
		default:
		}
		if stale {
			delete(m.live, spec.ID)
			old := e
			go func() {
				<-old.ready
				if old.link != nil {
					old.link.close()
				}
			}()
			e = nil
		}
	}
	if e == nil {
		e = &entry{spec: spec, version: version, ready: make(chan struct{}), lastUse: time.Now()}
		m.live[spec.ID] = e
		m.mu.Unlock()
		go m.start(e)
	} else {
		m.mu.Unlock()
	}
	select {
	case <-e.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if e.err != nil {
		return nil, e.err
	}
	return e, nil
}

const openTimeout = 45 * time.Second

func (m *Manager) start(e *entry) {
	id := e.spec.ID
	m.setState(id, State{Status: StatusConnecting, Since: time.Now()})
	m.log(id, "Connecting…")
	ctx, cancel := context.WithTimeout(context.Background(), openTimeout)
	l, info, err := m.open(ctx, e.spec, func(line string) { m.log(id, line) })
	cancel()
	m.mu.Lock()
	e.link, e.err = l, err
	if err == nil {
		e.state.Address, e.state.DNS = info.address, info.dns
	}
	close(e.ready)
	m.mu.Unlock()
	if err != nil {
		m.log(id, "Couldn't connect: "+err.Error())
		m.setState(id, State{Status: StatusFailed, Message: err.Error(), Since: time.Now()})
		m.mu.Lock()
		if m.live[id] == e {
			delete(m.live, id)
		}
		m.mu.Unlock()
		return
	}
	m.log(id, "Connected")
	m.setState(id, State{Status: StatusConnected, Since: time.Now(), Address: info.address, DNS: info.dns})
	if d := l.done(); d != nil {
		go func() {
			<-d
			m.mu.Lock()
			still := m.live[id] == e
			if still {
				delete(m.live, id)
			}
			m.mu.Unlock()
			if !still {
				return
			}
			msg := "The connection dropped"
			if f := l.failure(); f != nil {
				msg = f.Error()
			}
			m.log(id, msg)
			m.setState(id, State{Status: StatusFailed, Message: msg, Since: time.Now()})
		}()
	}
}

// opened is what a VPN told us once it's up.
type opened struct {
	address string
	dns     []string
}

func (m *Manager) open(ctx context.Context, s Spec, log func(string)) (link, opened, error) {
	switch s.Kind {
	case KindJump:
		if m.opt.Jump == nil {
			return nil, opened{}, errors.New("jump hosts aren't available")
		}
		id := s.Config.ServerID
		return stateless{func(ctx context.Context, network, addr string) (net.Conn, error) {
			dial, err := m.opt.Jump(ctx, id)
			if err != nil {
				return nil, err
			}
			return dial(ctx, network, addr)
		}}, opened{}, nil
	case KindSOCKS5:
		return stateless{socksDialer(s)}, opened{}, nil
	case KindHTTP:
		return stateless{httpDialer(s)}, opened{}, nil
	case KindWireGuard:
		return openWireGuard(ctx, s, log)
	case KindOpenConnect:
		return openOpenConnect(ctx, s, m.exe(), log)
	case KindOpenVPN, KindSSTP:
		return openNamespaced(ctx, s, m.exe(), log)
	}
	return nil, opened{}, fmt.Errorf("unknown tunnel kind %q", s.Kind)
}

// Dial opens a connection through the tunnel, opening the tunnel first if
// needed. A tunnel that died is opened again once.
func (m *Manager) Dial(ctx context.Context, spec Spec, network, addr string) (net.Conn, error) {
	for attempt := 0; ; attempt++ {
		e, err := m.get(ctx, spec)
		if err != nil {
			return nil, err
		}
		m.mu.Lock()
		e.lastUse = time.Now()
		m.mu.Unlock()
		c, err := e.link.dial(ctx, network, addr)
		if err != nil {
			if d := e.link.done(); d != nil && attempt == 0 {
				select {
				case <-d:
					continue
				default:
				}
			}
			return nil, err
		}
		m.mu.Lock()
		e.conns++
		e.state.Conns = e.conns
		m.mu.Unlock()
		return &counted{Conn: c, release: func() {
			m.mu.Lock()
			e.conns--
			e.state.Conns = e.conns
			e.lastUse = time.Now()
			m.mu.Unlock()
		}}, nil
	}
}

// Dialer is Dial bound to one tunnel.
func (m *Manager) Dialer(spec Spec) DialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return m.Dial(ctx, spec, network, addr)
	}
}

// TestResult is what a test found.
type TestResult struct {
	OK      bool      `json:"ok"`
	Message string    `json:"message"`
	Address string    `json:"address,omitempty"`
	DNS     []string  `json:"dns,omitempty"`
	Target  string    `json:"target,omitempty"`
	Reached bool      `json:"reached"`
	Ms      int64     `json:"ms"`
	Pin     string    `json:"pin,omitempty"`
	Log     []LogLine `json:"log"`
}

// Test opens a throwaway copy of the tunnel (nothing is saved or shared)
// and, when target is set, connects to it through the tunnel.
func (m *Manager) Test(ctx context.Context, spec Spec, target string) TestResult {
	r := newRing(400)
	var res TestResult
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, openTimeout+15*time.Second)
	defer cancel()
	r.add("Connecting…")
	l, info, err := m.open(ctx, spec, r.add)
	if err != nil {
		res.Message = err.Error()
		var ce *CertError
		if errors.As(err, &ce) {
			res.Pin = ce.Pin
		}
		r.add("Couldn't connect: " + err.Error())
		res.Log = r.lines()
		res.Message = Sentence(res.Message)
		return res
	}
	defer l.close()
	res.Address, res.DNS = info.address, info.dns
	if spec.Kind != KindJump && spec.Kind != KindSOCKS5 && spec.Kind != KindHTTP {
		r.add("Connected")
	}
	res.OK = true
	res.Message = "Connected"
	if target = strings.TrimSpace(target); target != "" {
		res.Target = target
		t0 := time.Now()
		c, err := l.dial(ctx, "tcp", target)
		if err != nil {
			res.OK = false
			res.Message = "Connected, but couldn't reach " + target + ": " + err.Error()
			r.add(res.Message)
		} else {
			c.Close()
			res.Reached = true
			res.Message = "Reached " + target
			r.add(fmt.Sprintf("Reached %s in %d ms", target, time.Since(t0).Milliseconds()))
		}
	}
	res.Ms = time.Since(start).Milliseconds()
	res.Log = r.lines()
	res.Message = Sentence(res.Message)
	return res
}

func (m *Manager) exe() string {
	if m.opt.Executable != "" {
		return m.opt.Executable
	}
	return selfExe()
}

// counted tells the manager when a connection through it closes.
type counted struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *counted) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// CloseWrite passes half-closes through when the connection supports them.
func (c *counted) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// LogLine is one line a tunnel wrote.
type LogLine struct {
	At   time.Time `json:"at"`
	Text string    `json:"text"`
}

type ring struct {
	mu  sync.Mutex
	max int
	buf []LogLine
}

func newRing(max int) *ring { return &ring{max: max} }

func (r *ring) add(text string) {
	text = strings.TrimRight(text, "\r\n")
	if text == "" {
		return
	}
	r.mu.Lock()
	r.buf = append(r.buf, LogLine{At: time.Now(), Text: redact(text)})
	if len(r.buf) > r.max {
		r.buf = r.buf[len(r.buf)-r.max:]
	}
	r.mu.Unlock()
}

func (r *ring) lines() []LogLine {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]LogLine{}, r.buf...)
}
