package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/secrets"
	"github.com/morche/backend/internal/tunnel"
)

// tunnelHandler keeps the ways Morche reaches servers it can't reach
// directly (VPNs, proxies, jump hosts). Owners of a workspace set them up;
// a server picks one in its connection settings.
type tunnelHandler struct {
	q       *sqlc.Queries
	box     *secrets.Box
	authz   *authz
	servers *serverHandler
	mgr     *tunnel.Manager
}

func newTunnelHandler(q *sqlc.Queries, box *secrets.Box, a *authz, servers *serverHandler) *tunnelHandler {
	h := &tunnelHandler{q: q, box: box, authz: a, servers: servers}
	_ = q.ResetTunnelStates(context.Background())
	h.mgr = tunnel.New(tunnel.Options{
		Jump: h.jump,
		OnState: func(id string, st tunnel.State) {
			tid, err := uuid.Parse(id)
			if err != nil {
				return
			}
			if err := q.RecordTunnelState(context.Background(), sqlc.RecordTunnelStateParams{
				ID: tid, Status: st.Status, StatusMessage: st.Message, Address: st.Address,
			}); err != nil {
				slog.Warn("record tunnel state", "error", err)
			}
		},
	})
	servers.tunnels = h
	return h
}

var tunnelKindLabels = map[string]string{
	tunnel.KindJump: "Jump host (SSH)", tunnel.KindSOCKS5: "SOCKS5 proxy", tunnel.KindHTTP: "HTTP proxy",
	tunnel.KindWireGuard: "WireGuard", tunnel.KindOpenVPN: "OpenVPN", tunnel.KindOpenConnect: "openconnect",
	tunnel.KindSSTP: "SSTP",
}

func tunnelKindLabel(kind string, c tunnel.Config) string {
	if kind == tunnel.KindOpenConnect && c.Protocol != "" {
		return tunnel.ProtocolLabel(c.Protocol)
	}
	return tunnelKindLabels[kind]
}

// ---- Models ----

type TunnelIDPath struct {
	ID string `path:"id" format:"uuid"`
}

// TunnelConfig is a tunnel's settings, without secrets. Only the fields of
// its kind are kept.
type TunnelConfig struct {
	ServerID      string   `json:"server_id,omitempty" doc:"jump: the Morche server to hop through"`
	Host          string   `json:"host,omitempty" maxLength:"253" doc:"socks5/http: the proxy; openconnect/sstp: the VPN server"`
	Port          int      `json:"port,omitempty" minimum:"0" maximum:"65535"`
	Username      string   `json:"username,omitempty" maxLength:"200"`
	TLS           bool     `json:"tls,omitempty" doc:"http: talk to the proxy over TLS"`
	Addresses     []string `json:"addresses,omitempty" maxItems:"8" doc:"wireguard: this side's addresses (Interface › Address)"`
	PeerPublicKey string   `json:"peer_public_key,omitempty" maxLength:"60"`
	Endpoint      string   `json:"endpoint,omitempty" maxLength:"260" doc:"wireguard: host:port"`
	AllowedIPs    []string `json:"allowed_ips,omitempty" maxItems:"64"`
	Keepalive     int      `json:"keepalive,omitempty" minimum:"0" maximum:"3600"`
	MTU           int      `json:"mtu,omitempty" minimum:"0" maximum:"9000"`
	Protocol      string   `json:"protocol,omitempty" enum:"anyconnect,fortinet,gp,pulse,nc,f5,array,"`
	Group         string   `json:"group,omitempty" maxLength:"200" doc:"openconnect: login group (authgroup)"`
	ServerCert    string   `json:"server_cert,omitempty" maxLength:"120" doc:"openconnect: the trusted certificate, pin-sha256:…; empty = the system's CAs"`
	IgnoreCert    bool     `json:"ignore_cert,omitempty" doc:"sstp: accept a certificate the system doesn't trust"`
	DNS           []string `json:"dns,omitempty" maxItems:"4" doc:"VPNs: name servers inside it; empty = what the VPN hands out"`
}

func (c TunnelConfig) toTunnel() tunnel.Config {
	return tunnel.Config{
		ServerID: c.ServerID, Host: c.Host, Port: c.Port, Username: c.Username, TLS: c.TLS,
		Addresses: c.Addresses, PeerPublicKey: c.PeerPublicKey, Endpoint: c.Endpoint,
		AllowedIPs: c.AllowedIPs, Keepalive: c.Keepalive, MTU: c.MTU, Protocol: c.Protocol,
		Group: c.Group, ServerCert: c.ServerCert, IgnoreCert: c.IgnoreCert, DNS: c.DNS,
	}
}

func fromTunnelConfig(c tunnel.Config) TunnelConfig {
	return TunnelConfig{
		ServerID: c.ServerID, Host: c.Host, Port: c.Port, Username: c.Username, TLS: c.TLS,
		Addresses: nonNil(c.Addresses), PeerPublicKey: c.PeerPublicKey, Endpoint: c.Endpoint,
		AllowedIPs: nonNil(c.AllowedIPs), Keepalive: c.Keepalive, MTU: c.MTU, Protocol: c.Protocol,
		Group: c.Group, ServerCert: c.ServerCert, IgnoreCert: c.IgnoreCert, DNS: nonNil(c.DNS),
	}
}

type Tunnel struct {
	ID              string       `json:"id" format:"uuid"`
	WorkspaceID     string       `json:"workspace_id" format:"uuid"`
	Name            string       `json:"name"`
	Kind            string       `json:"kind" enum:"jump,socks5,http,wireguard,openvpn,openconnect,sstp"`
	KindLabel       string       `json:"kind_label"`
	Config          TunnelConfig `json:"config"`
	Description     string       `json:"description"`
	HasPassword     bool         `json:"has_password"`
	HasPrivateKey   bool         `json:"has_private_key"`
	HasPresharedKey bool         `json:"has_preshared_key"`
	HasConfigFile   bool         `json:"has_config_file"`
	HasPassphrase   bool         `json:"has_passphrase"`
	// Remotes are the VPN servers an .ovpn file connects to.
	Remotes         []string   `json:"remotes"`
	Status          string     `json:"status" enum:"idle,connecting,connected,failed"`
	StatusMessage   string     `json:"status_message"`
	StatusAt        *time.Time `json:"status_at,omitempty"`
	Address         string     `json:"address" doc:"The address the VPN gave Morche"`
	DNS             []string   `json:"dns" doc:"Name servers in use inside the VPN"`
	Conns           int        `json:"conns" doc:"Connections open through it now"`
	ServerCount     int        `json:"server_count" doc:"Servers reached through it"`
	OtherCount      int        `json:"other_count" doc:"Databases, clusters, monitors and storages reached through it"`
	LastConnectedAt *time.Time `json:"last_connected_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type TunnelOutput struct {
	Body Tunnel
}

type TunnelsOutput struct {
	Body struct {
		Items []Tunnel `json:"items"`
		// Tools says which VPN programs are installed where Morche runs.
		Tools map[string]bool `json:"tools"`
	}
}

type TunnelBody struct {
	Name        string       `json:"name" minLength:"1" maxLength:"100"`
	Kind        string       `json:"kind" enum:"jump,socks5,http,wireguard,openvpn,openconnect,sstp"`
	Description string       `json:"description,omitempty" maxLength:"500"`
	Config      TunnelConfig `json:"config"`
	// Secrets: blank keeps the saved one.
	Password     string   `json:"password,omitempty" maxLength:"1024"`
	PrivateKey   string   `json:"private_key,omitempty" maxLength:"100"`
	PresharedKey string   `json:"preshared_key,omitempty" maxLength:"100"`
	ConfigFile   string   `json:"config_file,omitempty" maxLength:"262144" doc:"openvpn: the .ovpn file"`
	Passphrase   string   `json:"passphrase,omitempty" maxLength:"1024"`
	Clear        []string `json:"clear,omitempty" doc:"Saved secrets to drop" enum:"password,preshared_key,passphrase"`
}

func (h *tunnelHandler) openSecrets(t sqlc.Tunnel) (tunnel.Secrets, error) {
	var s tunnel.Secrets
	if len(t.SecretsEnc) == 0 {
		return s, nil
	}
	plain, err := h.box.Open(t.SecretsEnc)
	if err != nil {
		return s, err
	}
	err = json.Unmarshal([]byte(plain), &s)
	return s, err
}

func tunnelConfigOf(t sqlc.Tunnel) tunnel.Config {
	var c tunnel.Config
	_ = json.Unmarshal(t.Config, &c)
	return c
}

func (h *tunnelHandler) spec(t sqlc.Tunnel) (tunnel.Spec, error) {
	sec, err := h.openSecrets(t)
	if err != nil {
		return tunnel.Spec{}, err
	}
	return tunnel.Spec{ID: t.ID.String(), Name: t.Name, Kind: t.Kind, Config: tunnelConfigOf(t), Secrets: sec}, nil
}

func (h *tunnelHandler) toTunnel(t sqlc.Tunnel, servers int, others ...int) Tunnel {
	c := tunnelConfigOf(t)
	sec, _ := h.openSecrets(t)
	out := Tunnel{
		ID: t.ID.String(), WorkspaceID: t.WorkspaceID.String(), Name: t.Name, Kind: t.Kind,
		KindLabel: tunnelKindLabel(t.Kind, c), Config: fromTunnelConfig(c), Description: t.Description,
		HasPassword: sec.Password != "", HasPrivateKey: sec.PrivateKey != "",
		HasPresharedKey: sec.PresharedKey != "", HasConfigFile: sec.ConfigFile != "",
		HasPassphrase: sec.Passphrase != "", Remotes: []string{},
		Status: t.Status, StatusMessage: t.StatusMessage, StatusAt: t.StatusAt, Address: t.Address,
		DNS: []string{}, ServerCount: servers, LastConnectedAt: t.LastConnectedAt,
		OtherCount: sum(others),
		CreatedAt:  t.CreatedAt, UpdatedAt: t.UpdatedAt,
	}
	if t.Kind == tunnel.KindOpenVPN && sec.ConfigFile != "" {
		if f, err := tunnel.ParseOpenVPN(sec.ConfigFile); err == nil {
			out.Remotes = f.Remotes
		}
	}
	if st, ok := h.mgr.State(out.ID); ok {
		out.Status, out.StatusMessage, out.Conns = st.Status, st.Message, st.Conns
		if st.Address != "" {
			out.Address = st.Address
		}
		if st.DNS != nil {
			out.DNS = st.DNS
		}
		at := st.Since
		out.StatusAt = &at
	} else {
		// Not open: no address, whatever was stored.
		out.Address = ""
		if out.Status == tunnel.StatusConnected || out.Status == tunnel.StatusConnecting {
			out.Status = tunnel.StatusIdle
		}
	}
	return out
}

func (h *tunnelHandler) get(ctx context.Context, rawID string) (sqlc.Tunnel, error) {
	id, err := uuid.Parse(rawID)
	if err != nil {
		return sqlc.Tunnel{}, huma.Error404NotFound("Tunnel not found")
	}
	t, err := h.q.GetTunnel(ctx, id)
	if isNotFound(err) {
		return t, huma.Error404NotFound("Tunnel not found")
	}
	if err != nil {
		return t, internalError(err)
	}
	return t, nil
}

func sum(list []int) int {
	n := 0
	for _, v := range list {
		n += v
	}
	return n
}

// out is the tunnel with what goes through it counted.
func (h *tunnelHandler) out(ctx context.Context, t sqlc.Tunnel) Tunnel {
	users, _ := h.q.ListTunnelUsers(ctx, t.ID)
	servers := 0
	for _, u := range users {
		if u.Kind == "server" {
			servers++
		}
	}
	return h.toTunnel(t, servers, len(users)-servers)
}

// ---- Validation ----

var pinValue = regexp.MustCompile(`^pin-sha256:[A-Za-z0-9+/]{43}=$`)

// clean checks a body for its kind and drops the other kinds' fields.
func (h *tunnelHandler) clean(ctx context.Context, ws uuid.UUID, b *TunnelBody, sec *tunnel.Secrets) (tunnel.Config, error) {
	in := b.Config
	var c tunnel.Config
	trim := func(list []string) []string {
		var out []string
		for _, s := range list {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	host := func(field string, required bool) (string, error) {
		v := strings.TrimSpace(in.Host)
		if v == "" {
			if required {
				return "", fieldError("body.config."+field, "Enter the address", v)
			}
			return "", nil
		}
		n, err := normalizeHost(v)
		if err != nil {
			return "", fieldError("body.config."+field, "Enter a host name or IP address", v)
		}
		return n, nil
	}
	port := func(def int) int {
		if in.Port == 0 {
			return def
		}
		return in.Port
	}
	dns := trim(in.DNS)
	if _, err := tunnel.Addrs(dns); err != nil {
		return c, fieldError("body.config.dns", err.Error(), in.DNS)
	}
	user := strings.TrimSpace(in.Username)
	if strings.ContainsAny(user, "\r\n") {
		return c, fieldError("body.config.username", "One line only", user)
	}
	switch b.Kind {
	case tunnel.KindJump:
		id, err := uuid.Parse(in.ServerID)
		if err != nil {
			return c, fieldError("body.config.server_id", "Pick the server to hop through", in.ServerID)
		}
		s, err := h.q.GetServer(ctx, id)
		if err != nil || s.WorkspaceID != ws {
			return c, fieldError("body.config.server_id", "Pick a server in this workspace", in.ServerID)
		}
		c.ServerID = id.String()
		*sec = tunnel.Secrets{}
	case tunnel.KindSOCKS5, tunnel.KindHTTP:
		var err error
		if c.Host, err = host("host", true); err != nil {
			return c, err
		}
		c.Port = port(map[string]int{tunnel.KindSOCKS5: 1080, tunnel.KindHTTP: 3128}[b.Kind])
		c.Username = user
		c.TLS = b.Kind == tunnel.KindHTTP && in.TLS
		if user == "" {
			sec.Password = ""
		}
		*sec = tunnel.Secrets{Password: sec.Password}
	case tunnel.KindWireGuard:
		addrs := trim(in.Addresses)
		if len(addrs) == 0 {
			return c, fieldError("body.config.addresses", "Enter this side's address, like 10.0.0.2/32", in.Addresses)
		}
		if _, err := tunnel.Prefixes(addrs); err != nil {
			return c, fieldError("body.config.addresses", err.Error(), in.Addresses)
		}
		if _, err := tunnel.WireGuardKey(in.PeerPublicKey); err != nil {
			return c, fieldError("body.config.peer_public_key", "The peer's public key is 44 characters of base64", in.PeerPublicKey)
		}
		ep := strings.TrimSpace(in.Endpoint)
		eh, ep2, err := net.SplitHostPort(ep)
		if n, perr := strconv.Atoi(ep2); err != nil || eh == "" || perr != nil || n < 1 || n > 65535 {
			return c, fieldError("body.config.endpoint", "Enter host:port, like vpn.example.com:51820", ep)
		}
		allowed := trim(in.AllowedIPs)
		if _, err := tunnel.Prefixes(allowed); err != nil {
			return c, fieldError("body.config.allowed_ips", err.Error(), in.AllowedIPs)
		}
		if in.MTU != 0 && (in.MTU < 576 || in.MTU > 9000) {
			return c, fieldError("body.config.mtu", "Between 576 and 9000, or empty", in.MTU)
		}
		if sec.PrivateKey == "" {
			return c, fieldError("body.private_key", "Paste this side's private key", "")
		}
		if _, err := tunnel.WireGuardKey(sec.PrivateKey); err != nil {
			return c, fieldError("body.private_key", "The private key is 44 characters of base64", "")
		}
		if sec.PresharedKey != "" {
			if _, err := tunnel.WireGuardKey(sec.PresharedKey); err != nil {
				return c, fieldError("body.preshared_key", "The preshared key is 44 characters of base64", "")
			}
		}
		c.Addresses, c.PeerPublicKey, c.Endpoint, c.AllowedIPs = addrs, strings.TrimSpace(in.PeerPublicKey), ep, allowed
		c.Keepalive, c.MTU, c.DNS = in.Keepalive, in.MTU, dns
		*sec = tunnel.Secrets{PrivateKey: strings.TrimSpace(sec.PrivateKey), PresharedKey: strings.TrimSpace(sec.PresharedKey)}
	case tunnel.KindOpenVPN:
		if sec.ConfigFile == "" {
			return c, fieldError("body.config_file", "Paste or upload the .ovpn file", "")
		}
		f, err := tunnel.ParseOpenVPN(sec.ConfigFile)
		if err != nil {
			return c, fieldError("body.config_file", err.Error(), "")
		}
		if f.NeedsLogin && user == "" {
			return c, fieldError("body.config.username", "This VPN asks for a username and password", "")
		}
		if f.NeedsPassphrase && sec.Passphrase == "" {
			return c, fieldError("body.passphrase", "The file's private key is encrypted: enter its passphrase", "")
		}
		c.Username, c.DNS = user, dns
		pw := sec.Password
		if user == "" {
			pw = ""
		}
		*sec = tunnel.Secrets{ConfigFile: sec.ConfigFile, Password: pw, Passphrase: sec.Passphrase}
	case tunnel.KindOpenConnect:
		if !slices.Contains(tunnel.Protocols, in.Protocol) {
			return c, fieldError("body.config.protocol", "Pick the VPN's type", in.Protocol)
		}
		var err error
		if c.Host, err = host("host", true); err != nil {
			return c, err
		}
		c.Port = port(443)
		if user == "" {
			return c, fieldError("body.config.username", "Enter the username", "")
		}
		if sec.Password == "" {
			return c, fieldError("body.password", "Enter the password", "")
		}
		cert := strings.TrimSpace(in.ServerCert)
		if cert != "" && !pinValue.MatchString(cert) {
			return c, fieldError("body.config.server_cert", "A certificate pin looks like pin-sha256:… (44 characters after the colon)", cert)
		}
		group := strings.TrimSpace(in.Group)
		if strings.ContainsAny(group, "\r\n") {
			return c, fieldError("body.config.group", "One line only", group)
		}
		c.Protocol, c.Username, c.Group, c.ServerCert, c.DNS = in.Protocol, user, group, cert, dns
		*sec = tunnel.Secrets{Password: sec.Password}
	case tunnel.KindSSTP:
		var err error
		if c.Host, err = host("host", true); err != nil {
			return c, err
		}
		c.Port = port(443)
		if user == "" {
			return c, fieldError("body.config.username", "Enter the username", "")
		}
		if sec.Password == "" {
			return c, fieldError("body.password", "Enter the password", "")
		}
		c.Username, c.IgnoreCert, c.DNS = user, in.IgnoreCert, dns
		*sec = tunnel.Secrets{Password: sec.Password}
	default:
		return c, fieldError("body.kind", "Pick a kind", b.Kind)
	}
	return c, nil
}

// secretsOf merges the body's secrets over the saved ones.
func (h *tunnelHandler) secretsOf(b TunnelBody, prev *sqlc.Tunnel) (tunnel.Secrets, error) {
	var s tunnel.Secrets
	if prev != nil && prev.Kind == b.Kind {
		var err error
		if s, err = h.openSecrets(*prev); err != nil {
			return s, internalError(err)
		}
	}
	for _, c := range b.Clear {
		switch c {
		case "password":
			s.Password = ""
		case "preshared_key":
			s.PresharedKey = ""
		case "passphrase":
			s.Passphrase = ""
		}
	}
	set := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	set(&s.Password, b.Password)
	set(&s.PrivateKey, strings.TrimSpace(b.PrivateKey))
	set(&s.PresharedKey, strings.TrimSpace(b.PresharedKey))
	set(&s.ConfigFile, b.ConfigFile)
	set(&s.Passphrase, b.Passphrase)
	return s, nil
}

func (h *tunnelHandler) seal(s tunnel.Secrets) ([]byte, error) {
	if s == (tunnel.Secrets{}) {
		return nil, nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return h.box.Seal(string(b)), nil
}

func (h *tunnelHandler) ownerOf(ctx context.Context, p *principal) (uuid.UUID, error) {
	ws, err := h.authz.createTarget(ctx, p)
	if err != nil {
		return uuid.Nil, err
	}
	if p.Access.WorkspaceLevel(ws) < auth.Owner {
		return uuid.Nil, huma.Error403Forbidden("You need Owner access to the workspace to set up a tunnel.")
	}
	return ws, nil
}

// ---- Handlers ----

func (h *tunnelHandler) list(ctx context.Context, _ *struct{}) (*TunnelsOutput, error) {
	sc := principalOf(ctx).scope()
	rows, err := h.q.ListTunnels(ctx, sqlc.ListTunnelsParams{SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, WorkspaceID: sc.current})
	if err != nil {
		return nil, internalError(err)
	}
	out := &TunnelsOutput{}
	out.Body.Items = make([]Tunnel, 0, len(rows))
	for _, r := range rows {
		out.Body.Items = append(out.Body.Items, h.toTunnel(sqlc.Tunnel{
			ID: r.ID, WorkspaceID: r.WorkspaceID, Name: r.Name, Kind: r.Kind, Config: r.Config,
			SecretsEnc: r.SecretsEnc, Description: r.Description, Status: r.Status,
			StatusMessage: r.StatusMessage, Address: r.Address, StatusAt: r.StatusAt,
			LastConnectedAt: r.LastConnectedAt, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		}, int(r.ServerCount), int(r.OtherCount)))
	}
	out.Body.Tools = tunnelTools()
	return out, nil
}

// tunnelTools: which programs the VPN kinds need are installed here.
func tunnelTools() map[string]bool {
	has := func(name string) bool {
		_, err := exec.LookPath(name)
		return err == nil
	}
	return map[string]bool{
		tunnel.KindOpenVPN: has("openvpn"), tunnel.KindOpenConnect: has("openconnect"), tunnel.KindSSTP: has("sstpc"),
		tunnel.KindJump: true, tunnel.KindSOCKS5: true, tunnel.KindHTTP: true, tunnel.KindWireGuard: true,
	}
}

func (h *tunnelHandler) create(ctx context.Context, in *struct{ Body TunnelBody }) (*TunnelOutput, error) {
	p := principalOf(ctx)
	ws, err := h.ownerOf(ctx, p)
	if err != nil {
		return nil, err
	}
	b := in.Body
	sec, err := h.secretsOf(b, nil)
	if err != nil {
		return nil, err
	}
	c, err := h.clean(ctx, ws, &b, &sec)
	if err != nil {
		return nil, err
	}
	cj, _ := json.Marshal(c)
	enc, err := h.seal(sec)
	if err != nil {
		return nil, internalError(err)
	}
	t, err := h.q.CreateTunnel(ctx, sqlc.CreateTunnelParams{
		WorkspaceID: ws, Name: strings.TrimSpace(b.Name), Kind: b.Kind, Config: cj, SecretsEnc: enc,
		Description: strings.TrimSpace(b.Description),
	})
	if isUniqueViolation(err) {
		return nil, fieldError("body.name", "A tunnel with this name already exists", b.Name)
	}
	if err != nil {
		return nil, internalError(err)
	}
	return &TunnelOutput{Body: h.toTunnel(t, 0)}, nil
}

func (h *tunnelHandler) update(ctx context.Context, in *struct {
	TunnelIDPath
	Body TunnelBody
}) (*TunnelOutput, error) {
	prev, err := h.get(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	b := in.Body
	if b.Kind != prev.Kind {
		return nil, fieldError("body.kind", "A tunnel's kind can't change: add a new one", b.Kind)
	}
	sec, err := h.secretsOf(b, &prev)
	if err != nil {
		return nil, err
	}
	c, err := h.clean(ctx, prev.WorkspaceID, &b, &sec)
	if err != nil {
		return nil, err
	}
	cj, _ := json.Marshal(c)
	enc, err := h.seal(sec)
	if err != nil {
		return nil, internalError(err)
	}
	t, err := h.q.UpdateTunnel(ctx, sqlc.UpdateTunnelParams{
		ID: prev.ID, Name: strings.TrimSpace(b.Name), Config: cj, SecretsEnc: enc,
		Description: strings.TrimSpace(b.Description),
	})
	if isUniqueViolation(err) {
		return nil, fieldError("body.name", "A tunnel with this name already exists", b.Name)
	}
	if err != nil {
		return nil, internalError(err)
	}
	// Open connections keep the old settings until the tunnel reopens.
	h.mgr.Close(t.ID.String())
	h.servers.dropTunnelConns(ctx, t.ID)
	return &TunnelOutput{Body: h.out(ctx, t)}, nil
}

func (h *tunnelHandler) remove(ctx context.Context, in *TunnelIDPath) (*struct{}, error) {
	t, err := h.get(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	using, err := h.q.ListTunnelUsers(ctx, t.ID)
	if err != nil {
		return nil, internalError(err)
	}
	if len(using) > 0 {
		names := make([]string, 0, 3)
		for i, s := range using {
			if i == 3 {
				names = append(names, fmt.Sprintf("%d more", len(using)-3))
				break
			}
			names = append(names, s.Name)
		}
		return nil, huma.Error409Conflict("Still in use by " + strings.Join(names, ", ") + ". Change how they're reached first.")
	}
	h.mgr.Close(t.ID.String())
	if err := h.q.DeleteTunnel(ctx, t.ID); err != nil {
		return nil, internalError(err)
	}
	return nil, nil
}

type TunnelTestBody struct {
	TunnelBody
	TunnelID *string `json:"tunnel_id,omitempty" format:"uuid" doc:"When editing: the saved tunnel, whose secrets blank ones stand for"`
	Target   string  `json:"target,omitempty" maxLength:"260" doc:"host:port to reach through it, like 10.0.0.5:22"`
}

type TunnelTestOutput struct {
	Body tunnel.TestResult
}

func (h *tunnelHandler) test(ctx context.Context, in *struct{ Body TunnelTestBody }) (*TunnelTestOutput, error) {
	p := principalOf(ctx)
	b := in.Body
	var prev *sqlc.Tunnel
	var ws uuid.UUID
	if id := parseOptionalID(b.TunnelID); id != nil {
		t, err := h.get(ctx, id.String())
		if err != nil {
			return nil, err
		}
		switch lvl := p.Access.WorkspaceLevel(t.WorkspaceID); {
		case lvl == auth.None:
			return nil, huma.Error404NotFound("Tunnel not found")
		case lvl < auth.Owner:
			return nil, huma.Error403Forbidden("You need Owner access to use this tunnel's saved secrets.")
		}
		prev, ws = &t, t.WorkspaceID
	} else {
		var err error
		if ws, err = h.ownerOf(ctx, p); err != nil {
			return nil, err
		}
	}
	sec, err := h.secretsOf(b.TunnelBody, prev)
	if err != nil {
		return nil, err
	}
	c, err := h.clean(ctx, ws, &b.TunnelBody, &sec)
	if err != nil {
		return nil, err
	}
	target := strings.TrimSpace(b.Target)
	if target != "" {
		if _, port, err := net.SplitHostPort(target); err != nil || port == "" {
			return nil, fieldError("body.target", "Enter host:port, like 10.0.0.5:22", target)
		}
	}
	spec := tunnel.Spec{ID: "test-" + uuid.NewString(), Kind: b.Kind, Config: c, Secrets: sec}
	res := h.mgr.Test(ctx, spec, target)
	return &TunnelTestOutput{Body: res}, nil
}

type TunnelLogOutput struct {
	Body struct {
		Lines []tunnel.LogLine `json:"lines"`
	}
}

type TunnelServer struct {
	ID     string `json:"id" format:"uuid"`
	Name   string `json:"name"`
	Host   string `json:"host"`
	Port   int32  `json:"port"`
	Status string `json:"status"`
}

type TunnelUser struct {
	Kind   string `json:"kind" enum:"server,database,cluster,monitor,storage"`
	ID     string `json:"id" format:"uuid"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type TunnelUsersOutput struct {
	Body struct {
		Items []TunnelUser `json:"items"`
	}
}

type TunnelServersOutput struct {
	Body struct {
		Items []TunnelServer `json:"items"`
	}
}

// ---- Dialing ----

type hopsKey struct{}

// jump dials through a Morche server's pooled SSH connection.
func (h *tunnelHandler) jump(ctx context.Context, serverID string) (tunnel.DialFunc, error) {
	hops, _ := ctx.Value(hopsKey{}).([]string)
	if slices.Contains(hops, serverID) {
		return nil, errors.New("these jump hosts go round in a loop")
	}
	if len(hops) >= 5 {
		return nil, errors.New("too many jump hosts in a row (5 at most)")
	}
	ctx = context.WithValue(ctx, hopsKey{}, append(slices.Clone(hops), serverID))
	c, err := h.servers.conn(ctx, serverID)
	if err != nil {
		var se huma.StatusError
		if errors.As(err, &se) {
			return nil, fmt.Errorf("the jump host: %s", strings.TrimPrefix(err.Error(), "Couldn't connect to the server: "))
		}
		return nil, err
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c.Acquire()
		conn, err := c.Client.DialContext(ctx, network, addr)
		if err != nil {
			c.Release()
			return nil, fmt.Errorf("the jump host couldn't reach %s: %w", addr, err)
		}
		return &releasing{Conn: conn, release: c.Release}, nil
	}, nil
}

type releasing struct {
	net.Conn
	done    bool
	release func()
}

func (r *releasing) Close() error {
	err := r.Conn.Close()
	if !r.done {
		r.done = true
		r.release()
	}
	return err
}

// dialFor returns how to reach a server through its tunnel. The tunnel is
// read when dialing, so a change applies to the next connection.
func (h *tunnelHandler) dialFor(serverID uuid.UUID, ws uuid.UUID, tunnelID uuid.UUID) tunnel.DialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		t, err := h.q.GetTunnel(ctx, tunnelID)
		if err != nil {
			return nil, errors.New("its tunnel was removed")
		}
		if t.WorkspaceID != ws {
			return nil, fmt.Errorf("the tunnel %s is in another workspace", t.Name)
		}
		spec, err := h.spec(t)
		if err != nil {
			return nil, err
		}
		if t.Kind == tunnel.KindJump && tunnelConfigOf(t).ServerID == serverID.String() {
			return nil, errors.New("a server can't be its own jump host")
		}
		c, err := h.mgr.Dial(ctx, spec, network, addr)
		if err != nil {
			return nil, fmt.Errorf("through %s: %w", t.Name, err)
		}
		return c, nil
	}
}

// pick checks a tunnel picked for something in workspace ws (the body's
// field is named by field).
func (h *tunnelHandler) pick(ctx context.Context, p *principal, ws uuid.UUID, raw *string, field string) (*uuid.UUID, error) {
	id := parseOptionalID(raw)
	if id == nil {
		return nil, nil
	}
	t, err := h.q.GetTunnel(ctx, *id)
	if err != nil || t.WorkspaceID != ws || p.Access.WorkspaceLevel(ws) == auth.None {
		return nil, fieldError(field, "Pick a tunnel in this workspace", *raw)
	}
	if p.Access.WorkspaceLevel(ws) < auth.Operator {
		return nil, fieldError(field, "You need Operator access to the workspace to use its tunnels", *raw)
	}
	return id, nil
}

// dialVia reaches something that isn't a server through a tunnel.
func (h *tunnelHandler) dialVia(ws, tunnelID uuid.UUID) tunnel.DialFunc {
	return h.dialFor(uuid.Nil, ws, tunnelID)
}

// checkServerTunnel checks a tunnel a server is set to go through.
func (h *tunnelHandler) checkServerTunnel(ctx context.Context, p *principal, ws uuid.UUID, serverID *uuid.UUID, raw *string) (*uuid.UUID, error) {
	id, err := h.pick(ctx, p, ws, raw, "body.tunnel_id")
	if id == nil || err != nil {
		return id, err
	}
	t, err := h.q.GetTunnel(ctx, *id)
	if err != nil {
		return nil, internalError(err)
	}
	// A chain of jump hosts must end somewhere.
	seen := map[string]bool{}
	if serverID != nil {
		seen[serverID.String()] = true
	}
	for cur := t; cur.Kind == tunnel.KindJump; {
		next := tunnelConfigOf(cur).ServerID
		if seen[next] {
			return nil, fieldError("body.tunnel_id", "That would make the jump hosts go round in a loop", *raw)
		}
		seen[next] = true
		nid, _ := uuid.Parse(next)
		s, err := h.q.GetServer(ctx, nid)
		if err != nil || s.TunnelID == nil {
			break
		}
		if cur, err = h.q.GetTunnel(ctx, *s.TunnelID); err != nil {
			break
		}
		if len(seen) > 6 {
			return nil, fieldError("body.tunnel_id", "Too many jump hosts in a row (5 at most)", *raw)
		}
	}
	return id, nil
}

func registerTunnels(api huma.API, h *tunnelHandler) {
	tags := []string{"Tunnels"}

	huma.Register(api, huma.Operation{
		OperationID: "list-tunnels", Method: http.MethodGet, Path: "/tunnels",
		Summary: "List tunnels", Description: "VPNs, proxies and jump hosts servers can be reached through.", Tags: tags,
	}, h.list)

	huma.Register(api, huma.Operation{
		OperationID: "create-tunnel", Method: http.MethodPost, Path: "/tunnels",
		Summary: "Set up a tunnel", Tags: tags, DefaultStatus: http.StatusCreated,
	}, h.create)

	huma.Register(api, huma.Operation{
		OperationID: "test-tunnel", Method: http.MethodPost, Path: "/tunnels/test",
		Summary:     "Test tunnel settings",
		Description: "Opens a throwaway copy of the tunnel (nothing is saved) and, with a target, connects to it through the tunnel.",
		Tags:        tags,
	}, h.test)

	huma.Register(api, huma.Operation{
		OperationID: "get-tunnel", Method: http.MethodGet, Path: "/tunnels/{id}", Summary: "Get a tunnel", Tags: tags,
	}, func(ctx context.Context, in *TunnelIDPath) (*TunnelOutput, error) {
		t, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &TunnelOutput{Body: h.out(ctx, t)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-tunnel", Method: http.MethodPut, Path: "/tunnels/{id}",
		Summary: "Change a tunnel", Description: "Blank secrets keep the saved ones. It reconnects on next use.", Tags: tags,
	}, h.update)

	huma.Register(api, huma.Operation{
		OperationID: "delete-tunnel", Method: http.MethodDelete, Path: "/tunnels/{id}",
		Summary: "Remove a tunnel", Description: "Refused (409) while servers go through it.", Tags: tags,
		DefaultStatus: http.StatusNoContent,
	}, h.remove)

	huma.Register(api, huma.Operation{
		OperationID: "connect-tunnel", Method: http.MethodPost, Path: "/tunnels/{id}/connect",
		Summary: "Connect a tunnel now", Description: "Opens it and waits; it would otherwise open on first use.", Tags: tags,
	}, func(ctx context.Context, in *TunnelIDPath) (*TunnelOutput, error) {
		t, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		spec, err := h.spec(t)
		if err != nil {
			return nil, internalError(err)
		}
		_ = h.mgr.Open(ctx, spec) // the state says how it went
		if t, err = h.get(ctx, in.ID); err != nil {
			return nil, err
		}
		return &TunnelOutput{Body: h.out(ctx, t)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "disconnect-tunnel", Method: http.MethodPost, Path: "/tunnels/{id}/disconnect",
		Summary: "Disconnect a tunnel", Description: "Its servers' connections drop; it opens again on next use.", Tags: tags,
	}, func(ctx context.Context, in *TunnelIDPath) (*TunnelOutput, error) {
		t, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		h.mgr.Close(t.ID.String())
		h.servers.dropTunnelConns(ctx, t.ID)
		if t, err = h.get(ctx, in.ID); err != nil {
			return nil, err
		}
		return &TunnelOutput{Body: h.out(ctx, t)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-tunnel-log", Method: http.MethodGet, Path: "/tunnels/{id}/log",
		Summary: "Read a tunnel's log", Description: "What it wrote since Morche started (the last 400 lines).", Tags: tags,
	}, func(ctx context.Context, in *TunnelIDPath) (*TunnelLogOutput, error) {
		t, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		out := &TunnelLogOutput{}
		out.Body.Lines = h.mgr.Log(t.ID.String())
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-tunnel-users", Method: http.MethodGet, Path: "/tunnels/{id}/users",
		Summary: "What goes through a tunnel", Description: "Servers, databases, Proxmox clusters, monitors and storages, those the caller can see.", Tags: tags,
	}, func(ctx context.Context, in *TunnelIDPath) (*TunnelUsersOutput, error) {
		t, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		rows, err := h.q.ListTunnelUsers(ctx, t.ID)
		if err != nil {
			return nil, internalError(err)
		}
		acc := principalOf(ctx).Access
		out := &TunnelUsersOutput{}
		out.Body.Items = []TunnelUser{}
		for _, r := range rows {
			if r.Kind == "server" && acc.ServerLevel(r.WorkspaceID, r.ID) == auth.None {
				continue
			}
			out.Body.Items = append(out.Body.Items, TunnelUser{Kind: r.Kind, ID: r.ID.String(), Name: r.Name, Status: r.Status})
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-tunnel-servers", Method: http.MethodGet, Path: "/tunnels/{id}/servers",
		Summary: "Servers reached through a tunnel", Tags: tags,
	}, func(ctx context.Context, in *TunnelIDPath) (*TunnelServersOutput, error) {
		t, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		rows, err := h.q.ListTunnelServers(ctx, t.ID)
		if err != nil {
			return nil, internalError(err)
		}
		acc := principalOf(ctx).Access
		out := &TunnelServersOutput{}
		out.Body.Items = []TunnelServer{}
		for _, r := range rows {
			if acc.ServerLevel(r.WorkspaceID, r.ID) == auth.None {
				continue
			}
			out.Body.Items = append(out.Body.Items, TunnelServer{ID: r.ID.String(), Name: r.Name, Host: r.Host, Port: r.Port, Status: r.Status})
		}
		return out, nil
	})
}
