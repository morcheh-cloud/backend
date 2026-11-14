package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/proxmox"
)

// A console is opened in two steps: the API asks Proxmox for a ticket and
// hands the browser a one-time token (plus the VNC password noVNC needs),
// then the browser's websocket comes to the relay with that token. Proxmox's
// own socket is never reached from the browser, so the token stays here.

type pveConsoleGrant struct {
	cluster uuid.UUID
	user    uuid.UUID
	node    string
	kind    proxmox.Kind
	vmid    int
	mode    string // vnc | term
	ticket  proxmox.ConsoleTicket
	expires time.Time
}

type pveConsoles struct {
	mu     sync.Mutex
	grants map[string]pveConsoleGrant
}

var consoles = &pveConsoles{grants: map[string]pveConsoleGrant{}}

// A Proxmox console ticket is good for about 10 s before the socket attaches.
const consoleGrantTTL = 30 * time.Second

func (c *pveConsoles) put(g pveConsoleGrant) string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	token := base64.RawURLEncoding.EncodeToString(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, v := range c.grants {
		if now.After(v.expires) {
			delete(c.grants, k)
		}
	}
	g.expires = now.Add(consoleGrantTTL)
	c.grants[token] = g
	return token
}

// take hands out a grant once.
func (c *pveConsoles) take(token string) (pveConsoleGrant, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	g, ok := c.grants[token]
	delete(c.grants, token)
	if !ok || time.Now().After(g.expires) {
		return pveConsoleGrant{}, false
	}
	return g, true
}

// PVEConsole is what the browser needs to attach.
type PVEConsole struct {
	Token    string `json:"token" doc:"One-time, good for 30 s: pass it to the websocket"`
	Mode     string `json:"mode" enum:"vnc,term"`
	Password string `json:"password,omitempty" doc:"VNC password for noVNC (vnc only)"`
	Node     string `json:"node"`
	Kind     string `json:"kind" enum:"qemu,lxc"`
}

func registerPVEConsole(api huma.API, r chi.Router, h *pveHandler, origins []string) {
	// Not in the OpenAPI spec: websockets aren't expressible there.
	r.Get("/pve-clusters/{id}/console/connect", h.consoleSocket(originPatterns(origins)))

	huma.Register(api, huma.Operation{
		OperationID: "open-pve-console", Method: http.MethodPost, Path: "/pve-clusters/{id}/guests/{vmid}/console",
		Summary: "Open a console on a machine",
		Description: "mode `vnc` = the VM's screen (noVNC; containers too), `term` = a text console: a container's shell, or a VM's serial port (`serial`, like serial0). " +
			"Then connect a websocket to `/pve-clusters/{id}/console/connect?token=`. VNC carries raw RFB bytes both ways. " +
			"term carries terminal bytes as binary frames; the browser sends `{type:\"resize\",cols,rows}` as text, the relay sends `ready`, `exit` and `error`.",
		Tags: []string{"Virtual machines"},
	}, func(ctx context.Context, in *struct {
		PVEGuestPath
		Body struct {
			Mode   string `json:"mode" enum:"vnc,term"`
			Serial string `json:"serial,omitempty" pattern:"^(serial[0-3])?$"`
		}
	}) (*struct{ Body PVEConsole }, error) {
		c, cl, r, err := h.pveGuest(ctx, in.PVEGuestPath)
		if err != nil {
			return nil, err
		}
		if r.Template == 1 {
			return nil, huma.Error409Conflict("A template has no console.")
		}
		if r.Status != "running" {
			return nil, huma.Error409Conflict("Start the machine first: a console needs it running.")
		}
		kind := proxmox.Kind(r.Type)
		serial := in.Body.Serial
		if in.Body.Mode == "term" && kind == proxmox.QEMU && serial == "" {
			serial = "serial0"
		}
		var t proxmox.ConsoleTicket
		if in.Body.Mode == "vnc" {
			t, err = cl.VNCProxy(ctx, r.Node, kind, r.VMID)
		} else {
			t, err = cl.TermProxy(ctx, r.Node, kind, r.VMID, serial)
		}
		if err != nil {
			if in.Body.Mode == "term" && kind == proxmox.QEMU {
				_, msg := pveStatus(err)
				return nil, huma.Error409Conflict(fmt.Sprintf("The VM's %s can't be opened (%s). Add a serial port in Hardware and set the guest's console to it, or use the screen console.", serial, msg))
			}
			return nil, pveError(err)
		}
		token := consoles.put(pveConsoleGrant{
			cluster: c.ID, user: principalOf(ctx).User.ID, node: r.Node, kind: kind,
			vmid: r.VMID, mode: in.Body.Mode, ticket: t,
		})
		out := &struct{ Body PVEConsole }{Body: PVEConsole{Token: token, Mode: in.Body.Mode, Node: r.Node, Kind: r.Type}}
		if in.Body.Mode == "vnc" {
			out.Body.Password = t.Password
			if out.Body.Password == "" {
				out.Body.Password = t.Ticket
			}
		}
		return out, nil
	})
}

func (h *pveHandler) consoleSocket(origins []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: origins, Subprotocols: []string{"binary"}})
		if err != nil {
			return
		}
		defer ws.CloseNow()
		ws.SetReadLimit(4 << 20)
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		fail := func(status int, message string) {
			_ = writeJSON(ctx, ws, controlMessage{Type: "error", Status: status, Message: message})
			ws.Close(websocket.StatusCode(closeBase+status), truncate(message, 120))
		}

		clusterID := chi.URLParam(r, "id")
		token := ""
		if c, err := r.Cookie(sessionCookie); err == nil {
			token = c.Value
		}
		pol := onPVECluster(auth.Engineer)
		ctx = context.WithValue(ctx, clientKey{}, client{ip: hostOf(r.RemoteAddr), userAgent: truncate(r.UserAgent(), 256)})
		if denial := h.authz.addressRefused(ctx, hostOf(r.RemoteAddr)); denial != nil {
			fail(denial.status, denial.message)
			return
		}
		p, denial := h.authz.authorize(ctx, token, pol, clusterID, "")
		if denial != nil {
			fail(denial.status, denial.message)
			return
		}
		ctx, stop := h.authz.track(ctx, p, pol, clusterID)
		defer stop()

		g, ok := consoles.take(r.URL.Query().Get("token"))
		if !ok || g.cluster.String() != clusterID || g.user != p.User.ID {
			fail(http.StatusGone, "This console link has run out. Open the console again.")
			return
		}
		_, cl, err := h.withCluster(ctx, clusterID)
		if err != nil {
			fail(http.StatusNotFound, "Cluster not found")
			return
		}
		dctx, done := context.WithTimeout(ctx, 15*time.Second)
		up, err := cl.DialConsole(dctx, g.node, g.kind, g.vmid, g.ticket)
		done()
		if err != nil {
			_, msg := pveStatus(err)
			fail(http.StatusBadGateway, "Couldn't reach the console: "+cmpOr(msg, err.Error()))
			return
		}
		defer up.CloseNow()

		if g.mode == "vnc" {
			relayVNC(ctx, cancel, ws, up)
		} else {
			relayTerm(ctx, cancel, ws, up, g.ticket)
		}
		ws.Close(websocket.StatusNormalClosure, "")
	}
}

// relayVNC copies RFB bytes both ways.
func relayVNC(ctx context.Context, cancel context.CancelFunc, ws, up *websocket.Conn) {
	go func() {
		defer cancel()
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				return
			}
			if err := up.Write(ctx, websocket.MessageBinary, data); err != nil {
				return
			}
		}
	}()
	for {
		_, data, err := up.Read(ctx)
		if err != nil {
			return
		}
		if err := ws.Write(ctx, websocket.MessageBinary, data); err != nil {
			return
		}
	}
}

// relayTerm speaks Proxmox's termproxy protocol upstream ("user:ticket\n",
// then "0:LEN:DATA", "1:COLS:ROWS:" and "2" pings) and plain bytes to the
// browser, like the server terminal.
func relayTerm(ctx context.Context, cancel context.CancelFunc, ws, up *websocket.Conn, t proxmox.ConsoleTicket) {
	if err := up.Write(ctx, websocket.MessageBinary, []byte(t.User+":"+t.Ticket+"\n")); err != nil {
		_ = writeJSON(ctx, ws, controlMessage{Type: "error", Status: http.StatusBadGateway, Message: "The console refused the ticket."})
		return
	}
	var wmu sync.Mutex
	send := func(b []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		return up.Write(ctx, websocket.MessageBinary, b)
	}
	go func() {
		defer cancel()
		for {
			typ, data, err := ws.Read(ctx)
			if err != nil {
				return
			}
			if typ == websocket.MessageBinary {
				if err := send([]byte(fmt.Sprintf("0:%d:%s", len(data), data))); err != nil {
					return
				}
				continue
			}
			var msg controlMessage
			if json.Unmarshal(data, &msg) == nil && msg.Type == "resize" && msg.Cols > 0 && msg.Rows > 0 {
				if err := send([]byte(fmt.Sprintf("1:%d:%d:", msg.Cols, msg.Rows))); err != nil {
					return
				}
			}
		}
	}()
	go func() {
		tk := time.NewTicker(30 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				if send([]byte("2")) != nil {
					cancel()
					return
				}
			}
		}
	}()
	first := true
	for {
		_, data, err := up.Read(ctx)
		if err != nil {
			if ctx.Err() == nil {
				_ = writeJSON(ctx, ws, controlMessage{Type: "exit", Message: "The console closed."})
			}
			return
		}
		if first {
			first = false
			s := string(data)
			if !strings.HasPrefix(s, "OK") {
				_ = writeJSON(ctx, ws, controlMessage{Type: "error", Status: http.StatusBadGateway, Message: "The console refused the ticket."})
				return
			}
			_ = writeJSON(ctx, ws, controlMessage{Type: "ready"})
			data = data[2:]
			if len(data) == 0 {
				continue
			}
		}
		if err := ws.Write(ctx, websocket.MessageBinary, data); err != nil {
			return
		}
	}
}
