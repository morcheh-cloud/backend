package proxmox

import (
	"context"
	"net/http"

	"github.com/coder/websocket"
)

// DialConsole attaches to a console made by VNCProxy or TermProxy. The
// connection carries the token, the pinned certificate and the address check
// the other requests use.
func (c *Client) DialConsole(ctx context.Context, node string, kind Kind, vmid int, t ConsoleTicket) (*websocket.Conn, error) {
	h := http.Header{}
	h.Set("Authorization", c.auth)
	// websocket refuses a client with a timeout: the context bounds the dial.
	hc := &http.Client{Transport: c.http.Transport, CheckRedirect: c.http.CheckRedirect}
	conn, _, err := websocket.Dial(ctx, c.WebsocketURL(node, kind, vmid, t), &websocket.DialOptions{
		HTTPClient: hc, HTTPHeader: h, Subprotocols: []string{"binary"},
	})
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(16 << 20)
	return conn, nil
}
