package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/terminal"
)

// ---- Types ----

type TerminalSession struct {
	ID        string    `json:"id" format:"uuid"`
	Title     string    `json:"title" example:"Shell 1"`
	CreatedAt time.Time `json:"created_at"`
	Cols      int       `json:"cols" example:"120"`
	Rows      int       `json:"rows" example:"32"`
	Clients   int       `json:"clients" doc:"Browser tabs attached right now; 0 means it runs detached"`
	Recorded  bool      `json:"recorded" doc:"Its output is being recorded (the workspace records terminals)"`
}

type TerminalPath struct {
	ServerIDPath
	Session string `path:"session" format:"uuid"`
}

func toTerminal(i terminal.Info) TerminalSession {
	return TerminalSession{ID: i.ID, Title: i.Title, CreatedAt: i.Created, Cols: i.Cols, Rows: i.Rows, Clients: i.Clients, Recorded: i.Recorded}
}

// Control messages are JSON text frames; terminal bytes are binary frames.
type controlMessage struct {
	Type    string `json:"type"`
	ID      string `json:"id,omitempty"`
	Title   string `json:"title,omitempty"`
	Code    *int   `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Status  int    `json:"status,omitempty"`
	Cols    int    `json:"cols,omitempty"`
	Rows    int    `json:"rows,omitempty"`
	// On "session": the shell's output is being recorded.
	Recorded bool `json:"recorded,omitempty"`
}

// ---- Handlers ----

func registerTerminals(api huma.API, r chi.Router, h *serverHandler, origins []string) {
	tags := []string{"Terminal"}

	// Not in the OpenAPI spec: WebSockets aren't expressible there.
	r.Get("/servers/{id}/terminals/connect", h.terminalSocket(originPatterns(origins)))

	huma.Register(api, huma.Operation{
		OperationID: "list-terminals",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/terminals",
		Summary:     "List a server's open terminals",
		Description: "Shells keep running on the backend while no browser is attached, so a reload or a dropped network resumes them. " +
			"Connect with a WebSocket to `/servers/{id}/terminals/connect` (`?session=` to attach to one of these, else a new shell; `cols`, `rows`, `cwd` for a new one). " +
			"Binary frames carry terminal bytes both ways; JSON text frames carry control: the client sends `{type:\"resize\",cols,rows}`; the server sends `session`, `title`, `exit` and `error`.",
		Tags: tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct {
		Body struct {
			Items []TerminalSession `json:"items"`
		}
	}, error) {
		if _, err := h.get(ctx, in.ID); err != nil {
			return nil, err
		}
		out := &struct {
			Body struct {
				Items []TerminalSession `json:"items"`
			}
		}{}
		out.Body.Items = []TerminalSession{}
		for _, i := range h.terms.List(in.ID, principalOf(ctx).User.ID.String()) {
			out.Body.Items = append(out.Body.Items, toTerminal(i))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "rename-terminal",
		Method:      http.MethodPatch,
		Path:        "/servers/{id}/terminals/{session}",
		Summary:     "Rename a terminal",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		TerminalPath
		Body struct {
			Title string `json:"title" minLength:"1" maxLength:"64"`
		}
	}) (*struct{ Body TerminalSession }, error) {
		owner := principalOf(ctx).User.ID.String()
		s := h.terms.Get(in.ID, owner, in.Session)
		if s == nil {
			return nil, huma.Error404NotFound("terminal not found")
		}
		title := strings.TrimSpace(in.Body.Title)
		if title == "" {
			return nil, fieldError("body.title", "Enter a name", in.Body.Title)
		}
		s.SetTitle(title)
		for _, i := range h.terms.List(in.ID, owner) {
			if i.ID == s.ID {
				return &struct{ Body TerminalSession }{Body: toTerminal(i)}, nil
			}
		}
		return nil, huma.Error404NotFound("terminal not found")
	})

	huma.Register(api, huma.Operation{
		OperationID:   "close-terminal",
		Method:        http.MethodDelete,
		Path:          "/servers/{id}/terminals/{session}",
		Summary:       "Close a terminal",
		Description:   "Ends the shell (the server sends it SIGHUP). Attached browsers get an `exit` message.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *TerminalPath) (*struct{}, error) {
		s := h.terms.Get(in.ID, principalOf(ctx).User.ID.String(), in.Session)
		if s == nil {
			return nil, huma.Error404NotFound("terminal not found")
		}
		s.Kill()
		return nil, nil
	})
}

// originPatterns turns the CORS origins into the host patterns the
// WebSocket handshake accepts, so other sites can't open shells through a
// visitor's browser.
func originPatterns(origins []string) []string {
	var hosts []string
	for _, o := range origins {
		if o == "*" {
			return []string{"*"}
		}
		if u, err := url.Parse(o); err == nil && u.Host != "" {
			hosts = append(hosts, u.Host)
		}
	}
	return hosts
}

const (
	pingEvery = 30 * time.Second
	// Close codes 4000+status: the client can tell "session ended" (4404)
	// from "can't connect" (4502) and decide whether to retry.
	closeBase = 4000
)

func (h *serverHandler) terminalSocket(origins []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: origins})
		if err != nil {
			return // Accept already wrote the response
		}
		defer ws.CloseNow()
		// Pastes can be large; the browser splits them anyway.
		ws.SetReadLimit(1 << 20)

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		fail := func(status int, message string) {
			_ = writeJSON(ctx, ws, controlMessage{Type: "error", Status: status, Message: message})
			ws.Close(websocket.StatusCode(closeBase+status), truncate(message, 120))
		}

		serverID := chi.URLParam(r, "id")

		// This route sits outside the API, so it makes the same check by hand.
		// Answering after Accept lets the browser read why it was refused.
		token := ""
		if c, err := r.Cookie(sessionCookie); err == nil {
			token = c.Value
		}
		pol := onServer(auth.Engineer)
		p, denial := h.authz.authorize(ctx, token, pol, serverID, "")
		if denial != nil {
			fail(denial.status, denial.message)
			return
		}
		ctx, stop := h.authz.track(ctx, p, pol, serverID)
		defer stop()
		owner := p.User.ID.String()

		q := r.URL.Query()
		var sess *terminal.Session
		if sid := q.Get("session"); sid != "" {
			if sess = h.terms.Get(serverID, owner, sid); sess == nil {
				fail(http.StatusNotFound, "This terminal has ended.")
				return
			}
		} else {
			conn, err := h.conn(ctx, serverID)
			if err != nil {
				status, message := problem(err)
				fail(status, message)
				return
			}
			cols, _ := strconv.Atoi(q.Get("cols"))
			rows, _ := strconv.Atoi(q.Get("rows"))
			// A workspace that records gets no unrecorded shells.
			rec, err := h.recs.begin(ctx, serverID, p, cols, rows)
			if err != nil {
				slog.Error("start terminal recording", "error", err)
				fail(http.StatusServiceUnavailable, "This workspace records terminals, and the recording couldn't start. Try again.")
				return
			}
			opts := terminal.Options{Owner: owner, Cols: cols, Rows: rows, Cwd: q.Get("cwd")}
			if rec != nil {
				opts.Recorder = rec
			}
			cmds := newTermCommands(h.cmds, serverID, p, hostOf(r.RemoteAddr), rec)
			opts.Commands = cmds
			sess, err = h.terms.Start(serverID, conn, opts)
			if err != nil && rec != nil {
				rec.abandon()
			}
			if errors.Is(err, terminal.ErrTooMany) {
				fail(http.StatusTooManyRequests, err.Error())
				return
			}
			if err != nil {
				fail(http.StatusBadGateway, "Couldn't start a shell: "+err.Error())
				return
			}
			if rec != nil {
				rec.attach(sess)
			}
			cmds.attach(sess)
		}

		replay, sub, ok := sess.Attach()
		if !ok {
			fail(http.StatusNotFound, "This terminal has ended.")
			return
		}
		defer sess.Detach(sub)

		if err := writeJSON(ctx, ws, controlMessage{Type: "session", ID: sess.ID, Title: sess.Title(), Recorded: sess.Recorded()}); err != nil {
			return
		}
		if len(replay) > 0 {
			if err := ws.Write(ctx, websocket.MessageBinary, replay); err != nil {
				return
			}
		}

		// Browser → shell.
		go func() {
			defer cancel()
			for {
				typ, data, err := ws.Read(ctx)
				if err != nil {
					return
				}
				if typ == websocket.MessageBinary {
					if err := sess.Write(data); err != nil {
						return
					}
					continue
				}
				var msg controlMessage
				if json.Unmarshal(data, &msg) == nil && msg.Type == "resize" {
					if err := sess.Resize(msg.Cols, msg.Rows); err != nil {
						slog.Debug("terminal resize failed", "error", err)
					}
				}
			}
		}()

		go func() {
			t := time.NewTicker(pingEvery)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					pctx, done := context.WithTimeout(ctx, 10*time.Second)
					err := ws.Ping(pctx)
					done()
					if err != nil {
						cancel()
						return
					}
				}
			}
		}()

		// Shell → browser.
		for {
			select {
			case <-ctx.Done():
				return
			case ev, open := <-sub.C:
				switch {
				case !open && sub.Dropped():
					ws.Close(websocket.StatusTryAgainLater, "too slow")
					return
				case !open:
					return
				case ev.Exited:
					code := ev.Code
					_ = writeJSON(ctx, ws, controlMessage{Type: "exit", Code: &code})
					ws.Close(websocket.StatusNormalClosure, "exited")
					return
				case ev.Title != "":
					err = writeJSON(ctx, ws, controlMessage{Type: "title", Title: ev.Title})
				default:
					err = ws.Write(ctx, websocket.MessageBinary, ev.Data)
				}
				if err != nil {
					return
				}
			}
		}
	}
}

func writeJSON(ctx context.Context, ws *websocket.Conn, msg controlMessage) error {
	data, _ := json.Marshal(msg)
	return ws.Write(ctx, websocket.MessageText, data)
}

// problem unpacks a Huma error for a WebSocket error message.
func problem(err error) (int, string) {
	var se huma.StatusError
	if errors.As(err, &se) {
		var m *huma.ErrorModel
		if errors.As(err, &m) && m.Detail != "" {
			return se.GetStatus(), m.Detail
		}
		return se.GetStatus(), se.Error()
	}
	return http.StatusInternalServerError, "internal error"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
