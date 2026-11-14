// Package fake is an in-memory Proxmox VE API for development and tests: a
// three-node cluster with VMs, containers, templates, storages (one of them
// a Proxmox Backup Server), tasks with logs, snapshots, backups, firewall,
// HA and working consoles (a tiny VNC screen and a text shell). It answers
// the endpoints internal/proxmox uses, in Proxmox's shapes, and nothing more.
package fake

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Options configure a fake cluster.
type Options struct {
	// TokenID and Secret are the only API token accepted.
	TokenID string
	Secret  string
	// Speed scales how long tasks take (1 = the usual few seconds, 0.01 for tests).
	Speed float64
}

// Server is the fake cluster.
type Server struct {
	opt   Options
	start time.Time

	mu       sync.Mutex
	nodes    []*node
	guests   map[int]*guest
	storages []*storage
	volumes  map[string][]*volume // storage key → volumes (key = name, or node/name for local ones)
	tasks    []*task
	ha       map[string]*haResource
	tickets  map[string]*consoleTicket
	pid      int
}

// New builds the cluster with its starting machines.
func New(opt Options) *Server {
	if opt.Speed <= 0 {
		opt.Speed = 1
	}
	s := &Server{
		opt: opt, start: time.Now(), guests: map[int]*guest{}, volumes: map[string][]*volume{},
		ha: map[string]*haResource{}, tickets: map[string]*consoleTicket{}, pid: 4000,
	}
	s.seed()
	return s
}

// Handler serves /api2/json/… and /fake/… (switches for tests: a node
// going offline and back).
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"data":null}`))
			return
		}
		path := r.URL.Path
		switch {
		case strings.HasPrefix(path, "/api2/json/"):
			path = strings.TrimPrefix(path, "/api2/json")
		case strings.HasPrefix(path, "/fake/"):
			s.switches(w, r)
			return
		default:
			http.NotFound(w, r)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
			_ = r.ParseForm()
		}
		var segs []string
		for _, p := range strings.Split(strings.Trim(path, "/"), "/") {
			if v, err := url.PathUnescape(p); err == nil {
				segs = append(segs, v)
			} else {
				segs = append(segs, p)
			}
		}
		if len(segs) == 5 && segs[0] == "nodes" && segs[4] == "vncwebsocket" && r.Method == http.MethodGet {
			s.socket(w, r, segs)
			return
		}
		s.route(w, r, segs)
	})
}

func (s *Server) authorized(r *http.Request) bool {
	want := "PVEAPIToken=" + s.opt.TokenID + "=" + s.opt.Secret
	return r.Header.Get("Authorization") == want
}

// apiError is an answer with Proxmox's error shape.
type apiError struct {
	status int
	msg    string
	fields map[string]string
}

func (e *apiError) Error() string { return e.msg }

func fail(status int, format string, a ...any) *apiError {
	return &apiError{status: status, msg: fmt.Sprintf(format, a...)}
}

func badParam(field, msg string) *apiError {
	return &apiError{status: http.StatusBadRequest, msg: "Parameter verification failed.", fields: map[string]string{field: msg}}
}

func reply(w http.ResponseWriter, data any, err error) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	if err != nil {
		e, ok := err.(*apiError)
		if !ok {
			e = &apiError{status: http.StatusInternalServerError, msg: err.Error()}
		}
		w.WriteHeader(e.status)
		body := map[string]any{"data": nil, "message": e.msg + "\n"}
		if e.fields != nil {
			body["errors"] = e.fields
		}
		_ = json.NewEncoder(w).Encode(body)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func (s *Server) route(w http.ResponseWriter, r *http.Request, p []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.dispatch(r, p)
	if err == errSocket {
		return // a websocket took over
	}
	reply(w, data, err)
}

var errNotFound = &apiError{status: http.StatusNotImplemented, msg: "Method not implemented"}

func (s *Server) dispatch(r *http.Request, p []string) (any, error) {
	m := r.Method
	switch {
	case len(p) == 1 && p[0] == "version" && m == http.MethodGet:
		return map[string]any{"version": "8.3.2", "release": "8.3", "repoid": "3e76eec21c4a14a7"}, nil
	case len(p) >= 1 && p[0] == "cluster":
		return s.cluster(r, p[1:])
	case len(p) == 1 && p[0] == "nodes" && m == http.MethodGet:
		return s.listNodes(), nil
	case len(p) >= 2 && p[0] == "nodes":
		n := s.node(p[1])
		if n == nil {
			return nil, fail(http.StatusInternalServerError, "hostname lookup '%s' failed - failed to get address info for: %s: Name or service not known", p[1], p[1])
		}
		if !n.online {
			return nil, fail(595, "no route to host")
		}
		return s.nodeCall(r, n, p[2:])
	}
	return nil, errNotFound
}

func (s *Server) cluster(r *http.Request, p []string) (any, error) {
	m := r.Method
	switch {
	case len(p) == 1 && p[0] == "status":
		out := []map[string]any{{"type": "cluster", "id": "cluster", "name": "morche-lab", "nodes": len(s.nodes), "quorate": 1, "version": 5}}
		for i, n := range s.nodes {
			out = append(out, map[string]any{
				"type": "node", "id": "node/" + n.name, "name": n.name, "online": b2i(n.online),
				"local": b2i(i == 0), "ip": n.ip, "nodeid": i + 1, "level": "",
			})
		}
		return out, nil
	case len(p) == 1 && p[0] == "resources":
		return s.resources(r.URL.Query().Get("type")), nil
	case len(p) == 1 && p[0] == "nextid":
		return strconv.Itoa(s.nextID()), nil
	case len(p) >= 2 && p[0] == "ha":
		return s.haCall(r, p[1:])
	}
	_ = m
	return nil, errNotFound
}

func (s *Server) nodeCall(r *http.Request, n *node, p []string) (any, error) {
	m := r.Method
	if len(p) == 0 {
		return nil, errNotFound
	}
	switch p[0] {
	case "status":
		return s.nodeStatus(n), nil
	case "rrddata":
		return rrd(r.URL.Query().Get("timeframe"), nodeSample(n, s)), nil
	case "network":
		return n.bridges, nil
	case "storage":
		return s.storageCall(r, n, p[1:])
	case "vzdump":
		if m == http.MethodPost {
			return s.vzdump(r, n)
		}
	case "tasks":
		return s.taskCall(r, n, p[1:])
	case "qemu", "lxc":
		if len(p) == 1 && m == http.MethodPost {
			return s.createOrRestore(r, n, p[0])
		}
		if len(p) >= 2 {
			id, err := strconv.Atoi(p[1])
			if err != nil {
				return nil, badParam("vmid", "type check ('integer') failed")
			}
			g := s.guests[id]
			if g == nil || g.node != n.name || g.kind != p[0] {
				conf := "qemu-server"
				if p[0] == "lxc" {
					conf = "lxc"
				}
				return nil, fail(http.StatusInternalServerError, "Configuration file 'nodes/%s/%s/%d.conf' does not exist", n.name, conf, id)
			}
			return s.guestCall(r, n, g, p[2:])
		}
	}
	return nil, errNotFound
}

func (s *Server) node(name string) *node {
	for _, n := range s.nodes {
		if n.name == name {
			return n
		}
	}
	return nil
}

func (s *Server) nextID() int {
	for id := 100; ; id++ {
		if s.guests[id] == nil {
			return id
		}
	}
}

// switches: POST /fake/nodes/{node}/offline|online.
func (s *Server) switches(w http.ResponseWriter, r *http.Request) {
	p := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(p) == 4 && p[1] == "nodes" && r.Method == http.MethodPost {
		if n := s.node(p[2]); n != nil {
			n.online = p[3] == "online"
			if n.online {
				n.bootedAt = time.Now()
			}
			for _, g := range s.guests {
				if g.node == n.name && !n.online && g.status == "running" {
					g.status, g.paused = "stopped", false
				}
			}
			reply(w, "ok", nil)
			return
		}
	}
	reply(w, nil, errNotFound)
}

func (s *Server) dur(d time.Duration) time.Duration {
	return time.Duration(float64(d) * s.opt.Speed)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func form(r *http.Request, k string) string { return strings.TrimSpace(r.Form.Get(k)) }

func formBool(r *http.Request, k string) bool {
	v := form(r, k)
	return v == "1" || v == "true"
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

const (
	gib = int64(1) << 30
	mib = int64(1) << 20
)
