package api

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/netmap"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/terminal"
)

type NetworkServer struct {
	Server  Server          `json:"server"`
	Scanned bool            `json:"scanned" doc:"Its interfaces were read and it probed the others"`
	Error   string          `json:"error" doc:"Why it couldn't be read"`
	Host    *netmap.HostNet `json:"host,omitempty"`
}

type NetworkMap struct {
	ScannedAt  time.Time       `json:"scanned_at"`
	DurationMs int64           `json:"duration_ms" example:"4200"`
	Servers    []NetworkServer `json:"servers"`
	Networks   []netmap.Subnet `json:"networks"`
	Links      []netmap.Reach  `json:"links" doc:"One per ordered pair of servers"`
}

type NetworkMapInput struct {
	Refresh bool `query:"refresh" doc:"Scan again instead of returning the last scan"`
}

const (
	netmapTimeout        = 60 * time.Second
	netmapCollectTimeout = 20 * time.Second
	netmapProbeTimeout   = 30 * time.Second
)

// netmapState keeps the last scan; one scan runs at a time and requests that
// arrive meanwhile wait for it.
type netmapState struct {
	mu      sync.Mutex
	last    *NetworkMap
	running chan struct{}
}

func registerNetwork(api huma.API, h *serverHandler) {
	st := &netmapState{}
	huma.Register(api, huma.Operation{
		OperationID: "get-network-map",
		Method:      http.MethodGet,
		Path:        "/network/map",
		Summary:     "Network map of every server",
		Description: "Each server's interfaces, addresses and default routes (ip over SSH), the subnets they share, " +
			"and whether each server reaches every other one: a TCP connect to its SSH port and a ping, " +
			"on their shared LAN/VPN addresses and on the address Morcheh uses. " +
			"Returns the last scan unless `refresh` is set or there is none; a scan takes a few seconds.",
		Tags: []string{"Network"},
	}, func(ctx context.Context, in *NetworkMapInput) (*struct{ Body NetworkMap }, error) {
		p := principalOf(ctx)
		// A scan logs in to every server, so it isn't for read-only people.
		if in.Refresh && p.Access.Highest() < auth.Operator {
			return nil, forbidden(auth.Operator)
		}
		m, err := st.get(ctx, h, in.Refresh)
		if err != nil {
			return nil, err
		}
		seen, err := h.visibleMap(ctx, p, m)
		if err != nil {
			return nil, err
		}
		return &struct{ Body NetworkMap }{*seen}, nil
	})
}

// visibleMap is the part of a scan they may see. The scan is shared and cached,
// so this builds a copy, and asks the database where servers are today rather
// than trusting a scan that may be old.
func (h *serverHandler) visibleMap(ctx context.Context, p *principal, m *NetworkMap) (*NetworkMap, error) {
	ids := make([]uuid.UUID, 0, len(m.Servers))
	for _, s := range m.Servers {
		if id, err := uuid.Parse(s.Server.ID); err == nil {
			ids = append(ids, id)
		}
	}
	rows, err := h.q.ListServerWorkspaces(ctx, ids)
	if err != nil {
		return nil, internalError(err)
	}
	visible := make(map[string]bool, len(rows))
	for _, r := range rows {
		if p.Workspace != nil && r.WorkspaceID != *p.Workspace {
			continue
		}
		if p.Access.ServerLevel(r.WorkspaceID, r.ID) > auth.None {
			visible[r.ID.String()] = true
		}
	}

	out := *m
	out.Servers = make([]NetworkServer, 0, len(m.Servers))
	for _, s := range m.Servers {
		if visible[s.Server.ID] {
			out.Servers = append(out.Servers, s)
		}
	}
	out.Networks = make([]netmap.Subnet, 0, len(m.Networks))
	for _, n := range m.Networks {
		members := make([]netmap.SubnetMember, 0, len(n.Members))
		for _, member := range n.Members {
			if visible[member.ServerID] {
				members = append(members, member)
			}
		}
		if len(members) > 0 {
			n.Members = members
			out.Networks = append(out.Networks, n)
		}
	}
	out.Links = make([]netmap.Reach, 0, len(m.Links))
	for _, l := range m.Links {
		if visible[l.From] && visible[l.To] {
			out.Links = append(out.Links, l)
		}
	}
	return &out, nil
}

func (st *netmapState) get(ctx context.Context, h *serverHandler, refresh bool) (*NetworkMap, error) {
	st.mu.Lock()
	if st.last != nil && !refresh && st.running == nil {
		m := st.last
		st.mu.Unlock()
		return m, nil
	}
	wait := st.running
	if wait == nil {
		wait = make(chan struct{})
		st.running = wait
		// The scan outlives the request, so a reload still finds it cached.
		go func() {
			m, err := scanNetwork(context.WithoutCancel(ctx), h)
			st.mu.Lock()
			if err == nil {
				st.last = m
			}
			st.running = nil
			st.mu.Unlock()
			close(wait)
		}()
	}
	st.mu.Unlock()

	select {
	case <-wait:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.last == nil {
		return nil, internalError(errScanFailed)
	}
	return st.last, nil
}

var errScanFailed = errors.New("network scan failed")

func scanNetwork(ctx context.Context, h *serverHandler) (*NetworkMap, error) {
	ctx, cancel := context.WithTimeout(ctx, netmapTimeout)
	defer cancel()
	start := time.Now()

	// The filters need empty (not nil) arrays: cardinality(NULL) is NULL.
	none := []string{}
	rows, err := h.q.ListServers(ctx, sqlc.ListServersParams{
		SeeAll: true, WorkspaceIds: []uuid.UUID{}, ServerIds: []uuid.UUID{},
		OsIds: none, Statuses: none, Tags: none, AuthMethods: none,
		Sort: "name", Lim: 10_000,
	})
	if err != nil {
		return nil, err
	}
	out := &NetworkMap{Servers: make([]NetworkServer, len(rows))}
	nodes := make([]netmap.Node, len(rows))
	sem := make(chan struct{}, checkConcurrency)
	var wg sync.WaitGroup

	// 1. Every server's own interfaces.
	for i, row := range rows {
		s := row.Server
		out.Servers[i].Server = toServer(s)
		nodes[i] = netmap.Node{ID: s.ID.String(), Host: s.Host, Port: int(s.Port)}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			cctx, cancel := context.WithTimeout(ctx, netmapCollectTimeout)
			defer cancel()
			var text string
			err := h.withConn(cctx, s.ID.String(), func(c *sshpool.Conn) (err error) {
				text, err = runInput(cctx, c, "sh -c "+terminal.ShellQuote(netmap.CollectScript), "", netmapCollectTimeout)
				return err
			})
			if err != nil {
				out.Servers[i].Error = problemDetail(err)
				return
			}
			host := netmap.ParseHost(text)
			out.Servers[i].Host, out.Servers[i].Scanned = &host, true
			nodes[i].Scan = &host
		}()
	}
	wg.Wait()

	// 2. What servers share, and from each one, every other.
	out.Networks = netmap.Networks(nodes)
	targets := netmap.Targets(nodes, out.Networks)
	probes := make(map[string][]netmap.ReachProbe, len(targets))
	var mu sync.Mutex
	for _, n := range nodes {
		list := targets[n.ID]
		if n.Scan == nil || len(list) == 0 {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var text string
			_ = h.withConn(ctx, n.ID, func(c *sshpool.Conn) (err error) {
				text, err = runInput(ctx, c, "sh -c "+terminal.ShellQuote(netmap.ProbeScript), netmap.ProbeInput(list), netmapProbeTimeout)
				return err
			})
			mu.Lock()
			probes[n.ID] = netmap.ParseProbes(text, list)
			mu.Unlock()
		}()
	}
	wg.Wait()

	out.Links = netmap.Links(nodes, probes, targets)
	out.ScannedAt = time.Now().UTC()
	out.DurationMs = time.Since(start).Milliseconds()
	return out, nil
}

// problemDetail is the message a request would have shown for err.
func problemDetail(err error) string {
	if se, ok := toProblem(err).(huma.StatusError); ok {
		if m, ok := se.(*huma.ErrorModel); ok && m.Detail != "" {
			return m.Detail
		}
	}
	return err.Error()
}
