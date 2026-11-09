package api

import (
	"context"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/proxy"
	"github.com/morcheh/backend/internal/sshpool"
)

// Live traffic: each proxy's access logs are read from where the last read
// stopped, counted per minute and kept in memory for an hour. Reading happens
// when someone asks, at most every few seconds per proxy, so nothing runs
// while no one looks; after a restart the first read fills the hour back in
// from the end of the logs.

const (
	trafficEvery   = 4 * time.Second
	trafficKeep    = 60
	trafficMinutes = 30
)

type trafficCount struct{ requests, ok, redirects, client, server, bytes int64 }

type trafficState struct {
	mu        sync.Mutex
	collected time.Time
	err       string
	marks     map[string]proxy.LogMark
	minutes   map[string]map[int64]*trafficCount // host → unix minute → counts
}

type ProxyTrafficSource struct {
	ProxyID     uuid.UUID  `json:"proxy_id"`
	OK          bool       `json:"ok"`
	Error       string     `json:"error,omitempty"`
	CollectedAt *time.Time `json:"collected_at,omitempty"`
}

type ProxyHostTraffic struct {
	HostID       uuid.UUID `json:"host_id"`
	ProxyID      uuid.UUID `json:"proxy_id"`
	Requests     []int64   `json:"requests" doc:"Per minute, oldest first"`
	ServerErrors []int64   `json:"server_errors" doc:"5xx answers per minute"`
	ClientErrors []int64   `json:"client_errors" doc:"4xx answers per minute"`
	Bytes        []int64   `json:"bytes" doc:"Bytes sent per minute"`
}

type ProxyTraffic struct {
	Start   time.Time            `json:"start" doc:"Start of the first minute"`
	Minutes int                  `json:"minutes"`
	Sources []ProxyTrafficSource `json:"sources"`
	Hosts   []ProxyHostTraffic   `json:"hosts"`
}

func (h *proxyHandler) trafficOf(id uuid.UUID) *trafficState {
	h.mu.Lock()
	defer h.mu.Unlock()
	st, ok := h.traffic[id]
	if !ok {
		st = &trafficState{marks: map[string]proxy.LogMark{}, minutes: map[string]map[int64]*trafficCount{}}
		h.traffic[id] = st
	}
	return st
}

// collect reads what the proxy's logs gained, unless that was done moments
// ago. The caller holds st.mu.
func (h *proxyHandler) collect(ctx context.Context, p sqlc.Proxy, d proxy.Driver, st *trafficState) {
	if time.Since(st.collected) < trafficEvery {
		return
	}
	hosts, err := h.s.q.ListProxyHosts(ctx, p.ID)
	if err != nil {
		st.err = "Couldn't read the sites"
		return
	}
	ids := []string{}
	for _, x := range hosts {
		if x.Enabled {
			ids = append(ids, x.ID.String())
		}
	}
	if len(ids) == 0 {
		st.collected, st.err = time.Now(), ""
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var out string
	err = h.s.withConn(cctx, p.ServerID.String(), func(c *sshpool.Conn) error {
		sh, err := h.root(cctx, p.ServerID.String(), c)
		if err != nil {
			return err
		}
		out, err = sh.run(cctx, d.TrafficScript(ids, st.marks))
		return err
	})
	if err != nil {
		st.err = proxyProblemText(err)
		return
	}
	hits, marks := d.ParseTraffic(out)
	st.marks = marks
	oldest := time.Now().Unix()/60 - trafficKeep
	for _, hit := range hits {
		m := hit.Minute.Unix() / 60
		if m <= oldest {
			continue
		}
		per := st.minutes[hit.Host]
		if per == nil {
			per = map[int64]*trafficCount{}
			st.minutes[hit.Host] = per
		}
		c := per[m]
		if c == nil {
			c = &trafficCount{}
			per[m] = c
		}
		c.requests += hit.Requests
		c.bytes += hit.Bytes
		switch hit.Class {
		case 2:
			c.ok += hit.Requests
		case 3:
			c.redirects += hit.Requests
		case 4:
			c.client += hit.Requests
		case 5:
			c.server += hit.Requests
		}
	}
	// Forget old minutes and sites that are gone.
	for host, per := range st.minutes {
		if !slices.Contains(ids, host) {
			delete(st.minutes, host)
			continue
		}
		for m := range per {
			if m <= oldest {
				delete(per, m)
			}
		}
	}
	st.collected, st.err = time.Now(), ""
}

func (h *proxyHandler) registerTraffic(api huma.API, tags []string) {
	huma.Register(api, huma.Operation{
		OperationID: "get-proxy-traffic", Method: http.MethodGet, Path: "/proxy-traffic",
		Summary:     "Live requests per site",
		Description: "Requests, errors and bytes per minute over the last 30 minutes, for every site on the proxies you can see, read from their access logs. Calling it reads what the logs gained since the last call (at most every few seconds per proxy).",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ProxyID string `query:"proxy_id" format:"uuid" doc:"Only this proxy's sites"`
	}) (*struct{ Body ProxyTraffic }, error) {
		sc := principalOf(ctx).scope()
		rows, err := h.s.q.ListProxies(ctx, sqlc.ListProxiesParams{
			SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, ServerIds: sc.servers, WorkspaceID: sc.current,
		})
		if err != nil {
			return nil, internalError(err)
		}
		only := parseOptionalID(&in.ProxyID)
		now := time.Now().Unix() / 60
		first := now - trafficMinutes + 1
		out := ProxyTraffic{
			Start: time.Unix(first*60, 0).UTC(), Minutes: trafficMinutes,
			Sources: []ProxyTrafficSource{}, Hosts: []ProxyHostTraffic{},
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		for _, r := range rows {
			p := r.Proxy
			if only != nil && p.ID != *only {
				continue
			}
			d, ok := proxy.Get(p.Kind)
			if !ok || !d.Capabilities().Traffic {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				st := h.trafficOf(p.ID)
				st.mu.Lock()
				defer st.mu.Unlock()
				// A proxy known to be down isn't asked; what was counted stays.
				if p.Status != "unreachable" && p.Status != "not_installed" {
					h.collect(context.WithoutCancel(ctx), p, d, st)
				}
				src := ProxyTrafficSource{ProxyID: p.ID, OK: st.err == "" && !st.collected.IsZero(), Error: st.err}
				if !st.collected.IsZero() {
					t := st.collected
					src.CollectedAt = &t
				}
				hosts := make([]ProxyHostTraffic, 0, len(st.minutes))
				for host, per := range st.minutes {
					id, err := uuid.Parse(host)
					if err != nil {
						continue
					}
					ht := ProxyHostTraffic{
						HostID: id, ProxyID: p.ID,
						Requests: make([]int64, trafficMinutes), ServerErrors: make([]int64, trafficMinutes),
						ClientErrors: make([]int64, trafficMinutes), Bytes: make([]int64, trafficMinutes),
					}
					for m, c := range per {
						i := m - first
						if i < 0 || i >= trafficMinutes {
							continue
						}
						ht.Requests[i], ht.ServerErrors[i] = c.requests, c.server
						ht.ClientErrors[i], ht.Bytes[i] = c.client, c.bytes
					}
					hosts = append(hosts, ht)
				}
				mu.Lock()
				out.Sources = append(out.Sources, src)
				out.Hosts = append(out.Hosts, hosts...)
				mu.Unlock()
			}()
		}
		wg.Wait()
		slices.SortFunc(out.Sources, func(a, b ProxyTrafficSource) int { return compareIDs(a.ProxyID, b.ProxyID) })
		slices.SortFunc(out.Hosts, func(a, b ProxyHostTraffic) int { return compareIDs(a.HostID, b.HostID) })
		return &struct{ Body ProxyTraffic }{out}, nil
	})
}

func compareIDs(a, b uuid.UUID) int {
	for i := range a {
		if a[i] != b[i] {
			return int(a[i]) - int(b[i])
		}
	}
	return 0
}
