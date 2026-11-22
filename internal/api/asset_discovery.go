package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/jobs"
	"github.com/morche/backend/internal/notify"
	"github.com/morche/backend/internal/ports"
	"github.com/morche/backend/internal/sshpool"
	"github.com/morche/backend/internal/terminal"
)

// Asset discovery: finds what the workspace has that isn't in the inventory
// or managed by Morche yet, from what Morche can already reach (passive: no
// network scans). Sources: the open ports of each online server (databases
// nobody added), Proxmox guests and cloud servers that aren't panel servers,
// and DNS zones not listed as domains. Runs as job asset-discovery, on a
// schedule per workspace or by hand.

const assetDiscoveryKind = "asset-discovery"

// AssetDiscovery is one thing discovery found.
type AssetDiscovery struct {
	ID         string         `json:"id" format:"uuid"`
	Key        string         `json:"key" doc:"Stable id of what was found, e.g. db:<server>:<port>"`
	Kind       string         `json:"kind" enum:"database,virtual_machine,cloud_server,domain"`
	Title      string         `json:"title"`
	Detail     string         `json:"detail"`
	Source     string         `json:"source" enum:"ports,proxmox,cloud,dns"`
	ServerID   string         `json:"server_id,omitempty" format:"uuid"`
	ServerName string         `json:"server_name,omitempty"`
	Data       map[string]any `json:"data" doc:"What's needed to add it: engine, port, addresses…"`
	State      string         `json:"state" enum:"new,accepted,ignored"`
	AssetID    string         `json:"asset_id,omitempty" format:"uuid" doc:"The asset it was tracked as"`
	Gone       bool           `json:"gone" doc:"Not seen the last time its source was read"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
}

type assetDiscoveryParams struct {
	WorkspaceID string `json:"workspace_id"`
}

// AssetDiscoveryResult is what a discovery run found.
type AssetDiscoveryResult struct {
	Found    int      `json:"found"`
	Problems []string `json:"problems"`
}

var dbEngines = map[string]string{"postgresql": "postgres", "mysql": "mysql", "mariadb": "mysql", "mongodb": "mongodb", "redis": "redis", "sql server": "mssql", "microsoft sql server": "mssql", "clickhouse": "clickhouse"}

func engineOfService(s string) string {
	l := strings.ToLower(s)
	for k, v := range dbEngines {
		if strings.HasPrefix(l, k) {
			return v
		}
	}
	return ""
}

type discoveryFinding struct {
	key, kind, title, detail, source string
	server                           *uuid.UUID
	data                             map[string]any
}

func (h *assetHandler) runDiscovery(ctx context.Context, t *jobs.Task) (any, error) {
	var p assetDiscoveryParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	ws := uuid.MustParse(p.WorkspaceID)
	started := time.Now()
	h.syncAssets(ctx, ws, true)
	if err := h.q.TouchAssetDiscovery(ctx, ws); err != nil {
		slog.Warn("assets: touch discovery", "error", err)
	}

	var (
		mu       sync.Mutex
		found    []discoveryFinding
		covered  []string
		answered []string
		problems []string
	)
	add := func(f discoveryFinding) { mu.Lock(); found = append(found, f); mu.Unlock() }
	cover := func(key string) { mu.Lock(); covered = append(covered, key); mu.Unlock() }
	problem := func(s string) {
		mu.Lock()
		problems = append(problems, s)
		mu.Unlock()
		t.Logf("%s", s)
	}

	servers, err := h.q.DiscoveryServers(ctx, ws)
	if err != nil {
		return nil, err
	}
	hosts := map[string]sqlc.DiscoveryServersRow{}
	for _, s := range servers {
		hosts[strings.ToLower(s.Host)] = s
	}
	dbs, err := h.q.DiscoveryDatabases(ctx, ws)
	if err != nil {
		return nil, err
	}

	// 1. Databases listening on servers that nobody added.
	t.Update(func(pr *jobs.Progress) { pr.Phase = "Reading open ports"; pr.ItemsTotal = len(servers) })
	portsOK := true
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, s := range servers {
		if s.Status != "online" {
			continue
		}
		wg.Add(1)
		go func(s sqlc.DiscoveryServersRow) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			defer t.Update(func(pr *jobs.Progress) { pr.Items++ })
			cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
			defer cancel()
			var out string
			err := h.servers.withConn(cctx, s.ID.String(), func(c *sshpool.Conn) (err error) {
				out, err = run(cctx, c, "sh -c "+terminal.ShellQuote(ports.Script))
				return err
			})
			if err != nil {
				problem(fmt.Sprintf("%s: couldn't read open ports (%v)", s.Name, err))
				mu.Lock()
				portsOK = false
				mu.Unlock()
				return
			}
			rep := ports.Parse(out, time.Now())
			seen := map[string]bool{}
			for _, op := range rep.Ports {
				if op.Protocol != "tcp" {
					continue
				}
				engine := engineOfService(op.Service)
				if engine == "" {
					continue
				}
				key := fmt.Sprintf("db:%s:%d", s.ID, op.Port)
				if seen[key] {
					continue
				}
				seen[key] = true
				container := ""
				if op.Container != nil {
					container = op.Container.Name
				}
				if databaseKnown(dbs, s, op.Port, container) {
					cover(key)
					continue
				}
				sid := s.ID
				data := map[string]any{"engine": engine, "port": op.Port, "server_id": s.ID.String(), "server_name": s.Name,
					"host": s.Host, "exposure": op.Exposure, "service": op.Service}
				detail := fmt.Sprintf("%s on port %d of %s (%s)", op.Service, op.Port, s.Name, op.Exposure)
				if container != "" {
					data["container"] = container
					if op.Container.TargetPort > 0 {
						data["container_port"] = op.Container.TargetPort
					}
					detail += ", in container " + container
				}
				add(discoveryFinding{key: key, kind: "database", source: "ports", server: &sid,
					title: fmt.Sprintf("%s on %s", op.Service, s.Name), detail: detail, data: data})
			}
		}(s)
	}
	wg.Wait()
	if portsOK {
		answered = append(answered, "ports")
	}

	// 2. Proxmox guests that aren't panel servers.
	if h.pve != nil {
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Reading Proxmox" })
		clusters, _ := h.q.DiscoveryPVEClusters(ctx, ws)
		links, _ := h.q.DiscoveryPVELinks(ctx, ws)
		ok := true
		for _, c := range clusters {
			guests, err := h.pve.guestsOf(ctx, c)
			if err != nil {
				problem(fmt.Sprintf("%s: couldn't list machines (%v)", c.Name, err))
				ok = false
				continue
			}
			for _, g := range guests {
				if g.Template {
					continue
				}
				key := fmt.Sprintf("pve:%s:%d", c.ID, g.VMID)
				linked := slices.ContainsFunc(links, func(l sqlc.DiscoveryPVELinksRow) bool { return l.ClusterID == c.ID && int(l.Vmid) == g.VMID })
				if !linked {
					for _, ip := range g.IPs {
						if _, ok := hosts[strings.ToLower(ip)]; ok {
							linked = true
						}
					}
				}
				if !linked {
					if _, ok := hosts[strings.ToLower(g.Name)]; ok {
						linked = true
					}
				}
				if linked {
					cover(key)
					continue
				}
				kind := "VM"
				if g.Kind == "lxc" {
					kind = "Container"
				}
				detail := fmt.Sprintf("%s %d on %s · %s", kind, g.VMID, g.Node, g.Status)
				if len(g.IPs) > 0 {
					detail += " · " + strings.Join(g.IPs, ", ")
				}
				add(discoveryFinding{key: key, kind: "virtual_machine", source: "proxmox", title: g.Name + " (" + c.Name + ")", detail: detail,
					data: map[string]any{"cluster_id": c.ID.String(), "cluster_name": c.Name, "vmid": g.VMID, "name": g.Name,
						"guest_kind": g.Kind, "node": g.Node, "status": g.Status, "ips": g.IPs, "cpus": g.CPUs, "maxmem": g.MaxMem, "maxdisk": g.MaxDisk}})
			}
		}
		if ok {
			answered = append(answered, "proxmox")
		}
	}

	// 3. Cloud servers that aren't panel servers.
	if h.cloud != nil {
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Reading cloud accounts" })
		accounts, _ := h.q.DiscoveryCloudAccounts(ctx, ws)
		ok := true
		for _, a := range accounts {
			list, _, err := h.cloud.read(ctx, a, false)
			if err != nil {
				problem(fmt.Sprintf("%s: couldn't list servers (%v)", a.Name, err))
				ok = false
				continue
			}
			for _, s := range list.Servers {
				key := fmt.Sprintf("cloud:%s:%s", a.ID, s.ID)
				var ips []string
				linked := false
				for _, ad := range s.Addresses {
					ips = append(ips, ad.IP)
					if _, ok := hosts[strings.ToLower(ad.IP)]; ok {
						linked = true
					}
				}
				if linked {
					cover(key)
					continue
				}
				detail := fmt.Sprintf("%s · %s · %d CPU, %d MB", cmpOr(s.RegionName, s.Region), s.State, s.CPU, s.MemoryMB)
				if len(ips) > 0 {
					detail += " · " + strings.Join(ips, ", ")
				}
				add(discoveryFinding{key: key, kind: "cloud_server", source: "cloud", title: s.Name + " (" + a.Name + ")", detail: detail,
					data: map[string]any{"account_id": a.ID.String(), "account_name": a.Name, "provider": a.Provider, "server_id": s.ID,
						"name": s.Name, "region": cmpOr(s.RegionName, s.Region), "state": s.State, "ips": ips, "plan": s.Plan, "os": s.OS}})
			}
		}
		if ok {
			answered = append(answered, "cloud")
		}
	}

	// 4. DNS zones not listed as domains.
	if h.dns != nil {
		t.Update(func(pr *jobs.Progress) { pr.Phase = "Reading DNS zones" })
		rows, err := h.q.ListAssets(ctx, ws)
		if err != nil {
			return nil, err
		}
		domains := map[string]bool{}
		for _, r := range rows {
			if r.Asset.Kind == "domain" {
				domains[strings.ToLower(strings.TrimSuffix(r.Asset.Name, "."))] = true
			}
		}
		servers, _ := h.q.DiscoveryDNSServers(ctx, ws)
		ok := true
		seen := map[string]bool{}
		for _, s := range servers {
			zctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			zones, err := h.dns.zonesFor(zctx, s)
			cancel()
			{
				if err == nil {
					for _, z := range zones {
						name := strings.ToLower(strings.TrimSuffix(z.Name, "."))
						if z.Type != "Primary" || name == "" || strings.HasSuffix(name, ".arpa") || !strings.Contains(name, ".") || seen[name] {
							continue
						}
						seen[name] = true
						key := "zone:" + name
						if domains[name] {
							cover(key)
							continue
						}
						add(discoveryFinding{key: key, kind: "domain", source: "dns", title: name, detail: dnsZoneSourceText(s),
							data: map[string]any{"zone": name, "dns_server_id": s.ID.String(), "dns_server_name": s.Name}})
					}
				}
			}
			if err != nil {
				problem(fmt.Sprintf("%s: couldn't list zones (%v)", s.Name, err))
				ok = false
			}
		}
		if ok {
			answered = append(answered, "dns")
		}
	}

	for _, f := range found {
		data, _ := json.Marshal(f.data)
		if err := h.q.UpsertAssetDiscovery(ctx, sqlc.UpsertAssetDiscoveryParams{
			WorkspaceID: ws, Key: f.key, Kind: f.kind, Title: f.title, Detail: f.detail, Source: f.source,
			ServerID: f.server, Data: data,
		}); err != nil {
			return nil, err
		}
	}
	if len(covered) > 0 {
		if err := h.q.ResolveAssetDiscoveries(ctx, sqlc.ResolveAssetDiscoveriesParams{WorkspaceID: ws, Keys: covered}); err != nil {
			return nil, err
		}
	}
	if len(answered) > 0 {
		if err := h.q.MarkGoneAssetDiscoveries(ctx, sqlc.MarkGoneAssetDiscoveriesParams{WorkspaceID: ws, Sources: answered, Since: started}); err != nil {
			return nil, err
		}
	}
	t.Logf("Found %d unlisted item(s)", len(found))
	if problems == nil {
		problems = []string{}
	}
	return AssetDiscoveryResult{Found: len(found), Problems: problems}, nil
}

// databaseKnown: a database of the workspace already watches this port.
func databaseKnown(dbs []sqlc.DiscoveryDatabasesRow, s sqlc.DiscoveryServersRow, port int, container string) bool {
	for _, d := range dbs {
		if d.ServerID != nil && *d.ServerID == s.ID {
			if container != "" && d.Container != "" && (d.Container == container || strings.HasPrefix(container, d.Container)) {
				return true
			}
			if int(d.Port) == port && (d.Container == "" || container == "") {
				return true
			}
		}
		if d.Mode != "server" && int(d.Port) == port && strings.EqualFold(d.Host, s.Host) {
			return true
		}
	}
	return false
}

func toAssetDiscovery(d sqlc.ListAssetDiscoveriesRow) AssetDiscovery {
	out := AssetDiscovery{
		ID: d.ID.String(), Key: d.Key, Kind: d.Kind, Title: d.Title, Detail: d.Detail, Source: d.Source,
		ServerID: idString(d.ServerID), ServerName: d.ServerName, Data: map[string]any{}, State: d.State,
		AssetID: idString(d.AssetID), Gone: d.Gone, FirstSeen: d.FirstSeen, LastSeen: d.LastSeen,
	}
	_ = json.Unmarshal(d.Data, &out.Data)
	return out
}

// trackBody turns a finding into a hand-entered asset.
func trackBody(d sqlc.AssetDiscovery) AssetBody {
	data := map[string]any{}
	_ = json.Unmarshal(d.Data, &data)
	s := func(k string) string {
		switch v := data[k].(type) {
		case string:
			return v
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		}
		return ""
	}
	b := AssetBody{Name: d.Title, Description: d.Detail, Lifecycle: "active", Fields: map[string]string{}}
	switch d.Kind {
	case "database":
		b.Kind, b.Category = "service", "Database ("+s("service")+")"
		b.Fields["Server"], b.Fields["Port"] = s("server_name"), s("port")
		if c := s("container"); c != "" {
			b.Fields["Container"] = c
		}
	case "virtual_machine":
		b.Kind, b.Category, b.Name = "virtual_machine", "Proxmox", s("name")
		b.Vendor = "Proxmox VE"
		b.Fields["Cluster"], b.Fields["VMID"], b.Fields["Node"] = s("cluster_name"), s("vmid"), s("node")
	case "cloud_server":
		b.Kind, b.Category, b.Name = "cloud_resource", "Cloud server", s("name")
		b.Vendor, b.Location = s("provider"), s("region")
		b.Fields["Account"], b.Fields["Plan"] = s("account_name"), s("plan")
	case "domain":
		b.Kind, b.Category, b.Name = "domain", "Domain", s("zone")
		b.Fields["DNS server"] = s("dns_server_name")
	default:
		b.Kind = "other"
	}
	if b.Name == "" {
		b.Name = d.Title
	}
	return b
}

func registerAssetDiscovery(api huma.API, h *assetHandler) {
	tags := []string{"Assets"}
	h.servers.jobs.Handle(assetDiscoveryKind, h.runDiscovery)

	huma.Register(api, huma.Operation{
		OperationID: "list-asset-discoveries",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/asset-discoveries",
		Summary:     "List what discovery found",
		Description: "New first. A finding Morche now manages (its database was added, its machine became a server) is accepted by itself.",
		Tags:        tags,
	}, func(ctx context.Context, in *WorkspacePath) (*struct {
		Body struct {
			Items           []AssetDiscovery `json:"items"`
			LastDiscoveryAt *time.Time       `json:"last_discovery_at,omitempty"`
		}
	}, error) {
		ws := uuid.MustParse(in.ID)
		rows, err := h.q.ListAssetDiscoveries(ctx, ws)
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items           []AssetDiscovery `json:"items"`
				LastDiscoveryAt *time.Time       `json:"last_discovery_at,omitempty"`
			}
		}{}
		out.Body.Items = make([]AssetDiscovery, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = toAssetDiscovery(r)
		}
		if s, err := h.settings(ctx, ws); err == nil {
			out.Body.LastDiscoveryAt = s.LastDiscoveryAt
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "run-asset-discovery",
		Method:        http.MethodPost,
		Path:          "/workspaces/{id}/asset-discovery",
		Summary:       "Look for unlisted assets now",
		Description:   "Reads each online server's open ports and the workspace's Proxmox clusters, cloud accounts and DNS servers. Runs as a background job (kind `asset-discovery`).",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *WorkspacePath) (*JobOutput, error) {
		w, err := h.q.GetWorkspace(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		return submit(ctx, h.servers.jobs, jobs.Spec{
			Kind: assetDiscoveryKind, Title: "Find assets in " + w.Name,
			Params: assetDiscoveryParams{WorkspaceID: in.ID},
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-asset-discovery-state",
		Method:      http.MethodPost,
		Path:        "/workspaces/{id}/asset-discoveries/state",
		Summary:     "Ignore findings, or bring them back",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body struct {
			IDs   []string `json:"ids" minItems:"1" maxItems:"1000"`
			State string   `json:"state" enum:"new,ignored"`
		}
	}) (*struct{}, error) {
		ids := make([]uuid.UUID, 0, len(in.Body.IDs))
		for _, s := range in.Body.IDs {
			id, err := uuid.Parse(s)
			if err != nil {
				return nil, fieldError("body.ids", "Not a finding id", s)
			}
			ids = append(ids, id)
		}
		if err := h.q.SetAssetDiscoveryState(ctx, sqlc.SetAssetDiscoveryStateParams{
			WorkspaceID: uuid.MustParse(in.ID), Ids: ids, State: in.Body.State,
		}); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "track-asset-discovery",
		Method:        http.MethodPost,
		Path:          "/workspaces/{id}/asset-discoveries/track",
		Summary:       "List a finding as an asset without managing it",
		Description:   "Adds an asset entered by hand from what was found (an unmanaged database, a machine, a domain). To manage it in Morche instead, add it in its own section: the finding is accepted by itself on the next look.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body struct {
			ID string `json:"id" format:"uuid"`
		}
	}) (*AssetOutput, error) {
		ws := uuid.MustParse(in.ID)
		d, err := h.q.GetAssetDiscovery(ctx, sqlc.GetAssetDiscoveryParams{WorkspaceID: ws, ID: uuid.MustParse(in.Body.ID)})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("finding not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if d.AssetID != nil {
			return nil, huma.Error409Conflict("This finding is already listed as an asset")
		}
		id, err := h.create(ctx, ws, trackBody(d))
		if err != nil {
			return nil, err
		}
		if err := h.q.SetAssetDiscoveryAsset(ctx, sqlc.SetAssetDiscoveryAssetParams{ID: d.ID, AssetID: &id}); err != nil {
			return nil, internalError(err)
		}
		a, _, err := h.load(ctx, id.String())
		if err != nil {
			return nil, err
		}
		return &AssetOutput{a}, nil
	})
}

// startAssetLoops runs scheduled discovery and expiry/review reminders.
func startAssetLoops(h *assetHandler) {
	go func() {
		time.Sleep(time.Minute)
		for {
			h.discoverDue()
			h.remind()
			time.Sleep(15 * time.Minute)
		}
	}()
}

func (h *assetHandler) discoverDue() {
	ctx := context.Background()
	due, err := h.q.AssetWorkspacesDueForDiscovery(ctx)
	if err != nil {
		slog.Warn("assets: workspaces due", "error", err)
		return
	}
	for _, ws := range due {
		w, err := h.q.GetWorkspace(ctx, ws)
		if err != nil {
			continue
		}
		// Marked now so a slow run isn't queued again.
		_ = h.q.TouchAssetDiscovery(ctx, ws)
		if _, err := h.servers.jobs.Submit(ctx, jobs.Spec{
			Kind: assetDiscoveryKind, Title: "Find assets in " + w.Name,
			Params: assetDiscoveryParams{WorkspaceID: ws.String()},
		}); err != nil {
			slog.Warn("assets: queue discovery", "error", err)
		}
	}
}

// reminderFor says which threshold a date has crossed: "" = none yet.
func reminderFor(date string, thresholds []int32, today time.Time) (string, int) {
	d, err := time.Parse(time.DateOnly, date)
	if err != nil {
		return "", 0
	}
	left := int(d.Sub(today).Hours() / 24)
	if left < 0 {
		return date + "@expired", left
	}
	best := -1
	for _, t := range thresholds {
		if left <= int(t) && (best == -1 || int(t) < best) {
			best = int(t)
		}
	}
	if best == -1 {
		return "", left
	}
	return date + "@" + strconv.Itoa(best), left
}

func (h *assetHandler) remind() {
	if h.up == nil {
		return
	}
	ctx := context.Background()
	rows, err := h.q.ListAssetsForReminders(ctx)
	if err != nil {
		slog.Warn("assets: reminders", "error", err)
		return
	}
	now := time.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	settings := map[uuid.UUID]sqlc.AssetSetting{}
	for _, a := range rows {
		s, ok := settings[a.WorkspaceID]
		if !ok {
			if s, err = h.settings(ctx, a.WorkspaceID); err != nil {
				continue
			}
			settings[a.WorkspaceID] = s
		}
		reminded := map[string]string{}
		_ = json.Unmarshal(a.Reminded, &reminded)
		facts := map[string]any{}
		_ = json.Unmarshal(a.Facts, &facts)
		type due struct{ field, label, date string }
		var dues []due
		if a.WarrantyUntil != "" {
			dues = append(dues, due{"warranty_until", "warranty", a.WarrantyUntil})
		}
		if a.ExpiresOn != "" {
			label := "expiry"
			if a.AutoRenew {
				label = "renewal"
			}
			dues = append(dues, due{"expires_on", label, a.ExpiresOn})
		}
		if c, ok := facts["cert_expires_at"].(string); ok && len(c) >= 10 {
			dues = append(dues, due{"cert", "certificate", c[:10]})
		}
		if a.ReviewDays > 0 {
			from := a.CreatedAt
			if a.ReviewedAt != nil {
				from = *a.ReviewedAt
			}
			dues = append(dues, due{"review", "review", from.AddDate(0, 0, int(a.ReviewDays)).Format(time.DateOnly)})
		}
		changed := false
		for _, d := range dues {
			thresholds := s.RemindDays
			if d.field == "review" {
				thresholds = []int32{0}
			}
			mark, left := reminderFor(d.date, thresholds, today)
			if mark == "" || reminded[d.field] == mark {
				continue
			}
			reminded[d.field] = mark
			changed = true
			h.sendReminder(ctx, a, s, d.label, d.date, left)
		}
		if changed {
			raw, _ := json.Marshal(reminded)
			_ = h.q.SetAssetReminded(ctx, sqlc.SetAssetRemindedParams{ID: a.ID, Reminded: raw})
		}
	}
}

func (h *assetHandler) sendReminder(ctx context.Context, a sqlc.ListAssetsForRemindersRow, s sqlc.AssetSetting, label, date string, left int) {
	var title string
	switch {
	case label == "review" && left < 0:
		title = fmt.Sprintf("%s: review is %d days overdue", a.Name, -left)
	case label == "review":
		title = fmt.Sprintf("%s: time to review it", a.Name)
	case left < 0:
		title = fmt.Sprintf("%s: %s date passed %d days ago", a.Name, label, -left)
	case left == 0:
		title = fmt.Sprintf("%s: %s is today", a.Name, label)
	default:
		title = fmt.Sprintf("%s: %s in %d days", a.Name, label, left)
	}
	text := "Date: " + date + "."
	if label == "review" {
		text = "Confirm the asset is still needed and still has the right owner."
	}
	msg := notify.Message{Event: notify.EventReminder, Title: title, Text: text, At: time.Now(),
		Fields: []notify.Field{{Name: "Asset", Value: a.Name}, {Name: "Kind", Value: a.Kind}},
		Data:   map[string]any{"asset_id": a.ID.String(), "reason": label, "date": date}}
	if h.up.panelURL != "" {
		msg.URL = h.up.panelURL + "/assets/" + a.ID.String()
	}
	chans, err := h.q.AssetReminderChannels(ctx, sqlc.AssetReminderChannelsParams{WorkspaceID: a.WorkspaceID, Ids: s.ChannelIds})
	if err != nil {
		return
	}
	if len(a.ChannelIds) > 0 {
		own, err := h.q.AssetReminderChannels(ctx, sqlc.AssetReminderChannelsParams{WorkspaceID: a.WorkspaceID, Ids: a.ChannelIds})
		if err == nil {
			for _, c := range own {
				if !slices.ContainsFunc(chans, func(x sqlc.NotificationChannel) bool { return x.ID == c.ID }) {
					chans = append(chans, c)
				}
			}
		}
	}
	for _, c := range chans {
		go func(c sqlc.NotificationChannel) {
			ch, err := h.up.sendable(c)
			if err == nil {
				sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				err = notify.Send(sctx, ch, msg)
				cancel()
			}
			h.up.recordSend(context.Background(), c.ID, nil, msg.Title, err)
		}(c)
	}
}

// assetKindOfTarget maps an alert target to the asset that mirrors it.
func assetKindOfTarget(kind string) string {
	switch kind {
	case "pve":
		return "vm_cluster"
	}
	return kind
}
