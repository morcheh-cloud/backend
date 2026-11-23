package dbmon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Elasticsearch (and OpenSearch, which kept the same API) is watched over its
// REST API: cluster health, node stats, running tasks, and every so often the
// indices, settings and users. Nothing here writes; kill cancels a task.
type elasticEngine struct {
	cfg Config
	h   *HTTPDB

	// The slow parts of DatabaseSearch (documents, indices, watermarks,
	// read-only indices) read by heavy and put into every light look, since
	// carry doesn't move Search over.
	mu     sync.Mutex
	detail *elasticDetail
}

type elasticDetail struct {
	documents     *int64
	indexes       int32
	high, flood   *float64
	readOnly      []string
	thresholdsOff bool
	authOff       bool
}

func openElastic(ctx context.Context, cfg Config) (engine, error) {
	h, err := OpenHTTP(cfg)
	if err != nil {
		return nil, err
	}
	var root elasticRoot
	if err := h.JSON(ctx, http.MethodGet, "/", nil, &root); err != nil {
		h.Close()
		return nil, elasticOpenError(err)
	}
	if root.Version.Number == "" {
		h.Close()
		return nil, errors.New("the address answered, but not like Elasticsearch or OpenSearch. Check the port (usually 9200)")
	}
	return &elasticEngine{cfg: cfg, h: h}, nil
}

// elasticOpenError explains the usual first-connection problems.
func elasticOpenError(err error) error {
	var he *HTTPError
	if errors.As(err, &he) {
		switch he.Status {
		case http.StatusUnauthorized:
			return fmt.Errorf("the username, password or API key was refused: %w", err)
		case http.StatusForbidden:
			return fmt.Errorf("the login may not read the cluster's basic info (it needs the monitor cluster privilege): %w", err)
		}
		return err
	}
	if strings.Contains(err.Error(), "malformed HTTP response") || strings.Contains(err.Error(), "server gave HTTP response to HTTPS client") {
		return fmt.Errorf("the encryption setting doesn't match the server (it may speak plain HTTP, or need TLS): %w", err)
	}
	return err
}

func (e *elasticEngine) close() error { return e.h.Close() }

// elasticRoot is GET /.
type elasticRoot struct {
	Name        string `json:"name"`
	ClusterName string `json:"cluster_name"`
	Version     struct {
		Number       string `json:"number"`
		Distribution string `json:"distribution"`
		BuildFlavor  string `json:"build_flavor"`
	} `json:"version"`
}

// ElasticFlavor names what GET / says the cluster is.
func ElasticFlavor(distribution string) string {
	if strings.EqualFold(distribution, "opensearch") {
		return "OpenSearch"
	}
	return "Elasticsearch"
}

type elasticHealth struct {
	ClusterName         string `json:"cluster_name"`
	Status              string `json:"status"`
	Nodes               int32  `json:"number_of_nodes"`
	DataNodes           int32  `json:"number_of_data_nodes"`
	ActivePrimaryShards int32  `json:"active_primary_shards"`
	ActiveShards        int32  `json:"active_shards"`
	Relocating          int32  `json:"relocating_shards"`
	Initializing        int32  `json:"initializing_shards"`
	Unassigned          int32  `json:"unassigned_shards"`
	PendingTasks        int32  `json:"number_of_pending_tasks"`
	MaxWaitMs           int64  `json:"task_max_waiting_in_queue_millis"`
}

type elasticNodeStats struct {
	Nodes map[string]elasticNode `json:"nodes"`
}

type elasticNode struct {
	Name             string   `json:"name"`
	Host             string   `json:"host"`
	TransportAddress string   `json:"transport_address"`
	Roles            []string `json:"roles"`
	JVM              struct {
		Timestamp int64 `json:"timestamp"`
		Uptime    int64 `json:"uptime_in_millis"`
		Mem       struct {
			HeapUsed int64 `json:"heap_used_in_bytes"`
			HeapMax  int64 `json:"heap_max_in_bytes"`
		} `json:"mem"`
	} `json:"jvm"`
	OS struct {
		CPU struct {
			Percent int `json:"percent"`
		} `json:"cpu"`
		Mem struct {
			Total int64 `json:"total_in_bytes"`
			Used  int64 `json:"used_in_bytes"`
		} `json:"mem"`
	} `json:"os"`
	Process struct {
		OpenFDs int64 `json:"open_file_descriptors"`
		MaxFDs  int64 `json:"max_file_descriptors"`
	} `json:"process"`
	FS struct {
		Total struct {
			Total     int64 `json:"total_in_bytes"`
			Available int64 `json:"available_in_bytes"`
		} `json:"total"`
		Data []struct {
			Path      string `json:"path"`
			Total     int64  `json:"total_in_bytes"`
			Available int64  `json:"available_in_bytes"`
		} `json:"data"`
	} `json:"fs"`
	HTTP struct {
		CurrentOpen int32 `json:"current_open"`
		Clients     []struct {
			Agent         string `json:"agent"`
			RemoteAddress string `json:"remote_address"`
			LastURI       string `json:"last_uri"`
			ClosedMillis  *int64 `json:"closed_time_millis"`
			XOpaqueID     string `json:"x_opaque_id"`
		} `json:"clients"`
	} `json:"http"`
	Indices struct {
		Search struct {
			QueryTotal int64 `json:"query_total"`
			FetchTotal int64 `json:"fetch_total"`
			QueryCur   int64 `json:"query_current"`
		} `json:"search"`
		Indexing struct {
			IndexTotal  int64 `json:"index_total"`
			DeleteTotal int64 `json:"delete_total"`
		} `json:"indexing"`
		Get struct {
			Total int64 `json:"total"`
		} `json:"get"`
		QueryCache struct {
			Hits   int64 `json:"hit_count"`
			Misses int64 `json:"miss_count"`
		} `json:"query_cache"`
		Segments struct {
			Count int64 `json:"count"`
		} `json:"segments"`
	} `json:"indices"`
	Breakers map[string]struct {
		Tripped int64 `json:"tripped"`
	} `json:"breakers"`
}

func (n elasticNode) data() bool {
	if len(n.Roles) == 0 {
		return true // older versions don't list roles
	}
	for _, r := range n.Roles {
		if r == "data" || strings.HasPrefix(r, "data_") {
			return true
		}
	}
	return false
}

type elasticTask struct {
	Node        string `json:"node"`
	ID          int64  `json:"id"`
	Action      string `json:"action"`
	Description string `json:"description"`
	RunningNs   int64  `json:"running_time_in_nanos"`
	Cancellable bool   `json:"cancellable"`
	Parent      string `json:"parent_task_id"`
	Headers     struct {
		OpaqueID string `json:"X-Opaque-Id"`
	} `json:"headers"`
}

// elasticTaskActions are the tasks worth listing as sessions: what users
// started and that can take a while.
const elasticTaskActions = "*search*,*bulk*,*reindex*,*update_by_query*,*delete_by_query*,*forcemerge*,*snapshot*"

func (e *elasticEngine) light(ctx context.Context, s *DatabaseSnapshot) error {
	start := time.Now()
	var root elasticRoot
	if err := e.h.JSON(ctx, http.MethodGet, "/", nil, &root); err != nil {
		return err
	}
	s.LatencyMs = int32(time.Since(start).Milliseconds())
	s.Flavor = ElasticFlavor(root.Version.Distribution)
	s.Version = root.Version.Number
	enc := e.cfg.TLS != TLSDisable && e.cfg.TLS != ""
	s.Security.Encrypted = &enc
	if e.cfg.Username == "" && e.cfg.Password == "" {
		// It answered without any login.
		s.Security.AuthDisabled = true
	}
	x := &DatabaseSearch{Cluster: root.ClusterName, ReadOnlyIndices: []string{}}
	s.Search = x

	var hl elasticHealth
	if err := e.h.JSON(ctx, http.MethodGet, "/_cluster/health", nil, &hl); err != nil {
		s.note("cluster", "Couldn't read the cluster's health: "+elasticProblem(err))
	} else {
		x.Status = hl.Status
		x.Nodes, x.DataNodes = hl.Nodes, hl.DataNodes
		x.ActiveShards, x.PrimaryShards = hl.ActiveShards, hl.ActivePrimaryShards
		x.Relocating, x.Initializing, x.Unassigned = hl.Relocating, hl.Initializing, hl.Unassigned
		x.PendingTasks = hl.PendingTasks
		if hl.ClusterName != "" {
			x.Cluster = hl.ClusterName
		}
	}
	if hl.Nodes > 1 {
		s.Role = "primary"
		s.Replication.Set = x.Cluster
	} else {
		s.Role = "standalone"
	}

	var ns elasticNodeStats
	if err := e.h.JSON(ctx, http.MethodGet, "/_nodes/stats/jvm,os,fs,process,http,indices,breaker", nil, &ns); err != nil {
		s.note("nodes", "Couldn't read the node statistics: "+elasticProblem(err))
	} else {
		e.nodes(s, ns)
	}

	var tasks struct {
		Tasks []elasticTask `json:"tasks"`
	}
	if err := e.h.JSON(ctx, http.MethodGet, "/_tasks?detailed=true&group_by=none&actions="+elasticTaskActions, nil, &tasks); err != nil {
		s.note("sessions", "Couldn't list the running tasks: "+elasticProblem(err))
	} else {
		s.Sessions = elasticSessions(tasks.Tasks)
		x.Processing = int32(len(s.Sessions))
		s.Connections.Active = int32(len(s.Sessions))
	}

	d := e.cached()
	if d == nil {
		// The first look: read the slow parts now so it isn't missing them.
		d = &elasticDetail{}
		var dummy DatabaseSnapshot
		e.details(ctx, &dummy, d)
		e.mu.Lock()
		e.detail = d
		e.mu.Unlock()
	}
	x.Documents, x.Indexes = d.documents, d.indexes
	x.ReadOnlyIndices = append(x.ReadOnlyIndices, d.readOnly...)
	if !d.thresholdsOff {
		x.HighWatermark, x.FloodStage = d.high, d.flood
	}
	if d.authOff {
		s.Security.AuthDisabled = true
	}
	return nil
}

func (e *elasticEngine) cached() *elasticDetail {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.detail
}

// nodes fills memory, disk, connections, counters and members from node
// stats.
func (e *elasticEngine) nodes(s *DatabaseSnapshot, ns elasticNodeStats) {
	x := s.Search
	var (
		heapUsed, heapMax         int64
		queries, fetches, writes  int64
		hits, misses, tripped     int64
		openHTTP                  int32
		started                   time.Time
		fullest                   *DatabaseDisk
		fullestRatio, fullestHeap float64
		haveRatio, haveHeap       bool
		segments, fds, maxFDs     int64
		cpuMax                    int
	)
	ids := make([]string, 0, len(ns.Nodes))
	for id := range ns.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		n := ns.Nodes[id]
		heapUsed += n.JVM.Mem.HeapUsed
		heapMax += n.JVM.Mem.HeapMax
		if n.JVM.Mem.HeapMax > 0 {
			r := float64(n.JVM.Mem.HeapUsed) / float64(n.JVM.Mem.HeapMax)
			if !haveHeap || r > fullestHeap {
				fullestHeap, haveHeap = r, true
			}
		}
		if n.JVM.Timestamp > 0 && n.JVM.Uptime > 0 {
			t := time.UnixMilli(n.JVM.Timestamp - n.JVM.Uptime).Truncate(time.Second)
			if started.IsZero() || t.Before(started) {
				started = t
			}
		}
		queries += n.Indices.Search.QueryTotal
		fetches += n.Indices.Search.FetchTotal + n.Indices.Get.Total
		writes += n.Indices.Indexing.IndexTotal + n.Indices.Indexing.DeleteTotal
		hits += n.Indices.QueryCache.Hits
		misses += n.Indices.QueryCache.Misses
		segments += n.Indices.Segments.Count
		fds += n.Process.OpenFDs
		maxFDs = max(maxFDs, n.Process.MaxFDs)
		cpuMax = max(cpuMax, n.OS.CPU.Percent)
		openHTTP += n.HTTP.CurrentOpen
		for _, b := range n.Breakers {
			tripped += b.Tripped
		}
		if n.data() {
			total, avail := n.FS.Total.Total, n.FS.Total.Available
			path := ""
			if len(n.FS.Data) > 0 {
				path = n.FS.Data[0].Path
			}
			if total > 0 {
				r := 1 - float64(avail)/float64(total)
				if !haveRatio || r > fullestRatio {
					fullestRatio, haveRatio = r, true
					fullest = &DatabaseDisk{Path: path, TotalBytes: total, FreeBytes: avail, Source: "engine"}
				}
			}
		}
		for _, c := range n.HTTP.Clients {
			if c.ClosedMillis != nil {
				continue
			}
			s.all = append(s.all, DatabaseActivity{
				ID:     "",
				Client: hostOf(c.RemoteAddress),
				App:    c.Agent,
				User:   c.XOpaqueID,
				State:  "idle",
				Ours:   c.Agent == "morche",
			})
		}
		addr := n.TransportAddress
		if addr == "" {
			addr = n.Host
		}
		s.Replication.Replicas = append(s.Replication.Replicas, DatabaseReplica{
			Name:    n.Name,
			Address: addr,
			State:   strings.Join(elasticRoles(n.Roles), ", "),
			Healthy: true,
		})
	}
	if len(ns.Nodes) <= 1 {
		// One node isn't a cluster of copies.
		s.Replication.Replicas = nil
	}
	if heapMax > 0 {
		s.Memory = &DatabaseMemory{UsedBytes: heapUsed, LimitBytes: heapMax}
	}
	if haveHeap {
		x.HeapRatio = f64(fullestHeap)
	}
	if haveRatio {
		x.DiskRatio = f64(fullestRatio)
		s.Disk = fullest
		s.DataDir = fullest.Path
	}
	if !started.IsZero() {
		s.StartedAt = &started
	}
	s.Connections.Total = openHTTP
	s.counters.queries = i64(queries)
	s.counters.reads = i64(fetches)
	s.counters.writes = i64(writes)
	s.counters.cacheHits = i64(hits)
	s.counters.cacheReads = i64(hits + misses)
	s.fact("Nodes", "Segments", groupDigits(segments))
	if maxFDs > 0 {
		s.fact("Nodes", "Open files", fmt.Sprintf("%s of %s", groupDigits(fds), groupDigits(maxFDs)))
	}
	s.fact("Nodes", "Busiest CPU", fmt.Sprintf("%d%%", cpuMax))
	if tripped > 0 {
		s.fact("Memory", "Circuit breakers tripped", groupDigits(tripped)+" since start")
	}
}

// elasticRoles shortens the node roles: the data_* tiers read as "data".
func elasticRoles(roles []string) []string {
	var out []string
	for _, r := range roles {
		if strings.HasPrefix(r, "data_") {
			r = "data"
		}
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(addr, "[]")
}

// elasticSessions turns the task list into sessions: only the tasks people
// started (a shard-level child shows under its parent).
func elasticSessions(tasks []elasticTask) []DatabaseActivity {
	ids := map[string]bool{}
	for _, t := range tasks {
		ids[fmt.Sprintf("%s:%d", t.Node, t.ID)] = true
	}
	out := []DatabaseActivity{}
	for _, t := range tasks {
		if t.Parent != "" && ids[t.Parent] {
			continue
		}
		secs := float64(t.RunningNs) / 1e9
		q := t.Description
		if q == "" {
			q = t.Action
		}
		out = append(out, DatabaseActivity{
			ID:        fmt.Sprintf("%s:%d", t.Node, t.ID),
			User:      t.Headers.OpaqueID,
			App:       t.Action,
			State:     "active",
			Query:     truncate(q, queryLimit),
			Seconds:   &secs,
			BlockedBy: []string{},
			Ours:      strings.HasPrefix(t.Action, "cluster:monitor/"),
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return *out[i].Seconds > *out[j].Seconds })
	return out
}

// elasticProblem says why a part couldn't be read, in the login's terms.
func elasticProblem(err error) string {
	switch HTTPStatus(err) {
	case http.StatusForbidden:
		return "this login isn't allowed to (it needs the monitor cluster privilege, and view_index_metadata / monitor on the indices)."
	case http.StatusNotFound, http.StatusBadRequest:
		return "this version doesn't have it (" + err.Error() + ")."
	}
	return err.Error()
}

// elasticIndexRow is one line of _cat/indices?format=json&bytes=b.
type elasticIndexRow struct {
	Health    string `json:"health"`
	Status    string `json:"status"`
	Index     string `json:"index"`
	Pri       string `json:"pri"`
	Rep       string `json:"rep"`
	DocsCount string `json:"docs.count"`
	StoreSize string `json:"store.size"`
}

func atoi64(s string) (int64, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n, err == nil
}

// ElasticSystemIndex is an index Elasticsearch keeps for itself (or a data
// stream's backing index): its name starts with a dot.
func ElasticSystemIndex(name string) bool { return strings.HasPrefix(name, ".") }

func (e *elasticEngine) heavy(ctx context.Context, s *DatabaseSnapshot) error {
	d := &elasticDetail{}
	err := e.details(ctx, s, d)
	e.mu.Lock()
	e.detail = d
	e.mu.Unlock()
	return err
}

// details reads indices, cluster settings, read-only blocks, users and
// security, into s (heavy) and d (the parts every light look shows).
func (e *elasticEngine) details(ctx context.Context, s *DatabaseSnapshot, d *elasticDetail) error {
	var rows []elasticIndexRow
	if err := e.h.JSON(ctx, http.MethodGet, "/_cat/indices?format=json&bytes=b&expand_wildcards=all&h=health,status,index,pri,rep,docs.count,store.size", nil, &rows); err != nil {
		s.note("databases", "Couldn't list the indices: "+elasticProblem(err))
	} else {
		var total, docs int64
		haveDocs := false
		s.Databases = []DatabaseInfo{}
		for _, r := range rows {
			size, _ := atoi64(r.StoreSize)
			total += size
			n, ok := atoi64(r.DocsCount)
			if ok {
				docs += n
				haveDocs = true
			}
			if ElasticSystemIndex(r.Index) {
				continue
			}
			d.indexes++
			info := DatabaseInfo{Name: r.Index, SizeBytes: i64(size), State: strings.ToUpper(r.Status)}
			if ok {
				info.Tables = i64(n)
			}
			s.Databases = append(s.Databases, info)
			t := DatabaseTable{Name: r.Index, Kind: "index", SizeBytes: size}
			if ok {
				t.Rows = i64(n)
			}
			s.Tables = append(s.Tables, t)
		}
		sort.Slice(s.Databases, func(i, j int) bool { return s.Databases[i].Name < s.Databases[j].Name })
		sortTables(s)
		s.SizeBytes = i64(total)
		if haveDocs {
			d.documents = i64(docs)
		}
		s.fact("Data", "Indices", strconv.Itoa(int(d.indexes)))
		if d.documents != nil {
			s.fact("Data", "Documents", groupDigits(*d.documents))
		}
	}

	var cs struct {
		Persistent map[string]any `json:"persistent"`
		Transient  map[string]any `json:"transient"`
		Defaults   map[string]any `json:"defaults"`
	}
	if err := e.h.JSON(ctx, http.MethodGet, "/_cluster/settings?include_defaults=true&flat_settings=true", nil, &cs); err != nil {
		s.note("settings", "Couldn't read the cluster settings: "+elasticProblem(err))
	} else {
		get := func(k string) (string, bool) {
			for _, m := range []map[string]any{cs.Transient, cs.Persistent, cs.Defaults} {
				if v, ok := m[k]; ok {
					return settingText(v), true
				}
			}
			return "", false
		}
		if v, ok := get("cluster.routing.allocation.disk.threshold_enabled"); ok && v == "false" {
			d.thresholdsOff = true
			s.Security.Risks = append(s.Security.Risks, "Disk watermarks are turned off (cluster.routing.allocation.disk.threshold_enabled = false): a full disk can corrupt shards instead of blocking writes.")
		}
		if v, ok := get("cluster.routing.allocation.disk.watermark.high"); ok {
			d.high = WatermarkRatio(v)
		}
		if v, ok := get("cluster.routing.allocation.disk.watermark.flood_stage"); ok {
			d.flood = WatermarkRatio(v)
		}
		if v, ok := get("action.destructive_requires_name"); ok && v == "false" {
			s.Security.Risks = append(s.Security.Risks, "action.destructive_requires_name is false: a DELETE on * or _all removes every index.")
		}
		for _, k := range elasticWatched {
			if v, ok := get(k); ok {
				s.Settings = append(s.Settings, DatabaseSetting{Name: k, Value: v})
			}
		}
	}

	var blocks map[string]struct {
		Settings map[string]any `json:"settings"`
	}
	if err := e.h.JSON(ctx, http.MethodGet, "/_all/_settings/index.blocks.read_only*?flat_settings=true&expand_wildcards=all", nil, &blocks); err != nil {
		s.note("settings", "Couldn't read which indices are read-only: "+elasticProblem(err))
	} else {
		for name, b := range blocks {
			if settingText(b.Settings["index.blocks.read_only_allow_delete"]) == "true" || settingText(b.Settings["index.blocks.read_only"]) == "true" {
				d.readOnly = append(d.readOnly, name)
			}
		}
		sort.Strings(d.readOnly)
	}

	var hl elasticHealth
	if e.h.JSON(ctx, http.MethodGet, "/_cluster/health", nil, &hl) == nil {
		s.fact("Cluster", "Name", hl.ClusterName)
		s.fact("Cluster", "Status", hl.Status)
		s.fact("Cluster", "Nodes", fmt.Sprintf("%d (%d with data)", hl.Nodes, hl.DataNodes))
		s.fact("Cluster", "Shards", fmt.Sprintf("%d active, %d primary, %d unassigned", hl.ActiveShards, hl.ActivePrimaryShards, hl.Unassigned))
		s.fact("Cluster", "Pending tasks", strconv.Itoa(int(hl.PendingTasks)))
		if hl.MaxWaitMs > 0 {
			s.fact("Cluster", "Longest wait in the task queue", humanSeconds(float64(hl.MaxWaitMs)/1000))
		}
	}
	var root elasticRoot
	if e.h.JSON(ctx, http.MethodGet, "/", nil, &root) == nil {
		s.fact("Cluster", "Version", ElasticFlavor(root.Version.Distribution)+" "+root.Version.Number)
	}

	d.authOff = e.security(ctx, s)
	return nil
}

// elasticWatched are cluster settings worth showing and watching for changes.
var elasticWatched = []string{
	"cluster.routing.allocation.enable",
	"cluster.routing.allocation.disk.threshold_enabled",
	"cluster.routing.allocation.disk.watermark.low",
	"cluster.routing.allocation.disk.watermark.high",
	"cluster.routing.allocation.disk.watermark.flood_stage",
	"cluster.max_shards_per_node",
	"action.destructive_requires_name",
	"action.auto_create_index",
	"search.max_buckets",
	"indices.breaker.total.limit",
	"indices.memory.index_buffer_size",
	"xpack.security.enabled",
	"plugins.security.disabled",
}

// settingText is a flat setting's value as text (lists joined).
func settingText(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []any:
		parts := make([]string, len(x))
		for i, p := range x {
			parts[i] = settingText(p)
		}
		return strings.Join(parts, ",")
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// WatermarkRatio reads a disk watermark as a share of the disk. "90%" and
// "0.9" are shares; a byte size ("10gb", meaning that much left free) isn't,
// so it gives nil.
func WatermarkRatio(v string) *float64 {
	v = strings.TrimSpace(v)
	if p, ok := strings.CutSuffix(v, "%"); ok {
		f, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil || f < 0 || f > 100 {
			return nil
		}
		return f64(f / 100)
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 || f > 1 {
		return nil
	}
	return f64(f)
}

// security reads the users and whether security is on at all (false = off).
func (e *elasticEngine) security(ctx context.Context, s *DatabaseSnapshot) bool {
	var xp struct {
		Features struct {
			Security struct {
				Available bool `json:"available"`
				Enabled   bool `json:"enabled"`
			} `json:"security"`
		} `json:"features"`
	}
	if err := e.h.JSON(ctx, http.MethodGet, "/_xpack?categories=features", nil, &xp); err == nil {
		if !xp.Features.Security.Enabled {
			s.Security.AuthDisabled = true
			s.Security.Risks = append(s.Security.Risks, "Security is turned off (xpack.security.enabled = false): anyone who reaches the port can read and change everything.")
			return true
		}
	}
	var users map[string]struct {
		Roles   []string `json:"roles"`
		Enabled bool     `json:"enabled"`
	}
	if err := e.h.JSON(ctx, http.MethodGet, "/_security/user", nil, &users); err != nil {
		switch HTTPStatus(err) {
		case http.StatusForbidden:
			s.note("users", "This login can't list users (it needs the read_security or manage_security cluster privilege).")
		case http.StatusNotFound, http.StatusBadRequest, http.StatusInternalServerError:
			s.note("users", "The users can't be listed here: security isn't on, or this cluster manages users another way (OpenSearch: the security plugin).")
		default:
			s.note("users", "Couldn't list the users: "+err.Error())
		}
		return false
	}
	names := make([]string, 0, len(users))
	for n := range users {
		names = append(names, n)
	}
	sort.Strings(names)
	var admins int32
	for _, n := range names {
		u := users[n]
		admin := slices.Contains(u.Roles, "superuser")
		if admin && u.Enabled {
			admins++
		}
		s.Users = append(s.Users, DatabaseUser{Name: n, Admin: admin, Disabled: !u.Enabled})
	}
	s.Security.Admins = &admins
	return false
}

// kill cancels a task ("node:id"); connection makes no difference here.
func (e *elasticEngine) kill(ctx context.Context, id string, _ bool) error {
	node, num, ok := strings.Cut(id, ":")
	if !ok || node == "" {
		return errors.New("a task id looks like node:number")
	}
	if _, err := strconv.ParseInt(num, 10, 64); err != nil {
		return errors.New("a task id looks like node:number")
	}
	var res struct {
		NodeFailures []struct {
			Reason struct {
				Reason string `json:"reason"`
			} `json:"caused_by"`
		} `json:"node_failures"`
		TaskFailures []struct {
			Reason struct {
				Reason string `json:"reason"`
			} `json:"reason"`
		} `json:"task_failures"`
	}
	if err := e.h.JSON(ctx, http.MethodPost, Path("_tasks", id, "_cancel"), nil, &res); err != nil {
		if HTTPStatus(err) == http.StatusNotFound {
			return errors.New("that task has already finished")
		}
		return err
	}
	if len(res.TaskFailures) > 0 {
		return errors.New("the task couldn't be canceled: " + res.TaskFailures[0].Reason.Reason)
	}
	if len(res.NodeFailures) > 0 {
		return errors.New("the task couldn't be canceled: " + res.NodeFailures[0].Reason.Reason)
	}
	return nil
}

// ElasticQueryBody turns what someone typed into a search body: a whole body
// ({"query": …, "size": …}), a bare query ({"match": …}), or plain text, taken
// as a query_string (Lucene syntax).
func ElasticQueryBody(text string) (map[string]any, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return map[string]any{"query": map[string]any{"match_all": map[string]any{}}}, nil
	}
	if strings.HasPrefix(text, "{") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(text), &obj); err != nil {
			return nil, fmt.Errorf("the query isn't valid JSON: %w", err)
		}
		if _, ok := obj["query"]; ok {
			return obj, nil
		}
		for k := range obj {
			if elasticBodyKeys[k] {
				return obj, nil
			}
		}
		return map[string]any{"query": obj}, nil
	}
	return map[string]any{"query": map[string]any{"query_string": map[string]any{"query": text}}}, nil
}

// elasticBodyKeys are top-level keys of a search body (so the object isn't a
// bare query).
var elasticBodyKeys = map[string]bool{
	"aggs": true, "aggregations": true, "size": true, "from": true, "sort": true,
	"_source": true, "fields": true, "track_total_hits": true, "post_filter": true,
	"highlight": true, "knn": true, "search_after": true, "pit": true, "timeout": true,
	"collapse": true, "runtime_mappings": true, "suggest": true, "min_score": true,
}

// explain asks Elasticsearch how it rewrites the query into Lucene, per
// index, without running it.
func (e *elasticEngine) explain(ctx context.Context, database, query string) (*DatabasePlan, error) {
	body, err := ElasticQueryBody(query)
	if err != nil {
		return nil, err
	}
	q, ok := body["query"]
	if !ok {
		q = map[string]any{"match_all": map[string]any{}}
	}
	path := "/_validate/query?explain=true&rewrite=true"
	if database = strings.TrimSpace(database); database != "" {
		path = Path(database) + path
	}
	var res struct {
		Valid        bool   `json:"valid"`
		Error        string `json:"error"`
		Explanations []struct {
			Index       string `json:"index"`
			Valid       bool   `json:"valid"`
			Explanation string `json:"explanation"`
			Error       string `json:"error"`
		} `json:"explanations"`
	}
	if err := e.h.JSON(ctx, http.MethodPost, path, map[string]any{"query": q}, &res); err != nil {
		return nil, err
	}
	plan := &DatabasePlan{Format: "text", Warnings: []string{}}
	var b strings.Builder
	for _, x := range res.Explanations {
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		if x.Index != "" {
			b.WriteString(x.Index + ":\n")
		}
		if x.Valid {
			b.WriteString(x.Explanation)
		} else {
			b.WriteString("not valid: " + x.Error)
		}
	}
	if !res.Valid {
		msg := res.Error
		if msg == "" {
			for _, x := range res.Explanations {
				if x.Error != "" {
					msg = x.Error
					break
				}
			}
		}
		if msg == "" {
			msg = "Elasticsearch says the query isn't valid"
		}
		if b.Len() == 0 {
			return nil, errors.New(msg)
		}
		plan.Warnings = append(plan.Warnings, "The query isn't valid: "+msg)
	}
	plan.Plan = b.String()
	plan.Warnings = append(plan.Warnings, elasticPlanWarnings(plan.Plan)...)
	return plan, nil
}

// elasticPlanWarnings points at what usually makes a search slow.
func elasticPlanWarnings(plan string) []string {
	var out []string
	if strings.Contains(plan, ":*") || strings.Contains(plan, "AutomatonQuery") && strings.Contains(plan, "*") {
		out = append(out, "A wildcard at the start of a term makes every term of the field be checked. A keyword field with an ngram analyzer, or the wildcard field type, is faster.")
	}
	if strings.Contains(plan, "RegexpQuery") || strings.Contains(plan, ":/") {
		out = append(out, "Regular expressions are checked against every term of the field; keep them anchored and short.")
	}
	if strings.Contains(plan, "*:*") || strings.Contains(plan, "MatchAllDocsQuery") {
		out = append(out, "Matches every document.")
	}
	if strings.Contains(plan, "FuzzyQuery") || strings.Contains(plan, "~") {
		out = append(out, "Fuzzy matching expands to many terms; a prefix_length of 1–2 keeps it cheap.")
	}
	return out
}

// elasticMadeSettings are index settings the cluster sets itself (or that only
// make sense for the index they came from): left out of a definition and of a
// backup, since an index can't be created with them.
var elasticMadeSettings = []string{
	"uuid", "creation_date", "creation_date_string", "version", "provided_name",
	"resize", "history", "history_uuid", "routing.allocation.initial_recovery",
	"routing_partition_size_auto", "frozen", "verified_before_close",
	"lifecycle.indexing_complete", "shrink", "store.snapshot", "recovery_uuid",
	"hidden", "blocks.read_only_allow_delete", "blocks.write",
}

// CleanElasticSettings drops the cluster-made keys from an index's "index"
// settings (nested, as GET /<index> returns them), in place.
func CleanElasticSettings(index map[string]any) {
	for _, k := range elasticMadeSettings {
		deleteElasticPath(index, strings.Split(k, "."))
	}
}

func deleteElasticPath(m map[string]any, path []string) {
	if len(path) == 1 {
		delete(m, path[0])
		return
	}
	sub, ok := m[path[0]].(map[string]any)
	if !ok {
		return
	}
	deleteElasticPath(sub, path[1:])
	if len(sub) == 0 {
		delete(m, path[0])
	}
}

// CheckElasticIndexName says whether name can be an index's name, in words a
// person can act on.
func CheckElasticIndexName(name string) error {
	switch {
	case name == "":
		return errors.New("Name the index.")
	case name == "." || name == "..":
		return errors.New("An index can't be called . or ..")
	case len(name) > 255:
		return errors.New("An index name can be at most 255 bytes long.")
	case strings.ToLower(name) != name:
		return errors.New("Index names are lowercase only.")
	case strings.ContainsAny(name[:1], "-_+"):
		return errors.New("An index name can't start with -, _ or +.")
	case strings.ContainsAny(name, "\\/*?\"<>|,# :"):
		return errors.New("An index name can't hold spaces or any of \\ / * ? \" < > | , # :")
	}
	return nil
}
