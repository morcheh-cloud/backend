package dbmon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// meiliEngine watches a Meilisearch instance over its HTTP API. Meilisearch
// has no connections or statements to list: what runs is its task queue
// (one batch at a time), so the queue stands in for sessions.
type meiliEngine struct {
	cfg Config
	h   *HTTPDB

	mu sync.Mutex
	// Whether the instance refuses a request without a key, read now and
	// then (it only changes when Meilisearch restarts).
	authChecked time.Time
	authOpen    *bool
	// The metrics route is on (experimental feature), read by heavy.
	metrics bool
}

func openMeili(ctx context.Context, cfg Config) (engine, error) {
	h, err := OpenHTTP(cfg)
	if err != nil {
		return nil, err
	}
	// /health answers without a key; /version tells whether the key works.
	var v meiliVersion
	if err := h.JSON(ctx, http.MethodGet, "/version", nil, &v); err != nil {
		h.Close()
		return nil, err
	}
	return &meiliEngine{cfg: cfg, h: h}, nil
}

func (m *meiliEngine) close() error { return m.h.Close() }

type meiliVersion struct {
	PkgVersion string `json:"pkgVersion"`
	CommitDate string `json:"commitDate"`
}

type meiliIndexStats struct {
	NumberOfDocuments int64            `json:"numberOfDocuments"`
	RawDocumentDbSize *int64           `json:"rawDocumentDbSize"`
	AvgDocumentSize   *int64           `json:"avgDocumentSize"`
	IsIndexing        bool             `json:"isIndexing"`
	FieldDistribution map[string]int64 `json:"fieldDistribution"`
}

type meiliStats struct {
	DatabaseSize     int64                      `json:"databaseSize"`
	UsedDatabaseSize *int64                     `json:"usedDatabaseSize"`
	LastUpdate       *time.Time                 `json:"lastUpdate"`
	Indexes          map[string]meiliIndexStats `json:"indexes"`
}

// meiliTask is one entry of GET /tasks.
type meiliTask struct {
	UID        int64           `json:"uid"`
	IndexUID   *string         `json:"indexUid"`
	Status     string          `json:"status"`
	Type       string          `json:"type"`
	Details    json.RawMessage `json:"details"`
	Error      *meiliTaskError `json:"error"`
	EnqueuedAt *time.Time      `json:"enqueuedAt"`
	StartedAt  *time.Time      `json:"startedAt"`
}

type meiliTaskError struct {
	Message string `json:"message"`
	Code    string `json:"code"`
}

type meiliTasks struct {
	Results []meiliTask `json:"results"`
	Total   *int64      `json:"total"`
	From    *int64      `json:"from"`
}

func (m *meiliEngine) tasks(ctx context.Context, query url.Values) (*meiliTasks, error) {
	var t meiliTasks
	if err := m.h.JSON(ctx, http.MethodGet, "/tasks?"+query.Encode(), nil, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func (m *meiliEngine) light(ctx context.Context, s *DatabaseSnapshot) error {
	start := time.Now()
	var health struct {
		Status string `json:"status"`
	}
	if err := m.h.JSON(ctx, http.MethodGet, "/health", nil, &health); err != nil {
		return err
	}
	s.LatencyMs = int32(time.Since(start).Milliseconds())
	x := &DatabaseSearch{Status: "red"}
	if health.Status == "available" {
		x.Status = "green"
	}
	s.Search = x
	s.Flavor, s.Role = "Meilisearch", "standalone"

	var v meiliVersion
	if err := m.h.JSON(ctx, http.MethodGet, "/version", nil, &v); err != nil {
		return err
	}
	s.Version = v.PkgVersion
	s.fact("Server", "Version", v.PkgVersion)

	var st meiliStats
	if err := m.h.JSON(ctx, http.MethodGet, "/stats", nil, &st); err != nil {
		s.note("size", "Couldn't read /stats: "+err.Error())
	} else {
		size := st.DatabaseSize
		s.SizeBytes = &size
		var docs int64
		for _, ix := range st.Indexes {
			docs += ix.NumberOfDocuments
			if ix.IsIndexing {
				x.Indexing = true
			}
		}
		x.Documents = &docs
		x.Indexes = int32(len(st.Indexes))
		s.fact("Storage", "Indexes", groupDigits(int64(len(st.Indexes))))
		s.fact("Storage", "Documents", groupDigits(docs))
		s.fact("Storage", "Database size", humanBytes(st.DatabaseSize))
		if st.UsedDatabaseSize != nil {
			s.fact("Storage", "Used by data", humanBytes(*st.UsedDatabaseSize))
		}
		if st.LastUpdate != nil {
			s.fact("Storage", "Last update", st.LastUpdate.UTC().Format(time.RFC3339))
		}
	}

	m.queue(ctx, s, x)
	m.counters(ctx, s)

	enc := m.cfg.TLS != TLSDisable && m.cfg.TLS != ""
	s.Security.Encrypted = &enc
	if open := m.authState(ctx); open != nil && *open {
		s.Security.AuthDisabled = true
		s.Security.Risks = append(s.Security.Risks,
			"No master key is set: anyone who reaches the port can read, change and delete every index. Start Meilisearch with MEILI_MASTER_KEY (and MEILI_ENV=production).")
	}
	return nil
}

// queue reads the task queue: what waits (oldest first), what runs, and what
// failed in the last day.
func (m *meiliEngine) queue(ctx context.Context, s *DatabaseSnapshot, x *DatabaseSearch) {
	now := s.CollectedAt
	if now.IsZero() {
		now = time.Now()
	}
	add := func(t meiliTask, state string) {
		a := DatabaseActivity{ID: strconv.FormatInt(t.UID, 10), State: state, Query: meiliTaskText(t), BlockedBy: []string{}}
		if t.IndexUID != nil {
			a.Database = *t.IndexUID
		}
		since := t.EnqueuedAt
		if state == "active" && t.StartedAt != nil {
			since = t.StartedAt
		}
		if since != nil {
			a.Seconds = f64(max(0, now.Sub(*since).Seconds()))
		}
		s.Sessions = append(s.Sessions, a)
	}
	running, err := m.tasks(ctx, url.Values{"statuses": {"processing"}, "limit": {"20"}})
	if err != nil {
		s.note("sessions", "Couldn't read the task queue: "+err.Error())
		return
	}
	for _, t := range running.Results {
		add(t, "active")
	}
	x.Processing = int32(meiliTotal(running))
	waiting, err := m.tasks(ctx, url.Values{"statuses": {"enqueued"}, "limit": {"20"}, "reverse": {"true"}})
	if err == nil {
		x.Enqueued = int32(meiliTotal(waiting))
		if len(waiting.Results) > 0 && waiting.Results[0].EnqueuedAt != nil {
			x.OldestWait = f64(max(0, now.Sub(*waiting.Results[0].EnqueuedAt).Seconds()))
		}
		for _, t := range waiting.Results {
			add(t, "queued")
		}
	}
	failed, err := m.tasks(ctx, url.Values{
		"statuses":        {"failed"},
		"limit":           {"1"},
		"afterEnqueuedAt": {now.Add(-24 * time.Hour).UTC().Format(time.RFC3339)},
	})
	if err == nil {
		x.Failed = int32(meiliTotal(failed))
		if len(failed.Results) > 0 && failed.Results[0].Error != nil {
			x.LastFailure = truncate(failed.Results[0].Error.Message, 500)
		}
	}
	s.Connections.Active = x.Processing
	s.fact("Tasks", "Waiting", groupDigits(int64(x.Enqueued)))
	s.fact("Tasks", "Running", groupDigits(int64(x.Processing)))
	s.fact("Tasks", "Failed in the last 24 hours", groupDigits(int64(x.Failed)))
	if s.Sessions == nil {
		s.Sessions = []DatabaseActivity{}
	}
}

// meiliTotal is how many tasks matched: total (v1.x), else what came back.
func meiliTotal(t *meiliTasks) int64 {
	if t.Total != nil {
		return *t.Total
	}
	return int64(len(t.Results))
}

// meiliTaskText is a task's type plus the gist of its details.
func meiliTaskText(t meiliTask) string {
	var d map[string]any
	_ = json.Unmarshal(t.Details, &d)
	num := func(k string) (int64, bool) {
		if f, ok := d[k].(float64); ok {
			return int64(f), true
		}
		return 0, false
	}
	var parts []string
	if n, ok := num("receivedDocuments"); ok {
		parts = append(parts, groupDigits(n)+" documents received")
	}
	if n, ok := num("indexedDocuments"); ok {
		parts = append(parts, groupDigits(n)+" indexed")
	}
	if n, ok := num("providedIds"); ok {
		parts = append(parts, groupDigits(n)+" ids to delete")
	}
	if n, ok := num("deletedDocuments"); ok {
		parts = append(parts, groupDigits(n)+" deleted")
	}
	if f, ok := d["originalFilter"].(string); ok && f != "" {
		parts = append(parts, "filter "+f)
	}
	if len(parts) == 0 && len(d) > 0 {
		var keys []string
		for k := range d {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts = append(parts, strings.Join(keys, ", "))
	}
	if len(parts) == 0 {
		return t.Type
	}
	return truncate(t.Type+" ("+strings.Join(parts, ", ")+")", queryLimit)
}

// counters: every task gets the next uid, so the newest uid counts the
// changes ever sent (transactions: a task applies all or nothing). With the
// metrics route on, its request counters give searches per second.
func (m *meiliEngine) counters(ctx context.Context, s *DatabaseSnapshot) {
	if t, err := m.tasks(ctx, url.Values{"limit": {"1"}}); err == nil {
		switch {
		case len(t.Results) > 0:
			s.counters.transactions = i64(t.Results[0].UID + 1)
		case t.From == nil:
			s.counters.transactions = i64(0)
		}
	}
	m.mu.Lock()
	on := m.metrics
	m.mu.Unlock()
	if !on {
		return
	}
	raw, err := m.h.Raw(ctx, http.MethodGet, "/metrics", nil, 4<<20)
	if err != nil {
		return
	}
	if n, ok := meiliSearches(raw); ok {
		s.counters.queries = &n
	}
}

// meiliSearches sums the Prometheus request counters of the search routes.
func meiliSearches(raw []byte) (int64, bool) {
	var total float64
	found := false
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "meilisearch_http_requests_total{") {
			continue
		}
		end := strings.LastIndexByte(line, '}')
		if end < 0 {
			continue
		}
		labels := line[:end]
		if !strings.Contains(labels, `/search"`) && !strings.Contains(labels, `/multi-search"`) {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(line[end+1:]), 64)
		if err != nil {
			continue
		}
		total += v
		found = true
	}
	return int64(total), found
}

// authState says whether a request without a key gets in, read at most every
// five minutes.
func (m *meiliEngine) authState(ctx context.Context) *bool {
	m.mu.Lock()
	if time.Since(m.authChecked) < 5*time.Minute {
		v := m.authOpen
		m.mu.Unlock()
		return v
	}
	m.mu.Unlock()
	cfg := m.cfg
	cfg.Username, cfg.Password = "", ""
	var open *bool
	if h, err := OpenHTTP(cfg); err == nil {
		err := h.JSON(ctx, http.MethodGet, "/indexes?limit=1", nil, nil)
		h.Close()
		switch st := HTTPStatus(err); {
		case err == nil:
			open = new(true)
		case st == http.StatusUnauthorized || st == http.StatusForbidden:
			open = new(false)
		}
	}
	m.mu.Lock()
	m.authChecked, m.authOpen = time.Now(), open
	m.mu.Unlock()
	return open
}

type meiliIndex struct {
	UID        string     `json:"uid"`
	PrimaryKey *string    `json:"primaryKey"`
	CreatedAt  *time.Time `json:"createdAt"`
	UpdatedAt  *time.Time `json:"updatedAt"`
}

func (m *meiliEngine) heavy(ctx context.Context, s *DatabaseSnapshot) error {
	var list struct {
		Results []meiliIndex `json:"results"`
		Total   int64        `json:"total"`
	}
	if err := m.h.JSON(ctx, http.MethodGet, "/indexes?limit=1000", nil, &list); err != nil {
		return err
	}
	var st meiliStats
	if err := m.h.JSON(ctx, http.MethodGet, "/stats", nil, &st); err != nil {
		s.note("tables", "Couldn't read /stats: "+err.Error())
	}
	for _, ix := range list.Results {
		d := DatabaseInfo{Name: ix.UID}
		if is, ok := st.Indexes[ix.UID]; ok {
			d.Tables = i64(is.NumberOfDocuments)
			// Only the documents' own size is told per index (v1.13+);
			// the search structures aren't split by index.
			d.SizeBytes = is.RawDocumentDbSize
			t := DatabaseTable{Name: ix.UID, Kind: "index", Rows: i64(is.NumberOfDocuments)}
			if is.RawDocumentDbSize != nil {
				t.SizeBytes = *is.RawDocumentDbSize
			}
			s.Tables = append(s.Tables, t)
		}
		s.Databases = append(s.Databases, d)
	}
	if list.Total > int64(len(list.Results)) {
		s.note("tables", fmt.Sprintf("Only the first %d of %d indexes are listed.", len(list.Results), list.Total))
	}
	sort.SliceStable(s.Tables, func(i, j int) bool {
		if s.Tables[i].SizeBytes != s.Tables[j].SizeBytes {
			return s.Tables[i].SizeBytes > s.Tables[j].SizeBytes
		}
		return deref(s.Tables[i].Rows) > deref(s.Tables[j].Rows)
	})
	if len(s.Tables) > 20 {
		s.Tables = s.Tables[:20]
	}
	sort.SliceStable(s.Databases, func(i, j int) bool { return s.Databases[i].Name < s.Databases[j].Name })

	var v meiliVersion
	if m.h.JSON(ctx, http.MethodGet, "/version", nil, &v) == nil && v.CommitDate != "" {
		if t, err := time.Parse(time.RFC3339, v.CommitDate); err == nil {
			s.fact("Server", "Built", t.UTC().Format("2006-01-02"))
		}
	}

	m.features(ctx, s)
	m.keys(ctx, s)
	return nil
}

// features lists the experimental features and whether each is on.
func (m *meiliEngine) features(ctx context.Context, s *DatabaseSnapshot) {
	var f map[string]any
	if err := m.h.JSON(ctx, http.MethodGet, "/experimental-features", nil, &f); err != nil {
		s.note("settings", "Couldn't read the experimental features: "+err.Error())
		return
	}
	names := make([]string, 0, len(f))
	for k := range f {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		s.Settings = append(s.Settings, DatabaseSetting{Name: "experimental." + k, Value: fmt.Sprint(f[k])})
	}
	on, _ := f["metrics"].(bool)
	m.mu.Lock()
	m.metrics = on
	m.mu.Unlock()
}

// keys lists the API keys by name. The key values themselves are never kept.
func (m *meiliEngine) keys(ctx context.Context, s *DatabaseSnapshot) {
	var keys struct {
		Results []struct {
			Name        *string    `json:"name"`
			Description *string    `json:"description"`
			UID         string     `json:"uid"`
			Actions     []string   `json:"actions"`
			Indexes     []string   `json:"indexes"`
			ExpiresAt   *time.Time `json:"expiresAt"`
		} `json:"results"`
	}
	if err := m.h.JSON(ctx, http.MethodGet, "/keys?limit=1000", nil, &keys); err != nil {
		msg := "Couldn't list the API keys: " + err.Error()
		switch HTTPStatus(err) {
		case http.StatusUnauthorized, http.StatusForbidden:
			msg = "This key can't list the API keys; only the master key (or a key with keys.get) can. Connect with the master key to see them."
		}
		s.note("users", msg)
		return
	}
	var admins int32
	now := time.Now()
	for _, k := range keys.Results {
		u := DatabaseUser{Name: k.UID}
		if len(u.Name) > 8 {
			u.Name = u.Name[:8]
		}
		switch {
		case k.Name != nil && *k.Name != "":
			u.Name = *k.Name
		case k.Description != nil && *k.Description != "":
			u.Name = truncate(*k.Description, 80)
		}
		u.Admin = slices.Contains(k.Actions, "*") && slices.Contains(k.Indexes, "*")
		u.Disabled = k.ExpiresAt != nil && k.ExpiresAt.Before(now)
		if u.Admin && !u.Disabled {
			admins++
		}
		s.Users = append(s.Users, u)
	}
	none := int32(0)
	s.Security.Admins = &admins
	s.Security.NoPassword = &none
}

// kill cancels a task that waits or runs. There are no connections, so
// connection makes no difference.
func (m *meiliEngine) kill(ctx context.Context, id string, _ bool) error {
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		return errors.New("not a Meilisearch task number")
	}
	var t meiliTask
	if err := m.h.JSON(ctx, http.MethodGet, "/tasks/"+id, nil, &t); err != nil {
		if HTTPStatus(err) == http.StatusNotFound {
			return errors.New("that task doesn't exist any more")
		}
		return err
	}
	if t.Status != "enqueued" && t.Status != "processing" {
		return errors.New("that task has already finished")
	}
	return m.h.JSON(ctx, http.MethodPost, "/tasks/cancel?uids="+id, nil, nil)
}

func (m *meiliEngine) explain(context.Context, string, string) (*DatabasePlan, error) {
	return nil, ErrUnsupported
}
