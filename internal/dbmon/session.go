package dbmon

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// engine is one database kind's monitoring queries.
type engine interface {
	// light reads what changes every second: status, connections, sessions,
	// counters, replication, memory.
	light(ctx context.Context, s *DatabaseSnapshot) error
	// heavy reads what is slow to read or slow to change: sizes, tables,
	// indexes, users, settings, top queries.
	heavy(ctx context.Context, s *DatabaseSnapshot) error
	kill(ctx context.Context, id string, connection bool) error
	explain(ctx context.Context, database, query string) (*DatabasePlan, error)
	close() error
}

// DatabasePlan is how the database would run a statement, read without
// running it.
type DatabasePlan struct {
	Format string `json:"format" enum:"text,json" doc:"text: the engine's own tree; json: its JSON plan, pretty-printed"`
	Plan   string `json:"plan"`
	// Cost and rows are the planner's own estimates, when it gives them.
	Cost     *float64 `json:"cost" nullable:"true"`
	Rows     *float64 `json:"rows" nullable:"true"`
	Warnings []string `json:"warnings" doc:"What in the plan is usually slow, e.g. a full scan of a big table"`
}

// ErrUnsupported is an action this engine has no way to do.
var ErrUnsupported = errors.New("not supported for this database")

// Conn is an open monitoring connection to one database. It's safe for
// concurrent use; looks are serialised so rates stay meaningful.
type Conn struct {
	cfg Config
	e   engine

	mu      sync.Mutex
	prev    *DatabaseSnapshot
	details *DatabaseSnapshot
}

// Open connects and checks the login works. Monitoring uses at most two
// connections.
func Open(ctx context.Context, cfg Config) (*Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.timeout())
	defer cancel()
	var (
		e   engine
		err error
	)
	switch cfg.Engine {
	case Postgres:
		e, err = openPostgres(ctx, cfg)
	case MySQL:
		e, err = openMySQL(ctx, cfg)
	case MSSQL:
		e, err = openMSSQL(ctx, cfg)
	case Redis:
		e, err = openRedis(ctx, cfg)
	case Mongo:
		e, err = openMongo(ctx, cfg)
	default:
		return nil, fmt.Errorf("unknown engine %q", cfg.Engine)
	}
	if err != nil {
		return nil, err
	}
	return &Conn{cfg: cfg, e: e}, nil
}

func (c *Conn) Close() error { return c.e.close() }

// Collect looks at the database once. heavy also rereads the slow parts;
// otherwise the last ones read are carried over. A nil error with notes means
// some parts couldn't be read.
func (c *Conn) Collect(ctx context.Context, heavy bool) (*DatabaseSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	s := &DatabaseSnapshot{Engine: c.cfg.Engine, CollectedAt: time.Now()}
	lctx, cancel := context.WithTimeout(ctx, c.cfg.timeout())
	err := c.e.light(lctx, s)
	cancel()
	if err != nil {
		return nil, err
	}

	if heavy || c.details == nil {
		d := &DatabaseSnapshot{Engine: c.cfg.Engine}
		hctx, cancel := context.WithTimeout(ctx, 3*c.cfg.timeout())
		herr := c.e.heavy(hctx, d)
		cancel()
		if herr != nil {
			d.note("details", "Couldn't read sizes and details: "+herr.Error())
		}
		now := time.Now()
		d.DetailsAt = &now
		c.details = d
	}
	carry(s, c.details)
	summarize(s)
	s.Rates = rates(c.prev, s)
	c.prev = s
	return s, nil
}

// Kill stops what a session runs (or, with connection, closes it).
func (c *Conn) Kill(ctx context.Context, id string, connection bool) error {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.timeout())
	defer cancel()
	return c.e.kill(ctx, id, connection)
}

// Explain shows the plan for query without running it.
func (c *Conn) Explain(ctx context.Context, database, query string) (*DatabasePlan, error) {
	query = strings.TrimSpace(strings.TrimRight(strings.TrimSpace(query), ";"))
	if query == "" {
		return nil, errors.New("type a query")
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.timeout())
	defer cancel()
	return c.e.explain(ctx, database, query)
}

// carry puts the slow parts read earlier into a fresh look.
func carry(s, d *DatabaseSnapshot) {
	if d == nil {
		return
	}
	s.DetailsAt = d.DetailsAt
	if s.SizeBytes == nil {
		s.SizeBytes = d.SizeBytes
	}
	if s.Disk == nil {
		s.Disk = d.Disk
	}
	if s.DataDir == "" {
		s.DataDir = d.DataDir
	}
	if s.Log == nil {
		s.Log = d.Log
	}
	// Redis lists its databases (keyspace) in every look.
	if len(s.Databases) == 0 {
		s.Databases = slices.Clone(d.Databases)
	}
	s.Tables = d.Tables
	s.TablesScope = d.TablesScope
	s.IDColumns = d.IDColumns
	s.Indexes = d.Indexes
	s.Settings = d.Settings
	s.Users = d.Users
	if len(s.Queries) == 0 {
		s.Queries = d.Queries
		s.QueriesSource = d.QueriesSource
	}
	if s.Security.Admins == nil {
		s.Security.Admins = d.Security.Admins
	}
	if s.Security.NoPassword == nil {
		s.Security.NoPassword = d.Security.NoPassword
	}
	if s.Security.ListensOn == "" {
		s.Security.ListensOn = d.Security.ListensOn
	}
	s.Security.Risks = append(s.Security.Risks, d.Security.Risks...)
	s.Facts = append(s.Facts, d.Facts...)
	s.Notes = append(s.Notes, d.Notes...)
}

// sessionLimit caps the sessions sent; the busiest come first.
const sessionLimit = 100

// summarize fills the connection counts, the per-address groups and the busy
// sessions from every connection an engine listed (in s.all).
func summarize(s *DatabaseSnapshot) {
	all := s.all
	s.all = nil
	if s.Connections.Total == 0 {
		s.Connections.Total = int32(len(all))
	}
	var active, idle, idleTx, blocked int32
	clients := map[string]*DatabaseClient{}
	perDB := map[string]int32{}
	var busy []DatabaseActivity
	for _, a := range all {
		switch a.State {
		case "active":
			active++
		case "idle_in_tx":
			idleTx++
		default:
			idle++
		}
		if len(a.BlockedBy) > 0 {
			blocked++
		}
		if a.Database != "" {
			perDB[a.Database]++
		}
		addr := a.Client
		if addr == "" {
			addr = "local"
		}
		cl := clients[addr]
		if cl == nil {
			cl = &DatabaseClient{Address: addr}
			clients[addr] = cl
		}
		cl.Total++
		if a.State == "active" {
			cl.Active++
		}
		cl.Users = addUnique(cl.Users, a.User)
		cl.Databases = addUnique(cl.Databases, a.Database)
		cl.Apps = addUnique(cl.Apps, a.App)
		if a.State != "idle" || len(a.BlockedBy) > 0 {
			busy = append(busy, a)
		}
	}
	if s.Connections.Active == 0 {
		s.Connections.Active = active
	}
	if s.Connections.Idle == 0 && len(all) > 0 {
		s.Connections.Idle = idle
	}
	if s.Connections.IdleInTx == 0 {
		s.Connections.IdleInTx = idleTx
	}
	if s.Connections.Blocked == 0 {
		s.Connections.Blocked = blocked
	}
	for i := range s.Databases {
		s.Databases[i].Connections = perDB[s.Databases[i].Name]
	}
	if len(all) > 0 {
		s.Clients = make([]DatabaseClient, 0, len(clients))
		for _, c := range clients {
			s.Clients = append(s.Clients, *c)
		}
		sort.Slice(s.Clients, func(i, j int) bool {
			if s.Clients[i].Total != s.Clients[j].Total {
				return s.Clients[i].Total > s.Clients[j].Total
			}
			return s.Clients[i].Address < s.Clients[j].Address
		})
	}
	sort.SliceStable(busy, func(i, j int) bool {
		return longest(busy[i]) > longest(busy[j])
	})
	if len(busy) > sessionLimit {
		busy = busy[:sessionLimit]
	}
	if s.Sessions == nil {
		s.Sessions = busy
	}
	waits := map[string]int32{}
	for _, a := range busy {
		if a.Wait != "" && !a.Ours {
			waits[a.Wait]++
		}
	}
	if len(s.Waits) == 0 {
		for e, n := range waits {
			s.Waits = append(s.Waits, DatabaseWait{Event: e, Count: n})
		}
		sort.Slice(s.Waits, func(i, j int) bool {
			if s.Waits[i].Count != s.Waits[j].Count {
				return s.Waits[i].Count > s.Waits[j].Count
			}
			return s.Waits[i].Event < s.Waits[j].Event
		})
	}
	nonNil(s)
}

// nonNil makes every list an array in JSON, never null.
func nonNil(s *DatabaseSnapshot) {
	for _, p := range []*[]string{&s.Security.Risks} {
		if *p == nil {
			*p = []string{}
		}
	}
	if s.Databases == nil {
		s.Databases = []DatabaseInfo{}
	}
	if s.Clients == nil {
		s.Clients = []DatabaseClient{}
	}
	if s.Sessions == nil {
		s.Sessions = []DatabaseActivity{}
	}
	for i := range s.Sessions {
		if s.Sessions[i].BlockedBy == nil {
			s.Sessions[i].BlockedBy = []string{}
		}
	}
	for i := range s.Clients {
		for _, p := range []*[]string{&s.Clients[i].Users, &s.Clients[i].Databases, &s.Clients[i].Apps} {
			if *p == nil {
				*p = []string{}
			}
		}
	}
	if s.Queries == nil {
		s.Queries = []DatabaseQuery{}
	}
	if s.Tables == nil {
		s.Tables = []DatabaseTable{}
	}
	if s.IDColumns == nil {
		s.IDColumns = []DatabaseIDColumn{}
	}
	if s.Indexes == nil {
		s.Indexes = []DatabaseIndex{}
	}
	if s.Replication.Replicas == nil {
		s.Replication.Replicas = []DatabaseReplica{}
	}
	if s.Replication.Slots == nil {
		s.Replication.Slots = []DatabaseSlot{}
	}
	if s.Waits == nil {
		s.Waits = []DatabaseWait{}
	}
	if s.Settings == nil {
		s.Settings = []DatabaseSetting{}
	}
	if s.Users == nil {
		s.Users = []DatabaseUser{}
	}
	if s.Facts == nil {
		s.Facts = []DatabaseFact{}
	}
	if s.Notes == nil {
		s.Notes = []DatabaseNote{}
	}
}

func longest(a DatabaseActivity) float64 {
	m := -1.0
	if a.Seconds != nil {
		m = *a.Seconds
	}
	if a.TxSeconds != nil && *a.TxSeconds > m {
		m = *a.TxSeconds
	}
	return m
}

func addUnique(list []string, v string) []string {
	if v == "" || slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}

// rates divides the change in each counter by the time between two looks. A
// counter that went down (a restart, a reset) gives no rate.
func rates(prev, cur *DatabaseSnapshot) *DatabaseRates {
	if prev == nil {
		cur.CacheHit = ratio(nil, nil, cur.counters.cacheHits, cur.counters.cacheReads, cur.CacheHit)
		return nil
	}
	secs := cur.CollectedAt.Sub(prev.CollectedAt).Seconds()
	if secs <= 0 {
		return nil
	}
	p, c := prev.counters, cur.counters
	per := func(a, b *int64) *float64 {
		if a == nil || b == nil || *b < *a {
			return nil
		}
		v := float64(*b-*a) / secs
		return &v
	}
	diff := func(a, b *int64) *int64 {
		if a == nil || b == nil || *b < *a {
			return nil
		}
		v := *b - *a
		return &v
	}
	cur.CacheHit = ratio(p.cacheHits, p.cacheReads, c.cacheHits, c.cacheReads, cur.CacheHit)
	return &DatabaseRates{
		Queries:      per(p.queries, c.queries),
		Transactions: per(p.transactions, c.transactions),
		Reads:        per(p.reads, c.reads),
		Writes:       per(p.writes, c.writes),
		Deadlocks:    diff(p.deadlocks, c.deadlocks),
		FailedLogins: diff(p.failedLogins, c.failedLogins),
		Seconds:      secs,
	}
}

// ratio is the cache hit share: over the last interval when there was enough
// traffic, else since start; an engine's own figure wins.
func ratio(ph, pr, ch, cr *int64, own *float64) *float64 {
	if own != nil {
		return own
	}
	if ch == nil || cr == nil {
		return nil
	}
	if ph != nil && pr != nil && *cr-*pr >= 100 && *ch >= *ph {
		v := float64(*ch-*ph) / float64(*cr-*pr)
		return clamp01(v)
	}
	if *cr == 0 {
		return nil
	}
	return clamp01(float64(*ch) / float64(*cr))
}

func clamp01(v float64) *float64 {
	v = max(0, min(1, v))
	return &v
}

// ---- small helpers shared by the engines ----

func i64(v int64) *int64     { return &v }
func i32(v int32) *int32     { return &v }
func f64(v float64) *float64 { return &v }
func ptrTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// truncate keeps query text readable and bounded.
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

const queryLimit = 4000
