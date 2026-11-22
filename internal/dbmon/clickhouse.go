package dbmon

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

// clickhouseApp is the client name Morche's monitoring queries carry, so the
// top queries can leave them out.
const clickhouseApp = "morche-monitor"

type clickhouseEngine struct {
	cfg     Config
	db      *sql.DB
	version string
	// Where inserts slow down and fail for too many parts in a partition
	// (MergeTree settings, server-wide defaults).
	delayAt, throwAt int64
}

func openClickHouse(ctx context.Context, cfg Config) (engine, error) {
	db, err := openClickHouseDB(cfg, "", clickhouseApp)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(5 * time.Minute)
	c := &clickhouseEngine{cfg: cfg, db: db, delayAt: 1000, throwAt: 3000}
	if err := db.QueryRowContext(ctx, "SELECT version()").Scan(&c.version); err != nil {
		db.Close()
		return nil, err
	}
	c.partLimits(ctx)
	return c, nil
}

func (c *clickhouseEngine) close() error { return c.db.Close() }

// partLimits reads parts_to_delay_insert / parts_to_throw_insert. A table can
// override them; the server's defaults are what most tables use.
func (c *clickhouseEngine) partLimits(ctx context.Context) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT name, toInt64OrZero(value) FROM system.merge_tree_settings
		 WHERE name IN ('parts_to_delay_insert', 'parts_to_throw_insert')`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var v int64
		if rows.Scan(&name, &v) != nil || v <= 0 {
			continue
		}
		if name == "parts_to_delay_insert" {
			c.delayAt = v
		} else {
			c.throwAt = v
		}
	}
}

// chProblem says why a system table couldn't be read, in the login's terms.
func chProblem(what string, err error) string {
	switch ClickHouseCode(err) {
	case chAccessDenied:
		return "This login can't read " + what + ". Grant it SELECT on system.* (or the table) to see it."
	case 60: // UNKNOWN_TABLE
		return what + " doesn't exist on this server."
	}
	return "Couldn't read " + what + ": " + err.Error()
}

// pairs reads a name → number list.
func (c *clickhouseEngine) pairs(ctx context.Context, query string) (map[string]int64, error) {
	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var k string
		var v float64
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = int64(v)
	}
	return out, rows.Err()
}

// chEvents are the cumulative counters read for rates and facts. system.events
// leaves out the ones still at zero, so a missing name counts as 0.
var chEvents = []string{
	"Query", "SelectQuery", "InsertQuery", "FailedQuery", "FailedSelectQuery",
	"FailedInsertQuery", "InsertedRows", "InsertedBytes", "SelectedRows", "SelectedBytes",
	"MarkCacheHits", "MarkCacheMisses", "DelayedInserts", "RejectedInserts",
	"Merge", "MergedRows",
}

var chMetrics = []string{
	"TCPConnection", "HTTPConnection", "MySQLConnection", "PostgreSQLConnection",
	"InterserverConnection", "Query", "Merge", "PartMutation", "MemoryTracking",
	"ReadonlyReplica", "DelayedInserts",
}

func inList(names []string) string {
	return "('" + strings.Join(names, "','") + "')"
}

func (c *clickhouseEngine) light(ctx context.Context, s *DatabaseSnapshot) error {
	start := time.Now()
	var up float64
	if err := c.db.QueryRowContext(ctx, "SELECT toFloat64(uptime())").Scan(&up); err != nil {
		return err
	}
	s.LatencyMs = int32(time.Since(start).Milliseconds())
	s.Flavor = "ClickHouse"
	s.Version = c.version
	t := time.Now().Add(-time.Duration(up) * time.Second).Truncate(time.Second)
	s.StartedAt = &t
	s.Role = "standalone"
	enc := c.cfg.TLS != TLSDisable && c.cfg.TLS != ""
	s.Security.Encrypted = &enc

	metrics, err := c.pairs(ctx, "SELECT metric, toFloat64(value) FROM system.metrics WHERE metric IN "+inList(chMetrics))
	if err != nil {
		s.note("server", chProblem("system.metrics", err))
	}
	s.Connections.Total = int32(metrics["TCPConnection"] + metrics["HTTPConnection"] +
		metrics["MySQLConnection"] + metrics["PostgreSQLConnection"])
	if n := metrics["InterserverConnection"]; n > 0 {
		s.fact("Connections", "Between servers (replication)", groupDigits(n))
	}
	var maxConns int64
	if err := c.db.QueryRowContext(ctx,
		"SELECT toInt64OrZero(value) FROM system.server_settings WHERE name = 'max_connections'").Scan(&maxConns); err == nil && maxConns > 0 {
		s.Connections.Max = i32(int32(min(maxConns, 1<<31-1)))
	}

	{
		ev, err := c.pairs(ctx, "SELECT event, toFloat64(value) FROM system.events WHERE event IN "+inList(chEvents))
		if err != nil {
			s.note("server", chProblem("system.events", err))
		} else {
			get := func(k string) *int64 { v := ev[k]; return &v }
			s.counters = counters{
				queries: get("Query"),
				reads:   get("SelectedRows"),
				writes:  get("InsertedRows"),
			}
			if n := ev["FailedQuery"]; n > 0 {
				s.fact("Work", "Failed queries since start", groupDigits(n))
			}
			if n := ev["RejectedInserts"]; n > 0 {
				s.fact("Work", "Inserts refused: too many parts", groupDigits(n))
			}
			if n := ev["DelayedInserts"]; n > 0 {
				s.fact("Work", "Inserts slowed down: many parts", groupDigits(n))
			}
			s.fact("Work", "Rows inserted since start", groupDigits(ev["InsertedRows"]))
			s.fact("Work", "Data read since start", humanBytes(ev["SelectedBytes"]))
			if h, m := ev["MarkCacheHits"], ev["MarkCacheMisses"]; h+m >= 100 {
				s.fact("Memory", "Mark cache hits", pct(float64(h)/float64(h+m)))
			}
		}
	}
	if n := metrics["Merge"]; n > 0 {
		s.fact("Work", "Merges running", groupDigits(n))
	}
	if n := metrics["PartMutation"]; n > 0 {
		s.fact("Work", "Mutations running", groupDigits(n))
	}

	// Memory: what the server counts against max_server_memory_usage.
	var limit int64
	_ = c.db.QueryRowContext(ctx,
		"SELECT toInt64OrZero(value) FROM system.server_settings WHERE name = 'max_server_memory_usage'").Scan(&limit)
	if used, ok := metrics["MemoryTracking"]; ok {
		s.Memory = &DatabaseMemory{UsedBytes: used, LimitBytes: limit}
	}
	if am, err := c.pairs(ctx, `
		SELECT metric, value FROM system.asynchronous_metrics
		 WHERE metric IN ('MemoryResident', 'OSMemoryTotal', 'MaxPartCountForPartition')`); err == nil {
		if n := am["MemoryResident"]; n > 0 {
			s.fact("Memory", "Resident memory", humanBytes(n))
		}
		if n := am["OSMemoryTotal"]; n > 0 {
			s.fact("Memory", "Server memory", humanBytes(n))
		}
	}

	if err := c.activity(ctx, s); err != nil {
		s.note("sessions", chProblem("system.processes", err))
	}
	c.replication(ctx, s, metrics["ReadonlyReplica"])
	c.parts(ctx, s)
	c.mutations(ctx, s)
	return nil
}

// activity lists the running queries. ClickHouse has no list of idle
// connections: a session is a query in flight, and Clients groups those.
func (c *clickhouseEngine) activity(ctx context.Context, s *DatabaseSnapshot) error {
	rows, err := c.db.QueryContext(ctx, `
		SELECT query_id, user, toString(address), current_database, client_name,
		       elapsed, query, memory_usage, query_kind, query_id = queryID()
		  FROM system.processes
		 WHERE is_initial_query`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var running int32
	for rows.Next() {
		var (
			a          DatabaseActivity
			addr, kind string
			secs       float64
			mem        int64
		)
		if err := rows.Scan(&a.ID, &a.User, &addr, &a.Database, &a.App, &secs, &a.Query, &mem, &kind, &a.Ours); err != nil {
			return err
		}
		a.Client = strings.TrimPrefix(addr, "::ffff:")
		if a.Client == "::1" || a.Client == "127.0.0.1" || a.Client == "::" {
			a.Client = "local"
		}
		a.App = chApp(a.App)
		a.State = "active"
		a.Seconds = f64(secs)
		if mem > 0 {
			a.Wait = kind + " · " + humanBytes(mem)
		} else if kind != "" {
			a.Wait = kind
		}
		a.Query = truncate(a.Query, queryLimit)
		running++
		s.all = append(s.all, a)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.Connections.Active = running
	if s.Connections.Total > running {
		s.Connections.Idle = s.Connections.Total - running
	}
	return nil
}

// chApp turns "morche-monitor/1 clickhouse-go/2.51.0 (lv:go/1.25; os:linux)"
// or "ClickHouse client" into a short name.
func chApp(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.Index(name, " ("); i > 0 {
		name = name[:i]
	}
	if f := strings.Fields(name); len(f) > 0 && strings.Contains(f[0], "/") {
		return strings.SplitN(f[0], "/", 2)[0]
	}
	return name
}

// replication reads the replicated tables. ClickHouse has no primary or
// replica: every server holding a Replicated* table is one replica of it,
// coordinated through (Zoo)Keeper. The server stays standalone; Source is
// this server's own copying (the worst lag of its tables), Replicas the other
// members of its tables.
func (c *clickhouseEngine) replication(ctx context.Context, s *DatabaseSnapshot, readonlyReplicas int64) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT database, table, zookeeper_name, is_readonly, is_session_expired,
		       absolute_delay, queue_size, total_replicas, active_replicas,
		       zookeeper_exception, last_queue_update_exception,
		       arrayStringConcat(arrayMap(x -> concat(x.1, '=', toString(x.2)), mapItems(replica_is_active)), ',')
		  FROM system.replicas`)
	if err != nil {
		if ClickHouseCode(err) == chAccessDenied {
			s.note("replication", chProblem("system.replicas", err))
		}
		return
	}
	defer rows.Close()
	var (
		tables, readonly, queue int64
		lag                     float64
		keeper, problem         string
	)
	members := map[string]bool{}
	for rows.Next() {
		var (
			db, table, zk, zkErr, qErr, active string
			ro, expired                        bool
			delay, qsize                       uint64
			total, act                         uint32
		)
		if rows.Scan(&db, &table, &zk, &ro, &expired, &delay, &qsize, &total, &act, &zkErr, &qErr, &active) != nil {
			continue
		}
		tables++
		keeper = zk
		queue += int64(qsize)
		if float64(delay) > lag {
			lag = float64(delay)
		}
		if ro || expired {
			readonly++
			if problem == "" {
				problem = db + "." + table + " is read only"
				if zkErr != "" {
					problem += ": " + zkErr
				}
			}
		} else if problem == "" && qErr != "" {
			problem = db + "." + table + ": " + qErr
		}
		for _, kv := range strings.Split(active, ",") {
			name, on, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			if prev, seen := members[name]; !seen || prev {
				members[name] = on == "1"
			}
		}
	}
	if readonlyReplicas > 0 || readonly > 0 {
		s.ReadOnly = true
	}
	if tables == 0 {
		return
	}
	s.Replication.Set = fmt.Sprintf("%s tables replicated through %s", groupDigits(tables), cmp(keeper, "Keeper"))
	s.Replication.Source = &DatabaseSource{
		Address:    cmp(keeper, "Keeper"),
		Running:    readonly == 0,
		LagSeconds: f64(lag),
		Error:      truncate(problem, 500),
	}
	names := make([]string, 0, len(members))
	for n := range members {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		state := "active"
		if !members[n] {
			state = "inactive"
		}
		s.Replication.Replicas = append(s.Replication.Replicas, DatabaseReplica{Name: n, State: state, Healthy: members[n]})
	}
	s.fact("Replication", "Replicated tables", groupDigits(tables))
	s.fact("Replication", "Waiting in the replication queue", groupDigits(queue))
	if readonly > 0 {
		s.fact("Replication", "Read-only replicated tables", groupDigits(readonly))
	}
}

// parts finds the partition with the most active parts: past
// parts_to_delay_insert inserts slow down, past parts_to_throw_insert they
// fail with "Too many parts".
func (c *clickhouseEngine) parts(ctx context.Context, s *DatabaseSnapshot) {
	var p DatabaseParts
	err := c.db.QueryRowContext(ctx, `
		SELECT database, table, partition, toInt64(count()) AS n
		  FROM system.parts
		 WHERE active
		 GROUP BY database, table, partition
		 ORDER BY n DESC LIMIT 1`).Scan(&p.Database, &p.Table, &p.Partition, &p.Count)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return
	case err != nil:
		s.note("parts", chProblem("system.parts", err))
		return
	}
	p.DelayAt, p.ThrowAt = c.delayAt, c.throwAt
	s.Parts = &p
}

// mutations reads the ALTER … UPDATE/DELETE still being applied. A failed one
// is retried for ever and holds back every later one on its table.
func (c *clickhouseEngine) mutations(ctx context.Context, s *DatabaseSnapshot) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT database, table, mutation_id, command, create_time, parts_to_do,
		       latest_fail_reason
		  FROM system.mutations
		 WHERE NOT is_done
		 ORDER BY create_time`)
	if err != nil {
		if ClickHouseCode(err) == chAccessDenied {
			s.note("mutations", chProblem("system.mutations", err))
		}
		return
	}
	defer rows.Close()
	m := DatabaseMutations{}
	for rows.Next() {
		var (
			db, table, id, cmd, reason string
			created                    time.Time
			todo                       int64
		)
		if rows.Scan(&db, &table, &id, &cmd, &created, &todo, &reason) != nil {
			continue
		}
		m.Running++
		if reason != "" {
			m.Failed++
		}
		if m.Table == "" || reason != "" && m.Error == "" {
			m.Table = db + "." + table
			m.ID = id
			m.Command = truncate(cmd, 300)
			m.Error = truncate(reason, 500)
			m.PartsToDo = todo
			m.Seconds = max(0, time.Since(created).Seconds())
		}
	}
	if m.Running > 0 {
		s.Mutations = &m
	}
}

// chSystem are the databases that aren't the user's data.
const chSystem = "('system', 'INFORMATION_SCHEMA', 'information_schema')"

func (c *clickhouseEngine) heavy(ctx context.Context, s *DatabaseSnapshot) error {
	// The list (which a login sees for what it may read), then sizes from
	// system.parts, which may be closed to it.
	rows, err := c.db.QueryContext(ctx, `
		SELECT name, engine FROM system.databases
		 WHERE name NOT IN ('INFORMATION_SCHEMA', 'information_schema')
		 ORDER BY name`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var d DatabaseInfo
		var engine string
		if err := rows.Scan(&d.Name, &engine); err != nil {
			rows.Close()
			return err
		}
		if engine != "Atomic" {
			d.State = engine
		}
		s.Databases = append(s.Databases, d)
	}
	rows.Close()
	if counts, err := c.pairs(ctx, `
		SELECT database, toFloat64(count()) FROM system.tables
		 WHERE NOT is_temporary GROUP BY database`); err == nil {
		for i := range s.Databases {
			s.Databases[i].Tables = i64(counts[s.Databases[i].Name])
		}
	}
	if sizes, err := c.pairs(ctx, `
		SELECT database, toFloat64(sum(bytes_on_disk)) FROM system.parts
		 WHERE active GROUP BY database`); err == nil {
		var total int64
		for i := range s.Databases {
			n := sizes[s.Databases[i].Name]
			s.Databases[i].SizeBytes = i64(n)
			total += n
			if s.Databases[i].Name == "system" {
				s.fact("Storage", "System logs (system database)", humanBytes(n))
			}
		}
		s.SizeBytes = &total
		sort.SliceStable(s.Databases, func(i, j int) bool {
			return deref(s.Databases[i].SizeBytes) > deref(s.Databases[j].SizeBytes)
		})
	}

	c.tables(ctx, s)
	c.disks(ctx, s)
	c.settings(ctx, s)
	c.users(ctx, s)
	c.topQueries(ctx, s)
	c.partLimits(ctx)

	var detached, broken int64
	if err := c.db.QueryRowContext(ctx, `
		SELECT toInt64(count()), toInt64(countIf(reason NOT IN ('', 'clone')))
		  FROM system.detached_parts`).Scan(&detached, &broken); err == nil {
		if detached > 0 {
			s.fact("Storage", "Detached parts", groupDigits(detached))
		}
		if broken > 0 {
			s.fact("Storage", "Detached as broken or unexpected", groupDigits(broken))
		}
	} else if ClickHouseCode(err) == chAccessDenied {
		s.note("parts", chProblem("system.detached_parts", err))
	}
	return nil
}

func (c *clickhouseEngine) tables(ctx context.Context, s *DatabaseSnapshot) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT p.database, p.table, any(t.engine),
		       toInt64(sum(p.bytes_on_disk)),
		       toInt64(sum(p.primary_key_size + p.marks_bytes + p.secondary_indices_compressed_bytes)),
		       toInt64(sum(p.rows)), toInt64(sum(p.data_compressed_bytes)),
		       toInt64(sum(p.data_uncompressed_bytes)), toInt64(count())
		  FROM system.parts p
		  LEFT JOIN system.tables t ON t.database = p.database AND t.name = p.table
		 WHERE p.active AND p.database NOT IN `+chSystem+`
		 GROUP BY p.database, p.table
		 ORDER BY 4 DESC LIMIT 20`)
	if err != nil {
		s.note("tables", chProblem("system.parts", err))
		return
	}
	defer rows.Close()
	var packed, raw int64
	for rows.Next() {
		var t DatabaseTable
		var idx, n, comp, uncomp, parts int64
		if rows.Scan(&t.Database, &t.Name, &t.Kind, &t.SizeBytes, &idx, &n, &comp, &uncomp, &parts) != nil {
			continue
		}
		t.IndexBytes, t.Rows = &idx, &n
		packed += comp
		raw += uncomp
		if len(s.Tables) < 3 && comp > 0 && uncomp > 0 {
			s.fact("Storage", "Compression of "+t.Database+"."+t.Name, fmt.Sprintf("%.1f×", float64(uncomp)/float64(comp)))
		}
		s.Tables = append(s.Tables, t)
	}
	if packed > 0 && raw > 0 {
		s.fact("Storage", "Compression (largest tables)", fmt.Sprintf("%.1f× (%s → %s)", float64(raw)/float64(packed), humanBytes(raw), humanBytes(packed)))
	}
}

func (c *clickhouseEngine) disks(ctx context.Context, s *DatabaseSnapshot) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT name, path, toInt64(free_space), toInt64(total_space), toString(type)
		  FROM system.disks ORDER BY name = 'default' DESC, name`)
	if err != nil {
		s.note("disk", chProblem("system.disks", err))
		return
	}
	defer rows.Close()
	for rows.Next() {
		var name, path, kind string
		var free, total int64
		if rows.Scan(&name, &path, &free, &total, &kind) != nil {
			continue
		}
		if s.Disk == nil && total > 0 && total < 1<<62 {
			s.Disk = &DatabaseDisk{Path: path, TotalBytes: total, FreeBytes: free, Source: "engine"}
			s.DataDir = path
			continue
		}
		if total > 0 && total < 1<<62 {
			s.fact("Disks", name, fmt.Sprintf("%s free of %s (%s)", humanBytes(free), humanBytes(total), kind))
		} else {
			s.fact("Disks", name, kind)
		}
	}
}

// chSettings are server settings worth watching even at their defaults.
var chSettings = []string{
	"max_connections", "max_concurrent_queries", "max_server_memory_usage",
	"max_server_memory_usage_to_ram_ratio", "max_table_size_to_drop",
	"max_partition_size_to_drop", "background_pool_size", "mark_cache_size",
	"uncompressed_cache_size", "default_database", "timezone",
}

func (c *clickhouseEngine) settings(ctx context.Context, s *DatabaseSnapshot) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT name, value FROM system.server_settings
		 WHERE changed OR name IN `+inList(chSettings)+`
		 ORDER BY name`)
	if err != nil {
		s.note("settings", chProblem("system.server_settings", err))
		return
	}
	for rows.Next() {
		var st DatabaseSetting
		if rows.Scan(&st.Name, &st.Value) == nil {
			s.Settings = append(s.Settings, st)
		}
	}
	rows.Close()
	rows, err = c.db.QueryContext(ctx, `
		SELECT name, value FROM system.merge_tree_settings
		 WHERE changed OR name IN ('parts_to_delay_insert', 'parts_to_throw_insert', 'max_parts_in_total')
		 ORDER BY name`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var st DatabaseSetting
		if rows.Scan(&st.Name, &st.Value) == nil {
			st.Name = "merge_tree." + st.Name
			s.Settings = append(s.Settings, st)
		}
	}
}

// chAdminGrants are the grants that make a login an admin: it can manage
// logins, or has everything.
const chAdminGrants = "('ALL', 'ACCESS MANAGEMENT', 'CREATE USER', 'ALTER USER', 'ROLE ADMIN')"

func (c *clickhouseEngine) users(ctx context.Context, s *DatabaseSnapshot) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT u.name,
		       has(u.auth_type, 'no_password') OR has(u.auth_type, 'no_authentication'),
		       u.name IN (SELECT user_name FROM system.grants
		                   WHERE user_name IS NOT NULL AND access_type IN `+chAdminGrants+` AND database IS NULL)
		       OR hasAny(u.default_roles_list, (SELECT groupArray(role_name) FROM system.grants
		                   WHERE role_name IS NOT NULL AND access_type IN `+chAdminGrants+` AND database IS NULL)),
		       length(u.host_ip) = 0 AND length(u.host_names) = 0 AND length(u.host_names_regexp) = 0
		         AND length(u.host_names_like) = 0
		  FROM system.users u
		 ORDER BY u.name`)
	if err != nil {
		msg := chProblem("system.users", err)
		if ClickHouseCode(err) == chAccessDenied {
			msg = "This login can't list logins. Grant it SHOW USERS and SELECT on system.grants to see them."
		}
		s.note("users", msg)
		return
	}
	defer rows.Close()
	var admins, nopass int32
	for rows.Next() {
		var u DatabaseUser
		var noHost bool
		if rows.Scan(&u.Name, &u.NoPassword, &u.Admin, &noHost) != nil {
			continue
		}
		// No host at all = can't sign in from anywhere.
		u.Disabled = noHost
		if u.Admin {
			admins++
		}
		if u.NoPassword && !u.Disabled {
			nopass++
			if u.Name == "default" {
				s.Security.Risks = append(s.Security.Risks, "The default user has no password: anyone who reaches the port signs in.")
			}
		}
		s.Users = append(s.Users, u)
	}
	s.Security.Admins = &admins
	s.Security.NoPassword = &nopass
}

func (c *clickhouseEngine) topQueries(ctx context.Context, s *DatabaseSnapshot) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT any(query), any(current_database), toInt64(count()),
		       toFloat64(sum(query_duration_ms)), avg(query_duration_ms),
		       toInt64(sum(if(query_kind = 'Insert', written_rows, result_rows)))
		  FROM system.query_log
		 WHERE event_date >= yesterday() AND event_time > now() - INTERVAL 1 DAY
		   AND type IN ('QueryFinish', 'ExceptionWhileProcessing')
		   AND is_initial_query
		   AND client_name NOT LIKE '`+clickhouseApp+`/%'
		 GROUP BY normalized_query_hash
		 ORDER BY 4 DESC LIMIT 25`)
	if err != nil {
		msg := chProblem("system.query_log", err)
		if ClickHouseCode(err) == 60 {
			msg = "The query log is off (query_log in the server config), so there are no totals per query."
		}
		s.note("queries", msg)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var q DatabaseQuery
		var n int64
		if rows.Scan(&q.Query, &q.Database, &q.Calls, &q.TotalMs, &q.MeanMs, &n) != nil {
			continue
		}
		q.Rows = &n
		q.Query = truncate(q.Query, queryLimit)
		s.Queries = append(s.Queries, q)
	}
	s.QueriesSource = "system.query_log"
}

// kill cancels a running query. ClickHouse has no way to close one
// connection, so connection=true cancels its query too.
func (c *clickhouseEngine) kill(ctx context.Context, id string, _ bool) error {
	if id == "" || len(id) > 64 || strings.ContainsAny(id, "'\\\n\r") {
		return errors.New("not a ClickHouse query id")
	}
	// Read whether it runs first: the driver can't take KILL's answer when
	// nothing matched (an empty result).
	var n uint64
	if err := c.db.QueryRowContext(ctx,
		"SELECT count() FROM system.processes WHERE query_id = '"+id+"'").Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return errors.New("that query isn't running any more")
	}
	_, err := c.db.ExecContext(ctx, "KILL QUERY WHERE query_id = '"+id+"' ASYNC")
	return err
}

var (
	chRead  = regexp.MustCompile(`ReadFromMergeTree \(([^)]+)\)`)
	chParts = regexp.MustCompile(`^\s*(MinMax|Partition|PrimaryKey|Skip)\b`)
	chCount = regexp.MustCompile(`^\s*(Parts|Granules): (\d+)/(\d+)`)
)

// explain shows EXPLAIN indexes = 1 (which parts and granules each index
// leaves to read) and sums EXPLAIN ESTIMATE for the rows. Neither runs the
// query; it's also sent with readonly = 2.
func (c *clickhouseEngine) explain(ctx context.Context, database, query string) (*DatabasePlan, error) {
	db, err := openClickHouseDB(c.cfg, database, clickhouseApp)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx = clickhouse.Context(ctx, clickhouse.WithSettings(clickhouse.Settings{"readonly": 2}))

	rows, err := db.QueryContext(ctx, "EXPLAIN indexes = 1 "+query)
	if err != nil {
		return nil, err
	}
	var lines []string
	for rows.Next() {
		var l string
		if err := rows.Scan(&l); err != nil {
			rows.Close()
			return nil, err
		}
		lines = append(lines, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	p := &DatabasePlan{Format: "text", Plan: strings.Join(lines, "\n"), Warnings: []string{}}

	// Per table read: did the primary key narrow it down?
	table, index := "", ""
	for _, l := range lines {
		if m := chRead.FindStringSubmatch(l); m != nil {
			table, index = m[1], ""
			continue
		}
		if m := chParts.FindStringSubmatch(l); m != nil {
			index = m[1]
			continue
		}
		if m := chCount.FindStringSubmatch(l); m != nil && index == "PrimaryKey" && m[1] == "Granules" {
			got, _ := strconv.ParseInt(m[2], 10, 64)
			all, _ := strconv.ParseInt(m[3], 10, 64)
			if all >= 8 && got == all {
				p.Warnings = append(p.Warnings, fmt.Sprintf(
					"Reads all %s granules of %s: the primary key (ORDER BY) doesn't narrow it down. Filter on its first columns, or add a skip index or projection.", groupDigits(all), table))
			}
		}
	}

	if rows, err := db.QueryContext(ctx, "EXPLAIN ESTIMATE "+query); err == nil {
		var total float64
		found := false
		cols, _ := rows.Columns()
		for rows.Next() && len(cols) >= 4 {
			vals := make([]any, len(cols))
			var n uint64
			for i := range vals {
				vals[i] = new(any)
			}
			vals[3] = &n
			if rows.Scan(vals...) == nil {
				total += float64(n)
				found = true
			}
		}
		rows.Close()
		if found {
			p.Rows = &total
		}
	}
	return p, nil
}
