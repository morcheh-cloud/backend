package dbmon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type postgres struct {
	cfg  Config
	pool *pgxpool.Pool
	conn *pgx.ConnConfig
	// pg_stat_statements is installed in the database we connect to.
	pgss    bool
	version int // server_version_num
}

func openPostgres(ctx context.Context, cfg Config) (engine, error) {
	pc, err := pgxpool.ParseConfig("")
	if err != nil {
		return nil, err
	}
	cc := pc.ConnConfig
	cc.Host = cfg.Host
	cc.Port = uint16(cfg.Port)
	cc.User = cfg.Username
	cc.Password = cfg.Password
	cc.Database = cmp(cfg.Database, "postgres")
	cc.ConnectTimeout = cfg.timeout()
	cc.Fallbacks = nil
	cc.RuntimeParams = map[string]string{
		"application_name":  "morcheh-monitor",
		"statement_timeout": strconv.Itoa(int(cfg.timeout().Milliseconds())),
		"lock_timeout":      "2000",
	}
	if cc.TLSConfig, err = cfg.tlsConfig(); err != nil {
		return nil, err
	}
	dial := cfg.dialer()
	cc.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dial(ctx, network, addr)
	}
	if cfg.Tunneled {
		// The server at the other end resolves the name.
		cc.LookupFunc = func(_ context.Context, host string) ([]string, error) {
			return []string{host}, nil
		}
	}
	pc.MaxConns = 2
	pc.MinConns = 0
	pc.MaxConnIdleTime = 5 * time.Minute
	pc.HealthCheckPeriod = time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, err
	}
	p := &postgres{cfg: cfg, pool: pool, conn: cc}
	if err := pool.QueryRow(ctx,
		`SELECT current_setting('server_version_num')::int,
		        EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements')`,
	).Scan(&p.version, &p.pgss); err != nil {
		pool.Close()
		return nil, err
	}
	return p, nil
}

func (p *postgres) close() error {
	p.pool.Close()
	return nil
}

func cmp(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func (p *postgres) light(ctx context.Context, s *DatabaseSnapshot) error {
	start := time.Now()
	if _, err := p.pool.Exec(ctx, "SELECT 1"); err != nil {
		return err
	}
	s.LatencyMs = int32(time.Since(start).Milliseconds())
	s.Flavor = "PostgreSQL"

	var (
		version, readOnly string
		started           time.Time
		recovery          bool
		maxConn, reserved int32
		ssl               *bool
	)
	if err := p.pool.QueryRow(ctx, `
		SELECT current_setting('server_version'), pg_postmaster_start_time(),
		       pg_is_in_recovery(), current_setting('max_connections')::int,
		       current_setting('superuser_reserved_connections')::int,
		       current_setting('default_transaction_read_only'),
		       (SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid())`,
	).Scan(&version, &started, &recovery, &maxConn, &reserved, &readOnly, &ssl); err != nil {
		return err
	}
	s.Version = strings.Fields(version)[0]
	s.StartedAt = &started
	s.Connections.Max = &maxConn
	s.Connections.Reserved = reserved
	s.ReadOnly = recovery || readOnly == "on"
	s.Security.Encrypted = ssl

	// Cumulative counters, for rates and the cache hit ratio.
	var tx, hits, reads, rows, writes, deadlocks *int64
	if err := p.pool.QueryRow(ctx, `
		SELECT sum(xact_commit + xact_rollback)::bigint, sum(blks_hit)::bigint,
		       sum(blks_hit + blks_read)::bigint,
		       sum(tup_returned + tup_fetched)::bigint,
		       sum(tup_inserted + tup_updated + tup_deleted)::bigint,
		       sum(deadlocks)::bigint
		  FROM pg_stat_database`,
	).Scan(&tx, &hits, &reads, &rows, &writes, &deadlocks); err != nil {
		return err
	}
	s.counters = counters{transactions: tx, cacheHits: hits, cacheReads: reads,
		reads: rows, writes: writes, deadlocks: deadlocks}
	if p.pgss {
		var calls *int64
		if err := p.pool.QueryRow(ctx, `SELECT sum(calls)::bigint FROM pg_stat_statements`).Scan(&calls); err == nil {
			s.counters.queries = calls
		}
	}

	if err := p.activity(ctx, s); err != nil {
		return err
	}
	p.replication(ctx, s, recovery)
	return nil
}

func (p *postgres) activity(ctx context.Context, s *DatabaseSnapshot) error {
	rows, err := p.pool.Query(ctx, `
		SELECT a.pid::text, coalesce(a.usename, ''), coalesce(a.datname, ''),
		       coalesce(host(a.client_addr), ''), coalesce(a.application_name, ''),
		       coalesce(a.state, ''), coalesce(a.query, ''),
		       CASE WHEN a.state = 'active' THEN extract(epoch FROM now() - a.query_start)::float8 END,
		       extract(epoch FROM now() - a.xact_start)::float8,
		       coalesce(a.wait_event_type || ':' || a.wait_event, ''),
		       pg_blocking_pids(a.pid)::text[], a.pid = pg_backend_pid(),
		       s.ssl
		  FROM pg_stat_activity a
		  LEFT JOIN pg_stat_ssl s ON s.pid = a.pid
		 WHERE a.backend_type = 'client backend'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	hidden := false
	var plain int32
	for rows.Next() {
		var (
			a     DatabaseActivity
			state string
			ssl   *bool
		)
		if err := rows.Scan(&a.ID, &a.User, &a.Database, &a.Client, &a.App, &state,
			&a.Query, &a.Seconds, &a.TxSeconds, &a.Wait, &a.BlockedBy, &a.Ours, &ssl); err != nil {
			return err
		}
		switch {
		case strings.HasPrefix(state, "idle in transaction"):
			a.State = "idle_in_tx"
		case state == "idle" || state == "":
			a.State = "idle"
		default:
			a.State = "active"
		}
		if a.State == "idle" {
			// The last statement of an idle connection isn't what it runs.
			a.Query = ""
		}
		if a.Query == "<insufficient privilege>" {
			a.Query = ""
			hidden = true
		}
		a.Query = truncate(a.Query, queryLimit)
		if a.Wait == "Client:ClientRead" && a.State != "active" {
			a.Wait = ""
		}
		if a.Client != "" && ssl != nil && !*ssl && !a.Ours {
			plain++
		}
		s.all = append(s.all, a)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.Security.PlainClients = &plain
	if hidden {
		s.note("sessions", "This login sees only its own queries. Grant it pg_read_all_stats (or pg_monitor) to see everyone's.")
	}
	return nil
}

func (p *postgres) replication(ctx context.Context, s *DatabaseSnapshot, recovery bool) {
	if recovery {
		s.Role = "replica"
		src := &DatabaseSource{}
		var (
			status, host *string
			lag          *float64
		)
		err := p.pool.QueryRow(ctx, `
			SELECT (SELECT status FROM pg_stat_wal_receiver),
			       (SELECT sender_host FROM pg_stat_wal_receiver),
			       CASE WHEN pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn() THEN 0
			            ELSE extract(epoch FROM now() - pg_last_xact_replay_timestamp())::float8 END`,
		).Scan(&status, &host, &lag)
		if err != nil {
			s.note("replication", "Couldn't read the replica's state: "+err.Error())
			return
		}
		if host != nil {
			src.Address = *host
		}
		src.Running = status != nil && *status == "streaming"
		if status == nil {
			src.Error = "Not receiving WAL from a primary"
		}
		src.LagSeconds = lag
		s.Replication.Source = src
		return
	}

	rows, err := p.pool.Query(ctx, `
		SELECT coalesce(application_name, ''), coalesce(host(client_addr), ''),
		       coalesce(state, ''), coalesce(sync_state, ''),
		       extract(epoch FROM replay_lag)::float8,
		       pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn)::bigint
		  FROM pg_stat_replication`)
	if err != nil {
		s.note("replication", "Couldn't read replicas: "+err.Error())
	} else {
		for rows.Next() {
			var r DatabaseReplica
			if err := rows.Scan(&r.Name, &r.Address, &r.State, &r.Sync, &r.LagSeconds, &r.LagBytes); err != nil {
				break
			}
			r.Healthy = r.State == "streaming"
			s.Replication.Replicas = append(s.Replication.Replicas, r)
		}
		rows.Close()
	}
	s.Role = "standalone"
	if len(s.Replication.Replicas) > 0 {
		s.Role = "primary"
	}

	rows, err = p.pool.Query(ctx, `
		SELECT slot_name, active,
		       pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)::bigint
		  FROM pg_replication_slots`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var sl DatabaseSlot
		if err := rows.Scan(&sl.Name, &sl.Active, &sl.RetainedBytes); err != nil {
			return
		}
		s.Replication.Slots = append(s.Replication.Slots, sl)
	}
}

var pgSettings = []string{
	"max_connections", "shared_buffers", "effective_cache_size", "work_mem",
	"maintenance_work_mem", "max_wal_size", "wal_level", "synchronous_commit",
	"autovacuum", "log_min_duration_statement", "statement_timeout",
	"idle_in_transaction_session_timeout", "shared_preload_libraries",
	"ssl", "listen_addresses", "password_encryption", "data_directory",
	"max_replication_slots", "archive_mode", "fsync", "full_page_writes",
}

func (p *postgres) heavy(ctx context.Context, s *DatabaseSnapshot) error {
	// Databases and their sizes.
	rows, err := p.pool.Query(ctx, `
		SELECT datname,
		       CASE WHEN has_database_privilege(datname, 'CONNECT')
		            THEN pg_database_size(datname) END
		  FROM pg_database
		 WHERE datallowconn AND NOT datistemplate
		 ORDER BY 2 DESC NULLS LAST`)
	if err != nil {
		return err
	}
	var total int64
	for rows.Next() {
		var d DatabaseInfo
		if err := rows.Scan(&d.Name, &d.SizeBytes); err != nil {
			rows.Close()
			return err
		}
		if d.SizeBytes != nil {
			total += *d.SizeBytes
		}
		s.Databases = append(s.Databases, d)
	}
	rows.Close()
	s.SizeBytes = &total

	// Settings worth watching.
	rows, err = p.pool.Query(ctx,
		`SELECT name, current_setting(name) FROM pg_settings WHERE name = ANY($1) ORDER BY name`,
		pgSettings)
	if err == nil {
		for rows.Next() {
			var st DatabaseSetting
			if rows.Scan(&st.Name, &st.Value) == nil {
				s.Settings = append(s.Settings, st)
				switch st.Name {
				case "listen_addresses":
					s.Security.ListensOn = st.Value
				case "data_directory":
					s.DataDir = st.Value
				case "password_encryption":
					if st.Value == "md5" {
						s.Security.Risks = append(s.Security.Risks, "Passwords are stored as MD5 (password_encryption = md5); scram-sha-256 is safer.")
					}
				case "fsync":
					if st.Value == "off" {
						s.Security.Risks = append(s.Security.Risks, "fsync is off: a power cut can corrupt the database.")
					}
				}
			}
		}
		rows.Close()
	}

	// Logins.
	rows, err = p.pool.Query(ctx, `
		SELECT rolname, rolsuper, coalesce(rolvaliduntil < now(), false)
		  FROM pg_roles WHERE rolcanlogin ORDER BY rolname`)
	if err == nil {
		var admins int32
		for rows.Next() {
			var u DatabaseUser
			if rows.Scan(&u.Name, &u.Admin, &u.Disabled) == nil {
				if u.Admin {
					admins++
				}
				s.Users = append(s.Users, u)
			}
		}
		rows.Close()
		s.Security.Admins = &admins
	}

	// WAL on disk (pg_monitor or superuser).
	var wal *int64
	if err := p.pool.QueryRow(ctx, `SELECT sum(size)::bigint FROM pg_ls_waldir()`).Scan(&wal); err == nil {
		s.Log = &DatabaseLog{Kind: "WAL", SizeBytes: wal}
	} else {
		s.Log = &DatabaseLog{Kind: "WAL"}
	}

	p.topQueries(ctx, s)

	var temp *int64
	if err := p.pool.QueryRow(ctx, `SELECT sum(temp_bytes)::bigint FROM pg_stat_database`).Scan(&temp); err == nil && temp != nil {
		s.fact("Work", "Temp files written (since stats reset)", humanBytes(*temp))
	}

	// Tables, ID columns and unused indexes live in each database: read the
	// biggest few, one short connection at a time.
	read := 0
	for _, d := range s.Databases {
		if read == 5 {
			break
		}
		if d.SizeBytes == nil {
			continue
		}
		read++
		if err := p.perDatabase(ctx, d.Name, s); err != nil {
			s.note("tables", fmt.Sprintf("Couldn't read tables in %s: %v", d.Name, err))
		}
	}
	if len(s.Databases) > 5 {
		s.TablesScope = "the 5 largest databases"
	}
	sortTables(s)
	return nil
}

func (p *postgres) topQueries(ctx context.Context, s *DatabaseSnapshot) {
	if !p.pgss {
		s.note("queries", "Install pg_stat_statements to see which queries take the most time: add it to shared_preload_libraries, restart, then CREATE EXTENSION pg_stat_statements.")
		return
	}
	cols := "total_exec_time, mean_exec_time"
	if p.version < 130000 {
		cols = "total_time, mean_time"
	}
	rows, err := p.pool.Query(ctx, `
		SELECT s.query, coalesce(d.datname, ''), s.calls, s.`+strings.ReplaceAll(cols, ", ", ", s.")+`, s.rows
		  FROM pg_stat_statements s LEFT JOIN pg_database d ON d.oid = s.dbid
		 ORDER BY 4 DESC LIMIT 25`)
	if err != nil {
		s.note("queries", "Couldn't read pg_stat_statements: "+err.Error())
		return
	}
	defer rows.Close()
	for rows.Next() {
		var q DatabaseQuery
		var n int64
		if err := rows.Scan(&q.Query, &q.Database, &q.Calls, &q.TotalMs, &q.MeanMs, &n); err != nil {
			return
		}
		q.Rows = &n
		q.Query = truncate(q.Query, queryLimit)
		if q.Query == "<insufficient privilege>" {
			q.Query = ""
		}
		s.Queries = append(s.Queries, q)
	}
	s.QueriesSource = "pg_stat_statements"
}

func (p *postgres) perDatabase(ctx context.Context, name string, s *DatabaseSnapshot) error {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.timeout())
	defer cancel()
	cc := p.conn.Copy()
	cc.Database = name
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())

	rows, err := conn.Query(ctx, `
		SELECT n.nspname, c.relname, pg_total_relation_size(c.oid),
		       pg_indexes_size(c.oid), greatest(c.reltuples, 0)::bigint,
		       st.n_dead_tup, greatest(st.last_vacuum, st.last_autovacuum)
		  FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		  LEFT JOIN pg_stat_user_tables st ON st.relid = c.oid
		 WHERE c.relkind IN ('r', 'm')
		   AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		   AND n.nspname NOT LIKE 'pg_toast%'
		 ORDER BY 3 DESC LIMIT 15`)
	if err != nil {
		return err
	}
	for rows.Next() {
		t := DatabaseTable{Database: name}
		var idx int64
		var rowsN int64
		if err := rows.Scan(&t.Schema, &t.Name, &t.SizeBytes, &idx, &rowsN, &t.DeadRows, &t.LastVacuum); err != nil {
			rows.Close()
			return err
		}
		t.IndexBytes = &idx
		t.Rows = &rowsN
		s.Tables = append(s.Tables, t)
	}
	rows.Close()

	// Sequences behind serial/identity columns, against the column's type.
	rows, err = conn.Query(ctx, `
		SELECT t.relname, a.attname, format_type(a.atttypid, a.atttypmod),
		       seq.last_value::float8,
		       least(seq.max_value::float8, CASE a.atttypid
		             WHEN 'int2'::regtype THEN 32767
		             WHEN 'int4'::regtype THEN 2147483647
		             ELSE 9223372036854775807 END::float8)
		  FROM pg_depend d
		  JOIN pg_class sc ON sc.oid = d.objid AND sc.relkind = 'S'
		  JOIN pg_class t ON t.oid = d.refobjid
		  JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = d.refobjsubid
		  JOIN pg_sequences seq ON seq.schemaname = sc.relnamespace::regnamespace::text
		                       AND seq.sequencename = sc.relname
		 WHERE d.classid = 'pg_class'::regclass
		   AND d.refclassid = 'pg_class'::regclass
		   AND d.deptype IN ('a', 'i')
		   AND seq.last_value IS NOT NULL`)
	if err == nil {
		for rows.Next() {
			c := DatabaseIDColumn{Database: name}
			if rows.Scan(&c.Table, &c.Column, &c.Type, &c.Current, &c.Max) == nil && c.Max > 0 {
				c.Ratio = c.Current / c.Max
				s.IDColumns = append(s.IDColumns, c)
			}
		}
		rows.Close()
	}

	rows, err = conn.Query(ctx, `
		SELECT i.relname, i.indexrelname, pg_relation_size(i.indexrelid)
		  FROM pg_stat_user_indexes i
		  JOIN pg_index x ON x.indexrelid = i.indexrelid
		 WHERE i.idx_scan = 0 AND NOT x.indisunique AND NOT x.indisprimary
		 ORDER BY 3 DESC LIMIT 10`)
	if err == nil {
		for rows.Next() {
			ix := DatabaseIndex{Database: name}
			var size int64
			if rows.Scan(&ix.Table, &ix.Name, &size) == nil {
				ix.SizeBytes = &size
				s.Indexes = append(s.Indexes, ix)
			}
		}
		rows.Close()
	}
	return nil
}

func (p *postgres) kill(ctx context.Context, id string, connection bool) error {
	pid, err := strconv.Atoi(id)
	if err != nil {
		return errors.New("not a PostgreSQL process id")
	}
	fn := "pg_cancel_backend"
	if connection {
		fn = "pg_terminate_backend"
	}
	var ok bool
	if err := p.pool.QueryRow(ctx, "SELECT "+fn+"($1)", pid).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return errors.New("no such session (it may have ended)")
	}
	return nil
}

var (
	pgParam = regexp.MustCompile(`\$\d+`)
	pgCost  = regexp.MustCompile(`cost=[\d.]+\.\.([\d.]+) rows=(\d+)`)
	pgScan  = regexp.MustCompile(`Seq Scan on (\S+).*rows=(\d+)`)
)

func (p *postgres) explain(ctx context.Context, database, query string) (*DatabasePlan, error) {
	opts := "FORMAT TEXT"
	generic := pgParam.MatchString(query)
	if generic {
		if p.version < 160000 {
			return nil, errors.New("this query has $1-style parameters: put real values in their place (PostgreSQL 16+ can plan it as is)")
		}
		query = strings.TrimSuffix(strings.TrimSpace(query), ";")
		if strings.Contains(query, ";") {
			return nil, errors.New("explain one statement at a time")
		}
		opts += ", GENERIC_PLAN"
	}
	run := func(q interface {
		Begin(context.Context) (pgx.Tx, error)
	}) (*DatabasePlan, error) {
		// A read-only transaction that is always rolled back: EXPLAIN without
		// ANALYZE never runs the statement, and this makes sure of it.
		tx, err := q.Begin(ctx)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(ctx, "SET TRANSACTION READ ONLY"); err != nil {
			return nil, err
		}
		var lines []string
		if generic {
			// pgx counts $1 as an argument it wasn't given, so this goes as a
			// simple query (one statement only, checked above).
			res, err := tx.Conn().PgConn().Exec(ctx, "EXPLAIN ("+opts+") "+query).ReadAll()
			if err != nil {
				return nil, err
			}
			for _, r := range res[0].Rows {
				lines = append(lines, string(r[0]))
			}
			return pgPlan(lines), nil
		}
		rows, err := tx.Query(ctx, "EXPLAIN ("+opts+") "+query)
		if err != nil {
			return nil, err
		}
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
		return pgPlan(lines), nil
	}
	if database == "" || database == p.conn.Database {
		return run(p.pool)
	}
	cc := p.conn.Copy()
	cc.Database = database
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.Background())
	return run(conn)
}

func pgPlan(lines []string) *DatabasePlan {
	plan := &DatabasePlan{Format: "text", Plan: strings.Join(lines, "\n"), Warnings: []string{}}
	if len(lines) > 0 {
		if m := pgCost.FindStringSubmatch(lines[0]); m != nil {
			c, _ := strconv.ParseFloat(m[1], 64)
			r, _ := strconv.ParseFloat(m[2], 64)
			plan.Cost, plan.Rows = &c, &r
		}
	}
	for _, l := range lines {
		if m := pgScan.FindStringSubmatch(l); m != nil {
			if n, _ := strconv.Atoi(m[2]); n >= 10000 {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf(
					"Reads all of %s (about %s rows). An index on the filtered columns may help.", m[1], groupDigits(int64(n))))
			}
		}
	}
	return plan
}

func engineAuthErrorPostgres(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && (pg.Code == "28P01" || pg.Code == "28000")
}
