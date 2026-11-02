package dbmon

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

type mysqlEngine struct {
	cfg     Config
	db      *sql.DB
	mariadb bool
	version string
}

func openMySQL(ctx context.Context, cfg Config) (engine, error) {
	mc := mysql.NewConfig()
	mc.User = cfg.Username
	mc.Passwd = cfg.Password
	mc.Net = "tcp"
	mc.Addr = cfg.addr()
	mc.DBName = cfg.Database
	mc.Timeout = cfg.timeout()
	mc.ReadTimeout = 3 * cfg.timeout()
	mc.WriteTimeout = cfg.timeout()
	mc.ParseTime = true
	mc.ConnectionAttributes = "program_name:morcheh-monitor"
	tc, err := cfg.tlsConfig()
	if err != nil {
		return nil, err
	}
	mc.TLS = tc
	dial := cfg.dialer()
	mc.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dial(ctx, network, addr)
	}
	conn, err := mysql.NewConnector(mc)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(conn)
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(5 * time.Minute)
	m := &mysqlEngine{cfg: cfg, db: db}
	var comment string
	if err := db.QueryRowContext(ctx, "SELECT @@version, @@version_comment").Scan(&m.version, &comment); err != nil {
		db.Close()
		return nil, err
	}
	m.mariadb = strings.Contains(strings.ToLower(m.version+comment), "mariadb")
	return m, nil
}

func (m *mysqlEngine) close() error { return m.db.Close() }

// pairs reads a two-column SHOW into a map.
func (m *mysqlEngine) pairs(ctx context.Context, query string) (map[string]string, error) {
	rows, err := m.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v sql.NullString
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[strings.ToLower(k.String)] = v.String
	}
	return out, rows.Err()
}

func num(m map[string]string, keys ...string) *int64 {
	var total int64
	found := false
	for _, k := range keys {
		if v, ok := m[strings.ToLower(k)]; ok {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				total += n
				found = true
			}
		}
	}
	if !found {
		return nil
	}
	return &total
}

var mysqlVars = []string{
	"version", "max_connections", "read_only", "super_read_only",
	"innodb_buffer_pool_size", "bind_address", "require_secure_transport",
	"have_ssl", "log_bin", "binlog_expire_logs_seconds", "expire_logs_days",
	"sync_binlog", "innodb_flush_log_at_trx_commit", "slow_query_log",
	"long_query_time", "max_allowed_packet", "wait_timeout", "local_infile",
	"sql_mode", "datadir", "gtid_mode", "skip_name_resolve",
	"performance_schema", "character_set_server", "server_id",
	"innodb_log_file_size", "innodb_redo_log_capacity", "table_open_cache",
	"thread_cache_size", "tmp_table_size",
}

func (m *mysqlEngine) light(ctx context.Context, s *DatabaseSnapshot) error {
	start := time.Now()
	if _, err := m.db.ExecContext(ctx, "SELECT 1"); err != nil {
		return err
	}
	s.LatencyMs = int32(time.Since(start).Milliseconds())
	s.Flavor = "MySQL"
	if m.mariadb {
		s.Flavor = "MariaDB"
	}
	s.Version = strings.SplitN(m.version, "-", 2)[0]

	vars, err := m.pairs(ctx, "SHOW GLOBAL VARIABLES WHERE Variable_name IN ('"+strings.Join(mysqlVars, "','")+"')")
	if err != nil {
		return err
	}
	st, err := m.pairs(ctx, "SHOW GLOBAL STATUS")
	if err != nil {
		return err
	}
	if n := num(vars, "max_connections"); n != nil {
		s.Connections.Max = i32(int32(*n))
	}
	s.ReadOnly = vars["read_only"] == "ON" || vars["super_read_only"] == "ON"
	if up := num(st, "Uptime"); up != nil {
		t := time.Now().Add(-time.Duration(*up) * time.Second).Truncate(time.Second)
		s.StartedAt = &t
	}
	if n := num(st, "Threads_connected"); n != nil {
		s.Connections.Total = int32(*n)
	}
	reqs := num(st, "Innodb_buffer_pool_read_requests")
	disk := num(st, "Innodb_buffer_pool_reads")
	var hits *int64
	if reqs != nil && disk != nil {
		hits = i64(*reqs - *disk)
	}
	s.counters = counters{
		queries:      num(st, "Questions"),
		transactions: num(st, "Com_commit", "Com_rollback"),
		reads:        num(st, "Innodb_rows_read"),
		writes:       num(st, "Innodb_rows_inserted", "Innodb_rows_updated", "Innodb_rows_deleted"),
		failedLogins: num(st, "Aborted_connects"),
		cacheHits:    hits,
		cacheReads:   reqs,
	}
	s.counters.deadlocks = num(st, "Innodb_deadlocks") // MariaDB
	if s.counters.deadlocks == nil {
		var n int64
		if err := m.db.QueryRowContext(ctx,
			"SELECT `COUNT` FROM information_schema.INNODB_METRICS WHERE NAME = 'lock_deadlocks'",
		).Scan(&n); err == nil {
			s.counters.deadlocks = &n
		}
	}
	s.Security.FailedLogins = num(st, "Aborted_connects")

	var cipher sql.NullString
	var name string
	if err := m.db.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Ssl_cipher'").Scan(&name, &cipher); err == nil {
		enc := cipher.String != ""
		s.Security.Encrypted = &enc
	}

	if pool := num(vars, "innodb_buffer_pool_size"); pool != nil {
		used := num(st, "Innodb_buffer_pool_bytes_data")
		if used == nil {
			if pages, size := num(st, "Innodb_buffer_pool_pages_data"), num(st, "Innodb_page_size"); pages != nil && size != nil {
				used = i64(*pages * *size)
			}
		}
		if used != nil {
			s.Memory = &DatabaseMemory{UsedBytes: *used, LimitBytes: *pool}
		}
	}
	if n := num(st, "Max_used_connections"); n != nil {
		s.fact("Connections", "Most at once since start", groupDigits(*n))
	}
	if n := num(st, "Connection_errors_max_connections"); n != nil && *n > 0 {
		s.fact("Connections", "Refused: too many connections", groupDigits(*n))
	}
	if n := num(st, "Slow_queries"); n != nil {
		s.fact("Work", "Slow queries since start", groupDigits(*n))
	}
	if n := num(st, "Created_tmp_disk_tables"); n != nil {
		s.fact("Work", "Temporary tables written to disk", groupDigits(*n))
	}

	if err := m.activity(ctx, s); err != nil {
		return err
	}
	m.replication(ctx, s)
	return nil
}

func (m *mysqlEngine) activity(ctx context.Context, s *DatabaseSnapshot) error {
	var own int64
	if err := m.db.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&own); err != nil {
		return err
	}
	// Open transactions: how long, and who waits for whom.
	type trx struct {
		started time.Time
		waiting bool
	}
	trxs := map[string]trx{}
	if rows, err := m.db.QueryContext(ctx,
		"SELECT trx_mysql_thread_id, trx_started, trx_state FROM information_schema.INNODB_TRX"); err == nil {
		for rows.Next() {
			var id string
			var t trx
			var state string
			if rows.Scan(&id, &t.started, &state) == nil {
				t.waiting = state == "LOCK WAIT"
				trxs[id] = t
			}
		}
		rows.Close()
	}
	blockers := map[string][]string{}
	if len(trxs) > 0 {
		q := "SELECT waiting_pid, blocking_pid FROM sys.innodb_lock_waits"
		if m.mariadb {
			q = `SELECT r.trx_mysql_thread_id, b.trx_mysql_thread_id
			       FROM information_schema.INNODB_LOCK_WAITS w
			       JOIN information_schema.INNODB_TRX r ON r.trx_id = w.requesting_trx_id
			       JOIN information_schema.INNODB_TRX b ON b.trx_id = w.blocking_trx_id`
		}
		if rows, err := m.db.QueryContext(ctx, q); err == nil {
			for rows.Next() {
				var w, b string
				if rows.Scan(&w, &b) == nil {
					blockers[w] = addUnique(blockers[w], b)
				}
			}
			rows.Close()
		}
	}

	rows, err := m.db.QueryContext(ctx, `
		SELECT ID, coalesce(USER, ''), coalesce(HOST, ''), coalesce(DB, ''),
		       coalesce(COMMAND, ''), coalesce(TIME, 0), coalesce(STATE, ''),
		       coalesce(INFO, '')
		  FROM information_schema.PROCESSLIST`)
	if err != nil {
		return err
	}
	defer rows.Close()
	others := 0
	for rows.Next() {
		var (
			a                          DatabaseActivity
			id                         int64
			host, command, state, user string
			secs                       float64
		)
		if err := rows.Scan(&id, &user, &host, &a.Database, &command, &secs, &state, &a.Query); err != nil {
			return err
		}
		a.ID = strconv.FormatInt(id, 10)
		a.User = user
		if user == "system user" || user == "event_scheduler" || command == "Daemon" ||
			strings.HasPrefix(command, "Binlog Dump") || command == "Connect" && user == "system user" {
			if strings.HasPrefix(command, "Binlog Dump") {
				s.Replication.Replicas = append(s.Replication.Replicas, DatabaseReplica{
					Name: user, Address: stripPort(host), State: state, Healthy: true,
				})
			}
			continue
		}
		a.Client = stripPort(host)
		if a.Client == "localhost" {
			a.Client = ""
		}
		a.Ours = id == own
		if !a.Ours {
			others++
		}
		t, inTx := trxs[a.ID]
		if inTx {
			a.TxSeconds = f64(time.Since(t.started).Seconds())
		}
		switch {
		case command == "Sleep" && inTx:
			a.State = "idle_in_tx"
			a.Query = ""
		case command == "Sleep":
			a.State = "idle"
			a.Query = ""
		default:
			a.State = "active"
			a.Seconds = f64(secs)
			if state != "" {
				a.Wait = state
			}
		}
		if inTx && t.waiting {
			a.Wait = "Lock wait"
		}
		a.BlockedBy = blockers[a.ID]
		a.Query = truncate(a.Query, queryLimit)
		s.all = append(s.all, a)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if others == 0 && s.Connections.Total > 1 {
		s.note("sessions", "This login sees only its own connections. Grant it PROCESS to see everyone's.")
	}
	return nil
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func (m *mysqlEngine) replication(ctx context.Context, s *DatabaseSnapshot) {
	row, err := m.oneRow(ctx, "SHOW REPLICA STATUS")
	if err != nil {
		row, err = m.oneRow(ctx, "SHOW SLAVE STATUS")
	}
	if err != nil {
		if !strings.Contains(err.Error(), "1227") {
			s.note("replication", "Couldn't read replication: "+err.Error())
		} else {
			s.note("replication", "Grant this login REPLICATION CLIENT (MariaDB: SLAVE MONITOR) to see replication.")
		}
	}
	get := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := row[strings.ToLower(k)]; ok {
				return v
			}
		}
		return ""
	}
	switch {
	case row != nil:
		s.Role = "replica"
		src := &DatabaseSource{
			Address: get("Source_Host", "Master_Host"),
			Running: get("Replica_IO_Running", "Slave_IO_Running") == "Yes" &&
				get("Replica_SQL_Running", "Slave_SQL_Running") == "Yes",
			Error: strings.TrimSpace(get("Last_IO_Error") + " " + get("Last_SQL_Error")),
		}
		if p := get("Source_Port", "Master_Port"); p != "" && p != "3306" {
			src.Address += ":" + p
		}
		if lag, err := strconv.ParseFloat(get("Seconds_Behind_Source", "Seconds_Behind_Master"), 64); err == nil {
			src.LagSeconds = &lag
		}
		s.Replication.Source = src
	case len(s.Replication.Replicas) > 0:
		s.Role = "primary"
	default:
		s.Role = "standalone"
	}
}

// oneRow reads the first row of a SHOW as column → value; nil when empty.
func (m *mysqlEngine) oneRow(ctx context.Context, query string) (map[string]string, error) {
	rows, err := m.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	if !rows.Next() {
		return nil, rows.Err()
	}
	vals := make([]sql.NullString, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(cols))
	for i, c := range cols {
		out[strings.ToLower(c)] = vals[i].String
	}
	return out, nil
}

const mysqlSystem = "('mysql','sys','performance_schema','information_schema')"

func (m *mysqlEngine) heavy(ctx context.Context, s *DatabaseSnapshot) error {
	rows, err := m.db.QueryContext(ctx, `
		SELECT s.SCHEMA_NAME, sum(t.DATA_LENGTH + t.INDEX_LENGTH), count(t.TABLE_NAME)
		  FROM information_schema.SCHEMATA s
		  LEFT JOIN information_schema.TABLES t ON t.TABLE_SCHEMA = s.SCHEMA_NAME
		 WHERE s.SCHEMA_NAME NOT IN ('performance_schema', 'information_schema')
		 GROUP BY s.SCHEMA_NAME
		 ORDER BY 2 DESC`)
	if err != nil {
		return err
	}
	var total int64
	for rows.Next() {
		var d DatabaseInfo
		var size sql.NullInt64
		var n int64
		if err := rows.Scan(&d.Name, &size, &n); err != nil {
			rows.Close()
			return err
		}
		d.SizeBytes = i64(size.Int64)
		d.Tables = &n
		total += size.Int64
		s.Databases = append(s.Databases, d)
	}
	rows.Close()
	s.SizeBytes = &total

	rows, err = m.db.QueryContext(ctx, `
		SELECT TABLE_SCHEMA, TABLE_NAME, coalesce(DATA_LENGTH, 0), coalesce(INDEX_LENGTH, 0),
		       TABLE_ROWS, DATA_FREE
		  FROM information_schema.TABLES
		 WHERE TABLE_TYPE = 'BASE TABLE' AND TABLE_SCHEMA NOT IN `+mysqlSystem+`
		 ORDER BY DATA_LENGTH + INDEX_LENGTH DESC LIMIT 20`)
	if err == nil {
		for rows.Next() {
			var t DatabaseTable
			var data, idx int64
			var tr, free sql.NullInt64
			if rows.Scan(&t.Database, &t.Name, &data, &idx, &tr, &free) == nil {
				t.SizeBytes = data + idx
				t.IndexBytes = &idx
				if tr.Valid {
					t.Rows = &tr.Int64
				}
				if free.Valid {
					t.FreeBytes = &free.Int64
				}
				s.Tables = append(s.Tables, t)
			}
		}
		rows.Close()
	}

	rows, err = m.db.QueryContext(ctx, `
		SELECT t.TABLE_SCHEMA, t.TABLE_NAME, c.COLUMN_NAME, c.COLUMN_TYPE, t.AUTO_INCREMENT
		  FROM information_schema.TABLES t
		  JOIN information_schema.COLUMNS c
		    ON c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME
		 WHERE c.EXTRA LIKE '%auto_increment%' AND t.AUTO_INCREMENT IS NOT NULL
		   AND t.TABLE_SCHEMA NOT IN `+mysqlSystem)
	if err == nil {
		for rows.Next() {
			var c DatabaseIDColumn
			var next float64
			if rows.Scan(&c.Database, &c.Table, &c.Column, &c.Type, &next) == nil {
				c.Max = intMax(c.Type)
				c.Current = next - 1
				if c.Max > 0 {
					c.Ratio = c.Current / c.Max
					s.IDColumns = append(s.IDColumns, c)
				}
			}
		}
		rows.Close()
	}

	if rows, err = m.db.QueryContext(ctx,
		"SELECT object_schema, object_name, index_name FROM sys.schema_unused_indexes LIMIT 15"); err == nil {
		for rows.Next() {
			var ix DatabaseIndex
			if rows.Scan(&ix.Database, &ix.Table, &ix.Name) == nil {
				s.Indexes = append(s.Indexes, ix)
			}
		}
		rows.Close()
	}

	m.topQueries(ctx, s)

	vars, err := m.pairs(ctx, "SHOW GLOBAL VARIABLES WHERE Variable_name IN ('"+strings.Join(mysqlVars, "','")+"')")
	if err == nil {
		for _, k := range mysqlVars {
			if v, ok := vars[k]; ok && k != "version" {
				s.Settings = append(s.Settings, DatabaseSetting{Name: k, Value: v})
			}
		}
		s.DataDir = vars["datadir"]
		s.Security.ListensOn = vars["bind_address"]
		if m.mariadb && s.Security.ListensOn == "" {
			s.Security.ListensOn = "*"
		}
		if vars["local_infile"] == "ON" {
			s.Security.Risks = append(s.Security.Risks, "local_infile is on: clients can make the server read files they choose.")
		}
		if vars["innodb_flush_log_at_trx_commit"] == "0" {
			s.Security.Risks = append(s.Security.Risks, "innodb_flush_log_at_trx_commit = 0: up to a second of commits can be lost in a crash.")
		}
	}

	users := `
		SELECT User, Host, Super_priv = 'Y', coalesce(account_locked = 'Y', false),
		       coalesce(authentication_string = '', false) AND coalesce(plugin, '') NOT IN ('auth_socket', 'unix_socket')
		  FROM mysql.user ORDER BY User, Host`
	if m.mariadb {
		// MariaDB keeps the lock in mysql.global_priv's JSON.
		users = `
		SELECT u.User, u.Host, u.Super_priv = 'Y',
		       coalesce(JSON_VALUE(g.Priv, '$.account_locked') = 'true', false),
		       coalesce(u.authentication_string = '', false) AND coalesce(u.plugin, '') NOT IN ('auth_socket', 'unix_socket')
		  FROM mysql.user u
		  LEFT JOIN mysql.global_priv g ON g.User = u.User AND g.Host = u.Host
		 WHERE u.is_role = 'N' ORDER BY u.User, u.Host`
	}
	rows, err = m.db.QueryContext(ctx, users)
	if err == nil {
		var admins, nopass int32
		for rows.Next() {
			var u DatabaseUser
			var user, host string
			if rows.Scan(&user, &host, &u.Admin, &u.Disabled, &u.NoPassword) == nil {
				if strings.HasPrefix(user, "mysql.") || user == "mariadb.sys" {
					continue
				}
				u.Name = user + "@" + host
				if u.Admin {
					admins++
				}
				if u.NoPassword && !u.Disabled {
					nopass++
				}
				s.Users = append(s.Users, u)
			}
		}
		rows.Close()
		s.Security.Admins = &admins
		s.Security.NoPassword = &nopass
	} else {
		s.note("users", "Couldn't list logins (needs SELECT on mysql.user).")
	}

	if rows, err = m.db.QueryContext(ctx, "SHOW BINARY LOGS"); err == nil {
		var size int64
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			var name string
			var n int64
			vals[0], vals[1] = &name, &n
			for i := 2; i < len(cols); i++ {
				vals[i] = new(sql.RawBytes)
			}
			if rows.Scan(vals...) == nil {
				size += n
			}
		}
		rows.Close()
		s.Log = &DatabaseLog{Kind: "Binary log", SizeBytes: &size}
	}
	return nil
}

func (m *mysqlEngine) topQueries(ctx context.Context, s *DatabaseSnapshot) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT coalesce(DIGEST_TEXT, ''), coalesce(SCHEMA_NAME, ''), COUNT_STAR,
		       SUM_TIMER_WAIT / 1000000000, AVG_TIMER_WAIT / 1000000000, SUM_ROWS_SENT
		  FROM performance_schema.events_statements_summary_by_digest
		 WHERE DIGEST_TEXT IS NOT NULL
		 ORDER BY SUM_TIMER_WAIT DESC LIMIT 25`)
	if err != nil {
		msg := "Turn on performance_schema to see which queries take the most time."
		if !strings.Contains(err.Error(), "performance_schema") && !strings.Contains(err.Error(), "1142") {
			msg = "Couldn't read query statistics: " + err.Error()
		}
		s.note("queries", msg)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var q DatabaseQuery
		var sent int64
		if err := rows.Scan(&q.Query, &q.Database, &q.Calls, &q.TotalMs, &q.MeanMs, &sent); err != nil {
			return
		}
		q.Rows = &sent
		q.Query = truncate(q.Query, queryLimit)
		s.Queries = append(s.Queries, q)
	}
	if len(s.Queries) == 0 {
		s.note("queries", "performance_schema has no statement statistics yet (it may be off: performance_schema = ON in the config, then restart).")
		return
	}
	s.QueriesSource = "performance_schema"
}

// intMax is the largest value an integer column type holds.
func intMax(colType string) float64 {
	t := strings.ToLower(colType)
	unsigned := strings.Contains(t, "unsigned")
	pick := func(signed, uns float64) float64 {
		if unsigned {
			return uns
		}
		return signed
	}
	switch {
	case strings.HasPrefix(t, "tinyint"):
		return pick(127, 255)
	case strings.HasPrefix(t, "smallint"):
		return pick(32767, 65535)
	case strings.HasPrefix(t, "mediumint"):
		return pick(8388607, 16777215)
	case strings.HasPrefix(t, "int"):
		return pick(2147483647, 4294967295)
	case strings.HasPrefix(t, "bigint"):
		return pick(9223372036854775807, 18446744073709551615)
	}
	return 0
}

func (m *mysqlEngine) kill(ctx context.Context, id string, connection bool) error {
	n, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return errors.New("not a MySQL thread id")
	}
	stmt := "KILL QUERY "
	if connection {
		stmt = "KILL CONNECTION "
	}
	_, err = m.db.ExecContext(ctx, stmt+strconv.FormatUint(n, 10))
	return err
}

var (
	myScan = regexp.MustCompile(`Table scan on (\S+).*rows=([\d.e+]+)`)
	myCost = regexp.MustCompile(`cost=([\d.e+]+) rows=([\d.e+]+)`)
)

func (m *mysqlEngine) explain(ctx context.Context, database, query string) (*DatabasePlan, error) {
	conn, err := m.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	// The connection's default database changes: don't hand it back.
	defer func() {
		conn.ExecContext(context.Background(), "ROLLBACK")
		conn.Raw(func(any) error { return driver.ErrBadConn })
		conn.Close()
	}()
	if database != "" {
		if _, err := conn.ExecContext(ctx, "USE `"+strings.ReplaceAll(database, "`", "``")+"`"); err != nil {
			return nil, err
		}
	}
	if _, err := conn.ExecContext(ctx, "START TRANSACTION READ ONLY"); err != nil {
		return nil, err
	}

	if !m.mariadb {
		var plan string
		err := conn.QueryRowContext(ctx, "EXPLAIN FORMAT=TREE "+query).Scan(&plan)
		if err == nil {
			p := &DatabasePlan{Format: "text", Plan: plan, Warnings: []string{}}
			if mm := myCost.FindStringSubmatch(plan); mm != nil {
				c, _ := strconv.ParseFloat(mm[1], 64)
				r, _ := strconv.ParseFloat(mm[2], 64)
				p.Cost, p.Rows = &c, &r
			}
			for _, mm := range myScan.FindAllStringSubmatch(plan, -1) {
				if r, _ := strconv.ParseFloat(mm[2], 64); r >= 10000 {
					p.Warnings = append(p.Warnings, fmt.Sprintf(
						"Reads all of %s (about %s rows). An index on the filtered columns may help.", mm[1], groupDigits(int64(r))))
				}
			}
			return p, nil
		}
		if !strings.Contains(err.Error(), "1064") && !strings.Contains(err.Error(), "FORMAT") {
			return nil, err
		}
	}
	var plan string
	if err := conn.QueryRowContext(ctx, "EXPLAIN FORMAT=JSON "+query).Scan(&plan); err != nil {
		return nil, err
	}
	p := &DatabasePlan{Format: "json", Plan: plan, Warnings: []string{}}
	var tree any
	if json.Unmarshal([]byte(plan), &tree) == nil {
		if pretty, err := json.MarshalIndent(tree, "", "  "); err == nil {
			p.Plan = string(pretty)
		}
		// MariaDB 11 puts the total under query_block.cost.
		if root, ok := tree.(map[string]any); ok {
			if qb, ok := root["query_block"].(map[string]any); ok {
				if c, ok := qb["cost"].(float64); ok {
					p.Cost = &c
				}
			}
		}
		walkJSON(tree, func(o map[string]any) {
			if o["access_type"] == "ALL" {
				name, _ := o["table_name"].(string)
				rows, _ := o["rows"].(float64)
				if rows >= 10000 {
					p.Warnings = append(p.Warnings, fmt.Sprintf(
						"Reads all of %s (about %s rows). An index on the filtered columns may help.", name, groupDigits(int64(rows))))
				}
			}
		})
	}
	return p, nil
}

func walkJSON(v any, fn func(map[string]any)) {
	switch t := v.(type) {
	case map[string]any:
		fn(t)
		for _, c := range t {
			walkJSON(c, fn)
		}
	case []any:
		for _, c := range t {
			walkJSON(c, fn)
		}
	}
}

func engineAuthErrorMySQL(err error) bool {
	var me *mysql.MySQLError
	return errors.As(err, &me) && (me.Number == 1045 || me.Number == 1044 || me.Number == 1698)
}
