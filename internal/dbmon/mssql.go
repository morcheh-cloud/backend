package dbmon

import (
	"context"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"
)

type mssqlEngine struct {
	cfg Config
	db  *sql.DB
}

// hostDialer makes the driver hand the host name to our dialer instead of
// resolving it here: over SSH the other end resolves it, and the direct
// dialer checks the address it resolves.
type hostDialer struct {
	dial Dialer
	host string
}

func (d hostDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dial(ctx, network, addr)
}
func (d hostDialer) HostName() string { return d.host }

func openMSSQL(ctx context.Context, cfg Config) (engine, error) {
	q := url.Values{}
	q.Set("database", cmp(cfg.Database, "master"))
	q.Set("app name", "morcheh-monitor")
	q.Set("dial timeout", strconv.Itoa(int(cfg.timeout().Seconds())))
	switch cfg.TLS {
	case TLSDisable:
		q.Set("encrypt", "disable")
	case TLSRequire:
		q.Set("encrypt", "true")
		q.Set("TrustServerCertificate", "true")
	default:
		q.Set("encrypt", "true")
		q.Set("TrustServerCertificate", "false")
	}
	u := url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(cfg.Username, cfg.Password),
		Host:     cfg.addr(),
		RawQuery: q.Encode(),
	}
	p, err := msdsn.Parse(u.String())
	if err != nil {
		return nil, err
	}
	if cfg.TLS == TLSVerify && strings.TrimSpace(cfg.CACert) != "" && p.TLSConfig != nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACert)) {
			return nil, errors.New("the CA certificate isn't valid PEM")
		}
		p.TLSConfig.RootCAs = pool
	}
	conn := mssql.NewConnectorConfig(p)
	conn.Dialer = hostDialer{dial: cfg.dialer(), host: cfg.Host}
	db := sql.OpenDB(conn)
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(5 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return &mssqlEngine{cfg: cfg, db: db}, nil
}

func (m *mssqlEngine) close() error { return m.db.Close() }

func (m *mssqlEngine) light(ctx context.Context, s *DatabaseSnapshot) error {
	start := time.Now()
	if _, err := m.db.ExecContext(ctx, "SELECT 1"); err != nil {
		return err
	}
	s.LatencyMs = int32(time.Since(start).Milliseconds())
	s.Flavor = "SQL Server"

	var (
		version, edition string
		encrypt          sql.NullString
		hadr             sql.NullInt32
		userConns        sql.NullInt64
	)
	if err := m.db.QueryRowContext(ctx, `
		SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)),
		       CAST(SERVERPROPERTY('Edition') AS nvarchar(128)),
		       (SELECT encrypt_option FROM sys.dm_exec_connections WHERE session_id = @@SPID),
		       CAST(SERVERPROPERTY('IsHadrEnabled') AS int),
		       (SELECT CAST(value_in_use AS bigint) FROM sys.configurations WHERE name = 'user connections')`,
	).Scan(&version, &edition, &encrypt, &hadr, &userConns); err != nil {
		return err
	}
	s.Version = version
	s.Edition = edition
	if encrypt.Valid {
		enc := strings.EqualFold(encrypt.String, "TRUE")
		s.Security.Encrypted = &enc
	}
	// 0 = the default, 32,767.
	limit := int32(32767)
	if userConns.Valid && userConns.Int64 > 0 {
		limit = int32(userConns.Int64)
	}
	s.Connections.Max = &limit

	var started time.Time
	if err := m.db.QueryRowContext(ctx, "SELECT sqlserver_start_time FROM sys.dm_os_sys_info").Scan(&started); err == nil {
		s.StartedAt = &started
	} else {
		s.note("server", "Grant this login VIEW SERVER STATE (2022: VIEW SERVER PERFORMANCE STATE) to see uptime, sessions and counters.")
	}

	m.counters(ctx, s)
	m.memory(ctx, s)
	if err := m.activity(ctx, s); err != nil {
		return err
	}
	s.Role = "standalone"
	if hadr.Valid && hadr.Int32 == 1 {
		m.availability(ctx, s)
	}
	return nil
}

func (m *mssqlEngine) counters(ctx context.Context, s *DatabaseSnapshot) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT RTRIM(counter_name), RTRIM(instance_name), cntr_value
		  FROM sys.dm_os_performance_counters
		 WHERE counter_name IN ('Batch Requests/sec', 'Transactions/sec',
		       'Number of Deadlocks/sec', 'Buffer cache hit ratio',
		       'Buffer cache hit ratio base', 'Page life expectancy',
		       'Processes blocked', 'Logins/sec', 'User Connections')`)
	if err != nil {
		return
	}
	defer rows.Close()
	vals := map[string]int64{}
	for rows.Next() {
		var name, inst string
		var v int64
		if rows.Scan(&name, &inst, &v) != nil {
			continue
		}
		if inst == "" || inst == "_Total" {
			if _, seen := vals[name]; !seen || inst == "_Total" {
				vals[name] = v
			}
		}
	}
	get := func(k string) *int64 {
		if v, ok := vals[k]; ok {
			return &v
		}
		return nil
	}
	s.counters = counters{
		queries:      get("Batch Requests/sec"),
		transactions: get("Transactions/sec"),
		deadlocks:    get("Number of Deadlocks/sec"),
	}
	if h, b := get("Buffer cache hit ratio"), get("Buffer cache hit ratio base"); h != nil && b != nil && *b > 0 {
		s.CacheHit = clamp01(float64(*h) / float64(*b))
	}
	if v := get("Page life expectancy"); v != nil {
		s.fact("Memory", "Page life expectancy", groupDigits(*v)+" s")
	}
	if v := get("Processes blocked"); v != nil {
		s.Connections.Blocked = int32(*v)
	}
	if v := get("User Connections"); v != nil {
		s.Connections.Total = int32(*v)
	}
}

func (m *mssqlEngine) memory(ctx context.Context, s *DatabaseSnapshot) {
	var used, maxMB, total sql.NullInt64
	if err := m.db.QueryRowContext(ctx, `
		SELECT (SELECT physical_memory_in_use_kb * 1024 FROM sys.dm_os_process_memory),
		       (SELECT CAST(value_in_use AS bigint) FROM sys.configurations WHERE name = 'max server memory (MB)'),
		       (SELECT total_physical_memory_kb * 1024 FROM sys.dm_os_sys_memory)`,
	).Scan(&used, &maxMB, &total); err != nil || !used.Valid {
		return
	}
	limit := total.Int64
	if maxMB.Valid && maxMB.Int64 > 0 && maxMB.Int64 < 2147483647 {
		limit = maxMB.Int64 << 20
	}
	s.Memory = &DatabaseMemory{UsedBytes: used.Int64, LimitBytes: limit}
}

func (m *mssqlEngine) activity(ctx context.Context, s *DatabaseSnapshot) error {
	rows, err := m.db.QueryContext(ctx, `
		SELECT CAST(s.session_id AS varchar(10)), coalesce(s.login_name, ''),
		       coalesce(DB_NAME(coalesce(r.database_id, s.database_id)), ''),
		       coalesce(c.client_net_address, ''), coalesce(s.program_name, ''),
		       coalesce(r.status, ''), s.open_transaction_count,
		       coalesce(t.text, ''),
		       CAST(DATEDIFF_BIG(millisecond, r.start_time, sysdatetime()) / 1000.0 AS float),
		       CAST(tx.secs AS float), coalesce(r.wait_type, ''),
		       coalesce(r.blocking_session_id, 0), coalesce(c.encrypt_option, ''),
		       CAST(CASE WHEN s.session_id = @@SPID THEN 1 ELSE 0 END AS bit)
		  FROM sys.dm_exec_sessions s
		 OUTER APPLY (SELECT TOP 1 client_net_address, encrypt_option
		                FROM sys.dm_exec_connections
		               WHERE session_id = s.session_id) c
		  LEFT JOIN sys.dm_exec_requests r ON r.session_id = s.session_id
		 OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) t
		 OUTER APPLY (SELECT DATEDIFF(second, min(at.transaction_begin_time), sysdatetime()) AS secs
		                FROM sys.dm_tran_session_transactions st
		                JOIN sys.dm_tran_active_transactions at ON at.transaction_id = st.transaction_id
		               WHERE st.session_id = s.session_id) tx
		 WHERE s.is_user_process = 1`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var plain int32
	for rows.Next() {
		var (
			a          DatabaseActivity
			status     string
			openTx     int
			blocker    int
			encryption string
			secs, txs  sql.NullFloat64
		)
		if err := rows.Scan(&a.ID, &a.User, &a.Database, &a.Client, &a.App, &status,
			&openTx, &a.Query, &secs, &txs, &a.Wait, &blocker, &encryption, &a.Ours); err != nil {
			return err
		}
		switch {
		case status != "" && status != "sleeping" && status != "background":
			a.State = "active"
			if secs.Valid {
				a.Seconds = &secs.Float64
			}
		case openTx > 0:
			a.State = "idle_in_tx"
			a.Query = ""
		default:
			a.State = "idle"
			a.Query = ""
		}
		if txs.Valid {
			a.TxSeconds = &txs.Float64
		}
		if blocker > 0 {
			a.BlockedBy = []string{strconv.Itoa(blocker)}
		}
		if a.Client == "<local machine>" {
			a.Client = ""
		}
		if a.Client != "" && !strings.EqualFold(encryption, "TRUE") && !a.Ours {
			plain++
		}
		a.Query = truncate(a.Query, queryLimit)
		s.all = append(s.all, a)
	}
	s.Security.PlainClients = &plain
	return rows.Err()
}

func (m *mssqlEngine) availability(ctx context.Context, s *DatabaseSnapshot) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT ag.name, ar.replica_server_name, coalesce(ars.role_desc, ''),
		       coalesce(ars.connected_state_desc, ''),
		       coalesce(ars.synchronization_health_desc, ''), ars.is_local,
		       ar.availability_mode_desc,
		       (SELECT max(drs.secondary_lag_seconds) FROM sys.dm_hadr_database_replica_states drs
		         WHERE drs.replica_id = ar.replica_id)
		  FROM sys.availability_replicas ar
		  JOIN sys.availability_groups ag ON ag.group_id = ar.group_id
		  LEFT JOIN sys.dm_hadr_availability_replica_states ars ON ars.replica_id = ar.replica_id`)
	if err != nil {
		s.note("replication", "Couldn't read the availability group: "+err.Error())
		return
	}
	defer rows.Close()
	for rows.Next() {
		var (
			group, name, role, conn, health, mode string
			local                                 sql.NullBool
			lag                                   sql.NullInt64
		)
		if rows.Scan(&group, &name, &role, &conn, &health, &local, &mode, &lag) != nil {
			continue
		}
		s.Replication.Set = group
		if local.Valid && local.Bool {
			if role == "PRIMARY" {
				s.Role = "primary"
			} else if role == "SECONDARY" {
				s.Role = "replica"
			}
			continue
		}
		r := DatabaseReplica{
			Name: name, Address: name, State: strings.ToLower(role + " · " + conn),
			Healthy: health == "HEALTHY", Sync: strings.ToLower(strings.ReplaceAll(mode, "_", " ")),
		}
		if lag.Valid {
			r.LagSeconds = f64(float64(lag.Int64))
		}
		s.Replication.Replicas = append(s.Replication.Replicas, r)
	}
}

var mssqlSettings = []string{
	"max server memory (MB)", "min server memory (MB)", "max degree of parallelism",
	"cost threshold for parallelism", "user connections", "xp_cmdshell",
	"clr enabled", "remote admin connections", "Ad Hoc Distributed Queries",
	"Ole Automation Procedures", "optimize for ad hoc workloads",
	"backup compression default", "contained database authentication",
}

func quoteName(n string) string { return "[" + strings.ReplaceAll(n, "]", "]]") + "]" }

func (m *mssqlEngine) heavy(ctx context.Context, s *DatabaseSnapshot) error {
	rows, err := m.db.QueryContext(ctx, `
		SELECT d.name, d.state_desc, d.recovery_model_desc, d.log_reuse_wait_desc,
		       CAST(sum(CASE WHEN mf.type = 0 THEN mf.size ELSE 0 END) AS bigint) * 8192,
		       CAST(sum(CASE WHEN mf.type = 1 THEN mf.size ELSE 0 END) AS bigint) * 8192
		  FROM sys.databases d
		  JOIN sys.master_files mf ON mf.database_id = d.database_id
		 GROUP BY d.name, d.state_desc, d.recovery_model_desc, d.log_reuse_wait_desc
		 ORDER BY 5 DESC`)
	if err != nil {
		return err
	}
	var total int64
	for rows.Next() {
		var d DatabaseInfo
		var data, log int64
		if err := rows.Scan(&d.Name, &d.State, &d.Recovery, &d.LogWait, &data, &log); err != nil {
			rows.Close()
			return err
		}
		if d.LogWait == "NOTHING" {
			d.LogWait = ""
		}
		d.SizeBytes = i64(data + log)
		d.LogBytes = &log
		total += data + log
		s.Databases = append(s.Databases, d)
	}
	rows.Close()
	s.SizeBytes = &total

	// Share of each log in use.
	if rows, err := m.db.QueryContext(ctx, "DBCC SQLPERF(LOGSPACE) WITH NO_INFOMSGS"); err == nil {
		used := map[string]float64{}
		for rows.Next() {
			var name string
			var size, pct float64
			var status int
			if rows.Scan(&name, &size, &pct, &status) == nil {
				used[name] = pct / 100
			}
		}
		rows.Close()
		var worst float64
		var worstDB string
		for i := range s.Databases {
			if v, ok := used[s.Databases[i].Name]; ok {
				s.Databases[i].LogUsed = f64(v)
				if v > worst {
					worst, worstDB = v, s.Databases[i].Name
				}
			}
		}
		var logs int64
		for _, d := range s.Databases {
			logs += deref(d.LogBytes)
		}
		s.Log = &DatabaseLog{Kind: "Transaction log", SizeBytes: &logs, UsedRatio: f64(worst)}
		if worstDB != "" {
			s.Log.HeldBy = worstDB
			for _, d := range s.Databases {
				if d.Name == worstDB && d.LogWait != "" {
					s.Log.HeldBy = worstDB + " (" + d.LogWait + ")"
				}
			}
		}
	}

	// Last full backup msdb knows of, per database.
	if rows, err := m.db.QueryContext(ctx, `
		SELECT database_name, max(backup_finish_date)
		  FROM msdb.dbo.backupset WHERE type = 'D' GROUP BY database_name`); err == nil {
		last := map[string]time.Time{}
		for rows.Next() {
			var name string
			var at time.Time
			if rows.Scan(&name, &at) == nil {
				last[name] = at
			}
		}
		rows.Close()
		for i := range s.Databases {
			if t, ok := last[s.Databases[i].Name]; ok {
				s.Databases[i].LastBackup = ptrTime(t)
			}
		}
	}

	// Disk under the data files.
	var mount sql.NullString
	var vtotal, vfree sql.NullInt64
	if err := m.db.QueryRowContext(ctx, `
		SELECT TOP 1 vs.volume_mount_point, CAST(vs.total_bytes AS bigint), CAST(vs.available_bytes AS bigint)
		  FROM sys.master_files mf
		 CROSS APPLY sys.dm_os_volume_stats(mf.database_id, mf.file_id) vs
		 GROUP BY vs.volume_mount_point, vs.total_bytes, vs.available_bytes
		 ORDER BY sum(CAST(mf.size AS bigint)) DESC`).Scan(&mount, &vtotal, &vfree); err == nil && vtotal.Valid {
		s.Disk = &DatabaseDisk{Path: mount.String, TotalBytes: vtotal.Int64, FreeBytes: vfree.Int64, Source: "engine"}
	}
	var dataDir sql.NullString
	if m.db.QueryRowContext(ctx, "SELECT CAST(SERVERPROPERTY('InstanceDefaultDataPath') AS nvarchar(4000))").Scan(&dataDir) == nil {
		s.DataDir = dataDir.String
	}
	if s.Disk != nil && s.Disk.Path == "" {
		s.Disk.Path = s.DataDir
	}

	// Tables, identity columns and unused indexes, in the biggest user
	// databases.
	read := 0
	for _, d := range s.Databases {
		if read == 5 {
			break
		}
		if d.State != "ONLINE" || d.Name == "master" || d.Name == "model" || d.Name == "msdb" || d.Name == "tempdb" {
			continue
		}
		read++
		if err := m.perDatabase(ctx, d.Name, s); err != nil {
			s.note("tables", fmt.Sprintf("Couldn't read tables in %s: %v", d.Name, err))
		}
	}
	sortTables(s)

	m.topQueries(ctx, s)

	// Settings.
	rows, err = m.db.QueryContext(ctx, `
		SELECT name, CAST(value_in_use AS nvarchar(64)) FROM sys.configurations
		 WHERE name IN ('`+strings.Join(mssqlSettings, "','")+`') ORDER BY name`)
	if err == nil {
		for rows.Next() {
			var st DatabaseSetting
			if rows.Scan(&st.Name, &st.Value) == nil {
				s.Settings = append(s.Settings, st)
				if st.Value == "1" {
					switch st.Name {
					case "xp_cmdshell":
						s.Security.Risks = append(s.Security.Risks, "xp_cmdshell is on: SQL logins with rights to it can run commands on the server.")
					case "Ole Automation Procedures":
						s.Security.Risks = append(s.Security.Risks, "Ole Automation Procedures are on.")
					case "Ad Hoc Distributed Queries":
						s.Security.Risks = append(s.Security.Risks, "Ad Hoc Distributed Queries are on (OPENROWSET to anywhere).")
					}
				}
			}
		}
		rows.Close()
	}

	// Logins.
	rows, err = m.db.QueryContext(ctx, `
		SELECT name, coalesce(IS_SRVROLEMEMBER('sysadmin', name), 0), is_disabled
		  FROM sys.server_principals
		 WHERE type IN ('S', 'U', 'G', 'E', 'X') AND name NOT LIKE '##%'
		   AND name NOT LIKE 'NT SERVICE\%' AND name NOT LIKE 'NT AUTHORITY\%'
		 ORDER BY name`)
	if err == nil {
		var admins int32
		for rows.Next() {
			var u DatabaseUser
			var sa int
			if rows.Scan(&u.Name, &sa, &u.Disabled) == nil {
				u.Admin = sa == 1
				if u.Admin && !u.Disabled {
					admins++
				}
				s.Users = append(s.Users, u)
			}
		}
		rows.Close()
		s.Security.Admins = &admins
	}
	var empty sql.NullInt32
	if m.db.QueryRowContext(ctx,
		"SELECT count(*) FROM sys.sql_logins WHERE is_disabled = 0 AND PWDCOMPARE('', password_hash) = 1",
	).Scan(&empty) == nil && empty.Valid {
		s.Security.NoPassword = i32(empty.Int32)
	}

	var listen sql.NullString
	if m.db.QueryRowContext(ctx, `
		SELECT TOP 1 ip_address FROM sys.dm_tcp_listener_states
		 WHERE type_desc = 'TSQL' AND state_desc = 'ONLINE'
		 ORDER BY CASE WHEN ip_address IN ('::', '0.0.0.0') THEN 0 ELSE 1 END`).Scan(&listen) == nil {
		s.Security.ListensOn = listen.String
		if listen.String == "::" || listen.String == "0.0.0.0" {
			s.Security.ListensOn = "*"
		}
	}
	return nil
}

func (m *mssqlEngine) perDatabase(ctx context.Context, name string, s *DatabaseSnapshot) error {
	db := quoteName(name)
	rows, err := m.db.QueryContext(ctx, `
		SELECT TOP 15 sc.name, o.name,
		       sum(ps.reserved_page_count) * 8192,
		       sum(CASE WHEN ps.index_id > 1 THEN ps.reserved_page_count ELSE 0 END) * 8192,
		       sum(CASE WHEN ps.index_id < 2 THEN ps.row_count ELSE 0 END)
		  FROM `+db+`.sys.dm_db_partition_stats ps
		  JOIN `+db+`.sys.objects o ON o.object_id = ps.object_id
		  JOIN `+db+`.sys.schemas sc ON sc.schema_id = o.schema_id
		 WHERE o.is_ms_shipped = 0 AND o.type = 'U'
		 GROUP BY sc.name, o.name ORDER BY 3 DESC`)
	if err != nil {
		return err
	}
	for rows.Next() {
		t := DatabaseTable{Database: name}
		var idx, n int64
		if err := rows.Scan(&t.Schema, &t.Name, &t.SizeBytes, &idx, &n); err != nil {
			rows.Close()
			return err
		}
		t.IndexBytes = &idx
		t.Rows = &n
		s.Tables = append(s.Tables, t)
	}
	rows.Close()

	rows, err = m.db.QueryContext(ctx, `
		SELECT t.name, c.name, TYPE_NAME(c.system_type_id), CAST(c.last_value AS float),
		       c.precision
		  FROM `+db+`.sys.identity_columns c
		  JOIN `+db+`.sys.tables t ON t.object_id = c.object_id
		 WHERE c.last_value IS NOT NULL`)
	if err == nil {
		for rows.Next() {
			c := DatabaseIDColumn{Database: name}
			var precision int
			if rows.Scan(&c.Table, &c.Column, &c.Type, &c.Current, &precision) != nil {
				continue
			}
			switch c.Type {
			case "tinyint":
				c.Max = 255
			case "smallint":
				c.Max = 32767
			case "int":
				c.Max = 2147483647
			case "bigint":
				c.Max = 9223372036854775807
			default:
				c.Max = mathPow10(precision) - 1
			}
			if c.Max > 0 {
				c.Ratio = c.Current / c.Max
				s.IDColumns = append(s.IDColumns, c)
			}
		}
		rows.Close()
	}

	rows, err = m.db.QueryContext(ctx, `
		SELECT TOP 10 o.name, i.name, us.user_updates
		  FROM `+db+`.sys.indexes i
		  JOIN `+db+`.sys.objects o ON o.object_id = i.object_id
		  JOIN sys.dm_db_index_usage_stats us
		    ON us.object_id = i.object_id AND us.index_id = i.index_id AND us.database_id = DB_ID(@p1)
		 WHERE o.is_ms_shipped = 0 AND i.type_desc = 'NONCLUSTERED'
		   AND i.is_primary_key = 0 AND i.is_unique = 0
		   AND us.user_seeks + us.user_scans + us.user_lookups = 0 AND us.user_updates > 0
		 ORDER BY us.user_updates DESC`, name)
	if err == nil {
		for rows.Next() {
			ix := DatabaseIndex{Database: name}
			var w int64
			if rows.Scan(&ix.Table, &ix.Name, &w) == nil {
				ix.Writes = &w
				s.Indexes = append(s.Indexes, ix)
			}
		}
		rows.Close()
	}
	return nil
}

func mathPow10(n int) float64 {
	v := 1.0
	for range n {
		v *= 10
	}
	return v
}

func (m *mssqlEngine) topQueries(ctx context.Context, s *DatabaseSnapshot) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT TOP 25
		       SUBSTRING(t.text, qs.statement_start_offset / 2 + 1,
		         (CASE WHEN qs.statement_end_offset = -1 THEN DATALENGTH(t.text)
		               ELSE qs.statement_end_offset END - qs.statement_start_offset) / 2 + 1),
		       coalesce(DB_NAME(t.dbid), ''), qs.execution_count,
		       CAST(qs.total_elapsed_time / 1000.0 AS float),
		       CAST(qs.total_elapsed_time / 1000.0 / qs.execution_count AS float),
		       qs.total_rows
		  FROM sys.dm_exec_query_stats qs
		 CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) t
		 ORDER BY qs.total_elapsed_time DESC`)
	if err != nil {
		s.note("queries", "Couldn't read query statistics (needs VIEW SERVER STATE): "+err.Error())
		return
	}
	defer rows.Close()
	for rows.Next() {
		var q DatabaseQuery
		var text sql.NullString
		var n int64
		if rows.Scan(&text, &q.Database, &q.Calls, &q.TotalMs, &q.MeanMs, &n) != nil {
			continue
		}
		q.Query = truncate(text.String, queryLimit)
		q.Rows = &n
		s.Queries = append(s.Queries, q)
	}
	s.QueriesSource = "sys.dm_exec_query_stats"
}

func (m *mssqlEngine) kill(ctx context.Context, id string, _ bool) error {
	n, err := strconv.Atoi(id)
	if err != nil || n <= 0 {
		return errors.New("not a SQL Server session id")
	}
	_, err = m.db.ExecContext(ctx, "KILL "+strconv.Itoa(n))
	return err
}

func (m *mssqlEngine) explain(ctx context.Context, database, query string) (*DatabasePlan, error) {
	conn, err := m.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	// SHOWPLAN and USE change the session: never hand it back.
	defer func() {
		conn.Raw(func(any) error { return driver.ErrBadConn })
		conn.Close()
	}()
	if database != "" {
		if _, err := conn.ExecContext(ctx, "USE "+quoteName(database)); err != nil {
			return nil, err
		}
	}
	// With SHOWPLAN_ALL on, statements are compiled and described, never
	// run, and the setting must be alone in its batch.
	if _, err := conn.ExecContext(ctx, "SET SHOWPLAN_ALL ON"); err != nil {
		return nil, err
	}
	rows, err := conn.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	plan := &DatabasePlan{Format: "text", Warnings: []string{}}
	var lines []string
	for {
		cols, err := rows.Columns()
		if err != nil {
			return nil, err
		}
		idx := map[string]int{}
		for i, c := range cols {
			idx[c] = i
		}
		for rows.Next() {
			vals := make([]sql.NullString, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				return nil, err
			}
			get := func(c string) string {
				if i, ok := idx[c]; ok {
					return vals[i].String
				}
				return ""
			}
			lines = append(lines, strings.TrimRight(get("StmtText"), " "))
			rowsEst, _ := strconv.ParseFloat(get("EstimateRows"), 64)
			if plan.Cost == nil && get("Parent") == "0" {
				if c, err := strconv.ParseFloat(get("TotalSubtreeCost"), 64); err == nil {
					plan.Cost = &c
					plan.Rows = f64(rowsEst)
				}
			}
			op := get("PhysicalOp")
			if (op == "Table Scan" || op == "Clustered Index Scan" || op == "Index Scan") && rowsEst >= 10000 {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf(
					"%s of %s (about %s rows). An index on the filtered columns may help.",
					op, objectOf(get("Argument")), groupDigits(int64(rowsEst))))
			}
			if w := get("Warnings"); w != "" {
				plan.Warnings = append(plan.Warnings, w)
			}
		}
		if !rows.NextResultSet() {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	plan.Plan = strings.Join(lines, "\n")
	return plan, nil
}

// objectOf pulls the table out of a SHOWPLAN argument like
// OBJECT:([db].[dbo].[orders].[PK_orders]).
func objectOf(arg string) string {
	start := strings.Index(arg, "OBJECT:(")
	if start < 0 {
		return "a table"
	}
	rest := arg[start+8:]
	if end := strings.Index(rest, ")"); end >= 0 {
		rest = rest[:end]
	}
	parts := strings.Split(rest, ".")
	if len(parts) >= 3 {
		return strings.Join(parts[1:3], ".")
	}
	return rest
}

func engineAuthErrorMSSQL(err error) bool {
	var me mssql.Error
	return errors.As(err, &me) && (me.Number == 18456 || me.Number == 4060)
}
