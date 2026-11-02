// Package dbmon watches databases: it connects to PostgreSQL, MySQL/MariaDB,
// SQL Server, Redis and MongoDB with read-only monitoring queries, turns what
// each engine reports into one shape (a snapshot), and judges that snapshot
// against limits (checks). It knows nothing about HTTP or Morcheh's own
// tables; the API decides how a database is reached (directly or through a
// server over SSH) by passing a dialer.
package dbmon

import (
	"context"
	"net"
	"time"
)

// Engines.
const (
	Postgres = "postgres"
	MySQL    = "mysql"
	MSSQL    = "mssql"
	Redis    = "redis"
	Mongo    = "mongodb"
)

// Engines lists every engine, in the order the UI offers them.
var Engines = []string{Postgres, MySQL, MSSQL, Redis, Mongo}

// DefaultPort is each engine's usual port.
func DefaultPort(engine string) int {
	switch engine {
	case Postgres:
		return 5432
	case MySQL:
		return 3306
	case MSSQL:
		return 1433
	case Redis:
		return 6379
	case Mongo:
		return 27017
	}
	return 0
}

// TLS modes.
const (
	TLSDisable = "disable"
	TLSRequire = "require"
	TLSVerify  = "verify"
)

// Dialer opens the raw connection to the database.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Config is how to reach one database.
type Config struct {
	Engine   string
	Host     string
	Port     int
	Username string
	Password string
	// Database to connect to (Postgres: default postgres; MySQL: none; SQL
	// Server: default master; MongoDB: the auth source, default admin; Redis:
	// the db number, default 0).
	Database string
	TLS      string
	CACert   string
	// Dial reaches Host:Port. With Tunneled it gets the name as given (an SSH
	// server resolves it); without, it's a guarded net.Dialer.
	Dial     Dialer
	Tunneled bool
	// Timeout bounds connecting and each monitoring query.
	Timeout time.Duration
}

func (c Config) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 10 * time.Second
}

func (c Config) addr() string {
	return net.JoinHostPort(c.Host, itoa(c.Port))
}

// ---- Snapshot ----

// DatabaseSnapshot is everything one look at a database found. Lists are
// capped; a part an engine or the login's privileges can't give is left empty
// and explained in Notes.
type DatabaseSnapshot struct {
	Engine      string    `json:"engine" enum:"postgres,mysql,mssql,redis,mongodb"`
	Flavor      string    `json:"flavor" doc:"What it really is: PostgreSQL, MySQL, MariaDB, SQL Server, Redis, Valkey, MongoDB" example:"PostgreSQL"`
	Version     string    `json:"version" example:"17.2"`
	Edition     string    `json:"edition,omitempty" doc:"SQL Server edition, managed-service hints" example:"Developer Edition (64-bit)"`
	CollectedAt time.Time `json:"collected_at"`
	// Heavy parts (sizes, tables, users, settings, top queries) are read less
	// often; this is when they were last read.
	DetailsAt *time.Time `json:"details_at" nullable:"true"`
	LatencyMs int32      `json:"latency_ms" doc:"Round trip of a trivial query"`
	StartedAt *time.Time `json:"started_at" nullable:"true" doc:"When the server process started"`
	Role      string     `json:"role" enum:"primary,replica,standalone"`
	ReadOnly  bool       `json:"read_only"`

	Connections DatabaseConnections `json:"connections"`
	Rates       *DatabaseRates      `json:"rates,omitempty" doc:"Per second since the previous look; absent on the first one"`
	CacheHit    *float64            `json:"cache_hit" nullable:"true" doc:"Share of reads served from memory, 0–1"`
	Memory      *DatabaseMemory     `json:"memory,omitempty"`
	SizeBytes   *int64              `json:"size_bytes" nullable:"true" doc:"Everything stored, all databases together"`
	Disk        *DatabaseDisk       `json:"disk,omitempty" doc:"The disk holding the data"`
	DataDir     string              `json:"data_dir,omitempty" doc:"Where the data lives on its server"`
	Log         *DatabaseLog        `json:"log,omitempty" doc:"Write-ahead log, binary log, transaction log or oplog"`
	Persistence *DatabasePersist    `json:"persistence,omitempty" doc:"Redis: snapshots and the append-only file"`

	Databases     []DatabaseInfo      `json:"databases"`
	Clients       []DatabaseClient    `json:"clients" doc:"Connections grouped by address"`
	Sessions      []DatabaseActivity  `json:"sessions" doc:"Connections that are doing something, holding a transaction or blocked; longest first"`
	Queries       []DatabaseQuery     `json:"queries" doc:"Statements that took the most time in all"`
	QueriesSource string              `json:"queries_source" doc:"Where Queries came from; empty when nothing could tell" example:"pg_stat_statements"`
	Tables        []DatabaseTable     `json:"tables" doc:"Largest tables (collections, keys)"`
	TablesScope   string              `json:"tables_scope,omitempty" doc:"Which database Tables covers when it can't be all of them" example:"shop"`
	IDColumns     []DatabaseIDColumn  `json:"id_columns" doc:"Auto-increment columns, fullest first"`
	Indexes       []DatabaseIndex     `json:"indexes" doc:"Indexes nothing has used since statistics were reset"`
	Replication   DatabaseReplication `json:"replication"`
	Waits         []DatabaseWait      `json:"waits" doc:"What busy connections wait on right now"`
	Settings      []DatabaseSetting   `json:"settings" doc:"Settings worth knowing (and watching for changes)"`
	Users         []DatabaseUser      `json:"users"`
	Security      DatabaseSecurity    `json:"security"`
	Facts         []DatabaseFact      `json:"facts" doc:"Engine-specific numbers"`
	Notes         []DatabaseNote      `json:"notes" doc:"What couldn't be read, and why"`

	// Raw cumulative counters, for rates, and every connection the engine
	// listed, for the summaries; never sent.
	counters counters
	all      []DatabaseActivity
}

type DatabaseConnections struct {
	Total    int32  `json:"total" doc:"Client connections, ours included"`
	Active   int32  `json:"active" doc:"Running something right now"`
	Idle     int32  `json:"idle"`
	IdleInTx int32  `json:"idle_in_tx" doc:"Idle inside an open transaction (holds locks)"`
	Blocked  int32  `json:"blocked" doc:"Waiting on another connection's lock"`
	Max      *int32 `json:"max" nullable:"true" doc:"Most the server accepts"`
	Reserved int32  `json:"reserved" doc:"Kept back for admins"`
}

type DatabaseRates struct {
	Queries      *float64 `json:"queries" nullable:"true" doc:"Statements (or commands) per second"`
	Transactions *float64 `json:"transactions" nullable:"true"`
	Reads        *float64 `json:"reads" nullable:"true" doc:"Rows (or documents) read per second"`
	Writes       *float64 `json:"writes" nullable:"true" doc:"Rows written per second"`
	Deadlocks    *int64   `json:"deadlocks" nullable:"true" doc:"New deadlocks since the previous look"`
	FailedLogins *int64   `json:"failed_logins" nullable:"true" doc:"Failed sign-ins since the previous look"`
	Seconds      float64  `json:"seconds" doc:"Time between the two looks"`
}

type DatabaseMemory struct {
	UsedBytes  int64  `json:"used_bytes"`
	LimitBytes int64  `json:"limit_bytes" doc:"0 = no limit set"`
	Evicted    *int64 `json:"evicted" nullable:"true" doc:"Redis: keys pushed out to make room, since start"`
}

type DatabaseDisk struct {
	Path       string `json:"path"`
	TotalBytes int64  `json:"total_bytes"`
	FreeBytes  int64  `json:"free_bytes"`
	Source     string `json:"source" enum:"engine,server" doc:"engine: the database reported it; server: df on its server"`
}

type DatabaseLog struct {
	Kind      string   `json:"kind" example:"WAL"`
	SizeBytes *int64   `json:"size_bytes" nullable:"true"`
	UsedRatio *float64 `json:"used_ratio" nullable:"true" doc:"SQL Server: share of the log in use"`
	// What keeps it from shrinking, when the engine says.
	HeldBy string   `json:"held_by,omitempty" example:"replication slot standby1"`
	Window *float64 `json:"window_hours" nullable:"true" doc:"MongoDB: hours of changes the oplog holds"`
}

type DatabasePersist struct {
	RDBLastSave  *time.Time `json:"rdb_last_save" nullable:"true"`
	RDBStatus    string     `json:"rdb_status" doc:"ok or err"`
	RDBChanges   int64      `json:"rdb_changes" doc:"Writes since the last snapshot"`
	AOFEnabled   bool       `json:"aof_enabled"`
	AOFStatus    string     `json:"aof_status"`
	SaveSchedule string     `json:"save_schedule" doc:"The save setting; empty = snapshots off"`
}

type DatabaseInfo struct {
	Name        string     `json:"name"`
	SizeBytes   *int64     `json:"size_bytes" nullable:"true"`
	Tables      *int64     `json:"tables" nullable:"true" doc:"Tables, collections or keys"`
	Connections int32      `json:"connections"`
	State       string     `json:"state,omitempty" doc:"SQL Server: ONLINE, RESTORING…"`
	Recovery    string     `json:"recovery,omitempty" doc:"SQL Server recovery model"`
	LogBytes    *int64     `json:"log_bytes" nullable:"true"`
	LogUsed     *float64   `json:"log_used" nullable:"true"`
	LogWait     string     `json:"log_wait,omitempty" doc:"SQL Server: what keeps the log from being reused"`
	LastBackup  *time.Time `json:"last_backup" nullable:"true" doc:"SQL Server: last full backup msdb knows of"`
}

type DatabaseClient struct {
	Address   string   `json:"address" doc:"IP, or local socket" example:"10.0.0.12"`
	Total     int32    `json:"total"`
	Active    int32    `json:"active"`
	Users     []string `json:"users"`
	Databases []string `json:"databases"`
	Apps      []string `json:"apps"`
	New       bool     `json:"new" doc:"First showed up in the last day"`
}

type DatabaseActivity struct {
	ID        string   `json:"id" doc:"What Kill takes: pid, thread id, session id, client id or opid"`
	User      string   `json:"user"`
	Database  string   `json:"database"`
	Client    string   `json:"client"`
	App       string   `json:"app"`
	State     string   `json:"state" example:"active"`
	Query     string   `json:"query" doc:"Empty below Engineer access, and when the login can't see it"`
	Seconds   *float64 `json:"seconds" nullable:"true" doc:"How long the current statement has run"`
	TxSeconds *float64 `json:"tx_seconds" nullable:"true" doc:"How long its transaction has been open"`
	Wait      string   `json:"wait,omitempty" example:"Lock:transactionid"`
	BlockedBy []string `json:"blocked_by" doc:"Who it waits for"`
	Ours      bool     `json:"ours,omitempty" doc:"Morcheh's own monitoring connection"`
}

type DatabaseQuery struct {
	Query    string     `json:"query"`
	Database string     `json:"database,omitempty"`
	Calls    int64      `json:"calls"`
	TotalMs  float64    `json:"total_ms"`
	MeanMs   float64    `json:"mean_ms"`
	Rows     *int64     `json:"rows" nullable:"true"`
	At       *time.Time `json:"at,omitempty" nullable:"true" doc:"Redis slow log: when it ran"`
}

type DatabaseTable struct {
	Database   string     `json:"database,omitempty"`
	Schema     string     `json:"schema,omitempty"`
	Name       string     `json:"name"`
	Kind       string     `json:"kind,omitempty" doc:"Redis: the key's type"`
	SizeBytes  int64      `json:"size_bytes"`
	IndexBytes *int64     `json:"index_bytes" nullable:"true"`
	Rows       *int64     `json:"rows" nullable:"true" doc:"Estimated"`
	DeadRows   *int64     `json:"dead_rows" nullable:"true" doc:"PostgreSQL: rows waiting for vacuum"`
	FreeBytes  *int64     `json:"free_bytes" nullable:"true" doc:"MySQL: allocated but unused"`
	LastVacuum *time.Time `json:"last_vacuum" nullable:"true"`
}

type DatabaseIDColumn struct {
	Database string  `json:"database,omitempty"`
	Table    string  `json:"table"`
	Column   string  `json:"column"`
	Type     string  `json:"type" example:"integer"`
	Current  float64 `json:"current"`
	Max      float64 `json:"max"`
	Ratio    float64 `json:"ratio" doc:"Current / max"`
}

type DatabaseIndex struct {
	Database  string `json:"database,omitempty"`
	Table     string `json:"table"`
	Name      string `json:"name"`
	SizeBytes *int64 `json:"size_bytes" nullable:"true"`
	Writes    *int64 `json:"writes" nullable:"true" doc:"Updates it cost (SQL Server)"`
}

type DatabaseReplication struct {
	Replicas []DatabaseReplica `json:"replicas" doc:"Primary: who copies from it. Cluster: every member"`
	Source   *DatabaseSource   `json:"source,omitempty" doc:"Replica: where it copies from"`
	Slots    []DatabaseSlot    `json:"slots" doc:"PostgreSQL replication slots"`
	Set      string            `json:"set,omitempty" doc:"Replica set or availability group"`
}

type DatabaseReplica struct {
	Name       string   `json:"name"`
	Address    string   `json:"address"`
	State      string   `json:"state" example:"streaming"`
	Healthy    bool     `json:"healthy"`
	LagSeconds *float64 `json:"lag_seconds" nullable:"true"`
	LagBytes   *int64   `json:"lag_bytes" nullable:"true"`
	Sync       string   `json:"sync,omitempty" example:"async"`
}

type DatabaseSource struct {
	Address    string   `json:"address"`
	Running    bool     `json:"running" doc:"Receiving and applying changes"`
	LagSeconds *float64 `json:"lag_seconds" nullable:"true"`
	Error      string   `json:"error,omitempty"`
}

type DatabaseSlot struct {
	Name          string `json:"name"`
	Active        bool   `json:"active"`
	RetainedBytes *int64 `json:"retained_bytes" nullable:"true" doc:"WAL kept for it"`
}

type DatabaseWait struct {
	Event string `json:"event" example:"Lock:relation"`
	Count int32  `json:"count"`
}

type DatabaseSetting struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type DatabaseUser struct {
	Name       string `json:"name"`
	Admin      bool   `json:"admin" doc:"Superuser, sysadmin, root-like"`
	Disabled   bool   `json:"disabled,omitempty"`
	NoPassword bool   `json:"no_password,omitempty" doc:"Signs in without a password"`
}

type DatabaseSecurity struct {
	Encrypted    *bool    `json:"encrypted" nullable:"true" doc:"Our own connection is encrypted"`
	PlainClients *int32   `json:"plain_clients" nullable:"true" doc:"Other connections from the network without TLS"`
	ListensOn    string   `json:"listens_on,omitempty" doc:"Addresses it accepts connections on" example:"*"`
	AuthDisabled bool     `json:"auth_disabled" doc:"Anyone who reaches the port gets in"`
	Admins       *int32   `json:"admins" nullable:"true"`
	NoPassword   *int32   `json:"no_password" nullable:"true" doc:"Logins without a password"`
	FailedLogins *int64   `json:"failed_logins" nullable:"true" doc:"Since start"`
	Risks        []string `json:"risks" doc:"Settings that open a door, e.g. xp_cmdshell"`
}

type DatabaseFact struct {
	Group string `json:"group" example:"Memory"`
	Label string `json:"label" example:"Page life expectancy"`
	Value string `json:"value" example:"4 812 s"`
}

type DatabaseNote struct {
	Area    string `json:"area" example:"queries"`
	Message string `json:"message"`
}

// counters are cumulative totals; rates come from two of them.
type counters struct {
	queries, transactions, reads, writes, deadlocks, failedLogins *int64
	cacheHits, cacheReads                                         *int64
}

func (s *DatabaseSnapshot) note(area, msg string) {
	s.Notes = append(s.Notes, DatabaseNote{Area: area, Message: msg})
}

func (s *DatabaseSnapshot) fact(group, label, value string) {
	if value == "" {
		return
	}
	s.Facts = append(s.Facts, DatabaseFact{Group: group, Label: label, Value: value})
}
