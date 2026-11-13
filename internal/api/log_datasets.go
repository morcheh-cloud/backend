package api

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// logChild is a table whose rows belong to a dataset's row and go with it
// (deleted by its foreign key's ON DELETE CASCADE).
type logChild struct {
	Table  string
	Column string // its column holding the parent's key
	Parent string // the parent's column it points at
}

// logDataset is one kind of log or event Morche keeps, that a retention
// policy can archive. Everything here is fixed SQL, never user input.
type logDataset struct {
	Key   string
	Title string
	Group string
	About string
	Table string
	// Time is the column a row's age is read from.
	Time     string
	Children []logChild
	// Omit are columns never written to an archive (secrets).
	Omit []string
	// Busy is a condition (on alias t) for rows still in use: never archived.
	Busy string
	// Builtin says what happens to old rows without a policy.
	Builtin string
	// Suggested days for a new policy.
	Days int
}

var logDatasets = []logDataset{
	{
		Key: "command-log", Title: "Command log", Group: "Audit",
		About: "Every SSH command Morche ran and every command line typed in its terminals, with what they printed.",
		Table: "command_log", Time: "started_at",
		// Still running (a day on, it was lost: Morche stopped meanwhile).
		Busy:     "t.ended_at IS NULL AND t.started_at > now() - interval '1 day'",
		Children: []logChild{{Table: "command_log_output", Column: "id", Parent: "id"}},
		Builtin:  "Deleted after each workspace's Keep for setting (90 days by default).",
		Days:     90,
	},
	{
		Key: "terminal-recordings", Title: "Terminal recordings", Group: "Audit",
		About: "Replays of terminal sessions, when a workspace records them.",
		Table: "terminal_recordings", Time: "started_at",
		Busy:    "t.ended_at IS NULL AND t.started_at > now() - interval '1 day'",
		Builtin: "Deleted after each workspace's Keep for setting (90 days by default).",
		Days:    90,
	},
	{
		Key: "sign-ins", Title: "Sign-ins", Group: "Audit",
		About: "Every sign-in, failed attempt and sign-out, with the address and browser.",
		Table: "sign_ins", Time: "at",
		Builtin: "Deleted after 180 days.",
		Days:    180,
	},
	{
		Key: "secret-views", Title: "Password reveals", Group: "Audit",
		About: "Who revealed or copied a service's password, and when.",
		Table: "app_secret_views", Time: "created_at",
		Builtin: "Kept for good.",
		Days:    365,
	},
	{
		Key: "jobs", Title: "Background tasks", Group: "Runs",
		About: "Finished background tasks (copies, backups, installs…) with their output.",
		Table: "jobs", Time: "created_at", Busy: "t.state IN ('queued', 'running')",
		Builtin: "Deleted 30 days after they finish.",
		Days:    30,
	},
	{
		Key: "script-runs", Title: "Script runs", Group: "Runs",
		About: "Saved scripts and commands run on servers, with each server's output.",
		Table: "script_runs", Time: "created_at", Busy: "t.state IN ('queued', 'running')",
		Children: []logChild{{Table: "script_run_targets", Column: "run_id", Parent: "id"}},
		Builtin:  "Deleted after 90 days.",
		Days:     90,
	},
	{
		Key: "ansible-runs", Title: "Ansible runs", Group: "Runs",
		About: "Playbook runs with their output and per-server results.",
		Table: "ansible_runs", Time: "created_at", Busy: "t.state IN ('queued', 'running')",
		Builtin: "Kept for good.",
		Days:    180,
	},
	{
		Key: "schedule-runs", Title: "Cron job runs", Group: "Runs",
		About: "Each run of a cron job: what it did and how it ended.",
		Table: "schedule_runs", Time: "created_at", Busy: "t.state IN ('queued', 'running')",
		Builtin: "The newest runs of each cron job are kept, older ones deleted.",
		Days:    180,
	},
	{
		Key: "software-runs", Title: "Application runs", Group: "Runs",
		About: "Installs, updates and removals of applications, with each server's output. Secrets are never archived.",
		Table: "software_runs", Time: "created_at", Busy: "t.state IN ('queued', 'running')",
		Children: []logChild{{Table: "software_run_targets", Column: "run_id", Parent: "id"}},
		Omit:     []string{"secrets"},
		Builtin:  "Deleted after 90 days.",
		Days:     90,
	},
	{
		Key: "alert-events", Title: "Alert events", Group: "Alerts",
		About: "Every time an alert rule started or stopped firing.",
		Table: "alert_events", Time: "at",
		Builtin: "Deleted after SERVER_HISTORY (31 days by default).",
		Days:    90,
	},
	{
		Key: "notifications", Title: "Notifications sent", Group: "Alerts",
		About: "Each message sent to a notification channel and whether it got there.",
		Table: "notification_log", Time: "at",
		Builtin: "Kept for good.",
		Days:    90,
	},
	{
		Key: "server-samples", Title: "Server resource samples", Group: "Monitoring",
		About: "CPU, memory, disk and network read from each server every minute.",
		Table: "server_samples", Time: "at",
		Builtin: "Deleted after SERVER_HISTORY (31 days by default).",
		Days:    31,
	},
	{
		Key: "server-checks", Title: "Server checks", Group: "Monitoring",
		About: "Connection checks of each server, summed per bucket (uptime and latency).",
		Table: "server_check_buckets", Time: "bucket",
		Builtin: "Deleted after SERVER_HISTORY (31 days by default).",
		Days:    31,
	},
	{
		Key: "server-status", Title: "Server status changes", Group: "Monitoring",
		About: "Each time a server went online, offline or failed to sign in.",
		Table: "server_status_changes", Time: "at",
		Builtin: "Deleted after SERVER_HISTORY (31 days by default).",
		Days:    90,
	},
	{
		Key: "storage-checks", Title: "Storage checks", Group: "Monitoring",
		About: "Each connection check of a storage, with its latency.",
		Table: "storage_checks", Time: "checked_at",
		Builtin: "Deleted after STORAGE_HISTORY (31 days by default).",
		Days:    31,
	},
	{
		Key: "storage-usage", Title: "Storage measurements", Group: "Monitoring",
		About: "How much each storage held when it was measured.",
		Table: "storage_usage", Time: "measured_at",
		Builtin: "Deleted after 400 days.",
		Days:    400,
	},
	{
		Key: "database-samples", Title: "Database samples", Group: "Monitoring",
		About: "Connections, queries per second, cache hits and size read from each database.",
		Table: "database_samples", Time: "at",
		Builtin: "Deleted after 30 days.",
		Days:    30,
	},
	{
		Key: "database-events", Title: "Database events", Group: "Monitoring",
		About: "Checks that started or stopped failing on a database, and other changes.",
		Table: "database_events", Time: "at",
		Builtin: "Deleted after 90 days.",
		Days:    90,
	},
	{
		Key: "monitor-checks", Title: "Uptime checks", Group: "Monitoring",
		About: "Each check of an uptime monitor (daily totals are kept apart and stay).",
		Table: "monitor_checks", Time: "at",
		Builtin: "Deleted after MONITOR_HISTORY (14 days by default).",
		Days:    14,
	},
	{
		Key: "monitor-events", Title: "Uptime status changes", Group: "Monitoring",
		About: "Each time a monitor went up, down or degraded.",
		Table: "monitor_events", Time: "at",
		Builtin: "Kept for good.",
		Days:    365,
	},
	{
		Key: "docker-stats", Title: "Container project usage", Group: "Containers",
		About: "CPU, memory and network of each Compose project, recorded over time.",
		Table: "docker_project_stats", Time: "at",
		Builtin: "Deleted after the Containers setting Keep usage for (30 days by default).",
		Days:    30,
	},
	{
		Key: "docker-auto-update-events", Title: "Container auto-updates", Group: "Containers",
		About: "What each auto-update run did to each container.",
		Table: "docker_auto_update_events", Time: "at",
		Builtin: "Deleted after 180 days.",
		Days:    180,
	},
}

func logDatasetByKey(key string) (logDataset, bool) {
	i := slices.IndexFunc(logDatasets, func(d logDataset) bool { return d.Key == key })
	if i < 0 {
		return logDataset{}, false
	}
	return logDatasets[i], true
}

func logDatasetKeys() []string {
	out := make([]string, len(logDatasets))
	for i, d := range logDatasets {
		out[i] = d.Key
	}
	return out
}

// tables is the dataset's table and its children, parents first.
func (d logDataset) tables() []string {
	out := []string{d.Table}
	for _, c := range d.Children {
		out = append(out, c.Table)
	}
	return out
}

// ---- Who cleans up ----

// logOwners holds the datasets an enabled policy looks after. The built-in
// pruning skips them: their rows go when the policy says so, not before.
var logOwners = struct {
	sync.RWMutex
	keys map[string]bool
}{keys: map[string]bool{}}

// logOwned says a policy owns this dataset's clean-up.
func logOwned(key string) bool {
	logOwners.RLock()
	defer logOwners.RUnlock()
	return logOwners.keys[key]
}

func setLogOwners(keys []string) {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	logOwners.Lock()
	logOwners.keys = m
	logOwners.Unlock()
}

// ---- What the database knows about a table ----

type tableColumn struct {
	Name     string
	Type     string
	Nullable bool
	// Generated columns are read but never written.
	Generated bool
}

type tableForeignKey struct {
	Name     string
	Columns  []string
	RefTable string
	RefCols  []string
	OnDelete byte // a no action, r restrict, c cascade, n set null, d set default
}

type tableInfo struct {
	Columns []tableColumn
	Key     []string
	Out     []tableForeignKey // this table's references to others
	In      []tableForeignKey // others' references to this table (Name = their table)
}

func (t tableInfo) column(name string) (tableColumn, bool) {
	i := slices.IndexFunc(t.Columns, func(c tableColumn) bool { return c.Name == name })
	if i < 0 {
		return tableColumn{}, false
	}
	return t.Columns[i], true
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func readTableInfo(ctx context.Context, db querier, table string) (tableInfo, error) {
	var t tableInfo
	rows, err := db.Query(ctx, `
		SELECT a.attname, format_type(a.atttypid, a.atttypmod), NOT a.attnotnull, a.attgenerated <> ''
		FROM pg_attribute a
		WHERE a.attrelid = $1::regclass AND a.attnum > 0 AND NOT a.attisdropped
		ORDER BY a.attnum`, table)
	if err != nil {
		return t, err
	}
	for rows.Next() {
		var c tableColumn
		if err := rows.Scan(&c.Name, &c.Type, &c.Nullable, &c.Generated); err != nil {
			rows.Close()
			return t, err
		}
		t.Columns = append(t.Columns, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return t, err
	}
	rows, err = db.Query(ctx, `
		SELECT a.attname FROM pg_index i
		JOIN LATERAL unnest(i.indkey) WITH ORDINALITY k(attnum, n) ON true
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
		WHERE i.indrelid = $1::regclass AND i.indisprimary
		ORDER BY k.n`, table)
	if err != nil {
		return t, err
	}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			rows.Close()
			return t, err
		}
		t.Key = append(t.Key, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return t, err
	}
	fks := func(sql string) ([]tableForeignKey, error) {
		rows, err := db.Query(ctx, sql, table)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []tableForeignKey
		for rows.Next() {
			var f tableForeignKey
			var del string
			if err := rows.Scan(&f.Name, &f.Columns, &f.RefTable, &f.RefCols, &del); err != nil {
				return nil, err
			}
			if del != "" {
				f.OnDelete = del[0]
			}
			out = append(out, f)
		}
		return out, rows.Err()
	}
	const fkSQL = `
		SELECT %s,
			(SELECT array_agg(a.attname ORDER BY k.n) FROM unnest(c.conkey) WITH ORDINALITY k(attnum, n)
				JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum),
			%s,
			(SELECT array_agg(a.attname ORDER BY k.n) FROM unnest(c.confkey) WITH ORDINALITY k(attnum, n)
				JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.attnum),
			c.confdeltype::text
		FROM pg_constraint c
		WHERE c.contype = 'f' AND %s = $1::regclass`
	if t.Out, err = fks(fmt.Sprintf(fkSQL, "c.conname", "c.confrelid::regclass::text", "c.conrelid")); err != nil {
		return t, err
	}
	// For references in, Name is the referencing table and Columns its own.
	if t.In, err = fks(fmt.Sprintf(fkSQL, "c.conrelid::regclass::text", "c.confrelid::regclass::text", "c.confrelid")); err != nil {
		return t, err
	}
	return t, nil
}

func ident(name string) string { return pgx.Identifier{name}.Sanitize() }

func identList(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = ident(n)
	}
	return strings.Join(q, ", ")
}

// archivedColumns are the columns of a table written to an archive.
func (d logDataset) archivedColumns(info tableInfo) []string {
	var out []string
	for _, c := range info.Columns {
		if !slices.Contains(d.Omit, c.Name) {
			out = append(out, c.Name)
		}
	}
	return out
}

// timeLiteral writes a time into SQL (COPY takes no parameters). Only times
// Morche worked out itself go through here.
func timeLiteral(at time.Time) string {
	return "'" + at.UTC().Format(time.RFC3339Nano) + "'::timestamptz"
}

// windowWhere is the condition (alias t) for the dataset's rows in [from,
// to) that may go: not busy, and not pointed at by a table outside the
// dataset that would refuse or cascade the delete.
func (d logDataset) windowWhere(info tableInfo, from, to time.Time) string {
	parts := []string{fmt.Sprintf("t.%s >= %s AND t.%s < %s",
		ident(d.Time), timeLiteral(from), ident(d.Time), timeLiteral(to))}
	if d.Busy != "" {
		parts = append(parts, "NOT ("+d.Busy+")")
	}
	for _, in := range info.In {
		if in.OnDelete == 'n' || in.OnDelete == 'd' {
			continue // the link is just cleared
		}
		if slices.ContainsFunc(d.Children, func(c logChild) bool { return c.Table == in.Name }) {
			continue
		}
		var on []string
		for i, col := range in.Columns {
			on = append(on, fmt.Sprintf("r.%s = t.%s", ident(col), ident(in.RefCols[i])))
		}
		parts = append(parts, fmt.Sprintf("NOT EXISTS (SELECT 1 FROM %s r WHERE %s)", ident(in.Name), strings.Join(on, " AND ")))
	}
	return strings.Join(parts, " AND ")
}

// ---- Sizes ----

type logTableStats struct {
	Table      string
	TotalBytes int64
	HeapBytes  int64
	Rows       int64
	DeadRows   int64
	Vacuumed   *time.Time
}

func readTableStats(ctx context.Context, db *pgxpool.Pool, table string) (logTableStats, error) {
	s := logTableStats{Table: table}
	var est float64
	var vacuum, auto *time.Time
	err := db.QueryRow(ctx, `
		SELECT pg_total_relation_size(c.oid), pg_relation_size(c.oid), c.reltuples,
			coalesce(st.n_live_tup, 0), coalesce(st.n_dead_tup, 0), st.last_vacuum, st.last_autovacuum
		FROM pg_class c LEFT JOIN pg_stat_user_tables st ON st.relid = c.oid
		WHERE c.oid = $1::regclass`, table).Scan(&s.TotalBytes, &s.HeapBytes, &est, &s.Rows, &s.DeadRows, &vacuum, &auto)
	if err != nil {
		return s, err
	}
	if est > 0 && s.Rows == 0 {
		s.Rows = int64(est)
	}
	s.Vacuumed = vacuum
	if auto != nil && (vacuum == nil || auto.After(*vacuum)) {
		s.Vacuumed = auto
	}
	return s, nil
}
