package dbmon

import (
	"fmt"
	"slices"
	"time"
)

// Check levels. unknown = the check couldn't run (never shown as OK).
const (
	LevelOK       = "ok"
	LevelWarning  = "warning"
	LevelCritical = "critical"
	LevelUnknown  = "unknown"
)

// DatabaseCheck is one health check's verdict.
type DatabaseCheck struct {
	ID     string   `json:"id" example:"connections"`
	Area   string   `json:"area" enum:"availability,capacity,performance,replication,backup,security"`
	Title  string   `json:"title" example:"Connections"`
	Level  string   `json:"level" enum:"ok,warning,critical,unknown"`
	Reason string   `json:"reason" doc:"What was found" example:"182 of 200 connections in use (91%)"`
	Action string   `json:"action,omitempty" doc:"What to do about it"`
	Value  *float64 `json:"value" nullable:"true" doc:"The measured number the limits apply to"`
	Muted  bool     `json:"muted,omitempty" doc:"Left out of health and alerts"`
	// Since is when Level began; Pending is a different level seen once and
	// waiting for the next look to agree before it counts.
	Since   *time.Time `json:"since" nullable:"true"`
	Pending string     `json:"pending,omitempty"`
}

// DatabaseLimit is where a check turns warning and critical.
type DatabaseLimit struct {
	Warn float64 `json:"warn"`
	Crit float64 `json:"crit"`
}

// DatabaseCheckInfo describes a check for the settings page.
type DatabaseCheckInfo struct {
	ID    string         `json:"id"`
	Area  string         `json:"area"`
	Title string         `json:"title"`
	About string         `json:"about"`
	Unit  string         `json:"unit,omitempty" doc:"ratio (0–1), seconds, hours, ms, count, bytes"`
	Lower bool           `json:"lower,omitempty" doc:"Lower values are worse"`
	Limit *DatabaseLimit `json:"limit,omitempty" doc:"Default limits; absent = not adjustable"`
}

func lim(w, c float64) *DatabaseLimit { return &DatabaseLimit{Warn: w, Crit: c} }

// Checks lists every check with its default limits.
var Checks = []DatabaseCheckInfo{
	{ID: "reachable", Area: "availability", Title: "Reachable", About: "Morcheh can connect and sign in."},
	{ID: "latency", Area: "availability", Title: "Response time", About: "Round trip of a trivial query.", Unit: "ms", Limit: lim(500, 2000)},
	{ID: "database_state", Area: "availability", Title: "Database states", About: "SQL Server: every database is ONLINE."},
	{ID: "disk", Area: "capacity", Title: "Disk", About: "Share of the data disk in use.", Unit: "ratio", Limit: lim(0.85, 0.95)},
	{ID: "connections", Area: "capacity", Title: "Connections", About: "Share of the connection limit in use.", Unit: "ratio", Limit: lim(0.8, 0.95)},
	{ID: "memory", Area: "capacity", Title: "Memory limit", About: "Redis: share of maxmemory in use.", Unit: "ratio", Limit: lim(0.85, 0.95)},
	{ID: "id_columns", Area: "capacity", Title: "Auto-increment IDs", About: "The fullest auto-increment column, as a share of its type's maximum.", Unit: "ratio", Limit: lim(0.7, 0.9)},
	{ID: "log_space", Area: "capacity", Title: "Transaction log", About: "SQL Server: share of the fullest transaction log in use.", Unit: "ratio", Limit: lim(0.8, 0.95)},
	{ID: "replication_slots", Area: "capacity", Title: "Replication slots", About: "PostgreSQL: WAL kept for slots; an inactive slot keeps it forever.", Unit: "bytes", Limit: lim(10<<30, 50<<30)},
	{ID: "oplog_window", Area: "capacity", Title: "Oplog window", About: "MongoDB: hours of changes the oplog holds; a replica down longer can't catch up.", Unit: "hours", Lower: true, Limit: lim(24, 6)},
	{ID: "blocking", Area: "performance", Title: "Blocking", About: "Longest wait of a connection blocked by another one's lock.", Unit: "seconds", Limit: lim(30, 300)},
	{ID: "long_queries", Area: "performance", Title: "Long queries", About: "Longest running statement.", Unit: "seconds", Limit: lim(60, 600)},
	{ID: "long_transactions", Area: "performance", Title: "Long transactions", About: "Oldest open transaction. It holds locks and stops cleanup.", Unit: "seconds", Limit: lim(600, 3600)},
	{ID: "idle_in_transaction", Area: "performance", Title: "Idle in transaction", About: "Longest a connection sat idle inside an open transaction.", Unit: "seconds", Limit: lim(60, 600)},
	{ID: "deadlocks", Area: "performance", Title: "Deadlocks", About: "New deadlocks since the previous look.", Unit: "count", Limit: lim(1, 5)},
	{ID: "cache_hit", Area: "performance", Title: "Cache hit", About: "Share of reads served from memory.", Unit: "ratio", Lower: true, Limit: lim(0.9, 0.8)},
	{ID: "replication", Area: "replication", Title: "Replication", About: "Replicas are connected and how far behind they are.", Unit: "seconds", Limit: lim(30, 300)},
	{ID: "backup_age", Area: "backup", Title: "Last backup", About: "Hours since the last good backup.", Unit: "hours", Limit: lim(26, 72)},
	{ID: "restore_test", Area: "backup", Title: "Restore test", About: "The last backup was restored somewhere and checked."},
	{ID: "persistence", Area: "backup", Title: "Persistence", About: "Redis: snapshots and the append-only file are written without errors."},
	{ID: "tls", Area: "security", Title: "Encryption", About: "Connections are encrypted with TLS."},
	{ID: "authentication", Area: "security", Title: "Authentication", About: "Every login needs a password; access control is on."},
	{ID: "exposure", Area: "security", Title: "Exposure", About: "Whether the port is reachable from the internet."},
	{ID: "failed_logins", Area: "security", Title: "Failed sign-ins", About: "Failed sign-ins since the previous look.", Unit: "count", Limit: lim(10, 100)},
	{ID: "risky_settings", Area: "security", Title: "Risky settings", About: "Features that let a login reach the operating system or other servers."},
}

func checkInfo(id string) DatabaseCheckInfo {
	for _, c := range Checks {
		if c.ID == id {
			return c
		}
	}
	return DatabaseCheckInfo{ID: id, Title: id}
}

// EvalInput is what Evaluate judges.
type EvalInput struct {
	Engine   string
	Snapshot *DatabaseSnapshot // nil when the look failed
	Status   string            // Status* from Classify
	Message  string
	// Public: Morcheh reached it straight over the internet.
	Public bool
	// Direct: no panel server stands in front of it, so nothing reads its
	// disk unless the engine says.
	Direct bool
	// Morcheh's own backups.
	LastBackup      *time.Time
	BackupPlanned   bool
	LastRestoreTest *time.Time
	RestoreTestOK   bool
	Limits          map[string]DatabaseLimit
	Muted           []string
	Now             time.Time
}

func (in EvalInput) limit(id string) DatabaseLimit {
	if l, ok := in.Limits[id]; ok {
		return l
	}
	if c := checkInfo(id); c.Limit != nil {
		return *c.Limit
	}
	return DatabaseLimit{}
}

type evaluator struct {
	in  EvalInput
	out []DatabaseCheck
}

func (e *evaluator) add(id, level, reason, action string, value *float64) {
	c := checkInfo(id)
	e.out = append(e.out, DatabaseCheck{
		ID: id, Area: c.Area, Title: c.Title, Level: level, Reason: reason,
		Action: action, Value: value, Muted: slices.Contains(e.in.Muted, id),
	})
}

// grade puts v against the check's limits.
func (e *evaluator) grade(id string, v float64) string {
	l := e.in.limit(id)
	if checkInfo(id).Lower {
		switch {
		case v <= l.Crit:
			return LevelCritical
		case v <= l.Warn:
			return LevelWarning
		}
		return LevelOK
	}
	switch {
	case v >= l.Crit:
		return LevelCritical
	case v >= l.Warn:
		return LevelWarning
	}
	return LevelOK
}

func pct(v float64) string { return fmt.Sprintf("%.0f%%", v*100) }

// Evaluate judges one look. A failed look only judges availability; the other
// checks keep their last verdict (see Settle).
func Evaluate(in EvalInput) []DatabaseCheck {
	e := &evaluator{in: in}
	s := in.Snapshot
	if s == nil {
		e.add("reachable", LevelCritical, cmp(in.Message, "Couldn't connect"), unreachableAction(in.Status), nil)
		return e.out
	}
	e.add("reachable", LevelOK, "Connected and signed in", "", nil)
	e.availability(s)
	e.capacity(s)
	e.performance(s)
	e.replication(s)
	e.backup(s)
	e.security(s)
	return e.out
}

func unreachableAction(status string) string {
	switch status {
	case StatusAuthFailed:
		return "The username or password was refused. Check whether the password was changed, then update it here."
	case StatusTLSError:
		return "The TLS handshake failed. Check the server's certificate, or change the TLS mode in the connection settings."
	case StatusBlocked:
		return "The address is private or internal. A system admin can allow internal addresses for this database."
	}
	return "Check that the database is running, that its port is open to Morcheh, and the server it runs on."
}

func (e *evaluator) availability(s *DatabaseSnapshot) {
	ms := float64(s.LatencyMs)
	e.add("latency", e.grade("latency", ms), fmt.Sprintf("%d ms for a trivial query", s.LatencyMs),
		"A slow reply to a trivial query means the server is overloaded or the network is slow.", &ms)

	if e.in.Engine == MSSQL && len(s.Databases) > 0 {
		var bad []string
		for _, d := range s.Databases {
			if d.State != "" && d.State != "ONLINE" {
				bad = append(bad, d.Name+" is "+d.State)
			}
		}
		if len(bad) > 0 {
			e.add("database_state", LevelCritical, joinMax(bad, 3), "Look at the SQL Server error log for why the database isn't online.", nil)
		} else {
			e.add("database_state", LevelOK, "Every database is online", "", nil)
		}
	}
}

func (e *evaluator) capacity(s *DatabaseSnapshot) {
	switch {
	case s.Disk != nil && s.Disk.TotalBytes > 0:
		used := 1 - float64(s.Disk.FreeBytes)/float64(s.Disk.TotalBytes)
		e.add("disk", e.grade("disk", used),
			fmt.Sprintf("%s used, %s free of %s", pct(used), humanBytes(s.Disk.FreeBytes), humanBytes(s.Disk.TotalBytes)),
			"Free space on the data disk: remove old logs or backups, or grow the disk. A full disk stops writes.", &used)
	case e.in.Engine == Redis:
		// Redis lives in memory; its limit is the memory check.
	case e.in.Direct:
		e.add("disk", LevelUnknown, "Can't be checked over a direct connection: this database doesn't report its disk.",
			"Connect it through the panel server it runs on to have the disk checked.", nil)
	default:
		e.add("disk", LevelUnknown, "The disk hasn't been read yet.", "", nil)
	}

	if m := s.Connections.Max; m != nil && *m > 0 {
		used := float64(s.Connections.Total) / float64(*m)
		e.add("connections", e.grade("connections", used),
			fmt.Sprintf("%d of %d connections in use (%s)", s.Connections.Total, *m, pct(used)),
			"Find which app or address holds the most connections below; use a connection pool or raise the limit.", &used)
	} else {
		e.add("connections", LevelUnknown, "The connection limit isn't known.", "", nil)
	}

	if e.in.Engine == Redis && s.Memory != nil {
		if s.Memory.LimitBytes > 0 {
			used := float64(s.Memory.UsedBytes) / float64(s.Memory.LimitBytes)
			e.add("memory", e.grade("memory", used),
				fmt.Sprintf("%s of %s maxmemory (%s)", humanBytes(s.Memory.UsedBytes), humanBytes(s.Memory.LimitBytes), pct(used)),
				"At the limit Redis evicts keys or refuses writes, depending on maxmemory-policy.", &used)
		} else {
			e.add("memory", LevelWarning, "No maxmemory set: Redis can grow until the server runs out of memory.",
				"Set maxmemory and a maxmemory-policy.", nil)
		}
	}

	if e.in.Engine != Redis && e.in.Engine != Mongo {
		if len(s.IDColumns) > 0 {
			c := s.IDColumns[0]
			e.add("id_columns", e.grade("id_columns", c.Ratio),
				fmt.Sprintf("%s.%s (%s) is at %s of its maximum", c.Table, c.Column, c.Type, pct(c.Ratio)),
				"Change the column to a bigger type (bigint) before it runs out; inserts fail when it does.", &c.Ratio)
		} else if s.DetailsAt != nil {
			e.add("id_columns", LevelOK, "No auto-increment column near its limit", "", f64(0))
		}
	}

	if e.in.Engine == MSSQL && s.Log != nil && s.Log.UsedRatio != nil {
		v := *s.Log.UsedRatio
		e.add("log_space", e.grade("log_space", v), fmt.Sprintf("Fullest log: %s used, %s", s.Log.HeldBy, pct(v)),
			"Take log backups (FULL recovery) or find what holds the log (the reason in brackets).", &v)
	}

	if e.in.Engine == Postgres && len(s.Replication.Slots) > 0 {
		var worst int64
		var name string
		var inactive []string
		for _, sl := range s.Replication.Slots {
			if b := deref(sl.RetainedBytes); b >= worst {
				worst, name = b, sl.Name
			}
			if !sl.Active {
				inactive = append(inactive, sl.Name)
			}
		}
		v := float64(worst)
		level := e.grade("replication_slots", v)
		reason := fmt.Sprintf("Slot %s keeps %s of WAL", name, humanBytes(worst))
		if len(inactive) > 0 {
			level = worse(level, LevelWarning)
			reason += "; inactive: " + joinMax(inactive, 3)
		}
		e.add("replication_slots", level, reason,
			"Drop slots nobody uses (pg_drop_replication_slot); an inactive slot keeps WAL until the disk fills.", &v)
	}

	if e.in.Engine == Mongo && s.Log != nil && s.Log.Window != nil && s.Role != "standalone" {
		v := *s.Log.Window
		e.add("oplog_window", e.grade("oplog_window", v), fmt.Sprintf("The oplog holds %.1f hours of changes", v),
			"Grow the oplog (replSetResizeOplog) so a replica that's down for a while can still catch up.", &v)
	}
}

func (e *evaluator) performance(s *DatabaseSnapshot) {
	var blocked, query, tx, idleTx float64
	var bWho, qWho, tWho, iWho string
	for _, a := range s.Sessions {
		if a.Ours {
			continue
		}
		who := sessionLabel(a)
		if len(a.BlockedBy) > 0 && a.Seconds != nil && *a.Seconds > blocked {
			blocked, bWho = *a.Seconds, who+" waits for "+joinMax(a.BlockedBy, 3)
		}
		if a.State == "active" && a.Seconds != nil && *a.Seconds > query {
			query, qWho = *a.Seconds, who
		}
		if a.TxSeconds != nil {
			if *a.TxSeconds > tx {
				tx, tWho = *a.TxSeconds, who
			}
			if a.State == "idle_in_tx" && *a.TxSeconds > idleTx {
				idleTx, iWho = *a.TxSeconds, who
			}
		}
	}
	timed := func(id string, v float64, who, none, action string) {
		if v <= 0 {
			e.add(id, LevelOK, none, "", f64(0))
			return
		}
		e.add(id, e.grade(id, v), fmt.Sprintf("%s for %s", who, humanSeconds(v)), action, f64(v))
	}
	if e.in.Engine != Redis {
		if s.Connections.Blocked > 0 && blocked == 0 {
			e.add("blocking", LevelWarning, fmt.Sprintf("%d waiting for locks", s.Connections.Blocked),
				"See the blocking tree on the dashboard.", f64(0))
		} else {
			timed("blocking", blocked, bWho, "Nothing blocked",
				"Find the session at the head of the blocking tree; finish or kill it.")
		}
		timed("long_transactions", tx, tWho, "No long transaction",
			"A transaction left open holds locks and stops cleanup. Find the app that opened it, or kill the session.")
	}
	if e.in.Engine == Postgres || e.in.Engine == MySQL || e.in.Engine == MSSQL {
		timed("idle_in_transaction", idleTx, iWho, "No connection idle in a transaction",
			"The app opened a transaction and stopped. Fix it to commit or roll back; kill the session meanwhile.")
	}
	if e.in.Engine != Redis {
		timed("long_queries", query, qWho, "No long-running statement",
			"Look at the statement and its plan (Explain); it may need an index.")
	}

	if s.Rates != nil && s.Rates.Deadlocks != nil {
		n := float64(*s.Rates.Deadlocks)
		e.add("deadlocks", e.grade("deadlocks", n), fmt.Sprintf("%d new since the previous look", *s.Rates.Deadlocks),
			"Two transactions took the same locks in opposite order. The engine's log names them.", &n)
	}

	if e.in.Engine != Redis && s.CacheHit != nil {
		v := *s.CacheHit
		e.add("cache_hit", e.grade("cache_hit", v), pct(v)+" of reads served from memory",
			"Reads go to disk: the working set doesn't fit in memory. Add memory or the cache setting, or find the queries scanning a lot.", &v)
	}
}

func sessionLabel(a DatabaseActivity) string {
	who := "Session " + a.ID
	if a.User != "" {
		who += " (" + a.User
		if a.Client != "" {
			who += " from " + a.Client
		}
		who += ")"
	}
	return who
}

func (e *evaluator) replication(s *DatabaseSnapshot) {
	r := s.Replication
	if src := r.Source; src != nil {
		if !src.Running {
			e.add("replication", LevelCritical, "Replication stopped: "+cmp(src.Error, "not receiving changes"),
				"Look at the replica's error and the primary it copies from.", nil)
			return
		}
		if src.LagSeconds == nil {
			e.add("replication", LevelUnknown, "Running; the lag isn't known", "", nil)
			return
		}
		v := *src.LagSeconds
		e.add("replication", e.grade("replication", v), fmt.Sprintf("%s behind %s", humanSeconds(v), src.Address),
			"A replica falls behind when it can't apply changes as fast as they come, or the network is slow.", &v)
		return
	}
	if len(r.Replicas) == 0 {
		return
	}
	var worst float64
	var down []string
	for _, rep := range r.Replicas {
		if !rep.Healthy {
			down = append(down, rep.Name+" ("+rep.State+")")
		}
		if rep.LagSeconds != nil && *rep.LagSeconds > worst {
			worst = *rep.LagSeconds
		}
	}
	level := e.grade("replication", worst)
	reason := fmt.Sprintf("%d replicas, at most %s behind", len(r.Replicas), humanSeconds(worst))
	if len(down) > 0 {
		level = worse(level, LevelCritical)
		reason = "Not healthy: " + joinMax(down, 3)
	}
	e.add("replication", level, reason, "Look at the replica's own status and error log.", &worst)
}

func (e *evaluator) backup(s *DatabaseSnapshot) {
	last := e.in.LastBackup
	source := "Morcheh"
	if e.in.Engine == MSSQL {
		// The oldest last full backup of any user database, as msdb records it.
		var oldest *time.Time
		never := []string{}
		for _, d := range s.Databases {
			if d.Name == "tempdb" || d.Name == "model" {
				continue
			}
			if d.LastBackup == nil {
				never = append(never, d.Name)
				continue
			}
			if oldest == nil || d.LastBackup.Before(*oldest) {
				oldest = d.LastBackup
			}
		}
		if len(never) > 0 && last == nil && len(s.Databases) > 0 {
			e.add("backup_age", LevelCritical, "Never backed up: "+joinMax(never, 3),
				"Set up a backup plan for this database.", nil)
			goto rest
		}
		if oldest != nil && (last == nil || oldest.After(*last)) {
			last, source = oldest, "msdb"
		}
	}
	switch {
	case last != nil:
		h := e.in.Now.Sub(*last).Hours()
		e.add("backup_age", e.grade("backup_age", h), fmt.Sprintf("Last good backup %s ago (%s)", humanSeconds(h*3600), source),
			"Run a backup now and check why the schedule didn't.", &h)
	case e.in.BackupPlanned:
		e.add("backup_age", LevelUnknown, "The plan hasn't produced a backup yet.", "", nil)
	default:
		e.add("backup_age", LevelUnknown, "No backup known.", "Set up a backup plan in Morcheh to have this checked.", nil)
	}
rest:
	switch {
	case e.in.LastRestoreTest == nil:
		e.add("restore_test", LevelUnknown, "No backup has been restore-tested.", "Run a restore test from the backups tab.", nil)
	case !e.in.RestoreTestOK:
		e.add("restore_test", LevelCritical, "The last restore test failed.", "Open the test's details to see what failed.", nil)
	default:
		e.add("restore_test", LevelOK, "Last tested "+e.in.LastRestoreTest.Format(time.DateOnly), "", nil)
	}

	if p := s.Persistence; p != nil {
		switch {
		case p.RDBStatus == "err" || p.AOFStatus == "err":
			e.add("persistence", LevelCritical, "Writing to disk failed (snapshot or append-only file)",
				"Check free disk space and permissions on the Redis data folder; Redis may refuse writes.", nil)
		case p.SaveSchedule == "" && !p.AOFEnabled:
			e.add("persistence", LevelWarning, "Neither snapshots nor the append-only file are on: a restart loses every key.",
				"Turn on appendonly or a save schedule, unless this Redis is only a cache.", nil)
		default:
			e.add("persistence", LevelOK, "Data is written to disk", "", nil)
		}
	}
}

func (e *evaluator) security(s *DatabaseSnapshot) {
	sec := s.Security
	switch {
	case sec.Encrypted != nil && !*sec.Encrypted && e.in.Public:
		e.add("tls", LevelCritical, "Morcheh's connection over the internet isn't encrypted.",
			"Turn on TLS on the database and set the connection to Require or Verify.", nil)
	case sec.Encrypted != nil && !*sec.Encrypted:
		e.add("tls", LevelWarning, "Morcheh's connection isn't encrypted.", "Turn on TLS on the database.", nil)
	case sec.PlainClients != nil && *sec.PlainClients > 0:
		e.add("tls", LevelWarning, fmt.Sprintf("%d connections from the network without TLS", *sec.PlainClients),
			"Make the database require TLS, or the apps use it.", f64(float64(*sec.PlainClients)))
	case sec.Encrypted != nil:
		e.add("tls", LevelOK, "Encrypted", "", nil)
	}

	switch {
	case sec.AuthDisabled:
		e.add("authentication", LevelCritical, "Anyone who reaches the port gets in: access control is off.",
			"Turn on authentication and give every app its own login.", nil)
	case sec.NoPassword != nil && *sec.NoPassword > 0:
		e.add("authentication", LevelCritical, fmt.Sprintf("%d logins have no password", *sec.NoPassword),
			"Set a password on them, or remove them.", f64(float64(*sec.NoPassword)))
	case sec.NoPassword != nil || s.DetailsAt != nil:
		e.add("authentication", LevelOK, "Every login needs a password", "", nil)
	}

	switch {
	case e.in.Public && sec.AuthDisabled:
		e.add("exposure", LevelCritical, "Reachable from the internet with no password.",
			"Close the port in the firewall now.", nil)
	case e.in.Public:
		e.add("exposure", LevelWarning, "Reachable from the internet.",
			"Limit the port to the addresses that need it (firewall, security group).", nil)
	case sec.ListensOn == "*":
		e.add("exposure", LevelOK, "Listens on every address; reached through its server.", "", nil)
	default:
		e.add("exposure", LevelOK, "Not reached over the internet", "", nil)
	}

	if s.Rates != nil && s.Rates.FailedLogins != nil {
		n := float64(*s.Rates.FailedLogins)
		e.add("failed_logins", e.grade("failed_logins", n), fmt.Sprintf("%d since the previous look", *s.Rates.FailedLogins),
			"Many failures mean a wrong password in an app, or someone guessing. Check the database's log for the address.", &n)
	}

	if len(sec.Risks) > 0 {
		e.add("risky_settings", LevelWarning, joinMax(sec.Risks, 2), "Turn them off unless something needs them.", nil)
	} else if s.DetailsAt != nil {
		e.add("risky_settings", LevelOK, "None found", "", nil)
	}
}

func joinMax(list []string, n int) string {
	if len(list) <= n {
		return joinComma(list)
	}
	return joinComma(list[:n]) + fmt.Sprintf(" and %d more", len(list)-n)
}

func joinComma(list []string) string {
	out := ""
	for i, s := range list {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

var levelRank = map[string]int{LevelOK: 0, LevelUnknown: 0, LevelWarning: 1, LevelCritical: 2}

func worse(a, b string) string {
	if levelRank[b] > levelRank[a] {
		return b
	}
	return a
}

// Health is the worst level of the checks that count. Unknown checks don't
// pull it down; all unknown (or none) is unknown.
func Health(checks []DatabaseCheck) string {
	h, known := LevelOK, false
	for _, c := range checks {
		if c.Muted || c.Level == LevelUnknown {
			continue
		}
		known = true
		h = worse(h, c.Level)
	}
	if !known {
		return LevelUnknown
	}
	return h
}

// CheckChange is a check whose level changed, for events and alerts.
type CheckChange struct {
	Check DatabaseCheck
	From  string
}

// Settle merges a new evaluation into the last one. A level must be seen in
// two looks in a row before it counts, so one slow reply or a blip doesn't
// alert. Checks missing from next (a failed look judges only availability)
// keep their verdict. The first verdict of a check counts at once.
func Settle(prev, next []DatabaseCheck, now time.Time) ([]DatabaseCheck, []CheckChange) {
	old := map[string]DatabaseCheck{}
	for _, c := range prev {
		old[c.ID] = c
	}
	var out []DatabaseCheck
	var changes []CheckChange
	seen := map[string]bool{}
	for _, n := range next {
		seen[n.ID] = true
		p, ok := old[n.ID]
		switch {
		case !ok:
			n.Since = &now
			if n.Level == LevelWarning || n.Level == LevelCritical {
				changes = append(changes, CheckChange{Check: n, From: LevelOK})
			}
			out = append(out, n)
		case n.Level == p.Level:
			n.Since = p.Since
			out = append(out, n)
		case p.Pending == n.Level:
			n.Since = &now
			changes = append(changes, CheckChange{Check: n, From: p.Level})
			out = append(out, n)
		default:
			// Keep the counted verdict; note what was seen.
			p.Pending = n.Level
			p.Value = n.Value
			p.Muted = n.Muted
			out = append(out, p)
		}
	}
	for _, p := range prev {
		if !seen[p.ID] {
			p.Pending = ""
			out = append(out, p)
		}
	}
	return out, changes
}
