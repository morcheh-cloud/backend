package dbmon

import (
	"testing"
	"time"
)

func find(t *testing.T, checks []DatabaseCheck, id string) DatabaseCheck {
	t.Helper()
	for _, c := range checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no %s check in %+v", id, checks)
	return DatabaseCheck{}
}

func has(checks []DatabaseCheck, id string) bool {
	for _, c := range checks {
		if c.ID == id {
			return true
		}
	}
	return false
}

func snap() *DatabaseSnapshot {
	now := time.Now()
	return &DatabaseSnapshot{Engine: Postgres, LatencyMs: 3, DetailsAt: &now, CollectedAt: now,
		Security: DatabaseSecurity{Encrypted: new(true), NoPassword: i32(0)}}
}

func TestEvaluateDown(t *testing.T) {
	got := Evaluate(EvalInput{Engine: Postgres, Status: StatusAuthFailed, Message: "password authentication failed"})
	if len(got) != 1 {
		t.Fatalf("a failed look judges only availability, got %d checks", len(got))
	}
	c := got[0]
	if c.ID != "reachable" || c.Level != LevelCritical || c.Action == "" {
		t.Fatalf("got %+v", c)
	}
}

func TestEvaluateConnections(t *testing.T) {
	for _, tc := range []struct {
		total int32
		want  string
	}{{10, LevelOK}, {160, LevelWarning}, {190, LevelCritical}} {
		s := snap()
		s.Connections = DatabaseConnections{Total: tc.total, Max: i32(200)}
		if got := find(t, Evaluate(EvalInput{Engine: Postgres, Snapshot: s}), "connections").Level; got != tc.want {
			t.Errorf("%d/200: got %s, want %s", tc.total, got, tc.want)
		}
	}
	// A limit override applies.
	s := snap()
	s.Connections = DatabaseConnections{Total: 120, Max: i32(200)}
	in := EvalInput{Engine: Postgres, Snapshot: s, Limits: map[string]DatabaseLimit{"connections": {Warn: 0.5, Crit: 0.9}}}
	if got := find(t, Evaluate(in), "connections").Level; got != LevelWarning {
		t.Errorf("override: got %s", got)
	}
}

func TestEvaluateDiskUnknownWhenDirect(t *testing.T) {
	got := find(t, Evaluate(EvalInput{Engine: MySQL, Snapshot: snap(), Direct: true}), "disk")
	if got.Level != LevelUnknown {
		t.Fatalf("a disk nobody can read must be unknown, never OK: %+v", got)
	}
	s := snap()
	s.Disk = &DatabaseDisk{TotalBytes: 100, FreeBytes: 3}
	if got := find(t, Evaluate(EvalInput{Engine: MySQL, Snapshot: s}), "disk").Level; got != LevelCritical {
		t.Fatalf("97%% used: got %s", got)
	}
}

func TestEvaluateLowerIsWorse(t *testing.T) {
	s := snap()
	s.CacheHit = f64(0.85)
	if got := find(t, Evaluate(EvalInput{Engine: Postgres, Snapshot: s}), "cache_hit").Level; got != LevelWarning {
		t.Fatalf("85%% cache hit: got %s", got)
	}
	s.CacheHit = f64(0.99)
	if got := find(t, Evaluate(EvalInput{Engine: Postgres, Snapshot: s}), "cache_hit").Level; got != LevelOK {
		t.Fatalf("99%% cache hit: got %s", got)
	}
}

func TestEvaluateSessions(t *testing.T) {
	s := snap()
	s.Sessions = []DatabaseActivity{
		{ID: "1", User: "app", State: "idle_in_tx", TxSeconds: f64(700)},
		{ID: "2", User: "app", State: "active", Seconds: f64(40), BlockedBy: []string{"1"}},
		{ID: "3", State: "active", Seconds: f64(9000), TxSeconds: f64(9000), Ours: true},
	}
	got := Evaluate(EvalInput{Engine: Postgres, Snapshot: s})
	if l := find(t, got, "idle_in_transaction").Level; l != LevelCritical {
		t.Errorf("idle in tx 700 s: got %s", l)
	}
	if l := find(t, got, "blocking").Level; l != LevelWarning {
		t.Errorf("blocked 40 s: got %s", l)
	}
	if l := find(t, got, "long_queries").Level; l != LevelOK {
		t.Errorf("our own session must not count: got %s", l)
	}
}

func TestEvaluateBackup(t *testing.T) {
	now := time.Now()
	old := now.Add(-80 * time.Hour)
	got := find(t, Evaluate(EvalInput{Engine: Postgres, Snapshot: snap(), LastBackup: &old, Now: now}), "backup_age")
	if got.Level != LevelCritical {
		t.Errorf("80 h old: %+v", got)
	}
	if l := find(t, Evaluate(EvalInput{Engine: Postgres, Snapshot: snap(), Now: now}), "backup_age").Level; l != LevelUnknown {
		t.Errorf("no backup known must be unknown: got %s", l)
	}

	// SQL Server reads msdb; a database never backed up is critical.
	s := snap()
	s.Engine = MSSQL
	recent := now.Add(-2 * time.Hour)
	s.Databases = []DatabaseInfo{{Name: "master", State: "ONLINE", LastBackup: &recent}, {Name: "shop", State: "ONLINE"}}
	if l := find(t, Evaluate(EvalInput{Engine: MSSQL, Snapshot: s, Now: now}), "backup_age").Level; l != LevelCritical {
		t.Errorf("shop never backed up: got %s", l)
	}
}

func TestEvaluateSecurity(t *testing.T) {
	s := snap()
	s.Security.Encrypted = new(false)
	s.Security.AuthDisabled = true
	got := Evaluate(EvalInput{Engine: Mongo, Snapshot: s, Public: true})
	for _, id := range []string{"tls", "authentication", "exposure"} {
		if l := find(t, got, id).Level; l != LevelCritical {
			t.Errorf("%s: got %s", id, l)
		}
	}
}

func TestEvaluateEngineScope(t *testing.T) {
	s := snap()
	s.Engine = Redis
	s.Memory = &DatabaseMemory{UsedBytes: 10}
	got := Evaluate(EvalInput{Engine: Redis, Snapshot: s})
	if has(got, "disk") || has(got, "id_columns") || has(got, "long_transactions") {
		t.Errorf("Redis has no disk, ID or transaction checks: %+v", got)
	}
	if l := find(t, got, "memory").Level; l != LevelWarning {
		t.Errorf("no maxmemory: got %s", l)
	}
}

func TestHealth(t *testing.T) {
	checks := []DatabaseCheck{
		{ID: "a", Level: LevelOK},
		{ID: "b", Level: LevelCritical, Muted: true},
		{ID: "c", Level: LevelWarning},
		{ID: "d", Level: LevelUnknown},
	}
	if h := Health(checks); h != LevelWarning {
		t.Errorf("got %s", h)
	}
	if h := Health([]DatabaseCheck{{Level: LevelUnknown}}); h != LevelUnknown {
		t.Errorf("all unknown: got %s", h)
	}
}

func TestSettle(t *testing.T) {
	t0 := time.Now()
	c := func(id, level string) DatabaseCheck { return DatabaseCheck{ID: id, Level: level} }

	// The first verdict counts at once; a bad one is reported.
	cur, ch := Settle(nil, []DatabaseCheck{c("disk", LevelOK), c("tls", LevelWarning)}, t0)
	if len(ch) != 1 || ch[0].Check.ID != "tls" {
		t.Fatalf("first look: %+v", ch)
	}

	// One bad look is held back.
	cur, ch = Settle(cur, []DatabaseCheck{c("disk", LevelCritical), c("tls", LevelWarning)}, t0.Add(time.Minute))
	if len(ch) != 0 || find(t, cur, "disk").Level != LevelOK || find(t, cur, "disk").Pending != LevelCritical {
		t.Fatalf("blip must wait: %+v %+v", ch, cur)
	}

	// The second one agrees: it counts.
	cur, ch = Settle(cur, []DatabaseCheck{c("disk", LevelCritical), c("tls", LevelWarning)}, t0.Add(2*time.Minute))
	if len(ch) != 1 || ch[0].From != LevelOK || find(t, cur, "disk").Level != LevelCritical {
		t.Fatalf("second look: %+v %+v", ch, cur)
	}
	if s := find(t, cur, "disk").Since; s == nil || !s.Equal(t0.Add(2*time.Minute)) {
		t.Fatalf("since: %v", s)
	}

	// A failed look judges only reachability; the rest keep their verdict.
	cur, _ = Settle(cur, []DatabaseCheck{c("reachable", LevelCritical)}, t0.Add(3*time.Minute))
	if find(t, cur, "disk").Level != LevelCritical || find(t, cur, "tls").Level != LevelWarning {
		t.Fatalf("kept: %+v", cur)
	}
}

func TestDiff(t *testing.T) {
	now := time.Now()
	started := now.Add(-time.Hour)
	s := &DatabaseSnapshot{Version: "17.1", StartedAt: &started, CollectedAt: now, DetailsAt: &now,
		Users:    []DatabaseUser{{Name: "app"}, {Name: "postgres", Admin: true}},
		Settings: []DatabaseSetting{{Name: "max_connections", Value: "100"}},
		Clients:  []DatabaseClient{{Address: "10.0.0.5", Total: 3}},
	}
	ch, base := Diff(nil, s)
	if len(ch) != 0 {
		t.Fatalf("first look reports nothing: %+v", ch)
	}

	later := now.Add(time.Minute)
	restarted := later.Add(-10 * time.Second)
	s2 := &DatabaseSnapshot{Version: "17.2", StartedAt: &restarted, CollectedAt: later, DetailsAt: &later,
		Users:    []DatabaseUser{{Name: "app", Admin: true}, {Name: "postgres", Admin: true}, {Name: "eve"}},
		Settings: []DatabaseSetting{{Name: "max_connections", Value: "500"}},
		Clients:  []DatabaseClient{{Address: "10.0.0.5", Total: 3}, {Address: "203.0.113.9", Total: 1, Users: []string{"eve"}}},
	}
	ch, _ = Diff(base, s2)
	kinds := map[string]int{}
	for _, c := range ch {
		kinds[c.Kind]++
	}
	for _, k := range []string{"version", "restart", "user", "admin", "address", "setting"} {
		if kinds[k] != 1 {
			t.Errorf("%s: %d changes in %+v", k, kinds[k], ch)
		}
	}
}

func TestMarkNew(t *testing.T) {
	now := time.Now()
	look := func(at time.Time, addrs ...string) *DatabaseSnapshot {
		s := &DatabaseSnapshot{CollectedAt: at}
		for _, a := range addrs {
			s.Clients = append(s.Clients, DatabaseClient{Address: a, Total: 1})
		}
		return s
	}
	_, base := Diff(nil, look(now.Add(-48*time.Hour), "10.0.0.5", "local"))
	_, base = Diff(base, look(now.Add(-time.Hour), "10.0.0.5", "203.0.113.9"))

	s := look(now, "10.0.0.5", "203.0.113.9", "198.51.100.7", "local")
	got := MarkNew(base, s)
	want := map[string]bool{"10.0.0.5": false, "203.0.113.9": true, "198.51.100.7": true, "local": false}
	for _, c := range got.Clients {
		if c.New != want[c.Address] {
			t.Errorf("%s: new = %v", c.Address, c.New)
		}
	}
	if s.Clients[1].New {
		t.Error("the shared snapshot was changed")
	}

	_, base = Diff(base, look(now.Add(25*time.Hour), "203.0.113.9"))
	if MarkNew(base, look(now.Add(25*time.Hour), "203.0.113.9")).Clients[0].New {
		t.Error("still new after a day")
	}
}
