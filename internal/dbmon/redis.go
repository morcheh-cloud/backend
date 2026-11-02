package dbmon

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisClientName = "morcheh-monitor"

type redisEngine struct {
	cfg Config
	rdb *redis.Client
}

func openRedis(ctx context.Context, cfg Config) (engine, error) {
	db := 0
	if cfg.Database != "" {
		n, err := strconv.Atoi(strings.TrimPrefix(cfg.Database, "db"))
		if err != nil || n < 0 {
			return nil, errors.New("the Redis database is a number, e.g. 0")
		}
		db = n
	}
	tc, err := cfg.tlsConfig()
	if err != nil {
		return nil, err
	}
	dial := cfg.dialer()
	// A custom dialer replaces go-redis's own, TLS included.
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil || tc == nil {
			return c, err
		}
		tl := tls.Client(c, tc)
		if err := tl.HandshakeContext(ctx); err != nil {
			c.Close()
			return nil, err
		}
		return tl, nil
	}
	rdb := redis.NewClient(&redis.Options{
		Addr:            cfg.addr(),
		Username:        cfg.Username,
		Password:        cfg.Password,
		DB:              db,
		ClientName:      redisClientName,
		Protocol:        2,
		DisableIdentity: true,
		Dialer:          dialer,
		DialTimeout:     cfg.timeout(),
		ReadTimeout:     cfg.timeout(),
		WriteTimeout:    cfg.timeout(),
		PoolSize:        2,
		MaxRetries:      -1,
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		rdb.Close()
		return nil, err
	}
	return &redisEngine{cfg: cfg, rdb: rdb}, nil
}

func (r *redisEngine) close() error { return r.rdb.Close() }

// parseInfo turns INFO's "key:value" lines into a map.
func parseInfo(text string) map[string]string {
	m := map[string]string{}
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			m[k] = v
		}
	}
	return m
}

// fields splits "a=1,b=2" (keyspace and replica lines).
func fields(v string) map[string]string {
	m := map[string]string{}
	for p := range strings.SplitSeq(v, ",") {
		if k, val, ok := strings.Cut(p, "="); ok {
			m[k] = val
		}
	}
	return m
}

func infoInt(m map[string]string, k string) *int64 {
	v, ok := m[k]
	if !ok {
		return nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

func (r *redisEngine) config(ctx context.Context, name string) (string, bool) {
	m, err := r.rdb.ConfigGet(ctx, name).Result()
	if err != nil {
		return "", false
	}
	v, ok := m[name]
	return v, ok
}

func (r *redisEngine) light(ctx context.Context, s *DatabaseSnapshot) error {
	start := time.Now()
	if err := r.rdb.Ping(ctx).Err(); err != nil {
		return err
	}
	s.LatencyMs = int32(time.Since(start).Milliseconds())
	text, err := r.rdb.Info(ctx).Result()
	if err != nil {
		return err
	}
	in := parseInfo(text)

	s.Flavor, s.Version = "Redis", in["redis_version"]
	if v, ok := in["valkey_version"]; ok {
		s.Flavor, s.Version = "Valkey", v
	} else if in["server_name"] == "valkey" {
		s.Flavor = "Valkey"
	}
	if up := infoInt(in, "uptime_in_seconds"); up != nil {
		s.StartedAt = ptrTime(s.CollectedAt.Add(-time.Duration(*up) * time.Second))
	}
	if n := infoInt(in, "connected_clients"); n != nil {
		s.Connections.Total = int32(*n)
	}
	if n := infoInt(in, "blocked_clients"); n != nil {
		s.Connections.Blocked = int32(*n)
	}
	if v, ok := r.config(ctx, "maxclients"); ok {
		if n, err := strconv.ParseInt(v, 10, 32); err == nil {
			s.Connections.Max = i32(int32(n))
		}
	}

	hits, misses := infoInt(in, "keyspace_hits"), infoInt(in, "keyspace_misses")
	var reads *int64
	if hits != nil && misses != nil {
		reads = i64(*hits + *misses)
	}
	s.counters = counters{
		queries:      infoInt(in, "total_commands_processed"),
		failedLogins: infoInt(in, "acl_access_denied_auth"),
		cacheHits:    hits,
		cacheReads:   reads,
	}
	s.Security.FailedLogins = s.counters.failedLogins
	enc := r.cfg.TLS != TLSDisable
	s.Security.Encrypted = &enc

	if used := infoInt(in, "used_memory"); used != nil {
		s.Memory = &DatabaseMemory{UsedBytes: *used, Evicted: infoInt(in, "evicted_keys")}
		if limit := infoInt(in, "maxmemory"); limit != nil {
			s.Memory.LimitBytes = *limit
		}
		s.SizeBytes = used
	}

	p := &DatabasePersist{
		RDBStatus:  in["rdb_last_bgsave_status"],
		AOFEnabled: in["aof_enabled"] == "1",
		AOFStatus:  in["aof_last_write_status"],
	}
	if t := infoInt(in, "rdb_last_save_time"); t != nil && *t > 0 {
		p.RDBLastSave = ptrTime(time.Unix(*t, 0))
	}
	if n := infoInt(in, "rdb_changes_since_last_save"); n != nil {
		p.RDBChanges = *n
	}
	if v, ok := r.config(ctx, "save"); ok {
		p.SaveSchedule = v
	} else {
		p.SaveSchedule = "?"
	}
	s.Persistence = p

	for k, v := range in {
		if !strings.HasPrefix(k, "db") {
			continue
		}
		if _, err := strconv.Atoi(k[2:]); err != nil {
			continue
		}
		f := fields(v)
		keys, _ := strconv.ParseInt(f["keys"], 10, 64)
		s.Databases = append(s.Databases, DatabaseInfo{Name: k, Tables: &keys})
	}
	sort.Slice(s.Databases, func(i, j int) bool {
		a, _ := strconv.Atoi(s.Databases[i].Name[2:])
		b, _ := strconv.Atoi(s.Databases[j].Name[2:])
		return a < b
	})

	r.replication(in, s)

	for _, f := range []struct{ group, label, key, unit string }{
		{"Memory", "Fragmentation ratio", "mem_fragmentation_ratio", ""},
		{"Memory", "Peak used", "used_memory_peak_human", ""},
		{"Memory", "Eviction policy", "maxmemory_policy", ""},
		{"Clients", "Rejected connections", "rejected_connections", ""},
		{"Keys", "Expired keys", "expired_keys", ""},
		{"Keys", "Evicted keys", "evicted_keys", ""},
		{"Persistence", "Last fork", "latest_fork_usec", " µs"},
	} {
		if v := in[f.key]; v != "" {
			s.fact(f.group, f.label, v+f.unit)
		}
	}

	return r.activity(ctx, s)
}

func (r *redisEngine) replication(in map[string]string, s *DatabaseSnapshot) {
	s.Role = "standalone"
	switch in["role"] {
	case "slave", "replica":
		s.Role = "replica"
		s.ReadOnly = true
		src := &DatabaseSource{
			Address: net.JoinHostPort(in["master_host"], in["master_port"]),
			Running: in["master_link_status"] == "up",
		}
		if n := infoInt(in, "master_last_io_seconds_ago"); n != nil && *n >= 0 {
			src.LagSeconds = f64(float64(*n))
		}
		if !src.Running {
			if d := infoInt(in, "master_link_down_since_seconds"); d != nil {
				src.Error = "Link to the primary down for " + humanSeconds(float64(*d))
			} else {
				src.Error = "Not connected to the primary"
			}
		}
		s.Replication.Source = src
	}
	offset := infoInt(in, "master_repl_offset")
	for i := 0; ; i++ {
		v, ok := in["slave"+strconv.Itoa(i)]
		if !ok {
			break
		}
		f := fields(v)
		rep := DatabaseReplica{
			Name:    "replica " + strconv.Itoa(i),
			Address: net.JoinHostPort(f["ip"], f["port"]),
			State:   f["state"],
			Healthy: f["state"] == "online",
			Sync:    "async",
		}
		if lag, err := strconv.ParseFloat(f["lag"], 64); err == nil {
			rep.LagSeconds = &lag
		}
		if off, err := strconv.ParseInt(f["offset"], 10, 64); err == nil && offset != nil {
			rep.LagBytes = i64(max(0, *offset-off))
		}
		s.Replication.Replicas = append(s.Replication.Replicas, rep)
	}
	if s.Role == "standalone" && len(s.Replication.Replicas) > 0 {
		s.Role = "primary"
	}
}

func (r *redisEngine) activity(ctx context.Context, s *DatabaseSnapshot) error {
	text, err := r.rdb.ClientList(ctx).Result()
	if err != nil {
		s.note("sessions", "Couldn't list clients (CLIENT LIST): "+err.Error())
		return nil
	}
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := map[string]string{}
		for p := range strings.FieldsSeq(line) {
			if k, v, ok := strings.Cut(p, "="); ok {
				f[k] = v
			}
		}
		// Replicas and other internal links aren't clients.
		flags := f["flags"]
		if strings.ContainsAny(flags, "SM") {
			continue
		}
		a := DatabaseActivity{
			ID:     f["id"],
			User:   f["user"],
			Client: stripPort(f["addr"]),
			App:    cmp(f["name"], f["lib-name"]),
			Ours:   f["name"] == redisClientName,
		}
		if f["db"] != "" {
			a.Database = "db" + f["db"]
		}
		idle, _ := strconv.ParseFloat(f["idle"], 64)
		switch {
		case strings.Contains(flags, "b"):
			a.State = "active"
			a.Wait = "Blocking command"
			a.Query = f["cmd"]
			a.Seconds = &idle
		case f["multi"] != "" && f["multi"] != "-1":
			a.State = "idle_in_tx"
			a.TxSeconds = &idle
		case idle == 0 && !a.Ours && f["cmd"] != "NULL":
			a.State = "active"
			a.Query = f["cmd"]
		default:
			a.State = "idle"
		}
		if f["sub"] != "0" && f["sub"] != "" || f["psub"] != "0" && f["psub"] != "" {
			a.Wait = "Subscribed"
		}
		s.all = append(s.all, a)
	}
	return nil
}

var redisSettings = []string{
	"maxmemory", "maxmemory-policy", "maxclients", "timeout", "appendonly",
	"appendfsync", "save", "protected-mode", "bind", "port", "io-threads",
	"replica-read-only", "min-replicas-to-write", "lazyfree-lazy-eviction",
}

func (r *redisEngine) heavy(ctx context.Context, s *DatabaseSnapshot) error {
	configOK := true
	for _, name := range redisSettings {
		v, ok := r.config(ctx, name)
		if !ok {
			configOK = false
			continue
		}
		s.Settings = append(s.Settings, DatabaseSetting{Name: name, Value: v})
		switch name {
		case "bind":
			s.Security.ListensOn = v
			for b := range strings.FieldsSeq(v) {
				if b == "*" || b == "0.0.0.0" || b == "::" || b == "-::*" {
					s.Security.ListensOn = "*"
				}
			}
			if v == "" {
				s.Security.ListensOn = "*"
			}
		}
	}
	if !configOK {
		s.note("settings", "CONFIG GET is blocked for this login (common on managed Redis): settings, data folder and listen address are unknown.")
	}
	if dir, ok := r.config(ctx, "dir"); ok {
		s.DataDir = dir
	}

	r.users(ctx, s)

	if logs, err := r.rdb.SlowLogGet(ctx, 25).Result(); err == nil {
		for _, l := range logs {
			ms := float64(l.Duration.Microseconds()) / 1000
			q := DatabaseQuery{
				Query:   truncate(strings.Join(l.Args, " "), queryLimit),
				Calls:   1,
				TotalMs: ms,
				MeanMs:  ms,
				At:      ptrTime(l.Time),
			}
			s.Queries = append(s.Queries, q)
		}
		sort.SliceStable(s.Queries, func(i, j int) bool { return s.Queries[i].TotalMs > s.Queries[j].TotalMs })
		s.QueriesSource = "SLOWLOG"
	} else {
		s.note("queries", "Couldn't read the slow log: "+err.Error())
	}

	r.bigKeys(ctx, s)
	return nil
}

// users reads ACL LIST (Redis 6+), else the single requirepass.
func (r *redisEngine) users(ctx context.Context, s *DatabaseSnapshot) {
	list, err := r.rdb.Do(ctx, "ACL", "LIST").StringSlice()
	if err != nil {
		if pass, ok := r.config(ctx, "requirepass"); ok {
			s.Security.AuthDisabled = pass == ""
			if pass == "" {
				s.Security.NoPassword = i32(1)
			} else {
				s.Security.NoPassword = i32(0)
			}
		}
		return
	}
	var admins, nopass int32
	for _, line := range list {
		parts := strings.Fields(line)
		if len(parts) < 2 || parts[0] != "user" {
			continue
		}
		u := DatabaseUser{Name: parts[1], Disabled: true}
		for _, p := range parts[2:] {
			switch {
			case p == "on":
				u.Disabled = false
			case p == "nopass":
				u.NoPassword = true
			case p == "+@all" || p == "allcommands":
				u.Admin = true
			}
		}
		if !u.Disabled {
			if u.Admin {
				admins++
			}
			if u.NoPassword {
				nopass++
				if u.Name == "default" {
					s.Security.AuthDisabled = true
				}
			}
		}
		s.Users = append(s.Users, u)
	}
	s.Security.Admins = &admins
	s.Security.NoPassword = &nopass
	if s.Security.AuthDisabled {
		s.Security.Risks = append(s.Security.Risks,
			"The default user has no password: anyone who reaches the port can read and change every key.")
	}
}

// bigKeys samples keys of the selected database and keeps the largest, like
// redis-cli --memkeys, but bounded in keys and time.
func (r *redisEngine) bigKeys(ctx context.Context, s *DatabaseSnapshot) {
	const maxKeys = 5000
	deadline := time.Now().Add(3 * time.Second)
	var (
		cursor uint64
		seen   int
		top    []DatabaseTable
	)
	db := "db" + cmp(strings.TrimPrefix(r.cfg.Database, "db"), "0")
	for {
		keys, next, err := r.rdb.Scan(ctx, cursor, "", 500).Result()
		if err != nil {
			s.note("tables", "Couldn't sample keys: "+err.Error())
			return
		}
		if len(keys) > 0 {
			pipe := r.rdb.Pipeline()
			mem := make([]*redis.IntCmd, len(keys))
			typ := make([]*redis.StatusCmd, len(keys))
			for i, k := range keys {
				mem[i] = pipe.MemoryUsage(ctx, k)
				typ[i] = pipe.Type(ctx, k)
			}
			pipe.Exec(ctx)
			for i, k := range keys {
				size, err := mem[i].Result()
				if err != nil {
					continue
				}
				top = append(top, DatabaseTable{
					Database: db, Name: truncate(k, 200), Kind: typ[i].Val(), SizeBytes: size,
				})
			}
			sort.Slice(top, func(i, j int) bool { return top[i].SizeBytes > top[j].SizeBytes })
			if len(top) > 20 {
				top = top[:20]
			}
		}
		seen += len(keys)
		cursor = next
		if cursor == 0 || seen >= maxKeys || time.Now().After(deadline) {
			break
		}
	}
	s.Tables = top
	s.TablesScope = db
	if cursor != 0 {
		s.TablesScope = db + ", a sample of " + groupDigits(int64(seen)) + " keys"
	}
}

func (r *redisEngine) kill(ctx context.Context, id string, _ bool) error {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n <= 0 {
		return errors.New("not a Redis client id")
	}
	return r.rdb.Do(ctx, "CLIENT", "KILL", "ID", n).Err()
}

func (r *redisEngine) explain(context.Context, string, string) (*DatabasePlan, error) {
	return nil, ErrUnsupported
}
