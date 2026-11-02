package dbmon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

const mongoAppName = "morcheh-monitor"

type mongoEngine struct {
	cfg    Config
	client *mongo.Client
}

type dialFunc Dialer

func (d dialFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d(ctx, network, addr)
}

func openMongo(ctx context.Context, cfg Config) (engine, error) {
	tc, err := cfg.tlsConfig()
	if err != nil {
		return nil, err
	}
	opts := options.Client().
		SetHosts([]string{cfg.addr()}).
		SetDirect(true).
		SetAppName(mongoAppName).
		SetDialer(dialFunc(cfg.dialer())).
		SetConnectTimeout(cfg.timeout()).
		SetServerSelectionTimeout(cfg.timeout()).
		SetMaxPoolSize(2).
		SetRetryReads(false).
		SetRetryWrites(false).
		SetReadPreference(readpref.PrimaryPreferred())
	if cfg.Username != "" {
		opts.SetAuth(options.Credential{
			Username: cfg.Username, Password: cfg.Password,
			AuthSource: cmp(cfg.Database, "admin"),
		})
	}
	if tc != nil {
		opts.SetTLSConfig(tc)
	}
	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, nil); err != nil {
		client.Disconnect(context.Background())
		return nil, err
	}
	return &mongoEngine{cfg: cfg, client: client}, nil
}

func (m *mongoEngine) close() error { return m.client.Disconnect(context.Background()) }

func (m *mongoEngine) run(ctx context.Context, db string, cmd bson.D) (bson.Raw, error) {
	return m.client.Database(db).RunCommand(ctx, cmd).Raw()
}

func rawInt(r bson.Raw, path ...string) *int64 {
	v, err := r.LookupErr(path...)
	if err != nil {
		return nil
	}
	n, ok := v.AsInt64OK()
	if !ok {
		return nil
	}
	return &n
}

func rawFloat(r bson.Raw, path ...string) *float64 {
	v, err := r.LookupErr(path...)
	if err != nil {
		return nil
	}
	f, ok := v.AsFloat64OK()
	if !ok {
		return nil
	}
	return &f
}

func rawString(r bson.Raw, path ...string) string {
	v, err := r.LookupErr(path...)
	if err != nil {
		return ""
	}
	s, _ := v.StringValueOK()
	return s
}

func rawBool(r bson.Raw, path ...string) bool {
	v, err := r.LookupErr(path...)
	if err != nil {
		return false
	}
	if b, ok := v.BooleanOK(); ok {
		return b
	}
	n, ok := v.AsInt64OK()
	return ok && n != 0
}

func rawDocs(r bson.Raw, path ...string) []bson.Raw {
	v, err := r.LookupErr(path...)
	if err != nil {
		return nil
	}
	arr, ok := v.ArrayOK()
	if !ok {
		return nil
	}
	vals, _ := arr.Values()
	var out []bson.Raw
	for _, v := range vals {
		if d, ok := v.DocumentOK(); ok {
			out = append(out, d)
		}
	}
	return out
}

func sum(ns ...*int64) *int64 {
	var t int64
	for _, n := range ns {
		if n == nil {
			return nil
		}
		t += *n
	}
	return &t
}

func (m *mongoEngine) light(ctx context.Context, s *DatabaseSnapshot) error {
	start := time.Now()
	if err := m.client.Ping(ctx, nil); err != nil {
		return err
	}
	s.LatencyMs = int32(time.Since(start).Milliseconds())

	bi, err := m.run(ctx, "admin", bson.D{{Key: "buildInfo", Value: 1}})
	if err != nil {
		return err
	}
	s.Flavor, s.Version = "MongoDB", rawString(bi, "version")
	if rawString(bi, "psmdbVersion") != "" {
		s.Flavor = "Percona Server for MongoDB"
	}

	st, err := m.run(ctx, "admin", bson.D{{Key: "serverStatus", Value: 1}})
	if err != nil {
		s.note("server", "Couldn't run serverStatus (needs the clusterMonitor role): "+err.Error())
	} else {
		m.status(st, s)
	}
	enc := m.cfg.TLS != TLSDisable
	s.Security.Encrypted = &enc

	m.replication(ctx, s)
	m.activity(ctx, s)
	return nil
}

func (m *mongoEngine) status(st bson.Raw, s *DatabaseSnapshot) {
	if up := rawInt(st, "uptime"); up != nil {
		s.StartedAt = ptrTime(s.CollectedAt.Add(-time.Duration(*up) * time.Second))
	}
	cur, avail := rawInt(st, "connections", "current"), rawInt(st, "connections", "available")
	if cur != nil {
		s.Connections.Total = int32(*cur)
		if avail != nil {
			s.Connections.Max = i32(int32(*cur + *avail))
		}
	}
	if n := rawInt(st, "connections", "active"); n != nil {
		s.Connections.Active = int32(*n)
	}
	op := func(k string) *int64 { return rawInt(st, "opcounters", k) }
	requested := rawInt(st, "wiredTiger", "cache", "pages requested from the cache")
	read := rawInt(st, "wiredTiger", "cache", "pages read into cache")
	var hits *int64
	if requested != nil && read != nil {
		hits = i64(max(0, *requested-*read))
	}
	s.counters = counters{
		queries:    sum(op("insert"), op("query"), op("update"), op("delete"), op("getmore"), op("command")),
		reads:      sum(op("query"), op("getmore")),
		writes:     sum(op("insert"), op("update"), op("delete")),
		cacheHits:  hits,
		cacheReads: requested,
	}
	if n := rawInt(st, "transactions", "totalCommitted"); n != nil {
		s.counters.transactions = n
	}
	// Failed logins: received minus successful, over every mechanism.
	if mechs, err := st.LookupErr("security", "authentication", "mechanisms"); err == nil {
		if doc, ok := mechs.DocumentOK(); ok {
			els, _ := doc.Elements()
			var failed int64
			for _, e := range els {
				d, ok := e.Value().DocumentOK()
				if !ok {
					continue
				}
				rec, succ := rawInt(d, "authenticate", "received"), rawInt(d, "authenticate", "successful")
				if rec != nil && succ != nil {
					failed += *rec - *succ
				}
			}
			s.counters.failedLogins = &failed
			s.Security.FailedLogins = &failed
		}
	}

	if used := rawInt(st, "wiredTiger", "cache", "bytes currently in the cache"); used != nil {
		s.Memory = &DatabaseMemory{UsedBytes: *used}
		if limit := rawInt(st, "wiredTiger", "cache", "maximum bytes configured"); limit != nil {
			s.Memory.LimitBytes = *limit
		}
	}
	if res := rawInt(st, "mem", "resident"); res != nil {
		s.fact("Memory", "Resident memory", humanBytes(*res<<20))
	}
	if n := rawInt(st, "wiredTiger", "cache", "tracked dirty bytes in the cache"); n != nil {
		s.fact("Memory", "Dirty cache", humanBytes(*n))
	}
	// MongoDB doesn't say who holds a lock, only how many wait for one.
	if n := rawInt(st, "globalLock", "currentQueue", "total"); n != nil {
		s.Connections.Blocked = int32(*n)
		s.fact("Load", "Operations queued for locks", groupDigits(*n))
	}
	if n := rawInt(st, "transactions", "currentActive"); n != nil {
		s.fact("Load", "Open transactions", groupDigits(*n))
	}
	if n := rawInt(st, "asserts", "regular"); n != nil {
		s.fact("Health", "Regular asserts", groupDigits(*n))
	}
	if n := rawInt(st, "asserts", "warning"); n != nil {
		s.fact("Health", "Warning asserts", groupDigits(*n))
	}
	if n := rawInt(st, "metrics", "cursor", "timedOut"); n != nil {
		s.fact("Load", "Timed-out cursors", groupDigits(*n))
	}
}

func (m *mongoEngine) replication(ctx context.Context, s *DatabaseSnapshot) {
	s.Role = "standalone"
	rs, err := m.run(ctx, "admin", bson.D{{Key: "replSetGetStatus", Value: 1}})
	if err != nil {
		var ce mongo.CommandError
		// 76: not a replica set; 13: not allowed, which a standalone login
		// also hits.
		if errors.As(err, &ce) && ce.Code != 76 && ce.Code != 94 {
			s.note("replication", "Couldn't read the replica set: "+err.Error())
		}
		return
	}
	s.Replication.Set = rawString(rs, "set")
	members := rawDocs(rs, "members")
	var primaryOp int64
	for _, mb := range members {
		if rawString(mb, "stateStr") == "PRIMARY" {
			if v, err := mb.LookupErr("optimeDate"); err == nil {
				primaryOp, _ = v.DateTimeOK()
			}
		}
	}
	lagOf := func(mb bson.Raw) *float64 {
		v, err := mb.LookupErr("optimeDate")
		if err != nil || primaryOp == 0 {
			return nil
		}
		t, ok := v.DateTimeOK()
		if !ok {
			return nil
		}
		return f64(max(0, float64(primaryOp-t)/1000))
	}
	for _, mb := range members {
		state := rawString(mb, "stateStr")
		healthy := rawBool(mb, "health") || rawBool(mb, "self")
		if rawBool(mb, "self") {
			switch state {
			case "PRIMARY":
				s.Role = "primary"
			case "SECONDARY", "RECOVERING", "STARTUP2":
				s.Role = "replica"
				s.ReadOnly = true
				src := &DatabaseSource{
					Address:    rawString(mb, "syncSourceHost"),
					Running:    state == "SECONDARY",
					LagSeconds: lagOf(mb),
				}
				if state != "SECONDARY" {
					src.Error = "Member is " + strings.ToLower(state)
				}
				s.Replication.Source = src
			}
			continue
		}
		r := DatabaseReplica{
			Name:    rawString(mb, "name"),
			Address: rawString(mb, "name"),
			State:   strings.ToLower(state),
			Healthy: healthy && (state == "PRIMARY" || state == "SECONDARY" || state == "ARBITER"),
		}
		if state == "SECONDARY" {
			r.LagSeconds = lagOf(mb)
		}
		if msg := rawString(mb, "lastHeartbeatMessage"); msg != "" && !r.Healthy {
			r.State += " · " + msg
		}
		s.Replication.Replicas = append(s.Replication.Replicas, r)
	}
}

func (m *mongoEngine) activity(ctx context.Context, s *DatabaseSnapshot) {
	cur, err := m.client.Database("admin").Aggregate(ctx, bson.A{
		bson.D{{Key: "$currentOp", Value: bson.D{
			{Key: "allUsers", Value: true},
			{Key: "idleConnections", Value: true},
		}}},
	})
	if err != nil {
		s.note("sessions", "Couldn't list operations ($currentOp needs the clusterMonitor role): "+err.Error())
		return
	}
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		d := cur.Current
		client := rawString(d, "client")
		if client == "" && !strings.HasPrefix(rawString(d, "desc"), "conn") {
			continue // internal thread
		}
		a := DatabaseActivity{
			Client: stripPort(client),
			App:    rawString(d, "appName"),
		}
		if v, err := d.LookupErr("opid"); err == nil {
			if n, ok := v.AsInt64OK(); ok {
				a.ID = strconv.FormatInt(n, 10)
			} else if str, ok := v.StringValueOK(); ok {
				a.ID = str
			}
		}
		a.Ours = a.App == mongoAppName
		if users := rawDocs(d, "effectiveUsers"); len(users) > 0 {
			a.User = rawString(users[0], "user")
		}
		if ns := rawString(d, "ns"); ns != "" {
			a.Database, _, _ = strings.Cut(ns, ".")
		}
		active := rawBool(d, "active") && rawString(d, "op") != "none"
		_, inTx := d.LookupErr("transaction")
		switch {
		case active:
			a.State = "active"
			if us := rawInt(d, "microsecs_running"); us != nil {
				a.Seconds = f64(float64(*us) / 1e6)
			}
			if cmd, err := d.LookupErr("command"); err == nil {
				if b, err := bson.MarshalExtJSON(cmd.Document(), false, false); err == nil {
					a.Query = truncate(string(b), queryLimit)
				}
			}
		case inTx == nil:
			a.State = "idle_in_tx"
		default:
			a.State = "idle"
		}
		if us := rawInt(d, "transaction", "timeOpenMicros"); us != nil {
			a.TxSeconds = f64(float64(*us) / 1e6)
		}
		if rawBool(d, "waitingForLock") {
			a.Wait = "Lock"
		} else if rawBool(d, "waitingForFlowControl") {
			a.Wait = "Flow control"
		}
		s.all = append(s.all, a)
	}
}

func (m *mongoEngine) heavy(ctx context.Context, s *DatabaseSnapshot) error {
	ld, err := m.run(ctx, "admin", bson.D{{Key: "listDatabases", Value: 1}})
	if err != nil {
		return err
	}
	var total int64
	for _, d := range rawDocs(ld, "databases") {
		info := DatabaseInfo{Name: rawString(d, "name"), SizeBytes: rawInt(d, "sizeOnDisk")}
		total += deref(info.SizeBytes)
		s.Databases = append(s.Databases, info)
	}
	s.SizeBytes = &total
	sort.SliceStable(s.Databases, func(i, j int) bool {
		return deref(s.Databases[i].SizeBytes) > deref(s.Databases[j].SizeBytes)
	})

	read := 0
	for i := range s.Databases {
		d := &s.Databases[i]
		if i >= 20 {
			break
		}
		st, err := m.run(ctx, d.Name, bson.D{{Key: "dbStats", Value: 1}, {Key: "scale", Value: 1}})
		if err != nil {
			continue
		}
		d.Tables = rawInt(st, "collections")
		if s.Disk == nil {
			used, size := rawInt(st, "fsUsedSize"), rawInt(st, "fsTotalSize")
			if used != nil && size != nil && *size > 0 {
				s.Disk = &DatabaseDisk{TotalBytes: *size, FreeBytes: *size - *used, Source: "engine"}
			}
		}
		if d.Name == "local" || d.Name == "config" || d.Name == "admin" || read == 5 {
			continue
		}
		read++
		if err := m.collections(ctx, d.Name, s); err != nil {
			s.note("tables", fmt.Sprintf("Couldn't read collections in %s: %v", d.Name, err))
		}
	}
	sortTables(s)

	m.oplog(ctx, s)
	m.cmdLine(ctx, s)
	m.users(ctx, s)
	if s.Disk != nil {
		s.Disk.Path = s.DataDir
	}
	s.note("queries", "MongoDB keeps no running totals per query. Slow operations show in the database's profiler (db.setProfilingLevel(1)) and its log.")
	return nil
}

// collections reads the largest collections of one database and their
// unused indexes.
func (m *mongoEngine) collections(ctx context.Context, name string, s *DatabaseSnapshot) error {
	db := m.client.Database(name)
	names, err := db.ListCollectionNames(ctx, bson.D{{Key: "type", Value: "collection"}})
	if err != nil {
		return err
	}
	if len(names) > 50 {
		names = names[:50]
	}
	for _, c := range names {
		if strings.HasPrefix(c, "system.") {
			continue
		}
		st, err := db.RunCommand(ctx, bson.D{{Key: "collStats", Value: c}}).Raw()
		if err != nil {
			continue
		}
		storage, indexes := deref(rawInt(st, "storageSize")), deref(rawInt(st, "totalIndexSize"))
		t := DatabaseTable{
			Database: name, Name: c,
			SizeBytes:  storage + indexes,
			IndexBytes: &indexes,
			Rows:       rawInt(st, "count"),
			FreeBytes:  rawInt(st, "freeStorageSize"),
		}
		s.Tables = append(s.Tables, t)

		cur, err := db.Collection(c).Aggregate(ctx, bson.A{bson.D{{Key: "$indexStats", Value: bson.D{}}}})
		if err != nil {
			continue
		}
		for cur.Next(ctx) {
			ix := rawString(cur.Current, "name")
			if ix == "_id_" || deref(rawInt(cur.Current, "accesses", "ops")) > 0 {
				continue
			}
			s.Indexes = append(s.Indexes, DatabaseIndex{
				Database: name, Table: c, Name: ix,
				SizeBytes: rawInt(st, "indexSizes", ix),
			})
		}
		cur.Close(ctx)
	}
	return nil
}

func (m *mongoEngine) oplog(ctx context.Context, s *DatabaseSnapshot) {
	local := m.client.Database("local")
	st, err := local.RunCommand(ctx, bson.D{{Key: "collStats", Value: "oplog.rs"}}).Raw()
	if err != nil {
		return
	}
	l := &DatabaseLog{Kind: "Oplog", SizeBytes: rawInt(st, "size")}
	if size, maxSize := rawFloat(st, "size"), rawFloat(st, "maxSize"); size != nil && maxSize != nil && *maxSize > 0 {
		l.UsedRatio = clamp01(*size / *maxSize)
	}
	ts := func(dir int) (uint32, bool) {
		var doc bson.Raw
		err := local.Collection("oplog.rs").FindOne(ctx, bson.D{},
			options.FindOne().SetSort(bson.D{{Key: "$natural", Value: dir}}).SetProjection(bson.D{{Key: "ts", Value: 1}}),
		).Decode(&doc)
		if err != nil {
			return 0, false
		}
		v, err := doc.LookupErr("ts")
		if err != nil {
			return 0, false
		}
		t, _, ok := v.TimestampOK()
		return t, ok
	}
	first, ok1 := ts(1)
	last, ok2 := ts(-1)
	if ok1 && ok2 && last >= first {
		l.Window = f64(float64(last-first) / 3600)
	}
	s.Log = l
}

func (m *mongoEngine) cmdLine(ctx context.Context, s *DatabaseSnapshot) {
	r, err := m.run(ctx, "admin", bson.D{{Key: "getCmdLineOpts", Value: 1}})
	if err != nil {
		s.note("settings", "Couldn't read the startup options (getCmdLineOpts): "+err.Error())
		return
	}
	p, ok := r.Lookup("parsed").DocumentOK()
	if !ok {
		return
	}
	s.DataDir = rawString(p, "storage", "dbPath")
	bind := rawString(p, "net", "bindIp")
	if rawBool(p, "net", "bindIpAll") || strings.Contains(bind, "0.0.0.0") || strings.Contains(bind, "::") && !strings.Contains(bind, "::1") {
		s.Security.ListensOn = "*"
	} else {
		s.Security.ListensOn = bind
	}
	auth := rawString(p, "security", "authorization")
	keyFile := rawString(p, "security", "keyFile")
	if auth != "enabled" && keyFile == "" {
		s.Security.AuthDisabled = true
		s.Security.Risks = append(s.Security.Risks,
			"Access control is off (security.authorization): anyone who reaches the port can read and change everything.")
	}
	for _, f := range []struct {
		name string
		path []string
	}{
		{"net.bindIp", []string{"net", "bindIp"}},
		{"net.port", []string{"net", "port"}},
		{"net.tls.mode", []string{"net", "tls", "mode"}},
		{"security.authorization", []string{"security", "authorization"}},
		{"replication.replSetName", []string{"replication", "replSetName"}},
		{"replication.oplogSizeMB", []string{"replication", "oplogSizeMB"}},
		{"storage.dbPath", []string{"storage", "dbPath"}},
		{"storage.wiredTiger.engineConfig.cacheSizeGB", []string{"storage", "wiredTiger", "engineConfig", "cacheSizeGB"}},
		{"operationProfiling.mode", []string{"operationProfiling", "mode"}},
		{"operationProfiling.slowOpThresholdMs", []string{"operationProfiling", "slowOpThresholdMs"}},
	} {
		v, err := p.LookupErr(f.path...)
		if err != nil {
			continue
		}
		val := strings.Trim(v.String(), `"`)
		s.Settings = append(s.Settings, DatabaseSetting{Name: f.name, Value: val})
	}
}

var mongoAdminRoles = map[string]bool{
	"root": true, "userAdminAnyDatabase": true, "dbAdminAnyDatabase": true,
	"clusterAdmin": true, "readWriteAnyDatabase": true, "__system": true,
}

func (m *mongoEngine) users(ctx context.Context, s *DatabaseSnapshot) {
	r, err := m.run(ctx, "admin", bson.D{{Key: "usersInfo", Value: bson.D{{Key: "forAllDBs", Value: true}}}})
	if err != nil {
		s.note("users", "Couldn't list users (needs viewUser): "+err.Error())
		return
	}
	var admins int32
	for _, u := range rawDocs(r, "users") {
		user := DatabaseUser{Name: rawString(u, "user") + "@" + rawString(u, "db")}
		for _, role := range rawDocs(u, "roles") {
			if mongoAdminRoles[rawString(role, "role")] {
				user.Admin = true
			}
		}
		if user.Admin {
			admins++
		}
		s.Users = append(s.Users, user)
	}
	s.Security.Admins = &admins
}

func (m *mongoEngine) kill(ctx context.Context, id string, _ bool) error {
	var op any = id
	if n, err := strconv.ParseInt(id, 10, 64); err == nil {
		op = n
	} else if !strings.Contains(id, ":") {
		return errors.New("not a MongoDB operation id")
	}
	_, err := m.run(ctx, "admin", bson.D{{Key: "killOp", Value: 1}, {Key: "op", Value: op}})
	return err
}

// explain takes a JSON command: {"find": "orders", "filter": {…}} or
// {"aggregate": "orders", "pipeline": […]}, or the short form
// {"collection": "orders", "filter": {…}, "sort": {…}}. It asks for the
// query planner's choice only, which doesn't run the query.
func (m *mongoEngine) explain(ctx context.Context, database, query string) (*DatabasePlan, error) {
	if database == "" {
		return nil, errors.New("pick the database the query runs in")
	}
	var doc bson.D
	if err := bson.UnmarshalExtJSON([]byte(query), false, &doc); err != nil {
		return nil, errors.New(`write the query as JSON, e.g. {"collection": "orders", "filter": {"status": "open"}}`)
	}
	cmd := doc
	if len(doc) > 0 && doc[0].Key == "collection" {
		cmd = bson.D{{Key: "find", Value: doc[0].Value}}
		for _, e := range doc[1:] {
			cmd = append(cmd, e)
		}
	}
	if len(cmd) == 0 {
		return nil, errors.New("empty query")
	}
	switch cmd[0].Key {
	case "find", "aggregate", "count", "distinct":
	default:
		return nil, errors.New(`start with "find", "aggregate", "count", "distinct" or "collection"`)
	}
	r, err := m.run(ctx, database, bson.D{
		{Key: "explain", Value: cmd},
		{Key: "verbosity", Value: "queryPlanner"},
	})
	if err != nil {
		return nil, err
	}
	planner, err := r.LookupErr("queryPlanner")
	if err != nil {
		// Aggregations nest it under the first stage.
		planner, err = r.LookupErr("stages")
	}
	out := r
	if err == nil {
		if d, ok := planner.DocumentOK(); ok {
			out = d
		}
	}
	b, err := bson.MarshalExtJSONIndent(out, false, false, "", "  ")
	if err != nil {
		return nil, err
	}
	plan := &DatabasePlan{Format: "json", Plan: string(b), Warnings: []string{}}
	text := string(b)
	if strings.Contains(text, `"COLLSCAN"`) {
		plan.Warnings = append(plan.Warnings, "The plan reads the whole collection (COLLSCAN). An index on the filtered fields may help.")
	}
	if strings.Contains(text, `"SORT"`) {
		plan.Warnings = append(plan.Warnings, "Sorts in memory (SORT stage). An index matching the sort avoids it.")
	}
	return plan, nil
}
