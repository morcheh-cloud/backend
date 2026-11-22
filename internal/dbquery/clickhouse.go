package dbquery

import (
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"

	"github.com/morche/backend/internal/dbmon"
)

// chClient is the explorer on ClickHouse. It has no transactions, so reads
// are made safe by the server's readonly = 2 (settings may still change, data
// can't) and changes run one statement after another.
type chClient struct {
	db       *sql.DB
	database string // the one this handle is on ('' = the connection's own)
	def      string
	readonly int // the login's own readonly level: 1 = no settings may be sent
}

func openClickHouse(ctx context.Context, cfg dbmon.Config, name string) (*chClient, error) {
	db, err := dbmon.OpenClickHouse(ctx, cfg, name, app)
	if err != nil {
		return nil, err
	}
	c := &chClient{db: db, database: name, def: cfg.Database}
	var lvl string
	if err := db.QueryRowContext(ctx, `SELECT toString(getSetting('readonly'))`).Scan(&lvl); err == nil {
		c.readonly, _ = strconv.Atoi(lvl)
	}
	return c, nil
}

func (c *chClient) Close() error { return c.db.Close() }

var chSystem = map[string]bool{"system": true, "INFORMATION_SCHEMA": true, "information_schema": true}

func chQuote(name string) string {
	return "`" + strings.NewReplacer(`\`, `\\`, "`", "\\`").Replace(name) + "`"
}

// chLiteral is a string literal; ClickHouse reads backslash escapes in it.
func chLiteral(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

// chValue is a value given as text, read as the column's type (NULL bare).
func chValue(v *string, typ string) string {
	if v == nil {
		return "NULL"
	}
	if typ == "" || typ == "String" {
		return chLiteral(*v)
	}
	return "CAST(" + chLiteral(*v) + ", " + chLiteral(typ) + ")"
}

func chLikeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// current is the database a request means.
func (c *chClient) current(ctx context.Context, database string) string {
	if database != "" {
		return database
	}
	if c.database != "" {
		return c.database
	}
	var cur string
	if err := c.db.QueryRowContext(ctx, `SELECT currentDatabase()`).Scan(&cur); err == nil && cur != "" {
		return cur
	}
	if c.def != "" {
		return c.def
	}
	return "default"
}

func (c *chClient) table(database, name string) string {
	return chQuote(database) + "." + chQuote(name)
}

// settings are sent with every statement: read = readonly 2 unless the
// login is read only already; a time limit unless it may not change any.
func (c *chClient) settings(change bool, d time.Duration) clickhouse.Settings {
	s := clickhouse.Settings{}
	if c.readonly == 1 {
		return s
	}
	if !change && c.readonly == 0 {
		s["readonly"] = 2
	}
	if d > 0 {
		s["max_execution_time"] = max(1, int(d.Seconds()))
	}
	return s
}

func chKind(engine string) string {
	switch engine {
	case "View", "LiveView", "WindowView":
		return "view"
	case "MaterializedView":
		return "materialized_view"
	case "Dictionary":
		return "dictionary"
	}
	return "table"
}

func (c *chClient) Overview(ctx context.Context, database string) (*DatabaseOverview, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	o := &DatabaseOverview{Engine: dbmon.ClickHouse, Databases: []string{}, Schemas: []string{}, Objects: []DatabaseObject{}, Notes: []string{}}
	o.Database = c.current(ctx, database)
	if rows, err := queryStrings(ctx, c.db, `SELECT name FROM system.databases
		ORDER BY name IN ('system', 'INFORMATION_SCHEMA', 'information_schema'), name`); err != nil {
		o.Notes = append(o.Notes, "Couldn't read the list of databases: "+err.Error())
	} else {
		for _, r := range rows {
			o.Databases = append(o.Databases, r[0].String)
		}
	}
	rows, err := queryStrings(ctx, c.db, `SELECT name, engine, toString(total_rows), toString(total_bytes)
		FROM system.tables WHERE database = `+chLiteral(o.Database)+` AND NOT is_temporary
		ORDER BY name LIMIT 5001`)
	if err != nil {
		o.Notes = append(o.Notes, "Couldn't read tables: "+err.Error())
		return o, nil
	}
	for i, r := range rows {
		if i >= maxObjects {
			o.Capped = true
			break
		}
		kind := chKind(r[1].String)
		obj := DatabaseObject{Name: r[0].String, Kind: kind}
		if kind == "table" || kind == "materialized_view" {
			obj.Rows, obj.Bytes = nInt(r[2]), nInt(r[3])
		}
		o.Objects = append(o.Objects, obj)
	}
	return o, nil
}

// chColumn is a column as system.columns tells it.
type chColumn struct {
	name, typ, defaultKind, defaultExpr, comment, codec string
	primary, sorting, partition                         bool
}

func (c *chClient) columns(ctx context.Context, database, table string) ([]chColumn, error) {
	rows, err := queryStrings(ctx, c.db, `SELECT name, type, default_kind, default_expression, comment, compression_codec,
			toString(is_in_primary_key), toString(is_in_sorting_key), toString(is_in_partition_key)
		FROM system.columns WHERE database = `+chLiteral(database)+` AND table = `+chLiteral(table)+` ORDER BY position`)
	if err != nil {
		return nil, err
	}
	out := make([]chColumn, 0, len(rows))
	for _, r := range rows {
		out = append(out, chColumn{name: r[0].String, typ: r[1].String, defaultKind: r[2].String, defaultExpr: r[3].String,
			comment: r[4].String, codec: r[5].String, primary: r[6].String == "1", sorting: r[7].String == "1", partition: r[8].String == "1"})
	}
	return out, nil
}

// splitTop cuts an expression list on commas outside brackets and quotes.
func splitTop(s string) []string {
	var out []string
	depth, start := 0, 0
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		switch rs[i] {
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		case '\'', '`', '"':
			i = skipQuoted(rs, i, rs[i], true) - 1
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(string(rs[start:i])))
				start = i + 1
			}
		}
	}
	if t := strings.TrimSpace(string(rs[start:])); t != "" {
		out = append(out, t)
	}
	return out
}

func unquoteName(s string) string {
	if len(s) >= 2 && (s[0] == '`' || s[0] == '"') && s[len(s)-1] == s[0] {
		return strings.NewReplacer(`\\`, `\`, "\\`", "`", `\"`, `"`).Replace(s[1 : len(s)-1])
	}
	return s
}

var chTTL = regexp.MustCompile(`(?s)\bTTL\s+(.*?)(?:\s+SETTINGS\s|$)`)

// chEditable: only the MergeTree family changes rows in place.
func chReadOnly(database, engine, kind string) string {
	switch {
	case chSystem[database]:
		return "System tables can't be changed."
	case kind != "table":
		return ""
	case strings.HasSuffix(engine, "MergeTree"):
		return ""
	}
	return fmt.Sprintf("The %s engine can't add, change or remove rows one by one here. Use the Query tab.", engine)
}

func (c *chClient) Describe(ctx context.Context, database, _ string, name string) (*ObjectInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	db := c.current(ctx, database)
	rows, err := queryStrings(ctx, c.db, `SELECT engine, engine_full, sorting_key, primary_key, partition_key, sampling_key,
			create_table_query, toString(total_rows), toString(total_bytes), comment
		FROM system.tables WHERE database = `+chLiteral(db)+` AND name = `+chLiteral(name))
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	t := rows[0]
	engine := t[0].String
	info := &ObjectInfo{Name: name, Kind: chKind(engine), Columns: []ObjectColumn{}, Key: []string{}, Indexes: []ObjectIndex{}, Constraints: []ObjectConstraint{}}
	cols, err := c.columns(ctx, db, name)
	if err != nil {
		return nil, err
	}
	if len(cols) == 0 {
		return nil, ErrNotFound
	}
	names := map[string]bool{}
	for _, col := range cols {
		names[col.name] = true
		oc := ObjectColumn{Name: col.name, Type: col.typ, Comment: col.comment,
			Nullable: strings.HasPrefix(col.typ, "Nullable(") || strings.HasPrefix(col.typ, "LowCardinality(Nullable(")}
		if col.defaultKind != "" {
			oc.Default = ptr(col.defaultExpr)
			if col.defaultKind != "DEFAULT" {
				oc.Extra = strings.ToLower(col.defaultKind)
			}
		}
		if col.codec != "" {
			if oc.Extra != "" {
				oc.Extra += ", "
			}
			oc.Extra += col.codec
		}
		info.Columns = append(info.Columns, oc)
	}
	for _, k := range splitTop(t[3].String) {
		if k = unquoteName(k); names[k] {
			info.Key = append(info.Key, k)
		}
	}
	keys := map[string]bool{}
	for _, k := range info.Key {
		keys[k] = true
	}
	for i := range info.Columns {
		info.Columns[i].Key = keys[info.Columns[i].Name]
	}
	if t[3].String != "" {
		info.Indexes = append(info.Indexes, ObjectIndex{Name: "PRIMARY KEY", Definition: "(" + t[3].String + ")", Primary: true})
	}
	if rows, err := queryStrings(ctx, c.db, `SELECT name, type_full, expr, toString(granularity) FROM system.data_skipping_indices
		WHERE database = `+chLiteral(db)+` AND table = `+chLiteral(name)+` ORDER BY name`); err == nil {
		for _, r := range rows {
			info.Indexes = append(info.Indexes, ObjectIndex{Name: r[0].String, Definition: r[2].String + " TYPE " + r[1].String + " GRANULARITY " + r[3].String})
		}
	}
	if rows, err := queryStrings(ctx, c.db, `SHOW CREATE TABLE `+c.table(db, name)); err == nil && len(rows) > 0 {
		info.Definition = rows[0][0].String
	} else {
		info.Definition = t[6].String
	}
	fact := func(label, value string) {
		if value != "" {
			info.Facts = append(info.Facts, ObjectFact{Label: label, Value: value})
		}
	}
	fact("Engine", engine)
	fact("Sorting key", t[2].String)
	if t[3].String != t[2].String {
		fact("Primary key", t[3].String)
	}
	fact("Partition key", t[4].String)
	fact("Sampling key", t[5].String)
	if m := chTTL.FindStringSubmatch(t[1].String); m != nil {
		fact("TTL", strings.TrimSpace(m[1]))
	}
	if strings.HasSuffix(engine, "MergeTree") {
		if rows, err := queryStrings(ctx, c.db, `SELECT toString(count()), toString(sum(rows)), formatReadableSize(sum(bytes_on_disk)),
				formatReadableSize(sum(data_uncompressed_bytes)), toString(uniqExact(partition))
			FROM system.parts WHERE active AND database = `+chLiteral(db)+` AND table = `+chLiteral(name)); err == nil && len(rows) > 0 {
			r := rows[0]
			fact("Parts", r[0].String)
			fact("Partitions", r[4].String)
			fact("Rows", r[1].String)
			fact("On disk", r[2].String)
			fact("Uncompressed", r[3].String)
		}
	} else if t[7].Valid {
		fact("Rows", t[7].String)
	}
	fact("Comment", t[9].String)
	info.ReadOnly = chReadOnly(db, engine, info.Kind)
	info.KeyUnique = ptr(false)
	return info, nil
}

// Rows reads a page with filters. Values come back as ClickHouse writes them
// (toString), so arrays, maps and tuples read back the same way when edited.
func (c *chClient) Rows(ctx context.Context, req RowsRequest) (*RowsPage, error) {
	if req.Table == "" {
		return nil, refused("Pick a table.")
	}
	limit := limitOf(req.Limit, defaultLimit, 1000)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	db := c.current(ctx, req.Database)
	cols, err := c.columns(ctx, db, req.Table)
	if err != nil {
		return nil, err
	}
	if len(cols) == 0 {
		return nil, ErrNotFound
	}
	types := map[string]string{}
	for _, col := range cols {
		types[col.name] = col.typ
	}
	from := c.table(db, req.Table)
	var conds []string
	for _, f := range req.Filters {
		typ, ok := types[f.Column]
		if !ok {
			return nil, refused("%s has no column %q.", req.Table, f.Column)
		}
		conds = append(conds, chFilter(f, typ))
	}
	if s := strings.TrimSpace(req.Search); s != "" {
		var any []string
		p := chLiteral("%" + chLikeEscape(s) + "%")
		for _, col := range cols {
			any = append(any, "toString("+chQuote(col.name)+") ILIKE "+p)
		}
		conds = append(conds, "("+strings.Join(any, " OR ")+")")
	}
	join := " AND "
	if req.Match == "any" {
		join = " OR "
	}
	where := ""
	if len(conds) > 0 {
		where = "(" + strings.Join(conds, join) + ")"
	}
	if w := strings.TrimSpace(req.Where); w != "" {
		if len(Split(dbmon.ClickHouse, w)) > 1 {
			return nil, refused("The condition can't hold more than one statement.")
		}
		if err := checkRead(dbmon.ClickHouse, "SELECT 1 WHERE "+w); err != nil {
			return nil, err
		}
		if where != "" {
			where += " AND "
		}
		where += "(" + w + ")"
	}
	if where != "" {
		where = " WHERE " + where
	}
	var order []string
	for _, s := range req.Sort {
		dir := " ASC"
		if s.Desc {
			dir = " DESC"
		}
		order = append(order, chQuote(s.Column)+dir)
	}
	orderBy := ""
	if len(order) > 0 {
		orderBy = " ORDER BY " + strings.Join(order, ", ")
	}
	sel := make([]string, len(cols))
	for i, col := range cols {
		// Not aliased to its own name: ClickHouse would then filter and sort
		// on the text.
		sel[i] = "toString(" + chQuote(col.name) + ") AS `__morche_" + strconv.Itoa(i) + "`"
	}
	query := "SELECT " + strings.Join(sel, ", ") + " FROM " + from + where + orderBy + fmt.Sprintf(" LIMIT %d OFFSET %d", limit+1, req.Offset)
	qctx := clickhouse.Context(ctx, clickhouse.WithSettings(c.settings(false, 30*time.Second)))
	start := time.Now()
	rows, err := c.db.QueryContext(qctx, query)
	if err != nil {
		return nil, err
	}
	res, err := readRows(rows, limit)
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range res.Columns {
		res.Columns[i] = ResultColumn{Name: cols[i].name, Type: cols[i].typ}
	}
	res.Statement = short("SELECT * FROM " + from + where + orderBy + fmt.Sprintf(" LIMIT %d OFFSET %d", limit+1, req.Offset))
	res.Ms = time.Since(start).Milliseconds()
	out := &RowsPage{QueryResult: *res}
	if req.Count {
		if !res.Truncated && req.Offset == 0 {
			out.Total = ptr(int64(len(res.Rows)))
		} else {
			cctx, ccancel := context.WithTimeout(qctx, 10*time.Second)
			var n uint64
			err := c.db.QueryRowContext(cctx, "SELECT count() FROM "+from+where).Scan(&n)
			ccancel()
			if err == nil {
				out.Total = ptr(int64(n))
			}
		}
	}
	return out, nil
}

func chFilter(f RowFilter, typ string) string {
	col := chQuote(f.Column)
	v := func(s string) string { return chValue(&s, typ) }
	like := func(p string) string { return "toString(" + col + ") ILIKE " + chLiteral(p) }
	switch f.Op {
	case "eq":
		return col + " = " + v(f.Value)
	case "ne":
		return "(" + col + " != " + v(f.Value) + " OR " + col + " IS NULL)"
	case "gt":
		return col + " > " + v(f.Value)
	case "gte":
		return col + " >= " + v(f.Value)
	case "lt":
		return col + " < " + v(f.Value)
	case "lte":
		return col + " <= " + v(f.Value)
	case "contains":
		return like("%" + chLikeEscape(f.Value) + "%")
	case "not_contains":
		return "(NOT " + like("%"+chLikeEscape(f.Value)+"%") + " OR " + col + " IS NULL)"
	case "starts":
		return like(chLikeEscape(f.Value) + "%")
	case "ends":
		return like("%" + chLikeEscape(f.Value))
	case "null":
		return col + " IS NULL"
	case "not_null":
		return col + " IS NOT NULL"
	case "in":
		vals := f.Values
		if len(vals) == 0 {
			for _, s := range strings.Split(f.Value, ",") {
				if s = strings.TrimSpace(s); s != "" {
					vals = append(vals, s)
				}
			}
		}
		if len(vals) == 0 {
			return "0"
		}
		ps := make([]string, len(vals))
		for i, s := range vals {
			ps[i] = v(s)
		}
		return col + " IN (" + strings.Join(ps, ", ") + ")"
	}
	return "0"
}

// chReturnsRows: statements read with Query; the rest with Exec (the driver
// breaks the connection when DDL is sent as a query).
func chReturnsRows(st string) bool {
	ws := words(dbmon.ClickHouse, st)
	return len(ws) == 0 || chReadFirst[ws[0]]
}

var runSeq atomic.Uint64

func newRunID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "morche-" + hex.EncodeToString(b)
}

// Run runs a script statement by statement on one connection of its own
// (temporary tables and SET last for the run only). Read only = every
// statement checked and sent with readonly = 2. Stop = the context ends: the
// driver cancels the query and it's also killed by its query_id.
func (c *chClient) Run(ctx context.Context, _ string, script string, o RunOptions) ([]QueryResult, error) {
	stmts := Split(dbmon.ClickHouse, script)
	if len(stmts) == 0 {
		return nil, refused("Type a query first.")
	}
	if len(stmts) > 50 {
		return nil, refused("That's %d statements; run at most 50 at a time.", len(stmts))
	}
	if !o.Change {
		for _, s := range stmts {
			if err := checkRead(dbmon.ClickHouse, s); err != nil {
				return nil, err
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	conn, err := c.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		_ = conn.Close()
	}()
	settings := c.settings(o.Change, o.Timeout)
	if o.Change && c.readonly != 1 {
		settings["mutations_sync"] = 2
	}
	runID := newRunID()
	var out []QueryResult
	for _, st := range stmts {
		qid := runID + "-" + strconv.FormatUint(runSeq.Add(1), 10)
		var wrote uint64
		qctx := clickhouse.Context(ctx, clickhouse.WithSettings(settings), clickhouse.WithQueryID(qid),
			clickhouse.WithProgress(func(p *clickhouse.Progress) { wrote += p.WroteRows }))
		start := time.Now()
		r, err := c.one(qctx, conn, st, o.Limit, &wrote)
		if err != nil {
			if ctx.Err() != nil {
				c.kill(qid)
				err = ctx.Err()
			}
			err = chError(err)
			if len(stmts) > 1 {
				return out, fmt.Errorf("statement %d (%s): %w", len(out)+1, short(st), err)
			}
			return out, err
		}
		r.Ms = time.Since(start).Milliseconds()
		out = append(out, *r)
	}
	return out, nil
}

// kill stops a query the server may still be running after a cancel.
func (c *chClient) kill(qid string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = c.db.ExecContext(ctx, "KILL QUERY WHERE query_id = "+chLiteral(qid)+" ASYNC")
	}()
}

// chError says plainly what readonly refused.
func chError(err error) error {
	if dbmon.ClickHouseCode(err) == 164 {
		return refused("This changes something, and the query ran read only. Turn on Allow changes to run it. (%v)", err)
	}
	return err
}

func (c *chClient) one(ctx context.Context, conn *sql.Conn, st string, limit int, wrote *uint64) (*QueryResult, error) {
	if !chReturnsRows(st) {
		if _, err := conn.ExecContext(ctx, st); err != nil {
			return nil, err
		}
		r := &QueryResult{Statement: short(st), Columns: []ResultColumn{}, Rows: [][]*string{}, Message: "Done"}
		if *wrote > 0 {
			r.Affected = ptr(int64(*wrote))
		}
		return r, nil
	}
	rows, err := conn.QueryContext(ctx, st)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	r, err := readRows(rows, limit)
	if err != nil {
		return nil, err
	}
	r.Statement = short(st)
	return r, nil
}

// Edit adds rows to a MergeTree table and changes or removes them by the
// table's primary key. ClickHouse keys needn't be unique and nothing is
// transactional, so every change or removal is first counted: unless each
// matches exactly one row nothing runs. Then they run one by one (a failure
// leaves the ones before it done). Updates are ALTER TABLE … UPDATE and
// removals lightweight DELETEs, both waited for, so the next read sees them.
func (c *chClient) Edit(ctx context.Context, r EditRequest) (*EditResult, error) {
	info, err := c.Describe(ctx, r.Database, r.Schema, r.Table)
	if err != nil {
		return nil, err
	}
	if info.Kind != "table" {
		return nil, refused("%s is a %s; only tables can be changed here.", r.Table, strings.ReplaceAll(info.Kind, "_", " "))
	}
	if info.ReadOnly != "" {
		return nil, refused("%s", info.ReadOnly)
	}
	db := c.current(ctx, r.Database)
	cols, err := c.columns(ctx, db, r.Table)
	if err != nil {
		return nil, err
	}
	byName := map[string]chColumn{}
	var order []string
	for _, col := range cols {
		byName[col.name] = col
		order = append(order, col.name)
	}
	sorted := func(m map[string]*string, update bool) ([]string, error) {
		var names []string
		for n := range m {
			col, ok := byName[n]
			if !ok {
				return nil, refused("%s has no column %q.", r.Table, n)
			}
			switch col.defaultKind {
			case "MATERIALIZED", "ALIAS":
				return nil, refused("%s is worked out by ClickHouse (%s); it can't be set.", n, strings.ToLower(col.defaultKind))
			}
			if update && (col.sorting || col.primary || col.partition) {
				what := "sorting key"
				if col.partition {
					what = "partition key"
				}
				return nil, refused("%s is part of the table's %s, which ClickHouse can't change in place. Remove the row and add it again instead.", n, what)
			}
			names = append(names, n)
		}
		slices.SortFunc(names, func(a, b string) int { return slices.Index(order, a) - slices.Index(order, b) })
		return names, nil
	}
	table := c.table(db, r.Table)

	type chStmt struct {
		sql, where string
		one        bool
	}
	var stmts []chStmt
	for i, ch := range r.Changes {
		where := func() (string, error) {
			if len(info.Key) == 0 {
				return "", refused("%s has no primary key (ORDER BY tuple()), so a row can't be told apart safely. Change it with a query in the Query tab.", r.Table)
			}
			var parts []string
			for _, k := range info.Key {
				v, ok := ch.Key[k]
				if !ok || v == nil {
					return "", refused("Row %d: the key column %s is missing.", i+1, k)
				}
				parts = append(parts, chQuote(k)+" = "+chValue(v, byName[k].typ))
			}
			return " WHERE " + strings.Join(parts, " AND "), nil
		}
		switch ch.Op {
		case "insert":
			names, err := sorted(ch.Values, false)
			if err != nil {
				return nil, err
			}
			if len(names) == 0 {
				return nil, refused("Row %d: give at least one column a value.", i+1)
			}
			quoted := make([]string, len(names))
			vals := make([]string, len(names))
			for j, n := range names {
				quoted[j] = chQuote(n)
				vals[j] = chValue(ch.Values[n], byName[n].typ)
			}
			stmts = append(stmts, chStmt{sql: "INSERT INTO " + table + " (" + strings.Join(quoted, ", ") + ") VALUES (" + strings.Join(vals, ", ") + ")"})
		case "update":
			names, err := sorted(ch.Values, true)
			if err != nil {
				return nil, err
			}
			if len(names) == 0 {
				continue
			}
			w, err := where()
			if err != nil {
				return nil, err
			}
			sets := make([]string, len(names))
			for j, n := range names {
				sets[j] = chQuote(n) + " = " + chValue(ch.Values[n], byName[n].typ)
			}
			stmts = append(stmts, chStmt{sql: "ALTER TABLE " + table + " UPDATE " + strings.Join(sets, ", ") + w, where: w, one: true})
		case "delete":
			w, err := where()
			if err != nil {
				return nil, err
			}
			stmts = append(stmts, chStmt{sql: "DELETE FROM " + table + w, where: w, one: true})
		default:
			return nil, refused("unknown change %q", ch.Op)
		}
	}
	out := &EditResult{Statements: make([]string, len(stmts))}
	for i, s := range stmts {
		out.Statements[i] = s.sql + ";"
	}
	if r.Preview || len(stmts) == 0 {
		return out, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	settings := c.settings(true, 60*time.Second)
	if c.readonly != 1 {
		settings["mutations_sync"] = 2
		settings["lightweight_deletes_sync"] = 2
	}
	qctx := clickhouse.Context(ctx, clickhouse.WithSettings(settings))
	start := time.Now()
	for i, s := range stmts {
		if !s.one {
			continue
		}
		var n uint64
		if err := c.db.QueryRowContext(qctx, "SELECT count() FROM "+table+s.where).Scan(&n); err != nil {
			return nil, fmt.Errorf("row %d: %w", i+1, err)
		}
		switch {
		case n == 0:
			return nil, refused("Row %d was changed or removed since you read it. Nothing was saved; read the rows again.", i+1)
		case n > 1:
			return nil, refused("Row %d: %d rows share its key (%s), and ClickHouse keys don't have to be unique. Nothing was saved; change them with a query in the Query tab.", i+1, n, strings.Join(info.Key, ", "))
		}
	}
	for i, s := range stmts {
		if _, err := c.db.ExecContext(qctx, s.sql); err != nil {
			if i > 0 {
				return out, fmt.Errorf("row %d: %w (the rows before it were saved)", i+1, err)
			}
			return out, fmt.Errorf("row %d: %w", i+1, err)
		}
		out.Affected++
	}
	out.Ran = true
	out.Ms = time.Since(start).Milliseconds()
	return out, nil
}
