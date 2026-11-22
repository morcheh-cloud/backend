package dbsync

// ClickHouse as a sync end. It has no transactions, no row-level UPDATE and
// no unique keys, so:
//   - a table's key is its ORDER BY when the engine is a ReplacingMergeTree
//     (one row per key once merged; read with FINAL), else none (only full
//     copies, unless the sync names a key);
//   - a changed row is deleted (lightweight DELETE) and inserted again;
//   - rows go in through the driver's batch insert, one block per batch;
//   - a full copy loads a fresh copy of the table and swaps it in with
//     EXCHANGE TABLES, so readers never see it half empty.
//
// A ClickHouse target can also take rows from PostgreSQL or MySQL/MariaDB
// (analytics copies). Values are then compared in one canonical text form
// per target type (see canonFor), since the two databases print numbers,
// times and booleans differently.

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const ClickHouse Dialect = "clickhouse"

// chBase strips the Nullable and LowCardinality wrappers off a type.
func chBase(t string) string {
	for {
		switch {
		case strings.HasPrefix(t, "Nullable(") && strings.HasSuffix(t, ")"):
			t = t[len("Nullable(") : len(t)-1]
		case strings.HasPrefix(t, "LowCardinality(") && strings.HasSuffix(t, ")"):
			t = t[len("LowCardinality(") : len(t)-1]
		default:
			return t
		}
	}
}

// chName is the type's name without arguments: DateTime64(6, 'UTC') → DateTime64.
func chName(t string) string {
	b := chBase(t)
	if i := strings.IndexByte(b, '('); i >= 0 {
		return b[:i]
	}
	return b
}

func chInt(n string) bool {
	switch n {
	case "Int8", "Int16", "Int32", "Int64", "Int128", "Int256",
		"UInt8", "UInt16", "UInt32", "UInt64", "UInt128", "UInt256":
		return true
	}
	return false
}

func chDecimal(n string) bool { return strings.HasPrefix(n, "Decimal") }
func chFloat(n string) bool   { return n == "Float32" || n == "Float64" || n == "BFloat16" }
func chTime(n string) bool    { return n == "DateTime" || n == "DateTime64" }

func chKind(t string) string {
	n := chName(t)
	switch {
	case chInt(n), chDecimal(n), chFloat(n):
		return KindNumber
	case n == "String" || n == "FixedString":
		return KindText
	case chTime(n) || n == "Date" || n == "Date32":
		return KindTime
	}
	return KindOther
}

// chWritable says whether rows of this type can be written from text.
// Arrays, maps, tuples, JSON and the like can't: such columns are left out.
func chWritable(t string) bool {
	n := chName(t)
	switch {
	case chInt(n), chDecimal(n), chFloat(n), chTime(n):
		return true
	}
	switch n {
	case "Bool", "String", "FixedString", "UUID", "Date", "Date32", "Enum8", "Enum16", "IPv4", "IPv6":
		return true
	}
	return false
}

// chSel reads a column as text; times always in UTC.
func chSel(c Column) string {
	q := ClickHouse.quote(c.Name)
	if chTime(chName(c.Type)) {
		return "toString(" + q + ", 'UTC')"
	}
	return "toString(" + q + ")"
}

// chOrd: UUIDs sort by their halves in ClickHouse, not as text; sorting the
// text keeps the order the same as on the other side.
func chOrd(c Column) string {
	if chName(c.Type) == "UUID" {
		return "toString(" + ClickHouse.quote(c.Name) + ")"
	}
	return ClickHouse.quote(c.Name)
}

func chParam(c Column) string {
	n := chName(c.Type)
	switch {
	case chTime(n):
		return "parseDateTime64BestEffort(?, 9, 'UTC')"
	case n == "String" || n == "FixedString" || strings.HasPrefix(n, "Enum"):
		return "?"
	}
	return "CAST(? AS " + chBase(c.Type) + ")"
}

func chParamOrd(c Column) string {
	if c.Kind == KindText || chName(c.Type) == "UUID" {
		return "?"
	}
	return chParam(c)
}

// chValue turns a value read as text into what the driver's batch takes for
// the column's type.
func chValue(typ string, v sql.NullString) (any, error) {
	if !v.Valid {
		if !strings.Contains(typ, "Nullable(") {
			return nil, fmt.Errorf("NULL in a column that can't hold NULL (%s)", typ)
		}
		return nil, nil
	}
	s := v.String
	n := chName(typ)
	switch {
	case n == "Int128" || n == "Int256" || n == "UInt128" || n == "UInt256":
		b, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return nil, fmt.Errorf("%q isn't a whole number", s)
		}
		return b, nil
	case strings.HasPrefix(n, "UInt"):
		return strconv.ParseUint(s, 10, 64)
	case strings.HasPrefix(n, "Int"):
		return strconv.ParseInt(s, 10, 64)
	case chFloat(n):
		return strconv.ParseFloat(s, 64)
	case n == "Bool":
		switch strings.ToLower(s) {
		case "t", "true", "1", "y", "yes", "on":
			return true, nil
		case "f", "false", "0", "n", "no", "off":
			return false, nil
		}
		return nil, fmt.Errorf("%q isn't true or false", s)
	case n == "Date" || n == "Date32":
		t, ok := parseTime(s)
		if !ok {
			return nil, fmt.Errorf("%q isn't a date", s)
		}
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC), nil
	case chTime(n):
		t, ok := parseTime(s)
		if !ok {
			return nil, fmt.Errorf("%q isn't a date and time", s)
		}
		return t.UTC(), nil
	case !chWritable(typ):
		return nil, fmt.Errorf("can't write a %s from text", typ)
	}
	return s, nil // Decimal, String, UUID, Enum, IP: the driver parses them
}

// ---- Comparing values across engines ----

// canonFor is how a value is written before comparing, by the target's
// ClickHouse type, so "12.50" (PostgreSQL) and "12.5" (ClickHouse), or a
// time with and without an offset, count as the same.
func canonFor(typ string) func(string) string {
	n := chName(typ)
	switch {
	case chDecimal(n):
		return func(s string) string {
			if strings.Contains(s, ".") {
				s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
			}
			if s == "-0" {
				s = "0"
			}
			return s
		}
	case chFloat(n):
		return func(s string) string {
			f, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return s
			}
			return strconv.FormatFloat(f, 'g', -1, 64)
		}
	case chTime(n):
		return func(s string) string {
			t, ok := parseTime(s)
			if !ok {
				return s
			}
			return t.UTC().Format("2006-01-02 15:04:05.999999999")
		}
	case n == "Date" || n == "Date32":
		return func(s string) string {
			if len(s) > 10 {
				if t, ok := parseTime(s); ok {
					return t.Format("2006-01-02")
				}
			}
			return s
		}
	case n == "Bool":
		return func(s string) string {
			switch strings.ToLower(s) {
			case "t", "true", "1":
				return "true"
			case "f", "false", "0":
				return "false"
			}
			return s
		}
	}
	return nil
}

// setCanon fills pl.snorm / pl.dnorm when the two ends are different
// engines (the target then is ClickHouse).
func (r *Run) setCanon(pl *plan) {
	if r.Src.Dialect == r.Dst.Dialect {
		return
	}
	pl.snorm = make([]func(string) string, len(pl.cols))
	pl.dnorm = make([]func(string) string, len(pl.cols))
	for i, c := range pl.cols {
		canon := canonFor(pl.dcols[i].Type)
		pl.dnorm[i] = canon
		if r.Src.Dialect == Postgres && c.Kind == KindBinary {
			// bytea reads as \x0a0b…; the target holds the bytes.
			pl.snorm[i] = func(s string) string {
				if b, err := hex.DecodeString(strings.TrimPrefix(s, `\x`)); err == nil && strings.HasPrefix(s, `\x`) {
					return string(b)
				}
				return s
			}
			continue
		}
		pl.snorm[i] = canon
	}
}

func normRows(fns []func(string) string, rows []row) []row {
	if fns == nil {
		return rows
	}
	out := make([]row, len(rows))
	for i, rw := range rows {
		out[i] = normRow(fns, rw)
	}
	return out
}

func normRow(fns []func(string) string, rw row) row {
	if fns == nil || rw == nil {
		return rw
	}
	n := make(row, len(rw))
	for j, v := range rw {
		if v.Valid && fns[j] != nil {
			v.String = fns[j](v.String)
		}
		n[j] = v
	}
	return n
}

// ---- Reading the schema ----

// replacing says reads need FINAL to see one row per key.
func replacing(engine string) bool { return strings.Contains(engine, "ReplacingMergeTree") }

func clickhouseTables(ctx context.Context, db *sql.DB, database string) ([]Table, error) {
	byName := map[string]*Table{}
	var order []string
	sorting := map[string]string{}
	rows, err := db.QueryContext(ctx, `
		SELECT name, engine, sorting_key, toInt64(coalesce(total_rows, 0)), toInt64(coalesce(total_bytes, 0))
		FROM system.tables
		WHERE database = ? AND is_temporary = 0 AND NOT startsWith(name, '.inner')
			AND engine NOT IN ('View', 'MaterializedView', 'LiveView', 'WindowView', 'Dictionary')
		ORDER BY name`, database)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		t := &Table{KeyFrom: "none"}
		var sk string
		if err := rows.Scan(&t.Name, &t.Engine, &sk, &t.Rows, &t.Bytes); err != nil {
			rows.Close()
			return nil, err
		}
		byName[t.Name] = t
		sorting[t.Name] = sk
		order = append(order, t.Name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = db.QueryContext(ctx, `
		SELECT table, name, type, default_kind
		FROM system.columns
		WHERE database = ?
		ORDER BY table, position`, database)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var table, kind string
		var c Column
		if err := rows.Scan(&table, &c.Name, &c.Type, &kind); err != nil {
			rows.Close()
			return nil, err
		}
		c.Nullable = strings.Contains(c.Type, "Nullable(")
		c.Generated = kind == "MATERIALIZED" || kind == "ALIAS" || kind == "EPHEMERAL"
		c.Kind = chKind(c.Type)
		if t := byName[table]; t != nil {
			t.Columns = append(t.Columns, c)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]Table, len(order))
	for i, name := range order {
		t := byName[name]
		t.Sorting = sortingColumns(sorting[name], *t)
		if replacing(t.Engine) && len(t.Sorting) > 0 {
			t.Key, t.KeyFrom = t.Sorting, "sorting"
		}
		out[i] = *t
	}
	return out, nil
}

// sortingColumns splits an ORDER BY into column names; nil when any part is
// an expression (toDate(ts), …), which can't identify a row.
func sortingColumns(key string, t Table) []string {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(key, ",") {
		name := strings.TrimSpace(part)
		if strings.HasPrefix(name, "`") && strings.HasSuffix(name, "`") && len(name) > 1 {
			name = strings.ReplaceAll(name[1:len(name)-1], "``", "`")
		}
		if _, ok := t.column(name); !ok {
			return nil
		}
		out = append(out, name)
	}
	return out
}

// ---- Creating a missing table ----

var chCreateHead = regexp.MustCompile(`^CREATE TABLE [^\n(]+`)

func createClickHouse(ctx context.Context, src, dst Side, t Table, to Ref) (string, error) {
	if src.Dialect == ClickHouse {
		var stmt string
		if err := src.DB.QueryRowContext(ctx, "SHOW CREATE TABLE "+ClickHouse.table(t.Ref)).Scan(&stmt); err != nil {
			return "", err
		}
		loc := chCreateHead.FindStringIndex(stmt)
		if loc == nil {
			return "", fmt.Errorf("unexpected SHOW CREATE TABLE answer")
		}
		stmt = "CREATE TABLE IF NOT EXISTS " + ClickHouse.table(to) + stmt[loc[1]:]
		_, err := dst.DB.ExecContext(ctx, stmt)
		return "", err
	}
	key := map[string]bool{}
	for _, k := range t.Key {
		key[k] = true
	}
	var b strings.Builder
	b.WriteString("CREATE TABLE IF NOT EXISTS " + ClickHouse.table(to) + " (\n")
	first := true
	for _, c := range t.Columns {
		if c.Generated {
			continue
		}
		if !first {
			b.WriteString(",\n")
		}
		first = false
		typ := mapType(src.Dialect, c)
		if c.Nullable && !key[c.Name] {
			typ = "Nullable(" + typ + ")"
		}
		b.WriteString("  " + ClickHouse.quote(c.Name) + " " + typ)
	}
	b.WriteString("\n)")
	note := ""
	if len(t.Key) > 0 {
		keys := make([]string, len(t.Key))
		for i, k := range t.Key {
			keys[i] = ClickHouse.quote(k)
		}
		b.WriteString(" ENGINE = ReplacingMergeTree ORDER BY (" + strings.Join(keys, ", ") + ")")
	} else {
		b.WriteString(" ENGINE = MergeTree ORDER BY tuple()")
		note = "created without a key (MergeTree, ORDER BY tuple()): only full copies work"
	}
	_, err := dst.DB.ExecContext(ctx, b.String())
	return note, err
}

var typeArgs = regexp.MustCompile(`\((\d+)\s*,\s*(\d+)\)`)

// mapType picks a ClickHouse type for a PostgreSQL or MySQL column.
func mapType(d Dialect, c Column) string {
	t := strings.ToLower(c.Type)
	decimal := func() string {
		if m := typeArgs.FindStringSubmatch(t); m != nil {
			if p, _ := strconv.Atoi(m[1]); p >= 1 && p <= 76 {
				return "Decimal(" + m[1] + ", " + m[2] + ")"
			}
		}
		return "Decimal(76, 20)"
	}
	if d == MySQL {
		base := t
		if i := strings.IndexAny(base, "( "); i >= 0 {
			base = base[:i]
		}
		u := ""
		if strings.Contains(t, "unsigned") {
			u = "U"
		}
		switch base {
		case "tinyint":
			return u + "Int8"
		case "smallint", "year":
			if base == "year" {
				return "UInt16"
			}
			return u + "Int16"
		case "mediumint", "int", "integer":
			return u + "Int32"
		case "bigint":
			return u + "Int64"
		case "decimal", "numeric":
			return decimal()
		case "float":
			return "Float32"
		case "double", "real":
			return "Float64"
		case "date":
			return "Date32"
		case "datetime", "timestamp":
			return "DateTime64(6, 'UTC')"
		}
		return "String"
	}
	switch {
	case t == "smallint":
		return "Int16"
	case t == "integer":
		return "Int32"
	case t == "bigint":
		return "Int64"
	case t == "real":
		return "Float32"
	case t == "double precision":
		return "Float64"
	case strings.HasPrefix(t, "numeric"):
		return decimal()
	case t == "boolean":
		return "Bool"
	case t == "uuid":
		return "UUID"
	case t == "date":
		return "Date32"
	case strings.HasPrefix(t, "timestamp"):
		return "DateTime64(6, 'UTC')"
	}
	return "String" // text, json, bytea, arrays, time, interval, inet…
}

// ---- Writes ----

// chFlushAt is how many rows wait before they're sent as one block.
const chFlushAt = 50000

type pending struct {
	rw row
	op string // insert or update
}

// chQueue holds rows for the next block; updates delete the old copies
// first, so the block goes out at once then.
func (r *Run) chQueue(ctx context.Context, pl *plan, inserts, updates []row) error {
	if len(updates) > 0 {
		if err := r.chDelete(ctx, pl, updates); err != nil {
			for _, rw := range updates {
				if stop := r.failed(pl, "update", rw, err); stop != nil {
					return stop
				}
			}
			updates = nil
		}
	}
	for _, rw := range inserts {
		pl.pending = append(pl.pending, pending{rw, "insert"})
	}
	for _, rw := range updates {
		pl.pending = append(pl.pending, pending{rw, "update"})
	}
	if len(updates) > 0 || len(pl.pending) >= chFlushAt {
		return r.chFlush(ctx, pl)
	}
	return nil
}

// chFlush sends the waiting rows. Rows the driver can't convert are failed
// one by one; a block the server refuses is tried again row by row.
func (r *Run) chFlush(ctx context.Context, pl *plan) error {
	list := pl.pending
	pl.pending = nil
	if len(list) == 0 {
		return nil
	}
	var good []pending
	var vals [][]any
	for _, p := range list {
		v, err := r.chValues(pl, p.rw)
		if err != nil {
			if stop := r.failed(pl, p.op, p.rw, err); stop != nil {
				return stop
			}
			continue
		}
		good = append(good, p)
		vals = append(vals, v)
	}
	count := func(ps []pending) {
		for _, p := range ps {
			if p.op == "update" {
				pl.res.Updated++
			} else {
				pl.res.Inserted++
			}
		}
	}
	if len(good) == 0 {
		return nil
	}
	err := r.chBlock(ctx, pl.to.Ref, pl.dcols, vals)
	if err == nil {
		count(good)
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if len(good) > maxFailures*20 {
		// Too many to try one by one (each row would be its own part).
		for _, p := range good {
			if stop := r.failed(pl, p.op, p.rw, err); stop != nil {
				return stop
			}
		}
		return nil
	}
	for i, p := range good {
		if err := r.chBlock(ctx, pl.to.Ref, pl.dcols, vals[i:i+1]); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if stop := r.failed(pl, p.op, p.rw, err); stop != nil {
				return stop
			}
			continue
		}
		count(good[i : i+1])
	}
	return nil
}

func (r *Run) chValues(pl *plan, rw row) ([]any, error) {
	out := make([]any, len(pl.dcols))
	for j, c := range pl.dcols {
		v, err := chValue(c.Type, rw[j])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.Name, err)
		}
		out[j] = v
	}
	return out, nil
}

// chBlock is one batch insert: the driver collects the rows of a prepared
// INSERT and sends them as one block on Commit (no real transaction).
func (r *Run) chBlock(ctx context.Context, to Ref, cols []Column, vals [][]any) error {
	tx, err := r.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, "INSERT INTO "+ClickHouse.table(to)+" ("+ClickHouse.names(cols)+")")
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, v := range vals {
		if _, err := stmt.ExecContext(ctx, v...); err != nil {
			stmt.Close()
			tx.Rollback()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		stmt.Close()
		return err
	}
	return stmt.Close()
}

// chDelete removes rows by key: a lightweight DELETE, else a mutation the
// server waits for.
func (r *Run) chDelete(ctx context.Context, pl *plan, rows []row) error {
	per := min(r.Rules.Batch, 10000)
	for start := 0; start < len(rows); start += per {
		batch := rows[start:min(start+per, len(rows))]
		args := make([]any, 0, len(batch)*len(pl.key))
		for _, t := range batch {
			args = append(args, keyArgs(ClickHouse, pl.dcols, t, pl.key)...)
		}
		where := r.keysWhere(pl, len(batch))
		_, err := r.w.ExecContext(ctx, "DELETE FROM "+ClickHouse.table(pl.to.Ref)+" WHERE "+where, args...)
		if err != nil && ctx.Err() == nil {
			r.logf("lightweight delete on %s refused (%v); using ALTER TABLE … DELETE", pl.to.Ref, err)
			_, err = r.w.ExecContext(ctx, "ALTER TABLE "+ClickHouse.table(pl.to.Ref)+" DELETE WHERE "+where+" SETTINGS mutations_sync = 2", args...)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// chReload loads the whole source into a fresh copy of the target table and
// swaps the two, so the target is never seen empty.
func (r *Run) chReload(ctx context.Context, pl *plan) error {
	sd, dd := r.Src.Dialect, r.Dst.Dialect
	var n, m int64
	if err := r.Src.DB.QueryRowContext(ctx, countSQL(sd, pl.from)).Scan(&n); err != nil {
		return err
	}
	if err := r.Dst.DB.QueryRowContext(ctx, countSQL(dd, pl.to)).Scan(&m); err != nil {
		return err
	}
	pl.res.Read = n
	pl.res.Note = "no key: emptied and copied again"
	if r.DryRun {
		pl.res.Deleted, pl.res.Inserted = m, n
		pl.res.Reloaded = true
		return nil
	}
	tmp := Ref{Name: pl.to.Name + "_morche_reload"}
	into := tmp
	swap := true
	if _, err := r.w.ExecContext(ctx, "DROP TABLE IF EXISTS "+dd.table(tmp)); err != nil {
		return err
	}
	if _, err := r.w.ExecContext(ctx, "CREATE TABLE "+dd.table(tmp)+" AS "+dd.table(pl.to.Ref)); err != nil {
		r.logf("couldn't make a copy of %s to load (%v); emptying it instead", pl.to.Ref, err)
		swap, into = false, pl.to.Ref
		if _, err := r.w.ExecContext(ctx, "TRUNCATE TABLE "+dd.table(pl.to.Ref)); err != nil {
			pl.res.Failures = append(pl.res.Failures, Failure{Op: "reload", Error: firstLine(err.Error())})
			return fmt.Errorf("couldn't empty the target table: %w", err)
		}
	}
	dropTmp := func() {
		if swap {
			c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			r.w.ExecContext(c, "DROP TABLE IF EXISTS "+dd.table(tmp))
		}
	}
	rows, err := r.Src.DB.QueryContext(ctx, "SELECT "+sd.list(pl.cols)+" FROM "+sd.from(pl.from))
	if err != nil {
		dropTmp()
		return err
	}
	defer rows.Close()
	var vals [][]any
	var written int64
	flush := func() error {
		if len(vals) == 0 {
			return nil
		}
		if err := r.chBlock(ctx, into, pl.dcols, vals); err != nil {
			pl.res.Failures = append(pl.res.Failures, Failure{Op: "reload", Error: firstLine(err.Error())})
			return fmt.Errorf("the target refused rows: %w", err)
		}
		written += int64(len(vals))
		vals = vals[:0]
		if r.Progress != nil {
			r.Progress(pl.from.String(), pl.index, pl.all, written, n)
		}
		return nil
	}
	per := max(r.Rules.Batch, chFlushAt)
	for rows.Next() {
		rw := make(row, len(pl.cols))
		dest := make([]any, len(rw))
		for i := range rw {
			dest[i] = &rw[i]
		}
		if err := rows.Scan(dest...); err != nil {
			dropTmp()
			return err
		}
		v, err := r.chValues(pl, normRow(pl.snorm, rw))
		if err != nil {
			// Half a table is worse than the old one.
			pl.res.Failed++
			pl.res.Failures = append(pl.res.Failures, Failure{Op: "insert", Key: nil, Error: firstLine(err.Error())})
			dropTmp()
			return fmt.Errorf("the target can't take a row: %w", err)
		}
		vals = append(vals, v)
		if len(vals) >= per {
			if err := flush(); err != nil {
				dropTmp()
				return err
			}
		}
	}
	if err := rows.Err(); err != nil {
		dropTmp()
		return err
	}
	if err := flush(); err != nil {
		dropTmp()
		return err
	}
	if swap {
		if _, err := r.w.ExecContext(ctx, "EXCHANGE TABLES "+dd.table(pl.to.Ref)+" AND "+dd.table(tmp)); err != nil {
			dropTmp()
			return fmt.Errorf("couldn't swap the new copy in: %w", err)
		}
		dropTmp()
	}
	pl.res.Inserted = written
	pl.res.Deleted = m
	pl.res.Reloaded = true
	return nil
}
