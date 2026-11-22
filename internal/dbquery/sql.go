package dbquery

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/morche/backend/internal/dbmon"
)

type sqlClient struct {
	engine   string
	db       *sql.DB
	database string // the one this handle is on ('' = the connection's own)
	def      string // the connection's own database
}

func openSQL(ctx context.Context, cfg dbmon.Config, name string) (*sqlClient, error) {
	db, err := dbmon.OpenSQL(ctx, cfg, name, app)
	if err != nil {
		return nil, err
	}
	return &sqlClient{engine: cfg.Engine, db: db, database: name, def: cfg.Database}, nil
}

func (c *sqlClient) Close() error { return c.db.Close() }

// quote names an identifier safely for the engine.
func (c *sqlClient) quote(name string) string {
	switch c.engine {
	case dbmon.MySQL:
		return "`" + strings.ReplaceAll(name, "`", "``") + "`"
	case dbmon.MSSQL:
		return "[" + strings.ReplaceAll(name, "]", "]]") + "]"
	}
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func (c *sqlClient) table(schema, name string) string {
	if schema == "" {
		return c.quote(name)
	}
	return c.quote(schema) + "." + c.quote(name)
}

// param is the n-th (1-based) placeholder.
func (c *sqlClient) param(n int) string {
	switch c.engine {
	case dbmon.MySQL:
		return "?"
	case dbmon.MSSQL:
		return "@p" + strconv.Itoa(n)
	}
	return "$" + strconv.Itoa(n)
}

// dedicated is a connection of its own for one run, thrown away afterwards
// so nothing a statement set (SET, temp tables, a half-done transaction)
// reaches the next person.
func (c *sqlClient) dedicated(ctx context.Context) (*sql.Conn, func(), error) {
	conn, err := c.db.Conn(ctx)
	if err != nil {
		return nil, nil, err
	}
	return conn, func() {
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		_ = conn.Close()
	}, nil
}

// limitTime makes the server stop a statement on its own too, not only when
// the connection drops.
func (c *sqlClient) limitTime(ctx context.Context, q interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, d time.Duration, local bool) {
	ms := d.Milliseconds()
	switch c.engine {
	case dbmon.Postgres:
		scope := ""
		if local {
			scope = "LOCAL "
		}
		_, _ = q.ExecContext(ctx, "SET "+scope+"statement_timeout = "+strconv.FormatInt(ms, 10))
	case dbmon.MySQL:
		if _, err := q.ExecContext(ctx, "SET SESSION max_execution_time = "+strconv.FormatInt(ms, 10)); err != nil {
			// MariaDB names it differently, in seconds.
			_, _ = q.ExecContext(ctx, "SET SESSION max_statement_time = "+strconv.FormatFloat(d.Seconds(), 'f', 1, 64))
		}
	}
}

// Run runs a script. Read only: every statement checked, all inside one
// read-only transaction (SQL Server: one that's rolled back). Changes: one
// transaction too where the engine undoes DDL (Postgres, SQL Server), so a
// failing statement leaves nothing half done; MySQL runs them one by one.
func (c *sqlClient) Run(ctx context.Context, _ string, script string, o RunOptions) ([]QueryResult, error) {
	stmts := Split(c.engine, script)
	if len(stmts) == 0 {
		return nil, refused("Type a query first.")
	}
	if len(stmts) > 50 {
		return nil, refused("That's %d statements; run at most 50 at a time.", len(stmts))
	}
	if !o.Change {
		for _, s := range stmts {
			if err := checkRead(c.engine, s); err != nil {
				return nil, err
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	conn, done, err := c.dedicated(ctx)
	if err != nil {
		return nil, err
	}
	defer done()

	type runner interface {
		ExecContext(context.Context, string, ...any) (sql.Result, error)
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	}
	var q runner = conn
	var tx *sql.Tx
	useTx := !o.Change || c.engine != dbmon.MySQL
	if useTx {
		// SQL Server has no read-only transaction: a rollback undoes it.
		ro := !o.Change && c.engine != dbmon.MSSQL
		tx, err = conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: ro})
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		q = tx
	}
	c.limitTime(ctx, q, o.Timeout, useTx)

	var out []QueryResult
	for _, st := range stmts {
		start := time.Now()
		r, err := c.one(ctx, q, st, o.Limit)
		if err != nil {
			if len(stmts) > 1 {
				return out, fmt.Errorf("statement %d (%s): %w", len(out)+1, short(st), err)
			}
			return out, err
		}
		r.Ms = time.Since(start).Milliseconds()
		out = append(out, *r)
	}
	if tx != nil && o.Change {
		if err := tx.Commit(); err != nil {
			return out, err
		}
	}
	return out, nil
}

// returnsRows says whether a statement gives rows back (else it's run with
// Exec, which tells how many rows it touched).
func (c *sqlClient) returnsRows(st string) bool {
	ws := words(c.engine, st)
	if len(ws) == 0 {
		return true
	}
	if readFirst[ws[0]] || ws[0] == "CALL" || ws[0] == "EXEC" || ws[0] == "EXECUTE" || ws[0] == "PRAGMA" {
		return true
	}
	for _, w := range ws {
		if w == "RETURNING" || w == "OUTPUT" {
			return true
		}
	}
	return false
}

// one runs a statement and reads what it gives back.
func (c *sqlClient) one(ctx context.Context, q interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, st string, limit int) (*QueryResult, error) {
	if !c.returnsRows(st) {
		res, err := q.ExecContext(ctx, st)
		if err != nil {
			return nil, err
		}
		r := &QueryResult{Statement: short(st), Columns: []ResultColumn{}, Rows: [][]*string{}, Message: "Done"}
		if n, err := res.RowsAffected(); err == nil && n >= 0 {
			r.Affected = &n
		}
		return r, nil
	}
	rows, err := q.QueryContext(ctx, st)
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

// readRows reads up to limit rows (and every later result set's are left).
func readRows(rows *sql.Rows, limit int) (*QueryResult, error) {
	r := &QueryResult{Columns: []ResultColumn{}, Rows: [][]*string{}}
	types, err := rows.ColumnTypes()
	if err != nil {
		return nil, err
	}
	for _, t := range types {
		r.Columns = append(r.Columns, ResultColumn{Name: t.Name(), Type: t.DatabaseTypeName()})
	}
	size := 0
	for rows.Next() {
		if len(r.Rows) >= limit || size > maxResult {
			r.Truncated = true
			break
		}
		vals := make([]any, len(types))
		ptrs := make([]any, len(types))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make([]*string, len(vals))
		for i, v := range vals {
			row[i] = text(v, r.Columns[i].Type)
			if row[i] != nil {
				size += len(*row[i])
			}
		}
		r.Rows = append(r.Rows, row)
	}
	if err := rows.Err(); err != nil && !r.Truncated {
		return nil, err
	}
	if len(types) == 0 {
		// A statement with no result set: say how many rows it touched.
		r.Message = "Done"
	}
	return r, nil
}

// Rows reads a page of a table with filters, read only.
func (c *sqlClient) Rows(ctx context.Context, req RowsRequest) (*RowsPage, error) {
	if req.Table == "" {
		return nil, refused("Pick a table.")
	}
	limit := limitOf(req.Limit, defaultLimit, 1000)
	from := c.table(req.Schema, req.Table)
	if c.engine == dbmon.MySQL && req.Schema == "" && c.database != "" {
		from = c.table(c.database, req.Table)
	}

	var args []any
	var conds []string
	add := func(v any) string {
		args = append(args, v)
		return c.param(len(args))
	}
	for _, f := range req.Filters {
		cond, err := c.filter(f, add)
		if err != nil {
			return nil, err
		}
		conds = append(conds, cond)
	}
	if s := strings.TrimSpace(req.Search); s != "" {
		info, err := c.Describe(ctx, req.Database, req.Schema, req.Table)
		if err != nil {
			return nil, err
		}
		var any []string
		p := add("%" + likeEscape(s) + "%")
		for _, col := range info.Columns {
			any = append(any, c.asText(c.quote(col.Name))+" "+c.like()+" "+p+c.escape())
		}
		if len(any) > 0 {
			conds = append(conds, "("+strings.Join(any, " OR ")+")")
		}
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
		if strings.Contains(w, ";") && len(Split(c.engine, w)) > 1 {
			return nil, refused("The condition can't hold more than one statement.")
		}
		if c.engine == dbmon.MSSQL {
			if err := checkRead(c.engine, "SELECT 1 WHERE "+w); err != nil {
				return nil, err
			}
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
		order = append(order, c.quote(s.Column)+dir)
	}
	orderBy := ""
	if len(order) > 0 {
		orderBy = " ORDER BY " + strings.Join(order, ", ")
	}
	var page string
	switch c.engine {
	case dbmon.MSSQL:
		if orderBy == "" {
			orderBy = " ORDER BY (SELECT NULL)"
		}
		page = fmt.Sprintf(" OFFSET %d ROWS FETCH NEXT %d ROWS ONLY", req.Offset, limit+1)
	default:
		page = fmt.Sprintf(" LIMIT %d OFFSET %d", limit+1, req.Offset)
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, done, err := c.dedicated(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: c.engine != dbmon.MSSQL})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	c.limitTime(ctx, tx, 30*time.Second, true)

	start := time.Now()
	query := "SELECT * FROM " + from + where + orderBy + page
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	res, err := readRows(rows, limit)
	rows.Close()
	if err != nil {
		return nil, err
	}
	res.Statement = short(query)
	res.Ms = time.Since(start).Milliseconds()
	out := &RowsPage{QueryResult: *res}
	if req.Count {
		if !res.Truncated && req.Offset == 0 {
			out.Total = ptr(int64(len(res.Rows)))
		} else {
			cctx, ccancel := context.WithTimeout(ctx, 10*time.Second)
			var n int64
			err := tx.QueryRowContext(cctx, "SELECT count(*) FROM "+from+where, args...).Scan(&n)
			ccancel()
			if err == nil {
				out.Total = &n
			}
		}
	}
	return out, nil
}

func (c *sqlClient) like() string {
	if c.engine == dbmon.Postgres {
		return "ILIKE"
	}
	return "LIKE"
}

// escape names the backslash as LIKE's escape (MySQL's default already, and
// its string literals would read the backslash as one).
func (c *sqlClient) escape() string {
	if c.engine == dbmon.MySQL {
		return ""
	}
	return ` ESCAPE '\'`
}

func (c *sqlClient) asText(col string) string {
	switch c.engine {
	case dbmon.MySQL:
		return "CAST(" + col + " AS CHAR)"
	case dbmon.MSSQL:
		return "CAST(" + col + " AS NVARCHAR(MAX))"
	}
	return col + "::text"
}

func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`, `[`, `\[`)
	return r.Replace(s)
}

func (c *sqlClient) filter(f RowFilter, add func(any) string) (string, error) {
	col := c.quote(f.Column)
	switch f.Op {
	case "eq":
		return col + " = " + add(f.Value), nil
	case "ne":
		return "(" + col + " <> " + add(f.Value) + " OR " + col + " IS NULL)", nil
	case "gt":
		return col + " > " + add(f.Value), nil
	case "gte":
		return col + " >= " + add(f.Value), nil
	case "lt":
		return col + " < " + add(f.Value), nil
	case "lte":
		return col + " <= " + add(f.Value), nil
	case "contains":
		return c.asText(col) + " " + c.like() + " " + add("%"+likeEscape(f.Value)+"%") + c.escape(), nil
	case "not_contains":
		return "(" + c.asText(col) + " NOT " + c.like() + " " + add("%"+likeEscape(f.Value)+"%") + c.escape() + " OR " + col + " IS NULL)", nil
	case "starts":
		return c.asText(col) + " " + c.like() + " " + add(likeEscape(f.Value)+"%") + c.escape(), nil
	case "ends":
		return c.asText(col) + " " + c.like() + " " + add("%"+likeEscape(f.Value)) + c.escape(), nil
	case "null":
		return col + " IS NULL", nil
	case "not_null":
		return col + " IS NOT NULL", nil
	case "in":
		vals := f.Values
		if len(vals) == 0 {
			for _, v := range strings.Split(f.Value, ",") {
				if v = strings.TrimSpace(v); v != "" {
					vals = append(vals, v)
				}
			}
		}
		if len(vals) == 0 {
			return "1=0", nil
		}
		ps := make([]string, len(vals))
		for i, v := range vals {
			ps[i] = add(v)
		}
		return col + " IN (" + strings.Join(ps, ", ") + ")", nil
	}
	return "", refused("unknown filter %q", f.Op)
}

// queryStrings reads rows of text columns.
func queryStrings(ctx context.Context, db *sql.DB, q string, args ...any) ([][]sql.NullString, error) {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out [][]sql.NullString
	for rows.Next() {
		row := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range row {
			ptrs[i] = &row[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func nInt(s sql.NullString) *int64 {
	if !s.Valid {
		return nil
	}
	f, err := strconv.ParseFloat(s.String, 64)
	if err != nil || f < 0 {
		return nil
	}
	return ptr(int64(f))
}

func nStr(s sql.NullString) *string {
	if !s.Valid {
		return nil
	}
	return &s.String
}

// ErrNotFound is a table, collection or key that isn't there.
var ErrNotFound = errors.New("not found")
