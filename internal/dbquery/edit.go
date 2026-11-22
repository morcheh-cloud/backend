package dbquery

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/morche/backend/internal/dbmon"
)

// RowChange is one row added, changed or removed from the data explorer.
type RowChange struct {
	Op string `json:"op" enum:"insert,update,delete"`
	// The row's key as read (SQL: every primary key column; MongoDB: "_id"
	// as Extended JSON). Not for insert.
	Key map[string]*string `json:"key,omitempty"`
	// SQL: the columns to set, null = NULL. Columns left out keep their value
	// (insert: their default).
	Values map[string]*string `json:"values,omitempty"`
	// MongoDB: the whole new document as JSON (insert, update).
	Document string `json:"document,omitempty" maxLength:"1000000"`
}

// EditRequest changes rows of one table, all or nothing.
type EditRequest struct {
	Database string      `json:"database,omitempty" maxLength:"128"`
	Schema   string      `json:"schema,omitempty" maxLength:"128"`
	Table    string      `json:"table" minLength:"1" maxLength:"256"`
	Changes  []RowChange `json:"changes" minItems:"1" maxItems:"500"`
	Preview  bool        `json:"preview,omitempty" doc:"Only write out the statements, run nothing"`
}

type EditResult struct {
	Statements []string `json:"statements" doc:"What runs, values written in"`
	Affected   int64    `json:"affected"`
	Ran        bool     `json:"ran"`
	Ms         int64    `json:"ms"`
}

// Editor is a Client that can change rows by key.
type Editor interface {
	Edit(ctx context.Context, r EditRequest) (*EditResult, error)
}

// literal writes a value into SQL text, for showing a statement.
func (c *sqlClient) literal(v *string) string {
	if v == nil {
		return "NULL"
	}
	s := strings.ReplaceAll(*v, "'", "''")
	if c.engine == dbmon.MySQL {
		s = strings.ReplaceAll(s, `\`, `\\`)
	}
	if c.engine == dbmon.MSSQL {
		return "N'" + s + "'"
	}
	return "'" + s + "'"
}

type stmt struct {
	sql, shown string
	args       []any
	one        bool // must touch exactly one row
}

func (c *sqlClient) Edit(ctx context.Context, r EditRequest) (*EditResult, error) {
	info, err := c.Describe(ctx, r.Database, r.Schema, r.Table)
	if err != nil {
		return nil, err
	}
	if info.Kind != "table" {
		return nil, refused("%s is a %s; only tables can be changed here.", r.Table, strings.ReplaceAll(info.Kind, "_", " "))
	}
	cols := map[string]bool{}
	var order []string
	for _, col := range info.Columns {
		cols[col.Name] = true
		order = append(order, col.Name)
	}
	sorted := func(m map[string]*string) ([]string, error) {
		var names []string
		for n := range m {
			if !cols[n] {
				return nil, refused("%s has no column %q.", r.Table, n)
			}
			names = append(names, n)
		}
		slices.SortFunc(names, func(a, b string) int {
			return slices.Index(order, a) - slices.Index(order, b)
		})
		return names, nil
	}
	table := c.table(info.SchemaName, r.Table)
	if c.engine == dbmon.MySQL {
		db := r.Schema
		if db == "" {
			db = c.database
		}
		table = c.table(db, r.Table)
	}

	var stmts []stmt
	for i, ch := range r.Changes {
		var (
			q, shown strings.Builder
			args     []any
		)
		put := func(v *string) {
			if v == nil {
				args = append(args, nil)
			} else {
				args = append(args, *v)
			}
			q.WriteString(c.param(len(args)))
			shown.WriteString(c.literal(v))
		}
		both := func(s string) {
			q.WriteString(s)
			shown.WriteString(s)
		}
		where := func() error {
			if len(info.Key) == 0 {
				return refused("%s has no primary key, so a row can't be told apart safely. Change it with a query in the Query tab.", r.Table)
			}
			both(" WHERE ")
			for j, k := range info.Key {
				v, ok := ch.Key[k]
				if !ok || v == nil {
					return refused("Row %d: the key column %s is missing.", i+1, k)
				}
				if j > 0 {
					both(" AND ")
				}
				both(c.quote(k) + " = ")
				put(v)
			}
			return nil
		}
		switch ch.Op {
		case "insert":
			names, err := sorted(ch.Values)
			if err != nil {
				return nil, err
			}
			both("INSERT INTO " + table)
			if len(names) == 0 {
				if c.engine == dbmon.MySQL {
					both(" () VALUES ()")
				} else {
					both(" DEFAULT VALUES")
				}
				break
			}
			quoted := make([]string, len(names))
			for j, n := range names {
				quoted[j] = c.quote(n)
			}
			both(" (" + strings.Join(quoted, ", ") + ") VALUES (")
			for j, n := range names {
				if j > 0 {
					both(", ")
				}
				put(ch.Values[n])
			}
			both(")")
		case "update":
			names, err := sorted(ch.Values)
			if err != nil {
				return nil, err
			}
			if len(names) == 0 {
				continue
			}
			both("UPDATE " + table + " SET ")
			for j, n := range names {
				if j > 0 {
					both(", ")
				}
				both(c.quote(n) + " = ")
				put(ch.Values[n])
			}
			if err := where(); err != nil {
				return nil, err
			}
		case "delete":
			both("DELETE FROM " + table)
			if err := where(); err != nil {
				return nil, err
			}
		default:
			return nil, refused("unknown change %q", ch.Op)
		}
		stmts = append(stmts, stmt{sql: q.String(), shown: shown.String() + ";", args: args, one: ch.Op != "insert"})
	}

	out := &EditResult{Statements: make([]string, len(stmts))}
	for i, s := range stmts {
		out.Statements[i] = s.shown
	}
	if r.Preview || len(stmts) == 0 {
		return out, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	conn, done, err := c.dedicated(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	c.limitTime(ctx, tx, 60*time.Second, true)
	start := time.Now()
	for i, s := range stmts {
		res, err := tx.ExecContext(ctx, s.sql, s.args...)
		if err != nil {
			return nil, fmt.Errorf("row %d: %w", i+1, err)
		}
		n, _ := res.RowsAffected()
		if s.one && n != 1 {
			return nil, refused("Row %d was changed or removed since you read it (%d rows matched). Nothing was saved; read the rows again.", i+1, n)
		}
		out.Affected += n
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	out.Ran = true
	out.Ms = time.Since(start).Milliseconds()
	return out, nil
}

// Edit on MongoDB: insert a document, replace one by its _id, delete one.
func (m *mongoClient) Edit(ctx context.Context, r EditRequest) (*EditResult, error) {
	database := r.Database
	if database == "" {
		database = m.def
	}
	coll := m.client.Database(database).Collection(r.Table)
	type op struct {
		kind  string
		id    any
		doc   bson.D
		shown string
	}
	idOf := func(i int, ch RowChange) (any, string, error) {
		raw := ch.Key["_id"]
		if raw == nil {
			return nil, "", refused("Row %d: the _id is missing.", i+1)
		}
		var wrap bson.D
		if err := bson.UnmarshalExtJSON([]byte(`{"v":`+*raw+`}`), false, &wrap); err != nil || len(wrap) != 1 {
			return nil, "", refused("Row %d: the _id isn't valid JSON.", i+1)
		}
		return wrap[0].Value, *raw, nil
	}
	var ops []op
	for i, ch := range r.Changes {
		o := op{kind: ch.Op}
		if ch.Op != "insert" {
			id, shown, err := idOf(i, ch)
			if err != nil {
				return nil, err
			}
			o.id = id
			o.shown = `{"_id": ` + shown + `}`
		}
		if ch.Op != "delete" {
			if err := parseJSON(ch.Document, &o.doc); err != nil {
				return nil, refused("Row %d isn't a valid document: %v", i+1, err)
			}
			b, _ := bson.MarshalExtJSON(o.doc, false, false)
			if o.shown != "" {
				o.shown += ", "
			}
			o.shown += string(b)
		}
		name := map[string]string{"insert": "insertOne", "update": "replaceOne", "delete": "deleteOne"}[ch.Op]
		if name == "" {
			return nil, refused("unknown change %q", ch.Op)
		}
		o.shown = "db." + r.Table + "." + name + "(" + o.shown + ")"
		ops = append(ops, o)
	}
	out := &EditResult{Statements: make([]string, len(ops))}
	for i, o := range ops {
		out.Statements[i] = o.shown
	}
	if r.Preview {
		return out, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	start := time.Now()
	for i, o := range ops {
		filter := bson.D{{Key: "_id", Value: o.id}}
		var n int64
		switch o.kind {
		case "insert":
			if _, err := coll.InsertOne(ctx, o.doc); err != nil {
				return out, fmt.Errorf("row %d: %w", i+1, err)
			}
			n = 1
		case "update":
			res, err := coll.ReplaceOne(ctx, filter, o.doc)
			if err != nil {
				return out, fmt.Errorf("row %d: %w", i+1, err)
			}
			if res.MatchedCount != 1 {
				return out, refused("Row %d was removed since you read it. The rows before it were saved.", i+1)
			}
			n = res.ModifiedCount
		case "delete":
			res, err := coll.DeleteOne(ctx, filter)
			if err != nil {
				return out, fmt.Errorf("row %d: %w", i+1, err)
			}
			n = res.DeletedCount
		}
		out.Affected += n
	}
	out.Ran = true
	out.Ms = time.Since(start).Milliseconds()
	return out, nil
}
