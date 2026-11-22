// Package dbsync copies rows between two databases of the same family
// (PostgreSQL to PostgreSQL, MySQL/MariaDB to MySQL/MariaDB, ClickHouse to
// ClickHouse), or from PostgreSQL or MySQL into ClickHouse: it walks both
// sides of each table in key order, compares the rows and writes what
// differs, with a choice of what to do with rows that changed on both sides
// and with rows the target refuses.
package dbsync

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

type Dialect string

const (
	Postgres Dialect = "postgres"
	MySQL    Dialect = "mysql"
)

// Ref names a table. Schema is empty on MySQL (the database is the schema).
type Ref struct {
	Schema string `json:"schema,omitempty" maxLength:"128"`
	Name   string `json:"name" minLength:"1" maxLength:"128"`
}

func (r Ref) String() string {
	if r.Schema == "" {
		return r.Name
	}
	return r.Schema + "." + r.Name
}

// Value kinds, which decide how keys are ordered and compared.
const (
	KindNumber = "number"
	KindText   = "text"
	KindBinary = "binary"
	KindTime   = "time"
	KindOther  = "other"
)

type Column struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Nullable  bool   `json:"nullable"`
	Generated bool   `json:"generated" doc:"Computed by the database; never written"`
	Identity  bool   `json:"identity,omitempty" doc:"PostgreSQL GENERATED ALWAYS identity"`
	Serial    bool   `json:"serial,omitempty" doc:"Filled from a sequence or auto_increment"`
	Kind      string `json:"kind" enum:"number,text,binary,time,other"`
}

type Table struct {
	Ref
	Columns []Column `json:"columns"`
	Key     []string `json:"key" doc:"Primary key, or a unique index on non-null columns"`
	KeyFrom string   `json:"key_from" enum:"primary,unique,sorting,none" doc:"sorting = ClickHouse ReplacingMergeTree ORDER BY"`
	Rows    int64    `json:"rows" doc:"Estimate"`
	Bytes   int64    `json:"bytes"`
	Engine  string   `json:"engine,omitempty" doc:"ClickHouse: the table engine (MergeTree, ReplacingMergeTree…)"`
	Sorting []string `json:"sorting,omitempty" doc:"ClickHouse: ORDER BY columns. Only a ReplacingMergeTree's identify a row; on other engines a sync may still name them as its key when they're unique"`
}

func (t Table) column(name string) (Column, bool) {
	for _, c := range t.Columns {
		if c.Name == name {
			return c, true
		}
	}
	return Column{}, false
}

// ---- SQL text ----

func (d Dialect) quote(name string) string {
	if d == MySQL || d == ClickHouse {
		return "`" + strings.ReplaceAll(name, "`", "``") + "`"
	}
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func (d Dialect) table(r Ref) string {
	if r.Schema == "" {
		return d.quote(r.Name)
	}
	return d.quote(r.Schema) + "." + d.quote(r.Name)
}

// ph is the n-th (1-based) placeholder.
func (d Dialect) ph(n int) string {
	if d == MySQL || d == ClickHouse {
		return "?"
	}
	return fmt.Sprintf("$%d", n)
}

// sel reads a column as text, the same way on both sides.
func (d Dialect) sel(c Column) string {
	if d == ClickHouse {
		return chSel(c)
	}
	if d == Postgres {
		return d.quote(c.Name) + "::text"
	}
	return d.quote(c.Name)
}

// ord is how a column is ordered: byte order for text, so Go compares the
// same way the database sorts.
func (d Dialect) ord(c Column) string {
	if d == ClickHouse {
		return chOrd(c)
	}
	if c.Kind != KindText {
		return d.quote(c.Name)
	}
	if d == MySQL {
		return "CAST(" + d.quote(c.Name) + " AS BINARY)"
	}
	return d.quote(c.Name) + ` COLLATE "C"`
}

// from is a table to read from: ClickHouse's ReplacingMergeTree with FINAL,
// so each key shows once even before the server merged its copies.
func (d Dialect) from(t Table) string {
	if d == ClickHouse && replacing(t.Engine) {
		return d.table(t.Ref) + " FINAL"
	}
	return d.table(t.Ref)
}

func countSQL(d Dialect, t Table) string {
	if d == ClickHouse {
		return "SELECT toInt64(count()) FROM " + d.from(t)
	}
	return "SELECT count(*) FROM " + d.table(t.Ref)
}

// ---- Reading the schema ----

// Tables lists a database's tables with their columns and keys. On MySQL
// database names the schema; on Postgres the connection already is in it.
func Tables(ctx context.Context, db *sql.DB, d Dialect, database string) ([]Table, error) {
	switch d {
	case MySQL:
		return mysqlTables(ctx, db, database)
	case ClickHouse:
		return clickhouseTables(ctx, db, database)
	}
	return postgresTables(ctx, db)
}

func postgresTables(ctx context.Context, db *sql.DB) ([]Table, error) {
	const skip = `n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%'`
	byRef := map[Ref]*Table{}
	var order []Ref
	rows, err := db.QueryContext(ctx, `
		SELECT n.nspname, c.relname, greatest(c.reltuples, 0)::bigint, pg_total_relation_size(c.oid)
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition AND `+skip+`
		ORDER BY 1, 2`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		t := &Table{KeyFrom: "none"}
		if err := rows.Scan(&t.Schema, &t.Name, &t.Rows, &t.Bytes); err != nil {
			rows.Close()
			return nil, err
		}
		byRef[t.Ref] = t
		order = append(order, t.Ref)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = db.QueryContext(ctx, `
		SELECT n.nspname, c.relname, a.attname, format_type(a.atttypid, a.atttypmod), NOT a.attnotnull,
			a.attgenerated <> '', a.attidentity = 'a', a.attidentity <> '' OR coalesce(pg_get_expr(d.adbin, d.adrelid), '') LIKE 'nextval(%',
			t.typcategory, t.typname
		FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_type t ON t.oid = a.atttypid
		LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
		WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r', 'p') AND NOT c.relispartition AND `+skip+`
		ORDER BY 1, 2, a.attnum`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r Ref
		var c Column
		var cat, typ string
		if err := rows.Scan(&r.Schema, &r.Name, &c.Name, &c.Type, &c.Nullable, &c.Generated, &c.Identity, &c.Serial, &cat, &typ); err != nil {
			rows.Close()
			return nil, err
		}
		switch {
		case cat == "N" && typ != "money":
			c.Kind = KindNumber
		case cat == "S":
			c.Kind = KindText
		case typ == "bytea":
			c.Kind = KindBinary
		case cat == "D":
			c.Kind = KindTime
		default:
			c.Kind = KindOther
		}
		if t := byRef[r]; t != nil {
			t.Columns = append(t.Columns, c)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Primary keys first, then unique indexes on non-null columns.
	rows, err = db.QueryContext(ctx, `
		SELECT n.nspname, c.relname, i.indexrelid::bigint, i.indisprimary, a.attname, a.attnotnull
		FROM pg_index i
		JOIN pg_class c ON c.oid = i.indrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN LATERAL unnest(i.indkey) WITH ORDINALITY k(attnum, ord) ON true
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
		WHERE (i.indisprimary OR i.indisunique) AND i.indpred IS NULL AND i.indexprs IS NULL AND `+skip+`
		ORDER BY 1, 2, i.indisprimary DESC, 3, k.ord`)
	if err != nil {
		return nil, err
	}
	if err := keysFrom(rows, byRef); err != nil {
		return nil, err
	}
	out := make([]Table, len(order))
	for i, r := range order {
		out[i] = *byRef[r]
	}
	return out, nil
}

func mysqlTables(ctx context.Context, db *sql.DB, database string) ([]Table, error) {
	byRef := map[Ref]*Table{}
	var order []Ref
	rows, err := db.QueryContext(ctx, `
		SELECT TABLE_NAME, coalesce(TABLE_ROWS, 0), coalesce(DATA_LENGTH, 0) + coalesce(INDEX_LENGTH, 0)
		FROM information_schema.TABLES
		WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE'
		ORDER BY TABLE_NAME`, database)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		t := &Table{KeyFrom: "none"}
		if err := rows.Scan(&t.Name, &t.Rows, &t.Bytes); err != nil {
			rows.Close()
			return nil, err
		}
		byRef[t.Ref] = t
		order = append(order, t.Ref)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = db.QueryContext(ctx, `
		SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE = 'YES', DATA_TYPE, coalesce(EXTRA, '')
		FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = ?
		ORDER BY TABLE_NAME, ORDINAL_POSITION`, database)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r Ref
		var c Column
		var typ, extra string
		if err := rows.Scan(&r.Name, &c.Name, &c.Type, &c.Nullable, &typ, &extra); err != nil {
			rows.Close()
			return nil, err
		}
		extra = strings.ToUpper(extra)
		c.Generated = strings.Contains(extra, "GENERATED") && !strings.Contains(extra, "DEFAULT_GENERATED")
		c.Serial = strings.Contains(extra, "AUTO_INCREMENT")
		switch strings.ToLower(typ) {
		case "tinyint", "smallint", "mediumint", "int", "integer", "bigint", "decimal", "numeric", "float", "double", "real", "year":
			c.Kind = KindNumber
		case "char", "varchar", "tinytext", "text", "mediumtext", "longtext", "enum", "set":
			c.Kind = KindText
		case "binary", "varbinary", "tinyblob", "blob", "mediumblob", "longblob", "bit",
			"geometry", "point", "linestring", "polygon", "multipoint", "multilinestring", "multipolygon", "geometrycollection", "geomcollection":
			c.Kind = KindBinary
		case "date", "datetime", "timestamp", "time":
			c.Kind = KindTime
		default:
			c.Kind = KindOther
		}
		if t := byRef[r]; t != nil {
			t.Columns = append(t.Columns, c)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = db.QueryContext(ctx, `
		SELECT '', s.TABLE_NAME, s.INDEX_NAME, s.INDEX_NAME = 'PRIMARY', s.COLUMN_NAME, c.IS_NULLABLE = 'NO'
		FROM information_schema.STATISTICS s
		JOIN information_schema.COLUMNS c ON c.TABLE_SCHEMA = s.TABLE_SCHEMA AND c.TABLE_NAME = s.TABLE_NAME AND c.COLUMN_NAME = s.COLUMN_NAME
		WHERE s.TABLE_SCHEMA = ? AND s.NON_UNIQUE = 0 AND s.SUB_PART IS NULL
		ORDER BY s.TABLE_NAME, s.INDEX_NAME = 'PRIMARY' DESC, s.INDEX_NAME, s.SEQ_IN_INDEX`, database)
	if err != nil {
		return nil, err
	}
	if err := keysFrom(rows, byRef); err != nil {
		return nil, err
	}
	out := make([]Table, len(order))
	for i, r := range order {
		out[i] = *byRef[r]
	}
	return out, nil
}

// keysFrom picks each table's key: its primary key, else its first unique
// index whose columns are all NOT NULL. Rows come ordered by table, primary
// first, then index, then column position.
func keysFrom(rows *sql.Rows, byRef map[Ref]*Table) error {
	defer rows.Close()
	type idx struct {
		primary bool
		cols    []string
		notNull bool
	}
	found := map[Ref][]*idx{}
	seen := map[Ref]map[string]*idx{}
	for rows.Next() {
		var r Ref
		var id string
		var primary, notNull bool
		var col string
		if err := rows.Scan(&r.Schema, &r.Name, &id, &primary, &col, &notNull); err != nil {
			return err
		}
		if seen[r] == nil {
			seen[r] = map[string]*idx{}
		}
		x := seen[r][id]
		if x == nil {
			x = &idx{primary: primary, notNull: true}
			seen[r][id] = x
			found[r] = append(found[r], x)
		}
		x.cols = append(x.cols, col)
		x.notNull = x.notNull && notNull
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for r, list := range found {
		t := byRef[r]
		if t == nil {
			continue
		}
		sort.SliceStable(list, func(i, j int) bool { return list[i].primary && !list[j].primary })
		for _, x := range list {
			if x.primary {
				t.Key, t.KeyFrom = x.cols, "primary"
				break
			}
			if x.notNull {
				t.Key, t.KeyFrom = x.cols, "unique"
				break
			}
		}
	}
	return nil
}

// ---- Creating a missing table ----

// createTable makes dst like src on the target: columns and primary key
// (MySQL: its own CREATE TABLE, foreign keys left out, since the tables
// they point at may not be there yet).
func createTable(ctx context.Context, src, dst Side, t Table, to Ref) error {
	if src.Dialect == MySQL && dst.Dialect == MySQL {
		var name, stmt string
		if err := src.DB.QueryRowContext(ctx, "SHOW CREATE TABLE "+MySQL.table(t.Ref)).Scan(&name, &stmt); err != nil {
			return err
		}
		lines := strings.Split(stmt, "\n")
		kept := lines[:0]
		for _, l := range lines {
			if strings.Contains(l, "FOREIGN KEY") {
				continue
			}
			kept = append(kept, l)
		}
		// A trailing comma left by a dropped last line.
		for i := len(kept) - 1; i > 0; i-- {
			if strings.HasPrefix(strings.TrimSpace(kept[i]), ")") {
				kept[i-1] = strings.TrimSuffix(kept[i-1], ",")
				break
			}
		}
		stmt = strings.Join(kept, "\n")
		head := "CREATE TABLE " + MySQL.quote(t.Name)
		if !strings.HasPrefix(stmt, head) {
			return fmt.Errorf("unexpected SHOW CREATE TABLE answer")
		}
		stmt = "CREATE TABLE IF NOT EXISTS " + MySQL.table(to) + stmt[len(head):]
		_, err := dst.DB.ExecContext(ctx, stmt)
		return err
	}
	var b strings.Builder
	b.WriteString("CREATE TABLE IF NOT EXISTS " + Postgres.table(to) + " (\n")
	for i, c := range t.Columns {
		if i > 0 {
			b.WriteString(",\n")
		}
		b.WriteString("  " + Postgres.quote(c.Name) + " " + c.Type)
		if !c.Nullable {
			b.WriteString(" NOT NULL")
		}
	}
	if len(t.Key) > 0 && t.KeyFrom == "primary" {
		keys := make([]string, len(t.Key))
		for i, k := range t.Key {
			keys[i] = Postgres.quote(k)
		}
		b.WriteString(",\n  PRIMARY KEY (" + strings.Join(keys, ", ") + ")")
	}
	b.WriteString("\n)")
	if to.Schema != "" {
		if _, err := dst.DB.ExecContext(ctx, "CREATE SCHEMA IF NOT EXISTS "+Postgres.quote(to.Schema)); err != nil {
			return err
		}
	}
	if _, err := dst.DB.ExecContext(ctx, b.String()); err != nil {
		return err
	}
	if len(t.Key) > 0 && t.KeyFrom == "unique" {
		keys := make([]string, len(t.Key))
		for i, k := range t.Key {
			keys[i] = Postgres.quote(k)
		}
		_, err := dst.DB.ExecContext(ctx, "CREATE UNIQUE INDEX ON "+Postgres.table(to)+" ("+strings.Join(keys, ", ")+")")
		return err
	}
	return nil
}
