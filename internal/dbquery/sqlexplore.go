package dbquery

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/morche/backend/internal/dbmon"
)

const maxObjects = 5000

var mysqlSystem = map[string]bool{"information_schema": true, "mysql": true, "performance_schema": true, "sys": true}

func (c *sqlClient) Overview(ctx context.Context, _ string) (*DatabaseOverview, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	o := &DatabaseOverview{Engine: c.engine, Databases: []string{}, Schemas: []string{}, Objects: []DatabaseObject{}, Notes: []string{}}
	note := func(what string, err error) {
		o.Notes = append(o.Notes, "Couldn't read "+what+": "+err.Error())
	}
	var dbq, schemaQ, objQ string
	var args []any
	switch c.engine {
	case dbmon.Postgres:
		dbq = `SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY 1`
		schemaQ = `SELECT nspname FROM pg_namespace
			WHERE nspname NOT IN ('pg_catalog', 'information_schema') AND nspname NOT LIKE 'pg\_toast%' AND nspname NOT LIKE 'pg\_temp\_%'
			ORDER BY nspname = 'public' DESC, 1`
		objQ = `SELECT n.nspname, c.relname,
				CASE c.relkind WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized_view' WHEN 'f' THEN 'foreign_table' ELSE 'table' END,
				CASE WHEN c.reltuples < 0 THEN NULL ELSE c.reltuples::bigint END,
				CASE WHEN c.relkind IN ('r', 'p', 'm') THEN pg_total_relation_size(c.oid) END
			FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND NOT c.relispartition
			  AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp\_%'
			ORDER BY 1, 2 LIMIT 5001`
		var cur string
		if err := c.db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&cur); err == nil {
			o.Database = cur
		}
	case dbmon.MySQL:
		dbq = `SELECT schema_name FROM information_schema.schemata ORDER BY 1`
		o.Database = c.database
	case dbmon.MSSQL:
		dbq = `SELECT name FROM sys.databases WHERE state = 0 AND HAS_DBACCESS(name) = 1 ORDER BY CASE WHEN database_id <= 4 THEN 1 ELSE 0 END, name`
		schemaQ = `SELECT s.name FROM sys.schemas s WHERE s.schema_id < 16384 AND s.name NOT IN ('sys', 'INFORMATION_SCHEMA', 'guest')
			AND s.name NOT LIKE 'db\_%' ESCAPE '\' ORDER BY CASE s.name WHEN 'dbo' THEN 0 ELSE 1 END, s.name`
		objQ = `SELECT TOP 5001 s.name, o.name, CASE o.type WHEN 'V' THEN 'view' ELSE 'table' END,
				(SELECT SUM(p.rows) FROM sys.partitions p WHERE p.object_id = o.object_id AND p.index_id IN (0, 1)),
				(SELECT SUM(a.total_pages) * 8192 FROM sys.partitions p JOIN sys.allocation_units a ON a.container_id = p.partition_id WHERE p.object_id = o.object_id)
			FROM sys.objects o JOIN sys.schemas s ON s.schema_id = o.schema_id
			WHERE o.type IN ('U', 'V') AND o.is_ms_shipped = 0 ORDER BY 1, 2`
		var cur string
		if err := c.db.QueryRowContext(ctx, `SELECT DB_NAME()`).Scan(&cur); err == nil {
			o.Database = cur
		}
	}
	if rows, err := queryStrings(ctx, c.db, dbq); err != nil {
		note("the list of databases", err)
	} else {
		for _, r := range rows {
			o.Databases = append(o.Databases, r[0].String)
		}
	}
	if c.engine == dbmon.MySQL {
		if o.Database == "" {
			o.Database = c.def
		}
		if o.Database == "" {
			for _, d := range o.Databases {
				if !mysqlSystem[strings.ToLower(d)] {
					o.Database = d
					break
				}
			}
		}
		if o.Database == "" {
			return o, nil
		}
		objQ = `SELECT table_schema, table_name, CASE table_type WHEN 'VIEW' THEN 'view' WHEN 'SYSTEM VIEW' THEN 'view' ELSE 'table' END,
				table_rows, data_length + index_length
			FROM information_schema.tables WHERE table_schema = ? ORDER BY 2 LIMIT 5001`
		args = []any{o.Database}
	}
	if schemaQ != "" {
		if rows, err := queryStrings(ctx, c.db, schemaQ); err != nil {
			note("schemas", err)
		} else {
			for _, r := range rows {
				o.Schemas = append(o.Schemas, r[0].String)
			}
		}
	}
	rows, err := queryStrings(ctx, c.db, objQ, args...)
	if err != nil {
		note("tables", err)
		return o, nil
	}
	for i, r := range rows {
		if i >= maxObjects {
			o.Capped = true
			break
		}
		schema := r[0].String
		if c.engine == dbmon.MySQL {
			schema = ""
		}
		o.Objects = append(o.Objects, DatabaseObject{Schema: schema, Name: r[1].String, Kind: r[2].String, Rows: nInt(r[3]), Bytes: nInt(r[4])})
	}
	return o, nil
}

func (c *sqlClient) Describe(ctx context.Context, _ string, schema, name string) (*ObjectInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	info := &ObjectInfo{SchemaName: schema, Name: name, Columns: []ObjectColumn{}, Key: []string{}, Indexes: []ObjectIndex{}, Constraints: []ObjectConstraint{}}
	var err error
	switch c.engine {
	case dbmon.Postgres:
		err = c.describePostgres(ctx, info)
	case dbmon.MySQL:
		err = c.describeMySQL(ctx, info)
	case dbmon.MSSQL:
		err = c.describeMSSQL(ctx, info)
	}
	if err != nil {
		return nil, err
	}
	if len(info.Columns) == 0 {
		return nil, ErrNotFound
	}
	keys := map[string]bool{}
	for _, k := range info.Key {
		keys[k] = true
	}
	for i := range info.Columns {
		info.Columns[i].Key = keys[info.Columns[i].Name]
	}
	return info, nil
}

func (c *sqlClient) describePostgres(ctx context.Context, info *ObjectInfo) error {
	if info.SchemaName == "" {
		info.SchemaName = "public"
	}
	var oid, kind string
	err := c.db.QueryRowContext(ctx, `SELECT c.oid::text, c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relname = $2`, info.SchemaName, info.Name).Scan(&oid, &kind)
	if err == sql.ErrNoRows {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	info.Kind = map[string]string{"v": "view", "m": "materialized_view", "f": "foreign_table"}[kind]
	if info.Kind == "" {
		info.Kind = "table"
	}
	rows, err := queryStrings(ctx, c.db, `SELECT a.attname, format_type(a.atttypid, a.atttypmod), (NOT a.attnotnull)::text,
			pg_get_expr(d.adbin, d.adrelid), col_description(a.attrelid, a.attnum),
			CASE WHEN a.attidentity <> '' THEN 'identity' WHEN a.attgenerated <> '' THEN 'generated' ELSE '' END
		FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
		WHERE a.attrelid = $1::oid AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum`, oid)
	if err != nil {
		return err
	}
	for _, r := range rows {
		info.Columns = append(info.Columns, ObjectColumn{Name: r[0].String, Type: r[1].String, Nullable: r[2].String == "true",
			Default: nStr(r[3]), Comment: r[4].String, Extra: r[5].String})
	}
	if rows, err := queryStrings(ctx, c.db, `SELECT a.attname FROM pg_index i
		JOIN LATERAL unnest(i.indkey) WITH ORDINALITY k(attnum, n) ON true
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
		WHERE i.indrelid = $1::oid AND i.indisprimary ORDER BY k.n`, oid); err == nil {
		for _, r := range rows {
			info.Key = append(info.Key, r[0].String)
		}
	}
	if rows, err := queryStrings(ctx, c.db, `SELECT ic.relname, pg_get_indexdef(i.indexrelid), i.indisunique::text, i.indisprimary::text
		FROM pg_index i JOIN pg_class ic ON ic.oid = i.indexrelid WHERE i.indrelid = $1::oid ORDER BY i.indisprimary DESC, 1`, oid); err == nil {
		for _, r := range rows {
			info.Indexes = append(info.Indexes, ObjectIndex{Name: r[0].String, Definition: r[1].String, Unique: r[2].String == "true", Primary: r[3].String == "true"})
		}
	}
	if rows, err := queryStrings(ctx, c.db, `SELECT conname, contype::text, pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid = $1::oid AND contype IN ('f', 'c', 'u') ORDER BY contype, conname`, oid); err == nil {
		for _, r := range rows {
			kind := map[string]string{"f": "foreign_key", "c": "check", "u": "unique"}[r[1].String]
			info.Constraints = append(info.Constraints, ObjectConstraint{Name: r[0].String, Kind: kind, Definition: r[2].String})
		}
	}
	if info.Kind == "view" || info.Kind == "materialized_view" {
		var def sql.NullString
		if err := c.db.QueryRowContext(ctx, `SELECT pg_get_viewdef($1::oid, true)`, oid).Scan(&def); err == nil {
			info.Definition = def.String
		}
	}
	return nil
}

func (c *sqlClient) describeMySQL(ctx context.Context, info *ObjectInfo) error {
	db := info.SchemaName
	if db == "" {
		db = c.database
	}
	info.SchemaName = ""
	var kind string
	err := c.db.QueryRowContext(ctx, `SELECT table_type FROM information_schema.tables WHERE table_schema = ? AND table_name = ?`, db, info.Name).Scan(&kind)
	if err == sql.ErrNoRows {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	info.Kind = "table"
	if strings.Contains(kind, "VIEW") {
		info.Kind = "view"
	}
	rows, err := queryStrings(ctx, c.db, `SELECT column_name, column_type, is_nullable, column_default, column_comment, extra, column_key
		FROM information_schema.columns WHERE table_schema = ? AND table_name = ? ORDER BY ordinal_position`, db, info.Name)
	if err != nil {
		return err
	}
	for _, r := range rows {
		info.Columns = append(info.Columns, ObjectColumn{Name: r[0].String, Type: r[1].String, Nullable: r[2].String == "YES",
			Default: nStr(r[3]), Comment: r[4].String, Extra: r[5].String})
		if r[6].String == "PRI" {
			info.Key = append(info.Key, r[0].String)
		}
	}
	if rows, err := queryStrings(ctx, c.db, `SELECT index_name, GROUP_CONCAT(column_name ORDER BY seq_in_index SEPARATOR ', '), MIN(non_unique)
		FROM information_schema.statistics WHERE table_schema = ? AND table_name = ? GROUP BY index_name ORDER BY index_name = 'PRIMARY' DESC, 1`, db, info.Name); err == nil {
		for _, r := range rows {
			info.Indexes = append(info.Indexes, ObjectIndex{Name: r[0].String, Definition: "(" + r[1].String + ")", Unique: r[2].String == "0", Primary: r[0].String == "PRIMARY"})
		}
	}
	if rows, err := queryStrings(ctx, c.db, `SELECT constraint_name, GROUP_CONCAT(column_name ORDER BY ordinal_position SEPARATOR ', '),
			MAX(referenced_table_name), GROUP_CONCAT(referenced_column_name ORDER BY ordinal_position SEPARATOR ', ')
		FROM information_schema.key_column_usage WHERE table_schema = ? AND table_name = ? AND referenced_table_name IS NOT NULL
		GROUP BY constraint_name ORDER BY 1`, db, info.Name); err == nil {
		for _, r := range rows {
			info.Constraints = append(info.Constraints, ObjectConstraint{Name: r[0].String, Kind: "foreign_key",
				Definition: "FOREIGN KEY (" + r[1].String + ") REFERENCES " + r[2].String + " (" + r[3].String + ")"})
		}
	}
	what := "TABLE"
	if info.Kind == "view" {
		what = "VIEW"
	}
	if rows, err := queryStrings(ctx, c.db, "SHOW CREATE "+what+" "+c.quote(db)+"."+c.quote(info.Name)); err == nil && len(rows) > 0 && len(rows[0]) > 1 {
		info.Definition = rows[0][1].String
	}
	return nil
}

func (c *sqlClient) describeMSSQL(ctx context.Context, info *ObjectInfo) error {
	if info.SchemaName == "" {
		info.SchemaName = "dbo"
	}
	var id int64
	var kind string
	err := c.db.QueryRowContext(ctx, `SELECT o.object_id, o.type FROM sys.objects o JOIN sys.schemas s ON s.schema_id = o.schema_id
		WHERE s.name = @p1 AND o.name = @p2 AND o.type IN ('U', 'V')`, info.SchemaName, info.Name).Scan(&id, &kind)
	if err == sql.ErrNoRows {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	info.Kind = "table"
	if strings.TrimSpace(kind) == "V" {
		info.Kind = "view"
	}
	rows, err := queryStrings(ctx, c.db, `SELECT c.name,
			TYPE_NAME(c.user_type_id) + CASE
				WHEN TYPE_NAME(c.user_type_id) IN ('varchar', 'char', 'varbinary', 'binary') THEN '(' + CASE WHEN c.max_length = -1 THEN 'max' ELSE CAST(c.max_length AS varchar) END + ')'
				WHEN TYPE_NAME(c.user_type_id) IN ('nvarchar', 'nchar') THEN '(' + CASE WHEN c.max_length = -1 THEN 'max' ELSE CAST(c.max_length / 2 AS varchar) END + ')'
				WHEN TYPE_NAME(c.user_type_id) IN ('decimal', 'numeric') THEN '(' + CAST(c.precision AS varchar) + ',' + CAST(c.scale AS varchar) + ')'
				ELSE '' END,
			CASE WHEN c.is_nullable = 1 THEN 'true' ELSE 'false' END,
			OBJECT_DEFINITION(c.default_object_id),
			CASE WHEN c.is_identity = 1 THEN 'identity' WHEN c.is_computed = 1 THEN 'computed' ELSE '' END
		FROM sys.columns c WHERE c.object_id = @p1 ORDER BY c.column_id`, id)
	if err != nil {
		return err
	}
	for _, r := range rows {
		info.Columns = append(info.Columns, ObjectColumn{Name: r[0].String, Type: r[1].String, Nullable: r[2].String == "true", Default: nStr(r[3]), Extra: r[4].String})
	}
	if rows, err := queryStrings(ctx, c.db, `SELECT c.name FROM sys.indexes i
		JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
		JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
		WHERE i.object_id = @p1 AND i.is_primary_key = 1 ORDER BY ic.key_ordinal`, id); err == nil {
		for _, r := range rows {
			info.Key = append(info.Key, r[0].String)
		}
	}
	if rows, err := queryStrings(ctx, c.db, `SELECT i.name, i.type_desc, CASE WHEN i.is_unique = 1 THEN 'true' ELSE 'false' END,
			CASE WHEN i.is_primary_key = 1 THEN 'true' ELSE 'false' END,
			STUFF((SELECT ', ' + c.name FROM sys.index_columns ic JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
				WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id AND ic.is_included_column = 0 ORDER BY ic.key_ordinal FOR XML PATH('')), 1, 2, '')
		FROM sys.indexes i WHERE i.object_id = @p1 AND i.name IS NOT NULL ORDER BY i.is_primary_key DESC, i.name`, id); err == nil {
		for _, r := range rows {
			info.Indexes = append(info.Indexes, ObjectIndex{Name: r[0].String, Definition: strings.ToLower(r[1].String) + " (" + r[4].String + ")",
				Unique: r[2].String == "true", Primary: r[3].String == "true"})
		}
	}
	if rows, err := queryStrings(ctx, c.db, `SELECT fk.name,
			STUFF((SELECT ', ' + COL_NAME(k.parent_object_id, k.parent_column_id) FROM sys.foreign_key_columns k WHERE k.constraint_object_id = fk.object_id ORDER BY k.constraint_column_id FOR XML PATH('')), 1, 2, ''),
			OBJECT_SCHEMA_NAME(fk.referenced_object_id) + '.' + OBJECT_NAME(fk.referenced_object_id),
			STUFF((SELECT ', ' + COL_NAME(k.referenced_object_id, k.referenced_column_id) FROM sys.foreign_key_columns k WHERE k.constraint_object_id = fk.object_id ORDER BY k.constraint_column_id FOR XML PATH('')), 1, 2, '')
		FROM sys.foreign_keys fk WHERE fk.parent_object_id = @p1 ORDER BY fk.name`, id); err == nil {
		for _, r := range rows {
			info.Constraints = append(info.Constraints, ObjectConstraint{Name: r[0].String, Kind: "foreign_key",
				Definition: "FOREIGN KEY (" + r[1].String + ") REFERENCES " + r[2].String + " (" + r[3].String + ")"})
		}
	}
	if info.Kind == "view" {
		var def sql.NullString
		if err := c.db.QueryRowContext(ctx, `SELECT OBJECT_DEFINITION(@p1)`, id).Scan(&def); err == nil {
			info.Definition = def.String
		}
	}
	return nil
}
