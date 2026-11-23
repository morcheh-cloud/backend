// Package dbquery is the data explorer: it lists what a database holds,
// reads rows with filters, and runs the queries people type, read only unless
// they ask for changes. It reaches databases the way dbmon does (the caller
// passes a dbmon.Config) and knows nothing about HTTP or Morche's tables.
package dbquery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/morche/backend/internal/dbmon"
)

// Column is one column of a result.
type ResultColumn struct {
	Name string `json:"name"`
	Type string `json:"type" doc:"The engine's type name, when it gives one"`
}

// Result is what one statement gave back.
type QueryResult struct {
	Statement string         `json:"statement" doc:"The statement this answers, shortened"`
	Columns   []ResultColumn `json:"columns"`
	Rows      [][]*string    `json:"rows" doc:"Values as text; null is null"`
	Documents []string       `json:"documents,omitempty" doc:"MongoDB: each row's whole document as JSON"`
	Truncated bool           `json:"truncated" doc:"There were more rows than the limit"`
	Affected  *int64         `json:"affected" nullable:"true" doc:"Rows a change touched"`
	Message   string         `json:"message,omitempty"`
	Ms        int64          `json:"ms"`
}

// Rows is a page of a table, collection or key list.
type RowsPage struct {
	QueryResult
	Total      *int64 `json:"total" nullable:"true" doc:"Rows matching the filters, when counted"`
	Estimated  bool   `json:"estimated,omitempty" doc:"total is the engine's estimate"`
	NextCursor string `json:"next_cursor,omitempty" doc:"Redis: pass it back for the next page; empty = no more"`
}

// Filter narrows rows. Ops: eq, ne, gt, gte, lt, lte, contains,
// not_contains, starts, ends, in, null, not_null.
type RowFilter struct {
	Column string   `json:"column" minLength:"1" maxLength:"256"`
	Op     string   `json:"op" enum:"eq,ne,gt,gte,lt,lte,contains,not_contains,starts,ends,in,null,not_null"`
	Value  string   `json:"value,omitempty" maxLength:"10000"`
	Values []string `json:"values,omitempty" maxItems:"1000" doc:"For in"`
}

type RowSort struct {
	Column string `json:"column" minLength:"1" maxLength:"256"`
	Desc   bool   `json:"desc,omitempty"`
}

// RowsRequest asks for a page of one table (collection; Redis: keys).
type RowsRequest struct {
	Database string      `json:"database,omitempty" maxLength:"128"`
	Schema   string      `json:"schema,omitempty" maxLength:"128"`
	Table    string      `json:"table,omitempty" maxLength:"256" doc:"Redis: leave empty"`
	Filters  []RowFilter `json:"filters,omitempty" maxItems:"50"`
	Match    string      `json:"match,omitempty" enum:"all,any" doc:"all (default) or any filter"`
	Search   string      `json:"search,omitempty" maxLength:"1000" doc:"Text looked for in every column"`
	Where    string      `json:"where,omitempty" maxLength:"20000" doc:"Your own condition: SQL after WHERE, MongoDB a filter as JSON, Redis a key pattern. Run read only."`
	Sort     []RowSort   `json:"sort,omitempty" maxItems:"10"`
	Limit    int         `json:"limit,omitempty" minimum:"1" maximum:"1000" doc:"Default 100"`
	Offset   int64       `json:"offset,omitempty" minimum:"0"`
	Cursor   string      `json:"cursor,omitempty" maxLength:"64" doc:"Redis: next_cursor from the last page"`
	Count    bool        `json:"count,omitempty" doc:"Count every matching row too"`
}

// Object is a table, view or collection.
type DatabaseObject struct {
	Schema string `json:"schema"`
	Name   string `json:"name"`
	Kind   string `json:"kind" enum:"table,view,materialized_view,foreign_table,collection,timeseries,dictionary,index,alias,data_stream"`
	Rows   *int64 `json:"rows" nullable:"true" doc:"The engine's estimate"`
	Bytes  *int64 `json:"bytes" nullable:"true"`
}

// Overview is what a connection holds.
type DatabaseOverview struct {
	Engine    string           `json:"engine"`
	Databases []string         `json:"databases" doc:"Every database the login can open"`
	Database  string           `json:"database" doc:"The one listed below"`
	Schemas   []string         `json:"schemas" doc:"Postgres/SQL Server schemas in it"`
	Objects   []DatabaseObject `json:"objects"`
	Keys      *int64           `json:"keys,omitempty" nullable:"true" doc:"Redis: keys in the database"`
	Capped    bool             `json:"capped,omitempty" doc:"More objects than listed"`
	Notes     []string         `json:"notes"`
}

// ColumnInfo describes one column (MongoDB: a field seen in a sample).
type ObjectColumn struct {
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	Nullable bool    `json:"nullable"`
	Default  *string `json:"default" nullable:"true"`
	Key      bool    `json:"key" doc:"Part of the primary key"`
	Comment  string  `json:"comment,omitempty"`
	Extra    string  `json:"extra,omitempty" doc:"e.g. auto_increment, identity"`
}

type ObjectIndex struct {
	Name       string `json:"name"`
	Definition string `json:"definition"`
	Unique     bool   `json:"unique"`
	Primary    bool   `json:"primary"`
}

type ObjectConstraint struct {
	Name       string `json:"name"`
	Kind       string `json:"kind" enum:"foreign_key,check,unique"`
	Definition string `json:"definition"`
}

// ObjectInfo is one table's shape.
type ObjectInfo struct {
	SchemaName  string             `json:"schema"`
	Name        string             `json:"name"`
	Kind        string             `json:"kind"`
	Columns     []ObjectColumn     `json:"columns"`
	Key         []string           `json:"key"`
	Indexes     []ObjectIndex      `json:"indexes"`
	Constraints []ObjectConstraint `json:"constraints"`
	Definition  string             `json:"definition,omitempty" doc:"CREATE statement or view body, when the engine gives one"`
	Sampled     int                `json:"sampled,omitempty" doc:"MongoDB: documents the fields were read from"`
	Facts       []ObjectFact       `json:"facts,omitempty" doc:"ClickHouse: engine, sorting/partition key, TTL, parts and sizes"`
	ReadOnly    string             `json:"read_only,omitempty" doc:"Why its rows can't be added, changed or removed here; empty = they can (by key)"`
	KeyUnique   *bool              `json:"key_unique,omitempty" nullable:"true" doc:"false = the key may match several rows (ClickHouse): a change that matches more than one is refused"`
}

// ObjectFact is one labelled detail of a table.
type ObjectFact struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// KeyValue is one Redis key.
type RedisKey struct {
	Key       string       `json:"key"`
	Type      string       `json:"type"`
	TTLMs     int64        `json:"ttl_ms" doc:"-1 = never expires"`
	Size      int64        `json:"size" doc:"Length, items or members"`
	Text      *string      `json:"text" nullable:"true" doc:"A string's value"`
	Value     *QueryResult `json:"value,omitempty" doc:"Other types as rows"`
	Truncated bool         `json:"truncated"`
}

// RunOptions say how to run typed queries.
type RunOptions struct {
	Change  bool          // may write; otherwise read only
	Limit   int           // rows per result
	Timeout time.Duration // whole run
}

// Client is an open connection to one database (SQL: one database of the
// connection; MongoDB: all of them; Redis: one numbered database).
type Client interface {
	Overview(ctx context.Context, database string) (*DatabaseOverview, error)
	Describe(ctx context.Context, database, schema, name string) (*ObjectInfo, error)
	Rows(ctx context.Context, r RowsRequest) (*RowsPage, error)
	Run(ctx context.Context, database, query string, o RunOptions) ([]QueryResult, error)
	Close() error
}

// KeyReader is a Client that reads one key (Redis).
type KeyReader interface {
	Key(ctx context.Context, key string) (*RedisKey, error)
}

// ErrRefused is a query the chosen mode doesn't allow; its text says why.
type ErrRefused struct{ Reason string }

func (e *ErrRefused) Error() string { return e.Reason }

func refused(f string, a ...any) error { return &ErrRefused{Reason: fmt.Sprintf(f, a...)} }

var ErrUnsupported = errors.New("not possible for this database")

const app = "morche-explorer"

// Open connects. name is the database inside the connection (SQL), the
// numbered database (Redis), unused for MongoDB.
func Open(ctx context.Context, cfg dbmon.Config, name string) (Client, error) {
	switch cfg.Engine {
	case dbmon.Postgres, dbmon.MySQL, dbmon.MSSQL:
		return openSQL(ctx, cfg, name)
	case dbmon.Mongo:
		return openMongo(ctx, cfg)
	case dbmon.Redis:
		return openRedis(ctx, cfg, name)
	case dbmon.ClickHouse:
		return openClickHouse(ctx, cfg, name)
	case dbmon.Elastic:
		return openElastic(ctx, cfg)
	case dbmon.Meili:
		return openMeili(ctx, cfg)
	}
	return nil, fmt.Errorf("unknown engine %q", cfg.Engine)
}

const (
	defaultLimit = 100
	maxCell      = 64 << 10 // bytes kept of one value
	maxResult    = 16 << 20 // bytes of values in one result
)

func limitOf(n, def, most int) int {
	if n <= 0 {
		return def
	}
	return min(n, most)
}
