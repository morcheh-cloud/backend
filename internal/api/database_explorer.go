package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/dbmon"
	"github.com/morche/backend/internal/dbquery"
	"github.com/morche/backend/internal/sshpool"
)

// The data explorer (user request 2026-11-21): what a database holds, its
// rows with filters, and queries people type and keep. Reading = Engineer
// (like Explain: the data itself is sensitive); a run that may write =
// Owner, and one that drops or empties data needs the database's name typed.
// Every typed query lands in the history (the audit trail), kept 90 days.

type explorerHandler struct {
	db *databaseHandler
	q  *sqlc.Queries

	mu    sync.Mutex
	conns map[string]*explorerConn
}

// explorerConn is one open connection, kept a few minutes for the next click.
type explorerConn struct {
	c       dbquery.Client
	ssh     *sshpool.Conn
	used    time.Time
	busy    int
	ready   chan struct{}
	err     error
	closing bool
}

const explorerIdle = 3 * time.Minute

func newExplorerHandler(db *databaseHandler) *explorerHandler {
	h := &explorerHandler{db: db, q: db.q, conns: map[string]*explorerConn{}}
	go h.janitor()
	return h
}

func (h *explorerHandler) janitor() {
	t := time.NewTicker(30 * time.Second)
	prune := time.NewTicker(time.Hour)
	for {
		select {
		case <-t.C:
			h.mu.Lock()
			for k, c := range h.conns {
				if c.busy == 0 && c.err == nil && time.Since(c.used) > explorerIdle && readyNow(c.ready) {
					delete(h.conns, k)
					go c.close()
				}
			}
			h.mu.Unlock()
		case <-prune.C:
			_ = h.q.PruneDatabaseQueryRuns(context.Background())
		}
	}
}

func readyNow(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func (c *explorerConn) close() {
	if c.c != nil {
		_ = c.c.Close()
	}
	if c.ssh != nil {
		c.ssh.Release()
	}
}

// connKey changes whenever how the database is reached changes.
func connKey(d sqlc.Database, name string) string {
	sum := sha256.New()
	fmt.Fprintf(sum, "%s|%s|%s|%v|%s|%d|%s|%x|%s|%s|%s|%v|%s|%s",
		d.ID, d.Engine, d.Mode, d.ServerID, d.Host, d.Port, d.Username, d.PasswordEnc,
		d.Dbname, d.Tls, d.CaCert, d.AllowInternal, d.Container, name)
	return hex.EncodeToString(sum.Sum(nil))
}

// open hands out a connection to one database inside d (name: the SQL
// database, the Redis number; unused for MongoDB). Call done after.
func (h *explorerHandler) open(ctx context.Context, d sqlc.Database, name string) (dbquery.Client, func(), error) {
	if d.Engine == dbmon.Mongo {
		name = ""
	}
	key := connKey(d, name)
	h.mu.Lock()
	c := h.conns[key]
	if c == nil {
		c = &explorerConn{ready: make(chan struct{})}
		h.conns[key] = c
		go func() {
			cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cfg, ssh, err := h.db.config(cctx, d)
			if err == nil {
				cfg.Timeout = 15 * time.Second
				c.c, err = dbquery.Open(cctx, cfg, name)
			}
			if err != nil && ssh != nil {
				ssh.Release()
				ssh = nil
			}
			h.mu.Lock()
			c.ssh, c.err, c.used = ssh, err, time.Now()
			if err != nil && h.conns[key] == c {
				delete(h.conns, key)
			}
			h.mu.Unlock()
			close(c.ready)
		}()
	}
	c.busy++
	h.mu.Unlock()
	release := func() {
		h.mu.Lock()
		c.busy--
		c.used = time.Now()
		h.mu.Unlock()
	}
	select {
	case <-ctx.Done():
		release()
		return nil, nil, ctx.Err()
	case <-c.ready:
	}
	if c.err != nil {
		release()
		return nil, nil, explorerConnError(c.err)
	}
	return c.c, release, nil
}

// drop forgets a connection that failed mid-use, so the next try reconnects.
func (h *explorerHandler) drop(d sqlc.Database, name string) {
	if d.Engine == dbmon.Mongo {
		name = ""
	}
	key := connKey(d, name)
	h.mu.Lock()
	c := h.conns[key]
	if c != nil && readyNow(c.ready) {
		delete(h.conns, key)
		go func() {
			// Let current users finish.
			time.Sleep(time.Minute)
			c.close()
		}()
	}
	h.mu.Unlock()
}

func explorerConnError(err error) error {
	_, msg := classifyDB(err)
	if msg == "" {
		msg = err.Error()
	}
	return huma.Error422UnprocessableEntity("Couldn't connect: " + msg)
}

// explorerError turns a failed read into an answer.
func explorerError(what string, err error) error {
	var se huma.StatusError
	if errors.As(err, &se) {
		return err
	}
	var rf *dbquery.ErrRefused
	if errors.As(err, &rf) {
		return huma.Error422UnprocessableEntity(rf.Reason)
	}
	if errors.Is(err, dbquery.ErrNotFound) {
		return huma.Error404NotFound(what + ": not found")
	}
	if errors.Is(err, dbquery.ErrUnsupported) {
		return huma.Error422UnprocessableEntity(what + ": not possible for this database.")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return huma.Error422UnprocessableEntity(what + ": it took too long.")
	}
	return huma.Error422UnprocessableEntity(what + ": " + err.Error())
}

// withClient runs fn on an open connection; a broken connection is dropped
// and tried once more.
func (h *explorerHandler) withClient(ctx context.Context, d sqlc.Database, name string, fn func(dbquery.Client) error) error {
	for attempt := 0; ; attempt++ {
		c, done, err := h.open(ctx, d, name)
		if err != nil {
			return err
		}
		err = fn(c)
		done()
		if err != nil && attempt == 0 && brokenConn(err) && ctx.Err() == nil {
			h.drop(d, name)
			continue
		}
		return err
	}
}

func brokenConn(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, w := range []string{"broken pipe", "connection reset", "bad connection", "use of closed", "eof", "connection refused", "closed pool", "client is disconnected", "server selection"} {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// ---- API shapes ----

type DatabaseQueryRequest struct {
	Database       string `json:"database,omitempty" maxLength:"128" doc:"The database inside the connection (Redis: its number); empty = the connection's"`
	Query          string `json:"query" minLength:"1" maxLength:"100000" doc:"SQL; MongoDB: JSON or db.coll.find(…); Redis: one command per line"`
	Limit          int    `json:"limit,omitempty" minimum:"1" maximum:"10000" doc:"Rows kept per result, default 500"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" minimum:"1" maximum:"600" doc:"Default 30"`
	SavedID        string `json:"saved_id,omitempty" maxLength:"36" doc:"The saved query this runs, to count it"`
}

type DatabaseChangeRequest struct {
	Database       string `json:"database,omitempty" maxLength:"128"`
	Query          string `json:"query" minLength:"1" maxLength:"100000"`
	Limit          int    `json:"limit,omitempty" minimum:"1" maximum:"10000"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" minimum:"1" maximum:"600"`
	SavedID        string `json:"saved_id,omitempty" maxLength:"36"`
	Confirm        string `json:"confirm,omitempty" maxLength:"200" doc:"The database's name, when the query drops or empties data (the 422 for body.confirm says why)"`
}

type DatabaseQueryResult struct {
	Results []dbquery.QueryResult `json:"results"`
	Error   string                `json:"error,omitempty" doc:"What the database said when a statement failed; results holds the ones before it"`
	Mode    string                `json:"mode" enum:"read,change"`
	Ms      int64                 `json:"ms"`
	RunID   string                `json:"run_id"`
}

type DatabaseQueryRun struct {
	ID       string    `json:"id"`
	UserName string    `json:"user_name"`
	Mine     bool      `json:"mine"`
	Database string    `json:"database"`
	Query    string    `json:"query"`
	Mode     string    `json:"mode" enum:"read,change"`
	OK       bool      `json:"ok"`
	Error    string    `json:"error,omitempty"`
	Rows     int64     `json:"rows"`
	Ms       int64     `json:"ms"`
	At       time.Time `json:"at"`
}

type DatabaseSavedQuery struct {
	ID            string     `json:"id"`
	Title         string     `json:"title"`
	Description   string     `json:"description"`
	Database      string     `json:"database"`
	Query         string     `json:"query"`
	Shared        bool       `json:"shared"`
	Pinned        bool       `json:"pinned"`
	Mine          bool       `json:"mine"`
	CanEdit       bool       `json:"can_edit"`
	CreatedByName string     `json:"created_by_name"`
	UpdatedByName string     `json:"updated_by_name"`
	RunCount      int32      `json:"run_count"`
	LastRunAt     *time.Time `json:"last_run_at"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" doc:"Send it back as revision when saving"`
}

type DatabaseSavedQueryBody struct {
	Title       string     `json:"title" minLength:"1" maxLength:"200"`
	Description string     `json:"description,omitempty" maxLength:"2000"`
	Database    string     `json:"database,omitempty" maxLength:"128"`
	Query       string     `json:"query" minLength:"1" maxLength:"100000"`
	Shared      bool       `json:"shared,omitempty" doc:"Everyone who can query this database sees it"`
	Pinned      bool       `json:"pinned,omitempty"`
	Revision    *time.Time `json:"revision,omitempty" doc:"updated_at when you loaded it: 409 when someone saved in between"`
}

type DatabaseSavedQueryPath struct {
	ID    string `path:"id" format:"uuid"`
	Query string `path:"query" format:"uuid"`
}

const maxSavedQueries = 500

func (h *explorerHandler) toSaved(ctx context.Context, d sqlc.Database, s sqlc.DatabaseSavedQuery) DatabaseSavedQuery {
	p := principalOf(ctx)
	mine := p != nil && s.CreatedBy != nil && *s.CreatedBy == p.User.ID
	return DatabaseSavedQuery{
		ID: s.ID.String(), Title: s.Title, Description: s.Description, Database: s.Dbname, Query: s.Query,
		Shared: s.Shared, Pinned: s.Pinned, Mine: mine, CanEdit: h.mayEdit(ctx, d, s),
		CreatedByName: s.CreatedByName, UpdatedByName: s.UpdatedByName, RunCount: s.RunCount,
		LastRunAt: s.LastRunAt, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
}

// mayEdit: your own, or a shared one when you're an Owner of the database.
func (h *explorerHandler) mayEdit(ctx context.Context, d sqlc.Database, s sqlc.DatabaseSavedQuery) bool {
	p := principalOf(ctx)
	if p == nil {
		return false
	}
	if s.CreatedBy != nil && *s.CreatedBy == p.User.ID {
		return true
	}
	return s.Shared && databaseLevelOf(p.Access, d) >= auth.Owner
}

func (h *explorerHandler) saved(ctx context.Context, d sqlc.Database, raw string) (sqlc.DatabaseSavedQuery, error) {
	s, err := h.q.GetDatabaseSavedQuery(ctx, sqlc.GetDatabaseSavedQueryParams{ID: uuid.MustParse(raw), DatabaseID: d.ID})
	if isNotFound(err) {
		return s, huma.Error404NotFound("saved query not found")
	}
	if err != nil {
		return s, internalError(err)
	}
	p := principalOf(ctx)
	if !s.Shared && (p == nil || s.CreatedBy == nil || *s.CreatedBy != p.User.ID) {
		return s, huma.Error404NotFound("saved query not found")
	}
	return s, nil
}

func timeoutOf(sec int) time.Duration {
	if sec <= 0 {
		sec = 30
	}
	return time.Duration(sec) * time.Second
}

// run runs a typed query and writes it into the history.
func (h *explorerHandler) run(ctx context.Context, d sqlc.Database, database, query string, limit, timeout int, change bool, savedID string) (*DatabaseQueryResult, error) {
	if limit <= 0 {
		limit = 500
	}
	o := dbquery.RunOptions{Change: change, Limit: limit, Timeout: timeoutOf(timeout)}
	start := time.Now()
	var results []dbquery.QueryResult
	var runErr error
	err := h.withClient(ctx, d, database, func(c dbquery.Client) error {
		results, runErr = c.Run(ctx, database, query, o)
		if runErr != nil && len(results) == 0 && brokenConn(runErr) {
			return runErr
		}
		return nil
	})
	if err != nil && runErr == nil {
		return nil, err
	}
	var rf *dbquery.ErrRefused
	if errors.As(runErr, &rf) {
		return nil, fieldError("body.query", rf.Reason, nil)
	}
	mode := "read"
	if change {
		mode = "change"
	}
	out := &DatabaseQueryResult{Results: results, Mode: mode, Ms: time.Since(start).Milliseconds()}
	if out.Results == nil {
		out.Results = []dbquery.QueryResult{}
	}
	if runErr != nil {
		out.Error = runErr.Error()
		if errors.Is(runErr, context.DeadlineExceeded) {
			out.Error = fmt.Sprintf("Stopped after %s: it took too long. Raise the time limit to let it run longer.", o.Timeout)
		} else if errors.Is(runErr, context.Canceled) {
			out.Error = "Stopped."
		}
	}
	var rows int64
	for _, r := range out.Results {
		if r.Affected != nil {
			rows += *r.Affected
		} else {
			rows += int64(len(r.Rows))
		}
	}
	p := principalOf(ctx)
	var uid *uuid.UUID
	if p != nil {
		uid = p.ID()
	}
	q := query
	if len(q) > 20000 {
		q = q[:20000] + "…"
	}
	bg := context.WithoutCancel(ctx)
	run, err := h.q.CreateDatabaseQueryRun(bg, sqlc.CreateDatabaseQueryRunParams{
		DatabaseID: d.ID, UserID: uid, UserName: byName(p), Dbname: database, Query: q, Mode: mode,
		Ok: runErr == nil, Error: truncateText(out.Error, 2000), Rows: rows, Ms: out.Ms,
	})
	if err == nil {
		out.RunID = run.ID.String()
	}
	if id, err := uuid.Parse(savedID); err == nil {
		_ = h.q.MarkDatabaseSavedQueryRun(bg, sqlc.MarkDatabaseSavedQueryRunParams{ID: id, DatabaseID: d.ID})
	}
	return out, nil
}

func truncateText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func registerDatabaseExplorer(api huma.API, h *explorerHandler) {
	tags := []string{"Database explorer"}

	huma.Register(api, huma.Operation{
		OperationID: "get-database-explorer",
		Method:      http.MethodGet,
		Path:        "/databases/{id}/explore",
		Summary:     "What a database holds",
		Description: "Its databases, schemas and tables (MongoDB: collections; Redis: numbered databases and their key count). Engineer.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Database string `query:"database" maxLength:"128" doc:"Which database inside the connection; empty = the connection's own"`
	}) (*struct{ Body *dbquery.DatabaseOverview }, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		var o *dbquery.DatabaseOverview
		err = h.withClient(ctx, d, in.Database, func(c dbquery.Client) error {
			o, err = c.Overview(ctx, in.Database)
			return err
		})
		if err != nil {
			return nil, explorerError("Couldn't read it", err)
		}
		return &struct{ Body *dbquery.DatabaseOverview }{o}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "describe-database-object",
		Method:      http.MethodGet,
		Path:        "/databases/{id}/explore/object",
		Summary:     "A table's columns, keys and indexes",
		Description: "MongoDB: fields seen in a sample of 100 documents. Not for Redis. Engineer.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Database string `query:"database" maxLength:"128"`
		Schema   string `query:"schema" maxLength:"128"`
		Name     string `query:"name" minLength:"1" maxLength:"256" required:"true"`
	}) (*struct{ Body *dbquery.ObjectInfo }, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		var info *dbquery.ObjectInfo
		err = h.withClient(ctx, d, in.Database, func(c dbquery.Client) error {
			info, err = c.Describe(ctx, in.Database, in.Schema, in.Name)
			return err
		})
		if err != nil {
			return nil, explorerError("Couldn't read the table", err)
		}
		return &struct{ Body *dbquery.ObjectInfo }{info}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-database-rows",
		Method:      http.MethodPost,
		Path:        "/databases/{id}/explore/rows",
		Summary:     "A page of a table's rows",
		Description: "Filters, search, sort and paging, always read only (Redis: keys by pattern, paged by cursor). Engineer.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Body dbquery.RowsRequest
	}) (*struct{ Body *dbquery.RowsPage }, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		var rows *dbquery.RowsPage
		err = h.withClient(ctx, d, in.Body.Database, func(c dbquery.Client) error {
			rows, err = c.Rows(ctx, in.Body)
			return err
		})
		if err != nil {
			return nil, explorerError("Couldn't read the rows", err)
		}
		return &struct{ Body *dbquery.RowsPage }{rows}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-database-key",
		Method:      http.MethodGet,
		Path:        "/databases/{id}/explore/key",
		Summary:     "One Redis key's value",
		Description: "Strings up to 64 KiB, the first 1000 items of other types (streams: the newest 200). Engineer.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Database string `query:"database" maxLength:"16"`
		Key      string `query:"key" minLength:"1" maxLength:"10000" required:"true"`
	}) (*struct{ Body *dbquery.RedisKey }, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		var kv *dbquery.RedisKey
		err = h.withClient(ctx, d, in.Database, func(c dbquery.Client) error {
			kr, ok := c.(dbquery.KeyReader)
			if !ok {
				return dbquery.ErrUnsupported
			}
			kv, err = kr.Key(ctx, in.Key)
			return err
		})
		if err != nil {
			return nil, explorerError("Couldn't read the key", err)
		}
		return &struct{ Body *dbquery.RedisKey }{kv}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "run-database-query",
		Method:      http.MethodPost,
		Path:        "/databases/{id}/query",
		Summary:     "Run a query, read only",
		Description: "Each statement is checked and run inside a read-only transaction (SQL Server: one that's rolled back; ClickHouse: sent with readonly = 2, table functions that reach outside the database refused); writes are refused. A failing statement comes back in error with the results before it. Cancel the request to stop it. Engineer.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Body DatabaseQueryRequest
	}) (*struct{ Body *DatabaseQueryResult }, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		b := in.Body
		out, err := h.run(ctx, d, b.Database, b.Query, b.Limit, b.TimeoutSeconds, false, b.SavedID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body *DatabaseQueryResult }{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "run-database-change",
		Method:      http.MethodPost,
		Path:        "/databases/{id}/query/change",
		Summary:     "Run a query that may change data",
		Description: "Postgres and SQL Server run the whole script in one transaction (all or nothing); MySQL and ClickHouse statement by statement (ClickHouse waits for mutations: mutations_sync = 2); MongoDB and Redis as sent. A script that drops or empties data, or changes who may do what, needs confirm = the database's name. Owner.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Body DatabaseChangeRequest
	}) (*struct{ Body *DatabaseQueryResult }, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		b := in.Body
		if risks := dbquery.Risks(d.Engine, b.Query); len(risks) > 0 && strings.TrimSpace(b.Confirm) != d.Name {
			return nil, fieldError("body.confirm", "This drops or empties data, or changes who may do what: "+strings.Join(risks, " · ")+". Type the database's name to run it.", nil)
		}
		out, err := h.run(ctx, d, b.Database, b.Query, b.Limit, b.TimeoutSeconds, true, b.SavedID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body *DatabaseQueryResult }{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-database-query-runs",
		Method:      http.MethodGet,
		Path:        "/databases/{id}/query-runs",
		Summary:     "Queries run on a database",
		Description: "Newest first, kept 90 days. who=all (everyone's) needs Owner; otherwise your own.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Who    string    `query:"who" enum:"mine,all" default:"mine"`
		Before time.Time `query:"before" doc:"Older than this (the last item's at)"`
		Limit  int32     `query:"limit" minimum:"1" maximum:"200" default:"50"`
	}) (*struct {
		Body struct {
			Items []DatabaseQueryRun `json:"items"`
		}
	}, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		p := principalOf(ctx)
		params := sqlc.ListDatabaseQueryRunsParams{DatabaseID: d.ID, Lim: in.Limit}
		if in.Who == "all" {
			if databaseLevelOf(p.Access, d) < auth.Owner {
				return nil, huma.Error403Forbidden("You need Owner access to see everyone's queries")
			}
		} else {
			params.UserID = p.ID()
		}
		if !in.Before.IsZero() {
			params.Before = &in.Before
		}
		rows, err := h.q.ListDatabaseQueryRuns(ctx, params)
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []DatabaseQueryRun `json:"items"`
			}
		}{}
		out.Body.Items = make([]DatabaseQueryRun, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = DatabaseQueryRun{
				ID: r.ID.String(), UserName: r.UserName, Mine: r.UserID != nil && *r.UserID == p.User.ID,
				Database: r.Dbname, Query: r.Query, Mode: r.Mode, OK: r.Ok, Error: r.Error, Rows: r.Rows, Ms: r.Ms, At: r.At,
			}
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-database-saved-queries",
		Method:      http.MethodGet,
		Path:        "/databases/{id}/saved-queries",
		Summary:     "Saved queries",
		Description: "Shared ones and your own; pinned first. Engineer.",
		Tags:        tags,
	}, func(ctx context.Context, in *DatabaseIDPath) (*struct {
		Body struct {
			Items []DatabaseSavedQuery `json:"items"`
		}
	}, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		rows, err := h.q.ListDatabaseSavedQueries(ctx, sqlc.ListDatabaseSavedQueriesParams{DatabaseID: d.ID, UserID: principalOf(ctx).ID()})
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []DatabaseSavedQuery `json:"items"`
			}
		}{}
		out.Body.Items = make([]DatabaseSavedQuery, len(rows))
		for i, s := range rows {
			out.Body.Items[i] = h.toSaved(ctx, d, s)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-database-saved-query",
		Method:        http.MethodPost,
		Path:          "/databases/{id}/saved-queries",
		Summary:       "Save a query",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Body DatabaseSavedQueryBody
	}) (*struct{ Body DatabaseSavedQuery }, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		b := in.Body
		if strings.TrimSpace(b.Title) == "" {
			return nil, fieldError("body.title", "Give it a name.", nil)
		}
		if n, err := h.q.CountDatabaseSavedQueries(ctx, d.ID); err == nil && n >= maxSavedQueries {
			return nil, huma.Error409Conflict("This database already has 500 saved queries. Delete some first.")
		}
		p := principalOf(ctx)
		s, err := h.q.CreateDatabaseSavedQuery(ctx, sqlc.CreateDatabaseSavedQueryParams{
			DatabaseID: d.ID, Title: strings.TrimSpace(b.Title), Description: strings.TrimSpace(b.Description),
			Dbname: b.Database, Query: b.Query, Shared: b.Shared, Pinned: b.Pinned,
			CreatedBy: p.ID(), CreatedByName: byName(p),
		})
		if err != nil {
			return nil, internalError(err)
		}
		return &struct{ Body DatabaseSavedQuery }{h.toSaved(ctx, d, s)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-database-saved-query",
		Method:      http.MethodPut,
		Path:        "/databases/{id}/saved-queries/{query}",
		Summary:     "Change a saved query",
		Description: "Your own, or a shared one as an Owner of the database.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DatabaseSavedQueryPath
		Body DatabaseSavedQueryBody
	}) (*struct{ Body DatabaseSavedQuery }, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		old, err := h.saved(ctx, d, in.Query)
		if err != nil {
			return nil, err
		}
		if !h.mayEdit(ctx, d, old) {
			return nil, huma.Error403Forbidden("You need Owner access to change someone else's saved query")
		}
		b := in.Body
		if b.Revision != nil && !b.Revision.Equal(old.UpdatedAt) {
			return nil, huma.Error409Conflict("Someone else saved this query after you opened it.")
		}
		s, err := h.q.UpdateDatabaseSavedQuery(ctx, sqlc.UpdateDatabaseSavedQueryParams{
			ID: old.ID, DatabaseID: d.ID, Title: strings.TrimSpace(b.Title), Description: strings.TrimSpace(b.Description),
			Dbname: b.Database, Query: b.Query, Shared: b.Shared, Pinned: b.Pinned, UpdatedByName: byName(principalOf(ctx)),
		})
		if err != nil {
			return nil, internalError(err)
		}
		return &struct{ Body DatabaseSavedQuery }{h.toSaved(ctx, d, s)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-database-saved-query",
		Method:        http.MethodDelete,
		Path:          "/databases/{id}/saved-queries/{query}",
		Summary:       "Delete a saved query",
		Description:   "Your own, or a shared one as an Owner of the database.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *DatabaseSavedQueryPath) (*struct{}, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		old, err := h.saved(ctx, d, in.Query)
		if err != nil {
			var se huma.StatusError
			if errors.As(err, &se) && se.GetStatus() == http.StatusNotFound {
				return nil, nil
			}
			return nil, err
		}
		if !h.mayEdit(ctx, d, old) {
			return nil, huma.Error403Forbidden("You need Owner access to delete someone else's saved query")
		}
		if _, err := h.q.DeleteDatabaseSavedQuery(ctx, sqlc.DeleteDatabaseSavedQueryParams{ID: old.ID, DatabaseID: d.ID}); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})
}
