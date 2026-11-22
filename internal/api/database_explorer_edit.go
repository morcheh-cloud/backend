package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/dbquery"
)

// Changing rows from the data explorer (Owner), and filters kept per table.

// DatabaseViewState is what a saved filter puts back.
type DatabaseViewState struct {
	Search   string              `json:"search,omitempty" maxLength:"1000"`
	Filters  []dbquery.RowFilter `json:"filters,omitempty" maxItems:"50"`
	Match    string              `json:"match,omitempty" enum:"all,any"`
	Where    string              `json:"where,omitempty" maxLength:"20000"`
	Sort     []dbquery.RowSort   `json:"sort,omitempty" maxItems:"10"`
	PageSize int                 `json:"page_size,omitempty" minimum:"0" maximum:"1000"`
}

type DatabaseSavedView struct {
	ID            string            `json:"id"`
	Database      string            `json:"database"`
	Schema        string            `json:"schema"`
	Table         string            `json:"table"`
	Title         string            `json:"title"`
	State         DatabaseViewState `json:"state"`
	Shared        bool              `json:"shared"`
	Mine          bool              `json:"mine"`
	CanEdit       bool              `json:"can_edit"`
	CreatedByName string            `json:"created_by_name"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

type DatabaseSavedViewBody struct {
	Database string            `json:"database,omitempty" maxLength:"128"`
	Schema   string            `json:"schema,omitempty" maxLength:"128"`
	Table    string            `json:"table" minLength:"1" maxLength:"256"`
	Title    string            `json:"title" minLength:"1" maxLength:"200"`
	State    DatabaseViewState `json:"state"`
	Shared   bool              `json:"shared,omitempty"`
}

type DatabaseSavedViewPath struct {
	ID   string `path:"id" format:"uuid"`
	View string `path:"view" format:"uuid"`
}

const maxSavedViews = 1000

func (h *explorerHandler) toView(ctx context.Context, d sqlc.Database, v sqlc.DatabaseSavedView) DatabaseSavedView {
	p := principalOf(ctx)
	mine := p != nil && v.CreatedBy != nil && *v.CreatedBy == p.User.ID
	var st DatabaseViewState
	_ = json.Unmarshal(v.State, &st)
	return DatabaseSavedView{
		ID: v.ID.String(), Database: v.Dbname, Schema: v.SchemaName, Table: v.TableName, Title: v.Title,
		State: st, Shared: v.Shared, Mine: mine,
		CanEdit:       mine || (v.Shared && p != nil && databaseLevelOf(p.Access, d) >= auth.Owner),
		CreatedByName: v.CreatedByName, UpdatedAt: v.UpdatedAt,
	}
}

func (h *explorerHandler) view(ctx context.Context, d sqlc.Database, raw string) (sqlc.DatabaseSavedView, DatabaseSavedView, error) {
	v, err := h.q.GetDatabaseSavedView(ctx, sqlc.GetDatabaseSavedViewParams{ID: uuid.MustParse(raw), DatabaseID: d.ID})
	if isNotFound(err) {
		return v, DatabaseSavedView{}, huma.Error404NotFound("saved filter not found")
	}
	if err != nil {
		return v, DatabaseSavedView{}, internalError(err)
	}
	out := h.toView(ctx, d, v)
	if !v.Shared && !out.Mine {
		return v, out, huma.Error404NotFound("saved filter not found")
	}
	return v, out, nil
}

func registerDatabaseExplorerEdit(api huma.API, h *explorerHandler) {
	tags := []string{"Database explorer"}

	huma.Register(api, huma.Operation{
		OperationID: "edit-database-rows",
		Method:      http.MethodPost,
		Path:        "/databases/{id}/explore/edit",
		Summary:     "Add, change or remove rows of a table",
		Description: "By primary key (MongoDB: _id), all in one transaction on SQL engines; a change or removal that doesn't match exactly one row undoes everything. ClickHouse (MergeTree tables only, no transactions): every change and removal is counted first and nothing runs unless each matches exactly one row; then ALTER TABLE … UPDATE / lightweight DELETE one by one, waited for; sorting/partition key columns can't be changed. preview = only write out the statements. Owner. Every run lands in the query history.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Body dbquery.EditRequest
	}) (*struct{ Body *dbquery.EditResult }, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		var res *dbquery.EditResult
		err = h.withClient(ctx, d, in.Body.Database, func(c dbquery.Client) error {
			e, ok := c.(dbquery.Editor)
			if !ok {
				return dbquery.ErrUnsupported
			}
			res, err = e.Edit(ctx, in.Body)
			return err
		})
		if !in.Body.Preview {
			h.logEdit(ctx, d, in.Body, res, err)
		}
		if err != nil {
			return nil, explorerError("Nothing was saved", err)
		}
		return &struct{ Body *dbquery.EditResult }{res}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-database-saved-views",
		Method:      http.MethodGet,
		Path:        "/databases/{id}/saved-views",
		Summary:     "A table's saved filters",
		Description: "Shared ones and your own. Engineer.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Database string `query:"database" maxLength:"128"`
		Schema   string `query:"schema" maxLength:"128"`
		Table    string `query:"table" minLength:"1" maxLength:"256" required:"true"`
	}) (*struct {
		Body struct {
			Items []DatabaseSavedView `json:"items"`
		}
	}, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		rows, err := h.q.ListDatabaseSavedViews(ctx, sqlc.ListDatabaseSavedViewsParams{
			DatabaseID: d.ID, Dbname: in.Database, SchemaName: in.Schema, TableName: in.Table, UserID: principalOf(ctx).ID(),
		})
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []DatabaseSavedView `json:"items"`
			}
		}{}
		out.Body.Items = make([]DatabaseSavedView, len(rows))
		for i, v := range rows {
			out.Body.Items[i] = h.toView(ctx, d, v)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-database-saved-view",
		Method:        http.MethodPost,
		Path:          "/databases/{id}/saved-views",
		Summary:       "Save a table's filters",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		DatabaseIDPath
		Body DatabaseSavedViewBody
	}) (*struct{ Body DatabaseSavedView }, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		b := in.Body
		if strings.TrimSpace(b.Title) == "" {
			return nil, fieldError("body.title", "Give it a name.", nil)
		}
		if n, err := h.q.CountDatabaseSavedViews(ctx, d.ID); err == nil && n >= maxSavedViews {
			return nil, huma.Error409Conflict("This database already has 1000 saved filters. Delete some first.")
		}
		st, _ := json.Marshal(b.State)
		p := principalOf(ctx)
		v, err := h.q.CreateDatabaseSavedView(ctx, sqlc.CreateDatabaseSavedViewParams{
			DatabaseID: d.ID, Dbname: b.Database, SchemaName: b.Schema, TableName: b.Table,
			Title: strings.TrimSpace(b.Title), State: st, Shared: b.Shared, CreatedBy: p.ID(), CreatedByName: byName(p),
		})
		if err != nil {
			return nil, internalError(err)
		}
		return &struct{ Body DatabaseSavedView }{h.toView(ctx, d, v)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-database-saved-view",
		Method:      http.MethodPut,
		Path:        "/databases/{id}/saved-views/{view}",
		Summary:     "Change a saved filter",
		Description: "Your own, or a shared one as an Owner of the database. The table stays.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DatabaseSavedViewPath
		Body DatabaseSavedViewBody
	}) (*struct{ Body DatabaseSavedView }, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		old, cur, err := h.view(ctx, d, in.View)
		if err != nil {
			return nil, err
		}
		if !cur.CanEdit {
			return nil, huma.Error403Forbidden("You need Owner access to change someone else's saved filter")
		}
		shared := in.Body.Shared
		if !cur.Mine {
			shared = old.Shared
		}
		st, _ := json.Marshal(in.Body.State)
		v, err := h.q.UpdateDatabaseSavedView(ctx, sqlc.UpdateDatabaseSavedViewParams{
			ID: old.ID, DatabaseID: d.ID, Title: strings.TrimSpace(in.Body.Title), State: st, Shared: shared,
			UpdatedByName: byName(principalOf(ctx)),
		})
		if err != nil {
			return nil, internalError(err)
		}
		return &struct{ Body DatabaseSavedView }{h.toView(ctx, d, v)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-database-saved-view",
		Method:        http.MethodDelete,
		Path:          "/databases/{id}/saved-views/{view}",
		Summary:       "Delete a saved filter",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *DatabaseSavedViewPath) (*struct{}, error) {
		d, err := h.db.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		old, cur, err := h.view(ctx, d, in.View)
		if err != nil {
			var se huma.StatusError
			if errors.As(err, &se) && se.GetStatus() == http.StatusNotFound {
				return nil, nil
			}
			return nil, err
		}
		if !cur.CanEdit {
			return nil, huma.Error403Forbidden("You need Owner access to delete someone else's saved filter")
		}
		if _, err := h.q.DeleteDatabaseSavedView(ctx, sqlc.DeleteDatabaseSavedViewParams{ID: old.ID, DatabaseID: d.ID}); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})
}

// logEdit writes a row change into the query history, as the statements it ran.
func (h *explorerHandler) logEdit(ctx context.Context, d sqlc.Database, r dbquery.EditRequest, res *dbquery.EditResult, err error) {
	p := principalOf(ctx)
	var uid *uuid.UUID
	if p != nil {
		uid = p.ID()
	}
	q := "-- Changed rows of " + r.Table + " from the Data tab"
	var rows, ms int64
	if res != nil {
		q += "\n" + strings.Join(res.Statements, "\n")
		rows, ms = res.Affected, res.Ms
	}
	msg := ""
	if err != nil {
		msg = truncateText(err.Error(), 2000)
	}
	_, _ = h.q.CreateDatabaseQueryRun(context.WithoutCancel(ctx), sqlc.CreateDatabaseQueryRunParams{
		DatabaseID: d.ID, UserID: uid, UserName: byName(p), Dbname: r.Database, Query: truncateText(q, 20000),
		Mode: "change", Ok: err == nil, Error: msg, Rows: rows, Ms: ms,
	})
}
