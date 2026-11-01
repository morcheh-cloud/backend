package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/morcheh/backend/internal/database/sqlc"
)

type Folder struct {
	ID       string  `json:"id" format:"uuid"`
	ParentID *string `json:"parent_id" format:"uuid" nullable:"true" doc:"Parent folder; null at the top level"`
	Name     string  `json:"name" example:"Production"`
	// Only the folder's own servers; add the subfolders' counts for a total.
	ServerCount int32     `json:"server_count" doc:"Servers directly in this folder, not counting subfolders"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type FolderBody struct {
	Name     string  `json:"name" minLength:"1" maxLength:"64" example:"Production"`
	ParentID *string `json:"parent_id,omitempty" format:"uuid" nullable:"true" doc:"Parent folder; leave out or null for the top level"`
}

type FolderIDPath struct {
	ID string `path:"id" format:"uuid"`
}

type FolderOutput struct {
	Body Folder
}

type FolderListOutput struct {
	Body struct {
		Items []Folder `json:"items"`
	}
}

func toFolder(f sqlc.Folder, count int32) Folder {
	return Folder{
		ID:          f.ID.String(),
		ParentID:    optionalIDString(f.ParentID),
		Name:        f.Name,
		ServerCount: count,
		CreatedAt:   f.CreatedAt,
		UpdatedAt:   f.UpdatedAt,
	}
}

func registerFolders(api huma.API, db *pgxpool.Pool) {
	q := sqlc.New(db)
	tags := []string{"Folders"}

	huma.Register(api, huma.Operation{
		OperationID: "list-folders",
		Method:      http.MethodGet,
		Path:        "/folders",
		Summary:     "List folders",
		Description: "Every folder, flat; build the tree from parent_id.",
		Tags:        tags,
	}, func(ctx context.Context, _ *struct{}) (*FolderListOutput, error) {
		rows, err := q.ListFolders(ctx)
		if err != nil {
			return nil, internalError(err)
		}
		out := &FolderListOutput{}
		out.Body.Items = make([]Folder, 0, len(rows))
		for _, r := range rows {
			out.Body.Items = append(out.Body.Items, toFolder(sqlc.Folder{
				ID: r.ID, ParentID: r.ParentID, Name: r.Name, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
			}, r.ServerCount))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-folder",
		Method:        http.MethodPost,
		Path:          "/folders",
		Summary:       "Create a folder",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct{ Body FolderBody }) (*FolderOutput, error) {
		name := strings.TrimSpace(in.Body.Name)
		parent := parseOptionalID(in.Body.ParentID)
		if err := checkParent(ctx, q, parent); err != nil {
			return nil, err
		}
		f, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: name, ParentID: parent})
		if isUniqueViolation(err) {
			return nil, fieldError("body.name", "A folder with this name already exists here", name)
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &FolderOutput{Body: toFolder(f, 0)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-folder",
		Method:      http.MethodPut,
		Path:        "/folders/{id}",
		Summary:     "Rename or move a folder",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		FolderIDPath
		Body FolderBody
	}) (*FolderOutput, error) {
		id := uuid.MustParse(in.ID)
		name := strings.TrimSpace(in.Body.Name)
		parent := parseOptionalID(in.Body.ParentID)
		if err := checkParent(ctx, q, parent); err != nil {
			return nil, err
		}
		if parent != nil {
			cycle, err := q.FolderSubtreeContains(ctx, sqlc.FolderSubtreeContainsParams{FolderID: id, Candidate: *parent})
			if err != nil {
				return nil, internalError(err)
			}
			if cycle {
				return nil, fieldError("body.parent_id", "A folder can't be moved into itself or one of its subfolders", parent.String())
			}
		}
		f, err := q.UpdateFolder(ctx, sqlc.UpdateFolderParams{ID: id, Name: name, ParentID: parent})
		switch {
		case isNotFound(err):
			return nil, huma.Error404NotFound("folder not found")
		case isUniqueViolation(err):
			return nil, fieldError("body.name", "A folder with this name already exists there", name)
		case err != nil:
			return nil, internalError(err)
		}
		return &FolderOutput{Body: toFolder(f, 0)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-folder",
		Method:        http.MethodDelete,
		Path:          "/folders/{id}",
		Summary:       "Delete a folder",
		Description:   "Its servers and subfolders move up to the folder's parent; nothing else is deleted.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *FolderIDPath) (*struct{}, error) {
		id := uuid.MustParse(in.ID)
		tx, err := db.Begin(ctx)
		if err != nil {
			return nil, internalError(err)
		}
		defer tx.Rollback(ctx)
		qtx := q.WithTx(tx)

		f, err := qtx.GetFolder(ctx, id)
		if isNotFound(err) {
			return nil, huma.Error404NotFound("folder not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if err := qtx.MoveFolderServers(ctx, sqlc.MoveFolderServersParams{FolderID: &id, NewFolderID: f.ParentID}); err != nil {
			return nil, internalError(err)
		}
		err = qtx.ReparentFolderChildren(ctx, sqlc.ReparentFolderChildrenParams{FolderID: &id, NewParentID: f.ParentID})
		if isUniqueViolation(err) {
			return nil, huma.Error409Conflict("A subfolder has the same name as a folder in the parent; rename one first")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if _, err := qtx.DeleteFolder(ctx, id); err != nil {
			return nil, internalError(err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})
}

func checkParent(ctx context.Context, q *sqlc.Queries, parent *uuid.UUID) error {
	if parent == nil {
		return nil
	}
	_, err := q.GetFolder(ctx, *parent)
	if isNotFound(err) {
		return fieldError("body.parent_id", "Parent folder not found", parent.String())
	}
	if err != nil {
		return internalError(err)
	}
	return nil
}
