package api

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
)

type Folder struct {
	ID          string  `json:"id" format:"uuid"`
	WorkspaceID string  `json:"workspace_id" format:"uuid"`
	ParentID    *string `json:"parent_id" format:"uuid" nullable:"true" doc:"Parent folder; null at the top level"`
	Name        string  `json:"name" example:"Production"`
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
		WorkspaceID: f.WorkspaceID.String(),
		ParentID:    optionalIDString(f.ParentID),
		Name:        f.Name,
		ServerCount: count,
		CreatedAt:   f.CreatedAt,
		UpdatedAt:   f.UpdatedAt,
	}
}

// ownFolderWorkspace says whether they may arrange a workspace's folders: only
// its Owners do.
func ownFolderWorkspace(acc *auth.Access, ws uuid.UUID) error {
	switch level := acc.WorkspaceLevel(ws); {
	case level == auth.None:
		return huma.Error404NotFound("folder not found")
	case level < auth.Owner:
		return forbidden(auth.Owner)
	}
	return nil
}

// newFolderWorkspace is where a top-level folder goes: the one open in the
// panel, or the only one they own.
func (a *authz) newFolderWorkspace(ctx context.Context, p *principal) (uuid.UUID, error) {
	if p.Workspace != nil {
		if _, err := a.q.GetWorkspace(ctx, *p.Workspace); isNotFound(err) {
			return uuid.Nil, huma.Error404NotFound("workspace not found")
		} else if err != nil {
			return uuid.Nil, internalError(err)
		}
		if err := ownFolderWorkspace(p.Access, *p.Workspace); err != nil {
			return uuid.Nil, err
		}
		return *p.Workspace, nil
	}
	list, err := a.q.ListWorkspaces(ctx)
	if err != nil {
		return uuid.Nil, internalError(err)
	}
	var owned []uuid.UUID
	for _, w := range list {
		if p.Access.WorkspaceLevel(w.ID) >= auth.Owner {
			owned = append(owned, w.ID)
		}
	}
	switch len(owned) {
	case 0:
		return uuid.Nil, forbidden(auth.Owner)
	case 1:
		return owned[0], nil
	}
	return uuid.Nil, huma.Error422UnprocessableEntity("Choose a workspace first (" + workspaceHeader + " header).")
}

// pruneFolders drops, in workspaces reached only through single servers, the
// folders that don't lead to one of those servers. Their names and shape are
// none of the caller's business.
func pruneFolders(acc *auth.Access, rows []sqlc.ListFoldersRow) []sqlc.ListFoldersRow {
	if acc.Admin {
		return rows
	}
	byID := make(map[uuid.UUID]sqlc.ListFoldersRow, len(rows))
	for _, r := range rows {
		byID[r.ID] = r
	}
	keep := map[uuid.UUID]bool{}
	for _, r := range rows {
		if acc.WorkspaceLevel(r.WorkspaceID) > auth.None {
			keep[r.ID] = true
			continue
		}
		if r.ServerCount == 0 {
			continue
		}
		for cur := r; ; {
			keep[cur.ID] = true
			if cur.ParentID == nil {
				break
			}
			parent, ok := byID[*cur.ParentID]
			if !ok {
				break
			}
			cur = parent
		}
	}
	out := make([]sqlc.ListFoldersRow, 0, len(keep))
	for _, r := range rows {
		if keep[r.ID] {
			out = append(out, r)
		}
	}
	return out
}

func registerFolders(api huma.API, a *authz) {
	q, db := a.q, a.db
	tags := []string{"Folders"}

	huma.Register(api, huma.Operation{
		OperationID: "list-folders",
		Method:      http.MethodGet,
		Path:        "/folders",
		Summary:     "List folders",
		Description: "Every folder, flat; build the tree from parent_id.",
		Tags:        tags,
	}, func(ctx context.Context, _ *struct{}) (*FolderListOutput, error) {
		p := principalOf(ctx)
		sc := p.scope()
		// Workspaces reached through single servers show the way to those servers.
		reached := slices.Clone(sc.workspaces)
		partial, err := q.ListServerWorkspaces(ctx, sc.servers)
		if err != nil {
			return nil, internalError(err)
		}
		for _, r := range partial {
			reached = append(reached, r.WorkspaceID)
		}
		rows, err := q.ListFolders(ctx, sqlc.ListFoldersParams{
			SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, ServerIds: sc.servers,
			FolderWorkspaceIds: reached, WorkspaceID: sc.current,
		})
		if err != nil {
			return nil, internalError(err)
		}
		rows = pruneFolders(p.Access, rows)
		out := &FolderListOutput{}
		out.Body.Items = make([]Folder, 0, len(rows))
		for _, r := range rows {
			out.Body.Items = append(out.Body.Items, toFolder(sqlc.Folder{
				ID: r.ID, WorkspaceID: r.WorkspaceID, ParentID: r.ParentID, Name: r.Name, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
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
		p := principalOf(ctx)
		var ws uuid.UUID
		if parent != nil {
			pf, err := q.GetFolder(ctx, *parent)
			if isNotFound(err) || (err == nil && p.Access.WorkspaceLevel(pf.WorkspaceID) == auth.None) {
				return nil, fieldError("body.parent_id", "Parent folder not found", parent.String())
			}
			if err != nil {
				return nil, internalError(err)
			}
			ws = pf.WorkspaceID
			if err := ownFolderWorkspace(p.Access, ws); err != nil {
				return nil, err
			}
		} else {
			var err error
			if ws, err = a.newFolderWorkspace(ctx, p); err != nil {
				return nil, err
			}
		}
		f, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{WorkspaceID: ws, Name: name, ParentID: parent})
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
		cur, err := q.GetFolder(ctx, id)
		if isNotFound(err) {
			return nil, huma.Error404NotFound("folder not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if err := ownFolderWorkspace(principalOf(ctx).Access, cur.WorkspaceID); err != nil {
			return nil, err
		}
		name := strings.TrimSpace(in.Body.Name)
		parent := parseOptionalID(in.Body.ParentID)
		if err := checkParent(ctx, q, parent, cur.WorkspaceID); err != nil {
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
		cur, err := q.GetFolder(ctx, id)
		if isNotFound(err) {
			return nil, huma.Error404NotFound("folder not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if err := ownFolderWorkspace(principalOf(ctx).Access, cur.WorkspaceID); err != nil {
			return nil, err
		}
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

// checkParent checks a folder exists in the workspace.
func checkParent(ctx context.Context, q *sqlc.Queries, parent *uuid.UUID, ws uuid.UUID) error {
	if parent == nil {
		return nil
	}
	f, err := q.GetFolder(ctx, *parent)
	if isNotFound(err) || (err == nil && f.WorkspaceID != ws) {
		return fieldError("body.parent_id", "Parent folder not found", parent.String())
	}
	if err != nil {
		return internalError(err)
	}
	return nil
}
