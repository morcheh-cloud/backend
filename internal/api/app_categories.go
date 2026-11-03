package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
)

// Arranging the Services page (categories and the order of everything) is a
// workspace-wide change: it needs Engineer on the whole workspace.

type AppCategoryPath struct {
	ID         string `path:"id" format:"uuid" doc:"The workspace."`
	CategoryID string `path:"categoryId" format:"uuid"`
}

type AppCategoryOutput struct {
	Body AppCategory
}

type AppLayoutGroup struct {
	CategoryID *string  `json:"category_id,omitempty" nullable:"true" doc:"null = uncategorized."`
	AppIDs     []string `json:"app_ids" format:"uuid" doc:"In order. Services of other workspaces or already removed are skipped."`
}

type AppLayoutBody struct {
	Categories []string         `json:"categories" format:"uuid" doc:"Category order."`
	Groups     []AppLayoutGroup `json:"groups"`
}

func registerAppCategories(api huma.API, h *appHandler) {
	tags := []string{"apps"}

	huma.Register(api, huma.Operation{
		OperationID:   "create-app-category",
		Method:        http.MethodPost,
		Path:          "/workspaces/{id}/app-categories",
		Summary:       "Add a service category",
		Description:   "It goes last.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body struct {
			Name  string `json:"name" minLength:"1" maxLength:"64"`
			Color string `json:"color,omitempty" enum:"slate,red,orange,amber,green,teal,blue,indigo,violet,pink" default:"slate"`
		}
	}) (*AppCategoryOutput, error) {
		name, err := categoryName(in.Body.Name)
		if err != nil {
			return nil, err
		}
		c, err := h.q.CreateAppCategory(ctx, sqlc.CreateAppCategoryParams{
			WorkspaceID: uuid.MustParse(in.ID), Name: name, Color: in.Body.Color,
		})
		if isUniqueViolation(err) {
			return nil, categoryTaken(name)
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &AppCategoryOutput{Body: toAppCategory(c)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-app-category",
		Method:      http.MethodPatch,
		Path:        "/workspaces/{id}/app-categories/{categoryId}",
		Summary:     "Rename or recolor a service category",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		AppCategoryPath
		Body struct {
			Name  *string `json:"name,omitempty" minLength:"1" maxLength:"64"`
			Color *string `json:"color,omitempty" enum:"slate,red,orange,amber,green,teal,blue,indigo,violet,pink"`
		}
	}) (*AppCategoryOutput, error) {
		ws, id := uuid.MustParse(in.ID), uuid.MustParse(in.CategoryID)
		prev, err := h.q.GetAppCategory(ctx, id)
		if isNotFound(err) || (err == nil && prev.WorkspaceID != ws) {
			return nil, huma.Error404NotFound("category not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		next := sqlc.UpdateAppCategoryParams{ID: id, WorkspaceID: ws, Name: prev.Name, Color: prev.Color}
		if in.Body.Name != nil {
			if next.Name, err = categoryName(*in.Body.Name); err != nil {
				return nil, err
			}
		}
		if in.Body.Color != nil {
			next.Color = *in.Body.Color
		}
		c, err := h.q.UpdateAppCategory(ctx, next)
		if isUniqueViolation(err) {
			return nil, categoryTaken(next.Name)
		}
		if isNotFound(err) {
			return nil, huma.Error404NotFound("category not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &AppCategoryOutput{Body: toAppCategory(c)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-app-category",
		Method:        http.MethodDelete,
		Path:          "/workspaces/{id}/app-categories/{categoryId}",
		Summary:       "Remove a service category",
		Description:   "Its services stay, uncategorized.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *AppCategoryPath) (*struct{}, error) {
		n, err := h.q.DeleteAppCategory(ctx, sqlc.DeleteAppCategoryParams{
			ID: uuid.MustParse(in.CategoryID), WorkspaceID: uuid.MustParse(in.ID),
		})
		if err != nil {
			return nil, internalError(err)
		}
		if n == 0 {
			return nil, huma.Error404NotFound("category not found")
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-apps-layout",
		Method:      http.MethodPut,
		Path:        "/workspaces/{id}/apps/layout",
		Summary:     "Arrange the Services page",
		Description: "Sets the category order and which category each service is in, in what order (position = index). Answers the page as list-apps does.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body AppLayoutBody
	}) (*struct{ Body AppList }, error) {
		ws := uuid.MustParse(in.ID)
		err := h.a.inTx(ctx, func(q *sqlc.Queries) error {
			for i, raw := range in.Body.Categories {
				id, err := category(ctx, q, ws, raw)
				if err != nil || id == nil {
					return fieldError(fmt.Sprintf("body.categories[%d]", i), "There's no such category in this workspace.", raw)
				}
				if err := q.SetAppCategoryPosition(ctx, sqlc.SetAppCategoryPositionParams{ID: *id, WorkspaceID: ws, Position: int32(i)}); err != nil {
					return internalError(err)
				}
			}
			for i, g := range in.Body.Groups {
				raw := ""
				if g.CategoryID != nil {
					raw = *g.CategoryID
				}
				cat, err := category(ctx, q, ws, raw)
				if err != nil {
					return fieldError(fmt.Sprintf("body.groups[%d].category_id", i), "There's no such category in this workspace.", raw)
				}
				for j, app := range g.AppIDs {
					if err := q.SetAppPlace(ctx, sqlc.SetAppPlaceParams{
						ID: uuid.MustParse(app), WorkspaceID: ws, CategoryID: cat, Position: int32(j),
					}); err != nil {
						return internalError(err)
					}
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		list, err := h.list(ctx, principalOf(ctx), &ws, "")
		if err != nil {
			return nil, err
		}
		return &struct{ Body AppList }{Body: list}, nil
	})
}

func categoryName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", fieldError("body.name", "Enter a name.", raw)
	}
	return name, nil
}

func categoryTaken(name string) error {
	return fieldError("body.name", "There's already a category with this name.", name)
}
