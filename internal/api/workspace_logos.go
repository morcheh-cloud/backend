package api

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/appicon"
	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
)

// A workspace shows in the panel's switcher as its first letter or a Lucide
// icon on a palette color, or as an uploaded picture.

// WorkspaceLook is how a workspace is drawn in the panel.
type WorkspaceLook struct {
	Color    string  `json:"color" doc:"A palette key; the panel owns the actual colors."`
	LogoKind string  `json:"logo_kind" enum:"letter,icon,upload"`
	LogoIcon string  `json:"logo_icon"`
	LogoURL  *string `json:"logo_url,omitempty" doc:"Where to load the uploaded logo from; changes with the image. Missing = draw the letter or the icon."`
}

func workspaceLook(id uuid.UUID, color, kind, icon string, stamp *time.Time) WorkspaceLook {
	l := WorkspaceLook{Color: color, LogoKind: kind, LogoIcon: icon}
	if kind == "upload" && stamp != nil {
		u := fmt.Sprintf("/workspaces/%s/logo?v=%d", id, stamp.UnixMicro())
		l.LogoURL = &u
	}
	return l
}

// lookOf reads the logo stamp a workspace row doesn't carry.
func (a *authz) lookOf(ctx context.Context, w sqlc.Workspace) (WorkspaceLook, error) {
	var stamp *time.Time
	if w.LogoKind == "upload" {
		t, err := a.q.GetWorkspaceLogoStamp(ctx, w.ID)
		if err != nil && !isNotFound(err) {
			return WorkspaceLook{}, internalError(err)
		}
		if err == nil {
			stamp = &t
		}
	}
	return workspaceLook(w.ID, w.Color, w.LogoKind, w.LogoIcon, stamp), nil
}

// mergeLook puts the body's color and logo over the current ones; empty
// fields keep what is there.
func (b WorkspaceBody) mergeLook(w *sqlc.Workspace) error {
	if b.Color != "" {
		if !slices.Contains(appColors, b.Color) {
			return fieldError("body.color", "Pick one of the palette's colors.", b.Color)
		}
		w.Color = b.Color
	}
	if b.LogoKind != "" {
		w.LogoKind = b.LogoKind
	}
	if b.LogoIcon != "" {
		w.LogoIcon = b.LogoIcon
	}
	if w.LogoKind == "icon" && w.LogoIcon == "" {
		return fieldError("body.logo_icon", "Pick an icon.", b.LogoIcon)
	}
	return nil
}

// workspaceOut answers a workspace after an admin changed it.
func (a *authz) workspaceOut(ctx context.Context, w sqlc.Workspace) (*WorkspaceOutput, error) {
	counts, err := a.q.CountWorkspaceResources(ctx, w.ID)
	if err != nil {
		return nil, internalError(err)
	}
	look, err := a.lookOf(ctx, w)
	if err != nil {
		return nil, err
	}
	return &WorkspaceOutput{Body: PanelWorkspace{
		ID: w.ID.String(), Name: w.Name, Description: w.Description,
		Level: auth.Owner.String(), CanCreate: true,
		ServerCount: counts.Servers, StorageCount: counts.Storages, AppCount: counts.Apps,
		WorkspaceLook: look,
	}}, nil
}

type WorkspaceLogoUpload struct {
	WorkspacePath
	RawBody []byte `contentType:"application/octet-stream"`
}

func registerWorkspaceLogos(api huma.API, a *authz) {
	tags := []string{"Workspaces"}

	huma.Register(api, huma.Operation{
		OperationID: "get-workspace-logo",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/logo",
		Summary:     "A workspace's uploaded logo",
		Description: "For anyone who sees the workspace in their list. Use logo_url from the workspace, which changes with the image.",
		Tags:        tags,
		Responses: map[string]*huma.Response{"200": {
			Description: "The image",
			Content:     map[string]*huma.MediaType{"image/*": {Schema: &huma.Schema{Type: "string", Format: "binary"}}},
		}},
	}, func(ctx context.Context, in *WorkspacePath) (*AppLogoOutput, error) {
		missing := huma.Error404NotFound("this workspace has no logo image")
		id, err := uuid.Parse(in.ID)
		if err != nil {
			return nil, missing
		}
		// The same rule as the list: a workspace you can't see has no logo.
		visible, err := a.visibleWorkspaces(ctx, principalOf(ctx))
		if err != nil {
			return nil, internalError(err)
		}
		if !slices.ContainsFunc(visible, func(w PanelWorkspace) bool { return w.ID == id.String() }) {
			return nil, missing
		}
		logo, err := a.q.GetWorkspaceLogo(ctx, id)
		if isNotFound(err) {
			return nil, missing
		}
		if err != nil {
			return nil, internalError(err)
		}
		// An SVG opened on its own must not run anything.
		return &AppLogoOutput{
			ContentType: logo.ContentType, CacheControl: "private, max-age=86400", NoSniff: "nosniff",
			CSP: "default-src 'none'; style-src 'unsafe-inline'; sandbox", Body: logo.Data,
		}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:  "put-workspace-logo",
		Method:       http.MethodPut,
		Path:         "/workspaces/{id}/logo",
		Summary:      "Upload a workspace's logo",
		Description:  "The raw image (PNG, JPEG, GIF, WebP, ICO or SVG, up to 1 MB); its type is read from the bytes. The workspace switches to it (logo_kind = upload).",
		Tags:         tags,
		MaxBodyBytes: appicon.MaxSize,
	}, func(ctx context.Context, in *WorkspaceLogoUpload) (*WorkspaceOutput, error) {
		id, _ := uuid.Parse(in.ID)
		ct, ok := appicon.Sniff(in.RawBody)
		if !ok {
			return nil, huma.Error422UnprocessableEntity("Use a PNG, JPEG, GIF, WebP, ICO or SVG image.")
		}
		var w sqlc.Workspace
		err := a.inTx(ctx, func(q *sqlc.Queries) error {
			var err error
			w, err = q.SetWorkspaceLogoKind(ctx, sqlc.SetWorkspaceLogoKindParams{ID: id, LogoKind: "upload"})
			if isNotFound(err) {
				return huma.Error404NotFound("workspace not found")
			}
			if err != nil {
				return internalError(err)
			}
			if err := q.PutWorkspaceLogo(ctx, sqlc.PutWorkspaceLogoParams{WorkspaceID: id, ContentType: ct, Data: in.RawBody}); err != nil {
				return internalError(err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return a.workspaceOut(ctx, w)
	})
}
