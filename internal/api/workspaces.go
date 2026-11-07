package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
)

// PanelWorkspace is a workspace as the signed-in user sees it.
type PanelWorkspace struct {
	ID           string `json:"id" format:"uuid"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Level        string `json:"level" doc:"Your level on the whole workspace; none if you only reach some servers, storages or services in it."`
	CanCreate    bool   `json:"can_create" doc:"You can add servers, storages and services here."`
	Partial      bool   `json:"partial" doc:"You only reach some servers, storages or services in it."`
	ServerCount  int32  `json:"server_count" doc:"Servers you can reach here."`
	StorageCount int32  `json:"storage_count" doc:"Storages you can reach here."`
	AppCount     int32  `json:"app_count" doc:"Services you can reach here."`
	WorkspaceLook
}

type WorkspacePath struct {
	ID string `path:"id" format:"uuid"`
}

type WorkspaceBody struct {
	Name        string `json:"name" minLength:"1" maxLength:"64"`
	Description string `json:"description,omitempty" maxLength:"500"`
	Color       string `json:"color,omitempty" enum:"slate,red,orange,amber,green,teal,blue,indigo,violet,pink" doc:"Empty keeps the current one (indigo for a new workspace)."`
	LogoKind    string `json:"logo_kind,omitempty" enum:"letter,icon,upload" doc:"Empty keeps the current one. Leaving upload drops the picture; upload needs one (PUT /workspaces/{id}/logo)."`
	LogoIcon    string `json:"logo_icon,omitempty" pattern:"^[a-z0-9-]*$" maxLength:"40" doc:"The Lucide icon for logo_kind icon."`
}

type WorkspaceInput struct{ Body WorkspaceBody }

type WorkspaceUpdateInput struct {
	WorkspacePath
	Body WorkspaceBody
}

type WorkspaceOutput struct{ Body PanelWorkspace }

type WorkspaceListOutput struct {
	Body struct {
		Items []PanelWorkspace `json:"items"`
	}
}

type WorkspaceServer struct {
	ID   string `json:"id" format:"uuid"`
	Name string `json:"name"`
	Host string `json:"host"`
}

type WorkspaceStorage struct {
	ID       string `json:"id" format:"uuid"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
}

// WorkspaceApp is a service on the Services page.
type WorkspaceApp struct {
	ID      string `json:"id" format:"uuid"`
	Name    string `json:"name"`
	Address string `json:"address"`
}

type WorkspaceDetail struct {
	PanelWorkspace
	Servers  []WorkspaceServer  `json:"servers"`
	Storages []WorkspaceStorage `json:"storages"`
	Apps     []WorkspaceApp     `json:"apps"`
}

type WorkspaceDetailOutput struct{ Body WorkspaceDetail }

type WorkspaceAssignBody struct {
	ServerIDs  []string `json:"server_ids,omitempty" format:"uuid"`
	StorageIDs []string `json:"storage_ids,omitempty" format:"uuid"`
	AppIDs     []string `json:"app_ids,omitempty" format:"uuid" doc:"Services; they leave their category, which belongs to the old workspace."`
}

type WorkspaceAssignInput struct {
	WorkspacePath
	Body WorkspaceAssignBody
}

// PanelGrant is one row of who can reach what, with the names a screen shows.
type PanelGrant struct {
	ID            string    `json:"id" format:"uuid"`
	UserID        *string   `json:"user_id,omitempty" format:"uuid"`
	GroupID       *string   `json:"group_id,omitempty" format:"uuid"`
	WorkspaceID   *string   `json:"workspace_id,omitempty" format:"uuid"`
	ServerID      *string   `json:"server_id,omitempty" format:"uuid"`
	StorageID     *string   `json:"storage_id,omitempty" format:"uuid"`
	AppID         *string   `json:"app_id,omitempty" format:"uuid"`
	Level         string    `json:"level" enum:"viewer,operator,engineer,owner"`
	CanCreate     bool      `json:"can_create"`
	Username      *string   `json:"username,omitempty"`
	FullName      *string   `json:"full_name,omitempty"`
	UserStatus    *string   `json:"user_status,omitempty"`
	GroupName     *string   `json:"group_name,omitempty"`
	WorkspaceName *string   `json:"workspace_name,omitempty"`
	ServerName    *string   `json:"server_name,omitempty"`
	StorageName   *string   `json:"storage_name,omitempty"`
	AppName       *string   `json:"app_name,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type GrantListInput struct {
	UserID      string `query:"user_id" format:"uuid"`
	GroupID     string `query:"group_id" format:"uuid"`
	WorkspaceID string `query:"workspace_id" format:"uuid"`
	ServerID    string `query:"server_id" format:"uuid"`
	StorageID   string `query:"storage_id" format:"uuid"`
	AppID       string `query:"app_id" format:"uuid"`
}

type GrantListOutput struct {
	Body struct {
		Items []PanelGrant `json:"items"`
	}
}

type GrantBody struct {
	UserID  *string `json:"user_id,omitempty" format:"uuid"`
	GroupID *string `json:"group_id,omitempty" format:"uuid"`
	GrantSpec
}

type GrantInput struct{ Body GrantBody }

type GrantOutput struct {
	Body struct {
		ID string `json:"id" format:"uuid"`
	}
}

type GrantIDPath struct {
	ID string `path:"id" format:"uuid"`
}

type PrincipalUser struct {
	ID       string `json:"id" format:"uuid"`
	Username string `json:"username"`
	FullName string `json:"full_name"`
}

type PrincipalGroup struct {
	ID   string `json:"id" format:"uuid"`
	Name string `json:"name"`
}

type PrincipalsOutput struct {
	Body struct {
		Users  []PrincipalUser  `json:"users"`
		Groups []PrincipalGroup `json:"groups"`
	}
}

// visibleWorkspaces lists what someone can open: every workspace they have a
// grant on, and those where they only reach single servers, storages or
// services. The
// counts never reveal what's in a workspace beyond what they can reach.
func (a *authz) visibleWorkspaces(ctx context.Context, p *principal) ([]PanelWorkspace, error) {
	list, err := a.q.ListWorkspaces(ctx)
	if err != nil {
		return nil, err
	}
	acc := p.Access
	s := p.scope()
	servers, err := a.q.ListServerWorkspaces(ctx, s.servers)
	if err != nil {
		return nil, err
	}
	storages, err := a.q.ListStorageWorkspaces(ctx, s.storages)
	if err != nil {
		return nil, err
	}
	apps, err := a.q.ListAppWorkspaces(ctx, s.apps)
	if err != nil {
		return nil, err
	}
	serverCount, storageCount, appCount := map[uuid.UUID]int32{}, map[uuid.UUID]int32{}, map[uuid.UUID]int32{}
	for _, r := range servers {
		serverCount[r.WorkspaceID]++
	}
	for _, r := range storages {
		storageCount[r.WorkspaceID]++
	}
	for _, r := range apps {
		appCount[r.WorkspaceID]++
	}
	out := make([]PanelWorkspace, 0, len(list))
	for _, w := range list {
		level := acc.WorkspaceLevel(w.ID)
		v := PanelWorkspace{
			ID: w.ID.String(), Name: w.Name, Description: w.Description,
			Level: level.String(), CanCreate: acc.CanCreateIn(w.ID),
			WorkspaceLook: workspaceLook(w.ID, w.Color, w.LogoKind, w.LogoIcon, w.LogoUpdatedAt),
		}
		switch {
		case level > auth.None:
			v.ServerCount, v.StorageCount, v.AppCount = w.ServerCount, w.StorageCount, w.AppCount
		case serverCount[w.ID] > 0 || storageCount[w.ID] > 0 || appCount[w.ID] > 0:
			v.Partial = true
			v.ServerCount, v.StorageCount, v.AppCount = serverCount[w.ID], storageCount[w.ID], appCount[w.ID]
		case v.CanCreate:
		default:
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

func workspaceConflict(err error) error {
	if isUniqueViolation(err) {
		return fieldError("body.name", "A workspace with this name already exists.", nil)
	}
	return internalError(err)
}

// ownsTarget checks the caller is an Owner of a grant's target: only they may
// see or change who has access, and admins are Owner everywhere. It answers the
// workspace the target lives in.
func (a *authz) ownsTarget(ctx context.Context, acc *auth.Access, ws, srv, st, app *uuid.UUID) (workspace *uuid.UUID, err error) {
	missing := huma.Error404NotFound("not found")
	var level auth.Level
	switch {
	case ws != nil:
		if _, err := a.q.GetWorkspace(ctx, *ws); isNotFound(err) {
			return nil, missing
		} else if err != nil {
			return nil, internalError(err)
		}
		workspace, level = ws, acc.WorkspaceLevel(*ws)
	case srv != nil:
		id, err := a.q.GetServerWorkspace(ctx, *srv)
		if isNotFound(err) {
			return nil, missing
		}
		if err != nil {
			return nil, internalError(err)
		}
		workspace, level = &id, acc.ServerLevel(id, *srv)
	case st != nil:
		id, err := a.q.GetStorageWorkspace(ctx, *st)
		if isNotFound(err) {
			return nil, missing
		}
		if err != nil {
			return nil, internalError(err)
		}
		workspace, level = &id, acc.StorageLevel(id, *st)
	case app != nil:
		id, err := a.q.GetAppWorkspace(ctx, *app)
		if isNotFound(err) {
			return nil, missing
		}
		if err != nil {
			return nil, internalError(err)
		}
		workspace, level = &id, acc.AppLevel(id, *app)
	default:
		return nil, huma.Error403Forbidden("Choose a workspace, server, storage or service.")
	}
	if level == auth.None {
		return nil, missing
	}
	if level < auth.Owner {
		return nil, forbidden(auth.Owner)
	}
	return workspace, nil
}

func registerWorkspaces(api huma.API, a *authz) {
	tags := []string{"Workspaces"}

	huma.Register(api, huma.Operation{
		OperationID: "list-workspaces", Method: http.MethodGet, Path: "/workspaces",
		Summary: "List the workspaces you can open", Tags: tags,
	}, func(ctx context.Context, _ *struct{}) (*WorkspaceListOutput, error) {
		list, err := a.visibleWorkspaces(ctx, principalOf(ctx))
		if err != nil {
			return nil, internalError(err)
		}
		out := &WorkspaceListOutput{}
		out.Body.Items = list
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-workspace", Method: http.MethodGet, Path: "/workspaces/{id}",
		Summary: "Get a workspace and what's in it", Tags: tags,
	}, func(ctx context.Context, in *WorkspacePath) (*WorkspaceDetailOutput, error) {
		id, _ := uuid.Parse(in.ID)
		p := principalOf(ctx)
		w, err := a.q.GetWorkspace(ctx, id)
		if err != nil {
			return nil, internalError(err)
		}
		counts, err := a.q.CountWorkspaceResources(ctx, id)
		if err != nil {
			return nil, internalError(err)
		}
		servers, err := a.q.ListWorkspaceServers(ctx, id)
		if err != nil {
			return nil, internalError(err)
		}
		storages, err := a.q.ListWorkspaceStorages(ctx, id)
		if err != nil {
			return nil, internalError(err)
		}
		apps, err := a.q.ListWorkspaceApps(ctx, id)
		if err != nil {
			return nil, internalError(err)
		}
		look, err := a.lookOf(ctx, w)
		if err != nil {
			return nil, err
		}
		out := &WorkspaceDetailOutput{}
		out.Body.PanelWorkspace = PanelWorkspace{
			ID: w.ID.String(), Name: w.Name, Description: w.Description,
			Level: p.Level.String(), CanCreate: p.Access.CanCreateIn(id),
			ServerCount: counts.Servers, StorageCount: counts.Storages, AppCount: counts.Apps,
			WorkspaceLook: look,
		}
		out.Body.Servers = make([]WorkspaceServer, 0, len(servers))
		for _, s := range servers {
			out.Body.Servers = append(out.Body.Servers, WorkspaceServer{ID: s.ID.String(), Name: s.Name, Host: s.Host})
		}
		out.Body.Storages = make([]WorkspaceStorage, 0, len(storages))
		for _, s := range storages {
			out.Body.Storages = append(out.Body.Storages, WorkspaceStorage{ID: s.ID.String(), Name: s.Name, Protocol: s.Protocol})
		}
		out.Body.Apps = make([]WorkspaceApp, 0, len(apps))
		for _, s := range apps {
			out.Body.Apps = append(out.Body.Apps, WorkspaceApp{ID: s.ID.String(), Name: s.Name, Address: s.Address})
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-workspace", Method: http.MethodPost, Path: "/workspaces",
		Summary: "Create a workspace", Tags: tags, DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *WorkspaceInput) (*WorkspaceOutput, error) {
		b := in.Body
		look := sqlc.Workspace{Color: "indigo", LogoKind: "letter"}
		if err := b.mergeLook(&look); err != nil {
			return nil, err
		}
		if look.LogoKind == "upload" {
			return nil, fieldError("body.logo_kind", "Save the workspace first, then upload its logo.", b.LogoKind)
		}
		w, err := a.q.CreateWorkspace(ctx, sqlc.CreateWorkspaceParams{
			Name: strings.TrimSpace(b.Name), Description: strings.TrimSpace(b.Description),
			Color: look.Color, LogoKind: look.LogoKind, LogoIcon: look.LogoIcon,
		})
		if err != nil {
			return nil, workspaceConflict(err)
		}
		return &WorkspaceOutput{Body: PanelWorkspace{
			ID: w.ID.String(), Name: w.Name, Description: w.Description,
			Level: auth.Owner.String(), CanCreate: true,
			WorkspaceLook: workspaceLook(w.ID, w.Color, w.LogoKind, w.LogoIcon, nil),
		}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-workspace", Method: http.MethodPatch, Path: "/workspaces/{id}",
		Summary: "Edit a workspace", Tags: tags,
		Description: "Its name, description and how it shows in the panel (color and logo). An uploaded logo goes up with PUT /workspaces/{id}/logo.",
	}, func(ctx context.Context, in *WorkspaceUpdateInput) (*WorkspaceOutput, error) {
		id, _ := uuid.Parse(in.ID)
		b := in.Body
		var w sqlc.Workspace
		err := a.inTx(ctx, func(q *sqlc.Queries) error {
			prev, err := q.GetWorkspace(ctx, id)
			if isNotFound(err) {
				return huma.Error404NotFound("workspace not found")
			}
			if err != nil {
				return internalError(err)
			}
			look := prev
			if err := b.mergeLook(&look); err != nil {
				return err
			}
			if look.LogoKind == "upload" && prev.LogoKind != "upload" {
				if _, err := q.GetWorkspaceLogoStamp(ctx, id); isNotFound(err) {
					return fieldError("body.logo_kind", "Upload a logo first.", b.LogoKind)
				} else if err != nil {
					return internalError(err)
				}
			}
			if look.LogoKind != "upload" {
				if err := q.DeleteWorkspaceLogo(ctx, id); err != nil {
					return internalError(err)
				}
			}
			w, err = q.UpdateWorkspace(ctx, sqlc.UpdateWorkspaceParams{
				ID: id, Name: strings.TrimSpace(b.Name), Description: strings.TrimSpace(b.Description),
				Color: look.Color, LogoKind: look.LogoKind, LogoIcon: look.LogoIcon,
			})
			if err != nil {
				return workspaceConflict(err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return a.workspaceOut(ctx, w)
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-workspace", Method: http.MethodDelete, Path: "/workspaces/{id}",
		Summary: "Delete an empty workspace", Tags: tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *WorkspacePath) (*struct{}, error) {
		id, _ := uuid.Parse(in.ID)
		err := a.inTx(ctx, func(q *sqlc.Queries) error {
			if err := q.LockAuth(ctx); err != nil {
				return internalError(err)
			}
			counts, err := q.CountWorkspaceResources(ctx, id)
			if err != nil {
				return internalError(err)
			}
			if counts.Servers > 0 || counts.Storages > 0 || counts.Databases > 0 || counts.Apps > 0 {
				return huma.Error409Conflict("Move or remove its servers, storages, databases and services first.")
			}
			total, err := q.CountWorkspaces(ctx)
			if err != nil {
				return internalError(err)
			}
			if total <= 1 {
				return huma.Error409Conflict("This is the last workspace.")
			}
			n, err := q.DeleteWorkspace(ctx, id)
			if err != nil {
				return internalError(err)
			}
			if n == 0 {
				return huma.Error404NotFound("workspace not found")
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		a.invalidate()
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "assign-workspace", Method: http.MethodPost, Path: "/workspaces/{id}/assign",
		Summary: "Move servers, storages and services into a workspace", Tags: tags,
		Description:   "Moved servers leave their folder and moved services their category; both belong to the old workspace.",
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *WorkspaceAssignInput) (*struct{}, error) {
		id, _ := uuid.Parse(in.ID)
		err := a.inTx(ctx, func(q *sqlc.Queries) error {
			if _, err := q.GetWorkspace(ctx, id); isNotFound(err) {
				return huma.Error404NotFound("workspace not found")
			} else if err != nil {
				return internalError(err)
			}
			if _, err := q.MoveServersToWorkspace(ctx, sqlc.MoveServersToWorkspaceParams{WorkspaceID: id, Ids: parseIDs(in.Body.ServerIDs)}); err != nil {
				if isUniqueViolation(err) {
					return huma.Error409Conflict("A server with the same name is already in that workspace.")
				}
				return internalError(err)
			}
			if _, err := q.MoveStoragesToWorkspace(ctx, sqlc.MoveStoragesToWorkspaceParams{WorkspaceID: id, Ids: parseIDs(in.Body.StorageIDs)}); err != nil {
				if isUniqueViolation(err) {
					return huma.Error409Conflict("A storage with the same name is already in that workspace.")
				}
				return internalError(err)
			}
			if _, err := q.MoveAppsToWorkspace(ctx, sqlc.MoveAppsToWorkspaceParams{WorkspaceID: id, Ids: parseIDs(in.Body.AppIDs)}); err != nil {
				return internalError(err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		a.invalidate()
		return nil, nil
	})

	// ---- Who can reach what ----

	huma.Register(api, huma.Operation{
		OperationID: "list-grants", Method: http.MethodGet, Path: "/grants",
		Summary: "List who has access", Tags: tags,
		Description: "Admins can filter by anything. Others must name a workspace, server, storage or service they own.",
	}, func(ctx context.Context, in *GrantListInput) (*GrantListOutput, error) {
		p := principalOf(ctx)
		params := sqlc.ListGrantsParams{
			UserID: parseOptionalID(&in.UserID), GroupID: parseOptionalID(&in.GroupID),
			WorkspaceID: parseOptionalID(&in.WorkspaceID), ServerID: parseOptionalID(&in.ServerID),
			StorageID: parseOptionalID(&in.StorageID), AppID: parseOptionalID(&in.AppID),
		}
		if !p.Access.Admin {
			if params.UserID != nil || params.GroupID != nil {
				return nil, huma.Error403Forbidden("Only a system admin can do this.")
			}
			if _, err := a.ownsTarget(ctx, p.Access, params.WorkspaceID, params.ServerID, params.StorageID, params.AppID); err != nil {
				return nil, err
			}
		}
		rows, err := a.q.ListGrants(ctx, params)
		if err != nil {
			return nil, internalError(err)
		}
		out := &GrantListOutput{}
		out.Body.Items = make([]PanelGrant, 0, len(rows))
		for _, g := range rows {
			out.Body.Items = append(out.Body.Items, PanelGrant{
				ID: g.ID.String(), UserID: optionalIDString(g.UserID), GroupID: optionalIDString(g.GroupID),
				WorkspaceID: optionalIDString(g.WorkspaceID), ServerID: optionalIDString(g.ServerID),
				StorageID: optionalIDString(g.StorageID), AppID: optionalIDString(g.AppID), Level: g.Level, CanCreate: g.CanCreate,
				Username: g.Username, FullName: g.FullName, UserStatus: g.UserStatus, GroupName: g.GroupName,
				WorkspaceName: g.WorkspaceName, ServerName: g.ServerName, StorageName: g.StorageName, AppName: g.AppName,
				CreatedAt: g.CreatedAt,
			})
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-grant", Method: http.MethodPut, Path: "/grants",
		Summary: "Give or change access", Tags: tags,
		Description: "One person or group, one workspace, server, storage or service. Admins and the target's Owners can. Only admins decide who may add servers: an Owner passes on at most what they have themselves.",
	}, func(ctx context.Context, in *GrantInput) (*GrantOutput, error) {
		p := principalOf(ctx)
		user, group := parseOptionalID(in.Body.UserID), parseOptionalID(in.Body.GroupID)
		if (user == nil) == (group == nil) {
			return nil, fieldError("body.user_id", "Choose one person or group.", nil)
		}
		params, err := in.Body.GrantSpec.params("body.level")
		if err != nil {
			return nil, err
		}
		params.UserID, params.GroupID = user, group

		ws, err := a.ownsTarget(ctx, p.Access, params.WorkspaceID, params.ServerID, params.StorageID, params.AppID)
		if err != nil {
			return nil, err
		}
		existing, err := a.q.FindGrant(ctx, sqlc.FindGrantParams{
			UserID: user, GroupID: group, WorkspaceID: params.WorkspaceID,
			ServerID: params.ServerID, StorageID: params.StorageID, AppID: params.AppID,
		})
		found := err == nil
		if err != nil && !isNotFound(err) {
			return nil, internalError(err)
		}
		if params.WorkspaceID != nil {
			switch {
			case p.Access.Admin:
				if in.Body.CanCreate == nil && found {
					params.CanCreate = existing.CanCreate
				}
			case found:
				if in.Body.CanCreate != nil && *in.Body.CanCreate != existing.CanCreate {
					return nil, huma.Error403Forbidden("Only a system admin can change who may add servers.")
				}
				params.CanCreate = existing.CanCreate
			default:
				if in.Body.CanCreate != nil && *in.Body.CanCreate && !p.Access.CanCreateIn(*ws) {
					return nil, huma.Error403Forbidden("Only a system admin can change who may add servers.")
				}
				params.CanCreate = in.Body.Level == auth.Owner.String() && p.Access.CanCreateIn(*ws)
				if in.Body.CanCreate != nil {
					params.CanCreate = *in.Body.CanCreate
				}
			}
		}
		if !p.Access.Admin && user != nil && *user == p.User.ID {
			return nil, huma.Error403Forbidden("You can't change your own access.")
		}
		g, err := a.q.UpsertGrant(ctx, params)
		if isForeignKeyViolation(err) {
			return nil, fieldError("body.user_id", "That person or group no longer exists.", nil)
		}
		if err != nil {
			return nil, internalError(err)
		}
		a.invalidate()
		out := &GrantOutput{}
		out.Body.ID = g.ID.String()
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-grant", Method: http.MethodDelete, Path: "/grants/{id}",
		Summary: "Remove access", Tags: tags, DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *GrantIDPath) (*struct{}, error) {
		p := principalOf(ctx)
		id, _ := uuid.Parse(in.ID)
		g, err := a.q.GetGrant(ctx, id)
		if isNotFound(err) {
			return nil, huma.Error404NotFound("not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if _, err := a.ownsTarget(ctx, p.Access, g.WorkspaceID, g.ServerID, g.StorageID, g.AppID); err != nil {
			return nil, err
		}
		if !p.Access.Admin && g.UserID != nil && *g.UserID == p.User.ID {
			return nil, huma.Error403Forbidden("You can't change your own access.")
		}
		if _, err := a.q.DeleteGrant(ctx, id); err != nil {
			return nil, internalError(err)
		}
		a.invalidate()
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-principals", Method: http.MethodGet, Path: "/access/principals",
		Summary: "People and groups you can give access to", Tags: tags,
	}, func(ctx context.Context, _ *struct{}) (*PrincipalsOutput, error) {
		if acc := principalOf(ctx).Access; acc.Highest() < auth.Owner {
			return nil, forbidden(auth.Owner)
		}
		users, err := a.q.ListPrincipalUsers(ctx)
		if err != nil {
			return nil, internalError(err)
		}
		groups, err := a.q.ListGroups(ctx)
		if err != nil {
			return nil, internalError(err)
		}
		out := &PrincipalsOutput{}
		out.Body.Users = make([]PrincipalUser, 0, len(users))
		for _, u := range users {
			out.Body.Users = append(out.Body.Users, PrincipalUser{ID: u.ID.String(), Username: u.Username, FullName: u.FullName})
		}
		out.Body.Groups = make([]PrincipalGroup, 0, len(groups))
		for _, g := range groups {
			out.Body.Groups = append(out.Body.Groups, PrincipalGroup{ID: g.ID.String(), Name: g.Name})
		}
		return out, nil
	})
}
