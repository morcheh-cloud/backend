package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
)

type PanelUserPath struct {
	ID string `path:"id" format:"uuid"`
}

type PanelUserOutput struct{ Body PanelUser }

type PanelUserCount struct {
	Value string `json:"value"`
	Count int32  `json:"count"`
}

type PanelUserListInput struct {
	Status string `query:"status" enum:"pending,active,blocked"`
	Q      string `query:"q" maxLength:"128"`
}

type PanelUserListOutput struct {
	Body struct {
		Items  []PanelUser      `json:"items"`
		Counts []PanelUserCount `json:"counts"`
	}
}

// GrantSpec is one piece of access handed out while creating or approving
// someone. Exactly one target.
type GrantSpec struct {
	WorkspaceID *string `json:"workspace_id,omitempty" format:"uuid"`
	ServerID    *string `json:"server_id,omitempty" format:"uuid"`
	StorageID   *string `json:"storage_id,omitempty" format:"uuid"`
	Level       string  `json:"level" enum:"viewer,operator,engineer,owner"`
	CanCreate   *bool   `json:"can_create,omitempty" doc:"Add servers and storages to the workspace. Defaults to on for Owner."`
}

type PanelUserCreateBody struct {
	PanelSignup
	Role     string      `json:"role" enum:"admin,member"`
	GroupIDs []string    `json:"group_ids,omitempty" format:"uuid"`
	Grants   []GrantSpec `json:"grants,omitempty"`
}

type PanelUserCreateInput struct{ Body PanelUserCreateBody }

type PanelUserUpdateBody struct {
	Email     *string  `json:"email,omitempty" maxLength:"254"`
	FirstName *string  `json:"first_name,omitempty" maxLength:"64"`
	FullName  *string  `json:"full_name,omitempty" maxLength:"128"`
	Role      *string  `json:"role,omitempty" enum:"admin,member"`
	GroupIDs  []string `json:"group_ids,omitempty" format:"uuid" doc:"Replaces their groups; leave out to keep them."`
}

type PanelUserUpdateInput struct {
	PanelUserPath
	Body PanelUserUpdateBody
}

type PanelPasswordBody struct {
	Password string `json:"password" maxLength:"1024"`
}

type PanelPasswordInput struct {
	PanelUserPath
	Body PanelPasswordBody
}

type PanelApproveBody struct {
	GroupIDs []string    `json:"group_ids,omitempty" format:"uuid"`
	Grants   []GrantSpec `json:"grants,omitempty"`
}

type PanelApproveInput struct {
	PanelUserPath
	Body PanelApproveBody
}

// PanelGroup is a set of people who share access.
type PanelGroup struct {
	ID          string   `json:"id" format:"uuid"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	MemberIDs   []string `json:"member_ids"`
}

type PanelGroupBody struct {
	Name        string `json:"name" minLength:"1" maxLength:"64"`
	Description string `json:"description,omitempty" maxLength:"500"`
}

type PanelGroupPath struct {
	ID string `path:"id" format:"uuid"`
}

type PanelGroupInput struct{ Body PanelGroupBody }

type PanelGroupUpdateInput struct {
	PanelGroupPath
	Body PanelGroupBody
}

type PanelGroupMembersBody struct {
	UserIDs []string `json:"user_ids" format:"uuid"`
}

type PanelGroupMembersInput struct {
	PanelGroupPath
	Body PanelGroupMembersBody
}

type PanelGroupOutput struct{ Body PanelGroup }

type PanelGroupListOutput struct {
	Body struct {
		Items []PanelGroup `json:"items"`
	}
}

type PanelSettings struct {
	RegistrationOpen bool `json:"registration_open"`
}

type PanelSettingsInput struct{ Body PanelSettings }

type PanelSettingsOutput struct{ Body PanelSettings }

// groupsByUser gives each user's groups, and each group's users.
func groupsByUser(ctx context.Context, q *sqlc.Queries) (byUser, byGroup map[uuid.UUID][]string, err error) {
	rows, err := q.ListAllGroupMembers(ctx)
	if err != nil {
		return nil, nil, err
	}
	byUser, byGroup = map[uuid.UUID][]string{}, map[uuid.UUID][]string{}
	for _, r := range rows {
		byUser[r.UserID] = append(byUser[r.UserID], r.GroupID.String())
		byGroup[r.GroupID] = append(byGroup[r.GroupID], r.UserID.String())
	}
	return byUser, byGroup, nil
}

func (a *authz) adminUser(ctx context.Context, u sqlc.User) (*PanelUserOutput, error) {
	byUser, _, err := groupsByUser(ctx, a.q)
	if err != nil {
		return nil, internalError(err)
	}
	out := toPanelUser(u)
	out.GroupIDs = byUser[u.ID]
	if out.GroupIDs == nil {
		out.GroupIDs = []string{}
	}
	return &PanelUserOutput{Body: out}, nil
}

// lookupUser finds the user in the path, inside a transaction when q is one.
func lookupUser(ctx context.Context, q *sqlc.Queries, raw string) (sqlc.User, error) {
	id, err := uuid.Parse(raw)
	if err != nil {
		return sqlc.User{}, huma.Error404NotFound("user not found")
	}
	u, err := q.GetUser(ctx, id)
	if isNotFound(err) {
		return u, huma.Error404NotFound("user not found")
	}
	if err != nil {
		return u, internalError(err)
	}
	return u, nil
}

// keepAnAdmin refuses taking away the last working admin; nobody could undo it.
// Call it after LockAuth.
func keepAnAdmin(ctx context.Context, q *sqlc.Queries, u sqlc.User) error {
	if u.Role != "admin" || u.Status != "active" {
		return nil
	}
	n, err := q.CountActiveAdmins(ctx)
	if err != nil {
		return internalError(err)
	}
	if n <= 1 {
		return huma.Error409Conflict("This is the last admin. Make someone else an admin first.")
	}
	return nil
}

func notYourself(ctx context.Context, u sqlc.User, doing string) error {
	if principalOf(ctx).User.ID == u.ID {
		return huma.Error409Conflict("You can't " + doing + " your own account.")
	}
	return nil
}

// grantParams checks a GrantSpec and fills in its can_create default.
func (s GrantSpec) params(location string) (sqlc.UpsertGrantParams, error) {
	g := sqlc.UpsertGrantParams{
		WorkspaceID: parseOptionalID(s.WorkspaceID),
		ServerID:    parseOptionalID(s.ServerID),
		StorageID:   parseOptionalID(s.StorageID),
		Level:       s.Level,
	}
	n := 0
	for _, id := range []*uuid.UUID{g.WorkspaceID, g.ServerID, g.StorageID} {
		if id != nil {
			n++
		}
	}
	if n != 1 {
		return g, fieldError(location, "Choose one workspace, server or storage.", nil)
	}
	if g.WorkspaceID != nil {
		g.CanCreate = s.Level == auth.Owner.String()
		if s.CanCreate != nil {
			g.CanCreate = *s.CanCreate
		}
	} else if s.CanCreate != nil && *s.CanCreate {
		return g, fieldError(location, "Adding servers and storages can only be allowed on a workspace.", nil)
	}
	return g, nil
}

// applyGrants hands out access to a new or newly approved user.
func applyGrants(ctx context.Context, q *sqlc.Queries, user uuid.UUID, specs []GrantSpec) error {
	for _, s := range specs {
		g, err := s.params("body.grants")
		if err != nil {
			return err
		}
		g.UserID = &user
		if _, err := q.UpsertGrant(ctx, g); err != nil {
			if isForeignKeyViolation(err) {
				return fieldError("body.grants", "That workspace, server or storage no longer exists.", nil)
			}
			return internalError(err)
		}
	}
	return nil
}

func setUserGroups(ctx context.Context, q *sqlc.Queries, user uuid.UUID, raw []string) error {
	err := q.SetUserGroups(ctx, sqlc.SetUserGroupsParams{UserID: user, GroupIds: parseIDs(raw)})
	if isForeignKeyViolation(err) {
		return fieldError("body.group_ids", "That group no longer exists.", nil)
	}
	if err != nil {
		return internalError(err)
	}
	return nil
}

func registerAdmin(api huma.API, a *authz) {
	tags := []string{"Admin"}

	huma.Register(api, huma.Operation{
		OperationID: "admin-list-users", Method: http.MethodGet, Path: "/admin/users",
		Summary: "List panel users", Tags: tags,
	}, func(ctx context.Context, in *PanelUserListInput) (*PanelUserListOutput, error) {
		params := sqlc.ListUsersParams{}
		if in.Status != "" {
			params.Status = &in.Status
		}
		if q := strings.TrimSpace(in.Q); q != "" {
			params.Q = &q
		}
		users, err := a.q.ListUsers(ctx, params)
		if err != nil {
			return nil, internalError(err)
		}
		counts, err := a.q.UserStatusCounts(ctx)
		if err != nil {
			return nil, internalError(err)
		}
		byUser, _, err := groupsByUser(ctx, a.q)
		if err != nil {
			return nil, internalError(err)
		}
		out := &PanelUserListOutput{}
		out.Body.Items = make([]PanelUser, 0, len(users))
		for _, u := range users {
			p := toPanelUser(u)
			p.GroupIDs = byUser[u.ID]
			out.Body.Items = append(out.Body.Items, p)
		}
		out.Body.Counts = make([]PanelUserCount, 0, len(counts))
		for _, c := range counts {
			out.Body.Counts = append(out.Body.Counts, PanelUserCount{Value: c.Value, Count: c.Count})
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "admin-get-user", Method: http.MethodGet, Path: "/admin/users/{id}",
		Summary: "Get a panel user", Tags: tags,
	}, func(ctx context.Context, in *PanelUserPath) (*PanelUserOutput, error) {
		u, err := lookupUser(ctx, a.q, in.ID)
		if err != nil {
			return nil, err
		}
		return a.adminUser(ctx, u)
	})

	huma.Register(api, huma.Operation{
		OperationID: "admin-create-user", Method: http.MethodPost, Path: "/admin/users",
		Summary: "Add a panel user", Tags: tags,
		Description:   "The password is temporary: they must change it when they first sign in.",
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *PanelUserCreateInput) (*PanelUserOutput, error) {
		if err := in.Body.PanelSignup.clean(); err != nil {
			return nil, err
		}
		hash, err := auth.HashPassword(in.Body.Password)
		if err != nil {
			return nil, internalError(err)
		}
		var u sqlc.User
		err = a.inTx(ctx, func(q *sqlc.Queries) error {
			var err error
			u, err = q.CreateUser(ctx, sqlc.CreateUserParams{
				Username: in.Body.Username, Email: in.Body.Email,
				FirstName: in.Body.FirstName, FullName: in.Body.FullName,
				PasswordHash: hash, Role: in.Body.Role, Status: "active",
				MustChangePassword: true,
			})
			if err != nil {
				return userConflict(err)
			}
			if err := setUserGroups(ctx, q, u.ID, in.Body.GroupIDs); err != nil {
				return err
			}
			return applyGrants(ctx, q, u.ID, in.Body.Grants)
		})
		if err != nil {
			return nil, err
		}
		return a.adminUser(ctx, u)
	})

	huma.Register(api, huma.Operation{
		OperationID: "admin-update-user", Method: http.MethodPatch, Path: "/admin/users/{id}",
		Summary: "Edit a panel user", Tags: tags,
	}, func(ctx context.Context, in *PanelUserUpdateInput) (*PanelUserOutput, error) {
		var u sqlc.User
		err := a.inTx(ctx, func(q *sqlc.Queries) error {
			if err := q.LockAuth(ctx); err != nil {
				return internalError(err)
			}
			var err error
			if u, err = lookupUser(ctx, q, in.ID); err != nil {
				return err
			}
			b := in.Body
			if b.Email != nil || b.FirstName != nil || b.FullName != nil {
				p := PanelProfile{Email: u.Email, FirstName: u.FirstName, FullName: u.FullName}
				if b.Email != nil {
					p.Email = *b.Email
				}
				if b.FirstName != nil {
					p.FirstName = *b.FirstName
				}
				if b.FullName != nil {
					p.FullName = *b.FullName
				}
				if err := p.clean(); err != nil {
					return err
				}
				if u, err = q.UpdateUserProfile(ctx, sqlc.UpdateUserProfileParams{
					ID: u.ID, Email: p.Email, FirstName: p.FirstName, FullName: p.FullName,
				}); err != nil {
					return userConflict(err)
				}
			}
			if b.Role != nil && *b.Role != u.Role {
				if *b.Role != "admin" {
					if err := notYourself(ctx, u, "remove admin from"); err != nil {
						return err
					}
					if err := keepAnAdmin(ctx, q, u); err != nil {
						return err
					}
				}
				if u, err = q.SetUserRole(ctx, sqlc.SetUserRoleParams{ID: u.ID, Role: *b.Role}); err != nil {
					return internalError(err)
				}
			}
			if b.GroupIDs != nil {
				return setUserGroups(ctx, q, u.ID, b.GroupIDs)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		a.invalidate()
		return a.adminUser(ctx, u)
	})

	huma.Register(api, huma.Operation{
		OperationID: "admin-set-password", Method: http.MethodPost, Path: "/admin/users/{id}/password",
		Summary: "Set a temporary password", Tags: tags,
		Description: "Signs them out everywhere and closes their terminals; they must pick a new password at next sign-in.",
	}, func(ctx context.Context, in *PanelPasswordInput) (*PanelUserOutput, error) {
		u, err := lookupUser(ctx, a.q, in.ID)
		if err != nil {
			return nil, err
		}
		if err := notYourself(ctx, u, "set a temporary password on"); err != nil {
			return nil, err
		}
		if err := auth.CheckPassword(in.Body.Password, u.Username); err != nil {
			return nil, fieldError("body.password", err.Error(), nil)
		}
		hash, err := auth.HashPassword(in.Body.Password)
		if err != nil {
			return nil, internalError(err)
		}
		err = a.inTx(ctx, func(q *sqlc.Queries) error {
			var err error
			if u, err = q.SetUserPassword(ctx, sqlc.SetUserPasswordParams{
				ID: u.ID, PasswordHash: hash, MustChangePassword: true,
			}); err != nil {
				return internalError(err)
			}
			if err := q.DeleteUserSessions(ctx, u.ID); err != nil {
				return internalError(err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		a.terms.KillOwner(u.ID.String())
		a.invalidate()
		return a.adminUser(ctx, u)
	})

	huma.Register(api, huma.Operation{
		OperationID: "admin-approve-user", Method: http.MethodPost, Path: "/admin/users/{id}/approve",
		Summary: "Approve someone who signed up", Tags: tags,
	}, func(ctx context.Context, in *PanelApproveInput) (*PanelUserOutput, error) {
		var u sqlc.User
		err := a.inTx(ctx, func(q *sqlc.Queries) error {
			var err error
			if u, err = lookupUser(ctx, q, in.ID); err != nil {
				return err
			}
			if u.Status != "pending" {
				return huma.Error409Conflict("This person isn't waiting for approval.")
			}
			if u, err = q.SetUserStatus(ctx, sqlc.SetUserStatusParams{ID: u.ID, Status: "active"}); err != nil {
				return internalError(err)
			}
			if err := setUserGroups(ctx, q, u.ID, in.Body.GroupIDs); err != nil {
				return err
			}
			return applyGrants(ctx, q, u.ID, in.Body.Grants)
		})
		if err != nil {
			return nil, err
		}
		a.invalidate()
		return a.adminUser(ctx, u)
	})

	huma.Register(api, huma.Operation{
		OperationID: "admin-reject-user", Method: http.MethodPost, Path: "/admin/users/{id}/reject",
		Summary: "Reject someone who signed up", Tags: tags,
		Description:   "Deletes the account; they can sign up again while registration is open.",
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *PanelUserPath) (*struct{}, error) {
		err := a.inTx(ctx, func(q *sqlc.Queries) error {
			u, err := lookupUser(ctx, q, in.ID)
			if err != nil {
				return err
			}
			if u.Status != "pending" {
				return huma.Error409Conflict("This person isn't waiting for approval.")
			}
			if _, err := q.DeleteUser(ctx, u.ID); err != nil {
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

	huma.Register(api, huma.Operation{
		OperationID: "admin-block-user", Method: http.MethodPost, Path: "/admin/users/{id}/block",
		Summary: "Block a panel user", Tags: tags,
		Description: "Signs them out at once, closes their terminals and streams, and cancels their running jobs.",
	}, func(ctx context.Context, in *PanelUserPath) (*PanelUserOutput, error) {
		var u sqlc.User
		err := a.inTx(ctx, func(q *sqlc.Queries) error {
			if err := q.LockAuth(ctx); err != nil {
				return internalError(err)
			}
			var err error
			if u, err = lookupUser(ctx, q, in.ID); err != nil {
				return err
			}
			if err := notYourself(ctx, u, "block"); err != nil {
				return err
			}
			if err := keepAnAdmin(ctx, q, u); err != nil {
				return err
			}
			if u, err = q.SetUserStatus(ctx, sqlc.SetUserStatusParams{ID: u.ID, Status: "blocked"}); err != nil {
				return internalError(err)
			}
			if err := q.DeleteUserSessions(ctx, u.ID); err != nil {
				return internalError(err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		a.dropUser(ctx, u.ID, a.runningJobs(ctx, u.ID))
		return a.adminUser(ctx, u)
	})

	huma.Register(api, huma.Operation{
		OperationID: "admin-unblock-user", Method: http.MethodPost, Path: "/admin/users/{id}/unblock",
		Summary: "Unblock a panel user", Tags: tags,
	}, func(ctx context.Context, in *PanelUserPath) (*PanelUserOutput, error) {
		u, err := lookupUser(ctx, a.q, in.ID)
		if err != nil {
			return nil, err
		}
		if u.Status != "blocked" {
			return nil, huma.Error409Conflict("This person isn't blocked.")
		}
		if u, err = a.q.SetUserStatus(ctx, sqlc.SetUserStatusParams{ID: u.ID, Status: "active"}); err != nil {
			return nil, internalError(err)
		}
		a.invalidate()
		return a.adminUser(ctx, u)
	})

	huma.Register(api, huma.Operation{
		OperationID: "admin-delete-user", Method: http.MethodDelete, Path: "/admin/users/{id}",
		Summary: "Delete a panel user", Tags: tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *PanelUserPath) (*struct{}, error) {
		id, err := uuid.Parse(in.ID)
		if err != nil {
			return nil, huma.Error404NotFound("user not found")
		}
		running := a.runningJobs(ctx, id)
		err = a.inTx(ctx, func(q *sqlc.Queries) error {
			if err := q.LockAuth(ctx); err != nil {
				return internalError(err)
			}
			u, err := lookupUser(ctx, q, in.ID)
			if err != nil {
				return err
			}
			if err := notYourself(ctx, u, "delete"); err != nil {
				return err
			}
			if err := keepAnAdmin(ctx, q, u); err != nil {
				return err
			}
			if _, err := q.DeleteUser(ctx, u.ID); err != nil {
				return internalError(err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		a.dropUser(ctx, id, running)
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "admin-revoke-sessions", Method: http.MethodPost, Path: "/admin/users/{id}/revoke-sessions",
		Summary: "Sign someone out everywhere", Tags: tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *PanelUserPath) (*struct{}, error) {
		u, err := lookupUser(ctx, a.q, in.ID)
		if err != nil {
			return nil, err
		}
		if err := a.q.DeleteUserSessions(ctx, u.ID); err != nil {
			return nil, internalError(err)
		}
		a.terms.KillOwner(u.ID.String())
		a.invalidate()
		return nil, nil
	})

	// ---- Groups ----

	loadGroup := func(ctx context.Context, q *sqlc.Queries, g sqlc.UserGroup) (*PanelGroupOutput, error) {
		members, err := q.ListGroupMembers(ctx, g.ID)
		if err != nil {
			return nil, internalError(err)
		}
		out := &PanelGroupOutput{Body: PanelGroup{
			ID: g.ID.String(), Name: g.Name, Description: g.Description, MemberIDs: make([]string, 0, len(members)),
		}}
		for _, m := range members {
			out.Body.MemberIDs = append(out.Body.MemberIDs, m.String())
		}
		return out, nil
	}
	groupConflict := func(err error) error {
		if isUniqueViolation(err) {
			return fieldError("body.name", "A group with this name already exists.", nil)
		}
		return internalError(err)
	}

	huma.Register(api, huma.Operation{
		OperationID: "admin-list-groups", Method: http.MethodGet, Path: "/admin/groups",
		Summary: "List groups", Tags: tags,
	}, func(ctx context.Context, _ *struct{}) (*PanelGroupListOutput, error) {
		groups, err := a.q.ListGroups(ctx)
		if err != nil {
			return nil, internalError(err)
		}
		_, byGroup, err := groupsByUser(ctx, a.q)
		if err != nil {
			return nil, internalError(err)
		}
		out := &PanelGroupListOutput{}
		out.Body.Items = make([]PanelGroup, 0, len(groups))
		for _, g := range groups {
			members := byGroup[g.ID]
			if members == nil {
				members = []string{}
			}
			out.Body.Items = append(out.Body.Items, PanelGroup{
				ID: g.ID.String(), Name: g.Name, Description: g.Description, MemberIDs: members,
			})
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "admin-create-group", Method: http.MethodPost, Path: "/admin/groups",
		Summary: "Create a group", Tags: tags, DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *PanelGroupInput) (*PanelGroupOutput, error) {
		g, err := a.q.CreateGroup(ctx, sqlc.CreateGroupParams{
			Name: strings.TrimSpace(in.Body.Name), Description: strings.TrimSpace(in.Body.Description),
		})
		if err != nil {
			return nil, groupConflict(err)
		}
		return loadGroup(ctx, a.q, g)
	})

	huma.Register(api, huma.Operation{
		OperationID: "admin-update-group", Method: http.MethodPatch, Path: "/admin/groups/{id}",
		Summary: "Rename a group", Tags: tags,
	}, func(ctx context.Context, in *PanelGroupUpdateInput) (*PanelGroupOutput, error) {
		id, _ := uuid.Parse(in.ID)
		g, err := a.q.UpdateGroup(ctx, sqlc.UpdateGroupParams{
			ID: id, Name: strings.TrimSpace(in.Body.Name), Description: strings.TrimSpace(in.Body.Description),
		})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("group not found")
		}
		if err != nil {
			return nil, groupConflict(err)
		}
		return loadGroup(ctx, a.q, g)
	})

	huma.Register(api, huma.Operation{
		OperationID: "admin-delete-group", Method: http.MethodDelete, Path: "/admin/groups/{id}",
		Summary: "Delete a group", Tags: tags,
		Description:   "Its members lose the access it gave them.",
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *PanelGroupPath) (*struct{}, error) {
		id, _ := uuid.Parse(in.ID)
		n, err := a.q.DeleteGroup(ctx, id)
		if err != nil {
			return nil, internalError(err)
		}
		if n == 0 {
			return nil, huma.Error404NotFound("group not found")
		}
		a.invalidate()
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "admin-set-group-members", Method: http.MethodPut, Path: "/admin/groups/{id}/members",
		Summary: "Set a group's members", Tags: tags,
	}, func(ctx context.Context, in *PanelGroupMembersInput) (*PanelGroupOutput, error) {
		id, _ := uuid.Parse(in.ID)
		var out *PanelGroupOutput
		err := a.inTx(ctx, func(q *sqlc.Queries) error {
			g, err := q.GetGroup(ctx, id)
			if isNotFound(err) {
				return huma.Error404NotFound("group not found")
			}
			if err != nil {
				return internalError(err)
			}
			if err := q.ClearGroupMembers(ctx, id); err != nil {
				return internalError(err)
			}
			err = q.AddGroupMembers(ctx, sqlc.AddGroupMembersParams{GroupID: id, UserIds: parseIDs(in.Body.UserIDs)})
			if isForeignKeyViolation(err) {
				return fieldError("body.user_ids", "One of these people no longer exists.", nil)
			}
			if err != nil {
				return internalError(err)
			}
			out, err = loadGroup(ctx, q, g)
			return err
		})
		if err != nil {
			return nil, err
		}
		a.invalidate()
		return out, nil
	})

	// ---- Settings ----

	huma.Register(api, huma.Operation{
		OperationID: "admin-get-settings", Method: http.MethodGet, Path: "/admin/settings",
		Summary: "Get panel settings", Tags: tags,
	}, func(ctx context.Context, _ *struct{}) (*PanelSettingsOutput, error) {
		st, err := a.q.GetSettings(ctx)
		if err != nil {
			return nil, internalError(err)
		}
		return &PanelSettingsOutput{Body: PanelSettings{RegistrationOpen: st.RegistrationOpen}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "admin-update-settings", Method: http.MethodPatch, Path: "/admin/settings",
		Summary: "Change panel settings", Tags: tags,
	}, func(ctx context.Context, in *PanelSettingsInput) (*PanelSettingsOutput, error) {
		st, err := a.q.SetRegistrationOpen(ctx, in.Body.RegistrationOpen)
		if err != nil {
			return nil, internalError(err)
		}
		return &PanelSettingsOutput{Body: PanelSettings{RegistrationOpen: st.RegistrationOpen}}, nil
	})
}
