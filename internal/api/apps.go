package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/secrets"
)

// appHandler serves the Services page: the team's web services (Portainer,
// MinIO…) with their addresses and sign-ins.
type appHandler struct {
	q   *sqlc.Queries
	db  *pgxpool.Pool
	box *secrets.Box
	a   *authz
}

func newAppHandler(q *sqlc.Queries, db *pgxpool.Pool, box *secrets.Box, a *authz) *appHandler {
	return &appHandler{q: q, db: db, box: box, a: a}
}

// AppCategory is a group of services on the page, in one workspace.
type AppCategory struct {
	ID          string `json:"id" format:"uuid"`
	WorkspaceID string `json:"workspace_id" format:"uuid"`
	Name        string `json:"name"`
	Color       string `json:"color"`
	Position    int32  `json:"position"`
}

func toAppCategory(c sqlc.AppCategory) AppCategory {
	return AppCategory{
		ID: c.ID.String(), WorkspaceID: c.WorkspaceID.String(),
		Name: c.Name, Color: c.Color, Position: c.Position,
	}
}

type AppIDPath struct {
	ID string `path:"id" format:"uuid"`
}

type AppOutput struct {
	Body App
}

type AppList struct {
	Items      []App         `json:"items"`
	Categories []AppCategory `json:"categories" doc:"The categories this person may see or place services in, empty ones included when they can."`
}

// AppAccountInput is one sign-in in a create or update. Without id it's a
// new account; accounts left out of an update are removed.
type AppAccountInput struct {
	ID             *string `json:"id,omitempty" doc:"An existing account of this service."`
	Label          string  `json:"label,omitempty" maxLength:"64"`
	Username       string  `json:"username,omitempty" maxLength:"255"`
	Password       string  `json:"password,omitempty" maxLength:"4096" doc:"Empty keeps the saved one."`
	RemovePassword bool    `json:"remove_password,omitempty"`
}

type AppCreateBody struct {
	Name       string            `json:"name" minLength:"1" maxLength:"128"`
	Address    string            `json:"address" maxLength:"2048" doc:"http(s) URL; https:// is added when there's no scheme."`
	CategoryID *string           `json:"category_id,omitempty" doc:"A category in the same workspace; empty = none."`
	Note       string            `json:"note,omitempty" maxLength:"4000"`
	Color      string            `json:"color,omitempty" enum:"slate,red,orange,amber,green,teal,blue,indigo,violet,pink" default:"slate"`
	Critical   bool              `json:"critical,omitempty"`
	LogoKind   string            `json:"logo_kind,omitempty" enum:"auto,icon" default:"auto"`
	LogoIcon   string            `json:"logo_icon,omitempty" pattern:"^[a-z0-9-]*$" maxLength:"40"`
	Accounts   []AppAccountInput `json:"accounts,omitempty" maxItems:"20"`
}

type AppUpdateBody struct {
	Name       *string            `json:"name,omitempty" minLength:"1" maxLength:"128"`
	Address    *string            `json:"address,omitempty" maxLength:"2048"`
	CategoryID *string            `json:"category_id,omitempty" doc:"Moving it puts the service at the end of the new category; empty = none."`
	Note       *string            `json:"note,omitempty" maxLength:"4000"`
	Color      *string            `json:"color,omitempty" enum:"slate,red,orange,amber,green,teal,blue,indigo,violet,pink"`
	Critical   *bool              `json:"critical,omitempty"`
	LogoKind   *string            `json:"logo_kind,omitempty" enum:"auto,upload,icon" doc:"auto drops an uploaded logo; upload needs one."`
	LogoIcon   *string            `json:"logo_icon,omitempty" pattern:"^[a-z0-9-]*$" maxLength:"40"`
	Accounts   *[]AppAccountInput `json:"accounts,omitempty" maxItems:"20" doc:"The whole list, in order."`
}

func registerApps(api huma.API, h *appHandler) {
	tags := []string{"apps"}

	huma.Register(api, huma.Operation{
		OperationID: "list-apps",
		Method:      http.MethodGet,
		Path:        "/apps",
		Summary:     "List services",
		Description: "By category, then the order inside it; uncategorized last. q matches the name, address and note.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		Q string `query:"q" maxLength:"200"`
	}) (*struct{ Body AppList }, error) {
		p := principalOf(ctx)
		list, err := h.list(ctx, p, p.Workspace, in.Q)
		if err != nil {
			return nil, err
		}
		return &struct{ Body AppList }{Body: list}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-app",
		Method:        http.MethodPost,
		Path:          "/apps",
		Summary:       "Add a service",
		Description:   "Goes in the open workspace, at the end of its category.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, h.create)

	huma.Register(api, huma.Operation{
		OperationID: "get-app",
		Method:      http.MethodGet,
		Path:        "/apps/{id}",
		Summary:     "Get a service",
		Tags:        tags,
	}, func(ctx context.Context, in *AppIDPath) (*AppOutput, error) {
		row, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return h.one(ctx, row, principalOf(ctx).Level)
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-app",
		Method:      http.MethodPatch,
		Path:        "/apps/{id}",
		Summary:     "Change a service",
		Description: "Fields left out stay as they are.",
		Tags:        tags,
	}, h.update)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-app",
		Method:        http.MethodDelete,
		Path:          "/apps/{id}",
		Summary:       "Remove a service",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *AppIDPath) (*struct{}, error) {
		n, err := h.q.DeleteApp(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		if n == 0 {
			return nil, huma.Error404NotFound("service not found")
		}
		h.a.invalidate()
		return nil, nil
	})
}

// list is what someone sees on the page: the services they reach (in ws when
// given) and the categories they get.
func (h *appHandler) list(ctx context.Context, p *principal, ws *uuid.UUID, q string) (AppList, error) {
	sc := p.scope()
	params := sqlc.ListAppsParams{SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, AppIds: sc.apps, WorkspaceID: ws}
	all, err := h.q.ListApps(ctx, params)
	if err != nil {
		return AppList{}, internalError(err)
	}
	rows := all
	if q = strings.TrimSpace(q); q != "" {
		params.Pattern = "%" + likeEscaper.Replace(q) + "%"
		if rows, err = h.q.ListApps(ctx, params); err != nil {
			return AppList{}, internalError(err)
		}
	}

	acc := p.Access
	visible := make([]sqlc.App, 0, len(rows))
	for _, r := range rows {
		// A workspace grant with no level (only "can add") shows nothing.
		if acc.AppLevel(r.WorkspaceID, r.ID) > auth.None {
			visible = append(visible, r)
		}
	}
	accounts, logos, err := h.extras(ctx, visible)
	if err != nil {
		return AppList{}, err
	}
	out := AppList{Items: make([]App, 0, len(visible)), Categories: []AppCategory{}}
	for _, r := range visible {
		out.Items = append(out.Items, toApp(r, accounts[r.ID], logos[r.ID], acc.AppLevel(r.WorkspaceID, r.ID)))
	}

	var spaces []uuid.UUID
	seen := map[uuid.UUID]bool{}
	add := func(id uuid.UUID) {
		if !seen[id] && (ws == nil || id == *ws) {
			seen[id] = true
			spaces = append(spaces, id)
		}
	}
	if ws != nil {
		add(*ws)
	}
	for id := range acc.Workspaces {
		add(id)
	}
	for _, r := range all {
		add(r.WorkspaceID)
	}
	cats, err := h.q.ListAppCategories(ctx, spaces)
	if err != nil {
		return AppList{}, internalError(err)
	}
	byWorkspace := map[uuid.UUID][]sqlc.AppCategory{}
	for _, c := range cats {
		byWorkspace[c.WorkspaceID] = append(byWorkspace[c.WorkspaceID], c)
	}
	for _, id := range spaces {
		for _, c := range categoriesFor(acc, id, byWorkspace[id], all) {
			out.Categories = append(out.Categories, toAppCategory(c))
		}
	}
	return out, nil
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// extras loads the accounts and logo stamps of the given services.
func (h *appHandler) extras(ctx context.Context, rows []sqlc.App) (map[uuid.UUID][]sqlc.AppAccount, map[uuid.UUID][]logoStamp, error) {
	ids := make([]uuid.UUID, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	accounts := map[uuid.UUID][]sqlc.AppAccount{}
	logos := map[uuid.UUID][]logoStamp{}
	if len(ids) == 0 {
		return accounts, logos, nil
	}
	accs, err := h.q.ListAppAccounts(ctx, ids)
	if err != nil {
		return nil, nil, internalError(err)
	}
	for _, a := range accs {
		accounts[a.AppID] = append(accounts[a.AppID], a)
	}
	stamps, err := h.q.ListAppLogoStamps(ctx, ids)
	if err != nil {
		return nil, nil, internalError(err)
	}
	for _, s := range stamps {
		logos[s.AppID] = append(logos[s.AppID], logoStamp{Source: s.Source, UpdatedAt: s.UpdatedAt})
	}
	return accounts, logos, nil
}

func (h *appHandler) one(ctx context.Context, row sqlc.App, level auth.Level) (*AppOutput, error) {
	accounts, logos, err := h.extras(ctx, []sqlc.App{row})
	if err != nil {
		return nil, err
	}
	return &AppOutput{Body: toApp(row, accounts[row.ID], logos[row.ID], level)}, nil
}

func (h *appHandler) get(ctx context.Context, rawID string) (sqlc.App, error) {
	row, err := h.q.GetApp(ctx, uuid.MustParse(rawID))
	if isNotFound(err) {
		return row, huma.Error404NotFound("service not found")
	}
	if err != nil {
		return row, internalError(err)
	}
	return row, nil
}

// category resolves a category_id: empty is none, anything else must be a
// category of the service's workspace.
func category(ctx context.Context, q *sqlc.Queries, ws uuid.UUID, raw string) (*uuid.UUID, error) {
	if raw == "" {
		return nil, nil
	}
	bad := fieldError("body.category_id", "There's no such category in this workspace.", raw)
	id, err := uuid.Parse(raw)
	if err != nil {
		return nil, bad
	}
	c, err := q.GetAppCategory(ctx, id)
	if isNotFound(err) || (err == nil && c.WorkspaceID != ws) {
		return nil, bad
	}
	if err != nil {
		return nil, internalError(err)
	}
	return &c.ID, nil
}

func appName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", fieldError("body.name", "Enter a name.", raw)
	}
	return name, nil
}

func appAddress(raw string) (string, error) {
	addr, err := normalizeAddress(raw)
	if err != nil {
		return "", fieldError("body.address", err.Error(), raw)
	}
	return addr, nil
}

// saveAccounts makes the service's accounts exactly the given list, in its
// order. existing are the ones it has now.
func (h *appHandler) saveAccounts(ctx context.Context, q *sqlc.Queries, app uuid.UUID, in []AppAccountInput, existing []sqlc.AppAccount) error {
	byID := map[uuid.UUID]sqlc.AppAccount{}
	for _, a := range existing {
		byID[a.ID] = a
	}
	keep := []uuid.UUID{}
	for i, a := range in {
		label, username := strings.TrimSpace(a.Label), strings.TrimSpace(a.Username)
		var prev *sqlc.AppAccount
		if a.ID != nil && *a.ID != "" {
			id, err := uuid.Parse(*a.ID)
			p, ok := byID[id]
			if err != nil || !ok || p.ID == uuid.Nil {
				return fieldError(fmt.Sprintf("body.accounts[%d].id", i), "This account isn't there any more; reload and try again.", *a.ID)
			}
			// Seen once: a second entry with the same id is refused above.
			byID[id] = sqlc.AppAccount{}
			prev = &p
		}
		var password []byte
		switch {
		case a.Password != "":
			password = h.box.Seal(a.Password)
		case a.RemovePassword || prev == nil:
		default:
			password = prev.PasswordEnc
		}
		if label == "" && username == "" && password == nil {
			return fieldError(fmt.Sprintf("body.accounts[%d]", i), "Give the account a label, a username or a password.", nil)
		}
		if prev != nil {
			if _, err := q.UpdateAppAccount(ctx, sqlc.UpdateAppAccountParams{
				ID: prev.ID, AppID: app, Label: label, Username: username, PasswordEnc: password, Position: int32(i),
			}); err != nil {
				return internalError(err)
			}
			keep = append(keep, prev.ID)
			continue
		}
		row, err := q.CreateAppAccount(ctx, sqlc.CreateAppAccountParams{
			AppID: app, Label: label, Username: username, PasswordEnc: password, Position: int32(i),
		})
		if err != nil {
			return internalError(err)
		}
		keep = append(keep, row.ID)
	}
	if err := q.DeleteAppAccountsExcept(ctx, sqlc.DeleteAppAccountsExceptParams{AppID: app, Keep: keep}); err != nil {
		return internalError(err)
	}
	return nil
}

func (h *appHandler) create(ctx context.Context, in *struct{ Body AppCreateBody }) (*AppOutput, error) {
	p := principalOf(ctx)
	ws, err := h.a.createTarget(ctx, p)
	if err != nil {
		return nil, err
	}
	b := in.Body
	name, err := appName(b.Name)
	if err != nil {
		return nil, err
	}
	addr, err := appAddress(b.Address)
	if err != nil {
		return nil, err
	}
	var row sqlc.App
	err = h.a.inTx(ctx, func(q *sqlc.Queries) error {
		raw := ""
		if b.CategoryID != nil {
			raw = *b.CategoryID
		}
		cat, err := category(ctx, q, ws, raw)
		if err != nil {
			return err
		}
		pos, err := q.NextAppPosition(ctx, sqlc.NextAppPositionParams{WorkspaceID: ws, CategoryID: cat})
		if err != nil {
			return internalError(err)
		}
		row, err = q.CreateApp(ctx, sqlc.CreateAppParams{
			WorkspaceID: ws, CategoryID: cat, Name: name, Address: addr,
			Note: strings.TrimSpace(b.Note), Color: b.Color, Critical: b.Critical, Position: pos,
			LogoKind: b.LogoKind, LogoIcon: b.LogoIcon,
		})
		if err != nil {
			return internalError(err)
		}
		if err := h.saveAccounts(ctx, q, row.ID, b.Accounts, nil); err != nil {
			return err
		}
		if err := grantCreator(ctx, q, p, ws, nil, nil, &row.ID); err != nil {
			return internalError(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	h.a.invalidate()
	return h.one(ctx, row, auth.Owner)
}

func (h *appHandler) update(ctx context.Context, in *struct {
	AppIDPath
	Body AppUpdateBody
}) (*AppOutput, error) {
	prev, err := h.get(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	b := in.Body
	next := sqlc.UpdateAppParams{
		ID: prev.ID, CategoryID: prev.CategoryID, Name: prev.Name, Address: prev.Address,
		Note: prev.Note, Color: prev.Color, Critical: prev.Critical, Position: prev.Position,
		LogoKind: prev.LogoKind, LogoIcon: prev.LogoIcon,
	}
	if b.Name != nil {
		if next.Name, err = appName(*b.Name); err != nil {
			return nil, err
		}
	}
	if b.Address != nil {
		if next.Address, err = appAddress(*b.Address); err != nil {
			return nil, err
		}
	}
	if b.Note != nil {
		next.Note = strings.TrimSpace(*b.Note)
	}
	if b.Color != nil {
		next.Color = *b.Color
	}
	if b.Critical != nil {
		next.Critical = *b.Critical
	}
	if b.LogoIcon != nil {
		next.LogoIcon = *b.LogoIcon
	}
	if b.LogoKind != nil {
		next.LogoKind = *b.LogoKind
	}

	var row sqlc.App
	err = h.a.inTx(ctx, func(q *sqlc.Queries) error {
		if b.CategoryID != nil {
			cat, err := category(ctx, q, prev.WorkspaceID, *b.CategoryID)
			if err != nil {
				return err
			}
			if !sameID(cat, prev.CategoryID) {
				next.CategoryID = cat
				if next.Position, err = q.NextAppPosition(ctx, sqlc.NextAppPositionParams{WorkspaceID: prev.WorkspaceID, CategoryID: cat}); err != nil {
					return internalError(err)
				}
			}
		}
		if b.LogoKind != nil {
			switch *b.LogoKind {
			case "auto":
				if err := q.DeleteAppLogo(ctx, sqlc.DeleteAppLogoParams{AppID: prev.ID, Source: "upload"}); err != nil {
					return internalError(err)
				}
			case "upload":
				stamps, err := q.ListAppLogoStamps(ctx, []uuid.UUID{prev.ID})
				if err != nil {
					return internalError(err)
				}
				has := false
				for _, s := range stamps {
					has = has || s.Source == "upload"
				}
				if !has {
					return fieldError("body.logo_kind", "Upload a logo first.", *b.LogoKind)
				}
			}
		}
		var err error
		if row, err = q.UpdateApp(ctx, next); err != nil {
			return internalError(err)
		}
		if b.Accounts != nil {
			existing, err := q.ListAppAccounts(ctx, []uuid.UUID{prev.ID})
			if err != nil {
				return internalError(err)
			}
			if err := h.saveAccounts(ctx, q, prev.ID, *b.Accounts, existing); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return h.one(ctx, row, principalOf(ctx).Level)
}
