package api

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morche/backend/internal/registry"
)

// What a registry holds (Harbor repositories and their artifacts, Verdaccio
// packages and their versions) and who can sign in to it (Harbor robot
// accounts, Verdaccio users).

func registerPackageRegistryContents(api huma.API, h *registryHandler, base string, tags []string) {
	huma.Register(api, huma.Operation{
		OperationID: "list-package-registry-items", Method: http.MethodGet, Path: base + "/items",
		Summary: "What a registry holds", Description: "Harbor: repositories (newest first) and projects; Verdaccio: packages, its own first.",
		Tags: tags,
	}, func(ctx context.Context, in *struct {
		RegistryIDPath
		Q string `query:"q" maxLength:"200" doc:"Only names with this in them"`
	}) (*struct{ Body RegistryItems }, error) {
		row, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		r := row.PackageRegistry
		if err := mustReady(r); err != nil {
			return nil, err
		}
		q := strings.ToLower(strings.TrimSpace(in.Q))
		out := RegistryItems{Items: []RegistryItem{}, Projects: []RegistryProject{}}
		switch r.Kind {
		case registry.Harbor:
			err = h.harbor(ctx, r, func(c registry.HarborClient) error {
				ps, err := c.Projects(ctx)
				if err != nil {
					return err
				}
				mirror := map[int]bool{}
				for _, p := range ps {
					mirror[p.ID] = p.RegistryID > 0
					out.Projects = append(out.Projects, RegistryProject{Name: p.Name, Public: p.Metadata["public"] == "true", Mirror: p.RegistryID > 0, Repos: p.RepoCount})
				}
				rs, total, err := c.Repositories(ctx, q, 100)
				if err != nil {
					return err
				}
				out.Total = total
				for _, x := range rs {
					project, _, _ := strings.Cut(x.Name, "/")
					out.Items = append(out.Items, RegistryItem{
						Name: x.Name, Project: project, Versions: x.Artifacts, Pulls: x.Pulls, Mirror: mirror[x.ProjectID], Updated: x.Updated,
					})
				}
				return nil
			})
			if err != nil {
				return nil, registryProblem(err)
			}
		case registry.Verdaccio:
			text, err := h.root(ctx, r.ServerID, registry.ListPackagesScript(r.Project))
			if err != nil {
				return nil, shellFailure(err, "")
			}
			ps, err := registry.ParsePackages(text)
			if err != nil {
				return nil, huma.Error502BadGateway("Couldn't read Verdaccio's packages")
			}
			for _, p := range ps {
				if q != "" && !strings.Contains(strings.ToLower(p.Name), q) {
					continue
				}
				t, _ := time.Parse(time.RFC3339, p.Modified)
				out.Items = append(out.Items, RegistryItem{
					Name: p.Name, Versions: p.Versions, Size: p.Size, Latest: p.Latest, Description: p.Description,
					Private: p.Private, Mirror: !p.Private, Updated: t,
				})
			}
			out.Total = len(out.Items)
			if len(out.Items) > 500 {
				out.Items = out.Items[:500]
			}
		}
		return &struct{ Body RegistryItems }{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-package-registry-item", Method: http.MethodGet, Path: base + "/items/detail",
		Summary: "A repository's artifacts or a package's versions", Tags: tags,
	}, func(ctx context.Context, in *struct {
		RegistryIDPath
		Name string `query:"name" minLength:"1" maxLength:"300"`
	}) (*struct{ Body RegistryItemDetail }, error) {
		row, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		r := row.PackageRegistry
		if err := mustReady(r); err != nil {
			return nil, err
		}
		out := RegistryItemDetail{Name: in.Name, DistTags: map[string]string{}, Versions: []RegistryVersion{}}
		switch r.Kind {
		case registry.Harbor:
			err = h.harbor(ctx, r, func(c registry.HarborClient) error {
				as, err := c.Artifacts(ctx, in.Name)
				if err != nil {
					return err
				}
				for _, a := range as {
					v := RegistryVersion{Ref: a.Digest, Tags: []string{}, Size: a.Size, Kind: a.Type, Platforms: []string{}}
					for _, t := range a.Tags {
						v.Tags = append(v.Tags, t.Name)
					}
					if !a.PushTime.IsZero() {
						v.Pushed = &a.PushTime
					}
					if !a.PullTime.IsZero() && a.PullTime.Year() > 1 {
						v.Pulled = &a.PullTime
					}
					if a.ExtraAttrs.OS != "" {
						v.Platforms = append(v.Platforms, a.ExtraAttrs.OS+"/"+a.ExtraAttrs.Architecture)
					}
					for _, ref := range a.References {
						if ref.Platform.OS != "" && ref.Platform.OS != "unknown" {
							v.Platforms = append(v.Platforms, ref.Platform.OS+"/"+ref.Platform.Architecture)
						}
					}
					out.Versions = append(out.Versions, v)
				}
				sort.SliceStable(out.Versions, func(i, j int) bool {
					a, b := out.Versions[i].Pushed, out.Versions[j].Pushed
					return a != nil && (b == nil || a.After(*b))
				})
				return nil
			})
			if err != nil {
				return nil, registryProblem(err)
			}
		case registry.Verdaccio:
			if !registry.ValidPackage(in.Name) {
				return nil, huma.Error404NotFound("No such package")
			}
			text, err := h.root(ctx, r.ServerID, registry.PackageScript(r.Project, in.Name))
			if err != nil {
				if ce, ok := err.(*cmdError); ok && ce.code == 72 {
					return nil, huma.Error404NotFound("No such package")
				}
				return nil, shellFailure(err, "")
			}
			d, err := registry.ParsePackage(text)
			if err != nil {
				return nil, huma.Error502BadGateway("Couldn't read the package")
			}
			out.Description, out.License, out.Homepage, out.Private, out.DistTags = d.Description, d.License, d.Homepage, d.Private, d.DistTags
			tagsOf := map[string][]string{}
			for tag, v := range d.DistTags {
				tagsOf[v] = append(tagsOf[v], tag)
			}
			for _, v := range d.Versions {
				x := RegistryVersion{Ref: v.Version, Tags: tagsOf[v.Version], Size: v.Size, Platforms: []string{}, Deprecated: v.Deprecated, Author: v.Author}
				if x.Tags == nil {
					x.Tags = []string{}
				}
				if t, err := time.Parse(time.RFC3339, v.Time); err == nil {
					x.Pushed = &t
				}
				out.Versions = append(out.Versions, x)
			}
		}
		return &struct{ Body RegistryItemDetail }{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-package-registry-item", Method: http.MethodPost, Path: base + "/items/delete",
		Summary:     "Delete a repository, an artifact or a package",
		Description: "Harbor: the whole repository, or one artifact (`ref` = its digest) with its tags; the space comes back at the next cleanup. Verdaccio: the whole package with every version.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		RegistryIDPath
		Body struct {
			Name string `json:"name" minLength:"1" maxLength:"300"`
			Ref  string `json:"ref,omitempty" maxLength:"200" doc:"Harbor: one artifact's digest"`
		}
	}) (*struct{}, error) {
		row, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		r := row.PackageRegistry
		if err := mustReady(r); err != nil {
			return nil, err
		}
		switch r.Kind {
		case registry.Harbor:
			err = h.harbor(ctx, r, func(c registry.HarborClient) error {
				if in.Body.Ref != "" {
					return c.DeleteArtifact(ctx, in.Body.Name, in.Body.Ref)
				}
				return c.DeleteRepository(ctx, in.Body.Name)
			})
		case registry.Verdaccio:
			if !registry.ValidPackage(in.Body.Name) {
				return nil, huma.Error404NotFound("No such package")
			}
			err = h.verdaccio(ctx, r, func(c registry.VerdaccioClient) error { return c.Unpublish(ctx, in.Body.Name) })
		}
		if err != nil {
			return nil, registryProblem(err)
		}
		go h.check(context.WithoutCancel(ctx), r)
		return &struct{}{}, nil
	})

	type accountsOut struct {
		Body struct {
			Items []RegistryAccount `json:"items"`
		}
	}

	huma.Register(api, huma.Operation{
		OperationID: "list-package-registry-accounts", Method: http.MethodGet, Path: base + "/accounts",
		Summary: "Who can sign in to a registry", Description: "Harbor: robot accounts; Verdaccio: users.", Tags: tags,
	}, func(ctx context.Context, in *RegistryIDPath) (*accountsOut, error) {
		row, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		r := row.PackageRegistry
		if err := mustReady(r); err != nil {
			return nil, err
		}
		out := &accountsOut{}
		out.Body.Items = []RegistryAccount{}
		short := strings.Split(r.ID.String(), "-")[0]
		switch r.Kind {
		case registry.Harbor:
			err = h.harbor(ctx, r, func(c registry.HarborClient) error {
				rs, err := c.Robots(ctx)
				if err != nil {
					return err
				}
				for _, x := range rs {
					a := RegistryAccount{ID: strconv.Itoa(x.ID), Name: x.Name, Kind: "robot", Push: x.CanPush(), Disabled: x.Disabled,
						Note: x.Description, Morche: x.Name == "robot$morche-"+short}
					if x.ExpiresAt > 0 {
						t := time.Unix(x.ExpiresAt, 0)
						a.ExpiresAt = &t
					}
					if !x.Created.IsZero() {
						c := x.Created
						a.CreatedAt = &c
					}
					out.Body.Items = append(out.Body.Items, a)
				}
				return nil
			})
			if err != nil {
				return nil, registryProblem(err)
			}
		case registry.Verdaccio:
			text, err := h.root(ctx, r.ServerID, registry.ReadHtpasswdScript(r.Dir))
			if err != nil {
				return nil, shellFailure(err, "")
			}
			for _, u := range registry.HtpasswdUsers(text) {
				out.Body.Items = append(out.Body.Items, RegistryAccount{ID: u, Name: u, Kind: "user", Push: true, Morche: u == r.AdminUser})
			}
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-package-registry-account", Method: http.MethodPost, Path: base + "/accounts",
		Summary:     "Add a robot account (Harbor) or a user (Verdaccio)",
		Description: "Answers its password or secret once; Morche doesn't keep it.",
		Tags:        tags, DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		RegistryIDPath
		Body RegistryAccountBody
	}) (*struct{ Body RegistryAccountSecret }, error) {
		row, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		r := row.PackageRegistry
		if err := mustReady(r); err != nil {
			return nil, err
		}
		name := strings.ToLower(strings.TrimSpace(in.Body.Name))
		out := RegistryAccountSecret{}
		switch r.Kind {
		case registry.Harbor:
			if !registry.ValidRobot(name) {
				return nil, fieldError("body.name", "Use lowercase letters, digits and . _ -", name)
			}
			err = h.harbor(ctx, r, func(c registry.HarborClient) error {
				id, full, secret, err := c.CreateRobot(ctx, name, strings.TrimSpace(in.Body.Note), in.Body.Push, in.Body.Days)
				if err != nil {
					return err
				}
				now := time.Now()
				out.Account = RegistryAccount{ID: strconv.Itoa(id), Name: full, Kind: "robot", Push: in.Body.Push, Note: in.Body.Note, CreatedAt: &now}
				if in.Body.Days > 0 {
					e := now.AddDate(0, 0, in.Body.Days)
					out.Account.ExpiresAt = &e
				}
				out.Secret = secret
				return nil
			})
			if err != nil {
				var ae *registry.APIError
				if ok := asAPIError(err, &ae); ok && ae.Status == http.StatusConflict {
					return nil, fieldError("body.name", "A robot account with this name exists", name)
				}
				return nil, registryProblem(err)
			}
		case registry.Verdaccio:
			if !registry.ValidUser(name) {
				return nil, fieldError("body.name", "Use lowercase letters, digits and . _ -", name)
			}
			text, err := h.root(ctx, r.ServerID, registry.ReadHtpasswdScript(r.Dir))
			if err != nil {
				return nil, shellFailure(err, "")
			}
			for _, u := range registry.HtpasswdUsers(text) {
				if u == name {
					return nil, fieldError("body.name", "This user exists", name)
				}
			}
			secret := registry.Password(20)
			line, err := registry.HtpasswdLine(name, secret)
			if err != nil {
				return nil, internalError(err)
			}
			next := registry.SetHtpasswd(text, name, line)
			if _, err := h.root(ctx, r.ServerID, registry.WriteHtpasswdScript(r.Dir, next), registry.B64(next)); err != nil {
				return nil, shellFailure(err, "")
			}
			out.Account = RegistryAccount{ID: name, Name: name, Kind: "user", Push: true}
			out.Secret = secret
		}
		return &struct{ Body RegistryAccountSecret }{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "reset-package-registry-account", Method: http.MethodPost, Path: base + "/accounts/{account}/password",
		Summary: "Give a Verdaccio user a new password", Description: "Answers it once.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		RegistryIDPath
		Account string `path:"account" maxLength:"64"`
	}) (*struct{ Body RegistryAccountSecret }, error) {
		row, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		r := row.PackageRegistry
		if err := mustReady(r); err != nil {
			return nil, err
		}
		if r.Kind != registry.Verdaccio {
			return nil, huma.Error422UnprocessableEntity("Harbor robot accounts get a new secret by making a new one")
		}
		if in.Account == r.AdminUser {
			return nil, huma.Error422UnprocessableEntity("Morche signs in as this user; its password can't change here")
		}
		text, err := h.root(ctx, r.ServerID, registry.ReadHtpasswdScript(r.Dir))
		if err != nil {
			return nil, shellFailure(err, "")
		}
		found := false
		for _, u := range registry.HtpasswdUsers(text) {
			found = found || u == in.Account
		}
		if !found {
			return nil, huma.Error404NotFound("No such user")
		}
		secret := registry.Password(20)
		line, err := registry.HtpasswdLine(in.Account, secret)
		if err != nil {
			return nil, internalError(err)
		}
		next := registry.SetHtpasswd(text, in.Account, line)
		if _, err := h.root(ctx, r.ServerID, registry.WriteHtpasswdScript(r.Dir, next), registry.B64(next)); err != nil {
			return nil, shellFailure(err, "")
		}
		return &struct{ Body RegistryAccountSecret }{RegistryAccountSecret{
			Account: RegistryAccount{ID: in.Account, Name: in.Account, Kind: "user", Push: true}, Secret: secret,
		}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-package-registry-account", Method: http.MethodDelete, Path: base + "/accounts/{account}",
		Summary: "Remove a robot account or a user", Tags: tags,
	}, func(ctx context.Context, in *struct {
		RegistryIDPath
		Account string `path:"account" maxLength:"64"`
	}) (*struct{}, error) {
		row, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		r := row.PackageRegistry
		if err := mustReady(r); err != nil {
			return nil, err
		}
		switch r.Kind {
		case registry.Harbor:
			id, err := strconv.Atoi(in.Account)
			if err != nil {
				return nil, huma.Error404NotFound("No such robot account")
			}
			if err := h.harbor(ctx, r, func(c registry.HarborClient) error { return c.DeleteRobot(ctx, id) }); err != nil {
				return nil, registryProblem(err)
			}
		case registry.Verdaccio:
			if in.Account == r.AdminUser {
				return nil, huma.Error422UnprocessableEntity("Morche signs in as this user, so it stays")
			}
			text, err := h.root(ctx, r.ServerID, registry.ReadHtpasswdScript(r.Dir))
			if err != nil {
				return nil, shellFailure(err, "")
			}
			found := false
			for _, u := range registry.HtpasswdUsers(text) {
				found = found || u == in.Account
			}
			if !found {
				return nil, huma.Error404NotFound("No such user")
			}
			next := registry.SetHtpasswd(text, in.Account, "")
			if _, err := h.root(ctx, r.ServerID, registry.WriteHtpasswdScript(r.Dir, next), registry.B64(next)); err != nil {
				return nil, shellFailure(err, "")
			}
		}
		return &struct{}{}, nil
	})
}

func asAPIError(err error, out **registry.APIError) bool { return errors.As(err, out) }
