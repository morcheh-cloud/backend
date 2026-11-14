package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/cloud"
	"github.com/morcheh/backend/internal/cloud/arvan"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/dbmon"
	"github.com/morcheh/backend/internal/secrets"
)

// cloudHandler connects Morche to cloud providers' APIs (an API key per
// account). Servers are read live; only the key and the last check are
// stored. Changes (power, rename) need the account's allow_changes.
type cloudHandler struct {
	q       *sqlc.Queries
	box     *secrets.Box
	authz   *authz
	fakeURL string

	mu    sync.Mutex
	cache map[uuid.UUID]cloudCached
	res   map[uuid.UUID]cloudResCached
}

// A listing is kept briefly, so several people (and the monitor) don't each
// read every region.
type cloudCached struct {
	list    cloud.List
	err     error
	at      time.Time
	updated time.Time
}

const cloudCacheFor = 20 * time.Second

var cloudProviders = map[string]string{"arvan": "ArvanCloud"}

type CloudAccountIDPath struct {
	ID string `path:"id" format:"uuid"`
}

// CloudAccount is an account. Its API key never leaves the backend; key_hint
// is the last four characters.
type CloudAccount struct {
	ID            string     `json:"id" format:"uuid"`
	WorkspaceID   string     `json:"workspace_id" format:"uuid"`
	Provider      string     `json:"provider" enum:"arvan"`
	ProviderLabel string     `json:"provider_label"`
	Name          string     `json:"name"`
	KeyHint       string     `json:"key_hint"`
	Description   string     `json:"description"`
	Favorite      bool       `json:"favorite"`
	AllowChanges  bool       `json:"allow_changes" doc:"Power and rename are allowed; off = view only"`
	Status        string     `json:"status" enum:"unknown,online,unreachable,auth_failed,tls_error,blocked,error"`
	StatusMessage string     `json:"status_message"`
	ServerCount   int32      `json:"server_count"`
	RunningCount  int32      `json:"running_count"`
	LatencyMs     *int32     `json:"latency_ms,omitempty"`
	LastCheckedAt *time.Time `json:"last_checked_at,omitempty"`
	LastOnlineAt  *time.Time `json:"last_online_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func toCloudAccount(a sqlc.CloudAccount) CloudAccount {
	return CloudAccount{
		ID: a.ID.String(), WorkspaceID: a.WorkspaceID.String(), Provider: a.Provider,
		ProviderLabel: cloudProviders[a.Provider], Name: a.Name, KeyHint: a.KeyHint,
		Description: a.Description, Favorite: a.Favorite, AllowChanges: a.AllowChanges,
		Status: a.Status, StatusMessage: a.StatusMessage, ServerCount: a.ServerCount,
		RunningCount: a.RunningCount, LatencyMs: a.LatencyMs, LastCheckedAt: a.LastCheckedAt,
		LastOnlineAt: a.LastOnlineAt, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
	}
}

type CloudAccountOutput struct {
	Body CloudAccount
}

type CloudAccountBody struct {
	Provider     string `json:"provider" enum:"arvan"`
	Name         string `json:"name" minLength:"1" maxLength:"100"`
	APIKey       string `json:"api_key,omitempty" maxLength:"300" doc:"Blank on update keeps the saved key."`
	Description  string `json:"description,omitempty" maxLength:"500"`
	AllowChanges bool   `json:"allow_changes,omitempty" doc:"Let people with access power servers on/off and rename them"`
}

func keyHint(key string) string {
	if len(key) <= 4 {
		return ""
	}
	return key[len(key)-4:]
}

func cleanCloudKey(provider, raw string) (string, error) {
	key := raw
	if provider == "arvan" {
		key = arvan.CleanKey(raw)
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return "", fieldError("body.api_key", "Enter the API key", "")
	}
	if strings.ContainsAny(key, " \t\r\n") {
		return "", fieldError("body.api_key", "Paste just the key, with no spaces", "")
	}
	return key, nil
}

func (h *cloudHandler) provider(provider, key string) (cloud.Provider, error) {
	switch provider {
	case "arvan":
		if h.fakeURL != "" && strings.HasPrefix(key, "fake-") {
			return arvan.New(arvan.Config{
				Key: key, BaseURL: h.fakeURL, Dial: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			}), nil
		}
		return arvan.New(arvan.Config{Key: key, Dial: dbmon.DirectDialer(false)}), nil
	}
	return nil, fieldError("body.provider", "Pick a provider", provider)
}

func (h *cloudHandler) savedProvider(a sqlc.CloudAccount) (cloud.Provider, error) {
	key, err := h.box.Open(a.ApiKeyEnc)
	if err != nil {
		return nil, internalError(err)
	}
	return h.provider(a.Provider, key)
}

func cloudStatus(err error) (string, string) {
	var blocked *dbmon.BlockedError
	if errors.As(err, &blocked) {
		return dbmon.StatusBlocked, blocked.Error()
	}
	return cloud.Classify(err)
}

// cloudError turns what the provider said into the API's answer.
func cloudError(err error) error {
	var se huma.StatusError
	if errors.As(err, &se) {
		return err
	}
	var nf *cloud.NotFoundError
	var perm *cloud.PermissionError
	var auth *cloud.AuthError
	var api *cloud.APIError
	switch {
	case errors.As(err, &nf):
		return huma.Error404NotFound(nf.Error())
	case errors.As(err, &perm):
		return huma.Error422UnprocessableEntity(perm.Error())
	case errors.As(err, &auth):
		return huma.Error422UnprocessableEntity(auth.Error() + ". Check the account's API key.")
	case errors.As(err, &api):
		if api.Status == http.StatusConflict {
			return huma.Error409Conflict(api.Error())
		}
		return huma.Error422UnprocessableEntity(api.Error())
	}
	_, message := cloudStatus(err)
	return huma.Error502BadGateway("Couldn't reach the provider: " + message)
}

func (h *cloudHandler) account(ctx context.Context, rawID string) (sqlc.CloudAccount, error) {
	id, err := uuid.Parse(rawID)
	if err != nil {
		return sqlc.CloudAccount{}, huma.Error404NotFound("Account not found")
	}
	a, err := h.q.GetCloudAccount(ctx, id)
	if isNotFound(err) {
		return sqlc.CloudAccount{}, huma.Error404NotFound("Account not found")
	}
	if err != nil {
		return sqlc.CloudAccount{}, internalError(err)
	}
	return a, nil
}

func countRunning(list cloud.List) int32 {
	n := int32(0)
	for _, s := range list.Servers {
		if s.State == cloud.StateRunning {
			n++
		}
	}
	return n
}

func (h *cloudHandler) record(ctx context.Context, id uuid.UUID, list cloud.List, checkErr error) (sqlc.CloudAccount, error) {
	status, message := cloudStatus(checkErr)
	if checkErr == nil && len(list.Problems) > 0 {
		message = "Some regions couldn't be read"
	}
	var latency *int32
	if checkErr == nil {
		ms := int32(list.Latency.Milliseconds())
		latency = &ms
	}
	return h.q.RecordCloudAccountCheck(ctx, sqlc.RecordCloudAccountCheckParams{
		ID: id, Status: status, StatusMessage: message, ServerCount: int32(len(list.Servers)),
		RunningCount: countRunning(list), LatencyMs: latency,
	})
}

func (h *cloudHandler) forget(id uuid.UUID) {
	h.mu.Lock()
	delete(h.cache, id)
	delete(h.res, id)
	h.mu.Unlock()
}

// read lists an account's servers (from the short cache unless fresh) and
// records the check when it went to the provider.
func (h *cloudHandler) read(ctx context.Context, a sqlc.CloudAccount, fresh bool) (cloud.List, sqlc.CloudAccount, error) {
	h.mu.Lock()
	c, ok := h.cache[a.ID]
	h.mu.Unlock()
	if ok && !fresh && c.updated.Equal(a.UpdatedAt) && time.Since(c.at) < cloudCacheFor {
		return c.list, a, c.err
	}
	p, err := h.savedProvider(a)
	if err != nil {
		return cloud.List{}, a, err
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	list, listErr := p.Servers(cctx)
	if ctx.Err() != nil {
		return list, a, ctx.Err()
	}
	h.mu.Lock()
	h.cache[a.ID] = cloudCached{list: list, err: listErr, at: time.Now(), updated: a.UpdatedAt}
	h.mu.Unlock()
	if saved, err := h.record(context.WithoutCancel(ctx), a.ID, list, listErr); err == nil {
		a = saved
	}
	return list, a, listErr
}

func (h *cloudHandler) checkNow(ctx context.Context, a sqlc.CloudAccount) sqlc.CloudAccount {
	_, saved, _ := h.read(ctx, a, true)
	return saved
}

func (h *cloudHandler) ownerOfTarget(ctx context.Context, p *principal) (uuid.UUID, error) {
	ws, err := h.authz.createTarget(ctx, p)
	if err != nil {
		return uuid.Nil, err
	}
	if p.Access.WorkspaceLevel(ws) < auth.Owner {
		return uuid.Nil, huma.Error403Forbidden("You need Owner access to the workspace to connect a cloud account.")
	}
	return ws, nil
}

func (h *cloudHandler) create(ctx context.Context, in *struct{ Body CloudAccountBody }) (*CloudAccountOutput, error) {
	p := principalOf(ctx)
	b := in.Body
	ws, err := h.ownerOfTarget(ctx, p)
	if err != nil {
		return nil, err
	}
	if cloudProviders[b.Provider] == "" {
		return nil, fieldError("body.provider", "Pick a provider", b.Provider)
	}
	key, err := cleanCloudKey(b.Provider, b.APIKey)
	if err != nil {
		return nil, err
	}
	a, err := h.q.CreateCloudAccount(ctx, sqlc.CreateCloudAccountParams{
		WorkspaceID: ws, Provider: b.Provider, Name: strings.TrimSpace(b.Name),
		ApiKeyEnc: h.box.Seal(key), KeyHint: keyHint(key),
		Description: strings.TrimSpace(b.Description), AllowChanges: b.AllowChanges,
	})
	if isUniqueViolation(err) {
		return nil, fieldError("body.name", "An account with this name already exists", b.Name)
	}
	if err != nil {
		return nil, internalError(err)
	}
	return &CloudAccountOutput{Body: toCloudAccount(h.checkNow(ctx, a))}, nil
}

// resolveKey: blank = the saved key, for the same provider.
func (h *cloudHandler) resolveKey(prev sqlc.CloudAccount, provider, raw string) (string, error) {
	if strings.TrimSpace(raw) != "" {
		return cleanCloudKey(provider, raw)
	}
	if prev.Provider != provider {
		return "", fieldError("body.api_key", "The provider changed: enter its API key", "")
	}
	saved, err := h.box.Open(prev.ApiKeyEnc)
	if err != nil {
		return "", internalError(err)
	}
	return saved, nil
}

func (h *cloudHandler) update(ctx context.Context, in *struct {
	CloudAccountIDPath
	Body CloudAccountBody
}) (*CloudAccountOutput, error) {
	b := in.Body
	prev, err := h.account(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	if b.Provider != prev.Provider {
		return nil, fieldError("body.provider", "An account's provider can't change: add a new account", b.Provider)
	}
	key, err := h.resolveKey(prev, b.Provider, b.APIKey)
	if err != nil {
		return nil, err
	}
	a, err := h.q.UpdateCloudAccount(ctx, sqlc.UpdateCloudAccountParams{
		ID: prev.ID, Name: strings.TrimSpace(b.Name), ApiKeyEnc: h.box.Seal(key), KeyHint: keyHint(key),
		Description: strings.TrimSpace(b.Description), AllowChanges: b.AllowChanges,
	})
	if isUniqueViolation(err) {
		return nil, fieldError("body.name", "An account with this name already exists", b.Name)
	}
	if err != nil {
		return nil, internalError(err)
	}
	h.forget(a.ID)
	return &CloudAccountOutput{Body: toCloudAccount(h.checkNow(ctx, a))}, nil
}

type CloudTestBody struct {
	Provider  string  `json:"provider" enum:"arvan"`
	APIKey    string  `json:"api_key,omitempty" maxLength:"300"`
	AccountID *string `json:"account_id,omitempty" format:"uuid" doc:"When editing: the saved account, whose key a blank one stands for."`
}

type CloudTestOutput struct {
	Body struct {
		OK        bool                  `json:"ok"`
		Status    string                `json:"status"`
		Message   string                `json:"message"`
		Servers   int                   `json:"servers"`
		Running   int                   `json:"running"`
		Regions   int                   `json:"regions"`
		Problems  []cloud.RegionProblem `json:"problems"`
		LatencyMs int64                 `json:"latency_ms"`
	}
}

func (h *cloudHandler) test(ctx context.Context, in *struct{ Body CloudTestBody }) (*CloudTestOutput, error) {
	p := principalOf(ctx)
	b := in.Body
	if cloudProviders[b.Provider] == "" {
		return nil, fieldError("body.provider", "Pick a provider", b.Provider)
	}
	var key string
	if id := parseOptionalID(b.AccountID); id != nil {
		a, err := h.q.GetCloudAccount(ctx, *id)
		if isNotFound(err) || (err == nil && p.Access.WorkspaceLevel(a.WorkspaceID) == auth.None) {
			return nil, huma.Error404NotFound("Account not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if p.Access.WorkspaceLevel(a.WorkspaceID) < auth.Owner {
			return nil, huma.Error403Forbidden("You need Owner access to use this account's saved key.")
		}
		if key, err = h.resolveKey(a, b.Provider, b.APIKey); err != nil {
			return nil, err
		}
	} else {
		if _, err := h.ownerOfTarget(ctx, p); err != nil {
			return nil, err
		}
		var err error
		if key, err = cleanCloudKey(b.Provider, b.APIKey); err != nil {
			return nil, err
		}
	}
	prov, err := h.provider(b.Provider, key)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	list, listErr := prov.Servers(cctx)
	out := &CloudTestOutput{}
	out.Body.Status, out.Body.Message = cloudStatus(listErr)
	out.Body.OK = listErr == nil
	out.Body.Servers, out.Body.Running = len(list.Servers), int(countRunning(list))
	if listErr == nil {
		out.Body.Regions = len(list.Regions) - len(list.Problems)
	}
	out.Body.Problems = list.Problems
	if out.Body.Problems == nil {
		out.Body.Problems = []cloud.RegionProblem{}
	}
	out.Body.LatencyMs = list.Latency.Milliseconds()
	return out, nil
}

func (h *cloudHandler) listAccounts(ctx context.Context) ([]sqlc.CloudAccount, error) {
	sc := principalOf(ctx).scope()
	rows, err := h.q.ListCloudAccounts(ctx, sqlc.ListCloudAccountsParams{
		SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, WorkspaceID: sc.current,
	})
	if err != nil {
		return nil, internalError(err)
	}
	return rows, nil
}

type CloudAccountsOutput struct {
	Body struct {
		Items []CloudAccount `json:"items"`
	}
}

func registerCloudAccounts(api huma.API, h *cloudHandler) {
	tags := []string{"Cloud"}

	huma.Register(api, huma.Operation{
		OperationID: "list-cloud-accounts", Method: http.MethodGet, Path: "/cloud-accounts",
		Summary: "List cloud accounts", Description: "Favourites first, then by name.", Tags: tags,
	}, func(ctx context.Context, _ *struct{}) (*CloudAccountsOutput, error) {
		rows, err := h.listAccounts(ctx)
		if err != nil {
			return nil, err
		}
		out := &CloudAccountsOutput{}
		out.Body.Items = make([]CloudAccount, 0, len(rows))
		for _, r := range rows {
			out.Body.Items = append(out.Body.Items, toCloudAccount(r))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-cloud-account", Method: http.MethodPost, Path: "/cloud-accounts",
		Summary: "Connect a cloud account", Tags: tags, DefaultStatus: http.StatusCreated,
	}, h.create)

	huma.Register(api, huma.Operation{
		OperationID: "test-cloud-account", Method: http.MethodPost, Path: "/cloud-accounts/test-connection",
		Summary:     "Test a cloud API key",
		Description: "Lists the servers with the given key (read only) without saving anything.",
		Tags:        tags,
	}, h.test)

	huma.Register(api, huma.Operation{
		OperationID: "get-cloud-account", Method: http.MethodGet, Path: "/cloud-accounts/{id}",
		Summary: "Get a cloud account", Tags: tags,
	}, func(ctx context.Context, in *struct{ CloudAccountIDPath }) (*CloudAccountOutput, error) {
		a, err := h.account(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &CloudAccountOutput{Body: toCloudAccount(a)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-cloud-account", Method: http.MethodPut, Path: "/cloud-accounts/{id}",
		Summary: "Change a cloud account", Tags: tags,
	}, h.update)

	huma.Register(api, huma.Operation{
		OperationID: "delete-cloud-account", Method: http.MethodDelete, Path: "/cloud-accounts/{id}",
		Summary:     "Remove a cloud account",
		Description: "Morche forgets the account and its key. Nothing at the provider changes.",
		Tags:        tags, DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *struct{ CloudAccountIDPath }) (*struct{}, error) {
		id := uuid.MustParse(in.ID)
		if err := h.q.DeleteCloudAccount(ctx, id); err != nil {
			return nil, internalError(err)
		}
		h.forget(id)
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-cloud-account-favorite", Method: http.MethodPut, Path: "/cloud-accounts/{id}/favorite",
		Summary: "Star or unstar a cloud account", Tags: tags,
	}, func(ctx context.Context, in *struct {
		CloudAccountIDPath
		Body struct {
			Favorite bool `json:"favorite"`
		}
	}) (*CloudAccountOutput, error) {
		a, err := h.q.SetCloudAccountFavorite(ctx, sqlc.SetCloudAccountFavoriteParams{ID: uuid.MustParse(in.ID), Favorite: in.Body.Favorite})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("Account not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &CloudAccountOutput{Body: toCloudAccount(a)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "check-cloud-account", Method: http.MethodPost, Path: "/cloud-accounts/{id}/check",
		Summary: "Check a cloud account", Description: "Reads its servers again (read only).", Tags: tags,
	}, func(ctx context.Context, in *struct{ CloudAccountIDPath }) (*CloudAccountOutput, error) {
		a, err := h.account(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &CloudAccountOutput{Body: toCloudAccount(h.checkNow(ctx, a))}, nil
	})
}
