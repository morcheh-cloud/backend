package api

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/cloud"
	"github.com/morcheh/backend/internal/database/sqlc"
)

// CloudLinked is a Morche server at one of a cloud server's addresses.
type CloudLinked struct {
	ID     string `json:"id" format:"uuid"`
	Name   string `json:"name"`
	Host   string `json:"host"`
	Status string `json:"status"`
}

type CloudServer struct {
	cloud.Server
	AccountID   string        `json:"account_id" format:"uuid"`
	AccountName string        `json:"account_name"`
	Provider    string        `json:"provider"`
	Linked      []CloudLinked `json:"linked" doc:"Morche servers at one of its addresses"`
}

// CloudAccountRead is how reading one account went.
type CloudAccountRead struct {
	ID       string                `json:"id" format:"uuid"`
	Name     string                `json:"name"`
	Provider string                `json:"provider"`
	Status   string                `json:"status"`
	Message  string                `json:"message"`
	Problems []cloud.RegionProblem `json:"problems"`
	Regions  []cloud.Region        `json:"regions"`
	Changes  bool                  `json:"allow_changes"`
}

type CloudServersOutput struct {
	Body struct {
		Accounts []CloudAccountRead `json:"accounts"`
		Items    []CloudServer      `json:"items"`
		ReadAt   time.Time          `json:"read_at"`
	}
}

func (h *cloudHandler) linked(ctx context.Context, servers []cloud.Server) map[string][]CloudLinked {
	var hosts []string
	for _, s := range servers {
		for _, a := range s.Addresses {
			if !slices.Contains(hosts, a.IP) {
				hosts = append(hosts, a.IP)
			}
		}
	}
	out := map[string][]CloudLinked{}
	if len(hosts) == 0 {
		return out
	}
	sc := principalOf(ctx).scope()
	rows, err := h.q.ListServersByHost(ctx, sqlc.ListServersByHostParams{
		Hosts: hosts, SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, ServerIds: sc.servers,
	})
	if err != nil {
		slog.Warn("match cloud servers", "error", err)
		return out
	}
	for _, r := range rows {
		out[r.Host] = append(out[r.Host], CloudLinked{ID: r.ID.String(), Name: r.Name, Host: r.Host, Status: r.Status})
	}
	return out
}

func (h *cloudHandler) toServer(a sqlc.CloudAccount, s cloud.Server, links map[string][]CloudLinked) CloudServer {
	out := CloudServer{Server: s, AccountID: a.ID.String(), AccountName: a.Name, Provider: a.Provider, Linked: []CloudLinked{}}
	for _, ad := range s.Addresses {
		for _, l := range links[ad.IP] {
			if !slices.ContainsFunc(out.Linked, func(x CloudLinked) bool { return x.ID == l.ID }) {
				out.Linked = append(out.Linked, l)
			}
		}
	}
	if out.Addresses == nil {
		out.Addresses = []cloud.Address{}
	}
	return out
}

func (h *cloudHandler) listServers(ctx context.Context, in *struct {
	Account string `query:"account" doc:"Only this account"`
	Fresh   bool   `query:"fresh" doc:"Skip the short cache"`
}) (*CloudServersOutput, error) {
	accounts, err := h.listAccounts(ctx)
	if err != nil {
		return nil, err
	}
	if in.Account != "" {
		accounts = slices.DeleteFunc(accounts, func(a sqlc.CloudAccount) bool { return a.ID.String() != in.Account })
	}
	type result struct {
		a    sqlc.CloudAccount
		list cloud.List
		err  error
	}
	results := make([]result, len(accounts))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, a := range accounts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			list, saved, err := h.read(ctx, a, in.Fresh)
			results[i] = result{a: saved, list: list, err: err}
		}()
	}
	wg.Wait()

	var all []cloud.Server
	for _, r := range results {
		all = append(all, r.list.Servers...)
	}
	links := h.linked(ctx, all)
	out := &CloudServersOutput{}
	out.Body.Accounts = []CloudAccountRead{}
	out.Body.Items = []CloudServer{}
	out.Body.ReadAt = time.Now()
	for _, r := range results {
		status, message := cloudStatus(r.err)
		read := CloudAccountRead{
			ID: r.a.ID.String(), Name: r.a.Name, Provider: r.a.Provider, Status: status,
			Message: message, Problems: r.list.Problems, Regions: r.list.Regions, Changes: r.a.AllowChanges,
		}
		if read.Problems == nil {
			read.Problems = []cloud.RegionProblem{}
		}
		if read.Regions == nil {
			read.Regions = []cloud.Region{}
		}
		out.Body.Accounts = append(out.Body.Accounts, read)
		for _, s := range r.list.Servers {
			out.Body.Items = append(out.Body.Items, h.toServer(r.a, s, links))
		}
	}
	return out, nil
}

type CloudServerPath struct {
	CloudAccountIDPath
	Region string `path:"region" maxLength:"64"`
	Server string `path:"server" maxLength:"64"`
}

type CloudServerOutput struct {
	Body CloudServer
}

func (h *cloudHandler) server(ctx context.Context, in CloudServerPath) (sqlc.CloudAccount, cloud.Provider, cloud.Server, error) {
	a, err := h.account(ctx, in.ID)
	if err != nil {
		return a, nil, cloud.Server{}, err
	}
	p, err := h.savedProvider(a)
	if err != nil {
		return a, nil, cloud.Server{}, err
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	s, err := p.Server(cctx, in.Region, in.Server)
	if err != nil {
		return a, p, s, cloudError(err)
	}
	return a, p, s, nil
}

func (h *cloudHandler) answer(ctx context.Context, a sqlc.CloudAccount, s cloud.Server) *CloudServerOutput {
	return &CloudServerOutput{Body: h.toServer(a, s, h.linked(ctx, []cloud.Server{s}))}
}

// changing refuses a change on a view-only account, or for someone below
// the level it needs.
func changing(ctx context.Context, a sqlc.CloudAccount, need auth.Level) error {
	if !a.AllowChanges {
		return huma.Error403Forbidden("This account is view only. An Owner can turn on Allow changes in its settings.")
	}
	if principalOf(ctx).Access.WorkspaceLevel(a.WorkspaceID) < need {
		return huma.Error403Forbidden("You need " + need.String() + " access to the workspace.")
	}
	return nil
}

var cloudName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*$`)

var powerFits = map[string][]string{
	cloud.PowerOn:     {cloud.StateStopped},
	cloud.PowerOff:    {cloud.StateRunning},
	cloud.PowerReboot: {cloud.StateRunning},
}

func registerCloudServers(api huma.API, h *cloudHandler) {
	tags := []string{"Cloud"}

	huma.Register(api, huma.Operation{
		OperationID: "list-cloud-servers", Method: http.MethodGet, Path: "/cloud-servers",
		Summary:     "List cloud servers",
		Description: "Every server of every cloud account in the workspace, read live (kept 20 seconds). A region or account that fails is reported, the rest still show.",
		Tags:        tags,
	}, h.listServers)

	huma.Register(api, huma.Operation{
		OperationID: "get-cloud-server", Method: http.MethodGet, Path: "/cloud-accounts/{id}/servers/{region}/{server}",
		Summary: "Get a cloud server", Tags: tags,
	}, func(ctx context.Context, in *CloudServerPath) (*CloudServerOutput, error) {
		a, _, s, err := h.server(ctx, *in)
		if err != nil {
			return nil, err
		}
		return h.answer(ctx, a, s), nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "power-cloud-server", Method: http.MethodPost, Path: "/cloud-accounts/{id}/servers/{region}/{server}/power",
		Summary:     "Turn a cloud server on or off, or restart it",
		Description: "Needs the account's Allow changes. Answers the server as the provider reports it right after.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		CloudServerPath
		Body struct {
			Action string `json:"action" enum:"on,off,reboot"`
		}
	}) (*CloudServerOutput, error) {
		a, err := h.account(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if err := changing(ctx, a, auth.Operator); err != nil {
			return nil, err
		}
		a, p, s, err := h.server(ctx, in.CloudServerPath)
		if err != nil {
			return nil, err
		}
		if s.Task != "" {
			return nil, huma.Error409Conflict("The server is busy (" + strings.ToLower(s.Task) + "). Try again when it's done.")
		}
		if !slices.Contains(powerFits[in.Body.Action], s.State) {
			return nil, huma.Error409Conflict("The server is " + s.State + ".")
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := p.Power(cctx, in.Region, s.Zone, s.ID, in.Body.Action); err != nil {
			return nil, cloudError(err)
		}
		slog.Info("cloud server power", "account", a.ID, "server", s.ID, "action", in.Body.Action, "user", principalOf(ctx).User.ID)
		h.forget(a.ID)
		if fresh, err := p.Server(cctx, in.Region, s.ID); err == nil {
			s = fresh
		}
		return h.answer(ctx, a, s), nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "rename-cloud-server", Method: http.MethodPost, Path: "/cloud-accounts/{id}/servers/{region}/{server}/rename",
		Summary: "Rename a cloud server", Description: "Needs the account's Allow changes.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		CloudServerPath
		Body struct {
			Name string `json:"name" minLength:"1" maxLength:"63"`
		}
	}) (*CloudServerOutput, error) {
		a, err := h.account(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if err := changing(ctx, a, auth.Engineer); err != nil {
			return nil, err
		}
		name := strings.TrimSpace(in.Body.Name)
		if !cloudName.MatchString(name) {
			return nil, fieldError("body.name", "Use letters, digits, dots and dashes, starting with a letter or digit", name)
		}
		a, p, s, err := h.server(ctx, in.CloudServerPath)
		if err != nil {
			return nil, err
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := p.Rename(cctx, in.Region, s.Zone, s.ID, name); err != nil {
			return nil, cloudError(err)
		}
		h.forget(a.ID)
		if fresh, err := p.Server(cctx, in.Region, s.ID); err == nil {
			s = fresh
		} else {
			s.Name = name
		}
		return h.answer(ctx, a, s), nil
	})
}

// startCloudMonitor re-reads every account in the background so statuses and
// counts stay fresh without anyone on the page.
func startCloudMonitor(h *cloudHandler, every time.Duration) {
	if every <= 0 {
		return
	}
	var mu sync.Mutex
	running := map[uuid.UUID]bool{}
	go func() {
		sem := make(chan struct{}, 4)
		for range time.Tick(min(every, 15*time.Second)) {
			due, err := h.q.ListCloudAccountsDueForCheck(context.Background(), time.Now().Add(-every))
			if err != nil {
				slog.Warn("list cloud accounts due for check", "error", err)
				continue
			}
			for _, a := range due {
				mu.Lock()
				if running[a.ID] {
					mu.Unlock()
					continue
				}
				running[a.ID] = true
				mu.Unlock()
				sem <- struct{}{}
				go func() {
					defer func() { <-sem; mu.Lock(); delete(running, a.ID); mu.Unlock() }()
					ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
					defer cancel()
					h.read(ctx, a, true)
				}()
			}
		}
	}()
}
