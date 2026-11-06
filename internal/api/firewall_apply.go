package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/firewall"
	"github.com/morcheh/backend/internal/jobs"
)

const (
	fwApplyKind   = "firewall-apply"
	fwApplyAtOnce = 4
)

type FirewallApplyBody struct {
	ServerIDs []string           `json:"server_ids" minItems:"1" maxItems:"200" doc:"Engineer access on each is needed"`
	Rules     []FirewallRuleBody `json:"rules" minItems:"1" maxItems:"100"`
}

type fwApplyServer struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type fwApplyParams struct {
	Servers []fwApplyServer    `json:"servers"`
	Rules   []FirewallRuleBody `json:"rules"`
}

// FirewallApplyResult is one server's outcome, in the job's result.
type FirewallApplyResult struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status" enum:"done,failed,skipped"`
	Added   int    `json:"added"`
	Already int    `json:"already" doc:"Rules it had already"`
	Message string `json:"message,omitempty"`
}

func registerFirewallApply(api huma.API, h *serverHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "apply-firewall-rules",
		Method:      http.MethodPost,
		Path:        "/firewall/apply",
		Summary:     "Add rules to many servers",
		Description: "Runs as a background job (kind `firewall-apply`), a few servers at a time. Rules a server already has are skipped. " +
			"Each server gets all the rules or none. A server is left alone if the rules could cut SSH off, since nobody is there to confirm it.",
		Tags:          []string{"Firewall"},
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct{ Body FirewallApplyBody }) (*JobOutput, error) {
		return h.submitFirewallApply(ctx, in.Body)
	})
	h.jobs.Handle(fwApplyKind, h.runFirewallApply)
}

func (h *serverHandler) submitFirewallApply(ctx context.Context, b FirewallApplyBody) (*JobOutput, error) {
	for i, body := range b.Rules {
		in := body.input()
		if err := in.Normalize(); err != nil {
			var fe *firewall.FieldError
			if errors.As(err, &fe) {
				return nil, fieldError(fmt.Sprintf("body.rules[%d].%s", i, fe.Field), fe.Message, nil)
			}
			return nil, internalError(err)
		}
	}
	ids := parseIDs(b.ServerIDs)
	if len(ids) != len(b.ServerIDs) {
		return nil, fieldError("body.server_ids", "Those aren't all server ids", nil)
	}
	slices.SortFunc(ids, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	ids = slices.Compact(ids)
	if _, err := h.authz.requireServers(ctx, ids, auth.Engineer); err != nil {
		return nil, err
	}
	p := fwApplyParams{Rules: b.Rules}
	refs := make([]string, len(ids))
	for i, id := range ids {
		s, err := h.get(ctx, id.String())
		if err != nil {
			return nil, err
		}
		p.Servers = append(p.Servers, fwApplyServer{s.ID.String(), s.Name})
		refs[i] = id.String()
	}
	what := fmt.Sprintf("%d firewall rules", len(b.Rules))
	if len(b.Rules) == 1 {
		what = "1 firewall rule"
	}
	title := fmt.Sprintf("Add %s to %d servers", what, len(ids))
	if len(ids) == 1 {
		title = fmt.Sprintf("Add %s to %s", what, p.Servers[0].Name)
	}
	return submit(ctx, h.jobs, jobs.Spec{Kind: fwApplyKind, Title: title, Params: p, Refs: placeRefs(refs...)})
}

func (h *serverHandler) runFirewallApply(ctx context.Context, t *jobs.Task) (any, error) {
	var p fwApplyParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	actor := fwActor{}
	if id := t.CreatedBy(); id != nil {
		actor.id = id
		if u, err := h.q.GetUser(ctx, *id); err == nil {
			actor.name = displayName(u)
		}
	}
	t.Update(func(pr *jobs.Progress) { pr.Phase, pr.ItemsTotal = "Adding rules", len(p.Servers) })

	results := make([]FirewallApplyResult, len(p.Servers))
	slots := make(chan struct{}, fwApplyAtOnce)
	var wg sync.WaitGroup
	for i, s := range p.Servers {
		results[i] = FirewallApplyResult{ID: s.ID, Name: s.Name, Status: "skipped"}
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			r := &results[i]
			h.applyToServer(ctx, s, p.Rules, actor, r)
			switch {
			case r.Status == "failed":
				t.Logf("%s: failed: %s", s.Name, r.Message)
			case r.Message != "":
				t.Logf("%s: added %d, already there %d. %s", s.Name, r.Added, r.Already, r.Message)
			default:
				t.Logf("%s: added %d, already there %d", s.Name, r.Added, r.Already)
			}
			t.Update(func(pr *jobs.Progress) { pr.Items++; pr.Current = s.Name })
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	failed := 0
	for _, r := range results {
		if r.Status == "failed" {
			failed++
		}
	}
	if failed > 0 {
		// A failed job keeps no result, so the log above is what says which.
		return nil, fmt.Errorf("%d of %d servers failed: open the task to see why", failed, len(results))
	}
	return map[string]any{"servers": results}, nil
}

func (h *serverHandler) applyToServer(ctx context.Context, s fwApplyServer, rules []FirewallRuleBody, actor fwActor, r *FirewallApplyResult) {
	off := false
	_, err := h.fwChange(ctx, s.ID, fwOptions{actor: actor, unattended: true}, func(st *fwState) (fwPlan, error) {
		off = !st.o.Active
		p, added, already, err := st.planSet(rules)
		r.Added, r.Already = added, already
		return p, err
	})
	if err != nil {
		r.Status, r.Added, r.Message = "failed", 0, errorDetail(err)
		return
	}
	r.Status = "done"
	if off {
		r.Message = "The firewall is off here, so these rules do nothing until it's on."
	}
}

// errorDetail is an error's message without its status.
func errorDetail(err error) string {
	var m *huma.ErrorModel
	if errors.As(err, &m) && m.Detail != "" {
		return m.Detail
	}
	return err.Error()
}

// planSet adds the rules this firewall doesn't have yet. What only makes sense
// on the server they came from is adjusted: firewalld has no notes, ufw no
// zones, and a zone this server doesn't have means its default one.
func (st *fwState) planSet(rules []FirewallRuleBody) (p fwPlan, added, already int, err error) {
	risky := false
	var cmds []string
	for _, body := range rules {
		in := body.input()
		if err := in.Normalize(); err != nil {
			return fwPlan{}, 0, 0, err
		}
		if st.o.Backend == "ufw" {
			in.Zone = ""
		} else {
			in.Comment = ""
			if !slices.ContainsFunc(st.o.Zones, func(z firewall.Zone) bool { return z.Name == in.Zone }) {
				in.Zone = st.o.DefaultZone
			}
		}
		if in.Present(st.o.Rules) {
			already++
			continue
		}
		add, err := st.addCommands(in, 0)
		if err != nil {
			return fwPlan{}, 0, 0, err
		}
		cmds = append(cmds, add...)
		added++
		risky = risky || st.o.Active && st.stops(in)
	}
	summary := fmt.Sprintf("Add %d rules from another server", added)
	if added == 1 {
		summary = "Add 1 rule from another server"
	}
	return fwPlan{cmds: st.finish(cmds), risky: risky, summary: summary}, added, already, nil
}
