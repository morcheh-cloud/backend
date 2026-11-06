package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/firewall"
	"github.com/morcheh/backend/internal/sshpool"
)

const (
	fwApplied = "applied"
	fwPending = "pending"
	fwUndone  = "undone"

	// How many changes a server keeps, and the most a saved copy may take. A
	// copy goes back to the server as one command-line argument, which Linux
	// caps at 128 KiB, in base64.
	fwHistoryKeep   = 50
	fwSnapshotBytes = 64 << 10
)

// FirewallChange is one change made through Morcheh.
type FirewallChange struct {
	ID         string    `json:"id" format:"uuid"`
	Summary    string    `json:"summary" example:"Allow port 443/tcp"`
	User       string    `json:"user" doc:"Who made it"`
	Backend    string    `json:"backend" example:"ufw"`
	Status     string    `json:"status" enum:"applied,pending,undone" doc:"pending = waiting to be kept; undone = it was taken back straight away"`
	Added      []string  `json:"added" doc:"Rules and forwards it added"`
	Removed    []string  `json:"removed" doc:"Rules and forwards it removed"`
	Restorable bool      `json:"restorable" doc:"A copy of the firewall from before it was saved"`
	CreatedAt  time.Time `json:"created_at"`
}

type FirewallHistory struct {
	Items []FirewallChange `json:"items" doc:"Newest first; a server keeps its last 50"`
}

// FirewallChangePreview is what going back to before a change would do.
type FirewallChangePreview struct {
	Change    FirewallChange `json:"change"`
	Adds      []string       `json:"adds" doc:"Rules and forwards that would come back"`
	Removes   []string       `json:"removes" doc:"Rules and forwards that would go"`
	Settings  []string       `json:"settings" doc:"Settings that would change"`
	Reordered bool           `json:"reordered" doc:"The order of the rules would change"`
	Problem   string         `json:"problem" doc:"Why it can't go back; empty when it can"`
}

type FirewallChangePath struct {
	ID     string `path:"id" format:"uuid"`
	Change string `path:"change" format:"uuid"`
}

// fwSaved is the firewall as it was before a change: enough to say what going
// back would do, without unpacking the copy.
type fwSaved struct {
	Active   bool             `json:"active"`
	Boot     bool             `json:"boot"`
	Defaults FirewallDefaults `json:"defaults"`
	Rules    []string         `json:"rules"`
}

// fwActor is who a change is written down for.
type fwActor struct {
	id   *uuid.UUID
	name string
}

func actorOf(ctx context.Context) fwActor {
	p := principalOf(ctx)
	if p == nil {
		return fwActor{}
	}
	return fwActor{p.ID(), displayName(p.User)}
}

func displayName(u sqlc.User) string {
	if u.FullName != "" {
		return u.FullName
	}
	return u.Username
}

func registerFirewallHistory(api huma.API, h *serverHandler, base string) {
	tags := []string{"Firewall"}

	huma.Register(api, huma.Operation{
		OperationID: "firewall-history",
		Method:      http.MethodGet,
		Path:        base + "/history",
		Summary:     "Changes made through Morcheh",
		Description: "Read from Morcheh's database, so it works while the server is down. Changes made on the server by hand aren't here.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body FirewallHistory }, error) {
		rows, err := h.q.ListFirewallChanges(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct{ Body FirewallHistory }{}
		out.Body.Items = make([]FirewallChange, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = FirewallChange{
				ID: r.ID.String(), Summary: r.Summary, User: r.UserName, Backend: r.Backend, Status: fwStatus(r.Status, r.CreatedAt),
				Added: r.Added, Removed: r.Removed, Restorable: r.Restorable, CreatedAt: r.CreatedAt,
			}
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "firewall-change",
		Method:      http.MethodGet,
		Path:        base + "/history/{change}",
		Summary:     "What going back to before a change would do",
		Description: "Compares the firewall as it was with how it is now.",
		Tags:        tags,
	}, func(ctx context.Context, in *FirewallChangePath) (*struct{ Body FirewallChangePreview }, error) {
		row, err := h.firewallChangeRow(ctx, in.ID, in.Change)
		if err != nil {
			return nil, err
		}
		out := &struct{ Body FirewallChangePreview }{}
		err = h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.rootShell(ctx, in.ID, c)
			if err != nil {
				return err
			}
			st, err := collectFirewall(ctx, sh)
			if err != nil {
				return err
			}
			out.Body, err = previewFirewallChange(row, st)
			return err
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "restore-firewall-change",
		Method:      http.MethodPost,
		Path:        base + "/history/{change}/restore",
		Summary:     "Go back to before a change",
		Description: "Puts the whole firewall back as it was, which also takes back later changes. It's a change like any other: " +
			"with the firewall on it answers with `pending`, and it shows up in the history, so it can be taken back too.",
		Tags: tags,
	}, func(ctx context.Context, in *FirewallChangePath) (*FirewallOutput, error) {
		row, err := h.firewallChangeRow(ctx, in.ID, in.Change)
		if err != nil {
			return nil, err
		}
		return h.firewallChange(ctx, in.ID, func(st *fwState) (fwPlan, error) { return st.planRestore(row) })
	})
}

func (h *serverHandler) firewallChangeRow(ctx context.Context, server, change string) (sqlc.FirewallChange, error) {
	row, err := h.q.GetFirewallChange(ctx, sqlc.GetFirewallChangeParams{ID: uuid.MustParse(change), ServerID: uuid.MustParse(server)})
	if isNotFound(err) {
		return row, huma.Error404NotFound("That change isn't in the history any more")
	}
	if err != nil {
		return row, internalError(err)
	}
	return row, nil
}

// fwStatus reads a row's status. A change left waiting past its time was undone
// by the server, even if nobody has asked since.
func fwStatus(status string, at time.Time) string {
	if status == fwPending && time.Since(at) > (fwWindow+30)*time.Second {
		return fwUndone
	}
	return status
}

// fwSnapshot packs the firewall's configuration. It's only for going back
// later: failing to save one never stops a change, the entry just can't be
// restored.
func fwSnapshot(ctx context.Context, sh *rootShell, st *fwState) []byte {
	paths, _, err := st.rollback()
	if err != nil {
		return nil
	}
	script := fwEnv + `tar -C / -czf - ` + paths + ` 2>/dev/null | base64 | tr -d '\n'`
	res, err := sh.exec(ctx, script, fwCmdTimeout, fwSnapshotBytes*4/3+16)
	if err != nil || res.code != 0 || res.truncated {
		return nil
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(res.output)))
	if err != nil || len(data) == 0 || len(data) > fwSnapshotBytes {
		return nil
	}
	return data
}

// ruleLabel is how a rule reads in the history. It says everything that makes
// two rules different, since the history compares them by this text.
func ruleLabel(r firewall.FilterRule) string {
	s := describeExisting(r)
	if r.Direction == "out" || r.Direction == "routed" {
		s += " (" + r.Direction + ")"
	}
	if r.To != "" {
		s += " to " + r.To
	}
	if r.Interface != "" {
		s += " on " + r.Interface
	}
	if r.OutInterface != "" {
		s += " out on " + r.OutInterface
	}
	if r.Zone != "" {
		s += " (zone " + r.Zone + ")"
	}
	if r.Comment != "" {
		s += " · " + r.Comment
	}
	return s
}

func fwLabels(o FirewallOverview) []string {
	out := make([]string, 0, len(o.Rules)+len(o.Forwards))
	for _, r := range o.Rules {
		out = append(out, ruleLabel(r))
	}
	for _, f := range o.Forwards {
		out = append(out, forwardLabel(f))
	}
	return out
}

// without returns what's in a but not in b.
func without(a, b []string) []string {
	out := []string{}
	for _, s := range a {
		if !slices.Contains(b, s) && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// recordFirewallChange writes down a change that went through. The change has
// happened whatever happens here, so a failure is only logged.
func (h *serverHandler) recordFirewallChange(ctx context.Context, id string, actor fwActor, st, fresh *fwState, p fwPlan, snapshot []byte) {
	server := uuid.MustParse(id)
	saved, err := json.Marshal(fwSaved{st.o.Active, st.o.StartsAtBoot, st.o.Defaults, fwLabels(st.o)})
	if err != nil {
		slog.Warn("save a firewall change", "server", id, "error", err)
		return
	}
	added, removed := []string{}, []string{}
	if fresh != nil {
		before, after := fwLabels(st.o), fwLabels(fresh.o)
		added, removed = without(after, before), without(before, after)
	}
	status := fwApplied
	if p.risky {
		status = fwPending
	}
	// The change went ahead, so nothing was waiting on the server: whatever is
	// still marked as waiting ran out of time.
	h.settleFirewallChanges(ctx, id, fwUndone)
	if _, err := h.q.AddFirewallChange(ctx, sqlc.AddFirewallChangeParams{
		ServerID: server, UserID: actor.id, UserName: actor.name, Summary: p.summary, Backend: st.o.Backend,
		Status: status, StateBefore: saved, Added: added, Removed: removed, Snapshot: snapshot,
	}); err != nil {
		slog.Warn("save a firewall change", "server", id, "error", err)
		return
	}
	if err := h.q.PruneFirewallChanges(ctx, sqlc.PruneFirewallChangesParams{ServerID: server, Keep: fwHistoryKeep}); err != nil {
		slog.Warn("trim the firewall history", "server", id, "error", err)
	}
}

func (h *serverHandler) settleFirewallChanges(ctx context.Context, id, status string) {
	err := h.q.SettleFirewallChanges(context.WithoutCancel(ctx), sqlc.SettleFirewallChangesParams{Status: status, ServerID: uuid.MustParse(id)})
	if err != nil {
		slog.Warn("update a firewall change", "server", id, "error", err)
	}
}

func restoreProblem(row sqlc.FirewallChange, st *fwState) string {
	switch {
	case row.Snapshot == nil:
		return "Morcheh couldn't save a copy of the firewall before this change, so it can't go back to it."
	case row.Backend != st.o.Backend:
		return "This change was made on " + row.Backend + ", and the server now uses " + st.o.Backend + "."
	}
	return ""
}

func previewFirewallChange(row sqlc.FirewallChange, st *fwState) (FirewallChangePreview, error) {
	var then fwSaved
	if err := json.Unmarshal(row.StateBefore, &then); err != nil {
		return FirewallChangePreview{}, internalError(err)
	}
	now := fwLabels(st.o)
	out := FirewallChangePreview{
		Change: FirewallChange{
			ID: row.ID.String(), Summary: row.Summary, User: row.UserName, Backend: row.Backend, Status: fwStatus(row.Status, row.CreatedAt),
			Added: row.Added, Removed: row.Removed, Restorable: row.Snapshot != nil, CreatedAt: row.CreatedAt,
		},
		Adds: without(then.Rules, now), Removes: without(now, then.Rules), Settings: []string{},
		Problem: restoreProblem(row, st),
	}
	if len(out.Adds) == 0 && len(out.Removes) == 0 && !slices.Equal(then.Rules, now) {
		out.Reordered = true
	}
	if then.Active != st.o.Active {
		if then.Active {
			out.Settings = append(out.Settings, "The firewall would turn on")
		} else {
			out.Settings = append(out.Settings, "The firewall would turn off")
		}
	}
	for _, d := range []struct{ name, then, now string }{
		{"Incoming", then.Defaults.Incoming, st.o.Defaults.Incoming},
		{"Outgoing", then.Defaults.Outgoing, st.o.Defaults.Outgoing},
		{"Routed", then.Defaults.Routed, st.o.Defaults.Routed},
		{"Logging", then.Defaults.Logging, st.o.Defaults.Logging},
	} {
		if d.then != d.now {
			out.Settings = append(out.Settings, d.name+": "+d.now+" → "+d.then)
		}
	}
	return out, nil
}

// planRestore puts the saved configuration back. Under applyScript's net, like
// any other change: if it fails, or cuts Morcheh off, the firewall goes back to
// how it is now.
func (st *fwState) planRestore(row sqlc.FirewallChange) (fwPlan, error) {
	if msg := restoreProblem(row, st); msg != "" {
		return fwPlan{}, huma.Error422UnprocessableEntity(msg)
	}
	var then fwSaved
	if err := json.Unmarshal(row.StateBefore, &then); err != nil {
		return fwPlan{}, internalError(err)
	}
	unpack := func(dir string) []string {
		return []string{
			`printf '%s' ` + base64.StdEncoding.EncodeToString(row.Snapshot) + ` | base64 -d > "$d/restore.tgz" || fail "Could not write the saved copy to the server"`,
			`tar -tzf "$d/restore.tgz" >/dev/null 2>&1 || fail "The saved copy is damaged"`,
			`rm -rf ` + dir,
			`tar -C / -xzf "$d/restore.tgz" || fail "Could not unpack the saved copy"`,
		}
	}
	summary := "Go back to before: " + strings.TrimPrefix(row.Summary, "Go back to before: ")
	var cmds []string
	if st.o.Backend == "ufw" {
		cmds = append(unpack("/etc/ufw"), fwNatFlush, "r ufw --force disable")
		if then.Active {
			cmds = append(cmds, "r ufw --force enable", fwNatTidy)
		}
		return fwPlan{cmds: cmds, risky: then.Active, summary: summary}, nil
	}
	state := []string{"stop"}
	if then.Active {
		state = []string{"start"}
	}
	boot := "disable"
	if then.Boot {
		boot = "enable"
	}
	service, err := st.serviceCommands(append(state, boot)...)
	if err != nil {
		return fwPlan{}, err
	}
	cmds = append(unpack("/etc/firewalld"), service...)
	if then.Active {
		cmds = append(cmds, "r firewall-cmd --reload")
	}
	return fwPlan{cmds: cmds, risky: then.Active, summary: summary}, nil
}
