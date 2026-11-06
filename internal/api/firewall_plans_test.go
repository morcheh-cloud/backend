package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/firewall"
)

const fwTestRules = `
### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### deny tcp 22 0.0.0.0/0 any 203.0.113.9 in
### tuple ### allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in comment=776562
`

func ufwState(active bool) *fwState {
	st := &fwState{before: "*filter\nCOMMIT\n"}
	st.o.Backend, st.o.Active, st.o.SSHPort, st.o.MorchehIP = "ufw", active, 22, "203.0.113.9"
	st.o.Capabilities = FirewallCapabilities{Manage: true, Reorder: true, Forwards: true, ForwardFrom: true}
	st.o.Rules = firewall.ParseUFW(fwTestRules, "")
	st.o.Forwards = []firewall.Forward{}
	return st
}

func TestPlanMove(t *testing.T) {
	st := ufwState(true)
	r := st.o.Rules
	cases := []struct {
		name, id, before string
		verb             string // what the re-add should say; "" = nothing happens
		risky            bool
	}{
		{"to the top", r[3].ID, r[0].ID, "ufw insert 1 allow", false},
		{"to the end", r[0].ID, "", "ufw allow", true}, // the deny now wins for Morcheh
		{"up one", r[1].ID, r[0].ID, "ufw insert 1 allow", false},
		{"down one", r[1].ID, r[3].ID, "ufw insert 3 allow", false},
		{"above itself", r[1].ID, r[1].ID, "", false},
		{"already right above", r[1].ID, r[2].ID, "", false},
		{"already last", r[3].ID, "", "", false},
		{"block moved first", r[2].ID, r[0].ID, "ufw insert 1 deny", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := st.planMove(c.id, c.before)
			if err != nil {
				t.Fatal(err)
			}
			if c.verb == "" {
				if len(p.cmds) != 0 {
					t.Fatalf("expected no commands, got %q", p.cmds)
				}
				return
			}
			all := strings.Join(p.cmds, "\n")
			if !strings.Contains(all, "ufw delete") || !strings.Contains(all, c.verb) {
				t.Errorf("want delete and %q in:\n%s", c.verb, all)
			}
			if p.risky != c.risky {
				t.Errorf("risky = %v, want %v", p.risky, c.risky)
			}
		})
	}

	t.Run("not on firewalld", func(t *testing.T) {
		fd := &fwState{}
		fd.o.Backend = "firewalld"
		if _, err := fd.planMove("x", ""); err == nil {
			t.Fatal("expected a refusal")
		}
	})
	t.Run("gone", func(t *testing.T) {
		if _, err := st.planMove("nope", ""); err == nil {
			t.Fatal("expected not found")
		}
		if _, err := st.planMove(r[0].ID, "nope"); err == nil {
			t.Fatal("expected not found")
		}
	})
	t.Run("a move keeps the note", func(t *testing.T) {
		p, err := st.planMove(r[3].ID, r[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(p.cmds, "\n"), "comment web") {
			t.Errorf("note lost: %q", p.cmds)
		}
	})
}

func TestPlanSetSkipsWhatsThere(t *testing.T) {
	st := ufwState(true)
	p, added, already, err := st.planSet([]FirewallRuleBody{
		{Action: "allow", Protocol: "tcp", Port: "80"},
		{Action: "allow", Protocol: "tcp", Port: "8443", Zone: "public"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 || already != 1 {
		t.Fatalf("added %d, already %d", added, already)
	}
	if all := strings.Join(p.cmds, "\n"); !strings.Contains(all, "8443") || strings.Contains(all, "port 80 ") {
		t.Errorf("commands: %s", all)
	}

	p, added, already, err = st.planSet([]FirewallRuleBody{{Action: "allow", Protocol: "tcp", Port: "80"}})
	if err != nil || added != 0 || already != 1 || len(p.cmds) != 0 {
		t.Fatalf("nothing to do: %v %d %d %q", err, added, already, p.cmds)
	}

	p, _, _, err = st.planSet([]FirewallRuleBody{{Action: "block", Protocol: "tcp", Port: "22"}})
	if err != nil || !p.risky {
		t.Fatalf("closing SSH must be risky: %v %v", err, p.risky)
	}
}

func TestForwardPlanUFW(t *testing.T) {
	st := ufwState(true)
	f, err := st.forwardFrom(FirewallForwardBody{Protocol: "tcp", Port: "8080", ToAddress: "10.0.0.5", ToPort: "80"}, "")
	if err != nil {
		t.Fatal(err)
	}
	p, err := st.planForwards([]firewall.Forward{f}, "x")
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(p.cmds, "\n")
	for _, want := range []string{"ufw route allow", "before.rules", "ip_forward=1", "ufw reload", "MORCHEH-PRE"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}

	if _, err := st.forwardFrom(FirewallForwardBody{Protocol: "tcp", Port: "22", ToPort: "2222"}, ""); err == nil {
		t.Error("forwarding the SSH port must be refused")
	}
	st.o.Forwards = []firewall.Forward{f}
	if _, err := st.forwardFrom(FirewallForwardBody{Protocol: "tcp", Port: "8080", ToPort: "81"}, ""); err == nil {
		t.Error("an overlapping forward must be refused")
	}
	if _, err := st.forwardFrom(FirewallForwardBody{Protocol: "tcp", Port: "8080", ToPort: "81"}, f.ID); err != nil {
		t.Errorf("replacing itself is fine: %v", err)
	}
	st.before = ""
	if _, err := st.planForwards(nil, "x"); err == nil {
		t.Error("no before.rules must be refused")
	}
}

func TestFinishAddsNothingToNothing(t *testing.T) {
	st := &fwState{}
	st.o.Backend, st.o.Active = "firewalld", true
	if cmds := st.finish(nil); len(cmds) != 0 {
		t.Errorf("no change must stay no change: %q", cmds)
	}
}

func TestRestorePreview(t *testing.T) {
	st := ufwState(true)
	before := fwSaved{Active: false, Rules: append(fwLabels(st.o)[1:], "Allow port 25/tcp"), Defaults: FirewallDefaults{Incoming: "allow"}}
	raw, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	st.o.Defaults.Incoming = "deny"
	row := sqlc.FirewallChange{Backend: "ufw", Status: fwApplied, StateBefore: raw, Snapshot: []byte{1}}
	out, err := previewFirewallChange(row, st)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Adds) != 1 || out.Adds[0] != "Allow port 25/tcp" {
		t.Errorf("adds = %q", out.Adds)
	}
	if len(out.Removes) != 1 {
		t.Errorf("removes = %q", out.Removes)
	}
	if out.Reordered || out.Problem != "" {
		t.Errorf("reordered %v, problem %q", out.Reordered, out.Problem)
	}
	if len(out.Settings) != 2 {
		t.Errorf("settings = %q", out.Settings)
	}

	row.Snapshot = nil
	if _, err := st.planRestore(row); err == nil {
		t.Error("no copy must be refused")
	}
	row.Snapshot, row.Backend = []byte{1}, "firewalld"
	if _, err := st.planRestore(row); err == nil {
		t.Error("another tool must be refused")
	}
	row.Backend = "ufw"
	p, err := st.planRestore(row)
	if err != nil {
		t.Fatal(err)
	}
	if p.risky {
		t.Error("going back to off isn't risky")
	}
	all := strings.Join(p.cmds, "\n")
	if !strings.Contains(all, "tar -tzf") || !strings.Contains(all, "rm -rf /etc/ufw") {
		t.Errorf("commands: %s", all)
	}

	reorder := fwLabels(st.o)
	reorder[0], reorder[1] = reorder[1], reorder[0]
	raw, _ = json.Marshal(fwSaved{Active: true, Rules: reorder})
	row.StateBefore = raw
	st.o.Defaults = FirewallDefaults{}
	if out, err = previewFirewallChange(row, st); err != nil || !out.Reordered {
		t.Errorf("reordered: %v %v", out.Reordered, err)
	}
}
