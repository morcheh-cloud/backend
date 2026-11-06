package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/firewall"
)

const (
	// ufw filters forwarded traffic after the rewrite, so each forward has a
	// rule beside it. This note is how Morcheh knows which rules it may remove.
	fwForwardComment = "Port forward (added by Morcheh)"

	// fwNatFlush stops the forwards until before.rules is loaded again. Other
	// programs' rules in the nat table aren't touched.
	fwNatFlush = `iptables -w -t nat -F ` + firewall.ForwardChainP + ` 2>/dev/null; iptables -w -t nat -F ` + firewall.ForwardChainQ + ` 2>/dev/null; :`

	// fwNatTidy leaves one jump to each chain: every load of before.rules adds
	// another, since ufw loads it without flushing the built-in chains.
	fwNatTidy = `for p in "PREROUTING ` + firewall.ForwardChainP + `" "POSTROUTING ` + firewall.ForwardChainQ + `"; do
  set -- $p
  if iptables -w -t nat -S "$2" >/dev/null 2>&1; then
    while iptables -w -t nat -D "$1" -j "$2" 2>/dev/null; do :; done
    iptables -w -t nat -A "$1" -j "$2"
  fi
done`

	// fwNatDrop takes the chains away altogether.
	fwNatDrop = `for p in "PREROUTING ` + firewall.ForwardChainP + `" "POSTROUTING ` + firewall.ForwardChainQ + `"; do
  set -- $p
  while iptables -w -t nat -D "$1" -j "$2" 2>/dev/null; do :; done
  iptables -w -t nat -F "$2" 2>/dev/null
  iptables -w -t nat -X "$2" 2>/dev/null
done
:`

	fwRouting = `sed -i 's|^#*[[:space:]]*net/ipv4/ip_forward=.*|net/ipv4/ip_forward=1|' /etc/ufw/sysctl.conf || fail "Could not change /etc/ufw/sysctl.conf"
grep -q '^net/ipv4/ip_forward=1' /etc/ufw/sysctl.conf || echo 'net/ipv4/ip_forward=1' >> /etc/ufw/sysctl.conf`
)

type FirewallForwardBody struct {
	Protocol  string `json:"protocol" enum:"tcp,udp"`
	Port      string `json:"port" maxLength:"16" doc:"The port it arrives on, or a range like 5000-5010" example:"8080"`
	ToAddress string `json:"to_address,omitempty" maxLength:"15" doc:"Empty = this server" example:"10.0.0.5"`
	ToPort    string `json:"to_port,omitempty" maxLength:"5" doc:"Empty = the same port" example:"80"`
	From      string `json:"from,omitempty" maxLength:"18" doc:"ufw: only from this IPv4 address or network"`
	Interface string `json:"interface,omitempty" maxLength:"15" doc:"ufw: only arriving on this interface"`
	Comment   string `json:"comment,omitempty" maxLength:"120" doc:"ufw"`
	Zone      string `json:"zone,omitempty" maxLength:"32" doc:"firewalld; empty = the default zone"`
}

type FirewallForwardPath struct {
	ID      string `path:"id" format:"uuid"`
	Forward string `path:"forward" maxLength:"32"`
}

type FirewallForwardDeleteBody struct {
	IDs []string `json:"ids" minItems:"1" maxItems:"200" doc:"Forward ids from the overview"`
}

func registerFirewallForwards(api huma.API, h *serverHandler, base string) {
	tags := []string{"Firewall"}

	huma.Register(api, huma.Operation{
		OperationID: "add-firewall-forward",
		Method:      http.MethodPost,
		Path:        base + "/forwards",
		Summary:     "Forward a port",
		Description: "Sends what arrives on a port to another port here or to another machine. IPv4 only. " +
			"On ufw it also adds the rule that lets that traffic through. The port Morcheh uses for SSH can't be forwarded.",
		Tags: tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body FirewallForwardBody
	}) (*FirewallOutput, error) {
		return h.firewallChange(ctx, in.ID, func(st *fwState) (fwPlan, error) {
			f, err := st.forwardFrom(in.Body, "")
			if err != nil {
				return fwPlan{}, err
			}
			return st.planForwards(append(slices.Clone(st.o.Forwards), f), describeForward(f))
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-firewall-forward",
		Method:      http.MethodPut,
		Path:        base + "/forwards/{forward}",
		Summary:     "Change a port forward",
		Description: "404 when it's gone, for instance changed by hand meanwhile.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		FirewallForwardPath
		Body FirewallForwardBody
	}) (*FirewallOutput, error) {
		return h.firewallChange(ctx, in.ID, func(st *fwState) (fwPlan, error) {
			i := slices.IndexFunc(st.o.Forwards, func(f firewall.Forward) bool { return f.ID == in.Forward })
			if i < 0 {
				return fwPlan{}, huma.Error404NotFound("That forward is gone. It may have been changed on the server meanwhile.")
			}
			f, err := st.forwardFrom(in.Body, in.Forward)
			if err != nil {
				return fwPlan{}, err
			}
			next := slices.Clone(st.o.Forwards)
			next[i] = f
			return st.planForwards(next, "Change forward: "+describeForward(f))
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-firewall-forwards",
		Method:      http.MethodPost,
		Path:        base + "/forwards/delete",
		Summary:     "Delete port forwards",
		Description: "All of them or none. The rules Morcheh added beside them go too.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body FirewallForwardDeleteBody
	}) (*FirewallOutput, error) {
		return h.firewallChange(ctx, in.ID, func(st *fwState) (fwPlan, error) {
			var last firewall.Forward
			next := slices.Clone(st.o.Forwards)
			for _, id := range in.Body.IDs {
				i := slices.IndexFunc(next, func(f firewall.Forward) bool { return f.ID == id })
				if i < 0 {
					return fwPlan{}, huma.Error404NotFound("A forward is gone. It may have been changed on the server meanwhile.")
				}
				last = next[i]
				next = slices.Delete(next, i, i+1)
			}
			summary := fmt.Sprintf("Delete %d forwards", len(in.Body.IDs))
			if len(in.Body.IDs) == 1 {
				summary = "Delete forward: " + describeForward(last)
			}
			return st.planForwards(next, summary)
		})
	})
}

func describeForward(f firewall.Forward) string {
	to := "port " + f.Target()
	if f.Remote() {
		to = f.ToAddress + ":" + f.Target()
	}
	s := "Forward " + strings.ReplaceAll(f.Port, ":", "-") + "/" + f.Protocol + " to " + to
	if f.From != "" {
		s += " from " + f.From
	}
	return s
}

// forwardFrom checks a forward against this firewall. replacing is the one it
// takes the place of, if any.
func (st *fwState) forwardFrom(b FirewallForwardBody, replacing string) (firewall.Forward, error) {
	f := firewall.Forward{
		Protocol: b.Protocol, Port: b.Port, ToAddress: b.ToAddress, ToPort: b.ToPort,
		From: b.From, Interface: b.Interface, Comment: b.Comment,
	}
	if st.o.Backend == "firewalld" {
		if f.From != "" {
			return f, fieldError("body.from", "firewalld forwards can't be limited to a source", f.From)
		}
		if f.Interface != "" {
			return f, fieldError("body.interface", "With firewalld, interfaces belong to a zone: choose the zone instead", f.Interface)
		}
		f.Comment = ""
		f.Zone = st.zone(b.Zone)
		if !slices.ContainsFunc(st.o.Zones, func(z firewall.Zone) bool { return z.Name == f.Zone }) {
			return f, fieldError("body.zone", "This server has no zone called "+f.Zone, f.Zone)
		}
	}
	if err := f.Normalize(); err != nil {
		return f, fieldProblem(err)
	}
	if st.o.SSHPort != 0 && f.Covers(st.o.SSHPort) && (f.Protocol == "tcp") {
		return f, fieldError("body.port", "This is the port Morcheh reaches the server on: forwarding it would cut Morcheh off", f.Port)
	}
	for _, o := range st.o.Forwards {
		if o.ID != replacing && f.Overlaps(o) {
			return f, fieldError("body.port", "Another forward already uses this port", f.Port)
		}
	}
	return f, nil
}

// planForwards makes the forwards exactly these.
func (st *fwState) planForwards(next []firewall.Forward, summary string) (fwPlan, error) {
	if st.o.Backend == "firewalld" {
		return st.planFirewalldForwards(next, summary), nil
	}
	if !strings.Contains(st.before, "*filter") {
		return fwPlan{}, huma.Error422UnprocessableEntity("/etc/ufw/before.rules is missing or unreadable, so forwards can't be added")
	}
	before, err := firewall.UFWSetForwards(st.before, next)
	if err != nil {
		return fwPlan{}, huma.Error422UnprocessableEntity(err.Error())
	}

	// The rules beside the forwards: what's no longer needed goes, but only
	// Morcheh's own, and what's missing is added unless a rule does it already.
	var wanted []firewall.Input
	for _, f := range next {
		in := f.FilterInput(fwForwardComment)
		if err := in.Normalize(); err != nil {
			return fwPlan{}, fieldProblem(err)
		}
		wanted = append(wanted, in)
	}
	var cmds []string
	kept := make([]firewall.FilterRule, 0, len(st.o.Rules))
	for _, r := range st.o.Rules {
		needed := slices.ContainsFunc(wanted, func(in firewall.Input) bool { return in.Present([]firewall.FilterRule{r}) })
		if r.Comment == fwForwardComment && !needed {
			cmds = append(cmds, st.deleteCommand(r))
			continue
		}
		kept = append(kept, r)
	}
	for _, in := range wanted {
		if !in.Present(kept) {
			cmds = append(cmds, prefixed(firewall.UFWAdd(in, 0))...)
			kept = append(kept, firewall.FilterRule{
				Action: in.Action, Direction: in.Direction, Protocol: in.Protocol, Port: in.Port, From: in.From, To: in.To, Interface: in.Interface,
			})
		}
	}

	cmds = append(cmds, `printf '%s' `+base64.StdEncoding.EncodeToString([]byte(before))+
		` | base64 -d > /etc/ufw/before.rules || fail "Could not write /etc/ufw/before.rules"`)
	if slices.ContainsFunc(next, firewall.Forward.Remote) {
		cmds = append(cmds, fwRouting)
		if st.o.Active {
			cmds = append(cmds, "r sysctl -w net.ipv4.ip_forward=1")
		}
	}
	if st.o.Active {
		cmds = append(cmds, "r ufw reload", fwNatTidy)
	} else {
		cmds = append(cmds, fwNatFlush)
	}
	return fwPlan{cmds: cmds, summary: summary}, nil
}

func (st *fwState) planFirewalldForwards(next []firewall.Forward, summary string) fwPlan {
	var cmds []string
	has := func(list []firewall.Forward, id string) bool {
		return slices.ContainsFunc(list, func(f firewall.Forward) bool { return f.ID == id })
	}
	for _, f := range st.o.Forwards {
		if !has(next, f.ID) {
			cmds = append(cmds, "r $fc --zone="+f.Zone+" "+firewall.FirewalldForwardRemove(f))
		}
	}
	masquerade := map[string]bool{}
	for _, z := range st.o.Zones {
		masquerade[z.Name] = z.Masquerade
	}
	for _, f := range next {
		if has(st.o.Forwards, f.ID) {
			continue
		}
		cmds = append(cmds, "r $fc --zone="+f.Zone+" "+firewall.FirewalldForwardAdd(f))
		if f.Remote() && !masquerade[f.Zone] {
			cmds = append(cmds, "r $fc --zone="+f.Zone+" --add-masquerade")
			masquerade[f.Zone] = true
		}
	}
	return fwPlan{cmds: st.finish(cmds), summary: summary}
}

// forwardLabel is how a forward reads in the history.
func forwardLabel(f firewall.Forward) string {
	s := describeForward(f)
	if f.Interface != "" {
		s += " on " + f.Interface
	}
	if f.Zone != "" {
		s += " (zone " + f.Zone + ")"
	}
	if f.Comment != "" {
		s += " · " + f.Comment
	}
	return s
}
