package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/firewall"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/sshprobe"
	"github.com/morcheh/backend/internal/terminal"
)

// ---- Types ----

type FirewallDefaults struct {
	Incoming string `json:"incoming" doc:"What happens to incoming traffic no rule matches: allow, deny or reject"`
	Outgoing string `json:"outgoing" doc:"ufw only"`
	Routed   string `json:"routed" doc:"ufw only"`
	Logging  string `json:"logging" doc:"ufw: off, low, medium, high, full. firewalld: off, all, unicast, broadcast, multicast"`
}

type FirewallCapabilities struct {
	Manage    bool `json:"manage" doc:"Morcheh can change this firewall"`
	Comments  bool `json:"comments"`
	Outbound  bool `json:"outbound"`
	Routed    bool `json:"routed"`
	Interface bool `json:"interface"`
	Zones     bool `json:"zones"`
	Reorder   bool `json:"reorder" doc:"The order of the rules matters and can be changed"`
	Forwards  bool `json:"forwards" doc:"Morcheh can change port forwards"`
	// firewalld's forward ports have no source or interface of their own.
	ForwardFrom bool `json:"forward_from" doc:"A forward can be limited to a source and an interface"`
}

type FirewallPending struct {
	Summary     string `json:"summary" doc:"What was changed"`
	SecondsLeft int    `json:"seconds_left" doc:"When it runs out the server undoes the change by itself"`
}

type FirewallOverview struct {
	Access         string                `json:"access" enum:"root,sudo,user" doc:"Reading and changing the firewall needs root or sudo"`
	PackageManager string                `json:"package_manager" example:"apt-get"`
	Init           string                `json:"init" enum:"systemd,openrc,none"`
	Backend        string                `json:"backend" enum:"ufw,firewalld,nftables,iptables,none" doc:"The firewall in charge of this server"`
	Recommended    string                `json:"recommended" doc:"What installing a firewall would install here; empty when it can't be done" example:"ufw"`
	Active         bool                  `json:"active" doc:"Filtering traffic right now"`
	StartsAtBoot   bool                  `json:"starts_at_boot"`
	Version        string                `json:"version" example:"0.36.2"`
	Defaults       FirewallDefaults      `json:"defaults"`
	Zones          []firewall.Zone       `json:"zones" doc:"firewalld: every zone"`
	DefaultZone    string                `json:"default_zone,omitempty" doc:"firewalld"`
	Rules          []firewall.FilterRule `json:"rules" doc:"In the order the firewall applies them"`
	Forwards       []firewall.Forward    `json:"forwards" doc:"Ports sent on to another port or machine"`
	SSHPort        int                   `json:"ssh_port" doc:"The port Morcheh reaches this server on; 0 if unknown" example:"22"`
	MorchehIP      string                `json:"morcheh_ip" doc:"The address this server sees Morcheh's connection from"`
	YourIP         string                `json:"your_ip" doc:"The address of the person asking, when it isn't a loopback one"`
	Capabilities   FirewallCapabilities  `json:"capabilities"`
	Pending        *FirewallPending      `json:"pending,omitempty" doc:"A change waiting to be kept; while it's here, other changes are refused"`
	Warnings       []string              `json:"warnings"`
}

type FirewallOutput struct{ Body FirewallOverview }

type FirewallRuleBody struct {
	Action       string `json:"action" enum:"allow,block,reject,limit" doc:"limit = allow, but slow down an address opening many connections"`
	Direction    string `json:"direction,omitempty" enum:"in,out,routed" default:"in"`
	Protocol     string `json:"protocol,omitempty" enum:"any,tcp,udp" default:"any"`
	Port         string `json:"port,omitempty" maxLength:"128" doc:"A port, a range (5000-5010) or a list (80,443); empty = every port" example:"443"`
	Service      string `json:"service,omitempty" maxLength:"64" doc:"Instead of a port: a firewalld service or ufw application" example:"http"`
	From         string `json:"from,omitempty" maxLength:"64" doc:"An address or network; empty = anywhere" example:"203.0.113.0/24"`
	To           string `json:"to,omitempty" maxLength:"64" doc:"An address or network on this server; empty = any"`
	Interface    string `json:"interface,omitempty" maxLength:"15"`
	OutInterface string `json:"out_interface,omitempty" maxLength:"15"`
	Comment      string `json:"comment,omitempty" maxLength:"120" doc:"ufw only"`
	Zone         string `json:"zone,omitempty" maxLength:"32" doc:"firewalld; empty = the default zone"`
	Log          bool   `json:"log,omitempty"`
	Top          bool   `json:"top,omitempty" doc:"Put it before the other rules. Block and reject rules always go first"`
}

func (b FirewallRuleBody) input() firewall.Input {
	return firewall.Input{
		Action: b.Action, Direction: b.Direction, Protocol: b.Protocol, Port: b.Port, Service: b.Service,
		From: b.From, To: b.To, Interface: b.Interface, OutInterface: b.OutInterface, Comment: b.Comment,
		Zone: b.Zone, Log: b.Log, Top: b.Top,
	}
}

type FirewallEnableBody struct {
	Allow []FirewallRuleBody `json:"allow,omitempty" maxItems:"64" doc:"Rules to add before turning it on. SSH is always allowed"`
}

type FirewallDeleteBody struct {
	IDs []string `json:"ids" minItems:"1" maxItems:"500" doc:"Rule ids from the overview"`
}

type FirewallSettingsBody struct {
	Incoming    string `json:"incoming,omitempty" enum:"allow,deny,reject"`
	Outgoing    string `json:"outgoing,omitempty" enum:"allow,deny,reject" doc:"ufw only"`
	Routed      string `json:"routed,omitempty" enum:"allow,deny,reject" doc:"ufw only"`
	Logging     string `json:"logging,omitempty" enum:"off,low,medium,high,full,all,unicast,broadcast,multicast"`
	DefaultZone string `json:"default_zone,omitempty" maxLength:"32" doc:"firewalld"`
}

type FirewallMoveBody struct {
	Before string `json:"before,omitempty" maxLength:"32" doc:"Put it right above this rule; empty = after all the others"`
}

type FirewallRulePath struct {
	ID   string `path:"id" format:"uuid"`
	Rule string `path:"rule" maxLength:"32"`
}

type FirewallRawSection struct {
	Title   string `json:"title" example:"ufw status verbose"`
	Content string `json:"content"`
}

type FirewallRaw struct {
	Sections []FirewallRawSection `json:"sections"`
}

type FirewallLogInput struct {
	ID    string `path:"id" format:"uuid"`
	Lines int    `query:"lines" minimum:"100" maximum:"20000" default:"5000" doc:"How many log lines to look through"`
}

type FirewallLog struct {
	Source string              `json:"source" doc:"Where it was read from; empty when no log was readable" example:"/var/log/ufw.log"`
	Events []firewall.LogEvent `json:"events" doc:"Refused packets, newest first"`
}

// ---- Routes ----

const (
	fwMarker      = "@@morcheh-fw@@"
	fwDir         = "/run/morcheh-firewall"
	fwInstallKind = "firewall-install"
	// How long a change stands before the server undoes it by itself. A fresh
	// connection has to fail inside it (sshprobe gives up after 15 s).
	fwWindow      = 90
	fwCmdTimeout  = 60 * time.Second
	fwExitPrepare = 74 // nothing was changed
	fwExitRefused = 75 // the tool said no; already rolled back
	fwSSHComment  = "SSH access (added by Morcheh)"
)

func registerFirewall(api huma.API, h *serverHandler) {
	tags := []string{"Firewall"}
	base := "/servers/{id}/firewall"

	huma.Register(api, huma.Operation{
		OperationID: "get-firewall",
		Method:      http.MethodGet,
		Path:        base,
		Summary:     "The firewall on a server",
		Description: "Which firewall is in charge (ufw, firewalld, or plain nftables/iptables, which are read-only here), whether it's on, " +
			"its defaults and rules in one shape, the SSH port Morcheh depends on, and any change waiting to be kept.",
		Tags: tags,
	}, func(ctx context.Context, in *ServerIDPath) (*FirewallOutput, error) {
		out := &FirewallOutput{}
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.rootShell(ctx, in.ID, c)
			if err != nil {
				return err
			}
			st, err := collectFirewall(ctx, sh)
			if err == nil {
				out.Body = st.o
			}
			return err
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "firewall-raw",
		Method:      http.MethodGet,
		Path:        base + "/raw",
		Summary:     "The firewall's own view of its rules",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body FirewallRaw }, error) {
		return h.firewallRaw(ctx, in.ID)
	})

	huma.Register(api, huma.Operation{
		OperationID: "firewall-log",
		Method:      http.MethodGet,
		Path:        base + "/log",
		Summary:     "Traffic the firewall refused",
		Description: "From ufw's log, the journal or the kernel log. Empty until logging is on.",
		Tags:        tags,
	}, func(ctx context.Context, in *FirewallLogInput) (*struct{ Body FirewallLog }, error) {
		return h.firewallLog(ctx, in.ID, in.Lines)
	})

	huma.Register(api, huma.Operation{
		OperationID: "install-firewall",
		Method:      http.MethodPost,
		Path:        base + "/install",
		Summary:     "Install a firewall",
		Description: "ufw, or firewalld on the RHEL and SUSE families. It stays off until it's turned on. " +
			"Runs as a background job (kind `firewall-install`). 409 when one is already under way.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *ServerIDPath) (*JobOutput, error) {
		return h.submitFirewallInstall(ctx, in.ID)
	})
	h.jobs.Handle(fwInstallKind, h.runF2bPackage("Installing", fwInstallScript))

	huma.Register(api, huma.Operation{
		OperationID: "enable-firewall",
		Method:      http.MethodPost,
		Path:        base + "/enable",
		Summary:     "Turn the firewall on",
		Description: "Allows the SSH port Morcheh uses first, whatever the body says. Answers with `pending`: keep it within the time shown or the server undoes it.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body FirewallEnableBody
	}) (*FirewallOutput, error) {
		return h.firewallChange(ctx, in.ID, func(st *fwState) (fwPlan, error) { return st.planEnable(in.Body) })
	})

	huma.Register(api, huma.Operation{
		OperationID: "disable-firewall",
		Method:      http.MethodPost,
		Path:        base + "/disable",
		Summary:     "Turn the firewall off",
		Description: "Rules are kept, but nothing is filtered until it's turned on again.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*FirewallOutput, error) {
		return h.firewallChange(ctx, in.ID, (*fwState).planDisable)
	})

	huma.Register(api, huma.Operation{
		OperationID: "add-firewall-rule",
		Method:      http.MethodPost,
		Path:        base + "/rules",
		Summary:     "Add a rule",
		Description: "A rule that could cut the SSH connection off answers with `pending`, like turning it on.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body FirewallRuleBody
	}) (*FirewallOutput, error) {
		return h.firewallChange(ctx, in.ID, func(st *fwState) (fwPlan, error) { return st.planAdd(in.Body.input()) })
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-firewall-rule",
		Method:      http.MethodPut,
		Path:        base + "/rules/{rule}",
		Summary:     "Change a rule",
		Description: "Replaces it in the same place. 404 when it's gone, for instance changed by hand meanwhile.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		FirewallRulePath
		Body FirewallRuleBody
	}) (*FirewallOutput, error) {
		return h.firewallChange(ctx, in.ID, func(st *fwState) (fwPlan, error) { return st.planUpdate(in.Rule, in.Body.input()) })
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-firewall-rules",
		Method:      http.MethodPost,
		Path:        base + "/rules/delete",
		Summary:     "Delete rules",
		Description: "All of them or none. Removing what lets SSH in answers with `pending`.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body FirewallDeleteBody
	}) (*FirewallOutput, error) {
		return h.firewallChange(ctx, in.ID, func(st *fwState) (fwPlan, error) { return st.planDelete(in.Body.IDs) })
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-firewall-settings",
		Method:      http.MethodPut,
		Path:        base + "/settings",
		Summary:     "Change default policies, logging or the default zone",
		Description: "Only what's sent changes. Tightening a default answers with `pending`.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body FirewallSettingsBody
	}) (*FirewallOutput, error) {
		return h.firewallChange(ctx, in.ID, func(st *fwState) (fwPlan, error) { return st.planSettings(in.Body) })
	})

	huma.Register(api, huma.Operation{
		OperationID: "reset-firewall",
		Method:      http.MethodPost,
		Path:        base + "/reset",
		Summary:     "Remove every rule",
		Description: "Keeps SSH allowed and the firewall on or off as it was.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*FirewallOutput, error) {
		return h.firewallChange(ctx, in.ID, (*fwState).planReset)
	})

	huma.Register(api, huma.Operation{
		OperationID: "keep-firewall-change",
		Method:      http.MethodPost,
		Path:        base + "/pending/keep",
		Summary:     "Keep the change that's waiting",
		Description: "409 when nothing is waiting, for instance because time ran out and it was undone.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*FirewallOutput, error) {
		return h.firewallPending(ctx, in.ID, fwKeepScript)
	})

	huma.Register(api, huma.Operation{
		OperationID: "undo-firewall-change",
		Method:      http.MethodPost,
		Path:        base + "/pending/undo",
		Summary:     "Undo the change that's waiting",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*FirewallOutput, error) {
		return h.firewallPending(ctx, in.ID, fwUndoScript)
	})

	huma.Register(api, huma.Operation{
		OperationID: "move-firewall-rule",
		Method:      http.MethodPost,
		Path:        base + "/rules/{rule}/move",
		Summary:     "Change a rule's place",
		Description: "ufw only: the first rule that matches decides. A move that could cut the SSH connection off answers with `pending`.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		FirewallRulePath
		Body FirewallMoveBody
	}) (*FirewallOutput, error) {
		return h.firewallChange(ctx, in.ID, func(st *fwState) (fwPlan, error) { return st.planMove(in.Rule, in.Body.Before) })
	})

	registerFirewallForwards(api, h, base)
	registerFirewallHistory(api, h, base)
	registerFirewallApply(api, h)
}

// ---- Reading ----

const fwEnv = `export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"
`

var fwCollectScript = fwEnv + `m=` + fwMarker + `
echo "$m host"
` + hostScript + `
echo "$m tools"
for t in ufw firewall-cmd firewall-offline-cmd nft iptables; do command -v "$t" >/dev/null 2>&1 && echo "$t"; done
if [ -f ` + fwDir + `/armed ]; then
  echo "$m pending"
  echo "$(( $(cat ` + fwDir + `/expires) - $(date +%s) ))"
  cat ` + fwDir + `/summary; echo
fi
if command -v ufw >/dev/null 2>&1; then
  echo "$m ufw-status"; ufw status 2>&1 | head -n 1
  echo "$m ufw-version"; ufw version 2>&1 | head -n 1
  echo "$m ufw-conf"; cat /etc/ufw/ufw.conf 2>/dev/null
  echo "$m ufw-default"; cat /etc/default/ufw 2>/dev/null
  echo "$m ufw-rules"; cat /etc/ufw/user.rules 2>/dev/null
  echo "$m ufw-rules6"; cat /etc/ufw/user6.rules 2>/dev/null
  echo "$m ufw-before"; cat /etc/ufw/before.rules 2>/dev/null; echo
fi
if command -v firewall-cmd >/dev/null 2>&1; then
  if [ "$(timeout 8 firewall-cmd --state 2>/dev/null)" = running ]; then
    echo "$m fwd-running"; fc="timeout 15 firewall-cmd --permanent"; rt="timeout 15 firewall-cmd"
  else
    fc="timeout 15 firewall-offline-cmd"; rt=:
  fi
  echo "$m fwd-version"; ${fc% --permanent} --version 2>&1 | head -n 1
  echo "$m fwd-default"; $fc --get-default-zone 2>&1
  echo "$m fwd-log"; $fc --get-log-denied 2>&1
  echo "$m fwd-zones"; $fc --list-all-zones 2>&1
  echo "$m fwd-active"; $rt --get-active-zones 2>/dev/null
  echo "$m fwd-services"; grep -H '<port ' /usr/lib/firewalld/services/*.xml /etc/firewalld/services/*.xml 2>/dev/null
  echo "$m fwd-boot"
` + enabledScript("firewalld") + `fi
if command -v nft >/dev/null 2>&1; then echo "$m nft"; nft list ruleset 2>/dev/null; fi
if command -v iptables >/dev/null 2>&1; then echo "$m iptables"; iptables -S 2>/dev/null; fi
exit 0
`

// fwState is a server's firewall as read just now, which every change plans
// from: nothing a client sends is trusted to describe what's there.
type fwState struct {
	o      FirewallOverview
	init   string
	before string // ufw: /etc/ufw/before.rules
}

func splitFwSections(out string) map[string]string {
	sections := map[string]string{}
	for _, part := range strings.Split("\n"+out, "\n"+fwMarker+" ")[1:] {
		name, body, _ := strings.Cut(part, "\n")
		sections[strings.TrimSpace(name)] = body
	}
	return sections
}

func collectFirewall(ctx context.Context, sh *rootShell) (*fwState, error) {
	raw, err := sh.run(ctx, fwCollectScript)
	if err != nil {
		return nil, err
	}
	// sudo drops SSH_CONNECTION, so it's read outside of it.
	conn, err := run(ctx, sh.c, `echo "$SSH_CONNECTION"`)
	if err != nil {
		return nil, err
	}
	st := parseFirewall(splitFwSections(raw), sh.priv.access(), conn)
	if ip := clientOf(ctx).ip; ip != "" {
		if a, err := netip.ParseAddr(ip); err == nil && !a.IsLoopback() {
			st.o.YourIP = a.Unmap().String()
		}
	}
	return st, nil
}

func parseFirewall(s map[string]string, access, conn string) *fwState {
	host := parseHost(s["host"])
	st := &fwState{init: host.init}
	o := &st.o
	o.Access, o.PackageManager, o.Init = access, host.pm, host.init
	o.Rules, o.Zones, o.Warnings = []firewall.FilterRule{}, []firewall.Zone{}, []string{}
	o.Forwards = []firewall.Forward{}
	o.Recommended = fwPackage(host.pm)
	if f := strings.Fields(conn); len(f) == 4 {
		o.MorchehIP = f[0]
		o.SSHPort, _ = strconv.Atoi(f[3])
	}

	tools := strings.Fields(s["tools"])
	ufw, firewalld := slices.Contains(tools, "ufw"), slices.Contains(tools, "firewall-cmd")
	ufwActive := ufw && strings.Contains(s["ufw-status"], "Status: active")
	_, fwdActive := s["fwd-running"]

	var custom []firewall.FilterRule
	var customPolicy, customName string
	if rules, policy := firewall.ParseNft(s["nft"]); len(rules) > 0 {
		custom, customPolicy, customName = rules, policy, "nftables"
	} else if rules := firewall.ParseIptables(s["iptables"]); len(rules) > 0 {
		custom, customPolicy, customName = rules, firewall.IptablesPolicy(s["iptables"]), "iptables"
	}

	switch {
	case ufwActive:
		st.readUFW(s, true)
	case fwdActive:
		st.readFirewalld(s, true)
	case ufw:
		st.readUFW(s, false)
	case firewalld:
		st.readFirewalld(s, false)
	case firewall.CustomRules(custom):
		o.Backend, o.Active, o.StartsAtBoot, o.Rules = customName, true, true, custom
		o.Defaults.Incoming = customPolicy
	default:
		o.Backend = "none"
	}

	if o.Rules == nil {
		o.Rules = []firewall.FilterRule{}
	}
	if o.Zones == nil {
		o.Zones = []firewall.Zone{}
	}
	if ufwActive && fwdActive {
		o.Warnings = append(o.Warnings, "ufw and firewalld are both running. They overwrite each other's rules: turn one of them off.")
	}
	if o.Backend != customName && firewall.CustomRules(custom) {
		o.Warnings = append(o.Warnings, "This server also has "+customName+" rules Morcheh doesn't manage. They apply as well as the ones listed here.")
	}
	if access == "user" {
		o.Warnings = append(o.Warnings, "Reading and changing the firewall needs root: log in as root, or allow sudo for this user.")
	}
	if o.SSHPort != 0 {
		for i := range o.Rules {
			o.Rules[i].ProtectsSSH = o.Rules[i].Lets(o.SSHPort, o.MorchehIP)
		}
	}
	if p, ok := s["pending"]; ok {
		left, summary, _ := strings.Cut(p, "\n")
		n, _ := strconv.Atoi(strings.TrimSpace(left))
		o.Pending = &FirewallPending{Summary: strings.TrimSpace(summary), SecondsLeft: max(n, 0)}
	}
	return st
}

func (st *fwState) readUFW(s map[string]string, active bool) {
	o := &st.o
	o.Backend, o.Active = "ufw", active
	o.Rules = firewall.ParseUFW(s["ufw-rules"], s["ufw-rules6"])
	o.Defaults.Incoming, o.Defaults.Outgoing, o.Defaults.Routed = firewall.UFWDefaults(s["ufw-default"])
	o.StartsAtBoot, o.Defaults.Logging = firewall.UFWConf(s["ufw-conf"])
	o.Version = versionRe.FindString(s["ufw-version"])
	st.before = s["ufw-before"]
	o.Forwards = firewall.ParseUFWForwards(st.before)
	o.Capabilities = FirewallCapabilities{
		Manage: true, Comments: true, Outbound: true, Routed: true, Interface: true,
		Reorder: true, Forwards: true, ForwardFrom: true,
	}
}

func (st *fwState) readFirewalld(s map[string]string, active bool) {
	o := &st.o
	o.Backend, o.Active = "firewalld", active
	o.Zones = firewall.ParseZones(s["fwd-zones"])
	for _, name := range firewall.ParseActiveZones(s["fwd-active"]) {
		for i := range o.Zones {
			if o.Zones[i].Name == name {
				o.Zones[i].Active = true
			}
		}
	}
	o.DefaultZone = strings.TrimSpace(s["fwd-default"])
	for i := range o.Zones {
		if o.Zones[i].Name == o.DefaultZone {
			o.Zones[i].Default = true
			o.Defaults.Incoming = firewall.TargetPolicy(o.Zones[i].Target)
		}
	}
	o.Rules = firewall.FirewalldRules(o.Zones, firewall.ParseServicePorts(s["fwd-services"]))
	o.Defaults.Logging = strings.TrimSpace(s["fwd-log"])
	o.StartsAtBoot = strings.Contains(s["fwd-boot"], "enabled")
	o.Version = versionRe.FindString(s["fwd-version"])
	o.Forwards = firewall.FirewalldForwards(o.Zones)
	o.Capabilities = FirewallCapabilities{Manage: true, Zones: true, Forwards: true}
}

// fwPackage is the firewall to install: ufw where it's at home, firewalld on
// the families that ship it. (Debian's firewalld starts itself on install, so
// it's never the choice there.)
func fwPackage(pm string) string {
	switch pm {
	case "apt-get", "apk", "pacman":
		return "ufw"
	case "dnf", "yum", "zypper":
		return "firewalld"
	}
	return ""
}

func fwInstallScript(f hostFacts, _ f2bPackageParams) (string, error) {
	return packageScript(f.pm, "install", fwPackage(f.pm))
}

func (h *serverHandler) submitFirewallInstall(ctx context.Context, id string) (*JobOutput, error) {
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.fwRoot(ctx, id, c)
		if err != nil {
			return err
		}
		facts, err := sh.run(ctx, hostScript)
		if err != nil {
			return err
		}
		_, err = fwInstallScript(parseHost(facts), f2bPackageParams{})
		return err
	})
	if err != nil {
		return nil, toProblem(err)
	}
	refs := placeRefs(id)
	active := true
	list, err := h.jobs.List(ctx, sqlc.ListJobsParams{Ref: &refs[0], Active: &active, Lim: 200})
	if err != nil {
		return nil, internalError(err)
	}
	if slices.ContainsFunc(list, func(j sqlc.Job) bool { return j.Kind == fwInstallKind }) {
		return nil, huma.Error409Conflict("A firewall is already being installed on this server")
	}
	s, err := h.get(ctx, id)
	if err != nil {
		return nil, err
	}
	return submit(ctx, h.jobs, jobs.Spec{
		Kind: fwInstallKind, Title: "Install a firewall on " + s.Name, Params: f2bPackageParams{ServerID: id}, Refs: refs,
	})
}

func (h *serverHandler) fwRoot(ctx context.Context, id string, c *sshpool.Conn) (*rootShell, error) {
	sh, err := h.rootShell(ctx, id, c)
	if err != nil {
		return nil, err
	}
	if sh.priv == privUser {
		return nil, huma.Error403Forbidden("Changing the firewall needs root or sudo on this server")
	}
	return sh, nil
}

func (h *serverHandler) firewallRaw(ctx context.Context, id string) (*struct{ Body FirewallRaw }, error) {
	script := fwEnv + `m=` + fwMarker + `
show() { echo "$m $*"; "$@" 2>&1; }
command -v ufw >/dev/null 2>&1 && { show ufw status verbose; show ufw show added; show cat /etc/ufw/user.rules; }
if command -v firewall-cmd >/dev/null 2>&1; then
  if [ "$(timeout 8 firewall-cmd --state 2>/dev/null)" = running ]; then
    show timeout 15 firewall-cmd --list-all-zones
  else
    show timeout 15 firewall-offline-cmd --list-all-zones
  fi
fi
command -v nft >/dev/null 2>&1 && show nft list ruleset
command -v iptables >/dev/null 2>&1 && show iptables -S
exit 0
`
	out := &struct{ Body FirewallRaw }{}
	out.Body.Sections = []FirewallRawSection{}
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.fwRoot(ctx, id, c)
		if err != nil {
			return err
		}
		raw, err := sh.run(ctx, script)
		if err != nil {
			return err
		}
		for _, part := range strings.Split("\n"+raw, "\n"+fwMarker+" ")[1:] {
			title, body, _ := strings.Cut(part, "\n")
			out.Body.Sections = append(out.Body.Sections, FirewallRawSection{strings.TrimPrefix(title, "timeout 15 "), body})
		}
		return nil
	})
	return out, toProblem(err)
}

func (h *serverHandler) firewallLog(ctx context.Context, id string, lines int) (*struct{ Body FirewallLog }, error) {
	n := strconv.Itoa(lines)
	script := fwEnv + `m=` + fwMarker + `
if [ -s /var/log/ufw.log ]; then echo "$m /var/log/ufw.log"; tail -n ` + n + ` /var/log/ufw.log
elif command -v journalctl >/dev/null 2>&1 && journalctl -k -n 1 -q >/dev/null 2>&1; then
  echo "$m journal"; journalctl -k -n ` + n + ` -o short-iso --no-pager -q 2>/dev/null | grep 'SRC='
elif [ -r /var/log/kern.log ]; then echo "$m /var/log/kern.log"; tail -n ` + n + ` /var/log/kern.log | grep 'SRC='
elif [ -r /var/log/messages ]; then echo "$m /var/log/messages"; tail -n ` + n + ` /var/log/messages | grep 'SRC='
fi
exit 0
`
	out := &struct{ Body FirewallLog }{}
	out.Body.Events = []firewall.LogEvent{}
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.fwRoot(ctx, id, c)
		if err != nil {
			return err
		}
		raw, err := sh.run(ctx, script)
		if err != nil {
			return err
		}
		for name, body := range splitFwSections(raw) {
			out.Body.Source = name
			if events := firewall.ParseLog(body, time.Now()); events != nil {
				out.Body.Events = events
			}
		}
		return nil
	})
	return out, toProblem(err)
}

// ---- Planning a change ----

// fwPlan is what a change does. Commands run in order under the safety net
// of applyScript, each as a line of POSIX sh starting with `r`.
type fwPlan struct {
	cmds    []string
	risky   bool // could lock Morcheh out: it stands only until someone keeps it
	summary string
}

func (st *fwState) needsManaged() error {
	if st.o.Backend == "none" {
		return huma.Error422UnprocessableEntity("There's no firewall here yet: install one from this server's Firewall page")
	}
	if !st.o.Capabilities.Manage {
		return huma.Error422UnprocessableEntity("Morcheh only shows " + st.o.Backend + " rules. It can change ufw and firewalld.")
	}
	return nil
}

func (st *fwState) zone(name string) string {
	if name == "" {
		return st.o.DefaultZone
	}
	return name
}

func fieldProblem(err error) error {
	var fe *firewall.FieldError
	if errors.As(err, &fe) {
		return fieldError("body."+fe.Field, fe.Message, nil)
	}
	return err
}

// addCommands builds the lines that add a normalized rule.
func (st *fwState) addCommands(in firewall.Input, position int) ([]string, error) {
	if st.o.Backend == "ufw" {
		return prefixed(firewall.UFWAdd(in, position)), nil
	}
	in.Zone = st.zone(in.Zone)
	if !slices.ContainsFunc(st.o.Zones, func(z firewall.Zone) bool { return z.Name == in.Zone }) {
		return nil, fieldError("body.zone", "This server has no zone called "+in.Zone, in.Zone)
	}
	args, err := firewall.FirewalldAdd(in)
	if err != nil {
		return nil, fieldProblem(err)
	}
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = "r $fc --zone=" + in.Zone + " " + a
	}
	return out, nil
}

func prefixed(cmds []string) []string {
	out := make([]string, len(cmds))
	for i, c := range cmds {
		out[i] = "r " + c
	}
	return out
}

func (st *fwState) deleteCommand(r firewall.FilterRule) string {
	if st.o.Backend == "ufw" {
		return "r " + firewall.UFWDelete(r)
	}
	return "r $fc --zone=" + r.Zone + " " + firewall.FirewalldDelete(r)
}

// finish appends what makes firewalld's permanent changes take effect.
func (st *fwState) finish(cmds []string) []string {
	if len(cmds) == 0 || !st.o.Active {
		return cmds
	}
	if st.o.Backend == "firewalld" {
		return append(cmds, "r firewall-cmd --reload")
	}
	return append(cmds, fwNatTidy) // a change of default reloads before.rules
}

// keepsSSH says whether SSH stays reachable without the removed rules, by a
// rule that's left or by the default.
func (st *fwState) keepsSSH(removed []string) bool {
	if st.o.SSHPort == 0 || st.o.Defaults.Incoming == "allow" {
		return true
	}
	return slices.ContainsFunc(st.o.Rules, func(r firewall.FilterRule) bool {
		return r.ProtectsSSH && !slices.Contains(removed, r.ID)
	})
}

func (st *fwState) stops(in firewall.Input) bool {
	return st.o.SSHPort != 0 && in.Stops(st.o.SSHPort, st.o.MorchehIP, st.o.YourIP)
}

func describeRule(in firewall.Input) string {
	verb := map[string]string{"allow": "Allow", "block": "Block", "reject": "Reject", "limit": "Rate limit"}[in.Action]
	what := "all traffic"
	switch {
	case in.Service != "":
		what = in.Service
	case in.Port != "":
		what = "port " + in.Port
		if in.Protocol != "any" {
			what += "/" + in.Protocol
		}
	}
	if in.From != "" {
		what += " from " + in.From
	}
	return verb + " " + what
}

func (st *fwState) planAdd(in firewall.Input) (fwPlan, error) {
	if err := in.Normalize(); err != nil {
		return fwPlan{}, fieldProblem(err)
	}
	cmds, err := st.addCommands(in, 0)
	if err != nil {
		return fwPlan{}, err
	}
	return fwPlan{cmds: st.finish(cmds), risky: st.o.Active && st.stops(in), summary: describeRule(in)}, nil
}

func (st *fwState) planUpdate(id string, in firewall.Input) (fwPlan, error) {
	if err := in.Normalize(); err != nil {
		return fwPlan{}, fieldProblem(err)
	}
	old, ok := firewall.Find(st.o.Rules, id)
	if !ok {
		return fwPlan{}, huma.Error404NotFound("That rule is gone. It may have been changed on the server meanwhile.")
	}
	if !old.Editable {
		return fwPlan{}, huma.Error422UnprocessableEntity("This rule uses options the form doesn't have. Delete it and add a new one, or edit it on the server.")
	}
	// insert N counts IPv4 rules, and is past the end when this was the last.
	position, v4 := old.Position(), 0
	for _, r := range st.o.Rules {
		if r.Position() > 0 && r.ID != old.ID {
			v4++
		}
	}
	if position > v4 {
		position = 0
	}
	add, err := st.addCommands(in, position)
	if err != nil {
		return fwPlan{}, err
	}
	cmds := append([]string{st.deleteCommand(old)}, add...)
	lets := firewall.FilterRule{Direction: in.Direction, Action: in.Action, Protocol: in.Protocol, Port: in.Port, From: in.From}
	stillLets := st.o.SSHPort != 0 && in.Service == "" && lets.Lets(st.o.SSHPort, st.o.MorchehIP)
	risky := st.o.Active && (st.stops(in) || old.ProtectsSSH && !stillLets && !st.keepsSSH([]string{id}))
	return fwPlan{cmds: st.finish(cmds), risky: risky, summary: "Change rule: " + describeRule(in)}, nil
}

func (st *fwState) planDelete(ids []string) (fwPlan, error) {
	var cmds []string
	var last firewall.FilterRule
	for _, id := range ids {
		r, ok := firewall.Find(st.o.Rules, id)
		if !ok {
			return fwPlan{}, huma.Error404NotFound("A rule is gone. It may have been changed on the server meanwhile.")
		}
		if !r.Deletable {
			return fwPlan{}, huma.Error422UnprocessableEntity("This rule can't be removed here")
		}
		cmds, last = append(cmds, st.deleteCommand(r)), r
	}
	summary := fmt.Sprintf("Delete %d rules", len(ids))
	if len(ids) == 1 {
		summary = "Delete rule: " + describeExisting(last)
	}
	return fwPlan{cmds: st.finish(cmds), risky: st.o.Active && !st.keepsSSH(ids), summary: summary}, nil
}

// planMove puts a rule right above another one, or after all of them. ufw
// counts the rules' places on the IPv4 list, and rules only on the IPv6 list
// keep their own order after those.
func (st *fwState) planMove(id, before string) (fwPlan, error) {
	if !st.o.Capabilities.Reorder {
		return fwPlan{}, huma.Error422UnprocessableEntity("With " + st.o.Backend + ", the order of the rules doesn't matter")
	}
	r, ok := firewall.Find(st.o.Rules, id)
	if !ok {
		return fwPlan{}, huma.Error404NotFound("That rule is gone. It may have been changed on the server meanwhile.")
	}
	if r.Position() == 0 {
		return fwPlan{}, huma.Error422UnprocessableEntity("This rule only applies to IPv6, so it can't be moved among the others")
	}
	var order []firewall.FilterRule
	for _, o := range st.o.Rules {
		if o.Position() > 0 {
			order = append(order, o)
		}
	}
	last := len(order)
	to := last
	if before != "" {
		t, ok := firewall.Find(st.o.Rules, before)
		if !ok {
			return fwPlan{}, huma.Error404NotFound("That rule is gone. It may have been changed on the server meanwhile.")
		}
		if t.Position() > 0 {
			to = t.Position()
			if r.Position() < to {
				to--
			}
		}
	}
	if to == r.Position() {
		return fwPlan{}, nil
	}
	moved := slices.Delete(slices.Clone(order), r.Position()-1, r.Position())
	moved = slices.Insert(moved, to-1, r)

	position := to
	if to == last {
		position = 0 // past the end once it's been taken out: ufw adds it last
	}
	risky := false
	if st.o.Active && st.o.SSHPort != 0 {
		for _, ip := range []string{st.o.MorchehIP, st.o.YourIP} {
			if ip != "" && firstMatchLets(order, st.o.SSHPort, ip) && !firstMatchLets(moved, st.o.SSHPort, ip) {
				risky = true
			}
		}
	}
	return fwPlan{
		cmds:    st.finish(prefixed(firewall.UFWMove(r, position))),
		risky:   risky,
		summary: fmt.Sprintf("Move rule to place %d: %s", to, describeExisting(r)),
	}, nil
}

// firstMatchLets says whether the first rule to decide about an SSH connection
// lets it in. No rule deciding counts as letting it in: only a move's effect
// matters here, and the default stays what it was.
func firstMatchLets(rules []firewall.FilterRule, port int, ip string) bool {
	for _, r := range rules {
		if r.Lets(port, ip) {
			return true
		}
		if r.StopsSSH(port, ip) {
			return false
		}
	}
	return true
}

func describeExisting(r firewall.FilterRule) string {
	if r.Action == "other" {
		return r.Raw
	}
	return describeRule(firewall.Input{Action: r.Action, Protocol: r.Protocol, Port: r.Port, Service: r.Service, From: r.From})
}

// sshCommands builds the lines that open the port Morcheh uses. A firewall
// turned on without it would end the session that turned it on.
func (st *fwState) sshCommands() []string {
	port := st.o.SSHPort
	if port == 0 {
		port = 22
	}
	if st.o.Backend == "ufw" {
		return prefixed(firewall.UFWAdd(firewall.Input{
			Action: "allow", Direction: "in", Protocol: "tcp", Port: strconv.Itoa(port), Comment: fwSSHComment,
		}, 0))
	}
	if port == 22 {
		return []string{"r $fc --zone=" + st.o.DefaultZone + " --add-service=ssh"}
	}
	return []string{"r $fc --zone=" + st.o.DefaultZone + " --add-port=" + strconv.Itoa(port) + "/tcp"}
}

func (st *fwState) serviceCommands(actions ...string) ([]string, error) {
	var out []string
	for _, a := range actions {
		s, err := serviceScript(st.init, "firewalld", a, nil)
		if err != nil {
			return nil, err
		}
		out = append(out, "r "+s)
	}
	return out, nil
}

func (st *fwState) planEnable(b FirewallEnableBody) (fwPlan, error) {
	if st.o.Active {
		return fwPlan{}, huma.Error409Conflict("The firewall is already on")
	}
	var cmds []string
	if !st.keepsSSH(nil) || st.o.Defaults.Incoming == "allow" {
		cmds = append(cmds, st.sshCommands()...)
	}
	for i, body := range b.Allow {
		in := body.input()
		if err := in.Normalize(); err != nil {
			var fe *firewall.FieldError
			errors.As(err, &fe)
			return fwPlan{}, fieldError(fmt.Sprintf("body.allow[%d].%s", i, fe.Field), fe.Message, nil)
		}
		add, err := st.addCommands(in, 0)
		if err != nil {
			return fwPlan{}, err
		}
		cmds = append(cmds, add...)
	}
	if st.o.Backend == "ufw" {
		cmds = append(cmds, "r ufw --force enable", fwNatTidy)
	} else {
		start, err := st.serviceCommands("enable", "start")
		if err != nil {
			return fwPlan{}, err
		}
		cmds = append(cmds, start...)
	}
	return fwPlan{cmds: cmds, risky: true, summary: "Turn the firewall on"}, nil
}

func (st *fwState) planDisable() (fwPlan, error) {
	if !st.o.Active {
		return fwPlan{}, huma.Error409Conflict("The firewall is already off")
	}
	if st.o.Backend == "ufw" {
		// Turning ufw off leaves the nat table alone, so forwards would go on.
		return fwPlan{cmds: []string{"r ufw --force disable", fwNatFlush}, summary: "Turn the firewall off"}, nil
	}
	stop, err := st.serviceCommands("disable", "stop")
	if err != nil {
		return fwPlan{}, err
	}
	return fwPlan{cmds: stop, summary: "Turn the firewall off"}, nil
}

func (st *fwState) planReset() (fwPlan, error) {
	if st.o.Backend == "ufw" {
		// A reset replaces before.rules, but what it loaded stays in the kernel.
		cmds := append([]string{"r ufw --force reset", fwNatDrop}, st.sshCommands()...)
		if st.o.Active {
			cmds = append(cmds, "r ufw --force enable")
		}
		return fwPlan{cmds: cmds, risky: st.o.Active, summary: "Remove every rule"}, nil
	}
	var cmds []string
	for _, r := range st.o.Rules {
		cmds = append(cmds, st.deleteCommand(r))
	}
	for _, f := range st.o.Forwards {
		cmds = append(cmds, "r $fc --zone="+f.Zone+" "+firewall.FirewalldForwardRemove(f))
	}
	cmds = append(cmds, st.sshCommands()...)
	return fwPlan{cmds: st.finish(cmds), risky: st.o.Active, summary: "Remove every rule"}, nil
}

func (st *fwState) planSettings(b FirewallSettingsBody) (fwPlan, error) {
	var cmds, said []string
	risky := false
	tightens := func(now, next string) bool { return now == "allow" && next != "" && next != "allow" }
	switch st.o.Backend {
	case "ufw":
		if b.DefaultZone != "" {
			return fwPlan{}, fieldError("body.default_zone", "ufw has no zones", b.DefaultZone)
		}
		for _, p := range []struct{ name, next, now, word string }{
			{"incoming", b.Incoming, st.o.Defaults.Incoming, "incoming"},
			{"outgoing", b.Outgoing, st.o.Defaults.Outgoing, "outgoing"},
			{"routed", b.Routed, st.o.Defaults.Routed, "routed"},
		} {
			if p.next == "" || p.next == p.now {
				continue
			}
			cmds = append(cmds, "r ufw default "+p.next+" "+p.word)
			said = append(said, p.name+" "+p.next)
			if p.name != "routed" && tightens(p.now, p.next) || p.name == "incoming" && p.next != "allow" {
				risky = true
			}
		}
		if l := b.Logging; l != "" && l != st.o.Defaults.Logging {
			if !slices.Contains([]string{"off", "low", "medium", "high", "full"}, l) {
				return fwPlan{}, fieldError("body.logging", "ufw logging is off, low, medium, high or full", l)
			}
			cmds = append(cmds, "r ufw logging "+l)
			said = append(said, "logging "+l)
		}
	case "firewalld":
		if b.Outgoing != "" || b.Routed != "" {
			return fwPlan{}, huma.Error422UnprocessableEntity("firewalld zones only have an incoming default")
		}
		zone := st.o.DefaultZone
		if p := b.Incoming; p != "" && p != st.o.Defaults.Incoming {
			cmds = append(cmds, "r $fc --zone="+zone+" --set-target="+firewall.FirewalldTarget(p))
			said = append(said, "incoming "+p)
			risky = risky || p != "allow"
		}
		if l := b.Logging; l != "" && l != st.o.Defaults.Logging {
			if !slices.Contains([]string{"off", "all", "unicast", "broadcast", "multicast"}, l) {
				return fwPlan{}, fieldError("body.logging", "firewalld logging is off, all, unicast, broadcast or multicast", l)
			}
			// It isn't a zone setting, so it has no --permanent form.
			cmds = append(cmds, "r "+st.toolNow()+" --set-log-denied="+l)
			said = append(said, "logging "+l)
		}
		if z := b.DefaultZone; z != "" && z != st.o.DefaultZone {
			if !firewall.ValidZone(z) || !slices.ContainsFunc(st.o.Zones, func(v firewall.Zone) bool { return v.Name == z }) {
				return fwPlan{}, fieldError("body.default_zone", "This server has no zone called "+z, z)
			}
			cmds = append(cmds, "r "+st.toolNow()+" --set-default-zone="+z)
			said = append(said, "default zone "+z)
			risky = true
		}
	}
	return fwPlan{cmds: st.finish(cmds), risky: st.o.Active && risky, summary: "Settings: " + strings.Join(said, ", ")}, nil
}

// toolNow is firewalld's tool for settings that have no --permanent form.
func (st *fwState) toolNow() string {
	if st.o.Active {
		return "firewall-cmd"
	}
	return "firewall-offline-cmd"
}

// ---- Applying a change ----

// Every change runs on the server under a net that needs nothing from
// Morcheh: the configuration is saved, a detached timer will put it back, and
// only a later step disarms the timer. So a change that cuts the connection
// undoes itself even though nobody can reach the server to do it. The timer
// checks a token, so an older timer can't fire on a newer change.

// firewallChange reads the firewall fresh, plans from that, and applies.
// Changes to one server wait for each other.
func (h *serverHandler) firewallChange(ctx context.Context, id string, plan func(*fwState) (fwPlan, error)) (*FirewallOutput, error) {
	return h.fwChange(ctx, id, fwOptions{actor: actorOf(ctx)}, plan)
}

// fwOptions says who a change is for and whether they're there to answer.
type fwOptions struct {
	actor fwActor
	// Nobody can press Keep it during a background job, so a change that
	// would need that is refused.
	unattended bool
}

func (h *serverHandler) fwChange(ctx context.Context, id string, opts fwOptions, plan func(*fwState) (fwPlan, error)) (*FirewallOutput, error) {
	lock := fwLock(id)
	lock.Lock()
	defer lock.Unlock()

	var st *fwState
	var p fwPlan
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.fwRoot(ctx, id, c)
		if err != nil {
			return err
		}
		if st, err = collectFirewall(ctx, sh); err != nil {
			return err
		}
		if st.o.Pending != nil {
			return huma.Error409Conflict("Keep or undo the last change first: " + st.o.Pending.Summary)
		}
		if err := st.needsManaged(); err != nil {
			return err
		}
		p, err = plan(st)
		return err
	})
	if err != nil {
		return nil, toProblem(err)
	}
	if len(p.cmds) == 0 {
		return &FirewallOutput{st.o}, nil
	}
	if opts.unattended && p.risky {
		return nil, toProblem(huma.Error422UnprocessableEntity("This could cut SSH off, which needs someone to confirm it: make this change on the server's own page"))
	}

	// Stopping half way is the one thing that can't be allowed once it starts.
	ctx = context.WithoutCancel(ctx)
	c, err := h.conn(ctx, id)
	if err != nil {
		return nil, toProblem(err)
	}
	out := &FirewallOutput{}
	err = hold(c, func() error {
		sh, err := h.fwRoot(ctx, id, c)
		if err != nil {
			return err
		}
		snapshot := fwSnapshot(ctx, sh, st)
		if err := h.fwApply(ctx, id, sh, st, p); err != nil {
			return err
		}
		fresh, err := collectFirewall(ctx, sh)
		if err == nil {
			out.Body = fresh.o
		} else {
			fresh = nil
		}
		h.recordFirewallChange(ctx, id, opts.actor, st, fresh, p, snapshot)
		return err
	})
	return out, toProblem(err)
}

var fwLocks sync.Map

func fwLock(id string) *sync.Mutex {
	l, _ := fwLocks.LoadOrStore(id, &sync.Mutex{})
	return l.(*sync.Mutex)
}

func (h *serverHandler) fwApply(ctx context.Context, id string, sh *rootShell, st *fwState, p fwPlan) error {
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return internalError(err)
	}
	tok := hex.EncodeToString(token)
	script, err := st.applyScript(tok, p)
	if err != nil {
		return err
	}
	lost := huma.Error502BadGateway(fmt.Sprintf("The connection dropped during the change. If it cut Morcheh off, the server undoes it within %d seconds.", fwWindow))
	res, err := sh.exec(ctx, script, fwCmdTimeout, 64<<10)
	switch {
	case err != nil, res.timedOut:
		return lost
	case res.code == fwExitPrepare, res.code == fwExitRefused:
		return huma.Error422UnprocessableEntity(toolMessage(res.output))
	case res.code != 0:
		return huma.Error422UnprocessableEntity(fmt.Sprintf("The change failed (exit %d): %s", res.code, toolMessage(res.output)))
	}

	if !h.reachable(ctx, id) {
		if _, err := sh.run(ctx, fwUndoScript); err != nil {
			return lost
		}
		return huma.Error422UnprocessableEntity("That change would have cut Morcheh off from this server, so it was undone.")
	}
	if !p.risky {
		if _, err := sh.run(ctx, fwKeepScript); err != nil {
			return err
		}
	}
	return nil
}

// reachable tries a brand-new connection: the ones already open survive most
// rules through connection tracking, so they prove nothing.
func (h *serverHandler) reachable(ctx context.Context, id string) bool {
	s, err := h.get(ctx, id)
	if err != nil {
		return true
	}
	t, err := h.target(s)
	if err != nil {
		return true
	}
	client, _, err := sshprobe.Dial(ctx, t)
	if err != nil {
		var de *sshprobe.DialError
		return !errors.As(err, &de) || de.Status != sshprobe.StatusUnreachable
	}
	client.Close()
	return true
}

func toolMessage(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if i := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "ERROR: ") }); i >= 0 {
		// ufw-init's reason comes on the lines after this one.
		if strings.Contains(lines[i], "ufw-init") {
			return truncate(strings.Join(lines[i:], " "), 400)
		}
		lines = lines[i : i+1]
	}
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	msg := strings.TrimSpace(strings.TrimPrefix(strings.Join(lines, " "), "ERROR: "))
	if msg == "" {
		return "The firewall refused the change"
	}
	return truncate(msg, 400)
}

// applyScript saves the configuration, arms the timer and runs the plan.
// A command that fails rolls back at once.
func (st *fwState) applyScript(token string, p fwPlan) (string, error) {
	paths, rollback, err := st.rollback()
	if err != nil {
		return "", err
	}
	rollback += `[ -f "$d/ip_forward" ] && cat "$d/ip_forward" > /proc/sys/net/ipv4/ip_forward 2>/dev/null
rm -f "$d/summary" "$d/expires" "$d/snap.tar" "$d/rollback.sh" "$d/ip_forward" "$d/restore.tgz"`
	timer := "sleep " + strconv.Itoa(fwWindow) + `; [ "$(cat ` + fwDir + `/armed 2>/dev/null)" = ` + token + ` ] && sh ` + fwDir + `/rollback.sh`
	var b strings.Builder
	b.WriteString(fwEnv)
	b.WriteString(`d=` + fwDir + `
umask 077
mkdir -p "$d" || { echo "Could not write to $d"; exit ` + strconv.Itoa(fwExitPrepare) + `; }
rm -f "$d/armed"
tar -C / -cf "$d/snap.tar" ` + paths + ` 2>/dev/null || { echo "Could not save the current firewall configuration, so nothing was changed"; exit ` + strconv.Itoa(fwExitPrepare) + `; }
cat > "$d/rollback.sh" <<'MORCHEH_ROLLBACK'
` + rollback + `
MORCHEH_ROLLBACK
cat /proc/sys/net/ipv4/ip_forward > "$d/ip_forward" 2>/dev/null
printf '%s' ` + terminal.ShellQuote(p.summary) + ` > "$d/summary"
echo $(( $(date +%s) + ` + strconv.Itoa(fwWindow) + ` )) > "$d/expires"
printf '%s' ` + token + ` > "$d/armed"
setsid nohup sh -c ` + terminal.ShellQuote(timer) + ` >/dev/null 2>&1 </dev/null &
r() {
  o=$("$@" 2>&1); c=$?
  case "$o" in
    *"Rule deleted"*) ;;
    *"non-existent rule"*) c=1 ;;
  esac
  if [ "$c" -ne 0 ]; then
    printf '%s\n' "$o"
    sh "$d/rollback.sh" >/dev/null 2>&1
    exit ` + strconv.Itoa(fwExitRefused) + `
  fi
}
fail() {
  printf '%s\n' "$1"
  sh "$d/rollback.sh" >/dev/null 2>&1
  exit ` + strconv.Itoa(fwExitRefused) + `
}
`)
	if st.o.Backend == "firewalld" {
		if st.o.Active {
			b.WriteString("fc=\"firewall-cmd --permanent\"\n")
		} else {
			b.WriteString("fc=firewall-offline-cmd\n")
		}
	}
	for _, c := range p.cmds {
		b.WriteString(c + "\n")
	}
	return b.String(), nil
}

// rollback returns the paths to save and the script that restores them and
// brings the firewall back to how it was. The folder is swapped rather than
// unpacked over, so files a change added go too.
func (st *fwState) rollback() (paths, script string, err error) {
	restore := func(dir string) string {
		return `mv ` + dir + ` ` + dir + `.morcheh-undo 2>/dev/null
if tar -C / -xf "$d/snap.tar"; then rm -rf ` + dir + `.morcheh-undo; else mv ` + dir + `.morcheh-undo ` + dir + `; fi
`
	}
	head := fwEnv + `d=` + fwDir + `
rm -f "$d/armed"
`
	if st.o.Backend == "ufw" {
		script = head + restore("/etc/ufw") + fwNatFlush + "\nufw --force disable >/dev/null 2>&1\n"
		if st.o.Active {
			script += "ufw --force enable >/dev/null 2>&1\n" + fwNatTidy + "\n"
		}
		return "etc/ufw etc/default/ufw", script, nil
	}
	script = head + restore("/etc/firewalld")
	boot := "disable"
	if st.o.StartsAtBoot {
		boot = "enable"
	}
	bootLine, err := serviceScript(st.init, "firewalld", boot, nil)
	if err != nil {
		return "", "", err
	}
	if st.o.Active {
		start, err := serviceScript(st.init, "firewalld", "start", nil)
		if err != nil {
			return "", "", err
		}
		script += start + " >/dev/null 2>&1\nfirewall-cmd --reload >/dev/null 2>&1\n"
	} else {
		stop, err := serviceScript(st.init, "firewalld", "stop", nil)
		if err != nil {
			return "", "", err
		}
		script += stop + " >/dev/null 2>&1\n"
	}
	return "etc/firewalld", script + bootLine + " >/dev/null 2>&1\n", nil
}

const (
	fwKeepScript = `d=` + fwDir + `
[ -f "$d/armed" ] || exit 3
rm -f "$d/armed" "$d/summary" "$d/expires" "$d/snap.tar" "$d/rollback.sh" "$d/ip_forward" "$d/restore.tgz"
`
	fwUndoScript = `d=` + fwDir + `
[ -f "$d/armed" ] || exit 3
sh "$d/rollback.sh"
`
)

// firewallPending keeps or undoes what's waiting, whichever script it's given.
func (h *serverHandler) firewallPending(ctx context.Context, id, script string) (*FirewallOutput, error) {
	lock := fwLock(id)
	lock.Lock()
	defer lock.Unlock()

	out := &FirewallOutput{}
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.fwRoot(ctx, id, c)
		if err != nil {
			return err
		}
		res, err := sh.exec(ctx, script, fwCmdTimeout, 4<<10)
		if err != nil {
			return err
		}
		if res.code == 3 {
			h.settleFirewallChanges(ctx, id, fwUndone)
			return huma.Error409Conflict("Nothing is waiting: time ran out and the server undid the change")
		}
		if script == fwKeepScript {
			h.settleFirewallChanges(ctx, id, fwApplied)
		} else {
			h.settleFirewallChanges(ctx, id, fwUndone)
		}
		st, err := collectFirewall(ctx, sh)
		if err == nil {
			out.Body = st.o
		}
		return err
	})
	return out, toProblem(err)
}
