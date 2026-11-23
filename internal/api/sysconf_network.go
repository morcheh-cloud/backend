package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morche/backend/internal/sshpool"
	"github.com/morche/backend/internal/sysconf"
	"github.com/morche/backend/internal/terminal"
)

// ---- Types ----

type ServerIface struct {
	Name          string               `json:"name" example:"eth0"`
	Kind          string               `json:"kind" doc:"ethernet, wifi, bond, bridge, vlan or virtual"`
	MAC           string               `json:"mac"`
	State         string               `json:"state" enum:"up,down,unknown"`
	MTU           int                  `json:"mtu"`
	Addresses     []string             `json:"addresses" doc:"What it has right now, with prefixes"`
	Gateway       string               `json:"gateway" doc:"The default route through it right now"`
	CarriesMorche bool                 `json:"carries_morche" doc:"Morche reaches the server through this interface"`
	Virtual       bool                 `json:"virtual" doc:"Made by Docker, a bridge for VMs or similar: shown, not edited"`
	Config        *sysconf.IfaceConfig `json:"config" doc:"How it is set up; null = no config for it (it can't be edited)"`
	File          string               `json:"file" doc:"The netplan file, or the NetworkManager connection file"`
	Connection    string               `json:"connection" doc:"NetworkManager connection name"`
}

type IfaceRoute struct {
	To  string `json:"to"`
	Via string `json:"via"`
	Dev string `json:"dev"`
}

type NetworkOverview struct {
	Revision   string         `json:"revision"`
	Backend    string         `json:"backend" enum:"netplan,networkmanager,ifupdown,networkd,unknown"`
	Renderer   string         `json:"renderer" doc:"netplan's renderer (networkd or NetworkManager)"`
	Editable   bool           `json:"editable"`
	Note       string         `json:"note"`
	Interfaces []ServerIface  `json:"interfaces"`
	Routes     []IfaceRoute   `json:"routes"`
	CloudInit  bool           `json:"cloud_init" doc:"cloud-init writes the netplan config at boot (saving will ask to stop that)"`
	Pending    *ConfigPending `json:"pending" doc:"A change waiting for Keep it"`
	Writable   bool           `json:"writable"`
	MorcheAt   string         `json:"morche_at" doc:"The address Morche connects to"`
}

type NetworkBody struct {
	Revision             string              `json:"revision"`
	Iface                sysconf.IfaceConfig `json:"iface"`
	ConfirmAddressChange bool                `json:"confirm_address_change,omitempty" required:"false" doc:"Go ahead although Morche's address may change"`
	DisableCloudInit     bool                `json:"disable_cloud_init,omitempty" required:"false" doc:"Stop cloud-init writing the network config at boot (needed when it wrote the file)"`
}

type NetworkInput struct {
	ID   string `path:"id" format:"uuid"`
	Body NetworkBody
}

type NetworkPreviewFile struct {
	Path   string `json:"path"`
	Before string `json:"before"`
	After  string `json:"after"`
}

type NetworkPreview struct {
	Files    []NetworkPreviewFile `json:"files"`
	Commands []string             `json:"commands"`
	Warnings []string             `json:"warnings"`
	Problem  string               `json:"problem" doc:"Why it would be refused; empty when it can go"`
	Needs    string               `json:"needs" enum:",confirm_address_change,disable_cloud_init" doc:"What the body must also say for it to go"`
}

// ---- Reading ----

var virtualPrefixes = []string{"docker", "br-", "veth", "virbr", "vnet", "cni", "flannel", "cali", "tun", "tap", "wg", "tailscale", "zt", "lxc", "lxd", "podman", "kube", "vxlan", "genev", "dummy"}

func virtualIface(name string) bool {
	return slices.ContainsFunc(virtualPrefixes, func(p string) bool { return strings.HasPrefix(name, p) })
}

type ipAddr struct {
	Name      string `json:"ifname"`
	MTU       int    `json:"mtu"`
	OperState string `json:"operstate"`
	LinkType  string `json:"link_type"`
	Address   string `json:"address"`
	Info      []struct {
		Family string `json:"family"`
		Local  string `json:"local"`
		Prefix int    `json:"prefixlen"`
		Scope  string `json:"scope"`
	} `json:"addr_info"`
}

type ipRoute struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
}

// readInterfaces reads `ip -j addr` and `ip -j route` (lo left out).
func readInterfaces(addrJSON, routeJSON, morcheHost string) ([]ServerIface, []IfaceRoute, error) {
	var addrs []ipAddr
	if err := json.Unmarshal([]byte(addrJSON), &addrs); err != nil {
		return nil, nil, fmt.Errorf("ip addr: %w", err)
	}
	var rs []ipRoute
	if strings.TrimSpace(routeJSON) != "" {
		if err := json.Unmarshal([]byte(routeJSON), &rs); err != nil {
			return nil, nil, fmt.Errorf("ip route: %w", err)
		}
	}
	morche, _ := netip.ParseAddr(morcheHost)
	routes := make([]IfaceRoute, 0, len(rs))
	for _, r := range rs {
		routes = append(routes, IfaceRoute{To: r.Dst, Via: r.Gateway, Dev: r.Dev})
	}
	ifs := []ServerIface{}
	for _, a := range addrs {
		if a.LinkType == "loopback" || a.Name == "lo" {
			continue
		}
		n := ServerIface{Name: a.Name, MAC: a.Address, MTU: a.MTU, Addresses: []string{}, Virtual: virtualIface(a.Name), Kind: "ethernet"}
		switch strings.ToUpper(a.OperState) {
		case "UP":
			n.State = "up"
		case "DOWN", "LOWERLAYERDOWN":
			n.State = "down"
		default:
			n.State = "unknown"
		}
		if n.Virtual {
			n.Kind = "virtual"
		}
		for _, i := range a.Info {
			n.Addresses = append(n.Addresses, fmt.Sprintf("%s/%d", i.Local, i.Prefix))
			if ip, err := netip.ParseAddr(i.Local); err == nil && morche.IsValid() && ip == morche {
				n.CarriesMorche = true
			}
		}
		for _, r := range rs {
			if r.Dev == a.Name && r.Dst == "default" && r.Gateway != "" && n.Gateway == "" {
				n.Gateway = r.Gateway
			}
		}
		ifs = append(ifs, n)
	}
	return ifs, routes, nil
}

var nmUUID = regexp.MustCompile(`^[0-9a-f-]{36}$`)

var ifaceName = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,15}$`)

func checkIfaceConfig(c sysconf.IfaceConfig) error {
	if !ifaceName.MatchString(c.Name) {
		return fieldError("body.iface.name", "Not an interface name", c.Name)
	}
	for i, a := range c.Addresses {
		if !sysconf.ValidCIDR(a) {
			return fieldError(fmt.Sprintf("body.iface.addresses[%d]", i), "Give the address with its prefix, like 192.168.1.10/24", a)
		}
	}
	if c.Gateway4 != "" && (!sysconf.ValidIP(c.Gateway4) || isV6Addr(c.Gateway4)) {
		return fieldError("body.iface.gateway4", "Not an IPv4 address", c.Gateway4)
	}
	if c.Gateway6 != "" && (!sysconf.ValidIP(c.Gateway6) || !isV6Addr(c.Gateway6)) {
		return fieldError("body.iface.gateway6", "Not an IPv6 address", c.Gateway6)
	}
	for i, d := range c.DNS {
		if !sysconf.ValidIP(d) {
			return fieldError(fmt.Sprintf("body.iface.dns[%d]", i), "Not an IP address", d)
		}
	}
	for i, d := range c.Search {
		if !sysconf.ValidHostname(d) {
			return fieldError(fmt.Sprintf("body.iface.search[%d]", i), "Not a domain", d)
		}
	}
	if c.MTU != 0 && (c.MTU < 576 || c.MTU > 9216) {
		return fieldError("body.iface.mtu", "Use 576 to 9216, or leave it empty for the default", c.MTU)
	}
	if len(c.Addresses) > 32 || len(c.DNS) > 8 || len(c.Search) > 6 {
		return huma.Error422UnprocessableEntity("Too many addresses, DNS servers or search domains")
	}
	return nil
}

func isV6Addr(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is6() && !a.Is4In6()
}

// morcheAddressCheck says whether cfg keeps the address Morche uses on the
// interface it comes in through.
func morcheAddressCheck(host string, iface ServerIface, cfg sysconf.IfaceConfig) (warnings []string, refuse bool) {
	if !iface.CarriesMorche {
		return nil, false
	}
	for _, a := range cfg.Addresses {
		if p, err := netip.ParsePrefix(a); err == nil && p.Addr().String() == host {
			return nil, false
		}
	}
	if cfg.DHCP4 || cfg.DHCP6 {
		return []string{"Morche reaches this server at " + host + " through " + iface.Name + ". With DHCP the address may change: if it does, the change undoes itself after 90 seconds, or change the server's address in Morche."}, false
	}
	return nil, true
}

type netState struct {
	o        NetworkOverview
	netplan  map[string]string // path → text
	where    map[string]string // iface → netplan file
	conns    []nmConnFile
	cloudOff bool
}

type nmConnFile struct {
	conn sysconf.NmConn
	file string
}

const netScript = `printf '\036A\n'; ip -j addr 2>/dev/null
printf '\036R\n'; ip -j route 2>/dev/null
printf '\036N\n'; systemctl is-active NetworkManager 2>/dev/null
printf '\036I\n'; grep -s '^[[:space:]]*iface' /etc/network/interfaces /etc/network/interfaces.d/* | grep -v ' lo ' | head -1
printf '\036D\n'; ls /etc/systemd/network/*.network 2>/dev/null | head -1
printf '\036C\n'; grep -rls 'config:[[:space:]]*disabled' /etc/cloud/cloud.cfg.d/ 2>/dev/null | head -1
true`

func netSections(out string) map[string]string {
	m := map[string]string{}
	for _, chunk := range strings.Split(out, "\x1e")[1:] {
		k, v, _ := strings.Cut(chunk, "\n")
		m[k] = strings.TrimSpace(v)
	}
	return m
}

func (h *serverHandler) readNetwork(ctx context.Context, id string, sh *rootShell) (*netState, error) {
	srv, err := h.get(ctx, id)
	if err != nil {
		return nil, err
	}
	out, err := sh.run(ctx, netScript)
	if err != nil {
		return nil, err
	}
	sec := netSections(out)
	st := &netState{netplan: map[string]string{}, where: map[string]string{}}
	o := &st.o
	o.MorcheAt = srv.Host
	o.Writable = sh.priv != privUser
	if o.Interfaces, o.Routes, err = readInterfaces(sec["A"], sec["R"], srv.Host); err != nil {
		return nil, err
	}
	st.cloudOff = sec["C"] != ""

	files, err := listFiles(ctx, sh, "/etc/netplan/*.yaml", "/etc/netplan/*.yml")
	if err != nil {
		return nil, err
	}
	var read []configFile
	switch {
	case len(files) > 0:
		o.Backend = "netplan"
		read, o.Revision, err = readConfigFiles(ctx, sh, append(files, sysconf.CloudInitDisablePath)...)
		if err != nil {
			return nil, err
		}
		for _, f := range read {
			if f.Exists && f.Path != sysconf.CloudInitDisablePath {
				st.netplan[f.Path] = f.Text
			}
		}
		if len(st.netplan) < len(files) {
			o.Note = "Some netplan files couldn't be read: Morche needs root or sudo here."
			break
		}
		cfgs, where, err := sysconf.ReadNetplan(st.netplan)
		if err != nil {
			o.Note = "The netplan config doesn't parse, so it can only be read: " + err.Error()
			break
		}
		st.where = where
		o.Editable = o.Writable
		o.Renderer = "networkd"
		for p, t := range st.netplan {
			if strings.Contains(t, "NetworkManager") {
				o.Renderer = "NetworkManager"
			}
			if sysconf.CloudInitNetplan(p, t) && !st.cloudOff {
				o.CloudInit = true
			}
		}
		for i := range o.Interfaces {
			if c, ok := cfgs[o.Interfaces[i].Name]; ok && !o.Interfaces[i].Virtual {
				c = c.Filled()
				o.Interfaces[i].Config = &c
				o.Interfaces[i].Kind = c.Kind
				o.Interfaces[i].File = where[c.Name]
			}
		}
	case sec["N"] == "active":
		o.Backend = "networkmanager"
		list, err := sh.run(ctx, "nmcli -t -f UUID,DEVICE,FILENAME connection show 2>/dev/null")
		if err != nil {
			return nil, err
		}
		var uuids, paths []string
		fileOf := map[string]string{}
		for _, l := range strings.Split(strings.TrimSpace(list), "\n") {
			f := strings.Split(strings.ReplaceAll(l, `\:`, "\x00"), ":")
			if len(f) < 3 || f[1] == "" {
				continue
			}
			u := f[0]
			if !nmUUID.MatchString(u) {
				continue
			}
			uuids = append(uuids, u)
			fileOf[u] = strings.ReplaceAll(f[2], "\x00", ":")
			if fileOf[u] != "" {
				paths = append(paths, fileOf[u])
			}
		}
		var show strings.Builder
		for _, u := range uuids {
			s, err := sh.run(ctx, "nmcli -t -f "+sysconf.NmFields+" connection show "+u+" 2>/dev/null; echo")
			if err == nil {
				show.WriteString(s + "\n")
			}
		}
		read, o.Revision, err = readConfigFiles(ctx, sh, paths...)
		if err != nil {
			return nil, err
		}
		for _, c := range sysconf.ParseNmcli(show.String()) {
			st.conns = append(st.conns, nmConnFile{c, fileOf[c.UUID]})
		}
		o.Editable = o.Writable
		for i := range o.Interfaces {
			for _, c := range st.conns {
				if c.conn.Device == o.Interfaces[i].Name && !o.Interfaces[i].Virtual {
					cfg := c.conn.Config.Filled()
					o.Interfaces[i].Config = &cfg
					o.Interfaces[i].Kind = cfg.Kind
					o.Interfaces[i].File = c.file
					o.Interfaces[i].Connection = c.conn.Name
					break
				}
			}
		}
	case sec["I"] != "":
		o.Backend = "ifupdown"
		o.Note = "This server uses /etc/network/interfaces. Morche shows it here; edit that file in Files for now."
	case sec["D"] != "":
		o.Backend = "networkd"
		o.Note = "This server uses systemd-networkd files in /etc/systemd/network. Morche shows it here; edit those files in Files for now."
	default:
		o.Backend = "unknown"
		o.Note = "Morche couldn't tell how this server sets up its network."
	}
	if o.Revision == "" {
		o.Revision = revisionOf(read)
	}
	o.Pending = configPending(ctx, sh, "network")
	if o.Pending == nil {
		// Nothing waits on the server: a row still pending ran out of time
		// and the server undid it.
		h.settleConfig(ctx, id, "network", "undone")
	}
	return st, nil
}

// ---- Planning ----

func (st *netState) iface(name string) (ServerIface, bool) {
	for _, i := range st.o.Interfaces {
		if i.Name == name {
			return i, true
		}
	}
	return ServerIface{}, false
}

func netSummary(c sysconf.IfaceConfig) string {
	var parts []string
	if c.DHCP4 {
		parts = append(parts, "DHCP")
	}
	if len(c.Addresses) > 0 {
		parts = append(parts, strings.Join(c.Addresses, ", "))
	}
	if c.Gateway4 != "" {
		parts = append(parts, "gateway "+c.Gateway4)
	}
	if c.MTU > 0 {
		parts = append(parts, fmt.Sprintf("MTU %d", c.MTU))
	}
	if len(parts) == 0 {
		parts = append(parts, "no address")
	}
	return c.Name + ": " + strings.Join(parts, ", ")
}

func (st *netState) plan(b NetworkBody) (configPlan, NetworkPreview, error) {
	pv := NetworkPreview{Files: []NetworkPreviewFile{}, Commands: []string{}, Warnings: []string{}}
	o := st.o
	if !o.Editable {
		return configPlan{}, pv, huma.Error422UnprocessableEntity(strings.TrimSpace("The network can't be changed from Morche here. " + o.Note))
	}
	if o.Pending != nil {
		return configPlan{}, pv, huma.Error409Conflict("Keep or undo the last change first: " + o.Pending.Summary)
	}
	cfg := b.Iface
	iface, ok := st.iface(cfg.Name)
	if !ok || iface.Config == nil {
		return configPlan{}, pv, huma.Error422UnprocessableEntity(cfg.Name + " has no config Morche can change")
	}
	warn, refuse := morcheAddressCheck(o.MorcheAt, iface, cfg)
	pv.Warnings = append(pv.Warnings, warn...)
	if refuse {
		pv.Needs = "confirm_address_change"
		pv.Problem = "Morche reaches this server at " + o.MorcheAt + " on " + iface.Name + ", and this change takes that address away. Morche would lose the server; the change would undo itself after 90 seconds."
	}
	if iface.Gateway != "" && cfg.Gateway4 == "" && !cfg.DHCP4 && !isV6Addr(iface.Gateway) {
		pv.Warnings = append(pv.Warnings, "The default route goes through "+iface.Name+" now; without a gateway the server may not reach the internet.")
	}
	if !cfg.DHCP4 && !cfg.DHCP6 && len(cfg.Addresses) == 0 {
		pv.Warnings = append(pv.Warnings, iface.Name+" will have no address.")
	}
	p := configPlan{Area: "network", Summary: netSummary(cfg), Risky: true}

	switch o.Backend {
	case "netplan":
		file := st.where[cfg.Name]
		text := st.netplan[file]
		fresh, err := sysconf.EditNetplan(text, cfg)
		if err != nil {
			return p, pv, huma.Error422UnprocessableEntity(err.Error())
		}
		for f := range st.netplan {
			p.Read = append(p.Read, f)
		}
		slices.Sort(p.Read)
		p.Read = append(p.Read, sysconf.CloudInitDisablePath)
		p.Writes = []configWrite{{Path: file, Text: fresh, Mode: "0600"}}
		pv.Files = append(pv.Files, NetworkPreviewFile{Path: file, Before: text, After: fresh})
		if sysconf.CloudInitNetplan(file, text) && !st.cloudOff {
			if !b.DisableCloudInit {
				if pv.Needs == "" {
					pv.Needs = "disable_cloud_init"
					pv.Problem = "cloud-init wrote " + file + " and would write it again at the next boot, throwing this change away. Saving also tells cloud-init to stop doing that."
				}
			} else {
				p.Writes = append(p.Writes, configWrite{Path: sysconf.CloudInitDisablePath, Text: sysconf.CloudInitDisable})
				pv.Files = append(pv.Files, NetworkPreviewFile{Path: sysconf.CloudInitDisablePath, After: sysconf.CloudInitDisable})
			}
		}
		p.Check = "netplan generate"
		p.Apply = "netplan apply"
		p.Undo = "netplan apply"
		pv.Commands = []string{"netplan generate", "netplan apply"}
	case "networkmanager":
		var c nmConnFile
		for _, cc := range st.conns {
			if cc.conn.Device == cfg.Name {
				c = cc
			}
		}
		if c.file != "" {
			p.Read = []string{c.file}
		}
		args := sysconf.NmcliModify(c.conn, cfg)
		cmd := "nmcli connection modify " + c.conn.UUID + " " + quoteAll(args) + " && nmcli connection up " + c.conn.UUID
		p.Apply = cmd
		p.Undo = "nmcli connection reload && nmcli connection up " + c.conn.UUID
		pv.Commands = []string{"nmcli connection modify " + terminal.ShellQuote(c.conn.Name) + " " + quoteAll(args), "nmcli connection up " + terminal.ShellQuote(c.conn.Name)}
	}
	if b.ConfirmAddressChange && pv.Needs == "confirm_address_change" {
		pv.Needs, pv.Problem = "", ""
		// It may well lose Morche: then the timer puts it back.
	}
	if pv.Needs == "disable_cloud_init" && b.DisableCloudInit {
		pv.Needs, pv.Problem = "", ""
	}
	return p, pv, nil
}

func (h *serverHandler) networkOverview(ctx context.Context, id string) (*NetworkOverview, error) {
	var o NetworkOverview
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.rootShell(ctx, id, c)
		if err != nil {
			return err
		}
		st, err := h.readNetwork(ctx, id, sh)
		if err == nil {
			o = st.o
		}
		return err
	})
	return &o, toProblem(err)
}

func registerConfigNetwork(api huma.API, h *serverHandler) {
	tags := []string{"Server config"}

	huma.Register(api, huma.Operation{
		OperationID: "get-server-network",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/network",
		Summary:     "The server's network interfaces",
		Description: "Each interface with its live addresses and how it is set up (netplan or NetworkManager), the routes, and a change waiting for Keep it.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body NetworkOverview }, error) {
		o, err := h.networkOverview(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body NetworkOverview }{*o}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "preview-server-network",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/network/preview",
		Summary:     "What a change to an interface would write",
		Description: "The files before and after, the commands, warnings, and what the body must also confirm. Changes nothing.",
		Tags:        tags,
	}, func(ctx context.Context, in *NetworkInput) (*struct{ Body NetworkPreview }, error) {
		if err := checkIfaceConfig(in.Body.Iface); err != nil {
			return nil, err
		}
		var pv NetworkPreview
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.configRoot(ctx, in.ID, c)
			if err != nil {
				return err
			}
			st, err := h.readNetwork(ctx, in.ID, sh)
			if err != nil {
				return err
			}
			if in.Body.Revision != "" && st.o.Revision != in.Body.Revision {
				return huma.Error409Conflict("The network config changed on the server since you opened it. Load it again.")
			}
			_, pv, err = st.plan(in.Body)
			return err
		})
		if err != nil {
			return nil, toProblem(err)
		}
		return &struct{ Body NetworkPreview }{pv}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-server-network",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/network",
		Summary:     "Change one interface",
		Description: "Writes the config, checks it and applies it. The server undoes it by itself after 90 seconds unless it is kept " +
			"(POST /servers/{id}/config/network/keep), and at once when Morche can't reach the server after it.",
		Tags: tags,
	}, func(ctx context.Context, in *NetworkInput) (*struct{ Body NetworkOverview }, error) {
		if err := checkIfaceConfig(in.Body.Iface); err != nil {
			return nil, err
		}
		_, err := h.configChange(ctx, in.ID, in.Body.Revision, func(sh *rootShell) (configPlan, error) {
			st, err := h.readNetwork(ctx, in.ID, sh)
			if err != nil {
				return configPlan{}, err
			}
			p, pv, err := st.plan(in.Body)
			if err != nil {
				return p, err
			}
			if pv.Needs != "" {
				return p, huma.Error422UnprocessableEntity(pv.Problem)
			}
			return p, nil
		})
		if err != nil {
			return nil, err
		}
		o, err := h.networkOverview(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body NetworkOverview }{*o}, nil
	})

	configRestorers["network"] = func(ctx context.Context, h *serverHandler, id string, sh *rootShell, files []ConfigChangeFile) (configPlan, error) {
		st, err := h.readNetwork(ctx, id, sh)
		if err != nil {
			return configPlan{}, err
		}
		if st.o.Pending != nil {
			return configPlan{}, huma.Error409Conflict("Keep or undo the last change first")
		}
		p := configPlan{Risky: true}
		switch st.o.Backend {
		case "netplan":
			p.Check, p.Apply, p.Undo = "netplan generate", "netplan apply", "netplan apply"
		case "networkmanager":
			re := "nmcli connection reload && for u in $(nmcli -t -f UUID connection show --active); do nmcli connection up \"$u\" >/dev/null; done"
			p.Apply, p.Undo = re, re
		default:
			return p, huma.Error422UnprocessableEntity("The network can't be changed from Morche here")
		}
		return p, nil
	}
}
