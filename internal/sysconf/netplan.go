package sysconf

import (
	"bytes"
	"fmt"
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// IfaceConfig is how one interface gets its addresses, the same for netplan
// and NetworkManager.
type IfaceConfig struct {
	Name      string   `json:"name" example:"eth0"`
	Kind      string   `json:"kind,omitempty" required:"false" doc:"ethernet, wifi, bond, bridge or vlan (read only)"`
	DHCP4     bool     `json:"dhcp4"`
	DHCP6     bool     `json:"dhcp6"`
	Addresses []string `json:"addresses" doc:"Fixed addresses with their prefix, IPv4 and IPv6" example:"[\"192.168.1.10/24\"]"`
	Gateway4  string   `json:"gateway4" doc:"Default gateway for IPv4; empty = none"`
	Gateway6  string   `json:"gateway6" doc:"Default gateway for IPv6; empty = none"`
	DNS       []string `json:"dns" doc:"DNS servers set on this interface"`
	Search    []string `json:"search" doc:"Search domains set on this interface"`
	MTU       int      `json:"mtu" doc:"0 = the default"`
}

var netplanKinds = []struct{ section, kind string }{
	{"ethernets", "ethernet"}, {"wifis", "wifi"}, {"bonds", "bond"}, {"bridges", "bridge"}, {"vlans", "vlan"},
}

// CloudInitDisable is the cloud-init setting that stops it writing the
// network config again at boot.
const CloudInitDisable = "# Written by Morche: the network is set from Morche, so cloud-init must not write it again at boot.\nnetwork: {config: disabled}\n"

// CloudInitDisablePath is where CloudInitDisable goes.
const CloudInitDisablePath = "/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg"

// CloudInitNetplan says whether cloud-init wrote this netplan file.
func CloudInitNetplan(file, text string) bool {
	return path.Base(file) == "50-cloud-init.yaml" || strings.Contains(text, "generated from information provided by the datasource")
}

type npIface struct {
	DHCP4     any       `yaml:"dhcp4"`
	DHCP6     any       `yaml:"dhcp6"`
	Addresses []any     `yaml:"addresses"`
	Gateway4  string    `yaml:"gateway4"`
	Gateway6  string    `yaml:"gateway6"`
	Routes    []npRoute `yaml:"routes"`
	DNS       *struct {
		Addresses []string `yaml:"addresses"`
		Search    []string `yaml:"search"`
	} `yaml:"nameservers"`
	MTU *int `yaml:"mtu"`
}

type npRoute struct {
	To  string `yaml:"to"`
	Via string `yaml:"via"`
}

func yes(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return slices.Contains([]string{"true", "yes", "on", "y"}, strings.ToLower(x))
	}
	return false
}

func defaultRoute(to string) bool {
	return to == "default" || to == "0.0.0.0/0" || to == "::/0"
}

func isV6(s string) bool {
	a, err := netip.ParseAddr(strings.Split(s, "/")[0])
	return err == nil && a.Is6() && !a.Is4In6()
}

// ReadNetplan merges the files the way netplan does (by file name, later
// keys win) and says which file each interface was last set in.
func ReadNetplan(files map[string]string) (map[string]IfaceConfig, map[string]string, error) {
	names := make([]string, 0, len(files))
	for f := range files {
		names = append(names, f)
	}
	slices.SortFunc(names, func(a, b string) int { return strings.Compare(path.Base(a), path.Base(b)) })
	cfgs := map[string]IfaceConfig{}
	where := map[string]string{}
	for _, f := range names {
		var doc struct {
			Network map[string]yaml.Node `yaml:"network"`
		}
		if err := yaml.Unmarshal([]byte(files[f]), &doc); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", f, err)
		}
		for _, k := range netplanKinds {
			sec, ok := doc.Network[k.section]
			if !ok {
				continue
			}
			var ifaces map[string]yaml.Node
			if err := sec.Decode(&ifaces); err != nil {
				return nil, nil, fmt.Errorf("%s: %s: %w", f, k.section, err)
			}
			for name, n := range ifaces {
				var raw map[string]any
				_ = n.Decode(&raw)
				var ni npIface
				if err := n.Decode(&ni); err != nil {
					return nil, nil, fmt.Errorf("%s: %s: %w", f, name, err)
				}
				c, ok := cfgs[name]
				if !ok {
					c = IfaceConfig{Name: name, Kind: k.kind}
				}
				overlay(&c, ni, raw)
				cfgs[name] = c
				where[name] = f
			}
		}
	}
	return cfgs, where, nil
}

func overlay(c *IfaceConfig, ni npIface, raw map[string]any) {
	has := func(k string) bool { _, ok := raw[k]; return ok }
	if has("dhcp4") {
		c.DHCP4 = yes(ni.DHCP4)
	}
	if has("dhcp6") {
		c.DHCP6 = yes(ni.DHCP6)
	}
	if has("addresses") {
		c.Addresses = nil
		for _, a := range ni.Addresses {
			switch x := a.(type) {
			case string:
				c.Addresses = append(c.Addresses, x)
			case map[string]any:
				for k := range x {
					c.Addresses = append(c.Addresses, k)
				}
			}
		}
	}
	if ni.Gateway4 != "" {
		c.Gateway4 = ni.Gateway4
	}
	if ni.Gateway6 != "" {
		c.Gateway6 = ni.Gateway6
	}
	for _, r := range ni.Routes {
		if !defaultRoute(r.To) {
			continue
		}
		if isV6(r.Via) || r.To == "::/0" {
			c.Gateway6 = r.Via
		} else {
			c.Gateway4 = r.Via
		}
	}
	if ni.DNS != nil {
		c.DNS = ni.DNS.Addresses
		c.Search = ni.DNS.Search
	}
	if ni.MTU != nil {
		c.MTU = *ni.MTU
	}
}

// EditNetplan sets the keys Morche owns on one interface of a netplan file
// and leaves every other key (and the comments) as they were.
func EditNetplan(text string, cfg IfaceConfig) (string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return "", err
	}
	if len(doc.Content) == 0 {
		return "", fmt.Errorf("the file is empty")
	}
	network := mapGet(doc.Content[0], "network")
	var iface *yaml.Node
	for _, k := range netplanKinds {
		if sec := mapGet(network, k.section); sec != nil {
			if n := mapGet(sec, cfg.Name); n != nil {
				iface = n
				break
			}
		}
	}
	if iface == nil || iface.Kind != yaml.MappingNode {
		return "", fmt.Errorf("%s is not set in this file", cfg.Name)
	}

	setBool := func(key string, on bool) {
		if on {
			mapSet(iface, key, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
		} else {
			mapDel(iface, key)
		}
	}
	setBool("dhcp4", cfg.DHCP4)
	setBool("dhcp6", cfg.DHCP6)
	if len(cfg.Addresses) > 0 {
		mapSet(iface, "addresses", seq(cfg.Addresses, false))
	} else {
		mapDel(iface, "addresses")
	}
	mapDel(iface, "gateway4")
	mapDel(iface, "gateway6")

	routes := &yaml.Node{Kind: yaml.SequenceNode}
	if old := mapGet(iface, "routes"); old != nil && old.Kind == yaml.SequenceNode {
		for _, r := range old.Content {
			if to := mapGet(r, "to"); to != nil && defaultRoute(to.Value) {
				continue
			}
			routes.Content = append(routes.Content, r)
		}
	}
	var gws []*yaml.Node
	for _, gw := range []string{cfg.Gateway4, cfg.Gateway6} {
		if gw != "" {
			r := &yaml.Node{Kind: yaml.MappingNode}
			mapSet(r, "to", str("default"))
			mapSet(r, "via", str(gw))
			gws = append(gws, r)
		}
	}
	routes.Content = append(gws, routes.Content...)
	if len(routes.Content) > 0 {
		mapSet(iface, "routes", routes)
	} else {
		mapDel(iface, "routes")
	}

	if len(cfg.DNS) > 0 || len(cfg.Search) > 0 {
		ns := &yaml.Node{Kind: yaml.MappingNode}
		if len(cfg.DNS) > 0 {
			mapSet(ns, "addresses", seq(cfg.DNS, true))
		}
		if len(cfg.Search) > 0 {
			mapSet(ns, "search", seq(cfg.Search, true))
		}
		mapSet(iface, "nameservers", ns)
	} else {
		mapDel(iface, "nameservers")
	}
	if cfg.MTU > 0 {
		mapSet(iface, "mtu", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(cfg.MTU)})
	} else {
		mapDel(iface, "mtu")
	}

	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return "", err
	}
	_ = enc.Close()
	return b.String(), nil
}

func str(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s} }

func seq(vals []string, flow bool) *yaml.Node {
	n := &yaml.Node{Kind: yaml.SequenceNode}
	if flow {
		n.Style = yaml.FlowStyle
	}
	for _, v := range vals {
		n.Content = append(n.Content, str(v))
	}
	return n
}

func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func mapSet(m *yaml.Node, key string, v *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			v.HeadComment, v.LineComment = m.Content[i+1].HeadComment, m.Content[i+1].LineComment
			m.Content[i+1] = v
			return
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, v)
}

func mapDel(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = slices.Delete(m.Content, i, i+2)
			return
		}
	}
}
