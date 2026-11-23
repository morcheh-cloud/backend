package sysconf

import (
	"strconv"
	"strings"
)

// NmFields is what `nmcli -t -f <NmFields> connection show <uuid>` must ask
// for, in this order, for ParseNmcli.
const NmFields = "connection.uuid,connection.id,connection.interface-name,connection.type," +
	"ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns,ipv4.dns-search," +
	"ipv6.method,ipv6.addresses,ipv6.gateway,ipv6.dns,802-3-ethernet.mtu"

// NmConn is one NetworkManager connection profile.
type NmConn struct {
	UUID   string      `json:"uuid"`
	Name   string      `json:"name"`
	Device string      `json:"device"`
	Type   string      `json:"type"`
	Config IfaceConfig `json:"config"`
}

func nmKind(t string) string {
	switch t {
	case "802-3-ethernet", "ethernet":
		return "ethernet"
	case "802-11-wireless", "wifi":
		return "wifi"
	}
	return t
}

func nmList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" && s != "--" {
			out = append(out, s)
		}
	}
	return out
}

// ParseNmcli reads terse `connection show` blocks, one per connection,
// separated by blank lines.
func ParseNmcli(out string) []NmConn {
	var cs []NmConn
	var c *NmConn
	flush := func() {
		if c != nil && c.UUID != "" {
			c.Config.Name = c.Device
			c.Config.Kind = nmKind(c.Type)
			cs = append(cs, *c)
		}
		c = nil
	}
	for _, l := range lines(out) {
		if strings.TrimSpace(l) == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		v = strings.ReplaceAll(v, `\:`, ":")
		if v == "--" {
			v = ""
		}
		if c == nil {
			c = &NmConn{}
		}
		cfg := &c.Config
		switch k {
		case "connection.uuid":
			c.UUID = v
		case "connection.id":
			c.Name = v
		case "connection.interface-name":
			c.Device = v
		case "connection.type":
			c.Type = v
		case "ipv4.method":
			cfg.DHCP4 = v == "auto"
		case "ipv6.method":
			cfg.DHCP6 = v == "auto" || v == "dhcp"
		case "ipv4.addresses", "ipv6.addresses":
			cfg.Addresses = append(cfg.Addresses, nmList(v)...)
		case "ipv4.gateway":
			cfg.Gateway4 = v
		case "ipv6.gateway":
			cfg.Gateway6 = v
		case "ipv4.dns", "ipv6.dns":
			cfg.DNS = append(cfg.DNS, nmList(v)...)
		case "ipv4.dns-search":
			cfg.Search = nmList(v)
		case "802-3-ethernet.mtu":
			cfg.MTU, _ = strconv.Atoi(v)
		}
	}
	flush()
	return cs
}

// NmcliModify is the arguments after `nmcli connection modify <uuid>` that
// give the connection cfg. The caller quotes each one.
func NmcliModify(c NmConn, cfg IfaceConfig) []string {
	var a4, a6, d4, d6 []string
	for _, a := range cfg.Addresses {
		if isV6(a) {
			a6 = append(a6, a)
		} else {
			a4 = append(a4, a)
		}
	}
	for _, d := range cfg.DNS {
		if isV6(d) {
			d6 = append(d6, d)
		} else {
			d4 = append(d4, d)
		}
	}
	m4 := "disabled"
	switch {
	case cfg.DHCP4:
		m4 = "auto"
	case len(a4) > 0:
		m4 = "manual"
	}
	m6 := "ignore"
	switch {
	case cfg.DHCP6:
		m6 = "auto"
	case len(a6) > 0:
		m6 = "manual"
	}
	args := []string{
		"ipv4.method", m4, "ipv4.addresses", strings.Join(a4, ","), "ipv4.gateway", cfg.Gateway4,
		"ipv4.dns", strings.Join(d4, ","), "ipv4.dns-search", strings.Join(cfg.Search, ","),
		"ipv6.method", m6, "ipv6.addresses", strings.Join(a6, ","), "ipv6.gateway", cfg.Gateway6,
		"ipv6.dns", strings.Join(d6, ","),
	}
	if nmKind(c.Type) == "ethernet" {
		mtu := "auto"
		if cfg.MTU > 0 {
			mtu = strconv.Itoa(cfg.MTU)
		}
		args = append(args, "802-3-ethernet.mtu", mtu)
	}
	return args
}
