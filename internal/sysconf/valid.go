package sysconf

import (
	"net/netip"
	"regexp"
)

// Every value Morche writes into a config file goes through one of these
// first, so a value can never carry a newline or a second directive.

// ValidIP is a bare IPv4 or IPv6 address.
func ValidIP(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Zone() == ""
}

// ValidCIDR is an address with its prefix length.
func ValidCIDR(s string) bool {
	p, err := netip.ParsePrefix(s)
	return err == nil && p.Addr().Zone() == ""
}

// ValidServerName is a host name or an IP address (NTP servers, mirrors'
// hosts).
func ValidServerName(s string) bool { return ValidIP(s) || ValidHostname(s) }

var resolvOption = regexp.MustCompile(`^[a-z][a-z0-9-]*(:[0-9]{1,4})?$`)

// ValidResolvOption is one resolv.conf option such as edns0 or timeout:2.
func ValidResolvOption(s string) bool { return resolvOption.MatchString(s) }
