package api

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/morcheh/backend/internal/technitium"
)

// DNSZoneOptions is who may copy a zone (zone transfer) and which servers
// are told when it changes (notify). A Secondary also has its primaries.
type DNSZoneOptions struct {
	Type                string   `json:"type"`
	ZoneTransfer        string   `json:"zone_transfer" enum:"Deny,Allow,AllowOnlyZoneNameServers,UseSpecifiedNetworkACL,AllowZoneNameServersAndUseSpecifiedNetworkACL"`
	ZoneTransferAllowed []string `json:"zone_transfer_allowed" doc:"Addresses or networks; a leading ! refuses one."`
	Notify              string   `json:"notify" enum:"None,ZoneNameServers,SpecifiedNameServers,BothZoneAndSpecifiedNameServers"`
	NotifyServers       []string `json:"notify_servers"`
	PrimaryAddresses    []string `json:"primary_addresses" doc:"Secondary zones only."`
	NotifyFailed        bool     `json:"notify_failed"`
	NotifyFailedFor     []string `json:"notify_failed_for"`
}

type DNSZoneOptionsOutput struct {
	Body DNSZoneOptions
}

type DNSZoneOptionsBody struct {
	ZoneTransfer        string   `json:"zone_transfer" enum:"Deny,Allow,AllowOnlyZoneNameServers,UseSpecifiedNetworkACL,AllowZoneNameServersAndUseSpecifiedNetworkACL"`
	ZoneTransferAllowed []string `json:"zone_transfer_allowed" maxItems:"50"`
	Notify              string   `json:"notify" enum:"None,ZoneNameServers,SpecifiedNameServers,BothZoneAndSpecifiedNameServers"`
	NotifyServers       []string `json:"notify_servers" maxItems:"50"`
	PrimaryAddresses    []string `json:"primary_addresses,omitempty" maxItems:"10" doc:"Sent only for a Secondary zone."`
}

func zoneOptionsOf(ctx context.Context, c *technitium.Client, zone string) (*DNSZoneOptionsOutput, error) {
	o, err := c.ZoneOptions(ctx, zone)
	if err != nil {
		return nil, dnsError(err)
	}
	return &DNSZoneOptionsOutput{Body: DNSZoneOptions{
		Type:                o.Type,
		ZoneTransfer:        o.ZoneTransfer,
		ZoneTransferAllowed: orEmpty(o.ZoneTransferACL),
		Notify:              o.Notify,
		NotifyServers:       orEmpty(o.NotifyNameServers),
		PrimaryAddresses:    orEmpty(o.PrimaryAddresses),
		NotifyFailed:        o.NotifyFailed,
		NotifyFailedFor:     orEmpty(o.NotifyFailedFor),
	}}, nil
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// form checks every address and builds the options/set form. Lists go as a
// whole each time ("false" clears one), so what's sent is what's kept.
func (b *DNSZoneOptionsBody) form() (url.Values, error) {
	form := url.Values{"zoneTransfer": {b.ZoneTransfer}, "notify": {b.Notify}}

	acl, err := cleanList(b.ZoneTransferAllowed, "body.zone_transfer_allowed", func(v string) bool {
		v = strings.TrimPrefix(v, "!")
		if _, err := netip.ParsePrefix(v); err == nil {
			return true
		}
		_, err := netip.ParseAddr(v)
		return err == nil
	}, "Enter an IP address or a network like 10.0.0.0/24")
	if err != nil {
		return nil, err
	}
	if len(acl) == 0 && strings.Contains(b.ZoneTransfer, "UseSpecifiedNetworkACL") {
		return nil, fieldError("body.zone_transfer_allowed", "Add at least one address", nil)
	}
	setList(form, "zoneTransferNetworkACL", acl)

	notify, err := cleanList(b.NotifyServers, "body.notify_servers", func(v string) bool {
		_, err := netip.ParseAddr(v)
		return err == nil
	}, "Enter the server's IP address")
	if err != nil {
		return nil, err
	}
	if len(notify) == 0 && strings.Contains(b.Notify, "SpecifiedNameServers") {
		return nil, fieldError("body.notify_servers", "Add at least one address", nil)
	}
	setList(form, "notifyNameServers", notify)

	if b.PrimaryAddresses != nil {
		primaries, err := cleanList(b.PrimaryAddresses, "body.primary_addresses", func(v string) bool {
			return !strings.ContainsAny(v, " \t,")
		}, "Enter an IP address or a host name")
		if err != nil {
			return nil, err
		}
		setList(form, "primaryNameServerAddresses", primaries)
	}
	return form, nil
}

func cleanList(in []string, loc string, ok func(string) bool, msg string) ([]string, error) {
	out := make([]string, 0, len(in))
	for i, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if !ok(v) {
			return nil, fieldError(fmt.Sprintf("%s[%d]", loc, i), msg, v)
		}
		out = append(out, v)
	}
	return out, nil
}

func setList(form url.Values, key string, list []string) {
	if len(list) == 0 {
		form.Set(key, "false")
		return
	}
	form.Set(key, strings.Join(list, ","))
}
