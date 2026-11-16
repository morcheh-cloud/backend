package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morche/backend/internal/database/sqlc"
)

// AllowEntry is one address or range the panel answers when the allowlist is on.
type AllowEntry struct {
	Address string `json:"address" maxLength:"64" doc:"An address (203.0.113.7) or a range (203.0.113.0/24, 2001:db8::/48)"`
	Note    string `json:"note,omitempty" maxLength:"100" doc:"What it is, e.g. Office or VPN"`
}

// addressRefusedType marks the refusal, so the panel can say what happened
// instead of sending the person to the sign-in page.
const addressRefusedType = "urn:morche:address-not-allowed"

// Operations that answer from any address: the health check, monitors' push
// URLs and git webhooks (called by machines, not people) and the sign-in page's state, which is
// how the panel learns it's been refused.
var allowlistExempt = map[string]bool{
	"get-health":          true,
	"push-heartbeat":      true,
	"push-heartbeat-post": true,
	"docker-git-webhook":  true,
	"get-auth-state":      true,
}

// allowlist is the saved list, parsed. off means every address gets in.
type allowlist struct {
	on       bool
	prefixes []netip.Prefix
}

func (l *allowlist) allows(ip string) bool {
	if !l.on {
		return true
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap().WithZone("")
	for _, p := range l.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// parseAllowEntry reads "203.0.113.7" or "203.0.113.0/24" as a range.
func parseAllowEntry(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return p, err
		}
		if p.Addr().Is4In6() {
			return netip.Prefix{}, errors.New("use the plain IPv4 range")
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// prefixText writes a range the way people type it: a single address without
// its /32 or /128.
func prefixText(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

func readAllowEntries(raw []byte) []AllowEntry {
	var out []AllowEntry
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return []AllowEntry{}
	}
	return out
}

func toAllowlist(st sqlc.AppSetting) *allowlist {
	l := &allowlist{on: st.IpAllowlistEnabled}
	for _, e := range readAllowEntries(st.IpAllowlist) {
		if p, err := parseAllowEntry(e.Address); err == nil {
			l.prefixes = append(l.prefixes, p)
		}
	}
	return l
}

// reloadAllowlist reads the saved list. Called at start, on every save and
// once a minute (so a change from the command line is picked up).
func (a *authz) reloadAllowlist(ctx context.Context) (*allowlist, error) {
	st, err := a.q.GetSettings(ctx)
	if err != nil {
		return nil, err
	}
	l := toAllowlist(st)
	a.allow.Store(l)
	return l, nil
}

// currentAllowlist is the list in force. Until it could be read once, every
// request is refused: a database that's down at start must not open the gate.
func (a *authz) currentAllowlist(ctx context.Context) (*allowlist, error) {
	if l := a.allow.Load(); l != nil {
		return l, nil
	}
	return a.reloadAllowlist(ctx)
}

// addressRefused says why ip may not reach the panel, or nil.
func (a *authz) addressRefused(ctx context.Context, ip string) *denied {
	l, err := a.currentAllowlist(ctx)
	if err != nil {
		slog.Error("load the allowlist", "error", err)
		return &denied{http.StatusServiceUnavailable, "The panel can't check where you're connecting from right now. Try again in a moment."}
	}
	if l.allows(ip) {
		return nil
	}
	return &denied{http.StatusForbidden, fmt.Sprintf("Access from your address (%s) isn't allowed. Ask an admin to add it to the allowed addresses.", ip)}
}

// writeAddressRefused answers with a problem the panel can recognise by its type.
func writeAddressRefused(api huma.API, ctx huma.Context, d *denied) {
	m := &huma.ErrorModel{Status: d.status, Title: http.StatusText(d.status), Detail: d.message}
	if d.status == http.StatusForbidden {
		m.Type = addressRefusedType
	}
	ctx.SetHeader("Content-Type", "application/problem+json")
	ctx.SetStatus(d.status)
	if err := api.Marshal(ctx.BodyWriter(), "application/problem+json", m); err != nil {
		slog.Warn("write a refusal", "error", err)
	}
}

// noteRefusedSignIn logs a sign-in tried from an address that isn't allowed,
// at most once every ten minutes per address so a script can't fill the log.
func (a *authz) noteRefusedSignIn(ctx context.Context) {
	cl := clientOf(ctx)
	ok, err := a.rdb.Client.SetNX(ctx, "signin-refused:"+cl.ip, 1, 10*time.Minute).Result()
	if err != nil || !ok {
		return
	}
	a.logSignIn(ctx, a.q, sqlc.RecordSignInParams{
		Ip: cl.ip, Network: networkOf(cl.ip), UserAgent: cl.userAgent,
		Kind: "failed", Reason: "address_not_allowed",
	})
}

// networkOf is the part of an address that "a new address" compares: a /24
// for IPv4 and a /64 for IPv6, so a home connection that gets a new address
// every day isn't new each time.
func networkOf(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap().WithZone("")
	bits := 64
	if a.Is4() {
		bits = 24
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return ip
	}
	return p.String()
}

// privateAddress says the panel probably sees a proxy, not the person.
func privateAddress(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast()
}
