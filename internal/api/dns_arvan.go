package api

import (
	"context"
	"errors"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/arvancdn"
	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/cloud"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/dbmon"
	"github.com/morche/backend/internal/technitium"
)

// A DNS connection is a Technitium server or an ArvanCloud CDN account. For
// ArvanCloud the domains are the zones, and each has its CDN settings too
// (dns_cdn.go). Only GETs go to ArvanCloud unless the connection allows
// changes (off by default for ArvanCloud).
const (
	dnsKindTechnitium = "technitium"
	dnsKindArvan      = "arvan"
)

var errArvanConnection = errors.New("arvan connection")

func dnsKindOf(raw string) string {
	if raw == dnsKindArvan {
		return dnsKindArvan
	}
	return dnsKindTechnitium
}

// allowChangesOf: what was asked, else what was saved, else the kind's default.
func allowChangesOf(want *bool, prev *sqlc.DnsServer, kind string) bool {
	switch {
	case want != nil:
		return *want
	case prev != nil:
		return prev.AllowChanges
	}
	return kind != dnsKindArvan
}

// mustWrite refuses a change on a read-only connection.
func mustWrite(s sqlc.DnsServer) error {
	if s.AllowChanges {
		return nil
	}
	return huma.Error403Forbidden("Changes from Morche are off for " + s.Name + ". An Owner can turn on \"Allow changes from Morche\" in its settings.")
}

// connectionOf resolves the address and token to test or save. ArvanCloud has
// one fixed address; a blank key keeps the saved one.
func (h *dnsHandler) connectionOf(p *principal, prev *sqlc.DnsServer, kind, rawURL, rawToken string, skipVerify, internal bool) (dnsConnection, error) {
	if kind == dnsKindArvan {
		key := arvancdn.CleanKey(rawToken)
		if strings.ContainsAny(key, " \t\r\n") {
			return dnsConnection{}, fieldError("body.token", "Paste just the key, with no spaces", "")
		}
		if key == "" {
			if prev == nil {
				return dnsConnection{}, fieldError("body.token", "Enter the API key", "")
			}
			saved, err := h.box.Open(prev.TokenEnc)
			if err != nil {
				return dnsConnection{}, internalError(err)
			}
			key = saved
		}
		return dnsConnection{url: arvancdn.DefaultBase, token: key}, nil
	}
	clean, err := cleanDNSURL(rawURL)
	if err != nil {
		return dnsConnection{}, err
	}
	if err := allowInternal(p, prev, clean, internal); err != nil {
		return dnsConnection{}, err
	}
	token, err := h.resolveToken(prev, clean, strings.TrimSpace(rawToken))
	if err != nil {
		return dnsConnection{}, err
	}
	return dnsConnection{clean, token, skipVerify, internal}, nil
}

// arvanFor builds the CDN client. Keys starting with "fake-" go to the dev
// fake when one is set; a real key never does.
func (h *dnsHandler) arvanFor(key string) *arvancdn.Client {
	if base := h.arvanFakeBase(); base != "" && strings.HasPrefix(key, "fake-") {
		return arvancdn.New(arvancdn.Config{Key: key, BaseURL: base, Dial: (&net.Dialer{Timeout: 10 * time.Second}).DialContext})
	}
	return arvancdn.New(arvancdn.Config{Key: key, Dial: dbmon.DirectDialer(false)})
}

// The fake serves the CDN API next to the IaaS one: ARVAN_FAKE_URL
// http://127.0.0.1:8091/%s/v3 → http://127.0.0.1:8091/cdn/4.0.
func (h *dnsHandler) arvanFakeBase() string {
	if h.arvanFake == "" {
		return ""
	}
	u, err := url.Parse(strings.ReplaceAll(h.arvanFake, "%s", "x"))
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/cdn/4.0"
}

func (h *dnsHandler) savedArvan(s sqlc.DnsServer) (*arvancdn.Client, error) {
	key, err := h.box.Open(s.TokenEnc)
	if err != nil {
		return nil, err
	}
	return h.arvanFor(key), nil
}

func (h *dnsHandler) checkConnection(ctx context.Context, kind string, conn dnsConnection) (technitium.Info, error) {
	if kind == dnsKindArvan {
		info, err := h.arvanFor(conn.token).Check(ctx)
		return technitium.Info{Version: "CDN 4.0", Zones: info.Domains, Latency: info.Latency}, err
	}
	return h.client(conn).Check(ctx)
}

func (h *dnsHandler) checkServer(ctx context.Context, s sqlc.DnsServer) (technitium.Info, error) {
	token, err := h.box.Open(s.TokenEnc)
	if err != nil {
		return technitium.Info{}, err
	}
	return h.checkConnection(ctx, s.Kind, dnsConnection{s.Url, token, s.TlsSkipVerify, s.AllowInternal})
}

// DNSZoneCDN is what an ArvanCloud domain adds to its zone.
type DNSZoneCDN struct {
	Status      string   `json:"status" enum:"initializing,pending,active,moved" doc:"active = ArvanCloud answers for it; pending = the nameservers (or CNAME) aren't pointed at it yet"`
	Setup       string   `json:"setup" enum:"full,partial" doc:"full = ArvanCloud's nameservers; partial = chosen names by CNAME"`
	NSKeys      []string `json:"ns_keys" doc:"The nameservers to set at the registrar"`
	CurrentNS   []string `json:"current_ns" doc:"The nameservers the domain has now"`
	CNAMETarget string   `json:"cname_target,omitempty"`
	PlanLevel   int      `json:"plan_level"`
	Restriction []string `json:"restriction" doc:"paused, suspended, unfair, charged"`
	DomainID    string   `json:"domain_id"`
}

func cdnZone(d arvancdn.Domain) DNSZone {
	cdn := &DNSZoneCDN{
		Status: d.Status, Setup: d.Type, NSKeys: orEmpty(d.NSKeys), CurrentNS: orEmpty(d.CurrentNS),
		PlanLevel: d.PlanLevel, Restriction: orEmpty(d.Restriction), DomainID: d.ID,
	}
	if cdn.Setup == "" {
		cdn.Setup = "full"
	}
	if d.CustomCNAME != nil && *d.CustomCNAME != "" {
		cdn.CNAMETarget = *d.CustomCNAME
	} else if d.CNAMETarget != nil {
		cdn.CNAMETarget = *d.CNAMETarget
	}
	return DNSZone{
		Name: strings.TrimSuffix(d.Name, "."), Type: "Primary",
		Disabled:     slices.Contains(d.Restriction, "paused") || slices.Contains(d.Restriction, "suspended"),
		LastModified: d.UpdatedAt, CDN: cdn,
	}
}

// ArvanCloud domain lists are kept a few seconds: the zone views poll, and
// ArvanCloud limits requests per minute.
var arvanDomains = struct {
	sync.Mutex
	m map[uuid.UUID]arvanDomainsCached
}{m: map[uuid.UUID]arvanDomainsCached{}}

type arvanDomainsCached struct {
	at      time.Time
	domains []arvancdn.Domain
}

func forgetArvanDomains(id uuid.UUID) {
	arvanDomains.Lock()
	delete(arvanDomains.m, id)
	arvanDomains.Unlock()
}

func (h *dnsHandler) arvanDomainList(ctx context.Context, s sqlc.DnsServer) ([]arvancdn.Domain, error) {
	arvanDomains.Lock()
	c, ok := arvanDomains.m[s.ID]
	arvanDomains.Unlock()
	if ok && time.Since(c.at) < 20*time.Second {
		return c.domains, nil
	}
	cl, err := h.savedArvan(s)
	if err != nil {
		return nil, err
	}
	domains, err := cl.Domains(ctx)
	if err != nil {
		return nil, err
	}
	arvanDomains.Lock()
	arvanDomains.m[s.ID] = arvanDomainsCached{time.Now(), domains}
	arvanDomains.Unlock()
	return domains, nil
}

// zonesFor lists a connection's zones, whatever its kind.
func (h *dnsHandler) zonesFor(ctx context.Context, s sqlc.DnsServer) ([]DNSZone, error) {
	if s.Kind == dnsKindArvan {
		domains, err := h.arvanDomainList(ctx, s)
		if err != nil {
			return nil, err
		}
		out := make([]DNSZone, 0, len(domains))
		for _, d := range domains {
			out = append(out, cdnZone(d))
		}
		slices.SortFunc(out, func(a, b DNSZone) int { return strings.Compare(a.Name, b.Name) })
		return out, nil
	}
	c, err := h.savedClient(s)
	if err != nil {
		return nil, err
	}
	zones, err := c.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]DNSZone, 0, len(zones))
	for _, z := range zones {
		out = append(out, toDNSZone(z))
	}
	return out, nil
}

func dnsZoneSourceText(s sqlc.DnsServer) string {
	if s.Kind == dnsKindArvan {
		return "Domain on ArvanCloud (" + s.Name + ")"
	}
	return "Primary zone on " + s.Name
}

func (h *dnsHandler) createArvanDomain(ctx context.Context, s sqlc.DnsServer, zone, setup string, importRecords *bool) (string, error) {
	if zone == "." || !strings.Contains(zone, ".") || strings.ContainsAny(zone, "/:*") {
		return "", fieldError("body.name", "Enter a domain like example.com", zone)
	}
	if setup != "partial" {
		setup = "full"
	}
	imp := importRecords == nil || *importRecords
	cl, err := h.savedArvan(s)
	if err != nil {
		return "", internalError(err)
	}
	d, err := cl.CreateDomain(ctx, zone, setup, imp)
	forgetArvanDomains(s.ID)
	if err != nil {
		return "", arvanError(err)
	}
	if d.Name == "" {
		d.Name = zone
	}
	return d.Name, nil
}

// deleteArvanDomain removes a domain from the ArvanCloud account: the CDN
// stops serving it. Owner only, on a connection that allows changes.
func (h *dnsHandler) deleteArvanDomain(ctx context.Context, s sqlc.DnsServer, rawZone string) error {
	if principalOf(ctx).Access.WorkspaceLevel(s.WorkspaceID) < auth.Owner {
		return huma.Error403Forbidden("You need Owner access to remove a domain from ArvanCloud.")
	}
	if err := mustWrite(s); err != nil {
		return err
	}
	zone, err := cleanZone(rawZone)
	if err != nil {
		return err
	}
	cl, err := h.savedArvan(s)
	if err != nil {
		return internalError(err)
	}
	d, err := cl.Domain(ctx, zone)
	if err != nil {
		return arvanError(err)
	}
	err = cl.DeleteDomain(ctx, zone, d.ID)
	forgetArvanDomains(s.ID)
	if err != nil {
		return arvanError(err)
	}
	return nil
}

func isArvanError(err error) bool {
	var (
		a *cloud.AuthError
		p *cloud.PermissionError
		x *cloud.APIError
		n *cloud.NotFoundError
		v *arvancdn.ValidationError
	)
	return errors.As(err, &a) || errors.As(err, &p) || errors.As(err, &x) || errors.As(err, &n) || errors.As(err, &v)
}

func arvanStatus(err error) (string, string) {
	var v *arvancdn.ValidationError
	if errors.As(err, &v) {
		return "error", v.Error()
	}
	return cloud.Classify(err)
}

// arvanError turns what ArvanCloud said into the API's answer. Never a 403 or
// 401 for ArvanCloud's own refusals: those would make the panel re-check
// Morche's session.
func arvanError(err error) error {
	var (
		v *arvancdn.ValidationError
		p *cloud.PermissionError
		n *cloud.NotFoundError
		a *cloud.AuthError
		x *cloud.APIError
	)
	switch {
	case errors.As(err, &v):
		return huma.Error422UnprocessableEntity(v.Error())
	case errors.As(err, &p):
		return huma.Error422UnprocessableEntity(p.Error())
	case errors.As(err, &n):
		return huma.Error404NotFound(n.Error())
	case errors.As(err, &a):
		return huma.Error502BadGateway(a.Error())
	case errors.As(err, &x):
		if x.Status == 429 {
			return huma.Error429TooManyRequests(x.Error())
		}
		return huma.Error502BadGateway(x.Error())
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return huma.Error504GatewayTimeout("ArvanCloud didn't answer in time")
	}
	_, msg := cloud.Classify(err)
	return huma.Error502BadGateway("Couldn't reach ArvanCloud: " + msg)
}
