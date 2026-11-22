package api

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morche/backend/internal/arvancdn"
	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/database/sqlc"
)

// Names across every DNS connection: for the reverse proxy's domains, which
// zone answers for each name, what it points at, whether a CDN sits in front,
// and a way to point it at a server.

type DNSNameRecord struct {
	ID     string   `json:"id,omitempty" doc:"ArvanCloud: the record's id"`
	Type   string   `json:"type"`
	Values []string `json:"values"`
	Cloud  bool     `json:"cloud" doc:"Through ArvanCloud's CDN"`
	TTL    int64    `json:"ttl"`
}

type DNSNameMatch struct {
	Name       string          `json:"name"`
	Found      bool            `json:"found" doc:"A zone Morche manages covers this name"`
	ServerID   string          `json:"server_id,omitempty"`
	ServerName string          `json:"server_name,omitempty"`
	ServerKind string          `json:"server_kind,omitempty" enum:"technitium,arvan,"`
	Zone       string          `json:"zone,omitempty"`
	ZoneStatus string          `json:"zone_status,omitempty" doc:"ArvanCloud: the domain's status (active, pending…)"`
	Writable   bool            `json:"writable" doc:"This person may point it from Morche: Engineer, a primary zone, a connection that allows changes"`
	Records    []DNSNameRecord `json:"records" doc:"A, AAAA, CNAME and ANAME records of the name"`
	Problem    string          `json:"problem,omitempty" doc:"The zone was found but its records couldn't be read"`
}

var pointTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "ANAME": true}

func cleanName(n string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
}

// covers says whether zone holds name, and how specific it is.
func covers(zone, name string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// relName is a name relative to its zone, the way ArvanCloud writes it.
func relName(name, zone string) string {
	if name == zone {
		return "@"
	}
	return strings.TrimSuffix(name, "."+zone)
}

type zoneHit struct {
	server sqlc.DnsServer
	zone   DNSZone
}

// bestZone picks, for one name, the most specific zone; among copies of it a
// primary on a connection that allows changes wins.
func bestZone(hits []zoneHit, name string) *zoneHit {
	var best *zoneHit
	score := func(h zoneHit) int {
		n := len(h.zone.Name) * 8
		// An ArvanCloud domain that doesn't answer yet (nameservers not
		// pointed) or only by CNAME loses to a zone that does.
		if h.zone.CDN != nil && h.zone.CDN.Status != "active" {
			n -= 6
		} else if h.zone.CDN != nil && h.zone.CDN.Setup == "partial" {
			n -= 3
		}
		if h.zone.Type == "Primary" {
			n += 2
		}
		if h.server.AllowChanges {
			n++
		}
		return n
	}
	for i := range hits {
		h := hits[i]
		if !covers(strings.ToLower(h.zone.Name), name) || h.zone.Type == "Secondary" || h.zone.Type == "Stub" {
			continue
		}
		if best == nil || score(h) > score(*best) {
			best = &hits[i]
		}
	}
	return best
}

// zoneReads shares one read of a zone's records between the names of one
// request (ArvanCloud limits requests per minute).
type zoneReads struct {
	mu sync.Mutex
	m  map[string]*zoneRead
}

type zoneRead struct {
	once  sync.Once
	arvan []arvancdn.Record
	tech  []DNSRecord
	err   error
}

func (z *zoneReads) get(key string) *zoneRead {
	if z == nil {
		return &zoneRead{}
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.m == nil {
		z.m = map[string]*zoneRead{}
	}
	r := z.m[key]
	if r == nil {
		r = &zoneRead{}
		z.m[key] = r
	}
	return r
}

func (h *dnsHandler) nameRecords(ctx context.Context, s sqlc.DnsServer, zone, name string) ([]DNSNameRecord, error) {
	return h.nameRecordsShared(ctx, nil, s, zone, name)
}

func (h *dnsHandler) nameRecordsShared(ctx context.Context, reads *zoneReads, s sqlc.DnsServer, zone, name string) ([]DNSNameRecord, error) {
	out := []DNSNameRecord{}
	read := reads.get(s.ID.String() + "/" + zone)
	if s.Kind == dnsKindArvan {
		read.once.Do(func() {
			cl, err := h.savedArvan(s)
			if err != nil {
				read.err = err
				return
			}
			read.arvan, read.err = cl.Records(ctx, zone)
		})
		if read.err != nil {
			return nil, read.err
		}
		recs := read.arvan
		rel := relName(name, zone)
		for _, raw := range recs {
			r := toCDNRecord(raw)
			if !strings.EqualFold(r.Name, rel) || !pointTypes[r.Type] {
				continue
			}
			nr := DNSNameRecord{ID: r.ID, Type: r.Type, Cloud: r.Cloud, TTL: int64(r.TTL), Values: []string{}}
			for _, a := range r.Addresses {
				nr.Values = append(nr.Values, a.IP)
			}
			if r.Host != "" {
				nr.Values = append(nr.Values, r.Host)
			}
			out = append(out, nr)
		}
		return out, nil
	}
	read.once.Do(func() {
		c, err := h.savedClient(s)
		if err != nil {
			read.err = err
			return
		}
		_, raw, err := c.ListRecords(ctx, zone)
		if err != nil {
			read.err = err
			return
		}
		for _, rr := range raw {
			read.tech = append(read.tech, toDNSRecord(rr))
		}
	})
	if read.err != nil {
		return nil, read.err
	}
	byType := map[string]*DNSNameRecord{}
	for _, r := range read.tech {
		if cleanName(r.Name) != name || !pointTypes[r.Type] || r.Disabled {
			continue
		}
		nr := byType[r.Type]
		if nr == nil {
			nr = &DNSNameRecord{Type: r.Type, TTL: r.TTL, Values: []string{}}
			byType[r.Type] = nr
		}
		nr.Values = append(nr.Values, r.Value)
	}
	for _, t := range []string{"A", "AAAA", "CNAME", "ANAME"} {
		if nr := byType[t]; nr != nil {
			out = append(out, *nr)
		}
	}
	return out, nil
}

func (h *dnsHandler) matchName(ctx context.Context, p *principal, hit *zoneHit, name string) DNSNameMatch {
	return h.matchNameShared(ctx, nil, p, hit, name)
}

func (h *dnsHandler) matchNameShared(ctx context.Context, reads *zoneReads, p *principal, hit *zoneHit, name string) DNSNameMatch {
	m := DNSNameMatch{Name: name, Records: []DNSNameRecord{}}
	if hit == nil {
		return m
	}
	s := hit.server
	m.Found, m.ServerID, m.ServerName, m.ServerKind, m.Zone = true, s.ID.String(), s.Name, s.Kind, hit.zone.Name
	if hit.zone.CDN != nil {
		m.ZoneStatus = hit.zone.CDN.Status
	}
	m.Writable = s.AllowChanges && hit.zone.Type == "Primary" && p.Access.WorkspaceLevel(s.WorkspaceID) >= auth.Engineer &&
		(hit.zone.CDN == nil || hit.zone.CDN.Status != "moved")
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	recs, err := h.nameRecordsShared(rctx, reads, s, hit.zone.Name, name)
	if err != nil {
		_, m.Problem = dnsStatus(err)
		return m
	}
	m.Records = recs
	return m
}

type DNSNamesOutput struct {
	Body struct {
		Items []DNSNameMatch `json:"items"`
	}
}

type DNSPointBody struct {
	Name  string `json:"name" minLength:"1" maxLength:"255" doc:"Full name, like shop.example.com"`
	Type  string `json:"type" enum:"A,AAAA,CNAME"`
	Value string `json:"value" minLength:"1" maxLength:"255" doc:"The address (A, AAAA) or target name (CNAME)"`
	Cloud *bool  `json:"cloud,omitempty" doc:"ArvanCloud: through the CDN. Left out: as the record was, off for a new one."`
}

func registerDNSNames(api huma.API, h *dnsHandler) {
	tags := []string{"DNS"}

	huma.Register(api, huma.Operation{
		OperationID: "find-dns-names", Method: http.MethodGet, Path: "/dns-names",
		Summary:     "Where names are answered",
		Description: "For each name: the most specific zone on any DNS connection in scope, and the name's A/AAAA/CNAME/ANAME records there.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		Names []string `query:"name,explode" maxItems:"50"`
	}) (*DNSNamesOutput, error) {
		p := principalOf(ctx)
		sc := p.scope()
		rows, err := h.q.ListDNSServers(ctx, sqlc.ListDNSServersParams{
			SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, WorkspaceID: sc.current,
		})
		if err != nil {
			return nil, internalError(err)
		}
		var (
			mu   sync.Mutex
			wg   sync.WaitGroup
			hits []zoneHit
		)
		for _, s := range rows {
			wg.Go(func() {
				zones, err := h.zonesOf(ctx, s)
				if err != nil {
					return
				}
				mu.Lock()
				for _, z := range zones {
					hits = append(hits, zoneHit{s, z})
				}
				mu.Unlock()
			})
		}
		wg.Wait()
		out := &DNSNamesOutput{}
		out.Body.Items = make([]DNSNameMatch, 0, len(in.Names))
		seen := map[string]bool{}
		var names []string
		for _, n := range in.Names {
			n = cleanName(strings.TrimPrefix(n, "*."))
			if n != "" && !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
		results := make([]DNSNameMatch, len(names))
		reads := &zoneReads{}
		for i, n := range names {
			wg.Go(func() { results[i] = h.matchNameShared(ctx, reads, p, bestZone(hits, n), n) })
		}
		wg.Wait()
		out.Body.Items = append(out.Body.Items, results...)
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "point-dns-name", Method: http.MethodPost, Path: "/dns-servers/{id}/zones/{zone}/point",
		Summary:     "Point a name at an address",
		Description: "Changes the name's record of that type, or adds one. Refused when the name has a record of another kind (a CNAME next to an A), or several to choose from. Answers with the name's records, fresh.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body DNSPointBody
	}) (*struct{ Body DNSNameMatch }, error) {
		s, _, err := h.withDNS(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if err := mustWrite(s); err != nil {
			return nil, err
		}
		zone, err := cleanZone(in.Zone)
		if err != nil {
			return nil, err
		}
		zone = cleanName(zone)
		b := in.Body
		name := cleanName(b.Name)
		if !covers(zone, name) {
			return nil, fieldError("body.name", "This name isn't in "+zone, b.Name)
		}
		value := strings.TrimSpace(b.Value)
		switch b.Type {
		case "A", "AAAA":
			ip, err := netip.ParseAddr(value)
			if err != nil || (b.Type == "A") != ip.Is4() {
				return nil, fieldError("body.value", "Enter an "+map[bool]string{true: "IPv4", false: "IPv6"}[b.Type == "A"]+" address", value)
			}
			value = ip.String()
		default:
			value = trimHost(value)
		}
		recs, err := h.nameRecords(ctx, s, zone, name)
		if err != nil {
			return nil, dnsError(err)
		}
		var same []DNSNameRecord
		for _, r := range recs {
			if r.Type == b.Type {
				same = append(same, r)
				continue
			}
			conflict := r.Type == "CNAME" || b.Type == "CNAME" || r.Type == "ANAME"
			if conflict {
				return nil, huma.Error409Conflict(name + " already has a " + r.Type + " record: change it in the zone")
			}
		}
		if len(same) == 1 && len(same[0].Values) > 1 {
			return nil, huma.Error409Conflict(name + " has several " + b.Type + " addresses: change them in the zone")
		}
		if s.Kind == dnsKindArvan {
			err = h.pointArvan(ctx, s, zone, name, b.Type, value, b.Cloud, same)
		} else {
			err = h.pointTechnitium(ctx, s, zone, name, b.Type, value, same)
		}
		if err != nil {
			return nil, err
		}
		forgetArvanDomains(s.ID)
		zones, _ := h.zonesOf(ctx, s)
		var hit *zoneHit
		for _, z := range zones {
			if cleanName(z.Name) == zone {
				hit = &zoneHit{s, z}
			}
		}
		if hit == nil {
			hit = &zoneHit{s, DNSZone{Name: zone, Type: "Primary"}}
		}
		return &struct{ Body DNSNameMatch }{Body: h.matchName(ctx, principalOf(ctx), hit, name)}, nil
	})
}

func (h *dnsHandler) pointArvan(ctx context.Context, s sqlc.DnsServer, zone, name, typ, value string, cloud *bool, same []DNSNameRecord) error {
	cl, err := h.savedArvan(s)
	if err != nil {
		return internalError(err)
	}
	f := CDNRecordFields{Name: relName(name, zone), Type: typ}
	if cloud != nil {
		f.Cloud = *cloud
	}
	var existing *arvancdn.Record
	if len(same) == 1 {
		recs, err := cl.Records(ctx, zone)
		if err != nil {
			return arvanError(err)
		}
		i := slices.IndexFunc(recs, func(r arvancdn.Record) bool { return r.ID == same[0].ID })
		if i >= 0 {
			existing = &recs[i]
			cur := toCDNRecord(*existing)
			f = cur.CDNRecordFields
			if cloud != nil {
				f.Cloud = *cloud
			}
		}
	}
	switch typ {
	case "A", "AAAA":
		addr := CDNAddress{IP: value}
		if len(f.Addresses) == 1 {
			addr.Port, addr.Weight, addr.Country = f.Addresses[0].Port, f.Addresses[0].Weight, f.Addresses[0].Country
		}
		f.Addresses = []CDNAddress{addr}
	default:
		f.Host = value
	}
	rec, err := arvanRecord(f, "body")
	if err != nil {
		return err
	}
	if existing != nil {
		_, err = cl.UpdateRecord(ctx, zone, existing.ID, rec)
	} else {
		_, err = cl.CreateRecord(ctx, zone, rec)
	}
	if err != nil {
		return arvanError(err)
	}
	return nil
}

func (h *dnsHandler) pointTechnitium(ctx context.Context, s sqlc.DnsServer, zone, name, typ, value string, same []DNSNameRecord) error {
	c, err := h.savedClient(s)
	if err != nil {
		return internalError(err)
	}
	next := DNSRecordBody{Name: name, Type: typ, TTL: 3600, Value: value}
	if len(same) == 1 {
		cur := DNSRecordBody{Name: name, Type: typ, TTL: same[0].TTL, Value: same[0].Values[0]}
		next.TTL = cur.TTL
		if err := cur.normalize(zone, "body"); err != nil {
			return err
		}
		if err := next.normalize(zone, "body"); err != nil {
			return err
		}
		if err := c.UpdateRecord(ctx, updateForm(zone, &cur, &next)); err != nil {
			return dnsError(err)
		}
		return nil
	}
	if err := next.normalize(zone, "body"); err != nil {
		return err
	}
	if err := c.AddRecord(ctx, next.addForm(zone)); err != nil {
		return dnsError(err)
	}
	return nil
}
