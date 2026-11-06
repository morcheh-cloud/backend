package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/dbmon"
	"github.com/morcheh/backend/internal/secrets"
	"github.com/morcheh/backend/internal/technitium"
)

// dnsHandler connects Morcheh to any number of Technitium DNS servers. Zones
// and records live on those servers; only the connection is stored here.
type dnsHandler struct {
	q     *sqlc.Queries
	box   *secrets.Box
	authz *authz
}

type DNSServerIDPath struct {
	ID string `path:"id" format:"uuid"`
}

type DNSZonePath struct {
	ID   string `path:"id" format:"uuid"`
	Zone string `path:"zone" minLength:"1" maxLength:"255" doc:"The zone's name; a dot for the root zone"`
}

// DNSServer is a connection. The token never leaves the backend.
type DNSServer struct {
	ID            string     `json:"id" format:"uuid"`
	WorkspaceID   string     `json:"workspace_id" format:"uuid"`
	Name          string     `json:"name"`
	URL           string     `json:"url"`
	TLSSkipVerify bool       `json:"tls_skip_verify"`
	AllowInternal bool       `json:"allow_internal"`
	Description   string     `json:"description"`
	Favorite      bool       `json:"favorite"`
	Status        string     `json:"status" enum:"unknown,online,unreachable,auth_failed,tls_error,blocked,error"`
	StatusMessage string     `json:"status_message"`
	Version       string     `json:"version"`
	ServerDomain  string     `json:"server_domain"`
	ZoneCount     int32      `json:"zone_count"`
	LatencyMs     *int32     `json:"latency_ms,omitempty"`
	LastCheckedAt *time.Time `json:"last_checked_at,omitempty"`
	LastOnlineAt  *time.Time `json:"last_online_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func toDNSServer(s sqlc.DnsServer) DNSServer {
	return DNSServer{
		ID: s.ID.String(), WorkspaceID: s.WorkspaceID.String(), Name: s.Name, URL: s.Url,
		TLSSkipVerify: s.TlsSkipVerify, AllowInternal: s.AllowInternal, Description: s.Description,
		Favorite: s.Favorite, Status: s.Status, StatusMessage: s.StatusMessage, Version: s.Version,
		ServerDomain: s.ServerDomain, ZoneCount: s.ZoneCount, LatencyMs: s.LatencyMs,
		LastCheckedAt: s.LastCheckedAt, LastOnlineAt: s.LastOnlineAt,
		CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
}

type DNSServerOutput struct {
	Body DNSServer
}

type DNSServerBody struct {
	Name          string `json:"name" minLength:"1" maxLength:"100"`
	URL           string `json:"url" minLength:"1" maxLength:"500" doc:"The server's web console, like https://ns1.example.com:53443"`
	Token         string `json:"token,omitempty" maxLength:"500" doc:"API token. Blank on update keeps the saved one."`
	TLSSkipVerify bool   `json:"tls_skip_verify,omitempty"`
	AllowInternal bool   `json:"allow_internal,omitempty" doc:"Reach a private or loopback address. System admins only."`
	Description   string `json:"description,omitempty" maxLength:"500"`
}

// cleanDNSURL accepts a plain http(s) base address, and nothing that could
// smuggle credentials or send the token elsewhere.
func cleanDNSURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fieldError("body.url", "Enter an address like https://ns1.example.com:53443", raw)
	}
	if u.User != nil {
		return "", fieldError("body.url", "Leave the user and password out of the address", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fieldError("body.url", "Enter just the server's address, with no query", raw)
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}

// sameDNSOrigin says whether two addresses are the same place. A saved token
// is only ever sent back to where it was saved for.
func sameDNSOrigin(a, b string) bool {
	x, errX := url.Parse(a)
	y, errY := url.Parse(b)
	return errX == nil && errY == nil && strings.EqualFold(x.Host, y.Host) && x.Scheme == y.Scheme
}

func (h *dnsHandler) client(cfg dnsConnection) *technitium.Client {
	return technitium.New(technitium.Config{
		URL: cfg.url, Token: cfg.token, SkipVerify: cfg.skipVerify,
		Dial: technitium.Dialer(dbmon.DirectDialer(cfg.allowInternal)),
	})
}

type dnsConnection struct {
	url, token                string
	skipVerify, allowInternal bool
}

func (h *dnsHandler) savedClient(s sqlc.DnsServer) (*technitium.Client, error) {
	token, err := h.box.Open(s.TokenEnc)
	if err != nil {
		return nil, err
	}
	return h.client(dnsConnection{s.Url, token, s.TlsSkipVerify, s.AllowInternal}), nil
}

// dnsStatus adds the status only this layer knows about to the client's.
func dnsStatus(err error) (string, string) {
	var blocked *dbmon.BlockedError
	if errors.As(err, &blocked) {
		return dbmon.StatusBlocked, blocked.Error()
	}
	return technitium.Classify(err)
}

func (h *dnsHandler) record(ctx context.Context, id uuid.UUID, info technitium.Info, checkErr error) (sqlc.DnsServer, error) {
	status, message := dnsStatus(checkErr)
	var latency *int32
	if checkErr == nil {
		ms := int32(info.Latency.Milliseconds())
		latency = &ms
	}
	return h.q.RecordDNSServerCheck(ctx, sqlc.RecordDNSServerCheckParams{
		ID: id, Status: status, StatusMessage: message, Version: info.Version,
		ServerDomain: info.Domain, ZoneCount: int32(info.Zones), LatencyMs: latency,
	})
}

// dnsError turns what a DNS server said into the API's answer. A refusal from
// the server (a bad value, an existing record) is the caller's to fix.
func dnsError(err error) error {
	var api *technitium.APIError
	if errors.As(err, &api) {
		if strings.Contains(strings.ToLower(api.Message), "no such zone") {
			return huma.Error404NotFound(api.Message)
		}
		return huma.Error422UnprocessableEntity(api.Message)
	}
	_, message := dnsStatus(err)
	return huma.Error502BadGateway("Couldn't reach the DNS server: " + message)
}

// withDNS loads a server and hands over its client.
func (h *dnsHandler) withDNS(ctx context.Context, rawID string) (sqlc.DnsServer, *technitium.Client, error) {
	id, err := uuid.Parse(rawID)
	if err != nil {
		return sqlc.DnsServer{}, nil, huma.Error404NotFound("DNS server not found")
	}
	s, err := h.q.GetDNSServer(ctx, id)
	if isNotFound(err) {
		return sqlc.DnsServer{}, nil, huma.Error404NotFound("DNS server not found")
	}
	if err != nil {
		return sqlc.DnsServer{}, nil, internalError(err)
	}
	c, err := h.savedClient(s)
	if err != nil {
		return sqlc.DnsServer{}, nil, internalError(err)
	}
	return s, c, nil
}

// Names a zone can have: a domain, a dot for the root, and, when creating one,
// an IP address or a network for a reverse zone.
var dnsZoneName = regexp.MustCompile(`^[\p{L}\p{N}_*.:/-]+$`)

func cleanZone(raw string) (string, error) {
	z := strings.TrimSpace(raw)
	if z != "." {
		z = strings.TrimSuffix(z, ".")
	}
	if z == "" || !dnsZoneName.MatchString(z) {
		return "", huma.Error422UnprocessableEntity("That isn't a valid zone name")
	}
	return z, nil
}

// DNSZone is one zone on one server.
type DNSZone struct {
	Name         string     `json:"name"`
	Type         string     `json:"type"`
	DNSSECStatus string     `json:"dnssec_status"`
	SOASerial    uint32     `json:"soa_serial"`
	Disabled     bool       `json:"disabled"`
	SyncFailed   bool       `json:"sync_failed"`
	NotifyFailed bool       `json:"notify_failed"`
	Expired      bool       `json:"expired"`
	Expiry       *time.Time `json:"expiry,omitempty"`
	LastModified *time.Time `json:"last_modified,omitempty"`
}

func toDNSZone(z technitium.Zone) DNSZone {
	return DNSZone{
		Name: z.Name, Type: z.Type, DNSSECStatus: z.DNSSECStatus, SOASerial: z.SOASerial,
		Disabled: z.Disabled, SyncFailed: z.SyncFailed, NotifyFailed: z.NotifyFailed,
		Expired: z.IsExpired, Expiry: z.Expiry, LastModified: z.LastModified,
	}
}

// DNSZoneCopy is one server's copy of a zone, in the view across servers.
type DNSZoneCopy struct {
	ServerID   string `json:"server_id" format:"uuid"`
	ServerName string `json:"server_name"`
	DNSZone
}

// DNSZoneGroup is a zone and every server that has it.
type DNSZoneGroup struct {
	Name      string        `json:"name"`
	Copies    []DNSZoneCopy `json:"copies"`
	OutOfSync bool          `json:"out_of_sync" doc:"A secondary copy's serial differs from its primary's, or its last transfer failed."`
}

// DNSServerProblem is a server the view across servers couldn't read.
type DNSServerProblem struct {
	ServerID   string `json:"server_id" format:"uuid"`
	ServerName string `json:"server_name"`
	Message    string `json:"message"`
}

type DNSZonesEverywhereOutput struct {
	Body struct {
		Zones    []DNSZoneGroup     `json:"zones"`
		Problems []DNSServerProblem `json:"problems"`
	}
}

// groupZones merges every server's zones by name. Two independent primaries
// with different serials are normal, so only a secondary is compared.
func groupZones(copies []DNSZoneCopy) []DNSZoneGroup {
	byName := map[string]*DNSZoneGroup{}
	for _, c := range copies {
		key := strings.ToLower(c.Name)
		g := byName[key]
		if g == nil {
			g = &DNSZoneGroup{Name: c.Name}
			byName[key] = g
		}
		g.Copies = append(g.Copies, c)
	}
	out := make([]DNSZoneGroup, 0, len(byName))
	for _, g := range byName {
		// The primary first: that's the copy people edit.
		slices.SortStableFunc(g.Copies, func(a, b DNSZoneCopy) int {
			if (a.Type == "Primary") != (b.Type == "Primary") {
				if a.Type == "Primary" {
					return -1
				}
				return 1
			}
			return strings.Compare(a.ServerName, b.ServerName)
		})
		var primary *DNSZoneCopy
		if g.Copies[0].Type == "Primary" {
			primary = &g.Copies[0]
		}
		for _, c := range g.Copies {
			if c.Type != "Secondary" {
				continue
			}
			if c.SyncFailed || c.Expired || (primary != nil && c.SOASerial != primary.SOASerial) {
				g.OutOfSync = true
			}
		}
		out = append(out, *g)
	}
	slices.SortFunc(out, func(a, b DNSZoneGroup) int { return strings.Compare(a.Name, b.Name) })
	return out
}

type DNSZoneRecords struct {
	Zone    DNSZone     `json:"zone"`
	Records []DNSRecord `json:"records"`
}

type DNSRecordsOutput struct {
	Body DNSZoneRecords
}

// dnsConnectionFor resolves the settings to test or save, against what's saved
// when editing. Blank token = the saved one, only for the address it was saved
// for: otherwise changing the address could send it anywhere.
func (h *dnsHandler) resolveToken(prev *sqlc.DnsServer, cleanURL, token string) (string, error) {
	if token != "" {
		return token, nil
	}
	if prev == nil {
		return "", fieldError("body.token", "Enter an API token", "")
	}
	if !sameDNSOrigin(prev.Url, cleanURL) {
		return "", fieldError("body.token", "The address changed: enter the token again", "")
	}
	saved, err := h.box.Open(prev.TokenEnc)
	if err != nil {
		return "", internalError(err)
	}
	return saved, nil
}

// allowInternal refuses a private address to anyone but an admin, except one an
// admin already allowed, as long as it stays where it was.
func allowInternal(p *principal, prev *sqlc.DnsServer, cleanURL string, want bool) error {
	if !want || p.Access.Admin {
		return nil
	}
	if prev != nil && prev.AllowInternal && sameDNSOrigin(prev.Url, cleanURL) {
		return nil
	}
	return fieldError("body.allow_internal", "Only a system admin can allow private addresses", true)
}

func (h *dnsHandler) create(ctx context.Context, in *struct{ Body DNSServerBody }) (*DNSServerOutput, error) {
	p := principalOf(ctx)
	b := in.Body
	ws, err := h.authz.createTarget(ctx, p)
	if err != nil {
		return nil, err
	}
	if p.Access.WorkspaceLevel(ws) < auth.Engineer {
		return nil, huma.Error403Forbidden("You need Engineer access to the workspace to add a DNS server.")
	}
	clean, err := cleanDNSURL(b.URL)
	if err != nil {
		return nil, err
	}
	if err := allowInternal(p, nil, clean, b.AllowInternal); err != nil {
		return nil, err
	}
	token, err := h.resolveToken(nil, clean, strings.TrimSpace(b.Token))
	if err != nil {
		return nil, err
	}
	s, err := h.q.CreateDNSServer(ctx, sqlc.CreateDNSServerParams{
		WorkspaceID: ws, Name: strings.TrimSpace(b.Name), Url: clean, TokenEnc: h.box.Seal(token),
		TlsSkipVerify: b.TLSSkipVerify, AllowInternal: b.AllowInternal,
		Description: strings.TrimSpace(b.Description),
	})
	if isUniqueViolation(err) {
		return nil, fieldError("body.name", "A DNS server with this name already exists", b.Name)
	}
	if err != nil {
		return nil, internalError(err)
	}
	return &DNSServerOutput{Body: toDNSServer(s)}, nil
}

func (h *dnsHandler) update(ctx context.Context, in *struct {
	DNSServerIDPath
	Body DNSServerBody
}) (*DNSServerOutput, error) {
	p := principalOf(ctx)
	b := in.Body
	prev, _, err := h.withDNS(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	clean, err := cleanDNSURL(b.URL)
	if err != nil {
		return nil, err
	}
	if err := allowInternal(p, &prev, clean, b.AllowInternal); err != nil {
		return nil, err
	}
	token, err := h.resolveToken(&prev, clean, strings.TrimSpace(b.Token))
	if err != nil {
		return nil, err
	}
	s, err := h.q.UpdateDNSServer(ctx, sqlc.UpdateDNSServerParams{
		ID: prev.ID, Name: strings.TrimSpace(b.Name), Url: clean, TokenEnc: h.box.Seal(token),
		TlsSkipVerify: b.TLSSkipVerify, AllowInternal: b.AllowInternal,
		Description: strings.TrimSpace(b.Description),
	})
	if isUniqueViolation(err) {
		return nil, fieldError("body.name", "A DNS server with this name already exists", b.Name)
	}
	if err != nil {
		return nil, internalError(err)
	}
	return &DNSServerOutput{Body: toDNSServer(s)}, nil
}

type DNSTestBody struct {
	URL           string  `json:"url" minLength:"1" maxLength:"500"`
	Token         string  `json:"token,omitempty" maxLength:"500"`
	TLSSkipVerify bool    `json:"tls_skip_verify,omitempty"`
	AllowInternal bool    `json:"allow_internal,omitempty"`
	ServerID      *string `json:"server_id,omitempty" format:"uuid" doc:"When editing: the saved server, whose token a blank one stands for."`
}

type DNSTestOutput struct {
	Body struct {
		OK        bool   `json:"ok"`
		Status    string `json:"status"`
		Message   string `json:"message"`
		Version   string `json:"version"`
		Domain    string `json:"server_domain"`
		ZoneCount int    `json:"zone_count"`
		LatencyMs int64  `json:"latency_ms"`
	}
}

func (h *dnsHandler) test(ctx context.Context, in *struct{ Body DNSTestBody }) (*DNSTestOutput, error) {
	p := principalOf(ctx)
	b := in.Body
	var prev *sqlc.DnsServer
	if id := parseOptionalID(b.ServerID); id != nil {
		s, err := h.q.GetDNSServer(ctx, *id)
		if isNotFound(err) || (err == nil && p.Access.WorkspaceLevel(s.WorkspaceID) == auth.None) {
			return nil, huma.Error404NotFound("DNS server not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if p.Access.WorkspaceLevel(s.WorkspaceID) < auth.Owner {
			return nil, huma.Error403Forbidden("You need Owner access to use this server's saved token.")
		}
		prev = &s
	} else {
		ws, err := h.authz.createTarget(ctx, p)
		if err != nil {
			return nil, err
		}
		if p.Access.WorkspaceLevel(ws) < auth.Engineer {
			return nil, huma.Error403Forbidden("You need Engineer access to the workspace to add a DNS server.")
		}
	}
	clean, err := cleanDNSURL(b.URL)
	if err != nil {
		return nil, err
	}
	if err := allowInternal(p, prev, clean, b.AllowInternal); err != nil {
		return nil, err
	}
	token, err := h.resolveToken(prev, clean, strings.TrimSpace(b.Token))
	if err != nil {
		return nil, err
	}
	c := h.client(dnsConnection{clean, token, b.TLSSkipVerify, b.AllowInternal})
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	info, checkErr := c.Check(ctx)
	out := &DNSTestOutput{}
	out.Body.Status, out.Body.Message = dnsStatus(checkErr)
	out.Body.OK = checkErr == nil
	out.Body.Version, out.Body.Domain, out.Body.ZoneCount = info.Version, info.Domain, info.Zones
	out.Body.LatencyMs = info.Latency.Milliseconds()
	return out, nil
}

func registerDNS(api huma.API, h *dnsHandler) {
	tags := []string{"DNS"}

	huma.Register(api, huma.Operation{
		OperationID: "list-dns-servers", Method: http.MethodGet, Path: "/dns-servers",
		Summary: "List DNS servers", Description: "Favourites first, then by name.", Tags: tags,
	}, func(ctx context.Context, _ *struct{}) (*struct {
		Body struct {
			Items []DNSServer `json:"items"`
		}
	}, error) {
		sc := principalOf(ctx).scope()
		rows, err := h.q.ListDNSServers(ctx, sqlc.ListDNSServersParams{
			SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, WorkspaceID: sc.current,
		})
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []DNSServer `json:"items"`
			}
		}{}
		out.Body.Items = make([]DNSServer, 0, len(rows))
		for _, r := range rows {
			out.Body.Items = append(out.Body.Items, toDNSServer(r))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-dns-server", Method: http.MethodPost, Path: "/dns-servers",
		Summary: "Connect a DNS server", Tags: tags, DefaultStatus: http.StatusCreated,
	}, h.create)

	huma.Register(api, huma.Operation{
		OperationID: "test-dns-connection", Method: http.MethodPost, Path: "/dns-servers/test-connection",
		Summary:     "Test DNS server settings",
		Description: "Connects with the given settings without saving anything.", Tags: tags,
	}, h.test)

	huma.Register(api, huma.Operation{
		OperationID: "list-dns-zones-everywhere", Method: http.MethodGet, Path: "/dns-zones",
		Summary:     "Zones across every DNS server",
		Description: "Asks every server in scope at once. A server that doesn't answer is listed under problems, and the rest still come back.",
		Tags:        tags,
	}, func(ctx context.Context, _ *struct{}) (*DNSZonesEverywhereOutput, error) {
		sc := principalOf(ctx).scope()
		rows, err := h.q.ListDNSServers(ctx, sqlc.ListDNSServersParams{
			SeeAll: sc.seeAll, WorkspaceIds: sc.workspaces, WorkspaceID: sc.current,
		})
		if err != nil {
			return nil, internalError(err)
		}
		var (
			mu       sync.Mutex
			wg       sync.WaitGroup
			copies   []DNSZoneCopy
			problems = []DNSServerProblem{}
			sem      = make(chan struct{}, 8)
		)
		for _, s := range rows {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				zones, err := h.zonesOf(ctx, s)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					_, message := dnsStatus(err)
					problems = append(problems, DNSServerProblem{ServerID: s.ID.String(), ServerName: s.Name, Message: message})
					return
				}
				for _, z := range zones {
					copies = append(copies, DNSZoneCopy{ServerID: s.ID.String(), ServerName: s.Name, DNSZone: toDNSZone(z)})
				}
			}()
		}
		wg.Wait()
		slices.SortFunc(problems, func(a, b DNSServerProblem) int { return strings.Compare(a.ServerName, b.ServerName) })
		out := &DNSZonesEverywhereOutput{}
		out.Body.Zones = groupZones(copies)
		out.Body.Problems = problems
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-dns-server", Method: http.MethodGet, Path: "/dns-servers/{id}",
		Summary: "Get a DNS server", Tags: tags,
	}, func(ctx context.Context, in *struct{ DNSServerIDPath }) (*DNSServerOutput, error) {
		s, err := h.q.GetDNSServer(ctx, uuid.MustParse(in.ID))
		if isNotFound(err) {
			return nil, huma.Error404NotFound("DNS server not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &DNSServerOutput{Body: toDNSServer(s)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-dns-server", Method: http.MethodPut, Path: "/dns-servers/{id}",
		Summary: "Change a DNS server's connection", Tags: tags,
	}, h.update)

	huma.Register(api, huma.Operation{
		OperationID: "delete-dns-server", Method: http.MethodDelete, Path: "/dns-servers/{id}",
		Summary:     "Disconnect a DNS server",
		Description: "Morcheh forgets the connection and its token. Nothing on the DNS server changes.",
		Tags:        tags, DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *struct{ DNSServerIDPath }) (*struct{}, error) {
		if err := h.q.DeleteDNSServer(ctx, uuid.MustParse(in.ID)); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-dns-server-favorite", Method: http.MethodPut, Path: "/dns-servers/{id}/favorite",
		Summary: "Star or unstar a DNS server", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DNSServerIDPath
		Body struct {
			Favorite bool `json:"favorite"`
		}
	}) (*DNSServerOutput, error) {
		s, err := h.q.SetDNSServerFavorite(ctx, sqlc.SetDNSServerFavoriteParams{ID: uuid.MustParse(in.ID), Favorite: in.Body.Favorite})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("DNS server not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &DNSServerOutput{Body: toDNSServer(s)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "check-dns-server", Method: http.MethodPost, Path: "/dns-servers/{id}/check",
		Summary: "Check a DNS server's connection", Tags: tags,
	}, func(ctx context.Context, in *struct{ DNSServerIDPath }) (*DNSServerOutput, error) {
		s, c, err := h.withDNS(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		info, checkErr := c.Check(cctx)
		saved, err := h.record(ctx, s.ID, info, checkErr)
		if err != nil {
			return nil, internalError(err)
		}
		return &DNSServerOutput{Body: toDNSServer(saved)}, nil
	})

	type zonesOutput struct {
		Body struct {
			Items []DNSZone `json:"items"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "list-dns-zones", Method: http.MethodGet, Path: "/dns-servers/{id}/zones",
		Summary: "List a DNS server's zones", Description: "The server's built-in zones are left out.", Tags: tags,
	}, func(ctx context.Context, in *struct{ DNSServerIDPath }) (*zonesOutput, error) {
		_, c, err := h.withDNS(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		zones, err := c.ListZones(ctx)
		if err != nil {
			return nil, dnsError(err)
		}
		out := &zonesOutput{}
		out.Body.Items = make([]DNSZone, 0, len(zones))
		for _, z := range zones {
			out.Body.Items = append(out.Body.Items, toDNSZone(z))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "create-dns-zone", Method: http.MethodPost, Path: "/dns-servers/{id}/zones",
		Summary: "Create a zone", Tags: tags, DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		DNSServerIDPath
		Body struct {
			Name             string   `json:"name" minLength:"1" maxLength:"255" doc:"A domain, or an IP or network for a reverse zone"`
			Type             string   `json:"type" enum:"Primary,Secondary" doc:"Primary holds the records; Secondary copies them from a primary."`
			PrimaryAddresses []string `json:"primary_addresses,omitempty" maxItems:"10" doc:"Secondary: where to copy from. Blank asks the zone's SOA."`
		}
	}) (*struct {
		Body struct {
			Name string `json:"name"`
		}
	}, error) {
		_, c, err := h.withDNS(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		zone, err := cleanZone(in.Body.Name)
		if err != nil {
			return nil, fieldError("body.name", "Enter a domain like example.com, or a network like 10.0.0.0/24", in.Body.Name)
		}
		var primaries []string
		for _, a := range in.Body.PrimaryAddresses {
			if a = strings.TrimSpace(a); a != "" {
				primaries = append(primaries, a)
			}
		}
		if in.Body.Type != "Secondary" {
			primaries = nil
		}
		name, err := c.CreateZone(ctx, zone, in.Body.Type, primaries)
		if err != nil {
			return nil, dnsError(err)
		}
		out := &struct {
			Body struct {
				Name string `json:"name"`
			}
		}{}
		out.Body.Name = name
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-dns-zone", Method: http.MethodDelete, Path: "/dns-servers/{id}/zones/{zone}",
		Summary: "Delete a zone", Description: "Deletes it from the DNS server, with every record in it.",
		Tags: tags, DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *struct{ DNSZonePath }) (*struct{}, error) {
		_, c, zone, err := h.zoneRequest(ctx, in.DNSZonePath)
		if err != nil {
			return nil, err
		}
		if err := c.DeleteZone(ctx, zone); err != nil {
			return nil, dnsError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-dns-zone-enabled", Method: http.MethodPut, Path: "/dns-servers/{id}/zones/{zone}/enabled",
		Summary: "Enable or disable a zone", Description: "A disabled zone stays on the server but isn't answered for.",
		Tags: tags, DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body struct {
			Enabled bool `json:"enabled"`
		}
	}) (*struct{}, error) {
		_, c, zone, err := h.zoneRequest(ctx, in.DNSZonePath)
		if err != nil {
			return nil, err
		}
		if err := c.SetZoneEnabled(ctx, zone, in.Body.Enabled); err != nil {
			return nil, dnsError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-dns-records", Method: http.MethodGet, Path: "/dns-servers/{id}/zones/{zone}/records",
		Summary: "List a zone's records", Tags: tags,
	}, func(ctx context.Context, in *struct{ DNSZonePath }) (*DNSRecordsOutput, error) {
		_, c, zone, err := h.zoneRequest(ctx, in.DNSZonePath)
		if err != nil {
			return nil, err
		}
		return h.recordsOf(ctx, c, zone)
	})

	huma.Register(api, huma.Operation{
		OperationID: "add-dns-record", Method: http.MethodPost, Path: "/dns-servers/{id}/zones/{zone}/records",
		Summary: "Add a record", Description: "Answers with the zone's records, fresh.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body DNSRecordBody
	}) (*DNSRecordsOutput, error) {
		_, c, zone, err := h.zoneRequest(ctx, in.DNSZonePath)
		if err != nil {
			return nil, err
		}
		if err := in.Body.normalize(zone, "body"); err != nil {
			return nil, err
		}
		if err := c.AddRecord(ctx, in.Body.addForm(zone)); err != nil {
			return nil, dnsError(err)
		}
		// A new record can't be added disabled: that takes a second step.
		if in.Body.Disabled {
			if err := c.UpdateRecord(ctx, updateForm(zone, &in.Body, &in.Body)); err != nil {
				return nil, dnsError(err)
			}
		}
		return h.recordsOf(ctx, c, zone)
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-dns-record", Method: http.MethodPut, Path: "/dns-servers/{id}/zones/{zone}/records",
		Summary: "Change a record", Description: "`current` says which record, as it was read. Answers with the zone's records, fresh.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body struct {
			Current DNSRecordBody `json:"current"`
			New     DNSRecordBody `json:"new"`
		}
	}) (*DNSRecordsOutput, error) {
		_, c, zone, err := h.zoneRequest(ctx, in.DNSZonePath)
		if err != nil {
			return nil, err
		}
		cur, next := in.Body.Current, in.Body.New
		if err := cur.normalize(zone, "body.current"); err != nil {
			return nil, err
		}
		if err := next.normalize(zone, "body.new"); err != nil {
			return nil, err
		}
		if cur.Type != next.Type {
			return nil, fieldError("body.new.type", "A record's type can't change: add a new one and delete this", next.Type)
		}
		if err := c.UpdateRecord(ctx, updateForm(zone, &cur, &next)); err != nil {
			return nil, dnsError(err)
		}
		return h.recordsOf(ctx, c, zone)
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-dns-record", Method: http.MethodPost, Path: "/dns-servers/{id}/zones/{zone}/records/delete",
		Summary: "Delete a record", Description: "A POST because the record's data says which one. Answers with the zone's records, fresh.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body DNSRecordBody
	}) (*DNSRecordsOutput, error) {
		_, c, zone, err := h.zoneRequest(ctx, in.DNSZonePath)
		if err != nil {
			return nil, err
		}
		if err := in.Body.normalize(zone, "body"); err != nil {
			return nil, err
		}
		if err := c.DeleteRecord(ctx, deleteForm(zone, &in.Body)); err != nil {
			return nil, dnsError(err)
		}
		return h.recordsOf(ctx, c, zone)
	})
}

// zoneRequest is the start of every zone call: the server and a clean name.
func (h *dnsHandler) zoneRequest(ctx context.Context, path DNSZonePath) (sqlc.DnsServer, *technitium.Client, string, error) {
	s, c, err := h.withDNS(ctx, path.ID)
	if err != nil {
		return s, nil, "", err
	}
	zone, err := cleanZone(path.Zone)
	if err != nil {
		return s, nil, "", err
	}
	return s, c, zone, nil
}

func (h *dnsHandler) recordsOf(ctx context.Context, c *technitium.Client, zone string) (*DNSRecordsOutput, error) {
	z, raw, err := c.ListRecords(ctx, zone)
	if err != nil {
		return nil, dnsError(err)
	}
	out := &DNSRecordsOutput{}
	out.Body.Zone = toDNSZone(z)
	out.Body.Records = make([]DNSRecord, 0, len(raw))
	for _, r := range raw {
		out.Body.Records = append(out.Body.Records, toDNSRecord(r))
	}
	return out, nil
}

// zonesOf reads one server's zones for the view across servers, giving up
// soon so one dead server doesn't hold up the page.
func (h *dnsHandler) zonesOf(ctx context.Context, s sqlc.DnsServer) ([]technitium.Zone, error) {
	c, err := h.savedClient(s)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	return c.ListZones(ctx)
}
