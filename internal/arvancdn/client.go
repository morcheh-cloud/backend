// Package arvancdn talks to ArvanCloud's CDN API 4.0
// (https://napi.arvancloud.ir/cdn/4.0) with an API key: domains, their DNS
// records and the CDN settings Morche shows (HTTPS, caching, redirects,
// acceleration, traffic reports). Errors use the cloud package's types, so
// one Classify covers the IaaS and CDN clients.
package arvancdn

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/morche/backend/internal/cloud"
)

// DefaultBase is the API's address.
const DefaultBase = "https://napi.arvancloud.ir/cdn/4.0"

const (
	maxBody  = 16 << 20
	perPage  = 100
	maxPages = 50
)

// Config is how to reach ArvanCloud.
type Config struct {
	// Key is the API key, with or without its "Apikey " prefix.
	Key string
	// Dial opens connections.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// BaseURL overrides DefaultBase (the fake, tests).
	BaseURL string
	// Timeout for one request; 0 = 20 s.
	Timeout time.Duration
}

type Client struct {
	key  string
	base string
	http *http.Client
}

// CleanKey takes the key as pasted: "Apikey xxxx" or just "xxxx".
func CleanKey(raw string) string {
	s := strings.TrimSpace(raw)
	if len(s) > 7 && strings.EqualFold(s[:7], "apikey ") {
		s = strings.TrimSpace(s[7:])
	}
	return s
}

// New builds a client. It never follows redirects and ignores proxy
// variables, so the key goes nowhere but ArvanCloud.
func New(cfg Config) *Client {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = DefaultBase
	}
	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         cfg.Dial,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	return &Client{
		key:  CleanKey(cfg.Key),
		base: base,
		http: &http.Client{
			Timeout:   timeout,
			Transport: tr,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// FieldError is one of ArvanCloud's reasons for refusing a value.
type FieldError struct {
	Field   string
	Message string
}

// ValidationError is a 422: the message plus the fields it names.
type ValidationError struct {
	Message string
	Fields  []FieldError
}

func (e *ValidationError) Error() string {
	msg := e.Message
	for _, f := range e.Fields {
		if f.Message != "" && !strings.Contains(msg, f.Message) {
			if msg != "" {
				msg += " "
			}
			msg += f.Message
		}
	}
	if msg == "" {
		msg = "ArvanCloud refused the values"
	}
	return msg
}

type request struct {
	method string
	path   string
	query  url.Values
	body   any
	// raw sends this body as is, with its content type.
	raw         []byte
	contentType string
}

func (c *Client) send(ctx context.Context, r request) ([]byte, error) {
	u := c.base + r.path
	if len(r.query) > 0 {
		u += "?" + r.query.Encode()
	}
	var rd io.Reader
	ct := r.contentType
	switch {
	case r.raw != nil:
		rd = bytes.NewReader(r.raw)
	case r.body != nil:
		b, err := json.Marshal(r.body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
		ct = "application/json"
	}
	req, err := http.NewRequestWithContext(ctx, r.method, u, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Apikey "+c.key)
	req.Header.Set("Accept", "application/json")
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		return nil, apiError(res.StatusCode, raw)
	}
	return raw, nil
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	raw, err := c.send(ctx, request{method: method, path: path, query: query, body: body})
	if err != nil {
		return err
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return &cloud.APIError{Status: http.StatusBadGateway, Message: "ArvanCloud sent an answer Morche can't read"}
	}
	return nil
}

type errorBody struct {
	Message string          `json:"message"`
	Errors  json.RawMessage `json:"errors"`
}

// fieldErrors reads the errors in any of the shapes the API uses:
// {"field": ["a", "b"]}, {"field": "a"}, [["a"]] or ["a"].
func fieldErrors(raw json.RawMessage) []FieldError {
	if len(raw) == 0 {
		return nil
	}
	var out []FieldError
	var byField map[string]json.RawMessage
	if json.Unmarshal(raw, &byField) == nil {
		for field, v := range byField {
			for _, m := range flatStrings(v) {
				out = append(out, FieldError{Field: field, Message: m})
			}
		}
		return out
	}
	for _, m := range flatStrings(raw) {
		out = append(out, FieldError{Message: m})
	}
	return out
}

func flatStrings(raw json.RawMessage) []string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []string{s}
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	var out []string
	for _, item := range list {
		out = append(out, flatStrings(item)...)
	}
	return out
}

func apiError(status int, raw []byte) error {
	var eb errorBody
	_ = json.Unmarshal(raw, &eb)
	msg := strings.TrimSpace(eb.Message)
	switch status {
	case http.StatusUnauthorized:
		return &cloud.AuthError{Message: "ArvanCloud refused the API key"}
	case http.StatusForbidden:
		if msg == "" {
			msg = "not allowed"
		}
		return &cloud.PermissionError{Message: "ArvanCloud: " + msg + ". Check the key's access policy in the ArvanCloud panel."}
	case http.StatusNotFound:
		if msg == "" {
			msg = "not found"
		}
		return &cloud.NotFoundError{Message: "ArvanCloud: " + msg}
	case http.StatusUnprocessableEntity, http.StatusBadRequest, http.StatusConflict:
		return &ValidationError{Message: msg, Fields: fieldErrors(eb.Errors)}
	case http.StatusTooManyRequests:
		return &cloud.APIError{Status: status, Message: "ArvanCloud: too many requests, try again in a minute"}
	}
	if msg == "" {
		msg = "HTTP " + strconv.Itoa(status)
	}
	return &cloud.APIError{Status: status, Message: "ArvanCloud: " + msg}
}

type page struct {
	Meta struct {
		CurrentPage int `json:"current_page"`
		LastPage    int `json:"last_page"`
		Total       int `json:"total"`
	} `json:"meta"`
}

// all reads every page of a list.
func all[T any](ctx context.Context, c *Client, path string, query url.Values) ([]T, error) {
	var out []T
	for p := 1; p <= maxPages; p++ {
		q := url.Values{}
		for k, v := range query {
			q[k] = v
		}
		q.Set("page", strconv.Itoa(p))
		q.Set("per_page", strconv.Itoa(perPage))
		var res struct {
			page
			Data []T `json:"data"`
		}
		if err := c.do(ctx, http.MethodGet, path, q, nil, &res); err != nil {
			return nil, err
		}
		out = append(out, res.Data...)
		if res.Meta.LastPage <= p || len(res.Data) == 0 {
			break
		}
	}
	return out, nil
}

func domainPath(domain string, rest ...string) string {
	p := "/domains/" + url.PathEscape(domain)
	for _, r := range rest {
		p += "/" + r
	}
	return p
}

// Domains

// Domain is one domain on the account.
type Domain struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Type        string     `json:"type"`
	Status      string     `json:"status"`
	PlanLevel   int        `json:"plan_level"`
	NSKeys      []string   `json:"ns_keys"`
	CurrentNS   []string   `json:"current_ns"`
	CNAMETarget *string    `json:"cname_target"`
	CustomCNAME *string    `json:"custom_cname"`
	DNSCloud    bool       `json:"dns_cloud"`
	Restriction []string   `json:"restriction"`
	CreatedAt   *time.Time `json:"created_at"`
	UpdatedAt   *time.Time `json:"updated_at"`
}

// Info is what a check finds.
type Info struct {
	Domains int
	Latency time.Duration
}

// Check proves the key works and can read domains.
func (c *Client) Check(ctx context.Context) (Info, error) {
	start := time.Now()
	var res struct {
		page
		Data []Domain `json:"data"`
	}
	q := url.Values{"per_page": {"1"}}
	if err := c.do(ctx, http.MethodGet, "/domains", q, nil, &res); err != nil {
		return Info{}, err
	}
	n := res.Meta.Total
	if n == 0 {
		n = len(res.Data)
	}
	return Info{Domains: n, Latency: time.Since(start)}, nil
}

func (c *Client) Domains(ctx context.Context) ([]Domain, error) {
	return all[Domain](ctx, c, "/domains", nil)
}

func (c *Client) Domain(ctx context.Context, name string) (Domain, error) {
	var res struct {
		Data Domain `json:"data"`
	}
	err := c.do(ctx, http.MethodGet, domainPath(name), nil, nil, &res)
	return res.Data, err
}

// CreateDomain adds a domain: full = ArvanCloud answers for the whole zone
// (its nameservers), partial = only chosen names point at it by CNAME.
func (c *Client) CreateDomain(ctx context.Context, name, kind string, importRecords bool) (Domain, error) {
	body := map[string]any{"domain": name, "domain_type": kind, "import_dns_records": importRecords}
	var res struct {
		Data Domain `json:"data"`
	}
	err := c.do(ctx, http.MethodPost, "/domains/dns-service", nil, body, &res)
	return res.Data, err
}

// DeleteDomain removes the domain and its settings from the account. The API
// wants the domain's id as a confirmation.
func (c *Client) DeleteDomain(ctx context.Context, name, id string) error {
	return c.do(ctx, http.MethodDelete, domainPath(name), url.Values{"id": {id}}, nil, nil)
}

// NSCheck asks ArvanCloud to look at the domain's nameservers again.
type NSCheck struct {
	NSDomain []string `json:"ns_domain"`
	NSKeys   []string `json:"ns_keys"`
}

func (c *Client) CheckNS(ctx context.Context, name string) (NSCheck, error) {
	var res struct {
		Data NSCheck `json:"data"`
	}
	err := c.do(ctx, http.MethodGet, domainPath(name, "ns-keys", "check"), nil, nil, &res)
	return res.Data, err
}

// CheckCNAME asks ArvanCloud to look at a partial domain's CNAME again.
func (c *Client) CheckCNAME(ctx context.Context, name string) (Domain, error) {
	var res struct {
		Data Domain `json:"data"`
	}
	err := c.do(ctx, http.MethodGet, domainPath(name, "cname-setup", "check"), nil, nil, &res)
	return res.Data, err
}

// DNS records

// IPFilter is how a record with several addresses answers.
type IPFilter struct {
	Count     string `json:"count,omitempty"`
	Order     string `json:"order,omitempty"`
	GeoFilter string `json:"geo_filter,omitempty"`
}

// Record is a record as the API has it; Value's shape depends on Type
// (an array of addresses for a/aaaa, an object for the rest).
type Record struct {
	ID            string          `json:"id,omitempty"`
	Type          string          `json:"type"`
	Name          string          `json:"name"`
	TTL           int             `json:"ttl,omitempty"`
	Cloud         bool            `json:"cloud"`
	UpstreamHTTPS string          `json:"upstream_https,omitempty"`
	IPFilterMode  *IPFilter       `json:"ip_filter_mode,omitempty"`
	IsProtected   bool            `json:"is_protected,omitempty"`
	Usage         []string        `json:"usage,omitempty"`
	Value         json.RawMessage `json:"value"`
	CreatedAt     *time.Time      `json:"created_at,omitempty"`
	UpdatedAt     *time.Time      `json:"updated_at,omitempty"`
}

func (c *Client) Records(ctx context.Context, domain string) ([]Record, error) {
	return all[Record](ctx, c, domainPath(domain, "dns-records"), nil)
}

// writable is a record as sent: no read-only fields.
func writable(r Record) map[string]any {
	out := map[string]any{"type": r.Type, "name": r.Name, "value": r.Value, "cloud": r.Cloud}
	if r.TTL > 0 {
		out["ttl"] = r.TTL
	}
	if r.UpstreamHTTPS != "" {
		out["upstream_https"] = r.UpstreamHTTPS
	}
	if r.IPFilterMode != nil {
		out["ip_filter_mode"] = r.IPFilterMode
	}
	return out
}

func (c *Client) CreateRecord(ctx context.Context, domain string, r Record) (Record, error) {
	var res struct {
		Data Record `json:"data"`
	}
	err := c.do(ctx, http.MethodPost, domainPath(domain, "dns-records"), nil, writable(r), &res)
	return res.Data, err
}

func (c *Client) UpdateRecord(ctx context.Context, domain, id string, r Record) (Record, error) {
	var res struct {
		Data Record `json:"data"`
	}
	err := c.do(ctx, http.MethodPut, domainPath(domain, "dns-records", url.PathEscape(id)), nil, writable(r), &res)
	return res.Data, err
}

func (c *Client) DeleteRecord(ctx context.Context, domain, id string) error {
	return c.do(ctx, http.MethodDelete, domainPath(domain, "dns-records", url.PathEscape(id)), nil, nil, nil)
}

// SetCloud turns the CDN on or off for one record.
func (c *Client) SetCloud(ctx context.Context, domain, id string, on bool) (Record, error) {
	var res struct {
		Data Record `json:"data"`
	}
	err := c.do(ctx, http.MethodPut, domainPath(domain, "dns-records", url.PathEscape(id), "cloud"), nil, map[string]bool{"cloud": on}, &res)
	return res.Data, err
}

// DNSSEC is the domain's DNSSEC state; DS is the record for the registrar.
type DNSSEC struct {
	Enabled bool    `json:"enabled"`
	DS      *string `json:"ds"`
}

func (c *Client) DNSSEC(ctx context.Context, domain string) (DNSSEC, error) {
	var res struct {
		Data DNSSEC `json:"data"`
	}
	err := c.do(ctx, http.MethodGet, domainPath(domain, "dns-records", "dnssec"), nil, nil, &res)
	return res.Data, err
}

func (c *Client) SetDNSSEC(ctx context.Context, domain string, enable bool) (DNSSEC, error) {
	var res struct {
		Data DNSSEC `json:"data"`
	}
	err := c.do(ctx, http.MethodPut, domainPath(domain, "dns-records", "dnssec", "actions"), nil, map[string]bool{"enable": enable}, &res)
	return res.Data, err
}

// Export returns the zone as a BIND file.
func (c *Client) Export(ctx context.Context, domain string) ([]byte, error) {
	return c.send(ctx, request{method: http.MethodGet, path: domainPath(domain, "dns-records", "export")})
}

// Import adds the records of a BIND file.
func (c *Client) Import(ctx context.Context, domain string, zoneFile []byte) error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("f_zone_file", "zone.txt")
	if err != nil {
		return err
	}
	if _, err := part.Write(zoneFile); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	_, err = c.send(ctx, request{method: http.MethodPost, path: domainPath(domain, "dns-records", "import"), raw: buf.Bytes(), contentType: w.FormDataContentType()})
	return err
}

// Settings. Each is read and changed whole as JSON; the api package owns the
// shapes, so the client just carries them.

func (c *Client) getData(ctx context.Context, path string, out any) error {
	var res struct {
		Data json.RawMessage `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, nil, &res); err != nil {
		return err
	}
	if len(res.Data) == 0 || string(res.Data) == "null" {
		return nil
	}
	if err := json.Unmarshal(res.Data, out); err != nil {
		return &cloud.APIError{Status: http.StatusBadGateway, Message: "ArvanCloud sent an answer Morche can't read"}
	}
	return nil
}

func (c *Client) setData(ctx context.Context, method, path string, body, out any) error {
	var res struct {
		Data json.RawMessage `json:"data"`
	}
	if err := c.do(ctx, method, path, nil, body, &res); err != nil {
		return err
	}
	if out == nil || len(res.Data) == 0 || string(res.Data) == "null" {
		return nil
	}
	if err := json.Unmarshal(res.Data, out); err != nil {
		return &cloud.APIError{Status: http.StatusBadGateway, Message: "ArvanCloud sent an answer Morche can't read"}
	}
	return nil
}

// Setting names a settings endpoint and how it's changed.
type Setting struct {
	Path   string
	Method string
}

var (
	SettingSSL          = Setting{"ssl", http.MethodPatch}
	SettingCaching      = Setting{"caching", http.MethodPatch}
	SettingRedirect     = Setting{"settings/www-redirect", http.MethodPut}
	SettingAcceleration = Setting{"acceleration", http.MethodPatch}
)

func (c *Client) GetSetting(ctx context.Context, domain string, s Setting, out any) error {
	return c.getData(ctx, domainPath(domain, s.Path), out)
}

// SetSetting sends the changed fields; out gets what ArvanCloud answers,
// which some endpoints leave empty (read it again then).
func (c *Client) SetSetting(ctx context.Context, domain string, s Setting, body, out any) error {
	return c.setData(ctx, s.Method, domainPath(domain, s.Path), body, out)
}

// IssueCertificate asks for a free certificate for the domain.
func (c *Client) IssueCertificate(ctx context.Context, domain, provider string) error {
	body := map[string]string{}
	if provider != "" {
		body["provider"] = provider
	}
	return c.do(ctx, http.MethodPost, domainPath(domain, "ssl", "issue"), nil, body, nil)
}

// Purge empties the CDN cache: everything, or the given addresses (≤ 50).
func (c *Client) Purge(ctx context.Context, domain string, urls []string) error {
	body := map[string]any{"purge": "all"}
	if len(urls) > 0 {
		body = map[string]any{"purge": "individual", "purge_urls": urls}
	}
	return c.do(ctx, http.MethodPost, domainPath(domain, "caching", "purge"), nil, body, nil)
}

// Reports

// Chart is one chart: times and, per series name, a value for each time.
type Chart struct {
	Categories []string `json:"categories"`
	Series     []struct {
		Name string  `json:"name"`
		Data []int64 `json:"data"`
	} `json:"series"`
}

// Totals is a report's sums.
type Totals struct {
	Total int64 `json:"total"`
	Saved int64 `json:"saved"`
}

// Traffic is the traffic report: requests and bytes, total vs served from the
// cache.
type Traffic struct {
	Statistics struct {
		Traffics Totals `json:"traffics"`
		Requests Totals `json:"requests"`
	} `json:"statistics"`
	Charts struct {
		Requests Chart `json:"requests"`
		Traffics Chart `json:"traffics"`
	} `json:"charts"`
}

func (c *Client) Traffic(ctx context.Context, domain, period string) (Traffic, error) {
	var out Traffic
	err := c.getData(ctx, domainPath(domain, "reports", "traffics")+"?period="+url.QueryEscape(period), &out)
	return out, err
}

// StatusCount is one status code's share.
type StatusCount struct {
	Name string `json:"name"`
	Y    int64  `json:"y"`
}

func (c *Client) StatusSummary(ctx context.Context, domain, period string) ([]StatusCount, error) {
	var out struct {
		Charts struct {
			StatusCode []StatusCount `json:"status_code"`
		} `json:"charts"`
	}
	err := c.getData(ctx, domainPath(domain, "reports", "status", "summary")+"?period="+url.QueryEscape(period), &out)
	return out.Charts.StatusCode, err
}

// String is a helper for the fake and tests.
func (r Record) String() string { return fmt.Sprintf("%s %s %s", r.Type, r.Name, r.Value) }

// Security (firewall, WAF, rate limiting): lists, writes and order, carried
// as raw JSON; the api package owns the shapes.

// List reads every page of a domain's list, like "firewall/rules".
func (c *Client) List(ctx context.Context, domain, path string) ([]json.RawMessage, error) {
	return all[json.RawMessage](ctx, c, domainPath(domain, path), nil)
}

// Get reads one object answered under "data".
func (c *Client) Get(ctx context.Context, domain, path string, out any) error {
	return c.getData(ctx, domainPath(domain, path), out)
}

// Send writes to a domain's path; out gets what's under "data" (may be nil).
func (c *Client) Send(ctx context.Context, method, domain, path string, body, out any) error {
	return c.setData(ctx, method, domainPath(domain, path), body, out)
}

// Reprioritize moves a rule before or after another ("firewall" or
// "rate-limit"; WAF rules use "waf").
func (c *Client) Reprioritize(ctx context.Context, domain, kind, ruleID, beforeID, afterID string) error {
	body := map[string]string{"rule_id": ruleID}
	if beforeID != "" {
		body["before_rule_id"] = beforeID
	}
	if afterID != "" {
		body["after_rule_id"] = afterID
	}
	return c.do(ctx, http.MethodPost, domainPath(domain, kind, "actions", "reprioritize"), nil, body, nil)
}

// Account-wide lists (WAF packages on offer).
func (c *Client) GetAccount(ctx context.Context, path string, out any) error {
	return c.getData(ctx, "/"+strings.TrimPrefix(path, "/"), out)
}
