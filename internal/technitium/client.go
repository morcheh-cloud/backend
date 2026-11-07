// Package technitium talks to a Technitium DNS Server over its HTTP API.
package technitium

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Dialer opens a network connection. The caller decides which addresses are
// allowed (see dbmon.DirectDialer).
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

type Config struct {
	URL        string
	Token      string
	SkipVerify bool
	Dial       Dialer
}

type Client struct {
	base  string
	token string
	http  *http.Client
}

// A big zone's records are large, but not endless.
const maxResponse = 64 << 20

func New(cfg Config) *Client {
	return &Client{
		base:  strings.TrimRight(cfg.URL, "/"),
		token: cfg.Token,
		http: &http.Client{
			Timeout: 30 * time.Second,
			// The token goes in a header: no redirect or proxy may carry it
			// somewhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				Proxy:               nil,
				DialContext:         cfg.Dial,
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.SkipVerify, MinVersion: tls.VersionTLS12}, //nolint:gosec // the owner's explicit choice for a self-signed certificate
				TLSHandshakeTimeout: 10 * time.Second,
				DisableKeepAlives:   true,
			},
		},
	}
}

// AuthError means the server refused the token.
type AuthError struct{ Message string }

func (e *AuthError) Error() string { return e.Message }

// APIError is the DNS server answering, and saying no: a bad value, a zone
// that doesn't exist. The message is the server's own.
type APIError struct{ Message string }

func (e *APIError) Error() string { return e.Message }

// NotDNSError means something answered that isn't a Technitium server.
type NotDNSError struct{ Detail string }

func (e *NotDNSError) Error() string {
	return "That address didn't answer like a Technitium DNS server (" + e.Detail + ")"
}

// call posts form data, and decodes the answer's body into out when it is ok.
func (c *Client) call(ctx context.Context, path string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return &NotDNSError{Detail: fmt.Sprintf("it redirects to %s", res.Header.Get("Location"))}
	}
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return &AuthError{Message: "The DNS server refused this API token"}
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponse))
	if err != nil {
		return err
	}
	var head struct {
		Status       string          `json:"status"`
		ErrorMessage string          `json:"errorMessage"`
		Response     json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(data, &head); err != nil || head.Status == "" {
		return &NotDNSError{Detail: "HTTP " + strconv.Itoa(res.StatusCode)}
	}
	switch head.Status {
	case "ok":
	case "invalid-token":
		return &AuthError{Message: "The API token isn't valid (or was deleted on the DNS server)"}
	case "2fa-required":
		return &AuthError{Message: "The DNS server asks for two-factor authentication: use an API token, not a session"}
	default:
		msg := head.ErrorMessage
		if msg == "" {
			msg = "The DNS server refused the request"
		}
		return &APIError{Message: msg}
	}
	if out == nil {
		return nil
	}
	// Session info sits at the top level, everything else under "response".
	if len(head.Response) > 0 {
		data = head.Response
	}
	return json.Unmarshal(data, out)
}

// Info is what a check learns about the server.
type Info struct {
	Version string
	Domain  string
	Zones   int
	Latency time.Duration
}

// Check proves the address and the token work, and that the token can read
// zones (a token without that would look fine until the first page opens).
func (c *Client) Check(ctx context.Context) (Info, error) {
	start := time.Now()
	var session struct {
		Info struct {
			Version         string `json:"version"`
			DNSServerDomain string `json:"dnsServerDomain"`
		} `json:"info"`
	}
	if err := c.call(ctx, "/api/user/session/get", url.Values{}, &session); err != nil {
		return Info{}, err
	}
	latency := time.Since(start)
	zones, err := c.ListZones(ctx)
	if err != nil {
		return Info{}, err
	}
	return Info{
		Version: session.Info.Version, Domain: session.Info.DNSServerDomain,
		Zones: len(zones), Latency: latency,
	}, nil
}

// Zone is one authoritative zone. Name is "." for the root zone.
type Zone struct {
	Name         string     `json:"name"`
	Type         string     `json:"type"`
	Internal     bool       `json:"internal"`
	DNSSECStatus string     `json:"dnssecStatus"`
	SOASerial    uint32     `json:"soaSerial"`
	Expiry       *time.Time `json:"expiry"`
	IsExpired    bool       `json:"isExpired"`
	SyncFailed   bool       `json:"syncFailed"`
	NotifyFailed bool       `json:"notifyFailed"`
	LastModified *time.Time `json:"lastModified"`
	Disabled     bool       `json:"disabled"`
}

// ListZones returns the zones people host here, leaving out the built-in ones
// every server has (localhost, the reverse zones of loopback…).
func (c *Client) ListZones(ctx context.Context) ([]Zone, error) {
	var out struct {
		Zones []Zone `json:"zones"`
	}
	if err := c.call(ctx, "/api/zones/list", url.Values{}, &out); err != nil {
		return nil, err
	}
	zones := make([]Zone, 0, len(out.Zones))
	for _, z := range out.Zones {
		if z.Internal {
			continue
		}
		z.Name = displayZone(z.Name)
		zones = append(zones, z)
	}
	return zones, nil
}

func displayZone(name string) string {
	if name == "" {
		return "."
	}
	return name
}

// apiZone is the root zone's name as the API wants it.
func apiZone(name string) string {
	if name == "." {
		return ""
	}
	return name
}

// CreateZone returns the zone's name as the server settled it: a network like
// 10.0.0.0/24 becomes its reverse zone.
func (c *Client) CreateZone(ctx context.Context, name, kind string, primaries []string) (string, error) {
	form := url.Values{"zone": {apiZone(name)}, "type": {kind}}
	if len(primaries) > 0 {
		form.Set("primaryNameServerAddresses", strings.Join(primaries, ","))
	}
	var out struct {
		Domain string `json:"domain"`
	}
	if err := c.call(ctx, "/api/zones/create", form, &out); err != nil {
		return "", err
	}
	return displayZone(out.Domain), nil
}

func (c *Client) DeleteZone(ctx context.Context, name string) error {
	return c.call(ctx, "/api/zones/delete", url.Values{"zone": {apiZone(name)}}, nil)
}

func (c *Client) SetZoneEnabled(ctx context.Context, name string, enabled bool) error {
	path := "/api/zones/disable"
	if enabled {
		path = "/api/zones/enable"
	}
	return c.call(ctx, path, url.Values{"zone": {apiZone(name)}}, nil)
}

// RawRecord is a record as the server sends it; RData differs by type.
type RawRecord struct {
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	TTL      int64          `json:"ttl"`
	Disabled bool           `json:"disabled"`
	Comments string         `json:"comments"`
	RData    map[string]any `json:"rData"`
}

// ListRecords returns the zone and every record in it.
// ZoneOptions is who may copy a zone and who hears about its changes, plus a
// Secondary's primaries.
type ZoneOptions struct {
	Type              string   `json:"type"`
	ZoneTransfer      string   `json:"zoneTransfer"`
	ZoneTransferACL   []string `json:"zoneTransferNetworkACL"`
	Notify            string   `json:"notify"`
	NotifyNameServers []string `json:"notifyNameServers"`
	PrimaryAddresses  []string `json:"primaryNameServerAddresses"`
	NotifyFailed      bool     `json:"notifyFailed"`
	NotifyFailedFor   []string `json:"notifyFailedFor"`
}

func (c *Client) ZoneOptions(ctx context.Context, zone string) (ZoneOptions, error) {
	var out ZoneOptions
	err := c.call(ctx, "/api/zones/options/get", url.Values{"zone": {apiZone(zone)}}, &out)
	return out, err
}

// SetZoneOptions sends the form as is, with the zone added. An empty list
// is sent as "false", which is how the API clears one.
func (c *Client) SetZoneOptions(ctx context.Context, zone string, form url.Values) error {
	form.Set("zone", apiZone(zone))
	return c.call(ctx, "/api/zones/options/set", form, nil)
}

// Resync makes a Secondary copy the zone again from its primary.
func (c *Client) Resync(ctx context.Context, zone string) error {
	return c.call(ctx, "/api/zones/resync", url.Values{"zone": {apiZone(zone)}}, nil)
}

func (c *Client) ListRecords(ctx context.Context, zone string) (Zone, []RawRecord, error) {
	name := apiZone(zone)
	var out struct {
		Zone    Zone        `json:"zone"`
		Records []RawRecord `json:"records"`
	}
	form := url.Values{"domain": {name}, "zone": {name}, "listZone": {"true"}}
	if err := c.call(ctx, "/api/zones/records/get", form, &out); err != nil {
		return Zone{}, nil, err
	}
	out.Zone.Name = displayZone(out.Zone.Name)
	return out.Zone, out.Records, nil
}

// AddRecord, UpdateRecord and DeleteRecord take the fields built by
// the API layer (see Record.values).

func (c *Client) AddRecord(ctx context.Context, form url.Values) error {
	return c.call(ctx, "/api/zones/records/add", form, nil)
}

func (c *Client) UpdateRecord(ctx context.Context, form url.Values) error {
	return c.call(ctx, "/api/zones/records/update", form, nil)
}

func (c *Client) DeleteRecord(ctx context.Context, form url.Values) error {
	return c.call(ctx, "/api/zones/records/delete", form, nil)
}

// Classify turns an error into one of the statuses a DNS server can be in, and
// a message a person can act on.
func Classify(err error) (string, string) {
	if err == nil {
		return "online", ""
	}
	var (
		auth    *AuthError
		api     *APIError
		notDNS  *NotDNSError
		x509Err *tls.CertificateVerificationError
		netErr  net.Error
	)
	msg := err.Error()
	switch {
	case errors.As(err, &auth):
		return "auth_failed", msg
	case errors.As(err, &api), errors.As(err, &notDNS):
		return "error", msg
	case errors.As(err, &x509Err),
		strings.Contains(msg, "x509:"), strings.Contains(msg, "tls:"),
		strings.Contains(msg, "server gave HTTP response to HTTPS client"):
		return "tls_error", shortNetError(err)
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &netErr):
		return "unreachable", shortNetError(err)
	}
	return "error", shortNetError(err)
}

// shortNetError drops Go's `Post "https://…":` prefix.
func shortNetError(err error) string {
	var u *url.Error
	if errors.As(err, &u) {
		return u.Err.Error()
	}
	return err.Error()
}
