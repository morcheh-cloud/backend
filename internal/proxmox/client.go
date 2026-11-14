// Package proxmox talks to a Proxmox VE cluster through its HTTP API with an
// API token (PVEAPIToken). Nothing is installed on the cluster: Morche only
// keeps the address and the token.
//
// Every call goes to the one address that was saved. Any node of a cluster
// answers for all of them, and paths name the node a guest lives on.
package proxmox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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

// Config is how to reach a cluster.
type Config struct {
	// URL is the base address, like https://pve1.example.com:8006.
	URL string
	// TokenID is user@realm!tokenname; Secret is the token's UUID.
	TokenID, Secret string
	// Fingerprint pins the certificate (SHA-256, any case, colons or not).
	// When set the usual chain check is skipped: a self-signed cluster
	// certificate is the norm.
	Fingerprint string
	// SkipVerify accepts any certificate. Fingerprint is safer.
	SkipVerify bool
	// Dial opens connections (it refuses private addresses unless allowed).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Timeout for one request; 0 = 30 s.
	Timeout time.Duration
}

type Client struct {
	base string
	auth string
	http *http.Client
	cfg  Config
}

const maxBody = 64 << 20

// New builds a client. It never follows redirects and ignores proxy
// variables, so the token goes nowhere but the saved address.
func New(cfg Config) *Client {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         cfg.Dial,
		TLSClientConfig:     tlsConfig(cfg),
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	return &Client{
		base: strings.TrimRight(cfg.URL, "/") + "/api2/json",
		auth: "PVEAPIToken=" + cfg.TokenID + "=" + cfg.Secret,
		cfg:  cfg,
		http: &http.Client{
			Timeout:   timeout,
			Transport: tr,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// NormalizeFingerprint gives AA:BB:… upper case, or "" when raw isn't a
// SHA-256 fingerprint.
func NormalizeFingerprint(raw string) string {
	s := strings.ToUpper(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(raw)))
	if len(s) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(s); err != nil {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(s); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(s[i : i+2])
	}
	return b.String()
}

// FingerprintOf is a certificate's SHA-256 fingerprint as AA:BB:….
func FingerprintOf(der []byte) string {
	sum := sha256.Sum256(der)
	return NormalizeFingerprint(hex.EncodeToString(sum[:]))
}

// FingerprintError says the certificate isn't the pinned one.
type FingerprintError struct{ Got string }

func (e *FingerprintError) Error() string {
	return "the certificate's fingerprint changed (now " + e.Got + ")"
}

func tlsConfig(cfg Config) *tls.Config {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	if pin := NormalizeFingerprint(cfg.Fingerprint); pin != "" {
		c.InsecureSkipVerify = true
		c.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("tls: no certificate")
			}
			if got := FingerprintOf(raw[0]); got != pin {
				return &FingerprintError{Got: got}
			}
			return nil
		}
	} else if cfg.SkipVerify {
		c.InsecureSkipVerify = true
	}
	return c
}

// TLS is the client's TLS setup, for the console's websocket.
func (c *Client) TLS() *tls.Config { return tlsConfig(c.cfg) }

// HTTPClient is the client underneath (for websocket dials).
func (c *Client) HTTPClient() *http.Client { return c.http }

// AuthHeader is the Authorization value.
func (c *Client) AuthHeader() string { return c.auth }

// BaseURL is the API's base, ending in /api2/json.
func (c *Client) BaseURL() string { return c.base }

// PeekFingerprint connects without checking the certificate and gives its
// fingerprint, so a person can compare and pin it.
func PeekFingerprint(ctx context.Context, rawURL string, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" {
		return "", errors.New("not an https address")
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := dial(ctx, "tcp", host)
	if err != nil {
		return "", err
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}) //nolint:gosec // only reads the certificate
	if err := conn.HandshakeContext(ctx); err != nil {
		return "", err
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("no certificate")
	}
	return FingerprintOf(certs[0].Raw), nil
}

// Errors

// AuthError: the token was refused.
type AuthError struct{ Message string }

func (e *AuthError) Error() string { return "the API token was refused: " + e.Message }

// PermissionError: the token may not do this (Proxmox's privilege check).
type PermissionError struct{ Message string }

func (e *PermissionError) Error() string {
	return "the token isn't allowed to do this: " + e.Message
}

// APIError is Proxmox refusing a request: a bad value, a guest that's
// locked, a missing VM. Fields holds per-parameter problems.
type APIError struct {
	Status  int
	Message string
	Fields  map[string]string
}

func (e *APIError) Error() string {
	if len(e.Fields) > 0 {
		parts := make([]string, 0, len(e.Fields))
		for k, v := range e.Fields {
			parts = append(parts, k+": "+strings.TrimSpace(v))
		}
		return strings.TrimSpace(e.Message + " (" + strings.Join(parts, "; ") + ")")
	}
	return e.Message
}

// NotProxmoxError: something answered that isn't a Proxmox API.
type NotProxmoxError struct{ Message string }

func (e *NotProxmoxError) Error() string { return e.Message }

// Requests

func (c *Client) do(ctx context.Context, method, path string, params url.Values, out any) error {
	full := c.base + path
	var body io.Reader
	if method == http.MethodGet || method == http.MethodDelete {
		if len(params) > 0 {
			full += "?" + encode(params)
		}
	} else if params != nil {
		body = strings.NewReader(encode(params))
	}
	req, err := http.NewRequestWithContext(ctx, method, full, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.auth)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return c.send(req, out)
}

// encode is url.Values.Encode with %20 for spaces, which Proxmox wants in a
// few places (sshkeys are checked after one round of decoding).
func encode(v url.Values) string {
	return strings.ReplaceAll(v.Encode(), "+", "%20")
}

func (c *Client) send(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	return c.decode(resp, out)
}

func (c *Client) decode(resp *http.Response, out any) error {
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	// Proxmox puts the reason in the status line, e.g. "500 VM 100 not running".
	reason := strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode)))
	var env struct {
		Data   json.RawMessage   `json:"data"`
		Errors map[string]string `json:"errors"`
		Msg    string            `json:"message"`
	}
	jsonErr := json.Unmarshal(raw, &env)
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return &AuthError{Message: firstOf(reason, "authentication failure")}
	case resp.StatusCode == http.StatusForbidden:
		return &PermissionError{Message: firstOf(env.Msg, reason, "permission denied")}
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return &NotProxmoxError{Message: fmt.Sprintf("the address redirects (%d): it isn't the Proxmox API", resp.StatusCode)}
	case resp.StatusCode >= 400:
		if jsonErr != nil && resp.StatusCode == http.StatusNotFound {
			return &NotProxmoxError{Message: "this address has no Proxmox API (404)"}
		}
		msg := firstOf(env.Msg, reason, resp.Status)
		return &APIError{Status: resp.StatusCode, Message: strings.TrimSpace(msg), Fields: env.Errors}
	}
	if jsonErr != nil {
		return &NotProxmoxError{Message: "the answer isn't Proxmox's JSON"}
	}
	if out == nil || len(env.Data) == 0 || string(env.Data) == "null" {
		return nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("read the answer: %w", err)
	}
	return nil
}

func firstOf(s ...string) string {
	for _, v := range s {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func (c *Client) get(ctx context.Context, path string, q url.Values, out any) error {
	return c.do(ctx, http.MethodGet, path, q, out)
}

func (c *Client) post(ctx context.Context, path string, form url.Values, out any) error {
	if form == nil {
		form = url.Values{}
	}
	return c.do(ctx, http.MethodPost, path, form, out)
}

func (c *Client) put(ctx context.Context, path string, form url.Values, out any) error {
	if form == nil {
		form = url.Values{}
	}
	return c.do(ctx, http.MethodPut, path, form, out)
}

func (c *Client) del(ctx context.Context, path string, q url.Values, out any) error {
	return c.do(ctx, http.MethodDelete, path, q, out)
}

// upid runs a call that answers with a task id (or nothing, for the calls
// that finish at once).
func (c *Client) upid(ctx context.Context, method, path string, form url.Values) (string, error) {
	var out any
	if err := c.do(ctx, method, path, form, &out); err != nil {
		return "", err
	}
	if s, ok := out.(string); ok {
		return s, nil
	}
	return "", nil
}

// Classify sums up a failed (or not) request for the connection's status.
func Classify(err error) (string, string) {
	if err == nil {
		return "online", ""
	}
	var auth *AuthError
	var perm *PermissionError
	var api *APIError
	var notPVE *NotProxmoxError
	var fp *FingerprintError
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	switch {
	case errors.As(err, &auth):
		return "auth_failed", auth.Error()
	case errors.As(err, &perm):
		return "auth_failed", perm.Error()
	case errors.As(err, &fp):
		return "tls_error", fp.Error()
	case errors.As(err, &cert), errors.As(err, &unknown), errors.As(err, &host):
		return "tls_error", "the certificate isn't trusted: pin its fingerprint, or skip the check"
	case errors.As(err, &api):
		return "error", api.Error()
	case errors.As(err, &notPVE):
		return "error", notPVE.Error()
	}
	msg := shortNetError(err)
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "x509:") || strings.Contains(low, "tls:") ||
		strings.Contains(low, "server gave http response to https client"):
		return "tls_error", msg
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, context.DeadlineExceeded):
		return "unreachable", msg
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return "unreachable", msg
	}
	return "error", msg
}

func shortNetError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return err.Error()
}

// IsMissing says Proxmox answered that the guest, snapshot or volume
// doesn't exist.
func IsMissing(err error) bool {
	var api *APIError
	if !errors.As(err, &api) {
		return false
	}
	m := strings.ToLower(api.Message)
	return api.Status == http.StatusNotFound || strings.Contains(m, "does not exist") ||
		strings.Contains(m, "not exist") || strings.Contains(m, "no such")
}

// Values

// Num reads a number Proxmox may send as a number, a string or a bool.
func Num(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case json.Number:
		f, _ := x.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f
	case bool:
		if x {
			return 1
		}
	}
	return 0
}

// Str reads a value as text.
func Str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		if x {
			return "1"
		}
		return "0"
	}
	b, _ := json.Marshal(v)
	return string(bytes.Trim(b, `"`))
}
