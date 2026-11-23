package dbmon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPDB talks to a database that speaks JSON over HTTP (Elasticsearch,
// OpenSearch, Meilisearch), through cfg's dialer, so a tunnel through a
// server and the direct-address guard both apply.
type HTTPDB struct {
	cfg    Config
	base   string
	client *http.Client
	auth   string
}

// HTTPError is an answer outside 2xx.
type HTTPError struct {
	Status int
	// The engine's own error type (Elasticsearch error.type, Meilisearch code).
	Code    string
	Message string
}

func (e *HTTPError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("the database answered %d", e.Status)
}

// HTTPStatus is the status of an HTTPError, 0 for any other error.
func HTTPStatus(err error) int {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Status
	}
	return 0
}

// OpenHTTP prepares a client; it doesn't connect yet. ES takes a username +
// password (basic) or, with no username, an API key; Meilisearch takes the
// key as a bearer token.
func OpenHTTP(cfg Config) (*HTTPDB, error) {
	tc, err := cfg.tlsConfig()
	if err != nil {
		return nil, err
	}
	dial := cfg.dialer()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dial(ctx, network, addr)
		},
		TLSClientConfig:       tc,
		ForceAttemptHTTP2:     false,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 5 * time.Minute,
		Proxy:                 nil,
	}
	scheme := "http"
	if tc != nil {
		scheme = "https"
	}
	h := &HTTPDB{
		cfg:    cfg,
		base:   scheme + "://" + cfg.addr(),
		client: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	switch {
	case cfg.Engine == Meili && cfg.Password != "":
		h.auth = "Bearer " + cfg.Password
	case cfg.Username != "":
		h.auth = "Basic " + basicAuth(cfg.Username, cfg.Password)
	case cfg.Password != "":
		h.auth = "ApiKey " + cfg.Password
	}
	return h, nil
}

func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

// Close drops idle connections.
func (h *HTTPDB) Close() error {
	h.client.CloseIdleConnections()
	return nil
}

// Path joins escaped segments: Path("idx", "_doc", id) = "/idx/_doc/<id>".
func Path(seg ...string) string {
	var b strings.Builder
	for _, s := range seg {
		b.WriteByte('/')
		b.WriteString(url.PathEscape(s))
	}
	return b.String()
}

// Do sends one request. body may be nil, []byte, string, an io.Reader or a
// value marshalled as JSON. path starts with / and may carry a query.
// contentType empty = application/json.
func (h *HTTPDB) Do(ctx context.Context, method, path string, body any, contentType string) (*http.Response, error) {
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		r = bytes.NewReader(b)
	case string:
		r = strings.NewReader(b)
	case io.Reader:
		r = b
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.base+path, r)
	if err != nil {
		return nil, err
	}
	if r != nil {
		req.Header.Set("Content-Type", cmp(contentType, "application/json"))
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "morche")
	if h.auth != "" {
		req.Header.Set("Authorization", h.auth)
	}
	res, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		defer res.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		return nil, httpError(res.StatusCode, raw)
	}
	return res, nil
}

// JSON sends a request and decodes the answer into out (nil = drop it).
func (h *HTTPDB) JSON(ctx context.Context, method, path string, body, out any) error {
	res, err := h.Do(ctx, method, path, body, "")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if out == nil {
		_, _ = io.Copy(io.Discard, res.Body)
		return nil
	}
	dec := json.NewDecoder(res.Body)
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("couldn't read the answer: %w", err)
	}
	return nil
}

// Raw sends a request and returns the whole answer (status < 300), at most
// limit bytes.
func (h *HTTPDB) Raw(ctx context.Context, method, path string, body any, limit int64) ([]byte, error) {
	res, err := h.Do(ctx, method, path, body, "")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return io.ReadAll(io.LimitReader(res.Body, limit))
}

// httpError reads the engine's error body: Elasticsearch
// {"error":{"type","reason"}} or {"error":"text"}, Meilisearch
// {"message","code"}.
func httpError(status int, raw []byte) error {
	e := &HTTPError{Status: status}
	var es struct {
		Error json.RawMessage `json:"error"`
	}
	var ms struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	}
	if json.Unmarshal(raw, &ms) == nil && ms.Message != "" {
		e.Message, e.Code = ms.Message, ms.Code
	} else if json.Unmarshal(raw, &es) == nil && len(es.Error) > 0 {
		var obj struct {
			Type      string `json:"type"`
			Reason    string `json:"reason"`
			RootCause []struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"root_cause"`
		}
		var text string
		if json.Unmarshal(es.Error, &obj) == nil && (obj.Type != "" || obj.Reason != "") {
			e.Code, e.Message = obj.Type, obj.Reason
			if e.Message == "" && len(obj.RootCause) > 0 {
				e.Message = obj.RootCause[0].Reason
			}
		} else if json.Unmarshal(es.Error, &text) == nil {
			e.Message = text
		}
	}
	if e.Message == "" {
		t := strings.TrimSpace(string(raw))
		if len(t) > 300 {
			t = t[:300]
		}
		if t != "" && !strings.HasPrefix(t, "<") {
			e.Message = fmt.Sprintf("%d: %s", status, t)
		}
	}
	switch status {
	case http.StatusUnauthorized:
		if e.Message == "" {
			e.Message = "The username, password or key was refused."
		}
	case http.StatusForbidden:
		if e.Message == "" {
			e.Message = "The login isn't allowed to do that."
		}
	}
	return e
}

func engineAuthErrorHTTP(err error) bool {
	var he *HTTPError
	if !errors.As(err, &he) {
		return false
	}
	return he.Status == http.StatusUnauthorized ||
		he.Code == "invalid_api_key" || he.Code == "missing_authorization_header"
}
