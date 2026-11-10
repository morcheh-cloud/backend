package uptime

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const bodyLimit = 1 << 20

func transport(c MonitorConfig, env Env) *http.Transport {
	return &http.Transport{
		Proxy:               nil,
		DialContext:         env.Dial,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: c.IgnoreTLS, MinVersion: tls.VersionTLS10},
		TLSHandshakeTimeout: env.Timeout,
		ForceAttemptHTTP2:   true,
		DisableKeepAlives:   true,
	}
}

func httpClient(c MonitorConfig, env Env) *http.Client {
	return &http.Client{
		Transport: transport(c, env),
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if c.NoRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return errors.New("more than 10 redirects")
			}
			return nil
		},
	}
}

func setHeaders(req *http.Request, c MonitorConfig, s MonitorSecrets) {
	req.Header.Set("User-Agent", "Morcheh-Uptime/1.0")
	for k, v := range c.Headers {
		if k = strings.TrimSpace(k); k != "" {
			req.Header.Set(k, v)
		}
	}
	for k, v := range s.Headers {
		if k = strings.TrimSpace(k); k != "" {
			req.Header.Set(k, v)
		}
	}
	if c.Username != "" {
		req.SetBasicAuth(c.Username, s.Password)
	}
	if s.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.Token)
	}
}

// statusRange reads "200", "200-299" or "2xx".
func statusRange(s string) (int, int, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) == 3 && strings.HasSuffix(s, "xx") {
		d, err := strconv.Atoi(s[:1])
		if err != nil || d < 1 || d > 5 {
			return 0, 0, false
		}
		return d * 100, d*100 + 99, true
	}
	lo, hi, found := strings.Cut(s, "-")
	a, err := strconv.Atoi(strings.TrimSpace(lo))
	if err != nil || a < 100 || a > 599 {
		return 0, 0, false
	}
	if !found {
		return a, a, true
	}
	b, err := strconv.Atoi(strings.TrimSpace(hi))
	if err != nil || b < a || b > 599 {
		return 0, 0, false
	}
	return a, b, true
}

func acceptedStatus(code int, list []string) bool {
	if len(list) == 0 {
		return code >= 200 && code < 400
	}
	for _, s := range list {
		if lo, hi, ok := statusRange(s); ok && code >= lo && code <= hi {
			return true
		}
	}
	return false
}

// certWindow judges a certificate's expiry: down once expired, degraded
// within days.
func certWindow(r *CheckResult, notAfter time.Time, days int) {
	if days <= 0 {
		days = 14
	}
	t := notAfter
	r.CertExpires = &t
	left := time.Until(notAfter)
	switch {
	case left <= 0:
		r.Status = Down
		r.Message = "The certificate expired " + notAfter.Format("2 Jan 2006")
	case left < time.Duration(days)*24*time.Hour && r.Status == Up:
		r.Status = Degraded
		r.Message = fmt.Sprintf("The certificate expires in %d days (%s)", int(left.Hours()/24), notAfter.Format("2 Jan 2006"))
	}
}

func checkHTTP(ctx context.Context, c MonitorConfig, s MonitorSecrets, env Env) CheckResult {
	method := c.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if c.Body != "" {
		body = strings.NewReader(c.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSpace(c.URL), body)
	if err != nil {
		return down("Bad address: %s", err)
	}
	setHeaders(req, c, s)
	if c.Body != "" && req.Header.Get("Content-Type") == "" {
		if json.Valid([]byte(c.Body)) {
			req.Header.Set("Content-Type", "application/json")
		} else {
			req.Header.Set("Content-Type", "text/plain; charset=utf-8")
		}
	}
	start := time.Now()
	res, err := httpClient(c, env).Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		r := down("%s", errText(err))
		var cv *tls.CertificateVerificationError
		if errors.As(err, &cv) {
			r.Message = "The certificate isn't trusted: " + cv.Err.Error()
			r.Code = "TLS"
		}
		return r
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, bodyLimit))
	r := CheckResult{Status: Up, Code: strconv.Itoa(res.StatusCode)}
	r.took(start)
	r.Detail = clip(string(raw), 2000)
	r.Message = res.Status

	if !acceptedStatus(res.StatusCode, c.Statuses) {
		r.Status = Down
		r.Message = "Answered " + res.Status
		if len(c.Statuses) > 0 {
			r.Message += " (expected " + strings.Join(c.Statuses, ", ") + ")"
		}
		return r
	}
	if c.Keyword != "" {
		if ok, msg := keyword(string(raw), c); !ok {
			r.Status = Down
			r.Message = msg
			return r
		}
	}
	if c.JSONPath != "" {
		if ok, msg := jsonCheck(raw, c); !ok {
			r.Status = Down
			r.Message = msg
			return r
		}
	}
	if res.TLS != nil && len(res.TLS.PeerCertificates) > 0 {
		certWindow(&r, res.TLS.PeerCertificates[0].NotAfter, c.CertDays)
	}
	return r
}

func keyword(text string, c MonitorConfig) (bool, string) {
	switch c.KeywordMode {
	case "regex":
		re, err := regexp.Compile(c.Keyword)
		if err != nil {
			return false, "Bad regular expression: " + err.Error()
		}
		if re.MatchString(text) {
			return true, ""
		}
		return false, fmt.Sprintf("The answer doesn't match /%s/", c.Keyword)
	case "absent":
		if contains(text, c.Keyword, c.KeywordCase) {
			return false, fmt.Sprintf("The answer contains %q", c.Keyword)
		}
		return true, ""
	}
	if contains(text, c.Keyword, c.KeywordCase) {
		return true, ""
	}
	return false, fmt.Sprintf("%q isn't in the answer", c.Keyword)
}

func contains(text, word string, matchCase bool) bool {
	if matchCase {
		return strings.Contains(text, word)
	}
	return strings.Contains(strings.ToLower(text), strings.ToLower(word))
}

// ---- JSON ----

type step struct {
	key   string
	index int
	isIdx bool
}

// parsePath reads paths like status, $.data.items[0].ok, ["a key"].x.
func parsePath(p string) ([]step, error) {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "$")
	var out []step
	for i := 0; i < len(p); {
		switch p[i] {
		case '.':
			i++
		case '[':
			end := strings.IndexByte(p[i:], ']')
			if end < 0 {
				return nil, errors.New("a [ isn't closed")
			}
			inner := strings.TrimSpace(p[i+1 : i+end])
			i += end + 1
			if n, err := strconv.Atoi(inner); err == nil {
				out = append(out, step{index: n, isIdx: true})
				continue
			}
			inner = strings.Trim(inner, `"'`)
			if inner == "" {
				return nil, errors.New("empty [ ]")
			}
			out = append(out, step{key: inner})
		default:
			j := i
			for j < len(p) && p[j] != '.' && p[j] != '[' {
				j++
			}
			out = append(out, step{key: p[i:j]})
			i = j
		}
	}
	if len(out) == 0 {
		return nil, errors.New("enter a path, e.g. status or data.items[0].ok")
	}
	return out, nil
}

func lookup(v any, path []step) (any, bool) {
	for _, s := range path {
		switch t := v.(type) {
		case map[string]any:
			if s.isIdx {
				return nil, false
			}
			x, ok := t[s.key]
			if !ok {
				return nil, false
			}
			v = x
		case []any:
			if !s.isIdx {
				if s.key == "length" {
					v = float64(len(t))
					continue
				}
				return nil, false
			}
			i := s.index
			if i < 0 {
				i += len(t)
			}
			if i < 0 || i >= len(t) {
				return nil, false
			}
			v = t[i]
		default:
			return nil, false
		}
	}
	return v, true
}

func jsonString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return "null"
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func jsonCheck(raw []byte, c MonitorConfig) (bool, string) {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return false, "The answer isn't JSON"
	}
	path, err := parsePath(c.JSONPath)
	if err != nil {
		return false, err.Error()
	}
	v, ok := lookup(doc, path)
	op := c.JSONOp
	if op == "" {
		op = "eq"
	}
	if op == "exists" {
		if ok {
			return true, ""
		}
		return false, c.JSONPath + " isn't in the answer"
	}
	if !ok {
		return false, c.JSONPath + " isn't in the answer"
	}
	got := jsonString(v)
	want := c.JSONValue
	num := func() (float64, float64, bool) {
		a, e1 := strconv.ParseFloat(got, 64)
		b, e2 := strconv.ParseFloat(want, 64)
		return a, b, e1 == nil && e2 == nil
	}
	pass := false
	switch op {
	case "eq":
		pass = got == want
	case "ne":
		pass = got != want
	case "contains":
		pass = strings.Contains(got, want)
	case "gt":
		a, b, ok := num()
		pass = ok && a > b
	case "lt":
		a, b, ok := num()
		pass = ok && a < b
	}
	if pass {
		return true, ""
	}
	sym := map[string]string{"eq": "=", "ne": "≠", "contains": "contains", "gt": ">", "lt": "<"}[op]
	return false, fmt.Sprintf("%s is %s (expected %s %s)", c.JSONPath, clip(got, 100), sym, want)
}

// ---- WebSocket, Socket.IO, Elasticsearch ----

func checkWebSocket(ctx context.Context, c MonitorConfig, s MonitorSecrets, env Env) CheckResult {
	h := http.Header{}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	setHeaders(req, c, s)
	for k, v := range req.Header {
		h[k] = v
	}
	start := time.Now()
	conn, res, err := websocket.Dial(ctx, strings.TrimSpace(c.URL), &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: transport(c, env)},
		HTTPHeader: h,
	})
	if err != nil {
		if res != nil {
			return CheckResult{Status: Down, Code: strconv.Itoa(res.StatusCode), Message: "The upgrade was refused: " + res.Status}
		}
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return down("%s", errText(err))
	}
	defer conn.CloseNow()
	r := CheckResult{Status: Up, Code: "101", Message: "Connected"}
	if c.Send != "" {
		if err := conn.Write(ctx, websocket.MessageText, []byte(unescape(c.Send))); err != nil {
			return down("Couldn't send: %s", errText(err))
		}
	}
	if c.Expect != "" || c.Keyword != "" {
		want := c.Expect
		if want == "" {
			want = c.Keyword
		}
		_, msg, err := conn.Read(ctx)
		if err != nil {
			return down("No message came back: %s", errText(err))
		}
		r.Detail = clip(string(msg), 2000)
		cc := c
		cc.Keyword = want
		if ok, why := keyword(string(msg), cc); !ok {
			r.Status = Down
			r.Message = why
		} else {
			r.Message = "Connected and got the expected answer"
		}
	}
	r.took(start)
	conn.Close(websocket.StatusNormalClosure, "")
	return r
}

func checkSocketIO(ctx context.Context, c MonitorConfig, s MonitorSecrets, env Env) CheckResult {
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil {
		return down("Bad address: %s", err)
	}
	if !strings.Contains(u.Path, "socket.io") {
		u.Path = strings.TrimRight(u.Path, "/") + "/socket.io/"
	}
	q := u.Query()
	q.Set("EIO", "4")
	q.Set("transport", "polling")
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return down("Bad address: %s", err)
	}
	setHeaders(req, c, s)
	start := time.Now()
	res, err := httpClient(c, env).Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return down("%s", errText(err))
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	r := CheckResult{Code: strconv.Itoa(res.StatusCode), Detail: clip(string(raw), 2000)}
	r.took(start)
	if res.StatusCode != http.StatusOK {
		r.Status = Down
		r.Message = "The handshake was refused: " + res.Status
		return r
	}
	body := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(body, "0{") {
		r.Status = Down
		r.Message = "That isn't a Socket.IO (Engine.IO 4) answer"
		return r
	}
	var open struct {
		SID      string   `json:"sid"`
		Upgrades []string `json:"upgrades"`
	}
	_ = json.Unmarshal([]byte(body[1:]), &open)
	r.Status = Up
	r.Message = "Handshake done"
	if len(open.Upgrades) > 0 {
		r.Message += " (upgrades to " + strings.Join(open.Upgrades, ", ") + ")"
	}
	return r
}

func checkElastic(ctx context.Context, c MonitorConfig, s MonitorSecrets, env Env) CheckResult {
	u := strings.TrimRight(strings.TrimSpace(c.URL), "/") + "/_cluster/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return down("Bad address: %s", err)
	}
	setHeaders(req, c, s)
	start := time.Now()
	res, err := httpClient(c, env).Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return down("%s", errText(err))
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	r := CheckResult{Code: strconv.Itoa(res.StatusCode), Detail: clip(string(raw), 2000)}
	r.took(start)
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		r.Status = Down
		r.Message = "Sign-in was refused: " + res.Status
		return r
	}
	var h struct {
		Status            string `json:"status"`
		ClusterName       string `json:"cluster_name"`
		Nodes             int    `json:"number_of_nodes"`
		UnassignedShards  int    `json:"unassigned_shards"`
		RelocatingShards  int    `json:"relocating_shards"`
		InitializingShard int    `json:"initializing_shards"`
	}
	if err := json.Unmarshal(raw, &h); err != nil || h.Status == "" {
		r.Status = Down
		r.Message = "That isn't an Elasticsearch/OpenSearch answer (" + res.Status + ")"
		return r
	}
	r.Code = h.Status
	r.Message = fmt.Sprintf("Cluster %s is %s, %d nodes", h.ClusterName, h.Status, h.Nodes)
	if h.UnassignedShards > 0 {
		r.Message += fmt.Sprintf(", %d unassigned shards", h.UnassignedShards)
	}
	switch h.Status {
	case "green":
		r.Status = Up
	case "yellow":
		if c.MinHealthStatus == "yellow" {
			r.Status = Up
		} else {
			r.Status = Degraded
		}
	default:
		r.Status = Down
	}
	return r
}
