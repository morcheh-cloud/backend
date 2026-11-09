package api

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/proxy"
	"github.com/morcheh/backend/internal/sshpool"
)

// A site's requests, read from its access log on demand: a filtered list
// (followed live with a cursor) and a report over a time range. Nothing is
// stored; the log on the server is the record.

const (
	requestsWindowCap = 32 << 20 // a window read keeps the last 32 MB
	requestsFollowCap = 2 << 20  // a follow read, the last 2 MB
	wafWindowCap      = 16 << 20 // the firewall log beside a window read
	wafFollowCap      = 1 << 20
	reportCap         = 64 << 20
	reportCacheFor    = time.Minute
	reportTop         = 15
	reportMaxKeys     = 50_000 // distinct paths/IPs/… counted before "other"
)

var requestRanges = map[string]time.Duration{
	"15m": 15 * time.Minute, "1h": time.Hour, "6h": 6 * time.Hour,
	"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour,
}

// ProxyRequest is one line of a site's access log.
type ProxyRequest struct {
	Time           time.Time             `json:"time"`
	IP             string                `json:"ip"`
	User           string                `json:"user,omitempty" doc:"Login name sent with the request"`
	Method         string                `json:"method" doc:"Empty for a stream"`
	Path           string                `json:"path" doc:"Path and query string as asked"`
	Protocol       string                `json:"protocol"`
	Status         int                   `json:"status"`
	Bytes          int64                 `json:"bytes" doc:"Body bytes sent"`
	Referer        string                `json:"referer,omitempty"`
	Agent          string                `json:"agent,omitempty"`
	Domain         string                `json:"domain,omitempty" doc:"Host the request asked for"`
	DurationMs     *float64              `json:"duration_ms,omitempty" doc:"Time to answer, absent on lines written before detailed logging"`
	UpstreamMs     *float64              `json:"upstream_ms,omitempty" doc:"Time the upstream took"`
	UpstreamStatus string                `json:"upstream_status,omitempty"`
	UpstreamAddr   string                `json:"upstream_addr,omitempty"`
	Cache          string                `json:"cache,omitempty" doc:"HIT, MISS, EXPIRED, BYPASS…"`
	RequestLength  *int64                `json:"request_length,omitempty" doc:"Bytes received, headers included"`
	RequestID      string                `json:"request_id,omitempty"`
	Line           string                `json:"line" doc:"The line as written"`
	Firewall       *ProxyRequestFirewall `json:"firewall,omitempty" doc:"What the web application firewall made of it, when it flagged it"`
}

// ProxyRequestFirewall is the firewall's verdict on one request.
type ProxyRequestFirewall struct {
	Blocked bool             `json:"blocked" doc:"Refused by the firewall; false = only logged"`
	Rules   []proxy.WAFMatch `json:"rules"`
}

type ProxyRequestFirewallCounts struct {
	Blocked int64 `json:"blocked" doc:"Refused by the firewall"`
	Flagged int64 `json:"flagged" doc:"Logged by the firewall but let through"`
}

type ProxyRequestClasses struct {
	Ok           int64 `json:"ok" doc:"1xx and 2xx"`
	Redirects    int64 `json:"redirects" doc:"3xx"`
	ClientErrors int64 `json:"client_errors" doc:"4xx"`
	ServerErrors int64 `json:"server_errors" doc:"5xx"`
}

type ProxyRequests struct {
	Items    []ProxyRequest             `json:"items" doc:"Newest first"`
	Matched  int64                      `json:"matched" doc:"Lines matching every filter (more than items when cut by limit)"`
	Scanned  int64                      `json:"scanned" doc:"Lines read in the time range"`
	Classes  ProxyRequestClasses        `json:"classes" doc:"Matching lines per status class, the status filter left out"`
	Firewall ProxyRequestFirewallCounts `json:"firewall" doc:"Matching lines the firewall flagged, the firewall filter left out"`
	Cursor   string                     `json:"cursor" doc:"Pass back to get only lines written after this read"`
	Oldest   *time.Time                 `json:"oldest,omitempty" doc:"Oldest line read"`
	Partial  bool                       `json:"partial" doc:"The range held more than could be read: older lines were left out"`
	Reset    bool                       `json:"reset" doc:"The log was rotated since the cursor: read from its start"`
	Missing  bool                       `json:"missing" doc:"No log for this site on the server yet"`
	Detailed bool                       `json:"detailed" doc:"Some lines carry response times (written since detailed logging)"`
	Stream   bool                       `json:"stream"`
}

type ProxyRequestsInput struct {
	ID       string `path:"id" format:"uuid"`
	Host     string `path:"host" format:"uuid"`
	Cursor   string `query:"cursor" doc:"From a previous answer: only lines written since"`
	Range    string `query:"range" enum:"15m,1h,6h,24h,7d" default:"1h"`
	From     string `query:"from" doc:"RFC 3339; overrides range"`
	To       string `query:"to" doc:"RFC 3339"`
	Q        string `query:"q" maxLength:"200" doc:"Text anywhere in the line, any case"`
	Status   string `query:"status" doc:"Comma list of classes (2xx, 4xx…) and codes (404)"`
	Method   string `query:"method" doc:"Comma list"`
	Path     string `query:"path" maxLength:"500" doc:"Part of the path, any case"`
	IP       string `query:"ip" maxLength:"100" doc:"An address or its start (10.0.)"`
	Domain   string `query:"domain" maxLength:"253"`
	MinMs    int    `query:"min_ms" minimum:"0" doc:"Only requests that took at least this long"`
	Firewall string `query:"firewall" enum:"any,blocked,flagged" doc:"Only requests the firewall flagged: any, blocked (refused) or flagged (logged, let through)"`
	Limit    int    `query:"limit" minimum:"1" maximum:"2000" default:"300"`
}

// ── Report ──────────────────────────────────────────────────────────────

type ProxyReportTotals struct {
	Requests     int64    `json:"requests"`
	Visitors     int64    `json:"visitors" doc:"Distinct addresses"`
	Bytes        int64    `json:"bytes"`
	Ok           int64    `json:"ok"`
	Redirects    int64    `json:"redirects"`
	ClientErrors int64    `json:"client_errors"`
	ServerErrors int64    `json:"server_errors"`
	AvgMs        *float64 `json:"avg_ms"`
	P50Ms        *float64 `json:"p50_ms"`
	P95Ms        *float64 `json:"p95_ms"`
	P99Ms        *float64 `json:"p99_ms"`
	UpstreamMs   *float64 `json:"upstream_ms" doc:"Average time the upstream took"`
	CacheHits    int64    `json:"cache_hits"`
	CacheLookups int64    `json:"cache_lookups" doc:"Requests the proxy cache answered or looked up"`
	Received     int64    `json:"received" doc:"Bytes received (detailed lines only)"`
}

type ProxyReportSeries struct {
	Start        time.Time  `json:"start"`
	Bucket       int        `json:"bucket" doc:"Seconds per bucket"`
	Ok           []int64    `json:"ok"`
	Redirects    []int64    `json:"redirects"`
	ClientErrors []int64    `json:"client_errors"`
	ServerErrors []int64    `json:"server_errors"`
	Bytes        []int64    `json:"bytes"`
	Visitors     []int64    `json:"visitors"`
	AvgMs        []*float64 `json:"avg_ms"`
	P95Ms        []*float64 `json:"p95_ms"`
}

type ProxyReportCount struct {
	Name     string `json:"name"`
	Requests int64  `json:"requests"`
	Bytes    int64  `json:"bytes"`
	Errors   int64  `json:"errors" doc:"4xx and 5xx"`
}

type ProxyReportPath struct {
	Path     string   `json:"path" doc:"Without the query string"`
	Requests int64    `json:"requests"`
	Bytes    int64    `json:"bytes"`
	Errors   int64    `json:"errors"`
	AvgMs    *float64 `json:"avg_ms"`
	P95Ms    *float64 `json:"p95_ms"`
}

type ProxyReportIP struct {
	IP       string    `json:"ip"`
	Requests int64     `json:"requests"`
	Bytes    int64     `json:"bytes"`
	Errors   int64     `json:"errors"`
	Last     time.Time `json:"last"`
	Agent    string    `json:"agent,omitempty" doc:"Its most recent browser or client"`
}

type ProxyReportBin struct {
	UpToMs float64 `json:"up_to_ms" doc:"0 = everything slower than the bin before"`
	Count  int64   `json:"count"`
}

type ProxyHostReport struct {
	Range     string             `json:"range"`
	Start     time.Time          `json:"start"`
	End       time.Time          `json:"end"`
	TimeZone  string             `json:"time_zone"`
	Generated time.Time          `json:"generated"`
	Oldest    *time.Time         `json:"oldest,omitempty" doc:"Oldest line read"`
	Partial   bool               `json:"partial" doc:"Too much to read: older lines were left out"`
	Missing   bool               `json:"missing"`
	Detailed  bool               `json:"detailed"`
	Stream    bool               `json:"stream"`
	Totals    ProxyReportTotals  `json:"totals"`
	Previous  *ProxyReportTotals `json:"previous" doc:"The same length of time before, when the logs reach back that far"`
	Series    ProxyReportSeries  `json:"series"`
	Statuses  []ProxyReportCount `json:"statuses"`
	Methods   []ProxyReportCount `json:"methods"`
	Protocols []ProxyReportCount `json:"protocols"`
	Domains   []ProxyReportCount `json:"domains"`
	Cache     []ProxyReportCount `json:"cache"`
	Referrers []ProxyReportCount `json:"referrers" doc:"Other sites that sent visitors, by host"`
	Browsers  []ProxyReportCount `json:"browsers" doc:"Browsers, tools and bots"`
	Systems   []ProxyReportCount `json:"systems"`
	Devices   []ProxyReportCount `json:"devices" doc:"Desktop, Phone, Tablet, Bot, Tool"`
	Bots      []ProxyReportCount `json:"bots"`
	Upstreams []ProxyReportCount `json:"upstreams"`
	Paths     []ProxyReportPath  `json:"paths" doc:"Most asked"`
	Slowest   []ProxyReportPath  `json:"slowest" doc:"Highest average time, paths asked at least 3 times"`
	NotFound  []ProxyReportCount `json:"not_found" doc:"Paths answered 404"`
	Failing   []ProxyReportCount `json:"failing" doc:"Paths answered 5xx"`
	IPs       []ProxyReportIP    `json:"ips"`
	Durations []ProxyReportBin   `json:"durations"`
	Heatmap   [7][24]int64       `json:"heatmap" doc:"Requests by weekday (0 = Sunday) and hour, in the time zone"`
}

type reportCacheEntry struct {
	at   time.Time
	body *ProxyHostReport
}

var reportCache = struct {
	sync.Mutex
	m map[string]reportCacheEntry
}{m: map[string]reportCacheEntry{}}

// ── Handlers ────────────────────────────────────────────────────────────

// readAccess runs the driver's access script on the proxy's server.
func (h *proxyHandler) readAccess(ctx context.Context, p sqlc.Proxy, d proxy.Driver, hostID string, r proxy.LogRead) (proxy.LogChunk, error) {
	var chunk proxy.LogChunk
	server := p.ServerID.String()
	err := h.s.withConn(ctx, server, func(c *sshpool.Conn) error {
		sh, err := h.root(ctx, server, c)
		if err != nil {
			return err
		}
		out, err := sh.run(ctx, d.AccessScript(hostID, r))
		if err != nil {
			return err
		}
		chunk, err = d.ParseAccessOutput(out)
		return err
	})
	return chunk, err
}

// readAccessWAF is readAccess plus, when waf is set, the site's firewall
// log in the same SSH command (its lines, oldest first; none when there's no
// log or it can't be read).
func (h *proxyHandler) readAccessWAF(ctx context.Context, p sqlc.Proxy, d proxy.Driver, hostID string, r proxy.LogRead, waf *proxy.LogRead) (proxy.LogChunk, []string, error) {
	if waf == nil {
		chunk, err := h.readAccess(ctx, p, d, hostID, r)
		return chunk, nil, err
	}
	var chunk proxy.LogChunk
	var lines []string
	server := p.ServerID.String()
	err := h.s.withConn(ctx, server, func(c *sshpool.Conn) error {
		sh, err := h.root(ctx, server, c)
		if err != nil {
			return err
		}
		// Each part in a subshell: the scripts end with exit.
		out, err := sh.run(ctx, "(\n"+d.AccessScript(hostID, r)+")\necho "+wafSplit+"\n(\n"+d.WAFLogScript(hostID, *waf)+")\n")
		if err != nil {
			return err
		}
		access, rest, _ := strings.Cut(out, wafSplit+"\n")
		if chunk, err = d.ParseAccessOutput(access); err != nil {
			return err
		}
		if w, err := d.ParseAccessOutput(rest); err == nil && !w.Missing {
			lines = w.Lines
		}
		return nil
	})
	return chunk, lines, err
}

// wafSplit separates the two reads' output (the data in between is base64).
const wafSplit = "@@morcheh-waf"

func (h *proxyHandler) siteOf(ctx context.Context, proxyID, hostID string) (sqlc.GetProxyRow, proxy.Driver, sqlc.ProxyHost, proxy.HostConfig, error) {
	var cfg proxy.HostConfig
	r, d, err := h.getProxy(ctx, proxyID)
	if err != nil {
		return r, d, sqlc.ProxyHost{}, cfg, err
	}
	if !d.Capabilities().Traffic {
		return r, d, sqlc.ProxyHost{}, cfg, huma.Error422UnprocessableEntity("This proxy can't read its sites' requests")
	}
	host, err := h.s.q.GetProxyHost(ctx, sqlc.GetProxyHostParams{ID: uuid.MustParse(hostID), ProxyID: r.Proxy.ID})
	if isNotFound(err) {
		return r, d, host, cfg, huma.Error404NotFound("site not found")
	}
	if err != nil {
		return r, d, host, cfg, internalError(err)
	}
	_ = json.Unmarshal(host.Config, &cfg)
	return r, d, host, cfg, nil
}

func (h *proxyHandler) registerRequests(api huma.API, tags []string) {
	huma.Register(api, huma.Operation{
		OperationID: "list-proxy-host-requests", Method: http.MethodGet, Path: "/proxies/{id}/hosts/{host}/requests",
		Summary:     "A site's requests, from its access log",
		Description: "Lines of the site's access log in a time range, filtered, newest first. Pass the answer's cursor back to get only what was written since (live view).",
		Tags:        tags,
	}, func(ctx context.Context, in *ProxyRequestsInput) (*struct{ Body ProxyRequests }, error) {
		r, d, _, cfg, err := h.siteOf(ctx, in.ID, in.Host)
		if err != nil {
			return nil, err
		}
		now := time.Now()
		since, until := now.Add(-requestRanges[cmp.Or(in.Range, "1h")]), time.Time{}
		if in.From != "" {
			t, err := time.Parse(time.RFC3339, in.From)
			if err != nil {
				return nil, fieldError("query.from", "Not a date and time", in.From)
			}
			since = t
		}
		if in.To != "" {
			t, err := time.Parse(time.RFC3339, in.To)
			if err != nil {
				return nil, fieldError("query.to", "Not a date and time", in.To)
			}
			until = t
		}
		read := proxy.LogRead{Since: since, Grep: in.Q, Cap: requestsWindowCap}
		if in.Cursor != "" {
			inode, size, ok := strings.Cut(in.Cursor, ":")
			n, err := strconv.ParseInt(size, 10, 64)
			if !ok || err != nil || n < 0 {
				return nil, fieldError("query.cursor", "Not a cursor from this endpoint", in.Cursor)
			}
			read.Mark, read.Cap = &proxy.LogMark{Inode: inode, Size: n}, requestsFollowCap
		}
		// The firewall log over the same time (a minute more, for clocks a
		// second apart); a follow read only needs the last minutes.
		var withWAF *proxy.LogRead
		if cfg.Type != "stream" {
			wr := proxy.LogRead{Since: since.Add(-time.Minute), Cap: wafWindowCap}
			if read.Mark != nil {
				wr = proxy.LogRead{Since: now.Add(-15 * time.Minute), Cap: wafFollowCap}
			}
			withWAF = &wr
		}
		chunk, wafLines, err := h.readAccessWAF(ctx, r.Proxy, d, in.Host, read, withWAF)
		if err != nil {
			return nil, toProblem(err)
		}
		waf := newWAFIndex(d.ParseWAFLines(wafLines))
		out := ProxyRequests{
			Items: []ProxyRequest{}, Missing: chunk.Missing, Reset: chunk.Reset,
			Partial: chunk.Capped, Stream: cfg.Type == "stream",
		}
		if chunk.Missing {
			return &struct{ Body ProxyRequests }{out}, nil
		}
		out.Cursor = chunk.Mark.Inode + ":" + strconv.FormatInt(chunk.Mark.Size, 10)
		f := newRequestFilter(in)
		limit := cmp.Or(in.Limit, 300)
		var oldest time.Time
		// Lines come oldest first; walk back so the newest are kept.
		for i := len(chunk.Lines) - 1; i >= 0; i-- {
			e, ok := d.ParseAccess(chunk.Lines[i])
			if !ok {
				continue
			}
			if read.Mark == nil && e.Time.Before(since) {
				continue
			}
			if !until.IsZero() && e.Time.After(until) {
				continue
			}
			out.Scanned++
			if oldest.IsZero() || e.Time.Before(oldest) {
				oldest = e.Time
			}
			if e.Detailed {
				out.Detailed = true
			}
			if !f.match(e) {
				continue
			}
			ev := waf.find(e, chunk.Lines[i])
			fw := firewallMatch(in.Firewall, ev)
			if fw {
				countClass(&out.Classes, e.Status)
			}
			if !f.status(e.Status) {
				continue
			}
			if ev != nil && ev.Blocked {
				out.Firewall.Blocked++
			} else if ev != nil {
				out.Firewall.Flagged++
			}
			if !fw {
				continue
			}
			out.Matched++
			if len(out.Items) < limit {
				item := requestOut(e, chunk.Lines[i])
				if ev != nil {
					item.Firewall = &ProxyRequestFirewall{Blocked: ev.Blocked, Rules: ev.Rules}
				}
				out.Items = append(out.Items, item)
			}
		}
		// Rotated files can interleave by a few seconds; the list is by time.
		slices.SortStableFunc(out.Items, func(a, b ProxyRequest) int { return b.Time.Compare(a.Time) })
		if !oldest.IsZero() {
			out.Oldest = &oldest
		}
		return &struct{ Body ProxyRequests }{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-proxy-host-report", Method: http.MethodGet, Path: "/proxies/{id}/hosts/{host}/report",
		Summary:     "A report on a site's requests",
		Description: "Totals, requests over time, response times, statuses, paths, visitors, browsers and more, worked out from the site's access log (rotated files included). Kept for a minute.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ID    string `path:"id" format:"uuid"`
		Host  string `path:"host" format:"uuid"`
		Range string `query:"range" enum:"1h,24h,7d,30d" default:"24h"`
		TZ    string `query:"tz" doc:"IANA time zone for the buckets and the heatmap; default UTC"`
		Fresh bool   `query:"fresh" doc:"Read again, even if a report from the last minute is kept"`
	}) (*struct{ Body ProxyHostReport }, error) {
		loc := time.UTC
		if in.TZ != "" {
			l, err := time.LoadLocation(in.TZ)
			if err != nil {
				return nil, fieldError("query.tz", "Unknown time zone", in.TZ)
			}
			loc = l
		}
		rng := cmp.Or(in.Range, "24h")
		r, d, host, cfg, err := h.siteOf(ctx, in.ID, in.Host)
		if err != nil {
			return nil, err
		}
		key := in.Host + "|" + rng + "|" + loc.String()
		if !in.Fresh {
			reportCache.Lock()
			c, ok := reportCache.m[key]
			reportCache.Unlock()
			if ok && time.Since(c.at) < reportCacheFor {
				return &struct{ Body ProxyHostReport }{*c.body}, nil
			}
		}
		start, end, bucket := reportWindow(rng, time.Now(), loc)
		// Twice the range, for the comparison with the period before
		// (30 days: logs rarely go back 60).
		readFrom := start.Add(-end.Sub(start))
		if rng == "30d" {
			readFrom = start
		}
		chunk, err := h.readAccess(ctx, r.Proxy, d, in.Host, proxy.LogRead{Since: readFrom, Cap: reportCap})
		if err != nil {
			return nil, toProblem(err)
		}
		entries := make([]proxy.AccessEntry, 0, len(chunk.Lines))
		for _, l := range chunk.Lines {
			if e, ok := d.ParseAccess(l); ok {
				entries = append(entries, e)
			}
		}
		rep := buildHostReport(entries, start, end, bucket, loc, host.Domains)
		rep.Range, rep.Partial, rep.Missing, rep.Stream = rng, chunk.Capped, chunk.Missing, cfg.Type == "stream"
		if rng == "30d" || chunk.Capped {
			rep.Previous = nil
		}
		reportCache.Lock()
		for k, c := range reportCache.m {
			if time.Since(c.at) > reportCacheFor {
				delete(reportCache.m, k)
			}
		}
		reportCache.m[key] = reportCacheEntry{at: time.Now(), body: &rep}
		reportCache.Unlock()
		return &struct{ Body ProxyHostReport }{rep}, nil
	})
}

// ── Firewall ────────────────────────────────────────────────────────────

// wafIndex finds the firewall's record of a request: by request id (the
// firewall is told to use it), or else by address, method, path and second
// (records written before that).
type wafIndex struct {
	byID, byKey map[string]*proxy.WAFEvent
}

func newWAFIndex(events []proxy.WAFEvent) wafIndex {
	x := wafIndex{byID: map[string]*proxy.WAFEvent{}, byKey: map[string]*proxy.WAFEvent{}}
	for i := range events {
		e := &events[i]
		if e.ID != "" {
			x.byID[e.ID] = e
		}
		// ModSecurity writes the server's local time, like ctime(3).
		if t, err := time.Parse(time.ANSIC, e.Time); err == nil {
			x.byKey[wafKey(e.IP, e.Method, e.URI, t.Format(time.DateTime))] = e
		}
	}
	return x
}

func wafKey(ip, method, uri, wall string) string {
	return ip + "\x00" + method + "\x00" + uri + "\x00" + wall
}

// accessWallRe is a line's local time as written ([09/Nov/2026:14:29:24 +0000]).
var accessWallRe = regexp.MustCompile(`\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}) [+-]\d{4}\]`)

func (x wafIndex) find(e proxy.AccessEntry, line string) *proxy.WAFEvent {
	if len(x.byID) == 0 && len(x.byKey) == 0 {
		return nil
	}
	if e.RequestID != "" {
		if ev := x.byID[e.RequestID]; ev != nil {
			return ev
		}
	}
	m := accessWallRe.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	t, err := time.Parse("02/Jan/2006:15:04:05", m[1])
	if err != nil {
		return nil
	}
	return x.byKey[wafKey(e.IP, e.Method, e.Path, t.Format(time.DateTime))]
}

func firewallMatch(want string, ev *proxy.WAFEvent) bool {
	switch want {
	case "any":
		return ev != nil
	case "blocked":
		return ev != nil && ev.Blocked
	case "flagged":
		return ev != nil && !ev.Blocked
	}
	return true
}

// ── Filtering ───────────────────────────────────────────────────────────

type requestFilter struct {
	classes map[int]bool
	codes   map[int]bool
	methods map[string]bool
	path    string
	ip      string
	domain  string
	minSecs float64
}

func newRequestFilter(in *ProxyRequestsInput) requestFilter {
	f := requestFilter{
		classes: map[int]bool{}, codes: map[int]bool{}, methods: map[string]bool{},
		path: strings.ToLower(strings.TrimSpace(in.Path)), ip: strings.TrimSpace(in.IP),
		domain: strings.ToLower(strings.TrimSpace(in.Domain)), minSecs: float64(in.MinMs) / 1000,
	}
	for s := range strings.SplitSeq(in.Status, ",") {
		s = strings.ToLower(strings.TrimSpace(s))
		if len(s) == 3 && strings.HasSuffix(s, "xx") && s[0] >= '1' && s[0] <= '5' {
			f.classes[int(s[0]-'0')] = true
		} else if n, err := strconv.Atoi(s); err == nil {
			f.codes[n] = true
		}
	}
	for m := range strings.SplitSeq(in.Method, ",") {
		if m = strings.ToUpper(strings.TrimSpace(m)); m != "" {
			f.methods[m] = true
		}
	}
	return f
}

// match checks every filter but the status one.
func (f requestFilter) match(e proxy.AccessEntry) bool {
	if len(f.methods) > 0 && !f.methods[e.Method] {
		return false
	}
	if f.path != "" && !strings.Contains(strings.ToLower(e.Path), f.path) {
		return false
	}
	if f.ip != "" && !strings.HasPrefix(e.IP, f.ip) {
		return false
	}
	if f.domain != "" && e.Domain != f.domain {
		return false
	}
	if f.minSecs > 0 && e.Duration < f.minSecs {
		return false
	}
	return true
}

func (f requestFilter) status(code int) bool {
	if len(f.classes) == 0 && len(f.codes) == 0 {
		return true
	}
	return f.codes[code] || f.classes[code/100]
}

func countClass(c *ProxyRequestClasses, status int) {
	switch status / 100 {
	case 1, 2:
		c.Ok++
	case 3:
		c.Redirects++
	case 4:
		c.ClientErrors++
	case 5:
		c.ServerErrors++
	}
}

func ms(secs float64) *float64 {
	if secs < 0 {
		return nil
	}
	v := math.Round(secs*1e5) / 100 // ms, two decimals
	return &v
}

func requestOut(e proxy.AccessEntry, line string) ProxyRequest {
	out := ProxyRequest{
		Time: e.Time, IP: e.IP, User: e.User, Method: e.Method, Path: e.Path, Protocol: e.Protocol,
		Status: e.Status, Bytes: e.Bytes, Referer: e.Referer, Agent: e.Agent, Domain: e.Domain,
		DurationMs: ms(e.Duration), UpstreamMs: ms(e.Upstream), UpstreamStatus: e.UpstreamStatus,
		UpstreamAddr: e.UpstreamAddr, Cache: e.Cache, RequestID: e.RequestID, Line: line,
	}
	if e.RequestLength >= 0 && e.Detailed {
		n := e.RequestLength
		out.RequestLength = &n
	}
	return out
}

// ── Report ──────────────────────────────────────────────────────────────

// reportWindow is the range's buckets, ending with the one now falls in;
// day buckets start at midnight in loc.
func reportWindow(rng string, now time.Time, loc *time.Location) (start, end time.Time, bucket time.Duration) {
	switch rng {
	case "1h":
		bucket = time.Minute
		end = now.Truncate(bucket).Add(bucket)
		return end.Add(-time.Hour), end, bucket
	case "7d":
		// On the hour where the viewer is (Tehran is +3:30).
		bucket = time.Hour
		l := now.In(loc)
		end = time.Date(l.Year(), l.Month(), l.Day(), l.Hour()+1, 0, 0, 0, loc)
		return end.Add(-7 * 24 * time.Hour), end, bucket
	case "30d":
		bucket = 24 * time.Hour
		l := now.In(loc)
		end = time.Date(l.Year(), l.Month(), l.Day()+1, 0, 0, 0, 0, loc)
		return end.AddDate(0, 0, -30), end, bucket
	}
	bucket = 15 * time.Minute
	end = now.Truncate(bucket).Add(bucket)
	return end.Add(-24 * time.Hour), end, bucket
}

type tally struct {
	requests, bytes, errors int64
	secs                    []float64
}

type counter map[string]*tally

func (c counter) add(name string, e proxy.AccessEntry) *tally {
	t := c[name]
	if t == nil && len(c) >= reportMaxKeys {
		name = "(other)"
		t = c[name]
	}
	if t == nil {
		t = &tally{}
		c[name] = t
	}
	t.requests++
	t.bytes += e.Bytes
	if e.Status >= 400 {
		t.errors++
	}
	return t
}

func (c counter) top(n int) []ProxyReportCount {
	out := make([]ProxyReportCount, 0, len(c))
	for name, t := range c {
		out = append(out, ProxyReportCount{Name: name, Requests: t.requests, Bytes: t.bytes, Errors: t.errors})
	}
	slices.SortFunc(out, func(a, b ProxyReportCount) int {
		return cmp.Or(cmp.Compare(b.Requests, a.Requests), strings.Compare(a.Name, b.Name))
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

var durationEdges = []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

func quantile(sorted []float64, q float64) *float64 {
	if len(sorted) == 0 {
		return nil
	}
	i := int(math.Ceil(q*float64(len(sorted)))) - 1
	return ms(sorted[max(0, min(i, len(sorted)-1))])
}

func average(v []float64) *float64 {
	if len(v) == 0 {
		return nil
	}
	sum := 0.0
	for _, x := range v {
		sum += x
	}
	return ms(sum / float64(len(v)))
}

type totalsAcc struct {
	t        ProxyReportTotals
	ips      map[string]struct{}
	secs     []float64
	upstream []float64
}

func (a *totalsAcc) add(e proxy.AccessEntry) {
	if a.ips == nil {
		a.ips = map[string]struct{}{}
	}
	a.t.Requests++
	a.t.Bytes += e.Bytes
	a.ips[e.IP] = struct{}{}
	var c ProxyRequestClasses
	countClass(&c, e.Status)
	a.t.Ok += c.Ok
	a.t.Redirects += c.Redirects
	a.t.ClientErrors += c.ClientErrors
	a.t.ServerErrors += c.ServerErrors
	if e.Duration >= 0 {
		a.secs = append(a.secs, e.Duration)
	}
	if e.Upstream >= 0 {
		a.upstream = append(a.upstream, e.Upstream)
	}
	if e.Cache != "" {
		a.t.CacheLookups++
		if e.Cache == "HIT" || e.Cache == "STALE" || e.Cache == "REVALIDATED" || e.Cache == "UPDATING" {
			a.t.CacheHits++
		}
	}
	if e.Detailed && e.RequestLength > 0 {
		a.t.Received += e.RequestLength
	}
}

func (a *totalsAcc) done() ProxyReportTotals {
	t := a.t
	t.Visitors = int64(len(a.ips))
	slices.Sort(a.secs)
	t.AvgMs, t.P50Ms, t.P95Ms, t.P99Ms = average(a.secs), quantile(a.secs, .5), quantile(a.secs, .95), quantile(a.secs, .99)
	t.UpstreamMs = average(a.upstream)
	return t
}

func buildHostReport(entries []proxy.AccessEntry, start, end time.Time, bucket time.Duration, loc *time.Location, domains []string) ProxyHostReport {
	n := int(end.Sub(start) / bucket)
	rep := ProxyHostReport{
		Start: start, End: end, TimeZone: loc.String(), Generated: time.Now().UTC(),
		Series: ProxyReportSeries{
			Start: start, Bucket: int(bucket / time.Second),
			Ok: make([]int64, n), Redirects: make([]int64, n), ClientErrors: make([]int64, n),
			ServerErrors: make([]int64, n), Bytes: make([]int64, n), Visitors: make([]int64, n),
			AvgMs: make([]*float64, n), P95Ms: make([]*float64, n),
		},
	}
	own := map[string]bool{}
	for _, d := range domains {
		own[strings.ToLower(strings.TrimPrefix(d, "*."))] = true
	}
	prevStart := start.Add(-end.Sub(start))
	var cur, prev totalsAcc
	bucketIPs := make([]map[string]struct{}, n)
	bucketSecs := make([][]float64, n)
	statuses, methods, protocols, domainsC, cache := counter{}, counter{}, counter{}, counter{}, counter{}
	referrers, browsers, systems, devices, bots, upstreams := counter{}, counter{}, counter{}, counter{}, counter{}, counter{}
	paths, notFound, failing := counter{}, counter{}, counter{}
	type ipAcc struct {
		tally
		last  time.Time
		agent string
	}
	ips := map[string]*ipAcc{}
	bins := make([]int64, len(durationEdges)+1)
	var oldest time.Time
	for _, e := range entries {
		if oldest.IsZero() || e.Time.Before(oldest) {
			oldest = e.Time
		}
		if !e.Time.Before(prevStart) && e.Time.Before(start) {
			prev.add(e)
			continue
		}
		if e.Time.Before(start) || !e.Time.Before(end) {
			continue
		}
		if e.Detailed {
			rep.Detailed = true
		}
		cur.add(e)
		i := int(e.Time.Sub(start) / bucket)
		s := &rep.Series
		switch e.Status / 100 {
		case 1, 2:
			s.Ok[i]++
		case 3:
			s.Redirects[i]++
		case 4:
			s.ClientErrors[i]++
		case 5:
			s.ServerErrors[i]++
		}
		s.Bytes[i] += e.Bytes
		if bucketIPs[i] == nil {
			bucketIPs[i] = map[string]struct{}{}
		}
		bucketIPs[i][e.IP] = struct{}{}
		if e.Duration >= 0 {
			bucketSecs[i] = append(bucketSecs[i], e.Duration)
			b := len(durationEdges)
			for k, edge := range durationEdges {
				if e.Duration*1000 <= edge {
					b = k
					break
				}
			}
			bins[b]++
		}
		l := e.Time.In(loc)
		rep.Heatmap[l.Weekday()][l.Hour()]++

		statuses.add(strconv.Itoa(e.Status), e)
		if e.Method != "" {
			methods.add(e.Method, e)
		}
		if e.Protocol != "" {
			protocols.add(e.Protocol, e)
		}
		if e.Domain != "" {
			domainsC.add(e.Domain, e)
		}
		if e.Cache != "" {
			cache.add(e.Cache, e)
		}
		if e.UpstreamAddr != "" {
			for a := range strings.SplitSeq(e.UpstreamAddr, ",") {
				if a = strings.TrimSpace(strings.Split(a, " : ")[0]); a != "" {
					upstreams.add(a, e)
				}
			}
		}
		if ref := refHost(e.Referer); ref != "" && !own[ref] && !own[strings.TrimPrefix(ref, "www.")] && ref != e.Domain {
			referrers.add(ref, e)
		}
		ua := classifyAgent(e.Agent)
		browsers.add(ua.browser, e)
		if ua.system != "" {
			systems.add(ua.system, e)
		}
		devices.add(ua.device, e)
		if ua.device == "Bot" {
			bots.add(ua.browser, e)
		}
		if e.Method != "" {
			p, _, _ := strings.Cut(e.Path, "?")
			t := paths.add(p, e)
			if e.Duration >= 0 {
				t.secs = append(t.secs, e.Duration)
			}
			if e.Status == 404 {
				notFound.add(p, e)
			}
			if e.Status >= 500 {
				failing.add(p, e)
			}
		}
		ip := ips[e.IP]
		if ip == nil {
			if len(ips) >= reportMaxKeys {
				continue
			}
			ip = &ipAcc{}
			ips[e.IP] = ip
		}
		ip.requests++
		ip.bytes += e.Bytes
		if e.Status >= 400 {
			ip.errors++
		}
		if e.Time.After(ip.last) {
			ip.last = e.Time
			if ua.browser != "Other" {
				ip.agent = ua.browser
				if ua.system != "" {
					ip.agent += " · " + ua.system
				}
			}
		}
	}
	if !oldest.IsZero() {
		rep.Oldest = &oldest
	}
	rep.Totals = cur.done()
	// The comparison needs something logged before this period; a site
	// younger than that compares against what it had.
	if !oldest.IsZero() && oldest.Before(start) {
		p := prev.done()
		rep.Previous = &p
	}
	for i := range n {
		rep.Series.Visitors[i] = int64(len(bucketIPs[i]))
		slices.Sort(bucketSecs[i])
		rep.Series.AvgMs[i] = average(bucketSecs[i])
		rep.Series.P95Ms[i] = quantile(bucketSecs[i], .95)
	}
	rep.Statuses = statuses.top(0)
	slices.SortFunc(rep.Statuses, func(a, b ProxyReportCount) int { return strings.Compare(a.Name, b.Name) })
	rep.Methods, rep.Protocols, rep.Cache = methods.top(10), protocols.top(10), cache.top(10)
	rep.Domains, rep.Referrers, rep.Upstreams = domainsC.top(reportTop), referrers.top(reportTop), upstreams.top(reportTop)
	rep.Browsers, rep.Systems, rep.Devices, rep.Bots = browsers.top(reportTop), systems.top(reportTop), devices.top(0), bots.top(reportTop)
	rep.NotFound, rep.Failing = notFound.top(reportTop), failing.top(reportTop)

	all := make([]ProxyReportPath, 0, len(paths))
	for p, t := range paths {
		slices.Sort(t.secs)
		all = append(all, ProxyReportPath{Path: p, Requests: t.requests, Bytes: t.bytes, Errors: t.errors, AvgMs: average(t.secs), P95Ms: quantile(t.secs, .95)})
	}
	slices.SortFunc(all, func(a, b ProxyReportPath) int {
		return cmp.Or(cmp.Compare(b.Requests, a.Requests), strings.Compare(a.Path, b.Path))
	})
	rep.Paths = all[:min(len(all), reportTop)]
	slow := slices.DeleteFunc(slices.Clone(all), func(p ProxyReportPath) bool { return p.AvgMs == nil || p.Requests < 3 })
	slices.SortFunc(slow, func(a, b ProxyReportPath) int { return cmp.Compare(*b.AvgMs, *a.AvgMs) })
	rep.Slowest = slow[:min(len(slow), reportTop)]

	rep.IPs = make([]ProxyReportIP, 0, len(ips))
	for ip, a := range ips {
		rep.IPs = append(rep.IPs, ProxyReportIP{IP: ip, Requests: a.requests, Bytes: a.bytes, Errors: a.errors, Last: a.last, Agent: a.agent})
	}
	slices.SortFunc(rep.IPs, func(a, b ProxyReportIP) int {
		return cmp.Or(cmp.Compare(b.Requests, a.Requests), strings.Compare(a.IP, b.IP))
	})
	rep.IPs = rep.IPs[:min(len(rep.IPs), reportTop)]

	rep.Durations = make([]ProxyReportBin, len(bins))
	for i, c := range bins {
		edge := 0.0
		if i < len(durationEdges) {
			edge = durationEdges[i]
		}
		rep.Durations[i] = ProxyReportBin{UpToMs: edge, Count: c}
	}
	return rep
}

func refHost(ref string) string {
	if ref == "" {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// ── User agents ─────────────────────────────────────────────────────────

type agentKind struct{ browser, system, device string }

var (
	botRe      = regexp.MustCompile(`(?i)(googlebot|bingbot|yandex(?:bot|images)|baiduspider|duckduckbot|applebot|ahrefsbot|semrushbot|mj12bot|dotbot|petalbot|bytespider|gptbot|chatgpt-user|oai-searchbot|claudebot|claude-web|anthropic-ai|perplexitybot|ccbot|amazonbot|facebookexternalhit|meta-externalagent|twitterbot|linkedinbot|slackbot|discordbot|telegrambot|whatsapp|uptimerobot|pingdom|statuscake|censys|zgrab|masscan|nmap|nuclei|[a-z0-9_-]*bot\b|[a-z0-9_-]*spider|[a-z0-9_-]*crawler)`)
	toolRe     = regexp.MustCompile(`(?i)^(curl|wget|python-requests|python-urllib|python-httpx|aiohttp|go-http-client|okhttp|java|apache-httpclient|axios|node-fetch|undici|postmanruntime|insomnia|httpie|guzzlehttp|libwww-perl|ruby|dart|kube-probe|prometheus|grafana|elb-healthchecker|docker|helm|git)[/ ]?`)
	browserRes = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"Edge", regexp.MustCompile(`Edg(e|A|iOS)?/`)},
		{"Opera", regexp.MustCompile(`OPR/|Opera`)},
		{"Samsung Internet", regexp.MustCompile(`SamsungBrowser/`)},
		{"Yandex Browser", regexp.MustCompile(`YaBrowser/`)},
		{"Firefox", regexp.MustCompile(`Firefox/|FxiOS/`)},
		{"Chrome", regexp.MustCompile(`Chrome/|CriOS/`)},
		{"Safari", regexp.MustCompile(`Safari/`)},
	}
	systemRes = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"Android", regexp.MustCompile(`Android`)},
		{"iOS", regexp.MustCompile(`iPhone|iPad|iPod`)},
		{"Windows", regexp.MustCompile(`Windows`)},
		{"ChromeOS", regexp.MustCompile(`CrOS`)},
		{"macOS", regexp.MustCompile(`Macintosh|Mac OS X`)},
		{"Linux", regexp.MustCompile(`Linux|X11`)},
	}
	// An Android without "Mobile" is a tablet too (see classifyAgent).
	tabletRe = regexp.MustCompile(`iPad|Tablet`)
)

func classifyAgent(ua string) agentKind {
	if ua == "" {
		return agentKind{browser: "No user agent", device: "Tool"}
	}
	if m := botRe.FindString(ua); m != "" {
		return agentKind{browser: botName(m), device: "Bot"}
	}
	if m := toolRe.FindStringSubmatch(ua); m != nil {
		return agentKind{browser: m[1], device: "Tool"}
	}
	k := agentKind{browser: "Other", device: "Desktop"}
	for _, b := range browserRes {
		if b.re.MatchString(ua) {
			k.browser = b.name
			break
		}
	}
	for _, s := range systemRes {
		if s.re.MatchString(ua) {
			k.system = s.name
			break
		}
	}
	switch {
	case tabletRe.MatchString(ua) || (k.system == "Android" && !strings.Contains(ua, "Mobile")):
		k.device = "Tablet"
	case strings.Contains(ua, "Mobile") || k.system == "iOS" || k.system == "Android":
		k.device = "Phone"
	}
	return k
}

var botNames = map[string]string{
	"googlebot": "Googlebot", "bingbot": "Bingbot", "yandexbot": "YandexBot", "yandeximages": "YandexBot",
	"baiduspider": "Baidu", "duckduckbot": "DuckDuckGo", "applebot": "Applebot", "ahrefsbot": "AhrefsBot",
	"semrushbot": "SemrushBot", "mj12bot": "Majestic", "petalbot": "PetalBot", "bytespider": "Bytespider",
	"gptbot": "GPTBot", "chatgpt-user": "ChatGPT", "oai-searchbot": "OpenAI search", "claudebot": "ClaudeBot",
	"claude-web": "ClaudeBot", "anthropic-ai": "ClaudeBot", "perplexitybot": "PerplexityBot", "ccbot": "Common Crawl",
	"amazonbot": "Amazonbot", "facebookexternalhit": "Facebook", "meta-externalagent": "Meta", "twitterbot": "X (Twitter)",
	"linkedinbot": "LinkedIn", "slackbot": "Slack", "discordbot": "Discord", "telegrambot": "Telegram",
	"whatsapp": "WhatsApp", "uptimerobot": "UptimeRobot", "censys": "Censys", "zgrab": "zgrab scanner",
	"masscan": "masscan", "nmap": "Nmap", "nuclei": "Nuclei",
}

func botName(m string) string {
	if n, ok := botNames[strings.ToLower(m)]; ok {
		return n
	}
	if m == "" {
		return "Bot"
	}
	return fmt.Sprint(strings.ToUpper(m[:1]), m[1:])
}
