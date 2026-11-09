// Package proxy is the kind-neutral side of Morcheh's reverse proxies: the
// model of a site (HostConfig), its validation, and the Driver interface each
// proxy kind (nginx first) implements. A driver only builds shell scripts and
// reads their output; the API runs them over SSH.
package proxy

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Host types.
const (
	TypeProxy    = "proxy"
	TypeRedirect = "redirect"
	TypeStatic   = "static"
	// TypeNotFound answers every request with 404: parks names that must not
	// fall through to another site.
	TypeNotFound = "notfound"
	// TypeStream forwards a TCP or UDP port as is (databases, mail, games).
	// It has no domains.
	TypeStream = "stream"
)

// IsStream says whether a host is a port forward rather than a site.
func (h HostConfig) IsStream() bool { return h.Type == TypeStream }

// HostConfig is one site: which names it answers and what it does with them.
type HostConfig struct {
	Domains []string `json:"domains" maxItems:"50" doc:"Names it answers, like example.com or *.example.com; empty for a stream"`
	Type    string   `json:"type" enum:"proxy,redirect,static,notfound,stream"`

	// proxy
	Upstream     string `json:"upstream,omitempty" doc:"Where requests go, like http://127.0.0.1:3000" example:"http://127.0.0.1:3000"`
	WebSockets   bool   `json:"websockets,omitempty"`
	PreserveHost bool   `json:"preserve_host,omitempty" doc:"Send the visitor's Host header on, not the upstream's"`

	// redirect
	RedirectTo   string `json:"redirect_to,omitempty" doc:"Where visitors are sent, like https://example.com"`
	RedirectCode int    `json:"redirect_code,omitempty" enum:"0,301,302,307,308" doc:"0 = 301"`
	KeepPath     bool   `json:"keep_path,omitempty" doc:"Add the requested path and query to the target"`

	// static
	Root string `json:"root,omitempty" doc:"Folder the files are served from"`
	SPA  bool   `json:"spa,omitempty" doc:"Answer unknown paths with index.html (single-page apps)"`

	// stream
	ListenPort int    `json:"listen_port,omitempty" minimum:"0" maximum:"65535" doc:"Port the proxy listens on"`
	Protocol   string `json:"protocol,omitempty" enum:",tcp,udp" doc:"tcp (default) or udp"`
	StreamTo   string `json:"stream_to,omitempty" doc:"Where connections go, as host:port" example:"10.0.0.5:5432"`

	TLS HostTLS `json:"tls" required:"false" doc:"Plain http only when left out"`

	MaxBodyMB      int      `json:"max_body_mb,omitempty" minimum:"0" maximum:"100000" doc:"Largest upload; 0 = the proxy's default"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" minimum:"0" maximum:"86400" doc:"How long to wait for the upstream; 0 = the proxy's default"`
	Allow          []string `json:"allow,omitempty" maxItems:"500" doc:"Addresses or ranges always let in"`
	Deny           []string `json:"deny,omitempty" maxItems:"500" doc:"Addresses or ranges always refused"`
	// DefaultAccess is what happens to everyone the lists don't name. Left
	// empty it's deny when allow has entries (how sites saved before deny
	// existed behave), else allow.
	DefaultAccess string `json:"default_access,omitempty" enum:",allow,deny" doc:"Everyone else: allow or deny. Empty = deny when allow has entries, else allow"`
	// Countries limit a site by where its visitors are (http sites only).
	Countries   []string     `json:"countries,omitempty" maxItems:"250" doc:"Two-letter country codes (ISO 3166-1), like DE"`
	CountryMode string       `json:"country_mode,omitempty" enum:",allow,deny" doc:"allow = only these countries get in; deny = these are refused"`
	RateLimit   RateLimit    `json:"rate_limit" required:"false" doc:"Limits on requests, connections and speed"`
	Headers     []HeaderRule `json:"headers,omitempty" maxItems:"50"`
	Paths       []PathRule   `json:"paths,omitempty" maxItems:"50" doc:"Paths sent somewhere else than the main upstream"`
	Advanced    string       `json:"advanced,omitempty" maxLength:"16384" doc:"Extra directives in the proxy's own language, added inside the site"`

	// Tuning (Capabilities.Tuning): each one is used by some types only and
	// cleared by Normalize for the others.
	Gzip           bool   `json:"gzip,omitempty" doc:"Compress text answers (proxy, static)"`
	NoBuffering    bool   `json:"no_buffering,omitempty" doc:"Pass data straight through without buffering it (proxy): live updates, streamed answers, big uploads"`
	ConnectTimeout int    `json:"connect_timeout_seconds,omitempty" minimum:"0" maximum:"75" doc:"How long to try reaching the upstream; 0 = the proxy's default (proxy, stream)"`
	RealIP         RealIP `json:"real_ip" required:"false" doc:"Read the visitor's address from a CDN or load balancer in front (sites only)"`
	ProxyProtocol  bool   `json:"proxy_protocol,omitempty" doc:"Tell the upstream the visitor's address with the PROXY protocol (stream)"`
	HideVersion    bool   `json:"hide_version,omitempty" doc:"Leave the proxy's version out of headers and error pages (sites only)"`
	Cache          Cache  `json:"cache" required:"false" doc:"What browsers keep, and answers the proxy keeps itself (Capabilities.Cache)"`

	// Capabilities.Auth, Pages, Hardening, UpstreamTLS (see features.go).
	Auth            Auth        `json:"auth" required:"false" doc:"Visitors sign in first (proxy, static)"`
	UpstreamTLS     UpstreamTLS `json:"upstream_tls" required:"false" doc:"How an https upstream is reached (proxy)"`
	Maintenance     Maintenance `json:"maintenance" required:"false" doc:"A 503 page for everyone but some addresses (sites)"`
	ErrorPages      []ErrorPage `json:"error_pages,omitempty" maxItems:"11" doc:"Own pages for error statuses (sites)"`
	InterceptErrors bool        `json:"intercept_errors,omitempty" doc:"Show these pages for the upstream's own errors too (proxy)"`
	Hardening       Hardening   `json:"hardening" required:"false" doc:"Refuse requests no real visitor makes (sites)"`
	RequestID       bool        `json:"request_id,omitempty" doc:"Give every request an X-Request-ID, sent to the upstream and back to the visitor (sites)"`
	Brotli          bool        `json:"brotli,omitempty" doc:"Also compress with Brotli when the server's nginx has the module (proxy, static)"`
	CatchAll        bool        `json:"catch_all,omitempty" doc:"Answer every name no other site has, as the default server (404 hosts; one per proxy)"`
	NotFoundCode    int         `json:"not_found_code,omitempty" enum:"0,404,410,444" doc:"What a 404 host answers; 444 closes the connection without an answer. 0 = 404"`

	// Custom replaces the generated file: someone wrote it by hand, at their
	// own risk. The fields above still name the site (domains, type) in the
	// panel, but no longer change what's written.
	Custom string `json:"custom,omitempty" maxLength:"65536" doc:"The whole config file written by hand; when set it's written instead of the generated one"`
}

// IsCustom says whether the file is written by hand.
func (h HostConfig) IsCustom() bool { return h.Custom != "" }

// FileText is what's written for a host: the hand-written file when there is
// one, else what the driver renders.
func FileText(d Driver, id string, h HostConfig, env Env) string {
	if h.IsCustom() {
		return h.Custom + "\n"
	}
	return d.Render(id, h, env)
}

// RealIP trusts a CDN or load balancer in front of the site: requests from
// these addresses carry the visitor's own address in Header, which then
// counts for logs, access lists, countries and rate limits.
type RealIP struct {
	From   []string `json:"from,omitempty" maxItems:"200" doc:"Addresses or ranges of the CDN or load balancer"`
	Header string   `json:"header,omitempty" enum:",X-Forwarded-For,X-Real-IP,CF-Connecting-IP,True-Client-IP" doc:"Header holding the visitor's address; empty = X-Forwarded-For"`
}

// Cache is a site's caching: what browsers keep (proxy and static sites) and
// the upstream's answers kept on the proxy's disk (proxy sites).
type Cache struct {
	AssetDays  int  `json:"asset_days,omitempty" minimum:"0" maximum:"365" doc:"Browsers keep css, js, images, fonts and media this many days; 0 = leave the answer's own header"`
	PagesFresh bool `json:"pages_fresh,omitempty" doc:"Browsers check for a newer page (html) every time"`

	Enabled        bool     `json:"enabled,omitempty" doc:"Keep the upstream's answers on the proxy's disk and serve them from there (proxy)"`
	Minutes        int      `json:"minutes,omitempty" minimum:"0" maximum:"43200" doc:"How long an answer stays fresh when the upstream doesn't say; 0 = 10"`
	MaxSizeMB      int      `json:"max_size_mb,omitempty" minimum:"0" maximum:"1048576" doc:"Disk space the cache may use; 0 = 1024"`
	ServeStale     bool     `json:"serve_stale,omitempty" doc:"When the upstream is down, slow or failing, answer from the cache; refresh in the background"`
	IgnoreUpstream bool     `json:"ignore_upstream,omitempty" doc:"Cache even when the upstream says not to (Cache-Control, Expires); answers setting a cookie are still never kept"`
	SkipPaths      []string `json:"skip_paths,omitempty" maxItems:"50" doc:"Paths never cached, with everything under them, like /admin"`
	SkipCookies    []string `json:"skip_cookies,omitempty" maxItems:"20" doc:"Requests carrying a cookie whose name starts with one of these skip the cache (signed-in people), like wordpress_logged_in"`
	StatusHeader   bool     `json:"status_header,omitempty" doc:"Add X-Cache-Status (HIT, MISS, BYPASS…) to answers"`
}

// Browser says whether the cache sets anything for browsers.
func (c Cache) Browser() bool { return c.AssetDays > 0 || c.PagesFresh }

// FreshMinutes is how long an answer stays fresh.
func (c Cache) FreshMinutes() int {
	if c.Minutes > 0 {
		return c.Minutes
	}
	return 10
}

// SizeMB is the cache's disk limit.
func (c Cache) SizeMB() int {
	if c.MaxSizeMB > 0 {
		return c.MaxSizeMB
	}
	return 1024
}

// RealIPHeaders are the headers RealIP can read.
var RealIPHeaders = []string{"X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "True-Client-IP"}

// HostTLS serves the site over HTTPS with a certificate already on the server.
type HostTLS struct {
	Enabled     bool   `json:"enabled" required:"false"`
	Certificate string `json:"certificate,omitempty" doc:"Path of the certificate (full chain) on the server"`
	Key         string `json:"key,omitempty" doc:"Path of its private key on the server"`
	ForceHTTPS  bool   `json:"force_https,omitempty" doc:"Send plain http visitors to https"`
	ForceCode   int    `json:"force_code,omitempty" enum:"0,301,302,307,308" doc:"Status of that redirect; 0 = 301. 308 keeps the method and body of a POST"`
	HTTP2       bool   `json:"http2,omitempty"`
	HTTP3       bool   `json:"http3,omitempty" doc:"Also answer over HTTP/3 (QUIC, UDP port 443); needs nginx 1.25 or newer built with it"`
	HSTS        bool   `json:"hsts,omitempty" doc:"Tell browsers to only use https"`
	HSTSMaxAge  int    `json:"hsts_max_age,omitempty" minimum:"0" maximum:"63072000" doc:"How long browsers remember it, in seconds; 0 = a year"`
	HSTSSub     bool   `json:"hsts_subdomains,omitempty" doc:"The rule covers every subdomain too"`
	HSTSPreload bool   `json:"hsts_preload,omitempty" doc:"Ask to be built into browsers (hstspreload.org)"`
	// Profile picks protocols and ciphers from Mozilla's guidelines; empty =
	// the proxy's own defaults.
	Profile      string `json:"profile,omitempty" enum:",modern,intermediate,old" doc:"modern = TLS 1.3 only; intermediate = TLS 1.2 and 1.3 with strong ciphers; old = also TLS 1.0/1.1 for very old clients; empty = the proxy's defaults"`
	OCSP         bool   `json:"ocsp,omitempty" doc:"OCSP stapling: send the certificate's revocation status along (only for certificates that list an OCSP address)"`
	SessionCache bool   `json:"session_cache,omitempty" doc:"Remember TLS sessions for a day so returning visitors connect faster"`
	ClientCA     string `json:"client_ca,omitempty" doc:"Path of a CA file on the server: visitors must show a certificate it signed"`
	VerifyClient string `json:"verify_client,omitempty" enum:",on,optional" doc:"on = a client certificate is required; optional = asked for, not required; empty = off"`
}

// HSTSValue is the Strict-Transport-Security header the settings make.
func (t HostTLS) HSTSValue() string {
	age := t.HSTSMaxAge
	if age <= 0 {
		age = 31536000
	}
	v := fmt.Sprintf("max-age=%d", age)
	if t.HSTSSub {
		v += "; includeSubDomains"
	}
	if t.HSTSPreload {
		v += "; preload"
	}
	return v
}

// RateLimit slows down or refuses visitors who ask too much. Its zero value
// limits nothing.
type RateLimit struct {
	Rules       []RateRule `json:"rules,omitempty" maxItems:"20" doc:"Request limits; sites only"`
	ConnPerIP   int        `json:"conn_per_ip,omitempty" minimum:"0" maximum:"100000" doc:"Connections one visitor may hold open at once; 0 = no limit"`
	ConnTotal   int        `json:"conn_total,omitempty" minimum:"0" maximum:"1000000" doc:"Connections the whole site may hold open at once; 0 = no limit"`
	DownloadKBs int        `json:"download_kbs,omitempty" minimum:"0" maximum:"10000000" doc:"Speed sent to a visitor, per connection, in KB/s; 0 = no limit"`
	UploadKBs   int        `json:"upload_kbs,omitempty" minimum:"0" maximum:"10000000" doc:"Speed read from a visitor, per connection, in KB/s; port forwards only"`
	FullSpeedMB int        `json:"full_speed_mb,omitempty" minimum:"0" maximum:"100000" doc:"The first MB of each answer go at full speed; sites only"`
	Status      int        `json:"status,omitempty" enum:"0,429,503,444" doc:"Answer to refused requests; 0 = 429"`
	Exempt      []string   `json:"exempt,omitempty" maxItems:"200" doc:"Addresses or ranges never limited"`
	DryRun      bool       `json:"dry_run,omitempty" doc:"Only log who would have been limited"`
}

// IsZero says whether nothing is limited.
func (r RateLimit) IsZero() bool {
	return len(r.Rules) == 0 && r.ConnPerIP == 0 && r.ConnTotal == 0 && r.DownloadKBs == 0 && r.UploadKBs == 0
}

// RateRule is a number of requests per second or minute, counted per
// visitor or for the whole site, on the whole site or under one path.
type RateRule struct {
	Path    string   `json:"path,omitempty" maxLength:"500" doc:"Empty = the whole site; else this path and everything under it"`
	Rate    int      `json:"rate" minimum:"1" maximum:"1000000"`
	Per     string   `json:"per" enum:"second,minute"`
	Burst   int      `json:"burst,omitempty" minimum:"0" maximum:"100000" doc:"Extra requests let through at once above the rate"`
	Mode    string   `json:"mode,omitempty" enum:",nodelay,queue,delay" doc:"What the burst does: nodelay (default) serves it at once, queue slows it to the rate, delay serves the first ones at once and slows the rest"`
	Delay   int      `json:"delay,omitempty" minimum:"0" maximum:"100000" doc:"With mode delay: how many of the burst go at once"`
	Key     string   `json:"key,omitempty" enum:",ip,site" doc:"ip (default) counts each visitor apart; site counts every visitor together"`
	Methods []string `json:"methods,omitempty" maxItems:"7" doc:"Only these request methods count; empty = all"`
}

// Rate limit answers.
var rateStatuses = []int{429, 503, 444}

// Methods a rule can count.
var rateMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

// HeaderRule sets a header on the way in (to the upstream) or out (to the
// visitor), or takes one of the upstream's out of its answers (hide).
type HeaderRule struct {
	To    string `json:"to" enum:"request,response,hide"`
	Name  string `json:"name" maxLength:"100"`
	Value string `json:"value" maxLength:"2000"`
}

// PathRule does something else for some paths: send them to another
// upstream, redirect, serve files, refuse or answer a fixed text.
type PathRule struct {
	Path  string `json:"path" maxLength:"500" doc:"prefix: starts with /, matches it and everything under it; exact: only this path; regex: a pattern"`
	Match string `json:"match,omitempty" enum:",prefix,exact,regex" doc:"Empty = prefix"`
	// Action: empty = proxy.
	Action       string `json:"action,omitempty" enum:",proxy,redirect,static,deny,return" doc:"Empty = proxy"`
	Upstream     string `json:"upstream,omitempty" doc:"proxy: where requests go; empty = the site's own upstream (proxy sites)"`
	WebSockets   bool   `json:"websockets,omitempty"`
	StripPrefix  bool   `json:"strip_prefix,omitempty" doc:"proxy, prefix: take the path off before sending (/api/users goes as /users)"`
	Public       bool   `json:"public,omitempty" doc:"No sign-in on this path, when the site asks for one"`
	RedirectTo   string `json:"redirect_to,omitempty" doc:"redirect: a full address or a path on this site"`
	RedirectCode int    `json:"redirect_code,omitempty" enum:"0,301,302,307,308" doc:"redirect: 0 = 302"`
	Root         string `json:"root,omitempty" doc:"static: folder served for this path (exact: the file)"`
	Status       int    `json:"status,omitempty" minimum:"0" maximum:"599" doc:"deny: 403, 404, 410 or 444; return: 200–599"`
	Body         string `json:"body,omitempty" maxLength:"4096" doc:"return: the text answered"`
	Advanced     string `json:"advanced,omitempty" maxLength:"4096"`
}

// Problem is one thing wrong with a field, named the way the request body
// spells it (for example "domains[1]" or "tls.key").
type Problem struct {
	Field   string
	Message string
	Value   any
}

func (p Problem) Error() string { return p.Field + ": " + p.Message }

var (
	domainRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	headerRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,100}$`)
	// Paths and file names that need no quoting anywhere.
	cookieRe = regexp.MustCompile(`^[A-Za-z0-9._\-]+$`)
	pathRe   = regexp.MustCompile(`^/[A-Za-z0-9._~@%+=,:/\-]*$`)
)

// Normalize tidies what people type: trims, lowercases names, drops blanks
// and duplicates, and clears fields the type doesn't use.
func Normalize(h HostConfig) HostConfig {
	domains := []string{}
	for _, d := range h.Domains {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d != "" && !slices.Contains(domains, d) {
			domains = append(domains, d)
		}
	}
	h.Domains = domains
	h.Upstream = strings.TrimSpace(h.Upstream)
	h.RedirectTo = strings.TrimSpace(h.RedirectTo)
	h.Root = strings.TrimSpace(h.Root)
	h.StreamTo = strings.ToLower(strings.TrimSpace(h.StreamTo))
	h.TLS.Certificate = strings.TrimSpace(h.TLS.Certificate)
	h.TLS.Key = strings.TrimSpace(h.TLS.Key)
	h.TLS.ClientCA = strings.TrimSpace(h.TLS.ClientCA)
	if !h.TLS.ForceHTTPS {
		h.TLS.ForceCode = 0
	}
	if !h.TLS.HSTS {
		h.TLS.HSTSMaxAge, h.TLS.HSTSSub, h.TLS.HSTSPreload = 0, false, false
	}
	if h.TLS.ClientCA == "" {
		h.TLS.VerifyClient = ""
	}
	if h.Type != TypeStream {
		h.ListenPort, h.Protocol, h.StreamTo = 0, "", ""
	}
	switch h.Type {
	case TypeProxy:
		h.RedirectTo, h.RedirectCode, h.KeepPath, h.Root, h.SPA = "", 0, false, "", false
	case TypeNotFound:
		h.Upstream, h.WebSockets, h.PreserveHost, h.Root, h.SPA = "", false, false, "", false
		h.RedirectTo, h.RedirectCode, h.KeepPath = "", 0, false
		h.Paths, h.TimeoutSeconds, h.MaxBodyMB = []PathRule{}, 0, 0
	case TypeStream:
		h.Domains = []string{}
		h.Upstream, h.WebSockets, h.PreserveHost, h.Root, h.SPA = "", false, false, "", false
		h.RedirectTo, h.RedirectCode, h.KeepPath = "", 0, false
		h.Paths, h.Headers, h.MaxBodyMB, h.TLS = []PathRule{}, []HeaderRule{}, 0, HostTLS{}
		if h.Protocol == "" {
			h.Protocol = "tcp"
		}
	case TypeRedirect:
		h.Upstream, h.WebSockets, h.PreserveHost, h.Root, h.SPA = "", false, false, "", false
		h.Paths, h.TimeoutSeconds = nil, 0
		if h.RedirectCode == 0 {
			h.RedirectCode = 301
		}
	case TypeStatic:
		h.Upstream, h.WebSockets, h.PreserveHost = "", false, false
		h.RedirectTo, h.RedirectCode, h.KeepPath, h.TimeoutSeconds = "", 0, false, 0
	}
	if !h.TLS.Enabled {
		h.TLS = HostTLS{}
	}
	h.Allow, h.Deny = tidyList(h.Allow), tidyList(h.Deny)
	if h.DefaultAccess == "" {
		h.DefaultAccess = "allow"
		if len(h.Allow) > 0 {
			h.DefaultAccess = "deny"
		}
	}
	var countries []string
	for _, c := range h.Countries {
		if c = strings.ToUpper(strings.TrimSpace(c)); c != "" && !slices.Contains(countries, c) {
			countries = append(countries, c)
		}
	}
	h.Countries = countries
	if h.IsStream() || len(h.Countries) == 0 {
		h.Countries, h.CountryMode = nil, ""
	} else if h.CountryMode == "" {
		h.CountryMode = "deny"
	}
	h.RateLimit = normalizeRate(h.RateLimit, h.Type)
	headers := h.Headers[:0:0]
	for _, x := range h.Headers {
		x.Name, x.Value = strings.TrimSpace(x.Name), strings.TrimSpace(x.Value)
		if x.Name != "" {
			headers = append(headers, x)
		}
	}
	h.Headers = headers
	paths := h.Paths[:0:0]
	for _, p := range h.Paths {
		p = normalizePath(p)
		if p.Path != "" || p.Upstream != "" || p.RedirectTo != "" || p.Root != "" {
			paths = append(paths, p)
		}
	}
	h.Paths = paths
	h.Advanced = strings.TrimSpace(strings.ReplaceAll(h.Advanced, "\r\n", "\n"))
	h = normalizeTuning(h)
	h = normalizeFeatures(h)
	h.Custom = strings.TrimSpace(strings.ReplaceAll(h.Custom, "\r\n", "\n"))
	return h
}

// normalizeTuning clears the tuning options a type doesn't use.
func normalizeTuning(h HostConfig) HostConfig {
	if h.Type != TypeProxy && h.Type != TypeStatic {
		h.Gzip = false
	}
	if h.Type != TypeProxy {
		h.NoBuffering = false
	}
	switch h.Type {
	case TypeProxy:
	case TypeStatic:
		h.Cache = Cache{AssetDays: h.Cache.AssetDays, PagesFresh: h.Cache.PagesFresh}
	default:
		h.Cache = Cache{}
	}
	if !h.Cache.Enabled {
		h.Cache = Cache{AssetDays: h.Cache.AssetDays, PagesFresh: h.Cache.PagesFresh}
	}
	h.Cache.SkipPaths = tidyList(h.Cache.SkipPaths)
	h.Cache.SkipCookies = tidyList(h.Cache.SkipCookies)
	if h.Type != TypeProxy && h.Type != TypeStream {
		h.ConnectTimeout = 0
	}
	if h.IsStream() {
		h.RealIP, h.HideVersion = RealIP{}, false
	} else {
		h.ProxyProtocol = false
	}
	h.RealIP.From = tidyList(h.RealIP.From)
	if len(h.RealIP.From) == 0 {
		h.RealIP = RealIP{}
	} else if h.RealIP.Header == "" {
		h.RealIP.Header = "X-Forwarded-For"
	}
	return h
}

// tidyList trims and drops blanks and duplicates.
func tidyList(in []string) []string {
	var out []string
	for _, a := range in {
		if a = strings.TrimSpace(a); a != "" && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// RateLimited says whether a type can limit requests: redirects and 404
// hosts answer before any limit would run.
func RateLimited(t string) bool { return t == TypeProxy || t == TypeStatic || t == TypeStream }

func normalizeRate(r RateLimit, t string) RateLimit {
	if !RateLimited(t) {
		return RateLimit{}
	}
	r.Exempt = tidyList(r.Exempt)
	rules := r.Rules[:0:0]
	for _, x := range r.Rules {
		x.Path = strings.TrimSpace(x.Path)
		if x.Path == "/" {
			x.Path = ""
		}
		if x.Per == "" {
			x.Per = "second"
		}
		if x.Mode == "" {
			x.Mode = "nodelay"
		}
		if x.Key == "" {
			x.Key = "ip"
		}
		if x.Burst == 0 || x.Mode != "delay" {
			x.Delay = 0
		}
		var methods []string
		for _, m := range x.Methods {
			if m = strings.ToUpper(strings.TrimSpace(m)); m != "" && !slices.Contains(methods, m) {
				methods = append(methods, m)
			}
		}
		x.Methods = methods
		if t == TypeStream {
			continue
		}
		rules = append(rules, x)
	}
	r.Rules = rules
	if t == TypeStream {
		r.FullSpeedMB = 0
	} else {
		r.UploadKBs = 0
	}
	if r.DownloadKBs == 0 {
		r.FullSpeedMB = 0
	}
	if r.IsZero() {
		return RateLimit{}
	}
	if r.Status == 0 {
		r.Status = 429
	}
	return r
}

// validAddress accepts an address or a range.
func validAddress(a string) bool {
	if _, err := netip.ParsePrefix(a); err == nil {
		return true
	}
	_, err := netip.ParseAddr(a)
	return err == nil
}

// Validate checks a normalized host. Every value that ends up in a config
// file is checked here, so a driver can write them without quoting tricks.
func Validate(h HostConfig) []Problem {
	var out []Problem
	add := func(field, msg string, v any) { out = append(out, Problem{field, msg, v}) }
	if len(h.Domains) == 0 && !h.IsStream() && !h.CatchAll {
		add("domains", "Add at least one domain.", nil)
	}
	for i, d := range h.Domains {
		if !validDomain(d) {
			add(fmt.Sprintf("domains[%d]", i), "Not a domain name (like example.com or *.example.com).", d)
		}
	}
	switch h.Type {
	case TypeProxy:
		if msg := checkUpstream(h.Upstream); msg != "" {
			add("upstream", msg, h.Upstream)
		}
	case TypeRedirect:
		if msg := checkURL(h.RedirectTo); msg != "" {
			add("redirect_to", msg, h.RedirectTo)
		}
		if !slices.Contains([]int{301, 302, 307, 308}, h.RedirectCode) {
			add("redirect_code", "Use 301, 302, 307 or 308.", h.RedirectCode)
		}
	case TypeStatic:
		if !safePath(h.Root) {
			add("root", "Use a full folder path, like /var/www/site (letters, digits and . _ - / only).", h.Root)
		}
	case TypeNotFound:
	case TypeStream:
		switch {
		case h.ListenPort < 1 || h.ListenPort > 65535:
			add("listen_port", "Use a port from 1 to 65535.", h.ListenPort)
		case h.Protocol == "tcp" && (h.ListenPort == 80 || h.ListenPort == 443):
			add("listen_port", "80 and 443 carry the sites; pick another port.", h.ListenPort)
		}
		if h.Protocol != "tcp" && h.Protocol != "udp" {
			add("protocol", "Choose tcp or udp.", h.Protocol)
		}
		if msg := checkHostPort(h.StreamTo); msg != "" {
			add("stream_to", msg, h.StreamTo)
		}
	default:
		add("type", "Choose proxy, redirect, static, 404 or stream.", h.Type)
	}
	if h.TLS.Enabled {
		if !safePath(h.TLS.Certificate) {
			add("tls.certificate", "Use the full path of the certificate file.", h.TLS.Certificate)
		}
		if !safePath(h.TLS.Key) {
			add("tls.key", "Use the full path of the key file.", h.TLS.Key)
		}
		if h.TLS.ClientCA != "" && !safePath(h.TLS.ClientCA) {
			add("tls.client_ca", "Use the full path of the CA file.", h.TLS.ClientCA)
		}
		if h.TLS.ClientCA != "" && h.TLS.VerifyClient == "" {
			add("tls.verify_client", "Choose whether a client certificate is required or optional.", "")
		}
		if h.TLS.HSTSPreload && (!h.TLS.HSTSSub || h.TLS.HSTSMaxAge != 0 && h.TLS.HSTSMaxAge < 31536000) {
			add("tls.hsts_preload", "Preloading needs subdomains included and at least a year.", "")
		}
	}
	for i, a := range h.Allow {
		if !validAddress(a) {
			add(fmt.Sprintf("allow[%d]", i), "Not an address or range (like 10.0.0.0/8).", a)
		}
	}
	for i, a := range h.Deny {
		switch {
		case !validAddress(a):
			add(fmt.Sprintf("deny[%d]", i), "Not an address or range (like 10.0.0.0/8).", a)
		case slices.ContainsFunc(h.Allow, func(b string) bool { return SameAddress(a, b) }):
			add(fmt.Sprintf("deny[%d]", i), "This is also in the list let in; keep it in one list.", a)
		}
	}
	if h.DefaultAccess != "allow" && h.DefaultAccess != "deny" {
		add("default_access", "Choose allow or deny.", h.DefaultAccess)
	}
	for i, c := range h.Countries {
		if !countryRe.MatchString(c) {
			add(fmt.Sprintf("countries[%d]", i), "Use a two-letter country code, like DE.", c)
		}
	}
	if len(h.Countries) > 0 && h.CountryMode != "allow" && h.CountryMode != "deny" {
		add("country_mode", "Choose allow or deny.", h.CountryMode)
	}
	validateRate(h.RateLimit, add)
	for i, x := range h.Headers {
		switch {
		case x.To != "request" && x.To != "response" && x.To != "hide":
			add(fmt.Sprintf("headers[%d].to", i), "Choose request, response or hide.", x.To)
		case x.To == "hide" && h.Type != TypeProxy:
			add(fmt.Sprintf("headers[%d].to", i), "Only proxy sites have an upstream's headers to hide.", x.To)
		}
		if !headerRe.MatchString(x.Name) {
			add(fmt.Sprintf("headers[%d].name", i), "Letters, digits and - only.", x.Name)
		}
		if strings.ContainsAny(x.Value, "\"\\\n\r") {
			add(fmt.Sprintf("headers[%d].value", i), "Quotes, backslashes and line breaks aren't allowed.", x.Value)
		}
	}
	seen := map[string]bool{}
	for i, p := range h.Paths {
		validatePath(h, i, p, add)
		key := p.MatchOf() + " " + p.Path
		if seen[key] {
			add(fmt.Sprintf("paths[%d].path", i), "This path is listed twice.", p.Path)
		}
		seen[key] = true
	}
	validateFeatures(h, add)
	if msg := checkAdvanced(h.Advanced); msg != "" {
		add("advanced", msg, nil)
	}
	for i, a := range h.RealIP.From {
		if !validAddress(a) {
			add(fmt.Sprintf("real_ip.from[%d]", i), "Not an address or range (like 173.245.48.0/20).", a)
		}
	}
	if h.RealIP.Header != "" && !slices.Contains(RealIPHeaders, h.RealIP.Header) {
		add("real_ip.header", "Choose one of "+strings.Join(RealIPHeaders, ", ")+".", h.RealIP.Header)
	}
	if h.Cache.Enabled && h.NoBuffering {
		add("cache.enabled", "Pass straight through (Advanced) leaves nothing to keep: turn one of them off.", true)
	}
	for i, p := range h.Cache.SkipPaths {
		if !pathRe.MatchString(p) {
			add(fmt.Sprintf("cache.skip_paths[%d]", i), "Start with / and use letters, digits and . _ - / only.", p)
		}
	}
	for i, c := range h.Cache.SkipCookies {
		if !cookieRe.MatchString(c) {
			add(fmt.Sprintf("cache.skip_cookies[%d]", i), "Letters, digits and . _ - only.", c)
		}
	}
	if h.IsCustom() {
		if msg := checkCustom(h.Custom); msg != "" {
			add("custom", msg, nil)
		}
	}
	return out
}

// checkCustom keeps a hand-written file balanced and away from the markers
// the scripts use to write it.
func checkCustom(s string) string {
	for i, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "MORCHEH_") || strings.Contains(line, "@@morcheh-") {
			return fmt.Sprintf("Line %d starts with a word Morcheh keeps for itself (MORCHEH_ / @@morcheh-).", i+1)
		}
	}
	return checkAdvanced(s)
}

var countryRe = regexp.MustCompile(`^[A-Z]{2}$`)

// SameAddress says whether two entries name the same addresses (10.0.0.1
// and 10.0.0.1/32 do).
func SameAddress(a, b string) bool {
	pa, ea := ParseAddress(a)
	pb, eb := ParseAddress(b)
	return ea == nil && eb == nil && pa == pb
}

// ParseAddress reads an address or range as a range (an address is a range
// of one), masked.
func ParseAddress(a string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(a); err == nil {
		return p.Masked(), nil
	}
	ip, err := netip.ParseAddr(a)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(ip, ip.BitLen()), nil
}

func validateRate(r RateLimit, add func(field, msg string, v any)) {
	if r.IsZero() {
		return
	}
	if !slices.Contains(rateStatuses, r.Status) {
		add("rate_limit.status", "Use 429, 503 or 444.", r.Status)
	}
	for i, a := range r.Exempt {
		if !validAddress(a) {
			add(fmt.Sprintf("rate_limit.exempt[%d]", i), "Not an address or range (like 10.0.0.0/8).", a)
		}
	}
	seen := map[string]bool{}
	for i, x := range r.Rules {
		f := fmt.Sprintf("rate_limit.rules[%d]", i)
		if x.Path != "" && !pathRe.MatchString(x.Path) {
			add(f+".path", "Start with / and use letters, digits and . _ - / only.", x.Path)
		}
		if x.Rate < 1 {
			add(f+".rate", "Allow at least 1 request.", x.Rate)
		}
		if x.Per != "second" && x.Per != "minute" {
			add(f+".per", "Choose second or minute.", x.Per)
		}
		if x.Mode != "nodelay" && x.Mode != "queue" && x.Mode != "delay" {
			add(f+".mode", "Choose nodelay, queue or delay.", x.Mode)
		}
		if x.Key != "ip" && x.Key != "site" {
			add(f+".key", "Choose ip or site.", x.Key)
		}
		if x.Mode == "delay" && x.Burst > 0 && (x.Delay < 1 || x.Delay >= x.Burst) {
			add(f+".delay", fmt.Sprintf("Use 1 to %d: fewer than the burst.", max(x.Burst-1, 1)), x.Delay)
		}
		for _, m := range x.Methods {
			if !slices.Contains(rateMethods, m) {
				add(f+".methods", "Use GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS.", m)
				break
			}
		}
		key := fmt.Sprintf("%s|%s|%s|%s", x.Path, x.Key, x.Per, strings.Join(slices.Sorted(slices.Values(x.Methods)), ","))
		if seen[key] {
			add(f+".path", "Another limit already counts the same requests here.", x.Path)
		}
		seen[key] = true
	}
}

func validDomain(d string) bool {
	if len(d) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return true
	}
	return domainRe.MatchString(d)
}

func safePath(p string) bool {
	return pathRe.MatchString(p) && !slices.Contains(strings.Split(p, "/"), "..")
}

// checkHostPort accepts host:port, [v6]:port included.
func checkHostPort(s string) string {
	if s == "" {
		return "Say where connections go, like 10.0.0.5:5432."
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return "Use host:port, like 10.0.0.5:5432 or db.internal:5432."
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "The port must be from 1 to 65535."
	}
	if _, err := netip.ParseAddr(host); err != nil && !domainRe.MatchString(host) {
		return "Not an address or host name."
	}
	return ""
}

func checkUpstream(s string) string {
	if s == "" {
		return "Say where requests go, like http://127.0.0.1:3000."
	}
	return checkURL(s)
}

// checkURL accepts an http(s) address with nothing a config file would need
// to quote.
func checkURL(s string) string {
	if s == "" {
		return "Enter an address."
	}
	if strings.ContainsAny(s, " \t\n\r\"'`;{}\\") {
		return "Spaces, quotes, ; { } and \\ aren't allowed."
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "Use a full address starting with http:// or https://."
	}
	if u.User != nil {
		return "Leave the user name and password out of the address."
	}
	return ""
}

// checkAdvanced keeps raw directives from closing the block they sit in.
func checkAdvanced(s string) string {
	depth := 0
	quote := rune(0)
	for i, line := range strings.Split(s, "\n") {
		for _, r := range line {
			switch {
			case quote != 0:
				if r == quote {
					quote = 0
				}
			case r == '#':
				goto next
			case r == '"' || r == '\'':
				quote = r
			case r == '{':
				depth++
			case r == '}':
				depth--
				if depth < 0 {
					return fmt.Sprintf("Line %d closes a block it didn't open.", i+1)
				}
			}
		}
	next:
	}
	if quote != 0 {
		return "A quote is never closed."
	}
	if depth != 0 {
		return "A { is never closed."
	}
	return ""
}

// Overlaps finds names used by two hosts: each result is a domain of b that a
// already answers.
func Overlaps(a, b []string) []string {
	var out []string
	for _, d := range b {
		if slices.Contains(a, d) {
			out = append(out, d)
		}
	}
	return out
}

// Capabilities says which parts of HostConfig a kind can serve, so the panel
// shows only what works.
type Capabilities struct {
	Types        []string `json:"types"`
	WebSockets   bool     `json:"websockets"`
	Headers      bool     `json:"headers"`
	Paths        bool     `json:"paths"`
	Allow        bool     `json:"allow" doc:"Lists of addresses let in or refused"`
	Countries    bool     `json:"countries" doc:"Can let in or refuse visitors by country (sites only)"`
	RateLimit    bool     `json:"rate_limit" doc:"Can limit requests, connections and speed"`
	Advanced     bool     `json:"advanced" doc:"Raw directives in the proxy's own language"`
	Cache        bool     `json:"cache" doc:"Takes cache (browsers, and the proxy's own cache for proxy sites) and can clear it"`
	Tuning       bool     `json:"tuning" doc:"Takes the tuning options: gzip, no_buffering, connect_timeout_seconds, real_ip, proxy_protocol, hide_version"`
	Streams      bool     `json:"streams" doc:"Can forward TCP/UDP ports (type stream)"`
	Traffic      bool     `json:"traffic" doc:"Reports live request counts per site"`
	Certificates bool     `json:"certificates" doc:"Can get certificates on the server (ACME CAs like Let's Encrypt, self-signed, uploaded)"`
	TLSOptions   bool     `json:"tls_options" doc:"Takes HostTLS's extra settings (profile, HTTP/3, OCSP, session cache, client certificates)"`
	Auth         bool     `json:"auth" doc:"Takes auth: basic sign-in, and forward when the server's proxy can"`
	Pages        bool     `json:"pages" doc:"Takes maintenance and error_pages"`
	Hardening    bool     `json:"hardening" doc:"Takes hardening, request_id and catch_all"`
	UpstreamTLS  bool     `json:"upstream_tls" doc:"Takes upstream_tls"`
	PathActions  bool     `json:"path_actions" doc:"Paths take match and action (redirect, static, deny, return), strip_prefix and public"`
	Language     string   `json:"language" doc:"The config language, for syntax colors"`
	ConfigLabel  string   `json:"config_label" doc:"What its config is called, like nginx config"`
}

// Env is what rendering needs to know about the server.
type Env struct {
	Version string // like 1.24.0; empty = unknown
	IPv6    bool
	// QUICReuseport: this host carries reuseport on its HTTP/3 listen; only
	// one host on the server may.
	QUICReuseport bool
	// Brotli: the brotli module is loaded; CABundle is the system's CA file.
	Brotli   bool
	CABundle string
}

// File is one host rendered for the server.
type File struct {
	ID     string
	Config HostConfig
	Text   string
}

// Setup is what a driver's setup needs from the server.
type Setup struct {
	Init string
	PM   string // package manager: apt-get, dnf, yum, apk, zypper, pacman, or ""
	// Install is a script installing packages with PM (it fails when there
	// is none).
	Install func(pkgs ...string) string
}

// Hit is a count of requests in one minute with one status class.
type Hit struct {
	Host     string    // host id
	Minute   time.Time // start of the minute
	Class    int       // 2, 3, 4, 5; 0 = anything else
	Requests int64
	Bytes    int64
}

// LogMark is how far a host's access log was read: the file (inode) and
// the size seen.
type LogMark struct {
	Inode string
	Size  int64
}

// Status is the proxy's state on its server.
type Status struct {
	Installed   bool
	Version     string
	Running     bool
	Enabled     bool // starts at boot
	SetUp       bool // the panel's sites are loaded
	ConfigOK    bool
	ConfigError string
	IPv6        bool
	Init        string
	// Streams: "ready", "no_module" (the kind can't forward ports here
	// yet), "not_wired" (setup hasn't added it) or "taken" (the config
	// already has its own block for them).
	Streams string
	// Geo: "ready" (the IP-to-country lookup works), "off" (not set up yet)
	// or "" (the kind can't).
	Geo string
	// HTTP3: the proxy was built with HTTP/3 (QUIC).
	HTTP3 bool
	// Certbot is its version when installed (it gets and renews
	// certificates), else "".
	Certbot string
	// AuthRequest: forward auth works (nginx's auth_request module).
	AuthRequest bool
	// Brotli: the brotli module is loaded.
	Brotli bool
	// CABundle is the system's CA file, for checking https upstreams.
	CABundle string
}

// Site is a server block (or the kind's equivalent) found in the live config.
type Site struct {
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Domains  []string `json:"domains"`
	Listen   []string `json:"listen"`
	TLS      bool     `json:"tls"`
	Upstream string   `json:"upstream,omitempty"`
	Root     string   `json:"root,omitempty"`
	Redirect string   `json:"redirect,omitempty"`
	Text     string   `json:"text,omitempty"`
	Managed  bool     `json:"managed" doc:"Written by Morcheh"`
}

// Certificate is one found on the server: certbot's live folders and the
// ones Morcheh made or was given (/etc/ssl/morcheh).
type Certificate struct {
	Name        string     `json:"name"`
	Certificate string     `json:"certificate"`
	Key         string     `json:"key"`
	Domains     []string   `json:"domains"`
	Expires     *time.Time `json:"expires,omitempty"`
	Issuer      string     `json:"issuer,omitempty" doc:"Who signed it, like Let's Encrypt; Self-signed when it signed itself"`
	Source      string     `json:"source" enum:"certbot,morcheh" doc:"certbot = renewed by certbot on the server; morcheh = uploaded or self-signed through the panel, never renewed"`
}

// Inspection is everything the overview shows, read in one go.
type Inspection struct {
	Status
	Files        map[string]string // managed host id → its file on the server
	Sites        []Site
	Certificates []Certificate
}

// Driver is one proxy kind.
type Driver interface {
	Kind() string
	Label() string
	Capabilities() Capabilities
	// Validate adds the kind's own checks to Validate.
	Validate(h HostConfig) []Problem
	// Render is one host's config file.
	Render(id string, h HostConfig, env Env) string
	// InspectScript reads everything; ParseInspect reads its output.
	InspectScript() string
	ParseInspect(out string) Inspection
	// SetupScript installs the proxy when it's missing, wires it up and
	// starts it.
	SetupScript(s Setup) string
	// GeoScript turns the IP-to-country lookup on: the module, the database
	// and its monthly refresh.
	GeoScript(s Setup) string
	// ApplyScript replaces every managed file with files, tests the config
	// and reloads, putting the old files back on failure.
	ApplyScript(files []File) string
	// TestScript is ApplyScript without keeping anything: the files go in,
	// the config is tested (exit ExitTestFailed when refused, printing why)
	// and the old files come back. Nothing is reloaded.
	TestScript(files []File) string
	// TrafficScript reads what was added to the hosts' access logs since
	// marks; ParseTraffic reads its output.
	TrafficScript(hosts []string, marks map[string]LogMark) string
	ParseTraffic(out string) ([]Hit, map[string]LogMark)
	// CertificateScript gets or writes one certificate (see CertRequest).
	// It ends with exit 0 and the files in place, or prints why not.
	CertificateScript(r CertRequest, s Setup) string
	// PurgeCacheScript empties a site's own cache (Capabilities.Cache).
	PurgeCacheScript(hostID string) string
	// RemoveScript takes everything Morcheh wrote off the server.
	RemoveScript() string
	// ActionScript is test, reload, start, stop or restart.
	ActionScript(action, init string) (string, error)
	// LogScript prints the last lines of a host's log ("" = the proxy's own).
	LogScript(hostID, log string, lines int) string
}

// Exit codes the scripts share.
const (
	ExitNotInstalled = 5
	ExitTestFailed   = 3
	ExitReloadFailed = 4
	ExitNoStreams    = 6
	ExitPortTaken    = 7
)

var drivers = map[string]Driver{}

// Register adds a kind; drivers call it from init.
func Register(d Driver) { drivers[d.Kind()] = d }

// Get returns the driver of a kind.
func Get(kind string) (Driver, bool) {
	d, ok := drivers[kind]
	return d, ok
}

// Kinds lists every registered driver.
func Kinds() []Driver {
	out := make([]Driver, 0, len(drivers))
	for _, d := range drivers {
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b Driver) int { return strings.Compare(a.Kind(), b.Kind()) })
	return out
}
