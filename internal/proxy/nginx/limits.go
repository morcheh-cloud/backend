package nginx

import (
	"fmt"
	"hash/fnv"
	"regexp"
	"slices"
	"strings"

	"github.com/morcheh/backend/internal/proxy"
)

// Who may visit and how much they may ask. nginx's names for zones and
// variables are global, so each host's start with its tag; a zone's name also
// carries a hash of its key, since nginx refuses a reload that keeps a name
// but changes the key.

// GeoDir holds the IP-to-country database and the file that loads it.
const (
	GeoDir    = Dir + "/geo"
	GeoDB     = GeoDir + "/country.mmdb"
	GeoConf   = GeoDir + "/country.conf"
	GeoUpdate = GeoDir + "/update.sh"
	// GeoStream loads the database for port forwards (in stream {}).
	GeoStream = GeoDir + "/country.stream"
	// countryVar is the visitor's country code, set by GeoConf.
	countryVar = "$morcheh_country"
	// acmePath matches Let's Encrypt's challenge requests, which no country
	// rule or rate limit may stop (acmeLocation lets every address in).
	acmePath = `~^/\.well-known/acme-challenge/`
)

// tag is the start of a host's variable and zone names. It stays short:
// nginx's variables hash (variables_hash_bucket_size 64 by default) refuses
// a variable name over 46 characters, and the longest suffix is 12. So a
// real id (a UUID) becomes 12 hex characters of its hash.
func tag(id string) string {
	if d := cacheDirName(id); len(d) <= len("morcheh_")+12 {
		return d
	}
	f := fnv.New64a()
	f.Write([]byte(id))
	return fmt.Sprintf("morcheh_%012x", f.Sum64()&(1<<48-1))
}

// cacheDirName names a site's cache folder under CacheDir: the whole id,
// as it always was, so answers kept before stay found.
func cacheDirName(id string) string {
	return "morcheh_" + strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' {
			return r
		}
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return -1
	}, id)
}

func short(parts ...string) string {
	f := fnv.New32a()
	f.Write([]byte(strings.Join(parts, "\x00")))
	return fmt.Sprintf("%08x", f.Sum32())
}

// entry is one address or range of the access lists.
type entry struct {
	addr  string
	allow bool
	bits  int
}

// entries lists allow and deny, the narrowest range first: with nginx's
// "first match wins" that makes the most specific entry decide, like geo.
func entries(h proxy.HostConfig) []entry {
	var out []entry
	add := func(list []string, allow bool) {
		for _, a := range list {
			bits := 0
			if p, err := proxy.ParseAddress(a); err == nil {
				bits = p.Bits()
				if p.Addr().Is4() {
					bits += 96
				}
			}
			out = append(out, entry{a, allow, bits})
		}
	}
	add(h.Allow, true)
	add(h.Deny, false)
	slices.SortStableFunc(out, func(a, b entry) int { return b.bits - a.bits })
	return out
}

// accessBlocks are the http-level parts of a country rule: the visitor's
// address and country each give "a" (let in), "d" (refuse) or "n" (no say),
// and the address wins.
func accessBlocks(w *writer, t string, h proxy.HostConfig) {
	if len(h.Countries) == 0 {
		return
	}
	yes, no := "a", "d"
	other, unknown, listed := no, no, yes
	if h.DefaultAccess == "allow" {
		unknown = yes
	}
	if h.CountryMode == "deny" {
		listed, other = no, unknown
	}
	w.line("")
	w.line("# Who can visit: addresses first, then countries.")
	list := entries(h)
	if len(list) > 0 {
		w.open("geo $%s_ip", t)
		w.line("default n;")
		for _, e := range list {
			v := no
			if e.allow {
				v = yes
			}
			w.line("%s %s;", e.addr, v)
		}
		w.close()
	}
	w.open("map %s $%s_cc", countryVar, t)
	w.line("default %s;", other)
	w.line(`"" %s;`, unknown)
	for _, c := range h.Countries {
		w.line("%s %s;", c, listed)
	}
	w.close()
	// volatile: an error page's internal redirect must see its own $uri.
	w.open("map $uri $%s_acme", t)
	w.line("volatile;")
	w.line("default 0;")
	w.line("%s 1;", acmePath)
	w.line(`"~^%s" 1;`, regexp.QuoteMeta(internalPrefix))
	w.close()
	if len(list) > 0 {
		w.open(`map "$%s_acme:$%s_ip:$%s_cc" $%s_block`, t, t, t, t)
		w.line("volatile;")
		w.line("default 0;")
		w.line(`"0:d:a" 1;`)
		w.line(`"0:d:d" 1;`)
		w.line(`"0:n:d" 1;`)
		w.close()
		return
	}
	w.open(`map "$%s_acme:$%s_cc" $%s_block`, t, t, t)
	w.line("volatile;")
	w.line("default 0;")
	w.line(`"0:d" 1;`)
	w.close()
}

// access is the server-level part: a country rule's check, or plain allow
// and deny lines.
func access(w *writer, t string, h proxy.HostConfig) {
	if len(h.Countries) > 0 {
		w.line("")
		w.open("if ($%s_block)", t)
		w.line("return 403;")
		w.close()
		return
	}
	list := entries(h)
	if len(list) == 0 && h.DefaultAccess != "deny" {
		return
	}
	w.line("")
	for _, e := range list {
		if e.allow {
			w.line("allow %s;", e.addr)
		} else {
			w.line("deny %s;", e.addr)
		}
	}
	if h.DefaultAccess == "deny" {
		w.line("deny all;")
	}
}

// ---- Rate limits ----

type limitRule struct {
	proxy.RateRule
	zone string
}

// limits is a host's rate limits with their zone names worked out.
type limits struct {
	r      proxy.RateLimit
	stream bool
	rules  []limitRule
	// connIP and connSite are the connection zones ("" = no limit).
	connIP, connSite string
	// blocks are the http- (or stream-) level lines, written before the
	// server blocks.
	blocks writer
	keys   map[string]string
	t      string
}

func newLimits(t string, h proxy.HostConfig) *limits {
	l := &limits{r: h.RateLimit, stream: h.IsStream(), keys: map[string]string{}, t: t}
	if l.r.IsZero() {
		return l
	}
	b := &l.blocks
	b.line("")
	b.line("# Rate limits")
	// $<tag>_free is 1 for requests no limit counts: exempt addresses and,
	// on sites, Let's Encrypt's challenges.
	ip := fmt.Sprintf("$%s_free", t)
	if !l.stream {
		ip = fmt.Sprintf("$%s_free_ip", t)
	}
	if len(l.r.Exempt) > 0 {
		b.open("geo %s", ip)
		b.line("default 0;")
		for _, a := range l.r.Exempt {
			b.line("%s 1;", a)
		}
		b.close()
	}
	if !l.stream {
		if len(l.r.Exempt) > 0 {
			b.open(`map "%s:$uri" $%s_free`, ip, t)
			b.line("default 0;")
			b.line("~^1: 1;")
			b.line("~^0:/\\.well-known/acme-challenge/ 1;")
		} else {
			b.open("map $uri $%s_free", t)
			b.line("default 0;")
			b.line("%s 1;", acmePath)
		}
		b.close()
	}
	for _, x := range l.r.Rules {
		key := l.key(x.Key, x.Methods)
		zone := fmt.Sprintf("%s_req_%s", t, short(key, fmt.Sprint(x.Rate), x.Per))
		per := "r/s"
		if x.Per == "minute" {
			per = "r/m"
		}
		if !slices.ContainsFunc(l.rules, func(r limitRule) bool { return r.zone == zone }) {
			b.line("limit_req_zone %s zone=%s:%s rate=%d%s;", key, zone, zoneSize(x.Key), x.Rate, per)
		}
		l.rules = append(l.rules, limitRule{x, zone})
	}
	conn := func(kind string) string {
		key := l.key(kind, nil)
		zone := fmt.Sprintf("%s_conn_%s", t, short(key))
		b.line("limit_conn_zone %s zone=%s:%s;", key, zone, zoneSize(kind))
		return zone
	}
	if l.r.ConnPerIP > 0 {
		l.connIP = conn("ip")
	}
	if l.r.ConnTotal > 0 {
		l.connSite = conn("site")
	}
	return l
}

func zoneSize(key string) string {
	if key == "site" {
		return "1m"
	}
	return "10m"
}

// key is what a limit counts by: the visitor's address or one bucket for
// the whole site, made empty (not counted) for exempt addresses, ACME
// challenges and methods the rule leaves out.
func (l *limits) key(kind string, methods []string) string {
	base := "$binary_remote_addr"
	if kind == "site" {
		base = "$server_name"
		if l.stream {
			base = "$server_port"
		}
	}
	exempt := len(l.r.Exempt) > 0 || !l.stream
	if !exempt && len(methods) == 0 {
		return base
	}
	sorted := slices.Sorted(slices.Values(methods))
	name := fmt.Sprintf("$%s_key_%s", l.t, short(base, strings.Join(sorted, ",")))
	if _, ok := l.keys[name]; ok {
		return name
	}
	l.keys[name] = base
	b := &l.blocks
	switch {
	case len(methods) == 0:
		b.open("map $%s_free %s", l.t, name)
		b.line("default %s;", base)
		b.line(`1 "";`)
	case !exempt:
		b.open("map $request_method %s", name)
		b.line(`default "";`)
		for _, m := range sorted {
			b.line("%s %s;", m, base)
		}
	default:
		b.open(`map "$%s_free:$request_method" %s`, l.t, name)
		b.line(`default "";`)
		for _, m := range sorted {
			b.line(`"0:%s" %s;`, m, base)
		}
	}
	b.close()
	return name
}

func (l *limits) any() bool { return !l.r.IsZero() }

// pathRules are the rules on one path, not the whole site.
func (l *limits) pathRules() bool {
	return slices.ContainsFunc(l.rules, func(r limitRule) bool { return r.Path != "" })
}

func reqLine(w *writer, r limitRule) {
	s := "limit_req zone=" + r.zone
	if r.Burst > 0 {
		s += fmt.Sprintf(" burst=%d", r.Burst)
		switch r.Mode {
		case "nodelay":
			s += " nodelay"
		case "delay":
			s += fmt.Sprintf(" delay=%d", r.Delay)
		}
	}
	w.line("%s;", s)
}

// server writes the limits that hold for the whole site.
func (l *limits) server(w *writer, env proxy.Env) {
	if !l.any() {
		return
	}
	dry := l.r.DryRun && (env.Version == "" || atLeast(env.Version, 1, 17, 6))
	w.line("")
	if l.r.DryRun && !dry {
		w.line("# Dry run needs nginx 1.17.6 or later: these limits are enforced.")
	}
	if len(l.rules) > 0 {
		w.line("limit_req_status %d;", l.r.Status)
		if dry {
			w.line("limit_req_dry_run on;")
		}
		for _, r := range l.rules {
			if r.Path == "" {
				reqLine(w, r)
			}
		}
	}
	if l.connIP != "" || l.connSite != "" {
		if !l.stream {
			w.line("limit_conn_status %d;", l.r.Status)
		}
		if dry {
			w.line("limit_conn_dry_run on;")
		}
		if l.connIP != "" {
			w.line("limit_conn %s %d;", l.connIP, l.r.ConnPerIP)
		}
		if l.connSite != "" {
			w.line("limit_conn %s %d;", l.connSite, l.r.ConnTotal)
		}
	}
	if l.stream {
		if l.r.DownloadKBs > 0 {
			w.line("proxy_download_rate %dk;", l.r.DownloadKBs)
		}
		if l.r.UploadKBs > 0 {
			w.line("proxy_upload_rate %dk;", l.r.UploadKBs)
		}
		return
	}
	if l.r.DownloadKBs > 0 {
		w.line("limit_rate %dk;", l.r.DownloadKBs)
		if l.r.FullSpeedMB > 0 {
			w.line("limit_rate_after %dm;", l.r.FullSpeedMB)
		}
	}
}

// location writes the request limits of a location at path. A location with
// its own limit_req stops inheriting the site's, so they're repeated.
func (l *limits) location(w *writer, path string) {
	if !l.pathRules() {
		return
	}
	var own []limitRule
	for _, r := range l.rules {
		if r.Path != "" && strings.HasPrefix(path, r.Path) {
			own = append(own, r)
		}
	}
	if len(own) == 0 {
		return
	}
	for _, r := range l.rules {
		if r.Path == "" {
			reqLine(w, r)
		}
	}
	for _, r := range own {
		reqLine(w, r)
	}
}

// extraPaths are the paths limited that no Paths entry serves: each gets a
// location doing what the site does.
func (l *limits) extraPaths(h proxy.HostConfig) []string {
	var out []string
	for _, r := range l.rules {
		if r.Path == "" || slices.Contains(out, r.Path) {
			continue
		}
		if slices.ContainsFunc(h.Paths, func(p proxy.PathRule) bool { return p.Path == r.Path }) {
			continue
		}
		out = append(out, r.Path)
	}
	return out
}

// streamCountries is a port forward's country rule. stream {} has no if or
// return, so the check picks where the connection goes: the real upstream,
// or one that's never up (nginx closes the connection). The address lists
// are part of it, like a site's.
func streamCountries(w *writer, t string, h proxy.HostConfig) {
	if len(h.Countries) == 0 {
		return
	}
	yes, no := "a", "d"
	other, unknown, listed := no, no, yes
	if h.DefaultAccess == "allow" {
		unknown = yes
	}
	if h.CountryMode == "deny" {
		listed, other = no, unknown
	}
	target := t + "_main"
	if h.Balance.On() {
		target = poolName(t)
	} else {
		w.line("")
		w.open("upstream %s", target)
		w.line("server %s;", h.StreamTo)
		w.close()
	}
	refuse := t + "_refuse"
	w.line("")
	w.open("upstream %s", refuse)
	w.line("server 127.0.0.1:1 down;")
	w.close()
	w.line("")
	w.line("# Who can connect: addresses first, then countries.")
	list := entries(h)
	if len(list) > 0 {
		w.open("geo $%s_ip", t)
		w.line("default n;")
		for _, e := range list {
			v := no
			if e.allow {
				v = yes
			}
			w.line("%s %s;", e.addr, v)
		}
		w.close()
	}
	w.open("map %s $%s_cc", countryVar, t)
	w.line("default %s;", other)
	w.line(`"" %s;`, unknown)
	for _, c := range h.Countries {
		w.line("%s %s;", c, listed)
	}
	w.close()
	if len(list) > 0 {
		w.open(`map "$%s_ip:$%s_cc" $%s_to`, t, t, t)
		w.line("default %s;", target)
		w.line(`"d:a" %s;`, refuse)
		w.line(`"d:d" %s;`, refuse)
		w.line(`"n:d" %s;`, refuse)
		w.close()
		return
	}
	w.open("map $%s_cc $%s_to", t, t)
	w.line("default %s;", target)
	w.line("d %s;", refuse)
	w.close()
}
