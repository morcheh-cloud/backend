package nginx

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/morcheh/backend/internal/proxy"
)

// gzipTypes are the text types worth compressing (text/html always is).
var gzipTypes = []string{
	"text/plain", "text/css", "text/xml", "text/javascript",
	"application/javascript", "application/json", "application/xml",
	"application/rss+xml", "application/atom+xml", "application/manifest+json",
	"application/wasm", "image/svg+xml", "font/ttf", "font/otf",
}

// CacheDir holds the proxy caches, one folder per site; nginx makes the
// site's folder itself.
const CacheDir = "/var/cache/morcheh-nginx"

// assetTypes are the answers (by Content-Type) browsers may keep.
var assetTypes = []string{
	`~^text/css`, `~javascript`, `~^image/`, `~^font/`,
	`~^application/(?:font|x-font|vnd\.ms-fontobject|wasm)`, `~^(?:audio|video)/`,
}

// cacheBlocks are the http-level lines of a site's cache: the cache itself,
// the browser lifetimes by type and what skips the cache.
func cacheBlocks(w *writer, id, t string, h proxy.HostConfig) {
	c := h.Cache
	if c.Browser() {
		w.line("")
		w.open("map $sent_http_content_type $%s_expires", t)
		w.line("default off;")
		if c.PagesFresh {
			w.line("~^text/html -1;")
		}
		if c.AssetDays > 0 {
			for _, a := range assetTypes {
				w.line(`"%s" %dd;`, a, c.AssetDays)
			}
		}
		w.close()
	}
	if !c.Keeps() {
		return
	}
	inactive := max(c.LongestMinutes(), 1440)
	if c.Online.On() {
		inactive = max(inactive, c.Online.Days()*1440)
	}
	w.line("")
	w.line("proxy_cache_path %s/%s levels=1:2 keys_zone=%s_cache:10m max_size=%dm inactive=%dm use_temp_path=off;",
		CacheDir, cacheDirName(id), t, c.SizeMB(), inactive)
	varyMaps(w, t, c)
	if backupOnly(c) && !c.Online.KeepPrivate {
		// The app's Cache-Control is ignored for the copies' freshness, so
		// its "this page is one person's" is read here instead.
		w.open("map $upstream_http_cache_control $%s_private", t)
		w.line("default 0;")
		w.line(`"~*(?:private|no-store)" 1;`)
		w.close()
	}
	if len(c.SkipPaths) > 0 {
		w.open("map $uri $%s_skip_path", t)
		w.line("default 0;")
		for _, p := range c.SkipPaths {
			if strings.HasSuffix(p, "/") {
				w.line(`"~^%s" 1;`, regexp.QuoteMeta(p))
			} else {
				w.line(`"~^%s(?:/|$)" 1;`, regexp.QuoteMeta(p))
			}
		}
		w.close()
	}
	if len(c.SkipCookies) > 0 {
		names := make([]string, len(c.SkipCookies))
		for i, n := range c.SkipCookies {
			names[i] = regexp.QuoteMeta(n)
		}
		w.open("map $http_cookie $%s_skip_cookie", t)
		w.line("default 0;")
		w.line(`"~(?:^|;)\s*(?:%s)" 1;`, strings.Join(names, "|"))
		w.close()
	}
	if slowWait(h) > 0 {
		// 0 = a page that may have a copy: GET or HEAD, no WebSocket, not
		// signed in, not skipped. Anything else goes to slowPass.
		src := "$request_method:$http_upgrade$http_authorization:"
		if len(c.SkipPaths) > 0 {
			src += "$" + t + "_skip_path"
		}
		if len(c.SkipCookies) > 0 {
			src += "$" + t + "_skip_cookie"
		}
		w.open(`map "%s" $%s_pass`, src, t)
		w.line("default 1;")
		w.line(`"~^(?:GET|HEAD)::0*$" 0;`)
		w.close()
	}
}

// serverCache is the cache's server-level lines.
func serverCache(w *writer, t string, h proxy.HostConfig) {
	if h.Cache.Browser() {
		w.line("expires $%s_expires;", t)
	}
	if h.Cache.Enabled && h.Cache.StatusHeader {
		w.line("add_header X-Cache-Status $upstream_cache_status always;")
		if v := varyParts(t, h.Cache); v != "" {
			w.line(`add_header X-Cache-Variant "%s" always;`, v)
		}
	}
}

// proxyCache goes with every proxy_pass of a site that keeps answers.
// Signed-in requests (Authorization) and WebSocket upgrades always skip it.
func proxyCache(w *writer, t string, h proxy.HostConfig) {
	c := h.Cache
	if !c.Keeps() {
		return
	}
	skip := "$http_authorization $http_upgrade"
	if len(c.SkipPaths) > 0 {
		skip += " $" + t + "_skip_path"
	}
	if len(c.SkipCookies) > 0 {
		skip += " $" + t + "_skip_cookie"
	}
	w.line("proxy_cache %s_cache;", t)
	w.line("proxy_cache_key %s;", cacheKey(t, c))
	if c.Enabled {
		w.line("proxy_cache_valid 200 301 302 %dm;", c.FreshMinutes())
		w.line("proxy_cache_valid 404 1m;")
	} else {
		// Copies for Always online only: stale a second after they come, so
		// every visit still asks the app (cheaply, with If-Modified-Since /
		// If-None-Match), and never an error page over a good copy.
		w.line("proxy_cache_valid 200 301 302 1s;")
		w.line("proxy_cache_revalidate on;")
	}
	w.line("proxy_cache_lock on;")
	w.line("proxy_cache_bypass %s;", skip)
	if backupOnly(c) && !c.Online.KeepPrivate {
		skip += " $" + t + "_private"
	}
	w.line("proxy_no_cache %s;", skip)
	if o := c.Online; o.On() {
		when := "error timeout"
		if o.Mode == "fast" {
			when += " updating"
		}
		for _, s := range o.Statuses {
			when += fmt.Sprintf(" http_%d", s)
		}
		w.line("proxy_cache_use_stale %s;", when)
		if o.Mode == "fast" {
			w.line("proxy_cache_background_update on;")
		}
	}
	if c.IgnoreUpstream || backupOnly(c) {
		w.line("proxy_ignore_headers Cache-Control Expires;")
	}
}

// backupOnly: the site keeps answers only as Always online's copies.
func backupOnly(c proxy.Cache) bool { return !c.Enabled && c.Online.On() }

// offlineUpstream is where a site serving only its copies sends what it
// has no copy of: a socket that isn't there, so nginx fails at once (as if
// the app were down) and answers from the copy, or 502.
const offlineUpstream = "http://unix:/run/morcheh-nginx-offline.sock"

// cacheRules are the cache rules with their own time: a regex location
// each, nested in the location that proxies to the main upstream, so it
// keeps that location's headers, limits and access (nginx inherits them)
// while setting its own proxy_cache_valid, which takes no variables. The
// first rule matching the path wins.
// slow > 0 when the parent location sends what can't have a copy away
// (slowRoute): a rule's location must too, or it keeps the short wait.
func cacheRules(w *writer, t string, h proxy.HostConfig, slow int) {
	c := h.Cache
	if !c.Enabled {
		return
	}
	for _, g := range c.Groups {
		if !g.Rule() {
			continue
		}
		res := make([]string, len(g.Paths))
		for i, p := range g.Paths {
			res[i] = rulePathRegexp(p)
		}
		w.line("")
		w.line("# Cache rule: %s", oneLine(g.Name))
		w.open(`location ~ "^(?:%s)"`, strings.Join(res, "|"))
		if slow > 0 {
			slowRoute(w, t, h)
		}
		rulePass(w, t, h)
		if g.Never {
			w.line("proxy_no_cache 1;")
			w.line("proxy_cache_bypass 1;")
		} else {
			w.line("proxy_cache_valid 200 301 302 %dm;", g.Minutes)
			w.line("proxy_cache_valid 404 1m;")
		}
		w.close()
	}
}

// rulePass repeats the main proxy_pass in a rule's location (nginx doesn't
// inherit it). A regex location can't pass with a path part, so a base
// path the upstream has (http://app/base/) is put in with a rewrite, and
// the key, which may use $uri, reads the path as it was asked.
func rulePass(w *writer, t string, h proxy.HostConfig) {
	upstream, _ := pooled(t, h, h.Upstream)
	origin, base := upstream, ""
	if i := strings.Index(upstream, "://"); i >= 0 {
		if j := strings.Index(upstream[i+3:], "/"); j >= 0 {
			origin, base = upstream[:i+3+j], upstream[i+3+j:]
		}
	}
	if base != "" && base != "/" {
		w.line("set $%s_asked $uri;", t)
		w.line("rewrite ^/(.*)$ %s$1 break;", strings.TrimSuffix(base, "/")+"/")
		w.line("proxy_cache_key %s;", strings.ReplaceAll(cacheKey(t, h.Cache), "$uri", "$"+t+"_asked"))
	}
	w.line("proxy_pass %s;", origin)
}

// rulePathRegexp is the PCRE for one rule path, read like a purge path
// (keyRegexp) but on the path alone: /blog = itself and everything under
// it, /blog/ = everything under it, * = any characters, *.css = any path.
func rulePathRegexp(p string) string {
	if strings.HasPrefix(p, "*") && !strings.HasPrefix(p, "*/") {
		p = "/" + p
	}
	parts := strings.Split(p, "*")
	for i := range parts {
		parts[i] = regexp.QuoteMeta(parts[i])
	}
	re := strings.Join(parts, ".*")
	switch {
	case strings.HasSuffix(p, "*"):
		return re + "$"
	case strings.HasSuffix(p, "/"):
		return re
	}
	return re + "(?:/|$)"
}

// cacheKey tells kept answers apart. The purge script reads it back from
// the KEY line nginx writes at the top of each file (see keyRegexp).
// A split cache puts its variant first, "phone,android,en|", made only of
// [A-Za-z0-9_.,-] by varyMaps so the purge can skip it.
func cacheKey(t string, c proxy.Cache) string {
	key := "$scheme$host$request_uri"
	switch c.Query {
	case "none":
		key = "$scheme$host$uri"
	case "only":
		parts := make([]string, len(c.QueryParams))
		for i, q := range c.QueryParams {
			parts[i] = q + "=$arg_" + q
		}
		key = "$scheme$host$uri?" + strings.Join(parts, "&")
	}
	if v := varyParts(t, c); v != "" {
		key = `"` + v + "|" + key + `"`
	}
	return key
}

// varyParts names the variables that split the cache, comma-separated.
func varyParts(t string, c proxy.Cache) string {
	var parts []string
	if c.VaryDevice {
		parts = append(parts, "$"+t+"_device")
	}
	if c.VaryOS {
		parts = append(parts, "$"+t+"_os")
	}
	if c.VaryLanguage {
		parts = append(parts, "$"+t+"_lang")
	}
	for i := range c.VaryHeaders {
		parts = append(parts, fmt.Sprintf("$%s_vh%d", t, i))
	}
	for i := range c.VaryCookies {
		parts = append(parts, fmt.Sprintf("$%s_vc%d", t, i))
	}
	return strings.Join(parts, ",")
}

// Device and OS by User-Agent; the first matching line wins, so the more
// specific ones go first (an Android tablet has no "Mobile").
var (
	deviceLines = [][2]string{
		{`~*ipad|tablet|kindle|silk/|playbook`, "tablet"},
		{`~*android(?!.*mobile)`, "tablet"},
		{`~*mobi|iphone|ipod|android|blackberry|opera mini|iemobile|windows phone`, "phone"},
	}
	osLines = [][2]string{
		{`~*windows phone`, "windows"},
		{`~*iphone|ipad|ipod`, "ios"},
		{`~*android`, "android"},
		{`~*cros`, "chromeos"},
		{`~*mac os x|macintosh`, "macos"},
		{`~*windows`, "windows"},
		{`~*linux|x11`, "linux"},
	}
)

// safeValue keeps a header or cookie value usable in the key: plain ones as
// they are, none when missing, other for anything odd or long.
const safeValue = `"~^([A-Za-z0-9_.-]{1,40})$" $1;`

// varyMaps are the http-level maps behind varyParts.
func varyMaps(w *writer, t string, c proxy.Cache) {
	table := func(from, name, def string, lines [][2]string) {
		w.open("map %s $%s_%s", from, t, name)
		w.line("default %s;", def)
		for _, l := range lines {
			w.line(`"%s" %s;`, l[0], l[1])
		}
		w.close()
	}
	if c.VaryDevice {
		table("$http_user_agent", "device", "desktop", deviceLines)
	}
	if c.VaryOS {
		table("$http_user_agent", "os", "other", osLines)
	}
	if c.VaryLanguage {
		w.open("map $http_accept_language $%s_lang", t)
		w.line("default none;")
		w.line(`"~^\s*([A-Za-z]{2,3})" $1;`)
		w.close()
	}
	value := func(from, name string) {
		w.open("map %s $%s_%s", from, t, name)
		w.line("default none;")
		w.line(safeValue)
		w.line(`"~." other;`)
		w.close()
	}
	for i, h := range c.VaryHeaders {
		value("$http_"+strings.ToLower(strings.ReplaceAll(h, "-", "_")), fmt.Sprintf("vh%d", i))
	}
	for i, k := range c.VaryCookies {
		value("$cookie_"+k, fmt.Sprintf("vc%d", i))
	}
}

// ereQuote escapes s for a POSIX extended regexp, * becoming any.
func ereQuote(s, any string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '*':
			b.WriteString(any)
		case strings.ContainsRune(`.[]{}()\^$|?+`, r):
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// keyRegexp matches the KEY line of the answers one PurgeFilter path picks.
// Keys are scheme, host and address run together (httpsexample.com/a?b).
// A path covers itself, everything under it and any query string, unless
// it has a ?query of its own.
func keyRegexp(p string) string {
	scheme := "https?"
	for _, s := range []string{"https://", "http://"} {
		if strings.HasPrefix(strings.ToLower(p), s) {
			scheme, p = strings.TrimSuffix(s, "://"), p[len(s):]
			break
		}
	}
	host := "[^/]*"
	// "*.css" (a * first and no /) is any path, not a domain.
	if strings.HasPrefix(p, "*") && !strings.Contains(p, "/") {
		p = "/" + p
	}
	if !strings.HasPrefix(p, "/") {
		d, rest, _ := strings.Cut(p, "/")
		if strings.ContainsAny(d, ".*") {
			if i := strings.LastIndex(d, ":"); i >= 0 {
				d = d[:i]
			}
			host, p = ereQuote(strings.ToLower(d), "[^/]*"), "/"+rest
		} else {
			p = "/" + p
		}
	}
	path, query, hasQuery := strings.Cut(p, "?")
	// A split cache's key starts with its variant (see cacheKey).
	re := "^KEY: ([A-Za-z0-9_.,-]*\\|)?" + scheme + host + ereQuote(path, ".*")
	if hasQuery {
		return re + "\\?" + ereQuote(query, ".*") + "$"
	}
	if !strings.HasSuffix(path, "/") && !strings.HasSuffix(path, "*") {
		re += "(/.*)?"
	} else if !strings.HasSuffix(path, "*") {
		re += ".*"
	}
	return re + "(\\?.*)?$"
}

// headerRegexp matches the line of an answer header nginx keeps in the file
// with the app's answer: the value, or one item of a list, or any value.
func headerRegexp(name, value string) string {
	var n strings.Builder
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' {
			n.WriteString("[" + string(r) + string(r-'a'+'A') + "]")
		} else {
			n.WriteString(ereQuote(string(r), ""))
		}
	}
	if value == "" {
		return "^" + n.String() + ":"
	}
	return "^" + n.String() + ":(.*[ ,;])?[ ]*" + ereQuote(value, "[^ ,;]*") + "[ ]*([,;].*)?\r?$"
}

// PurgeCacheScript clears the site's kept answers f picks, or counts them.
// Cache files are named by the md5 of the key (no spaces), so plain lists
// and xargs are safe; nginx's temp files (name.0000000001) are left alone.
// The last line is "MORCHEH_PURGE <answers> <KiB>".
func (Driver) PurgeCacheScript(hostID string, f proxy.PurgeFilter, dryRun bool) string {
	var keys []string
	for _, p := range f.Paths {
		keys = append(keys, keyRegexp(p))
	}
	pick := ""
	if len(keys) > 0 {
		pick += " | xargs -r grep -l -E -e " + shellQuote("("+strings.Join(keys, ")|(")+")") + " 2>/dev/null"
	}
	if f.Header != "" {
		pick += " | xargs -r grep -l -E -e " + shellQuote(headerRegexp(f.Header, f.Value)) + " 2>/dev/null"
	}
	act := `xargs -r rm -f < "$t"`
	if dryRun {
		act = ":"
	}
	return head + `export LC_ALL=C
d=` + CacheDir + "/" + cacheDirName(hostID) + `
if [ ! -d "$d" ]; then echo "MORCHEH_PURGE 0 0"; exit 0; fi
t=$(mktemp) || exit 1
trap 'rm -f "$t"' EXIT
find "$d" -type f | grep -E '/[0-9a-f]{32}$'` + pick + ` > "$t"
n=$(grep -c . "$t")
kb=0
if [ "$n" -gt 0 ]; then kb=$(xargs -r du -k < "$t" 2>/dev/null | awk '{s+=$1} END {print s+0}'); fi
` + act + ` || exit 1
echo "MORCHEH_PURGE $n $kb"
`
}

// KeptPagesScript lists the site's kept answers, newest first: per file its
// mtime (when nginx wrote it or the app last confirmed it), size, the app's
// status line and the KEY line, which sit near the start of the file.
func (Driver) KeptPagesScript(hostID string, limit int) string {
	return head + `export LC_ALL=C
d=` + CacheDir + "/" + cacheDirName(hostID) + `
now=$(date +%s)
if [ ! -d "$d" ]; then printf 'MORCHEH_PAGES\t0\t0\t%s\n' "$now"; exit 0; fi
t=$(mktemp) || exit 1
trap 'rm -f "$t"' EXIT
find "$d" -type f -printf '%T@ %s %p\n' | grep -E '/[0-9a-f]{32}$' > "$t"
n=$(grep -c . "$t")
kb=$(awk '{s+=$2} END {printf "%d", s/1024}' "$t")
printf 'MORCHEH_PAGES\t%s\t%s\t%s\n' "$n" "$kb" "$now"
sort -rn "$t" | head -n ` + strconv.Itoa(limit) + ` | while read -r m s p; do
	l=$(head -c 16384 "$p" 2>/dev/null | grep -a -m2 -E '^(KEY: |HTTP/)' | tr -d '\r\t')
	k=$(printf '%s\n' "$l" | grep -m1 '^KEY: ')
	h=$(printf '%s\n' "$l" | grep -m1 '^HTTP/')
	[ -n "$k" ] && printf 'P\t%s\t%s\t%s\t%s\n' "${m%.*}" "$s" "$h" "$k"
done
exit 0
`
}

// serverTuning writes the server-level options: the visitor's address from a
// CDN, the version kept out of answers, compression.
func serverTuning(w *writer, h proxy.HostConfig) {
	if len(h.RealIP.From) == 0 && !h.HideVersion && !h.Gzip {
		return
	}
	w.line("")
	for _, a := range h.RealIP.From {
		w.line("set_real_ip_from %s;", a)
	}
	if len(h.RealIP.From) > 0 {
		w.line("real_ip_header %s;", h.RealIP.Header)
		if h.RealIP.Header == "X-Forwarded-For" {
			w.line("real_ip_recursive on;")
		}
	}
	if h.HideVersion {
		w.line("server_tokens off;")
	}
	if h.Gzip {
		w.line("gzip on;")
		w.line("gzip_vary on;")
		w.line("gzip_proxied any;")
		w.line("gzip_comp_level 5;")
		w.line("gzip_min_length 1024;")
		w.line("gzip_types %s;", strings.Join(gzipTypes, " "))
	}
}

// connectWait is how long nginx tries to reach the app; 0 = nginx's 60 s.
func connectWait(h proxy.HostConfig) int {
	wait := h.ConnectTimeout
	if o := h.Cache.Online; o.On() && (wait == 0 || o.Wait() < wait) {
		// A down app's copy shouldn't wait nginx's 60 s.
		wait = o.Wait()
	}
	return wait
}

// slowWait is Always online's limit on a slow page, for a proxy site's
// main location; 0 = none.
func slowWait(h proxy.HostConfig) int {
	if h.Type != proxy.TypeProxy || h.NoBuffering {
		return 0
	}
	return h.Cache.Online.Slow(h.TimeoutSeconds)
}

// slowRoute sends what can't have a copy (other methods, WebSockets,
// signed-in or skipped requests) to slowPass's location, which keeps the
// site's own timeout, so only pages are cut short. It runs before the
// access checks, which slowPass's location inherits from the server.
func slowRoute(w *writer, t string, h proxy.HostConfig) {
	// An error_page here drops the server's: repeat them.
	serverErrorPages(w, h)
	w.line("recursive_error_pages on;")
	w.line("error_page 418 = @%s_pass;", t)
	w.open("if ($%s_pass)", t)
	w.line("return 418;")
	w.close()
}

// slowPass is the named location slowRoute sends to: the plain proxy,
// with the site's own timeout and no copies.
func slowPass(w *writer, t string, h proxy.HostConfig, env proxy.Env) {
	plain := h
	plain.ConnectTimeout = connectWait(h)
	plain.Cache = proxy.Cache{}
	w.line("")
	w.open("location @%s_pass", t)
	w.line("recursive_error_pages on;")
	proxyPass(w, t, plain, env, h.Upstream, h.WebSockets, 0)
	w.close()
}

// upstreamTuning goes with every proxy_pass of a site.
func upstreamTuning(w *writer, h proxy.HostConfig) {
	if wait := connectWait(h); wait > 0 {
		w.line("proxy_connect_timeout %ds;", wait)
	}
	if h.NoBuffering {
		w.line("proxy_buffering off;")
		w.line("proxy_request_buffering off;")
	}
}

// streamTuning goes after a port forward's proxy_pass.
func streamTuning(w *writer, h proxy.HostConfig) {
	if h.ConnectTimeout > 0 {
		w.line("proxy_connect_timeout %ds;", h.ConnectTimeout)
	}
	if h.ProxyProtocol {
		w.line("proxy_protocol on;")
	}
}

// oneLine keeps a name the person typed to one printable line, for a
// comment in the config.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}
