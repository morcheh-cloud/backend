package nginx

import (
	"regexp"
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
func cacheBlocks(w *writer, t string, h proxy.HostConfig) {
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
	if !c.Enabled {
		return
	}
	w.line("")
	w.line("proxy_cache_path %s/%s levels=1:2 keys_zone=%s_cache:10m max_size=%dm inactive=%dm use_temp_path=off;",
		CacheDir, t, t, c.SizeMB(), max(c.FreshMinutes(), 1440))
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
}

// serverCache is the cache's server-level lines.
func serverCache(w *writer, t string, h proxy.HostConfig) {
	if h.Cache.Browser() {
		w.line("expires $%s_expires;", t)
	}
	if h.Cache.Enabled && h.Cache.StatusHeader {
		w.line("add_header X-Cache-Status $upstream_cache_status always;")
	}
}

// proxyCache goes with every proxy_pass of a site that keeps answers.
// Signed-in requests (Authorization) and WebSocket upgrades always skip it.
func proxyCache(w *writer, t string, h proxy.HostConfig) {
	c := h.Cache
	if !c.Enabled {
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
	w.line("proxy_cache_key $scheme$host$request_uri;")
	w.line("proxy_cache_valid 200 301 302 %dm;", c.FreshMinutes())
	w.line("proxy_cache_valid 404 1m;")
	w.line("proxy_cache_lock on;")
	w.line("proxy_cache_bypass %s;", skip)
	w.line("proxy_no_cache %s;", skip)
	if c.ServeStale {
		w.line("proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;")
		w.line("proxy_cache_background_update on;")
	}
	if c.IgnoreUpstream {
		w.line("proxy_ignore_headers Cache-Control Expires;")
	}
}

// PurgeCacheScript empties a site's proxy cache and says how much it freed.
func (Driver) PurgeCacheScript(hostID string) string {
	d := CacheDir + "/" + tag(hostID)
	return head + `d=` + d + `
if [ ! -d "$d" ] || [ -z "$(ls -A "$d" 2>/dev/null)" ]; then echo "The cache was already empty."; exit 0; fi
size=$(du -sh "$d" 2>/dev/null | cut -f1)
find "$d" -mindepth 1 -delete || exit 1
echo "Cleared ${size:-the cache}."
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

// upstreamTuning goes with every proxy_pass of a site.
func upstreamTuning(w *writer, h proxy.HostConfig) {
	if h.ConnectTimeout > 0 {
		w.line("proxy_connect_timeout %ds;", h.ConnectTimeout)
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
