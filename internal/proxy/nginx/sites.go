package nginx

import (
	"net"
	"net/url"

	"github.com/morcheh/backend/internal/proxy"
)

// mirrorLocation is where copies of requests go; an exact location, so it
// wins over the site's own internal pages.
const mirrorLocation = internalPrefix + "mirror"

// storageHide are answer headers of S3 servers visitors don't need.
var storageHide = []string{
	"Set-Cookie", "x-amz-id-2", "x-amz-request-id", "x-amz-version-id",
	"x-amz-server-side-encryption", "x-amz-storage-class", "x-amz-bucket-region",
	"x-amz-replication-status", "x-amz-expiration", "x-minio-deployment-id",
}

// storageSite serves a bucket: paths become object keys under the bucket and
// folder, a path ending in / reads its index.html, and a missing file is a
// 404 (S3 answers 403 when it may not list the bucket) or, for single-page
// apps, the folder's index.html.
func storageSite(w *writer, id, t string, h proxy.HostConfig, env proxy.Env, lim *limits) {
	prefix := h.Storage.Prefix()
	main := func() {
		w.open(`if ($request_method !~ ^(GET|HEAD)$)`)
		w.line("return 405;")
		w.close()
		w.line("rewrite ^(.*)/$ $1/index.html;")
		w.line(`rewrite "^/(.*)$" "%s/$1?" break;`, prefix)
		storagePass(w, h)
		w.line("proxy_intercept_errors on;")
		missing := "=404 @" + t + "_missing"
		if h.SPA {
			missing = "= @" + t + "_index"
		} else if i := pageFor(h, 404); i >= 0 {
			missing = "=404 " + errorPage(i)
		}
		w.line("error_page 403 404 %s;", missing)
		// An error_page here drops the server's: repeat them.
		errorPageLines(w, h)
	}
	paths(w, id, h, env, lim, main)
	w.line("")
	w.open("location /")
	main()
	w.close()
	w.line("")
	if h.SPA {
		w.open("location @%s_index", t)
		w.line(`rewrite ^ "%s/index.html" break;`, prefix)
		storagePass(w, h)
		w.close()
	} else {
		w.open("location @%s_missing", t)
		w.line("return 404;")
		w.close()
	}
}

// pageFor is the index of the site's own page for a status, or -1.
func pageFor(h proxy.HostConfig, code int) int {
	for i, p := range h.ErrorPages {
		for _, c := range p.Codes {
			if c == code {
				return i
			}
		}
	}
	return -1
}

// storagePass reads a file from the storage, without keys, cookies or
// anything that would identify the visitor's session to it.
func storagePass(w *writer, h proxy.HostConfig) {
	w.line("proxy_pass %s;", h.Storage.Endpoint)
	w.line("proxy_http_version 1.1;")
	w.line(`proxy_set_header Connection "";`)
	w.line(`proxy_set_header Authorization "";`)
	w.line(`proxy_set_header Cookie "";`)
	for _, x := range h.Headers {
		if x.To == "request" {
			w.line(`proxy_set_header %s "%s";`, x.Name, x.Value)
		}
	}
	for _, x := range storageHide {
		w.line("proxy_hide_header %s;", x)
	}
	if u, err := url.Parse(h.Storage.Endpoint); err == nil && u.Scheme == "https" {
		w.line("proxy_ssl_server_name on;")
	}
	upstreamTuning(w, h)
}

// mirrorTarget is the test server's host:port and whether it's https.
func mirrorTarget(m proxy.Mirror) (hostPort, name string, https bool) {
	u, err := url.Parse(m.To)
	if err != nil {
		return "", "", false
	}
	https = u.Scheme == "https"
	port := u.Port()
	if port == "" {
		port = "80"
		if https {
			port = "443"
		}
	}
	return net.JoinHostPort(u.Hostname(), port), u.Hostname(), https
}

// mirrorBlocks are the http-level parts of a mirror: the test server as an
// upstream (so proxy_pass can carry $request_uri without a resolver) and,
// for a share of requests, the split that picks them.
func mirrorBlocks(w *writer, t string, h proxy.HostConfig) {
	m := h.Mirror
	if !m.On() {
		return
	}
	hostPort, _, _ := mirrorTarget(m)
	w.line("")
	w.open("upstream %s_mirror", t)
	w.line("server %s;", hostPort)
	w.line("keepalive 8;")
	w.close()
	if m.Percent > 0 {
		w.line("")
		w.open(`split_clients "$request_id" $%s_mirror_skip`, t)
		w.line(`%d%% "";`, m.Percent)
		w.line("* 1;")
		w.close()
	}
}

// mirrorServer copies every request of the site.
func mirrorServer(w *writer, h proxy.HostConfig) {
	if !h.Mirror.On() {
		return
	}
	w.line("")
	w.line("mirror %s;", mirrorLocation)
	if h.Mirror.SkipBody {
		w.line("mirror_request_body off;")
	}
}

// mirrorLocations sends the copy on; its answer is thrown away. Short
// timeouts keep a slow test server from holding connections.
func mirrorLocations(w *writer, t string, h proxy.HostConfig) {
	m := h.Mirror
	if !m.On() {
		return
	}
	hostPort, name, https := mirrorTarget(m)
	scheme := "http"
	if https {
		scheme = "https"
	}
	w.line("")
	w.open("location = %s", mirrorLocation)
	w.line("internal;")
	if m.Percent > 0 {
		w.open("if ($%s_mirror_skip)", t)
		w.line("return 204;")
		w.close()
	}
	w.line("proxy_pass %s://%s_mirror$request_uri;", scheme, t)
	w.line("proxy_http_version 1.1;")
	w.line(`proxy_set_header Connection "";`)
	if h.PreserveHost {
		w.line("proxy_set_header Host $host;")
	} else {
		w.line("proxy_set_header Host %s;", hostPort)
	}
	w.line("proxy_set_header X-Real-IP $remote_addr;")
	w.line("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
	w.line("proxy_set_header X-Forwarded-Proto $scheme;")
	w.line("proxy_set_header X-Forwarded-Host $host;")
	w.line("proxy_set_header X-Morcheh-Mirror 1;")
	if m.SkipBody {
		w.line("proxy_pass_request_body off;")
		w.line(`proxy_set_header Content-Length "";`)
	}
	if https {
		w.line("proxy_ssl_server_name on;")
		w.line("proxy_ssl_name %s;", name)
	}
	w.line("proxy_connect_timeout 2s;")
	w.line("proxy_send_timeout 10s;")
	w.line("proxy_read_timeout 10s;")
	w.close()
}
