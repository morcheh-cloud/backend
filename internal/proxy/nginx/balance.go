package nginx

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/morcheh/backend/internal/proxy"
)

// poolName is a balanced host's upstream block.
func poolName(t string) string { return t + "_pool" }

// upstreamBlock writes the upstream {} of a balanced host: the method, the
// main server, the others, and kept-alive connections. It sits before the
// server block, in http {} for a site and stream {} for a forward.
func upstreamBlock(w *writer, t string, h proxy.HostConfig) {
	b := h.Balance
	if !b.On() {
		return
	}
	w.line("")
	w.open("upstream %s", poolName(t))
	// A shared zone makes least_conn, max_conns and failures count across
	// all workers, not per worker.
	w.line("zone %s 64k;", poolName(t))
	switch b.Method {
	case proxy.MethodLeastConn:
		w.line("least_conn;")
	case proxy.MethodIPHash:
		w.line("ip_hash;")
	case proxy.MethodHash:
		consistent := ""
		if b.Consistent {
			consistent = " consistent"
		}
		w.line("hash %s%s;", hashKey(h), consistent)
	case proxy.MethodRandom:
		if b.RandomTwo {
			w.line("random two least_conn;")
		} else {
			w.line("random;")
		}
	}
	serverLine(w, h.MainServer(), b.Main, b)
	for _, s := range b.Servers {
		serverLine(w, s.Address, s, b)
	}
	if b.Keepalive > 0 {
		w.line("keepalive %d;", b.Keepalive)
	}
	w.close()
}

func serverLine(w *writer, addr string, s proxy.UpstreamServer, b proxy.Balance) {
	var p []string
	if s.Weight > 1 {
		p = append(p, "weight="+strconv.Itoa(s.Weight))
	}
	if b.MaxFails > 0 {
		p = append(p, "max_fails="+strconv.Itoa(b.MaxFails))
	}
	if b.FailTimeout > 0 {
		p = append(p, "fail_timeout="+strconv.Itoa(b.FailTimeout)+"s")
	}
	if s.MaxConns > 0 {
		p = append(p, "max_conns="+strconv.Itoa(s.MaxConns))
	}
	if s.Backup {
		p = append(p, "backup")
	}
	if s.Down {
		p = append(p, "down")
	}
	if s.Note != "" {
		w.line("# %s", s.Note)
	}
	line := "server " + addr
	if len(p) > 0 {
		line += " " + strings.Join(p, " ")
	}
	w.line("%s;", line)
}

// hashKey is the variable hash picks a server by.
func hashKey(h proxy.HostConfig) string {
	b := h.Balance
	switch {
	case h.IsStream():
		return "$remote_addr"
	case b.HashKey == "uri":
		return "$request_uri"
	case b.HashKey == "cookie":
		return "$cookie_" + b.HashName
	case b.HashKey == "header":
		return "$http_" + strings.ReplaceAll(strings.ToLower(b.HashName), "-", "_")
	case b.HashKey == "arg":
		return "$arg_" + b.HashName
	}
	return "$remote_addr"
}

// pooled turns an address that goes to the main upstream into one that goes
// to the pool, keeping its path; ok is false when it goes elsewhere (a path
// rule's own upstream) or there is no pool.
func pooled(t string, h proxy.HostConfig, upstream string) (string, bool) {
	if !h.Balance.On() || proxy.Origin(upstream) != proxy.Origin(h.Upstream) {
		return upstream, false
	}
	u, err := url.Parse(upstream)
	if err != nil {
		return upstream, false
	}
	rest := ""
	if i := strings.Index(upstream, u.Host); i >= 0 {
		rest = upstream[i+len(u.Host):]
	}
	return u.Scheme + "://" + poolName(t) + rest, true
}

// mainHost is the main upstream's host as written ([v6] and port kept),
// sent as Host when the pool's name would be.
func mainHost(h proxy.HostConfig) string {
	u, err := url.Parse(h.Upstream)
	if err != nil {
		return ""
	}
	return u.Host
}

// retryLines say when a failed request goes to the next server.
func retryLines(w *writer, b proxy.Balance, stream bool) {
	switch {
	case b.NoRetry:
		w.line("proxy_next_upstream off;")
		return
	case !stream && len(b.RetryOn) > 0:
		w.line("proxy_next_upstream %s;", strings.Join(b.RetryOn, " "))
	}
	if b.Tries > 0 {
		w.line("proxy_next_upstream_tries %d;", b.Tries)
	}
	if b.RetryTimeout > 0 {
		w.line("proxy_next_upstream_timeout %ds;", b.RetryTimeout)
	}
}
