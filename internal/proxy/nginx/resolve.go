package nginx

import (
	"net"
	"slices"
	"strings"

	"github.com/morche/backend/internal/proxy"
)

// ---- Names looked up again while nginx runs ----
//
// nginx turns an upstream's name into addresses once, when it starts or
// reloads. With nginx in a container, app:3000 is usually another
// container: recreated (compose up, an update), it gets a new address and
// nginx keeps sending to the old one (502) until a reload, and nginx won't
// start at all while the name doesn't resolve. From 1.27.3 an upstream
// server can carry resolve: nginx asks the container's DNS (Docker's
// 127.0.0.11, Podman's gateway) again as it runs. So when the proxy runs
// in a container, a site or forward whose address is a name goes through
// an upstream block with resolve on each named server.

// resolveValid is how long an answer is kept before nginx asks again.
const resolveValid = "10s"

// resolves: names can be looked up again on this proxy.
func resolves(env proxy.Env) bool {
	return env.Resolver != "" && atLeast(env.Version, 1, 27, 3)
}

// named: addr (host:port, or a bare host) is a name nginx must look up
// again: not an address, not localhost, and not one the container's
// /etc/hosts gives (a DNS server doesn't know those).
func named(env proxy.Env, addr string) bool {
	if !resolves(env) || addr == "" {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "" || net.ParseIP(host) != nil || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false
	}
	return !slices.Contains(env.HostsNames, host)
}

// pooledOn: the main address goes through the host's upstream block, to
// balance or to be looked up again.
func pooledOn(h proxy.HostConfig, env proxy.Env) bool {
	if h.Balance.On() {
		return true
	}
	passes := h.IsStream() || h.Type == proxy.TypeProxy || h.Type == ""
	return passes && named(env, h.MainServer())
}

// resolverLine is the DNS server an upstream block asks.
func resolverLine(w *writer, env proxy.Env) {
	r := env.Resolver
	if strings.Contains(r, ":") && !strings.HasPrefix(r, "[") {
		r = "[" + r + "]"
	}
	// ipv6=off: apps in containers seldom listen on IPv6, and half the
	// tries would fail on a dual-stack network.
	w.line("resolver %s valid=%s ipv6=off;", r, resolveValid)
}
