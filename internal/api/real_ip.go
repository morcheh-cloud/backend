package api

import (
	"net"
	"net/http"
	"strings"
)

// proxiedIP sets r.RemoteAddr to the visitor's address as the proxy in front
// saw it (TRUST_PROXY): the last X-Forwarded-For entry, the one that proxy
// added itself. Earlier entries, X-Real-IP and True-Client-IP can come from
// the visitor (most proxies pass them on), so they are never believed.
// Behind more than one proxy this is the nearer proxy's view.
func proxiedIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ip := lastForwarded(r.Header.Values("X-Forwarded-For")); ip != "" {
			r.RemoteAddr = net.JoinHostPort(ip, "0")
		}
		next.ServeHTTP(w, r)
	})
}

func lastForwarded(values []string) string {
	for i := len(values) - 1; i >= 0; i-- {
		parts := strings.Split(values[i], ",")
		for j := len(parts) - 1; j >= 0; j-- {
			p := strings.TrimSpace(parts[j])
			if p == "" {
				continue
			}
			if ip := net.ParseIP(p); ip != nil {
				return ip.String()
			}
			return ""
		}
	}
	return ""
}
