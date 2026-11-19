package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxiedIP(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string][]string
		want    string
	}{
		{"none", nil, "10.0.0.1"},
		{"proxy added one", map[string][]string{"X-Forwarded-For": {"203.0.113.7"}}, "203.0.113.7"},
		{"visitor sent their own first", map[string][]string{"X-Forwarded-For": {"1.2.3.4, 203.0.113.7"}}, "203.0.113.7"},
		{"split over headers", map[string][]string{"X-Forwarded-For": {"1.2.3.4", "203.0.113.7"}}, "203.0.113.7"},
		{"others ignored", map[string][]string{"True-Client-Ip": {"1.2.3.4"}, "X-Real-Ip": {"1.2.3.4"}}, "10.0.0.1"},
		{"garbage last", map[string][]string{"X-Forwarded-For": {"203.0.113.7, nope"}}, "10.0.0.1"},
		{"ipv6", map[string][]string{"X-Forwarded-For": {"2001:db8::1"}}, "2001:db8::1"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		for k, v := range c.headers {
			req.Header[k] = v
		}
		var got string
		proxiedIP(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got = hostOf(r.RemoteAddr)
		})).ServeHTTP(httptest.NewRecorder(), req)
		if got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}
