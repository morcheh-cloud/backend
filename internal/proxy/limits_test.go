package proxy

import "testing"

func fields(ps []Problem) map[string]bool {
	m := map[string]bool{}
	for _, p := range ps {
		m[p.Field] = true
	}
	return m
}

func TestAccessNormalize(t *testing.T) {
	h := Normalize(HostConfig{Domains: []string{"a.test"}, Type: TypeProxy, Upstream: "http://x", Allow: []string{" 10.0.0.1 ", "10.0.0.1"}})
	if h.DefaultAccess != "deny" || len(h.Allow) != 1 {
		t.Errorf("allow only → default deny, deduped: %+v", h)
	}
	h = Normalize(HostConfig{Domains: []string{"a.test"}, Type: TypeProxy, Upstream: "http://x", Countries: []string{"de", "DE"}})
	if h.CountryMode != "deny" || len(h.Countries) != 1 || h.Countries[0] != "DE" || h.DefaultAccess != "allow" {
		t.Errorf("countries = %+v", h)
	}
	bad := fields(Validate(Normalize(HostConfig{
		Domains: []string{"a.test"}, Type: TypeProxy, Upstream: "http://x",
		Allow: []string{"10.0.0.0/8", "nope"}, Deny: []string{"10.0.0.0/8"}, Countries: []string{"XYZ"},
	})))
	for _, f := range []string{"allow[1]", "deny[0]", "countries[0]"} {
		if !bad[f] {
			t.Errorf("no problem on %s: %v", f, bad)
		}
	}
}

func TestRateNormalize(t *testing.T) {
	h := Normalize(HostConfig{Domains: []string{"a.test"}, Type: TypeRedirect, RedirectTo: "https://b.test",
		RateLimit: RateLimit{Rules: []RateRule{{Rate: 1}}}})
	if !h.RateLimit.IsZero() {
		t.Errorf("redirects take no limits: %+v", h.RateLimit)
	}
	h = Normalize(HostConfig{Domains: []string{"a.test"}, Type: TypeProxy, Upstream: "http://x",
		RateLimit: RateLimit{Rules: []RateRule{{Path: "/", Rate: 1, Delay: 3, Methods: []string{"get", "GET"}}}, UploadKBs: 5}})
	r := h.RateLimit.Rules[0]
	if r.Path != "" || r.Per != "second" || r.Mode != "nodelay" || r.Key != "ip" || r.Delay != 0 || len(r.Methods) != 1 || h.RateLimit.Status != 429 || h.RateLimit.UploadKBs != 0 {
		t.Errorf("rate = %+v", h.RateLimit)
	}
	bad := fields(Validate(Normalize(HostConfig{Domains: []string{"a.test"}, Type: TypeProxy, Upstream: "http://x",
		RateLimit: RateLimit{Rules: []RateRule{{Rate: 1}, {Rate: 2}, {Path: "nope", Rate: 1}}, Exempt: []string{"x"}}})))
	for _, f := range []string{"rate_limit.rules[1].path", "rate_limit.rules[2].path", "rate_limit.exempt[0]"} {
		if !bad[f] {
			t.Errorf("no problem on %s: %v", f, bad)
		}
	}
}
