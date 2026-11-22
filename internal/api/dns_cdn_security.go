package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morche/backend/internal/arvancdn"
)

// An ArvanCloud domain's firewall, WAF and rate limiting, under
// /dns-servers/{id}/zones/{zone}/cdn/{firewall,waf,rate-limit}. Every write
// answers the whole section, fresh.

// Firewall

type CDNFirewallSettings struct {
	DefaultAction       string `json:"default_action" enum:"allow,deny,drop,bypass,challenge" doc:"What happens to a request no rule matched"`
	VerifySNI           bool   `json:"verify_sni" doc:"Refuse TLS requests whose SNI isn't this domain"`
	SkipGlobalWhitelist bool   `json:"skip_global_whitelist"`
	SkipGlobalFirewall  bool   `json:"skip_global_firewall" doc:"Leave out the account-wide firewall rules"`
}

type CDNFirewallSettingsPatch struct {
	DefaultAction       *string `json:"default_action,omitempty" enum:"allow,deny,challenge"`
	VerifySNI           *bool   `json:"verify_sni,omitempty"`
	SkipGlobalWhitelist *bool   `json:"skip_global_whitelist,omitempty"`
	SkipGlobalFirewall  *bool   `json:"skip_global_firewall,omitempty"`
}

type CDNFirewallRuleFields struct {
	Name       string   `json:"name" minLength:"1" maxLength:"100"`
	FilterExpr string   `json:"filter_expr" minLength:"3" maxLength:"5000" doc:"ArvanCloud's filter expression, like ip.geoip.country in {\"IR\"} and http.request.uri.path contains \"/admin\""`
	Action     string   `json:"action" enum:"allow,deny,bypass,challenge"`
	Enabled    bool     `json:"enabled"`
	Note       string   `json:"note,omitempty" maxLength:"500"`
	Skip       []string `json:"skip,omitempty" enum:"rate_limit,challenge,waf" doc:"bypass: which protections the matched requests skip"`
}

type CDNFirewallRule struct {
	ID string `json:"id"`
	CDNFirewallRuleFields
	Priority     int  `json:"priority"`
	AccountLevel bool `json:"account_level" doc:"An account-wide rule: changed in ArvanCloud's panel"`
}

type CDNFirewall struct {
	Settings CDNFirewallSettings `json:"settings"`
	Rules    []CDNFirewallRule   `json:"rules"`
}

type arvanFirewallRule struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	FilterExpr    string         `json:"filter_expr"`
	Action        string         `json:"action"`
	Priority      int            `json:"priority"`
	IsEnabled     bool           `json:"is_enabled"`
	Note          string         `json:"note"`
	AccountLevel  bool           `json:"is_account_level"`
	ActionDetails map[string]any `json:"action_details"`
}

var bypassKeys = map[string]string{"rate_limit": "rlimit", "challenge": "challenge", "waf": "waf"}

func firewallBody(f CDNFirewallRuleFields) map[string]any {
	b := map[string]any{
		"name": strings.TrimSpace(f.Name), "filter_expr": strings.TrimSpace(f.FilterExpr),
		"action": f.Action, "is_enabled": f.Enabled, "note": strings.TrimSpace(f.Note),
	}
	if f.Action == "bypass" {
		d := map[string]any{"rlimit": false, "challenge": false, "waf": false}
		for _, s := range f.Skip {
			d[bypassKeys[s]] = true
		}
		b["action_details"] = d
	}
	return b
}

func (h *dnsHandler) firewallOf(ctx context.Context, cl *arvancdn.Client, zone string) (*CDNFirewall, error) {
	out := &CDNFirewall{Rules: []CDNFirewallRule{}}
	raw := map[string]any{}
	if err := cl.Get(ctx, zone, "firewall/settings", &raw); err != nil {
		return nil, arvanError(err)
	}
	if err := fromArvan(raw, &out.Settings); err != nil {
		return nil, huma.Error502BadGateway("ArvanCloud sent firewall settings Morche can't read")
	}
	list, err := cl.List(ctx, zone, "firewall/rules")
	if err != nil {
		return nil, arvanError(err)
	}
	for _, item := range list {
		var r arvanFirewallRule
		if json.Unmarshal(item, &r) != nil {
			continue
		}
		rule := CDNFirewallRule{
			ID: r.ID, Priority: r.Priority, AccountLevel: r.AccountLevel,
			CDNFirewallRuleFields: CDNFirewallRuleFields{
				Name: r.Name, FilterExpr: r.FilterExpr, Action: r.Action, Enabled: r.IsEnabled, Note: r.Note,
			},
		}
		if r.Action == "bypass" {
			for k, v := range bypassKeys {
				if on, _ := r.ActionDetails[v].(bool); on {
					rule.Skip = append(rule.Skip, k)
				}
			}
			slices.Sort(rule.Skip)
		}
		out.Rules = append(out.Rules, rule)
	}
	slices.SortStableFunc(out.Rules, func(a, b CDNFirewallRule) int { return a.Priority - b.Priority })
	return out, nil
}

// Rate limiting

type CDNRateLimitSettings struct {
	DDoSDetection  bool     `json:"ddos_detection" doc:"Let ArvanCloud spot request floods by itself"`
	ExcludeSources []string `json:"exclude_sources" doc:"Addresses or ranges never limited"`
}

type CDNRateLimitSettingsPatch struct {
	DDoSDetection  *bool    `json:"ddos_detection,omitempty"`
	ExcludeSources []string `json:"exclude_sources,omitempty" maxItems:"100"`
}

type CDNRateLimitRuleFields struct {
	URLPattern     string   `json:"url_pattern" minLength:"1" maxLength:"500" doc:"Path pattern; * matches anything, like /api/*"`
	Rate           int      `json:"rate" minimum:"1" maximum:"4000000" doc:"Requests allowed per visitor in time_duration"`
	TimeDuration   int      `json:"time_duration" minimum:"1" maximum:"2592000" doc:"Seconds"`
	Burst          *int     `json:"burst,omitempty" minimum:"1" maximum:"4000000" doc:"Extra requests let through at once"`
	BlockDuration  *int     `json:"block_duration,omitempty" minimum:"0" maximum:"86400" doc:"Seconds a visitor over the limit stays limited"`
	Action         string   `json:"action" enum:"block,challenge"`
	Enabled        bool     `json:"enabled"`
	Methods        []string `json:"methods,omitempty" enum:"GET,POST,PUT,HEAD,DELETE,OPTIONS" doc:"Only these methods count; none = all"`
	ExcludeSources []string `json:"exclude_sources,omitempty" maxItems:"100"`
}

type CDNRateLimitRule struct {
	ID string `json:"id"`
	CDNRateLimitRuleFields
	Priority int `json:"priority"`
}

type CDNRateLimit struct {
	Settings CDNRateLimitSettings `json:"settings"`
	Rules    []CDNRateLimitRule   `json:"rules"`
}

type arvanRateRule struct {
	ID             string   `json:"id"`
	URLPattern     string   `json:"url_pattern"`
	Rate           int      `json:"rate"`
	TimeDuration   int      `json:"time_duration"`
	Burst          *int     `json:"burst"`
	BlockDuration  *int     `json:"block_duration"`
	Action         string   `json:"action"`
	IsEnabled      bool     `json:"is_enabled"`
	AllowedMethods []string `json:"allowed_methods"`
	ExcludeSources []string `json:"exclude_sources"`
	Priority       int      `json:"priority"`
}

func cleanSources(list []string, field string) ([]string, error) {
	out := []string{}
	for i, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked().String())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fieldError(fmt.Sprintf("%s[%d]", field, i), "Enter an address or a range like 203.0.113.0/24", s)
		}
		bits := 32
		if a.Is6() {
			bits = 128
		}
		out = append(out, netip.PrefixFrom(a, bits).String())
	}
	return out, nil
}

func rateBody(f CDNRateLimitRuleFields) (map[string]any, error) {
	ex, err := cleanSources(f.ExcludeSources, "body.exclude_sources")
	if err != nil {
		return nil, err
	}
	pattern := strings.TrimSpace(f.URLPattern)
	if !strings.HasPrefix(pattern, "/") && !strings.HasPrefix(pattern, "*") {
		pattern = "/" + pattern
	}
	b := map[string]any{
		"url_pattern": pattern, "rate": f.Rate, "time_duration": f.TimeDuration,
		"action": f.Action, "is_enabled": f.Enabled, "exclude_sources": ex,
		"allowed_methods": orEmpty(f.Methods),
	}
	if f.Burst != nil {
		b["burst"] = *f.Burst
	}
	if f.BlockDuration != nil {
		b["block_duration"] = *f.BlockDuration
	}
	return b, nil
}

func (h *dnsHandler) rateLimitOf(ctx context.Context, cl *arvancdn.Client, zone string) (*CDNRateLimit, error) {
	out := &CDNRateLimit{Rules: []CDNRateLimitRule{}}
	raw := map[string]any{}
	if err := cl.Get(ctx, zone, "rate-limit/settings", &raw); err != nil {
		return nil, arvanError(err)
	}
	if err := fromArvan(raw, &out.Settings); err != nil {
		return nil, huma.Error502BadGateway("ArvanCloud sent rate limit settings Morche can't read")
	}
	out.Settings.ExcludeSources = orEmpty(out.Settings.ExcludeSources)
	list, err := cl.List(ctx, zone, "rate-limit/rules")
	if err != nil {
		return nil, arvanError(err)
	}
	for i, item := range list {
		var r arvanRateRule
		if json.Unmarshal(item, &r) != nil {
			continue
		}
		if r.Priority == 0 {
			r.Priority = i + 1
		}
		out.Rules = append(out.Rules, CDNRateLimitRule{ID: r.ID, Priority: r.Priority, CDNRateLimitRuleFields: CDNRateLimitRuleFields{
			URLPattern: r.URLPattern, Rate: r.Rate, TimeDuration: r.TimeDuration, Burst: r.Burst, BlockDuration: r.BlockDuration,
			Action: r.Action, Enabled: r.IsEnabled, Methods: orEmpty(r.AllowedMethods), ExcludeSources: orEmpty(r.ExcludeSources),
		}})
	}
	slices.SortStableFunc(out.Rules, func(a, b CDNRateLimitRule) int { return a.Priority - b.Priority })
	return out, nil
}

// WAF

type CDNWAFPackage struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Provider      string `json:"provider"`
	Enabled       bool   `json:"enabled"`
	DisabledRules int    `json:"disabled_rules" doc:"Rules of the package turned off"`
}

type CDNWAFRuleFields struct {
	URLPattern string   `json:"url_pattern" minLength:"1" maxLength:"500" doc:"Path pattern; * matches anything"`
	Sources    []string `json:"sources,omitempty" maxItems:"20" doc:"Only requests from these addresses; none = everyone"`
	Action     string   `json:"action" enum:"protect,passthrough" doc:"passthrough = the WAF doesn't look at these requests"`
	Enabled    bool     `json:"enabled"`
}

type CDNWAFRule struct {
	ID string `json:"id"`
	CDNWAFRuleFields
	Exceptions int `json:"exceptions" doc:"Package rules skipped on these requests (changed in ArvanCloud's panel)"`
	Priority   int `json:"priority"`
}

type CDNWAF struct {
	Mode      string          `json:"mode" enum:"off,detect,protect" doc:"detect = only log what it would block"`
	Packages  []CDNWAFPackage `json:"packages"`
	Available []CDNWAFPackage `json:"available" doc:"Packages that can be added"`
	Rules     []CDNWAFRule    `json:"rules"`
}

type arvanWAFPackage struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Provider struct {
		Name string `json:"name"`
	} `json:"provider"`
	IsEnabled     *bool    `json:"is_enabled"`
	DisabledRules []string `json:"disabled_rules"`
}

func toWAFPackage(p arvanWAFPackage) CDNWAFPackage {
	return CDNWAFPackage{
		ID: p.ID, Name: p.Name, Provider: p.Provider.Name,
		Enabled: p.IsEnabled == nil || *p.IsEnabled, DisabledRules: len(p.DisabledRules),
	}
}

func (h *dnsHandler) wafOf(ctx context.Context, cl *arvancdn.Client, zone string) (*CDNWAF, error) {
	out := &CDNWAF{Packages: []CDNWAFPackage{}, Available: []CDNWAFPackage{}, Rules: []CDNWAFRule{}}
	raw := map[string]any{}
	if err := cl.Get(ctx, zone, "waf/settings", &raw); err != nil {
		return nil, arvanError(err)
	}
	var settings struct {
		Mode string `json:"mode"`
	}
	if err := fromArvan(raw, &settings, "mode"); err != nil {
		return nil, huma.Error502BadGateway("ArvanCloud sent WAF settings Morche can't read")
	}
	out.Mode = settings.Mode
	if out.Mode == "" {
		out.Mode = "off"
	}
	var pkgs []arvanWAFPackage
	if err := cl.Get(ctx, zone, "waf/packages", &pkgs); err != nil {
		return nil, arvanError(err)
	}
	for _, p := range pkgs {
		out.Packages = append(out.Packages, toWAFPackage(p))
	}
	// What can be added is a nicety: a plan without it still shows the rest.
	var avail []arvanWAFPackage
	if err := cl.Get(ctx, zone, "waf/packages?available=true", &avail); err == nil {
		for _, p := range avail {
			if !slices.ContainsFunc(out.Packages, func(x CDNWAFPackage) bool { return x.ID == p.ID }) {
				out.Available = append(out.Available, toWAFPackage(p))
			}
		}
	}
	list, err := cl.List(ctx, zone, "waf/rules")
	if err != nil {
		return nil, arvanError(err)
	}
	for i, item := range list {
		var r struct {
			ID         string   `json:"id"`
			URLPattern string   `json:"url_pattern"`
			Sources    []string `json:"sources"`
			Action     string   `json:"action"`
			IsEnabled  bool     `json:"is_enabled"`
			Exceptions []any    `json:"exceptions"`
			Priority   int      `json:"priority"`
		}
		if json.Unmarshal(item, &r) != nil {
			continue
		}
		if r.Priority == 0 {
			r.Priority = i + 1
		}
		out.Rules = append(out.Rules, CDNWAFRule{ID: r.ID, Exceptions: len(r.Exceptions), Priority: r.Priority,
			CDNWAFRuleFields: CDNWAFRuleFields{URLPattern: r.URLPattern, Sources: orEmpty(r.Sources), Action: r.Action, Enabled: r.IsEnabled}})
	}
	slices.SortStableFunc(out.Rules, func(a, b CDNWAFRule) int { return a.Priority - b.Priority })
	return out, nil
}

func wafRuleBody(f CDNWAFRuleFields) (map[string]any, error) {
	src, err := cleanSources(f.Sources, "body.sources")
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"url_pattern": strings.TrimSpace(f.URLPattern), "sources": src, "action": f.Action, "is_enabled": f.Enabled,
	}, nil
}

type CDNRulePath struct {
	DNSZonePath
	Rule string `path:"rule" minLength:"1" maxLength:"64" doc:"The rule's id"`
}

type CDNMoveBody struct {
	Before string `json:"before,omitempty" maxLength:"64" doc:"Put it just before this rule"`
	After  string `json:"after,omitempty" maxLength:"64" doc:"Put it just after this rule"`
}

func registerDNSCDNSecurity(api huma.API, h *dnsHandler) {
	tags := []string{"DNS"}
	type fwOut struct{ Body CDNFirewall }
	type rlOut struct{ Body CDNRateLimit }
	type wafOut struct{ Body CDNWAF }

	fresh := func(ctx context.Context, cl *arvancdn.Client, zone, kind string) (any, error) {
		switch kind {
		case "firewall":
			f, err := h.firewallOf(ctx, cl, zone)
			if err != nil {
				return nil, err
			}
			return &fwOut{Body: *f}, nil
		case "rate-limit":
			r, err := h.rateLimitOf(ctx, cl, zone)
			if err != nil {
				return nil, err
			}
			return &rlOut{Body: *r}, nil
		}
		w, err := h.wafOf(ctx, cl, zone)
		if err != nil {
			return nil, err
		}
		return &wafOut{Body: *w}, nil
	}

	// Firewall

	huma.Register(api, huma.Operation{
		OperationID: "get-cdn-firewall", Method: http.MethodGet, Path: "/dns-servers/{id}/zones/{zone}/cdn/firewall",
		Summary: "An ArvanCloud domain's firewall", Description: "Its settings and rules, in the order they're checked.", Tags: tags,
	}, func(ctx context.Context, in *struct{ DNSZonePath }) (*fwOut, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, false)
		if err != nil {
			return nil, err
		}
		out, err := fresh(ctx, cl, zone, "firewall")
		if err != nil {
			return nil, err
		}
		return out.(*fwOut), nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "update-cdn-firewall-settings", Method: http.MethodPatch, Path: "/dns-servers/{id}/zones/{zone}/cdn/firewall/settings",
		Summary: "Change an ArvanCloud domain's firewall settings", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body CDNFirewallSettingsPatch
	}) (*fwOut, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		body, err := toArvan(in.Body)
		if err != nil {
			return nil, internalError(err)
		}
		if err := cl.Send(ctx, http.MethodPatch, zone, "firewall/settings", body, nil); err != nil {
			return nil, arvanError(err)
		}
		out, err := fresh(ctx, cl, zone, "firewall")
		if err != nil {
			return nil, err
		}
		return out.(*fwOut), nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "add-cdn-firewall-rule", Method: http.MethodPost, Path: "/dns-servers/{id}/zones/{zone}/cdn/firewall/rules",
		Summary: "Add a firewall rule", Description: "It goes last. Answers with the firewall, fresh.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body CDNFirewallRuleFields
	}) (*fwOut, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		if err := cl.Send(ctx, http.MethodPost, zone, "firewall/rules", firewallBody(in.Body), nil); err != nil {
			return nil, arvanError(err)
		}
		out, err := fresh(ctx, cl, zone, "firewall")
		if err != nil {
			return nil, err
		}
		return out.(*fwOut), nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "update-cdn-firewall-rule", Method: http.MethodPut, Path: "/dns-servers/{id}/zones/{zone}/cdn/firewall/rules/{rule}",
		Summary: "Change a firewall rule", Tags: tags,
	}, func(ctx context.Context, in *struct {
		CDNRulePath
		Body CDNFirewallRuleFields
	}) (*fwOut, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		if err := cl.Send(ctx, http.MethodPatch, zone, "firewall/rules/"+in.Rule, firewallBody(in.Body), nil); err != nil {
			return nil, arvanError(err)
		}
		out, err := fresh(ctx, cl, zone, "firewall")
		if err != nil {
			return nil, err
		}
		return out.(*fwOut), nil
	})

	// Rate limiting

	huma.Register(api, huma.Operation{
		OperationID: "get-cdn-rate-limit", Method: http.MethodGet, Path: "/dns-servers/{id}/zones/{zone}/cdn/rate-limit",
		Summary: "An ArvanCloud domain's rate limits", Tags: tags,
	}, func(ctx context.Context, in *struct{ DNSZonePath }) (*rlOut, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, false)
		if err != nil {
			return nil, err
		}
		out, err := fresh(ctx, cl, zone, "rate-limit")
		if err != nil {
			return nil, err
		}
		return out.(*rlOut), nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "update-cdn-rate-limit-settings", Method: http.MethodPatch, Path: "/dns-servers/{id}/zones/{zone}/cdn/rate-limit/settings",
		Summary: "Change an ArvanCloud domain's rate limit settings", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body CDNRateLimitSettingsPatch
	}) (*rlOut, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		body := map[string]any{}
		if in.Body.DDoSDetection != nil {
			body["ddos_detection"] = *in.Body.DDoSDetection
		}
		if in.Body.ExcludeSources != nil {
			ex, err := cleanSources(in.Body.ExcludeSources, "body.exclude_sources")
			if err != nil {
				return nil, err
			}
			body["exclude_sources"] = ex
		}
		if err := cl.Send(ctx, http.MethodPatch, zone, "rate-limit/settings", body, nil); err != nil {
			return nil, arvanError(err)
		}
		out, err := fresh(ctx, cl, zone, "rate-limit")
		if err != nil {
			return nil, err
		}
		return out.(*rlOut), nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "add-cdn-rate-limit-rule", Method: http.MethodPost, Path: "/dns-servers/{id}/zones/{zone}/cdn/rate-limit/rules",
		Summary: "Add a rate limit rule", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body CDNRateLimitRuleFields
	}) (*rlOut, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		body, err := rateBody(in.Body)
		if err != nil {
			return nil, err
		}
		if err := cl.Send(ctx, http.MethodPost, zone, "rate-limit/rules", body, nil); err != nil {
			return nil, arvanError(err)
		}
		out, err := fresh(ctx, cl, zone, "rate-limit")
		if err != nil {
			return nil, err
		}
		return out.(*rlOut), nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "update-cdn-rate-limit-rule", Method: http.MethodPut, Path: "/dns-servers/{id}/zones/{zone}/cdn/rate-limit/rules/{rule}",
		Summary: "Change a rate limit rule", Tags: tags,
	}, func(ctx context.Context, in *struct {
		CDNRulePath
		Body CDNRateLimitRuleFields
	}) (*rlOut, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		body, err := rateBody(in.Body)
		if err != nil {
			return nil, err
		}
		if err := cl.Send(ctx, http.MethodPatch, zone, "rate-limit/rules/"+in.Rule, body, nil); err != nil {
			return nil, arvanError(err)
		}
		out, err := fresh(ctx, cl, zone, "rate-limit")
		if err != nil {
			return nil, err
		}
		return out.(*rlOut), nil
	})

	// WAF

	huma.Register(api, huma.Operation{
		OperationID: "get-cdn-waf", Method: http.MethodGet, Path: "/dns-servers/{id}/zones/{zone}/cdn/waf",
		Summary: "An ArvanCloud domain's WAF", Description: "Its mode, rule packages and path rules.", Tags: tags,
	}, func(ctx context.Context, in *struct{ DNSZonePath }) (*wafOut, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, false)
		if err != nil {
			return nil, err
		}
		out, err := fresh(ctx, cl, zone, "waf")
		if err != nil {
			return nil, err
		}
		return out.(*wafOut), nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "update-cdn-waf-mode", Method: http.MethodPut, Path: "/dns-servers/{id}/zones/{zone}/cdn/waf/mode",
		Summary: "Turn an ArvanCloud domain's WAF off, to log only, or to block", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body struct {
			Mode string `json:"mode" enum:"off,detect,protect"`
		}
	}) (*wafOut, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		body, err := toArvan(map[string]any{"mode": in.Body.Mode}, "mode")
		if err != nil {
			return nil, internalError(err)
		}
		if err := cl.Send(ctx, http.MethodPatch, zone, "waf/settings", body, nil); err != nil {
			return nil, arvanError(err)
		}
		out, err := fresh(ctx, cl, zone, "waf")
		if err != nil {
			return nil, err
		}
		return out.(*wafOut), nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "add-cdn-waf-package", Method: http.MethodPost, Path: "/dns-servers/{id}/zones/{zone}/cdn/waf/packages",
		Summary: "Add a WAF rule package", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body struct {
			ID string `json:"id" minLength:"1" maxLength:"100"`
		}
	}) (*wafOut, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		if err := cl.Send(ctx, http.MethodPost, zone, "waf/packages", map[string]string{"id": in.Body.ID}, nil); err != nil {
			return nil, arvanError(err)
		}
		out, err := fresh(ctx, cl, zone, "waf")
		if err != nil {
			return nil, err
		}
		return out.(*wafOut), nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "set-cdn-waf-package", Method: http.MethodPut, Path: "/dns-servers/{id}/zones/{zone}/cdn/waf/packages/{rule}",
		Summary: "Turn a WAF package on or off", Tags: tags,
	}, func(ctx context.Context, in *struct {
		CDNRulePath
		Body struct {
			Enabled bool `json:"enabled"`
		}
	}) (*wafOut, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		if err := cl.Send(ctx, http.MethodPatch, zone, "waf/packages/"+in.Rule, map[string]bool{"is_enabled": in.Body.Enabled}, nil); err != nil {
			return nil, arvanError(err)
		}
		out, err := fresh(ctx, cl, zone, "waf")
		if err != nil {
			return nil, err
		}
		return out.(*wafOut), nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "delete-cdn-waf-package", Method: http.MethodDelete, Path: "/dns-servers/{id}/zones/{zone}/cdn/waf/packages/{rule}",
		Summary: "Remove a WAF package", Tags: tags,
	}, func(ctx context.Context, in *struct{ CDNRulePath }) (*wafOut, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		if err := cl.Send(ctx, http.MethodDelete, zone, "waf/packages/"+in.Rule, nil, nil); err != nil {
			return nil, arvanError(err)
		}
		out, err := fresh(ctx, cl, zone, "waf")
		if err != nil {
			return nil, err
		}
		return out.(*wafOut), nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "add-cdn-waf-rule", Method: http.MethodPost, Path: "/dns-servers/{id}/zones/{zone}/cdn/waf/rules",
		Summary: "Add a WAF path rule", Tags: tags,
	}, func(ctx context.Context, in *struct {
		DNSZonePath
		Body CDNWAFRuleFields
	}) (*wafOut, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		body, err := wafRuleBody(in.Body)
		if err != nil {
			return nil, err
		}
		if err := cl.Send(ctx, http.MethodPost, zone, "waf/rules", body, nil); err != nil {
			return nil, arvanError(err)
		}
		out, err := fresh(ctx, cl, zone, "waf")
		if err != nil {
			return nil, err
		}
		return out.(*wafOut), nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "update-cdn-waf-rule", Method: http.MethodPut, Path: "/dns-servers/{id}/zones/{zone}/cdn/waf/rules/{rule}",
		Summary: "Change a WAF path rule", Tags: tags,
	}, func(ctx context.Context, in *struct {
		CDNRulePath
		Body CDNWAFRuleFields
	}) (*wafOut, error) {
		_, cl, zone, err := h.cdnRequest(ctx, in.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		body, err := wafRuleBody(in.Body)
		if err != nil {
			return nil, err
		}
		if err := cl.Send(ctx, http.MethodPatch, zone, "waf/rules/"+in.Rule, body, nil); err != nil {
			return nil, arvanError(err)
		}
		out, err := fresh(ctx, cl, zone, "waf")
		if err != nil {
			return nil, err
		}
		return out.(*wafOut), nil
	})

	// Shared: delete, move, on/off for every kind of rule.
	registerCDNRuleOps(api, h, "firewall", "firewall rule", h.firewallOf)
	registerCDNRuleOps(api, h, "rate-limit", "rate limit rule", h.rateLimitOf)
	registerCDNRuleOps(api, h, "waf", "WAF path rule", h.wafOf)
}

// registerCDNRuleOps adds delete, on/off and move for one kind of rule; each
// answers the kind's whole section, read again.
func registerCDNRuleOps[T any](api huma.API, h *dnsHandler, kind, noun string, read func(context.Context, *arvancdn.Client, string) (*T, error)) {
	tags := []string{"DNS"}
	base := "/dns-servers/{id}/zones/{zone}/cdn/" + kind + "/rules/{rule}"
	type output struct{ Body T }
	run := func(ctx context.Context, p CDNRulePath, act func(*arvancdn.Client, string) error) (*output, error) {
		_, cl, zone, err := h.cdnRequest(ctx, p.DNSZonePath, true)
		if err != nil {
			return nil, err
		}
		if err := act(cl, zone); err != nil {
			return nil, arvanError(err)
		}
		v, err := read(ctx, cl, zone)
		if err != nil {
			return nil, err
		}
		return &output{Body: *v}, nil
	}

	huma.Register(api, huma.Operation{
		OperationID: "delete-cdn-" + kind + "-rule", Method: http.MethodDelete, Path: base,
		Summary: "Remove a " + noun, Tags: tags,
	}, func(ctx context.Context, in *struct{ CDNRulePath }) (*output, error) {
		return run(ctx, in.CDNRulePath, func(cl *arvancdn.Client, zone string) error {
			return cl.Send(ctx, http.MethodDelete, zone, kind+"/rules/"+in.Rule, nil, nil)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-cdn-" + kind + "-rule-enabled", Method: http.MethodPut, Path: base + "/enabled",
		Summary: "Turn a " + noun + " on or off", Tags: tags,
	}, func(ctx context.Context, in *struct {
		CDNRulePath
		Body struct {
			Enabled bool `json:"enabled"`
		}
	}) (*output, error) {
		return run(ctx, in.CDNRulePath, func(cl *arvancdn.Client, zone string) error {
			return cl.Send(ctx, http.MethodPatch, zone, kind+"/rules/"+in.Rule, map[string]bool{"is_enabled": in.Body.Enabled}, nil)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "move-cdn-" + kind + "-rule", Method: http.MethodPost, Path: base + "/move",
		Summary: "Move a " + noun + " before or after another", Description: "Rules are checked in order; the first match decides.", Tags: tags,
	}, func(ctx context.Context, in *struct {
		CDNRulePath
		Body CDNMoveBody
	}) (*output, error) {
		if in.Body.Before == "" && in.Body.After == "" {
			return nil, fieldError("body.before", "Say which rule it goes before or after", nil)
		}
		return run(ctx, in.CDNRulePath, func(cl *arvancdn.Client, zone string) error {
			return cl.Reprioritize(ctx, zone, kind, in.Rule, in.Body.Before, in.Body.After)
		})
	})
}
