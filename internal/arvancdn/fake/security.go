package fake

import (
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"
)

// Firewall, WAF and rate limiting of one domain, kept as plain maps the way
// the API sends them.
type security struct {
	settings map[string]map[string]any   // "firewall", "rate-limit", "waf"
	lists    map[string][]map[string]any // "firewall/rules", "rate-limit/rules", "waf/rules"
	packages []map[string]any            // WAF packages on the domain
}

// The WAF packages ArvanCloud offers.
var wafPackages = []map[string]any{
	{"id": "owasp-crs", "name": "OWASP Core Rule Set", "provider": map[string]any{"name": "OWASP", "logo": ""}, "params_schema": map[string]any{}, "disabled_rules": []string{}, "disabled_rulesets": []string{}},
	{"id": "arvan-wordpress", "name": "WordPress", "provider": map[string]any{"name": "ArvanCloud", "logo": ""}, "params_schema": map[string]any{}, "disabled_rules": []string{}, "disabled_rulesets": []string{}},
	{"id": "arvan-php", "name": "PHP applications", "provider": map[string]any{"name": "ArvanCloud", "logo": ""}, "params_schema": map[string]any{}, "disabled_rules": []string{}, "disabled_rulesets": []string{}},
}

func clone(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func newSecurity(active bool) *security {
	s := &security{
		settings: map[string]map[string]any{
			"firewall":   {"is_enabled": true, "default_action": "allow", "verify_sni": true, "skip_global_whitelist": false, "skip_global_firewall": false, "default_action_details": nil},
			"rate-limit": {"ddos_detection": false, "exclude_sources": []string{}},
			"waf": {"is_enabled": false, "mode": false, "log_redaction": map[string]any{
				"cookies": []string{}, "headers": []string{"authorization", "proxy-authorization", "cookie"},
				"all_headers": false, "body": true, "records": false, "replacement_string": "--REDACTED--",
			}},
		},
		lists: map[string][]map[string]any{"firewall/rules": {}, "rate-limit/rules": {}, "waf/rules": {}},
	}
	if active {
		s.settings["waf"]["mode"] = "detect"
		s.settings["waf"]["is_enabled"] = true
		p := clone(wafPackages[0])
		p["is_enabled"], p["params"] = true, map[string]any{}
		s.packages = []map[string]any{p}
		s.lists["firewall/rules"] = []map[string]any{
			{"id": uuid.NewString(), "name": "Office", "filter_expr": `ip.src in {185.206.92.0/24}`, "action": "allow", "priority": 1, "is_enabled": true, "note": "Our office", "is_account_level": false},
			{"id": uuid.NewString(), "name": "Block bad bots", "filter_expr": `http.user_agent contains "sqlmap"`, "action": "deny", "priority": 2, "is_enabled": true, "note": "", "is_account_level": false},
			{"id": uuid.NewString(), "name": "Challenge outside Iran", "filter_expr": `not ip.geoip.country in {"IR"} and http.request.uri.path contains "/admin"`, "action": "challenge", "priority": 3, "is_enabled": false, "note": "", "is_account_level": false},
		}
		s.lists["rate-limit/rules"] = []map[string]any{
			{"id": uuid.NewString(), "url_pattern": "/api/*", "rate": 100, "time_duration": 60, "burst": 20, "block_duration": 300, "action": "block", "is_enabled": true, "allowed_methods": []string{"GET", "POST"}, "exclude_sources": []string{}, "priority": 1},
			{"id": uuid.NewString(), "url_pattern": "/login", "rate": 5, "time_duration": 60, "burst": 1, "block_duration": 900, "action": "challenge", "is_enabled": true, "allowed_methods": []string{"POST"}, "exclude_sources": []string{"185.206.92.0/24"}, "priority": 2},
		}
		s.lists["waf/rules"] = []map[string]any{
			{"id": uuid.NewString(), "url_pattern": "/api/webhooks/*", "sources": []string{}, "action": "passthrough", "is_enabled": true, "exceptions": []any{}, "priority": 1},
		}
	}
	return s
}

func (d *domain) security() *security {
	if d.sec == nil {
		d.sec = newSecurity(d.Status == "active" && d.Type == "full")
	}
	return d.sec
}

func reorder(list []map[string]any) {
	for i, r := range list {
		r["priority"] = i + 1
	}
}

// serveSecurity answers the security paths of a domain; false = not one.
func serveSecurity(w http.ResponseWriter, r *http.Request, d *domain, sub []string) bool {
	if len(sub) < 2 || (sub[0] != "firewall" && sub[0] != "rate-limit" && sub[0] != "waf") {
		return false
	}
	s := d.security()
	kind := sub[0]
	switch {
	case sub[1] == "settings" && len(sub) == 2:
		m := s.settings[kind]
		if r.Method == http.MethodPatch {
			for k, v := range readBody(r) {
				if k == "is_enabled" {
					continue
				}
				if _, ok := m[k]; !ok && k != "default_action_details" {
					invalid(w, k, "Unknown setting.")
					return true
				}
				m[k] = v
			}
			if kind == "waf" {
				m["is_enabled"] = m["mode"] != false
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": m})
	case sub[1] == "actions" && len(sub) == 3 && sub[2] == "reprioritize" && r.Method == http.MethodPost:
		list := s.lists[kind+"/rules"]
		b := readBody(r)
		id, _ := b["rule_id"].(string)
		i := slices.IndexFunc(list, func(x map[string]any) bool { return x["id"] == id })
		if i < 0 {
			fail(w, http.StatusNotFound, "Rule not found")
			return true
		}
		rule := list[i]
		list = slices.Delete(list, i, i+1)
		at := len(list)
		if before, ok := b["before_rule_id"].(string); ok {
			if j := slices.IndexFunc(list, func(x map[string]any) bool { return x["id"] == before }); j >= 0 {
				at = j
			}
		} else if after, ok := b["after_rule_id"].(string); ok {
			if j := slices.IndexFunc(list, func(x map[string]any) bool { return x["id"] == after }); j >= 0 {
				at = j + 1
			}
		}
		list = slices.Insert(list, at, rule)
		reorder(list)
		s.lists[kind+"/rules"] = list
		writeJSON(w, http.StatusOK, map[string]any{"message": "Priorities updated"})
	case sub[1] == "rules":
		key := kind + "/rules"
		list := s.lists[key]
		if len(sub) == 2 {
			switch r.Method {
			case http.MethodGet:
				items := []any{}
				for _, x := range list {
					items = append(items, x)
				}
				writeJSON(w, http.StatusOK, paged(r, items))
			case http.MethodPost:
				b := readBody(r)
				if msg, field := checkRule(kind, b); msg != "" {
					invalid(w, field, msg)
					return true
				}
				b["id"] = uuid.NewString()
				if _, ok := b["is_enabled"]; !ok {
					b["is_enabled"] = true
				}
				list = append(list, b)
				reorder(list)
				s.lists[key] = list
				writeJSON(w, http.StatusCreated, map[string]any{"data": b})
			default:
				fail(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return true
		}
		i := slices.IndexFunc(list, func(x map[string]any) bool { return x["id"] == sub[2] })
		if i < 0 {
			fail(w, http.StatusNotFound, "Rule not found")
			return true
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, map[string]any{"data": list[i]})
		case http.MethodPatch, http.MethodPut:
			next := clone(list[i])
			for k, v := range readBody(r) {
				next[k] = v
			}
			if msg, field := checkRule(kind, next); msg != "" {
				invalid(w, field, msg)
				return true
			}
			list[i] = next
			writeJSON(w, http.StatusOK, map[string]any{"data": next})
		case http.MethodDelete:
			list = slices.Delete(list, i, i+1)
			reorder(list)
			s.lists[key] = list
			writeJSON(w, http.StatusOK, map[string]any{"message": "Rule removed"})
		default:
			fail(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	case kind == "waf" && sub[1] == "packages":
		if len(sub) == 2 {
			switch r.Method {
			case http.MethodGet:
				if r.URL.Query().Get("available") == "true" {
					var out []map[string]any
					for _, p := range wafPackages {
						if !slices.ContainsFunc(s.packages, func(x map[string]any) bool { return x["id"] == p["id"] }) {
							out = append(out, p)
						}
					}
					writeJSON(w, http.StatusOK, map[string]any{"data": out})
					return true
				}
				writeJSON(w, http.StatusOK, map[string]any{"data": s.packages})
			case http.MethodPost:
				id, _ := readBody(r)["id"].(string)
				j := slices.IndexFunc(wafPackages, func(x map[string]any) bool { return x["id"] == id })
				if j < 0 {
					invalid(w, "id", "The selected package is invalid.")
					return true
				}
				if slices.ContainsFunc(s.packages, func(x map[string]any) bool { return x["id"] == id }) {
					invalid(w, "id", "The package is already added.")
					return true
				}
				p := clone(wafPackages[j])
				p["is_enabled"], p["params"] = true, map[string]any{}
				s.packages = append(s.packages, p)
				writeJSON(w, http.StatusOK, map[string]any{"data": p})
			default:
				fail(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return true
		}
		i := slices.IndexFunc(s.packages, func(x map[string]any) bool { return x["id"] == sub[2] })
		if i < 0 {
			fail(w, http.StatusNotFound, "Package not found")
			return true
		}
		switch r.Method {
		case http.MethodPatch:
			for k, v := range readBody(r) {
				if k == "is_enabled" || k == "params" || k == "disabled_rules" || k == "disabled_rulesets" {
					s.packages[i][k] = v
				}
			}
			writeJSON(w, http.StatusOK, map[string]any{"data": s.packages[i]})
		case http.MethodDelete:
			s.packages = slices.Delete(s.packages, i, i+1)
			writeJSON(w, http.StatusOK, map[string]any{"message": "Package removed"})
		default:
			writeJSON(w, http.StatusOK, map[string]any{"data": s.packages[i]})
		}
	default:
		fail(w, http.StatusNotFound, "not found")
	}
	return true
}

func checkRule(kind string, b map[string]any) (string, string) {
	str := func(k string) string { v, _ := b[k].(string); return strings.TrimSpace(v) }
	num := func(k string) float64 { v, _ := b[k].(float64); return v }
	switch kind {
	case "firewall":
		if str("name") == "" {
			return "The name field is required.", "name"
		}
		if len(str("filter_expr")) < 3 {
			return "The filter expr must be at least 3 characters.", "filter_expr"
		}
		if strings.Count(str("filter_expr"), "{") != strings.Count(str("filter_expr"), "}") {
			return "The filter expression is invalid: unbalanced braces.", "filter_expr"
		}
		if !slices.Contains([]string{"allow", "deny", "bypass", "challenge"}, str("action")) {
			return "The selected action is invalid.", "action"
		}
	case "rate-limit":
		if str("url_pattern") == "" {
			return "The url pattern field is required.", "url_pattern"
		}
		if num("rate") < 1 {
			return "The rate must be at least 1.", "rate"
		}
		if num("time_duration") < 1 {
			return "The time duration must be at least 1.", "time_duration"
		}
	case "waf":
		if str("url_pattern") == "" {
			return "The url pattern field is required.", "url_pattern"
		}
		if !slices.Contains([]string{"protect", "passthrough"}, str("action")) {
			return "The selected action is invalid.", "action"
		}
	}
	return "", ""
}

// serveAccountWAF answers GET /waf: presets and packages.
func serveAccountWAF(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"presets": []any{
			map[string]any{"id": "7f3c2a10-0000-4000-8000-000000000001", "name": "Recommended", "packages": []any{map[string]any{"name": "OWASP Core Rule Set"}}},
		},
		"packages": wafPackages,
	}})
}
