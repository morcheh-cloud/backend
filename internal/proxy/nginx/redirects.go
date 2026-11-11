package nginx

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/morcheh/backend/internal/proxy"
)

// Redirects are two maps at http level: $<tag>_rd on the decoded path
// ($uri) for exact, starts-with and pattern rules, and, when a rule names a
// query, $<tag>_rdq on the address as sent ($request_uri) whose default is
// the first. Each value is "<code>:<target>"; the server block turns it into
// a return with one if per code used, before locations are picked.
//
// nginx matches map strings ignoring case and checks them before regexes,
// which run in order: so exact rules win, then the first matching pattern.

// hashKeyMax is the longest exact key the default map_hash_bucket_size (64)
// holds; longer ones become anchored regexes.
const hashKeyMax = 46

// acmeKey keeps certificate checks out of every redirect.
var acmeKey = quote(`~^/\.well-known/acme-challenge/`) + ` "";`

func redirectVar(t string, rules []proxy.RedirectRule) string {
	if slices.ContainsFunc(rules, proxy.RedirectRule.Conditional) {
		return "$" + t + "_rdc"
	}
	if slices.ContainsFunc(rules, proxy.RedirectRule.HasQuery) {
		return "$" + t + "_rdq"
	}
	return "$" + t + "_rd"
}

// redirectBlocks writes the maps.
func redirectBlocks(w *writer, t string, h proxy.HostConfig) {
	all := h.Redirects.On()
	if len(all) == 0 {
		return
	}
	var rules, cond []proxy.RedirectRule
	for _, r := range all {
		if r.Conditional() {
			cond = append(cond, r)
		} else {
			rules = append(rules, r)
		}
	}
	strict := h.Redirects.StrictSlash
	w.line("")
	w.line("# Redirects: exact addresses first, then patterns in order.")
	w.open("map $uri $%s_rd", t)
	w.line(`default "";`)
	// Exact keys, both slash forms unless strict; a form another rule
	// names itself is left to that rule.
	taken := map[string]bool{}
	for _, r := range rules {
		if r.MatchOf() == proxy.MatchExact && !r.HasQuery() {
			taken[strings.ToLower(r.From)] = true
		}
	}
	var regexes []string
	for _, r := range rules {
		if r.MatchOf() != proxy.MatchExact || r.HasQuery() {
			continue
		}
		v := redirectValue(t, r, r.To)
		keys := []string{r.From}
		if !strict && r.From != "/" {
			alt := strings.TrimRight(r.From, "/")
			if alt == r.From {
				alt += "/"
			}
			if alt != "" && !taken[strings.ToLower(alt)] {
				keys = append(keys, alt)
				taken[strings.ToLower(alt)] = true
			}
		}
		for _, k := range keys {
			if len(k) > hashKeyMax {
				regexes = append(regexes, quote("~*^"+regexp.QuoteMeta(k)+"$")+" "+v+";")
				continue
			}
			w.line("%s %s;", quote(k), v)
		}
	}
	w.line("%s", acmeKey)
	for _, x := range regexes {
		w.line("%s", x)
	}
	for _, r := range rules {
		switch r.MatchOf() {
		case proxy.MatchPrefix:
			re := "~*^" + regexp.QuoteMeta(r.From) + "(?:/(.*))?$"
			if r.From == "/" {
				re = "~*^/(.*)$"
			}
			to := r.To
			if !strings.HasSuffix(to, "/") {
				to += "/"
			}
			w.line("%s %s;", quote(re), redirectValue(t, r, to+"$1"))
		case proxy.MatchRegex:
			w.line("%s %s;", quote("~"+r.From), redirectValue(t, r, r.To))
		}
	}
	w.close()

	// A target with its own query adds the visitor's after an &, if any.
	if slices.ContainsFunc(all, func(r proxy.RedirectRule) bool {
		return r.KeepQuery && r.Code != 410 && strings.Contains(r.To, "?")
	}) {
		w.line("")
		w.open("map $args $%s_rdargs", t)
		w.line(`"" "";`)
		w.line(`default "&$args";`)
		w.close()
	}

	if slices.ContainsFunc(rules, proxy.RedirectRule.HasQuery) {
		queryMap(w, t, rules)
	}
	if len(cond) > 0 {
		conditionMap(w, t, cond, redirectVar(t, rules), strict)
	}
}

func queryMap(w *writer, t string, rules []proxy.RedirectRule) {
	w.line("")
	w.open("map $request_uri $%s_rdq", t)
	w.line("default $%s_rd;", t)
	for _, r := range rules {
		if !r.HasQuery() {
			continue
		}
		v := redirectValue(t, r, r.To)
		if len(r.From) > hashKeyMax {
			w.line("%s %s;", quote("~*^"+regexp.QuoteMeta(r.From)+"$"), v)
		} else {
			w.line("%s %s;", quote(r.From), v)
		}
	}
	w.close()
}

// conditionMap holds the rules with conditions: one string of the facts in
// use (time, country, device, language) and the path, joined by |, matched
// by a regex per rule in list order; nothing matching falls through to the
// plain rules (def).
func conditionMap(w *writer, t string, rules []proxy.RedirectRule, def string, strict bool) {
	var timeUsed, country, device, lang bool
	for _, r := range rules {
		c := r.When
		timeUsed = timeUsed || c.From != "" || c.Until != ""
		country = country || len(c.Countries) > 0
		device = device || len(c.Devices) > 0
		lang = lang || len(c.Languages) > 0
	}
	if device {
		w.line("")
		w.open("map $http_user_agent $%s_rddev", t)
		w.line("default desktop;")
		for _, l := range deviceLines {
			w.line(`"%s" %s;`, l[0], l[1])
		}
		w.close()
	}
	if lang {
		w.line("")
		w.open("map $http_accept_language $%s_rdlang", t)
		w.line(`default "";`)
		w.line(`"~^\s*([A-Za-z]{2,3})" $1;`)
		w.close()
	}
	var fields []string
	if timeUsed {
		fields = append(fields, "$time_iso8601")
	}
	if country {
		fields = append(fields, countryVar)
	}
	if device {
		fields = append(fields, "$"+t+"_rddev")
	}
	if lang {
		fields = append(fields, "$"+t+"_rdlang")
	}
	fields = append(fields, "$uri")
	w.line("")
	w.line("# Redirects with conditions, in list order.")
	w.open("map %s $%s_rdc", quote(strings.Join(fields, "|")), t)
	w.line("default %s;", def)
	skip := "^" + strings.Repeat(`[^|]*\|`, len(fields)-1)
	w.line("%s;", quote("~"+skip+`/\.well-known/acme-challenge/`)+` ""`)
	for _, r := range rules {
		c := r.When
		re := "^"
		if timeUsed {
			re += timeWindow(c.From, c.Until) + `\|`
		}
		if country {
			re += oneOf(c.Countries, false) + `\|`
		}
		if device {
			re += oneOf(c.Devices, false) + `\|`
		}
		if lang {
			re += oneOf(c.Languages, true) + `\|`
		}
		path, to := conditionPath(r, strict)
		w.line("%s %s;", quote("~"+re+path), redirectValue(t, r, to))
	}
	w.close()
}

// oneOf matches a field holding one of the values, anything when none.
func oneOf(values []string, fold bool) string {
	if len(values) == 0 {
		return "[^|]*"
	}
	q := make([]string, len(values))
	for i, v := range values {
		q[i] = regexp.QuoteMeta(v)
	}
	if fold {
		return "(?i:" + strings.Join(q, "|") + ")"
	}
	return "(?:" + strings.Join(q, "|") + ")"
}

// timeWindow matches $time_iso8601 from from (included) until until (not),
// comparing the YYYY-MM-DDTHH:MM digits.
func timeWindow(from, until string) string {
	re := ""
	if from != "" {
		re += "(?=" + timeAtLeast(from) + ")"
	}
	if until != "" {
		re += "(?=" + timeBelow(until) + ")"
	}
	return re + "[^|]*"
}

// timeAtLeast matches text starting with s or anything after it in digit order
// (s's other characters are fixed).
func timeAtLeast(s string) string {
	alts := []string{regexp.QuoteMeta(s)}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= '0' && c < '9' {
			alts = append(alts, regexp.QuoteMeta(s[:i])+"["+string(c+1)+"-9]")
		}
	}
	return "(?:" + strings.Join(alts, "|") + ")"
}

// timeBelow matches text that comes before s in digit order.
func timeBelow(s string) string {
	var alts []string
	for i := 0; i < len(s); i++ {
		if c := s[i]; c > '0' && c <= '9' {
			alts = append(alts, regexp.QuoteMeta(s[:i])+"[0-"+string(c-1)+"]")
		}
	}
	if len(alts) == 0 {
		return "(?!)"
	}
	return "(?:" + strings.Join(alts, "|") + ")"
}

// conditionPath is the path part of a conditional rule's regex and its
// target: exact and starts-with ignore case like the plain maps, a pattern
// keeps its own captures ($1… stay the same, the facts before have none).
func conditionPath(r proxy.RedirectRule, strict bool) (string, string) {
	switch r.MatchOf() {
	case proxy.MatchPrefix:
		to := r.To
		if !strings.HasSuffix(to, "/") {
			to += "/"
		}
		if r.From == "/" {
			return "/(.*)$", to + "$1"
		}
		return "(?i:" + regexp.QuoteMeta(r.From) + ")(?:/(.*))?$", to + "$1"
	case proxy.MatchRegex:
		p := r.From
		flags := ""
		if rest, ok := strings.CutPrefix(p, "(?i)"); ok {
			flags, p = "(?i)", rest
		}
		if strings.HasPrefix(p, "^") {
			return flags + "(?:" + anchorRe.ReplaceAllString(p, "$1") + ")", r.To
		}
		return flags + ".*?(?:" + p + ")", r.To
	}
	from := r.From
	if from == "/" {
		return "/$", r.To
	}
	if strict {
		return "(?i:" + regexp.QuoteMeta(from) + ")$", r.To
	}
	return "(?i:" + regexp.QuoteMeta(strings.TrimRight(from, "/")) + ")/?$", r.To
}

// anchorRe finds the ^ that starts a pattern or one of its top
// alternatives; the path starts right after the facts, so they go.
var anchorRe = regexp.MustCompile(`(^|\||\((?:\?:)?)\^`)

// redirectValue is a map value: "<code>:<target>", the visitor's query added
// when the rule keeps it.
func redirectValue(t string, r proxy.RedirectRule, to string) string {
	if r.Code == 410 {
		return `"410:"`
	}
	if r.KeepQuery {
		if strings.Contains(to, "?") {
			to += "$" + t + "_rdargs"
		} else {
			to += "$is_args$args"
		}
	}
	return quote(strconv.Itoa(r.Code) + ":" + to)
}

// quote puts a value in double quotes, escaping what nginx would read.
func quote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// redirectServer writes the returns. toHTTPS (the port 80 block of a site
// forcing https) sends paths on this site straight to https.
func redirectServer(w *writer, t string, h proxy.HostConfig, toHTTPS bool) {
	rules := h.Redirects.On()
	if len(rules) == 0 {
		return
	}
	v := redirectVar(t, rules)
	var codes []int
	for _, r := range rules {
		if !slices.Contains(codes, r.Code) {
			codes = append(codes, r.Code)
		}
	}
	slices.Sort(codes)
	w.line("")
	w.line("# Redirects")
	for _, c := range codes {
		if c == 410 {
			w.open(`if (%s = "410:")`, v)
			w.line("return 410;")
			w.close()
			continue
		}
		if toHTTPS {
			w.open(`if (%s ~ "^%d:(/.*)$")`, v, c)
			w.line("return %d https://$host$1;", c)
			w.close()
		}
		w.open(`if (%s ~ "^%d:(.+)$")`, v, c)
		w.line("return %d $1;", c)
		w.close()
	}
}
