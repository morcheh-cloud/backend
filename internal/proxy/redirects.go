package proxy

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// MaxRedirects is how many redirect rules a site can carry.
const MaxRedirects = 5000

// Redirects send old addresses of a site to new ones before anything else
// answers (every type but stream; Capabilities.Redirects).
type Redirects struct {
	Rules []RedirectRule `json:"rules,omitempty" maxItems:"5000" doc:"Exact addresses win; then the first matching starts-with or pattern rule in list order"`
	// StrictSlash keeps /old and /old/ apart; off, an exact rule takes both.
	StrictSlash bool `json:"strict_slash,omitempty" doc:"Treat /old and /old/ as different addresses (exact rules)"`
}

// RedirectRule is one old address and where it goes.
type RedirectRule struct {
	From string `json:"from" maxLength:"2048" doc:"The old address: a path like /old-page (with ?query for an exact rule), or a pattern"`
	// Match: exact (the default) also takes the address with a query unless
	// From has one itself; prefix takes From and everything under it, adding
	// the rest to To; regex is a PCRE pattern on the path, $1… usable in To.
	Match     string `json:"match,omitempty" enum:",exact,prefix,regex" doc:"exact (default), prefix (the path and everything under it) or regex"`
	To        string `json:"to,omitempty" maxLength:"2048" doc:"Where it goes: a path on this site or a full http(s) address; empty for 410"`
	Code      int    `json:"code,omitempty" enum:"0,301,302,307,308,410" doc:"0 = 301; 410 answers Gone instead of redirecting"`
	KeepQuery bool   `json:"keep_query,omitempty" doc:"Add the visitor's query string to the target"`
	Off       bool   `json:"off,omitempty" doc:"Kept in the list but not used"`
	Note      string `json:"note,omitempty" maxLength:"200"`
	// When limits the rule to some visitors or a time window; the other
	// visitors fall through to the rules without one.
	When *RedirectWhen `json:"when,omitempty" doc:"Only redirect when all of these hold; rules with conditions are checked first, in list order"`
}

// RedirectWhen is a rule's conditions; an empty list or time is no limit.
type RedirectWhen struct {
	Countries []string `json:"countries,omitempty" maxItems:"250" doc:"The visitor's country (two-letter codes, like DE); needs country lookup"`
	Languages []string `json:"languages,omitempty" maxItems:"30" doc:"The browser's first language (Accept-Language), like fa or en"`
	Devices   []string `json:"devices,omitempty" maxItems:"3" doc:"phone, tablet or desktop, by User-Agent"`
	From      string   `json:"from,omitempty" doc:"From this time on, 2006-01-02T15:04 in the proxy server's time"`
	Until     string   `json:"until,omitempty" doc:"Before this time, 2006-01-02T15:04 in the proxy server's time"`
}

// RedirectDevices are the device kinds a rule can name.
var RedirectDevices = []string{"phone", "tablet", "desktop"}

// WhenLayout is how a condition's times are written.
const WhenLayout = "2006-01-02T15:04"

// Empty says whether the conditions limit nothing.
func (w *RedirectWhen) Empty() bool {
	return w == nil || len(w.Countries)+len(w.Languages)+len(w.Devices) == 0 && w.From == "" && w.Until == ""
}

// Conditional says whether the rule has conditions.
func (r RedirectRule) Conditional() bool { return !r.When.Empty() }

// UsesCountries says whether a rule in use needs country lookup.
func (r Redirects) UsesCountries() bool {
	return slices.ContainsFunc(r.On(), func(x RedirectRule) bool { return x.Conditional() && len(x.When.Countries) > 0 })
}

var (
	langRe      = regexp.MustCompile(`^[a-z]{2,3}$`)
	twoLetterRe = regexp.MustCompile(`^[A-Z]{2}$`)
)

func normalizeWhen(w *RedirectWhen) *RedirectWhen {
	if w == nil {
		return nil
	}
	tidy := func(list []string, upper bool) []string {
		var out []string
		for _, x := range list {
			x = strings.TrimSpace(x)
			if upper {
				x = strings.ToUpper(x)
			} else {
				x = strings.ToLower(x)
			}
			if x != "" && !slices.Contains(out, x) {
				out = append(out, x)
			}
		}
		return out
	}
	n := &RedirectWhen{
		Countries: tidy(w.Countries, true), Languages: tidy(w.Languages, false), Devices: tidy(w.Devices, false),
		From: strings.TrimSpace(w.From), Until: strings.TrimSpace(w.Until),
	}
	if n.Empty() {
		return nil
	}
	return n
}

func validateWhen(f string, r RedirectRule, add func(field, msg string, v any)) {
	w := r.When
	if w.Empty() {
		return
	}
	if r.HasQuery() {
		add(f+".from", "A rule with conditions can't name a query; leave the ?… out.", r.From)
	}
	for i, c := range w.Countries {
		if !twoLetterRe.MatchString(c) {
			add(fmt.Sprintf("%s.when.countries[%d]", f, i), "Use a two-letter country code, like DE.", c)
		}
	}
	for i, l := range w.Languages {
		if !langRe.MatchString(l) {
			add(fmt.Sprintf("%s.when.languages[%d]", f, i), "Use a two- or three-letter language code, like fa.", l)
		}
	}
	for i, d := range w.Devices {
		if !slices.Contains(RedirectDevices, d) {
			add(fmt.Sprintf("%s.when.devices[%d]", f, i), "Choose phone, tablet or desktop.", d)
		}
	}
	if len(w.Devices) == len(RedirectDevices) {
		add(f+".when.devices", "Every device is picked; leave them all off instead.", w.Devices)
	}
	var from, until time.Time
	var err error
	if w.From != "" {
		if from, err = time.Parse(WhenLayout, w.From); err != nil {
			add(f+".when.from", "Use a date and time like 2026-12-01T09:00.", w.From)
		}
	}
	if w.Until != "" {
		if until, err = time.Parse(WhenLayout, w.Until); err != nil {
			add(f+".when.until", "Use a date and time like 2026-12-31T23:59.", w.Until)
		}
	}
	if !from.IsZero() && !until.IsZero() && !until.After(from) {
		add(f+".when.until", "The end has to come after the start.", w.Until)
	}
}

// MatchOf is the rule's match, exact when empty.
func (r RedirectRule) MatchOf() string {
	if r.Match == "" {
		return MatchExact
	}
	return r.Match
}

// HasQuery says whether an exact rule names a query string itself.
func (r RedirectRule) HasQuery() bool {
	return r.MatchOf() == MatchExact && strings.Contains(r.From, "?")
}

// On returns the rules that are in use.
func (r Redirects) On() []RedirectRule {
	var out []RedirectRule
	for _, x := range r.Rules {
		if !x.Off {
			out = append(out, x)
		}
	}
	return out
}

// RedirectCodes are the answers a rule can give.
var RedirectCodes = []int{301, 302, 307, 308, 410}

var (
	captureRe = regexp.MustCompile(`\$[1-9]`)
	// A target may not carry anything a quoted config value would change.
	badTargetRe = regexp.MustCompile("[\\s\"'`\\\\{};]")
)

func normalizeRedirects(h HostConfig) HostConfig {
	if h.IsStream() {
		h.Redirects = Redirects{}
		return h
	}
	rules := h.Redirects.Rules[:0:0]
	for _, r := range h.Redirects.Rules {
		r.From, r.To = strings.TrimSpace(r.From), strings.TrimSpace(r.To)
		r.Note = strings.Join(strings.Fields(r.Note), " ")
		if r.From == "" && r.To == "" {
			continue
		}
		if r.Match == "" {
			r.Match = MatchExact
		}
		if r.Code == 0 {
			r.Code = 301
		}
		if r.Match != MatchRegex {
			r.From = sitePath(r.From, h.Domains)
		}
		if r.Match == MatchPrefix && len(r.From) > 1 {
			r.From = strings.TrimRight(r.From, "/")
			if r.From == "" {
				r.From = "/"
			}
		}
		if r.Code == 410 {
			r.To, r.KeepQuery = "", false
		}
		r.When = normalizeWhen(r.When)
		rules = append(rules, r)
	}
	h.Redirects.Rules = rules
	if len(rules) == 0 {
		h.Redirects = Redirects{StrictSlash: h.Redirects.StrictSlash}
	}
	return h
}

// sitePath turns an address of this site (https://example.com/old?x=1) into
// its path (/old?x=1), decodes %XX in the path (nginx matches the decoded
// one) and adds a missing leading slash. Another site's address is left as
// it is, for Validate to name.
func sitePath(s string, domains []string) string {
	low := strings.ToLower(s)
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") || strings.HasPrefix(s, "//") {
		u, err := url.Parse(s)
		if err != nil || !ownsHost(domains, strings.ToLower(u.Hostname())) {
			return s
		}
		s = u.EscapedPath()
		if s == "" {
			s = "/"
		}
		if u.RawQuery != "" {
			s += "?" + u.RawQuery
		}
	}
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	path, query, hasQuery := strings.Cut(s, "?")
	if p, err := url.PathUnescape(path); err == nil && !strings.ContainsAny(p, "\x00\r\n?") {
		path = p
	}
	if hasQuery {
		return path + "?" + query
	}
	return path
}

// ownsHost says whether one of a site's names answers host.
func ownsHost(domains []string, host string) bool {
	for _, d := range domains {
		if d == host {
			return true
		}
		if rest, ok := strings.CutPrefix(d, "*."); ok && strings.HasSuffix(host, "."+rest) {
			return true
		}
	}
	return false
}

// SlashKey is how an exact path compares with others: lowercased (nginx
// matches it ignoring case) and, unless strict, without a trailing slash.
func SlashKey(from string, strict bool) string {
	k := strings.ToLower(from)
	if !strict && len(k) > 1 && !strings.Contains(k, "?") {
		k = strings.TrimRight(k, "/")
		if k == "" {
			k = "/"
		}
	}
	return k
}

func validateRedirects(h HostConfig, add func(field, msg string, v any)) {
	if len(h.Redirects.Rules) > MaxRedirects {
		add("redirects.rules", fmt.Sprintf("Up to %d rules.", MaxRedirects), len(h.Redirects.Rules))
	}
	seen := map[string]bool{}
	for i, r := range h.Redirects.Rules {
		f := fmt.Sprintf("redirects.rules[%d]", i)
		m := r.MatchOf()
		switch m {
		case MatchExact, MatchPrefix:
			if msg := checkFromPath(r.From, m); msg != "" {
				add(f+".from", msg, r.From)
			}
		case MatchRegex:
			if msg := checkRegex(r.From); msg != "" {
				add(f+".from", msg, r.From)
			}
		default:
			add(f+".match", "Choose exact, starts with or pattern.", r.Match)
		}
		if !slices.Contains(RedirectCodes, r.Code) {
			add(f+".code", "Use 301, 302, 307, 308 or 410.", r.Code)
		}
		if r.Code != 410 {
			if msg := checkTarget(r, m); msg != "" {
				add(f+".to", msg, r.To)
			} else if m == MatchExact && selfLoop(r, h.Redirects.StrictSlash) {
				add(f+".to", "This sends the address to itself.", r.To)
			}
		}
		validateWhen(f, r, add)
		if r.Off || r.Conditional() {
			continue
		}
		key := m + " " + r.From
		if m == MatchExact {
			key = m + " " + SlashKey(r.From, h.Redirects.StrictSlash)
		}
		if seen[key] {
			add(f+".from", "This address is listed twice.", r.From)
		}
		seen[key] = true
	}
}

func checkFromPath(s, match string) string {
	switch {
	case s == "":
		return "Enter the old address, like /old-page."
	case strings.HasPrefix(strings.ToLower(s), "http://"), strings.HasPrefix(strings.ToLower(s), "https://"):
		return "That's another site's address; use a path on this one, like /old-page."
	case strings.ContainsAny(s, "\"\\\x00\r\n\t"):
		return "Quotes, \\ and line breaks aren't allowed."
	case strings.HasPrefix(strings.ToLower(s), "/.well-known/acme-challenge/"):
		return "Certificate checks use this path; it can't be redirected."
	case match == MatchPrefix && strings.Contains(s, "?"):
		return "A starts-with rule can't name a query; use an exact rule."
	}
	return ""
}

func checkTarget(r RedirectRule, match string) string {
	t := r.To
	switch {
	case t == "":
		return "Enter where it goes, like /new-page or https://example.com/."
	case badTargetRe.MatchString(t):
		return "Spaces, quotes, \\ ; { } aren't allowed."
	}
	if rest := captureRe.ReplaceAllString(t, ""); strings.Contains(rest, "$") {
		return "$ is only allowed as $1 to $9."
	}
	if captureRe.MatchString(t) && match != MatchRegex {
		return "$1 to $9 only work with a pattern."
	}
	if match == MatchPrefix && strings.Contains(t, "?") {
		return "A starts-with rule adds the rest of the path to the target, so it can't have a query."
	}
	if strings.HasPrefix(t, "/") {
		if strings.HasPrefix(t, "//") {
			return "Use a full address (https://…) or a path starting with one /."
		}
		return ""
	}
	if msg := checkURL(captureRe.ReplaceAllString(t, "1")); msg != "" {
		return "Use a path like /new-page or a full address starting with http:// or https://."
	}
	return ""
}

// selfLoop says whether an exact rule sends its address back to itself.
func selfLoop(r RedirectRule, strict bool) bool {
	to := r.To
	if strings.Contains(to, "://") {
		return false
	}
	if !r.HasQuery() {
		to, _, _ = strings.Cut(to, "?")
	}
	return SlashKey(to, strict) == SlashKey(r.From, strict)
}
