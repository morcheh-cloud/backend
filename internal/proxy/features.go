package proxy

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Auth asks visitors to sign in before the site answers: a user name and
// password checked by the proxy (basic), or a sign-in service like Authelia,
// oauth2-proxy or authentik asked about every request (forward). Proxy and
// static sites only.
type Auth struct {
	Mode  string     `json:"mode,omitempty" enum:",basic,forward" doc:"basic = user names and passwords; forward = ask a sign-in service; empty = off"`
	Realm string     `json:"realm,omitempty" maxLength:"100" doc:"Text the browser's sign-in box shows (basic); empty = Restricted"`
	Users []AuthUser `json:"users,omitempty" maxItems:"200" doc:"Who may sign in (basic)"`
	// Forward is the sign-in service (forward).
	Forward ForwardAuth `json:"forward" required:"false"`
	// SkipForAllowed lets the addresses in Allow in without signing in.
	SkipForAllowed bool `json:"skip_for_allowed,omitempty" doc:"Addresses in the Always let in list don't have to sign in"`
}

// On says whether visitors have to sign in.
func (a Auth) On() bool { return a.Mode != "" }

// AuthUser is one sign-in. Password is only ever sent in: the API turns it
// into Hash (SHA-512 crypt) and never answers either.
type AuthUser struct {
	Name     string `json:"name" maxLength:"64"`
	Password string `json:"password,omitempty" maxLength:"200" doc:"New password; empty keeps the saved one. Never sent back"`
	Hash     string `json:"hash,omitempty" maxLength:"200" doc:"Set by Morcheh; never sent back, ignored when sent"`
}

// ForwardAuth is a sign-in service asked about every request: a 2xx answer
// lets the visitor in, 401 sends them to SigninURL, anything else refuses.
type ForwardAuth struct {
	URL       string   `json:"url,omitempty" doc:"The service's check address, like http://127.0.0.1:9091/api/authz/auth-request" example:"http://127.0.0.1:9091/api/authz/auth-request"`
	SigninURL string   `json:"signin_url,omitempty" doc:"Where visitors who aren't signed in are sent (the page they wanted is added as rd=); empty = they get the 401"`
	Headers   []string `json:"headers,omitempty" maxItems:"20" doc:"Headers of the service's answer passed on to the upstream, like Remote-User"`
	PassPath  string   `json:"pass_path,omitempty" maxLength:"200" doc:"A path the service serves itself on this site, sent to it without a check, like /oauth2/"`
}

// UpstreamTLS is how the proxy talks to an https upstream (proxy sites).
type UpstreamTLS struct {
	Verify      bool   `json:"verify,omitempty" doc:"Check the upstream's certificate; off accepts any (self-signed included)"`
	CA          string `json:"ca,omitempty" doc:"CA file on the server to check it against; empty = the system's"`
	Name        string `json:"name,omitempty" doc:"Name sent (SNI) and checked; empty = the upstream address's host"`
	Certificate string `json:"certificate,omitempty" doc:"Client certificate shown to the upstream (mutual TLS)"`
	Key         string `json:"key,omitempty" doc:"Its private key"`
}

// IsZero says whether nothing is set.
func (u UpstreamTLS) IsZero() bool { return u == UpstreamTLS{} }

// Maintenance shows a "back soon" page (503) to everyone but some addresses.
type Maintenance struct {
	Enabled      bool     `json:"enabled,omitempty"`
	Allow        []string `json:"allow,omitempty" maxItems:"100" doc:"Addresses or ranges that still see the site"`
	Title        string   `json:"title,omitempty" maxLength:"200" doc:"Empty = We'll be back soon"`
	Message      string   `json:"message,omitempty" maxLength:"2000"`
	RetryMinutes int      `json:"retry_minutes,omitempty" minimum:"0" maximum:"10080" doc:"Sent as Retry-After; 0 = none"`
}

// ErrorPage is the page shown for some statuses.
type ErrorPage struct {
	Codes   []int  `json:"codes" maxItems:"11"`
	Title   string `json:"title,omitempty" maxLength:"200"`
	Message string `json:"message,omitempty" maxLength:"2000"`
}

// ErrorCodes are the statuses an error page can show for.
var ErrorCodes = []int{400, 403, 404, 405, 408, 413, 429, 500, 502, 503, 504}

// Hardening refuses requests no real visitor makes.
type Hardening struct {
	Dotfiles   bool     `json:"dotfiles,omitempty" doc:"Hidden files and folders like /.git and /.env (/.well-known stays open)"`
	Backups    bool     `json:"backups,omitempty" doc:"Backup and dump files: .bak .old .orig .swp .sql .sqlite … and names ending in ~"`
	Scanners   bool     `json:"scanners,omitempty" doc:"Known attack tools by their User-Agent (sqlmap, nikto, nuclei …)"`
	AICrawlers bool     `json:"ai_crawlers,omitempty" doc:"AI training crawlers (GPTBot, ClaudeBot, CCBot, Bytespider …)"`
	Probes     bool     `json:"probes,omitempty" doc:"Paths bots try on every site: phpMyAdmin, cgi-bin, phpunit, router exploits"`
	Methods    []string `json:"methods,omitempty" maxItems:"9" doc:"Only these request methods are answered (others get 405); empty = all"`
	Status     int      `json:"status,omitempty" enum:"0,403,404,444" doc:"Answer to refused requests; 0 = 404"`
}

// On says whether anything is refused.
func (h Hardening) On() bool {
	return h.Dotfiles || h.Backups || h.Scanners || h.AICrawlers || h.Probes || len(h.Methods) > 0
}

// HardeningMethods are the methods Hardening.Methods may name.
var HardeningMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "PROPFIND", "PROPPATCH"}

// Path rule matches and actions.
const (
	MatchPrefix = "prefix"
	MatchExact  = "exact"
	MatchRegex  = "regex"

	ActionProxy    = "proxy"
	ActionRedirect = "redirect"
	ActionStatic   = "static"
	ActionDeny     = "deny"
	ActionReturn   = "return"
)

// MatchOf and ActionOf fill a path rule's defaults.
func (p PathRule) MatchOf() string {
	if p.Match == "" {
		return MatchPrefix
	}
	return p.Match
}

func (p PathRule) ActionOf() string {
	if p.Action == "" {
		return ActionProxy
	}
	return p.Action
}

var (
	userRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)
	// Escapes nginx's config parser would change inside quotes.
	nginxEscRe = regexp.MustCompile(`\\[\\"'ntr]`)
)

// normalizeFeatures tidies and clears the newer options by type.
func normalizeFeatures(h HostConfig) HostConfig {
	site := h.Type == TypeProxy || h.Type == TypeStatic
	if !site {
		h.Auth = Auth{}
	}
	switch h.Auth.Mode {
	case "":
		h.Auth = Auth{}
	case "basic":
		h.Auth.Forward = ForwardAuth{}
		h.Auth.Realm = strings.TrimSpace(h.Auth.Realm)
		users := h.Auth.Users[:0:0]
		for _, u := range h.Auth.Users {
			u.Name = strings.TrimSpace(u.Name)
			if u.Name != "" || u.Password != "" {
				users = append(users, u)
			}
		}
		h.Auth.Users = users
	case "forward":
		h.Auth.Users, h.Auth.Realm = nil, ""
		f := &h.Auth.Forward
		f.URL, f.SigninURL = strings.TrimSpace(f.URL), strings.TrimSpace(f.SigninURL)
		f.PassPath = strings.TrimSpace(f.PassPath)
		f.Headers = tidyList(f.Headers)
	}
	if len(h.Allow) == 0 {
		h.Auth.SkipForAllowed = false
	}

	if h.Type != TypeProxy {
		h.UpstreamTLS, h.InterceptErrors = UpstreamTLS{}, false
	}
	u := &h.UpstreamTLS
	u.CA, u.Name = strings.TrimSpace(u.CA), strings.ToLower(strings.TrimSpace(u.Name))
	u.Certificate, u.Key = strings.TrimSpace(u.Certificate), strings.TrimSpace(u.Key)
	if !u.Verify {
		u.CA = ""
	}

	if h.IsStream() || h.Type == TypeNotFound {
		h.Maintenance = Maintenance{}
	}
	m := &h.Maintenance
	m.Allow = tidyList(m.Allow)
	m.Title, m.Message = strings.TrimSpace(m.Title), strings.TrimSpace(strings.ReplaceAll(m.Message, "\r\n", "\n"))

	if h.IsStream() {
		h.ErrorPages, h.Hardening, h.RequestID = nil, Hardening{}, false
	}
	pages := h.ErrorPages[:0:0]
	for _, p := range h.ErrorPages {
		p.Title, p.Message = strings.TrimSpace(p.Title), strings.TrimSpace(strings.ReplaceAll(p.Message, "\r\n", "\n"))
		var codes []int
		for _, c := range p.Codes {
			if !slices.Contains(codes, c) {
				codes = append(codes, c)
			}
		}
		slices.Sort(codes)
		p.Codes = codes
		if len(p.Codes) > 0 || p.Title != "" || p.Message != "" {
			pages = append(pages, p)
		}
	}
	h.ErrorPages = pages
	if len(h.ErrorPages) == 0 {
		h.InterceptErrors = false
	}

	var methods []string
	for _, x := range h.Hardening.Methods {
		if x = strings.ToUpper(strings.TrimSpace(x)); x != "" && !slices.Contains(methods, x) {
			methods = append(methods, x)
		}
	}
	h.Hardening.Methods = methods
	if !h.Hardening.On() {
		h.Hardening = Hardening{}
	} else if h.Hardening.Status == 0 {
		h.Hardening.Status = 404
	}

	if h.Type != TypeProxy && h.Type != TypeStatic {
		h.Brotli = false
	}
	if h.Type == TypeNotFound {
		if h.NotFoundCode == 0 {
			h.NotFoundCode = 404
		}
		if h.CatchAll {
			h.TLS.ForceHTTPS, h.TLS.ForceCode = false, 0
		}
	} else {
		h.CatchAll, h.NotFoundCode = false, 0
	}

	for i, x := range h.Headers {
		if x.To == "hide" {
			h.Headers[i].Value = ""
		}
	}
	return h
}

// normalizePath tidies one path rule and clears what its action doesn't use.
func normalizePath(p PathRule) PathRule {
	p.Path, p.Upstream = strings.TrimSpace(p.Path), strings.TrimSpace(p.Upstream)
	p.RedirectTo, p.Root = strings.TrimSpace(p.RedirectTo), strings.TrimSpace(p.Root)
	p.Advanced = strings.TrimSpace(strings.ReplaceAll(p.Advanced, "\r\n", "\n"))
	p.Body = strings.ReplaceAll(p.Body, "\r\n", "\n")
	if p.Match == MatchPrefix {
		p.Match = ""
	}
	if p.Action == ActionProxy {
		p.Action = ""
	}
	if p.ActionOf() != ActionProxy {
		p.Upstream, p.WebSockets, p.StripPrefix = "", false, false
	}
	if p.MatchOf() != MatchPrefix {
		p.StripPrefix = false
	}
	if p.ActionOf() != ActionRedirect {
		p.RedirectTo, p.RedirectCode = "", 0
	} else if p.RedirectCode == 0 {
		p.RedirectCode = 302
	}
	if p.ActionOf() != ActionStatic {
		p.Root = ""
	}
	switch p.ActionOf() {
	case ActionDeny:
		p.Body = ""
		if p.Status == 0 {
			p.Status = 403
		}
	case ActionReturn:
		if p.Status == 0 {
			p.Status = 200
		}
	default:
		p.Status, p.Body = 0, ""
	}
	return p
}

// validateFeatures checks the newer options.
func validateFeatures(h HostConfig, add func(field, msg string, v any)) {
	a := h.Auth
	switch a.Mode {
	case "":
	case "basic":
		if strings.ContainsAny(a.Realm, "\"\\$\n\r;{}") || strings.EqualFold(a.Realm, "off") {
			add("auth.realm", `Quotes, \ $ ; { } aren't allowed, nor the word off.`, a.Realm)
		}
		if len(a.Users) == 0 {
			add("auth.users", "Add at least one person who may sign in.", nil)
		}
		seen := map[string]bool{}
		for i, u := range a.Users {
			f := fmt.Sprintf("auth.users[%d]", i)
			switch {
			case !userRe.MatchString(u.Name):
				add(f+".name", "Letters, digits and . _ @ - only, up to 64.", u.Name)
			case seen[u.Name]:
				add(f+".name", "This name is listed twice.", u.Name)
			}
			seen[u.Name] = true
			if strings.ContainsAny(u.Password, "\n\r") {
				add(f+".password", "Line breaks aren't allowed.", nil)
			}
		}
	case "forward":
		f := a.Forward
		if msg := checkURL(f.URL); msg != "" {
			add("auth.forward.url", msg, f.URL)
		}
		if f.SigninURL != "" {
			if msg := checkURL(f.SigninURL); msg != "" {
				add("auth.forward.signin_url", msg, f.SigninURL)
			} else if strings.Contains(f.SigninURL, "$") {
				add("auth.forward.signin_url", "$ isn't allowed.", f.SigninURL)
			}
		}
		for i, x := range f.Headers {
			if !headerRe.MatchString(x) {
				add(fmt.Sprintf("auth.forward.headers[%d]", i), "Letters, digits and - only.", x)
			}
		}
		if f.PassPath != "" && (!pathRe.MatchString(f.PassPath) || f.PassPath == "/") {
			add("auth.forward.pass_path", "Start with / and use letters, digits and . _ - / only (not / alone).", f.PassPath)
		} else if f.PassPath != "" {
			for _, p := range h.Paths {
				if p.MatchOf() == MatchPrefix && p.Path == f.PassPath {
					add("auth.forward.pass_path", "A path rule already uses "+f.PassPath+"; pick another or remove that rule.", f.PassPath)
					break
				}
			}
		}
	default:
		add("auth.mode", "Choose basic or forward.", a.Mode)
	}

	u := h.UpstreamTLS
	for _, x := range []struct{ field, v string }{
		{"upstream_tls.ca", u.CA}, {"upstream_tls.certificate", u.Certificate}, {"upstream_tls.key", u.Key},
	} {
		if x.v != "" && !safePath(x.v) {
			add(x.field, "Use the full path of a file on the server.", x.v)
		}
	}
	if (u.Certificate == "") != (u.Key == "") {
		add("upstream_tls.key", "A client certificate needs both the certificate and its key.", nil)
	}
	if u.Name != "" && !domainRe.MatchString(u.Name) {
		add("upstream_tls.name", "Not a host name.", u.Name)
	}

	for i, x := range h.Maintenance.Allow {
		if !validAddress(x) {
			add(fmt.Sprintf("maintenance.allow[%d]", i), "Not an address or range (like 10.0.0.0/8).", x)
		}
	}

	used := map[int]bool{}
	for i, p := range h.ErrorPages {
		f := fmt.Sprintf("error_pages[%d]", i)
		if len(p.Codes) == 0 {
			add(f+".codes", "Pick at least one status.", nil)
		}
		for _, c := range p.Codes {
			switch {
			case !slices.Contains(ErrorCodes, c):
				add(f+".codes", fmt.Sprintf("%d can't have its own page.", c), c)
			case used[c]:
				add(f+".codes", fmt.Sprintf("%d already has a page.", c), c)
			case c == 503 && h.Maintenance.Enabled:
				add(f+".codes", "Maintenance mode shows its own page for 503 while it's on.", c)
			}
			used[c] = true
		}
	}

	hd := h.Hardening
	if hd.On() && !slices.Contains([]int{403, 404, 444}, hd.Status) {
		add("hardening.status", "Use 403, 404 or 444.", hd.Status)
	}
	for _, m := range hd.Methods {
		if !slices.Contains(HardeningMethods, m) {
			add("hardening.methods", "Use "+strings.Join(HardeningMethods, ", ")+".", m)
			break
		}
	}
	if len(hd.Methods) > 0 && !slices.Contains(hd.Methods, "GET") {
		add("hardening.methods", "Keep GET, or no page opens.", nil)
	}

	if h.Type == TypeNotFound && !slices.Contains([]int{404, 410, 444}, h.NotFoundCode) {
		add("not_found_code", "Use 404, 410 or 444.", h.NotFoundCode)
	}
}

// validatePath checks one path rule.
func validatePath(h HostConfig, i int, p PathRule, add func(field, msg string, v any)) {
	f := fmt.Sprintf("paths[%d]", i)
	switch p.MatchOf() {
	case MatchPrefix:
		switch {
		case !pathRe.MatchString(p.Path):
			add(f+".path", "Start with / and use letters, digits and . _ - / only.", p.Path)
		case p.Path == "/":
			add(f+".path", "/ is the whole site: change what the site does instead.", p.Path)
		}
	case MatchExact:
		if !pathRe.MatchString(p.Path) {
			add(f+".path", "Start with / and use letters, digits and . _ - / only.", p.Path)
		}
	case MatchRegex:
		if msg := checkRegex(p.Path); msg != "" {
			add(f+".path", msg, p.Path)
		}
	default:
		add(f+".match", "Choose prefix, exact or regex.", p.Match)
	}
	if p.MatchOf() != MatchRegex && strings.HasPrefix(p.Path+"/", "/__morcheh/") {
		add(f+".path", "Paths under /__morcheh/ are kept for the pages Morcheh answers itself.", p.Path)
	}
	switch p.ActionOf() {
	case ActionProxy:
		up := p.Upstream
		if up == "" {
			if h.Type != TypeProxy {
				add(f+".upstream", "Say where requests go, like http://127.0.0.1:3000.", up)
				break
			}
			up = h.Upstream
		} else if msg := checkUpstream(up); msg != "" {
			add(f+".upstream", msg, up)
			break
		}
		if p.MatchOf() == MatchRegex && hasURIPart(up) {
			add(f+".upstream", "A regex path can't send to an address with a path; leave the path out (http://host:port).", up)
		}
	case ActionRedirect:
		if strings.HasPrefix(p.RedirectTo, "/") {
			if !pathRe.MatchString(p.RedirectTo) {
				add(f+".redirect_to", "Use a path like /new or a full address.", p.RedirectTo)
			}
		} else if msg := checkURL(p.RedirectTo); msg != "" {
			add(f+".redirect_to", msg, p.RedirectTo)
		}
		if !slices.Contains([]int{301, 302, 307, 308}, p.RedirectCode) {
			add(f+".redirect_code", "Use 301, 302, 307 or 308.", p.RedirectCode)
		}
	case ActionStatic:
		if !safePath(p.Root) {
			add(f+".root", "Use a full folder path, like /var/www/files.", p.Root)
		}
	case ActionDeny:
		if !slices.Contains([]int{403, 404, 410, 444}, p.Status) {
			add(f+".status", "Use 403, 404, 410 or 444.", p.Status)
		}
	case ActionReturn:
		if p.Status < 200 || p.Status > 599 {
			add(f+".status", "Use a status from 200 to 599.", p.Status)
		}
		if strings.Contains(p.Body, "$") {
			add(f+".body", "$ isn't allowed.", nil)
		}
	default:
		add(f+".action", "Choose proxy, redirect, static, deny or return.", p.Action)
	}
	if msg := checkAdvanced(p.Advanced); msg != "" {
		add(f+".advanced", msg, nil)
	}
}

// checkRegex accepts a regex nginx can take in quotes as written.
func checkRegex(s string) string {
	if s == "" {
		return "Enter a pattern, like \\.php$."
	}
	if strings.ContainsAny(s, "\" \t\n\r") {
		return "Quotes and spaces aren't allowed."
	}
	if nginxEscRe.MatchString(s) || strings.HasSuffix(s, `\`) {
		return `\\ \" \' \n \t \r and a final \ aren't allowed.`
	}
	if _, err := regexp.Compile(s); err != nil {
		return "Not a valid pattern: " + strings.TrimPrefix(err.Error(), "error parsing regexp: ")
	}
	return ""
}

// hasURIPart says whether an address carries a path (anything after host:port).
func hasURIPart(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Path != ""
}

// Origin is an address without its path: scheme://host[:port].
func Origin(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	return u.Scheme + "://" + u.Host
}
