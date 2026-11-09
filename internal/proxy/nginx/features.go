package nginx

import (
	"fmt"
	"html"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/morcheh/backend/internal/proxy"
)

// Sign-in, maintenance and error pages, hardening, and the extra path
// actions. Pages Morcheh answers itself live under internalPrefix, inside
// locations marked internal, so a visitor can't open them directly.

const (
	// AuthDir holds one password file per host using basic sign-in.
	AuthDir        = Dir + "/auth"
	internalPrefix = "/__morcheh/"
	authLocation   = internalPrefix + "auth"
	maintPage      = internalPrefix + "maintenance.html"
	// defaultCABundle is used when the server didn't say where its CA file is.
	defaultCABundle = "/etc/ssl/certs/ca-certificates.crt"
)

// AuthFile is a host's password file.
func AuthFile(id string) string { return AuthDir + "/" + id + ".htpasswd" }

func errorPage(i int) string { return fmt.Sprintf("%serror-%d.html", internalPrefix, i) }

// hasPages says whether the site answers any page of its own.
func hasPages(h proxy.HostConfig) bool {
	return h.Maintenance.Enabled || len(h.ErrorPages) > 0 || h.Auth.Mode == "forward"
}

// openUp lets a location past the site's sign-in.
func openUp(w *writer, h proxy.HostConfig) {
	switch h.Auth.Mode {
	case "basic":
		w.line("auth_basic off;")
	case "forward":
		w.line("auth_request off;")
	}
}

// featureBlocks are the http-level lines: who skips the sign-in, who sees
// the site in maintenance, what hardening refuses.
func featureBlocks(w *writer, t string, h proxy.HostConfig) {
	a := h.Auth
	if a.SkipForAllowed && len(h.Allow) > 0 {
		w.line("")
		switch a.Mode {
		case "basic":
			w.line("# Addresses let in without signing in.")
			w.open("geo $%s_realm", t)
			w.line(`default "%s";`, realm(a))
			for _, x := range h.Allow {
				w.line("%s off;", x)
			}
			w.close()
		case "forward":
			w.line("# Addresses let in without signing in.")
			w.open("geo $%s_noauth", t)
			w.line("default 0;")
			for _, x := range h.Allow {
				w.line("%s 1;", x)
			}
			w.close()
		}
	}

	if m := h.Maintenance; m.Enabled {
		w.line("")
		w.line("# Maintenance: everyone but these addresses gets the 503 page.")
		w.open("geo $%s_maint_ip", t)
		w.line("default 1;")
		for _, x := range m.Allow {
			w.line("%s 0;", x)
		}
		w.close()
		w.open(`map "$%s_maint_ip:$uri" $%s_maint`, t, t)
		w.line("volatile;")
		w.line("default 0;")
		w.line(`"~^1:%s" 0;`, regexp.QuoteMeta(internalPrefix))
		w.line(`"~^1:/\.well-known/acme-challenge/" 0;`)
		w.line(`"~^1:" 1;`)
		w.close()
	}

	hd := h.Hardening
	if !hd.On() {
		return
	}
	w.line("")
	w.line("# Hardening: requests no real visitor makes.")
	w.open("map $uri $%s_h_uri", t)
	w.line("volatile;")
	w.line("default 0;")
	w.line(`"~^%s" x;`, regexp.QuoteMeta(internalPrefix))
	w.line(`"~^/\.well-known/" 0;`)
	if hd.Dotfiles {
		w.line(`"~/\." 1;`)
	}
	if hd.Backups {
		w.line(`"~*(\.(bak|old|orig|save|swp|swo|sql|sqlite|sqlite3|dump)|~)$" 1;`)
	}
	if hd.Probes {
		w.line(`"~*^/(phpmyadmin|pma|myadmin|mysqladmin|adminer|dbadmin)(/|$|\.php)" 1;`)
		w.line(`"~*^/cgi-bin/" 1;`)
		w.line(`"~*/vendor/phpunit/" 1;`)
		w.line(`"~*^/(boaform|hnap1|goform|setup\.cgi)" 1;`)
		w.line(`"~*(/etc/passwd|win\.ini)" 1;`)
	}
	w.close()
	if hd.Scanners || hd.AICrawlers {
		w.open("map $http_user_agent $%s_h_ua", t)
		w.line("default 0;")
		if hd.Scanners {
			w.line(`"~*(sqlmap|nikto|nmap|masscan|zgrab|nuclei|acunetix|wpscan|dirbuster|gobuster|feroxbuster|ffuf|whatweb|jaeles|netsparker|openvas)" 1;`)
		}
		if hd.AICrawlers {
			w.line(`"~*(GPTBot|ChatGPT-User|OAI-SearchBot|CCBot|ClaudeBot|Claude-Web|anthropic-ai|PerplexityBot|Bytespider|Amazonbot|meta-externalagent|cohere-ai|Diffbot|ImagesiftBot|Omgilibot|YouBot)" 1;`)
		}
		w.close()
		w.open(`map "$%s_h_uri$%s_h_ua" $%s_harden`, t, t, t)
		w.line("volatile;")
	} else {
		w.open(`map $%s_h_uri $%s_harden`, t, t)
		w.line("volatile;")
	}
	w.line("default 0;")
	w.line(`"~^x" 0;`)
	w.line(`"~1" 1;`)
	w.close()
	if len(hd.Methods) > 0 {
		w.open("map $request_method $%s_h_method", t)
		w.line("volatile;")
		w.line("default 1;")
		for _, m := range methodsWithHead(hd.Methods) {
			w.line("%s 0;", m)
		}
		w.close()
	}
}

// methodsWithHead adds HEAD to a list with GET: nginx answers both alike.
func methodsWithHead(ms []string) []string {
	if slices.Contains(ms, "GET") && !slices.Contains(ms, "HEAD") {
		return append(slices.Clone(ms), "HEAD")
	}
	return ms
}

func realm(a proxy.Auth) string {
	if a.Realm == "" {
		return "Restricted"
	}
	return a.Realm
}

// serverFeatures are the server-level lines.
func serverFeatures(w *writer, id, t string, h proxy.HostConfig, env proxy.Env) {
	hd := h.Hardening
	if len(hd.Methods) > 0 {
		w.line("")
		w.open("if ($%s_h_method)", t)
		w.line("return 405;")
		w.close()
	}
	if hd.On() && (hd.Dotfiles || hd.Backups || hd.Probes || hd.Scanners || hd.AICrawlers) {
		w.line("")
		w.open("if ($%s_harden)", t)
		w.line("return %d;", hd.Status)
		w.close()
	}
	if h.Maintenance.Enabled {
		w.line("")
		w.line("error_page 503 %s;", maintPage)
		w.open("if ($%s_maint)", t)
		w.line("return 503;")
		w.close()
	}
	if len(h.ErrorPages) > 0 {
		w.line("")
		for i, p := range h.ErrorPages {
			codes := make([]string, len(p.Codes))
			for j, c := range p.Codes {
				codes[j] = strconv.Itoa(c)
			}
			w.line("error_page %s %s;", strings.Join(codes, " "), errorPage(i))
		}
	}

	a := h.Auth
	switch a.Mode {
	case "basic":
		w.line("")
		if a.SkipForAllowed && len(h.Allow) > 0 {
			w.line("auth_basic $%s_realm;", t)
		} else {
			w.line(`auth_basic "%s";`, realm(a))
		}
		w.line("auth_basic_user_file %s;", AuthFile(id))
	case "forward":
		w.line("")
		w.line("auth_request %s;", authLocation)
		for i, x := range a.Forward.Headers {
			w.line("auth_request_set $%s_auth_%d $upstream_http_%s;", t, i, headerVar(x))
		}
		if s := a.Forward.SigninURL; s != "" {
			sep := "?"
			if strings.Contains(s, "?") {
				sep = "&"
			}
			w.line("error_page 401 =302 %s%srd=$scheme://$http_host$request_uri;", s, sep)
		}
	}

	if h.RequestID {
		w.line("")
		w.line("add_header X-Request-ID $request_id always;")
	}
	if h.Brotli {
		w.line("")
		if env.Brotli {
			w.line("brotli on;")
			w.line("brotli_comp_level 5;")
			w.line("brotli_min_length 1024;")
			w.line("brotli_types %s;", strings.Join(gzipTypes, " "))
		} else {
			w.line("# Brotli is on in the panel, but this nginx has no brotli module.")
		}
	}
}

// headerVar is how nginx names a header in $upstream_http_*.
func headerVar(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "-", "_")
}

// internalLocations are the pages and checks the site answers itself.
func internalLocations(w *writer, t string, h proxy.HostConfig) {
	if !hasPages(h) {
		return
	}
	w.line("")
	w.open("location ^~ %s", internalPrefix)
	w.line("internal;")
	w.close()

	if m := h.Maintenance; m.Enabled {
		title := m.Title
		if title == "" {
			title = "We'll be back soon"
		}
		msg := m.Message
		if msg == "" {
			msg = "This site is down for maintenance. Please try again in a little while."
		}
		w.line("")
		w.open("location = %s", maintPage)
		pageLines(w, h)
		if m.RetryMinutes > 0 {
			w.line("add_header Retry-After %d always;", m.RetryMinutes*60)
		}
		w.line(`add_header Cache-Control "no-store" always;`)
		serverHeaders(w, h)
		w.line(`return 200 "%s";`, pageHTML(title, msg))
		w.close()
	}
	for i, p := range h.ErrorPages {
		title := p.Title
		if title == "" {
			title = defaultTitle(p.Codes)
		}
		w.line("")
		w.open("location = %s", errorPage(i))
		pageLines(w, h)
		w.line(`return 200 "%s";`, pageHTML(title, p.Message))
		w.close()
	}

	f := h.Auth.Forward
	if h.Auth.Mode != "forward" {
		return
	}
	w.line("")
	w.open("location = %s", authLocation)
	w.line("internal;")
	if h.Auth.SkipForAllowed && len(h.Allow) > 0 {
		w.open("if ($%s_noauth)", t)
		w.line("return 204;")
		w.close()
	}
	w.line("proxy_pass %s;", f.URL)
	w.line("proxy_pass_request_body off;")
	w.line(`proxy_set_header Content-Length "";`)
	w.line("proxy_set_header X-Original-URL $scheme://$http_host$request_uri;")
	w.line("proxy_set_header X-Original-Method $request_method;")
	w.line("proxy_set_header X-Forwarded-Method $request_method;")
	w.line("proxy_set_header X-Forwarded-Proto $scheme;")
	w.line("proxy_set_header X-Forwarded-Host $http_host;")
	w.line("proxy_set_header X-Forwarded-Uri $request_uri;")
	w.line("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
	w.line("proxy_set_header X-Real-IP $remote_addr;")
	if strings.HasPrefix(f.URL, "https://") {
		w.line("proxy_ssl_server_name on;")
	}
	w.close()
	if f.PassPath != "" {
		w.line("")
		w.open("location ^~ %s", f.PassPath)
		w.line("auth_request off;")
		w.line("proxy_pass %s;", proxy.Origin(f.URL))
		w.line("proxy_http_version 1.1;")
		w.line("proxy_set_header Host $host;")
		w.line("proxy_set_header X-Real-IP $remote_addr;")
		w.line("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
		w.line("proxy_set_header X-Forwarded-Proto $scheme;")
		w.line("proxy_set_header X-Forwarded-Host $host;")
		w.line("proxy_set_header X-Forwarded-Uri $request_uri;")
		if strings.HasPrefix(f.URL, "https://") {
			w.line("proxy_ssl_server_name on;")
		}
		w.close()
	}
}

// pageLines open a page to everyone who got the error, signed in or not.
func pageLines(w *writer, h proxy.HostConfig) {
	w.line("internal;")
	w.line("allow all;")
	openUp(w, h)
	w.line(`default_type "text/html; charset=utf-8";`)
}

var statusTitles = map[int]string{
	400: "Bad request", 403: "Access denied", 404: "Page not found",
	405: "Not allowed", 408: "Request timed out", 413: "That's too large",
	429: "Too many requests", 500: "Something went wrong", 502: "Service unavailable",
	503: "Service unavailable", 504: "Service unavailable",
}

func defaultTitle(codes []int) string {
	if len(codes) == 0 {
		return "Something went wrong"
	}
	return statusTitles[codes[0]]
}

// pageHTML is a small page, written as an nginx string: no $ (a variable),
// " or \ survive as text, and it stays on one line.
func pageHTML(title, message string) string {
	esc := func(s string) string {
		s = html.EscapeString(s)
		s = strings.NewReplacer("$", "&#36;", `\`, "&#92;", "\n", "<br>").Replace(s)
		return s
	}
	body := "<h1>" + esc(title) + "</h1>"
	if message != "" {
		body += "<p>" + esc(message) + "</p>"
	}
	return `<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>` + esc(title) +
		`</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.6 system-ui,-apple-system,Segoe UI,sans-serif;background:#fff;color:#1c2024}main{max-width:32rem;padding:2rem;text-align:center}h1{font-weight:300;font-size:2rem;margin:0 0 .75rem}p{margin:0;color:#60646c}@media (prefers-color-scheme:dark){body{background:#111113;color:#edeef0}p{color:#b0b4ba}}</style></head><body><main>` +
		body + `</main></body></html>`
}

// upstreamTLSLines go with a proxy_pass to an https address.
func upstreamTLSLines(w *writer, h proxy.HostConfig, env proxy.Env) {
	w.line("proxy_ssl_server_name on;")
	u := h.UpstreamTLS
	if u.Name != "" {
		w.line("proxy_ssl_name %s;", u.Name)
	}
	if u.Verify {
		ca := u.CA
		if ca == "" {
			ca = env.CABundle
		}
		if ca == "" {
			ca = defaultCABundle
		}
		w.line("proxy_ssl_verify on;")
		w.line("proxy_ssl_verify_depth 4;")
		w.line("proxy_ssl_trusted_certificate %s;", ca)
	}
	if u.Certificate != "" {
		w.line("proxy_ssl_certificate %s;", u.Certificate)
		w.line("proxy_ssl_certificate_key %s;", u.Key)
	}
}

// locationOf is a path rule's location line.
func locationOf(p proxy.PathRule) string {
	switch p.MatchOf() {
	case proxy.MatchExact:
		return "= " + p.Path
	case proxy.MatchRegex:
		return `~ "` + p.Path + `"`
	}
	return p.Path
}

// pathBody writes what a path rule does inside its location.
func pathBody(w *writer, t string, h proxy.HostConfig, env proxy.Env, p proxy.PathRule) {
	switch p.ActionOf() {
	case proxy.ActionRedirect:
		w.line("return %d %s;", p.RedirectCode, p.RedirectTo)
	case proxy.ActionDeny:
		w.line("return %d;", p.Status)
	case proxy.ActionReturn:
		w.line("default_type text/plain;")
		body := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(p.Body)
		w.line(`return %d "%s";`, p.Status, body)
	case proxy.ActionStatic:
		switch p.MatchOf() {
		case proxy.MatchRegex:
			w.line("root %s;", strings.TrimRight(p.Root, "/"))
		case proxy.MatchExact:
			w.line("alias %s;", strings.TrimRight(p.Root, "/"))
		default:
			alias := strings.TrimRight(p.Root, "/")
			if strings.HasSuffix(p.Path, "/") {
				alias += "/"
			}
			w.line("alias %s;", alias)
			w.line("index index.html index.htm;")
		}
	default:
		up := p.Upstream
		if up == "" {
			up = h.Upstream
		}
		if p.StripPrefix {
			base := ""
			if u, err := url.Parse(up); err == nil {
				base = strings.TrimRight(u.EscapedPath(), "/")
			}
			prefix := regexp.QuoteMeta(strings.TrimRight(p.Path, "/"))
			w.line(`rewrite "^%s/?(.*)$" "%s/$1" break;`, prefix, base)
			up = proxy.Origin(up)
		}
		proxyPass(w, t, h, env, up, p.WebSockets)
	}
}

// htpasswd is a host's password file: one "name:hash" line per person.
func htpasswd(a proxy.Auth) string {
	var b strings.Builder
	for _, u := range a.Users {
		if u.Hash != "" {
			b.WriteString(u.Name + ":" + u.Hash + "\n")
		}
	}
	return b.String()
}

// authOwner lets nginx's workers read the password files and nobody else:
// the group of the user nginx.conf names, else the usual web user.
const authOwner = `if ls "$n/auth"/*.htpasswd >/dev/null 2>&1; then
  wu=$(nginx -T 2>/dev/null | sed -n 's/^[[:space:]]*user[[:space:]][[:space:]]*\([^[:space:];]*\).*/\1/p' | head -n 1)
  [ -n "$wu" ] || for x in www-data nginx http nobody; do id "$x" >/dev/null 2>&1 && { wu=$x; break; }; done
  wg=$(id -gn "$wu" 2>/dev/null)
  if [ -n "$wg" ] && chgrp "$wg" "$n/auth"/*.htpasswd 2>/dev/null; then chmod 640 "$n/auth"/*.htpasswd; else chmod 644 "$n/auth"/*.htpasswd; fi
fi
`

// serverHeaders repeats the server's add_header lines in a location with
// its own: nginx drops the inherited ones there.
func serverHeaders(w *writer, h proxy.HostConfig) {
	if h.TLS.Enabled && h.TLS.HTTP3 {
		w.line(`add_header Alt-Svc 'h3=":443"; ma=86400' always;`)
	}
	if h.TLS.Enabled && h.TLS.HSTS {
		w.line(`add_header Strict-Transport-Security "%s" always;`, h.TLS.HSTSValue())
	}
	for _, x := range h.Headers {
		if x.To == "response" {
			w.line(`add_header %s "%s" always;`, x.Name, x.Value)
		}
	}
	if h.RequestID {
		w.line("add_header X-Request-ID $request_id always;")
	}
}
