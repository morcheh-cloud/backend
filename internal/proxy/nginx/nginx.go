// Package nginx is the nginx driver: it renders hosts into server blocks in
// /etc/nginx/morcheh/hosts, wired in with one include in conf.d (http.d on
// Alpine), and reads the live config back with nginx -T. Port forwards
// (streams) go to /etc/nginx/morcheh/streams, inside a stream block in
// /etc/nginx/morcheh/stream.conf that is included from nginx's main context.
package nginx

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/morcheh/backend/internal/proxy"
)

const (
	// Dir holds everything Morcheh writes; HostsDir one file per host.
	Dir      = "/etc/nginx/morcheh"
	HostsDir = Dir + "/hosts"
	// StreamsDir holds one file per port forward; StreamConf is the stream
	// block that loads them.
	StreamsDir = Dir + "/streams"
	StreamConf = Dir + "/stream.conf"
	// ReleasedDir keeps, per hand-written file Morcheh took default_server
	// from, its path (.path), the file before (.orig) and after (.now).
	ReleasedDir = Dir + "/released"
	// streamHook is the main-context include put where nginx loads modules
	// (Debian, Ubuntu), else appended to nginx.conf.
	streamHook     = "/etc/nginx/modules-enabled/zz-morcheh-stream.conf"
	streamHookLine = "include " + StreamConf + "; " + marker
	// IncludeName is the file put in conf.d (or http.d) to load the hosts.
	IncludeName = "morcheh.conf"
	logDir      = "/var/log/nginx"
	marker      = "# Managed by Morcheh"
)

// AccessFormat is the sites' log format: nginx's combined one with the
// domain, times, upstream and cache after it, so readers of combined lines
// (the traffic counter) read both, and older lines still parse.
const (
	AccessFormat     = "morcheh_access"
	accessFormatText = `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$host" $request_time "$upstream_response_time" "$upstream_cache_status" "$upstream_status" "$upstream_addr" $request_length "$request_id"`
)

// Include is the whole include file. The map lets WebSocket hosts close
// plain connections properly.
const Include = marker + `: sites added in the panel live in ` + HostsDir + `.
# Changes made here are overwritten.
log_format ` + AccessFormat + ` '` + accessFormatText + `';
map $http_upgrade $morcheh_connection {
    default upgrade;
    ''      close;
}
include ` + GeoDir + `/*.conf;
include ` + HostsDir + `/*.conf;
`

// StreamBlock is the whole stream.conf. Its log format keeps the fields of
// nginx's combined one, so the traffic counter reads both the same way.
const StreamBlock = marker + `: ports forwarded in the panel live in ` + StreamsDir + `.
# Changes made here are overwritten.
stream {
    log_format morcheh_stream '$remote_addr - - [$time_local] "$protocol" $status $bytes_sent "-" "-"';
    include ` + GeoDir + `/*.stream;
    include ` + StreamsDir + `/*.conf;
}
`

func init() { proxy.Register(Driver{}) }

// Driver is the nginx kind.
type Driver struct{}

func (Driver) Kind() string  { return "nginx" }
func (Driver) Label() string { return "nginx" }

func (Driver) Capabilities() proxy.Capabilities {
	return proxy.Capabilities{
		Types: []string{
			proxy.TypeProxy, proxy.TypeRedirect, proxy.TypeStatic,
			proxy.TypeNotFound, proxy.TypeStream, proxy.TypeStorage,
		},
		WebSockets: true, Headers: true, Paths: true, Allow: true, Advanced: true,
		Tuning: true, Cache: true,
		Auth: true, Pages: true, Hardening: true, UpstreamTLS: true, PathActions: true,
		Balancing: true, Mirror: true, Redirects: true,
		Countries: true, RateLimit: true,
		Streams: true, Traffic: true, Certificates: true, TLSOptions: true,
		Language: "nginx", ConfigLabel: "nginx config",
	}
}

func (Driver) Validate(proxy.HostConfig) []proxy.Problem { return nil }

// AccessLog and ErrorLog are a host's own logs.
func AccessLog(id string) string { return logDir + "/morcheh-" + id + ".access.log" }
func ErrorLog(id string) string  { return logDir + "/morcheh-" + id + ".error.log" }

// ---- Rendering ----

type writer struct {
	b     strings.Builder
	depth int
}

func (w *writer) line(format string, args ...any) {
	if format == "" {
		w.b.WriteString("\n")
		return
	}
	w.b.WriteString(strings.Repeat("    ", w.depth))
	fmt.Fprintf(&w.b, format, args...)
	w.b.WriteString("\n")
}

func (w *writer) open(format string, args ...any) {
	w.line(format+" {", args...)
	w.depth++
}

func (w *writer) close() {
	w.depth--
	w.line("}")
}

// raw writes typed directives, indented to the current block.
func (w *writer) raw(text string) {
	for _, l := range strings.Split(text, "\n") {
		if strings.TrimSpace(l) == "" {
			w.line("")
			continue
		}
		w.line("%s", strings.TrimRight(l, " \t"))
	}
}

func (d Driver) Render(id string, h proxy.HostConfig, env proxy.Env) string {
	if h.IsStream() {
		return renderStream(id, h, env)
	}
	w := &writer{}
	w.line("%s: edit this site in the panel; changes made here are overwritten.", marker)
	w.line("# Host %s", id)
	t := tag(id)
	lim := newLimits(t, h)
	accessBlocks(w, t, h)
	w.b.WriteString(lim.blocks.b.String())
	cacheBlocks(w, id, t, h)
	featureBlocks(w, t, h)
	imageBlocks(w, t, h)
	upstreamBlock(w, t, h)
	mirrorBlocks(w, t, h)
	redirectBlocks(w, t, h)
	names := strings.Join(h.Domains, " ")
	def := ""
	if h.CatchAll {
		names = strings.TrimSpace("_ " + names)
		def = " default_server"
	}
	ipv6 := env.IPv6
	newHTTP2 := atLeast(env.Version, 1, 25, 1)

	logs := func() {
		w.line("access_log %s %s;", AccessLog(id), AccessFormat)
		w.line("error_log %s;", ErrorLog(id))
	}

	if h.TLS.Enabled && h.TLS.ForceHTTPS {
		w.line("")
		w.open("server")
		w.line("listen 80%s;", def)
		if ipv6 {
			w.line("listen [::]:80%s;", def)
		}
		w.line("server_name %s;", names)
		logs()
		acmeLocation(w, proxy.HostConfig{})
		redirectServer(w, t, h, true)
		code := h.TLS.ForceCode
		if code == 0 {
			code = 301
		}
		w.line("")
		w.open("location /")
		w.line("return %d https://$host$request_uri;", code)
		w.close()
		w.close()
	}

	w.line("")
	w.open("server")
	if !h.TLS.Enabled || !h.TLS.ForceHTTPS {
		w.line("listen 80%s;", def)
		if ipv6 {
			w.line("listen [::]:80%s;", def)
		}
	}
	// A catch-all without a certificate refuses https for unknown names
	// instead of showing another site's certificate.
	reject := h.CatchAll && !h.TLS.Enabled && atLeast(env.Version, 1, 19, 4)
	if reject {
		w.line("listen 443 ssl default_server;")
		if ipv6 {
			w.line("listen [::]:443 ssl default_server;")
		}
		w.line("ssl_reject_handshake on;")
	}
	if h.TLS.Enabled {
		suffix := ""
		if h.TLS.HTTP2 && !newHTTP2 {
			suffix = " http2"
		}
		w.line("listen 443 ssl%s%s;", def, suffix)
		if ipv6 {
			w.line("listen [::]:443 ssl%s%s;", def, suffix)
		}
		if h.TLS.HTTP3 {
			reuse := ""
			if env.QUICReuseport {
				reuse = " reuseport"
			}
			w.line("listen 443 quic%s;", reuse)
			if ipv6 {
				w.line("listen [::]:443 quic%s;", reuse)
			}
		}
		if h.TLS.HTTP2 && newHTTP2 {
			w.line("http2 on;")
		}
	}
	w.line("server_name %s;", names)
	logs()
	if h.TLS.Enabled {
		tlsLines(w, h.TLS)
	}

	access(w, t, h)
	wafServer(w, id, h)
	lim.server(w, env)
	serverTuning(w, h)
	serverCache(w, t, h)
	if h.MaxBodyMB > 0 || hasHeaders(h, "response") {
		w.line("")
	}
	if h.MaxBodyMB > 0 {
		w.line("client_max_body_size %dm;", h.MaxBodyMB)
	}
	for _, x := range h.Headers {
		if x.To == "response" {
			w.line(`add_header %s "%s" always;`, x.Name, x.Value)
		}
	}
	redirectServer(w, t, h, false)
	serverFeatures(w, id, t, h, env)
	mirrorServer(w, h)

	if !h.TLS.Enabled || !h.TLS.ForceHTTPS {
		acmeLocation(w, h)
	}
	// Returns sit in location / so the certificate check above still answers.
	switch h.Type {
	case proxy.TypeNotFound:
		w.line("")
		code := h.NotFoundCode
		if code == 0 {
			code = 404
		}
		w.open("location /")
		w.line("return %d;", code)
		w.close()
	case proxy.TypeRedirect:
		w.line("")
		target := h.RedirectTo
		if h.KeepPath {
			target = strings.TrimRight(target, "/") + "$request_uri"
		}
		w.open("location /")
		w.line("return %d %s;", h.RedirectCode, target)
		w.close()
	case proxy.TypeStatic:
		w.line("")
		w.line("root %s;", h.Root)
		w.line("index index.html index.htm;")
		files := func() {
			if h.SPA {
				w.line("try_files $uri $uri/ /index.html;")
			} else {
				w.line("try_files $uri $uri/ =404;")
			}
		}
		paths(w, id, h, env, lim, files)
		w.line("")
		w.open("location /")
		imageRoute(w, t, h)
		files()
		w.close()
		imageServe(w, t, h, func() { w.line("try_files $uri =404;") })
	case proxy.TypeStorage:
		storageSite(w, id, t, h, env, lim)
	default:
		slow := slowWait(h)
		main := func(slow int) {
			proxyPass(w, t, h, env, h.Upstream, h.WebSockets, slow)
			cacheRules(w, t, h, slow)
		}
		paths(w, id, h, env, lim, func() { main(0) })
		w.line("")
		w.open("location /")
		imageRoute(w, t, h)
		if slow > 0 {
			slowRoute(w, t, h)
		}
		main(slow)
		w.close()
		if slow > 0 {
			slowPass(w, t, h, env)
		}
		imageServe(w, t, h, func() {
			proxyPass(w, t, h, env, h.Upstream, false, 0)
		})
	}
	internalLocations(w, t, h)
	mirrorLocations(w, t, h)

	if h.Advanced != "" {
		w.line("")
		w.line("# Advanced")
		w.raw(h.Advanced)
	}
	w.close()
	return w.b.String()
}

// renderStream is a port forward: a server block inside stream {}.
func renderStream(id string, h proxy.HostConfig, env proxy.Env) string {
	w := &writer{}
	w.line("%s: edit this forward in the panel; changes made here are overwritten.", marker)
	w.line("# Stream %s", id)
	t := tag(id)
	lim := newLimits(t, h)
	w.b.WriteString(lim.blocks.b.String())
	upstreamBlock(w, t, h)
	streamCountries(w, t, h)
	w.line("")
	w.open("server")
	udp := ""
	if h.Protocol == "udp" {
		udp = " udp"
	}
	w.line("listen %d%s;", h.ListenPort, udp)
	if env.IPv6 {
		w.line("listen [::]:%d%s;", h.ListenPort, udp)
	}
	w.line("access_log %s morcheh_stream;", AccessLog(id))
	w.line("error_log %s;", ErrorLog(id))
	if len(h.Countries) == 0 {
		access(w, t, h)
	}
	lim.server(w, env)
	w.line("")
	if len(h.Countries) > 0 {
		w.line("proxy_pass $%s_to;", t)
		if h.Balance.On() {
			retryLines(w, h.Balance, true)
		}
	} else if h.Balance.On() {
		w.line("proxy_pass %s;", poolName(t))
		retryLines(w, h.Balance, true)
	} else {
		w.line("proxy_pass %s;", h.StreamTo)
	}
	if h.TimeoutSeconds > 0 {
		w.line("proxy_timeout %ds;", h.TimeoutSeconds)
	}
	streamTuning(w, h)
	if h.Advanced != "" {
		w.line("")
		w.line("# Advanced")
		w.raw(h.Advanced)
	}
	w.close()
	return w.b.String()
}

func hasHeaders(h proxy.HostConfig, to string) bool {
	for _, x := range h.Headers {
		if x.To == to {
			return true
		}
	}
	return false
}

// paths writes the Paths locations, then a location for each path a rate
// limit names that no Paths entry serves, doing what the site does (main).
func paths(w *writer, id string, h proxy.HostConfig, env proxy.Env, lim *limits, main func()) {
	for _, p := range h.Paths {
		w.line("")
		w.open("location %s", locationOf(p))
		pathAccess(w, p)
		if p.Public {
			openUp(w, h)
		}
		if p.Login {
			authLines(w, id, lim.t, h, true)
		}
		pathBody(w, lim.t, h, env, p)
		if p.MatchOf() != proxy.MatchRegex {
			lim.location(w, p.Path)
		}
		if p.Advanced != "" {
			w.raw(p.Advanced)
		}
		w.close()
	}
	for _, p := range lim.extraPaths(h) {
		w.line("")
		w.open("location %s", p)
		main()
		lim.location(w, p)
		w.close()
	}
}

// slow > 0 = Always online's wait for a page to start coming back (the
// location also carries slowRoute, so only pages get it).
func proxyPass(w *writer, t string, h proxy.HostConfig, env proxy.Env, upstream string, ws bool, slow int) {
	upstream, pool := pooled(t, h, upstream)
	if h.Cache.Online.Mode == "copies" {
		upstream, pool = offlineUpstream, false
	}
	w.line("proxy_pass %s;", upstream)
	w.line("proxy_http_version 1.1;")
	switch {
	case h.PreserveHost:
		w.line("proxy_set_header Host $host;")
	case pool:
		// Else nginx would send the pool's name.
		w.line("proxy_set_header Host %s;", mainHost(h))
	}
	w.line("proxy_set_header X-Real-IP $remote_addr;")
	w.line("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
	w.line("proxy_set_header X-Forwarded-Proto $scheme;")
	w.line("proxy_set_header X-Forwarded-Host $host;")
	if ws {
		w.line("proxy_set_header Upgrade $http_upgrade;")
		w.line("proxy_set_header Connection $morcheh_connection;")
	} else {
		w.line(`proxy_set_header Connection "";`)
	}
	if h.RequestID {
		w.line("proxy_set_header X-Request-ID $request_id;")
	}
	if h.Auth.Mode == "forward" {
		for i, x := range h.Auth.Forward.Headers {
			w.line("proxy_set_header %s $%s_auth_%d;", x, t, i)
		}
	}
	for _, x := range h.Headers {
		switch x.To {
		case "request":
			w.line(`proxy_set_header %s "%s";`, x.Name, x.Value)
		case "hide":
			w.line("proxy_hide_header %s;", x.Name)
		}
	}
	if h.InterceptErrors {
		w.line("proxy_intercept_errors on;")
	}
	if u, err := url.Parse(upstream); err == nil && u.Scheme == "https" {
		upstreamTLSLines(w, h, env, pool)
	}
	if pool {
		retryLines(w, h.Balance, false)
	}
	switch {
	case slow > 0:
		w.line("proxy_read_timeout %ds;", slow)
		if h.TimeoutSeconds > 0 {
			w.line("proxy_send_timeout %ds;", h.TimeoutSeconds)
		}
	case h.TimeoutSeconds > 0:
		w.line("proxy_read_timeout %ds;", h.TimeoutSeconds)
		w.line("proxy_send_timeout %ds;", h.TimeoutSeconds)
	case ws:
		w.line("proxy_read_timeout 1h;")
		w.line("proxy_send_timeout 1h;")
	}
	upstreamTuning(w, h)
	proxyCache(w, t, h)
}

// atLeast compares a dotted version with major.minor.patch; unknown = no.
func atLeast(v string, want ...int) bool {
	parts := strings.Split(v, ".")
	for i, w := range want {
		if i >= len(parts) {
			return false
		}
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return false
		}
		if n != w {
			return n > w
		}
	}
	return true
}

// ---- Scripts ----

// head finds nginx even through sudo's secure_path quirks, and picks the
// folder the stock nginx.conf includes inside http. running only counts a
// master in its own PID namespace, so nginx in a container doesn't pass for
// the server's (and the other way round).
const head = `PATH=$PATH:/usr/sbin:/sbin:/usr/local/sbin:/usr/local/nginx/sbin
if [ -d /etc/nginx/http.d ]; then inc=/etc/nginx/http.d; else inc=/etc/nginx/conf.d; fi
running() {
  me=$(readlink /proc/self/ns/pid 2>/dev/null)
  for p in /proc/[0-9]*; do
    case "$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)" in
    "nginx: master"*) [ "$(readlink "$p/ns/pid" 2>/dev/null)" = "$me" ] && return 0 ;;
    esac
  done
  return 1
}
`

// streamFns: stream_state prints ready, taken, not_wired or no_module (see
// proxy.Status.Streams); wire_stream and unwire_stream add and take away the
// main-context include.
const streamFns = `conf=$(nginx -V 2>&1 | sed -n 's/.*--conf-path=\([^ ]*\).*/\1/p'); [ -n "$conf" ] || conf=/etc/nginx/nginx.conf
stream_state() {
  dump=$(nginx -T 2>/dev/null)
  if printf '%s\n' "$dump" | grep -qF 'include ` + StreamsDir + `/*.conf;'; then echo ready
  elif printf '%s\n' "$dump" | grep -qE '^[[:space:]]*stream[[:space:]]*[{]'; then echo taken
  elif nginx -V 2>&1 | grep -qE -- '--with-stream( |$)' || printf '%s\n' "$dump" | grep -qE '^[[:space:]]*load_module[[:space:]].*ngx_stream_module'; then echo not_wired
  else echo no_module; fi
}
write_stream() {
  mkdir -p ` + StreamsDir + ` || return 1
  cat > ` + StreamConf + ` <<'MORCHEH_STREAM'
` + StreamBlock + `MORCHEH_STREAM
  chmod 644 ` + StreamConf + `
}
wire_stream() {
  write_stream || return 1
  if [ -d /etc/nginx/modules-enabled ] && grep -qE '^[[:space:]]*include[[:space:]]+/etc/nginx/modules-enabled/[*][.]conf' "$conf"; then
    echo '` + streamHookLine + `' > ` + streamHook + `
  elif ! grep -qF '` + streamHookLine + `' "$conf"; then
    printf '\n%s\n' '` + streamHookLine + `' >> "$conf"
  fi
}
unwire_stream() {
  rm -f ` + streamHook + `
  if [ -f "$conf" ] && grep -qF '` + streamHookLine + `' "$conf"; then
    t=$(mktemp) && grep -vF '` + streamHookLine + `' "$conf" > "$t" && cat "$t" > "$conf"; rm -f "$t"
  fi
}
`

// certsList prints certbot's live folders and Morcheh's own, for parseCerts.
const certsList = `for d in /etc/letsencrypt/live/*/ ` + proxy.SelfDir + `/*/; do
  [ -f "$d/fullchain.pem" ] || continue
  echo "cert ${d%/}"
  if command -v openssl >/dev/null 2>&1; then
    openssl x509 -in "$d/fullchain.pem" -noout -enddate 2>/dev/null
    openssl x509 -in "$d/fullchain.pem" -noout -issuer 2>/dev/null
    openssl x509 -in "$d/fullchain.pem" -noout -subject 2>/dev/null
    openssl x509 -in "$d/fullchain.pem" -noout -ext subjectAltName 2>/dev/null
  fi
done
`

// certbotVersion prints certbot's version when it's installed.
const certbotVersion = `command -v certbot >/dev/null 2>&1 && echo "certbot $(certbot --version 2>&1 | sed -n 's/^certbot \([0-9.]*\).*/\1/p' | head -n 1)"
`

const sectionMark = "@@morcheh-section:"
const fileMark = "@@morcheh-file:"

func (Driver) InspectScript() string {
	return head + `M() { printf '\n` + sectionMark + `%s@@\n' "$1"; }
M facts
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then echo "init systemd"
elif command -v rc-service >/dev/null 2>&1 && [ -d /run/openrc ]; then echo "init openrc"
else echo "init none"; fi
[ -f /proc/net/if_inet6 ] && echo ipv6
if ! command -v nginx >/dev/null 2>&1; then echo missing; M end; exit 0; fi
echo "version $(nginx -v 2>&1 | sed -n 's#.*nginx/\([0-9][0-9.]*\).*#\1#p')"
running && echo running
nginx -V 2>&1 | grep -qE -- '--with-stream( |$)' && echo stream_static
if [ -d /run/systemd/system ]; then systemctl is-enabled nginx 2>/dev/null | grep -qx enabled && echo enabled
elif command -v rc-update >/dev/null 2>&1; then rc-update show default 2>/dev/null | grep -qw nginx && echo enabled; fi
M test
nginx -t 2>&1; echo "exit $?"
M dump
nginx -T 2>/dev/null
M files
for f in ` + HostsDir + `/*.conf ` + StreamsDir + `/*.conf; do [ -f "$f" ] || continue; printf '\n` + fileMark + `%s@@\n' "$(basename "$f" .conf)"; cat "$f"; done
M released
for x in ` + ReleasedDir + `/*.path; do [ -f "$x" ] && { cat "$x"; echo; }; done
M certs
` + certsList + `M tls
nginx -V 2>&1 | grep -q -- '--with-http_v3_module' && echo http3
nginx -V 2>&1 | grep -q -- '--with-http_auth_request_module' && echo auth_request
nginx -V 2>&1 | grep -qi -- 'brotli' && echo brotli
nginx -V 2>&1 | grep -qi -- 'modsecurity' && echo modsecurity
nginx -V 2>&1 | grep -qE -- '--with-http_image_filter_module( |$)' && echo image_filter
[ -f ` + WAFConf + ` ] && echo waf_rules
for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem /etc/ssl/cert.pem; do [ -f "$f" ] && { echo "cabundle $f"; break; }; done
` + certbotVersion + `M end
`
}

// writeInclude puts the include file in place (the folder may be missing
// on a hand-built nginx).
func writeInclude() string {
	return `mkdir -p "$inc" ` + HostsDir + ` || exit 1
cat > "$inc/` + IncludeName + `" <<'MORCHEH_INCLUDE'
` + Include + `MORCHEH_INCLUDE
chmod 644 "$inc/` + IncludeName + `"
`
}

func serviceCmd(init, action string) string {
	switch init {
	case "systemd":
		return "systemctl " + action + " nginx"
	case "openrc":
		switch action {
		case "enable":
			return "rc-update add nginx default"
		}
		return "rc-service nginx " + action
	}
	switch action {
	case "start":
		return "nginx"
	case "stop":
		return "nginx -s quit"
	case "restart":
		return "{ nginx -s quit; sleep 1; nginx; }"
	}
	return "true"
}

// streamPackage is the package holding the stream module, where it's a
// separate one.
func streamPackage(pm string) string {
	switch pm {
	case "apt-get":
		return "libnginx-mod-stream"
	case "dnf", "yum", "apk":
		return "nginx-mod-stream"
	}
	return ""
}

func (Driver) SetupScript(su proxy.Setup) string {
	addModule := `echo "This nginx has no stream module, so port forwards won't be available."`
	if su.Container != nil {
		addModule = `echo "This nginx image has no stream module, so port forwards won't be available (the official nginx images have it)."`
	} else if pkg := streamPackage(su.PM); pkg != "" {
		addModule = `echo "Adding nginx's stream module (for TCP/UDP port forwards)…"
  if ! { ` + su.Install(pkg) + `; } >/dev/null 2>&1; then echo "Couldn't add it, so port forwards won't be available."; fi`
	}
	var install, start string
	if su.Container == nil {
		install = `if ! command -v nginx >/dev/null 2>&1; then
  echo "Installing nginx…"
  ` + su.Install("nginx") + ` || exit $?
  command -v nginx >/dev/null 2>&1 || { echo "nginx still isn't there after installing it"; exit 1; }
fi
`
		start = `echo "Starting nginx…"
` + serviceCmd(su.Init, "enable") + ` >/dev/null 2>&1
if running; then nginx -s reload || exit 4; else ` + serviceCmd(su.Init, "start") + ` || exit 4; fi
`
	} else {
		// The image brings nginx and the runtime starts it.
		install = `command -v nginx >/dev/null 2>&1 || { echo "There's no nginx in this container."; exit ` + strconv.Itoa(proxy.ExitNotInstalled) + `; }
`
		start = `echo "Reloading nginx…"
if running; then nginx -s reload || exit 4; else echo "nginx isn't running in the container."; exit 4; fi
`
	}
	return head + install + streamFns + `echo "Adding Morcheh's sites folder to nginx…"
` + writeInclude() + `if ! out=$(nginx -t 2>&1); then printf '%s\n' "$out"; exit 3; fi
st=$(stream_state)
if [ "$st" = no_module ]; then
  ` + addModule + `
  st=$(stream_state)
fi
if [ "$st" = not_wired ]; then
  echo "Adding Morcheh's port forwards folder to nginx…"
  wire_stream
  if ! nginx -t >/dev/null 2>&1; then unwire_stream; echo "nginx refused its stream block, so port forwards won't be available."; fi
elif [ "$st" = ready ]; then
  write_stream
elif [ "$st" = taken ]; then
  echo "nginx.conf has its own stream block: add 'include ` + StreamsDir + `/*.conf;' inside it to use port forwards."
fi
` + start + `echo "nginx is ready."
`
}

func (Driver) ApplyScript(files []proxy.File, t proxy.Takeover) string {
	return applyScript(files, t, false)
}

// TestScript puts files in place just long enough for nginx -t, then always
// puts the old ones back; nothing is reloaded.
func (Driver) TestScript(files []proxy.File, t proxy.Takeover) string {
	return applyScript(files, t, true)
}

// defaultFns: take FILE strips default_server from the listen lines on
// port 80 and 443 of a hand-written file, keeping copies in ReleasedDir;
// give_back puts back every file taken before, unless it changed since.
// Files are written through (cat >), so a symlink stays one. When $b is
// set, keep saves a file's first state there for restore().
const defaultFns = `R=` + ReleasedDir + `
keep() {
  [ -n "$b" ] || return 0
  mkdir -p "$b/hand"
  [ -f "$b/hand/$2.path" ] && return 0
  printf '%s' "$1" > "$b/hand/$2.path"; cat "$1" > "$b/hand/$2.data"
}
take() {
  [ -f "$1" ] || return 0
  k=$(printf '%s' "$1" | cksum | cut -d' ' -f1)
  t=$(mktemp) || return 1
  sed -E '/^[[:space:]]*listen[[:space:]]+([^;[:space:]]*:)?(80|443)([[:space:];]|$)/ s/[[:space:]]+default_server([[:space:];])/\1/' "$1" > "$t"
  if cmp -s "$t" "$1"; then rm -f "$t"; return 0; fi
  keep "$1" "$k"
  mkdir -p "$R"
  cat "$1" > "$R/$k.orig"; printf '%s' "$1" > "$R/$k.path"
  cat "$t" > "$1"; cat "$1" > "$R/$k.now"; rm -f "$t"
}
give_back() {
  for x in "$R"/*.path; do
    [ -f "$x" ] || continue
    k=${x%.path}; p=$(cat "$x")
    if [ -f "$p" ] && cmp -s "$p" "$k.now"; then
      keep "$p" "$(basename "$k")"
      cat "$k.orig" > "$p"
    else
      echo "$p changed after Morcheh took the default site from it, so default_server wasn't put back there."
    fi
    rm -f "$k.path" "$k.orig" "$k.now"
  done
}
`

// takeoverLines does what t says, after the managed files are in place.
func takeoverLines(t proxy.Takeover) string {
	if !t.Hold {
		return "give_back\n"
	}
	var b strings.Builder
	for _, f := range t.From {
		b.WriteString("take " + shellQuote(f) + " || { restore; exit 1; }\n")
	}
	return b.String()
}

func applyScript(files []proxy.File, t proxy.Takeover, test bool) string {
	var b strings.Builder
	b.WriteString(head)
	b.WriteString("command -v nginx >/dev/null 2>&1 || exit " + strconv.Itoa(proxy.ExitNotInstalled) + "\n")
	b.WriteString("mkdir -p " + CacheDir + "\n")
	b.WriteString(streamFns)
	b.WriteString(writeInclude())
	var streams []proxy.File
	for _, f := range files {
		if f.Config.IsStream() {
			streams = append(streams, f)
		}
	}
	noStreams := strconv.Itoa(proxy.ExitNoStreams)
	if len(streams) > 0 {
		wire := "wire_stream || exit 1"
		if test {
			// A test leaves nginx.conf alone: Save wires the forwards in.
			wire = `echo "Port forwards aren't wired into nginx yet, so they weren't tested."`
		}
		b.WriteString(`case "$(stream_state)" in
ready) write_stream ;;
not_wired) ` + wire + ` ;;
taken) echo "nginx.conf already has its own stream block. Add 'include ` + StreamsDir + `/*.conf;' inside it, then save again."; exit ` + noStreams + ` ;;
*) echo "This nginx can't forward ports: its stream module is missing. Press Set up on the proxy to add it."; exit ` + noStreams + ` ;;
esac
`)
		// A port another program holds would only fail at reload, after nginx
		// has said yes; stop before that.
		b.WriteString(`taken_by() { ss -lnp -$1 "( sport = :$2 )" 2>/dev/null | tail -n +2 | grep -o 'users:(("[^"]*"' | head -n 1 | cut -d'"' -f2; }
if command -v ss >/dev/null 2>&1; then
`)
		for _, f := range streams {
			flag := "t"
			if f.Config.Protocol == "udp" {
				flag = "u"
			}
			port := strconv.Itoa(f.Config.ListenPort)
			fmt.Fprintf(&b, `  p=$(taken_by %s %s); if [ -n "$p" ] && [ "$p" != nginx ]; then echo "Port %s/%s is already used by $p on this server."; exit %d; fi
`, flag, port, port, f.Config.Protocol, proxy.ExitPortTaken)
		}
		b.WriteString("fi\n")
	}
	b.WriteString(defaultFns)
	b.WriteString(`b=$(mktemp -d ` + Dir + `/.bak.XXXXXX) || exit 1
mkdir -p ` + StreamsDir + ` ` + AuthDir + ` "$b/hosts" "$b/streams" "$b/auth" "$b/hand"
[ -d "$R" ] && cp -pR "$R" "$b/released"
for f in ` + HostsDir + `/*.conf; do [ -f "$f" ] && cp -p "$f" "$b/hosts"/; done
for f in ` + StreamsDir + `/*.conf; do [ -f "$f" ] && cp -p "$f" "$b/streams"/; done
for f in ` + AuthDir + `/*.htpasswd; do [ -f "$f" ] && cp -p "$f" "$b/auth"/; done
restore() {
  rm -f ` + HostsDir + `/*.conf ` + StreamsDir + `/*.conf ` + AuthDir + `/*.htpasswd
  for f in "$b/hosts"/*.conf; do [ -f "$f" ] && mv -f "$f" ` + HostsDir + `/; done
  for f in "$b/streams"/*.conf; do [ -f "$f" ] && mv -f "$f" ` + StreamsDir + `/; done
  for f in "$b/auth"/*.htpasswd; do [ -f "$f" ] && mv -f "$f" ` + AuthDir + `/; done
  for f in "$b/hand"/*.path; do [ -f "$f" ] && cat "${f%.path}.data" > "$(cat "$f")"; done
  rm -rf "$R"; [ -d "$b/released" ] && mv "$b/released" "$R"
  rm -rf "$b"
}
n=$(mktemp -d ` + Dir + `/.new.XXXXXX) || { rm -rf "$b"; exit 1; }
mkdir -p "$n/hosts" "$n/streams" "$n/auth"
`)
	sorted := slices.Clone(files)
	slices.SortFunc(sorted, func(a, c proxy.File) int { return strings.Compare(a.ID, c.ID) })
	for _, f := range sorted {
		sub := "hosts"
		if f.Config.IsStream() {
			sub = "streams"
		}
		eof := "MORCHEH_HOST_" + strings.ReplaceAll(f.ID, "-", "")
		b.WriteString(`cat > "$n/` + sub + `/` + f.ID + `.conf" <<'` + eof + "'\n" + f.Text + eof + "\n")
		if f.Config.Auth.Mode == "basic" {
			pw := "MORCHEH_AUTH_" + strings.ReplaceAll(f.ID, "-", "")
			b.WriteString(`cat > "$n/auth/` + f.ID + `.htpasswd" <<'` + pw + "'\n" + htpasswd(f.Config.Auth) + pw + "\n")
		}
	}
	b.WriteString(`chmod 644 "$n"/*/*.conf 2>/dev/null
` + authOwner + `rm -f ` + HostsDir + `/*.conf ` + StreamsDir + `/*.conf ` + AuthDir + `/*.htpasswd
for f in "$n/hosts"/*.conf; do [ -f "$f" ] && mv -f "$f" ` + HostsDir + `/; done
for f in "$n/streams"/*.conf; do [ -f "$f" ] && mv -f "$f" ` + StreamsDir + `/; done
for f in "$n/auth"/*.htpasswd; do [ -f "$f" ] && mv -f "$f" ` + AuthDir + `/; done
rm -rf "$n"
`)
	b.WriteString(takeoverLines(t))
	if test {
		b.WriteString(`out=$(nginx -t 2>&1); rc=$?
restore
printf '%s\n' "$out"
[ $rc -eq 0 ] || exit ` + strconv.Itoa(proxy.ExitTestFailed) + `
`)
		return b.String()
	}
	b.WriteString(`if ! out=$(nginx -t 2>&1); then restore; printf '%s\n' "$out"; exit ` + strconv.Itoa(proxy.ExitTestFailed) + `; fi
if running; then
  if ! out=$(nginx -s reload 2>&1); then restore; nginx -s reload >/dev/null 2>&1; printf '%s\n' "$out"; exit ` + strconv.Itoa(proxy.ExitReloadFailed) + `; fi
fi
rm -rf "$b"
`)
	return b.String()
}

func (Driver) RemoveScript() string {
	return head + defaultFns + `give_back
if command -v nginx >/dev/null 2>&1; then
` + streamFns + `unwire_stream
fi
for f in /etc/nginx/conf.d/` + IncludeName + ` /etc/nginx/http.d/` + IncludeName + `; do
  [ -f "$f" ] && head -n 1 "$f" | grep -q '^` + marker + `' && rm -f "$f"
done
rm -rf ` + Dir + ` ` + CacheDir + `
rm -f ` + geoCron + `
command -v nginx >/dev/null 2>&1 || exit 0
if nginx -t >/dev/null 2>&1 && running; then nginx -s reload; fi
exit 0
`
}

func (Driver) ActionScript(action, init string) (string, error) {
	test := `if ! out=$(nginx -t 2>&1); then printf '%s\n' "$out"; exit ` + strconv.Itoa(proxy.ExitTestFailed) + "; fi\n"
	s := head + "command -v nginx >/dev/null 2>&1 || exit " + strconv.Itoa(proxy.ExitNotInstalled) + "\n"
	switch action {
	case "test":
		return s + "nginx -t 2>&1\n", nil
	case "reload":
		return s + test + "if running; then nginx -s reload 2>&1; else echo 'nginx isn'\\''t running'; exit 1; fi\n", nil
	case "start", "restart":
		return s + test + serviceCmd(init, action) + " 2>&1\n", nil
	case "stop":
		return s + serviceCmd(init, action) + " 2>&1\n", nil
	}
	return "", fmt.Errorf("unknown action %q", action)
}

func (Driver) LogScript(hostID, log string, lines int) string {
	f := logDir + "/" + log + ".log"
	if hostID != "" {
		f = logDir + "/morcheh-" + hostID + "." + log + ".log"
	}
	return fmt.Sprintf("if [ -f %s ]; then tail -n %d %s; else echo '@@morcheh-nolog'; fi\n", f, lines, f)
}
