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
	// streamHook is the main-context include put where nginx loads modules
	// (Debian, Ubuntu), else appended to nginx.conf.
	streamHook     = "/etc/nginx/modules-enabled/zz-morcheh-stream.conf"
	streamHookLine = "include " + StreamConf + "; " + marker
	// IncludeName is the file put in conf.d (or http.d) to load the hosts.
	IncludeName = "morcheh.conf"
	logDir      = "/var/log/nginx"
	marker      = "# Managed by Morcheh"
)

// Include is the whole include file. The map lets WebSocket hosts close
// plain connections properly.
const Include = marker + `: sites added in the panel live in ` + HostsDir + `.
# Changes made here are overwritten.
map $http_upgrade $morcheh_connection {
    default upgrade;
    ''      close;
}
include ` + HostsDir + `/*.conf;
`

// StreamBlock is the whole stream.conf. Its log format keeps the fields of
// nginx's combined one, so the traffic counter reads both the same way.
const StreamBlock = marker + `: ports forwarded in the panel live in ` + StreamsDir + `.
# Changes made here are overwritten.
stream {
    log_format morcheh_stream '$remote_addr - - [$time_local] "$protocol" $status $bytes_sent "-" "-"';
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
			proxy.TypeNotFound, proxy.TypeStream,
		},
		WebSockets: true, Headers: true, Paths: true, Allow: true, Advanced: true,
		Streams: true, Traffic: true,
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
	names := strings.Join(h.Domains, " ")
	ipv6 := env.IPv6
	newHTTP2 := atLeast(env.Version, 1, 25, 1)

	logs := func() {
		w.line("access_log %s;", AccessLog(id))
		w.line("error_log %s;", ErrorLog(id))
	}

	if h.TLS.Enabled && h.TLS.ForceHTTPS {
		w.line("")
		w.open("server")
		w.line("listen 80;")
		if ipv6 {
			w.line("listen [::]:80;")
		}
		w.line("server_name %s;", names)
		logs()
		w.line("")
		w.line("return 301 https://$host$request_uri;")
		w.close()
	}

	w.line("")
	w.open("server")
	if !h.TLS.Enabled || !h.TLS.ForceHTTPS {
		w.line("listen 80;")
		if ipv6 {
			w.line("listen [::]:80;")
		}
	}
	if h.TLS.Enabled {
		suffix := ""
		if h.TLS.HTTP2 && !newHTTP2 {
			suffix = " http2"
		}
		w.line("listen 443 ssl%s;", suffix)
		if ipv6 {
			w.line("listen [::]:443 ssl%s;", suffix)
		}
		if h.TLS.HTTP2 && newHTTP2 {
			w.line("http2 on;")
		}
	}
	w.line("server_name %s;", names)
	logs()
	if h.TLS.Enabled {
		w.line("")
		w.line("ssl_certificate %s;", h.TLS.Certificate)
		w.line("ssl_certificate_key %s;", h.TLS.Key)
		if h.TLS.HSTS {
			w.line(`add_header Strict-Transport-Security "max-age=31536000" always;`)
		}
	}

	if len(h.Allow) > 0 || h.MaxBodyMB > 0 || hasHeaders(h, "response") {
		w.line("")
	}
	for _, a := range h.Allow {
		w.line("allow %s;", a)
	}
	if len(h.Allow) > 0 {
		w.line("deny all;")
	}
	if h.MaxBodyMB > 0 {
		w.line("client_max_body_size %dm;", h.MaxBodyMB)
	}
	for _, x := range h.Headers {
		if x.To == "response" {
			w.line(`add_header %s "%s" always;`, x.Name, x.Value)
		}
	}

	switch h.Type {
	case proxy.TypeNotFound:
		w.line("")
		w.line("return 404;")
	case proxy.TypeRedirect:
		w.line("")
		target := h.RedirectTo
		if h.KeepPath {
			target = strings.TrimRight(target, "/") + "$request_uri"
		}
		w.line("return %d %s;", h.RedirectCode, target)
	case proxy.TypeStatic:
		w.line("")
		w.line("root %s;", h.Root)
		w.line("index index.html index.htm;")
		paths(w, h)
		w.line("")
		w.open("location /")
		if h.SPA {
			w.line("try_files $uri $uri/ /index.html;")
		} else {
			w.line("try_files $uri $uri/ =404;")
		}
		w.close()
	default:
		paths(w, h)
		w.line("")
		w.open("location /")
		proxyPass(w, h, h.Upstream, h.WebSockets)
		w.close()
	}

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
	if len(h.Allow) > 0 {
		w.line("")
		for _, a := range h.Allow {
			w.line("allow %s;", a)
		}
		w.line("deny all;")
	}
	w.line("")
	w.line("proxy_pass %s;", h.StreamTo)
	if h.TimeoutSeconds > 0 {
		w.line("proxy_timeout %ds;", h.TimeoutSeconds)
	}
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

func paths(w *writer, h proxy.HostConfig) {
	for _, p := range h.Paths {
		w.line("")
		w.open("location %s", p.Path)
		proxyPass(w, h, p.Upstream, p.WebSockets)
		if p.Advanced != "" {
			w.raw(p.Advanced)
		}
		w.close()
	}
}

func proxyPass(w *writer, h proxy.HostConfig, upstream string, ws bool) {
	w.line("proxy_pass %s;", upstream)
	w.line("proxy_http_version 1.1;")
	if h.PreserveHost {
		w.line("proxy_set_header Host $host;")
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
	for _, x := range h.Headers {
		if x.To == "request" {
			w.line(`proxy_set_header %s "%s";`, x.Name, x.Value)
		}
	}
	if u, err := url.Parse(upstream); err == nil && u.Scheme == "https" {
		w.line("proxy_ssl_server_name on;")
	}
	switch {
	case h.TimeoutSeconds > 0:
		w.line("proxy_read_timeout %ds;", h.TimeoutSeconds)
		w.line("proxy_send_timeout %ds;", h.TimeoutSeconds)
	case ws:
		w.line("proxy_read_timeout 1h;")
		w.line("proxy_send_timeout 1h;")
	}
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
// folder the stock nginx.conf includes inside http.
const head = `PATH=$PATH:/usr/sbin:/sbin:/usr/local/sbin:/usr/local/nginx/sbin
if [ -d /etc/nginx/http.d ]; then inc=/etc/nginx/http.d; else inc=/etc/nginx/conf.d; fi
running() { for p in /proc/[0-9]*; do tr '\0' ' ' < "$p/cmdline" 2>/dev/null; echo; done | grep -q '[n]ginx: master'; }
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
M certs
for d in /etc/letsencrypt/live/*/; do
  [ -f "$d/fullchain.pem" ] || continue
  echo "cert $(basename "$d")"
  if command -v openssl >/dev/null 2>&1; then
    openssl x509 -in "$d/fullchain.pem" -noout -enddate 2>/dev/null
    openssl x509 -in "$d/fullchain.pem" -noout -ext subjectAltName 2>/dev/null
  fi
done
M end
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
	if pkg := streamPackage(su.PM); pkg != "" {
		addModule = `echo "Adding nginx's stream module (for TCP/UDP port forwards)…"
  if ! { ` + su.Install(pkg) + `; } >/dev/null 2>&1; then echo "Couldn't add it, so port forwards won't be available."; fi`
	}
	s := head + `if ! command -v nginx >/dev/null 2>&1; then
  echo "Installing nginx…"
  ` + su.Install("nginx") + ` || exit $?
  command -v nginx >/dev/null 2>&1 || { echo "nginx still isn't there after installing it"; exit 1; }
fi
` + streamFns + `echo "Adding Morcheh's sites folder to nginx…"
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
echo "Starting nginx…"
` + serviceCmd(su.Init, "enable") + ` >/dev/null 2>&1
if running; then nginx -s reload || exit 4; else ` + serviceCmd(su.Init, "start") + ` || exit 4; fi
echo "nginx is ready."
`
	return s
}

func (Driver) ApplyScript(files []proxy.File) string {
	var b strings.Builder
	b.WriteString(head)
	b.WriteString("command -v nginx >/dev/null 2>&1 || exit " + strconv.Itoa(proxy.ExitNotInstalled) + "\n")
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
		b.WriteString(`case "$(stream_state)" in
ready) write_stream ;;
not_wired) wire_stream || exit 1 ;;
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
	b.WriteString(`b=$(mktemp -d ` + Dir + `/.bak.XXXXXX) || exit 1
mkdir -p ` + StreamsDir + ` "$b/hosts" "$b/streams"
for f in ` + HostsDir + `/*.conf; do [ -f "$f" ] && cp -p "$f" "$b/hosts"/; done
for f in ` + StreamsDir + `/*.conf; do [ -f "$f" ] && cp -p "$f" "$b/streams"/; done
restore() {
  rm -f ` + HostsDir + `/*.conf ` + StreamsDir + `/*.conf
  for f in "$b/hosts"/*.conf; do [ -f "$f" ] && mv -f "$f" ` + HostsDir + `/; done
  for f in "$b/streams"/*.conf; do [ -f "$f" ] && mv -f "$f" ` + StreamsDir + `/; done
  rm -rf "$b"
}
n=$(mktemp -d ` + Dir + `/.new.XXXXXX) || { rm -rf "$b"; exit 1; }
mkdir -p "$n/hosts" "$n/streams"
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
	}
	b.WriteString(`chmod 644 "$n"/*/*.conf 2>/dev/null
rm -f ` + HostsDir + `/*.conf ` + StreamsDir + `/*.conf
for f in "$n/hosts"/*.conf; do [ -f "$f" ] && mv -f "$f" ` + HostsDir + `/; done
for f in "$n/streams"/*.conf; do [ -f "$f" ] && mv -f "$f" ` + StreamsDir + `/; done
rm -rf "$n"
if ! out=$(nginx -t 2>&1); then restore; printf '%s\n' "$out"; exit ` + strconv.Itoa(proxy.ExitTestFailed) + `; fi
if running; then
  if ! out=$(nginx -s reload 2>&1); then restore; nginx -s reload >/dev/null 2>&1; printf '%s\n' "$out"; exit ` + strconv.Itoa(proxy.ExitReloadFailed) + `; fi
fi
rm -rf "$b"
`)
	return b.String()
}

func (Driver) RemoveScript() string {
	return head + `if command -v nginx >/dev/null 2>&1; then
` + streamFns + `unwire_stream
fi
for f in /etc/nginx/conf.d/` + IncludeName + ` /etc/nginx/http.d/` + IncludeName + `; do
  [ -f "$f" ] && head -n 1 "$f" | grep -q '^` + marker + `' && rm -f "$f"
done
rm -rf ` + Dir + `
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
