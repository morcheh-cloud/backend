// Package nginx is the nginx driver: it renders hosts into server blocks in
// /etc/nginx/morcheh/hosts, wired in with one include in conf.d (http.d on
// Alpine), and reads the live config back with nginx -T.
package nginx

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/morcheh/backend/internal/proxy"
)

const (
	// Dir holds everything Morcheh writes; HostsDir one file per host.
	Dir      = "/etc/nginx/morcheh"
	HostsDir = Dir + "/hosts"
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

func init() { proxy.Register(Driver{}) }

// Driver is the nginx kind.
type Driver struct{}

func (Driver) Kind() string  { return "nginx" }
func (Driver) Label() string { return "nginx" }

func (Driver) Capabilities() proxy.Capabilities {
	return proxy.Capabilities{
		Types:      []string{proxy.TypeProxy, proxy.TypeRedirect, proxy.TypeStatic},
		WebSockets: true, Headers: true, Paths: true, Allow: true, Advanced: true,
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
if [ -d /run/systemd/system ]; then systemctl is-enabled nginx 2>/dev/null | grep -qx enabled && echo enabled
elif command -v rc-update >/dev/null 2>&1; then rc-update show default 2>/dev/null | grep -qw nginx && echo enabled; fi
M test
nginx -t 2>&1; echo "exit $?"
M dump
nginx -T 2>/dev/null
M files
for f in ` + HostsDir + `/*.conf; do [ -f "$f" ] || continue; printf '\n` + fileMark + `%s@@\n' "$(basename "$f" .conf)"; cat "$f"; done
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

func (Driver) SetupScript(install, init string) string {
	s := head + `if ! command -v nginx >/dev/null 2>&1; then
  echo "Installing nginx…"
  ` + install + ` || exit $?
  command -v nginx >/dev/null 2>&1 || { echo "nginx still isn't there after installing it"; exit 1; }
fi
echo "Adding Morcheh's sites folder to nginx…"
` + writeInclude() + `if ! out=$(nginx -t 2>&1); then printf '%s\n' "$out"; exit 3; fi
echo "Starting nginx…"
` + serviceCmd(init, "enable") + ` >/dev/null 2>&1
if running; then nginx -s reload || exit 4; else ` + serviceCmd(init, "start") + ` || exit 4; fi
echo "nginx is ready."
`
	return s
}

func (Driver) ApplyScript(files map[string]string) string {
	var b strings.Builder
	b.WriteString(head)
	b.WriteString("command -v nginx >/dev/null 2>&1 || exit " + strconv.Itoa(proxy.ExitNotInstalled) + "\n")
	b.WriteString(writeInclude())
	b.WriteString(`d=` + HostsDir + `
b=$(mktemp -d ` + Dir + `/.bak.XXXXXX) || exit 1
for f in "$d"/*.conf; do [ -f "$f" ] && cp -p "$f" "$b"/; done
restore() { rm -f "$d"/*.conf; for f in "$b"/*.conf; do [ -f "$f" ] && mv -f "$f" "$d"/; done; rm -rf "$b"; }
n=$(mktemp -d ` + Dir + `/.new.XXXXXX) || { rm -rf "$b"; exit 1; }
`)
	ids := make([]string, 0, len(files))
	for id := range files {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		eof := "MORCHEH_HOST_" + strings.ReplaceAll(id, "-", "")
		b.WriteString(`cat > "$n/` + id + `.conf" <<'` + eof + "'\n" + files[id] + eof + "\n")
	}
	b.WriteString(`chmod 644 "$n"/*.conf 2>/dev/null
rm -f "$d"/*.conf
for f in "$n"/*.conf; do [ -f "$f" ] && mv -f "$f" "$d"/; done
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
	return head + `for f in /etc/nginx/conf.d/` + IncludeName + ` /etc/nginx/http.d/` + IncludeName + `; do
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
