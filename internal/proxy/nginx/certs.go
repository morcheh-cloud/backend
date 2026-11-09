package nginx

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/morcheh/backend/internal/proxy"
)

// Mozilla's server-side TLS guidelines (5.7), by profile.
var profiles = map[string][]string{
	"modern": {
		"ssl_protocols TLSv1.3;",
		"ssl_ecdh_curve X25519:prime256v1:secp384r1;",
		"ssl_prefer_server_ciphers off;",
	},
	"intermediate": {
		"ssl_protocols TLSv1.2 TLSv1.3;",
		"ssl_ecdh_curve X25519:prime256v1:secp384r1;",
		"ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;",
		"ssl_prefer_server_ciphers off;",
	},
	"old": {
		"ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;",
		"ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:@SECLEVEL=0;",
		"ssl_prefer_server_ciphers on;",
	},
}

// tlsLines are the https server's certificate and TLS settings.
func tlsLines(w *writer, t proxy.HostTLS) {
	w.line("")
	w.line("ssl_certificate %s;", t.Certificate)
	w.line("ssl_certificate_key %s;", t.Key)
	for _, l := range profiles[t.Profile] {
		w.line("%s", l)
	}
	if t.SessionCache {
		w.line("ssl_session_cache shared:morcheh_tls:10m;")
		w.line("ssl_session_timeout 1d;")
		w.line("ssl_session_tickets off;")
	}
	if t.OCSP {
		w.line("ssl_stapling on;")
		w.line("ssl_stapling_verify on;")
	}
	if t.ClientCA != "" {
		w.line("ssl_client_certificate %s;", t.ClientCA)
		w.line("ssl_verify_client %s;", t.VerifyClient)
	}
	if t.HTTP3 {
		w.line(`add_header Alt-Svc 'h3=":443"; ma=86400' always;`)
	}
	if t.HSTS {
		w.line(`add_header Strict-Transport-Security "%s" always;`, t.HSTSValue())
	}
}

// acmeLocation answers certificate authorities' HTTP-01 checks on port 80,
// whatever the site does with everything else.
func acmeLocation(w *writer, h proxy.HostConfig) {
	w.line("")
	w.open("location ^~ /.well-known/acme-challenge/")
	w.line("allow all;")
	openUp(w, h)
	if h.WAF.On() {
		w.line("modsecurity off;")
	}
	w.line("root %s;", proxy.ACMEWebroot)
	w.line("default_type text/plain;")
	w.line("try_files $uri =404;")
	w.close()
}

// deployHook reloads nginx after certbot renews any certificate.
const deployHook = "/etc/letsencrypt/renewal-hooks/deploy/morcheh-nginx.sh"

// CertificateScript gets a certificate from an ACME CA with certbot (webroot,
// through a short-lived server block for names no site serves yet), makes a
// self-signed one, or writes an uploaded pair. Exit codes: ExitNotInstalled
// when nginx is missing (ACME only), ExitTestFailed when the temporary block
// is refused, anything else = it failed, with the reason printed.
func (Driver) CertificateScript(r proxy.CertRequest, s proxy.Setup) string {
	cert, key := r.Paths()
	var b strings.Builder
	b.WriteString(head)
	b.WriteString("umask 022\n")
	switch r.Source {
	case proxy.CertUpload:
		dir := proxy.SelfDir + "/" + r.Name
		fmt.Fprintf(&b, `mkdir -p %[1]s && chmod 700 %[1]s || exit 1
printf '%%s' '%[2]s' | base64 -d > %[3]s.new || { echo "Couldn't write the certificate."; exit 1; }
(umask 077; printf '%%s' '%[4]s' | base64 -d > %[5]s.new) || { echo "Couldn't write the key."; exit 1; }
mv -f %[3]s.new %[3]s && mv -f %[5]s.new %[5]s && chmod 600 %[5]s || exit 1
echo "Saved to %[1]s."
`, dir, b64(r.Certificate+"\n"), cert, b64(r.Key+"\n"), key)
	case proxy.CertSelfSigned:
		dir := proxy.SelfDir + "/" + r.Name
		newKey := "ec -pkeyopt ec_paramgen_curve:prime256v1"
		if r.KeyType == "rsa" {
			newKey = "rsa:2048"
		}
		cn := r.Domains[0]
		if len(cn) > 64 {
			cn = "morcheh"
		}
		var alt []string
		for _, d := range r.Domains {
			if isIP(d) {
				alt = append(alt, "IP:"+d)
			} else {
				alt = append(alt, "DNS:"+d)
			}
		}
		fmt.Fprintf(&b, `if ! command -v openssl >/dev/null 2>&1; then
  echo "Installing openssl…"
  %[1]s
fi
command -v openssl >/dev/null 2>&1 || { echo "openssl isn't installed and couldn't be."; exit 1; }
mkdir -p %[2]s && chmod 700 %[2]s || exit 1
openssl req -x509 -newkey %[3]s -nodes -days %[4]d -subj '/CN=%[5]s' -addext 'subjectAltName=%[6]s' -keyout %[7]s.new -out %[8]s.new 2>&1 || { rm -f %[7]s.new %[8]s.new; echo "openssl couldn't make the certificate."; exit 1; }
mv -f %[8]s.new %[8]s && mv -f %[7]s.new %[7]s && chmod 600 %[7]s || exit 1
echo "Made a self-signed certificate for %[9]s, valid %[4]d days, in %[2]s."
`, indent(s.Install("openssl"), "  "), dir, newKey, r.Days, cn, strings.Join(alt, ","), key, cert, strings.Join(r.Domains, ", "))
	case proxy.CertACME:
		if s.Container != nil {
			b.WriteString(acmeContainerScript(r, s))
		} else {
			b.WriteString(acmeScript(r, s))
		}
	}
	if s.Container != nil && r.Source != proxy.CertACME {
		b.WriteString(pushCert(*s.Container, cert, key))
	}
	return b.String()
}

// acmeBlock is the temporary server block answering the CA's check for
// names no site serves yet, cut where the IPv6 listen goes (when the server
// has IPv6).
func acmeBlock(r proxy.CertRequest) (first, rest string) {
	w := &writer{}
	w.line("%s: a temporary block for a certificate check; it's removed when done.", marker)
	w.open("server")
	w.line("listen 80;")
	w.line("server_name %s;", strings.Join(r.Domains, " "))
	acmeLocation(w, proxy.HostConfig{})
	w.line("")
	w.open("location /")
	w.line("return 404;")
	w.close()
	w.close()
	text := w.b.String()
	cut := strings.Index(text, "listen 80;\n") + len("listen 80;\n")
	return text[:cut], text[cut:]
}

// acmeTmp is where the temporary block goes.
func acmeTmp(r proxy.CertRequest) string { return HostsDir + "/zz-acme-" + r.Name + ".conf" }

// acmeOpen writes the temporary block, tests and reloads (exit
// ExitTestFailed, with nginx's words, when it's refused). It leaves
// reload() and tmp defined.
func acmeOpen(r proxy.CertRequest) string {
	first, rest := acmeBlock(r)
	return fmt.Sprintf(`mkdir -p %[1]s/.well-known/acme-challenge && chmod 755 %[1]s %[1]s/.well-known %[1]s/.well-known/acme-challenge || exit 1
tmp=%[2]s
cat > "$tmp" <<'MORCHEH_ACME'
%[3]sMORCHEH_ACME
[ -f /proc/net/if_inet6 ] && v6='    listen [::]:80;' || v6=''
cat >> "$tmp" <<MORCHEH_ACME
$v6
MORCHEH_ACME
cat >> "$tmp" <<'MORCHEH_ACME'
%[4]sMORCHEH_ACME
reload() { nginx -s reload >/dev/null 2>&1; sleep 1; }
if ! out=$(nginx -t 2>&1); then rm -f "$tmp"; printf '%%s\n' "$out"; exit %[5]d; fi
reload
`, proxy.ACMEWebroot, acmeTmp(r), first, rest, proxy.ExitTestFailed)
}

// acmeArgs are certbot's arguments but how it answers the check.
func acmeArgs(r proxy.CertRequest) []string {
	args := []string{
		"certonly", "--non-interactive", "--agree-tos",
		"--cert-name", q(r.Name),
		"--server", q(r.DirectoryURL()),
	}
	for _, d := range r.Domains {
		args = append(args, "-d", q(d))
	}
	if r.Email != "" {
		args = append(args, "--email", q(r.Email), "--no-eff-email")
	} else {
		args = append(args, "--register-unsafely-without-email")
	}
	if r.Force {
		args = append(args, "--force-renewal")
	} else {
		args = append(args, "--keep-until-expiring")
	}
	return args
}

// certbotNeeded installs certbot when it's missing and prints its version.
func certbotNeeded(s proxy.Setup) string {
	return `if ! command -v certbot >/dev/null 2>&1; then
  echo "Installing certbot…"
  ` + indent(s.Install("certbot"), "  ") + `
fi
command -v certbot >/dev/null 2>&1 || { echo "certbot isn't installed and couldn't be. Install it by hand, then try again."; exit 1; }
echo "$(certbot --version 2>&1 | head -n 1)"
`
}

// eabConfig puts the EAB HMAC key in a root-only file, not on the command
// line, and adds it to args.
func eabConfig(r proxy.CertRequest, args *[]string, fail string) string {
	if r.EABKid == "" {
		return ""
	}
	*args = append(*args, "--config", `"$cfg"`)
	return fmt.Sprintf(`cfg=$(mktemp) && chmod 600 "$cfg" && printf 'eab-kid = %%s\neab-hmac-key = %%s\n' %s %s > "$cfg" || { %s; exit 1; }
`, q(r.EABKid), q(r.EABHMAC), fail)
}

// certbotRun runs certbot with args (key type when it knows it) and leaves
// its status in rc.
func certbotRun(r proxy.CertRequest, args []string) string {
	keyType := "ecdsa"
	if r.KeyType == "rsa" {
		keyType = "rsa"
	}
	return fmt.Sprintf(`kt=""
if certbot --help all 2>/dev/null | grep -q -- '--key-type'; then kt="--key-type %s"; fi
printf 'Asking %%s for %%s…\n' %s %s
certbot %s $kt 2>&1
rc=$?
`, keyType, q(r.DirectoryURL()), q(strings.Join(r.Domains, ", ")), strings.Join(args, " "))
}

const acmeRefused = `  echo "The certificate authority refused. Check that these names point to this server and that port 80 is open to the internet."
  exit 1
`

func acmeScript(r proxy.CertRequest, s proxy.Setup) string {
	args := append(acmeArgs(r), "--webroot", "-w", proxy.ACMEWebroot)
	var b strings.Builder
	fmt.Fprintf(&b, `command -v nginx >/dev/null 2>&1 || exit %[1]d
running || { echo "nginx isn't running, so the certificate authority can't reach this server. Start it first."; exit 1; }
%[2]smkdir -p "$(dirname %[3]s)" && cat > %[3]s <<'MORCHEH_HOOK'
#!/bin/sh
# Managed by Morcheh: reload nginx after certbot renews a certificate.
PATH=$PATH:/usr/sbin:/sbin:/usr/local/sbin
nginx -t >/dev/null 2>&1 || exit 0
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet nginx; then systemctl reload nginx; else nginx -s reload; fi
MORCHEH_HOOK
chmod 755 %[3]s
cfg=""
%[4]scleanup() { rm -f "$tmp" "$cfg"; nginx -t >/dev/null 2>&1 && reload; }
`, proxy.ExitNotInstalled, certbotNeeded(s), deployHook, acmeOpen(r))
	b.WriteString(eabConfig(r, &args, "cleanup"))
	b.WriteString(certbotRun(r, args))
	fmt.Fprintf(&b, `cleanup
if [ $rc -ne 0 ]; then
%s
fi
[ -f %[2]s ] || { echo "certbot finished but left no certificate."; exit 1; }
echo "Certificate ready in $(dirname %[2]s). certbot renews it before it expires and reloads nginx."
`, strings.TrimRight(acmeRefused, "\n"), certPath(r))
	return b.String()
}

func certPath(r proxy.CertRequest) string {
	c, _ := r.Paths()
	return c
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// q quotes a value for sh.
func q(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func indent(s, pad string) string {
	return strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n"+pad)
}

func isIP(s string) bool {
	if strings.Count(s, ":") >= 2 {
		return true
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}
