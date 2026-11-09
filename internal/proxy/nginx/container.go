package nginx

import (
	"fmt"
	"strings"

	"github.com/morcheh/backend/internal/proxy"
)

// ---- nginx in a container: what runs on the server around it ----

// HostInspectScript lists the server's certificates and certbot (they live
// on the server and are copied into the container). Its facts say
// "installed" only so ParseInspect reads on; the caller takes nothing else.
func (Driver) HostInspectScript() string {
	return head + `M() { printf '\n` + sectionMark + `%s@@\n' "$1"; }
M facts
echo "version host"
M certs
` + certsList + `M tls
` + certbotVersion + `M end
`
}

// rotateScript rotates the container's Morcheh logs like logrotate does on
// a server (name.1, then name.N.gz, 14 kept) and has nginx reopen them.
func rotateScript(c proxy.Container) string {
	return `#!/bin/sh
# Managed by Morcheh: rotates the logs of nginx in the container ` + c.Name + `.
` + strings.TrimSuffix(proxy.HostPath(), "\n") + `
` + c.Runtime + ` exec -i -u 0 ` + q(c.Name) + ` sh -s <<'MORCHEH_ROTATE_IN'
cd ` + logDir + ` 2>/dev/null || exit 0
r=0
for f in morcheh-*.log; do
  [ -f "$f" ] && [ -s "$f" ] || continue
  rm -f "$f.14.gz"
  i=13
  while [ $i -ge 2 ]; do
    [ -f "$f.$i.gz" ] && mv -f "$f.$i.gz" "$f.$((i+1)).gz"
    i=$((i-1))
  done
  [ -f "$f.1" ] && gzip -c "$f.1" > "$f.2.gz" && rm -f "$f.1"
  mv -f "$f" "$f.1"
  r=1
done
[ $r = 1 ] && nginx -s reopen >/dev/null 2>&1
exit 0
MORCHEH_ROTATE_IN
`
}

func (Driver) HostSetupScript(c proxy.Container) string {
	dir := c.HostDir()
	return proxy.HostPath() + fmt.Sprintf(`mkdir -p %[1]s && chmod 700 %[1]s || exit 1
cat > %[1]s/rotate.sh <<'MORCHEH_ROTATE'
%[2]sMORCHEH_ROTATE
chmod 700 %[1]s/rotate.sh
if [ -d /etc/cron.d ]; then
  printf '# Managed by Morcheh: rotates the logs of nginx in the container %%s.\n17 3 * * * root %%s >/dev/null 2>&1\n' %[3]s %[1]s/rotate.sh > %[4]s && chmod 644 %[4]s
else
  echo "This server has no /etc/cron.d, so the container's logs won't be rotated: run %[1]s/rotate.sh daily yourself."
fi
`, dir, rotateScript(c), q(c.Name), c.CronFile())
}

// HostRemoveScript takes the log rotation away; certbot's hooks stay while
// its renewal settings still name them.
func (Driver) HostRemoveScript(c proxy.Container) string {
	return fmt.Sprintf("rm -f %s/rotate.sh %s\nexit 0\n", c.HostDir(), c.CronFile())
}

// pushCert copies a certificate pair from the server into the container.
func pushCert(c proxy.Container, cert, key string) string {
	return c.Check() + c.PushFn() + fmt.Sprintf(`push %s %s || exit 1
echo "Copied into the container %s."
`, q(cert), q(key), c.Name)
}

// acmeContainerScript gets a certificate with certbot on the server while
// nginx answers the CA's check inside the container: certbot's manual hooks
// put the token into the container's webroot, and its deploy hook copies
// the files in and reloads nginx there (on every renewal too).
func acmeContainerScript(r proxy.CertRequest, s proxy.Setup) string {
	c := *s.Container
	dir := c.HostDir()
	ex := c.Runtime + " exec -i -u 0 " + q(c.Name)
	path := strings.TrimSuffix(proxy.HostPath(), "\n")
	challenge := proxy.ACMEWebroot + "/.well-known/acme-challenge"
	args := append(acmeArgs(r), "--manual", "--preferred-challenges", "http",
		"--manual-auth-hook", dir+"/auth.sh",
		"--manual-cleanup-hook", dir+"/cleanup.sh",
		"--deploy-hook", dir+"/deploy.sh")
	var b strings.Builder
	b.WriteString(c.Check())
	b.WriteString(certbotNeeded(s))
	fmt.Fprintf(&b, `mkdir -p %[1]s && chmod 700 %[1]s || exit 1
cat > %[1]s/auth.sh <<'MORCHEH_HOOK'
#!/bin/sh
# Managed by Morcheh: puts certbot's check into the container %[2]s.
%[3]s
printf '%%s' "$CERTBOT_VALIDATION" | %[4]s sh -c 'd=%[5]s; mkdir -p "$d" && cat > "$d/$1" && chmod 644 "$d/$1"' sh "$CERTBOT_TOKEN"
MORCHEH_HOOK
cat > %[1]s/cleanup.sh <<'MORCHEH_HOOK'
#!/bin/sh
# Managed by Morcheh: removes certbot's check from the container %[2]s.
%[3]s
%[4]s sh -c 'rm -f "%[5]s/$1"' sh "$CERTBOT_TOKEN" </dev/null
exit 0
MORCHEH_HOOK
cat > %[1]s/deploy.sh <<'MORCHEH_HOOK'
#!/bin/sh
# Managed by Morcheh: copies renewed certificates into the container %[2]s
# and reloads its nginx.
%[3]s
[ -n "$RENEWED_LINEAGE" ] || exit 0
%[6]spush "$RENEWED_LINEAGE/fullchain.pem" "$RENEWED_LINEAGE/privkey.pem" "$RENEWED_LINEAGE/chain.pem" "$RENEWED_LINEAGE/cert.pem" || exit 1
%[7]s sh -c 'nginx -t >/dev/null 2>&1 && nginx -s reload' </dev/null
exit 0
MORCHEH_HOOK
chmod 700 %[1]s/auth.sh %[1]s/cleanup.sh %[1]s/deploy.sh
`, dir, c.Name, path, ex, challenge, c.PushFn(), c.Runtime+" exec -u 0 "+q(c.Name))
	// The temporary block goes in (and comes out) inside the container.
	b.WriteString(c.Run(head + acmeOpen(r)))
	b.WriteString("rc=$?; [ $rc -eq 0 ] || exit $rc\ncfg=\"\"\n")
	// (Not indented: the heredoc inside must end at the start of a line.)
	b.WriteString("cleanup() {\nrm -f \"$cfg\"\n" + strings.TrimSuffix(c.Run(fmt.Sprintf(
		"%srm -f %s\nnginx -t >/dev/null 2>&1 && nginx -s reload >/dev/null 2>&1\nexit 0\n", head, acmeTmp(r))), "\n") + " >/dev/null 2>&1\n}\n")
	b.WriteString(eabConfig(r, &args, "cleanup"))
	b.WriteString(certbotRun(r, args))
	fmt.Fprintf(&b, `cleanup
if [ $rc -ne 0 ]; then
%s
fi
[ -f %[2]s ] || { echo "certbot finished but left no certificate."; exit 1; }
RENEWED_LINEAGE=$(dirname %[2]s) sh %[3]s/deploy.sh || { echo "Couldn't copy the certificate into the container %[4]s."; exit 1; }
echo "Certificate ready in $(dirname %[2]s) and copied into the container. certbot renews it before it expires, copies it in again and reloads nginx."
`, strings.TrimRight(acmeRefused, "\n"), certPath(r), dir, c.Name)
	return b.String()
}

// DetectScript finds nginx on the server (a master in the server's own PID
// namespace counts as running) and containers running nginx, OpenResty or
// Angie.
func (Driver) DetectScript() string {
	return head + `if command -v nginx >/dev/null 2>&1; then
  v=$(nginx -v 2>&1 | sed -n 's/.*nginx\/\([^ ]*\).*/\1/p')
  echo "native ${v:-unknown}"
  running && echo native_running
fi
` + proxy.DetectRuntimes("nginx|openresty|angie")
}
