package nginx

import (
	"strconv"

	"github.com/morcheh/backend/internal/proxy"
)

// The IP-to-country lookup behind country rules: nginx's GeoIP2 module
// reading DB-IP's free country database (CC BY 4.0), refreshed monthly.

// geoCron are the monthly cron entries that refresh the database.
const geoCron = "/etc/cron.monthly/morcheh-geoip /etc/periodic/monthly/morcheh-geoip"

// geoConf loads the database and names the visitor's country.
const geoConf = marker + `: the visitor's country for country rules.
geoip2 ` + GeoDB + ` {
    ` + countryVar + ` country iso_code;
}
`

// geoUpdate downloads this month's database (or last month's, early in the
// month) and reloads nginx. It runs from cron, so it stands alone.
const geoUpdate = `#!/bin/sh
` + marker + `: refreshes the IP-to-country database for country rules.
# IP to country data by DB-IP.com (https://db-ip.com), CC BY 4.0.
PATH=$PATH:/usr/sbin:/sbin:/usr/local/sbin:/usr/local/nginx/sbin
dir=` + GeoDir + `
y=$(date +%Y); m=$(date +%m); m=${m#0}
if [ "$m" -eq 1 ]; then py=$((y-1)); pm=12; else py=$y; pm=$((m-1)); fi
t=$(mktemp "$dir/.dl.XXXXXX") || exit 1
ok=
for ym in "$(printf '%d-%02d' "$y" "$m")" "$(printf '%d-%02d' "$py" "$pm")"; do
  url="https://download.db-ip.com/free/dbip-country-lite-$ym.mmdb.gz"
  if command -v curl >/dev/null 2>&1; then curl -fsSL --max-time 600 -o "$t.gz" "$url"; else wget -q -T 600 -O "$t.gz" "$url"; fi &&
    gzip -dc "$t.gz" > "$t" && [ "$(wc -c < "$t")" -gt 1000000 ] && { ok=1; break; }
done
rm -f "$t.gz"
if [ -z "$ok" ]; then rm -f "$t"; echo "Couldn't download the IP-to-country database from db-ip.com."; exit 1; fi
chmod 644 "$t"
mv -f "$t" "$dir/country.mmdb"
if [ -f ` + GeoConf + ` ] && nginx -t >/dev/null 2>&1; then nginx -s reload >/dev/null 2>&1; fi
exit 0
`

// geoPackage is the package holding the GeoIP2 module.
func geoPackage(pm string) string {
	switch pm {
	case "apt-get":
		return "libnginx-mod-http-geoip2"
	case "dnf", "yum", "apk":
		return "nginx-mod-http-geoip2"
	}
	return ""
}

func (Driver) GeoScript(su proxy.Setup) string {
	module := `echo "Add nginx's GeoIP2 module by hand: no package for it is known here."`
	if pkg := geoPackage(su.PM); pkg != "" {
		module = `echo "Adding nginx's GeoIP2 module…"
if ! { ` + su.Install(pkg) + `; } >/dev/null 2>&1; then echo "The package manager couldn't add ` + pkg + `."; fi`
	}
	fetcher := `echo "Neither curl nor wget is here: install one, then try again."; exit 1`
	if su.PM != "" {
		fetcher = `{ ` + su.Install("curl") + `; } >/dev/null 2>&1 || { echo "Couldn't install curl."; exit 1; }`
	}
	test := strconv.Itoa(proxy.ExitTestFailed)
	return head + `command -v nginx >/dev/null 2>&1 || exit ` + strconv.Itoa(proxy.ExitNotInstalled) + `
if ! out=$(nginx -t 2>&1); then printf '%s\n' "$out"; echo "nginx's configuration already has a problem; fix it first."; exit ` + test + `; fi
` + module + `
command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || ` + fetcher + `
mkdir -p ` + GeoDir + ` || exit 1
cat > ` + GeoUpdate + ` <<'MORCHEH_GEO_UPDATE'
` + geoUpdate + `MORCHEH_GEO_UPDATE
chmod 755 ` + GeoUpdate + `
echo "Downloading the IP-to-country database (DB-IP Lite)…"
` + GeoUpdate + ` || exit 1
cat > ` + GeoConf + ` <<'MORCHEH_GEO_CONF'
` + geoConf + `MORCHEH_GEO_CONF
chmod 644 ` + GeoConf + `
` + writeInclude() + `if ! out=$(nginx -t 2>&1); then
  rm -f ` + GeoConf + `
  printf '%s\n' "$out"
  echo "nginx couldn't load the GeoIP2 module, so country rules can't be used on this server."
  exit ` + test + `
fi
done_cron=
for d in /etc/cron.monthly /etc/periodic/monthly; do
  [ -d "$d" ] || continue
  printf '#!/bin/sh\n` + marker + `\nexec ` + GeoUpdate + ` >/dev/null 2>&1\n' > "$d/morcheh-geoip"
  chmod 755 "$d/morcheh-geoip"; done_cron=1; break
done
[ -n "$done_cron" ] || echo "No monthly cron folder here: run ` + GeoUpdate + ` now and then to keep the countries current."
if running; then nginx -s reload || exit ` + strconv.Itoa(proxy.ExitReloadFailed) + `; fi
echo "Country lookup is ready."
`
}
