package nginx

import (
	"strconv"

	"github.com/morcheh/backend/internal/proxy"
)

// brotliPackage is the distribution's package with the Brotli filter module
// (what `brotli on` needs; brotli_static isn't used).
func brotliPackage(pm string) string {
	switch pm {
	case "apt-get":
		return "libnginx-mod-http-brotli-filter"
	case "apk":
		return "nginx-mod-http-brotli"
	}
	return ""
}

// brotliLoaded is true when nginx's configuration loads the module (or it
// was built in).
const brotliLoaded = `brotli_loaded() { nginx -T 2>/dev/null | grep -qE '^[[:space:]]*load_module[[:space:]][^;]*brotli' || nginx -V 2>&1 | grep -qi -- 'brotli'; }
`

// BrotliScript adds the Brotli module from the distribution's packages.
// The module packages only fit the distribution's own nginx, so a build
// from elsewhere (nginx.org, compiled) is left alone with a note.
func (Driver) BrotliScript(su proxy.Setup) string {
	test := strconv.Itoa(proxy.ExitTestFailed)
	pkg := brotliPackage(su.PM)
	install := `echo "No package for nginx's Brotli module is known on this system: add ngx_brotli by hand (it has to be built for this nginx version)."; exit 1`
	if pkg != "" {
		guard := ""
		if su.PM == "apt-get" {
			// nginx.org's package has no nginx-common; the distribution's
			// modules would pull the distribution's nginx in over it.
			guard = `if ! dpkg -s nginx-common >/dev/null 2>&1 && ! dpkg -s nginx-core >/dev/null 2>&1 && ! dpkg-query -W -f='${Maintainer}' nginx 2>/dev/null | grep -qiE 'debian|ubuntu'; then
  echo "This nginx doesn't come from the distribution's packages (nginx.org or built by hand?), so its Brotli module can't be installed from them. Add ngx_brotli by hand."
  exit 1
fi
`
		}
		install = guard + `echo "Installing ` + pkg + `…"
if ! { ` + su.Install(pkg) + `; }; then
  echo "The package manager couldn't install ` + pkg + ` (Debian 12+, Ubuntu 23.04+ and Alpine have it)."
  exit 1
fi
`
	}
	return head + brotliLoaded + `command -v nginx >/dev/null 2>&1 || exit ` + strconv.Itoa(proxy.ExitNotInstalled) + `
if brotli_loaded; then echo "The Brotli module is already loaded."; exit 0; fi
if ! out=$(nginx -t 2>&1); then printf '%s\n' "$out"; echo "nginx's configuration already has a problem; fix it first."; exit ` + test + `; fi
` + install + `if ! out=$(nginx -t 2>&1); then
  printf '%s\n' "$out"
  echo "nginx doesn't accept the Brotli module."
  exit ` + test + `
fi
if ! brotli_loaded; then echo "The package is installed, but nginx doesn't load the Brotli module."; exit ` + test + `; fi
if running; then nginx -s reload || exit ` + strconv.Itoa(proxy.ExitReloadFailed) + `; fi
echo "Brotli is ready."
`
}
