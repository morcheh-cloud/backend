package nginx

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/morcheh/backend/internal/proxy"
)

// Extra modules from the distribution's packages: Brotli, the ModSecurity
// firewall with the OWASP Core Rule Set, image resizing, and GeoIP2 for
// port forwards. The module packages only fit the distribution's own nginx,
// so a build from elsewhere (nginx.org, compiled) is left alone with a note.

const (
	// WAFDir holds the firewall's settings: base.conf (the engine) and
	// crs.conf (base + the Core Rule Set), loaded by every site that has it
	// on.
	WAFDir  = Dir + "/waf"
	WAFBase = WAFDir + "/base.conf"
	WAFConf = WAFDir + "/crs.conf"
	// wafLogDir holds one firewall log per site, outside nginx's own logs
	// (whose rotation would leave ModSecurity writing to the old file).
	wafLogDir = logDir + "/morcheh-waf"
	// wafRotate keeps those logs small.
	wafRotate = "/etc/logrotate.d/morcheh-waf"
)

// WAFLog is a host's firewall log: one JSON line per flagged request.
func WAFLog(id string) string { return wafLogDir + "/" + id + ".log" }

// moduleSpec is how one module is added.
type moduleSpec struct {
	label string // like "the Brotli module"
	// pkgs are the packages for a package manager (nil = none known).
	pkgs func(pm string) []string
	// loaded is a shell test that's true when nginx loads the module.
	loaded string
	// manual says what to do when no package is known.
	manual string
	// pre runs before anything is installed (exit to stop).
	pre func(su proxy.Setup) string
	// post sets the module up once it loads: files, then its own test.
	post func(su proxy.Setup) string
	done string
}

// loadedTest is true when nginx's configuration loads a module whose file
// name matches re, or it was built in (static matches nginx -V).
func loadedTest(re, static string) string {
	t := `nginx -T 2>/dev/null | grep -qE '^[[:space:]]*load_module[[:space:]][^;]*` + re + `'`
	if static != "" {
		t += ` || nginx -V 2>&1 | grep -qE -- '` + static + `'`
	}
	return t
}

var moduleSpecs = map[string]moduleSpec{
	proxy.ModuleBrotli: {
		label: "the Brotli module",
		pkgs: func(pm string) []string {
			switch pm {
			case "apt-get":
				return []string{"libnginx-mod-http-brotli-filter"}
			case "apk":
				return []string{"nginx-mod-http-brotli"}
			}
			return nil
		},
		loaded: loadedTest("brotli", "brotli"),
		manual: "Add ngx_brotli by hand (it has to be built for this nginx version).",
		done:   "Brotli is ready.",
	},
	proxy.ModuleWAF: {
		label: "the ModSecurity firewall",
		pkgs: func(pm string) []string {
			if pm == "apt-get" {
				return []string{"libnginx-mod-http-modsecurity", "modsecurity-crs"}
			}
			return nil
		},
		loaded: loadedTest("modsecurity", "modsecurity"),
		manual: "Install ModSecurity for nginx and the OWASP Core Rule Set by hand, then try again.",
		post:   wafPost,
		done:   "The firewall is ready: turn it on in a site's Security tab.",
	},
	proxy.ModuleImageFilter: {
		label: "the image resizing module",
		pkgs: func(pm string) []string {
			switch pm {
			case "apt-get":
				return []string{"libnginx-mod-http-image-filter"}
			case "dnf", "yum", "apk":
				return []string{"nginx-mod-http-image-filter"}
			}
			return nil
		},
		loaded: loadedTest("image_filter", "--with-http_image_filter_module( |$)"),
		manual: "Add nginx's image_filter module by hand (it has to be built for this nginx version).",
		done:   "Image resizing is ready.",
	},
	proxy.ModuleStreamGeo: {
		label: "GeoIP2 for port forwards",
		pkgs: func(pm string) []string {
			switch pm {
			case "apt-get":
				return []string{"libnginx-mod-stream-geoip2"}
			case "dnf", "yum", "apk":
				return []string{"nginx-mod-stream-geoip2"}
			}
			return nil
		},
		loaded: loadedTest("ngx_stream_geoip2", ""),
		manual: "Add nginx's stream GeoIP2 module by hand (it has to be built for this nginx version).",
		pre: func(proxy.Setup) string {
			return streamFns + `if [ "$(stream_state)" != ready ]; then echo "Port forwarding isn't set up on this server yet: add a port forward first."; exit 1; fi
`
		},
		post: streamGeoPost,
		done: "Port forwards can use countries now.",
	},
}

// ModuleScript adds a module from the distribution's packages and sets it
// up; it exits 0 at once when there's nothing to do.
func (Driver) ModuleScript(module string, su proxy.Setup) string {
	m, ok := moduleSpecs[module]
	if !ok {
		return `echo "Unknown module."; exit 1`
	}
	test := strconv.Itoa(proxy.ExitTestFailed)
	pkgs := m.pkgs(su.PM)
	install := `echo "No package for ` + m.label + ` is known on this system. ` + m.manual + `"; exit 1
`
	if len(pkgs) > 0 {
		list := strings.Join(pkgs, " ")
		guard := ""
		if su.PM == "apt-get" {
			// nginx.org's package has no nginx-common; the distribution's
			// modules would pull the distribution's nginx in over it.
			guard = `if ! dpkg -s nginx-common >/dev/null 2>&1 && ! dpkg -s nginx-core >/dev/null 2>&1 && ! dpkg-query -W -f='${Maintainer}' nginx 2>/dev/null | grep -qiE 'debian|ubuntu'; then
  echo "This nginx doesn't come from the distribution's packages (nginx.org or built by hand?), so ` + m.label + ` can't be installed from them. ` + m.manual + `"
  exit 1
fi
`
		}
		install = guard + `echo "Installing ` + list + `…"
if ! { ` + su.Install(pkgs...) + `; }; then
  echo "The package manager couldn't install ` + list + `."
  exit 1
fi
`
	}
	pre, post, need := "", "", "mod_loaded"
	if m.pre != nil {
		pre = m.pre(su)
	}
	if m.post != nil {
		post = m.post(su)
	} else {
		pre += `if mod_loaded; then echo "` + capital(m.label) + ` is already loaded."; exit 0; fi
`
	}
	if module == proxy.ModuleWAF {
		// The rule set may be missing while the module is there.
		need = "mod_loaded && waf_crs >/dev/null"
	}
	return head + `mod_loaded() { ` + m.loaded + `; }
` + wafCRSFn + `command -v nginx >/dev/null 2>&1 || exit ` + strconv.Itoa(proxy.ExitNotInstalled) + `
if ! out=$(nginx -t 2>&1); then printf '%s\n' "$out"; echo "nginx's configuration already has a problem; fix it first."; exit ` + test + `; fi
` + pre + `if ! { ` + need + `; }; then
` + install + `  if ! out=$(nginx -t 2>&1); then
    printf '%s\n' "$out"
    echo "nginx doesn't accept ` + m.label + `."
    exit ` + test + `
  fi
fi
if ! mod_loaded; then echo "The package is installed, but nginx doesn't load ` + m.label + `."; exit ` + test + `; fi
` + post + `if running; then nginx -s reload || exit ` + strconv.Itoa(proxy.ExitReloadFailed) + `; fi
echo "` + m.done + `"
`
}

func capital(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// wafCRSFn prints the Core Rule Set's setup file and rules folder, as
// "setup rules", or fails when it isn't there.
const wafCRSFn = `waf_crs() {
  s=; r=
  for f in /etc/modsecurity/crs/crs-setup.conf /etc/modsecurity/crs-setup.conf /usr/share/modsecurity-crs/crs-setup.conf /etc/nginx/modsec/crs-setup.conf; do [ -f "$f" ] && { s=$f; break; }; done
  for d in /usr/share/modsecurity-crs/rules /etc/modsecurity/crs/rules /usr/share/owasp-modsecurity-crs/rules /etc/nginx/modsec/rules; do ls "$d"/REQUEST-*.conf >/dev/null 2>&1 && { r=$d; break; }; done
  [ -n "$s" ] && [ -n "$r" ] && echo "$s $r"
}
`

// wafBase is the engine's settings: requests (and their bodies) are read,
// answers aren't; flagged requests are logged as JSON lines, per site
// (SecAuditLog is set by each site).
const wafBase = marker + `: the firewall's engine settings, loaded by every site with the firewall on.
SecRequestBodyAccess On
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction ProcessPartial
SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"
SecPcreMatchLimit 100000
SecPcreMatchLimitRecursion 100000
SecResponseBodyAccess Off
SecTmpDir /tmp/
SecDataDir /tmp/
SecArgumentSeparator &
SecCookieFormat 0
SecStatusEngine Off
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts AHZ
SecAuditLogType Serial
SecAuditLogFormat JSON
`

func wafPost(proxy.Setup) string {
	test := strconv.Itoa(proxy.ExitTestFailed)
	return `crs=$(waf_crs) || { echo "The OWASP Core Rule Set isn't here (looked in /usr/share/modsecurity-crs and /etc/modsecurity). Install it, then try again."; exit 1; }
setup=${crs% *}; rules=${crs#* }
mkdir -p ` + WAFDir + ` ` + wafLogDir + ` || exit 1
chmod 755 ` + wafLogDir + `
cat > ` + WAFBase + ` <<'MORCHEH_WAF_BASE'
` + wafBase + `MORCHEH_WAF_BASE
for u in /etc/nginx/unicode.mapping /etc/modsecurity/unicode.mapping /usr/share/modsecurity-crs/unicode.mapping; do
  [ -f "$u" ] && { echo "SecUnicodeMapFile $u 20127" >> ` + WAFBase + `; break; }
done
{
  echo '` + marker + `: the firewall with the OWASP Core Rule Set.'
  echo 'Include ` + WAFBase + `'
  echo "Include $setup"
  d=${setup%/*}
  [ -f "$d/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf" ] && echo "Include $d/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
  echo "Include $rules/*.conf"
  [ -f "$d/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf" ] && echo "Include $d/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf"
} > ` + WAFConf + `
chmod 644 ` + WAFBase + ` ` + WAFConf + `
if [ -d /etc/logrotate.d ]; then
  printf '%s\n' '` + marker + `' '` + wafLogDir + `/*.log {' '    weekly' '    rotate 4' '    maxsize 20M' '    missingok' '    notifempty' '    compress' '    delaycompress' '    copytruncate' '}' > ` + wafRotate + `
fi
# The rules only load where a site uses them: try them once in http {}.
t="$inc/zz-morcheh-waf-test.conf"
echo 'modsecurity_rules_file ` + WAFConf + `;' > "$t"
if ! out=$(nginx -t 2>&1); then
  rm -f "$t"
  printf '%s\n' "$out"
  echo "ModSecurity doesn't accept the Core Rule Set here."
  exit ` + test + `
fi
rm -f "$t"
`
}

const geoStreamConf = marker + `: the visitor's country for port forwards' country rules.
geoip2 ` + GeoDB + ` {
    ` + countryVar + ` country iso_code;
}
`

func streamGeoPost(su proxy.Setup) string {
	test := strconv.Itoa(proxy.ExitTestFailed)
	return `if [ ! -s ` + GeoDB + ` ]; then
` + geoData(su) + geoCronPart + `fi
cat > ` + GeoStream + ` <<'MORCHEH_GEO_STREAM'
` + geoStreamConf + `MORCHEH_GEO_STREAM
chmod 644 ` + GeoStream + `
write_stream || exit 1
if ! out=$(nginx -t 2>&1); then
  rm -f ` + GeoStream + `
  printf '%s\n' "$out"
  echo "nginx couldn't load GeoIP2 for port forwards."
  exit ` + test + `
fi
`
}

// WAFEventsScript prints a host's newest firewall log lines.
func (Driver) WAFEventsScript(hostID string, limit int) string {
	return `tail -n ` + strconv.Itoa(limit) + ` ` + WAFLog(hostID) + ` 2>/dev/null; exit 0
`
}

// wafLine is the part of ModSecurity's JSON audit record that's read.
type wafLine struct {
	Transaction struct {
		ClientIP  string `json:"client_ip"`
		TimeStamp string `json:"time_stamp"`
		UniqueID  string `json:"unique_id"`
		Request   struct {
			Method string `json:"method"`
			URI    string `json:"uri"`
		} `json:"request"`
		Response struct {
			HTTPCode int `json:"http_code"`
		} `json:"response"`
		Producer struct {
			Engine string `json:"secrules_engine"`
		} `json:"producer"`
		Messages []struct {
			Message string `json:"message"`
			Details struct {
				RuleID   string `json:"ruleId"`
				Data     string `json:"data"`
				Severity string `json:"severity"`
			} `json:"details"`
		} `json:"messages"`
	} `json:"transaction"`
}

// ParseWAFEvents reads WAFEventsScript's output, newest first. The
// anomaly-score summaries (949110, 980130…) stay: they say why a request
// was refused.
func (d Driver) ParseWAFEvents(out string) []proxy.WAFEvent {
	return d.ParseWAFLines(strings.Split(out, "\n"))
}

// refusing says a matched rule stops the request when the engine is on:
// the anomaly-score totals, and Morcheh's own unreadable-body rule.
func refusing(id string) bool {
	return strings.HasPrefix(id, "949") || strings.HasPrefix(id, "959") || id == "200002"
}

// ParseWAFLines reads firewall log lines (oldest first), newest first.
func (Driver) ParseWAFLines(lines []string) []proxy.WAFEvent {
	events := []proxy.WAFEvent{}
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(l, "{") {
			continue
		}
		var x wafLine
		if json.Unmarshal([]byte(l), &x) != nil {
			continue
		}
		t := x.Transaction
		// The audit log also keeps 5xx answers no rule matched (the app was
		// down): those aren't the firewall's doing.
		if len(t.Messages) == 0 {
			continue
		}
		e := proxy.WAFEvent{
			Time: t.TimeStamp, IP: t.ClientIP, Method: t.Request.Method,
			URI: t.Request.URI, Status: t.Response.HTTPCode, ID: t.UniqueID,
			Rules: []proxy.WAFMatch{},
		}
		for _, m := range t.Messages {
			e.Rules = append(e.Rules, proxy.WAFMatch{
				ID: m.Details.RuleID, Message: m.Message,
				Data: m.Details.Data, Severity: m.Details.Severity,
			})
			if t.Producer.Engine == "Enabled" && refusing(m.Details.RuleID) {
				e.Blocked = true
			}
		}
		events = append(events, e)
	}
	return events
}

// ---- Rendering ----

// wafServer turns the firewall on for a site. The paranoia level and score
// go before the rule set (its setup reads them once), the rules turned off
// after it (they must exist by then).
func wafServer(w *writer, id string, h proxy.HostConfig) {
	f := h.WAF
	if !f.On() {
		return
	}
	engine := "On"
	if f.Mode == "detect" {
		engine = "DetectionOnly"
	}
	w.line("")
	w.line("# Firewall (ModSecurity + OWASP Core Rule Set)")
	w.line("modsecurity on;")
	// The firewall log then names requests as the access log does, so a
	// request in the site's logs shows what the firewall made of it.
	w.line(`modsecurity_transaction_id "$request_id";`)
	w.line("modsecurity_rules '")
	w.depth++
	w.line(`SecAction "id:10001,phase:1,pass,nolog,t:none,setvar:tx.paranoia_level=%d"`, f.Paranoia)
	w.line(`SecAction "id:10002,phase:1,pass,nolog,t:none,setvar:tx.inbound_anomaly_score_threshold=%d"`, f.Threshold)
	for i, p := range f.SkipPaths {
		w.line(`SecRule REQUEST_FILENAME "@beginsWith %s" "id:%d,phase:1,pass,nolog,t:none,ctl:ruleEngine=Off"`, p, 10100+i)
	}
	w.depth--
	w.line("';")
	w.line("modsecurity_rules_file %s;", WAFConf)
	w.line("modsecurity_rules '")
	w.depth++
	w.line("SecRuleEngine %s", engine)
	w.line("SecAuditLog %s", WAFLog(id))
	if len(f.SkipRules) > 0 {
		ids := make([]string, len(f.SkipRules))
		for i, r := range f.SkipRules {
			ids[i] = strconv.Itoa(r)
		}
		w.line("SecRuleRemoveById %s", strings.Join(ids, " "))
	}
	w.depth--
	w.line("';")
}

// imageLocation is where a picture asked for with an allowed ?w= or ?h= is
// sent (location / rewrites to it): the file is fetched as usual, then
// resized.
const imageLocation = internalPrefix + "img"

// imageBlocks are the http-level maps: the allowed sizes and whether a
// request is a picture to resize.
func imageBlocks(w *writer, t string, h proxy.HostConfig) {
	if !h.Images.Enabled {
		return
	}
	w.line("")
	w.line("# Images resized with ?w= and ?h= (only these sizes).")
	for _, d := range []string{"w", "h"} {
		w.open("map $arg_%s $%s_i%s", d, t, d)
		w.line("default -;")
		for _, s := range h.Images.SizesOrDefault() {
			w.line("%d %d;", s, s)
		}
		w.close()
	}
	w.open(`map "$%s_iw$%s_ih:$uri" $%s_img`, t, t, t)
	w.line("volatile;")
	w.line("default 0;")
	w.line(`"~^--:" 0;`)
	w.line(`"~*\.(jpe?g|png|gif|webp)$" 1;`)
	w.close()
}

// imageRoute sends pictures to resize to imageLocation (inside location /).
func imageRoute(w *writer, t string, h proxy.HostConfig) {
	if !h.Images.Enabled {
		return
	}
	w.open("if ($%s_img)", t)
	w.line("rewrite ^ %s$uri last;", imageLocation)
	w.close()
}

// imageServe is the resizing location; serve fetches the file the way the
// site does (its URI is the original one again).
func imageServe(w *writer, t string, h proxy.HostConfig, serve func()) {
	im := h.Images
	if !im.Enabled {
		return
	}
	q := im.Quality
	if q == 0 {
		q = 80
	}
	size := im.MaxSizeMB
	if size == 0 {
		size = 10
	}
	w.line("")
	w.open("location ^~ %s/", imageLocation)
	w.line("internal;")
	flag := " break"
	if h.Type == proxy.TypeStorage {
		// The storage's own rewrites follow.
		flag = ""
	}
	w.line("rewrite ^%s(/.*)$ $1%s;", regexp.QuoteMeta(imageLocation), flag)
	serve()
	w.line("image_filter %s $%s_iw $%s_ih;", im.Mode, t, t)
	w.line("image_filter_buffer %dM;", size)
	w.line("image_filter_jpeg_quality %d;", q)
	w.line("image_filter_webp_quality %d;", q)
	w.line("image_filter_interlace on;")
	w.close()
}
