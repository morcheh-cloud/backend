package registry

import (
	"strings"
)

// HarborConfig is what harbor.yml is written from.
type HarborConfig struct {
	Dir           string // the installer's folder (holds harbor.yml, docker-compose.yml)
	Hostname      string // the name clients use, or the server's address
	ExternalURL   string // https://registry.example.com when behind a proxy, else ""
	Port          int    // http port, bound to 127.0.0.1 unless Open
	Open          bool   // listen on every address (no proxy in front)
	AdminPassword string
	DBPassword    string
	Scanner       bool
}

// HarborYML renders harbor.yml: plain http on Port (TLS is the reverse
// proxy's job), data and logs inside the project folder.
func HarborYML(c HarborConfig) string {
	var b strings.Builder
	w := func(s string) { b.WriteString(s + "\n") }
	w("# Written by Morche. Changes here are kept until Morche sets Harbor up again.")
	w("hostname: " + yamlStr(c.Hostname))
	w("http:")
	w("  port: " + itoa(c.Port))
	if c.ExternalURL != "" {
		w("external_url: " + yamlStr(c.ExternalURL))
	}
	w("harbor_admin_password: " + yamlStr(c.AdminPassword))
	w("database:")
	w("  password: " + yamlStr(c.DBPassword))
	w("  max_idle_conns: 50")
	w("  max_open_conns: 300")
	// Harbor's prepare script reads this line with awk: no quotes.
	w("data_volume: " + c.Dir + "/data")
	if c.Scanner {
		w("trivy:")
		w("  ignore_unfixed: false")
		w("  skip_update: false")
		w("  skip_java_db_update: false")
		w("  offline_scan: false")
		w("  security_check: vuln")
		w("  insecure: false")
		w("  timeout: 5m0s")
	}
	w("jobservice:")
	w("  max_job_workers: 4")
	w("  max_job_duration_hours: 24")
	w("  job_loggers:")
	w("    - STD_OUTPUT")
	w("    - FILE")
	w("  logger_sweeper_duration: 1")
	w("notification:")
	w("  webhook_job_max_retry: 3")
	w("  webhook_job_http_client_timeout: 3")
	w("log:")
	w("  level: info")
	w("  local:")
	w("    rotate_count: 10")
	w("    rotate_size: 100M")
	w("    location: " + yamlStr(c.Dir+"/logs"))
	w("_version: 2.15.0")
	w("proxy:")
	w("  http_proxy:")
	w("  https_proxy:")
	w("  no_proxy:")
	w("  components:")
	w("    - core")
	w("    - jobservice")
	w("    - trivy")
	w("upload_purging:")
	w("  enabled: true")
	w("  age: 168h")
	w("  interval: 24h")
	w("  dryrun: false")
	w("cache:")
	w("  enabled: false")
	w("  expire_hours: 24")
	return b.String()
}

func yamlStr(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// HarborInstallScript downloads Harbor's online installer (once), writes
// harbor.yml, runs its prepare step (which writes docker-compose.yml and
// the components' config), keeps the port on the loopback unless open,
// and starts it. (Harbor's own nginx passes on the X-Forwarded-Proto the
// reverse proxy in front sets.) Progress lines start with "==> ".
func HarborInstallScript(c HarborConfig, project string) string {
	q := Quote
	url := "https://github.com/goharbor/harbor/releases/download/" + HarborVersion + "/harbor-online-installer-" + HarborVersion + ".tgz"
	prepare := "./prepare"
	if c.Scanner {
		prepare += " --with-trivy"
	}
	bind := `sed -i -E 's/^([[:space:]]*-[[:space:]]*)"?` + itoa(c.Port) + `:8080"?[[:space:]]*$/\1"127.0.0.1:` + itoa(c.Port) + `:8080"/' docker-compose.yml`
	if c.Open {
		bind = "true"
	}
	return `set -e
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || { echo "Docker isn't installed or running on this server" >&2; exit ` + itoa(ExitNoDocker) + `; }
` + composeDetect + `mkdir -p ` + q(c.Dir) + `
cd ` + q(c.Dir) + `
if [ ! -x ./prepare ] || [ "$(cat .morche-version 2>/dev/null)" != ` + q(HarborVersion) + ` ]; then
  echo "==> Downloading Harbor ` + HarborVersion + `"
  if command -v curl >/dev/null 2>&1; then curl -fsSL --retry 3 -o harbor.tgz ` + q(url) + ` || { echo "Couldn't download Harbor's installer from GitHub" >&2; exit ` + itoa(ExitNoFetch) + `; }
  elif command -v wget >/dev/null 2>&1; then wget -q -O harbor.tgz ` + q(url) + ` || { echo "Couldn't download Harbor's installer from GitHub" >&2; exit ` + itoa(ExitNoFetch) + `; }
  else echo "Neither curl nor wget is installed" >&2; exit ` + itoa(ExitNoFetch) + `; fi
  tar xzf harbor.tgz --strip-components=1
  rm -f harbor.tgz
  printf '%s' ` + q(HarborVersion) + ` > .morche-version
fi
umask 077
` + writeFile(c.Dir+"/harbor.yml", HarborYML(c)) + `umask 022
mkdir -p data logs
echo "==> Preparing the configuration"
` + prepare + ` > .morche-prepare.log 2>&1 || { tail -n 20 .morche-prepare.log >&2; echo "Harbor's prepare step failed" >&2; exit 1; }
grep -v '^[[:space:]]*$' .morche-prepare.log | tail -n 15
` + bind + `
# Harbor's containers log to tcp://localhost:1514, which Docker may resolve
# to ::1 while the log container only listens on 127.0.0.1.
sed -i 's#tcp://localhost:1514#tcp://127.0.0.1:1514#g' docker-compose.yml
# harbor-log's sudo (to run rsyslog as syslog) needs DAC_READ_SEARCH with
# newer PAM/Docker, or it restarts for ever and nothing else can log.
awk '/^  log:$/{inlog=1} /^  [a-z]/ && !/^  log:$/{inlog=0} {print} inlog && /^      - DAC_OVERRIDE$/ && !done {print "      - DAC_READ_SEARCH"; done=1}' docker-compose.yml > docker-compose.yml.morche && mv docker-compose.yml.morche docker-compose.yml
echo "==> Pulling the images"
$C -p ` + q(project) + ` pull 2>&1 | grep -Ev '^\s*$' | tail -n 40
echo "==> Starting Harbor"
# Every container logs through harbor-log: start it first and wait until it
# takes connections, or the others fail to start.
$C -p ` + q(project) + ` up -d log 2>&1
i=0
while [ $i -lt 30 ]; do
  if command -v bash >/dev/null 2>&1; then bash -c ': >/dev/tcp/127.0.0.1/1514' 2>/dev/null && break
  elif command -v nc >/dev/null 2>&1; then nc -z 127.0.0.1 1514 2>/dev/null && break
  else sleep 5; break; fi
  i=$((i+1)); sleep 1
done
n=0
until $C -p ` + q(project) + ` up -d 2>&1; do
  n=$((n+1)); [ $n -ge 3 ] && exit 1
  echo "Some containers didn't start yet; trying again in 5 seconds"
  sleep 5
done
`
}

// HarborDBPassword reads the database password from a harbor.yml written
// before: a second deploy must keep it, or Harbor can't open its database.
func HarborDBPassword(yml string) string {
	in := false
	for l := range strings.SplitSeq(yml, "\n") {
		switch {
		case strings.HasPrefix(l, "database:"):
			in = true
		case in && strings.HasPrefix(l, "  password:"):
			v := strings.TrimSpace(strings.TrimPrefix(l, "  password:"))
			v = strings.TrimSuffix(strings.TrimPrefix(v, `"`), `"`)
			return strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(v)
		case in && l != "" && l[0] != ' ':
			in = false
		}
	}
	return ""
}

// HarborContainers are the fixed container names Harbor's compose file uses.
var HarborContainers = []string{"harbor-log", "registry", "registryctl", "harbor-db", "harbor-core", "harbor-portal",
	"harbor-jobservice", "redis", "nginx", "trivy-adapter"}
