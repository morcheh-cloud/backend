package software

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
)

// lib is prepended to every script: which package manager the server has,
// and the same few operations on each.
const lib = `export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a LC_ALL=C
PM=none
for p in apt-get dnf yum zypper apk pacman; do
  if command -v "$p" >/dev/null 2>&1; then
    case "$p" in apt-get) PM=apt ;; *) PM=$p ;; esac
    break
  fi
done
# Another package manager (unattended-upgrades, a person's apt…) holds the
# lock: wait for it, up to 15 minutes, instead of failing at once. apt also
# waits on its own when it starts while the lock is taken.
APT_LOCK="-o DPkg::Lock::Timeout=900"
export ZYPP_LOCK_TIMEOUT=900
pkg_holder() {
  case "$PM" in
    apt)
      # The lock files say it best; fuser isn't always there.
      if command -v fuser >/dev/null 2>&1 && fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock >/dev/null 2>&1; then
        echo "another apt or dpkg"
        return 0
      fi
      # unattended-upgrade-shutdown (same short name) idles all day: skip it.
      for pid in $(pgrep -x unattended-upgr 2>/dev/null); do
        if ! tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -q shutdown; then
          echo "unattended-upgrades ($pid)"
          return 0
        fi
      done
      names="apt apt-get aptitude dpkg" ;;
    dnf) names="dnf dnf5 rpm" ;;
    yum) names="yum rpm" ;;
    zypper) names="zypper rpm" ;;
    apk) names="apk" ;;
    pacman) names="pacman" ;;
    *) return 1 ;;
  esac
  for n in $names; do
    pid=$(pgrep -x "$n" 2>/dev/null | head -n1)
    if [ -n "$pid" ]; then
      echo "$n ($pid)"
      return 0
    fi
  done
  return 1
}
pkg_wait() {
  command -v pgrep >/dev/null 2>&1 || return 0
  waited=0
  while holder=$(pkg_holder); do
    if [ "$waited" -eq 0 ]; then
      echo "Another package manager is running: $holder. Waiting for it to finish…"
    fi
    if [ "$waited" -ge 900 ]; then
      echo "It's still running after 15 minutes: $holder. Try again once it's done." >&2
      return 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
  if [ "$waited" -gt 0 ]; then echo "It finished after $waited s; going on."; fi
}
pkg_refresh() {
  pkg_wait || return 1
  case "$PM" in
    apt) apt-get $APT_LOCK update -q ;;
    dnf) dnf -q -y makecache ;;
    yum) yum -q -y makecache ;;
    zypper) zypper -q -n refresh ;;
    apk) apk update -q ;;
    pacman) pacman -Sy --noconfirm ;;
    *) echo "This server has no package manager Morcheh knows (apt, dnf, yum, zypper, apk, pacman)." >&2; return 1 ;;
  esac
}
pkg_install() {
  pkg_wait || return 1
  case "$PM" in
    apt) apt-get $APT_LOCK install -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@" ;;
    dnf) dnf install -y -q "$@" ;;
    yum) yum install -y -q "$@" ;;
    zypper) zypper -n -q install "$@" ;;
    apk) apk add -q "$@" ;;
    pacman) pacman -S --noconfirm --needed "$@" ;;
    *) echo "This server has no package manager Morcheh knows." >&2; return 1 ;;
  esac
}
pkg_remove() {
  pkg_wait || return 1
  case "$PM" in
    apt) apt-get $APT_LOCK remove -y -q "$@" ;;
    dnf) dnf remove -y -q "$@" ;;
    yum) yum remove -y -q "$@" ;;
    zypper) zypper -n -q remove "$@" ;;
    apk) apk del -q "$@" ;;
    pacman) pacman -R --noconfirm "$@" ;;
    *) return 1 ;;
  esac
}
pkg_upgrade() {
  pkg_wait || return 1
  case "$PM" in
    apt) apt-get $APT_LOCK install -y -q --only-upgrade -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@" ;;
    dnf) dnf upgrade -y -q "$@" ;;
    yum) yum update -y -q "$@" ;;
    zypper) zypper -n -q update "$@" ;;
    apk) apk add -u -q "$@" ;;
    pacman) pacman -S --noconfirm "$@" ;;
    *) return 1 ;;
  esac
}
pkg_version() {
  case "$PM" in
    apt) dpkg-query -W -f='${Status} ${Version}\n' "$1" 2>/dev/null | awk '$3=="installed"{print $4; exit}' ;;
    dnf|yum|zypper) rpm -q --qf '%{VERSION}-%{RELEASE}\n' "$1" 2>/dev/null | grep -v 'not installed' | head -n1 ;;
    apk) apk list -I "$1" 2>/dev/null | awk '{print $1; exit}' | sed "s/^$1-//" ;;
    pacman) pacman -Q "$1" 2>/dev/null | awk '{print $2; exit}' ;;
  esac
}
pkg_latest() {
  case "$PM" in
    apt) apt-cache policy "$1" 2>/dev/null | awk '/Candidate:/{if ($2 != "(none)") print $2; exit}' ;;
    dnf) dnf -q list --upgrades "$1" 2>/dev/null | awk -v p="$1" 'index($1, p".")==1 {print $2; exit}' ;;
    yum) yum -q list updates "$1" 2>/dev/null | awk -v p="$1" 'index($1, p".")==1 {print $2; exit}' ;;
    apk) apk list -u "$1" 2>/dev/null | awk '{print $1; exit}' | sed "s/^$1-//" ;;
    pacman) pacman -Qu "$1" 2>/dev/null | awk '{print $4; exit}' ;;
  esac
}
# The ones of the named packages that are installed here.
pkg_have() {
  have=""
  for p in "$@"; do
    if [ -n "$(pkg_version "$p")" ]; then have="$have $p"; fi
  done
  echo "${have# }"
}
need_root() {
  if [ "$(id -u)" != 0 ]; then echo "This needs root: the login user can't use sudo." >&2; exit 1; fi
}
need_compose() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker isn't installed on this server. Install Docker first (it's in Applications)." >&2; exit 1
  fi
  if ! docker compose version >/dev/null 2>&1; then
    echo "Docker's compose plugin isn't installed on this server. Install or update Docker from Applications." >&2; exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "Docker is installed but not running (or can't be reached)." >&2; exit 1
  fi
}
# wait_up waits for every container of the project in this folder to be
# running (not restarting) twice in a row, and shows the logs if not.
wait_up() {
  i=0; ok=0
  while [ "$i" -lt "${1:-90}" ]; do
    sleep 3; i=$((i + 3))
    all=$(docker compose ps -a -q 2>/dev/null | wc -l)
    up=$(docker compose ps -q --status running 2>/dev/null | wc -l)
    bad=$(docker compose ps -q --status restarting 2>/dev/null | wc -l)
    if [ "$all" -gt 0 ] && [ "$up" -eq "$all" ] && [ "$bad" -eq 0 ]; then
      ok=$((ok + 1))
      if [ "$ok" -ge 2 ]; then echo "All containers are running."; return 0; fi
    else
      ok=0
    fi
  done
  echo "Not every container came up in ${1:-90} seconds:" >&2
  docker compose ps -a >&2
  echo "Last log lines:" >&2
  docker compose logs --no-color --tail 40 >&2
  return 1
}
`

// b64 writes content to a file through base64, so nothing in it is read by
// the shell.
func writeFile(b *strings.Builder, path, content, mode string) {
	enc := base64.StdEncoding.EncodeToString([]byte(content))
	fmt.Fprintf(b, "printf '%%s' '%s' | base64 -d > %s.new\n", enc, path)
	if mode != "" {
		fmt.Fprintf(b, "chmod %s %s.new\n", mode, path)
	}
	fmt.Fprintf(b, "mv -f %s.new %s\n", path, path)
}

// pkgsCase sets PKGS to the recipe's packages for the server's manager.
func pkgsCase(r Recipe) string {
	return pmCase("PKGS", r.Packages) + pmCase("ALSO", r.Also)
}

// pmCase sets the shell variable name to the list for the server's package
// manager (yum takes dnf's when it has none of its own).
func pmCase(name string, lists map[string][]string) string {
	if len(lists) == 0 {
		return name + "=''\n"
	}
	var b strings.Builder
	b.WriteString("case \"$PM\" in\n")
	pms := make([]string, 0, len(lists))
	for pm := range lists {
		if pm != "default" {
			pms = append(pms, pm)
		}
	}
	sort.Strings(pms)
	for _, pm := range pms {
		fmt.Fprintf(&b, "  %s) %s=%q ;;\n", pm, name, strings.Join(lists[pm], " "))
	}
	if _, ok := lists["dnf"]; ok {
		if _, ok := lists["yum"]; !ok {
			fmt.Fprintf(&b, "  yum) %s=%q ;;\n", name, strings.Join(lists["dnf"], " "))
		}
	}
	fmt.Fprintf(&b, "  *) %s=%q ;;\n", name, strings.Join(lists["default"], " "))
	b.WriteString("esac\n")
	return b.String()
}

func osGuard(r Recipe) string {
	var b strings.Builder
	if r.Kind == KindPackage && r.Install == "" {
		b.WriteString("if [ -z \"$PKGS\" ]; then echo \"" + r.Name + " has no package for this server's package manager ($PM).\" >&2; exit 1; fi\n")
	}
	if len(r.OS) > 0 {
		fmt.Fprintf(&b, "case \"$PM\" in %s) ;; *) echo \"%s works only with %s (this server uses $PM).\" >&2; exit 1 ;; esac\n",
			strings.Join(r.OS, "|"), r.Name, strings.Join(r.OS, ", "))
	}
	return b.String()
}

// Env renders values as a compose .env file.
func Env(values map[string]string) string {
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("# Written by Morcheh. Change the settings from the panel.\n")
	for _, n := range names {
		fmt.Fprintf(&b, "%s='%s'\n", n, values[n])
	}
	return b.String()
}

// InstallOptions change an install.
type InstallOptions struct {
	// Docker apps: remove volumes left by an earlier install first.
	Fresh bool
}

// InstallScript installs r. Package and script recipes read values from the
// environment; a Docker app gets them in its .env file.
func InstallScript(r Recipe, values map[string]string, opt InstallOptions) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString(lib)
	b.WriteString("need_root\n")
	switch r.Kind {
	case KindDocker:
		dir, proj := Dir(r.ID), Project(r.ID)
		b.WriteString("need_compose\n")
		fmt.Fprintf(&b, "mkdir -p %s && chmod 700 %s && cd %s\n", dir, dir, dir)
		fmt.Fprintf(&b, "export COMPOSE_PROJECT_NAME=%s\n", proj)
		if opt.Fresh {
			b.WriteString("echo 'Removing data left by an earlier install…'\n")
			b.WriteString("docker compose down -v --remove-orphans >/dev/null 2>&1 || true\n")
			fmt.Fprintf(&b, "docker volume ls -q --filter label=com.docker.compose.project=%s | xargs -r docker volume rm >/dev/null 2>&1 || true\n", proj)
		}
		b.WriteString("rm -f compose.override.yml compose.rollback.yml\n")
		writeFile(&b, "compose.yml", r.Compose, "600")
		writeFile(&b, ".env", Env(values), "600")
		b.WriteString("echo 'Checking the compose file…'\n")
		b.WriteString("docker compose config -q\n")
		b.WriteString("echo 'Pulling images…'\n")
		b.WriteString("docker compose pull --quiet 2>&1 || docker compose pull\n")
		b.WriteString("echo 'Starting…'\n")
		b.WriteString("docker compose up -d --remove-orphans\n")
		b.WriteString("wait_up 120\n")
	default:
		if r.Kind == KindPackage {
			b.WriteString(pkgsCase(r))
		}
		b.WriteString(osGuard(r))
		if r.Install != "" {
			b.WriteString(r.Install)
			b.WriteString("\n")
		} else {
			b.WriteString("echo \"Installing $PKGS with $PM…\"\n")
			b.WriteString("pkg_refresh\n")
			b.WriteString("# shellcheck disable=SC2086\npkg_install $PKGS\n")
		}
	}
	return b.String()
}

// UpdateScript updates r to its newest version. A Docker app keeps the
// images it ran as morcheh-rollback/<project>-<service>:previous, with a
// compose.rollback.yml that runs them.
func UpdateScript(r Recipe) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString(lib)
	b.WriteString("need_root\n")
	switch r.Kind {
	case KindDocker:
		dir, proj := Dir(r.ID), Project(r.ID)
		b.WriteString("need_compose\n")
		fmt.Fprintf(&b, "cd %s\n", dir)
		fmt.Fprintf(&b, "export COMPOSE_PROJECT_NAME=%s\n", proj)
		b.WriteString("rm -f compose.override.yml\n")
		b.WriteString("echo 'Keeping the current images to go back to…'\n")
		b.WriteString("services=''\n")
		b.WriteString("for svc in $(docker compose config --services); do\n")
		b.WriteString("  cid=$(docker compose ps -a -q \"$svc\" | head -n1)\n")
		b.WriteString("  [ -n \"$cid\" ] || continue\n")
		b.WriteString("  img=$(docker inspect --format '{{.Image}}' \"$cid\")\n")
		fmt.Fprintf(&b, "  tag=\"morcheh-rollback/$(echo %s-$svc | tr 'A-Z_' 'a-z-'):previous\"\n", proj)
		b.WriteString("  docker tag \"$img\" \"$tag\" && services=\"$services $svc=$tag\"\n")
		b.WriteString("done\n")
		b.WriteString("if [ -n \"$services\" ]; then\n")
		b.WriteString("  { echo 'services:'; for s in $services; do printf '  %s:\\n    image: %s\\n    pull_policy: never\\n' \"${s%%=*}\" \"${s#*=}\"; done; } > compose.rollback.yml.new\n")
		b.WriteString("  chmod 600 compose.rollback.yml.new && mv -f compose.rollback.yml.new compose.rollback.yml\n")
		b.WriteString("fi\n")
		b.WriteString("echo 'Pulling new images…'\n")
		b.WriteString("docker compose pull --quiet 2>&1 || docker compose pull\n")
		b.WriteString("echo 'Starting…'\n")
		b.WriteString("docker compose up -d --remove-orphans\n")
		b.WriteString("wait_up 120\n")
		b.WriteString("docker image prune -f >/dev/null 2>&1 || true\n")
	default:
		if r.Kind == KindPackage {
			b.WriteString(pkgsCase(r))
		}
		b.WriteString(osGuard(r))
		switch {
		case r.Update != "":
			b.WriteString(r.Update)
			b.WriteString("\n")
		case r.Kind == KindPackage:
			// Only what is installed: the server may have the distro's
			// build (ALSO) or just some of the packages.
			b.WriteString("if [ -z \"$PKGS$ALSO\" ]; then echo 'There is no package to update on this server.' >&2; exit 1; fi\n")
			b.WriteString("# shellcheck disable=SC2086\nHAVE=$(pkg_have $PKGS $ALSO)\n")
			b.WriteString("if [ -z \"$HAVE\" ]; then echo \"None of its packages ($PKGS $ALSO) is installed with $PM here, so $PM can't update it. It may have been installed another way (a snap, a static binary…).\" >&2; exit 1; fi\n")
			b.WriteString("echo \"Updating $HAVE with $PM…\"\n")
			b.WriteString("pkg_refresh\n")
			b.WriteString("# shellcheck disable=SC2086\npkg_upgrade $HAVE\n")
		default:
			b.WriteString("echo 'This app has no update script.' >&2; exit 1\n")
		}
	}
	return b.String()
}

// RollbackScript runs a Docker app on the images it had before its last
// update, until the next update.
func RollbackScript(r Recipe) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString(lib)
	b.WriteString("need_root\nneed_compose\n")
	fmt.Fprintf(&b, "cd %s\n", Dir(r.ID))
	fmt.Fprintf(&b, "export COMPOSE_PROJECT_NAME=%s\n", Project(r.ID))
	b.WriteString("if [ ! -f compose.rollback.yml ]; then echo 'There is no earlier version to go back to.' >&2; exit 1; fi\n")
	b.WriteString("cp compose.rollback.yml compose.override.yml\n")
	b.WriteString("echo 'Starting the earlier version…'\n")
	b.WriteString("docker compose up -d --remove-orphans\n")
	b.WriteString("wait_up 120\n")
	return b.String()
}

// UninstallOptions change an uninstall.
type UninstallOptions struct {
	// Docker apps: remove its volumes and folder too.
	RemoveData bool
}

// UninstallScript removes r.
func UninstallScript(r Recipe, opt UninstallOptions) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString(lib)
	b.WriteString("need_root\n")
	switch r.Kind {
	case KindDocker:
		dir, proj := Dir(r.ID), Project(r.ID)
		b.WriteString("need_compose\n")
		fmt.Fprintf(&b, "export COMPOSE_PROJECT_NAME=%s\n", proj)
		fmt.Fprintf(&b, "if [ -d %s ]; then cd %s; fi\n", dir, dir)
		if opt.RemoveData {
			b.WriteString("echo 'Stopping and removing the containers and their data…'\n")
			b.WriteString("if [ -f compose.yml ]; then docker compose down -v --remove-orphans; fi\n")
			fmt.Fprintf(&b, "docker volume ls -q --filter label=com.docker.compose.project=%s | xargs -r docker volume rm >/dev/null 2>&1 || true\n", proj)
			fmt.Fprintf(&b, "docker images -q 'morcheh-rollback/%s-*' | xargs -r docker rmi -f >/dev/null 2>&1 || true\n", proj)
			fmt.Fprintf(&b, "cd / && rm -rf %s\n", dir)
		} else {
			b.WriteString("echo 'Stopping and removing the containers (the data stays)…'\n")
			b.WriteString("if [ -f compose.yml ]; then docker compose down --remove-orphans; fi\n")
			b.WriteString("rm -f compose.yml compose.override.yml compose.rollback.yml .env\n")
			fmt.Fprintf(&b, "echo 'Its volumes stay on the server: docker volume ls --filter label=com.docker.compose.project=%s'\n", proj)
		}
	default:
		if r.Kind == KindPackage {
			b.WriteString(pkgsCase(r))
		}
		switch {
		case r.Uninstall != "":
			b.WriteString(r.Uninstall)
			b.WriteString("\n")
		case r.Kind == KindPackage:
			b.WriteString("if [ -z \"$PKGS$ALSO\" ]; then echo 'There is no package to remove on this server.' >&2; exit 1; fi\n")
			b.WriteString("# shellcheck disable=SC2086\nHAVE=$(pkg_have $PKGS $ALSO)\n")
			b.WriteString("if [ -z \"$HAVE\" ]; then echo 'None of its packages is installed here; nothing to remove.'; exit 0; fi\n")
			b.WriteString("echo \"Removing $HAVE…\"\n")
			b.WriteString("# shellcheck disable=SC2086\npkg_remove $HAVE\n")
		default:
			b.WriteString("echo 'This app has no uninstall script.' >&2; exit 1\n")
		}
	}
	return b.String()
}

// SystemOptions change a system upgrade.
type SystemOptions struct {
	SecurityOnly bool
	// apt full-upgrade / dist-upgrade: may remove packages.
	Full bool
}

// SystemUpgradeScript upgrades every package on the server.
func SystemUpgradeScript(opt SystemOptions) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString(lib)
	b.WriteString("need_root\n")
	b.WriteString("echo \"Refreshing the package lists ($PM)…\"\n")
	b.WriteString("pkg_refresh\n")
	b.WriteString("pkg_wait\n")
	b.WriteString("case \"$PM\" in\n")
	b.WriteString("  apt)\n")
	o := "$APT_LOCK -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
	if opt.SecurityOnly {
		b.WriteString("    pkgs=$(apt list --upgradable 2>/dev/null | grep -e '-security' | cut -d/ -f1 | tr '\\n' ' ')\n")
		b.WriteString("    if [ -z \"$pkgs\" ]; then echo 'No security updates.'; exit 0; fi\n")
		fmt.Fprintf(&b, "    # shellcheck disable=SC2086\n    apt-get install --only-upgrade %s $pkgs ;;\n", o)
	} else if opt.Full {
		fmt.Fprintf(&b, "    apt-get full-upgrade %s && apt-get $APT_LOCK autoremove -y -q ;;\n", o)
	} else {
		fmt.Fprintf(&b, "    apt-get upgrade %s ;;\n", o)
	}
	if opt.SecurityOnly {
		b.WriteString("  dnf) dnf upgrade -y --security ;;\n")
		b.WriteString("  yum) yum update -y --security ;;\n")
		b.WriteString("  zypper) zypper -n patch --category security ;;\n")
		b.WriteString("  *) echo \"Security-only updates aren't supported with $PM.\" >&2; exit 1 ;;\n")
	} else {
		b.WriteString("  dnf) dnf upgrade -y ;;\n")
		b.WriteString("  yum) yum update -y ;;\n")
		b.WriteString("  zypper) zypper -n update ;;\n")
		b.WriteString("  apk) apk upgrade ;;\n")
		b.WriteString("  pacman) pacman -Su --noconfirm ;;\n")
		b.WriteString("  *) echo 'No package manager Morcheh knows.' >&2; exit 1 ;;\n")
	}
	b.WriteString("esac\n")
	b.WriteString("if [ -f /var/run/reboot-required ]; then echo 'The server needs a restart to finish.'; fi\n")
	return b.String()
}

// ComposeScript runs a compose command in a Docker app's folder.
func ComposeScript(id, args string) string {
	return ComposeAt(Dir(id), Project(id), args)
}

// ComposeAt runs a compose command for any compose project: one Morcheh
// installed, or one found on the server (its folder from the labels).
func ComposeAt(dir, project, args string) string {
	var b strings.Builder
	b.WriteString(lib)
	b.WriteString("need_compose\n")
	if dir != "" {
		fmt.Fprintf(&b, "cd %s || { echo 'Its folder is gone from the server.' >&2; exit 1; }\n", shellQuote(dir))
	}
	fmt.Fprintf(&b, "docker compose -p %s %s\n", shellQuote(project), args)
	return b.String()
}

// UpdateFoundScript pulls and restarts a compose project Morcheh didn't
// install, in its own folder. There's no going back for these.
func UpdateFoundScript(dir, project string) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString(lib)
	b.WriteString("need_root\nneed_compose\n")
	fmt.Fprintf(&b, "cd %s || { echo 'Its compose folder is gone from the server.' >&2; exit 1; }\n", shellQuote(dir))
	fmt.Fprintf(&b, "export COMPOSE_PROJECT_NAME=%s\n", shellQuote(project))
	b.WriteString("echo 'Pulling new images…'\n")
	b.WriteString("docker compose pull --quiet 2>&1 || docker compose pull\n")
	b.WriteString("echo 'Starting…'\n")
	b.WriteString("docker compose up -d\n")
	b.WriteString("wait_up 120\n")
	return b.String()
}

// shellQuote quotes s for sh.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// SaveComposeScript checks a new compose file, then puts it in place and
// applies it. The old one comes back if the check fails.
func SaveComposeScript(id, content string) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString(lib)
	b.WriteString("need_root\nneed_compose\n")
	fmt.Fprintf(&b, "cd %s\n", Dir(id))
	fmt.Fprintf(&b, "export COMPOSE_PROJECT_NAME=%s\n", Project(id))
	enc := base64.StdEncoding.EncodeToString([]byte(content))
	fmt.Fprintf(&b, "printf '%%s' '%s' | base64 -d > compose.check.yml\n", enc)
	b.WriteString("chmod 600 compose.check.yml\n")
	b.WriteString("if ! docker compose -f compose.check.yml config -q; then rm -f compose.check.yml; exit 3; fi\n")
	b.WriteString("cp compose.yml compose.yml.previous && mv -f compose.check.yml compose.yml\n")
	b.WriteString("docker compose up -d --remove-orphans\n")
	b.WriteString("wait_up 90\n")
	return b.String()
}

// ReadComposeScript prints a Docker app's compose file.
func ReadComposeScript(id string) string {
	return fmt.Sprintf("cat %s/compose.yml\n", Dir(id))
}

// PreflightScript reports what an install needs to know about a server.
func PreflightScript(r Recipe, ports []int) string {
	var b strings.Builder
	b.WriteString(lib)
	b.WriteString("echo \"pm=$PM\"\n")
	b.WriteString("echo \"root=$( [ \"$(id -u)\" = 0 ] && echo 1 || echo 0)\"\n")
	b.WriteString("echo \"docker=$(docker version --format '{{.Server.Version}}' 2>/dev/null)\"\n")
	b.WriteString("echo \"compose=$(docker compose version --short 2>/dev/null)\"\n")
	b.WriteString("echo \"arch=$(uname -m)\"\n")
	b.WriteString("d=/opt; [ -d /opt ] || d=/\n")
	b.WriteString("echo \"free_kb=$(df -Pk \"$d\" 2>/dev/null | awk 'NR==2{print $4}')\"\n")
	for _, p := range ports {
		fmt.Fprintf(&b, "if command -v ss >/dev/null 2>&1; then ss -Hltnu \"sport = :%d\" 2>/dev/null | grep -q . && echo \"busy=%d\"; fi\n", p, p)
	}
	if r.Kind == KindDocker {
		fmt.Fprintf(&b, "[ -f %s/compose.yml ] && echo 'here=1'\n", Dir(r.ID))
		fmt.Fprintf(&b, "n=$(docker volume ls -q --filter label=com.docker.compose.project=%s 2>/dev/null | wc -l); [ \"$n\" -gt 0 ] && echo 'old_data=1'\n", Project(r.ID))
	}
	b.WriteString("exit 0\n")
	return b.String()
}

// Lib is the shell library every software script starts with: PM is the
// server's package manager, and pkg_wait, pkg_refresh, pkg_install,
// pkg_remove, pkg_upgrade and need_root work on any of them.
func Lib() string { return lib }
