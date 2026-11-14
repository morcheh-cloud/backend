package software

import (
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
    *) echo "This server has no package manager Morche knows (apt, dnf, yum, zypper, apk, pacman)." >&2; return 1 ;;
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
    *) echo "This server has no package manager Morche knows." >&2; return 1 ;;
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
`

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

// InstallScript installs r. Its scripts read the values from the
// environment.
func InstallScript(r Recipe) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString(lib)
	b.WriteString("need_root\n")
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
	return b.String()
}

// UpdateScript updates r to its newest version.
func UpdateScript(r Recipe) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString(lib)
	b.WriteString("need_root\n")
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
	return b.String()
}

// UninstallScript removes r.
func UninstallScript(r Recipe) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString(lib)
	b.WriteString("need_root\n")
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
		b.WriteString("  *) echo 'No package manager Morche knows.' >&2; exit 1 ;;\n")
	}
	b.WriteString("esac\n")
	b.WriteString("if [ -f /var/run/reboot-required ]; then echo 'The server needs a restart to finish.'; fi\n")
	return b.String()
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
	b.WriteString("exit 0\n")
	return b.String()
}

// Lib is the shell library every software script starts with: PM is the
// server's package manager, and pkg_wait, pkg_refresh, pkg_install,
// pkg_remove, pkg_upgrade and need_root work on any of them.
func Lib() string { return lib }
