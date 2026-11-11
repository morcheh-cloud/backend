package packages

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/morcheh/backend/internal/software"
)

// Actions a job can run.
const (
	ActInstall    = "install"
	ActRemove     = "remove"
	ActPurge      = "purge"
	ActUpgrade    = "upgrade"
	ActReinstall  = "reinstall"
	ActUpgradeAll = "upgrade-all"
	ActAutoremove = "autoremove"
	ActClean      = "clean"
)

// Upgrade-all modes.
const (
	ModeAll      = "all"
	ModeSecurity = "security"
	ModeFull     = "full"
)

// Marks.
const (
	MarkHold   = "hold"
	MarkUnhold = "unhold"
	MarkAuto   = "auto"
	MarkManual = "manual"
)

// lib is software's shell library plus T (a tab) and N (a newline), for
// query formats that don't read escapes (dnf5).
func lib() string { return software.Lib() + "T=$(printf '\\t')\nN='\n'\n" }

func q(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func quoted(names []string) string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = q(n)
	}
	return strings.Join(out, " ")
}

// OverviewScript prints the installed packages, updates and settings in
// "@@ section" blocks for ParseOverview. It reads only the local package
// database and lists; it never downloads anything.
func OverviewScript() string {
	return lib() + `
echo "@@ meta"
echo "pm $PM"
echo "tz $(date +%z)"
if [ -f /var/run/reboot-required ]; then echo "reboot 1"; fi
echo "@@ reboot-pkgs"
cat /var/run/reboot-required.pkgs 2>/dev/null
newest() { find "$@" -printf '%T@\n' 2>/dev/null | sort -n | tail -n1; }
bytes() { find "$@" -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1} END {print s+0}'; }
case "$PM" in
apt)
  echo "@@ installed"
  dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Installed-Size}\t${Section}\t${db:Status-Abbrev}\t${binary:Summary}\n' 2>/dev/null
  echo "@@ auto"
  apt-mark showauto 2>/dev/null
  echo "@@ dates"
  find /var/lib/dpkg/info -maxdepth 1 -name '*.list' -printf '%f\t%T@\n' 2>/dev/null
  echo "@@ upgradable"
  apt list --upgradable 2>/dev/null
  echo "@@ autoremove"
  apt-get -s autoremove 2>/dev/null | awk '/^Remv /{print $2}'
  echo "@@ meta"
  echo "lists $(newest /var/lib/apt/lists -maxdepth 1 -type f -name '*_Packages*')"
  echo "cache $(bytes /var/cache/apt/archives -maxdepth 1 -name '*.deb')"
  if dpkg-query -W -f='${db:Status-Abbrev}' unattended-upgrades 2>/dev/null | grep -q '^ii'; then echo "auto_tool unattended-upgrades"; fi
  AU=; eval "$(apt-config shell AU APT::Periodic::Unattended-Upgrade 2>/dev/null)"
  echo "auto_value ${AU:-0}"
  ;;
dnf|yum|zypper)
  echo "@@ installed"
  rpm -qa --qf '%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SIZE}\t%{GROUP}\tii\t%{SUMMARY}\t%{INSTALLTIME}\n' 2>/dev/null | grep -v '^gpg-pubkey'
  case "$PM" in
  dnf)
    echo "@@ auto"
    dnf -q repoquery --installed --qf "%{name}${T}%{reason}${N}" 2>/dev/null | awk -F'\t' 'tolower($2) ~ /dependency/ {print $1}'
    echo "@@ held"
    dnf -q versionlock list 2>/dev/null
    echo "@@ upgradable"
    dnf -q check-update 2>/dev/null
    echo "@@ security"
    dnf -q updateinfo list --security 2>/dev/null
    echo "@@ autoremove"
    dnf -q repoquery --unneeded --qf "%{name}${N}" 2>/dev/null
    echo "@@ meta"
    if dnf -q versionlock list >/dev/null 2>&1; then echo "versionlock 1"; fi
    if dnf -q needs-restarting -r 2>/dev/null | grep -qi 'reboot is required'; then echo "reboot 1"; fi
    echo "lists $(newest /var/cache/dnf /var/cache/libdnf5 -maxdepth 4 -name repomd.xml)"
    echo "cache $(bytes /var/cache/dnf /var/cache/libdnf5 -name '*.rpm')"
    for u in dnf-automatic-install.timer dnf5-automatic.timer dnf-automatic.timer; do
      if [ -n "$(systemctl list-unit-files "$u" 2>/dev/null | grep "^$u")" ]; then
        echo "auto_tool $u"
        echo "auto_value $(systemctl is-enabled "$u" 2>/dev/null)"
        if grep -Eq '^[[:space:]]*apply_updates[[:space:]]*=[[:space:]]*(yes|true|1)' /etc/dnf/automatic.conf 2>/dev/null; then echo "auto_apply 1"; fi
        break
      fi
    done
    ;;
  yum)
    echo "@@ held"
    yum -q versionlock list 2>/dev/null
    echo "@@ upgradable"
    yum -q check-update 2>/dev/null
    echo "@@ security"
    yum -q updateinfo list security 2>/dev/null
    echo "@@ meta"
    if yum -q versionlock list >/dev/null 2>&1; then echo "versionlock 1"; fi
    if command -v needs-restarting >/dev/null 2>&1 && needs-restarting -r 2>/dev/null | grep -qi 'reboot is required'; then echo "reboot 1"; fi
    echo "lists $(newest /var/cache/yum -maxdepth 4 -name repomd.xml)"
    echo "cache $(bytes /var/cache/yum -name '*.rpm')"
    ;;
  zypper)
    echo "@@ auto"
    grep -v '^#' /var/lib/zypp/AutoInstalled 2>/dev/null
    echo "@@ held"
    zypper -q --no-refresh locks 2>/dev/null
    echo "@@ upgradable"
    zypper -q --no-refresh lu 2>/dev/null
    echo "@@ autoremove"
    zypper -q --no-refresh pa --unneeded 2>/dev/null
    echo "@@ meta"
    zypper -q needs-rebooting >/dev/null 2>&1; [ $? -eq 102 ] && echo "reboot 1"
    echo "lists $(newest /var/cache/zypp/raw -maxdepth 4 -name repomd.xml)"
    echo "cache $(bytes /var/cache/zypp/packages -name '*.rpm')"
    ;;
  esac
  ;;
apk)
  echo "@@ apkdb"
  grep -E '^(P|V|A|I|T|C|o):|^$' /lib/apk/db/installed 2>/dev/null
  echo "@@ world"
  cat /etc/apk/world 2>/dev/null
  echo "@@ upgradable"
  apk list -u 2>/dev/null
  echo "@@ meta"
  echo "lists $(newest /var/cache/apk /etc/apk/cache -maxdepth 1 -name 'APKINDEX*')"
  echo "cache $(bytes /var/cache/apk /etc/apk/cache -maxdepth 1 -name '*.apk')"
  ;;
pacman)
  echo "@@ pacdesc"
  cat /var/lib/pacman/local/*/desc 2>/dev/null
  echo "@@ upgradable"
  pacman -Qu 2>/dev/null
  echo "@@ autoremove"
  pacman -Qdtq 2>/dev/null
  echo "@@ held"
  sed -n 's/^[[:space:]]*IgnorePkg[[:space:]]*=//p' /etc/pacman.conf 2>/dev/null | tr ' ' '\n'
  echo "@@ meta"
  echo "lists $(newest /var/lib/pacman/sync -maxdepth 1 -name '*.db')"
  echo "cache $(bytes /var/cache/pacman/pkg -maxdepth 1 -name '*.pkg.tar*')"
  ;;
esac
exit 0
`
}

// InfoScript prints everything about one package for ParseInfo.
func InfoScript(name string) string {
	return lib() + "n=" + q(name) + `
echo "@@ meta"
echo "pm $PM"
case "$PM" in
apt)
  echo "@@ status"; dpkg-query -s "$n" 2>/dev/null
  echo "@@ show"; apt-cache show --no-all-versions "$n" 2>/dev/null
  echo "@@ policy"; apt-cache policy "$n" 2>/dev/null
  echo "@@ rdepends"; apt-cache rdepends --installed --no-recommends --no-suggests --no-conflicts --no-breaks --no-replaces --no-enhances "$n" 2>/dev/null
  echo "@@ files"; dpkg -L "$n" 2>/dev/null | head -n 20000
  ;;
dnf|yum|zypper)
  echo "@@ rpm"; rpm -qi "$n" 2>/dev/null
  echo "@@ files"; rpm -ql "$n" 2>/dev/null | grep -v '^(contains no files)' | head -n 20000
  echo "@@ depends"
  rpm -qR "$n" 2>/dev/null | awk '{print $1}' | grep -v '^rpmlib(' | sort -u | xargs -r rpm -q --whatprovides --qf '%{NAME}\n' 2>/dev/null | grep -v '^no package provides' | sort -u
  echo "@@ rdepends"
  rpm -q --provides "$n" 2>/dev/null | awk '{print $1}' | sort -u | xargs -r rpm -q --whatrequires --qf '%{NAME}\n' 2>/dev/null | grep -v '^no package requires' | sort -u
  case "$PM" in
  dnf) echo "@@ remote"; dnf -q info "$n" 2>/dev/null; echo "@@ versions"; dnf -q list --showduplicates "$n" 2>/dev/null ;;
  yum) echo "@@ remote"; yum -q info "$n" 2>/dev/null; echo "@@ versions"; yum -q list --showduplicates "$n" 2>/dev/null ;;
  zypper) echo "@@ remote"; zypper -q --no-refresh info "$n" 2>/dev/null; echo "@@ zversions"; zypper -q --no-refresh se -s --match-exact -t package "$n" 2>/dev/null ;;
  esac
  ;;
apk)
  echo "@@ apkinfo"; apk info -a "$n" 2>/dev/null
  echo "@@ apklist"; apk list "$n" 2>/dev/null
  echo "@@ policy"; apk policy "$n" 2>/dev/null
  ;;
pacman)
  echo "@@ local"; pacman -Qi "$n" 2>/dev/null
  echo "@@ sync"; pacman -Si "$n" 2>/dev/null
  echo "@@ files"; pacman -Qlq "$n" 2>/dev/null | head -n 20000
  ;;
esac
exit 0
`
}

// SearchScript looks q up in the repositories, for ParseSearch.
func SearchScript(query string) string {
	re := regexp.QuoteMeta(strings.TrimSpace(query))
	glob := "*" + strings.ReplaceAll(strings.TrimSpace(query), " ", "*") + "*"
	return lib() + "re=" + q(re) + "\nglob=" + q(glob) + `
echo "@@ meta"
echo "pm $PM"
case "$PM" in
apt)
  echo "@@ apt"; apt-cache search -- "$re" 2>/dev/null | head -n 2000
  ;;
dnf)
  echo "@@ rq"; dnf -q repoquery --latest-limit 1 --qf "%{name}${T}%{version}-%{release}${T}%{repoid}${T}%{summary}${N}" "$glob" 2>/dev/null | head -n 2000
  ;;
yum)
  echo "@@ yum"; yum -q list available "$glob" 2>/dev/null | head -n 2000
  ;;
zypper)
  echo "@@ zypper"; zypper -q --no-refresh se -t package -- "$re" 2>/dev/null | head -n 2000
  ;;
apk)
  echo "@@ apk"; apk search -v -d -- "$glob" 2>/dev/null | head -n 2000
  ;;
pacman)
  echo "@@ pacman"; pacman -Ss -- "$re" 2>/dev/null | head -n 4000
  ;;
esac
exit 0
`
}

// CandidatesScript prints the installed and available versions of names,
// to fill in search results (apt and yum list names first).
func CandidatesScript(names []string) string {
	return lib() + `
echo "@@ meta"
echo "pm $PM"
case "$PM" in
apt) echo "@@ policy"; apt-cache policy ` + quoted(names) + ` 2>/dev/null ;;
apk) echo "@@ apk"; apk list -I ` + quoted(names) + ` 2>/dev/null ;;
dnf|yum|zypper) echo "@@ rpm"; rpm -q --qf '%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\n' ` + quoted(names) + ` 2>/dev/null | grep -v 'is not installed' ;;
esac
exit 0
`
}

// HistoryScript prints the package manager's log for ParseHistory.
func HistoryScript() string {
	return lib() + `
echo "@@ meta"
echo "pm $PM"
echo "tz $(date +%z)"
case "$PM" in
apt)
  echo "@@ apt"
  for f in $(ls -1 /var/log/apt/history.log.*.gz 2>/dev/null | sort -t. -k3 -n -r); do zcat "$f" 2>/dev/null; done | tail -c 3000000
  cat /var/log/apt/history.log 2>/dev/null | tail -c 3000000
  ;;
dnf|yum)
  ids=$($PM -q history list 2>/dev/null | awk '$1 ~ /^[0-9]+$/ {print $1}' | head -n 60)
  if [ -n "$ids" ]; then echo "@@ dnfhist"; $PM -q history info $ids 2>/dev/null; fi
  echo "@@ rpmlast"; rpm -qa --qf '%{INSTALLTIME}\t%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\n' 2>/dev/null | grep -v '^[0-9]*	gpg-pubkey' | sort -n | tail -n 5000
  ;;
zypper)
  echo "@@ zypp"; tail -n 20000 /var/log/zypp/history 2>/dev/null
  ;;
pacman)
  echo "@@ pacman"; tail -n 20000 /var/log/pacman.log 2>/dev/null
  ;;
esac
exit 0
`
}

// PreviewScript asks the package manager what an action would do, without
// doing it. It needs root on dnf, yum and zypper.
func PreviewScript(action, mode string, names []string, version string) (string, error) {
	cmd, err := previewCommands(action, mode, names, version)
	if err != nil {
		return "", err
	}
	return lib() + `
echo "@@ meta"
echo "pm $PM"
echo "@@ out"
case "$PM" in
` + cmd + `
*) echo "This server has no package manager Morcheh knows." ;;
esac 2>&1
echo "@@ installed"
case "$PM" in
pacman) pacman -Q 2>/dev/null ;;
esac
exit 0
`, nil
}

func previewCommands(action, mode string, names []string, version string) (string, error) {
	n := quoted(names)
	nv := func(sep string) string {
		if version == "" {
			return n
		}
		return q(names[0] + sep + version)
	}
	var apt, dnf, zyp, apk, pac string
	switch action {
	case ActInstall:
		apt = "apt-get -s install --allow-downgrades " + nv("=")
		dnf = "$PM --assumeno install " + nv("-")
		if version != "" {
			dnf = "if rpm -q " + q(names[0]) + " >/dev/null 2>&1; then $PM --assumeno downgrade " + nv("-") + " || $PM --assumeno upgrade " + nv("-") + "; else $PM --assumeno install " + nv("-") + "; fi"
		}
		zyp = "zypper -n --no-refresh install --dry-run --oldpackage " + nv("=")
		apk = "apk add --simulate " + nv("=")
		pac = "pacman -S --print --print-format '%n %v' " + n
	case ActRemove, ActPurge:
		apt = "apt-get -s remove " + n
		if action == ActPurge {
			apt = "apt-get -s purge " + n
		}
		dnf = "$PM --assumeno remove " + n
		zyp = "zypper -n --no-refresh remove --dry-run " + n
		apk = "apk del --simulate " + n
		pac = "pacman -R --print --print-format '%n %v' " + n
	case ActUpgrade:
		apt = "apt-get -s install --only-upgrade " + n
		dnf = "$PM --assumeno upgrade " + n
		zyp = "zypper -n --no-refresh update --dry-run " + n
		apk = "apk add -u --simulate " + n
		pac = "pacman -S --print --print-format '%n %v' " + n
	case ActReinstall:
		apt = "apt-get -s install --reinstall " + n
		dnf = "$PM --assumeno reinstall " + n
		zyp = "zypper -n --no-refresh install --force --dry-run " + n
		apk = "apk fix --reinstall --simulate " + n
		pac = "pacman -S --print --print-format '%n %v' " + n
	case ActUpgradeAll:
		apt = "apt-get -s upgrade"
		switch mode {
		case ModeFull:
			apt = "apt-get -s dist-upgrade"
		case ModeSecurity:
			apt = "pkgs=$(apt list --upgradable 2>/dev/null | grep -e '-security' | cut -d/ -f1 | tr '\\n' ' '); [ -n \"$pkgs\" ] && apt-get -s install --only-upgrade $pkgs"
		}
		dnf = "$PM --assumeno upgrade"
		if mode == ModeSecurity {
			dnf += " --security"
		}
		zyp = "zypper -n --no-refresh update --dry-run"
		if mode == ModeSecurity {
			zyp = "zypper -n --no-refresh patch --category security --dry-run"
		}
		apk = "apk upgrade --simulate"
		pac = "pacman -Su --print --print-format '%n %v'"
	case ActAutoremove:
		apt = "apt-get -s autoremove"
		dnf = "$PM --assumeno autoremove"
		zyp = "u=$(zypper -q --no-refresh pa --unneeded | awk -F'|' 'NR>2 {gsub(/ /, \"\", $3); print $3}'); [ -n \"$u\" ] && zypper -n --no-refresh remove --dry-run $u"
		apk = "true"
		pac = "o=$(pacman -Qdtq); [ -n \"$o\" ] && pacman -R --print --print-format '%n %v' $o"
	default:
		return "", fmt.Errorf("%s has no preview", action)
	}
	return "apt) " + apt + " ;;\ndnf|yum) " + dnf + " ;;\nzypper) " + zyp + " ;;\napk) " + apk + " ;;\npacman) " + pac + " ;;\n", nil
}

// ActionScript runs an action. It prints what it does as it goes, and
// fails (non-zero) when the package manager does.
func ActionScript(action, mode string, names []string, version string) (string, error) {
	if action == ActUpgradeAll {
		return software.SystemUpgradeScript(software.SystemOptions{SecurityOnly: mode == ModeSecurity, Full: mode == ModeFull}), nil
	}
	n := quoted(names)
	nv := func(sep string) string {
		if version == "" {
			return n
		}
		return q(names[0] + sep + version)
	}
	opts := "$APT_LOCK -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
	var body string
	switch action {
	case ActInstall:
		body = `case "$PM" in
apt) apt-get ` + opts + ` install --allow-downgrades ` + nv("=") + ` ;;
dnf|yum) ` + func() string {
			if version == "" {
				return "$PM -y install " + n
			}
			return "if rpm -q " + q(names[0]) + " >/dev/null 2>&1; then $PM -y downgrade " + nv("-") + " || $PM -y upgrade " + nv("-") + "; else $PM -y install " + nv("-") + "; fi"
		}() + ` ;;
zypper) zypper -n install --oldpackage ` + nv("=") + ` ;;
apk) apk add ` + nv("=") + ` ;;
pacman) pacman -S --noconfirm --needed ` + n + ` ;;
esac`
	case ActRemove:
		body = `case "$PM" in
apt) apt-get ` + opts + ` remove ` + n + ` ;;
dnf|yum) $PM -y remove ` + n + ` ;;
zypper) zypper -n remove ` + n + ` ;;
apk) apk del ` + n + ` ;;
pacman) pacman -R --noconfirm ` + n + ` ;;
esac`
	case ActPurge:
		body = `case "$PM" in
apt) apt-get ` + opts + ` purge ` + n + ` ;;
*) echo "Only apt keeps configuration files apart." >&2; exit 1 ;;
esac`
	case ActUpgrade:
		body = `case "$PM" in
apt) apt-get ` + opts + ` install --only-upgrade ` + n + ` ;;
dnf) dnf -y upgrade ` + n + ` ;;
yum) yum -y update ` + n + ` ;;
zypper) zypper -n update ` + n + ` ;;
apk) apk add -u ` + n + ` ;;
pacman) pacman -S --noconfirm ` + n + ` ;;
esac`
	case ActReinstall:
		body = `case "$PM" in
apt) apt-get ` + opts + ` install --reinstall ` + n + ` ;;
dnf|yum) $PM -y reinstall ` + n + ` ;;
zypper) zypper -n install --force ` + n + ` ;;
apk) apk fix --reinstall ` + n + ` ;;
pacman) pacman -S --noconfirm ` + n + ` ;;
esac`
	case ActAutoremove:
		body = `case "$PM" in
apt) apt-get $APT_LOCK -y -q autoremove ;;
dnf|yum) $PM -y autoremove ;;
zypper) u=$(zypper -q --no-refresh pa --unneeded | awk -F'|' 'NR>2 {gsub(/ /, "", $3); print $3}'); if [ -n "$u" ]; then zypper -n remove $u; else echo "Nothing to remove."; fi ;;
pacman) o=$(pacman -Qdtq); if [ -n "$o" ]; then pacman -Rns --noconfirm $o; else echo "Nothing to remove."; fi ;;
*) echo "Nothing to remove: $PM removes unneeded packages by itself." ;;
esac`
	case ActClean:
		body = `case "$PM" in
apt) apt-get clean ;;
dnf|yum) $PM clean packages ;;
zypper) zypper clean ;;
apk) apk cache clean 2>/dev/null || rm -f /var/cache/apk/*.apk ;;
pacman) pacman -Sc --noconfirm ;;
esac
echo "The package cache is empty."`
	default:
		return "", fmt.Errorf("unknown action %q", action)
	}
	return "set -e\n" + lib() + "need_root\npkg_wait\n" + body + "\n" +
		"if [ -f /var/run/reboot-required ]; then echo 'The server needs a restart to finish.'; fi\n", nil
}

// RefreshScript downloads fresh package lists.
func RefreshScript() string {
	return "set -e\n" + lib() + "need_root\necho \"Refreshing the package lists ($PM)…\"\npkg_refresh\necho 'Done.'\n"
}

// MarkScript holds, unholds, or marks packages as installed by hand or as
// dependencies.
func MarkScript(mark string, names []string) (string, error) {
	n := quoted(names)
	var body string
	switch mark {
	case MarkHold:
		body = `case "$PM" in
apt) apt-mark hold ` + n + ` ;;
dnf|yum) $PM -q versionlock add ` + n + ` ;;
zypper) zypper -q addlock ` + n + ` ;;
*) echo "Holding packages isn't supported with $PM." >&2; exit 3 ;;
esac`
	case MarkUnhold:
		body = `case "$PM" in
apt) apt-mark unhold ` + n + ` ;;
dnf) for p in ` + n + `; do dnf -q versionlock delete "$p"; done ;;
yum) for p in ` + n + `; do yum -q versionlock delete "$p" || yum -q versionlock delete "*:$p-*"; done ;;
zypper) zypper -q removelock ` + n + ` ;;
*) echo "Holding packages isn't supported with $PM." >&2; exit 3 ;;
esac`
	case MarkAuto:
		body = `case "$PM" in
apt) apt-mark auto ` + n + ` ;;
dnf) if dnf mark --help 2>&1 | grep -q dependency; then dnf -q mark dependency ` + n + `; else dnf -q mark remove ` + n + `; fi ;;
pacman) pacman -D --asdeps ` + n + ` ;;
*) echo "Marking packages isn't supported with $PM." >&2; exit 3 ;;
esac`
	case MarkManual:
		body = `case "$PM" in
apt) apt-mark manual ` + n + ` ;;
dnf) if dnf mark --help 2>&1 | grep -q dependency; then dnf -q mark user ` + n + `; else dnf -q mark install ` + n + `; fi ;;
pacman) pacman -D --asexplicit ` + n + ` ;;
*) echo "Marking packages isn't supported with $PM." >&2; exit 3 ;;
esac`
	default:
		return "", fmt.Errorf("unknown mark %q", mark)
	}
	return lib() + "need_root\npkg_wait >&2\n" + body + " >&2\n", nil
}

// AutoUpdatesScript turns automatic updates on or off.
func AutoUpdatesScript(enabled bool) string {
	on := "0"
	if enabled {
		on = "1"
	}
	return lib() + "need_root\non=" + on + `
case "$PM" in
apt)
  if [ "$on" = 1 ] && ! dpkg-query -W -f='${db:Status-Abbrev}' unattended-upgrades 2>/dev/null | grep -q '^ii'; then
    echo "unattended-upgrades isn't installed: install it first." >&2; exit 3
  fi
  printf 'APT::Periodic::Update-Package-Lists "%s";\nAPT::Periodic::Unattended-Upgrade "%s";\n' "$on" "$on" > /etc/apt/apt.conf.d/20auto-upgrades.new
  mv -f /etc/apt/apt.conf.d/20auto-upgrades.new /etc/apt/apt.conf.d/20auto-upgrades
  ;;
dnf)
  unit=
  for u in dnf-automatic-install.timer dnf5-automatic.timer dnf-automatic.timer; do
    if [ -n "$(systemctl list-unit-files "$u" 2>/dev/null | grep "^$u")" ]; then unit=$u; break; fi
  done
  if [ -z "$unit" ]; then echo "dnf-automatic isn't installed: install it first." >&2; exit 3; fi
  if [ "$on" = 1 ]; then
    if [ "$unit" != dnf-automatic-install.timer ]; then
      c=/etc/dnf/automatic.conf
      if [ -f "$c" ] && grep -Eq '^[[:space:]]*apply_updates[[:space:]]*=' "$c"; then
        sed -i -E 's/^[[:space:]]*apply_updates[[:space:]]*=.*/apply_updates = yes/' "$c"
      elif [ -f "$c" ] && grep -q '^\[commands\]' "$c"; then
        sed -i '/^\[commands\]/a apply_updates = yes' "$c"
      else
        printf '[commands]\napply_updates = yes\n' >> "$c"
      fi
    fi
    systemctl enable --now "$unit" >&2
  else
    systemctl disable --now "$unit" >&2
  fi
  ;;
*) echo "Automatic updates can't be set from Morcheh with $PM." >&2; exit 3 ;;
esac
`
}
