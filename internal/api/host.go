package api

import (
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/terminal"
)

// Shared by every module that installs a package and runs a service on the
// server (fail2ban today; firewalls, auditd… later): which package manager and
// init system the server has, and the commands for each.

// hostScript prints `pm <name>` and `init <systemd|openrc|none>`.
const hostScript = `for p in apt-get dnf yum zypper apk pacman; do
  command -v "$p" >/dev/null 2>&1 && { echo "pm $p"; break; }
done
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then echo "init systemd"
elif command -v rc-service >/dev/null 2>&1 && [ -d /run/openrc ]; then echo "init openrc"
else echo "init none"; fi
`

type hostFacts struct {
	pm   string // apt-get, dnf, yum, zypper, apk, pacman, or empty
	init string // systemd, openrc or none
}

func parseHost(out string) hostFacts {
	f := hostFacts{init: "none"}
	for _, line := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch k {
		case "pm":
			f.pm = v
		case "init":
			f.init = v
		}
	}
	return f
}

// How long a package install or removal may take.
const packageTimeout = 10 * time.Minute

// packageScript installs (or removes, or purges) packages without prompts.
// RHEL-likes ship fail2ban & co. in EPEL, so a failed dnf/yum install
// retries once after enabling it.
func packageScript(pm, op string, pkgs ...string) (string, error) {
	quoted := make([]string, len(pkgs))
	for i, p := range pkgs {
		quoted[i] = terminal.ShellQuote(p)
	}
	list := strings.Join(quoted, " ")
	switch pm + " " + op {
	case "apt-get install":
		return "export DEBIAN_FRONTEND=noninteractive\napt-get update -q && apt-get install -y -q " + list, nil
	case "apt-get remove":
		return "export DEBIAN_FRONTEND=noninteractive\napt-get remove -y -q " + list, nil
	case "apt-get purge":
		return "export DEBIAN_FRONTEND=noninteractive\napt-get purge -y -q " + list, nil
	case "dnf install", "yum install":
		return pm + " install -y " + list + " || { " + pm + " install -y epel-release && " + pm + " install -y " + list + "; }", nil
	case "dnf remove", "dnf purge", "yum remove", "yum purge":
		return pm + " remove -y " + list, nil
	case "zypper install":
		return "zypper -n install " + list, nil
	case "zypper remove", "zypper purge":
		return "zypper -n remove " + list, nil
	case "apk install":
		return "apk add --no-progress " + list, nil
	case "apk remove", "apk purge":
		return "apk del --no-progress " + list, nil
	case "pacman install":
		return "pacman -S --noconfirm --needed " + list, nil
	case "pacman remove":
		return "pacman -R --noconfirm " + list, nil
	case "pacman purge":
		return "pacman -Rns --noconfirm " + list, nil
	case " install", " remove", " purge":
		return "", huma.Error422UnprocessableEntity("No supported package manager (apt, dnf, yum, zypper, apk, pacman) on this server")
	}
	return "", huma.Error422UnprocessableEntity("Unknown package operation: " + op)
}

// serviceScript runs one action on a service. Without an init system,
// `direct` gives the command per action (start/stop/restart/reload), e.g.
// fail2ban-client's own; enable/disable then can't be done.
func serviceScript(init, name, action string, direct map[string]string) (string, error) {
	svc := terminal.ShellQuote(name)
	switch init {
	case "systemd":
		return "systemctl " + action + " " + svc, nil
	case "openrc":
		switch action {
		case "enable":
			return "rc-update add " + svc + " default", nil
		case "disable":
			return "rc-update del " + svc + " default", nil
		}
		return "rc-service " + svc + " " + action, nil
	}
	if cmd, ok := direct[action]; ok {
		return cmd, nil
	}
	return "", huma.Error422UnprocessableEntity("This server has no init system (systemd or OpenRC) to start " + name + " at boot")
}

// enabledScript prints "enabled" when the service starts at boot, under
// whichever init system the server runs.
func enabledScript(name string) string {
	svc := terminal.ShellQuote(name)
	return "if [ -d /run/systemd/system ]; then systemctl is-enabled " + svc + " 2>/dev/null | grep -qx enabled && echo enabled\n" +
		"elif command -v rc-update >/dev/null 2>&1; then rc-update show default 2>/dev/null | grep -qw " + svc + " && echo enabled; fi\n"
}

// processScript prints "running" when a process's command line contains
// pattern (no pgrep on minimal images).
func processScript(pattern string) string {
	return "for p in /proc/[0-9]*; do tr '\\0' ' ' < \"$p/cmdline\" 2>/dev/null; echo; done | grep -q " +
		terminal.ShellQuote(pattern) + " && echo running\n"
}
