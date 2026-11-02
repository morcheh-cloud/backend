package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/terminal"
)

type PowerOverview struct {
	Access         string         `json:"access" enum:"root,sudo,user" doc:"How the login user can act as root; rebooting needs root or sudo"`
	Init           string         `json:"init" enum:"systemd,openrc,none"`
	Container      bool           `json:"container" doc:"The server is a container: rebooting or shutting it down usually stops the container"`
	Kernel         string         `json:"kernel" doc:"The running kernel (uname -r)"`
	ServerTime     time.Time      `json:"server_time"`
	BootTime       time.Time      `json:"boot_time"`
	UptimeSeconds  int64          `json:"uptime_seconds"`
	Sessions       int            `json:"sessions" doc:"Login sessions open right now (who)"`
	RebootRequired bool           `json:"reboot_required"`
	RebootReasons  []string       `json:"reboot_reasons" doc:"Why a reboot is waiting, as sentences"`
	RebootPackages []string       `json:"reboot_packages" doc:"Packages asking for it (Debian/Ubuntu reboot-required.pkgs)"`
	CanSchedule    bool           `json:"can_schedule" doc:"A delayed reboot or shutdown can be scheduled and cancelled (systemd)"`
	Scheduled      *PowerSchedule `json:"scheduled,omitempty" doc:"A pending delayed reboot or shutdown"`
}

type PowerSchedule struct {
	Action  string    `json:"action" enum:"reboot,poweroff,halt,kexec"`
	At      time.Time `json:"at"`
	Message string    `json:"message,omitempty" doc:"What logged-in users were told"`
}

type PowerActionBody struct {
	Action       string `json:"action" enum:"reboot,poweroff"`
	DelayMinutes int    `json:"delay_minutes,omitempty" minimum:"0" maximum:"10080" doc:"0 = now. Later needs systemd"`
	Message      string `json:"message,omitempty" maxLength:"200" doc:"Broadcast to logged-in users (wall)"`
}

type PowerActionResult struct {
	Action    string    `json:"action" enum:"reboot,poweroff"`
	At        time.Time `json:"at" doc:"When it happens, by the server's clock"`
	Scheduled bool      `json:"scheduled" doc:"Delayed: it can still be cancelled"`
	BootTime  time.Time `json:"boot_time" doc:"The boot before this one; a later boot_time means the server is back"`
}

// powerScript reads everything the power page shows in one round trip, as
// `key value` lines.
const powerScript = `echo "now $(date +%s)"
awk '/^btime/{print "btime", $2}' /proc/stat
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then echo "init systemd"
elif command -v rc-service >/dev/null 2>&1 && [ -d /run/openrc ]; then echo "init openrc"
else echo "init none"; fi
ct=
if [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then ct=1
elif command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt -cq; then ct=1
elif [ -r /proc/1/environ ] && tr '\0' '\n' </proc/1/environ | grep -q '^container='; then ct=1; fi
[ -n "$ct" ] && echo container
k=$(uname -r)
echo "kernel $k"
echo "sessions $(who 2>/dev/null | wc -l)"
f=/run/systemd/shutdown/scheduled
[ -r "$f" ] && sed 's/^/sched /' "$f"
if [ -f /var/run/reboot-required ]; then
  echo "required packages"
  [ -r /var/run/reboot-required.pkgs ] && sort -u /var/run/reboot-required.pkgs | sed 's/^/pkg /'
fi
if command -v needs-restarting >/dev/null 2>&1; then
  timeout 20 needs-restarting -r >/dev/null 2>&1
  [ $? -eq 1 ] && echo "required core"
fi
[ -z "$ct" ] && [ -d /lib/modules ] && [ ! -d "/lib/modules/$k" ] && echo "required kernel"
exit 0
`

var rebootReasons = map[string]string{
	"packages": "Updated packages asked for a reboot",
	"core":     "Core packages (kernel, glibc, systemd…) were updated since the last boot",
	"kernel":   "A newer kernel is installed than the one running",
}

func parsePower(out string) PowerOverview {
	o := PowerOverview{Init: "none", RebootReasons: []string{}, RebootPackages: []string{}}
	var sched PowerSchedule
	for _, line := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch k {
		case "now":
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				o.ServerTime = time.Unix(n, 0).UTC()
			}
		case "btime":
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				o.BootTime = time.Unix(n, 0).UTC()
			}
		case "init":
			o.Init = v
		case "container":
			o.Container = true
		case "kernel":
			o.Kernel = v
		case "sessions":
			o.Sessions, _ = strconv.Atoi(strings.TrimSpace(v))
		case "required":
			if r, ok := rebootReasons[v]; ok {
				o.RebootRequired = true
				o.RebootReasons = append(o.RebootReasons, r)
			}
		case "pkg":
			if v != "" {
				o.RebootPackages = append(o.RebootPackages, v)
			}
		case "sched":
			// logind's /run/systemd/shutdown/scheduled: USEC=, MODE=, WALL_MESSAGE=
			key, val, _ := strings.Cut(v, "=")
			switch key {
			case "USEC":
				if n, err := strconv.ParseInt(val, 10, 64); err == nil {
					sched.At = time.UnixMicro(n).UTC()
				}
			case "MODE":
				sched.Action = val
			case "WALL_MESSAGE":
				sched.Message = val
			}
		}
	}
	if !o.BootTime.IsZero() && !o.ServerTime.IsZero() {
		o.UptimeSeconds = int64(o.ServerTime.Sub(o.BootTime).Seconds())
	}
	o.CanSchedule = o.Init == "systemd"
	switch sched.Action {
	case "reboot", "poweroff", "halt", "kexec":
		if !sched.At.IsZero() {
			o.Scheduled = &sched
		}
	}
	return o
}

func registerPower(api huma.API, h *serverHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "get-power",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/power",
		Summary:     "Power state",
		Description: "Boot time, init system, logged-in sessions, whether a reboot is waiting (reboot-required, needs-restarting, " +
			"a removed running kernel) and a pending scheduled reboot or shutdown.",
		Tags: []string{"Power"},
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body PowerOverview }, error) {
		out := &struct{ Body PowerOverview }{}
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			o, err := h.powerOverview(ctx, in.ID, c)
			out.Body = o
			return err
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "power-action",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/power",
		Summary:     "Reboot or shut down",
		Description: "Now (the command runs detached a couple of seconds later, so the answer gets back first) or in " +
			"`delay_minutes` (systemd's shutdown, cancellable). Needs root or sudo. Poll the server's check until " +
			"`boot_time` is later than the one answered here to know it's back.",
		Tags: []string{"Power"},
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body PowerActionBody
	}) (*struct{ Body PowerActionResult }, error) {
		b := in.Body
		msg := strings.Join(strings.Fields(b.Message), " ")
		out := &struct{ Body PowerActionResult }{}
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.powerRoot(ctx, in.ID, c)
			if err != nil {
				return err
			}
			facts, err := sh.run(ctx, powerScript)
			if err != nil {
				return err
			}
			o := parsePower(facts)
			if b.DelayMinutes > 0 && !o.CanSchedule {
				return fieldError("body.delay_minutes", "Scheduling needs systemd; this server can only "+verb(b.Action)+" now", b.DelayMinutes)
			}
			if _, err := sh.run(ctx, powerCommand(b.Action, b.DelayMinutes, msg)); err != nil {
				return err
			}
			at := o.ServerTime
			if at.IsZero() {
				at = time.Now().UTC()
			}
			out.Body = PowerActionResult{
				Action:    b.Action,
				At:        at.Add(time.Duration(b.DelayMinutes) * time.Minute),
				Scheduled: b.DelayMinutes > 0,
				BootTime:  o.BootTime,
			}
			return nil
		})
		if err == nil && b.DelayMinutes == 0 {
			// The connection is about to die; the next request dials again.
			go func() {
				time.Sleep(3 * time.Second)
				h.pool.Drop(in.ID)
			}()
		}
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "cancel-power",
		Method:      http.MethodDelete,
		Path:        "/servers/{id}/power/schedule",
		Summary:     "Cancel a scheduled reboot or shutdown",
		Description: "Runs `shutdown -c` and answers the power state after it.",
		Tags:        []string{"Power"},
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body PowerOverview }, error) {
		out := &struct{ Body PowerOverview }{}
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.powerRoot(ctx, in.ID, c)
			if err != nil {
				return err
			}
			if _, err := sh.run(ctx, "shutdown -c"); err != nil {
				return err
			}
			o, err := h.powerOverview(ctx, in.ID, c)
			out.Body = o
			return err
		})
		return out, toProblem(err)
	})
}

func (h *serverHandler) powerOverview(ctx context.Context, id string, c *sshpool.Conn) (PowerOverview, error) {
	sh, err := h.rootShell(ctx, id, c)
	if err != nil {
		return PowerOverview{}, err
	}
	out, err := sh.run(ctx, powerScript)
	if err != nil {
		return PowerOverview{}, err
	}
	o := parsePower(out)
	o.Access = sh.priv.access()
	return o, nil
}

// powerRoot is a root shell, or 403.
func (h *serverHandler) powerRoot(ctx context.Context, id string, c *sshpool.Conn) (*rootShell, error) {
	sh, err := h.rootShell(ctx, id, c)
	if err != nil {
		return nil, err
	}
	if sh.priv == privUser {
		return nil, huma.Error403Forbidden("Rebooting or shutting down needs root or sudo on this server")
	}
	return sh, nil
}

func verb(action string) string {
	if action == "poweroff" {
		return "shut down"
	}
	return "reboot"
}

// powerCommand reboots or powers off. Later: systemd's shutdown schedules it
// and returns. Now: the command runs detached after a short sleep, so this
// session (and the API's answer) finishes before the connection drops.
func powerCommand(action string, delay int, msg string) string {
	flag := "-r"
	if action == "poweroff" {
		flag = "-P"
	}
	if delay > 0 {
		cmd := "shutdown " + flag + " +" + strconv.Itoa(delay)
		if msg != "" {
			cmd += " " + terminal.ShellQuote(msg)
		}
		return cmd + " 2>&1"
	}
	act := terminal.ShellQuote(action)
	script := `if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then c="systemctl ` + action + `"
elif command -v ` + act + ` >/dev/null 2>&1; then c=` + act + `
elif command -v shutdown >/dev/null 2>&1; then c="shutdown ` + flag + ` now"
else echo "No ` + action + ` command on this server" >&2; exit 127; fi
`
	if msg != "" {
		script += "command -v wall >/dev/null 2>&1 && printf '%s\\n' " + terminal.ShellQuote(msg) + " | wall 2>/dev/null\n"
	}
	script += `d=; command -v setsid >/dev/null 2>&1 && d=setsid
$d nohup sh -c "sleep 2; $c" </dev/null >/dev/null 2>&1 &
exit 0
`
	return script
}
