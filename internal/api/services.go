package api

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/sse"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/services"
	"github.com/morcheh/backend/internal/sshpool"
)

// ---- Types ----

type ServicesOverview struct {
	Init     string             `json:"init" enum:"systemd,openrc,none" doc:"The service manager; none = neither systemd nor OpenRC runs (e.g. a container)"`
	Access   string             `json:"access" enum:"root,sudo,user" doc:"Starting, stopping or changing services needs root or sudo"`
	Version  string             `json:"version" example:"systemd 255 (255.4-1ubuntu8)"`
	State    string             `json:"state" doc:"systemctl is-system-running: running, degraded (a unit failed), starting, maintenance…" example:"running"`
	Services []services.Service `json:"services"`
	Warnings []string           `json:"warnings"`
}

type ServiceDetails struct {
	services.Details
	Init         string `json:"init" enum:"systemd,openrc"`
	Override     string `json:"override" doc:"Where Morcheh writes overrides: <unit>.d/override.conf in /etc/systemd/system" example:"/etc/systemd/system/nginx.service.d/override.conf"`
	Revision     string `json:"revision" doc:"Of the override file as it is now (empty file when there is none); send it back when saving"`
	FileRevision string `json:"file_revision" doc:"Of the unit file, for editing a custom unit"`
}

type ServiceLogs struct {
	Source  string              `json:"source" enum:"journal,none" doc:"none: the server has no journal (OpenRC, no systemd-journald)"`
	Note    string              `json:"note,omitempty"`
	Entries []services.LogEntry `json:"entries" doc:"Oldest first"`
}

type ServicePath struct {
	ID   string `path:"id" format:"uuid"`
	Unit string `path:"unit" maxLength:"256" example:"nginx.service"`
}

type ServiceActionBody struct {
	Action string `json:"action" enum:"start,stop,restart,reload,enable,disable,mask,unmask,reset-failed,kill"`
	Now    bool   `json:"now,omitempty" doc:"With enable/disable/mask: also start or stop it now"`
	Signal string `json:"signal,omitempty" enum:"TERM,KILL,HUP,INT,USR1,USR2" default:"TERM" doc:"With kill"`
	Force  bool   `json:"force,omitempty" doc:"Stop, disable, mask or kill a protected service (sshd, dbus, journald…) anyway"`
}

type ServiceFileBody struct {
	Content  string `json:"content" maxLength:"262144" doc:"The whole file; empty removes an override"`
	Revision string `json:"revision" doc:"From the details: 409 when the file changed since"`
	Restart  bool   `json:"restart,omitempty" doc:"Restart the service after systemd reloads it (when it runs)"`
}

type ServiceCreateBody struct {
	Name    string `json:"name" minLength:"1" maxLength:"200" doc:".service is added when missing" example:"myapp.service"`
	Content string `json:"content" minLength:"1" maxLength:"262144" doc:"The unit file" example:"[Unit]\nDescription=My app\n\n[Service]\nExecStart=/usr/bin/myapp\n\n[Install]\nWantedBy=multi-user.target\n"`
	Enable  bool   `json:"enable,omitempty" doc:"Start it at boot"`
	Start   bool   `json:"start,omitempty" doc:"Start it now"`
}

type serviceOutput struct{ Body services.Service }

// ---- Routes ----

func registerServices(api huma.API, h *serverHandler) {
	tags := []string{"Services"}

	huma.Register(api, huma.Operation{
		OperationID: "list-services",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/services",
		Summary:     "Services on a server",
		Description: "Every systemd service unit (loaded or installed) with its state, boot setting, main PID, memory, CPU and " +
			"restarts; OpenRC init scripts with their state and runlevels; nothing when neither runs.",
		Tags: tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body ServicesOverview }, error) {
		out := &struct{ Body ServicesOverview }{}
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.rootShell(ctx, in.ID, c)
			if err != nil {
				return err
			}
			o, err := collectServices(ctx, sh)
			if err == nil {
				out.Body = *o
			}
			return err
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-service",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/services/{unit}",
		Summary:     "One service in detail",
		Description: "Its state plus dependencies, commands, environment, restart policy and its unit file with drop-ins " +
			"(systemctl cat). OpenRC: the init script and its conf.d file.",
		Tags: tags,
	}, func(ctx context.Context, in *ServicePath) (*struct{ Body ServiceDetails }, error) {
		out := &struct{ Body ServiceDetails }{}
		err := h.withService(ctx, in, false, func(sh *rootShell, init, unit string) error {
			d, err := serviceDetails(ctx, sh, init, unit)
			if err == nil {
				out.Body = *d
			}
			return err
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-service-logs",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/services/{unit}/logs",
		Summary:     "A service's recent journal",
		Description: "The last `lines` journal entries for the unit (journalctl -u), oldest first. For new entries as they come, use the stream.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServicePath
		Lines    int    `query:"lines" minimum:"1" maximum:"5000" default:"300"`
		Priority int    `query:"priority" minimum:"0" maximum:"7" default:"7" doc:"Only entries this important or more: 3 errors, 4 warnings, 6 info, 7 everything"`
		Since    string `query:"since" enum:",15m,1h,24h,7d,boot" doc:"Only entries since then; boot = since the last boot"`
	}) (*struct{ Body ServiceLogs }, error) {
		out := &struct{ Body ServiceLogs }{}
		err := h.withService(ctx, &in.ServicePath, false, func(sh *rootShell, init, unit string) error {
			if init != "systemd" {
				out.Body = ServiceLogs{Source: "none", Entries: []services.LogEntry{},
					Note: "This server has no systemd journal. OpenRC services log to their own files or syslog (/var/log/messages)."}
				return nil
			}
			raw, err := sh.run(ctx, journalScript(unit, journalArgs(in.Priority, in.Since)+" -n "+strconv.Itoa(in.Lines)))
			if err != nil {
				return err
			}
			out.Body = ServiceLogs{Source: "journal", Entries: []services.LogEntry{}}
			for _, l := range strings.Split(raw, "\n") {
				if e, ok := services.ParseJournalLine(l); ok {
					out.Body.Entries = append(out.Body.Entries, e)
				}
			}
			return nil
		})
		return out, toProblem(err)
	})

	sse.Register(api, huma.Operation{
		OperationID: "stream-service-logs",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/services/{unit}/logs/stream",
		Summary:     "Follow a service's journal",
		Description: "Server-sent events: an `entry` for every new journal line of the unit (journalctl -f), after `after` " +
			"when given; `problem` when it can't be followed, and the stream ends.",
		Tags: tags,
	}, map[string]any{"entry": services.LogEntry{}, "problem": StatsProblem{}},
		func(ctx context.Context, in *struct {
			ServicePath
			After    string `query:"after" maxLength:"1000" doc:"A cursor from the last entry already shown"`
			Priority int    `query:"priority" minimum:"0" maximum:"7" default:"7"`
		}, send sse.Sender) {
			err := h.withService(ctx, &in.ServicePath, false, func(sh *rootShell, init, unit string) error {
				if init != "systemd" {
					return huma.Error422UnprocessableEntity("This server has no systemd journal to follow")
				}
				args := journalArgs(in.Priority, "") + " -f"
				if in.After != "" {
					args += " --after-cursor " + q(in.After)
				} else {
					args += " -n 0"
				}
				return followJournal(ctx, sh, journalScript(unit, args), send)
			})
			if err != nil && ctx.Err() == nil {
				p := StatsProblem{Status: http.StatusBadGateway, Detail: err.Error()}
				if se, ok := toProblem(err).(huma.StatusError); ok {
					p.Status = se.GetStatus()
					if m, ok := se.(*huma.ErrorModel); ok {
						p.Detail = m.Detail
					}
				}
				send.Data(p)
			}
		})

	huma.Register(api, huma.Operation{
		OperationID: "service-action",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/services/{unit}/action",
		Summary:     "Start, stop, restart, enable… a service",
		Description: "Waits for systemd to finish the job; a failed start answers 422 with systemd's reason. Answers the service as " +
			"it is after. Stopping, disabling, masking or killing a protected service (sshd, dbus, journald…) needs `force`. " +
			"OpenRC: start/stop/restart/reload, enable/disable (default runlevel), reset-failed (zap).",
		Tags: tags,
	}, func(ctx context.Context, in *struct {
		ServicePath
		Body ServiceActionBody
	}) (*serviceOutput, error) {
		// Operators keep services running; changing how they run is for Engineers.
		routine := slices.Contains([]string{"start", "stop", "restart", "reload"}, in.Body.Action)
		if (!routine || in.Body.Force) && principalOf(ctx).Level < auth.Engineer {
			return nil, forbidden(auth.Engineer)
		}
		out := &serviceOutput{}
		err := h.withService(ctx, &in.ServicePath, true, func(sh *rootShell, init, unit string) error {
			b := in.Body
			if services.Protected(unit) && !b.Force && slices.Contains([]string{"stop", "disable", "mask", "kill"}, b.Action) {
				return huma.Error422UnprocessableEntity(unit + " is protected: Morcheh or the system needs it. Send force to " + b.Action + " it anyway")
			}
			script, err := actionScript(init, unit, b)
			if err != nil {
				return err
			}
			if err := runChange(ctx, sh, script); err != nil {
				return err
			}
			s, err := oneService(ctx, sh, init, unit)
			if err == nil {
				out.Body = *s
			}
			return err
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "save-service-override",
		Method:      http.MethodPut,
		Path:        "/servers/{id}/services/{unit}/override",
		Summary:     "Save a service's override",
		Description: "Writes /etc/systemd/system/<unit>.d/override.conf (what `systemctl edit` does; empty content removes it), " +
			"reloads systemd and checks the unit still loads, else puts the old file back (422 with systemd's reason). " +
			"A stale `revision` answers 409.",
		Tags: tags,
	}, func(ctx context.Context, in *struct {
		ServicePath
		Body ServiceFileBody
	}) (*serviceOutput, error) {
		out := &serviceOutput{}
		err := h.withService(ctx, &in.ServicePath, true, func(sh *rootShell, init, unit string) error {
			if init != "systemd" {
				return huma.Error422UnprocessableEntity("Overrides are a systemd feature")
			}
			s, err := writeUnitFile(ctx, sh, unit, overridePath(unit), in.Body)
			if err == nil {
				out.Body = *s
			}
			return err
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "save-service-file",
		Method:      http.MethodPut,
		Path:        "/servers/{id}/services/{unit}/file",
		Summary:     "Save a custom service's unit file",
		Description: "Only for units whose file is in /etc/systemd/system (not a link to a package's file): writes it, reloads " +
			"systemd and checks it loads, else restores it (422). Packaged units are changed with an override.",
		Tags: tags,
	}, func(ctx context.Context, in *struct {
		ServicePath
		Body ServiceFileBody
	}) (*serviceOutput, error) {
		out := &serviceOutput{}
		err := h.withService(ctx, &in.ServicePath, true, func(sh *rootShell, init, unit string) error {
			if init != "systemd" {
				return huma.Error422UnprocessableEntity("Editing unit files needs systemd")
			}
			cur, err := oneService(ctx, sh, init, unit)
			if err != nil {
				return err
			}
			if !cur.Custom {
				return huma.Error422UnprocessableEntity(unit + " comes from a package (" + cur.Path + "); change it with an override")
			}
			if strings.TrimSpace(in.Body.Content) == "" {
				return fieldError("body.content", "A unit file can't be empty", nil)
			}
			s, err := writeUnitFile(ctx, sh, unit, cur.Path, in.Body)
			if err == nil {
				out.Body = *s
			}
			return err
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-service",
		Method:        http.MethodPost,
		Path:          "/servers/{id}/services",
		Summary:       "Add a service",
		Description:   "Writes /etc/systemd/system/<name>, reloads systemd, checks it loads, then enables and starts it when asked.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body ServiceCreateBody
	}) (*serviceOutput, error) {
		out := &serviceOutput{}
		name := in.Body.Name
		if !strings.HasSuffix(name, ".service") {
			name += ".service"
		}
		if !unitRe.MatchString(name) || strings.Contains(name, "@") || strings.Contains(name, "\\") {
			return nil, fieldError("body.name", "Use letters, digits and : _ . - (no spaces)", in.Body.Name)
		}
		p := &ServicePath{ID: in.ID, Unit: name}
		err := h.withService(ctx, p, true, func(sh *rootShell, init, unit string) error {
			if init != "systemd" {
				return huma.Error422UnprocessableEntity("Adding services needs systemd")
			}
			raw, err := sh.run(ctx, "systemctl show -p LoadState "+q(unit)+"; [ -e "+q("/etc/systemd/system/"+unit)+" ] && echo exists; exit 0")
			if err != nil {
				return err
			}
			if strings.Contains(raw, "exists") || !strings.Contains(raw, "LoadState=not-found") {
				return fieldError("body.name", unit+" already exists", in.Body.Name)
			}
			if _, err := writeUnitFile(ctx, sh, unit, "/etc/systemd/system/"+unit,
				ServiceFileBody{Content: in.Body.Content, Revision: services.Revision("")}); err != nil {
				return err
			}
			var then []string
			if in.Body.Enable {
				then = append(then, "systemctl enable "+q(unit))
			}
			if in.Body.Start {
				then = append(then, "systemctl start "+q(unit))
			}
			if len(then) > 0 {
				if err := runChange(ctx, sh, strings.Join(then, " && ")); err != nil {
					return huma.Error422UnprocessableEntity("Added " + unit + ", but: " + errDetail(err))
				}
			}
			s, err := oneService(ctx, sh, init, unit)
			if err == nil {
				out.Body = *s
			}
			return err
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-service",
		Method:        http.MethodDelete,
		Path:          "/servers/{id}/services/{unit}",
		Summary:       "Remove a custom service",
		Description:   "Stops and disables it, deletes its unit file and drop-ins from /etc/systemd/system and reloads systemd. Packaged units can't be removed here.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *ServicePath) (*struct{}, error) {
		err := h.withService(ctx, in, true, func(sh *rootShell, init, unit string) error {
			if init != "systemd" {
				return huma.Error422UnprocessableEntity("Removing services needs systemd")
			}
			cur, err := oneService(ctx, sh, init, unit)
			if err != nil {
				return err
			}
			if !cur.Custom {
				return huma.Error422UnprocessableEntity(unit + " comes from a package; disable or mask it instead")
			}
			if cur.Protected {
				return huma.Error422UnprocessableEntity(unit + " is protected: Morcheh or the system needs it")
			}
			u := q(unit)
			return runChange(ctx, sh, "systemctl disable --now "+u+" 2>/dev/null\nrm -f "+q(cur.Path)+"\nrm -rf "+
				q("/etc/systemd/system/"+unit+".d")+"\nsystemctl daemon-reload\nsystemctl reset-failed "+u+" 2>/dev/null\nexit 0")
		})
		return nil, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID:   "reload-services",
		Method:        http.MethodPost,
		Path:          "/servers/{id}/services/daemon-reload",
		Summary:       "Reload systemd",
		Description:   "systemctl daemon-reload: systemd rereads every unit file changed on disk. Running services keep running.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{}, error) {
		p := &ServicePath{ID: in.ID, Unit: "daemon-reload"}
		err := h.withService(ctx, p, true, func(sh *rootShell, init, _ string) error {
			if init != "systemd" {
				return huma.Error422UnprocessableEntity("This server doesn't run systemd")
			}
			return runChange(ctx, sh, "systemctl daemon-reload")
		})
		return nil, toProblem(err)
	})
}

// ---- Reading ----

const initScript = `if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then echo systemd
elif command -v rc-service >/dev/null 2>&1 && [ -d /run/openrc ]; then echo openrc
else echo none; fi
`

var servicesScript = `PATH="$PATH:/usr/sbin:/sbin"
m=` + cronMarker + `
case $(` + initScript + `) in
systemd)
  echo "$m init systemd"
  echo "$m version"; systemctl --version 2>/dev/null | head -n 1
  echo "$m state"; systemctl is-system-running 2>/dev/null
  u=$( { systemctl list-units --type=service --all --no-legend --plain --no-pager; systemctl list-unit-files --type=service --no-legend --no-pager; } 2>/dev/null | awk '$1 ~ /\.service$/ && $1 !~ /@\.service$/ { print $1 }' | sort -u)
  echo "$m show"
  if [ -n "$u" ]; then
    systemctl show --no-pager --timestamp=unix -p ` + strings.Join(services.ListProps, ",") + ` $u 2>/dev/null ||
      systemctl show --no-pager -p ` + strings.Join(services.ListProps, ",") + ` $u 2>/dev/null
  fi ;;
openrc)
  echo "$m init openrc"
  echo "$m version"; openrc --version 2>/dev/null | head -n 1
  echo "$m scripts"
  for f in /etc/init.d/*; do
    [ -f "$f" ] && [ -x "$f" ] || continue
    n=${f##*/}
    case $n in *.sh|functions*) continue ;; esac
    printf '%s\t%s\n' "$n" "$(sed -n 's/^[[:space:]]*description=//p' "$f" 2>/dev/null | head -n 1)"
  done
  echo "$m status"; rc-status --all --nocolor 2>/dev/null || rc-status --all 2>/dev/null
  echo "$m update"; rc-update show -v 2>/dev/null ;;
*) echo "$m init none" ;;
esac
exit 0
`

func collectServices(ctx context.Context, sh *rootShell) (*ServicesOverview, error) {
	raw, err := sh.run(ctx, servicesScript)
	if err != nil {
		return nil, err
	}
	o := &ServicesOverview{Init: "none", Access: sh.priv.access(), Services: []services.Service{}, Warnings: []string{}}
	var rc services.OpenRCInput
	for _, sec := range splitSections(raw) {
		body := strings.TrimSpace(sec.body)
		switch sec.kind {
		case "init":
			o.Init = strings.Join(sec.args, " ")
		case "version":
			o.Version = body
		case "state":
			o.State = body
		case "show":
			o.Services = services.List(services.ParseShow(sec.body))
		case "scripts":
			rc.Scripts = cleanDescriptions(sec.body)
		case "status":
			rc.Status = sec.body
		case "update":
			rc.Update = sec.body
		}
	}
	if o.Init == "openrc" {
		o.Services = services.OpenRC(rc)
	}
	slices.SortFunc(o.Services, func(a, b services.Service) int { return strings.Compare(a.Name, b.Name) })
	return o, nil
}

// cleanDescriptions strips the quotes off description="…" values.
func cleanDescriptions(body string) string {
	lines := strings.Split(body, "\n")
	for i, l := range lines {
		if name, desc, ok := strings.Cut(l, "\t"); ok {
			lines[i] = name + "\t" + strings.Trim(strings.TrimSpace(desc), `"'`)
		}
	}
	return strings.Join(lines, "\n")
}

func showScript(unit string, props []string) string {
	p := strings.Join(props, ",")
	return "systemctl show --no-pager --timestamp=unix -p " + p + " " + q(unit) + " 2>/dev/null || systemctl show --no-pager -p " + p + " " + q(unit)
}

// oneService reads one service as the list shows it.
func oneService(ctx context.Context, sh *rootShell, init, unit string) (*services.Service, error) {
	if init == "openrc" {
		o, err := collectServices(ctx, sh)
		if err != nil {
			return nil, err
		}
		for _, s := range o.Services {
			if s.Name == unit {
				return &s, nil
			}
		}
		return nil, noService(unit)
	}
	raw, err := sh.run(ctx, showScript(unit, services.ListProps))
	if err != nil {
		return nil, err
	}
	blocks := services.ParseShow(raw)
	if len(blocks) == 0 {
		return nil, noService(unit)
	}
	s := services.FromProps(blocks[0])
	if s.Load == "not-found" && s.Active == "inactive" {
		return nil, noService(unit)
	}
	return &s, nil
}

func serviceDetails(ctx context.Context, sh *rootShell, init, unit string) (*ServiceDetails, error) {
	if init == "openrc" {
		s, err := oneService(ctx, sh, init, unit)
		if err != nil {
			return nil, err
		}
		raw, err := sh.run(ctx, "for f in "+q("/etc/init.d/"+unit)+" "+q("/etc/conf.d/"+unit)+"; do [ -r \"$f\" ] && { echo \"# $f\"; cat \"$f\"; echo; }; done; exit 0")
		if err != nil {
			return nil, err
		}
		d := services.Details{Service: *s, Requires: []string{}, Wants: []string{}, WantedBy: []string{}, RequiredBy: []string{},
			After: []string{}, Before: []string{}, Conflicts: []string{}, ExecStart: []string{}, Environment: []string{},
			EnvironmentFiles: []string{}, Documentation: []string{}, Files: services.ParseCat(raw)}
		return &ServiceDetails{Details: d, Init: init}, nil
	}
	m := cronMarker
	raw, err := sh.run(ctx, "echo '"+m+" show'\n"+showScript(unit, services.DetailProps)+"\necho '"+m+" cat'\nsystemctl cat --no-pager "+
		q(unit)+" 2>/dev/null\necho '"+m+" override'\ncat "+q(overridePath(unit))+" 2>/dev/null\nexit 0")
	if err != nil {
		return nil, err
	}
	var show, cat, override string
	for _, sec := range splitSections(raw) {
		switch sec.kind {
		case "show":
			show = sec.body
		case "cat":
			cat = sec.body
		case "override":
			override = sec.body
		}
	}
	blocks := services.ParseShow(show)
	if len(blocks) == 0 {
		return nil, noService(unit)
	}
	d := services.DetailsFrom(blocks[0], cat)
	if d.Load == "not-found" && d.Active == "inactive" {
		return nil, noService(unit)
	}
	out := &ServiceDetails{Details: d, Init: init, Override: overridePath(unit), Revision: services.Revision(override)}
	for _, f := range d.Files {
		if f.Path == d.Path {
			out.FileRevision = services.Revision(f.Content)
		}
	}
	return out, nil
}

// ---- Changing ----

var unitRe = regexp.MustCompile(`^[A-Za-z0-9:_.@\\][A-Za-z0-9:_.@\\-]*$`)

func noService(unit string) error { return huma.Error404NotFound("No service named " + unit) }

// withService checks the unit name, finds the init system and runs fn as
// root when possible; write needs root or sudo.
func (h *serverHandler) withService(ctx context.Context, in *ServicePath, write bool, fn func(sh *rootShell, init, unit string) error) error {
	unit := in.Unit
	if !unitRe.MatchString(unit) {
		return fieldError("path.unit", "Not a service name", unit)
	}
	return h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
		sh, err := h.rootShell(ctx, in.ID, c)
		if err != nil {
			return err
		}
		if write && sh.priv == privUser {
			return huma.Error403Forbidden("Managing services needs root or sudo on this server")
		}
		raw, err := sh.run(ctx, initScript)
		if err != nil {
			return err
		}
		init := strings.TrimSpace(raw)
		switch init {
		case "systemd":
			if unit != "daemon-reload" && !strings.Contains(unit, ".") {
				unit += ".service"
			}
		case "openrc":
		default:
			return huma.Error422UnprocessableEntity("This server runs neither systemd nor OpenRC, so there are no services to manage")
		}
		return fn(sh, init, unit)
	})
}

func actionScript(init, unit string, b ServiceActionBody) (string, error) {
	u := q(unit)
	if init == "openrc" {
		start, stop := "", ""
		if b.Now {
			start, stop = " && rc-service "+u+" start", " && rc-service "+u+" stop"
		}
		switch b.Action {
		case "start", "stop", "restart", "reload":
			return "rc-service " + u + " " + b.Action, nil
		case "enable":
			return "rc-update add " + u + " default" + start, nil
		case "disable":
			return "rc-update del " + u + " default" + stop, nil
		case "reset-failed":
			return "rc-service " + u + " zap", nil
		}
		return "", huma.Error422UnprocessableEntity("OpenRC can't " + b.Action + " a service")
	}
	now := ""
	if b.Now {
		now = " --now"
	}
	switch b.Action {
	case "enable", "disable", "mask":
		return "systemctl " + b.Action + now + " " + u, nil
	case "start", "restart":
		// A simple service counts as started at once; wait a moment so one
		// that exits straight away comes back as failed, not running.
		return "systemctl " + b.Action + " " + u + " && sleep 1", nil
	case "kill":
		sig := b.Signal
		if sig == "" {
			sig = "TERM"
		}
		return "systemctl kill -s " + sig + " " + u, nil
	}
	return "systemctl " + b.Action + " " + u, nil
}

// runChange runs a script as root; a non-zero exit is a 422 with what the
// command said (systemd's first line is its reason).
func runChange(ctx context.Context, sh *rootShell, script string) error {
	res, err := sh.exec(ctx, "PATH=\"$PATH:/usr/sbin:/sbin\"\n"+script, 2*time.Minute, 64<<10)
	if err != nil {
		return err
	}
	switch {
	case res.timedOut:
		return huma.Error504GatewayTimeout("The server took too long; the job may still be running")
	case res.code != 0:
		return huma.Error422UnprocessableEntity(systemdReason(string(res.output), res.code))
	}
	return nil
}

// systemdReason keeps what explains a failure and drops systemd's pointers
// to `systemctl status` / `journalctl -xe`.
func systemdReason(out string, code int) string {
	var keep []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "See \"systemctl status") || strings.HasPrefix(l, "See 'systemctl status") ||
			strings.HasPrefix(l, "details.") || strings.HasPrefix(l, "\"journalctl -xe") {
			continue
		}
		keep = append(keep, l)
	}
	if len(keep) == 0 {
		return fmt.Sprintf("The command failed (exit %d)", code)
	}
	return strings.Join(keep[max(0, len(keep)-4):], "\n")
}

func errDetail(err error) string {
	if m, ok := err.(*huma.ErrorModel); ok {
		return m.Detail
	}
	return err.Error()
}

func overridePath(unit string) string { return "/etc/systemd/system/" + unit + ".d/override.conf" }

// writeUnitFile writes a unit file or drop-in (empty content removes a
// drop-in), reloads systemd and checks the unit still loads, else puts the
// old file back. Answers the unit as it is after.
func writeUnitFile(ctx context.Context, sh *rootShell, unit, path string, b ServiceFileBody) (*services.Service, error) {
	cur, err := sh.run(ctx, "cat "+q(path)+" 2>/dev/null; exit 0")
	if err != nil {
		return nil, err
	}
	if services.Revision(cur) != b.Revision {
		return nil, huma.Error409Conflict("The file changed on the server since you opened it")
	}
	content := services.Normalize(b.Content)
	p, bak := q(path), q(path+".morcheh-bak")
	dir := q(path[:strings.LastIndex(path, "/")])
	var script string
	if content == "" {
		script = "[ -f " + p + " ] && mv -f " + p + " " + bak + "\nrmdir " + dir + " 2>/dev/null\n"
	} else {
		eof := "MORCHEH_" + randomSuffix()
		script = "mkdir -p " + dir + "\nrm -f " + bak + "\n[ -f " + p + " ] && cp -p " + p + " " + bak + "\ncat > " + p +
			" <<'" + eof + "'\n" + content + eof + "\nchmod 644 " + p + "\n"
	}
	restore := "rm -f " + p + "\n[ -f " + bak + " ] && mv -f " + bak + " " + p + "\nrmdir " + dir + " 2>/dev/null\n"
	if content != "" {
		// systemd only warns about a bad line and ignores it; verify finds
		// those lines before anything is reloaded.
		script += "command -v systemd-analyze >/dev/null && timeout 30 systemd-analyze verify " + q(unit) +
			" 2>&1 | grep -F -e " + q(path+":") + " -e " + q(unit+": ") + "\nexit 0\n"
	}
	out, err := sh.run(ctx, script)
	if err != nil {
		return nil, err
	}
	verify := out
	if issues := verifyIssues(verify, path); issues != "" {
		if _, err := sh.run(ctx, restore+"exit 0"); err != nil {
			return nil, err
		}
		return nil, fieldError("body.content", issues, nil)
	}
	out, err = sh.run(ctx, "systemctl daemon-reload\nsystemctl show -p LoadState -p LoadError "+q(unit))
	if err != nil {
		return nil, err
	}
	props := services.ParseShow("Id=" + unit + "\n" + out)
	if len(props) > 0 {
		if st := props[0]["LoadState"]; len(st) > 0 && (st[0] == "bad-setting" || st[0] == "error") {
			reason := "systemd can't load it"
			if r := unitIssue(verify, unit); r != "" {
				reason = r
			} else if le := props[0]["LoadError"]; len(le) > 0 {
				// org.freedesktop.systemd1.BadUnitSetting "Unit x.service has a bad unit file setting."
				if _, msg, ok := strings.Cut(le[0], " "); ok {
					reason = strings.TrimSuffix(strings.Trim(msg, `"`), ".")
				}
			}
			if _, err := sh.run(ctx, restore+"systemctl daemon-reload\n"); err != nil {
				return nil, err
			}
			return nil, fieldError("body.content", reason+". Nothing was changed.", nil)
		}
	}
	if _, err := sh.run(ctx, "rm -f "+bak); err != nil {
		return nil, err
	}
	if b.Restart {
		if err := runChange(ctx, sh, "systemctl is-active -q "+q(unit)+" && systemctl restart "+q(unit)+"; exit 0"); err != nil {
			return nil, err
		}
	}
	return oneService(ctx, sh, "systemd", unit)
}

// verifyIssues turns systemd-analyze's complaints about path into lines
// like "Line 3: Missing '='"; empty when there are none.
func verifyIssues(out, path string) string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(l), path+":")
		if !ok {
			continue
		}
		n, msg, ok := strings.Cut(rest, ":")
		if _, err := strconv.Atoi(n); !ok || err != nil {
			continue
		}
		msg = strings.TrimSuffix(strings.TrimSpace(msg), ".")
		msg = strings.TrimSuffix(strings.Replace(msg, ", ignoring:", ":", 1), ", ignoring line")
		msg = strings.TrimSuffix(msg, ", ignoring")
		lines = append(lines, "Line "+n+": "+msg)
	}
	return strings.Join(lines, "\n")
}

// unitIssue is what systemd-analyze said about the unit as a whole, e.g.
// "Service has no ExecStart=, ExecStop=, or SuccessAction=. Refusing".
func unitIssue(out, unit string) string {
	for _, l := range strings.Split(out, "\n") {
		if msg, ok := strings.CutPrefix(strings.TrimSpace(l), unit+": "); ok {
			return strings.TrimSuffix(msg, ".")
		}
	}
	return ""
}

// ---- Journal ----

var sinceArgs = map[string]string{"15m": "--since=-15min", "1h": "--since=-1h", "24h": "--since=-24h", "7d": "--since=-7d", "boot": "-b"}

func journalArgs(priority int, since string) string {
	a := ""
	if priority < 7 {
		a += " -p " + strconv.Itoa(priority)
	}
	if s := sinceArgs[since]; s != "" {
		a += " " + s
	}
	return a
}

// journalScript reads the unit's journal as JSON, with only the fields the
// page uses when journalctl supports picking them (systemd 236+).
func journalScript(unit, args string) string {
	base := "journalctl -q --no-pager -o json -u " + q(unit) + args
	return base + " --output-fields=MESSAGE,PRIORITY,_PID,SYSLOG_IDENTIFIER 2>/dev/null || " + base
}

// followJournal streams journalctl -f until ctx ends. The script keeps
// reading stdin, so when the stream closes (stdin ends) it stops journalctl
// instead of leaving it behind on the server.
func followJournal(ctx context.Context, sh *rootShell, script string, send sse.Sender) error {
	cmd, password := sh.command("( " + script + " ) & p=$!\ncat >/dev/null\nkill $p 2>/dev/null\n")
	sess, err := sh.c.Client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return err
	}
	pr, pw := io.Pipe()
	sess.Stdin = pr
	go func() {
		if password != "" {
			pw.Write([]byte(password))
		}
		<-ctx.Done()
		pw.Close()
	}()
	if err := sess.Start(cmd); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { sess.Close() })
	defer stop()

	lines := make(chan string, 256)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case l, ok := <-lines:
			if !ok {
				return nil
			}
			if e, ok := services.ParseJournalLine(l); ok {
				if send.Data(e) != nil {
					return nil
				}
			}
		case <-ping.C:
			if send(sse.Message{Comment: "ping"}) != nil {
				return nil
			}
		}
	}
}
