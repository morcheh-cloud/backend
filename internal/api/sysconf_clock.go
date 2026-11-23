package api

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morche/backend/internal/sshpool"
	"github.com/morche/backend/internal/sysconf"
	"github.com/morche/backend/internal/terminal"
)

const (
	hostnamePath    = "/etc/hostname"
	timesyncdConf   = "/etc/systemd/timesyncd.conf"
	timesyncdDropIn = "/etc/systemd/timesyncd.conf.d/90-morche.conf"
)

var (
	chronyConfs = []string{"/etc/chrony/chrony.conf", "/etc/chrony.conf"}
	clockFiles  = append(append([]string{}, chronyConfs...), timesyncdConf, timesyncdDropIn)
)

type ClockOverview struct {
	Revision       string   `json:"revision" doc:"Covers the time-sync files"`
	Hostname       string   `json:"hostname"`
	PrettyHostname string   `json:"pretty_hostname" doc:"The free-text name some tools show"`
	Timezone       string   `json:"timezone" example:"Asia/Tehran"`
	LocalTime      string   `json:"local_time" doc:"The server's clock when it was read, with its offset" example:"2026-11-23T10:00:00+0330"`
	Service        string   `json:"service" enum:"chrony,timesyncd,ntpd,none" doc:"What keeps the clock right"`
	NTP            bool     `json:"ntp" doc:"Time sync is turned on"`
	CanNTP         bool     `json:"can_ntp" doc:"timedatectl can turn time sync on or off"`
	Synced         bool     `json:"synced" doc:"The clock is in step with its time servers"`
	OffsetMS       *float64 `json:"offset_ms" doc:"How far the clock is from its time servers (positive = ahead)"`
	Servers        []string `json:"servers" doc:"The time servers it asks"`
	CanSetServers  bool     `json:"can_set_servers"`
	Writable       bool     `json:"writable" doc:"Morche has root or sudo here"`
}

type HostnameBody struct {
	Hostname       string `json:"hostname" maxLength:"253" example:"web-1"`
	PrettyHostname string `json:"pretty_hostname,omitempty" required:"false" maxLength:"64"`
	FixHosts       bool   `json:"fix_hosts" doc:"Point 127.0.1.1 in /etc/hosts at the new name too (recommended: sudo slows down otherwise)"`
}

type HostnameInput struct {
	ID   string `path:"id" format:"uuid"`
	Body HostnameBody
}

type ClockBody struct {
	Revision string   `json:"revision"`
	Timezone string   `json:"timezone,omitempty" required:"false"`
	NTP      *bool    `json:"ntp,omitempty" required:"false"`
	Servers  []string `json:"servers,omitempty" required:"false" maxItems:"10" doc:"Leave out to keep them"`
}

type ClockInput struct {
	ID   string `path:"id" format:"uuid"`
	Body ClockBody
}

var tzRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+\-]*(/[A-Za-z0-9_+\-]+)*$`)

func validTimezone(z string) bool { return len(z) <= 64 && tzRe.MatchString(z) }

var (
	chronyOffset = regexp.MustCompile(`System time\s*:\s*([0-9.]+) seconds (fast|slow)`)
	syncOffset   = regexp.MustCompile(`Offset:\s*([+-]?[0-9.]+)(us|ms|s|min)`)
)

// parseClockOffset reads chronyc tracking or timedatectl timesync-status, in
// milliseconds, positive = the clock is ahead.
func parseClockOffset(out string) (float64, bool) {
	if m := chronyOffset.FindStringSubmatch(out); m != nil {
		v, _ := strconv.ParseFloat(m[1], 64)
		if m[2] == "slow" {
			v = -v
		}
		return v * 1000, true
	}
	if m := syncOffset.FindStringSubmatch(out); m != nil {
		v, _ := strconv.ParseFloat(m[1], 64)
		switch m[2] {
		case "us":
			v /= 1000
		case "s":
			v *= 1000
		case "min":
			v *= 60000
		}
		return v, true
	}
	return 0, false
}

const clockScript = `echo "P $(hostnamectl --pretty 2>/dev/null)"
echo "H $(hostname)"
echo "N $(date +%Y-%m-%dT%H:%M:%S%z)"
timedatectl show 2>/dev/null | sed 's/^/T /'
echo "Z $(readlink /etc/localtime 2>/dev/null)"
echo "Y $(cat /etc/timezone 2>/dev/null)"
for s in chronyd chrony systemd-timesyncd ntpd ntp; do [ "$(systemctl is-active $s 2>/dev/null)" = active ] && echo "S $s"; done
(chronyc -n tracking 2>/dev/null || timedatectl timesync-status 2>/dev/null) | sed 's/^/O /'
true`

type clockFacts struct {
	o    ClockOverview
	unit string // the systemd unit of the time service
	// chrony's sourcedir files (Ubuntu keeps its pools there).
	sources []string
}

const (
	chronySourceDir = "/etc/chrony/sources.d"
	chronyMorche    = chronySourceDir + "/90-morche.sources"
)

func (f clockFacts) files() []string {
	out := append([]string{}, clockFiles...)
	for _, s := range f.sources {
		if s != chronyMorche {
			out = append(out, s)
		}
	}
	return append(out, chronyMorche)
}

func readClock(out string) clockFacts {
	var f clockFacts
	var td, offset strings.Builder
	zoneLink, zoneFile := "", ""
	for _, l := range strings.Split(out, "\n") {
		if len(l) < 2 {
			continue
		}
		k, v := l[:1], strings.TrimSpace(l[2:])
		switch k {
		case "P":
			f.o.PrettyHostname = v
		case "H":
			f.o.Hostname = v
		case "N":
			f.o.LocalTime = v
		case "T":
			td.WriteString(v + "\n")
		case "Z":
			zoneLink = v
		case "Y":
			zoneFile = v
		case "S":
			if f.unit == "" {
				f.unit = v
			}
		case "O":
			offset.WriteString(v + "\n")
		}
	}
	c := sysconf.ParseTimedatectl(td.String())
	f.o.Timezone, f.o.NTP, f.o.Synced, f.o.CanNTP = c.Timezone, c.NTP, c.Synced, c.CanNTP
	if f.o.Timezone == "" {
		if i := strings.Index(zoneLink, "zoneinfo/"); i >= 0 {
			f.o.Timezone = zoneLink[i+len("zoneinfo/"):]
		} else {
			f.o.Timezone = zoneFile
		}
	}
	switch f.unit {
	case "chronyd", "chrony":
		f.o.Service = "chrony"
	case "systemd-timesyncd":
		f.o.Service = "timesyncd"
	case "ntpd", "ntp":
		f.o.Service = "ntpd"
	default:
		f.o.Service = "none"
	}
	if ms, ok := parseClockOffset(offset.String()); ok {
		f.o.OffsetMS = &ms
	}
	return f
}

func chronyConf(files []configFile) (string, string) {
	for _, p := range chronyConfs {
		if t, ok := fileText(files, p); ok {
			return p, t
		}
	}
	return "", ""
}

func (h *serverHandler) clockFacts(ctx context.Context, sh *rootShell) (clockFacts, []configFile, string, error) {
	out, err := sh.run(ctx, clockScript)
	if err != nil {
		return clockFacts{}, nil, "", err
	}
	f := readClock(out)
	f.sources, err = listFiles(ctx, sh, chronySourceDir+"/*.sources")
	if err != nil {
		return f, nil, "", err
	}
	files, rev, err := readConfigFiles(ctx, sh, f.files()...)
	if err != nil {
		return f, nil, "", err
	}
	f.o.Revision = rev
	f.o.Writable = sh.priv != privUser
	f.o.Servers = []string{}
	switch f.o.Service {
	case "chrony":
		if p, t := chronyConf(files); p != "" {
			servers := sysconf.ParseChronyServers(t)
			for _, src := range f.sources {
				st, _ := fileText(files, src)
				servers = append(servers, sysconf.ParseChronyServers(st)...)
			}
			f.o.Servers = orEmpty(servers)
			f.o.CanSetServers = true
		}
	case "timesyncd":
		f.o.CanSetServers = true
		if t, ok := fileText(files, timesyncdDropIn); ok {
			f.o.Servers = orEmpty(sysconf.ParseTimesyncd(t))
		} else {
			t, _ := fileText(files, timesyncdConf)
			f.o.Servers = orEmpty(sysconf.ParseTimesyncd(t))
		}
	}
	return f, files, rev, nil
}

func (h *serverHandler) clockOverview(ctx context.Context, id string) (*ClockOverview, error) {
	var o ClockOverview
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.rootShell(ctx, id, c)
		if err != nil {
			return err
		}
		f, _, _, err := h.clockFacts(ctx, sh)
		o = f.o
		return err
	})
	return &o, toProblem(err)
}

func timeServiceRestart(unit string) string {
	if unit == "" {
		return ""
	}
	return "systemctl restart " + terminal.ShellQuote(unit)
}

func andThen(parts ...string) string {
	var keep []string
	for _, p := range parts {
		if p != "" {
			keep = append(keep, p)
		}
	}
	return strings.Join(keep, " && ")
}

func registerConfigClock(api huma.API, h *serverHandler) {
	tags := []string{"Server config"}

	huma.Register(api, huma.Operation{
		OperationID: "get-server-clock",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/clock",
		Summary:     "The server's name, time zone and time sync",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body ClockOverview }, error) {
		o, err := h.clockOverview(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body ClockOverview }{*o}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-server-hostname",
		Method:      http.MethodPut,
		Path:        "/servers/{id}/hostname",
		Summary:     "Rename the server",
		Description: "Writes /etc/hostname, sets the running name and (with fix_hosts) points 127.0.1.1 in /etc/hosts at it. Morche's own name for the server stays as it is.",
		Tags:        tags,
	}, func(ctx context.Context, in *HostnameInput) (*struct{ Body ClockOverview }, error) {
		b := in.Body
		if !sysconf.ValidHostname(b.Hostname) {
			return nil, fieldError("body.hostname", "Use letters, digits, hyphens and dots; no spaces", b.Hostname)
		}
		if strings.ContainsAny(b.PrettyHostname, "\n\r\x00'\"\\`$") {
			return nil, fieldError("body.pretty_hostname", "Keep it to plain text", b.PrettyHostname)
		}
		_, err := h.configChange(ctx, in.ID, "", func(sh *rootShell) (configPlan, error) {
			files, _, err := readConfigFiles(ctx, sh, hostnamePath, hostsPath)
			if err != nil {
				return configPlan{}, err
			}
			old, _ := sh.run(ctx, "hostname")
			old = strings.TrimSpace(old)
			q := terminal.ShellQuote(b.Hostname)
			p := configPlan{
				Area: "clock", Summary: "Rename to " + b.Hostname,
				Read:   []string{hostnamePath, hostsPath},
				Writes: []configWrite{{Path: hostnamePath, Text: b.Hostname + "\n"}},
				Apply:  "hostname " + q + " && { ! command -v hostnamectl >/dev/null 2>&1 || hostnamectl set-hostname " + q + " 2>/dev/null || true; }",
				Undo:   `hostname "$(cat /etc/hostname)"; command -v hostnamectl >/dev/null 2>&1 && hostnamectl set-hostname "$(cat /etc/hostname)" 2>/dev/null`,
			}
			if b.PrettyHostname != "" {
				p.Apply += " && { hostnamectl set-hostname --pretty " + terminal.ShellQuote(b.PrettyHostname) + " 2>/dev/null || true; }"
			}
			if b.FixHosts {
				hosts, _ := fileText(files, hostsPath)
				p.Writes = append(p.Writes, configWrite{Path: hostsPath, Text: sysconf.SetHostname(hosts, old, b.Hostname)})
			}
			return p, nil
		})
		if err != nil {
			return nil, err
		}
		o, err := h.clockOverview(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body ClockOverview }{*o}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-server-clock",
		Method:      http.MethodPut,
		Path:        "/servers/{id}/clock",
		Summary:     "Set the time zone and time sync",
		Description: "Each field left out stays as it is. Time servers go into chrony's config or Morche's timesyncd drop-in, then the service restarts.",
		Tags:        tags,
	}, func(ctx context.Context, in *ClockInput) (*struct{ Body ClockOverview }, error) {
		b := in.Body
		if b.Timezone != "" && !validTimezone(b.Timezone) {
			return nil, fieldError("body.timezone", "Not a time zone name", b.Timezone)
		}
		for i, s := range b.Servers {
			if !sysconf.ValidServerName(s) {
				return nil, fieldError("body.servers["+itoa(i)+"]", "Give a host name or an IP address", s)
			}
		}
		_, err := h.configChange(ctx, in.ID, b.Revision, func(sh *rootShell) (configPlan, error) {
			f, files, _, err := h.clockFacts(ctx, sh)
			if err != nil {
				return configPlan{}, err
			}
			p := configPlan{Area: "clock", Read: f.files(), Keep: []string{"/etc/localtime", "/etc/timezone"}}
			var what []string
			if b.Timezone != "" && b.Timezone != f.o.Timezone {
				z := terminal.ShellQuote(b.Timezone)
				p.Check = andThen(p.Check, "[ -f /usr/share/zoneinfo/"+z+" ] || { echo 'There is no time zone called '"+z+"; exit 1; }")
				p.Apply = andThen(p.Apply, "{ timedatectl set-timezone "+z+" 2>/dev/null || { ln -sf /usr/share/zoneinfo/"+z+" /etc/localtime && echo "+z+" > /etc/timezone; }; }")
				what = append(what, "time zone "+b.Timezone)
			}
			if b.NTP != nil && *b.NTP != f.o.NTP {
				if !f.o.CanNTP {
					return p, huma.Error422UnprocessableEntity("timedatectl can't turn time sync on or off here: no time sync service is installed")
				}
				p.Apply = andThen(p.Apply, "timedatectl set-ntp "+strconv.FormatBool(*b.NTP))
				what = append(what, map[bool]string{true: "time sync on", false: "time sync off"}[*b.NTP])
			}
			if b.Servers != nil {
				switch f.o.Service {
				case "chrony":
					path, text := chronyConf(files)
					if path == "" {
						return p, huma.Error422UnprocessableEntity("chrony's config file wasn't found")
					}
					if len(b.Servers) == 0 {
						return p, fieldError("body.servers", "Give at least one time server", b.Servers)
					}
					if strings.Contains(text, "sourcedir "+chronySourceDir) {
						// The servers go in Morche's own sources file; the
						// others there and in chrony.conf go, so only these
						// are asked.
						p.Writes = append(p.Writes, configWrite{Path: chronyMorche, Text: sysconf.PrintChronySources(b.Servers)})
						for _, src := range f.sources {
							if src != chronyMorche {
								p.Writes = append(p.Writes, configWrite{Path: src, Remove: true})
							}
						}
						if len(sysconf.ParseChronyServers(text)) > 0 {
							p.Writes = append(p.Writes, configWrite{Path: path, Text: sysconf.SetChronyServers(text, nil)})
						}
					} else {
						p.Writes = append(p.Writes, configWrite{Path: path, Text: sysconf.SetChronyServers(text, b.Servers)})
					}
				case "timesyncd":
					w := configWrite{Path: timesyncdDropIn, Text: sysconf.PrintTimesyncdDropIn(b.Servers)}
					if len(b.Servers) == 0 {
						w = configWrite{Path: timesyncdDropIn, Remove: true}
					}
					p.Writes = append(p.Writes, w)
				default:
					return p, huma.Error422UnprocessableEntity("Time servers can be set for chrony or systemd-timesyncd; this server runs neither")
				}
				p.Apply = andThen(p.Apply, timeServiceRestart(f.unit))
				p.Undo = timeServiceRestart(f.unit)
				what = append(what, "time servers "+strings.Join(b.Servers, ", "))
			}
			if len(what) == 0 {
				return p, huma.Error422UnprocessableEntity("Nothing to change")
			}
			s := strings.Join(what, ", ")
			p.Summary = strings.ToUpper(s[:1]) + s[1:]
			return p, nil
		})
		if err != nil {
			return nil, err
		}
		o, err := h.clockOverview(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body ClockOverview }{*o}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "sync-server-clock",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/clock/sync",
		Summary:     "Bring the clock in step now",
		Description: "chrony: makestep; systemd-timesyncd: restart it so it asks again.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body ClockOverview }, error) {
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.configRoot(ctx, in.ID, c)
			if err != nil {
				return err
			}
			f, _, _, err := h.clockFacts(ctx, sh)
			if err != nil {
				return err
			}
			script := ""
			switch f.o.Service {
			case "chrony":
				script = "chronyc -a makestep"
			case "timesyncd":
				script = "systemctl restart systemd-timesyncd"
			default:
				return huma.Error422UnprocessableEntity("No time sync service runs on this server")
			}
			res, err := sh.exec(ctx, script, configTimeout, 8<<10)
			if err != nil {
				return err
			}
			if res.code != 0 {
				return huma.Error422UnprocessableEntity(configMessage(res.output, "It didn't work"))
			}
			return nil
		})
		if err != nil {
			return nil, toProblem(err)
		}
		o, err := h.clockOverview(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body ClockOverview }{*o}, nil
	})

	configRestorers["clock"] = func(ctx context.Context, h *serverHandler, _ string, sh *rootShell, _ []ConfigChangeFile) (configPlan, error) {
		out, err := sh.run(ctx, clockScript)
		if err != nil {
			return configPlan{}, err
		}
		unit := readClock(out).unit
		host := `[ -f /etc/hostname ] && hostname "$(cat /etc/hostname)"`
		return configPlan{Read: clockFiles, Apply: andThen(timeServiceRestart(unit), host), Undo: andThen(timeServiceRestart(unit), host)}, nil
	}
}
