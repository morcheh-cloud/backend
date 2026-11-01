package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/terminal"
)

// ---- Types ----

type CronEnv struct {
	Name  string `json:"name" example:"MAILTO"`
	Value string `json:"value" example:"ops@example.com"`
}

type CronJob struct {
	Line     int    `json:"line" doc:"0-based line in the table's content; with the table's revision it identifies the job"`
	Name     string `json:"name" doc:"The comment line right above the job, if any" example:"Nightly backup"`
	Schedule string `json:"schedule" doc:"Five fields, or a nickname like @daily or @reboot" example:"0 3 * * *"`
	User     string `json:"user" doc:"Who it runs as" example:"root"`
	Command  string `json:"command" example:"/usr/local/bin/backup.sh"`
	Enabled  bool   `json:"enabled" doc:"false when the line is commented out"`
}

type CronTable struct {
	ID       string    `json:"id" example:"user:root" doc:"user:<name> for a user's crontab, file:<path> for a system one"`
	Kind     string    `json:"kind" enum:"user,system" doc:"System tables name the user on every line"`
	User     string    `json:"user" doc:"Owner of a user crontab; empty for system files"`
	Path     string    `json:"path" example:"/var/spool/cron/crontabs/root"`
	Editable bool      `json:"editable"`
	Revision string    `json:"revision" doc:"Send it back when changing the table, to detect edits made meanwhile"`
	Content  string    `json:"content"`
	Env      []CronEnv `json:"env"`
	Jobs     []CronJob `json:"jobs"`
}

type CronUser struct {
	Name string `json:"name" example:"deploy"`
	UID  int    `json:"uid" example:"1000"`
}

type CronScript struct {
	Period string `json:"period" example:"daily" doc:"hourly, daily, weekly, monthly, 15min…"`
	Path   string `json:"path" example:"/etc/cron.daily/logrotate"`
}

type CronTimer struct {
	Unit        string     `json:"unit" example:"apt-daily.timer"`
	Service     string     `json:"service" doc:"What it starts" example:"apt-daily.service"`
	Description string     `json:"description"`
	Schedule    []string   `json:"schedule" doc:"OnCalendar= and monotonic settings, as systemd reports them" example:"OnCalendar=*-*-* 06:00:00"`
	Next        *time.Time `json:"next,omitempty"`
	Last        *time.Time `json:"last,omitempty"`
	Enabled     string     `json:"enabled" doc:"The unit file state: enabled, disabled, static…" example:"enabled"`
	Active      bool       `json:"active" doc:"The timer is armed"`
	Running     bool       `json:"running" doc:"Its service is running right now"`
	Result      string     `json:"result" doc:"How the service's last run ended: success, exit-code, timeout…" example:"success"`
	ExitStatus  int        `json:"exit_status"`
}

type CronOverview struct {
	LoginUser  string       `json:"login_user" example:"deploy"`
	Access     string       `json:"access" enum:"root,sudo,user" doc:"root and sudo can see and change every user's crontab; user only its own"`
	Timezone   string       `json:"timezone" doc:"IANA name, when the server reports one" example:"Europe/Berlin"`
	UTCOffset  string       `json:"utc_offset" example:"+01:00"`
	ServerTime time.Time    `json:"server_time"`
	Daemon     string       `json:"daemon" doc:"The cron daemon running; empty when none is" example:"cron"`
	Users      []CronUser   `json:"users" doc:"Accounts that can own a crontab"`
	Tables     []CronTable  `json:"tables"`
	Timers     []CronTimer  `json:"timers"`
	Scripts    []CronScript `json:"scripts" doc:"Run by run-parts or periodic, e.g. /etc/cron.daily"`
	Warnings   []string     `json:"warnings"`
}

type CronJobInput struct {
	Name     string `json:"name,omitempty" maxLength:"200" doc:"Saved as a comment above the job"`
	Schedule string `json:"schedule" minLength:"1" maxLength:"200" example:"*/15 * * * *"`
	User     string `json:"user,omitempty" maxLength:"32" doc:"Required in system tables; ignored in user crontabs"`
	Command  string `json:"command" minLength:"1" maxLength:"4000"`
	Enabled  bool   `json:"enabled"`
}

type CronTableRef struct {
	Table    string `json:"table" minLength:"1" maxLength:"300" example:"user:root"`
	Revision string `json:"revision" doc:"From the table as last read; a different one answers 409"`
}

type CronRunBody struct {
	Command string `json:"command" minLength:"1" maxLength:"4000"`
	User    string `json:"user,omitempty" maxLength:"32" doc:"Run as this user; default the login user"`
	Table   string `json:"table,omitempty" maxLength:"300" doc:"Use this table's variables (PATH, SHELL…), as cron would"`
	Timeout int    `json:"timeout,omitempty" minimum:"1" maximum:"600" default:"60" doc:"Seconds"`
}

type CronRunResult struct {
	ExitCode   int       `json:"exit_code" doc:"-1 when it was stopped"`
	Output     string    `json:"output" doc:"stdout and stderr together"`
	Truncated  bool      `json:"truncated"`
	TimedOut   bool      `json:"timed_out"`
	StartedAt  time.Time `json:"started_at"`
	DurationMs int64     `json:"duration_ms"`
}

type CronRun struct {
	Time    time.Time `json:"time"`
	User    string    `json:"user" example:"root"`
	Command string    `json:"command"`
}

type CronHistory struct {
	Source string    `json:"source" doc:"journal, a log file's path, or empty when no cron log was readable" example:"journal"`
	Runs   []CronRun `json:"runs" doc:"Newest first"`
	Note   string    `json:"note"`
}

type CronTableOutput struct{ Body CronTable }

const (
	cronMarker     = "@@morcheh@@"
	maxCrontab     = 256 << 10
	maxRunOutput   = 256 << 10
	defaultRunTime = 60
)

// ---- Handlers ----

func registerCron(api huma.API, h *serverHandler) {
	tags := []string{"Cron"}

	huma.Register(api, huma.Operation{
		OperationID: "get-cron",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/cron",
		Summary:     "Every scheduled job on a server",
		Description: "User crontabs, /etc/crontab and /etc/cron.d, systemd timers and periodic scripts. " +
			"With root or sudo every user's crontab is read; otherwise only the login user's.",
		Tags: tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body CronOverview }, error) {
		out := &struct{ Body CronOverview }{}
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.rootShell(ctx, in.ID, c)
			if err != nil {
				return err
			}
			o, err := h.collectCron(ctx, in.ID, sh)
			if err != nil {
				return err
			}
			out.Body = *o
			return nil
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "cron-history",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/cron/history",
		Summary:     "Recent cron runs",
		Description: "Read from the journal or the syslog files; reading them usually needs root or sudo.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body CronHistory }, error) {
		out := &struct{ Body CronHistory }{}
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.rootShell(ctx, in.ID, c)
			if err != nil {
				return err
			}
			raw, err := sh.run(ctx, historyScript)
			if err != nil {
				return err
			}
			out.Body = parseHistory(raw, time.Now())
			switch {
			case len(out.Body.Runs) > 0:
			case sh.priv == privUser:
				out.Body.Note = "Reading the cron log usually needs root or sudo."
			case out.Body.Source == "":
				out.Body.Note = "This server keeps no cron log: no journal, /var/log/cron or syslog file."
			}
			return nil
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID:   "add-cron-job",
		Method:        http.MethodPost,
		Path:          "/servers/{id}/cron/jobs",
		Summary:       "Add a job",
		Description:   "Appends to the table, creating a user's crontab if it has none.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body struct {
			Table string       `json:"table" minLength:"1" maxLength:"300" example:"user:root"`
			Job   CronJobInput `json:"job"`
		}
	}) (*CronTableOutput, error) {
		return h.editTable(ctx, in.ID, in.Body.Table, "", func(t *CronTable, lines []string) ([]string, error) {
			line, err := jobLine(in.Body.Job, t, "body.job")
			if err != nil {
				return nil, err
			}
			for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
				lines = lines[:len(lines)-1]
			}
			// A comment right above would be read back as this job's name.
			if n := len(lines); n > 0 && in.Body.Job.Name == "" && strings.HasPrefix(strings.TrimSpace(lines[n-1]), "#") {
				lines = append(lines, "")
			}
			if in.Body.Job.Name != "" {
				lines = append(lines, "# "+in.Body.Job.Name)
			}
			return append(lines, line), nil
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-cron-job",
		Method:      http.MethodPut,
		Path:        "/servers/{id}/cron/jobs",
		Summary:     "Change a job",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body struct {
			CronTableRef
			Line int          `json:"line" minimum:"0"`
			Job  CronJobInput `json:"job"`
		}
	}) (*CronTableOutput, error) {
		b := in.Body
		return h.editTable(ctx, in.ID, b.Table, b.Revision, func(t *CronTable, lines []string) ([]string, error) {
			jobs := parsedJobs(t)
			j, ok := jobs[b.Line]
			if !ok {
				return nil, huma.Error409Conflict("That job isn't there any more. Reload and try again.")
			}
			line, err := jobLine(b.Job, t, "body.job")
			if err != nil {
				return nil, err
			}
			lines[b.Line] = line
			switch {
			case j.nameLine >= 0 && b.Job.Name != "":
				lines[j.nameLine] = "# " + b.Job.Name
			case j.nameLine >= 0:
				lines = slices.Delete(lines, j.nameLine, j.nameLine+1)
			case b.Job.Name != "":
				lines = slices.Insert(lines, b.Line, "# "+b.Job.Name)
			}
			return lines, nil
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-cron-jobs",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/cron/jobs/delete",
		Summary:     "Delete jobs",
		Description: "Removes the jobs at these lines of one table, with their name comments.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body struct {
			CronTableRef
			Lines []int `json:"lines" minItems:"1" maxItems:"1000"`
		}
	}) (*CronTableOutput, error) {
		b := in.Body
		return h.editTable(ctx, in.ID, b.Table, b.Revision, func(t *CronTable, lines []string) ([]string, error) {
			jobs := parsedJobs(t)
			drop := map[int]bool{}
			for _, n := range b.Lines {
				j, ok := jobs[n]
				if !ok {
					return nil, huma.Error409Conflict("A job you picked isn't there any more. Reload and try again.")
				}
				drop[n] = true
				if j.nameLine >= 0 {
					drop[j.nameLine] = true
				}
			}
			kept := lines[:0:0]
			for i, l := range lines {
				if !drop[i] {
					kept = append(kept, l)
				}
			}
			return kept, nil
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "enable-cron-jobs",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/cron/jobs/enable",
		Summary:     "Turn jobs on or off",
		Description: "A turned-off job stays in the table, commented out.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body struct {
			CronTableRef
			Lines   []int `json:"lines" minItems:"1" maxItems:"1000"`
			Enabled bool  `json:"enabled"`
		}
	}) (*CronTableOutput, error) {
		b := in.Body
		return h.editTable(ctx, in.ID, b.Table, b.Revision, func(t *CronTable, lines []string) ([]string, error) {
			jobs := parsedJobs(t)
			for _, n := range b.Lines {
				j, ok := jobs[n]
				if !ok {
					return nil, huma.Error409Conflict("A job you picked isn't there any more. Reload and try again.")
				}
				lines[n] = formatJob(j.CronJob.Schedule, j.CronJob.User, j.CronJob.Command, b.Enabled, t.Kind == "system")
			}
			return lines, nil
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "save-crontab",
		Method:      http.MethodPut,
		Path:        "/servers/{id}/cron/tables",
		Summary:     "Replace a table's text",
		Description: "Every line must be a job, a variable, a comment or blank.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body struct {
			CronTableRef
			Content string `json:"content" maxLength:"262144"`
		}
	}) (*CronTableOutput, error) {
		b := in.Body
		return h.editTable(ctx, in.ID, b.Table, b.Revision, func(t *CronTable, _ []string) ([]string, error) {
			lines := strings.Split(strings.ReplaceAll(b.Content, "\r\n", "\n"), "\n")
			for i, l := range lines {
				s := strings.TrimSpace(l)
				if s == "" || strings.HasPrefix(s, "#") || cronEnvRe.MatchString(s) {
					continue
				}
				if _, ok := parseJobLine(s, t.Kind == "system"); !ok {
					msg := fmt.Sprintf("Line %d isn't a job, a variable or a comment", i+1)
					if t.Kind == "system" {
						msg += " (system tables name the user after the schedule)"
					}
					return nil, fieldError("body.content", msg, i+1)
				}
			}
			return lines, nil
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "run-cron-command",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/cron/run",
		Summary:     "Run a job's command now",
		Description: "Runs it the way cron would: as the job's user, from its home folder, with a bare environment " +
			"(the table's variables, PATH=/usr/bin:/bin by default) and `%` read as cron reads it. Waits for it to finish.",
		Tags: tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body CronRunBody
	}) (*struct{ Body CronRunResult }, error) {
		out := &struct{ Body CronRunResult }{}
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.rootShell(ctx, in.ID, c)
			if err != nil {
				return err
			}
			res, err := h.runCron(ctx, in.ID, sh, in.Body)
			if err != nil {
				return err
			}
			out.Body = *res
			return nil
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID:   "cron-timer-action",
		Method:        http.MethodPost,
		Path:          "/servers/{id}/cron/timers/action",
		Summary:       "Run, enable or disable a systemd timer",
		Description:   "`run` starts the timer's service now without waiting for it. Needs root or sudo.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body struct {
			Unit   string `json:"unit" pattern:"^[A-Za-z0-9:_.@\\\\-]+\\.timer$" maxLength:"256" example:"apt-daily.timer"`
			Action string `json:"action" enum:"run,enable,disable"`
		}
	}) (*struct{}, error) {
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.rootShell(ctx, in.ID, c)
			if err != nil {
				return err
			}
			if sh.priv == privUser {
				return huma.Error403Forbidden("Managing timers needs root or sudo on this server")
			}
			unit := terminal.ShellQuote(in.Body.Unit)
			var script string
			switch in.Body.Action {
			case "run":
				script = "s=$(systemctl show -p Triggers --value " + unit + ") && [ -n \"$s\" ] && systemctl start --no-block $s"
			case "enable":
				script = "systemctl enable --now " + unit
			default:
				script = "systemctl disable --now " + unit
			}
			_, err = sh.run(ctx, script)
			return err
		})
		return nil, toProblem(err)
	})
}

// ---- Reading ----

// collectScript prints everything cron-related, in sections that start with
// a marker line. Run as root it sees every user's crontab.
const collectScript = `m=` + cronMarker + `
echo "$m who"; id -u
echo "$m clock"; date '+%s %z'
echo "$m tz"
tz=$(timedatectl show -p Timezone --value 2>/dev/null)
[ -n "$tz" ] || tz=$(cat /etc/timezone 2>/dev/null)
[ -n "$tz" ] || tz=$(readlink /etc/localtime 2>/dev/null | sed -n 's|.*zoneinfo/||p')
echo "$tz"
echo "$m daemon"
for p in /proc/[0-9]*; do
  read -r c 2>/dev/null < "$p/comm" || continue
  case $c in
    cron|crond|cronie|fcron|dcron) echo "$c"; break ;;
    busybox) tr '\0' ' ' 2>/dev/null < "$p/cmdline" | grep -q ' crond' && { echo "busybox crond"; break; } ;;
  esac
done
echo "$m users"
awk -F: '$1 != "nobody" { print $1 ":" $3 }' /etc/passwd 2>/dev/null
for d in /var/spool/cron/crontabs /var/spool/cron/tabs /var/spool/cron /etc/crontabs; do
  [ -d "$d" ] || continue
  for f in "$d"/*; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    echo "$m user ${f##*/} $f"; cat "$f"; echo
  done
done
if [ "$(id -u)" != 0 ]; then
  out=$(crontab -l 2>&1); rc=$?
  echo "$m self $rc"; printf '%s\n' "$out"
fi
for f in /etc/crontab /etc/cron.d/*; do
  [ -f "$f" ] && [ -r "$f" ] || continue
  echo "$m file $f"; cat "$f"; echo
done
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/periodic/*; do
  [ -d "$d" ] || continue
  for f in "$d"/*; do [ -f "$f" ] && [ -x "$f" ] && echo "$m script ${d##*/} $f"; done
done
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  t=$( { systemctl list-unit-files --type=timer --no-legend --no-pager; systemctl list-units --type=timer --all --no-legend --no-pager --plain; } 2>/dev/null | awk '$1 ~ /\.timer$/ && $1 !~ /@\.timer$/ { print $1 }' | sort -u)
  if [ -n "$t" ]; then
    s=$(systemctl show -p Triggers $t 2>/dev/null | sed -n 's/^Triggers=//p')
    p=Id,Description,Triggers,NextElapseUSecRealtime,LastTriggerUSec,ActiveState,UnitFileState,TimersCalendar,TimersMonotonic,Result,ExecMainStatus
    echo "$m timers"
    systemctl show --no-pager --timestamp=unix -p $p $t $s 2>/dev/null || systemctl show --no-pager -p $p $t $s 2>/dev/null
  fi
fi
exit 0
`

type cronSection struct {
	kind string
	args []string
	body string
}

func splitSections(out string) []cronSection {
	var secs []cronSection
	for _, part := range strings.Split("\n"+out, "\n"+cronMarker+" ")[1:] {
		head, body, _ := strings.Cut(part, "\n")
		f := strings.Fields(head)
		if len(f) == 0 {
			continue
		}
		secs = append(secs, cronSection{kind: f[0], args: f[1:], body: body})
	}
	return secs
}

func (h *serverHandler) collectCron(ctx context.Context, id string, sh *rootShell) (*CronOverview, error) {
	raw, err := sh.run(ctx, collectScript)
	if err != nil {
		return nil, err
	}
	s, err := h.get(ctx, id)
	if err != nil {
		return nil, err
	}
	o := &CronOverview{
		LoginUser: s.Username, Access: sh.priv.access(),
		Users: []CronUser{}, Tables: []CronTable{}, Timers: []CronTimer{}, Scripts: []CronScript{}, Warnings: []string{},
	}
	privileged := sh.priv != privUser
	seen := map[string]bool{}
	var files []CronTable
	for _, sec := range splitSections(raw) {
		body := strings.TrimSuffix(sec.body, "\n")
		switch sec.kind {
		case "clock":
			if f := strings.Fields(body); len(f) == 2 {
				if sec, err := strconv.ParseInt(f[0], 10, 64); err == nil {
					o.ServerTime = time.Unix(sec, 0).UTC()
				}
				o.UTCOffset = formatOffset(f[1])
			}
		case "tz":
			o.Timezone = strings.TrimSpace(body)
		case "daemon":
			o.Daemon = strings.TrimSpace(body)
		case "users":
			for _, l := range strings.Split(body, "\n") {
				name, uid, ok := strings.Cut(l, ":")
				if n, err := strconv.Atoi(uid); ok && err == nil {
					o.Users = append(o.Users, CronUser{Name: name, UID: n})
				}
			}
		case "user":
			if len(sec.args) < 2 {
				continue
			}
			user := sec.args[0]
			if seen[user] || user == "cron.update" || strings.HasPrefix(user, ".") || !cronUserRe.MatchString(user) {
				continue
			}
			seen[user] = true
			o.Tables = append(o.Tables, newTable("user:"+user, "user", user, strings.Join(sec.args[1:], " "), body,
				privileged || user == s.Username))
		case "self":
			// Only the login user's own crontab is readable.
			rc := ""
			if len(sec.args) > 0 {
				rc = sec.args[0]
			}
			switch {
			case seen[s.Username]:
			case rc == "0":
				seen[s.Username] = true
				o.Tables = append(o.Tables, newTable("user:"+s.Username, "user", s.Username, "", body, true))
			case strings.Contains(body, "no crontab for"):
				seen[s.Username] = true
				o.Tables = append(o.Tables, newTable("user:"+s.Username, "user", s.Username, "", "", true))
			case rc == "127":
				o.Warnings = append(o.Warnings, "crontab isn't installed on this server.")
			default:
				o.Warnings = append(o.Warnings, "Couldn't read "+s.Username+"'s crontab: "+lastLines(body, 2))
			}
		case "file":
			path := strings.Join(sec.args, " ")
			if isSystemCrontab(path) {
				files = append(files, newTable("file:"+path, "system", "", path, body, privileged))
			}
		case "script":
			if len(sec.args) == 2 {
				o.Scripts = append(o.Scripts, CronScript{Period: strings.TrimPrefix(sec.args[0], "cron."), Path: sec.args[1]})
			}
		case "timers":
			o.Timers = parseTimers(body)
		}
	}
	// The login user can always start a crontab of their own.
	if !seen[s.Username] && (privileged || len(o.Warnings) == 0) {
		o.Tables = append(o.Tables, newTable("user:"+s.Username, "user", s.Username, "", "", true))
	}
	slices.SortStableFunc(o.Tables, func(a, b CronTable) int {
		return strings.Compare(tableOrder(a, s.Username), tableOrder(b, s.Username))
	})
	o.Tables = append(o.Tables, files...)
	if o.Daemon == "busybox crond" && len(files) > 0 {
		o.Warnings = append(o.Warnings, "BusyBox crond only runs user crontabs; jobs in /etc/crontab and /etc/cron.d are ignored.")
	}
	return o, nil
}

// tableOrder lists root first, then the login user, then everyone else.
func tableOrder(t CronTable, login string) string {
	switch t.User {
	case "root":
		return "0"
	case login:
		return "1"
	}
	return "2" + t.User
}

func isSystemCrontab(path string) bool {
	return path == "/etc/crontab" || cronDFileRe.MatchString(path)
}

// formatOffset turns date's +0330 into +03:30.
func formatOffset(z string) string {
	if len(z) == 5 {
		return z[:3] + ":" + z[3:]
	}
	return z
}

func newTable(id, kind, user, path, content string, editable bool) CronTable {
	if kind == "user" {
		content = stripCrontabHeader(content)
	}
	content = normalizeCrontab(content)
	t := CronTable{ID: id, Kind: kind, User: user, Path: path, Editable: editable, Content: content,
		Revision: revision(content), Env: []CronEnv{}, Jobs: []CronJob{}}
	for _, j := range parseTable(&t) {
		t.Jobs = append(t.Jobs, j.CronJob)
	}
	return t
}

func revision(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:12])
}

// normalizeCrontab gives every table the same shape, so its revision doesn't
// change with how it was read: Unix newlines and exactly one at the end.
func normalizeCrontab(s string) string {
	s = strings.TrimRight(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	if s != "" {
		s += "\n"
	}
	return s
}

// stripCrontabHeader drops the lines Debian's crontab puts on top of what it
// installs ("# DO NOT EDIT THIS FILE…"); crontab -l hides them too.
func stripCrontabHeader(s string) string {
	for {
		line, rest, _ := strings.Cut(s, "\n")
		if !strings.HasPrefix(line, "# DO NOT EDIT THIS FILE") &&
			!(strings.HasPrefix(line, "# (") && (strings.Contains(line, " installed on ") || strings.Contains(line, "Cron version"))) {
			return s
		}
		s = rest
	}
}

var (
	cronEnvRe   = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$`)
	cronFieldRe = regexp.MustCompile(`^(?:\*|\?|L|[0-9]+[LW]?|[A-Za-z]{3})(?:[-/,#](?:\*|L|[0-9]+[LW]?|[A-Za-z]{3}))*$`)
	cronUserRe  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}\$?$`)
	cronDFileRe = regexp.MustCompile(`^/etc/cron\.d/[A-Za-z0-9_-]+$`)
	// Comments that describe the format rather than name a job.
	cronHelpRe = regexp.MustCompile(`(?i)^m\s+h\s+dom|^min(ute)?\s+hour|command to be executed`)
)

var cronNicknames = map[string]bool{
	"@reboot": true, "@yearly": true, "@annually": true, "@monthly": true,
	"@weekly": true, "@daily": true, "@midnight": true, "@hourly": true,
}

type jobFields struct{ schedule, user, command string }

// parseJobLine reads "schedule [user] command"; system tables name the user.
func parseJobLine(s string, system bool) (jobFields, bool) {
	var j jobFields
	rest := s
	var sched []string
	if tok, r := nextField(rest); strings.HasPrefix(tok, "@") {
		if !cronNicknames[strings.ToLower(tok)] {
			return j, false
		}
		sched, rest = []string{tok}, r
	} else {
		for range 5 {
			tok, r := nextField(rest)
			if !cronFieldRe.MatchString(tok) {
				return j, false
			}
			sched, rest = append(sched, tok), r
		}
	}
	if system {
		j.user, rest = nextField(rest)
		if !cronUserRe.MatchString(j.user) {
			return j, false
		}
	}
	j.schedule, j.command = strings.Join(sched, " "), strings.TrimSpace(rest)
	return j, j.command != ""
}

func nextField(s string) (field, rest string) {
	s = strings.TrimLeft(s, " \t")
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], s[i:]
	}
	return s, ""
}

type parsedJob struct {
	CronJob
	nameLine int // the comment above it that names it; -1 for none
}

// parseTable fills t.Env and returns its jobs. A commented-out job line is a
// turned-off job; the comment right above a job is its name.
func parseTable(t *CronTable) []parsedJob {
	var jobs []parsedJob
	system := t.Kind == "system"
	name, nameLine := "", -1
	add := func(i int, f jobFields, enabled bool) {
		user := f.user
		if !system {
			user = t.User
		}
		jobs = append(jobs, parsedJob{CronJob{Line: i, Name: name, Schedule: f.schedule, User: user, Command: f.command, Enabled: enabled}, nameLine})
	}
	for i, raw := range strings.Split(strings.TrimSuffix(t.Content, "\n"), "\n") {
		s := strings.TrimSpace(raw)
		if comment, ok := strings.CutPrefix(s, "#"); ok {
			comment = strings.TrimSpace(comment)
			if f, ok := parseJobLine(comment, system); ok && !cronHelpRe.MatchString(f.command) && f.user != "user-name" {
				add(i, f, false)
				name, nameLine = "", -1
			} else if comment != "" && len(comment) <= 200 && !cronHelpRe.MatchString(comment) {
				name, nameLine = comment, i
			} else {
				name, nameLine = "", -1
			}
			continue
		}
		if f, ok := parseJobLine(s, system); ok {
			add(i, f, true)
		} else if m := cronEnvRe.FindStringSubmatch(s); m != nil {
			t.Env = append(t.Env, CronEnv{Name: m[1], Value: unquote(m[2])})
		}
		name, nameLine = "", -1
	}
	return jobs
}

func parsedJobs(t *CronTable) map[int]parsedJob {
	m := map[int]parsedJob{}
	for _, j := range parseTable(&CronTable{Kind: t.Kind, User: t.User, Content: t.Content}) {
		m[j.Line] = j
	}
	return m
}

func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

// ---- Writing ----

func formatJob(schedule, user, command string, enabled, system bool) string {
	parts := []string{schedule}
	if system {
		parts = append(parts, user)
	}
	line := strings.Join(append(parts, command), " ")
	if !enabled {
		line = "#" + line
	}
	return line
}

// jobLine validates a job from the client and formats it for table t.
func jobLine(in CronJobInput, t *CronTable, loc string) (string, error) {
	system := t.Kind == "system"
	sched := strings.Join(strings.Fields(in.Schedule), " ")
	cmd := strings.TrimSpace(in.Command)
	switch {
	case strings.ContainsAny(in.Name, "\r\n"):
		return "", fieldError(loc+".name", "The name has to fit on one line", in.Name)
	case strings.ContainsAny(cmd, "\r\n"):
		return "", fieldError(loc+".command", "Cron runs one line; put longer commands in a script", nil)
	case cmd == "":
		return "", fieldError(loc+".command", "Enter a command", nil)
	case system && !cronUserRe.MatchString(in.User):
		return "", fieldError(loc+".user", "Pick the user it runs as", in.User)
	}
	if _, ok := parseJobLine(strings.TrimSpace(in.Name), system); ok {
		return "", fieldError(loc+".name", "That name would be read as a job; reword it", in.Name)
	}
	line := formatJob(sched, in.User, cmd, true, system)
	if f, ok := parseJobLine(line, system); !ok || f.schedule != sched {
		return "", fieldError(loc+".schedule", "Not a valid cron schedule", in.Schedule)
	}
	if msg := checkSchedule(sched); msg != "" {
		return "", fieldError(loc+".schedule", msg, in.Schedule)
	}
	return formatJob(sched, in.User, cmd, in.Enabled, system), nil
}

var cronFields = [5]struct {
	name     string
	min, max int
	names    []string
}{
	{"minute", 0, 59, nil},
	{"hour", 0, 23, nil},
	{"day of month", 1, 31, nil},
	{"month", 1, 12, []string{"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"}},
	{"day of week", 0, 7, []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}},
}

// checkSchedule checks the numbers in a five-field schedule against each
// field's range, as standard cron reads them; "" when it is fine.
func checkSchedule(sched string) string {
	fields := strings.Fields(sched)
	if len(fields) != 5 {
		return "" // a nickname
	}
	for i, field := range fields {
		f := cronFields[i]
		for _, part := range strings.Split(field, ",") {
			rng, step, hasStep := strings.Cut(part, "/")
			if hasStep {
				if n, err := strconv.Atoi(step); err != nil || n < 1 {
					return "The step in the " + f.name + " field must be a positive number"
				}
			}
			if rng == "*" {
				continue
			}
			lo, hi, isRange := strings.Cut(rng, "-")
			for _, v := range []string{lo, hi} {
				if v == "" && !isRange {
					continue
				}
				n, err := strconv.Atoi(v)
				if err != nil {
					n = slices.Index(f.names, strings.ToLower(v))
					if n < 0 {
						return fmt.Sprintf("%q isn't valid in the %s field", v, f.name)
					}
					if i == 3 {
						n++
					}
				}
				if n < f.min || n > f.max {
					return fmt.Sprintf("The %s must be %d–%d", f.name, f.min, f.max)
				}
			}
		}
	}
	return ""
}

// editTable reads table id fresh, checks it still has the revision the
// client saw (unless rev is empty), applies edit to its lines and installs
// the result.
func (h *serverHandler) editTable(ctx context.Context, id, tableID, rev string,
	edit func(t *CronTable, lines []string) ([]string, error),
) (*CronTableOutput, error) {
	out := &CronTableOutput{}
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.rootShell(ctx, id, c)
		if err != nil {
			return err
		}
		o, err := h.collectCron(ctx, id, sh)
		if err != nil {
			return err
		}
		t, err := findTable(o, tableID)
		if err != nil {
			return err
		}
		if !t.Editable {
			return huma.Error403Forbidden("Changing " + tableLabel(t) + " needs root or sudo on this server")
		}
		if rev != "" && rev != t.Revision {
			return huma.Error409Conflict(tableLabel(t) + " changed on the server since you loaded it. Reload and try again.")
		}
		lines, err := edit(t, strings.Split(strings.TrimSuffix(t.Content, "\n"), "\n"))
		if err != nil {
			return err
		}
		content := normalizeCrontab(strings.Join(lines, "\n"))
		if len(content) > maxCrontab {
			return huma.Error422UnprocessableEntity("The table would be too big")
		}
		if err := writeTable(ctx, sh, t, o.LoginUser, content); err != nil {
			return err
		}
		out.Body = newTable(t.ID, t.Kind, t.User, t.Path, content, true)
		return nil
	})
	return out, toProblem(err)
}

// findTable picks a table from what was just read. A user without a crontab
// gets an empty one, as long as the account exists.
func findTable(o *CronOverview, id string) (*CronTable, error) {
	for i := range o.Tables {
		if o.Tables[i].ID == id {
			return &o.Tables[i], nil
		}
	}
	if user, ok := strings.CutPrefix(id, "user:"); ok && cronUserRe.MatchString(user) {
		for _, u := range o.Users {
			if u.Name == user {
				t := newTable(id, "user", user, "", "", o.Access != "user" || user == o.LoginUser)
				return &t, nil
			}
		}
		return nil, fieldError("body.table", "No user "+user+" on this server", id)
	}
	return nil, huma.Error404NotFound("No such cron table: " + strings.TrimPrefix(id, "file:"))
}

func tableLabel(t *CronTable) string {
	if t.Kind == "user" {
		return t.User + "'s crontab"
	}
	return t.Path
}

// writeTable installs content: user crontabs through crontab (which also
// tells the daemon), system files by replacing the file.
func writeTable(ctx context.Context, sh *rootShell, t *CronTable, login, content string) error {
	eof := "MORCHEH_" + randomSuffix()
	doc := " <<'" + eof + "'\n" + content + eof + "\n"
	var script string
	switch {
	case t.Kind == "user" && sh.priv == privUser:
		script = "crontab -" + doc
	case t.Kind == "user":
		script = "crontab -u " + terminal.ShellQuote(t.User) + " -" + doc
	default:
		f := terminal.ShellQuote(t.Path)
		script = "t=$(mktemp \"$(dirname " + f + ")/.morcheh.XXXXXX\") || exit 1\n" +
			"cat > \"$t\"" + doc +
			"chmod 644 \"$t\" && mv -f \"$t\" " + f + " || { rm -f \"$t\"; exit 1; }\n"
	}
	_, err := sh.run(ctx, script)
	return err
}

// ---- Running ----

func (h *serverHandler) runCron(ctx context.Context, id string, sh *rootShell, in CronRunBody) (*CronRunResult, error) {
	s, err := h.get(ctx, id)
	if err != nil {
		return nil, err
	}
	user := in.User
	if user == "" {
		user = s.Username
	}
	if !cronUserRe.MatchString(user) {
		return nil, fieldError("body.user", "Not a user name", user)
	}
	if user != s.Username && sh.priv == privUser {
		return nil, huma.Error403Forbidden("Running as another user needs root or sudo on this server")
	}
	env := map[string]string{"PATH": "/usr/bin:/bin", "SHELL": "/bin/sh"}
	if in.Table != "" {
		o, err := h.collectCron(ctx, id, sh)
		if err != nil {
			return nil, err
		}
		if t, err := findTable(o, in.Table); err == nil {
			for _, e := range t.Env {
				env[e.Name] = e.Value
			}
		}
	}
	timeout := in.Timeout
	if timeout == 0 {
		timeout = defaultRunTime
	}

	cmd, stdin, hasStdin := cronCommand(strings.TrimSpace(in.Command))
	vars := []string{"HOME=\"$h\"", "LOGNAME=" + terminal.ShellQuote(user), "USER=" + terminal.ShellQuote(user)}
	for _, k := range sortedKeys(env) {
		if k != "HOME" && cronEnvRe.MatchString(k+"=") {
			vars = append(vars, k+"="+terminal.ShellQuote(env[k]))
		}
	}
	shell := terminal.ShellQuote(env["SHELL"])
	// As root, switch to the job's user with su; -m keeps the bare env.
	runAs := shell + " -c " + terminal.ShellQuote(cmd)
	if sh.priv != privUser && user != "root" {
		runAs = "su -m -s " + shell + " -c " + terminal.ShellQuote(cmd) + " " + terminal.ShellQuote(user)
	}
	input := " </dev/null"
	if hasStdin {
		eof := "MORCHEH_" + randomSuffix()
		input = " <<'" + eof + "'\n" + stdin + "\n" + eof
	}
	script := "u=" + terminal.ShellQuote(user) + "\n" +
		`h=$(awk -F: -v u="$u" '$1 == u { print $6; exit }' /etc/passwd)` + "\n" +
		`[ -n "$h" ] || h=/` + "\n" +
		`cd "$h" 2>/dev/null || cd /` + "\n" +
		`t=; command -v timeout >/dev/null 2>&1 && t="timeout ` + strconv.Itoa(timeout) + `"` + "\n" +
		"exec $t env -i " + strings.Join(vars, " ") + " " + runAs + input + "\n"

	started := time.Now()
	res, err := sh.exec(ctx, script, time.Duration(timeout+10)*time.Second, maxRunOutput)
	if err != nil {
		return nil, err
	}
	// timeout(1) ends with 124 (GNU) or the signal's status (busybox).
	timedOut := res.timedOut || (res.duration >= time.Duration(timeout)*time.Second && slices.Contains([]int{124, 137, 143}, res.code))
	return &CronRunResult{
		ExitCode: res.code, Output: string(res.output), Truncated: res.truncated, TimedOut: timedOut,
		StartedAt: started.UTC(), DurationMs: res.duration.Milliseconds(),
	}, nil
}

// cronCommand applies cron's rule for %: the first unescaped one ends the
// command and the rest is its stdin, with every further % a newline. \% is a
// literal %.
func cronCommand(raw string) (cmd, stdin string, hasStdin bool) {
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		switch {
		case raw[i] == '\\' && i+1 < len(raw) && raw[i+1] == '%':
			b.WriteByte('%')
			i++
		case raw[i] == '%':
			return b.String(), strings.ReplaceAll(raw[i+1:], "%", "\n"), true
		default:
			b.WriteByte(raw[i])
		}
	}
	return b.String(), "", false
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// ---- Timers ----

// parseTimers reads `systemctl show` blocks for the timers and the services
// they trigger, and joins each timer with its service.
func parseTimers(out string) []CronTimer {
	units := map[string]map[string][]string{}
	var order []string
	for _, block := range strings.Split(out, "\n\n") {
		props := map[string][]string{}
		for _, l := range strings.Split(block, "\n") {
			if k, v, ok := strings.Cut(l, "="); ok {
				props[k] = append(props[k], v)
			}
		}
		id := first(props["Id"])
		if id == "" {
			continue
		}
		if _, dup := units[id]; !dup {
			order = append(order, id)
		}
		units[id] = props
	}
	timers := []CronTimer{}
	for _, id := range order {
		p := units[id]
		if !strings.HasSuffix(id, ".timer") {
			continue
		}
		t := CronTimer{
			Unit: id, Service: first(p["Triggers"]), Description: first(p["Description"]),
			Next: systemdTime(first(p["NextElapseUSecRealtime"])), Last: systemdTime(first(p["LastTriggerUSec"])),
			Enabled: first(p["UnitFileState"]), Active: first(p["ActiveState"]) == "active", Schedule: []string{},
		}
		for _, v := range append(p["TimersCalendar"], p["TimersMonotonic"]...) {
			// { OnCalendar=*-*-* 06:00:00 ; next_elapse=@1793586600 }
			v = strings.Trim(v, "{} ")
			if setting, _, _ := strings.Cut(v, " ; "); setting != "" {
				t.Schedule = append(t.Schedule, strings.TrimSpace(setting))
			}
		}
		if svc := units[t.Service]; svc != nil {
			t.Result = first(svc["Result"])
			t.ExitStatus, _ = strconv.Atoi(first(svc["ExecMainStatus"]))
			t.Running = slices.Contains([]string{"active", "activating", "reloading"}, first(svc["ActiveState"]))
		}
		timers = append(timers, t)
	}
	return timers
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// systemdTime reads "@1793586600" (--timestamp=unix) or the default
// "Sun 2026-11-01 14:51:15 UTC"; empty or n/a is no time.
func systemdTime(v string) *time.Time {
	v = strings.TrimSpace(v)
	if sec, ok := strings.CutPrefix(v, "@"); ok {
		n, err := strconv.ParseInt(sec, 10, 64)
		if err != nil || n == 0 {
			return nil
		}
		t := time.Unix(n, 0).UTC()
		return &t
	}
	for _, layout := range []string{"Mon 2006-01-02 15:04:05 -0700", "Mon 2006-01-02 15:04:05 MST"} {
		if t, err := time.Parse(layout, v); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

// ---- History ----

const historyScript = `m=` + cronMarker + `
echo "$m clock"; date '+%s %z'
if [ -d /run/systemd/system ] && command -v journalctl >/dev/null 2>&1; then
  echo "$m journal"
  journalctl -q --no-pager -o short-iso -n 5000 -t CRON -t cron -t crond -t CROND 2>/dev/null | grep -E ' CMD | cmd ' | tail -n 1000
else
  for f in /var/log/cron /var/log/cron.log /var/log/syslog /var/log/messages; do
    [ -r "$f" ] || continue
    echo "$m file $f"
    grep -E '(CRON|crond)(\[[0-9]+\])?:' "$f" 2>/dev/null | grep -E ' CMD | cmd ' | tail -n 1000
    break
  done
fi
exit 0
`

var (
	// "2026-11-01T12:17:01+03:30 host CRON[1]: msg" (journal, rsyslog)
	isoLogRe = regexp.MustCompile(`^(\d{4}-\d\d-\d\dT\S+) \S+ [^:\s]+?(?:\[\d+\])?: (.*)$`)
	// "Nov  1 12:17:01 host CRON[1]: msg" (classic syslog)
	bsdLogRe = regexp.MustCompile(`^([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) \S+ [^:\s]+?(?:\[\d+\])?: (.*)$`)
	// Debian cron and cronie: "(root) CMD (command)"
	cmdMsgRe = regexp.MustCompile(`^\((\S+)\) CMD \((.*)\)$`)
	// busybox crond: "USER root pid 123 cmd command"
	bbMsgRe = regexp.MustCompile(`^USER (\S+) pid \d+ cmd (.*)$`)
)

func parseHistory(out string, now time.Time) CronHistory {
	h := CronHistory{Runs: []CronRun{}}
	loc := time.UTC
	for _, sec := range splitSections(out) {
		switch sec.kind {
		case "clock":
			if f := strings.Fields(sec.body); len(f) == 2 {
				if t, err := time.Parse("-0700", f[1]); err == nil {
					_, off := t.Zone()
					loc = time.FixedZone(f[1], off)
				}
			}
		case "journal", "file":
			h.Source = sec.kind
			if sec.kind == "file" {
				h.Source = strings.Join(sec.args, " ")
			}
			for _, l := range strings.Split(sec.body, "\n") {
				if r, ok := parseRun(l, loc, now); ok {
					h.Runs = append(h.Runs, r)
				}
			}
		}
	}
	slices.Reverse(h.Runs)
	return h
}

func parseRun(line string, loc *time.Location, now time.Time) (CronRun, bool) {
	var r CronRun
	var ts, msg string
	if m := isoLogRe.FindStringSubmatch(line); m != nil {
		ts, msg = m[1], m[2]
		var err error
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05-0700", "2006-01-02T15:04:05.999999-0700"} {
			if r.Time, err = time.Parse(layout, ts); err == nil {
				break
			}
		}
		if err != nil {
			return r, false
		}
	} else if m := bsdLogRe.FindStringSubmatch(line); m != nil {
		ts, msg = m[1], m[2]
		t, err := time.ParseInLocation("Jan _2 15:04:05", ts, loc)
		if err != nil {
			return r, false
		}
		// Syslog leaves out the year: it's this year unless that is ahead.
		t = t.AddDate(now.In(loc).Year(), 0, 0)
		if t.After(now.Add(24 * time.Hour)) {
			t = t.AddDate(-1, 0, 0)
		}
		r.Time = t
	} else {
		return r, false
	}
	r.Time = r.Time.UTC()
	if m := cmdMsgRe.FindStringSubmatch(msg); m != nil {
		r.User, r.Command = m[1], m[2]
	} else if m := bbMsgRe.FindStringSubmatch(msg); m != nil {
		r.User, r.Command = m[1], m[2]
	} else {
		return r, false
	}
	return r, true
}
