// Package services reads what systemd (or OpenRC) reports about services:
// `systemctl show` blocks, `systemctl cat`, journal JSON lines and OpenRC's
// rc-status. It only parses; the api package runs the commands.
package services

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Service struct {
	Name        string     `json:"name" doc:"The unit (systemd) or init script (OpenRC)" example:"nginx.service"`
	Description string     `json:"description" example:"A high performance web server"`
	Load        string     `json:"load" doc:"loaded, not-found, masked, bad-setting, error (OpenRC: loaded)" example:"loaded"`
	Active      string     `json:"active" doc:"active, inactive, failed, activating, deactivating, reloading" example:"active"`
	Sub         string     `json:"sub" doc:"The finer state: running, exited, dead, failed, auto-restart… (OpenRC: started, stopped, crashed…)" example:"running"`
	Enabled     string     `json:"enabled" doc:"Starts at boot: enabled, disabled, static, masked, indirect, generated, alias, transient, linked… Empty when unknown" example:"enabled"`
	Preset      string     `json:"preset,omitempty" doc:"What the distribution's preset says it should be" example:"enabled"`
	Type        string     `json:"type,omitempty" doc:"simple, exec, forking, oneshot, notify, dbus, idle" example:"forking"`
	MainPID     int        `json:"main_pid" doc:"0 when not running"`
	Memory      *int64     `json:"memory,omitempty" doc:"Bytes in use by its cgroup, when accounting is on"`
	CPUNs       *int64     `json:"cpu_ns,omitempty" doc:"CPU time used since it started, in nanoseconds"`
	Tasks       *int       `json:"tasks,omitempty" doc:"Processes and threads"`
	Since       *time.Time `json:"since,omitempty" doc:"When it entered its current state"`
	Restarts    int        `json:"restarts" doc:"Automatic restarts since it was started by hand"`
	Result      string     `json:"result,omitempty" doc:"How its last run ended: success, exit-code, signal, timeout, core-dump…" example:"success"`
	ExitCode    int        `json:"exit_code" doc:"Exit status of its main process's last run"`
	User        string     `json:"user,omitempty" doc:"User= it runs as; empty is root" example:"www-data"`
	Path        string     `json:"path,omitempty" doc:"Its unit file" example:"/usr/lib/systemd/system/nginx.service"`
	DropIns     []string   `json:"drop_ins" doc:"Drop-in files that change it"`
	TriggeredBy []string   `json:"triggered_by" doc:"Sockets, timers or paths that start it" example:"[\"docker.socket\"]"`
	Custom      bool       `json:"custom" doc:"Its unit file lives in /etc/systemd/system, so it can be edited or removed here"`
	CanStart    bool       `json:"can_start"`
	CanStop     bool       `json:"can_stop"`
	CanReload   bool       `json:"can_reload" doc:"It reloads its configuration without a restart"`
	NeedReload  bool       `json:"need_reload" doc:"Its unit file changed on disk since systemd read it (daemon-reload)"`
	Protected   bool       `json:"protected" doc:"Morcheh reaches the server through it (sshd) or the system needs it to run; stopping it asks for force"`
}

// Properties ListProps asks `systemctl show` for.
var ListProps = []string{
	"Id", "Description", "LoadState", "ActiveState", "SubState", "UnitFileState", "UnitFilePreset", "Type",
	"MainPID", "MemoryCurrent", "CPUUsageNSec", "TasksCurrent", "StateChangeTimestamp", "NRestarts", "Result",
	"ExecMainStatus", "User", "FragmentPath", "DropInPaths", "TriggeredBy", "CanStart", "CanStop", "CanReload",
	"NeedDaemonReload",
}

type Details struct {
	Service
	Requires         []string   `json:"requires"`
	Wants            []string   `json:"wants"`
	WantedBy         []string   `json:"wanted_by" doc:"Targets that pull it in at boot"`
	RequiredBy       []string   `json:"required_by"`
	After            []string   `json:"after"`
	Before           []string   `json:"before"`
	Conflicts        []string   `json:"conflicts"`
	ExecStart        []string   `json:"exec_start" doc:"Command lines it starts" example:"[\"/usr/sbin/nginx -g daemon on; master_process on;\"]"`
	WorkingDirectory string     `json:"working_directory,omitempty"`
	Environment      []string   `json:"environment" doc:"KEY=value pairs set on it" example:"[\"NODE_ENV=production\"]"`
	EnvironmentFiles []string   `json:"environment_files"`
	Restart          string     `json:"restart,omitempty" doc:"Restart= policy: no, on-failure, always…" example:"on-failure"`
	RestartSec       string     `json:"restart_sec,omitempty" example:"5s"`
	Documentation    []string   `json:"documentation" example:"[\"man:nginx(8)\"]"`
	StatusText       string     `json:"status_text,omitempty" doc:"What the service itself reports (sd_notify STATUS=)"`
	ActiveSince      *time.Time `json:"active_since,omitempty" doc:"When it last became active"`
	Files            []UnitFile `json:"files" doc:"The unit file and its drop-ins, as systemd reads them"`
}

// DetailProps adds what the details view shows to ListProps.
var DetailProps = append(slices.Clone(ListProps),
	"Requires", "Wants", "WantedBy", "RequiredBy", "After", "Before", "Conflicts", "ExecStart",
	"WorkingDirectory", "Environment", "EnvironmentFiles", "Restart", "RestartUSec", "Documentation",
	"StatusText", "ActiveEnterTimestamp",
)

type UnitFile struct {
	Path    string `json:"path" example:"/etc/systemd/system/nginx.service.d/override.conf"`
	Content string `json:"content"`
	DropIn  bool   `json:"drop_in" doc:"A drop-in (.conf in <unit>.d/) rather than the unit file"`
}

// Props is one `systemctl show` block. A property may repeat (ExecStart).
type Props map[string][]string

func (p Props) get(k string) string {
	if v := p[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// list splits a space-separated property (Requires, DropInPaths…).
func (p Props) list(k string) []string {
	out := []string{}
	for _, v := range p[k] {
		out = append(out, strings.Fields(v)...)
	}
	return out
}

// ParseShow splits `systemctl show` output into blocks, one per unit, in
// order; an alias shows up with its real Id and is kept once.
func ParseShow(out string) []Props {
	var blocks []Props
	seen := map[string]bool{}
	for _, block := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n\n") {
		p := Props{}
		for _, l := range strings.Split(block, "\n") {
			if k, v, ok := strings.Cut(l, "="); ok {
				p[k] = append(p[k], v)
			}
		}
		id := p.get("Id")
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		blocks = append(blocks, p)
	}
	return blocks
}

// List turns show blocks into services, leaving out units that are only
// referenced (not-found) and not running.
func List(blocks []Props) []Service {
	out := []Service{}
	for _, p := range blocks {
		s := FromProps(p)
		if s.Load == "not-found" && s.Active == "inactive" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func FromProps(p Props) Service {
	s := Service{
		Name: p.get("Id"), Description: p.get("Description"),
		Load: p.get("LoadState"), Active: p.get("ActiveState"), Sub: p.get("SubState"),
		Enabled: p.get("UnitFileState"), Type: p.get("Type"),
		Result: p.get("Result"), User: p.get("User"), Path: p.get("FragmentPath"),
		DropIns: p.list("DropInPaths"), TriggeredBy: p.list("TriggeredBy"),
		CanStart: p.get("CanStart") == "yes", CanStop: p.get("CanStop") == "yes",
		CanReload: p.get("CanReload") == "yes", NeedReload: p.get("NeedDaemonReload") == "yes",
	}
	// UnitFilePreset is "enabled" or "disabled"; older systemd leaves it out.
	if v := p.get("UnitFilePreset"); v == "enabled" || v == "disabled" {
		s.Preset = v
	}
	s.MainPID, _ = strconv.Atoi(p.get("MainPID"))
	s.Restarts, _ = strconv.Atoi(p.get("NRestarts"))
	s.ExitCode, _ = strconv.Atoi(p.get("ExecMainStatus"))
	s.Memory = counter(p.get("MemoryCurrent"))
	s.CPUNs = counter(p.get("CPUUsageNSec"))
	if n := counter(p.get("TasksCurrent")); n != nil {
		t := int(*n)
		s.Tasks = &t
	}
	s.Since = Time(p.get("StateChangeTimestamp"))
	s.Custom = strings.HasPrefix(s.Path, "/etc/systemd/system/")
	s.Protected = Protected(s.Name)
	return s
}

// counter reads a systemd counter; "[not set]" and UINT64_MAX mean unknown.
func counter(v string) *int64 {
	n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
	if err != nil || n == 1<<64-1 || n > 1<<62 {
		return nil
	}
	i := int64(n)
	return &i
}

// Time reads "@1793586600" (--timestamp=unix) or the default
// "Sun 2026-11-01 14:51:15 UTC"; empty or n/a is no time.
func Time(v string) *time.Time {
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

// The ones Morcheh logs in through, or that the system can't run without.
var protected = []string{
	"ssh.service", "sshd.service", "ssh.socket", "sshd.socket", "dropbear.service",
	"dbus.service", "dbus-broker.service", "systemd-journald.service", "systemd-logind.service",
	"systemd-udevd.service", "systemd-networkd.service", "NetworkManager.service", "networking.service",
	"sshd", "dropbear", "networking", "udev", "syslog",
}

func Protected(name string) bool { return slices.Contains(protected, name) }

// Details reads one unit's full show block and its `systemctl cat`.
func DetailsFrom(p Props, cat string) Details {
	d := Details{
		Service:  FromProps(p),
		Requires: p.list("Requires"), Wants: p.list("Wants"), WantedBy: p.list("WantedBy"),
		RequiredBy: p.list("RequiredBy"), After: p.list("After"), Before: p.list("Before"),
		Conflicts: p.list("Conflicts"), ExecStart: []string{}, Environment: []string{},
		EnvironmentFiles: []string{}, Documentation: p.list("Documentation"),
		WorkingDirectory: p.get("WorkingDirectory"), Restart: p.get("Restart"),
		RestartSec: p.get("RestartUSec"), StatusText: p.get("StatusText"),
		ActiveSince: Time(p.get("ActiveEnterTimestamp")),
		Files:       ParseCat(cat),
	}
	for _, v := range p["ExecStart"] {
		if cmd := execArgv(v); cmd != "" {
			d.ExecStart = append(d.ExecStart, cmd)
		}
	}
	for _, v := range p["Environment"] {
		d.Environment = append(d.Environment, splitEnv(v)...)
	}
	for _, v := range p["EnvironmentFiles"] {
		// "/etc/default/ssh (ignore_errors=yes)"
		if f, _, _ := strings.Cut(v, " ("); f != "" {
			d.EnvironmentFiles = append(d.EnvironmentFiles, f)
		}
	}
	return d
}

var argvRe = regexp.MustCompile(`argv\[\]=(.*?) ; (?:ignore_errors|flags)=`)

// execArgv takes the command line out of
// "{ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -g daemon on; ; ignore_errors=no ; … }".
func execArgv(v string) string {
	if m := argvRe.FindStringSubmatch(v); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// splitEnv splits `Environment=A=1 "B=two words"` into its pairs.
func splitEnv(v string) []string {
	var out []string
	var cur strings.Builder
	quote := byte(0)
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case quote != 0 && c == quote:
			quote = 0
		case quote == 0 && (c == '"' || c == '\''):
			quote = c
		case quote == 0 && c == ' ':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// ParseCat splits `systemctl cat` output: each file starts with "# /path".
func ParseCat(out string) []UnitFile {
	files := []UnitFile{}
	var cur *UnitFile
	var body []string
	done := func() {
		if cur != nil {
			cur.Content = strings.TrimRight(strings.Join(body, "\n"), "\n") + "\n"
			files = append(files, *cur)
		}
	}
	for _, l := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		if p, ok := strings.CutPrefix(l, "# /"); ok && !strings.Contains(p, " ") {
			done()
			path := "/" + p
			cur, body = &UnitFile{Path: path, DropIn: strings.Contains(path, ".d/")}, nil
			continue
		}
		if cur != nil {
			body = append(body, l)
		}
	}
	done()
	// cat puts a blank line between files: it isn't part of the file above.
	return files
}

// ---- Journal ----

type LogEntry struct {
	Time     time.Time `json:"time"`
	Priority int       `json:"priority" doc:"0 emerg … 3 err, 4 warning, 5 notice, 6 info, 7 debug" example:"6"`
	Message  string    `json:"message"`
	PID      int       `json:"pid,omitempty"`
	Ident    string    `json:"ident,omitempty" doc:"Who logged it (SYSLOG_IDENTIFIER)" example:"nginx"`
	Cursor   string    `json:"cursor" doc:"Where this entry sits in the journal, to continue after it"`
}

// ParseJournalLine reads one line of `journalctl -o json`.
func ParseJournalLine(line string) (LogEntry, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "{") {
		return LogEntry{}, false
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return LogEntry{}, false
	}
	e := LogEntry{Priority: 6, Message: field(raw["MESSAGE"]), Ident: field(raw["SYSLOG_IDENTIFIER"]),
		Cursor: field(raw["__CURSOR"])}
	if us, err := strconv.ParseInt(field(raw["__REALTIME_TIMESTAMP"]), 10, 64); err == nil {
		e.Time = time.UnixMicro(us).UTC()
	}
	if p, err := strconv.Atoi(field(raw["PRIORITY"])); err == nil {
		e.Priority = p
	}
	e.PID, _ = strconv.Atoi(field(raw["_PID"]))
	return e, true
}

// field reads a journal field: a string, or an array of bytes when it isn't
// valid UTF-8 (or a list of them when the field repeats).
func field(m json.RawMessage) string {
	if len(m) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(m, &s) == nil {
		return s
	}
	var b []byte
	var ints []int
	if json.Unmarshal(m, &ints) == nil {
		for _, i := range ints {
			b = append(b, byte(i))
		}
		return strings.ToValidUTF8(string(b), "�")
	}
	var many []json.RawMessage
	if json.Unmarshal(m, &many) == nil && len(many) > 0 {
		return field(many[0])
	}
	return ""
}

// ---- OpenRC ----

// OpenRCInput is what the OpenRC collect script prints, by section.
type OpenRCInput struct {
	Scripts string // "name<TAB>description" per init script
	Status  string // rc-status --all --nocolor
	Update  string // rc-update show -v
}

var (
	rcStatusRe = regexp.MustCompile(`^\s*(\S+)\s+\[\s*([a-z]+)`)
	rcUpdateRe = regexp.MustCompile(`^\s*(\S+)\s*\|\s*(.*)$`)
)

func OpenRC(in OpenRCInput) []Service {
	state := map[string]string{}
	for _, l := range strings.Split(in.Status, "\n") {
		if m := rcStatusRe.FindStringSubmatch(l); m != nil {
			state[m[1]] = m[2]
		}
	}
	levels := map[string]string{}
	for _, l := range strings.Split(in.Update, "\n") {
		if m := rcUpdateRe.FindStringSubmatch(l); m != nil {
			levels[m[1]] = strings.Join(strings.Fields(m[2]), " ")
		}
	}
	out := []Service{}
	for _, l := range strings.Split(in.Scripts, "\n") {
		name, desc, _ := strings.Cut(strings.TrimSpace(l), "\t")
		if name == "" {
			continue
		}
		sub := state[name]
		if sub == "" {
			sub = "stopped"
		}
		s := Service{
			Name: name, Description: desc, Load: "loaded", Sub: sub,
			Path: "/etc/init.d/" + name, DropIns: []string{}, TriggeredBy: []string{},
			CanStart: true, CanStop: true, Protected: Protected(name),
		}
		switch sub {
		case "started":
			s.Active = "active"
		case "starting":
			s.Active = "activating"
		case "stopping":
			s.Active = "deactivating"
		case "crashed", "failed":
			s.Active = "failed"
		default:
			s.Active = "inactive"
		}
		switch lv := levels[name]; {
		case lv == "":
			s.Enabled = "disabled"
		case strings.Contains(" "+lv+" ", " default ") || strings.Contains(" "+lv+" ", " boot ") ||
			strings.Contains(" "+lv+" ", " sysinit "):
			s.Enabled = "enabled"
		default:
			s.Enabled = lv // another runlevel, e.g. "shutdown"
		}
		out = append(out, s)
	}
	return out
}

// ---- Files ----

// Normalize gives a unit file one shape, so its revision doesn't change with
// how it was read: Unix newlines and exactly one at the end (none if empty).
func Normalize(s string) string {
	s = strings.TrimRight(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return s + "\n"
}

// Revision identifies a file's content, for spotting edits made meanwhile.
func Revision(content string) string {
	sum := sha256.Sum256([]byte(Normalize(content)))
	return hex.EncodeToString(sum[:12])
}
