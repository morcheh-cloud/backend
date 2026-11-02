package api

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/fail2ban"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/terminal"
)

// ---- Types ----

type Fail2banSection struct {
	Settings map[string]string `json:"settings" doc:"Effective value of every key the section sets, after all files are read"`
	Origin   map[string]string `json:"origin" doc:"For each key, the file its effective value comes from"`
}

type Fail2banJail struct {
	Name    string `json:"name" example:"sshd"`
	Enabled bool   `json:"enabled" doc:"What the configuration says (the jail's own enabled, else [DEFAULT]'s)"`
	Active  bool   `json:"active" doc:"Running in fail2ban right now"`
	Source  string `json:"source" doc:"The file that first defines the jail" example:"/etc/fail2ban/jail.conf"`
	Custom  bool   `json:"custom" doc:"Defined only in .local files, so deleting it removes it (instead of resetting it)"`
	Fail2banSection
	Status *fail2ban.JailStatus `json:"status,omitempty" doc:"Only for active jails"`
	Bans   []fail2ban.Ban       `json:"bans" doc:"Banned addresses with their time window"`
}

type Fail2banFile struct {
	Path     string `json:"path" example:"/etc/fail2ban/jail.local"`
	Exists   bool   `json:"exists"`
	Content  string `json:"content"`
	Revision string `json:"revision" doc:"Send it back when changing the file, to detect edits made meanwhile"`
}

type Fail2banOverview struct {
	Access         string          `json:"access" enum:"root,sudo,user" doc:"Managing fail2ban needs root or sudo"`
	PackageManager string          `json:"package_manager" doc:"apt-get, dnf, yum, zypper, apk, pacman; empty when none is found" example:"apt-get"`
	Init           string          `json:"init" enum:"systemd,openrc,none"`
	Installed      bool            `json:"installed"`
	Version        string          `json:"version" example:"1.1.0"`
	Running        bool            `json:"running" doc:"The fail2ban server process is up"`
	Responding     bool            `json:"responding" doc:"fail2ban-client could talk to it (needs root), so jail status is known"`
	StartsAtBoot   bool            `json:"starts_at_boot"`
	Defaults       Fail2banSection `json:"defaults" doc:"[DEFAULT]: what every jail inherits"`
	Jails          []Fail2banJail  `json:"jails" doc:"Every jail the configuration defines, enabled or not"`
	Filters        []string        `json:"filters" doc:"Names in filter.d"`
	Actions        []string        `json:"actions" doc:"Names in action.d"`
	Files          []string        `json:"files" doc:"Jail config files, in the order fail2ban reads them (later wins)"`
	Config         Fail2banFile    `json:"config" doc:"jail.local, where every change made here is written"`
	Warnings       []string        `json:"warnings"`
}

type Fail2banTask struct {
	OK         bool   `json:"ok"`
	ExitCode   int    `json:"exit_code" doc:"-1 when it was stopped"`
	Output     string `json:"output" doc:"stdout and stderr together"`
	Truncated  bool   `json:"truncated"`
	DurationMs int64  `json:"duration_ms"`
}

type Fail2banInstallBody struct {
	ProtectSSH bool `json:"protect_ssh,omitempty" default:"true" doc:"Turn the sshd jail on when no jail.local exists yet"`
}

type Fail2banUninstallBody struct {
	Purge bool `json:"purge,omitempty" doc:"Also remove its configuration (apt, pacman)"`
}

type Fail2banServiceBody struct {
	Action string `json:"action" enum:"start,stop,restart,reload,enable,disable" doc:"enable/disable = start at boot or not"`
}

type Fail2banSettingsBody struct {
	Revision string            `json:"revision" doc:"jail.local's revision as last read; a different one answers 409"`
	Set      map[string]string `json:"set,omitempty" doc:"Keys to write into the section of jail.local; newlines make a multi-line value" example:"{\"bantime\":\"1h\"}"`
	Unset    []string          `json:"unset,omitempty" doc:"Keys to remove from the section of jail.local, so the inherited value applies again"`
}

type Fail2banJailPath struct {
	ID   string `path:"id" format:"uuid"`
	Jail string `path:"jail" maxLength:"64" example:"sshd"`
}

type Fail2banJailInput struct {
	Fail2banJailPath
	Body Fail2banSettingsBody
}

type Fail2banDeleteJailInput struct {
	Fail2banJailPath
	Revision string `query:"revision" doc:"jail.local's revision as last read"`
}

type Fail2banConfigBody struct {
	Revision string `json:"revision"`
	Content  string `json:"content" maxLength:"262144"`
}

type Fail2banBanBody struct {
	Jail string `json:"jail,omitempty" maxLength:"64" doc:"Required to ban; to unban, empty means every jail" example:"sshd"`
	IP   string `json:"ip" minLength:"1" maxLength:"64" doc:"An address, or a network in CIDR form" example:"192.0.2.1"`
}

type Fail2banLogInput struct {
	ID    string `path:"id" format:"uuid"`
	Lines int    `query:"lines" minimum:"10" maximum:"5000" default:"500"`
}

type Fail2banLog struct {
	Source string           `json:"source" doc:"The log file, journal, or empty when none was readable" example:"/var/log/fail2ban.log"`
	Lines  []string         `json:"lines" doc:"Oldest first"`
	Events []fail2ban.Event `json:"events" doc:"Ban activity from those lines, newest first"`
}

type Fail2banFilterPath struct {
	ID     string `path:"id" format:"uuid"`
	Filter string `path:"filter" maxLength:"64" example:"sshd"`
}

type Fail2banFilter struct {
	Name  string       `json:"name" example:"sshd"`
	Conf  Fail2banFile `json:"conf" doc:"filter.d/<name>.conf as the package ships it (read-only here)"`
	Local Fail2banFile `json:"local" doc:"filter.d/<name>.local: overrides, or the whole filter for a custom one"`
}

type Fail2banFilterInput struct {
	Fail2banFilterPath
	Body Fail2banConfigBody
}

type Fail2banTestBody struct {
	Filter      string `json:"filter,omitempty" maxLength:"64" doc:"A filter from filter.d; or give failregex" example:"sshd"`
	FailRegex   string `json:"failregex,omitempty" maxLength:"4000" doc:"A regex to try instead of a filter (<HOST> marks the address)"`
	IgnoreRegex string `json:"ignoreregex,omitempty" maxLength:"4000"`
	Log         string `json:"log,omitempty" maxLength:"1024" doc:"A log file path, or \"journal\" for the systemd journal" example:"/var/log/auth.log"`
	Sample      string `json:"sample,omitempty" maxLength:"262144" doc:"Log lines to test against instead of a file"`
}

type Fail2banTestResult struct {
	fail2ban.RegexSummary
	Matches []string `json:"matches" doc:"The lines that matched (at most 200)"`
	Output  string   `json:"output" doc:"fail2ban-regex's whole report"`
}

const (
	f2bDir       = "/etc/fail2ban"
	f2bJailLocal = f2bDir + "/jail.local"
	f2bMarker    = "@@morcheh@@"
	f2bService   = "fail2ban"
)

var (
	f2bNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$`)
	f2bKeyRe  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
)

// ---- Handlers ----

func registerFail2ban(api huma.API, h *serverHandler) {
	tags := []string{"Security"}
	base := "/servers/{id}/security/fail2ban"

	huma.Register(api, huma.Operation{
		OperationID: "get-fail2ban",
		Method:      http.MethodGet,
		Path:        base,
		Summary:     "Fail2ban on a server",
		Description: "Whether it's installed and running, the effective configuration of every jail (merged from jail.conf, jail.d and jail.local), " +
			"live counts and banned addresses for the active ones, and jail.local itself.",
		Tags: tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body Fail2banOverview }, error) {
		return h.fail2banOverview(ctx, in.ID)
	})

	huma.Register(api, huma.Operation{
		OperationID: "install-fail2ban",
		Method:      http.MethodPost,
		Path:        base + "/install",
		Summary:     "Install fail2ban",
		Description: "With the server's package manager (EPEL on RHEL-likes), then starts it and enables it at boot. " +
			"Checked at once, then runs as a background job (kind `fail2ban-install`); it can't be canceled once the package manager is running. " +
			"409 when an install or removal is already under way.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body Fail2banInstallBody
	}) (*JobOutput, error) {
		return h.submitF2bPackage(ctx, in.ID, f2bInstallKind, f2bPackageParams{ServerID: in.ID, ProtectSSH: in.Body.ProtectSSH})
	})
	h.jobs.Handle(f2bInstallKind, h.runF2bPackage("Installing", f2bInstallScript))

	huma.Register(api, huma.Operation{
		OperationID:   "uninstall-fail2ban",
		Method:        http.MethodPost,
		Path:          base + "/uninstall",
		Summary:       "Remove fail2ban",
		Description:   "Stops it (lifting every ban) and removes the package. Runs as a background job (kind `fail2ban-uninstall`), like install.",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body Fail2banUninstallBody
	}) (*JobOutput, error) {
		return h.submitF2bPackage(ctx, in.ID, f2bRemoveKind, f2bPackageParams{ServerID: in.ID, Purge: in.Body.Purge})
	})
	h.jobs.Handle(f2bRemoveKind, h.runF2bPackage("Removing", f2bRemoveScript))

	huma.Register(api, huma.Operation{
		OperationID: "fail2ban-service",
		Method:      http.MethodPost,
		Path:        base + "/service",
		Summary:     "Start, stop, restart or reload fail2ban, or set it to start at boot",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body Fail2banServiceBody
	}) (*struct{ Body Fail2banTask }, error) {
		return h.fail2banTask(ctx, in.ID, func(f hostFacts) (string, error) {
			if in.Body.Action == "reload" {
				return "fail2ban-client reload", nil
			}
			return serviceScript(f.init, f2bService, in.Body.Action, f2bDirect)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-fail2ban-defaults",
		Method:      http.MethodPut,
		Path:        base + "/defaults",
		Summary:     "Change what every jail inherits",
		Description: "Writes [DEFAULT] keys into jail.local, checks the configuration (fail2ban-client -t) and reloads; " +
			"a configuration fail2ban rejects is put back and answers 422.",
		Tags: tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body Fail2banSettingsBody
	}) (*struct{ Body Fail2banOverview }, error) {
		return h.editJailLocal(ctx, in.ID, in.Body.Revision, func(d *fail2ban.Doc) error {
			return applySettings(d, "DEFAULT", in.Body)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-fail2ban-jail",
		Method:      http.MethodPut,
		Path:        base + "/jails/{jail}",
		Summary:     "Change, enable or add a jail",
		Description: "Writes the jail's keys into its section of jail.local (adding the section, which creates a custom jail when " +
			"no other file defines it), checks the configuration and reloads. Set enabled=true/false to turn it on or off.",
		Tags: tags,
	}, func(ctx context.Context, in *Fail2banJailInput) (*struct{ Body Fail2banOverview }, error) {
		if err := checkJailName(in.Jail); err != nil {
			return nil, err
		}
		return h.editJailLocal(ctx, in.ID, in.Body.Revision, func(d *fail2ban.Doc) error {
			return applySettings(d, in.Jail, in.Body)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-fail2ban-jail",
		Method:      http.MethodDelete,
		Path:        base + "/jails/{jail}",
		Summary:     "Reset or delete a jail",
		Description: "Removes the jail's section from jail.local: a jail defined elsewhere goes back to its shipped settings, a custom one is gone.",
		Tags:        tags,
	}, func(ctx context.Context, in *Fail2banDeleteJailInput) (*struct{ Body Fail2banOverview }, error) {
		if err := checkJailName(in.Jail); err != nil {
			return nil, err
		}
		return h.editJailLocal(ctx, in.ID, in.Revision, func(d *fail2ban.Doc) error {
			if !d.HasSection(in.Jail) {
				return huma.Error404NotFound(in.Jail + " isn't in jail.local")
			}
			d.RemoveSection(in.Jail)
			return nil
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "save-fail2ban-config",
		Method:      http.MethodPut,
		Path:        base + "/config",
		Summary:     "Replace jail.local",
		Description: "The whole file as text; checked and reloaded like any other change.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body Fail2banConfigBody
	}) (*struct{ Body Fail2banOverview }, error) {
		return h.editJailLocal(ctx, in.ID, in.Body.Revision, func(d *fail2ban.Doc) error {
			*d = *fail2ban.Parse(in.Body.Content)
			return nil
		})
	})

	huma.Register(api, huma.Operation{
		OperationID:   "fail2ban-ban",
		Method:        http.MethodPost,
		Path:          base + "/ban",
		Summary:       "Ban an address in a jail",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body Fail2banBanBody
	}) (*struct{}, error) {
		if in.Body.Jail == "" {
			return nil, fieldError("body.jail", "Pick the jail to ban it in", "")
		}
		return nil, h.fail2banClient(ctx, in.ID, in.Body, "banip")
	})

	huma.Register(api, huma.Operation{
		OperationID:   "fail2ban-unban",
		Method:        http.MethodPost,
		Path:          base + "/unban",
		Summary:       "Lift a ban, in one jail or all",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body Fail2banBanBody
	}) (*struct{}, error) {
		return nil, h.fail2banClient(ctx, in.ID, in.Body, "unbanip")
	})

	huma.Register(api, huma.Operation{
		OperationID: "fail2ban-log",
		Method:      http.MethodGet,
		Path:        base + "/log",
		Summary:     "Fail2ban's recent log and ban activity",
		Description: "From its log target: a file, else the journal.",
		Tags:        tags,
	}, func(ctx context.Context, in *Fail2banLogInput) (*struct{ Body Fail2banLog }, error) {
		out := &struct{ Body Fail2banLog }{}
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.rootShell(ctx, in.ID, c)
			if err != nil {
				return err
			}
			raw, err := sh.run(ctx, f2bLogScript(in.Lines))
			if err != nil {
				return err
			}
			out.Body = parseF2bLog(raw)
			return nil
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-fail2ban-filter",
		Method:      http.MethodGet,
		Path:        base + "/filters/{filter}",
		Summary:     "A filter's definition",
		Tags:        tags,
	}, func(ctx context.Context, in *Fail2banFilterPath) (*struct{ Body Fail2banFilter }, error) {
		if err := checkFilterName(in.Filter); err != nil {
			return nil, err
		}
		out := &struct{ Body Fail2banFilter }{}
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.rootShell(ctx, in.ID, c)
			if err != nil {
				return err
			}
			f, err := readFilter(ctx, sh, in.Filter)
			if err == nil {
				out.Body = *f
			}
			return err
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "save-fail2ban-filter",
		Method:      http.MethodPut,
		Path:        base + "/filters/{filter}",
		Summary:     "Write a filter's .local file",
		Description: "Overrides for a shipped filter, or a whole new one. Empty content deletes the .local file. Checked and reloaded like jail.local.",
		Tags:        tags,
	}, func(ctx context.Context, in *Fail2banFilterInput) (*struct{ Body Fail2banFilter }, error) {
		if err := checkFilterName(in.Filter); err != nil {
			return nil, err
		}
		out := &struct{ Body Fail2banFilter }{}
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.f2bRoot(ctx, in.ID, c)
			if err != nil {
				return err
			}
			f, err := readFilter(ctx, sh, in.Filter)
			if err != nil {
				return err
			}
			if f.Local.Revision != in.Body.Revision {
				return huma.Error409Conflict(f.Local.Path + " changed on the server since you opened it")
			}
			if err := writeChecked(ctx, sh, f.Local.Path, normalizeConfig(in.Body.Content)); err != nil {
				return err
			}
			f, err = readFilter(ctx, sh, in.Filter)
			if err == nil {
				out.Body = *f
			}
			return err
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "test-fail2ban-filter",
		Method:      http.MethodPost,
		Path:        base + "/test",
		Summary:     "Try a filter or regex against a log",
		Description: "Runs fail2ban-regex on a log file, the journal or pasted lines, and reports how many lines match.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body Fail2banTestBody
	}) (*struct{ Body Fail2banTestResult }, error) {
		script, err := f2bTestScript(in.Body)
		if err != nil {
			return nil, err
		}
		out := &struct{ Body Fail2banTestResult }{}
		err = h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.rootShell(ctx, in.ID, c)
			if err != nil {
				return err
			}
			res, err := sh.exec(ctx, script, 90*time.Second, 512<<10)
			if err != nil {
				return err
			}
			text := string(res.output)
			sum, ok := fail2ban.ParseRegex(text)
			if !ok {
				if res.timedOut {
					return huma.Error504GatewayTimeout("fail2ban-regex took too long")
				}
				return huma.Error422UnprocessableEntity("fail2ban-regex failed: " + lastLines(text, 4))
			}
			out.Body = Fail2banTestResult{RegexSummary: sum, Matches: regexMatches(text, 200), Output: text}
			return nil
		})
		return out, toProblem(err)
	})
}

// fail2ban-client's own commands, for servers without an init system (e.g.
// containers). -x clears a stale socket left by a crash.
var f2bDirect = map[string]string{
	"start":   "mkdir -p /var/run/fail2ban && fail2ban-client -x start",
	"stop":    "fail2ban-client stop",
	"restart": "mkdir -p /var/run/fail2ban && { fail2ban-client ping >/dev/null 2>&1 && fail2ban-client restart || fail2ban-client -x start; }",
}

// ---- Reading ----

func (h *serverHandler) fail2banOverview(ctx context.Context, id string) (*struct{ Body Fail2banOverview }, error) {
	out := &struct{ Body Fail2banOverview }{}
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.rootShell(ctx, id, c)
		if err != nil {
			return err
		}
		o, err := collectFail2ban(ctx, sh)
		if err == nil {
			out.Body = *o
		}
		return err
	})
	return out, toProblem(err)
}

// The process check spells the name as a bracket pattern so grep doesn't
// find itself (or this script) in the process list.
var f2bCollectScript = `m=` + f2bMarker + `
echo "$m host"
` + hostScript + `
command -v fail2ban-client >/dev/null 2>&1 || exit 0
echo "$m version"; fail2ban-client --version 2>&1 | head -n 1
echo "$m boot"
` + enabledScript(f2bService) + `
echo "$m proc"
` + processScript("[f]ail2ban-server") + `
for f in ` + f2bDir + `/jail.conf ` + f2bDir + `/jail.d/*.conf ` + f2bJailLocal + ` ` + f2bDir + `/jail.d/*.local; do
  [ -f "$f" ] && [ -r "$f" ] || continue
  echo "$m file $f"; cat "$f"; echo
done
for k in filter action; do
  echo "$m $k"
  for f in ` + f2bDir + `/$k.d/*.conf ` + f2bDir + `/$k.d/*.local; do [ -f "$f" ] && { b=${f##*/}; echo "${b%.*}"; }; done | sort -u
done
fail2ban-client ping >/dev/null 2>&1 || exit 0
echo "$m responding"
for j in $(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' '); do
  echo "$m jail $j"; fail2ban-client status "$j" 2>&1
  echo "$m bans $j"; fail2ban-client get "$j" banip --with-time 2>/dev/null
done
exit 0
`

var versionRe = regexp.MustCompile(`v?(\d+\.\d+(?:\.\d+)*)`)

func collectFail2ban(ctx context.Context, sh *rootShell) (*Fail2banOverview, error) {
	raw, err := sh.run(ctx, f2bCollectScript)
	if err != nil {
		return nil, err
	}
	o := &Fail2banOverview{
		Access:   sh.priv.access(),
		Init:     "none",
		Jails:    []Fail2banJail{},
		Filters:  []string{},
		Actions:  []string{},
		Files:    []string{},
		Warnings: []string{},
		Config:   Fail2banFile{Path: f2bJailLocal, Revision: revision("")},
	}
	var layers []fail2ban.Layer
	statuses := map[string]fail2ban.JailStatus{}
	bans := map[string][]fail2ban.Ban{}
	var active []string
	for _, s := range splitF2bSections(raw) {
		switch s.kind {
		case "host":
			f := parseHost(s.body)
			o.PackageManager, o.Init = f.pm, f.init
		case "version":
			o.Installed = true
			if m := versionRe.FindStringSubmatch(s.body); m != nil {
				o.Version = m[1]
			}
		case "boot":
			o.StartsAtBoot = strings.Contains(s.body, "enabled")
		case "proc":
			o.Running = strings.Contains(s.body, "running")
		case "file":
			p := strings.Join(s.args, " ")
			o.Files = append(o.Files, p)
			layers = append(layers, fail2ban.Layer{Path: p, Doc: fail2ban.Parse(s.body)})
			if p == f2bJailLocal {
				o.Config = Fail2banFile{Path: p, Exists: true, Content: s.body, Revision: revision(s.body)}
			}
		case "filter":
			o.Filters = strings.Fields(s.body)
		case "action":
			o.Actions = strings.Fields(s.body)
		case "responding":
			o.Responding, o.Running = true, true
		case "jail":
			if len(s.args) > 0 {
				active = append(active, s.args[0])
				statuses[s.args[0]] = fail2ban.ParseStatus(s.body)
			}
		case "bans":
			if len(s.args) > 0 {
				bans[s.args[0]] = fail2ban.ParseBans(s.body)
			}
		}
	}

	merged := fail2ban.Merge(layers)
	o.Defaults = sectionView(merged.Sections["DEFAULT"])
	for _, name := range merged.Order {
		if name == "DEFAULT" || name == "INCLUDES" {
			continue
		}
		sec := merged.Sections[name]
		enabled, ok := sec["enabled"]
		if !ok {
			enabled = merged.Sections["DEFAULT"]["enabled"]
		}
		src := fail2ban.DefinedIn(layers, name)
		j := Fail2banJail{
			Name:            name,
			Enabled:         fail2ban.Bool(enabled.Value),
			Active:          slices.Contains(active, name),
			Source:          src,
			Custom:          strings.HasSuffix(src, ".local"),
			Fail2banSection: sectionView(sec),
			Bans:            []fail2ban.Ban{},
		}
		if st, ok := statuses[name]; ok {
			j.Status = &st
			j.Bans = jailBans(st, bans[name])
		}
		o.Jails = append(o.Jails, j)
	}
	// Running jails the files don't explain (added at runtime).
	for _, name := range active {
		if _, ok := merged.Sections[name]; !ok {
			st := statuses[name]
			o.Jails = append(o.Jails, Fail2banJail{
				Name: name, Enabled: true, Active: true, Custom: true,
				Fail2banSection: sectionView(nil), Status: &st, Bans: jailBans(st, bans[name]),
			})
		}
	}

	switch {
	case !o.Installed:
	case sh.priv == privUser:
		o.Warnings = append(o.Warnings, "Managing fail2ban needs root: log in as root, or allow sudo for this user.")
	case !o.Running:
		o.Warnings = append(o.Warnings, "Fail2ban is installed but not running, so nothing is being banned.")
	}
	if o.Installed && o.Init == "none" {
		o.Warnings = append(o.Warnings, "This server has no init system, so fail2ban won't start again by itself after a reboot.")
	}
	return o, nil
}

type f2bSection struct {
	kind string
	args []string
	body string
}

// splitF2bSections cuts collect output at its marker lines. A file's body
// comes out byte for byte: the echo after cat adds the newline the marker
// split takes away.
func splitF2bSections(out string) []f2bSection {
	var secs []f2bSection
	for _, part := range strings.Split("\n"+out, "\n"+f2bMarker+" ")[1:] {
		head, body, _ := strings.Cut(part, "\n")
		f := strings.Fields(head)
		if len(f) == 0 {
			continue
		}
		secs = append(secs, f2bSection{kind: f[0], args: f[1:], body: body})
	}
	return secs
}

func sectionView(sec map[string]fail2ban.Setting) Fail2banSection {
	v := Fail2banSection{Settings: map[string]string{}, Origin: map[string]string{}}
	for k, s := range sec {
		v.Settings[k], v.Origin[k] = s.Value, s.Path
	}
	return v
}

// jailBans keeps the timed list when fail2ban gave one (1.0+), else the
// plain addresses from the status.
func jailBans(st fail2ban.JailStatus, timed []fail2ban.Ban) []fail2ban.Ban {
	if len(timed) > 0 {
		return timed
	}
	out := make([]fail2ban.Ban, 0, len(st.BannedIPs))
	for _, ip := range st.BannedIPs {
		out = append(out, fail2ban.Ban{IP: ip})
	}
	return out
}

// ---- Changing ----

// f2bRoot is a root shell, or 403: every change needs root.
func (h *serverHandler) f2bRoot(ctx context.Context, id string, c *sshpool.Conn) (*rootShell, error) {
	sh, err := h.rootShell(ctx, id, c)
	if err != nil {
		return nil, err
	}
	if sh.priv == privUser {
		return nil, huma.Error403Forbidden("Managing fail2ban needs root or sudo on this server")
	}
	return sh, nil
}

// fail2banTask runs a script built from the server's package manager and
// init system, and reports how it went.
func (h *serverHandler) fail2banTask(ctx context.Context, id string, build func(hostFacts) (string, error)) (*struct{ Body Fail2banTask }, error) {
	out := &struct{ Body Fail2banTask }{}
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.f2bRoot(ctx, id, c)
		if err != nil {
			return err
		}
		facts, err := sh.run(ctx, hostScript)
		if err != nil {
			return err
		}
		script, err := build(parseHost(facts))
		if err != nil {
			return err
		}
		res, err := sh.exec(ctx, script, packageTimeout, 256<<10)
		if err != nil {
			return err
		}
		out.Body = Fail2banTask{
			OK:         res.code == 0,
			ExitCode:   res.code,
			Output:     string(res.output),
			Truncated:  res.truncated,
			DurationMs: res.duration.Milliseconds(),
		}
		return nil
	})
	return out, toProblem(err)
}

// ---- Install & remove (background jobs) ----

const (
	f2bInstallKind = "fail2ban-install"
	f2bRemoveKind  = "fail2ban-uninstall"
)

type f2bPackageParams struct {
	ServerID   string `json:"server_id"`
	ProtectSSH bool   `json:"protect_ssh,omitempty"`
	Purge      bool   `json:"purge,omitempty"`
}

// f2bStartFailed is the install script's exit code when the package went on
// but the service wouldn't start, which is a different thing to tell the user.
const f2bStartFailed = 90

func f2bInstallScript(f hostFacts, p f2bPackageParams) (string, error) {
	install, err := packageScript(f.pm, "install", "fail2ban")
	if err != nil {
		return "", err
	}
	s := install + " || exit $?\n"
	if p.ProtectSSH {
		// The sshd jail fails fail2ban's start without a log to watch:
		// point it at the one the server has, else the journal
		// (Debian 12+ has no auth.log), else leave it off.
		s += "if [ ! -e " + f2bJailLocal + " ]; then\n" +
			"  l=''; for f in /var/log/auth.log /var/log/secure /var/log/messages; do [ -f \"$f\" ] && { l=$f; break; }; done\n" +
			"  if [ -n \"$l\" ]; then printf '[sshd]\\nenabled = true\\nlogpath = %s\\n' \"$l\" > " + f2bJailLocal + "\n" +
			"  elif [ -d /run/systemd/system ]; then printf '[sshd]\\nenabled = true\\nbackend = systemd\\n' > " + f2bJailLocal + "\n" +
			"  else echo 'Morcheh: no SSH log on this server (no syslog or journal), so the sshd jail stays off.'; fi\n" +
			"fi\n"
	}
	code := " || exit " + strconv.Itoa(f2bStartFailed) + "\n"
	switch f.init {
	case "systemd":
		s += "{ systemctl enable fail2ban && systemctl restart fail2ban; }" + code
	case "openrc":
		s += "{ rc-update add fail2ban default && rc-service fail2ban restart; }" + code
	default:
		s += "{ " + f2bDirect["restart"] + "; }" + code
	}
	return s, nil
}

func f2bRemoveScript(f hostFacts, p f2bPackageParams) (string, error) {
	op := "remove"
	if p.Purge {
		op = "purge"
	}
	remove, err := packageScript(f.pm, op, "fail2ban")
	if err != nil {
		return "", err
	}
	stop, _ := serviceScript(f.init, f2bService, "stop", f2bDirect)
	return stop + " >/dev/null 2>&1\n" + remove + "\n", nil
}

// submitF2bPackage answers what it can at once (no root, no package manager,
// one already running), then queues the job.
func (h *serverHandler) submitF2bPackage(ctx context.Context, id, kind string, p f2bPackageParams) (*JobOutput, error) {
	build := f2bInstallScript
	title := "Install fail2ban on "
	if kind == f2bRemoveKind {
		build, title = f2bRemoveScript, "Remove fail2ban from "
	}
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.f2bRoot(ctx, id, c)
		if err != nil {
			return err
		}
		facts, err := sh.run(ctx, hostScript)
		if err != nil {
			return err
		}
		_, err = build(parseHost(facts), p)
		return err
	})
	if err != nil {
		return nil, toProblem(err)
	}
	refs := placeRefs(id)
	active := true
	list, err := h.jobs.List(ctx, sqlc.ListJobsParams{Ref: &refs[0], Active: &active, Lim: 200})
	if err != nil {
		return nil, internalError(err)
	}
	if slices.ContainsFunc(list, func(j sqlc.Job) bool { return j.Kind == f2bInstallKind || j.Kind == f2bRemoveKind }) {
		return nil, huma.Error409Conflict("Fail2ban is already being installed or removed on this server")
	}
	s, err := h.get(ctx, id)
	if err != nil {
		return nil, err
	}
	return submit(ctx, h.jobs, jobs.Spec{Kind: kind, Title: title + s.Name, Params: p, Refs: refs})
}

// runF2bPackage runs the package manager. Stopping one half way can leave the
// server's packages broken, and a process under sudo isn't ours to kill, so
// the job can't be canceled from then on; packageTimeout is its limit.
func (h *serverHandler) runF2bPackage(phase string, build func(hostFacts, f2bPackageParams) (string, error)) jobs.Handler {
	return func(ctx context.Context, t *jobs.Task) (any, error) {
		var p f2bPackageParams
		if err := t.Decode(&p); err != nil {
			return nil, err
		}
		err := h.withConn(ctx, p.ServerID, func(c *sshpool.Conn) error {
			sh, err := h.f2bRoot(ctx, p.ServerID, c)
			if err != nil {
				return err
			}
			facts, err := sh.run(ctx, hostScript)
			if err != nil {
				return err
			}
			script, err := build(parseHost(facts), p)
			if err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Locked = phase, true })
			var last string
			lines := &lineWriter{fn: func(l string) {
				last = l
				t.Logf("%s", l)
				t.Update(func(pr *jobs.Progress) { pr.Current = l })
			}}
			res, err := sh.execTo(ctx, script, packageTimeout, lines)
			lines.flush()
			switch {
			case err != nil:
				return err
			case ctx.Err() != nil:
				return ctx.Err()
			case res.timedOut:
				return fmt.Errorf("It took longer than %d minutes, so Morcheh stopped waiting", int(packageTimeout.Minutes()))
			case res.code == f2bStartFailed:
				return fmt.Errorf("Fail2ban was installed but didn't start: %s", last)
			case res.code != 0:
				return fmt.Errorf("The package manager failed (exit %d): %s", res.code, last)
			}
			return nil
		})
		return nil, jobError(err)
	}
}

func checkJailName(name string) error {
	if !f2bNameRe.MatchString(name) || name == "DEFAULT" || name == "INCLUDES" {
		return fieldError("path.jail", "A jail name is letters, digits and _ . @ -", name)
	}
	return nil
}

func checkFilterName(name string) error {
	if !f2bNameRe.MatchString(name) {
		return fieldError("path.filter", "A filter name is letters, digits and _ . @ -", name)
	}
	return nil
}

func applySettings(d *fail2ban.Doc, section string, b Fail2banSettingsBody) error {
	for _, k := range sortedKeys(b.Set) {
		if !f2bKeyRe.MatchString(k) {
			return fieldError("body.set."+k, "Not a setting name", k)
		}
		v := b.Set[k]
		if strings.ContainsAny(v, "\x00\r") || len(v) > 4000 {
			return fieldError("body.set."+k, "Not a valid value", v)
		}
		d.Set(section, k, v)
	}
	for _, k := range b.Unset {
		d.Unset(section, strings.ToLower(k))
	}
	if len(b.Set) == 0 && len(b.Unset) == 0 && !d.HasSection(section) {
		// An empty update still creates the section (a new custom jail).
		d.Set(section, "enabled", "false")
	}
	return nil
}

// editJailLocal reads jail.local, checks it is still the revision the user
// saw, applies edit, writes it back through writeChecked and answers the
// fresh overview.
func (h *serverHandler) editJailLocal(ctx context.Context, id, rev string, edit func(*fail2ban.Doc) error) (*struct{ Body Fail2banOverview }, error) {
	out := &struct{ Body Fail2banOverview }{}
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.f2bRoot(ctx, id, c)
		if err != nil {
			return err
		}
		cur, err := readConfig(ctx, sh, f2bJailLocal)
		if err != nil {
			return err
		}
		if cur.Revision != rev {
			return huma.Error409Conflict("jail.local changed on the server since you loaded it")
		}
		doc := fail2ban.Parse(cur.Content)
		if err := edit(doc); err != nil {
			return err
		}
		if err := writeChecked(ctx, sh, f2bJailLocal, doc.String()); err != nil {
			return err
		}
		o, err := collectFail2ban(ctx, sh)
		if err == nil {
			out.Body = *o
		}
		return err
	})
	return out, toProblem(err)
}

func readConfig(ctx context.Context, sh *rootShell, p string) (Fail2banFile, error) {
	f := terminal.ShellQuote(p)
	raw, err := sh.run(ctx, "if [ -f "+f+" ]; then echo y; cat "+f+"; else echo n; fi")
	if err != nil {
		return Fail2banFile{}, err
	}
	flag, content, _ := strings.Cut(raw, "\n")
	if flag != "y" {
		content = ""
	}
	return Fail2banFile{Path: p, Exists: flag == "y", Content: content, Revision: revision(content)}, nil
}

func readFilter(ctx context.Context, sh *rootShell, name string) (*Fail2banFilter, error) {
	base := f2bDir + "/filter.d/" + name
	conf, err := readConfig(ctx, sh, base+".conf")
	if err != nil {
		return nil, err
	}
	local, err := readConfig(ctx, sh, base+".local")
	if err != nil {
		return nil, err
	}
	return &Fail2banFilter{Name: name, Conf: conf, Local: local}, nil
}

func normalizeConfig(s string) string {
	s = strings.TrimRight(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	if s != "" {
		s += "\n"
	}
	return s
}

// writeChecked replaces a config file (empty content deletes it), asks
// fail2ban whether the whole configuration still reads, and reloads it when
// running. Either failing puts the old file back and answers 422 with what
// fail2ban said.
func writeChecked(ctx context.Context, sh *rootShell, p, content string) error {
	f := terminal.ShellQuote(p)
	dir := terminal.ShellQuote(path.Dir(p))
	script := "f=" + f + "; b=''\n" +
		"if [ -f \"$f\" ]; then b=$(mktemp " + dir + "/.morcheh.bak.XXXXXX) && cp -p \"$f\" \"$b\" || exit 1; fi\n" +
		"restore() { if [ -n \"$b\" ]; then mv -f \"$b\" \"$f\"; else rm -f \"$f\"; fi; }\n"
	if content == "" {
		script += "rm -f \"$f\"\n"
	} else {
		eof := "MORCHEH_" + randomSuffix()
		script += "t=$(mktemp " + dir + "/.morcheh.XXXXXX) || exit 1\n" +
			"cat > \"$t\" <<'" + eof + "'\n" + content + eof + "\n" +
			"chmod 644 \"$t\" && mv -f \"$t\" \"$f\" || { rm -f \"$t\" \"$b\"; exit 1; }\n"
	}
	script += "if ! out=$(fail2ban-client -t 2>&1); then restore; printf '%s\\n' \"$out\"; exit 3; fi\n" +
		"if fail2ban-client ping >/dev/null 2>&1; then\n" +
		"  if ! out=$(fail2ban-client reload 2>&1); then restore; fail2ban-client reload >/dev/null 2>&1; printf '%s\\n' \"$out\"; exit 4; fi\n" +
		"fi\n" +
		"[ -z \"$b\" ] || rm -f \"$b\"\n"
	res, err := sh.exec(ctx, script, 2*time.Minute, 64<<10)
	if err != nil {
		return err
	}
	switch {
	case res.timedOut:
		return huma.Error504GatewayTimeout("fail2ban took too long to check the configuration")
	case res.code == 3:
		return huma.Error422UnprocessableEntity("Fail2ban rejected the configuration, so the old file was put back:\n" + f2bErrors(res.output))
	case res.code == 4:
		return huma.Error422UnprocessableEntity("Fail2ban couldn't reload with it, so the old file was put back:\n" + f2bErrors(res.output))
	case res.code != 0:
		return huma.Error422UnprocessableEntity("Couldn't write " + p + ": " + lastLines(string(res.output), 3))
	}
	return nil
}

// f2bErrors keeps fail2ban's ERROR lines, else the end of its output.
func f2bErrors(out []byte) string {
	var errs []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "ERROR") {
			errs = append(errs, strings.TrimSpace(l))
		}
	}
	if len(errs) == 0 {
		return lastLines(string(out), 5)
	}
	return strings.Join(errs[max(0, len(errs)-8):], "\n")
}

func (h *serverHandler) fail2banClient(ctx context.Context, id string, b Fail2banBanBody, op string) error {
	ip := strings.TrimSpace(b.IP)
	if _, err := netip.ParseAddr(ip); err != nil {
		if _, err := netip.ParsePrefix(ip); err != nil {
			return fieldError("body.ip", "Not an IP address or CIDR network", b.IP)
		}
	}
	var cmd string
	switch {
	case b.Jail != "":
		if err := checkJailName(b.Jail); err != nil {
			return err
		}
		cmd = "fail2ban-client set " + terminal.ShellQuote(b.Jail) + " " + op + " " + terminal.ShellQuote(ip)
	default:
		cmd = "fail2ban-client unban " + terminal.ShellQuote(ip)
	}
	return toProblem(h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.f2bRoot(ctx, id, c)
		if err != nil {
			return err
		}
		res, err := sh.exec(ctx, cmd, 30*time.Second, 16<<10)
		if err != nil {
			return err
		}
		if res.code != 0 {
			return huma.Error422UnprocessableEntity("fail2ban refused: " + lastLines(string(res.output), 3))
		}
		return nil
	}))
}

// ---- Log ----

func f2bLogScript(n int) string {
	lines := strconv.Itoa(n)
	return `t=$(fail2ban-client get logtarget 2>/dev/null | sed -n 's/^.*- //p' | head -n 1)
case $t in /*) ;; *) t=''; [ -f /var/log/fail2ban.log ] && t=/var/log/fail2ban.log ;; esac
if [ -n "$t" ] && [ -r "$t" ]; then echo "$t"; tail -n ` + lines + ` "$t"; exit 0; fi
if command -v journalctl >/dev/null 2>&1; then echo journal; journalctl -u fail2ban -n ` + lines + ` --no-pager -o short-iso 2>/dev/null; exit 0; fi
echo
`
}

func parseF2bLog(raw string) Fail2banLog {
	src, rest, _ := strings.Cut(raw, "\n")
	l := Fail2banLog{Source: strings.TrimSpace(src), Lines: []string{}, Events: []fail2ban.Event{}}
	for _, line := range strings.Split(strings.TrimRight(rest, "\n"), "\n") {
		if line != "" && !strings.HasPrefix(line, "-- ") {
			l.Lines = append(l.Lines, line)
		}
	}
	ev := fail2ban.ParseEvents(l.Lines)
	slices.Reverse(ev)
	if ev != nil {
		l.Events = ev
	}
	return l
}

// ---- Testing filters ----

func f2bTestScript(b Fail2banTestBody) (string, error) {
	var pattern string
	switch {
	case b.FailRegex != "":
		pattern = terminal.ShellQuote(b.FailRegex)
	case b.Filter != "":
		if err := checkFilterName(b.Filter); err != nil {
			return "", err
		}
		pattern = terminal.ShellQuote(b.Filter)
	default:
		return "", fieldError("body.filter", "Pick a filter or write a regex", "")
	}
	ignore := ""
	if b.IgnoreRegex != "" {
		ignore = " " + terminal.ShellQuote(b.IgnoreRegex)
	}
	run := "fail2ban-regex --print-all-matched "
	switch {
	case b.Sample != "":
		eof := "MORCHEH_" + randomSuffix()
		return "t=$(mktemp) || exit 1\ncat > \"$t\" <<'" + eof + "'\n" + normalizeConfig(b.Sample) + eof + "\n" +
			run + "\"$t\" " + pattern + ignore + " 2>&1\nrc=$?; rm -f \"$t\"; exit $rc\n", nil
	case b.Log == "journal":
		return run + "systemd-journal " + pattern + ignore + " 2>&1\n", nil
	case strings.HasPrefix(b.Log, "/"):
		return run + terminal.ShellQuote(b.Log) + " " + pattern + ignore + " 2>&1\n", nil
	}
	return "", fieldError("body.log", "Give a log file path, \"journal\", or sample lines", b.Log)
}

// regexMatches reads the "|  line" rows under "Matched line(s):".
func regexMatches(out string, limit int) []string {
	matches := []string{}
	in := false
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.Contains(line, "Matched line(s):"):
			in = true
		case in && strings.HasPrefix(line, "|  "):
			if len(matches) < limit {
				matches = append(matches, strings.TrimSpace(line[3:]))
			}
		case in:
			in = false
		}
	}
	return matches
}
