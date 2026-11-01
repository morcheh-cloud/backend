package api

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/terminal"
	"github.com/morcheh/backend/internal/users"
)

// ---- Types ----

type UsersOverview struct {
	LoginUser       string          `json:"login_user" doc:"The account Morcheh logs in as; it can't be deleted, locked, renamed or lose sudo here" example:"deploy"`
	Access          string          `json:"access" enum:"root,sudo,user" doc:"Changing accounts needs root or sudo"`
	Tools           string          `json:"tools" enum:"shadow,busybox,none" doc:"shadow: useradd/usermod…; busybox: adduser/addgroup only (no renames, expiry or usermod changes)"`
	Commands        []string        `json:"commands" doc:"Account tools found on the server" example:"[\"useradd\",\"chage\",\"visudo\"]"`
	ShadowReadable  bool            `json:"shadow_readable" doc:"/etc/shadow could be read, so password and expiry states are known"`
	SudoInstalled   bool            `json:"sudo_installed"`
	SudoReadable    bool            `json:"sudo_readable" doc:"sudoers could be read; otherwise sudo rights are guessed from the sudo/wheel/admin groups"`
	SudoIncludesDir bool            `json:"sudo_includes_dir" doc:"/etc/sudoers reads /etc/sudoers.d, where Morcheh writes its rules"`
	SudoGroup       string          `json:"sudo_group" doc:"A group (sudo, wheel or admin) whose members get sudo for every command; empty when none does" example:"sudo"`
	LoginHistory    bool            `json:"login_history" doc:"The server keeps login records (lastlog or wtmp), so last_login means something"`
	UIDMin          int             `json:"uid_min" doc:"First uid of a regular account (UID_MIN in login.defs)" example:"1000"`
	Shells          []string        `json:"shells" doc:"From /etc/shells" example:"[\"/bin/bash\",\"/bin/sh\"]"`
	Users           []users.User    `json:"users"`
	Groups          []users.Group   `json:"groups"`
	SudoRules       []users.Rule    `json:"sudo_rules" doc:"Every user rule in sudoers and sudoers.d"`
	Sessions        []users.Session `json:"sessions" doc:"Logged in right now (who)"`
	Warnings        []string        `json:"warnings"`
}

func (o *UsersOverview) has(cmd string) bool { return slices.Contains(o.Commands, cmd) }

func (o *UsersOverview) user(name string) *users.User {
	for i := range o.Users {
		if o.Users[i].Name == name {
			return &o.Users[i]
		}
	}
	return nil
}

func (o *UsersOverview) group(name string) *users.Group {
	for i := range o.Groups {
		if o.Groups[i].Name == name {
			return &o.Groups[i]
		}
	}
	return nil
}

type UsersOutput struct{ Body UsersOverview }

type UserPath struct {
	ID   string `path:"id" format:"uuid"`
	User string `path:"user" maxLength:"64" example:"deploy"`
}

type GroupPath struct {
	ID    string `path:"id" format:"uuid"`
	Group string `path:"group" maxLength:"64" example:"docker"`
}

type UserCreateBody struct {
	Name               string   `json:"name" minLength:"1" maxLength:"32" example:"deploy"`
	FullName           string   `json:"full_name,omitempty" maxLength:"200" example:"Deploy bot"`
	Shell              string   `json:"shell,omitempty" maxLength:"200" doc:"Default /bin/bash when the server has it, else /bin/sh" example:"/bin/bash"`
	Home               string   `json:"home,omitempty" maxLength:"500" doc:"Default /home/<name>"`
	CreateHome         bool     `json:"create_home" doc:"Create the home folder (from /etc/skel)"`
	UID                *int     `json:"uid,omitempty" minimum:"1" maximum:"2147483646" doc:"Default the next free one"`
	PrimaryGroup       string   `json:"primary_group,omitempty" maxLength:"32" doc:"An existing group; default a new group named after the user"`
	Groups             []string `json:"groups,omitempty" maxItems:"200" doc:"Supplementary groups" example:"[\"docker\"]"`
	System             bool     `json:"system,omitempty" doc:"A service account (uid below UID_MIN)"`
	Password           string   `json:"password,omitempty" maxLength:"256" doc:"Empty: no password, so it logs in with a key only. Sent hashed (SHA-512) to the server"`
	MustChangePassword bool     `json:"must_change_password,omitempty" doc:"Ask for a new password at the first login"`
	Sudo               string   `json:"sudo,omitempty" enum:"none,password,nopasswd" default:"none"`
	AuthorizedKey      string   `json:"authorized_key,omitempty" maxLength:"16000" doc:"A public key for ~/.ssh/authorized_keys" example:"ssh-ed25519 AAAAC3Nza… you@laptop"`
}

type UserUpdateBody struct {
	Name           *string   `json:"name,omitempty" minLength:"1" maxLength:"32" doc:"Rename (its personal group too)"`
	FullName       *string   `json:"full_name,omitempty" maxLength:"200"`
	Shell          *string   `json:"shell,omitempty" maxLength:"200"`
	Home           *string   `json:"home,omitempty" maxLength:"500"`
	MoveHome       bool      `json:"move_home,omitempty" doc:"With home: move the old folder's contents there"`
	PrimaryGroup   *string   `json:"primary_group,omitempty" maxLength:"32"`
	Groups         *[]string `json:"groups,omitempty" maxItems:"200" doc:"The full list of supplementary groups"`
	AccountExpires *string   `json:"account_expires,omitempty" doc:"YYYY-MM-DD, or empty for never" example:"2027-01-31"`
	Sudo           *string   `json:"sudo,omitempty" enum:"none,password,nopasswd" doc:"none: no sudo; password: every command, asking for the user's password; nopasswd: every command, without asking"`
}

type UserPasswordBody struct {
	Password           string `json:"password" minLength:"1" maxLength:"256" doc:"Sent hashed (SHA-512) to the server; also unlocks a locked password"`
	MustChangePassword bool   `json:"must_change_password,omitempty" doc:"Ask for a new one at the next login"`
}

type UserLockBody struct {
	Locked bool `json:"locked" doc:"true: no logins at all, password or key (the password is kept for unlock)"`
	Logout bool `json:"logout,omitempty" doc:"With locked: also end their sessions and processes"`
}

type GroupCreateBody struct {
	Name    string   `json:"name" minLength:"1" maxLength:"32" example:"deployers"`
	GID     *int     `json:"gid,omitempty" minimum:"1" maximum:"2147483646"`
	System  bool     `json:"system,omitempty" doc:"gid below UID_MIN"`
	Members []string `json:"members,omitempty" maxItems:"500"`
}

type GroupUpdateBody struct {
	Name    *string   `json:"name,omitempty" minLength:"1" maxLength:"32"`
	Members *[]string `json:"members,omitempty" maxItems:"500" doc:"The full member list"`
}

// ---- Routes ----

func registerUsers(api huma.API, h *serverHandler) {
	tags := []string{"Users"}

	huma.Register(api, huma.Operation{
		OperationID: "get-users",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/users",
		Summary:     "Accounts and groups on a server",
		Description: "Every account in /etc/passwd with its groups, password and expiry state (from /etc/shadow), sudo rights " +
			"(from sudoers), last login and current sessions; every group; and the sudoers rules.",
		Tags: tags,
	}, func(ctx context.Context, in *ServerIDPath) (*UsersOutput, error) {
		out := &UsersOutput{}
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.rootShell(ctx, in.ID, c)
			if err != nil {
				return err
			}
			o, err := h.collectUsers(ctx, in.ID, sh)
			if err == nil {
				out.Body = *o
			}
			return err
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-user",
		Method:        http.MethodPost,
		Path:          "/servers/{id}/users",
		Summary:       "Add an account",
		Description:   "useradd (or BusyBox adduser), then the password, sudo level and SSH key. Answers the fresh overview.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body UserCreateBody
	}) (*UsersOutput, error) {
		return h.changeUsers(ctx, in.ID, func(o *UsersOverview) (string, error) {
			return createUserScript(o, in.Body)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-user",
		Method:      http.MethodPatch,
		Path:        "/servers/{id}/users/{user}",
		Summary:     "Change an account",
		Description: "Only the fields sent change. sudo rewrites how the account gets sudo: the sudo group, or a rule in " +
			"/etc/sudoers.d/morcheh-<name>; its own rules elsewhere are commented out. Every sudoers change is checked with visudo " +
			"and put back when it fails.",
		Tags: tags,
	}, func(ctx context.Context, in *struct {
		UserPath
		Body UserUpdateBody
	}) (*UsersOutput, error) {
		return h.changeUsers(ctx, in.ID, func(o *UsersOverview) (string, error) {
			u := o.user(in.User)
			if u == nil {
				return "", noUser(in.User)
			}
			return updateUserScript(o, u, in.Body)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-user",
		Method:      http.MethodDelete,
		Path:        "/servers/{id}/users/{user}",
		Summary:     "Remove an account",
		Description: "userdel (or deluser), and its Morcheh sudo rule. The login user and root can't be removed.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		UserPath
		RemoveHome bool `query:"remove_home" doc:"Also delete the home folder and mail spool"`
		Force      bool `query:"force" doc:"End its processes first (else a logged-in account can't be removed)"`
	}) (*UsersOutput, error) {
		return h.changeUsers(ctx, in.ID, func(o *UsersOverview) (string, error) {
			u := o.user(in.User)
			if u == nil {
				return "", noUser(in.User)
			}
			if err := protect(o, u, "remove"); err != nil {
				return "", err
			}
			s, err := sudoScript(o, u, u.Name, "none", true)
			if err != nil {
				return "", err
			}
			if in.Force {
				s += killScript(u.Name)
			}
			switch {
			case o.has("userdel"):
				s += "userdel"
				if in.RemoveHome {
					s += " -r"
				}
				if in.Force {
					s += " -f"
				}
			case o.has("deluser"):
				s += "deluser"
				if in.RemoveHome {
					s += " --remove-home"
				}
			default:
				return "", noTools()
			}
			return s + " " + q(u.Name) + "\n", nil
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-user-password",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/users/{user}/password",
		Summary:     "Set an account's password",
		Description: "Hashed here (SHA-512 crypt) and written with chpasswd -e, so the plain password never reaches the server.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		UserPath
		Body UserPasswordBody
	}) (*UsersOutput, error) {
		return h.changeUsers(ctx, in.ID, func(o *UsersOverview) (string, error) {
			u := o.user(in.User)
			if u == nil {
				return "", noUser(in.User)
			}
			return passwordScript(o, u.Name, in.Body.Password, in.Body.MustChangePassword)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "lock-user",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/users/{user}/lock",
		Summary:     "Lock or unlock an account",
		Description: "Locking puts ! in front of the password and expires the account (1970-01-02), which also stops SSH key logins. " +
			"Unlocking undoes both and keeps the old password.",
		Tags: tags,
	}, func(ctx context.Context, in *struct {
		UserPath
		Body UserLockBody
	}) (*UsersOutput, error) {
		return h.changeUsers(ctx, in.ID, func(o *UsersOverview) (string, error) {
			u := o.user(in.User)
			if u == nil {
				return "", noUser(in.User)
			}
			if err := protect(o, u, "lock"); err != nil {
				return "", err
			}
			return lockScript(o, u, in.Body)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "logout-user",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/users/{user}/logout",
		Summary:     "End an account's sessions",
		Description: "loginctl terminate-user where systemd runs, then kills every process the account owns.",
		Tags:        tags,
	}, func(ctx context.Context, in *UserPath) (*UsersOutput, error) {
		return h.changeUsers(ctx, in.ID, func(o *UsersOverview) (string, error) {
			u := o.user(in.User)
			if u == nil {
				return "", noUser(in.User)
			}
			if err := protect(o, u, "log out"); err != nil {
				return "", err
			}
			return killScript(u.Name), nil
		})
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-group",
		Method:        http.MethodPost,
		Path:          "/servers/{id}/groups",
		Summary:       "Add a group",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body GroupCreateBody
	}) (*UsersOutput, error) {
		return h.changeUsers(ctx, in.ID, func(o *UsersOverview) (string, error) {
			return createGroupScript(o, in.Body)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-group",
		Method:      http.MethodPatch,
		Path:        "/servers/{id}/groups/{group}",
		Summary:     "Rename a group or set its members",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		GroupPath
		Body GroupUpdateBody
	}) (*UsersOutput, error) {
		return h.changeUsers(ctx, in.ID, func(o *UsersOverview) (string, error) {
			g := o.group(in.Group)
			if g == nil {
				return "", noGroup(in.Group)
			}
			return updateGroupScript(o, g, in.Body)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "delete-group",
		Method:      http.MethodDelete,
		Path:        "/servers/{id}/groups/{group}",
		Summary:     "Remove a group",
		Description: "Refused while it is an account's primary group.",
		Tags:        tags,
	}, func(ctx context.Context, in *GroupPath) (*UsersOutput, error) {
		return h.changeUsers(ctx, in.ID, func(o *UsersOverview) (string, error) {
			g := o.group(in.Group)
			if g == nil {
				return "", noGroup(in.Group)
			}
			if len(g.Primary) > 0 {
				return "", huma.Error422UnprocessableEntity("It's the primary group of " + strings.Join(g.Primary, ", ") +
					"; give them another one first")
			}
			if g.Sudo && (slices.Contains(g.Members, o.LoginUser)) {
				return "", huma.Error422UnprocessableEntity(o.LoginUser + " gets sudo through it, and Morcheh needs that to manage this server")
			}
			switch {
			case o.has("groupdel"):
				return "groupdel " + q(g.Name) + "\n", nil
			case o.has("delgroup"):
				return "delgroup " + q(g.Name) + "\n", nil
			}
			return "", noTools()
		})
	})
}

// ---- Collect ----

var usersCollectScript = `PATH="$PATH:/usr/sbin:/sbin"
m=` + cronMarker + `
echo "$m now"; date +%s
echo "$m passwd"; cat /etc/passwd
echo "$m group"; cat /etc/group
if [ -r /etc/shadow ]; then echo "$m shadow"; cat /etc/shadow; fi
echo "$m defs"; sed -n 's/^[[:space:]]*UID_MIN[[:space:]]\{1,\}\([0-9]\{1,\}\).*/\1/p' /etc/login.defs 2>/dev/null | head -n 1
echo "$m shells"; grep -v '^[[:space:]]*#' /etc/shells 2>/dev/null
echo "$m tools"
for t in useradd usermod userdel groupadd groupmod groupdel gpasswd chage chpasswd adduser deluser addgroup delgroup passwd sudo visudo loginctl pkill; do
  command -v "$t" >/dev/null 2>&1 && echo "$t"
done
[ -e /etc/sudoers ] && echo "$m sudo-present"
if [ -r /etc/sudoers ]; then
  echo "$m sudoers /etc/sudoers"; cat /etc/sudoers; echo
  for f in /etc/sudoers.d/*; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    echo "$m sudoers $f"; cat "$f"; echo
  done
fi
echo "$m who"; who 2>/dev/null
echo "$m lastlog"
if command -v lastlog2 >/dev/null 2>&1; then lastlog2 2>/dev/null
elif command -v lastlog >/dev/null 2>&1; then lastlog 2>/dev/null; fi
echo "$m last"; last -w --time-format iso 2>/dev/null | head -n 2000
echo "$m homes"
while IFS=: read -r n _ _ _ _ h _; do
  [ -n "$h" ] && [ "$h" != / ] && [ -d "$h" ] || continue
  k="$h/.ssh/authorized_keys"
  if [ ! -x "$h" ]; then c=-1
  elif [ -f "$k" ]; then
    if [ -r "$k" ]; then c=$(grep -c '^[[:space:]]*[^#[:space:]]' "$k"); else c=-1; fi
  else c=0; fi
  echo "$n $c"
done < /etc/passwd
exit 0
`

func (h *serverHandler) collectUsers(ctx context.Context, id string, sh *rootShell) (*UsersOverview, error) {
	raw, err := sh.run(ctx, usersCollectScript)
	if err != nil {
		return nil, err
	}
	s, err := h.get(ctx, id)
	if err != nil {
		return nil, err
	}
	o := &UsersOverview{
		LoginUser: s.Username, Access: sh.priv.access(),
		Commands: []string{}, Shells: []string{}, Warnings: []string{},
	}
	in := users.Input{Homes: map[string]int{}}
	var lastlog, last string
	for _, sec := range splitSections(raw) {
		body := sec.body
		switch sec.kind {
		case "now":
			if n, err := strconv.ParseInt(strings.TrimSpace(body), 10, 64); err == nil {
				in.Now = time.Unix(n, 0)
			}
		case "passwd":
			in.Passwd = body
		case "group":
			in.Group = body
		case "shadow":
			in.Shadow, in.HasShadow = body, true
		case "defs":
			in.UIDMin, _ = strconv.Atoi(strings.TrimSpace(body))
		case "shells":
			for _, l := range strings.Split(body, "\n") {
				if l = strings.TrimSpace(l); strings.HasPrefix(l, "/") && !slices.Contains(o.Shells, l) {
					o.Shells = append(o.Shells, l)
				}
			}
		case "tools":
			o.Commands = append(o.Commands, strings.Fields(body)...)
		case "sudo-present":
			o.SudoInstalled = true
		case "sudoers":
			in.Sudoers = append(in.Sudoers, users.File{Path: strings.Join(sec.args, " "), Content: body})
		case "who":
			in.Who = body
		case "lastlog":
			lastlog = body
		case "last":
			last = body
		case "homes":
			for _, l := range strings.Split(body, "\n") {
				f := strings.Fields(l)
				if len(f) == 2 {
					n, err := strconv.Atoi(f[1])
					if err != nil {
						n = -1
					}
					in.Homes[f[0]] = n
				}
			}
		}
	}
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	if in.UIDMin <= 0 {
		in.UIDMin = 1000
	}
	in.Lastlog, in.Last = lastlog, last
	r := users.Build(in)

	o.UIDMin = in.UIDMin
	o.Users, o.Groups, o.SudoRules, o.Sessions, o.SudoGroup = r.Users, r.Groups, r.Rules, r.Sessions, r.SudoGroup
	o.ShadowReadable = in.HasShadow
	o.SudoInstalled = o.SudoInstalled || o.has("sudo")
	o.SudoReadable = len(in.Sudoers) > 0
	if o.SudoReadable {
		o.SudoIncludesDir = users.IncludesDir(in.Sudoers[0].Content)
	}
	// Some lastlog builds print every account with "Never logged in": only
	// real dates count as history.
	for _, u := range o.Users {
		if u.LastLogin != nil {
			o.LoginHistory = true
			break
		}
	}
	o.LoginHistory = o.LoginHistory || strings.TrimSpace(last) != ""
	switch {
	case o.has("useradd"):
		o.Tools = "shadow"
	case o.has("adduser"):
		o.Tools = "busybox"
	default:
		o.Tools = "none"
	}
	for _, u := range o.Users {
		if u.UID == 0 && u.Name != "root" {
			o.Warnings = append(o.Warnings, u.Name+" has uid 0, so it is root under another name")
		}
	}
	return o, nil
}

// changeUsers runs a change built from the current state (as root or with
// sudo) and answers the state after it.
func (h *serverHandler) changeUsers(ctx context.Context, id string, build func(o *UsersOverview) (string, error)) (*UsersOutput, error) {
	out := &UsersOutput{}
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.rootShell(ctx, id, c)
		if err != nil {
			return err
		}
		if sh.priv == privUser {
			return huma.Error403Forbidden("Managing accounts needs root or sudo on this server")
		}
		o, err := h.collectUsers(ctx, id, sh)
		if err != nil {
			return err
		}
		script, err := build(o)
		if err != nil {
			return err
		}
		if script != "" {
			res, err := sh.exec(ctx, "PATH=\"$PATH:/usr/sbin:/sbin\"\n"+script, 2*time.Minute, 64<<10)
			if err != nil {
				return err
			}
			switch {
			case res.timedOut:
				return huma.Error504GatewayTimeout("The server took too long")
			case res.code == 127:
				return huma.Error422UnprocessableEntity("A command this needs isn't on the server: " + lastLines(string(res.output), 2))
			case res.code != 0:
				msg := lastLines(string(res.output), 4)
				if msg == "" {
					msg = fmt.Sprintf("The change failed (exit %d)", res.code)
				}
				return huma.Error422UnprocessableEntity(msg)
			}
		}
		o, err = h.collectUsers(ctx, id, sh)
		if err == nil {
			out.Body = *o
		}
		return err
	})
	return out, toProblem(err)
}

// ---- Scripts ----

var (
	q          = terminal.ShellQuote
	nameRe     = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
	keyRe      = regexp.MustCompile(`^(\S+ )?(ssh-[a-z0-9-]+|ecdsa-sha2-[a-z0-9-]+|sk-[a-z0-9@.-]+) [A-Za-z0-9+/]+=*( .*)?$`)
	sudoLevels = []string{"none", "password", "nopasswd"}
)

func noUser(name string) error  { return huma.Error404NotFound("No account named " + name) }
func noGroup(name string) error { return huma.Error404NotFound("No group named " + name) }
func noTools() error {
	return huma.Error422UnprocessableEntity("This server has no account tools (useradd or adduser)")
}

func busyboxCant(loc, what string) error {
	return fieldError(loc, "This server only has BusyBox's account tools, which can't "+what, nil)
}

func checkName(loc, name string) error {
	if !nameRe.MatchString(name) {
		return fieldError(loc, "Use lowercase letters, digits, _ . or -, starting with a letter or _ (at most 32)", name)
	}
	return nil
}

func checkAbsPath(loc, p string) error {
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, ":\n\r") {
		return fieldError(loc, "Must be an absolute path without a colon", p)
	}
	return nil
}

func checkFullName(loc, s string) error {
	if strings.ContainsAny(s, ":,\n\r") {
		return fieldError(loc, "Can't contain : , or a line break", s)
	}
	return nil
}

func loginShell(sh string) bool {
	base := path.Base(sh)
	return base != "nologin" && base != "false"
}

// protect refuses changes that would lock Morcheh out or touch root.
func protect(o *UsersOverview, u *users.User, what string) error {
	if u.UID == 0 {
		return huma.Error422UnprocessableEntity("Can't " + what + " " + u.Name + ": it's root (uid 0)")
	}
	if u.Name == o.LoginUser {
		return huma.Error422UnprocessableEntity("Can't " + what + " " + u.Name + ": Morcheh logs in to this server with it")
	}
	return nil
}

func checkGroups(o *UsersOverview, loc string, names []string) error {
	for i, g := range names {
		if o.group(g) == nil {
			return fieldError(fmt.Sprintf("%s[%d]", loc, i), "No group named "+g, g)
		}
	}
	return nil
}

func addMember(o *UsersOverview, user, group string) string {
	switch {
	case o.has("gpasswd"):
		return "gpasswd -a " + q(user) + " " + q(group) + " >/dev/null\n"
	case o.has("usermod"):
		return "usermod -a -G " + q(group) + " " + q(user) + "\n"
	}
	return "addgroup " + q(user) + " " + q(group) + "\n"
}

func removeMember(o *UsersOverview, user, group string) string {
	if o.has("gpasswd") {
		return "gpasswd -d " + q(user) + " " + q(group) + " >/dev/null\n"
	}
	return "delgroup " + q(user) + " " + q(group) + "\n"
}

func killScript(name string) string {
	return "if command -v loginctl >/dev/null 2>&1; then loginctl terminate-user " + q(name) + " >/dev/null 2>&1 || true; fi\n" +
		"pkill -KILL -u " + q(name) + " >/dev/null 2>&1 || true\n"
}

func passwordScript(o *UsersOverview, name, password string, mustChange bool) (string, error) {
	if strings.ContainsAny(password, "\n\r") {
		return "", fieldError("body.password", "Can't contain a line break", nil)
	}
	hash, err := sha512_crypt.New().Generate([]byte(password), nil)
	if err != nil {
		return "", internalError(err)
	}
	var s string
	switch {
	case o.has("chpasswd"):
		eof := "MORCHEH_" + randomSuffix()
		s = "chpasswd -e <<'" + eof + "'\n" + name + ":" + hash + "\n" + eof + "\n"
	case o.has("usermod"):
		s = "usermod -p " + q(hash) + " " + q(name) + "\n"
	default:
		return "", huma.Error422UnprocessableEntity("This server has no chpasswd or usermod to set a password with")
	}
	if mustChange {
		if !o.has("chage") {
			return "", fieldError("body.must_change_password", "This server has no chage, so it can't ask for a new password", nil)
		}
		s += "chage -d 0 " + q(name) + "\n"
	}
	return s, nil
}

func lockScript(o *UsersOverview, u *users.User, b UserLockBody) (string, error) {
	n := q(u.Name)
	if !o.has("usermod") {
		if b.Locked {
			return "passwd -l " + n + " >/dev/null\n", nil
		}
		return "passwd -u " + n + " >/dev/null\n", nil
	}
	if b.Locked {
		s := "usermod -L -e 1970-01-02 " + n + "\n"
		if b.Logout {
			s += killScript(u.Name)
		}
		return s, nil
	}
	// usermod -U refuses a lone "!" (it would leave no password): that
	// account had none, so it goes back to "no password login".
	s := "p=$(awk -F: -v u=" + n + " '$1==u{print $2}' /etc/shadow)\n" +
		"case \"$p\" in '!'|'!!') usermod -p '*' " + n + " ;; '!'*) usermod -U " + n + " ;; esac\n"
	if u.AccountExpires == "1970-01-02" {
		s += "usermod -e '' " + n + "\n"
	}
	return s, nil
}

func authorizedKeyScript(name, key string) string {
	n := q(name)
	return "h=$(awk -F: -v u=" + n + " '$1==u{print $6}' /etc/passwd)\n" +
		"[ -d \"$h\" ] || { echo \"No home folder to put the SSH key in\" >&2; exit 1; }\n" +
		"g=$(id -g " + n + ")\n" +
		"mkdir -p \"$h/.ssh\" && chmod 700 \"$h/.ssh\" && chown " + n + ":\"$g\" \"$h/.ssh\"\n" +
		"printf '%s\\n' " + q(key) + " >> \"$h/.ssh/authorized_keys\"\n" +
		"chmod 600 \"$h/.ssh/authorized_keys\" && chown " + n + ":\"$g\" \"$h/.ssh/authorized_keys\"\n"
}

func createUserScript(o *UsersOverview, b UserCreateBody) (string, error) {
	if err := checkName("body.name", b.Name); err != nil {
		return "", err
	}
	if o.user(b.Name) != nil {
		return "", fieldError("body.name", b.Name+" already exists", b.Name)
	}
	if err := checkFullName("body.full_name", b.FullName); err != nil {
		return "", err
	}
	shell := b.Shell
	if shell == "" {
		shell = "/bin/sh"
		if slices.Contains(o.Shells, "/bin/bash") {
			shell = "/bin/bash"
		}
	}
	if err := checkAbsPath("body.shell", shell); err != nil {
		return "", err
	}
	home := b.Home
	if home == "" {
		home = "/home/" + b.Name
	}
	if err := checkAbsPath("body.home", home); err != nil {
		return "", err
	}
	if b.UID != nil {
		for _, u := range o.Users {
			if u.UID == *b.UID {
				return "", fieldError("body.uid", fmt.Sprintf("%s already has uid %d", u.Name, *b.UID), *b.UID)
			}
		}
	}
	if b.PrimaryGroup != "" && o.group(b.PrimaryGroup) == nil {
		return "", fieldError("body.primary_group", "No group named "+b.PrimaryGroup, b.PrimaryGroup)
	}
	if b.PrimaryGroup == "" && o.group(b.Name) != nil {
		return "", fieldError("body.primary_group", "A group named "+b.Name+" already exists; pick it (or another) as the primary group", nil)
	}
	if err := checkGroups(o, "body.groups", b.Groups); err != nil {
		return "", err
	}
	key := strings.TrimSpace(b.AuthorizedKey)
	if key != "" && (strings.ContainsAny(key, "\n\r") || !keyRe.MatchString(key)) {
		return "", fieldError("body.authorized_key", "Paste one public key line, like ssh-ed25519 AAAA… name", nil)
	}
	if key != "" && !b.CreateHome {
		return "", fieldError("body.authorized_key", "The key goes in the home folder, so create it too", nil)
	}
	if b.Sudo == "" {
		b.Sudo = "none"
	}

	groups := slices.Clone(b.Groups)
	level := b.Sudo
	// Password sudo through the sudo group is just one more group.
	if level == "password" && o.SudoGroup != "" {
		if !slices.Contains(groups, o.SudoGroup) && b.PrimaryGroup != o.SudoGroup {
			groups = append(groups, o.SudoGroup)
		}
		level = "keep"
	}

	var s string
	switch o.Tools {
	case "shadow":
		args := []string{"useradd"}
		if b.System {
			args = append(args, "-r")
		}
		if b.UID != nil {
			args = append(args, "-u", strconv.Itoa(*b.UID))
		}
		if b.FullName != "" {
			args = append(args, "-c", q(b.FullName))
		}
		args = append(args, "-s", q(shell), "-d", q(home))
		if b.CreateHome {
			args = append(args, "-m")
		} else {
			args = append(args, "-M")
		}
		if b.PrimaryGroup != "" {
			args = append(args, "-g", q(b.PrimaryGroup))
		} else {
			args = append(args, "-U")
		}
		if len(groups) > 0 {
			args = append(args, "-G", q(strings.Join(groups, ",")))
		}
		s = strings.Join(append(args, q(b.Name)), " ") + "\n"
	case "busybox":
		args := []string{"adduser", "-D"}
		if b.System {
			args = append(args, "-S")
		}
		if b.UID != nil {
			args = append(args, "-u", strconv.Itoa(*b.UID))
		}
		if b.FullName != "" {
			args = append(args, "-g", q(b.FullName))
		}
		args = append(args, "-s", q(shell), "-h", q(home))
		if !b.CreateHome {
			args = append(args, "-H")
		}
		if b.PrimaryGroup != "" {
			args = append(args, "-G", q(b.PrimaryGroup))
		}
		s = strings.Join(append(args, q(b.Name)), " ") + "\n"
		for _, g := range groups {
			s += "addgroup " + q(b.Name) + " " + q(g) + "\n"
		}
	default:
		return "", noTools()
	}

	if b.Password != "" {
		p, err := passwordScript(o, b.Name, b.Password, b.MustChangePassword)
		if err != nil {
			return "", err
		}
		s += p
	} else if b.MustChangePassword {
		return "", fieldError("body.must_change_password", "Set a password first", nil)
	}
	if key != "" {
		s += authorizedKeyScript(b.Name, key)
	}
	if level != "keep" {
		pg := b.PrimaryGroup
		if pg == "" {
			pg = b.Name
		}
		// A new account: only stale rules naming it and its chosen groups count.
		nu := &users.User{Name: b.Name, UID: -1, PrimaryGroup: pg, Groups: groups}
		sudo, err := sudoScript(o, nu, b.Name, level, level == "none")
		if err != nil {
			return "", err
		}
		s += sudo
	}
	return s, nil
}

func updateUserScript(o *UsersOverview, u *users.User, b UserUpdateBody) (string, error) {
	var flags []string
	busybox := !o.has("usermod")
	name := u.Name

	if b.Name != nil && *b.Name != u.Name {
		if err := protect(o, u, "rename"); err != nil {
			return "", err
		}
		if err := checkName("body.name", *b.Name); err != nil {
			return "", err
		}
		if o.user(*b.Name) != nil {
			return "", fieldError("body.name", *b.Name+" already exists", *b.Name)
		}
		if busybox {
			return "", busyboxCant("body.name", "rename an account")
		}
		name = *b.Name
		flags = append(flags, "-l", q(name))
	}
	if b.FullName != nil && *b.FullName != u.FullName {
		if err := checkFullName("body.full_name", *b.FullName); err != nil {
			return "", err
		}
		flags = append(flags, "-c", q(*b.FullName))
	}
	if b.Shell != nil && *b.Shell != u.Shell {
		if err := checkAbsPath("body.shell", *b.Shell); err != nil {
			return "", err
		}
		if !loginShell(*b.Shell) && (u.UID == 0 || u.Name == o.LoginUser) {
			return "", fieldError("body.shell", u.Name+" needs a login shell", *b.Shell)
		}
		flags = append(flags, "-s", q(*b.Shell))
	}
	if b.Home != nil && *b.Home != u.Home {
		if err := checkAbsPath("body.home", *b.Home); err != nil {
			return "", err
		}
		flags = append(flags, "-d", q(*b.Home))
		if b.MoveHome {
			flags = append(flags, "-m")
		}
	}
	if b.PrimaryGroup != nil && *b.PrimaryGroup != u.PrimaryGroup {
		if o.group(*b.PrimaryGroup) == nil {
			return "", fieldError("body.primary_group", "No group named "+*b.PrimaryGroup, *b.PrimaryGroup)
		}
		flags = append(flags, "-g", q(*b.PrimaryGroup))
	}
	if b.AccountExpires != nil && *b.AccountExpires != u.AccountExpires {
		d := *b.AccountExpires
		if d != "" {
			if _, err := time.Parse("2006-01-02", d); err != nil {
				return "", fieldError("body.account_expires", "Use YYYY-MM-DD", d)
			}
			if err := protect(o, u, "set an expiry date on"); err != nil {
				return "", err
			}
		}
		if busybox {
			return "", busyboxCant("body.account_expires", "set an expiry date")
		}
		flags = append(flags, "-e", q(d))
	}

	// Supplementary groups: the full list replaces the current one.
	groups := u.Groups
	var addGroups, removeGroups []string
	if b.Groups != nil {
		if err := checkGroups(o, "body.groups", *b.Groups); err != nil {
			return "", err
		}
		groups = slices.DeleteFunc(slices.Clone(*b.Groups), func(g string) bool { return g == "" })
		slices.Sort(groups)
		groups = slices.Compact(groups)
		for _, g := range groups {
			if !slices.Contains(u.Groups, g) {
				addGroups = append(addGroups, g)
			}
		}
		for _, g := range u.Groups {
			if !slices.Contains(groups, g) {
				removeGroups = append(removeGroups, g)
				if gr := o.group(g); gr != nil && gr.Sudo && u.Name == o.LoginUser {
					return "", fieldError("body.groups", u.Name+" gets sudo through "+g+", and Morcheh needs that to manage this server", g)
				}
			}
		}
		if len(addGroups)+len(removeGroups) > 0 && !busybox {
			flags = append(flags, "-G", q(strings.Join(groups, ",")))
		}
	}
	if busybox && len(flags) > 0 {
		return "", busyboxCant("body", "change an account's name, shell, home or primary group")
	}

	var s string
	if len(flags) > 0 {
		s = "usermod " + strings.Join(flags, " ") + " " + q(u.Name) + "\n"
	}
	if busybox {
		for _, g := range addGroups {
			s += addMember(o, u.Name, g)
		}
		for _, g := range removeGroups {
			s += removeMember(o, u.Name, g)
		}
	}
	// The personal group follows a rename.
	if name != u.Name && u.PrimaryGroup == u.Name && o.has("groupmod") && o.group(name) == nil {
		if g := o.group(u.Name); g != nil && len(g.Primary) == 1 {
			s += "groupmod -n " + q(name) + " " + q(u.Name) + "\n"
		}
	}

	// Sudo: an explicit level, or the current one carried over a rename.
	level := ""
	if b.Sudo != nil && *b.Sudo != currentSudo(u) {
		if !slices.Contains(sudoLevels, *b.Sudo) {
			return "", fieldError("body.sudo", "One of none, password, nopasswd", *b.Sudo)
		}
		if err := protect(o, u, "change sudo for"); err != nil {
			return "", err
		}
		level = *b.Sudo
	} else if name != u.Name && hasOwnRules(o, u) {
		level = currentSudo(u)
	}
	if level != "" {
		after := *u
		after.Groups = groups
		sudo, err := sudoScript(o, &after, name, level, false)
		if err != nil {
			return "", err
		}
		s += sudo
	}
	return s, nil
}

func currentSudo(u *users.User) string {
	switch {
	case u.Sudo == "full" && u.SudoNoPassword:
		return "nopasswd"
	case u.Sudo == "full":
		return "password"
	}
	return "none"
}

// ownsRule: a rule that names the account itself (not a group).
func ownsRule(r users.Rule, u *users.User) bool {
	return slices.Contains(r.Who, u.Name) || (u.UID >= 0 && slices.Contains(r.Who, "#"+strconv.Itoa(u.UID)))
}

func hasOwnRules(o *UsersOverview, u *users.User) bool {
	return slices.ContainsFunc(o.SudoRules, func(r users.Rule) bool { return r.Active && ownsRule(r, u) })
}

func managedSudoers(name string) string {
	return "/etc/sudoers.d/" + users.ManagedPrefix + strings.ReplaceAll(name, ".", "_")
}

// sudoScript gives u (called name once the change is done) one sudo level:
//   - none: out of every group that grants sudo, no rule of its own
//   - password: in the sudo group, else a rule in sudoers.d/morcheh-<name>
//   - nopasswd: a NOPASSWD rule there, and out of the sudo groups
//
// Its rules in other files are commented out. sudoers changes are checked
// with visudo and put back when the result doesn't parse. lenient (removing
// the account) skips what it can't do instead of failing.
func sudoScript(o *UsersOverview, u *users.User, name, level string, lenient bool) (string, error) {
	var s strings.Builder
	member := func(g string) bool { return u.PrimaryGroup == g || slices.Contains(u.Groups, g) }

	// Group memberships.
	var add, remove []string
	for _, g := range o.Groups {
		if !g.Sudo || !member(g.Name) {
			continue
		}
		if level == "password" && (g.Name == o.SudoGroup || o.SudoGroup == "") {
			continue
		}
		if u.PrimaryGroup == g.Name {
			if level == "none" && !lenient {
				return "", fieldError("body.sudo", g.Name+" is "+u.Name+"'s primary group and gives sudo; pick another primary group first", nil)
			}
			continue
		}
		remove = append(remove, g.Name)
	}
	if level == "password" && o.SudoGroup != "" && !member(o.SudoGroup) {
		add = append(add, o.SudoGroup)
	}
	if !lenient {
		for _, g := range add {
			s.WriteString(addMember(o, name, g))
		}
		for _, g := range remove {
			s.WriteString(removeMember(o, name, g))
		}
	}

	// Rules of its own elsewhere.
	newFile, oldFile := managedSudoers(name), managedSudoers(u.Name)
	type edit struct {
		file   string
		ranges [][2]int
	}
	var edits []edit
	for _, r := range o.SudoRules {
		if !r.Active || r.File == newFile || r.File == oldFile || !ownsRule(r, u) {
			continue
		}
		if len(r.Who) > 1 {
			if lenient {
				continue
			}
			return "", fieldError("body.sudo", fmt.Sprintf("%s line %d gives sudo to %s together with others; change it by hand",
				r.File, r.Line, u.Name), nil)
		}
		i := slices.IndexFunc(edits, func(e edit) bool { return e.file == r.File })
		if i < 0 {
			edits = append(edits, edit{file: r.File})
			i = len(edits) - 1
		}
		edits[i].ranges = append(edits[i].ranges, [2]int{r.Line, r.EndLine})
	}

	rule := ""
	switch {
	case level == "nopasswd":
		rule = name + " ALL=(ALL:ALL) NOPASSWD: ALL"
	case level == "password" && o.SudoGroup == "" && !slices.ContainsFunc(o.Groups, func(g users.Group) bool { return g.Sudo && member(g.Name) }):
		rule = name + " ALL=(ALL:ALL) ALL"
	}
	managed := slices.ContainsFunc(o.SudoRules, func(r users.Rule) bool { return r.File == newFile || r.File == oldFile })
	if len(edits) == 0 && rule == "" && !managed {
		return s.String(), nil
	}

	switch {
	case !o.SudoInstalled:
		if lenient {
			return s.String(), nil
		}
		return "", fieldError("body.sudo", "sudo isn't installed on this server", nil)
	case !o.has("visudo"):
		if lenient {
			return s.String() + "rm -f " + q(oldFile) + " " + q(newFile) + "\n", nil
		}
		return "", fieldError("body.sudo", "This server has no visudo to check a sudoers change with", nil)
	case rule != "" && !o.SudoIncludesDir:
		return "", fieldError("body.sudo", "/etc/sudoers doesn't read /etc/sudoers.d, where the rule would go", nil)
	}

	// Back up every file touched, so a failed check puts them all back.
	var restore, cleanup []string
	for i, e := range edits {
		v := fmt.Sprintf("b%d", i)
		fmt.Fprintf(&s, "%s=$(mktemp %s/.morcheh.bak.XXXXXX) && cp -p %s \"$%s\" || exit 1\n", v, q(path.Dir(e.file)), q(e.file), v)
		restore = append(restore, fmt.Sprintf("mv -f \"$%s\" %s", v, q(e.file)))
		cleanup = append(cleanup, fmt.Sprintf("rm -f \"$%s\"", v))
	}
	managedFiles := []string{newFile}
	if oldFile != newFile {
		managedFiles = append(managedFiles, oldFile)
	}
	for i, f := range managedFiles {
		v := fmt.Sprintf("m%d", i)
		fmt.Fprintf(&s, "%s=''; if [ -f %s ]; then %s=$(mktemp /etc/sudoers.d/.morcheh.bak.XXXXXX) && cp -p %s \"$%s\" || exit 1; fi\n", v, q(f), v, q(f), v)
		restore = append(restore, fmt.Sprintf("if [ -n \"$%s\" ]; then mv -f \"$%s\" %s; else rm -f %s; fi", v, v, q(f), q(f)))
		cleanup = append(cleanup, fmt.Sprintf("[ -z \"$%s\" ] || rm -f \"$%s\"", v, v))
	}
	s.WriteString("restore() {\n  " + strings.Join(restore, "\n  ") + "\n}\n")

	for _, e := range edits {
		var exprs []string
		for _, r := range e.ranges {
			exprs = append(exprs, fmt.Sprintf("-e '%d,%ds/^/# (disabled by Morcheh) /'", r[0], r[1]))
		}
		fmt.Fprintf(&s, "sed -i %s %s || { restore; exit 1; }\n", strings.Join(exprs, " "), q(e.file))
	}
	s.WriteString("rm -f " + q(oldFile) + " " + q(newFile) + "\n")
	if rule != "" {
		// sudo skips names with a dot, so the temp file is ignored until
		// it's checked and moved in place.
		s.WriteString("t=$(mktemp /etc/sudoers.d/.morcheh.XXXXXX) || { restore; exit 1; }\n" +
			"printf '%s\\n' " + q("# Added by Morcheh") + " " + q(rule) + " > \"$t\" && chmod 440 \"$t\" || { rm -f \"$t\"; restore; exit 1; }\n" +
			"if ! out=$(visudo -cf \"$t\" 2>&1); then rm -f \"$t\"; restore; printf '%s\\n' \"$out\" >&2; exit 1; fi\n" +
			"mv -f \"$t\" " + q(newFile) + " || { restore; exit 1; }\n")
	}
	s.WriteString("if ! out=$(visudo -c 2>&1); then restore; printf 'sudoers no longer parsed, so it was put back:\\n%s\\n' \"$out\" >&2; exit 1; fi\n")
	s.WriteString(strings.Join(cleanup, "\n") + "\n")
	return s.String(), nil
}

func createGroupScript(o *UsersOverview, b GroupCreateBody) (string, error) {
	if err := checkName("body.name", b.Name); err != nil {
		return "", err
	}
	if o.group(b.Name) != nil {
		return "", fieldError("body.name", b.Name+" already exists", b.Name)
	}
	if b.GID != nil {
		for _, g := range o.Groups {
			if g.GID == *b.GID {
				return "", fieldError("body.gid", fmt.Sprintf("%s already has gid %d", g.Name, *b.GID), *b.GID)
			}
		}
	}
	for i, m := range b.Members {
		if o.user(m) == nil {
			return "", fieldError(fmt.Sprintf("body.members[%d]", i), "No account named "+m, m)
		}
	}
	var s string
	switch {
	case o.has("groupadd"):
		s = "groupadd"
		if b.System {
			s += " -r"
		}
		if b.GID != nil {
			s += " -g " + strconv.Itoa(*b.GID)
		}
		s += " " + q(b.Name) + "\n"
		if len(b.Members) > 0 && o.has("gpasswd") {
			s += "gpasswd -M " + q(strings.Join(b.Members, ",")) + " " + q(b.Name) + "\n"
			return s, nil
		}
	case o.has("addgroup"):
		s = "addgroup"
		if b.System {
			s += " -S"
		}
		if b.GID != nil {
			s += " -g " + strconv.Itoa(*b.GID)
		}
		s += " " + q(b.Name) + "\n"
	default:
		return "", noTools()
	}
	for _, m := range b.Members {
		s += addMember(o, m, b.Name)
	}
	return s, nil
}

func updateGroupScript(o *UsersOverview, g *users.Group, b GroupUpdateBody) (string, error) {
	var s string
	if b.Members != nil {
		members := slices.DeleteFunc(slices.Clone(*b.Members), func(m string) bool { return m == "" })
		slices.Sort(members)
		members = slices.Compact(members)
		for i, m := range members {
			if o.user(m) == nil {
				return "", fieldError(fmt.Sprintf("body.members[%d]", i), "No account named "+m, m)
			}
		}
		if g.Sudo && slices.Contains(g.Members, o.LoginUser) && !slices.Contains(members, o.LoginUser) {
			return "", fieldError("body.members", o.LoginUser+" gets sudo through "+g.Name+", and Morcheh needs that to manage this server", nil)
		}
		changed := len(members) != len(g.Members) || slices.ContainsFunc(members, func(m string) bool { return !slices.Contains(g.Members, m) })
		switch {
		case !changed:
		case o.has("gpasswd"):
			s += "gpasswd -M " + q(strings.Join(members, ",")) + " " + q(g.Name) + "\n"
		default:
			for _, m := range members {
				if !slices.Contains(g.Members, m) {
					s += addMember(o, m, g.Name)
				}
			}
			for _, m := range g.Members {
				if !slices.Contains(members, m) {
					s += removeMember(o, m, g.Name)
				}
			}
		}
	}
	if b.Name != nil && *b.Name != g.Name {
		if err := checkName("body.name", *b.Name); err != nil {
			return "", err
		}
		if o.group(*b.Name) != nil {
			return "", fieldError("body.name", *b.Name+" already exists", *b.Name)
		}
		if g.Sudo {
			return "", fieldError("body.name", "sudoers gives sudo to %"+g.Name+" by name, so renaming it would take sudo away from its members", nil)
		}
		if !o.has("groupmod") {
			return "", busyboxCant("body.name", "rename a group")
		}
		s += "groupmod -n " + q(*b.Name) + " " + q(g.Name) + "\n"
	}
	return s, nil
}
