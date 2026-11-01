// Package users reads a server's accounts: /etc/passwd, /etc/group,
// /etc/shadow, sudoers, and login records. It only parses text; the api
// package runs the commands.
package users

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type User struct {
	Name         string   `json:"name" example:"deploy"`
	UID          int      `json:"uid" example:"1000"`
	GID          int      `json:"gid" example:"1000"`
	PrimaryGroup string   `json:"primary_group" example:"deploy"`
	Groups       []string `json:"groups" doc:"Supplementary groups" example:"[\"docker\",\"sudo\"]"`
	FullName     string   `json:"full_name" doc:"The first GECOS field" example:"Deploy bot"`
	Home         string   `json:"home" example:"/home/deploy"`
	HomeExists   bool     `json:"home_exists"`
	Shell        string   `json:"shell" example:"/bin/bash"`
	CanLogin     bool     `json:"can_login" doc:"Has a real shell (not nologin or false)"`
	System       bool     `json:"system" doc:"A service account: uid below UID_MIN, or nobody. root is not one"`

	Password string `json:"password" enum:"set,empty,unset,unknown" doc:"set: has a password; empty: logs in WITHOUT one; unset: can't log in with a password; unknown: /etc/shadow unreadable"`
	Locked   bool   `json:"locked" doc:"Locked: the password has a ! in front (it comes back on unlock), or the account expired on 1970-01-02, which also stops key logins"`
	Expired  bool   `json:"expired" doc:"The account's expiry date has passed, so it can't log in at all (keys included)"`

	AccountExpires     string `json:"account_expires,omitempty" doc:"YYYY-MM-DD, when the account stops working" example:"2027-01-31"`
	PasswordChanged    string `json:"password_changed,omitempty" doc:"YYYY-MM-DD" example:"2026-10-02"`
	MustChangePassword bool   `json:"must_change_password" doc:"Has to pick a new password at the next login"`
	PasswordExpires    string `json:"password_expires,omitempty" doc:"YYYY-MM-DD, when the password has to be changed (from the max age)"`

	Sudo           string   `json:"sudo" enum:"none,full,limited" doc:"full: any command as root; limited: only some commands"`
	SudoNoPassword bool     `json:"sudo_nopasswd" doc:"sudo doesn't ask for a password"`
	SudoVia        []string `json:"sudo_via" doc:"What grants it: group:<name> or a sudoers file" example:"[\"group:sudo\"]"`

	LastLogin *Login `json:"last_login,omitempty"`
	Sessions  int    `json:"sessions" doc:"Logged in right now"`
	SSHKeys   int    `json:"ssh_keys" doc:"Keys in ~/.ssh/authorized_keys; -1 when it can't be read"`
}

type Login struct {
	Time time.Time `json:"time"`
	From string    `json:"from" doc:"Address, or empty for a local login" example:"203.0.113.7"`
	TTY  string    `json:"tty" example:"pts/0"`
}

type Group struct {
	Name    string   `json:"name" example:"docker"`
	GID     int      `json:"gid" example:"998"`
	Members []string `json:"members" doc:"Users listed in /etc/group"`
	Primary []string `json:"primary" doc:"Users whose primary group it is (members too, though /etc/group doesn't list them)"`
	System  bool     `json:"system" doc:"gid below UID_MIN"`
	Sudo    bool     `json:"sudo" doc:"Its members get sudo for every command"`
}

type Rule struct {
	File       string   `json:"file" example:"/etc/sudoers.d/deploy"`
	Line       int      `json:"line" doc:"1-based first line"`
	EndLine    int      `json:"end_line" doc:"Last line (rules can continue with a backslash)"`
	Text       string   `json:"text" example:"deploy ALL=(ALL:ALL) NOPASSWD: ALL"`
	Who        []string `json:"who" doc:"User names, %group, %#gid, #uid or ALL" example:"[\"deploy\"]"`
	Full       bool     `json:"full" doc:"Grants every command"`
	NoPassword bool     `json:"nopasswd"`
	Active     bool     `json:"active" doc:"false for files sudo skips (a . or ~ in the name)"`
	Managed    bool     `json:"managed" doc:"Written by Morcheh (sudoers.d/morcheh-*)"`
}

type Session struct {
	User  string `json:"user" example:"deploy"`
	TTY   string `json:"tty" example:"pts/0"`
	From  string `json:"from" example:"203.0.113.7"`
	Since string `json:"since" doc:"As who printed it, in the server's time" example:"2026-11-01 09:12"`
}

// Input is what the collect script read.
type Input struct {
	Now      time.Time
	Passwd   string
	Group    string
	Shadow   string
	HasShadow bool
	UIDMin   int
	Sudoers  []File // /etc/sudoers first
	Who      string
	Lastlog  string
	Last     string
	Homes    map[string]int // user → authorized key count (-1 unreadable), for homes that exist
}

type File struct {
	Path    string
	Content string
}

type Result struct {
	Users     []User
	Groups    []Group
	Rules     []Rule
	Sessions  []Session
	SudoGroup string // a group whose %rule grants every command
}

// SudoGroups are the conventional groups that grant sudo.
var SudoGroups = []string{"sudo", "wheel", "admin"}

const ManagedPrefix = "morcheh-"

// LockDay is the account expiry (days since 1970) a full lock sets.
const LockDay = 1

func Build(in Input) Result {
	if in.UIDMin <= 0 {
		in.UIDMin = 1000
	}
	var r Result
	r.Groups = parseGroups(in.Group, in.UIDMin)
	byGID := map[int]*Group{}
	byName := map[string]*Group{}
	for i := range r.Groups {
		g := &r.Groups[i]
		if _, ok := byGID[g.GID]; !ok {
			byGID[g.GID] = g
		}
		byName[g.Name] = g
	}

	for _, f := range in.Sudoers {
		r.Rules = append(r.Rules, ParseSudoers(f.Path, f.Content)...)
	}
	if r.Rules == nil {
		r.Rules = []Rule{}
	}
	for _, rule := range r.Rules {
		if !rule.Active || !rule.Full {
			continue
		}
		for _, w := range rule.Who {
			if g, ok := byName[strings.TrimPrefix(w, "%")]; ok && strings.HasPrefix(w, "%") {
				g.Sudo = true
			}
			if gid, ok := strings.CutPrefix(w, "%#"); ok {
				if n, err := strconv.Atoi(gid); err == nil && byGID[n] != nil {
					byGID[n].Sudo = true
				}
			}
		}
	}
	for _, name := range SudoGroups {
		if g, ok := byName[name]; ok && g.Sudo {
			r.SudoGroup = name
			break
		}
	}

	shadow := parseShadow(in.Shadow)
	sessions := parseWho(in.Who)
	r.Sessions = sessions
	logins := parseLastlog(in.Lastlog)
	for u, l := range parseLast(in.Last) {
		if cur, ok := logins[u]; !ok || l.Time.After(cur.Time) {
			logins[u] = l
		}
	}
	today := int(in.Now.Unix() / 86400)

	for _, line := range strings.Split(in.Passwd, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), ":")
		if len(f) < 7 || f[0] == "" || strings.HasPrefix(f[0], "+") || strings.HasPrefix(f[0], "-") {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		u := User{
			Name: f[0], UID: uid, GID: gid,
			FullName: strings.TrimSpace(strings.SplitN(f[4], ",", 2)[0]),
			Home:     f[5], Shell: f[6],
			Groups: []string{}, SudoVia: []string{}, Sudo: "none",
		}
		if g := byGID[gid]; g != nil {
			u.PrimaryGroup = g.Name
			g.Primary = append(g.Primary, u.Name)
		}
		u.CanLogin = loginShell(u.Shell)
		u.System = uid != 0 && (uid < in.UIDMin || uid >= 65534)
		if n, ok := in.Homes[u.Name]; ok {
			u.HomeExists = true
			u.SSHKeys = n
		}

		pw := f[1]
		if s, ok := shadow[u.Name]; ok {
			pw = s.hash
			if s.lastChange != nil {
				if *s.lastChange == 0 {
					u.MustChangePassword = true
				} else {
					u.PasswordChanged = day(*s.lastChange)
					if s.maxDays != nil && *s.maxDays > 0 && *s.maxDays < 99999 {
						u.PasswordExpires = day(*s.lastChange + *s.maxDays)
					}
				}
			}
			if s.expire != nil {
				u.AccountExpires = day(*s.expire)
				u.Expired = *s.expire <= today
				// Day 1 is how a lock also stops key logins (usermod -L -e 1).
				if *s.expire == LockDay {
					u.Locked, u.Expired = true, false
				}
			}
		} else if pw == "x" && !in.HasShadow {
			pw = ""
			u.Password = "unknown"
		}
		if u.Password == "" {
			var locked bool
			u.Password, locked = passwordState(pw)
			u.Locked = u.Locked || locked
		}

		if l, ok := logins[u.Name]; ok {
			u.LastLogin = &l
		}
		for _, s := range sessions {
			if s.User == u.Name {
				u.Sessions++
			}
		}
		r.Users = append(r.Users, u)
	}

	// Supplementary groups, in /etc/group order.
	index := map[string]int{}
	for i, u := range r.Users {
		index[u.Name] = i
	}
	for _, g := range r.Groups {
		for _, m := range g.Members {
			if i, ok := index[m]; ok && !slices.Contains(r.Users[i].Groups, g.Name) && r.Users[i].PrimaryGroup != g.Name {
				r.Users[i].Groups = append(r.Users[i].Groups, g.Name)
			}
		}
	}

	readable := len(in.Sudoers) > 0
	for i := range r.Users {
		u := &r.Users[i]
		if readable {
			applySudo(u, r.Rules, byName, byGID)
		} else {
			// Without sudoers, the usual groups are the best guess.
			for _, g := range SudoGroups {
				if u.PrimaryGroup == g || slices.Contains(u.Groups, g) {
					u.Sudo = "full"
					u.SudoVia = append(u.SudoVia, "group:"+g)
				}
			}
		}
	}
	if r.Users == nil {
		r.Users = []User{}
	}
	if r.Sessions == nil {
		r.Sessions = []Session{}
	}
	return r
}

func applySudo(u *User, rules []Rule, byName map[string]*Group, byGID map[int]*Group) {
	member := func(g string) bool { return u.PrimaryGroup == g || slices.Contains(u.Groups, g) }
	for _, rule := range rules {
		if !rule.Active {
			continue
		}
		via := ""
		for _, w := range rule.Who {
			switch {
			case w == "ALL" || w == u.Name || w == "#"+strconv.Itoa(u.UID):
				via = rule.File
			case strings.HasPrefix(w, "%#"):
				n, err := strconv.Atoi(w[2:])
				if g := byGID[n]; err == nil && g != nil && member(g.Name) {
					via = "group:" + g.Name
				}
			case strings.HasPrefix(w, "%"):
				if member(w[1:]) && byName[w[1:]] != nil {
					via = "group:" + w[1:]
				}
			}
			if via != "" {
				break
			}
		}
		if via == "" {
			continue
		}
		if !slices.Contains(u.SudoVia, via) {
			u.SudoVia = append(u.SudoVia, via)
		}
		switch {
		case rule.Full:
			u.Sudo = "full"
		case u.Sudo == "none":
			u.Sudo = "limited"
		}
		if rule.NoPassword {
			u.SudoNoPassword = true
		}
	}
}

func day(days int) string {
	return time.Unix(int64(days)*86400, 0).UTC().Format("2006-01-02")
}

func loginShell(sh string) bool {
	base := sh[strings.LastIndex(sh, "/")+1:]
	return sh != "" && base != "nologin" && base != "false" && base != "sync" && base != "halt" && base != "shutdown"
}

// passwordState reads a shadow (or passwd) hash field.
func passwordState(pw string) (state string, locked bool) {
	if pw == "" {
		return "empty", false
	}
	rest := strings.TrimLeft(pw, "!")
	locked = rest != pw
	if rest == "" || strings.HasPrefix(rest, "*") || rest == "x" {
		return "unset", false
	}
	return "set", locked
}

func parseGroups(text string, uidMin int) []Group {
	out := []Group{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), ":")
		if len(f) < 4 || f[0] == "" || strings.HasPrefix(f[0], "+") || strings.HasPrefix(f[0], "-") {
			continue
		}
		gid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		g := Group{Name: f[0], GID: gid, Members: []string{}, Primary: []string{}, System: gid < uidMin || gid >= 65534}
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" && !slices.Contains(g.Members, m) {
				g.Members = append(g.Members, m)
			}
		}
		out = append(out, g)
	}
	return out
}

type shadowEntry struct {
	hash       string
	lastChange *int
	maxDays    *int
	expire     *int
}

func parseShadow(text string) map[string]shadowEntry {
	out := map[string]shadowEntry{}
	num := func(s string) *int {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
			return &n
		}
		return nil
	}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), ":")
		if len(f) < 2 || f[0] == "" {
			continue
		}
		e := shadowEntry{hash: f[1]}
		if len(f) > 2 {
			e.lastChange = num(f[2])
		}
		if len(f) > 4 {
			e.maxDays = num(f[4])
		}
		if len(f) > 7 {
			e.expire = num(f[7])
		}
		out[f[0]] = e
	}
	return out
}

var (
	includeRe = regexp.MustCompile(`^[#@]include(dir)?\s`)
	aliasRe   = regexp.MustCompile(`^(User|Runas|Host|Cmnd|Cmd)_Alias\s`)
	fullRe    = regexp.MustCompile(`(^|[:=,)\s])ALL\s*$`)
	uidRe     = regexp.MustCompile(`^ #\d`)
)

// ParseSudoers lists the user specifications (rules) of one sudoers file.
// Defaults, aliases and include lines are skipped.
func ParseSudoers(path, content string) []Rule {
	base := path[strings.LastIndex(path, "/")+1:]
	active := path == "/etc/sudoers" || !(strings.Contains(base, ".") || strings.HasSuffix(base, "~"))
	var out []Rule
	lines := strings.Split(content, "\n")
	for i := 0; i < len(lines); i++ {
		start := i
		text := strings.TrimSpace(lines[i])
		for strings.HasSuffix(text, "\\") && i+1 < len(lines) {
			i++
			text = strings.TrimSuffix(text, "\\") + " " + strings.TrimSpace(lines[i])
		}
		if text == "" || includeRe.MatchString(text) || strings.HasPrefix(text, "#") ||
			strings.HasPrefix(text, "Defaults") || aliasRe.MatchString(text) {
			continue
		}
		// Drop a trailing comment (sudoers comments start at an unescaped #
		// that isn't #uid).
		if j := strings.Index(text, " #"); j > 0 && !uidRe.MatchString(text[j:]) {
			text = strings.TrimSpace(text[:j])
		}
		who, _, ok := strings.Cut(text, " ")
		if !ok || !strings.Contains(text, "=") {
			continue
		}
		var names []string
		for _, w := range strings.Split(who, ",") {
			if w = strings.TrimSpace(w); w != "" {
				names = append(names, w)
			}
		}
		out = append(out, Rule{
			File: path, Line: start + 1, EndLine: i + 1, Text: text, Who: names,
			Full:       fullRe.MatchString(text),
			NoPassword: strings.Contains(text, "NOPASSWD:"),
			Active:     active,
			Managed:    strings.HasPrefix(base, ManagedPrefix),
		})
	}
	return out
}

// IncludesDir reports whether /etc/sudoers reads /etc/sudoers.d.
func IncludesDir(sudoers string) bool {
	for _, l := range strings.Split(sudoers, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && (f[0] == "#includedir" || f[0] == "@includedir") && strings.TrimSuffix(f[1], "/") == "/etc/sudoers.d" {
			return true
		}
	}
	return false
}

var whoDateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

func parseWho(text string) []Session {
	var out []Session
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] == "USER" {
			continue
		}
		s := Session{User: f[0], TTY: f[1]}
		if i, j := strings.LastIndex(line, "("), strings.LastIndex(line, ")"); i >= 0 && j > i {
			s.From = line[i+1 : j]
		}
		if len(f) >= 4 && whoDateRe.MatchString(f[2]) {
			s.Since = f[2] + " " + f[3]
		}
		out = append(out, s)
	}
	return out
}

// lastlog and lastlog2: "user port [from] Sun Nov  1 10:00:00 +0000 2026".
func parseLastlog(text string) map[string]Login {
	out := map[string]Login{}
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "**Never logged in**") || strings.HasPrefix(line, "Username") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 7 {
			continue
		}
		t, err := time.Parse("Mon Jan 2 15:04:05 -0700 2006", strings.Join(f[len(f)-6:], " "))
		if err != nil {
			continue
		}
		l := Login{Time: t.UTC()}
		mid := f[1 : len(f)-6]
		switch len(mid) {
		case 1:
			if strings.Contains(mid[0], "/") || strings.HasPrefix(mid[0], "tty") || strings.HasPrefix(mid[0], "ssh") {
				l.TTY = mid[0]
			} else {
				l.From = mid[0]
			}
		case 2:
			l.TTY, l.From = mid[0], mid[1]
		}
		out[f[0]] = l
	}
	return out
}

// last -w --time-format iso, newest first: the first line per user counts.
func parseLast(text string) map[string]Login {
	out := map[string]Login{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] == "reboot" || f[0] == "shutdown" || f[0] == "wtmp" || f[0] == "btmp" {
			continue
		}
		if _, ok := out[f[0]]; ok {
			continue
		}
		for i := 1; i < len(f) && i <= 3; i++ {
			t, err := time.Parse(time.RFC3339, f[i])
			if err != nil {
				continue
			}
			l := Login{Time: t.UTC()}
			if i > 1 {
				l.TTY = f[1]
			}
			if i > 2 && f[2] != "0.0.0.0" && f[2] != ":0" {
				l.From = f[2]
			}
			out[f[0]] = l
			break
		}
	}
	return out
}
