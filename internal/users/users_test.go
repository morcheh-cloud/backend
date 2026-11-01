package users

import (
	"slices"
	"testing"
	"time"
)

const passwd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice Doe,,,:/home/alice:/bin/bash
bob:x:1001:1001::/home/bob:/bin/sh
deploy:x:1002:1002:Deploy bot:/srv/deploy:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
`

const group = `root:x:0:
sudo:x:27:alice
docker:x:998:alice,deploy
alice:x:1000:
bob:x:1001:
deploy:x:1002:
ops:x:1003:bob
nogroup:x:65534:
`

const shadow = `root:!:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
alice:$6$abc$hash:20000:0:90:7:::
bob:!$6$abc$hash:0:0:99999:7::20300:
deploy::20000:0:99999:7::1:
`

const sudoers = `Defaults env_reset
Cmnd_Alias RESTART = /bin/systemctl restart nginx
root ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL # admins
@includedir /etc/sudoers.d
`

func build(t *testing.T) Result {
	t.Helper()
	return Build(Input{
		Now:    time.Date(2025, 8, 1, 0, 0, 0, 0, time.UTC), // day 20301
		Passwd: passwd, Group: group, Shadow: shadow, HasShadow: true, UIDMin: 1000,
		Sudoers: []File{
			{"/etc/sudoers", sudoers},
			{"/etc/sudoers.d/deploy", "deploy ALL=(ALL) NOPASSWD: ALL\n"},
			{"/etc/sudoers.d/ops", "%ops ALL=(root) NOPASSWD: /bin/systemctl restart \\\n  nginx\n"},
			{"/etc/sudoers.d/old.bak", "bob ALL=(ALL) ALL\n"},
		},
		Who:     "alice    pts/0        2025-08-01 09:12 (203.0.113.7)\nalice    pts/1        2025-08-01 09:30 (203.0.113.7)\n",
		Lastlog: "deploy           ssh      198.51.100.2     Thu Jul 31 10:00:00 +0000 2025\nbob                                         **Never logged in**\n",
		Last:    "alice    pts/0        203.0.113.7      2025-08-01T09:12:00+00:00   still logged in\nreboot   system boot  6.1.0            2025-07-30T08:00:00+00:00   still running\n",
		Homes:   map[string]int{"root": 1, "alice": 2, "deploy": -1},
	})
}

func user(t *testing.T, r Result, name string) User {
	t.Helper()
	i := slices.IndexFunc(r.Users, func(u User) bool { return u.Name == name })
	if i < 0 {
		t.Fatalf("no user %s", name)
	}
	return r.Users[i]
}

func TestBuildUsers(t *testing.T) {
	r := build(t)
	if len(r.Users) != 6 {
		t.Fatalf("users = %d", len(r.Users))
	}
	if r.SudoGroup != "sudo" {
		t.Errorf("sudo group = %q", r.SudoGroup)
	}

	root := user(t, r, "root")
	if root.System || root.Password != "unset" || root.Locked || root.Sudo != "full" || root.SSHKeys != 1 {
		t.Errorf("root = %+v", root)
	}
	if d := user(t, r, "daemon"); !d.System || d.CanLogin || d.Password != "unset" {
		t.Errorf("daemon = %+v", d)
	}
	if n := user(t, r, "nobody"); !n.System {
		t.Errorf("nobody isn't system")
	}

	a := user(t, r, "alice")
	if a.FullName != "Alice Doe" || a.PrimaryGroup != "alice" || !slices.Equal(a.Groups, []string{"sudo", "docker"}) {
		t.Errorf("alice groups = %+v", a)
	}
	if a.Password != "set" || a.Sudo != "full" || a.SudoNoPassword || !slices.Equal(a.SudoVia, []string{"group:sudo"}) {
		t.Errorf("alice sudo = %+v", a)
	}
	if a.Sessions != 2 || a.LastLogin == nil || a.LastLogin.From != "203.0.113.7" || a.LastLogin.TTY != "pts/0" {
		t.Errorf("alice activity = %+v %+v", a, a.LastLogin)
	}
	if a.PasswordChanged != "2024-10-04" || a.PasswordExpires != "2025-01-02" || !a.HomeExists || a.SSHKeys != 2 {
		t.Errorf("alice dates = %+v", a)
	}

	b := user(t, r, "bob")
	if !b.Locked || b.Password != "set" || !b.MustChangePassword || b.AccountExpires != "2025-07-31" || !b.Expired {
		t.Errorf("bob state = %+v", b)
	}
	// The .bak file is skipped by sudo, so only %ops counts.
	if b.Sudo != "limited" || !b.SudoNoPassword || b.LastLogin != nil || b.HomeExists {
		t.Errorf("bob sudo = %+v", b)
	}

	d := user(t, r, "deploy")
	if d.Password != "empty" || !d.Locked || d.Expired || d.Sudo != "full" || !d.SudoNoPassword || d.SSHKeys != -1 {
		t.Errorf("deploy = %+v", d)
	}
	if d.LastLogin == nil || d.LastLogin.From != "198.51.100.2" || d.LastLogin.TTY != "ssh" {
		t.Errorf("deploy login = %+v", d.LastLogin)
	}
}

func TestBuildGroups(t *testing.T) {
	r := build(t)
	gi := slices.IndexFunc(r.Groups, func(g Group) bool { return g.Name == "sudo" })
	if g := r.Groups[gi]; !g.Sudo || !g.System {
		t.Errorf("sudo group = %+v", g)
	}
	gi = slices.IndexFunc(r.Groups, func(g Group) bool { return g.Name == "alice" })
	if g := r.Groups[gi]; g.System || !slices.Equal(g.Primary, []string{"alice"}) {
		t.Errorf("alice group = %+v", g)
	}
	gi = slices.IndexFunc(r.Groups, func(g Group) bool { return g.Name == "ops" })
	if g := r.Groups[gi]; g.Sudo {
		t.Errorf("ops only has a limited rule: %+v", g)
	}
}

func TestParseSudoers(t *testing.T) {
	rules := ParseSudoers("/etc/sudoers.d/ops", "# c\n%ops,bob ALL=(root) NOPASSWD: /bin/a \\\n  /bin/b\nalice ALL=(ALL:ALL) ALL\n")
	if len(rules) != 2 {
		t.Fatalf("rules = %+v", rules)
	}
	if r := rules[0]; r.Line != 2 || r.EndLine != 3 || r.Full || !r.NoPassword || !slices.Equal(r.Who, []string{"%ops", "bob"}) {
		t.Errorf("rule 0 = %+v", r)
	}
	if r := rules[1]; r.Line != 4 || !r.Full || !r.Active || r.Managed {
		t.Errorf("rule 1 = %+v", r)
	}
	if r := ParseSudoers("/etc/sudoers.d/morcheh-x", "x ALL=(ALL) ALL"); !r[0].Managed {
		t.Errorf("not managed")
	}
	if !IncludesDir(sudoers) || IncludesDir("root ALL=(ALL) ALL") {
		t.Errorf("IncludesDir")
	}
}

func TestNoSudoers(t *testing.T) {
	r := Build(Input{Now: time.Now(), Passwd: passwd, Group: group})
	if a := user(t, r, "alice"); a.Sudo != "full" || a.Password != "unknown" {
		t.Errorf("alice = %+v", a)
	}
}
