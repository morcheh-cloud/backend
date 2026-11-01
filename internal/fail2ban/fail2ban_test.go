package fail2ban

import (
	"slices"
	"testing"
)

const sample = `# local overrides
[DEFAULT]
bantime  = 1h ; an hour
ignoreip = 127.0.0.1/8
           10.0.0.0/8

[sshd]
# keep ssh safe
enabled = true
port: ssh

[nginx-http-auth]
enabled = false
`

func TestParseValues(t *testing.T) {
	d := Parse(sample)
	if got := d.Sections(); !slices.Equal(got, []string{"DEFAULT", "sshd", "nginx-http-auth"}) {
		t.Fatalf("sections = %v", got)
	}
	def := d.Values("DEFAULT")
	if def["bantime"] != "1h" {
		t.Errorf("bantime = %q", def["bantime"])
	}
	if def["ignoreip"] != "127.0.0.1/8\n10.0.0.0/8" {
		t.Errorf("ignoreip = %q", def["ignoreip"])
	}
	if v := d.Values("sshd")["port"]; v != "ssh" {
		t.Errorf("port = %q", v)
	}
}

func TestEdit(t *testing.T) {
	d := Parse(sample)
	d.Set("DEFAULT", "ignoreip", "127.0.0.1/8 ::1")
	d.Set("sshd", "maxretry", "3")
	d.Set("recidive", "enabled", "true")
	d.Unset("sshd", "port")
	d.RemoveSection("nginx-http-auth")
	want := `# local overrides
[DEFAULT]
bantime  = 1h ; an hour
ignoreip = 127.0.0.1/8 ::1

[sshd]
# keep ssh safe
enabled = true
maxretry = 3

[recidive]
enabled = true
`
	if got := d.String(); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestMultilineSet(t *testing.T) {
	d := Parse("")
	d.Set("sshd", "logpath", "/var/log/a.log\n/var/log/b.log")
	if got := d.String(); got != "[sshd]\nlogpath = /var/log/a.log\n          /var/log/b.log\n" {
		t.Fatalf("got %q", got)
	}
	if v := Parse(d.String()).Values("sshd")["logpath"]; v != "/var/log/a.log\n/var/log/b.log" {
		t.Fatalf("round trip = %q", v)
	}
}

func TestDefaultFirst(t *testing.T) {
	d := Parse("# mine\n[sshd]\nenabled = true\n")
	d.Set("DEFAULT", "bantime", "1h")
	if got := d.String(); got != "# mine\n[DEFAULT]\nbantime = 1h\n\n[sshd]\nenabled = true\n" {
		t.Fatalf("got %q", got)
	}
}

func TestMerge(t *testing.T) {
	m := Merge([]Layer{
		{Path: "jail.conf", Doc: Parse("[DEFAULT]\nbantime = 10m\n[sshd]\nport = ssh\n")},
		{Path: "jail.local", Doc: Parse("[DEFAULT]\nbantime = 1h\n")},
	})
	if s := m.Sections["DEFAULT"]["bantime"]; s.Value != "1h" || s.Path != "jail.local" {
		t.Fatalf("bantime = %+v", s)
	}
	if !slices.Equal(m.Order, []string{"DEFAULT", "sshd"}) {
		t.Fatalf("order = %v", m.Order)
	}
}

func TestParseStatus(t *testing.T) {
	out := "Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t2\n|  |- Total failed:\t9\n|  `- File list:\t/var/log/auth.log\n`- Actions\n   |- Currently banned:\t1\n   |- Total banned:\t3\n   `- Banned IP list:\t192.0.2.1\n"
	s := ParseStatus(out)
	if s.CurrentlyFailed != 2 || s.TotalFailed != 9 || s.CurrentlyBanned != 1 || s.TotalBanned != 3 {
		t.Fatalf("counts = %+v", s)
	}
	if !slices.Equal(s.Files, []string{"/var/log/auth.log"}) || !slices.Equal(s.BannedIPs, []string{"192.0.2.1"}) {
		t.Fatalf("lists = %+v", s)
	}
	if got := ParseJailList("Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, recidive\n"); !slices.Equal(got, []string{"sshd", "recidive"}) {
		t.Fatalf("jails = %v", got)
	}
}

func TestParseBansAndEvents(t *testing.T) {
	bans := ParseBans("192.0.2.1 \t2026-11-01 10:00:00 + 600 = 2026-11-01 10:10:00\n")
	if len(bans) != 1 || bans[0].Seconds != 600 || bans[0].Until != "2026-11-01 10:10:00" {
		t.Fatalf("bans = %+v", bans)
	}
	ev := ParseEvents([]string{
		"2026-11-01 10:00:00,123 fail2ban.filter  [812]: INFO    [sshd] Found 192.0.2.1 - 2026-11-01 10:00:00",
		"2026-11-01 10:00:01,001 fail2ban.actions [812]: NOTICE  [sshd] Restore Ban 192.0.2.9",
		"2026-11-01 10:00:02,001 fail2ban.server  [812]: INFO    Reload finished.",
		"2026-11-01T10:00:03+0000 web fail2ban-server[812]: NOTICE  [sshd] Ban 192.0.2.1",
	})
	if len(ev) != 3 || ev[2].Time != "2026-11-01 10:00:03" || ev[2].Action != "ban" || ev[0].Action != "found" || ev[1].Action != "restore" || ev[1].IP != "192.0.2.9" {
		t.Fatalf("events = %+v", ev)
	}
}
