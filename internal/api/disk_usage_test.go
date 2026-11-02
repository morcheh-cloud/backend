package api

import "testing"

func TestParseUsage(t *testing.T) {
	out := "@df /dev/sda1 1000 600 400 60% /\n" +
		"@mounts\n" +
		"/dev/sda1 / ext4 rw 0 0\n" +
		"/dev/sdb1 /srv/my\\040data xfs rw 0 0\n" +
		"@du\n" +
		"300\t/srv/logs\n" +
		"du: cannot read directory '/srv/private': Permission denied\n" +
		"4\t/srv/private\n" +
		"20\t/srv/a.txt\n" +
		"324\t/srv\n"
	u := parseUsage("/srv", out, nil)

	if u.Size != 324*1024 {
		t.Errorf("size = %d", u.Size)
	}
	if u.Unreadable != 1 {
		t.Errorf("unreadable = %d", u.Unreadable)
	}
	if len(u.Entries) != 3 || u.Entries[0].Name != "logs" || u.Entries[2].Name != "private" {
		t.Fatalf("entries = %+v", u.Entries)
	}
	if u.Disk == nil || u.Disk.Mount != "/" || u.Disk.Type != "ext4" || u.Disk.Used != 600*1024 {
		t.Errorf("disk = %+v", u.Disk)
	}
	if got := unescapeMount(`/srv/my\040data`); got != "/srv/my data" {
		t.Errorf("unescape = %q", got)
	}
}
