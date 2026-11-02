package api

import (
	"testing"
	"time"
)

func TestParsePower(t *testing.T) {
	o := parsePower(`now 1761990000
btime 1761900000
init systemd
kernel 6.8.0-45-generic
sessions       2
sched USEC=1761990300000000
sched WARN_WALL=1
sched MODE=reboot
sched WALL_MESSAGE=Kernel update
required packages
pkg linux-image-6.8.0-47-generic
pkg libc6
required kernel
`)
	if o.UptimeSeconds != 90000 || o.Sessions != 2 || !o.CanSchedule || o.Kernel != "6.8.0-45-generic" {
		t.Fatalf("basics: %+v", o)
	}
	if !o.RebootRequired || len(o.RebootReasons) != 2 || len(o.RebootPackages) != 2 {
		t.Fatalf("reboot required: %+v", o)
	}
	s := o.Scheduled
	if s == nil || s.Action != "reboot" || s.Message != "Kernel update" || !s.At.Equal(time.Unix(1761990300, 0)) {
		t.Fatalf("schedule: %+v", s)
	}

	o = parsePower("now 10\nbtime 5\ninit none\ncontainer\nsessions 0\n")
	if o.CanSchedule || !o.Container || o.Scheduled != nil || o.RebootRequired {
		t.Fatalf("container: %+v", o)
	}
}
