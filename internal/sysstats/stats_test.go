package sysstats

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

const netDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 5000 10 0 0 0 0 0 0 5000 10 0 0 0 0 0 0
  eth0: %d 100 0 0 0 0 0 0 %d 90 0 0 0 0 0 0
veth12ab: 999999 1 0 0 0 0 0 0 999999 1 0 0 0 0 0 0
`

func TestParse(t *testing.T) {
	out := "@os\nLinux\n@cpus\n4\n@load\n0.42 0.38 0.30 2/231 9876\n" +
		"@sample1\n1000.00 3900.00\ncpu  100 0 100 700 100 0 0 0 0 0\n" +
		fmt.Sprintf(netDev, 1000, 2000) +
		"@sample2\n1001.00 3903.00\ncpu  150 0 150 1350 150 0 0 0 0 0\n" +
		fmt.Sprintf(netDev, 3048, 2512) +
		"@mem\nMemTotal:        8000000 kB\nMemFree:          1000000 kB\nMemAvailable:     6000000 kB\n" +
		"Buffers:           100000 kB\nCached:           2000000 kB\nSReclaimable:      100000 kB\n" +
		"SwapTotal:        1000000 kB\nSwapFree:          750000 kB\n" +
		"@df\nFilesystem     Type     1024-blocks      Used Available Capacity Mounted on\n" +
		"udev           devtmpfs     4000000         0   4000000       0% /dev\n" +
		"tmpfs          tmpfs         800000      1000    799000       1% /run\n" +
		"/dev/sda1      ext4       100000000  40000000  55000000      43% /\n" +
		"/dev/sdb1      xfs        500000000 100000000 400000000      20% /mnt/my data\n" +
		"/dev/sda1      ext4       100000000  40000000  55000000      43% /var/lib/docker/x\n" +
		"/dev/loop0     squashfs       64000     64000         0     100% /snap/core/1\n"

	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	s, err := Parse(out, now)
	if err != nil {
		t.Fatal(err)
	}
	if s.UptimeSeconds != 1001 || !s.BootedAt.Equal(now.Add(-1001*time.Second)) {
		t.Errorf("uptime = %d, booted %v", s.UptimeSeconds, s.BootedAt)
	}
	// Δtotal = 800, Δidle+iowait = 650+50 → 12.5% busy, 6.25% iowait.
	if s.CPU.Cores != 4 || s.CPU.UsagePercent != 12.5 || s.CPU.IOWaitPercent != 6.3 || s.CPU.Load1 != 0.42 {
		t.Errorf("cpu = %+v", s.CPU)
	}
	if s.Processes != 231 {
		t.Errorf("processes = %d", s.Processes)
	}
	if s.Network.RxBytesPerSec != 2048 || s.Network.TxBytesPerSec != 512 || s.Network.RxBytesTotal != 3048 {
		t.Errorf("network = %+v", s.Network)
	}
	if s.Memory.UsedBytes != 2000000*1024 || s.Memory.SwapUsedBytes != 250000*1024 {
		t.Errorf("memory = %+v", s.Memory)
	}
	if len(s.Disks) != 2 || s.Disks[0].Mount != "/" || s.Disks[1].Mount != "/mnt/my data" {
		t.Fatalf("disks = %+v", s.Disks)
	}
	if d := s.Disks[0]; d.Type != "ext4" || d.UsedPercent != 42.1 {
		t.Errorf("root = %+v", d)
	}
}

func TestParseBusyboxDfWithoutType(t *testing.T) {
	disks := parseDf("Filesystem 1024-blocks Used Available Capacity Mounted on\n" +
		"overlay 2000 500 1500 25% /\n" +
		"tmpfs 64 0 64 0% /dev\n")
	if len(disks) != 1 || disks[0].Mount != "/" || disks[0].Type != "" {
		t.Errorf("disks = %+v", disks)
	}
}

func TestParseNotLinux(t *testing.T) {
	if _, err := Parse("@os\nDarwin\n", time.Now()); err != ErrUnsupported {
		t.Errorf("err = %v", err)
	}
}

func TestStream(t *testing.T) {
	frame := func(up string, busy, rx int, df bool) string {
		f := "@cpus\n2\n@load\n1.00 0.50 0.25 1/100 1\n@sample\n" + up + " 0\n" +
			fmt.Sprintf("cpu  %d 0 0 1000 0 0 0 0 0 0\n", busy) + fmt.Sprintf(netDev, rx, 0) +
			"@mem\nMemTotal: 1000 kB\nMemAvailable: 500 kB\n"
		if df {
			f += "@df\nFilesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 2000 500 1500 25% /\n"
		}
		return f + "@end\n"
	}
	out := frame("10.00", 0, 0, true) + frame("11.00", 1000, 100, false) + frame("12.00", 1000, 300, false)
	var got []Stats
	err := Stream(strings.NewReader(out), time.Now, func(s Stats) { got = append(got, s) })
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d frames", len(got))
	}
	if got[0].CPU.UsagePercent != 100 || got[1].CPU.UsagePercent != 0 || got[1].Network.RxBytesPerSec != 200 {
		t.Errorf("stats = %+v / %+v", got[0], got[1])
	}
	if len(got[1].Disks) != 1 || got[1].Disks[0].Mount != "/" {
		t.Errorf("disks not carried over: %+v", got[1].Disks)
	}
	if err := Stream(strings.NewReader("@unsupported\n"), time.Now, func(Stats) {}); err != ErrUnsupported {
		t.Errorf("err = %v", err)
	}
}
