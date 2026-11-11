package procs

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseStatOddName(t *testing.T) {
	line := "4242 (we ird) (x)) S 1 4242 4242 0 -1 4194560 100 0 0 0 250 50 0 0 20 5 3 0 1532 104857600 2560 18446744073709551615"
	pid, st, ok := ParseStat(line)
	if !ok || pid != 4242 {
		t.Fatalf("parse failed: %v %d", ok, pid)
	}
	if st.comm != "we ird) (x)" || st.state != "S" || st.ppid != 1 || st.utime != 250 || st.stime != 50 ||
		st.nice != 5 || st.threads != 3 || st.start != 1532 || st.vsize != 104857600 || st.rss != 2560 {
		t.Fatalf("wrong fields: %+v", st)
	}
}

func TestUnitOf(t *testing.T) {
	cases := map[string][2]string{
		"/system.slice/nginx.service":                                       {"nginx.service", ""},
		"/user.slice/user-1000.slice/session-3.scope":                       {"", "3"},
		"/user.slice/user-1000.slice/user@1000.service/app.slice/x.service": {"", ""},
		"/system.slice/docker-abc.scope":                                    {"", ""},
	}
	for in, want := range cases {
		u, s := unitOf(in)
		if u != want[0] || s != want[1] {
			t.Errorf("%s: got %q %q, want %q", in, u, s, want)
		}
	}
}

func TestHexAddr(t *testing.T) {
	cases := map[string]string{
		"0100007F:0050":                         "127.0.0.1:80",
		"00000000:1F90":                         "0.0.0.0:8080",
		"00000000000000000000000000000000:0016": "[::]:22",
		"0000000000000000FFFF00000100007F:01BB": "127.0.0.1:443",
	}
	for in, want := range cases {
		if got := hexAddr(in); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}

func TestParseResults(t *testing.T) {
	ts := []ProcessTarget{{10, 1}, {11, 2}, {12, 3}, {13, 4}}
	out := "10 ok\n11 gone\n12 fail kill: (12) - Operation not permitted\n13 ok\n13 alive\n@waited\n"
	r := ParseResults(out, ts)
	if !r[0].OK || !r[0].Ended || !r[1].Gone || r[2].OK || !strings.HasPrefix(r[2].Error, "Not allowed") || !r[3].OK || r[3].Ended {
		t.Fatalf("wrong results: %+v", r)
	}
}

// The scripts on this machine: a real /proc, our own process found, the
// script's own processes left out.
func TestScriptsLocally(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs Linux")
	}
	out, err := exec.Command("sh", "-c", Script).Output()
	if err != nil {
		t.Fatal(err)
	}
	r, err := Parse(string(out), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var me *Process
	for i, p := range r.Processes {
		if p.Command == "sleep 1" || strings.HasPrefix(p.Command, "ps -ww") {
			t.Errorf("the script's own process is listed: %s", p.Command)
		}
		if p.PID == os.Getpid() {
			me = &r.Processes[i]
		}
	}
	if me == nil {
		t.Fatal("this test's process isn't listed")
	}
	if !me.Morcheh || me.Memory == 0 || me.User == "" || me.Threads == 0 || me.StartedAt.IsZero() {
		t.Errorf("wrong self: %+v", *me)
	}
	if r.Cores < 1 || r.MemoryTotal == 0 || r.SampleMillis < 900 {
		t.Errorf("wrong totals: %+v", r)
	}

	d, err := exec.Command("sh", "-c", DetailsScript(me.PID, me.Start, true)).Output()
	if err != nil {
		t.Fatal(err)
	}
	det, err := ParseDetails(string(d), me.PID, me.Start)
	if err != nil {
		t.Fatal(err)
	}
	if det.Exe == "" || det.Cwd == "" || len(det.Argv) == 0 || len(det.Env) == 0 || det.OpenFiles == 0 {
		t.Errorf("wrong details: %+v", det)
	}
	if _, err := ParseDetails(mustRun(t, DetailsScript(me.PID, me.Start+1, false)), me.PID, me.Start+1); err != ErrGone {
		t.Errorf("a wrong start should be gone, got %v", err)
	}

	// TERM to a sleeping child: delivered and ended.
	c := exec.Command("sleep", "30")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	go c.Wait()
	var start int64
	for range 20 {
		b, _ := os.ReadFile("/proc/" + itoa(c.Process.Pid) + "/stat")
		if _, st, ok := ParseStat(string(b)); ok {
			start = st.start
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	ts := []ProcessTarget{{c.Process.Pid, start}, {1, 0}}
	res := ParseResults(mustRun(t, SignalScript("TERM", ts, false)), ts)
	if !res[0].OK || !res[0].Ended {
		t.Errorf("sleep not ended: %+v", res[0])
	}
	if res[1].OK {
		t.Errorf("PID 1 with a wrong start was signalled: %+v", res[1])
	}
}

func mustRun(t *testing.T, script string) string {
	t.Helper()
	out, err := exec.Command("sh", "-c", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func itoa(i int) string { return strconv.Itoa(i) }
