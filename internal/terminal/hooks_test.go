package terminal

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func osc(nonce, body string) string { return oscPrefix + nonce + ";" + body + "\a" }

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestOSCFilterStripsAndReports(t *testing.T) {
	f := &oscFilter{nonce: "n1"}
	in := "hello " + osc("n1", "r;bash;0") + "$ " + osc("n1", "s;5;"+b64("/root")+";"+b64("ls -la")) +
		"out" + osc("n1", "e;2") + "\x1b[0m"
	out, ev := f.feed([]byte(in))
	if got := string(out); got != "hello $ out\x1b[0m" {
		t.Fatalf("output = %q", got)
	}
	if len(ev) != 3 || ev[0].kind != 'r' || ev[0].shell != "bash" || ev[0].uid != 0 {
		t.Fatalf("events = %+v", ev)
	}
	if ev[1].cmd != "ls -la" || ev[1].cwd != "/root" || ev[2].code != 2 {
		t.Fatalf("events = %+v", ev)
	}
}

func TestOSCFilterSplitAcrossReads(t *testing.T) {
	f := &oscFilter{nonce: "n1"}
	in := "a" + osc("n1", "s;1;"+b64("/")+";"+b64("echo hi")) + "b"
	var out strings.Builder
	var n int
	for i := 0; i < len(in); i++ { // one byte at a time
		o, ev := f.feed([]byte{in[i]})
		out.Write(o)
		n += len(ev)
	}
	if out.String() != "ab" || n != 1 {
		t.Fatalf("output = %q, events = %d", out.String(), n)
	}
}

func TestOSCFilterWrongNonceDropped(t *testing.T) {
	f := &oscFilter{nonce: "n1"}
	out, ev := f.feed([]byte("x" + osc("evil", "s;1;;"+b64("rm -rf /")) + "y"))
	if string(out) != "xy" || len(ev) != 0 {
		t.Fatalf("output = %q, events = %+v", out, ev)
	}
}

func TestOSCFilterHistoryRepeatCountedOnce(t *testing.T) {
	f := &oscFilter{nonce: "n"}
	s := osc("n", "s;7;"+b64("/")+";"+b64("uptime"))
	_, ev := f.feed([]byte(s + s))
	if len(ev) != 1 {
		t.Fatalf("events = %+v", ev)
	}
	// zsh sends no history number: each counts.
	_, ev = f.feed([]byte(osc("n", "s;;"+b64("/")+";"+b64("a")) + osc("n", "s;;"+b64("/")+";"+b64("a"))))
	if len(ev) != 2 {
		t.Fatalf("zsh events = %+v", ev)
	}
}

func TestOSCFilterOtherEscapesPass(t *testing.T) {
	f := &oscFilter{nonce: "n"}
	in := "\x1b]0;title\a\x1b[31mred\x1b"
	out, _ := f.feed([]byte(in))
	rest, _ := f.feed([]byte("[0m"))
	if got := string(out) + string(rest); got != in+"[0m" {
		t.Fatalf("output = %q", got)
	}
}

type fakeCommands struct{ log []string }

func (f *fakeCommands) Ready(shell string, uid int)           { f.log = append(f.log, "ready") }
func (f *fakeCommands) Started(cmd, cwd string, at time.Time) { f.log = append(f.log, "start "+cmd) }
func (f *fakeCommands) Output(data []byte)                    { f.log = append(f.log, "out "+string(data)) }
func (f *fakeCommands) Finished(code int, at time.Time)       { f.log = append(f.log, "end") }
func (f *fakeCommands) Closed(code int, at time.Time)         {}

func TestReportSplitsOutputAroundEvents(t *testing.T) {
	f := &oscFilter{nonce: "n1"}
	in := "$ " + osc("n1", "s;5;"+b64("/")+";"+b64("ls")) + "a b\n" + osc("n1", "e;0") + "$ "
	data, ev := f.feed([]byte(in))
	c := &fakeCommands{}
	(&Session{cmds: c}).report(data, ev)
	want := []string{"out $ ", "start ls", "out a b\n", "end", "out $ "}
	if strings.Join(c.log, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q", c.log)
	}
}
