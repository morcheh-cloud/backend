package procs

import (
	"fmt"
	"strconv"
	"strings"
)

// Signals that can be sent, by name (kill -s takes them without SIG).
var Signals = []string{"TERM", "KILL", "HUP", "INT", "QUIT", "STOP", "CONT", "USR1", "USR2"}

// ProcessTarget names one process: its PID and its start (ticks since boot), so a
// PID that was reused by another process is never touched.
type ProcessTarget struct {
	PID   int   `json:"pid" minimum:"2"`
	Start int64 `json:"start" minimum:"0"`
}

type ProcessResult struct {
	PID   int    `json:"pid"`
	OK    bool   `json:"ok" doc:"The signal was delivered (or the priority changed)"`
	Gone  bool   `json:"gone" doc:"It had already ended, or its PID belongs to another process now"`
	Ended bool   `json:"ended" doc:"It ended within a couple of seconds after the signal"`
	Error string `json:"error,omitempty"`
}

// guard is shell that refuses protected processes unless force is set:
// PID 1, kernel threads, Morcheh's own connection (the script's ancestors)
// and the names in Protected.
func guard(force bool) string {
	if force {
		return "protected() { return 1; }\n"
	}
	return `own=""; a=$$
while [ "${a:-0}" -gt 1 ]; do own="$own $a "; a=$(awk '{sub(/.*\) /,""); print $2}' /proc/$a/stat 2>/dev/null); done
protected() {
  [ "$1" -le 2 ] && return 0
  case "$own" in *" $1 "*) return 0;; esac
  pp=$(awk '{sub(/.*\) /,""); print $2}' /proc/$1/stat 2>/dev/null)
  [ "$pp" = 2 ] && return 0
  case "$(cat /proc/$1/comm 2>/dev/null)" in ` + strings.Join(protectedNames, "|") + `) return 0;; esac
  return 1
}
`
}

func targetList(ts []ProcessTarget) string {
	var b strings.Builder
	for _, t := range ts {
		fmt.Fprintf(&b, " %d:%d", t.PID, t.Start)
	}
	return b.String()
}

// SignalScript sends sig to every target and, for signals that end a
// process, waits up to 2 s to see which ones did. Prints one line per
// target: "<pid> ok|gone|protected|fail <message>", then "<pid> ended".
func SignalScript(sig string, ts []ProcessTarget, force bool) string {
	wait := sig == "TERM" || sig == "KILL" || sig == "INT" || sig == "QUIT" || sig == "HUP"
	var b strings.Builder
	b.WriteString("export LC_ALL=C\n" + startOf + "\n" + guard(force))
	b.WriteString("sent=\"\"\nfor t in" + targetList(ts) + "; do\n  p=${t%:*}; s=${t#*:}\n")
	b.WriteString(`  [ "$(startof $p)" = "$s" ] || { echo "$p gone"; continue; }
  protected $p && { echo "$p protected"; continue; }
  if e=$(kill -s ` + sig + ` $p 2>&1); then echo "$p ok"; sent="$sent $t"; else echo "$p fail $e"; fi
done
`)
	if wait {
		b.WriteString(`alive() { [ "$(startof $1)" = "$2" ] && [ "$(awk '{sub(/.*\) /,""); print $1}' /proc/$1/stat 2>/dev/null)" != Z ]; }
i=0
while [ -n "$sent" ] && [ $i -lt 20 ]; do
  left=""
  for t in $sent; do alive ${t%:*} ${t#*:} && left="$left $t"; done
  sent=$left
  [ -z "$sent" ] && break
  sleep 0.1 2>/dev/null || sleep 1
  i=$((i+1))
done
for t in $sent; do alive ${t%:*} ${t#*:} && echo "${t%:*} alive"; done
echo @waited
`)
	}
	b.WriteString("exit 0\n")
	return b.String()
}

// ReniceScript sets the nice value of every target.
func ReniceScript(nice int, ts []ProcessTarget, force bool) string {
	var b strings.Builder
	b.WriteString("export LC_ALL=C\n" + startOf + "\n" + guard(force))
	b.WriteString("for t in" + targetList(ts) + "; do\n  p=${t%:*}; s=${t#*:}\n")
	b.WriteString(`  [ "$(startof $p)" = "$s" ] || { echo "$p gone"; continue; }
  protected $p && { echo "$p protected"; continue; }
  if e=$(renice -n ` + strconv.Itoa(nice) + ` -p $p 2>&1 >/dev/null); then echo "$p ok"; else echo "$p fail $e"; fi
done
exit 0
`)
	return b.String()
}

// ParseResults reads SignalScript's or ReniceScript's output into one
// result per target, in the targets' order.
func ParseResults(out string, ts []ProcessTarget) []ProcessResult {
	by := map[int]*ProcessResult{}
	res := make([]ProcessResult, len(ts))
	for i, t := range ts {
		res[i] = ProcessResult{PID: t.PID}
		by[t.PID] = &res[i]
	}
	waited := strings.Contains(out, "@waited")
	alive := map[int]bool{}
	for _, l := range lines(out) {
		f := strings.SplitN(l, " ", 3)
		if len(f) < 2 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		r := by[pid]
		if err != nil || r == nil {
			continue
		}
		switch f[1] {
		case "ok":
			r.OK = true
		case "gone":
			r.Gone = true
		case "protected":
			r.Error = "Protected: the system or Morcheh needs it. Send force to do it anyway"
		case "fail":
			r.Error = failText(f)
		case "alive":
			alive[pid] = true
		}
	}
	if waited {
		for i := range res {
			res[i].Ended = res[i].OK && !alive[res[i].PID]
		}
	}
	return res
}

func failText(f []string) string {
	msg := ""
	if len(f) == 3 {
		msg = strings.TrimSpace(f[2])
	}
	switch {
	case strings.Contains(msg, "not permitted"), strings.Contains(msg, "denied"):
		return "Not allowed: it belongs to another user and the login user can't act as root here"
	case strings.Contains(msg, "No such process"):
		return "It ended before the signal arrived"
	case msg == "":
		return "It failed"
	}
	return msg
}
