package firewall

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// LogEvent is one packet the firewall logged as refused.
type LogEvent struct {
	At        time.Time `json:"at"`
	Action    string    `json:"action" enum:"block,reject,limit" doc:"limit = refused by a rate limit"`
	Source    string    `json:"source" example:"203.0.113.9"`
	Dest      string    `json:"dest"`
	Protocol  string    `json:"protocol" example:"TCP"`
	Port      int       `json:"port" doc:"The port it wanted; 0 for protocols without one"`
	Interface string    `json:"interface,omitempty"`
}

var (
	logFieldRe = regexp.MustCompile(`\b(IN|SRC|DST|PROTO|DPT)=(\S*)`)
	logISORe   = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^ ]*)`)
	logBSDRe   = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})`)
)

func logAction(line string) string {
	switch {
	case strings.Contains(line, "UFW LIMIT"):
		return "limit"
	case strings.Contains(line, "REJECT"):
		return "reject"
	case strings.Contains(line, "UFW BLOCK"), strings.Contains(line, "DROP"):
		return "block"
	}
	return ""
}

// ParseLog picks the refused packets out of kernel log lines, newest first.
// Allowed and audit lines are skipped. A syslog line has no year, so it gets
// now's, or last year's when that would put it in the future.
func ParseLog(raw string, now time.Time) []LogEvent {
	var events []LogEvent
	for _, line := range strings.Split(raw, "\n") {
		action := logAction(line)
		if action == "" || !strings.Contains(line, "SRC=") {
			continue
		}
		e := LogEvent{Action: action, At: logTime(line, now)}
		for _, m := range logFieldRe.FindAllStringSubmatch(line, -1) {
			switch m[1] {
			case "IN":
				e.Interface = m[2]
			case "SRC":
				e.Source = m[2]
			case "DST":
				e.Dest = m[2]
			case "PROTO":
				e.Protocol = m[2]
			case "DPT":
				e.Port, _ = strconv.Atoi(m[2])
			}
		}
		events = append(events, e)
	}
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	return events
}

func logTime(line string, now time.Time) time.Time {
	if m := logISORe.FindString(line); m != "" {
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05-0700"} {
			if t, err := time.Parse(layout, m); err == nil {
				return t
			}
		}
	}
	if m := logBSDRe.FindString(line); m != "" {
		if t, err := time.ParseInLocation("Jan 2 15:04:05", strings.Join(strings.Fields(m), " "), now.Location()); err == nil {
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(24 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
			return t
		}
	}
	return time.Time{}
}
