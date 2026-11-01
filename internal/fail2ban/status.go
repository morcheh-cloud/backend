package fail2ban

import (
	"regexp"
	"strconv"
	"strings"
)

// JailStatus is what `fail2ban-client status <jail>` reports.
type JailStatus struct {
	CurrentlyFailed int      `json:"currently_failed"`
	TotalFailed     int      `json:"total_failed"`
	CurrentlyBanned int      `json:"currently_banned"`
	TotalBanned     int      `json:"total_banned"`
	Files           []string `json:"files" doc:"Log files the jail watches"`
	JournalMatches  string   `json:"journal_matches" doc:"With the systemd backend: the journal filter instead of files"`
	BannedIPs       []string `json:"banned_ips"`
}

// ParseJailList reads the jail names out of `fail2ban-client status`.
func ParseJailList(out string) []string {
	for _, line := range strings.Split(out, "\n") {
		_, rest, ok := strings.Cut(line, "Jail list:")
		if !ok {
			continue
		}
		var names []string
		for _, n := range strings.Split(rest, ",") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
		return names
	}
	return nil
}

// ParseStatus reads one jail's status tree:
//
//	|- Filter
//	|  |- Currently failed:	0
//	|  `- File list:	/var/log/auth.log
//	`- Actions
//	   `- Banned IP list:	192.0.2.1 192.0.2.7
func ParseStatus(out string) JailStatus {
	s := JailStatus{Files: []string{}, BannedIPs: []string{}}
	for _, line := range strings.Split(out, "\n") {
		i := strings.Index(line, "- ")
		if i < 0 {
			continue
		}
		key, val, ok := strings.Cut(line[i+2:], ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		n, _ := strconv.Atoi(val)
		switch strings.TrimSpace(key) {
		case "Currently failed":
			s.CurrentlyFailed = n
		case "Total failed":
			s.TotalFailed = n
		case "Currently banned":
			s.CurrentlyBanned = n
		case "Total banned":
			s.TotalBanned = n
		case "File list":
			s.Files = strings.Fields(val)
		case "Journal matches":
			s.JournalMatches = val
		case "Banned IP list":
			s.BannedIPs = strings.Fields(val)
		}
	}
	return s
}

// Ban is one banned address with its time window, when fail2ban says.
type Ban struct {
	IP      string `json:"ip" example:"192.0.2.1"`
	Since   string `json:"since,omitempty" doc:"Server-local time, as fail2ban prints it" example:"2026-11-01 10:00:00"`
	Seconds int    `json:"seconds,omitempty" doc:"Ban length; -1 is forever"`
	Until   string `json:"until,omitempty" doc:"Server-local time the ban ends" example:"2026-11-01 10:10:00"`
}

var banTimeRe = regexp.MustCompile(`^(\S+)\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\s+\+\s+(-?\d+)\s+=\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)`)

// ParseBans reads `fail2ban-client get <jail> banip --with-time`, one ban
// per line: `192.0.2.1 	2026-11-01 10:00:00 + 600 = 2026-11-01 10:10:00`.
// Lines without times keep just the address.
func ParseBans(out string) []Ban {
	var bans []Ban
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if m := banTimeRe.FindStringSubmatch(line); m != nil {
			n, _ := strconv.Atoi(m[3])
			bans = append(bans, Ban{IP: m[1], Since: m[2], Seconds: n, Until: m[4]})
			continue
		}
		for _, f := range strings.Fields(line) {
			bans = append(bans, Ban{IP: f})
		}
	}
	return bans
}

// Event is one line of fail2ban's log about an address.
type Event struct {
	Time   string `json:"time" doc:"Server-local time" example:"2026-11-01 10:00:00"`
	Jail   string `json:"jail" example:"sshd"`
	Action string `json:"action" enum:"found,ban,unban,restore,increase,ignore" doc:"found = a failure matched; restore = a ban put back after a restart"`
	IP     string `json:"ip" example:"192.0.2.1"`
}

// Matches fail2ban's own log lines and the journal's (short-iso, with a T).
var eventRe = regexp.MustCompile(`(\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d).*?\]:.*?\[([^\]]+)\]\s+(Found|Ban|Unban|Restore Ban|Increase Ban|Ignore)\s+(\S+)`)

// ParseEvents picks the ban activity out of fail2ban log lines, in order.
func ParseEvents(lines []string) []Event {
	var events []Event
	for _, line := range lines {
		m := eventRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		action := strings.ToLower(strings.Fields(m[3])[0])
		events = append(events, Event{Time: strings.Replace(m[1], "T", " ", 1), Jail: m[2], Action: action, IP: m[4]})
	}
	return events
}

// RegexSummary is the counts fail2ban-regex reports for a test.
type RegexSummary struct {
	Lines   int `json:"lines"`
	Ignored int `json:"ignored"`
	Matched int `json:"matched"`
	Missed  int `json:"missed"`
}

var regexLinesRe = regexp.MustCompile(`Lines:\s+(\d+) lines,\s+(\d+) ignored,\s+(\d+) matched,\s+(\d+) missed`)

// ParseRegex reads `Lines: 120 lines, 0 ignored, 3 matched, 117 missed`.
func ParseRegex(out string) (RegexSummary, bool) {
	m := regexLinesRe.FindStringSubmatch(out)
	if m == nil {
		return RegexSummary{}, false
	}
	n := func(i int) int { v, _ := strconv.Atoi(m[i]); return v }
	return RegexSummary{Lines: n(1), Ignored: n(2), Matched: n(3), Missed: n(4)}, true
}
