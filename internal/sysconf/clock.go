package sysconf

import (
	"strings"
)

// Clock is what `timedatectl show` says.
type Clock struct {
	Timezone string
	NTP      bool
	Synced   bool
	CanNTP   bool
}

func ParseTimedatectl(out string) Clock {
	var c Clock
	for _, l := range lines(out) {
		k, v, _ := strings.Cut(strings.TrimSpace(l), "=")
		switch k {
		case "Timezone":
			c.Timezone = v
		case "NTP":
			c.NTP = v == "yes"
		case "NTPSynchronized":
			c.Synced = v == "yes"
		case "CanNTP":
			c.CanNTP = v == "yes"
		}
	}
	return c
}

func chronySource(l string) (string, bool) {
	f := strings.Fields(l)
	if len(f) >= 2 && (f[0] == "server" || f[0] == "pool") {
		return f[1], true
	}
	return "", false
}

// ParseChronyServers lists the server and pool lines of a chrony.conf.
func ParseChronyServers(conf string) []string {
	var out []string
	for _, l := range lines(conf) {
		if s, ok := chronySource(l); ok {
			out = append(out, s)
		}
	}
	return out
}

// SetChronyServers puts servers where the first server/pool line was (or at
// the top) and drops the other ones.
func SetChronyServers(conf string, servers []string) string {
	var fresh []string
	for _, s := range servers {
		fresh = append(fresh, "server "+s+" iburst")
	}
	var out []string
	placed := false
	for _, l := range lines(conf) {
		if _, ok := chronySource(l); ok {
			if !placed {
				out = append(out, fresh...)
				placed = true
			}
			continue
		}
		out = append(out, l)
	}
	if !placed {
		out = append(fresh, out...)
	}
	return join(out)
}

// PrintTimesyncdDropIn is Morche's systemd-timesyncd drop-in.
func PrintTimesyncdDropIn(servers []string) string {
	return "# Written by Morche. Change it from Morche, or remove this file to go back to the defaults.\n[Time]\nNTP=" + strings.Join(servers, " ") + "\n"
}

// ParseTimesyncd reads NTP= (and FallbackNTP= when there is no NTP=).
func ParseTimesyncd(text string) []string {
	var ntp, fallback []string
	for _, l := range lines(text) {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		switch strings.TrimSpace(k) {
		case "NTP":
			ntp = strings.Fields(v)
		case "FallbackNTP":
			fallback = strings.Fields(v)
		}
	}
	if len(ntp) > 0 {
		return ntp
	}
	return fallback
}

// PrintChronySources is Morche's file in chrony's sourcedir.
func PrintChronySources(servers []string) string {
	s := "# Written by Morche. Change it from Morche.\n"
	for _, srv := range servers {
		s += "server " + srv + " iburst\n"
	}
	return s
}
