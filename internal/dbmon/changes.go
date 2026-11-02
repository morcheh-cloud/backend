package dbmon

import (
	"fmt"
	"slices"
	"time"
)

// DatabaseBaseline is what a database looked like when last compared: the
// changes worth knowing about are differences from it.
type DatabaseBaseline struct {
	Version   string            `json:"version"`
	StartedAt *time.Time        `json:"started_at"`
	Users     []string          `json:"users"`
	Admins    []string          `json:"admins"`
	Addresses map[string]string `json:"addresses" doc:"Client address → when last seen (RFC 3339)"`
	FirstSeen map[string]string `json:"first_seen" doc:"Client address → when it first showed up; absent = before Morcheh compared"`
	Settings  map[string]string `json:"settings"`
}

// Change is one difference found, for the event timeline.
type Change struct {
	Kind     string // version, restart, user, admin, address, setting
	Severity string // info, warning
	Title    string
	Detail   string
}

// addressMemory is how long an address stays known after it was last seen.
const addressMemory = 30 * 24 * time.Hour

// newFor is how long an address counts as new after it first showed up.
const newFor = 24 * time.Hour

// Diff compares a look with the baseline and returns what changed plus the
// new baseline. A nil baseline is the first look: it's recorded, nothing is
// reported. Parts the look didn't read (no details yet) aren't compared.
func Diff(base *DatabaseBaseline, s *DatabaseSnapshot) ([]Change, *DatabaseBaseline) {
	next := &DatabaseBaseline{
		Version: s.Version, StartedAt: s.StartedAt,
		Addresses: map[string]string{}, FirstSeen: map[string]string{},
		Settings: map[string]string{},
	}
	now := s.CollectedAt
	if base != nil {
		for a, seen := range base.Addresses {
			if t, err := time.Parse(time.RFC3339, seen); err == nil && now.Sub(t) < addressMemory {
				next.Addresses[a] = seen
				if first, ok := base.FirstSeen[a]; ok {
					next.FirstSeen[a] = first
				}
			}
		}
	}
	details := s.DetailsAt != nil
	if details {
		for _, u := range s.Users {
			next.Users = append(next.Users, u.Name)
			if u.Admin {
				next.Admins = append(next.Admins, u.Name)
			}
		}
		for _, st := range s.Settings {
			next.Settings[st.Name] = st.Value
		}
	} else if base != nil {
		next.Users, next.Admins, next.Settings = base.Users, base.Admins, base.Settings
	}

	var out []Change
	first := base == nil
	if !first && base.Version != "" && s.Version != "" && base.Version != s.Version {
		out = append(out, Change{Kind: "version", Severity: "info", Title: "Version changed",
			Detail: base.Version + " → " + s.Version})
	}
	if !first && base.StartedAt != nil && s.StartedAt != nil && s.StartedAt.Sub(*base.StartedAt) > time.Minute {
		out = append(out, Change{Kind: "restart", Severity: "warning", Title: "Restarted",
			Detail: "The server process started at " + s.StartedAt.UTC().Format(time.RFC3339)})
	}

	for _, c := range s.Clients {
		a := c.Address
		if a == "" || a == "local" {
			continue
		}
		_, known := next.Addresses[a]
		next.Addresses[a] = now.UTC().Format(time.RFC3339)
		if !first && !known {
			next.FirstSeen[a] = next.Addresses[a]
			detail := fmt.Sprintf("%d connections", c.Total)
			if len(c.Users) > 0 {
				detail += " as " + joinMax(c.Users, 3)
			}
			out = append(out, Change{Kind: "address", Severity: "info", Title: "New client address " + a, Detail: detail})
		}
	}

	if first || !details || base.Users == nil {
		return out, next
	}
	for _, u := range next.Users {
		if !slices.Contains(base.Users, u) {
			out = append(out, Change{Kind: "user", Severity: "warning", Title: "New login " + u})
		}
	}
	for _, u := range base.Users {
		if !slices.Contains(next.Users, u) {
			out = append(out, Change{Kind: "user", Severity: "info", Title: "Login removed: " + u})
		}
	}
	for _, u := range next.Admins {
		if !slices.Contains(base.Admins, u) && slices.Contains(base.Users, u) {
			out = append(out, Change{Kind: "admin", Severity: "warning", Title: u + " became an admin"})
		}
	}
	for _, st := range s.Settings {
		if old, ok := base.Settings[st.Name]; ok && old != st.Value {
			out = append(out, Change{Kind: "setting", Severity: "info", Title: "Setting " + st.Name + " changed",
				Detail: cmp(old, "(empty)") + " → " + cmp(st.Value, "(empty)")})
		}
	}
	return out, next
}

// MarkNew flags the clients whose address showed up in the last day, or
// since the last compare. The snapshot is shared, so a flagged one is copied.
func MarkNew(base *DatabaseBaseline, s *DatabaseSnapshot) *DatabaseSnapshot {
	if base == nil {
		return s
	}
	out := s
	for i, c := range s.Clients {
		if !base.isNew(c.Address, s.CollectedAt) {
			continue
		}
		if out == s {
			cp := *s
			cp.Clients = slices.Clone(s.Clients)
			out = &cp
		}
		out.Clients[i].New = true
	}
	return out
}

func (b *DatabaseBaseline) isNew(addr string, now time.Time) bool {
	if addr == "" || addr == "local" {
		return false
	}
	if _, known := b.Addresses[addr]; !known {
		return true
	}
	t, err := time.Parse(time.RFC3339, b.FirstSeen[addr])
	return err == nil && now.Sub(t) < newFor
}
