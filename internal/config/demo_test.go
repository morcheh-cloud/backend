package config

import (
	"testing"
	"time"
)

func TestNextDemoReset(t *testing.T) {
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	cases := []struct {
		every     time.Duration
		now, want string
	}{
		{time.Hour, "2026-11-19T10:20:00Z", "2026-11-19T11:00:00Z"},
		{time.Hour, "2026-11-19T10:00:00Z", "2026-11-19T11:00:00Z"},
		{30 * time.Minute, "2026-11-19T10:31:00Z", "2026-11-19T11:00:00Z"},
		{7 * time.Hour, "2026-11-19T22:00:00Z", "2026-11-20T00:00:00Z"},
		{time.Hour, "2026-11-19T13:20:00+03:30", "2026-11-19T10:00:00Z"},
	}
	for _, c := range cases {
		cfg := Config{DemoResetInterval: c.every}
		if got := cfg.NextDemoReset(at(c.now)); !got.Equal(at(c.want)) {
			t.Errorf("every %s at %s: got %s, want %s", c.every, c.now, got, c.want)
		}
	}
}
