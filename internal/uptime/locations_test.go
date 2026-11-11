package uptime

import "testing"

func probe(status string, unreachable bool) Probe {
	ms := 100
	return Probe{Location: "x", Name: "x", Result: CheckResult{Status: status, Message: status, LatencyMs: &ms}, Unreachable: unreachable}
}

func TestCombine(t *testing.T) {
	cases := []struct {
		name   string
		rule   Rule
		probes []Probe
		want   string
	}{
		{"single down stays down", DefaultRule, []Probe{probe(Down, false)}, Down},
		{"single degraded stays degraded even with never", Rule{Down: "any", Degraded: "never"}, []Probe{probe(Degraded, false)}, Degraded},
		{"majority: 1 of 3 down = degraded", DefaultRule, []Probe{probe(Down, false), probe(Up, false), probe(Up, false)}, Degraded},
		{"majority: 2 of 3 down = down", DefaultRule, []Probe{probe(Down, false), probe(Down, false), probe(Up, false)}, Down},
		{"majority of 2 needs both", DefaultRule, []Probe{probe(Down, false), probe(Up, false)}, Degraded},
		{"any: one down = down", Rule{Down: "any", Degraded: "any"}, []Probe{probe(Down, false), probe(Up, false)}, Down},
		{"all: 2 of 3 = degraded", Rule{Down: "all", Degraded: "any"}, []Probe{probe(Down, false), probe(Down, false), probe(Up, false)}, Degraded},
		{"never: 1 of 3 = up", Rule{Down: "majority", Degraded: "never"}, []Probe{probe(Down, false), probe(Up, false), probe(Up, false)}, Up},
		{"count 2 of degraded: 1 = up", Rule{Down: "all", Degraded: "count", DegradedCount: 2}, []Probe{probe(Down, false), probe(Up, false), probe(Up, false)}, Up},
		{"count down 2: 2 = down", Rule{Down: "count", DownCount: 2, Degraded: "any"}, []Probe{probe(Down, false), probe(Down, false), probe(Up, false), probe(Up, false)}, Down},
		{"unreachable doesn't vote", DefaultRule, []Probe{probe(Down, true), probe(Up, false), probe(Up, false)}, Up},
		{"unreachable: 1 of the 2 that answered", Rule{Down: "all", Degraded: "any"}, []Probe{probe(Down, true), probe(Down, false), probe(Down, false)}, Down},
		{"none answered = down", DefaultRule, []Probe{probe(Down, true), probe(Down, true)}, Down},
		{"no locations = down", DefaultRule, nil, Down},
		{"slow from one = degraded", DefaultRule, []Probe{probe(Degraded, false), probe(Up, false)}, Degraded},
	}
	for _, c := range cases {
		got := Combine(c.rule, c.probes)
		if got.Status != c.want {
			t.Errorf("%s: got %s (%s), want %s", c.name, got.Status, got.Message, c.want)
		}
		if len(got.Locations) != len(c.probes) {
			t.Errorf("%s: %d locations, want %d", c.name, len(got.Locations), len(c.probes))
		}
	}
}
