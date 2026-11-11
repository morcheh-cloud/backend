package api

import (
	"testing"
	"time"

	"github.com/morcheh/backend/internal/database/sqlc"
)

func TestMetricSampleValue(t *testing.T) {
	s := metricSample{cpu: 95, swap: -1, disks: []diskUse{{"/", 40}, {"/var", 91}}}
	cases := []struct {
		rule   sqlc.AlertRule
		want   float64
		detail string
		ok     bool
	}{
		{sqlc.AlertRule{Metric: metricCPU}, 95, "", true},
		{sqlc.AlertRule{Metric: metricSwap}, -1, "", false},
		{sqlc.AlertRule{Metric: metricDisk}, 91, "/var", true},
		{sqlc.AlertRule{Metric: metricDisk, Mount: "/"}, 40, "/", true},
		{sqlc.AlertRule{Metric: metricDisk, Mount: "/data"}, 0, "", false},
	}
	for _, c := range cases {
		v, d, ok := s.value(c.rule)
		if ok != c.ok || (ok && (v != c.want || d != c.detail)) {
			t.Errorf("%s %q: got %v %q %v, want %v %q %v", c.rule.Metric, c.rule.Mount, v, d, ok, c.want, c.detail, c.ok)
		}
	}
}

func TestBreached(t *testing.T) {
	above := sqlc.AlertRule{Op: "above", Threshold: 90}
	below := sqlc.AlertRule{Op: "below", Threshold: 10}
	if !breached(above, 91) || breached(above, 90) || !breached(below, 5) || breached(below, 10) {
		t.Fatal("breached compares wrongly")
	}
}

func TestMetricWindow(t *testing.T) {
	if _, b := metricWindow("1h", time.Minute); b != time.Minute {
		t.Errorf("1h bucket %v", b)
	}
	if _, b := metricWindow("1h", 5*time.Minute); b != 5*time.Minute {
		t.Errorf("bucket finer than samples: %v", b)
	}
	if s, b := metricWindow("30d", time.Minute); s != 720*time.Hour || b != 6*time.Hour {
		t.Errorf("30d %v %v", s, b)
	}
}
