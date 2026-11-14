package fake

import (
	"math"
	"time"
)

// rrd answers an rrddata call: 70 points ending now, one per step of the
// timeframe, each from sample(t).
func rrd(timeframe string, sample func(t float64) map[string]float64) []map[string]any {
	step := map[string]int64{"hour": 60, "day": 1800, "week": 10800, "month": 43200, "year": 604800}[timeframe]
	if step == 0 {
		step = 60
	}
	const points = 70
	end := time.Now().Unix() / step * step
	out := make([]map[string]any, 0, points)
	for i := points - 1; i >= 0; i-- {
		t := end - int64(i)*step
		row := map[string]any{"time": t}
		for k, v := range sample(float64(t)) {
			row[k] = v
		}
		out = append(out, row)
	}
	return out
}

// nodeSample is a node's numbers at time t: the sum of its running guests on
// top of the host's own small load.
func nodeSample(n *node, s *Server) func(t float64) map[string]float64 {
	return func(t float64) map[string]float64 {
		cpu := 0.02 + 0.02*wave(t, n.idx, 20)
		mem := float64(3*gib + int64(n.idx)*400*mib)
		var netin, netout float64
		for _, g := range s.guests {
			if g.node != n.name || !g.running() {
				continue
			}
			sm := g.sample(t)
			cpu += sm["cpu"] * float64(g.cpus()) / float64(n.cores)
			mem += sm["mem"]
			netin += sm["netin"]
			netout += sm["netout"]
		}
		cpu = math.Min(cpu, 1)
		return map[string]float64{
			"cpu": cpu, "maxcpu": float64(n.cores),
			"iowait":   0.002 + 0.01*wave(t, n.idx, 33),
			"loadavg":  cpu * float64(n.cores) * (0.9 + 0.2*wave(t, n.idx, 90)),
			"memtotal": float64(n.mem), "memused": math.Min(mem, float64(n.mem)),
			"swaptotal": float64(8 * gib), "swapused": float64(int64(n.idx) * 120 * mib),
			"roottotal": float64(98 * gib), "rootused": float64(9*gib + int64(n.idx)*gib),
			"netin": netin + 3000, "netout": netout + 2000,
		}
	}
}
