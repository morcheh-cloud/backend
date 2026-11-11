package uptime

import (
	"fmt"
	"strings"
)

// Morcheh names the location that is Morcheh itself (no server in between).
const Morcheh = "morcheh"

// Unknown is a location's status when it couldn't check at all (its server
// was unreachable): it doesn't vote.
const Unknown = "unknown"

// LocationResult is what one location found in a round.
type LocationResult struct {
	Location  string `json:"location" doc:"morcheh, or the server's id"`
	Name      string `json:"name"`
	Status    string `json:"status" enum:"up,degraded,down,unknown" doc:"unknown = it couldn't check (its server was unreachable); it doesn't vote"`
	LatencyMs *int   `json:"latency_ms,omitempty"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message"`
	Detail    string `json:"detail,omitempty"`
}

// Rule turns the answers of several locations into one status.
type Rule struct {
	// Down: any, majority, all or count (at least DownCount).
	Down      string
	DownCount int
	// Degraded, when the failures don't reach Down: any, majority, count
	// (at least DegradedCount locations with trouble) or never.
	Degraded      string
	DegradedCount int
}

// DefaultRule is used when a body leaves the rule out.
var DefaultRule = Rule{Down: "majority", DownCount: 2, Degraded: "any", DegradedCount: 1}

// DownNeed is how many of n answering locations must fail for down.
func (r Rule) DownNeed(n int) int {
	switch r.Down {
	case "any":
		return 1
	case "all":
		return max(n, 1)
	case "count":
		return max(min(r.DownCount, n), 1)
	default:
		return n/2 + 1
	}
}

// DegradedNeed is how many of n answering locations with trouble make it
// degraded; 0 = never.
func (r Rule) DegradedNeed(n int) int {
	switch r.Degraded {
	case "never":
		return 0
	case "majority":
		return n/2 + 1
	case "count":
		return max(min(r.DegradedCount, n), 1)
	default:
		return 1
	}
}

// Probe is one location's check.
type Probe struct {
	Location string
	Name     string
	Result   CheckResult
	// Unreachable: the location itself couldn't check (no SSH to its server).
	Unreachable bool
}

func (p Probe) status() string {
	switch {
	case p.Unreachable:
		return Unknown
	case p.Result.Status == Up || p.Result.Status == Degraded:
		return p.Result.Status
	}
	return Down
}

// Combine votes: the locations' answers become one result, by the rule.
// Locations that couldn't check don't count; when none could, it's down.
// The result lists every location's answer.
func Combine(rule Rule, probes []Probe) CheckResult {
	locs := make([]LocationResult, len(probes))
	for i, p := range probes {
		locs[i] = LocationResult{
			Location: p.Location, Name: p.Name, Status: p.status(), LatencyMs: p.Result.LatencyMs,
			Code: p.Result.Code, Message: p.Result.Message, Detail: p.Result.Detail,
		}
	}
	if len(probes) == 0 {
		return CheckResult{Status: Down, Code: "via", Message: "No location to check from: its server was removed", Locations: locs}
	}
	if len(probes) == 1 {
		r := probes[0].Result
		if r.Status != Up && r.Status != Degraded {
			r.Status = Down
		}
		r.Locations = locs
		return r
	}

	var answered, downs, troubles []int
	var unknown []string
	for i, l := range locs {
		switch l.Status {
		case Unknown:
			unknown = append(unknown, l.Name)
			continue
		case Down:
			downs = append(downs, i)
			troubles = append(troubles, i)
		case Degraded:
			troubles = append(troubles, i)
		}
		answered = append(answered, i)
	}
	out := CheckResult{Locations: locs}
	if len(answered) == 0 {
		out.Status, out.Code = Down, "via"
		out.Message = "Couldn't check from any location: " + probes[0].Result.Message
		return out
	}

	// Latency = the average of the locations that measured one; the
	// certificate = the one that ends first.
	sum, n := 0, 0
	for _, i := range answered {
		r := probes[i].Result
		if r.LatencyMs != nil {
			sum += *r.LatencyMs
			n++
		}
		if r.CertExpires != nil && (out.CertExpires == nil || r.CertExpires.Before(*out.CertExpires)) {
			t := *r.CertExpires
			out.CertExpires = &t
		}
	}
	if n > 0 {
		avg := (sum + n/2) / n
		out.LatencyMs = &avg
	}

	total := len(answered)
	list := func(idx []int) string {
		parts := make([]string, 0, len(idx))
		for _, i := range idx {
			parts = append(parts, locs[i].Name+": "+locs[i].Message)
		}
		return strings.Join(parts, "; ")
	}
	switch need := rule.DegradedNeed(total); {
	case len(downs) >= rule.DownNeed(total):
		out.Status, out.Code = Down, locs[downs[0]].Code
		out.Message = fmt.Sprintf("Down from %d of %d locations. %s", len(downs), total, list(downs))
		out.Detail = locs[downs[0]].Detail
	case need > 0 && len(troubles) >= need:
		out.Status, out.Code = Degraded, locs[troubles[0]].Code
		out.Message = fmt.Sprintf("Trouble from %d of %d locations. %s", len(troubles), total, list(troubles))
		out.Detail = locs[troubles[0]].Detail
	default:
		first := answered[0]
		for _, i := range answered {
			if locs[i].Status == Up {
				first = i
				break
			}
		}
		out.Status, out.Code, out.Detail = Up, locs[first].Code, locs[first].Detail
		if len(troubles) == 0 {
			out.Message = fmt.Sprintf("Up from all %d locations. %s", total, locs[first].Message)
		} else {
			out.Message = fmt.Sprintf("Up: only %d of %d locations had trouble. %s", len(troubles), total, list(troubles))
		}
	}
	if len(unknown) > 0 {
		out.Message += " (Couldn't check from " + strings.Join(unknown, ", ") + ")"
	}
	return out
}
