package ansible

import (
	"encoding/json"
	"time"
)

// Event is one line from Morcheh's callback plugin.
type RunEvent struct {
	E    string  `json:"e"`
	T    float64 `json:"t"`
	ID   string  `json:"id,omitempty"`
	Play string  `json:"play,omitempty"`
	Task string  `json:"task,omitempty"`
	Name string  `json:"name,omitempty"`
	// play: its host pattern; result, start, retry: the host.
	Hosts   string `json:"hosts,omitempty"`
	Host    string `json:"host,omitempty"`
	Action  string `json:"action,omitempty"`
	Handler bool   `json:"handler,omitempty"`
	Path    string `json:"path,omitempty"`
	Reason  string `json:"reason,omitempty"`
	// result
	Status string          `json:"status,omitempty"`
	Msg    string          `json:"msg,omitempty"`
	Rc     *int            `json:"rc,omitempty"`
	Stdout string          `json:"stdout,omitempty"`
	Stderr string          `json:"stderr,omitempty"`
	Diff   json.RawMessage `json:"diff,omitempty"`
	Items  []ItemResult          `json:"items,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
	// retry
	Attempt int `json:"attempt,omitempty"`
	Retries int `json:"retries,omitempty"`
	// stats
	Stats map[string]HostStats `json:"stats,omitempty"`
}

// Stats is one host's line of the play recap.
type HostStats struct {
	Ok          int `json:"ok"`
	Changed     int `json:"changed"`
	Failed      int `json:"failed"`
	Unreachable int `json:"unreachable"`
	Skipped     int `json:"skipped"`
	Rescued     int `json:"rescued"`
	Ignored     int `json:"ignored"`
}

// Item is one loop item's result.
type ItemResult struct {
	Item   json.RawMessage `json:"item" doc:"The item (any JSON value)"`
	Status string          `json:"status" enum:"ok,changed,failed,skipped"`
	Msg    string          `json:"msg,omitempty"`
	Rc     *int            `json:"rc,omitempty"`
	Stdout string          `json:"stdout,omitempty"`
	Stderr string          `json:"stderr,omitempty"`
}

// ParseEvent reads one line.
func ParseEvent(line []byte) (RunEvent, error) {
	var ev RunEvent
	err := json.Unmarshal(line, &ev)
	return ev, err
}

// Play is one play of a run, with its tasks as they ran.
type RunPlay struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	Hosts string  `json:"hosts" doc:"Its host pattern"`
	Tasks []*RunTask `json:"tasks"`
	// NoHosts says the play matched no host, or every host failed before it ended.
	NoHosts string `json:"no_hosts,omitempty" enum:"matched,remaining"`
}

// Task is one task with each host's result.
type RunTask struct {
	ID      string             `json:"id"`
	Name    string             `json:"name"`
	Action  string             `json:"action"`
	Handler bool               `json:"handler"`
	Path    string             `json:"path,omitempty" doc:"Where it's written (file:line)"`
	Started time.Time          `json:"started_at"`
	Results map[string]*TaskResult `json:"results" doc:"By inventory host name"`
}

// Result is what a task did on one host.
type TaskResult struct {
	Status string          `json:"status" enum:"running,ok,changed,failed,ignored,skipped,unreachable"`
	Msg    string          `json:"msg,omitempty"`
	Rc     *int            `json:"rc,omitempty"`
	Stdout string          `json:"stdout,omitempty"`
	Stderr string          `json:"stderr,omitempty"`
	Diff   json.RawMessage `json:"diff,omitempty" doc:"Ansible's diff (with --diff)"`
	Items  []ItemResult          `json:"items,omitempty" doc:"Per loop item"`
	Data   json.RawMessage `json:"data,omitempty" doc:"The rest of the module's answer"`
	// Attempts is set while an until/retries loop runs again.
	Attempts  int       `json:"attempts,omitempty"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at,omitzero"`
}

// Log is what the callback reported so far: the plays with their tasks and
// the recap. Not safe for concurrent use.
type Log struct {
	Plays []*RunPlay          `json:"plays"`
	Recap map[string]HostStats `json:"recap"`
	tasks map[string]*RunTask
	plays map[string]*RunPlay
}

func NewLog() *Log {
	return &Log{Plays: []*RunPlay{}, tasks: map[string]*RunTask{}, plays: map[string]*RunPlay{}}
}

func when(t float64) time.Time {
	if t == 0 {
		return time.Now()
	}
	return time.Unix(0, int64(t*1e9)).UTC()
}

// Apply adds an event. It returns the task the event was about (nil for
// play and stats events).
func (l *Log) Apply(ev RunEvent) *RunTask {
	switch ev.E {
	case "play":
		p := &RunPlay{ID: ev.ID, Name: ev.Name, Hosts: ev.Hosts, Tasks: []*RunTask{}}
		l.Plays = append(l.Plays, p)
		l.plays[ev.ID] = p
	case "no_hosts":
		if p := l.plays[ev.Play]; p != nil {
			p.NoHosts = ev.Reason
		}
	case "task":
		p := l.plays[ev.Play]
		if p == nil {
			p = &RunPlay{ID: ev.Play, Tasks: []*RunTask{}}
			l.Plays = append(l.Plays, p)
			l.plays[ev.Play] = p
		}
		// A task runs again for each include loop; keep one entry.
		if t := l.tasks[ev.ID]; t != nil {
			return t
		}
		t := &RunTask{ID: ev.ID, Name: ev.Name, Action: ev.Action, Handler: ev.Handler, Path: ev.Path, Started: when(ev.T), Results: map[string]*TaskResult{}}
		p.Tasks = append(p.Tasks, t)
		l.tasks[ev.ID] = t
		return t
	case "start":
		if t := l.tasks[ev.Task]; t != nil {
			t.Results[ev.Host] = &TaskResult{Status: "running", StartedAt: when(ev.T)}
			return t
		}
	case "retry":
		if t := l.tasks[ev.Task]; t != nil {
			if r := t.Results[ev.Host]; r != nil {
				r.Attempts = ev.Attempt
			}
			return t
		}
	case "result":
		t := l.tasks[ev.Task]
		if t == nil {
			return nil
		}
		started := when(ev.T)
		if old := t.Results[ev.Host]; old != nil {
			started = old.StartedAt
		}
		t.Results[ev.Host] = &TaskResult{
			Status: ev.Status, Msg: ev.Msg, Rc: ev.Rc, Stdout: ev.Stdout, Stderr: ev.Stderr,
			Diff: ev.Diff, Items: ev.Items, Data: ev.Data,
			StartedAt: started, EndedAt: when(ev.T),
		}
		return t
	case "stats":
		l.Recap = ev.Stats
	}
	return nil
}

// Close marks results still running as never finished (the run stopped), and
// fills the recap from the results when ansible-playbook didn't get to print
// one.
func (l *Log) Close() {
	for _, p := range l.Plays {
		for _, t := range p.Tasks {
			for _, r := range t.Results {
				if r.Status == "running" {
					r.Status, r.Msg = "failed", "Stopped before it finished"
					r.EndedAt = time.Now().UTC()
				}
			}
		}
	}
	if l.Recap != nil {
		return
	}
	l.Recap = map[string]HostStats{}
	for _, p := range l.Plays {
		for _, t := range p.Tasks {
			for host, r := range t.Results {
				s := l.Recap[host]
				switch r.Status {
				case "ok":
					s.Ok++
				case "changed":
					s.Ok++
					s.Changed++
				case "failed":
					s.Failed++
				case "ignored":
					s.Ok++
					s.Ignored++
				case "skipped":
					s.Skipped++
				case "unreachable":
					s.Unreachable++
				}
				l.Recap[host] = s
			}
		}
	}
}
