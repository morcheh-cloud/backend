package fake

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type logLine struct {
	at   time.Time
	text string
}

type task struct {
	upid, node, typ, id, user string
	start, end                time.Time
	exit                      string
	lines                     []logLine
	timer                     *time.Timer
	undo                      func()
}

func (t *task) done() bool { return !t.end.IsZero() }

func (t *task) row() map[string]any {
	row := map[string]any{
		"upid": t.upid, "node": t.node, "type": t.typ, "id": t.id, "user": t.user,
		"starttime": t.start.Unix(), "pid": 0, "pstart": 0,
	}
	if t.done() {
		row["endtime"], row["status"] = t.end.Unix(), t.exit
	}
	return row
}

// run starts a task taking about d (scaled by Speed). Its log lines show up
// spread over that time; effect runs at the end, and an error from it fails
// the task with that message.
func (s *Server) run(node, typ, id string, d time.Duration, lines []string, effect func() error) string {
	return s.runTask(node, typ, id, d, lines, effect).upid
}

func (s *Server) runTask(node, typ, id string, d time.Duration, lines []string, effect func() error) *task {
	s.pid++
	now := time.Now()
	d = s.dur(d)
	user := s.opt.TokenID
	if i := strings.Index(user, "!"); i > 0 {
		user = user[:i]
	}
	t := &task{
		upid: fmt.Sprintf("UPID:%s:%08X:%08X:%08X:%s:%s:%s:", node, s.pid, uint32(now.Sub(s.start).Milliseconds()/10), now.Unix(), typ, id, s.opt.TokenID),
		node: node, typ: typ, id: id, user: user, start: now,
	}
	for i, l := range lines {
		t.lines = append(t.lines, logLine{at: now.Add(d * time.Duration(i) / time.Duration(len(lines)+1)), text: l})
	}
	s.tasks = append(s.tasks, t)
	if len(s.tasks) > 2000 {
		s.tasks = s.tasks[len(s.tasks)-2000:]
	}
	t.timer = time.AfterFunc(d, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if t.done() {
			return
		}
		var err error
		if effect != nil {
			err = effect()
		}
		s.finish(t, err)
	})
	return t
}

func (s *Server) finish(t *task, err error) {
	t.end = time.Now()
	if err != nil {
		t.exit = err.Error()
		t.lines = append(t.lines, logLine{at: t.end, text: "TASK ERROR: " + t.exit})
		return
	}
	t.exit = "OK"
	t.lines = append(t.lines, logLine{at: t.end, text: "TASK OK"})
}

// addDone records a task that already ended (for the history at start-up).
func (s *Server) addDone(node, typ, id string, at time.Time, took time.Duration, exit string, lines ...string) {
	s.pid++
	user := strings.SplitN(s.opt.TokenID, "!", 2)[0]
	t := &task{
		upid: fmt.Sprintf("UPID:%s:%08X:%08X:%08X:%s:%s:%s:", node, s.pid, uint32(s.pid*97), at.Unix(), typ, id, user),
		node: node, typ: typ, id: id, user: user, start: at, end: at.Add(took), exit: exit,
	}
	for _, l := range lines {
		t.lines = append(t.lines, logLine{at: at, text: l})
	}
	last := "TASK OK"
	if exit != "OK" {
		last = "TASK ERROR: " + exit
	}
	t.lines = append(t.lines, logLine{at: t.end, text: last})
	s.tasks = append(s.tasks, t)
}

func (s *Server) task(upid string) *task {
	for _, t := range s.tasks {
		if t.upid == upid {
			return t
		}
	}
	return nil
}

func (s *Server) taskCall(r *http.Request, n *node, p []string) (any, error) {
	if len(p) == 0 && r.Method == http.MethodGet {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit <= 0 {
			limit = 50
		}
		vmid := q.Get("vmid")
		out := []map[string]any{}
		for i := len(s.tasks) - 1; i >= 0 && len(out) < limit; i-- {
			t := s.tasks[i]
			if t.node != n.name || (vmid != "" && t.id != vmid) {
				continue
			}
			out = append(out, t.row())
		}
		return out, nil
	}
	if len(p) == 0 {
		return nil, errNotFound
	}
	t := s.task(p[0])
	if t == nil || t.node != n.name {
		return nil, fail(http.StatusInternalServerError, "unable to parse worker upid '%s'", p[0])
	}
	switch {
	case len(p) == 1 && r.Method == http.MethodDelete:
		if !t.done() {
			t.timer.Stop()
			if t.undo != nil {
				t.undo()
			}
			if id, err := strconv.Atoi(t.id); err == nil {
				if g := s.guests[id]; g != nil && g.lock != "" {
					g.lock = ""
				}
			}
			s.finish(t, fmt.Errorf("interrupted by signal"))
		}
		return nil, nil
	case len(p) == 2 && p[1] == "status":
		row := t.row()
		row["status"] = "running"
		if t.done() {
			row["status"], row["exitstatus"] = "stopped", t.exit
		}
		return row, nil
	case len(p) == 2 && p[1] == "log":
		q := r.URL.Query()
		start, _ := strconv.Atoi(q.Get("start"))
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit <= 0 {
			limit = 50
		}
		now := time.Now()
		out := []map[string]any{}
		n := 0
		for _, l := range t.lines {
			if l.at.After(now) {
				break
			}
			n++
			if n <= start {
				continue
			}
			if len(out) >= limit {
				break
			}
			out = append(out, map[string]any{"n": n, "t": l.text})
		}
		return out, nil
	}
	return nil, errNotFound
}

// seedTasks writes a few days of history.
func (s *Server) seedTasks(now time.Time) {
	day := 24 * time.Hour
	for d := 6; d >= 1; d-- {
		at := now.Add(-time.Duration(d) * day).Truncate(day).Add(time.Hour + 30*time.Minute)
		for _, id := range []int{100, 101, 103, 104} {
			g := s.guests[id]
			exit := "OK"
			if d == 2 && id == 101 {
				exit = "job errors"
			}
			s.addDone(g.node, "vzdump", strconv.Itoa(id), at, 3*time.Minute, exit,
				"INFO: starting new backup job: vzdump "+strconv.Itoa(id)+" --storage pbs --mode snapshot",
				"INFO: Starting Backup of VM "+strconv.Itoa(id)+" ("+g.kind+")",
				"INFO: Backup finished")
			at = at.Add(4 * time.Minute)
		}
	}
	s.addDone("pve1", "qmstart", "100", now.Add(-6*day-3*time.Hour), 2*time.Second, "OK")
	s.addDone("pve3", "qmstart", "105", now.Add(-2*day-5*time.Hour), 2*time.Second, "OK")
	s.addDone("pve2", "qmshutdown", "102", now.Add(-26*time.Hour), 40*time.Second, "OK")
	s.addDone("pve3", "vzstop", "106", now.Add(-20*time.Hour), time.Second, "OK")
	s.addDone("pve1", "qmsnapshot", "100", now.Add(-2*day), 4*time.Second, "OK", "snapshotting 'drive-scsi0' (before-upgrade)")
	s.addDone("pve2", "aptupdate", "", now.Add(-10*time.Hour), 20*time.Second, "OK")
	for i := range s.tasks {
		for j := i + 1; j < len(s.tasks); j++ {
			if s.tasks[j].start.Before(s.tasks[i].start) {
				s.tasks[i], s.tasks[j] = s.tasks[j], s.tasks[i]
			}
		}
	}
}
