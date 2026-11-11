package api

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/cmdlog"
	"github.com/morcheh/backend/internal/database/sqlc"
)

func testLog() *commandLog {
	return &commandLog{
		dirty: map[uuid.UUID]*logRow{}, held: map[uuid.UUID]*logRow{},
		repeats: map[repeatKey]*logRow{}, wake: make(chan struct{}, 1),
	}
}

func heldRead(l *commandLog, at time.Time) *logRow {
	id, _ := uuid.NewV7()
	r := &logRow{
		SaveCommandLogParams: sqlc.SaveCommandLogParams{ID: id, StartedAt: at, Repeats: 1, LastAt: at},
		key:                  &repeatKey{source: "Files", text: "ls /"},
	}
	l.held[id] = r
	return r
}

func TestRepeatedReadsFold(t *testing.T) {
	l := testLog()
	now := time.Now()
	a := heldRead(l, now)
	l.end(a, cmdlog.Result{Code: 0}, now)
	b := heldRead(l, now.Add(time.Second))
	l.end(b, cmdlog.Result{Code: 0}, now.Add(2*time.Second))
	if len(l.dirty) != 1 || a.Repeats != 2 || l.dirty[a.ID] == nil {
		t.Fatalf("dirty = %d, repeats = %d", len(l.dirty), a.Repeats)
	}
	// A different result is a row of its own.
	c := heldRead(l, now.Add(3*time.Second))
	l.end(c, cmdlog.Result{Code: 1}, now.Add(3*time.Second))
	if len(l.dirty) != 2 || c.Repeats != 1 {
		t.Fatalf("dirty = %d, repeats = %d", len(l.dirty), c.Repeats)
	}
}

func TestCommandLogStatus(t *testing.T) {
	now := time.Now()
	zero, one := int32(0), int32(1)
	cases := map[string]sqlc.CommandLog{
		"running":     {StartedAt: now},
		"ok":          {StartedAt: now, EndedAt: &now, ExitCode: &zero},
		"failed":      {StartedAt: now, EndedAt: &now, ExitCode: &one},
		"interrupted": {StartedAt: now, EndedAt: &now, Interrupted: true},
		"ended":       {StartedAt: now, EndedAt: &now},
	}
	for want, row := range cases {
		if got := toCommandLog(row, uuid.Nil).Status; got != want {
			t.Errorf("status = %s, want %s", got, want)
		}
	}
}

func TestCursorRoundTrip(t *testing.T) {
	id, _ := uuid.NewV7()
	at := time.Date(2026, 11, 11, 10, 0, 0, 123456789, time.UTC)
	got, gid, ok := parseCursor(cursorOf(sqlc.CommandLog{ID: id, StartedAt: at}))
	if !ok || !got.Equal(at) || gid != id {
		t.Fatalf("got %v %v %v", got, gid, ok)
	}
}
