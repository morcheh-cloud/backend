package api

import (
	"context"
	"log/slog"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/cmdlog"
	"github.com/morcheh/backend/internal/database/sqlc"
)

// The command log's writer: the SSH pool and the terminals report commands
// here (cmdlog.Sink); rows are written in batches every commandFlush, so a
// command costs no database round trip on the way to the server.

const (
	commandFlush = time.Second
	// A command's text is kept up to this size.
	commandMax = 64 << 10
	// The same read (same server, person, page and command, same result)
	// within this long counts as a repeat of the row before.
	repeatWindow = 10 * time.Minute
	// A read still running after this long is written as running; shorter
	// ones are written once they end, so repeats can fold into one row.
	readHold = 5 * time.Second
	// How long looked-up names and settings are trusted.
	lookupTTL = time.Minute
)

type commandLog struct {
	q *sqlc.Queries

	mu      sync.Mutex
	dirty   map[uuid.UUID]*logRow
	held    map[uuid.UUID]*logRow // reads not written yet
	repeats map[repeatKey]*logRow
	servers map[uuid.UUID]cached[serverLookup]
	users   map[uuid.UUID]cached[string]
	setts   map[uuid.UUID]cached[sqlc.CommandLogSetting]
	wake    chan struct{}
}

type cached[T any] struct {
	v  T
	at time.Time
}

type serverLookup struct {
	workspace uuid.UUID
	name      string
	ok        bool
}

type repeatKey struct {
	server uuid.UUID
	user   uuid.UUID
	source string
	text   string
}

// logRow is one row as it will be written.
type logRow struct {
	sqlc.SaveCommandLogParams
	key *repeatKey
	// What it printed is kept (the workspace keeps output, and this kind
	// of row is worth it); output waits to be written.
	keepOutput bool
	output     *cmdlog.Output
	// The output text last queued, so a folded repeat that printed the
	// same isn't written again.
	kept string
}

func newCommandLog(q *sqlc.Queries) *commandLog {
	l := &commandLog{
		q: q, dirty: map[uuid.UUID]*logRow{}, held: map[uuid.UUID]*logRow{},
		repeats: map[repeatKey]*logRow{},
		servers: map[uuid.UUID]cached[serverLookup]{}, users: map[uuid.UUID]cached[string]{},
		setts: map[uuid.UUID]cached[sqlc.CommandLogSetting]{}, wake: make(chan struct{}, 1),
	}
	go l.writer()
	go l.janitor()
	return l
}

// Begin implements cmdlog.Sink.
func (l *commandLog) Begin(ctx context.Context, c cmdlog.Command) cmdlog.Handle {
	row := l.row(ctx, c)
	if row == nil {
		return nil
	}
	l.mu.Lock()
	if c.Origin.Kind == cmdlog.Read {
		l.held[row.ID] = row
	} else {
		l.dirty[row.ID] = row
	}
	l.mu.Unlock()
	return &logHandle{l: l, row: row}
}

// row builds the row for c, or nil when its workspace doesn't keep it.
func (l *commandLog) row(ctx context.Context, c cmdlog.Command) *logRow {
	sid, err := uuid.Parse(c.ServerID)
	if err != nil {
		return nil
	}
	ctx = context.WithoutCancel(ctx)
	srv := l.server(ctx, sid)
	if !srv.ok {
		return nil
	}
	s := l.settings(ctx, srv.workspace)
	switch {
	case !s.Enabled:
		return nil
	case c.Origin.Kind == cmdlog.Read && !s.LogReads:
		return nil
	case c.Origin.Kind == cmdlog.Automatic && !s.LogAutomatic:
		return nil
	}
	text, truncated := c.Text, false
	if len(text) > commandMax {
		text, truncated = cutUTF8(text, commandMax), true
	}
	entry := "command"
	if c.Shell {
		entry = "shell"
	}
	id, _ := uuid.NewV7()
	r := &logRow{SaveCommandLogParams: sqlc.SaveCommandLogParams{
		ID: id, WorkspaceID: srv.workspace, ServerID: &sid, ServerName: srv.name,
		UserID: c.Origin.UserID, Kind: string(c.Origin.Kind), Entry: entry,
		Source: c.Origin.Source, Ref: c.Origin.Ref, RecordingID: c.RecordingID,
		Command: text, Truncated: truncated, Cwd: c.Cwd, AsRoot: c.AsRoot,
		StartedAt: c.Started, Repeats: 1, LastAt: c.Started, ClientIp: c.Origin.ClientIP,
	}}
	if c.RecordingID != nil {
		ms := c.RecordingMs
		r.RecordingMs = &ms
	}
	if c.Origin.UserID != nil {
		r.UserName = l.user(ctx, *c.Origin.UserID)
	}
	r.keepOutput = s.LogOutput && !c.Shell
	if c.Origin.Kind == cmdlog.Read {
		k := repeatKey{server: sid, source: r.Source, text: text}
		if c.Origin.UserID != nil {
			k.user = *c.Origin.UserID
		}
		r.key = &k
	}
	return r
}

// cutUTF8 cuts s to at most n bytes without splitting a character.
func cutUTF8(s string, n int) string {
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

type logHandle struct {
	l    *commandLog
	row  *logRow
	once sync.Once
}

func (h *logHandle) End(r cmdlog.Result) {
	h.once.Do(func() { h.l.end(h.row, r, time.Now()) })
}

func (l *commandLog) end(row *logRow, r cmdlog.Result, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	code := int32(r.Code)
	if r.Code >= 0 {
		row.ExitCode = &code
	}
	row.Error = r.Error
	row.EndedAt, row.LastAt = &at, at
	if row.keepOutput && r.Output != nil {
		row.output, row.kept = r.Output, r.Output.Text
	}
	if _, held := l.held[row.ID]; held {
		delete(l.held, row.ID)
		// A repeat of the read before: count it there instead.
		if prev := l.repeats[*row.key]; prev != nil && sameEnd(prev, row) && at.Sub(prev.LastAt) < repeatWindow {
			prev.Repeats++
			prev.LastAt = at
			// The folded row shows what the latest one printed.
			if row.output != nil && row.output.Text != prev.kept {
				prev.output, prev.kept = row.output, row.output.Text
			}
			l.dirty[prev.ID] = prev
			l.poke()
			return
		}
		l.repeats[*row.key] = row
	}
	l.dirty[row.ID] = row
	l.poke()
}

func sameEnd(a, b *logRow) bool {
	if (a.ExitCode == nil) != (b.ExitCode == nil) {
		return false
	}
	return (a.ExitCode == nil || *a.ExitCode == *b.ExitCode) && a.Error == b.Error
}

// poke wakes the writer for a row that ended; caller holds l.mu.
func (l *commandLog) poke() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

// update changes a written row (a shell's note, a command's root flag).
func (l *commandLog) update(row *logRow, fn func(*sqlc.SaveCommandLogParams)) {
	l.mu.Lock()
	fn(&row.SaveCommandLogParams)
	if _, held := l.held[row.ID]; !held {
		l.dirty[row.ID] = row
	}
	l.mu.Unlock()
}

func (l *commandLog) writer() {
	t := time.NewTicker(commandFlush)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-l.wake:
			// Let the rest of a burst arrive first.
			time.Sleep(commandFlush / 4)
		}
		l.flush()
	}
}

func (l *commandLog) flush() {
	now := time.Now()
	l.mu.Lock()
	for id, r := range l.held {
		if now.Sub(r.StartedAt) > readHold {
			delete(l.held, id)
			l.dirty[id] = r
		}
	}
	for k, r := range l.repeats {
		if now.Sub(r.LastAt) > repeatWindow {
			delete(l.repeats, k)
		}
	}
	if len(l.dirty) == 0 {
		l.mu.Unlock()
		return
	}
	batch := make([]sqlc.SaveCommandLogParams, 0, len(l.dirty))
	var outputs []sqlc.SaveCommandLogOutputParams
	for id, r := range l.dirty {
		batch = append(batch, r.SaveCommandLogParams)
		if o := r.output; o != nil {
			outputs = append(outputs, sqlc.SaveCommandLogOutputParams{
				ID: id, Output: o.Text, Size: o.Size, Truncated: o.Truncated, Note: o.Note,
			})
			r.output = nil
		}
		delete(l.dirty, id)
	}
	l.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	l.q.SaveCommandLog(ctx, batch).Exec(func(i int, err error) {
		if err != nil {
			slog.Warn("command log write", "server", batch[i].ServerName, "error", err)
		}
	})
	// After the rows: an output belongs to one.
	if len(outputs) > 0 {
		l.q.SaveCommandLogOutput(ctx, outputs).Exec(func(i int, err error) {
			if err != nil {
				slog.Warn("command output write", "error", err)
			}
		})
	}
}

// janitor closes rows a previous run left open, then prunes past keep_days.
func (l *commandLog) janitor() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	if n, err := l.q.InterruptCommandLog(ctx); err != nil {
		slog.Error("close interrupted commands", "error", err)
	} else if n > 0 {
		slog.Info("closed commands left running", "count", n)
	}
	cancel()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		if n, err := l.q.PruneCommandLog(ctx); err != nil {
			slog.Error("prune command log", "error", err)
		} else if n > 0 {
			slog.Info("pruned command log", "count", n)
		}
		cancel()
		time.Sleep(time.Hour)
	}
}

// ---- Lookups ----

func (l *commandLog) server(ctx context.Context, id uuid.UUID) serverLookup {
	l.mu.Lock()
	c, ok := l.servers[id]
	l.mu.Unlock()
	if ok && time.Since(c.at) < lookupTTL {
		return c.v
	}
	var v serverLookup
	if s, err := l.q.GetServer(ctx, id); err == nil {
		v = serverLookup{workspace: s.WorkspaceID, name: s.Name, ok: true}
	} else if ok {
		v = c.v // keep the last answer through a database hiccup
	}
	l.mu.Lock()
	l.servers[id] = cached[serverLookup]{v, time.Now()}
	l.mu.Unlock()
	return v
}

func (l *commandLog) user(ctx context.Context, id uuid.UUID) string {
	l.mu.Lock()
	c, ok := l.users[id]
	l.mu.Unlock()
	if ok && time.Since(c.at) < lookupTTL {
		return c.v
	}
	name := c.v
	if u, err := l.q.GetUser(ctx, id); err == nil {
		name = cmpOr(u.FullName, u.Username)
	}
	l.mu.Lock()
	l.users[id] = cached[string]{name, time.Now()}
	l.mu.Unlock()
	return name
}

// settings are the workspace's, or the defaults without a row.
func (l *commandLog) settings(ctx context.Context, ws uuid.UUID) sqlc.CommandLogSetting {
	l.mu.Lock()
	c, ok := l.setts[ws]
	l.mu.Unlock()
	if ok && time.Since(c.at) < lookupTTL {
		return c.v
	}
	s, err := l.q.GetCommandLogSettings(ctx, ws)
	switch {
	case err == nil:
	case isNotFound(err):
		s = defaultCommandLogSettings(ws)
	case ok:
		s = c.v
	default:
		s = defaultCommandLogSettings(ws)
	}
	l.mu.Lock()
	l.setts[ws] = cached[sqlc.CommandLogSetting]{s, time.Now()}
	l.mu.Unlock()
	return s
}

// forget drops cached settings after they change.
func (l *commandLog) forget(ws uuid.UUID) {
	l.mu.Lock()
	delete(l.setts, ws)
	l.mu.Unlock()
}

func defaultCommandLogSettings(ws uuid.UUID) sqlc.CommandLogSetting {
	return sqlc.CommandLogSetting{WorkspaceID: ws, Enabled: true, KeepDays: defaultKeepDays, LogReads: true, LogOutput: true}
}
