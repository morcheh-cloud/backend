package api

// Watched syncs: a server's folder followed as it changes. Morche keeps one
// SSH session per watched sync running `inotifywait -m -r` on the server
// (inotify-tools, nothing else installed) and copies what changed to the
// destination storage a few seconds after the writes settle. A full run
// catches up after every (re)connect, and on the sync's own interval.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/pkg/sftp"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/cmdlog"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/storage"
	"github.com/morcheh/backend/internal/terminal"
)

type StorageSyncWatchChange struct {
	Path   string    `json:"path" doc:"Relative to the source folder"`
	Action string    `json:"action" enum:"copied,deleted,failed"`
	Folder bool      `json:"folder,omitempty"`
	Bytes  int64     `json:"bytes,omitempty"`
	Error  string    `json:"error,omitempty"`
	At     time.Time `json:"at"`
}

type StorageSyncWatch struct {
	State       string                   `json:"state" enum:"starting,watching,reconnecting,failed,missing,limit,paused" doc:"missing = inotify-tools isn't on the server; limit = more folders than the server lets one user watch"`
	Message     string                   `json:"message" doc:"Why it isn't watching"`
	Since       *time.Time               `json:"since" doc:"Watching since"`
	Folders     int                      `json:"folders" doc:"Folders under the source, each one watched"`
	Limit       int                      `json:"limit" doc:"The server's fs.inotify.max_user_watches; 0 = unknown"`
	Queued      int                      `json:"queued" doc:"Changes waiting to be copied"`
	Copying     bool                     `json:"copying"`
	LastEventAt *time.Time               `json:"last_event_at"`
	LastPushAt  *time.Time               `json:"last_push_at" doc:"When changes were last copied"`
	Pushed      int                      `json:"pushed" doc:"Files copied since Morche started watching"`
	Deleted     int                      `json:"deleted"`
	Failed      int                      `json:"failed"`
	Bytes       int64                    `json:"bytes"`
	Recent      []StorageSyncWatchChange `json:"recent" doc:"Newest first, the last 30"`
}

const (
	watchRecent       = 30
	watchMaxWait      = 30 * time.Second // copy at the latest this long after the first change
	watchBatch        = 1000             // or once this many paths are waiting
	watchMaxQueue     = 100_000          // past this, a full run catches up instead
	defaultWatchLimit = 524288
)

var watchBackoff = []time.Duration{5 * time.Second, 10 * time.Second, 30 * time.Second, 60 * time.Second}

// errWatch is a reason to stop and try again later, with the state to show.
type errWatch struct {
	state, msg string
}

func (e *errWatch) Error() string { return e.msg }

// ---- The manager ----

type syncWatches struct {
	h      *storageSyncHandler
	kickCh chan struct{}

	mu sync.Mutex
	m  map[uuid.UUID]*syncWatch
}

func newSyncWatches(h *storageSyncHandler) *syncWatches {
	return &syncWatches{h: h, kickCh: make(chan struct{}, 1), m: map[uuid.UUID]*syncWatch{}}
}

// kick asks the manager to look at the saved syncs again.
func (ws *syncWatches) kick() {
	select {
	case ws.kickCh <- struct{}{}:
	default:
	}
}

// run keeps one watcher per watched sync until ctx ends.
func (ws *syncWatches) run(ctx context.Context, every time.Duration) {
	every = max(every, 15*time.Second)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		ws.refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-ws.kickCh:
		}
	}
}

// watchKey changes when anything the watcher uses changes.
func watchKey(s sqlc.StorageSync) string {
	by := ""
	if s.UpdatedBy != nil {
		by = s.UpdatedBy.String()
	} else if s.CreatedBy != nil {
		by = s.CreatedBy.String()
	}
	return strings.Join([]string{
		sourceID(s).String(), s.SourcePath, s.DestStorageID.String(), s.DestPath, s.Mode, string(s.Options), by,
	}, "\x00")
}

func (ws *syncWatches) refresh(ctx context.Context) {
	list, err := ws.h.q.ListWatchedStorageSyncs(ctx)
	if err != nil {
		slog.Warn("list watched storage syncs", "error", err)
		return
	}
	want := map[uuid.UUID]sqlc.StorageSync{}
	for _, s := range list {
		want[s.ID] = s
	}
	ws.mu.Lock()
	defer ws.mu.Unlock()
	for id, w := range ws.m {
		if s, ok := want[id]; !ok || watchKey(s) != w.key {
			w.stop()
			delete(ws.m, id)
		}
	}
	for id, s := range want {
		if _, ok := ws.m[id]; ok {
			continue
		}
		w := &syncWatch{h: ws.h, id: id, key: watchKey(s), wake: make(chan struct{}, 1)}
		w.st.State = "starting"
		wctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		w.cancel = cancel
		ws.m[id] = w
		go w.loop(wctx, s)
	}
}

func (ws *syncWatches) get(id uuid.UUID) *syncWatch {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	return ws.m[id]
}

// state is what the watcher of s is doing; nil when s isn't watched.
func (ws *syncWatches) state(s sqlc.StorageSync) *StorageSyncWatch {
	if s.Trigger != "watch" {
		return nil
	}
	if s.Paused {
		return &StorageSyncWatch{State: "paused", Recent: []StorageSyncWatchChange{}}
	}
	w := ws.get(s.ID)
	if w == nil {
		return &StorageSyncWatch{State: "starting", Recent: []StorageSyncWatchChange{}}
	}
	return w.snapshot()
}

// restart drops the watcher's session (or its wait) and starts over.
func (ws *syncWatches) restart(id uuid.UUID) {
	if w := ws.get(id); w != nil {
		w.restart()
		return
	}
	ws.kick()
}

// ---- One watcher ----

type syncWatch struct {
	h      *storageSyncHandler
	id     uuid.UUID
	key    string
	cancel context.CancelFunc
	wake   chan struct{}

	mu      sync.Mutex
	st      StorageSyncWatch
	attempt context.CancelFunc
}

func (w *syncWatch) stop() { w.cancel() }

func (w *syncWatch) restart() {
	w.mu.Lock()
	if w.attempt != nil {
		w.attempt()
	}
	w.mu.Unlock()
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *syncWatch) update(fn func(st *StorageSyncWatch)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fn(&w.st)
}

func (w *syncWatch) snapshot() *StorageSyncWatch {
	w.mu.Lock()
	defer w.mu.Unlock()
	st := w.st
	st.Recent = append([]StorageSyncWatchChange{}, w.st.Recent...)
	return &st
}

func (w *syncWatch) note(c StorageSyncWatchChange) {
	w.update(func(st *StorageSyncWatch) {
		st.Recent = append([]StorageSyncWatchChange{c}, st.Recent...)
		if len(st.Recent) > watchRecent {
			st.Recent = st.Recent[:watchRecent]
		}
		switch c.Action {
		case "copied":
			st.Pushed++
			st.Bytes += c.Bytes
		case "deleted":
			st.Deleted++
		case "failed":
			st.Failed++
		}
		now := c.At
		st.LastPushAt = &now
	})
}

func (w *syncWatch) loop(ctx context.Context, s sqlc.StorageSync) {
	tries := 0
	for ctx.Err() == nil {
		actx, cancel := context.WithCancel(ctx)
		w.mu.Lock()
		w.attempt = cancel
		w.mu.Unlock()
		watched, err := w.once(actx, s)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if watched {
			tries = 0
		}
		wait := watchBackoff[min(tries, len(watchBackoff)-1)]
		tries++
		var we *errWatch
		switch {
		case errors.As(err, &we):
			w.update(func(st *StorageSyncWatch) {
				st.State, st.Message, st.Since, st.Queued, st.Copying = we.state, we.msg, nil, 0, false
			})
			if we.state != "reconnecting" {
				wait = time.Minute
			}
		case err != nil:
			msg := upperFirst(problemText(err))
			w.update(func(st *StorageSyncWatch) {
				st.State, st.Message, st.Since, st.Queued, st.Copying = "reconnecting", msg, nil, 0, false
			})
		default:
			w.update(func(st *StorageSyncWatch) {
				st.State, st.Message, st.Since, st.Queued, st.Copying = "reconnecting", "The watch on the server ended.", nil, 0, false
			})
		}
		select {
		case <-ctx.Done():
			return
		case <-w.wake:
			tries = 0
		case <-time.After(wait):
		}
		w.update(func(st *StorageSyncWatch) { st.State = "starting" })
	}
}

func watchScript(dir string) string {
	d := terminal.ShellQuote(dir)
	return `command -v inotifywait >/dev/null 2>&1 || { echo MORCHEH-MISSING; exit 0; }
[ -d ` + d + ` ] || { echo MORCHEH-NODIR; exit 0; }
echo "MORCHEH-LIMIT $(cat /proc/sys/fs/inotify/max_user_watches 2>/dev/null)"
echo "MORCHEH-DIRS $(find ` + d + ` -xdev -type d 2>/dev/null | wc -l)"
exec 3<&0
inotifywait -m -r -e close_write,moved_to,moved_from,delete,create,delete_self,move_self --format 'E|%e|%w%f' -- ` + d + ` 2>&1 </dev/null &
p=$!
# A background job's stdin is /dev/null in sh, so hand it the session's
# through fd 3: when Morche closes it, the watch ends.
( cat >/dev/null; kill $p 2>/dev/null ) <&3 >/dev/null 2>&1 &
wait $p
echo "MORCHEH-EXIT $?"
`
}

// once runs one session: connect, watch, copy, until it ends. watched says
// it got as far as watching.
func (w *syncWatch) once(ctx context.Context, s sqlc.StorageSync) (watched bool, err error) {
	h := w.h
	who, acc, err := h.runAs(ctx, s)
	if err != nil {
		return false, &errWatch{"failed", upperFirst(problemText(err))}
	}
	if sourceLevel(acc, s) < auth.Operator {
		return false, &errWatch{"failed", fmt.Sprintf("%s no longer has Operator access to the server.", who)}
	}
	if acc.StorageLevel(s.WorkspaceID, s.DestStorageID) < auth.Engineer {
		return false, &errWatch{"failed", fmt.Sprintf("%s no longer has Engineer access to the destination.", who)}
	}
	if s.SourceServerID == nil {
		return false, &errWatch{"failed", "Only a server's folder can be watched."}
	}
	o := decodeSyncOptions(s.Options)
	match, _ := storage.NewMatcher(o.Excludes)
	root := storage.Clean(s.SourcePath)
	dstID := s.DestStorageID.String()
	serverID := s.SourceServerID.String()

	err = h.st.with(ctx, StorageTransferEnd{StorageID: &dstID}, func(dst place) error {
		if dst.readOnly {
			return &errWatch{"failed", dst.name + " is read-only in Morche."}
		}
		return h.st.servers.withSFTP(ctx, serverID, func(c *sshpool.Conn, sc *sftp.Client) error {
			src := storage.NewSFTP(sc)
			p := &watchPass{w: w, s: s, o: o, match: match, root: root, src: src, dst: dst.fs}
			err := p.follow(ctx, c)
			watched = p.watched
			return err
		})
	})
	return watched, err
}

// ---- A session ----

type watchOp struct {
	del    bool
	folder bool
}

type watchPass struct {
	w        *syncWatch
	s        sqlc.StorageSync
	o        StorageSyncOptions
	match    storage.Matcher
	root     string
	src, dst storage.FS
	watched  bool
}

func (p *watchPass) follow(ctx context.Context, c *sshpool.Conn) error {
	script := watchScript(p.root)
	lctx := cmdlog.Background(ctx, "Storage sync: "+p.s.Name)
	sess, err := c.Session(lctx)
	if err != nil {
		return err
	}
	logAs{script: script, noStdout: true}.apply(sess)
	defer sess.Close()
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return err
	}
	pr, pw := io.Pipe()
	sess.Stdin = pr
	go func() {
		<-ctx.Done()
		pw.Close()
	}()
	if err := sess.Start("sh -c " + terminal.ShellQuote(script)); err != nil {
		return err
	}
	stopClose := context.AfterFunc(ctx, func() { sess.Close() })
	defer stopClose()

	lines := make(chan string, 4096)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()

	pending := map[string]watchOp{}
	var first, last time.Time
	busy := false
	done := make(chan []StorageSyncWatchChange, 1)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	delay := time.Duration(max(p.o.WatchDelaySeconds, 1)) * time.Second
	limit, folders := 0, 0
	tail := []string{}

	setQueued := func() {
		n := len(pending)
		p.w.update(func(st *StorageSyncWatch) { st.Queued, st.Copying = n, busy })
	}
	flush := func() {
		if busy || len(pending) == 0 {
			return
		}
		batch := pending
		pending = map[string]watchOp{}
		first = time.Time{}
		busy = true
		setQueued()
		go func() { done <- p.copy(ctx, batch) }()
	}
	// Wait for a copy going on before returning, so nothing writes after.
	defer func() {
		if busy {
			<-done
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case changes := <-done:
			busy = false
			for i := len(changes) - 1; i >= 0; i-- {
				p.w.note(changes[i])
			}
			setQueued()
		case <-tick.C:
			if len(pending) > 0 && (time.Since(last) >= delay || time.Since(first) >= watchMaxWait || len(pending) >= watchBatch) {
				flush()
			}
		case l, ok := <-lines:
			if !ok {
				if err := sess.Wait(); err != nil && ctx.Err() == nil {
					return fmt.Errorf("the connection to the server ended: %w", err)
				}
				return nil
			}
			switch {
			case l == "MORCHEH-MISSING":
				return &errWatch{"missing", "inotify-tools isn't installed on the server, so changes can't be followed."}
			case l == "MORCHEH-NODIR":
				return &errWatch{"failed", fmt.Sprintf("%s isn't a folder on the server.", p.root)}
			case strings.HasPrefix(l, "MORCHEH-LIMIT "):
				limit, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(l, "MORCHEH-LIMIT ")))
				p.w.update(func(st *StorageSyncWatch) { st.Limit = limit })
			case strings.HasPrefix(l, "MORCHEH-DIRS "):
				folders, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(l, "MORCHEH-DIRS ")))
				p.w.update(func(st *StorageSyncWatch) { st.Folders = folders })
				if limit > 0 && folders >= limit {
					return &errWatch{"limit", fmt.Sprintf("The folder has %d folders, more than the %d the server lets one user watch.", folders, limit)}
				}
			case strings.HasPrefix(l, "MORCHEH-EXIT "):
				msg := "The watch on the server stopped."
				if len(tail) > 0 {
					msg = tail[len(tail)-1]
				}
				if strings.Contains(strings.Join(tail, "\n"), "upper limit on inotify watches") {
					return &errWatch{"limit", fmt.Sprintf("The server lets one user watch %d folders, and this folder has %d (with other programs' watches counted too).", limit, folders)}
				}
				if strings.Contains(strings.Join(tail, "\n"), "upper limit on inotify instances") {
					return &errWatch{"limit", "The server ran out of inotify instances for this user (fs.inotify.max_user_instances)."}
				}
				return errors.New(msg)
			case strings.HasPrefix(l, "E|"):
				ev, name, ok := strings.Cut(strings.TrimPrefix(l, "E|"), "|")
				if !ok {
					continue
				}
				if p.event(pending, ev, name) {
					now := time.Now()
					if first.IsZero() {
						first = now
					}
					last = now
					p.w.update(func(st *StorageSyncWatch) { st.LastEventAt = &now })
					if len(pending) > watchMaxQueue {
						pending = map[string]watchOp{}
						p.catchUp(ctx)
					}
					setQueued()
				}
				if strings.Contains(ev, "Q_OVERFLOW") {
					p.catchUp(ctx)
				}
			case l == "Watches established.":
				p.watched = true
				now := time.Now()
				p.w.update(func(st *StorageSyncWatch) { st.State, st.Message, st.Since = "watching", "", &now })
				p.catchUp(ctx)
			default:
				if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "Setting up watches") {
					tail = append(tail, l)
					if len(tail) > 5 {
						tail = tail[1:]
					}
				}
			}
		}
	}
}

// catchUp starts a full run, which copies what changed while no one watched.
func (p *watchPass) catchUp(ctx context.Context) {
	s, err := p.w.h.q.GetStorageSync(ctx, p.s.ID)
	if err != nil || s.Paused {
		return
	}
	if _, _, err := p.w.h.start(ctx, s, nil, "watch", false); err != nil {
		slog.Warn("start a storage sync catch-up", "sync", s.ID, "error", err)
	}
}

// event adds one inotify event to the queue; false = nothing to do.
func (p *watchPass) event(pending map[string]watchOp, ev, name string) bool {
	full := storage.Clean(name)
	rel := strings.TrimPrefix(strings.TrimPrefix(full, p.root), "/")
	if rel == "" || !storage.Within(full, p.root) || p.match.Excluded(rel) {
		return false
	}
	flags := map[string]bool{}
	for f := range strings.SplitSeq(ev, ",") {
		flags[f] = true
	}
	dir := flags["ISDIR"]
	switch {
	case flags["CLOSE_WRITE"], flags["MOVED_TO"], flags["CREATE"] && dir:
		pending[rel] = watchOp{folder: dir}
	case flags["DELETE"], flags["MOVED_FROM"]:
		if p.s.Mode != storage.SyncMirror || p.o.DeleteDelayHours > 0 {
			// Update keeps what the source lost; a delay leaves deletions to
			// the full runs, which hold them.
			delete(pending, rel)
			return false
		}
		pending[rel] = watchOp{del: true, folder: dir}
	default:
		return false
	}
	return true
}

// copy applies one batch, in path order so folders come before what's in them.
func (p *watchPass) copy(ctx context.Context, batch map[string]watchOp) []StorageSyncWatchChange {
	var out []StorageSyncWatchChange
	keys := make([]string, 0, len(batch))
	for k := range batch {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var copiedFolders []string
	under := func(rel string) bool {
		for _, f := range copiedFolders {
			if strings.HasPrefix(rel, f+"/") {
				return true
			}
		}
		return false
	}
	dstRoot := storage.Clean(p.s.DestPath)
	for _, rel := range keys {
		if ctx.Err() != nil {
			break
		}
		op := batch[rel]
		from, to := path.Join(p.root, rel), path.Join(dstRoot, rel)
		now := time.Now()
		if op.del {
			err := p.dst.Remove(ctx, to)
			if err != nil && errors.Is(err, fs.ErrNotExist) {
				continue
			}
			c := StorageSyncWatchChange{Path: rel, Action: "deleted", Folder: op.folder, At: now}
			if err != nil {
				c.Action, c.Error = "failed", upperFirst(problemText(err))
			}
			out = append(out, c)
			continue
		}
		if under(rel) {
			continue
		}
		e, err := p.src.Stat(ctx, from)
		if err != nil {
			// Gone again before it could be copied.
			continue
		}
		if p.o.Existing == "missing" {
			if _, err := p.dst.Stat(ctx, to); err == nil {
				continue
			}
		}
		var prog storage.Progress
		err = storage.CopyTree(ctx, p.src, from, p.dst, to, &prog)
		c := StorageSyncWatchChange{Path: rel, Action: "copied", Folder: e.Dir, Bytes: prog.Bytes, At: time.Now()}
		if err != nil {
			c.Action, c.Error = "failed", upperFirst(problemText(err))
		}
		if e.Dir {
			copiedFolders = append(copiedFolders, rel)
		}
		out = append(out, c)
	}
	return out
}

// ---- Routes ----

func registerStorageSyncWatch(api huma.API, h *storageSyncHandler) {
	tags := []string{"Storage syncs"}

	huma.Register(api, huma.Operation{
		OperationID: "restart-storage-sync-watch",
		Method:      http.MethodPost,
		Path:        "/storage-syncs/{id}/watch/restart",
		Summary:     "Start watching a server's folder over",
		Description: "Drops the watch session (or the wait before the next try) and connects again, which also runs a full catch-up.",
		Tags:        tags,
	}, func(ctx context.Context, in *StorageSyncPath) (*StorageSyncOutput, error) {
		s, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if s.Trigger != "watch" {
			return nil, huma.Error422UnprocessableEntity("This one doesn't watch for changes.")
		}
		h.watches.restart(s.ID)
		out, err := h.one(ctx, s)
		if err != nil {
			return nil, err
		}
		return &StorageSyncOutput{out}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "raise-storage-sync-watch-limit",
		Method:      http.MethodPost,
		Path:        "/storage-syncs/{id}/watch/raise-limit",
		Summary:     "Let the server watch more folders",
		Description: "Sets fs.inotify.max_user_watches on the source server now and in /etc/sysctl.d/90-morcheh-inotify.conf, then watches again. Needs Engineer on the server and root or sudo without a password. Each watched folder takes about 1 KB of kernel memory.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		StorageSyncPath
		Body struct {
			Limit int `json:"limit,omitempty" minimum:"0" maximum:"16777216" doc:"0 = enough for this folder, at least 524288"`
		}
	}) (*StorageSyncOutput, error) {
		s, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if s.SourceServerID == nil {
			return nil, huma.Error422UnprocessableEntity("The source isn't a server.")
		}
		if principalOf(ctx).Access.ServerLevel(s.WorkspaceID, *s.SourceServerID) < auth.Engineer {
			return nil, forbidden(auth.Engineer)
		}
		n := in.Body.Limit
		if n == 0 {
			n = defaultWatchLimit
			if w := h.watches.get(s.ID); w != nil {
				if st := w.snapshot(); st.Folders*2 > n {
					n = st.Folders * 2
				}
			}
		}
		id := s.SourceServerID.String()
		err = h.st.servers.withConn(ctx, id, func(c *sshpool.Conn) error {
			sh, err := h.st.servers.rootShell(ctx, id, c)
			if err != nil {
				return err
			}
			if sh.priv == privUser {
				return huma.Error422UnprocessableEntity("Morche signs in to this server without root or passwordless sudo, so it can't change the limit. Run as root: sysctl -w fs.inotify.max_user_watches=" + strconv.Itoa(n))
			}
			v := strconv.Itoa(n)
			_, err = sh.run(ctx, "sysctl -w fs.inotify.max_user_watches="+v+" >/dev/null && mkdir -p /etc/sysctl.d && printf 'fs.inotify.max_user_watches=%s\\n' "+v+" > /etc/sysctl.d/90-morcheh-inotify.conf")
			return err
		})
		if err != nil {
			var se huma.StatusError
			if errors.As(err, &se) {
				return nil, err
			}
			return nil, huma.Error422UnprocessableEntity("The server refused: " + problemText(err))
		}
		h.watches.restart(s.ID)
		out, err := h.one(ctx, s)
		if err != nil {
			return nil, err
		}
		return &StorageSyncOutput{out}, nil
	})
}
