package api

import (
	"strings"
	"testing"

	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/storage"
)

func TestWatchEvent(t *testing.T) {
	match, _ := storage.NewMatcher([]string{"*.tmp"})
	pass := func(mode string, delay int) *watchPass {
		return &watchPass{
			s:     sqlc.StorageSync{Mode: mode},
			o:     StorageSyncOptions{DeleteDelayHours: delay},
			match: match,
			root:  "/srv/data",
		}
	}
	cases := []struct {
		name      string
		p         *watchPass
		ev, file  string
		want      bool
		wantOp    watchOp
		wantInMap bool
	}{
		{"written file", pass(storage.SyncMirror, 0), "CLOSE_WRITE,CLOSE", "/srv/data/a.txt", true, watchOp{}, true},
		{"deep file", pass(storage.SyncMirror, 0), "MOVED_TO", "/srv/data/x/y/z.txt", true, watchOp{}, true},
		{"new folder", pass(storage.SyncMirror, 0), "CREATE,ISDIR", "/srv/data/sub", true, watchOp{folder: true}, true},
		{"new file, not written yet", pass(storage.SyncMirror, 0), "CREATE", "/srv/data/b.txt", false, watchOp{}, false},
		{"excluded", pass(storage.SyncMirror, 0), "CLOSE_WRITE,CLOSE", "/srv/data/c.tmp", false, watchOp{}, false},
		{"outside the root", pass(storage.SyncMirror, 0), "CLOSE_WRITE,CLOSE", "/srv/database/a.txt", false, watchOp{}, false},
		{"the root itself", pass(storage.SyncMirror, 0), "DELETE_SELF", "/srv/data/", false, watchOp{}, false},
		{"mirror delete", pass(storage.SyncMirror, 0), "DELETE", "/srv/data/a.txt", true, watchOp{del: true}, true},
		{"mirror delete with a delay", pass(storage.SyncMirror, 24), "DELETE", "/srv/data/a.txt", false, watchOp{}, false},
		{"update keeps deleted files", pass(storage.SyncUpdate, 0), "DELETE", "/srv/data/a.txt", false, watchOp{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pending := map[string]watchOp{}
			if got := c.p.event(pending, c.ev, c.file); got != c.want {
				t.Fatalf("event() = %v, want %v", got, c.want)
			}
			op, ok := pending[strings.TrimPrefix(storage.Clean(c.file), c.p.root+"/")]
			if c.wantInMap && (!ok || op != c.wantOp) {
				t.Fatalf("pending = %v, want %v queued", pending, c.wantOp)
			}
			if !c.wantInMap && len(pending) != 0 {
				t.Fatalf("pending = %v, want nothing queued", pending)
			}
		})
	}
}
