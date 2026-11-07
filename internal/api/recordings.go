package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/recording"
	"github.com/morcheh/backend/internal/terminal"
)

// Terminal recordings: when a workspace turns them on, every new shell on its
// servers keeps its output (never its input) as an asciicast, saved every
// saveEvery and when the shell ends. The person who opened a shell sees its
// recording; a workspace (or server) Owner sees everyone's.

const (
	recordingSaveEvery = 30 * time.Second
	defaultKeepDays    = 90
)

type recordings struct {
	q       *sqlc.Queries
	servers *serverHandler

	mu   sync.Mutex
	live map[uuid.UUID]*liveRecording
}

func newRecordings(q *sqlc.Queries, servers *serverHandler) *recordings {
	return &recordings{q: q, servers: servers, live: map[uuid.UUID]*liveRecording{}}
}

// liveRecording is one shell being recorded; it is the session's
// terminal.Recorder.
type liveRecording struct {
	id    uuid.UUID
	r     *recordings
	cast  *recording.Cast
	sess  atomic.Pointer[terminal.Session]
	ended chan int
}

func (l *liveRecording) Output(data []byte)    { l.cast.Output(data) }
func (l *liveRecording) Resize(cols, rows int) { l.cast.Resize(cols, rows) }
func (l *liveRecording) Ended(code int) {
	select {
	case l.ended <- code:
	default:
	}
}

func (l *liveRecording) title() string {
	if s := l.sess.Load(); s != nil {
		return s.Title()
	}
	return ""
}

// begin starts a recording for a shell about to open, or returns nil when the
// server's workspace doesn't record. Call attach once the session exists, or
// abandon if it couldn't start.
func (r *recordings) begin(ctx context.Context, serverID string, p *principal, cols, rows int) (*liveRecording, error) {
	srv, err := r.servers.get(ctx, serverID)
	if err != nil {
		return nil, err
	}
	settings, err := r.q.GetTerminalRecordingSettings(ctx, srv.WorkspaceID)
	if isNotFound(err) || (err == nil && !settings.Enabled) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cols, rows = termSize(cols, 80), termSize(rows, 24)
	started := time.Now()
	id, err := r.q.CreateTerminalRecording(ctx, sqlc.CreateTerminalRecordingParams{
		WorkspaceID: srv.WorkspaceID, ServerID: &srv.ID, ServerName: srv.Name,
		UserID: &p.User.ID, UserName: cmpOr(p.User.FullName, p.User.Username),
		Cols: int32(cols), Rows: int32(rows), StartedAt: started,
	})
	if err != nil {
		return nil, err
	}
	return &liveRecording{
		id: id, r: r, cast: recording.New(cols, rows, "", started), ended: make(chan int, 1),
	}, nil
}

// The terminal package's own bounds for a size.
func termSize(n, fallback int) int {
	if n <= 0 {
		return fallback
	}
	return min(n, 1000)
}

func (l *liveRecording) attach(s *terminal.Session) {
	l.sess.Store(s)
	l.r.mu.Lock()
	l.r.live[l.id] = l
	l.r.mu.Unlock()
	go l.run()
}

func (l *liveRecording) abandon() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := l.r.q.DeleteTerminalRecording(ctx, l.id); err != nil {
		slog.Warn("drop unused recording", "error", err)
	}
}

func (l *liveRecording) run() {
	t := time.NewTicker(recordingSaveEvery)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if l.cast.Changed() {
				l.save(l.cast.Snapshot(), nil)
			}
		case code := <-l.ended:
			c := int32(code)
			var exit *int32
			if code >= 0 {
				exit = &c
			}
			l.save(l.cast.Close(), &exit)
			l.r.mu.Lock()
			delete(l.r.live, l.id)
			l.r.mu.Unlock()
			return
		}
	}
}

// save writes the recording; with exit set it is the last save.
func (l *liveRecording) save(s recording.Snapshot, exit **int32) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var err error
	if exit != nil {
		err = l.r.q.EndTerminalRecording(ctx, sqlc.EndTerminalRecordingParams{
			ID: l.id, Title: l.title(), DurationMs: s.Duration.Milliseconds(), Size: s.Size,
			Truncated: s.Truncated, Data: s.Data, ExitCode: *exit,
		})
	} else {
		err = l.r.q.SaveTerminalRecording(ctx, sqlc.SaveTerminalRecordingParams{
			ID: l.id, Title: l.title(), DurationMs: s.Duration.Milliseconds(), Size: s.Size,
			Truncated: s.Truncated, Data: s.Data,
		})
	}
	if err != nil {
		slog.Error("save terminal recording", "id", l.id, "error", err)
	}
}

func (r *recordings) liveOne(id uuid.UUID) *liveRecording {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.live[id]
}

// startRecordingJanitor closes recordings a previous run left open, then
// drops old ones every hour.
func startRecordingJanitor(r *recordings) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		if n, err := r.q.InterruptTerminalRecordings(ctx); err != nil {
			slog.Error("close interrupted recordings", "error", err)
		} else if n > 0 {
			slog.Info("closed interrupted terminal recordings", "count", n)
		}
		cancel()
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			if n, err := r.q.PruneTerminalRecordings(ctx); err != nil {
				slog.Error("prune terminal recordings", "error", err)
			} else if n > 0 {
				slog.Info("pruned terminal recordings", "count", n)
			}
			cancel()
			time.Sleep(time.Hour)
		}
	}()
}

// ---- API ----

type TerminalRecording struct {
	ID          string     `json:"id" format:"uuid"`
	WorkspaceID string     `json:"workspace_id" format:"uuid"`
	ServerID    *string    `json:"server_id,omitempty" format:"uuid" doc:"Missing when the server was deleted"`
	ServerName  string     `json:"server_name"`
	UserName    string     `json:"user_name" doc:"Who opened the shell"`
	Mine        bool       `json:"mine" doc:"The caller opened this shell"`
	Title       string     `json:"title" example:"Shell 1"`
	Cols        int        `json:"cols"`
	Rows        int        `json:"rows"`
	StartedAt   time.Time  `json:"started_at"`
	EndedAt     *time.Time `json:"ended_at,omitempty" doc:"Missing while the shell runs"`
	Live        bool       `json:"live" doc:"The shell is still open"`
	ExitCode    *int       `json:"exit_code,omitempty"`
	Interrupted bool       `json:"interrupted" doc:"Morcheh restarted while the shell was open; the end is missing"`
	DurationMs  int64      `json:"duration_ms"`
	Size        int64      `json:"size" doc:"Output bytes recorded"`
	Truncated   bool       `json:"truncated" doc:"It reached the size limit; later output wasn't kept"`
	CanDelete   bool       `json:"can_delete"`
}

type recordingRow = sqlc.GetTerminalRecordingInfoRow

func (r *recordings) toRecording(row recordingRow, acc *auth.Access, me uuid.UUID) TerminalRecording {
	out := TerminalRecording{
		ID: row.ID.String(), WorkspaceID: row.WorkspaceID.String(), ServerName: row.ServerName,
		UserName: row.UserName, Mine: row.UserID != nil && *row.UserID == me, Title: row.Title,
		Cols: int(row.Cols), Rows: int(row.Rows), StartedAt: row.StartedAt, EndedAt: row.EndedAt,
		Live: row.EndedAt == nil, Interrupted: row.Interrupted, DurationMs: row.DurationMs,
		Size: row.Size, Truncated: row.Truncated,
		CanDelete: row.EndedAt != nil && acc.WorkspaceLevel(row.WorkspaceID) >= auth.Owner,
	}
	if row.ServerID != nil {
		s := row.ServerID.String()
		out.ServerID = &s
	}
	if row.ExitCode != nil {
		c := int(*row.ExitCode)
		out.ExitCode = &c
	}
	if out.Live {
		if l := r.liveOne(row.ID); l != nil {
			s := l.cast.Snapshot()
			out.Size, out.Truncated = s.Size, s.Truncated
			if t := l.title(); t != "" {
				out.Title = t
			}
		}
		out.DurationMs = time.Since(row.StartedAt).Milliseconds()
	}
	return out
}

// seesAll: an Owner of the workspace, or of the server the shell ran on.
func seesAllRecordings(acc *auth.Access, ws uuid.UUID, server *uuid.UUID) bool {
	if acc.WorkspaceLevel(ws) >= auth.Owner {
		return true
	}
	return server != nil && acc.ServerLevel(ws, *server) >= auth.Owner
}

type RecordingSettings struct {
	Enabled       bool       `json:"enabled"`
	KeepDays      int        `json:"keep_days" doc:"Recordings older than this are deleted"`
	UpdatedByName string     `json:"updated_by_name,omitempty"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
}

type recordingSettingsOutput struct{ Body RecordingSettings }

type recordingSettingsBody struct {
	Enabled  bool `json:"enabled"`
	KeepDays int  `json:"keep_days" minimum:"1" maximum:"3650"`
}

type recordingList struct {
	Body struct {
		Items []TerminalRecording `json:"items"`
		Total int                 `json:"total"`
		// Whether the list holds everyone's sessions or only the caller's.
		Everyone bool `json:"everyone"`
	}
}

type RecordingListQuery struct {
	Q      string `query:"q" doc:"In the title, server or person"`
	Mine   bool   `query:"mine" doc:"Only the caller's own, even for an Owner"`
	Limit  int32  `query:"limit" minimum:"1" maximum:"200" default:"50"`
	Offset int32  `query:"offset" minimum:"0"`
}

type RecordingPath struct {
	ID string `path:"id" format:"uuid"`
}

type recordingCastOutput struct {
	ContentType     string `header:"Content-Type"`
	ContentEncoding string `header:"Content-Encoding"`
	CacheControl    string `header:"Cache-Control"`
	Body            []byte
}

func registerRecordings(api huma.API, r *recordings) {
	tags := []string{"Terminal recordings"}

	huma.Register(api, huma.Operation{
		OperationID: "get-recording-settings",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/terminal-recording",
		Summary:     "Whether a workspace records its terminals",
		Tags:        tags,
	}, func(ctx context.Context, in *WorkspacePath) (*recordingSettingsOutput, error) {
		s, err := r.q.GetTerminalRecordingSettings(ctx, uuid.MustParse(in.ID))
		if isNotFound(err) {
			return &recordingSettingsOutput{Body: RecordingSettings{KeepDays: defaultKeepDays}}, nil
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &recordingSettingsOutput{Body: toRecordingSettings(s)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-recording-settings",
		Method:      http.MethodPut,
		Path:        "/workspaces/{id}/terminal-recording",
		Summary:     "Turn terminal recording on or off for a workspace",
		Description: "Applies to shells opened from now on; open ones keep going as they started.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body recordingSettingsBody
	}) (*recordingSettingsOutput, error) {
		p := principalOf(ctx)
		s, err := r.q.SetTerminalRecordingSettings(ctx, sqlc.SetTerminalRecordingSettingsParams{
			WorkspaceID: uuid.MustParse(in.ID), Enabled: in.Body.Enabled,
			KeepDays: int32(in.Body.KeepDays), UpdatedByName: cmpOr(p.User.FullName, p.User.Username),
		})
		if err != nil {
			return nil, internalError(err)
		}
		return &recordingSettingsOutput{Body: toRecordingSettings(s)}, nil
	})

	list := func(ctx context.Context, params sqlc.ListTerminalRecordingsParams, everyone bool) (*recordingList, error) {
		p := principalOf(ctx)
		if !everyone {
			params.UserID = &p.User.ID
		}
		count := sqlc.CountTerminalRecordingsParams{
			WorkspaceID: params.WorkspaceID, ServerID: params.ServerID, UserID: params.UserID, Q: params.Q,
		}
		rows, err := r.q.ListTerminalRecordings(ctx, params)
		if err != nil {
			return nil, internalError(err)
		}
		total, err := r.q.CountTerminalRecordings(ctx, count)
		if err != nil {
			return nil, internalError(err)
		}
		out := &recordingList{}
		out.Body.Total, out.Body.Everyone = int(total), everyone
		out.Body.Items = make([]TerminalRecording, len(rows))
		for i, row := range rows {
			out.Body.Items[i] = r.toRecording(recordingRow(row), p.Access, p.User.ID)
		}
		return out, nil
	}
	query := func(in RecordingListQuery) sqlc.ListTerminalRecordingsParams {
		params := sqlc.ListTerminalRecordingsParams{Lim: in.Limit, Off: in.Offset}
		if q := strings.TrimSpace(in.Q); q != "" {
			params.Q = &q
		}
		return params
	}

	huma.Register(api, huma.Operation{
		OperationID: "list-workspace-recordings",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/terminal-recordings",
		Summary:     "List a workspace's terminal recordings, newest first",
		Description: "A workspace Owner gets everyone's; anyone else only their own.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		RecordingListQuery
	}) (*recordingList, error) {
		ws := uuid.MustParse(in.ID)
		params := query(in.RecordingListQuery)
		params.WorkspaceID = &ws
		everyone := !in.Mine && principalOf(ctx).Access.WorkspaceLevel(ws) >= auth.Owner
		return list(ctx, params, everyone)
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-server-recordings",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/terminal-recordings",
		Summary:     "List the terminal recordings made on a server, newest first",
		Description: "An Owner of the server gets everyone's; anyone else only their own.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		RecordingListQuery
	}) (*recordingList, error) {
		srv, err := r.servers.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		params := query(in.RecordingListQuery)
		params.ServerID = &srv.ID
		everyone := !in.Mine && principalOf(ctx).Access.ServerLevel(srv.WorkspaceID, srv.ID) >= auth.Owner
		return list(ctx, params, everyone)
	})

	// find loads a recording the caller may watch; anything else is 404.
	find := func(ctx context.Context, raw string) (recordingRow, error) {
		missing := huma.Error404NotFound("recording not found")
		id, err := uuid.Parse(raw)
		if err != nil {
			return recordingRow{}, missing
		}
		row, err := r.q.GetTerminalRecordingInfo(ctx, id)
		if isNotFound(err) {
			return row, missing
		}
		if err != nil {
			return row, internalError(err)
		}
		p := principalOf(ctx)
		mine := row.UserID != nil && *row.UserID == p.User.ID
		if !mine && !seesAllRecordings(p.Access, row.WorkspaceID, row.ServerID) {
			return row, missing
		}
		return row, nil
	}

	huma.Register(api, huma.Operation{
		OperationID: "get-recording",
		Method:      http.MethodGet,
		Path:        "/terminal-recordings/{id}",
		Summary:     "A terminal recording's details",
		Tags:        tags,
	}, func(ctx context.Context, in *RecordingPath) (*struct{ Body TerminalRecording }, error) {
		row, err := find(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		p := principalOf(ctx)
		return &struct{ Body TerminalRecording }{Body: r.toRecording(row, p.Access, p.User.ID)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-recording-cast",
		Method:      http.MethodGet,
		Path:        "/terminal-recordings/{id}/cast",
		Summary:     "A terminal recording as an asciicast v2 file",
		Description: "While the shell runs, everything recorded so far.",
		Tags:        tags,
		Responses: map[string]*huma.Response{"200": {
			Description: "asciicast v2: a JSON header line, then one JSON event per line",
			Content:     map[string]*huma.MediaType{"application/x-asciicast": {Schema: &huma.Schema{Type: "string"}}},
		}},
	}, func(ctx context.Context, in *RecordingPath) (*recordingCastOutput, error) {
		row, err := find(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		out := &recordingCastOutput{ContentType: "application/x-asciicast", CacheControl: "private, no-store"}
		var stored []byte
		if l := r.liveOne(row.ID); l != nil {
			stored = l.cast.Snapshot().Data
		} else {
			d, err := r.q.GetTerminalRecordingData(ctx, row.ID)
			if err != nil {
				return nil, internalError(err)
			}
			// A finished recording is a whole gzip: the browser unpacks it.
			if d.EndedAt != nil && !d.Interrupted && len(d.Data) > 0 {
				out.ContentEncoding, out.Body = "gzip", d.Data
				return out, nil
			}
			stored = d.Data
		}
		if out.Body, err = recording.Read(stored); err != nil {
			return nil, internalError(err)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-recording",
		Method:        http.MethodDelete,
		Path:          "/terminal-recordings/{id}",
		Summary:       "Delete a terminal recording",
		Description:   "Workspace Owner only, and not while its shell is open.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *RecordingPath) (*struct{}, error) {
		row, err := find(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if principalOf(ctx).Access.WorkspaceLevel(row.WorkspaceID) < auth.Owner {
			return nil, huma.Error403Forbidden("You need Owner access to the workspace to delete recordings.")
		}
		if row.EndedAt == nil {
			return nil, huma.Error409Conflict("This shell is still open. Its recording can be deleted once it ends.")
		}
		if _, err := r.q.DeleteTerminalRecording(ctx, row.ID); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})
}

func toRecordingSettings(s sqlc.TerminalRecordingSetting) RecordingSettings {
	return RecordingSettings{
		Enabled: s.Enabled, KeepDays: int(s.KeepDays), UpdatedByName: s.UpdatedByName, UpdatedAt: &s.UpdatedAt,
	}
}
