package api

import (
	"bytes"
	"context"
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
)

// The command log's API: settings per workspace, lists with filters (a
// workspace's or a server's), one entry, filter choices and a CSV export.
// Like terminal recordings, an Owner (of the workspace, or of the server for
// its own list) sees everyone's commands; anyone else only their own.

type CommandLogEntry struct {
	ID          string     `json:"id" format:"uuid"`
	WorkspaceID string     `json:"workspace_id" format:"uuid"`
	ServerID    *string    `json:"server_id,omitempty" format:"uuid" doc:"Missing when the server was deleted"`
	ServerName  string     `json:"server_name"`
	UserID      *string    `json:"user_id,omitempty" format:"uuid" doc:"Missing for Morcheh's own commands"`
	UserName    string     `json:"user_name"`
	Mine        bool       `json:"mine"`
	Kind        string     `json:"kind" enum:"terminal,change,read,job,schedule,automatic"`
	Entry       string     `json:"entry" enum:"command,shell" doc:"shell = a terminal being opened; command = a command"`
	Source      string     `json:"source" doc:"What it was for: the page action, task or terminal name"`
	Ref         string     `json:"ref,omitempty" doc:"The task or terminal it belongs to"`
	RecordingID *string    `json:"recording_id,omitempty" format:"uuid"`
	RecordingMs *int64     `json:"recording_ms,omitempty" doc:"Where in the recording it starts"`
	Command     string     `json:"command"`
	Truncated   bool       `json:"truncated" doc:"Only the first 64 KiB were kept"`
	Cwd         string     `json:"cwd,omitempty"`
	AsRoot      bool       `json:"as_root"`
	StartedAt   time.Time  `json:"started_at"`
	EndedAt     *time.Time `json:"ended_at,omitempty"`
	DurationMs  *int64     `json:"duration_ms,omitempty"`
	ExitCode    *int       `json:"exit_code,omitempty"`
	Error       string     `json:"error,omitempty"`
	Note        string     `json:"note,omitempty"`
	Status      string     `json:"status" enum:"ok,failed,running,interrupted,ended"`
	Repeats     int        `json:"repeats" doc:"Times it ran the same way in a row (reads only)"`
	LastAt      time.Time  `json:"last_at"`
	ClientIP    string     `json:"client_ip,omitempty"`
	// Only on one entry (get-command-log), never in lists.
	Output *CommandOutput `json:"output,omitempty" doc:"What it printed, when kept (one entry only)"`
}

type CommandOutput struct {
	Text      string `json:"text" doc:"stdout and stderr together; terminal output keeps its colours (ANSI)"`
	Size      int64  `json:"size" doc:"Bytes printed in all"`
	Truncated bool   `json:"truncated" doc:"Only the first 16 KiB and the last 48 KiB were kept"`
	Note      string `json:"note,omitempty" doc:"Why nothing was kept although it printed something"`
}

func toCommandLog(row sqlc.CommandLog, me uuid.UUID) CommandLogEntry {
	out := CommandLogEntry{
		ID: row.ID.String(), WorkspaceID: row.WorkspaceID.String(), ServerName: row.ServerName,
		UserName: row.UserName, Mine: row.UserID != nil && *row.UserID == me, Kind: row.Kind,
		Entry: row.Entry, Source: row.Source, Ref: row.Ref, RecordingMs: row.RecordingMs,
		Command: row.Command, Truncated: row.Truncated, Cwd: row.Cwd, AsRoot: row.AsRoot,
		StartedAt: row.StartedAt, EndedAt: row.EndedAt, Error: row.Error, Note: row.Note,
		Repeats: int(row.Repeats), LastAt: row.LastAt, ClientIP: row.ClientIp,
	}
	if row.ServerID != nil {
		s := row.ServerID.String()
		out.ServerID = &s
	}
	if row.UserID != nil {
		s := row.UserID.String()
		out.UserID = &s
	}
	if row.RecordingID != nil {
		s := row.RecordingID.String()
		out.RecordingID = &s
	}
	if row.ExitCode != nil {
		c := int(*row.ExitCode)
		out.ExitCode = &c
	}
	if row.EndedAt != nil {
		d := row.EndedAt.Sub(row.StartedAt).Milliseconds()
		out.DurationMs = &d
	}
	switch {
	case row.EndedAt == nil:
		out.Status = "running"
	case row.Interrupted:
		out.Status = "interrupted"
	case (row.ExitCode != nil && *row.ExitCode != 0) || row.Error != "":
		out.Status = "failed"
	case row.ExitCode != nil:
		out.Status = "ok"
	default:
		out.Status = "ended"
	}
	return out
}

type CommandLogSettings struct {
	Enabled      bool       `json:"enabled"`
	KeepDays     int        `json:"keep_days" doc:"Entries older than this are deleted"`
	LogReads     bool       `json:"log_reads" doc:"Also keep commands run to show a page (lists, details, logs)"`
	LogAutomatic bool       `json:"log_automatic" doc:"Also keep Morcheh's own upkeep (live stats, checks, monitors)"`
	LogOutput    bool       `json:"log_output" doc:"Keep what commands print (typed in a terminal, changes, tasks, cron jobs)"`
	UpdatedBy    string     `json:"updated_by_name,omitempty"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
}

func toCommandLogSettings(s sqlc.CommandLogSetting) CommandLogSettings {
	out := CommandLogSettings{
		Enabled: s.Enabled, KeepDays: int(s.KeepDays), LogReads: s.LogReads, LogAutomatic: s.LogAutomatic,
		LogOutput: s.LogOutput, UpdatedBy: s.UpdatedByName,
	}
	if !s.UpdatedAt.IsZero() {
		out.UpdatedAt = &s.UpdatedAt
	}
	return out
}

type commandLogSettingsOutput struct{ Body CommandLogSettings }

type CommandLogQuery struct {
	Q         string    `query:"q" doc:"In the command, what it was for, or the folder"`
	Server    string    `query:"server" doc:"Only this server (workspace list)"`
	User      string    `query:"user" doc:"Only this person (Owners)"`
	Mine      bool      `query:"mine" doc:"Only the caller's own, even for an Owner"`
	Kind      []string  `query:"kind,explode" enum:"terminal,change,read,job,schedule,automatic" doc:"Why they ran; several are allowed"`
	Status    string    `query:"status" enum:"ok,failed,running,interrupted" doc:"How they ended"`
	Root      bool      `query:"root" doc:"Only commands run as root"`
	Entry     string    `query:"entry" enum:"command,shell" doc:"shell = terminals being opened"`
	Ref       string    `query:"ref" doc:"Only the commands of this task or terminal"`
	Recording string    `query:"recording" doc:"Only the commands of this terminal recording"`
	Since     time.Time `query:"since" doc:"Started at or after"`
	Until     time.Time `query:"until" doc:"Started before"`
	Before    string    `query:"before" doc:"The next page: the previous answer's next"`
	Limit     int32     `query:"limit" minimum:"1" maximum:"200" default:"50"`
}

type commandLogList struct {
	Body struct {
		Items []CommandLogEntry `json:"items"`
		// Set when there may be more: pass it as before.
		Next string `json:"next,omitempty"`
		// Whether the list holds everyone's commands or only the caller's.
		Everyone bool `json:"everyone"`
	}
}

type CommandLogFacet struct {
	ID    *string `json:"id,omitempty" format:"uuid" doc:"Missing for Morcheh itself"`
	Name  string  `json:"name"`
	Count int     `json:"count"`
}

type commandLogFacets struct {
	Body struct {
		People  []CommandLogFacet `json:"people"`
		Servers []CommandLogFacet `json:"servers"`
	}
}

type CommandLogPath struct {
	ID string `path:"id" format:"uuid"`
}

type commandLogExport struct {
	ContentType        string `header:"Content-Type"`
	ContentDisposition string `header:"Content-Disposition"`
	CacheControl       string `header:"Cache-Control"`
	Body               []byte
}

const exportMax = 20000

func registerCommandLog(api huma.API, h *serverHandler) {
	tags := []string{"Command log"}
	l := h.cmds

	huma.Register(api, huma.Operation{
		OperationID: "get-command-log-settings",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/command-log/settings",
		Summary:     "What a workspace's command log keeps, and for how long",
		Tags:        tags,
	}, func(ctx context.Context, in *WorkspacePath) (*commandLogSettingsOutput, error) {
		ws := uuid.MustParse(in.ID)
		s, err := h.q.GetCommandLogSettings(ctx, ws)
		if isNotFound(err) {
			s, err = defaultCommandLogSettings(ws), nil
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &commandLogSettingsOutput{Body: toCommandLogSettings(s)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-command-log-settings",
		Method:      http.MethodPut,
		Path:        "/workspaces/{id}/command-log/settings",
		Summary:     "Change what a workspace's command log keeps",
		Description: "Applies to commands from now on. A shorter keep_days deletes older entries within the hour.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body struct {
			Enabled      bool `json:"enabled"`
			KeepDays     int  `json:"keep_days" minimum:"1" maximum:"3650"`
			LogReads     bool `json:"log_reads"`
			LogAutomatic bool `json:"log_automatic"`
			LogOutput    bool `json:"log_output"`
		}
	}) (*commandLogSettingsOutput, error) {
		p := principalOf(ctx)
		ws := uuid.MustParse(in.ID)
		s, err := h.q.SetCommandLogSettings(ctx, sqlc.SetCommandLogSettingsParams{
			WorkspaceID: ws, Enabled: in.Body.Enabled, KeepDays: int32(in.Body.KeepDays),
			LogReads: in.Body.LogReads, LogAutomatic: in.Body.LogAutomatic,
			LogOutput: in.Body.LogOutput, UpdatedByName: cmpOr(p.User.FullName, p.User.Username),
		})
		if err != nil {
			return nil, internalError(err)
		}
		l.forget(ws)
		return &commandLogSettingsOutput{Body: toCommandLogSettings(s)}, nil
	})

	// params turns the query into the list's filters; everyone says whether
	// the caller sees other people's commands.
	params := func(ctx context.Context, in CommandLogQuery, everyone bool) (sqlc.ListCommandLogParams, error) {
		p := principalOf(ctx)
		out := sqlc.ListCommandLogParams{Lim: in.Limit}
		if !everyone {
			out.OnlyUser = &p.User.ID
		}
		if in.Server != "" {
			id, err := uuid.Parse(in.Server)
			if err != nil {
				return out, fieldError("query.server", "Not a server id", in.Server)
			}
			out.ServerID = &id
		}
		if in.User != "" {
			id, err := uuid.Parse(in.User)
			if err != nil {
				return out, fieldError("query.user", "Not a person's id", in.User)
			}
			out.UserID = &id
		}
		if len(in.Kind) > 0 {
			out.Kinds = in.Kind
		}
		if q := strings.TrimSpace(in.Q); q != "" {
			out.Q = &q
		}
		for _, f := range []struct {
			v   string
			dst **string
		}{{in.Status, &out.Status}, {in.Entry, &out.Entry}, {in.Ref, &out.Ref}} {
			if f.v != "" {
				v := f.v
				*f.dst = &v
			}
		}
		if in.Recording != "" {
			id, err := uuid.Parse(in.Recording)
			if err != nil {
				return out, fieldError("query.recording", "Not a recording id", in.Recording)
			}
			out.RecordingID = &id
		}
		if in.Root {
			t := true
			out.AsRoot = &t
		}
		if !in.Since.IsZero() {
			out.Since = &in.Since
		}
		if !in.Until.IsZero() {
			out.Until = &in.Until
		}
		if in.Before != "" {
			at, id, ok := parseCursor(in.Before)
			if !ok {
				return out, fieldError("query.before", "Not a page cursor", in.Before)
			}
			out.BeforeAt, out.BeforeID = &at, &id
		}
		return out, nil
	}

	list := func(ctx context.Context, in CommandLogQuery, scope func(*sqlc.ListCommandLogParams), everyone bool) (*commandLogList, error) {
		pp, err := params(ctx, in, everyone)
		if err != nil {
			return nil, err
		}
		scope(&pp)
		rows, err := h.q.ListCommandLog(ctx, pp)
		if err != nil {
			return nil, internalError(err)
		}
		me := principalOf(ctx).User.ID
		out := &commandLogList{}
		out.Body.Everyone = everyone
		out.Body.Items = make([]CommandLogEntry, len(rows))
		for i, row := range rows {
			out.Body.Items[i] = toCommandLog(row, me)
		}
		if n := len(rows); n > 0 && n == int(pp.Lim) {
			out.Body.Next = cursorOf(rows[n-1])
		}
		return out, nil
	}

	workspaceEveryone := func(ctx context.Context, ws uuid.UUID, mine bool) bool {
		return !mine && principalOf(ctx).Access.WorkspaceLevel(ws) >= auth.Owner
	}
	serverEveryone := func(ctx context.Context, srv sqlc.Server, mine bool) bool {
		return !mine && seesAllRecordings(principalOf(ctx).Access, srv.WorkspaceID, &srv.ID)
	}

	huma.Register(api, huma.Operation{
		OperationID: "list-workspace-command-log",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/command-log",
		Summary:     "Commands run on a workspace's servers, newest first",
		Description: "Every command Morcheh ran over SSH and every command line typed into its terminals (bash and zsh). " +
			"A workspace Owner gets everyone's; anyone else only their own.",
		Tags: tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		CommandLogQuery
	}) (*commandLogList, error) {
		ws := uuid.MustParse(in.ID)
		return list(ctx, in.CommandLogQuery, func(p *sqlc.ListCommandLogParams) { p.WorkspaceID = &ws },
			workspaceEveryone(ctx, ws, in.Mine))
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-server-command-log",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/command-log",
		Summary:     "Commands run on a server, newest first",
		Description: "An Owner of the server gets everyone's; anyone else only their own.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		CommandLogQuery
	}) (*commandLogList, error) {
		srv, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return list(ctx, in.CommandLogQuery, func(p *sqlc.ListCommandLogParams) { p.ServerID = &srv.ID },
			serverEveryone(ctx, srv, in.Mine))
	})

	facets := func(ctx context.Context, ws uuid.UUID, server *uuid.UUID, everyone bool) (*commandLogFacets, error) {
		p := principalOf(ctx)
		var only *uuid.UUID
		if !everyone {
			only = &p.User.ID
		}
		s := l.settings(ctx, ws)
		since := time.Now().AddDate(0, 0, -int(s.KeepDays))
		people, err := h.q.CommandLogPeople(ctx, sqlc.CommandLogPeopleParams{
			WorkspaceID: &ws, ServerID: server, OnlyUser: only, Since: since,
		})
		if err != nil {
			return nil, internalError(err)
		}
		out := &commandLogFacets{}
		out.Body.People = make([]CommandLogFacet, 0, len(people))
		for _, r := range people {
			f := CommandLogFacet{Name: r.UserName, Count: int(r.N)}
			if r.UserID != nil {
				id := r.UserID.String()
				f.ID = &id
			}
			out.Body.People = append(out.Body.People, f)
		}
		out.Body.Servers = []CommandLogFacet{}
		if server == nil {
			servers, err := h.q.CommandLogServers(ctx, sqlc.CommandLogServersParams{
				WorkspaceID: ws, OnlyUser: only, Since: since,
			})
			if err != nil {
				return nil, internalError(err)
			}
			for _, r := range servers {
				id := r.ServerID.String()
				out.Body.Servers = append(out.Body.Servers, CommandLogFacet{ID: &id, Name: r.ServerName, Count: int(r.N)})
			}
		}
		return out, nil
	}

	huma.Register(api, huma.Operation{
		OperationID: "workspace-command-log-facets",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/command-log/facets",
		Summary:     "The people and servers in a workspace's command log, for filters",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Mine bool `query:"mine"`
	}) (*commandLogFacets, error) {
		ws := uuid.MustParse(in.ID)
		return facets(ctx, ws, nil, workspaceEveryone(ctx, ws, in.Mine))
	})

	huma.Register(api, huma.Operation{
		OperationID: "server-command-log-facets",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/command-log/facets",
		Summary:     "The people in a server's command log, for filters",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Mine bool `query:"mine"`
	}) (*commandLogFacets, error) {
		srv, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return facets(ctx, srv.WorkspaceID, &srv.ID, serverEveryone(ctx, srv, in.Mine))
	})

	export := func(ctx context.Context, in CommandLogQuery, scope func(*sqlc.ListCommandLogParams), everyone bool, name string) (*commandLogExport, error) {
		pp, err := params(ctx, in, everyone)
		if err != nil {
			return nil, err
		}
		scope(&pp)
		pp.Lim, pp.BeforeAt, pp.BeforeID = exportMax, nil, nil
		rows, err := h.q.ListCommandLog(ctx, pp)
		if err != nil {
			return nil, internalError(err)
		}
		var buf bytes.Buffer
		buf.WriteString("\uFEFF") // so spreadsheet apps read it as UTF-8
		w := csv.NewWriter(&buf)
		_ = w.Write([]string{"started_at", "ended_at", "server", "person", "kind", "for", "command", "folder", "as_root", "status", "exit_code", "error", "repeats", "client_ip"})
		me := principalOf(ctx).User.ID
		for _, row := range rows {
			e := toCommandLog(row, me)
			ended, code := "", ""
			if e.EndedAt != nil {
				ended = e.EndedAt.UTC().Format(time.RFC3339)
			}
			if e.ExitCode != nil {
				code = strconv.Itoa(*e.ExitCode)
			}
			_ = w.Write([]string{
				e.StartedAt.UTC().Format(time.RFC3339), ended, e.ServerName, cmpOr(e.UserName, "Morcheh"),
				e.Kind, e.Source, csvSafe(e.Command), csvSafe(e.Cwd), strconv.FormatBool(e.AsRoot), e.Status, code,
				csvSafe(e.Error), strconv.Itoa(e.Repeats), e.ClientIP,
			})
		}
		w.Flush()
		file := "commands-" + safeFileName(name) + "-" + time.Now().Format("2006-01-02") + ".csv"
		return &commandLogExport{
			ContentType: "text/csv; charset=utf-8", CacheControl: "private, no-store",
			ContentDisposition: `attachment; filename="` + file + `"`, Body: buf.Bytes(),
		}, nil
	}
	csvResponse := map[string]*huma.Response{"200": {
		Description: "CSV, newest first, up to 20,000 rows",
		Content:     map[string]*huma.MediaType{"text/csv": {Schema: &huma.Schema{Type: "string"}}},
	}}

	huma.Register(api, huma.Operation{
		OperationID: "export-workspace-command-log",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/command-log/export",
		Summary:     "A workspace's command log as CSV, with the same filters",
		Tags:        tags,
		Responses:   csvResponse,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		CommandLogQuery
	}) (*commandLogExport, error) {
		ws := uuid.MustParse(in.ID)
		name := "workspace"
		if w, err := h.q.GetWorkspace(ctx, ws); err == nil {
			name = w.Name
		}
		return export(ctx, in.CommandLogQuery, func(p *sqlc.ListCommandLogParams) { p.WorkspaceID = &ws },
			workspaceEveryone(ctx, ws, in.Mine), name)
	})

	huma.Register(api, huma.Operation{
		OperationID: "export-server-command-log",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/command-log/export",
		Summary:     "A server's command log as CSV, with the same filters",
		Tags:        tags,
		Responses:   csvResponse,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		CommandLogQuery
	}) (*commandLogExport, error) {
		srv, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return export(ctx, in.CommandLogQuery, func(p *sqlc.ListCommandLogParams) { p.ServerID = &srv.ID },
			serverEveryone(ctx, srv, in.Mine), srv.Name)
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-command-log",
		Method:      http.MethodGet,
		Path:        "/command-log/{id}",
		Summary:     "One command log entry",
		Tags:        tags,
	}, func(ctx context.Context, in *CommandLogPath) (*struct{ Body CommandLogEntry }, error) {
		missing := huma.Error404NotFound("entry not found")
		id, err := uuid.Parse(in.ID)
		if err != nil {
			return nil, missing
		}
		row, err := h.q.GetCommandLog(ctx, id)
		if isNotFound(err) {
			return nil, missing
		}
		if err != nil {
			return nil, internalError(err)
		}
		p := principalOf(ctx)
		mine := row.UserID != nil && *row.UserID == p.User.ID
		if !mine && !seesAllRecordings(p.Access, row.WorkspaceID, row.ServerID) {
			return nil, missing
		}
		out := toCommandLog(row, p.User.ID)
		if o, err := h.q.GetCommandLogOutput(ctx, id); err == nil {
			out.Output = &CommandOutput{Text: o.Output, Size: o.Size, Truncated: o.Truncated, Note: o.Note}
		} else if !isNotFound(err) {
			return nil, internalError(err)
		}
		return &struct{ Body CommandLogEntry }{Body: out}, nil
	})
}

func cursorOf(row sqlc.CommandLog) string {
	return row.StartedAt.UTC().Format(time.RFC3339Nano) + "_" + row.ID.String()
}

func parseCursor(s string) (time.Time, uuid.UUID, bool) {
	at, id, ok := strings.Cut(s, "_")
	if !ok {
		return time.Time{}, uuid.Nil, false
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	u, err := uuid.Parse(id)
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	return t, u, true
}

// csvSafe keeps a spreadsheet from running a cell as a formula.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func safeFileName(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		}
		return '-'
	}, s)
	return cmpOr(strings.Trim(s, "-"), "log")
}
