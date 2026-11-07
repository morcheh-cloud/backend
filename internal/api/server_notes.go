package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
)

// ServerNote is something the team wrote down about a server, in Markdown.
type ServerNote struct {
	ID            string    `json:"id" format:"uuid"`
	Title         string    `json:"title"`
	Body          string    `json:"body" doc:"Markdown"`
	Pinned        bool      `json:"pinned" doc:"Shown on the server's overview"`
	CreatedByName string    `json:"created_by_name"`
	UpdatedByName string    `json:"updated_by_name"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" doc:"Send it back as revision when saving"`
}

func toServerNote(n sqlc.ServerNote) ServerNote {
	return ServerNote{
		ID: n.ID.String(), Title: n.Title, Body: n.Body, Pinned: n.Pinned,
		CreatedByName: n.CreatedByName, UpdatedByName: n.UpdatedByName,
		CreatedAt: n.CreatedAt, UpdatedAt: n.UpdatedAt,
	}
}

type serverNoteBody struct {
	Title  string `json:"title" maxLength:"200"`
	Body   string `json:"body" maxLength:"100000"`
	Pinned bool   `json:"pinned,omitempty"`
}

// Spelled out: Huma leaves an unexported embedded struct out of the schema.
type serverNoteUpdate struct {
	Title    string     `json:"title" maxLength:"200"`
	Body     string     `json:"body" maxLength:"100000"`
	Pinned   bool       `json:"pinned,omitempty"`
	Revision *time.Time `json:"revision,omitempty" doc:"The note's updated_at when you loaded it: 409 when someone saved in between"`
}

type serverNotePath struct {
	ID   string `path:"id" format:"uuid"`
	Note string `path:"note" format:"uuid"`
}

type serverNoteOutput struct{ Body ServerNote }

// maxServerNotes keeps one server from collecting an endless pile.
const maxServerNotes = 200

func checkServerNote(b serverNoteBody) error {
	if strings.TrimSpace(b.Title) == "" && strings.TrimSpace(b.Body) == "" {
		return fieldError("body.body", "Write something first.", nil)
	}
	return nil
}

func registerServerNotes(api huma.API, h *serverHandler) {
	tags := []string{"Server notes"}

	huma.Register(api, huma.Operation{
		OperationID: "list-server-notes",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/notes",
		Summary:     "List a server's notes",
		Description: "Pinned first, then the most recently changed.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct {
		Body struct {
			Items []ServerNote `json:"items"`
		}
	}, error) {
		rows, err := h.q.ListServerNotes(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []ServerNote `json:"items"`
			}
		}{}
		out.Body.Items = make([]ServerNote, len(rows))
		for i, n := range rows {
			out.Body.Items[i] = toServerNote(n)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-server-note",
		Method:        http.MethodPost,
		Path:          "/servers/{id}/notes",
		Summary:       "Write a note on a server",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body serverNoteBody
	}) (*serverNoteOutput, error) {
		if err := checkServerNote(in.Body); err != nil {
			return nil, err
		}
		id := uuid.MustParse(in.ID)
		n, err := h.q.CountServerNotes(ctx, id)
		if err != nil {
			return nil, internalError(err)
		}
		if n >= maxServerNotes {
			return nil, huma.Error409Conflict("This server already has 200 notes. Delete some first.")
		}
		p := principalOf(ctx)
		note, err := h.q.CreateServerNote(ctx, sqlc.CreateServerNoteParams{
			ServerID: id, Title: strings.TrimSpace(in.Body.Title), Body: in.Body.Body, Pinned: in.Body.Pinned,
			CreatedBy: p.ID(), CreatedByName: cmpOr(p.User.FullName, p.User.Username),
		})
		if err != nil {
			return nil, internalError(err)
		}
		return &serverNoteOutput{toServerNote(note)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-server-note",
		Method:      http.MethodPut,
		Path:        "/servers/{id}/notes/{note}",
		Summary:     "Save changes to a note",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		serverNotePath
		Body serverNoteUpdate
	}) (*serverNoteOutput, error) {
		if err := checkServerNote(serverNoteBody{Title: in.Body.Title, Body: in.Body.Body}); err != nil {
			return nil, err
		}
		key := sqlc.GetServerNoteParams{ID: uuid.MustParse(in.Note), ServerID: uuid.MustParse(in.ID)}
		old, err := h.q.GetServerNote(ctx, key)
		if isNotFound(err) {
			return nil, huma.Error404NotFound("note not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if in.Body.Revision != nil && !in.Body.Revision.Equal(old.UpdatedAt) {
			return nil, huma.Error409Conflict("Someone else saved this note after you opened it.")
		}
		p := principalOf(ctx)
		note, err := h.q.UpdateServerNote(ctx, sqlc.UpdateServerNoteParams{
			ID: key.ID, ServerID: key.ServerID, Title: strings.TrimSpace(in.Body.Title), Body: in.Body.Body,
			Pinned: in.Body.Pinned, UpdatedByName: cmpOr(p.User.FullName, p.User.Username),
		})
		if err != nil {
			return nil, internalError(err)
		}
		return &serverNoteOutput{toServerNote(note)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "pin-server-note",
		Method:      http.MethodPut,
		Path:        "/servers/{id}/notes/{note}/pinned",
		Summary:     "Pin a note to the overview, or unpin it",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		serverNotePath
		Body struct {
			Pinned bool `json:"pinned"`
		}
	}) (*serverNoteOutput, error) {
		note, err := h.q.SetServerNotePinned(ctx, sqlc.SetServerNotePinnedParams{
			ID: uuid.MustParse(in.Note), ServerID: uuid.MustParse(in.ID), Pinned: in.Body.Pinned,
		})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("note not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &serverNoteOutput{toServerNote(note)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-server-note",
		Method:        http.MethodDelete,
		Path:          "/servers/{id}/notes/{note}",
		Summary:       "Delete a note",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *serverNotePath) (*struct{}, error) {
		if _, err := h.q.DeleteServerNote(ctx, sqlc.DeleteServerNoteParams{
			ID: uuid.MustParse(in.Note), ServerID: uuid.MustParse(in.ID),
		}); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})
}
