package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/database/sqlc"
)

// Asset notes: what the team writes down about an asset, in Markdown, like
// server notes. Everyone who sees the asset reads them; Operators on the
// workspace and the asset's own owner, deputy or owning group write.

// AssetNote is a note on an asset.
type AssetNote struct {
	ID            string    `json:"id" format:"uuid"`
	Title         string    `json:"title"`
	Body          string    `json:"body" doc:"Markdown"`
	Pinned        bool      `json:"pinned" doc:"Shown on the asset's overview"`
	CreatedByName string    `json:"created_by_name"`
	UpdatedByName string    `json:"updated_by_name"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" doc:"Send it back as revision when saving"`
}

func toAssetNote(n sqlc.AssetNote) AssetNote {
	return AssetNote{
		ID: n.ID.String(), Title: n.Title, Body: n.Body, Pinned: n.Pinned,
		CreatedByName: n.CreatedByName, UpdatedByName: n.UpdatedByName,
		CreatedAt: n.CreatedAt, UpdatedAt: n.UpdatedAt,
	}
}

type assetNoteBody struct {
	Title  string `json:"title" maxLength:"200"`
	Body   string `json:"body" maxLength:"100000"`
	Pinned bool   `json:"pinned,omitempty"`
}

// Spelled out: Huma leaves an unexported embedded struct out of the schema.
type assetNoteUpdate struct {
	Title    string     `json:"title" maxLength:"200"`
	Body     string     `json:"body" maxLength:"100000"`
	Pinned   bool       `json:"pinned,omitempty"`
	Revision *time.Time `json:"revision,omitempty" doc:"The note's updated_at when you loaded it: 409 when someone saved in between"`
}

type AssetNotePath struct {
	ID   string `path:"id" format:"uuid"`
	Note string `path:"note" format:"uuid"`
}

type assetNoteOutput struct{ Body AssetNote }

const maxAssetNotes = 200

// mayWriteNotes: Operator on the workspace, or the one who answers for it.
func (h *assetHandler) mayWriteNotes(ctx context.Context, id string) (uuid.UUID, error) {
	a, stored, err := h.load(ctx, id)
	if err != nil {
		return uuid.Nil, err
	}
	if !h.mayReview(ctx, principalOf(ctx), a) {
		return uuid.Nil, huma.Error403Forbidden("You need Operator access, or to own this asset, to write notes on it")
	}
	return stored.ID, nil
}

func registerAssetNotes(api huma.API, h *assetHandler) {
	tags := []string{"Assets"}

	huma.Register(api, huma.Operation{
		OperationID: "list-asset-notes",
		Method:      http.MethodGet,
		Path:        "/assets/{id}/notes",
		Summary:     "List an asset's notes",
		Description: "Pinned first, then the most recently changed.",
		Tags:        tags,
	}, func(ctx context.Context, in *AssetIDPath) (*struct {
		Body struct {
			Items []AssetNote `json:"items"`
		}
	}, error) {
		rows, err := h.q.ListAssetNotes(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []AssetNote `json:"items"`
			}
		}{}
		out.Body.Items = make([]AssetNote, len(rows))
		for i, n := range rows {
			out.Body.Items[i] = toAssetNote(n)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-asset-note",
		Method:        http.MethodPost,
		Path:          "/assets/{id}/notes",
		Summary:       "Write a note on an asset",
		Description:   "Operator on the workspace, or the asset's owner, deputy or a member of its owning group.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		AssetIDPath
		Body assetNoteBody
	}) (*assetNoteOutput, error) {
		if strings.TrimSpace(in.Body.Title) == "" && strings.TrimSpace(in.Body.Body) == "" {
			return nil, fieldError("body.body", "Write something first.", nil)
		}
		id, err := h.mayWriteNotes(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if n, err := h.q.CountAssetNotes(ctx, id); err == nil && n >= maxAssetNotes {
			return nil, huma.Error409Conflict("This asset already has 200 notes. Delete some first.")
		}
		p := principalOf(ctx)
		note, err := h.q.CreateAssetNote(ctx, sqlc.CreateAssetNoteParams{
			AssetID: id, Title: strings.TrimSpace(in.Body.Title), Body: in.Body.Body, Pinned: in.Body.Pinned,
			CreatedBy: p.ID(), CreatedByName: byName(p),
		})
		if err != nil {
			return nil, internalError(err)
		}
		h.event(ctx, id, byName(p), "noted", []AssetChange{{Field: "note", To: noteLabel(note)}})
		return &assetNoteOutput{toAssetNote(note)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-asset-note",
		Method:      http.MethodPut,
		Path:        "/assets/{id}/notes/{note}",
		Summary:     "Save changes to an asset note",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		AssetNotePath
		Body assetNoteUpdate
	}) (*assetNoteOutput, error) {
		if strings.TrimSpace(in.Body.Title) == "" && strings.TrimSpace(in.Body.Body) == "" {
			return nil, fieldError("body.body", "Write something first.", nil)
		}
		id, err := h.mayWriteNotes(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		key := sqlc.GetAssetNoteParams{ID: uuid.MustParse(in.Note), AssetID: id}
		old, err := h.q.GetAssetNote(ctx, key)
		if isNotFound(err) {
			return nil, huma.Error404NotFound("note not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if in.Body.Revision != nil && !in.Body.Revision.Equal(old.UpdatedAt) {
			return nil, huma.Error409Conflict("Someone else saved this note after you opened it.")
		}
		note, err := h.q.UpdateAssetNote(ctx, sqlc.UpdateAssetNoteParams{
			ID: key.ID, AssetID: id, Title: strings.TrimSpace(in.Body.Title), Body: in.Body.Body,
			Pinned: in.Body.Pinned, UpdatedByName: byName(principalOf(ctx)),
		})
		if err != nil {
			return nil, internalError(err)
		}
		return &assetNoteOutput{toAssetNote(note)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "pin-asset-note",
		Method:      http.MethodPut,
		Path:        "/assets/{id}/notes/{note}/pinned",
		Summary:     "Pin an asset note to its overview, or unpin it",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		AssetNotePath
		Body struct {
			Pinned bool `json:"pinned"`
		}
	}) (*assetNoteOutput, error) {
		id, err := h.mayWriteNotes(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		note, err := h.q.SetAssetNotePinned(ctx, sqlc.SetAssetNotePinnedParams{
			ID: uuid.MustParse(in.Note), AssetID: id, Pinned: in.Body.Pinned,
		})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("note not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		return &assetNoteOutput{toAssetNote(note)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-asset-note",
		Method:        http.MethodDelete,
		Path:          "/assets/{id}/notes/{note}",
		Summary:       "Delete an asset note",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *AssetNotePath) (*struct{}, error) {
		id, err := h.mayWriteNotes(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		key := sqlc.GetAssetNoteParams{ID: uuid.MustParse(in.Note), AssetID: id}
		old, err := h.q.GetAssetNote(ctx, key)
		if isNotFound(err) {
			return nil, nil
		}
		if err != nil {
			return nil, internalError(err)
		}
		if _, err := h.q.DeleteAssetNote(ctx, sqlc.DeleteAssetNoteParams{ID: key.ID, AssetID: id}); err != nil {
			return nil, internalError(err)
		}
		h.event(ctx, id, byName(principalOf(ctx)), "unnoted", []AssetChange{{Field: "note", From: noteLabel(old)}})
		return nil, nil
	})
}

// noteLabel names a note in the history: its title, else its first line.
func noteLabel(n sqlc.AssetNote) string {
	if t := strings.TrimSpace(n.Title); t != "" {
		return t
	}
	for _, l := range strings.Split(n.Body, "\n") {
		l = strings.TrimSpace(strings.TrimLeft(l, "#>*- "))
		if l != "" {
			if len(l) > 80 {
				l = l[:80] + "…"
			}
			return l
		}
	}
	return "Untitled note"
}
