package api

import (
	"errors"
	"log/slog"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

func isNotFound(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}

// internalError logs the cause and hides it from the client.
func internalError(err error) error {
	slog.Error("request failed", "error", err)
	return huma.Error500InternalServerError("internal error")
}

// fieldError is a 422 pointing at one request field, so the client can show
// the message next to that input. location is like "body.host".
func fieldError(location, message string, value any) error {
	return huma.Error422UnprocessableEntity(message, &huma.ErrorDetail{
		Location: location,
		Message:  message,
		Value:    value,
	})
}

// parseOptionalID turns an optional uuid string (already format-checked by
// Huma) into a pointer; nil and "" both mean none.
func parseOptionalID(s *string) *uuid.UUID {
	if s == nil || *s == "" {
		return nil
	}
	id, err := uuid.Parse(*s)
	if err != nil {
		return nil
	}
	return &id
}

func optionalIDString(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	s := id.String()
	return &s
}

func parseIDs(raw []string) []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(raw))
	for _, s := range raw {
		if id, err := uuid.Parse(s); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}
