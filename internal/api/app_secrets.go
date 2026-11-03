package api

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
)

// A service's passwords are read one at a time, and every read is logged in
// the same transaction: a reveal nobody could see later never happens.

type AppAccountPath struct {
	ID        string `path:"id" format:"uuid"`
	AccountID string `path:"accountId" format:"uuid"`
}

type AppSecretOutput struct {
	CacheControl string `header:"Cache-Control"`
	Body         struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
}

type AppSecretView struct {
	ID           string    `json:"id" format:"uuid"`
	AccountLabel string    `json:"account_label" doc:"As it was then; kept after the account is removed."`
	UserName     string    `json:"user_name"`
	IP           string    `json:"ip"`
	CreatedAt    time.Time `json:"created_at"`
}

type AppActivityOutput struct {
	Body struct {
		Items []AppSecretView `json:"items"`
	}
}

func registerAppSecrets(api huma.API, h *appHandler) {
	tags := []string{"apps"}

	huma.Register(api, huma.Operation{
		OperationID: "reveal-app-account",
		Method:      http.MethodPost,
		Path:        "/apps/{id}/accounts/{accountId}/reveal",
		Summary:     "Reveal a service account's password",
		Description: "Logged in the service's activity. POST and `Cache-Control: no-store` so nothing caches it.",
		Tags:        tags,
	}, func(ctx context.Context, in *AppAccountPath) (*AppSecretOutput, error) {
		p := principalOf(ctx)
		app, account := uuid.MustParse(in.ID), uuid.MustParse(in.AccountID)
		out := &AppSecretOutput{CacheControl: "no-store"}
		err := h.a.inTx(ctx, func(q *sqlc.Queries) error {
			acc, err := q.GetAppAccount(ctx, sqlc.GetAppAccountParams{ID: account, AppID: app})
			if isNotFound(err) {
				return huma.Error404NotFound("account not found")
			}
			if err != nil {
				return internalError(err)
			}
			if len(acc.PasswordEnc) == 0 {
				return huma.Error422UnprocessableEntity("This account has no password saved.")
			}
			pw, err := h.box.Open(acc.PasswordEnc)
			if err != nil {
				return internalError(err)
			}
			label := acc.Label
			if label == "" {
				label = acc.Username
			}
			name := p.User.FullName
			if name == "" {
				name = p.User.Username
			}
			if err := q.CreateAppSecretView(ctx, sqlc.CreateAppSecretViewParams{
				AppID: app, AccountID: &acc.ID, AccountLabel: label,
				UserID: &p.User.ID, UserName: name, Ip: clientOf(ctx).ip,
			}); err != nil {
				return internalError(err)
			}
			out.Body.Username, out.Body.Password = acc.Username, pw
			return nil
		})
		if err != nil {
			return nil, err
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-app-activity",
		Method:      http.MethodGet,
		Path:        "/apps/{id}/activity",
		Summary:     "Who revealed this service's passwords",
		Description: "The last 200 reveals, newest first.",
		Tags:        tags,
	}, func(ctx context.Context, in *AppIDPath) (*AppActivityOutput, error) {
		rows, err := h.q.ListAppSecretViews(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		out := &AppActivityOutput{}
		out.Body.Items = make([]AppSecretView, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = AppSecretView{
				ID: r.ID.String(), AccountLabel: r.AccountLabel, UserName: r.UserName, IP: r.Ip, CreatedAt: r.CreatedAt,
			}
		}
		return out, nil
	})
}
