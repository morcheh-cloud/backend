package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/appicon"
	"github.com/morcheh/backend/internal/database/sqlc"
)

// A service's logo is its favicon (fetched by the backend whenever the
// address changes, never by the browser), an uploaded image, or a Lucide icon
// the panel draws. Both images are kept, so switching back costs nothing.

type AppLogoOutput struct {
	ContentType  string `header:"Content-Type"`
	CacheControl string `header:"Cache-Control"`
	NoSniff      string `header:"X-Content-Type-Options"`
	CSP          string `header:"Content-Security-Policy"`
	Body         []byte
}

type AppLogoUpload struct {
	AppIDPath
	RawBody []byte `contentType:"application/octet-stream"`
}

func registerAppLogos(api huma.API, h *appHandler) {
	tags := []string{"apps"}

	huma.Register(api, huma.Operation{
		OperationID: "get-app-logo",
		Method:      http.MethodGet,
		Path:        "/apps/{id}/logo",
		Summary:     "A service's logo image",
		Description: "The image its logo_kind picks. Use logo_url from the service, which changes with the image.",
		Tags:        tags,
		Responses: map[string]*huma.Response{"200": {
			Description: "The image",
			Content:     map[string]*huma.MediaType{"image/*": {Schema: &huma.Schema{Type: "string", Format: "binary"}}},
		}},
	}, func(ctx context.Context, in *AppIDPath) (*AppLogoOutput, error) {
		app, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		source := map[string]string{"auto": "favicon", "upload": "upload"}[app.LogoKind]
		if source == "" {
			return nil, huma.Error404NotFound("this service has no logo image")
		}
		logo, err := h.q.GetAppLogo(ctx, sqlc.GetAppLogoParams{AppID: app.ID, Source: source})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("this service has no logo image")
		}
		if err != nil {
			return nil, internalError(err)
		}
		// An SVG opened on its own must not run anything.
		return &AppLogoOutput{
			ContentType: logo.ContentType, CacheControl: "private, max-age=86400", NoSniff: "nosniff",
			CSP: "default-src 'none'; style-src 'unsafe-inline'; sandbox", Body: logo.Data,
		}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:  "put-app-logo",
		Method:       http.MethodPut,
		Path:         "/apps/{id}/logo",
		Summary:      "Upload a service's logo",
		Description:  "The raw image (PNG, JPEG, GIF, WebP, ICO or SVG, up to 1 MB); its type is read from the bytes. The service switches to it (logo_kind = upload).",
		Tags:         tags,
		MaxBodyBytes: appicon.MaxSize,
	}, func(ctx context.Context, in *AppLogoUpload) (*AppOutput, error) {
		app, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		ct, ok := appicon.Sniff(in.RawBody)
		if !ok {
			return nil, huma.Error422UnprocessableEntity("Use a PNG, JPEG, GIF, WebP, ICO or SVG image.")
		}
		var row sqlc.App
		err = h.a.inTx(ctx, func(q *sqlc.Queries) error {
			if err := q.PutAppLogo(ctx, sqlc.PutAppLogoParams{AppID: app.ID, Source: "upload", ContentType: ct, Data: in.RawBody}); err != nil {
				return internalError(err)
			}
			var err error
			if row, err = q.SetAppLogoKind(ctx, sqlc.SetAppLogoKindParams{ID: app.ID, LogoKind: "upload"}); err != nil {
				return internalError(err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return h.one(ctx, row, principalOf(ctx).Level)
	})

	huma.Register(api, huma.Operation{
		OperationID: "refetch-app-icon",
		Method:      http.MethodPost,
		Path:        "/apps/{id}/refetch-icon",
		Summary:     "Fetch a service's favicon again",
		Description: "Waits for it. Only the stored favicon changes; logo_kind stays as it is.",
		Tags:        tags,
	}, func(ctx context.Context, in *AppIDPath) (*AppOutput, error) {
		app, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		fetchCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		icon, err := appicon.Fetch(fetchCtx, app.Address)
		if err != nil {
			return nil, huma.Error422UnprocessableEntity("Couldn't get an icon from this address. Upload one instead.")
		}
		if _, err := h.q.PutAppFavicon(ctx, sqlc.PutAppFaviconParams{
			AppID: app.ID, Address: app.Address, ContentType: icon.ContentType, Data: icon.Data,
		}); err != nil {
			return nil, internalError(err)
		}
		return h.current(ctx, app.ID)
	})
}

// current answers a service as it is now, at the caller's level.
func (h *appHandler) current(ctx context.Context, id uuid.UUID) (*AppOutput, error) {
	row, err := h.q.GetApp(ctx, id)
	if err != nil {
		return nil, internalError(err)
	}
	return h.one(ctx, row, principalOf(ctx).Level)
}

// refreshIcon fetches a service's favicon in the background, after its
// address was set. Failures are only logged, without the address.
func (h *appHandler) refreshIcon(id uuid.UUID, address string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	icon, err := appicon.Fetch(ctx, address)
	if err != nil {
		slog.Warn("fetch service icon", "app", id, "error", err)
		return
	}
	if _, err := h.q.PutAppFavicon(ctx, sqlc.PutAppFaviconParams{
		AppID: id, Address: address, ContentType: icon.ContentType, Data: icon.Data,
	}); err != nil {
		slog.Warn("store service icon", "app", id, "error", err)
	}
}
