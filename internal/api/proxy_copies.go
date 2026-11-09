package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/proxy"
	"github.com/morcheh/backend/internal/sshpool"
)

type ProxyKeptPagesInput struct {
	ProxyHostPath
	Limit int `query:"limit" minimum:"1" maximum:"1000" default:"300" doc:"Most pages listed, newest first"`
}

type ProxyKeptPagesResult struct {
	OK       bool   `json:"ok"`
	ExitCode int    `json:"exit_code,omitempty"`
	Output   string `json:"output,omitempty" doc:"The script's output when it failed"`
	proxy.KeptPages
}

func (h *proxyHandler) registerKeptPages(api huma.API, base string, tags []string) {
	huma.Register(api, huma.Operation{
		OperationID: "list-proxy-host-kept-pages", Method: http.MethodGet, Path: base + "/hosts/{host}/cache/pages",
		Summary:     "The pages a site keeps a copy of",
		Description: "The answers the proxy keeps for the site (its cache, or Always online's copies), newest first, with how old each copy is: what visitors would still get while the app is down.",
		Tags:        tags,
	}, func(ctx context.Context, in *ProxyKeptPagesInput) (*struct{ Body ProxyKeptPagesResult }, error) {
		r, d, err := h.getProxy(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if !d.Capabilities().Cache {
			return nil, huma.Error422UnprocessableEntity(d.Label() + " can't cache answers")
		}
		host, err := h.s.q.GetProxyHost(ctx, sqlc.GetProxyHostParams{ID: uuid.MustParse(in.Host), ProxyID: r.Proxy.ID})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("site not found")
		} else if err != nil {
			return nil, internalError(err)
		}
		limit := in.Limit
		if limit <= 0 {
			limit = 300
		}
		out := &struct{ Body ProxyKeptPagesResult }{}
		server := r.Proxy.ServerID.String()
		err = h.s.withConn(ctx, server, func(c *sshpool.Conn) error {
			sh, err := h.shell(ctx, r.Proxy, c)
			if err != nil {
				return err
			}
			res, err := sh.exec(ctx, d.KeptPagesScript(in.Host, limit), 2*time.Minute, 1<<20)
			if err != nil {
				return err
			}
			text := string(res.output)
			pages, ok := proxy.ParseKeptPages(text, configOf(host).Domains)
			if res.code != 0 || !ok {
				out.Body = ProxyKeptPagesResult{ExitCode: res.code, Output: strings.TrimSpace(text)}
				return nil
			}
			if pages.Pages == nil {
				pages.Pages = []proxy.KeptPage{}
			}
			out.Body = ProxyKeptPagesResult{OK: true, KeptPages: pages}
			return nil
		})
		if err != nil {
			return nil, toProblem(err)
		}
		return out, nil
	})
}
