package api

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/ports"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/terminal"
)

func registerPorts(api huma.API, h *serverHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "list-ports",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/ports",
		Summary:     "List open ports",
		Description: "Listening TCP and UDP sockets (ss, else netstat), each with the process holding it, its systemd unit, " +
			"the Docker/Podman container a published port forwards to, and a best guess at the service. " +
			"Read-only; runs as root through `sudo -n` when that works without a password, else only the login user's processes are named.",
		Tags: []string{"Network"},
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body ports.PortsReport }, error) {
		var out string
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) (err error) {
			out, err = run(ctx, c, "sh -c "+terminal.ShellQuote(ports.Script))
			return err
		})
		if err != nil {
			return nil, toProblem(err)
		}
		return &struct{ Body ports.PortsReport }{ports.Parse(out, time.Now())}, nil
	})
}
