package api

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/morche/backend/internal/sshpool"
	"github.com/morche/backend/internal/terminal"
)

// A shell inside a container rides the terminal manager: `docker exec -it`
// (or podman's) runs over the server's SSH in a PTY, so reconnects, replay,
// recordings and the audit log work as for a server shell.

var execUserPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}(:[A-Za-z0-9_.-]{1,64})?$`)

// execShells are the shells the panel may ask for; "" picks bash, else sh.
var execShells = map[string]bool{"": true, "bash": true, "sh": true, "ash": true, "zsh": true}

type execRefusal struct {
	status  int
	message string
}

func (e *execRefusal) Error() string { return e.message }

// containerShell resolves a container on the server and returns the command
// that opens a shell in it, what to feed stdin first (sudo's password), and
// a title for the session.
func (h *serverHandler) containerShell(ctx context.Context, serverID string, c *sshpool.Conn, container, user, shell string) (cmd, input, title, id string, err error) {
	if user != "" && !execUserPattern.MatchString(user) {
		return "", "", "", "", &execRefusal{http.StatusUnprocessableEntity, "That user name isn't valid."}
	}
	if !execShells[shell] {
		return "", "", "", "", &execRefusal{http.StatusUnprocessableEntity, "Pick bash, sh, ash or zsh."}
	}
	e, err := h.engine(ctx, serverID, c)
	if err != nil {
		return "", "", "", "", err
	}
	ins, _, err := e.client.Inspect(ctx, container, false)
	if err != nil {
		return "", "", "", "", &execRefusal{http.StatusNotFound, "This container doesn't exist any more."}
	}
	if !ins.State.Running || ins.State.Paused {
		return "", "", "", "", &execRefusal{http.StatusConflict, "Start the container first: a shell needs it running."}
	}
	name := strings.TrimPrefix(ins.Name, "/")

	inner := `if command -v bash >/dev/null 2>&1; then exec bash; else exec sh; fi`
	if shell != "" {
		inner = "exec " + shell
	}
	args := "exec -it -e TERM=xterm-256color -e COLORTERM=truecolor"
	if user != "" {
		args += " -u " + terminal.ShellQuote(user)
	}
	script := `cli=docker; command -v docker >/dev/null 2>&1 || cli=podman; exec "$cli" ` + args +
		" -- " + terminal.ShellQuote(ins.ID) + " sh -c " + terminal.ShellQuote(inner)

	cmd = "sh -c " + terminal.ShellQuote(script)
	if e.via == "sudo" {
		sh, err := h.rootShell(ctx, serverID, c)
		if err != nil {
			return "", "", "", "", err
		}
		cmd, input = sh.command(script)
	}
	title = name
	if user != "" {
		title += " (" + user + ")"
	}
	return cmd, input, title, ins.ID, nil
}
