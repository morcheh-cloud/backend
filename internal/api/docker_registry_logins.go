package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/jobs"
	"github.com/morche/backend/internal/sshpool"
	"github.com/morche/backend/internal/terminal"
)

// Signing a server's own Docker in to a registry (docker login), so the
// docker CLI, compose and tools like Watchtower on the server can pull from
// it too. Morche's own pulls never need this: they carry the login with them.

const dockerRegistryLoginKind = "docker-registry-login"

type DockerRegistrySignInBody struct {
	Remove bool `json:"remove,omitempty" required:"false" doc:"Sign out everywhere Morche signed in, then forget the registry"`
}

type dockerRegistryLoginParams struct {
	WorkspaceID string `json:"workspace_id"`
	RegistryID  string `json:"registry_id"`
	Remove      bool   `json:"remove,omitempty"`
}

type DockerRegistryLoginResult struct {
	SignedIn  int `json:"signed_in"`
	SignedOut int `json:"signed_out"`
	Failed    int `json:"failed"`
	Skipped   int `json:"skipped" doc:"Servers without Docker"`
}

func registerDockerRegistryLogins(api huma.API, h *serverHandler) {
	huma.Register(api, huma.Operation{
		OperationID:   "sign-in-docker-registry",
		Method:        http.MethodPost,
		Path:          "/workspaces/{id}/docker/registries/{registry}/sign-in",
		Summary:       "Sign the servers' Docker in to a registry",
		Description:   "Runs as a background job (kind `docker-registry-login`): `docker login` on every server the registry is for when `sign_in_on_servers` is on, and `docker logout` where Morche signed in before but the registry no longer covers (or signing in is off). With `remove`, signs out everywhere and then forgets the registry. The password goes in on stdin, never a command line.",
		Tags:          []string{"Containers"},
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		DockerRegistryPath
		Body DockerRegistrySignInBody
	}) (*JobOutput, error) {
		ws := uuid.MustParse(in.ID)
		r, err := h.q.GetDockerRegistry(ctx, sqlc.GetDockerRegistryParams{ID: uuid.MustParse(in.Registry), WorkspaceID: ws})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("No such registry")
		}
		if err != nil {
			return nil, internalError(err)
		}
		title := "Sign servers in to " + r.Address
		if in.Body.Remove {
			title = "Sign servers out of " + r.Address
		}
		return submit(ctx, h.jobs, jobs.Spec{
			Kind: dockerRegistryLoginKind, Title: title,
			Params: dockerRegistryLoginParams{WorkspaceID: in.ID, RegistryID: in.Registry, Remove: in.Body.Remove},
			Target: &JobPlace{Registry: in.Registry, Name: r.Name},
		})
	})
	h.jobs.Handle(dockerRegistryLoginKind, h.runDockerRegistryLogin)
}

type registryStep struct {
	server sqlc.ListWorkspaceServersRow
	out    bool // sign out
}

func (h *serverHandler) runDockerRegistryLogin(ctx context.Context, t *jobs.Task) (any, error) {
	var p dockerRegistryLoginParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	ws := uuid.MustParse(p.WorkspaceID)
	r, err := h.q.GetDockerRegistry(ctx, sqlc.GetDockerRegistryParams{ID: uuid.MustParse(p.RegistryID), WorkspaceID: ws})
	if err != nil {
		return nil, fmt.Errorf("the registry is gone")
	}
	servers, err := h.q.ListWorkspaceServers(ctx, ws)
	if err != nil {
		return nil, err
	}
	logins, err := h.q.ListDockerRegistryLogins(ctx, ws)
	if err != nil {
		return nil, err
	}
	had := map[uuid.UUID]bool{}
	for _, l := range logins {
		if l.RegistryID == r.ID {
			had[l.ServerID] = true
		}
	}
	pass := ""
	if len(r.PasswordEnc) > 0 {
		b, err := h.box.Open(r.PasswordEnc)
		if err != nil {
			return nil, fmt.Errorf("the saved password can't be read")
		}
		pass = string(b)
	}

	var steps []registryStep
	for _, s := range servers {
		in := !p.Remove && r.SignInOnServers && registryCovers(r, s.ID)
		switch {
		case in:
			steps = append(steps, registryStep{server: s})
		case had[s.ID]:
			steps = append(steps, registryStep{server: s, out: true})
		}
	}
	res := DockerRegistryLoginResult{}
	if len(steps) == 0 {
		t.Logf("Nothing to do: no server to sign in or out.")
	}
	var mu sync.Mutex
	done := 0
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	t.Update(func(pr *jobs.Progress) { pr.Phase, pr.ItemsTotal = "Signing in", len(steps) })
	for _, st := range steps {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			as, msg, err := h.registryLogin(ctx, st.server.ID.String(), r, pass, st.out)
			mu.Lock()
			defer mu.Unlock()
			done++
			name := st.server.Name
			switch {
			case errors.Is(err, errNoDocker):
				res.Skipped++
				t.Logf("%s: no Docker here, skipped", name)
				_ = h.q.DeleteDockerRegistryLogin(ctx, sqlc.DeleteDockerRegistryLoginParams{RegistryID: r.ID, ServerID: st.server.ID})
			case err != nil:
				res.Failed++
				t.Logf("%s: %s", name, err.Error())
				if st.out {
					// Keep the row: the login may still be there.
					_ = h.q.UpsertDockerRegistryLogin(ctx, sqlc.UpsertDockerRegistryLoginParams{RegistryID: r.ID, ServerID: st.server.ID, Ok: false, Message: "Couldn't sign out: " + err.Error(), AsUser: as})
				} else {
					_ = h.q.UpsertDockerRegistryLogin(ctx, sqlc.UpsertDockerRegistryLoginParams{RegistryID: r.ID, ServerID: st.server.ID, Ok: false, Message: err.Error(), AsUser: as})
				}
			case st.out:
				res.SignedOut++
				t.Logf("%s: signed out", name)
				_ = h.q.DeleteDockerRegistryLogin(ctx, sqlc.DeleteDockerRegistryLoginParams{RegistryID: r.ID, ServerID: st.server.ID})
			default:
				res.SignedIn++
				t.Logf("%s: %s (as %s)", name, msg, as)
				_ = h.q.UpsertDockerRegistryLogin(ctx, sqlc.UpsertDockerRegistryLoginParams{RegistryID: r.ID, ServerID: st.server.ID, Ok: true, Message: msg, AsUser: as})
			}
			t.Update(func(pr *jobs.Progress) { pr.Items, pr.Current = done, name })
		}()
	}
	wg.Wait()
	if p.Remove {
		if res.Failed > 0 {
			return res, fmt.Errorf("couldn't sign out on %d server(s); the registry was kept, so you can try again", res.Failed)
		}
		if _, err := h.q.DeleteDockerRegistry(ctx, sqlc.DeleteDockerRegistryParams{ID: r.ID, WorkspaceID: ws}); err != nil {
			return res, err
		}
		t.Logf("Forgot the registry %s.", r.Name)
	}
	t.Update(func(pr *jobs.Progress) { pr.Phase = "Done" })
	if res.Failed > 0 && res.SignedIn+res.SignedOut == 0 {
		return res, fmt.Errorf("failed on every server (%d)", res.Failed)
	}
	return res, nil
}

// registryLogin runs docker login (or logout) on one server, as root when
// it can. It answers whose Docker config it went into.
func (h *serverHandler) registryLogin(ctx context.Context, serverID string, r sqlc.DockerRegistry, pass string, out bool) (as, msg string, err error) {
	s, err := h.get(ctx, serverID)
	if err != nil {
		return "", "", err
	}
	as = s.Username
	host := terminal.ShellQuote(registryServer(r.Address))
	if !out && strings.TrimSpace(r.Username) == "" {
		return as, "", fmt.Errorf("the registry login has no username")
	}
	err = h.withConn(ctx, serverID, func(c *sshpool.Conn) error {
		sh, err := h.rootShell(ctx, serverID, c)
		if err != nil {
			return err
		}
		if sh.priv != privUser {
			as = "root"
		}
		script := "docker logout " + host
		input := ""
		if !out {
			script = "docker login --username " + terminal.ShellQuote(r.Username) + " --password-stdin " + host
			input = pass
		}
		script = "command -v docker >/dev/null 2>&1 || { echo " + noDockerMark + "; exit 0; }; " + script
		cmd, prefix := wrapCommand(sh.priv, sh.password, "", script)
		got, err := runLogged(ctx, c, cmd, prefix+input, 60*time.Second, logAs{script: script, asRoot: sh.priv != privUser, secrets: []string{pass}})
		if err != nil {
			return fmt.Errorf("%s", scrub(problemText(err), pass))
		}
		if strings.Contains(got, noDockerMark) {
			return errNoDocker
		}
		msg = scrub(lastLine(got), pass)
		return nil
	})
	if msg == "" {
		msg = "Login Succeeded"
	}
	return as, msg, err
}

const noDockerMark = "MORCHE_NO_DOCKER"

var errNoDocker = errors.New("Docker isn't installed")

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
