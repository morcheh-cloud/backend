package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/cmdlog"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/terminal"
)

// GitOps: a compose project can come from a git repository. Morche keeps a
// shallow clone in the project's folder on the server and deploys it again
// when the branch moves: by hand, from a webhook (GitHub, GitLab, Gitea…) or
// by polling the branch. The access token is sealed in the database and only
// ever reaches the server on stdin, never in a command line.

const dockerGitDeployKind = "docker-git-deploy"

var (
	gitBranchRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._/-]{0,199}$`)
	gitPathRe   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._/ -]{0,199}$`)
	gitUserRe   = regexp.MustCompile(`^[A-Za-z0-9._@+-]{0,100}$`)
)

type DockerGitSource struct {
	Project        string     `json:"project"`
	Dir            string     `json:"dir" doc:"Where the clone lives on the server"`
	RepoURL        string     `json:"repo_url"`
	Branch         string     `json:"branch"`
	ComposePath    string     `json:"compose_path" doc:"The compose file inside the repository; empty = compose.yaml (or its other usual names) at the top"`
	Username       string     `json:"username"`
	HasToken       bool       `json:"has_token"`
	AutoDeploy     bool       `json:"auto_deploy" doc:"Deploy when the webhook is called or polling sees a new commit"`
	PollMinutes    int        `json:"poll_minutes" doc:"Look for new commits every this many minutes; 0 = only the webhook"`
	WebhookToken   string     `json:"webhook_token,omitempty" doc:"The secret in the webhook address (Engineer and up)"`
	LastCommit     string     `json:"last_commit"`
	LastMessage    string     `json:"last_message"`
	LastAuthor     string     `json:"last_author"`
	LastDeployedAt *time.Time `json:"last_deployed_at,omitempty"`
	LastCheckedAt  *time.Time `json:"last_checked_at,omitempty"`
	LastError      string     `json:"last_error"`
	Deploying      bool       `json:"deploying"`
	By             string     `json:"by" doc:"Whose access webhook and polling deploys run with"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type DockerGitState struct {
	Source *DockerGitSource `json:"source" doc:"null when the project isn't connected to a repository"`
}

type DockerGitBody struct {
	RepoURL     string `json:"repo_url" maxLength:"500" doc:"An https address of the repository"`
	Branch      string `json:"branch,omitempty" maxLength:"200"`
	ComposePath string `json:"compose_path,omitempty" maxLength:"200"`
	Username    string `json:"username,omitempty" maxLength:"100"`
	Token       string `json:"token,omitempty" maxLength:"4000" doc:"An access token for a private repository; blank keeps the saved one"`
	ClearToken  bool   `json:"clear_token,omitempty" doc:"Forget the saved token"`
	AutoDeploy  bool   `json:"auto_deploy"`
	PollMinutes int    `json:"poll_minutes" minimum:"0" maximum:"1440"`
	Deploy      bool   `json:"deploy,omitempty" doc:"Deploy right after saving (a job)"`
}

type DockerGitCreateBody struct {
	Name string `json:"name" maxLength:"63"`
	DockerGitBody
}

type DockerGitDeployBody struct {
	Force bool `json:"force,omitempty" doc:"Deploy even when the branch hasn't moved"`
}

type DockerGitSaved struct {
	Source DockerGitSource `json:"source"`
	Job    *Job            `json:"job,omitempty"`
}

type DockerGitHookInput struct {
	Token   string `path:"token" maxLength:"100"`
	RawBody []byte `required:"false"`
}

type DockerGitHookOutput struct {
	Status int
	Body   struct {
		OK      bool    `json:"ok"`
		JobID   *string `json:"job_id,omitempty"`
		Message string  `json:"message"`
	}
}

type gitDeployParams struct {
	ServerID string `json:"server_id"`
	Project  string `json:"project"`
	Force    bool   `json:"force,omitempty"`
	Trigger  string `json:"trigger"`
}

// gitBusy keeps one deploy per project at a time.
var gitBusy sync.Map

func gitKey(server, project string) string { return server + "/" + project }

func hookHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (h *serverHandler) gitSourceOut(s sqlc.DockerGitSource, showHook bool) DockerGitSource {
	_, busy := gitBusy.Load(gitKey(s.ServerID.String(), s.Project))
	out := DockerGitSource{
		Project: s.Project, Dir: s.Dir, RepoURL: s.RepoUrl, Branch: s.Branch, ComposePath: s.ComposePath,
		Username: s.Username, HasToken: s.TokenEnc != nil, AutoDeploy: s.AutoDeploy, PollMinutes: int(s.PollMinutes),
		LastCommit: s.LastCommit, LastMessage: s.LastMessage, LastAuthor: s.LastAuthor,
		LastDeployedAt: s.LastDeployedAt, LastCheckedAt: s.LastCheckedAt, LastError: s.LastError,
		Deploying: busy, By: s.CreatedByName, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
	if showHook {
		if t, err := h.box.Open(s.WebhookEnc); err == nil {
			out.WebhookToken = t
		}
	}
	return out
}

// checkGitBody tidies and checks what a person typed.
func checkGitBody(b *DockerGitBody) error {
	b.RepoURL = strings.TrimSpace(b.RepoURL)
	b.Branch = strings.TrimSpace(b.Branch)
	b.ComposePath = strings.Trim(strings.TrimSpace(b.ComposePath), "/")
	b.Username = strings.TrimSpace(b.Username)
	b.Token = strings.TrimSpace(b.Token)
	u, err := url.Parse(b.RepoURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fieldError("body.repo_url", "Give the repository's https address, e.g. https://github.com/team/app.git", b.RepoURL)
	}
	if u.User != nil {
		return fieldError("body.repo_url", "Leave the login out of the address: put the token in its own field", "")
	}
	if strings.ContainsAny(b.RepoURL, " \t\n'\"") {
		return fieldError("body.repo_url", "The address can't hold spaces or quotes", b.RepoURL)
	}
	if b.Branch == "" {
		b.Branch = "main"
	}
	if !gitBranchRe.MatchString(b.Branch) || strings.Contains(b.Branch, "..") {
		return fieldError("body.branch", "That isn't a branch name", b.Branch)
	}
	if b.ComposePath != "" && (!gitPathRe.MatchString(b.ComposePath) || strings.Contains(b.ComposePath, "..")) {
		return fieldError("body.compose_path", "Give a path inside the repository, e.g. deploy/compose.yaml", b.ComposePath)
	}
	if !gitUserRe.MatchString(b.Username) {
		return fieldError("body.username", "That user name isn't valid", b.Username)
	}
	if strings.ContainsAny(b.Token, "\n\r") {
		return fieldError("body.token", "The token is one line", "")
	}
	return nil
}

// gitPrelude starts a git script: reads the token from stdin, checks git is
// there and sets an askpass helper that hands git the user and token from
// the environment (so neither appears in argv).
func gitPrelude(user string) string {
	if user == "" {
		user = "x-access-token"
	}
	return `IFS= read -r MT || true
command -v git >/dev/null 2>&1 || { echo "git isn't installed on the server (install the git package)" >&2; exit 69; }
export GIT_TERMINAL_PROMPT=0
if [ -n "$MT" ]; then
  A=$(mktemp) || exit 3
  trap 'rm -f "$A"' EXIT
  cat > "$A" <<'MORCHEH_ASKPASS'
#!/bin/sh
case "$1" in Username*) printf '%s\n' "$MORCHEH_GIT_USER" ;; *) printf '%s\n' "$MORCHEH_GIT_TOKEN" ;; esac
MORCHEH_ASKPASS
  chmod 700 "$A"
  export GIT_ASKPASS="$A" MORCHEH_GIT_USER=` + terminal.ShellQuote(user) + ` MORCHEH_GIT_TOKEN="$MT"
fi
g() { git -c safe.directory='*' -c credential.helper= "$@"; }
`
}

// gitRun runs a git script with the token fed on stdin after sudo's prefix.
func gitRun(ctx context.Context, sh *rootShell, script, token string, timeout time.Duration) (string, error) {
	cmd, prefix := sh.command(script)
	stdin := prefix + token + "\n"
	return runLogged(ctx, sh.c, cmd, stdin, timeout, sh.hiding(false, token).logAs(script))
}

// gitProblem turns git's complaints into plain words.
func gitProblem(err error) error {
	var ce *cmdError
	if !errors.As(err, &ce) {
		return err
	}
	m := ce.msg
	switch {
	case strings.Contains(m, "could not read Username"), strings.Contains(m, "Authentication failed"),
		strings.Contains(m, "terminal prompts disabled"), strings.Contains(m, "403"), strings.Contains(m, "401"):
		return errors.New("The repository refused the login: it needs an access token, or the saved one is wrong or expired")
	case strings.Contains(m, "couldn't find remote ref"), strings.Contains(m, "Remote branch") && strings.Contains(m, "not found"):
		return errors.New("The repository has no such branch")
	case strings.Contains(m, "not found") && strings.Contains(m, "repository"):
		return errors.New("No repository at that address (or it's private and needs a token)")
	case strings.Contains(m, "Could not resolve host"):
		return errors.New("The server can't find the repository's host (check its DNS and internet access)")
	}
	return err
}

type gitFetchResult struct {
	old, new, subject, author, file string
}

// gitFetch brings the clone in dir up to the branch's head and finds the
// compose file.
func gitFetch(ctx context.Context, sh *rootShell, s sqlc.DockerGitSource, token string) (gitFetchResult, error) {
	q := terminal.ShellQuote
	find := `F=""
for f in ` + strings.Join(composeFileNames, " ") + `; do if [ -f "$f" ]; then F=$f; break; fi; done`
	if s.ComposePath != "" {
		find = `F=""; [ -f ` + q(s.ComposePath) + ` ] && F=` + q(s.ComposePath)
	}
	script := gitPrelude(s.Username) + `D=` + q(s.Dir) + `
mkdir -p "$D" && cd "$D" || exit 3
[ -d .git ] || g init -q || exit 3
if g remote get-url origin >/dev/null 2>&1; then g remote set-url origin ` + q(s.RepoUrl) + `; else g remote add origin ` + q(s.RepoUrl) + `; fi || exit 3
OLD=$(g rev-parse -q --verify HEAD 2>/dev/null || true)
g fetch -q --depth 1 origin ` + q(s.Branch) + ` || exit 68
g reset -q --hard FETCH_HEAD || exit 3
` + find + `
printf 'old\t%s\nnew\t%s\n' "$OLD" "$(g rev-parse HEAD)"
printf 'subject\t%s\nauthor\t%s\nfile\t%s\n' "$(g log -1 --format=%s)" "$(g log -1 --format=%an)" "$F"
`
	out, err := gitRun(ctx, sh, script, token, 5*time.Minute)
	if err != nil {
		return gitFetchResult{}, gitProblem(err)
	}
	var r gitFetchResult
	for line := range strings.SplitSeq(out, "\n") {
		k, v, _ := strings.Cut(line, "\t")
		switch k {
		case "old":
			r.old = v
		case "new":
			r.new = v
		case "subject":
			r.subject = v
		case "author":
			r.author = v
		case "file":
			r.file = v
		}
	}
	return r, nil
}

// gitHead asks the repository for the branch's head without touching the
// clone.
func gitHead(ctx context.Context, sh *rootShell, s sqlc.DockerGitSource, token string) (string, error) {
	script := gitPrelude(s.Username) + `g ls-remote ` + terminal.ShellQuote(s.RepoUrl) + ` ` + terminal.ShellQuote("refs/heads/"+s.Branch) + ` | cut -f1`
	out, err := gitRun(ctx, sh, script, token, time.Minute)
	if err != nil {
		return "", gitProblem(err)
	}
	head := strings.TrimSpace(out)
	if head == "" {
		return "", errors.New("The repository has no such branch")
	}
	return head, nil
}

func (h *serverHandler) gitToken(s sqlc.DockerGitSource) (string, error) {
	if s.TokenEnc == nil {
		return "", nil
	}
	return h.box.Open(s.TokenEnc)
}

func shortCommit(c string) string {
	if len(c) > 7 {
		return c[:7]
	}
	return c
}

func (h *serverHandler) runGitDeploy(ctx context.Context, t *jobs.Task) (any, error) {
	var p gitDeployParams
	if err := t.Decode(&p); err != nil {
		return nil, err
	}
	key := gitKey(p.ServerID, p.Project)
	if _, busy := gitBusy.LoadOrStore(key, true); busy {
		return nil, jobError(errors.New("Another deploy of this project is running"))
	}
	defer gitBusy.Delete(key)
	sid, err := uuid.Parse(p.ServerID)
	if err != nil {
		return nil, err
	}
	s, err := h.q.GetDockerGitSource(ctx, sqlc.GetDockerGitSourceParams{ServerID: sid, Project: p.Project})
	if err != nil {
		if isNotFound(err) {
			return nil, jobError(errors.New("This project isn't connected to a repository any more"))
		}
		return nil, err
	}
	token, err := h.gitToken(s)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (any, error) {
		_ = h.q.DockerGitChecked(context.WithoutCancel(ctx), sqlc.DockerGitCheckedParams{ServerID: sid, Project: p.Project, LastError: err.Error()})
		return nil, jobError(err)
	}

	t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Current = "Fetching", s.RepoUrl+" @ "+s.Branch })
	t.Logf("Fetching %s (%s)", s.RepoUrl, s.Branch)
	var r gitFetchResult
	err = h.withShell(ctx, p.ServerID, func(_ *sshpool.Conn, sh *rootShell) error {
		var err error
		r, err = gitFetch(ctx, sh, s, token)
		return err
	})
	if err != nil {
		return fail(shellFailure(err, ""))
	}
	t.Logf("Commit %s: %s (%s)", shortCommit(r.new), r.subject, r.author)
	if !p.Force && r.new == r.old && r.new == s.LastCommit {
		t.Logf("Nothing new since the last deploy")
		_ = h.q.DockerGitChecked(ctx, sqlc.DockerGitCheckedParams{ServerID: sid, Project: p.Project})
		return map[string]any{"project": p.Project, "commit": r.new, "deployed": false}, nil
	}
	if r.file == "" {
		want := cmpOr(s.ComposePath, strings.Join(composeFileNames, ", "))
		return fail(errors.New("The repository has no compose file (looked for " + want + ")"))
	}

	file := path.Join(s.Dir, r.file)
	dir := path.Dir(file)
	_, root, _ := h.dockerProjects(ctx, p.ServerID)
	cp := dockerComposeParams{
		ServerID: p.ServerID, Project: p.Project, Action: "up", Dir: dir, Files: []string{file},
		Managed: root != "" && path.Dir(dir) == root, Root: root,
	}
	var images []string
	_ = h.withShell(ctx, p.ServerID, func(_ *sshpool.Conn, sh *rootShell) error {
		var err error
		images, err = composeImages(ctx, sh, cp)
		return err
	})
	for _, image := range images {
		// An image built from the repository can't be pulled: compose
		// builds it below.
		if err := h.pullWithAuth(ctx, t, p.ServerID, []string{image}, false); err != nil {
			t.Logf("Couldn't pull %s, it'll be built or used as it is", image)
		}
	}
	t.Update(func(pr *jobs.Progress) { pr.Phase, pr.Current = "Deploying", p.Project })
	err = h.withShell(ctx, p.ServerID, func(_ *sshpool.Conn, sh *rootShell) error {
		return h.composeRun(ctx, t, sh, cp, h.composeUpArgs(ctx, p.ServerID)+" --build")
	})
	if err != nil {
		return fail(err)
	}

	dp := DockerProject{Name: p.Project, Dir: dir, Files: []string{file}, Managed: cp.Managed}
	if d, err := h.readProjectFiles(ctx, p.ServerID, dp); err == nil && d.Readable && !d.Missing {
		note := "Commit " + shortCommit(r.new)
		if r.subject != "" {
			note += ": " + r.subject
		}
		h.recordProjectVersion(ctx, p.ServerID, p.Project, d.Compose, d.Env, d.HasEnv, "git", note)
	}
	if len(r.subject) > 300 {
		r.subject = r.subject[:300]
	}
	_ = h.q.DockerGitDeployed(ctx, sqlc.DockerGitDeployedParams{
		ServerID: sid, Project: p.Project, LastCommit: r.new, LastMessage: r.subject, LastAuthor: r.author,
	})
	t.Update(func(pr *jobs.Progress) { pr.Phase = "Done" })
	return map[string]any{"project": p.Project, "commit": r.new, "deployed": true}, nil
}

// submitGitDeploy starts a deploy job. by is set for deploys no person
// started (webhook, polling), so the job belongs to whoever set it up.
func (h *serverHandler) submitGitDeploy(ctx context.Context, s sqlc.DockerGitSource, force bool, trigger string, by *uuid.UUID) (*JobOutput, error) {
	srv, err := h.q.GetServer(ctx, s.ServerID)
	if err != nil {
		return nil, internalError(err)
	}
	spec := jobs.Spec{
		Kind:  dockerGitDeployKind,
		Title: "Deploy " + s.Project + " from git on " + srv.Name,
		Params: gitDeployParams{
			ServerID: s.ServerID.String(), Project: s.Project, Force: force, Trigger: trigger,
		},
		Refs:   placeRefs(s.ServerID.String()),
		Target: &JobPlace{ServerID: s.ServerID.String(), Name: srv.Name, Path: s.Dir},
	}
	if by != nil {
		spec.CreatedBy = by
		j, err := h.jobs.Submit(ctx, spec)
		if err != nil {
			return nil, internalError(err)
		}
		return &JobOutput{toJob(j, false)}, nil
	}
	return submit(ctx, h.jobs, spec)
}

// saveGitSource checks the repository can be read from the server, then
// keeps the source.
func (h *serverHandler) saveGitSource(ctx context.Context, serverID, project, dir string, b DockerGitBody, prev *sqlc.DockerGitSource) (sqlc.DockerGitSource, error) {
	sid, _ := uuid.Parse(serverID)
	tokenEnc := []byte(nil)
	token := b.Token
	switch {
	case b.ClearToken:
		token = ""
	case token != "":
		tokenEnc = h.box.Seal(token)
	case prev != nil && prev.TokenEnc != nil:
		tokenEnc = prev.TokenEnc
		var err error
		if token, err = h.box.Open(prev.TokenEnc); err != nil {
			return sqlc.DockerGitSource{}, internalError(err)
		}
	}
	probe := sqlc.DockerGitSource{RepoUrl: b.RepoURL, Branch: b.Branch, Username: b.Username}
	err := h.withShell(ctx, serverID, func(_ *sshpool.Conn, sh *rootShell) error {
		_, err := gitHead(ctx, sh, probe, token)
		return err
	})
	if err != nil {
		var ce *cmdError
		if errors.As(err, &ce) && ce.code == 69 {
			return sqlc.DockerGitSource{}, huma.Error422UnprocessableEntity(ce.msg)
		}
		msg := problemText(err)
		switch {
		case strings.Contains(msg, "no such branch"):
			return sqlc.DockerGitSource{}, fieldError("body.branch", msg, b.Branch)
		case strings.Contains(msg, "refused the login"):
			return sqlc.DockerGitSource{}, fieldError("body.token", msg, "")
		}
		return sqlc.DockerGitSource{}, fieldError("body.repo_url", msg, b.RepoURL)
	}
	hook := pushToken()
	hookEnc, hookSum := h.box.Seal(hook), hookHash(hook)
	if prev != nil {
		hookEnc, hookSum = prev.WebhookEnc, prev.WebhookHash
	}
	pr := principalOf(ctx)
	s, err := h.q.UpsertDockerGitSource(ctx, sqlc.UpsertDockerGitSourceParams{
		ServerID: sid, Project: project, Dir: dir, RepoUrl: b.RepoURL, Branch: b.Branch,
		ComposePath: b.ComposePath, Username: b.Username, TokenEnc: tokenEnc,
		AutoDeploy: b.AutoDeploy, PollMinutes: int32(b.PollMinutes),
		WebhookEnc: hookEnc, WebhookHash: hookSum,
		CreatedBy: pr.ID(), CreatedByName: cmpOr(pr.User.FullName, pr.User.Username),
	})
	if err != nil {
		return s, internalError(err)
	}
	return s, nil
}

func (h *serverHandler) gitSource(ctx context.Context, in *DockerProjectPath) (sqlc.DockerGitSource, error) {
	sid, err := uuid.Parse(in.ID)
	if err != nil {
		return sqlc.DockerGitSource{}, huma.Error404NotFound("server not found")
	}
	s, err := h.q.GetDockerGitSource(ctx, sqlc.GetDockerGitSourceParams{ServerID: sid, Project: in.Project})
	if isNotFound(err) {
		return s, huma.Error404NotFound("This project isn't connected to a repository")
	}
	if err != nil {
		return s, internalError(err)
	}
	return s, nil
}

func registerDockerGit(api huma.API, h *serverHandler) {
	tags := []string{"Containers"}
	base := "/servers/{id}/docker/projects/{project}/git"

	huma.Register(api, huma.Operation{
		OperationID: "get-docker-project-git",
		Method:      http.MethodGet,
		Path:        base,
		Summary:     "A project's git repository",
		Description: "Where the project's files come from, the last deployed commit and the webhook's secret (Engineer and up). `source` is null when the project isn't connected.",
		Tags:        tags,
	}, func(ctx context.Context, in *DockerProjectPath) (*struct{ Body DockerGitState }, error) {
		sid, err := uuid.Parse(in.ID)
		if err != nil {
			return nil, huma.Error404NotFound("server not found")
		}
		out := &struct{ Body DockerGitState }{}
		s, err := h.q.GetDockerGitSource(ctx, sqlc.GetDockerGitSourceParams{ServerID: sid, Project: in.Project})
		if isNotFound(err) {
			return out, nil
		}
		if err != nil {
			return nil, internalError(err)
		}
		src := h.gitSourceOut(s, principalOf(ctx).Level >= auth.Engineer)
		out.Body.Source = &src
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "save-docker-project-git",
		Method:      http.MethodPut,
		Path:        base,
		Summary:     "Connect a project to a git repository",
		Description: "Checks the server can read the branch, then keeps the source. The next deploy clones the repository into the project's folder (tracked files are replaced, others such as .env stay). Webhook and polling deploys run with the access of whoever saved it last.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		DockerProjectPath
		Body DockerGitBody
	}) (*struct{ Body DockerGitSaved }, error) {
		b := in.Body
		if err := checkGitBody(&b); err != nil {
			return nil, err
		}
		p, _, err := h.dockerProject(ctx, in.ID, in.Project)
		if err != nil {
			return nil, err
		}
		if p.Dir == "" {
			return nil, huma.Error422UnprocessableEntity("Its containers don't say which folder the project is in")
		}
		var prev *sqlc.DockerGitSource
		if s, err := h.gitSource(ctx, &in.DockerProjectPath); err == nil {
			prev = &s
		}
		dir := p.Dir
		if prev != nil {
			dir = prev.Dir
		} else if b.ComposePath != "" {
			// The compose file sits in a sub-folder: the clone is the folder
			// above it.
			for range strings.Split(path.Dir(b.ComposePath), "/") {
				if path.Dir(b.ComposePath) != "." {
					dir = path.Dir(dir)
				}
			}
		}
		s, err := h.saveGitSource(ctx, in.ID, p.Name, dir, b, prev)
		if err != nil {
			return nil, err
		}
		out := &struct{ Body DockerGitSaved }{DockerGitSaved{Source: h.gitSourceOut(s, true)}}
		if b.Deploy {
			j, err := h.submitGitDeploy(ctx, s, true, "manual", nil)
			if err != nil {
				return nil, err
			}
			out.Body.Job = &j.Body
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-docker-project-git",
		Method:        http.MethodDelete,
		Path:          base,
		Summary:       "Disconnect a project from its repository",
		Description:   "The files and the clone stay on the server; only Morche stops following the repository.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *DockerProjectPath) (*struct{}, error) {
		sid, _ := uuid.Parse(in.ID)
		n, err := h.q.DeleteDockerGitSource(ctx, sqlc.DeleteDockerGitSourceParams{ServerID: sid, Project: in.Project})
		if err != nil {
			return nil, internalError(err)
		}
		if n == 0 {
			return nil, huma.Error404NotFound("This project isn't connected to a repository")
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "deploy-docker-project-git",
		Method:        http.MethodPost,
		Path:          base + "/deploy",
		Summary:       "Deploy a project from its repository",
		Description:   "Fetches the branch, and when it moved (or with `force`) runs compose up with --build. Runs as a job (kind `docker-git-deploy`).",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		DockerProjectPath
		Body DockerGitDeployBody
	}) (*JobOutput, error) {
		s, err := h.gitSource(ctx, &in.DockerProjectPath)
		if err != nil {
			return nil, err
		}
		if _, busy := gitBusy.Load(gitKey(in.ID, in.Project)); busy {
			return nil, huma.Error409Conflict("A deploy of this project is running")
		}
		return h.submitGitDeploy(ctx, s, in.Body.Force, "manual", nil)
	})

	huma.Register(api, huma.Operation{
		OperationID: "reset-docker-project-webhook",
		Method:      http.MethodPost,
		Path:        base + "/webhook-token",
		Summary:     "Make a new webhook address",
		Description: "The old address stops working at once.",
		Tags:        tags,
	}, func(ctx context.Context, in *DockerProjectPath) (*struct{ Body DockerGitSource }, error) {
		if _, err := h.gitSource(ctx, in); err != nil {
			return nil, err
		}
		sid, _ := uuid.Parse(in.ID)
		hook := pushToken()
		s, err := h.q.SetDockerGitWebhook(ctx, sqlc.SetDockerGitWebhookParams{
			ServerID: sid, Project: in.Project, WebhookEnc: h.box.Seal(hook), WebhookHash: hookHash(hook),
		})
		if err != nil {
			return nil, internalError(err)
		}
		return &struct{ Body DockerGitSource }{h.gitSourceOut(s, true)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-docker-project-git",
		Method:        http.MethodPost,
		Path:          "/servers/{id}/docker/projects/git",
		Summary:       "Make a compose project from a git repository",
		Description:   "Clones the repository into a new folder under the projects folder and deploys it (a job, kind `docker-git-deploy`).",
		Tags:          tags,
		DefaultStatus: http.StatusAccepted,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body DockerGitCreateBody
	}) (*struct{ Body DockerGitSaved }, error) {
		b := in.Body
		if !projectNameRe.MatchString(b.Name) {
			return nil, fieldError("body.name", "Use lowercase letters, digits, - and _ (starting with a letter or digit)", b.Name)
		}
		if err := checkGitBody(&b.DockerGitBody); err != nil {
			return nil, err
		}
		ps, root, err := h.dockerProjects(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		for _, p := range ps {
			if p.Name == b.Name {
				return nil, fieldError("body.name", "This server already has a project called "+b.Name, b.Name)
			}
		}
		dir := path.Join(root, b.Name)
		// Refuse a folder that already holds something.
		err = h.withShell(ctx, in.ID, func(_ *sshpool.Conn, sh *rootShell) error {
			_, err := sh.run(ctx, "d="+terminal.ShellQuote(dir)+`; if [ -e "$d" ] && [ "$(ls -A "$d" 2>/dev/null)" ]; then echo "$d already holds files" >&2; exit 66; fi`)
			return err
		})
		if err != nil {
			var ce *cmdError
			if errors.As(err, &ce) && ce.code == 66 {
				return nil, fieldError("body.name", ce.msg, b.Name)
			}
			return nil, shellFailure(err, "")
		}
		s, err := h.saveGitSource(ctx, in.ID, b.Name, dir, b.DockerGitBody, nil)
		if err != nil {
			return nil, err
		}
		j, err := h.submitGitDeploy(ctx, s, true, "create", nil)
		if err != nil {
			return nil, err
		}
		return &struct{ Body DockerGitSaved }{DockerGitSaved{Source: h.gitSourceOut(s, true), Job: &j.Body}}, nil
	})

	hook := func(ctx context.Context, in *DockerGitHookInput) (*DockerGitHookOutput, error) {
		s, err := h.q.GetDockerGitSourceByHook(ctx, hookHash(in.Token))
		if isNotFound(err) {
			return nil, huma.Error404NotFound("No project has this webhook address")
		}
		if err != nil {
			return nil, internalError(err)
		}
		out := &DockerGitHookOutput{Status: http.StatusAccepted}
		out.Body.OK = true
		// GitHub, GitLab, Gitea and Bitbucket-style bodies name the ref:
		// a push to another branch is ignored.
		var body struct {
			Ref string `json:"ref"`
		}
		if len(in.RawBody) > 0 && json.Unmarshal(in.RawBody, &body) == nil && body.Ref != "" &&
			body.Ref != "refs/heads/"+s.Branch && body.Ref != s.Branch {
			out.Status = http.StatusOK
			out.Body.Message = "Ignored: a push to " + body.Ref + ", not " + s.Branch
			return out, nil
		}
		if !s.AutoDeploy {
			out.Status = http.StatusOK
			out.Body.Message = "Ignored: automatic deploys are off for this project"
			return out, nil
		}
		if _, busy := gitBusy.Load(gitKey(s.ServerID.String(), s.Project)); busy {
			out.Status = http.StatusOK
			out.Body.Message = "A deploy is already running"
			return out, nil
		}
		j, err := h.submitGitDeploy(context.WithoutCancel(ctx), s, false, "webhook", s.CreatedBy)
		if err != nil {
			return nil, err
		}
		out.Body.JobID = &j.Body.ID
		out.Body.Message = "Deploying"
		return out, nil
	}
	huma.Register(api, huma.Operation{
		OperationID: "docker-git-webhook", Method: http.MethodPost, Path: "/hooks/docker/{token}",
		Summary:      "Deploy a git project (webhook)",
		Description:  "Point a repository's push webhook here. No sign-in; the token is the secret. A push to another branch is ignored.",
		Tags:         tags,
		MaxBodyBytes: 5 << 20,
	}, hook)
	// Huma always requires a raw body; a bare POST (curl -X POST, CI
	// scripts) is fine here. The handler shares this RequestBody pointer.
	if op := api.OpenAPI().Paths["/hooks/docker/{token}"]; op != nil && op.Post != nil && op.Post.RequestBody != nil {
		op.Post.RequestBody.Required = false
	}

	h.jobs.Handle(dockerGitDeployKind, h.runGitDeploy)
}

// startDockerGitLoop polls connected repositories and deploys a project
// when its branch moved.
func startDockerGitLoop(h *serverHandler) {
	go func() {
		sem := make(chan struct{}, 4)
		for range time.Tick(time.Minute) {
			ctx := context.Background()
			due, err := h.q.DueDockerGitSources(ctx)
			if err != nil {
				slog.Warn("docker git: list sources to poll", "error", err)
				continue
			}
			for _, s := range due {
				key := gitKey(s.ServerID.String(), s.Project)
				if _, busy := gitBusy.Load(key); busy {
					continue
				}
				sem <- struct{}{}
				go func(s sqlc.DockerGitSource) {
					defer func() { <-sem }()
					h.pollGitSource(s)
				}(s)
			}
		}
	}()
}

func (h *serverHandler) pollGitSource(s sqlc.DockerGitSource) {
	ctx, cancel := context.WithTimeout(cmdlog.Background(context.Background(), "Docker"), 2*time.Minute)
	defer cancel()
	token, err := h.gitToken(s)
	if err != nil {
		return
	}
	var head string
	err = h.withShell(ctx, s.ServerID.String(), func(_ *sshpool.Conn, sh *rootShell) error {
		var err error
		head, err = gitHead(ctx, sh, s, token)
		return err
	})
	msg := ""
	if err != nil {
		msg = problemText(err)
	}
	_ = h.q.DockerGitChecked(ctx, sqlc.DockerGitCheckedParams{ServerID: s.ServerID, Project: s.Project, LastError: msg})
	if err != nil || head == s.LastCommit {
		return
	}
	if _, err := h.submitGitDeploy(ctx, s, false, "poll", s.CreatedBy); err != nil {
		slog.Warn("docker git: start a deploy", "project", s.Project, "error", err)
	}
}
