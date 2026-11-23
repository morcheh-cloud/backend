package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/cmdlog"
	"github.com/morche/backend/internal/config"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/sshprobe"
	"github.com/morche/backend/internal/terminal"
)

// The machine Morche runs on ("This server"). With MANAGE_HOST the backend
// adds it once by itself, with a key it makes for itself, in the status
// needs_login: someone signs in to it once from the panel (Morche then puts
// its key on the machine and forgets the password), or puts the key there by
// hand and the next check finds it.

const (
	morcheHostName        = "This server"
	morcheHostDescription = "The machine Morche runs on."
	needsLoginMessage     = "Sign in once so Morche can manage the machine it runs on."
)

type morcheHostHandler struct {
	cfg *config.Config
	s   *serverHandler
}

// startMorcheHost adds the machine Morche runs on once MANAGE_HOST is set and
// a workspace exists (a fresh install has none until first-run setup).
func startMorcheHost(h *morcheHostHandler) {
	if !h.cfg.ManageHost {
		return
	}
	go func() {
		for {
			done, err := h.ensure(context.Background())
			if err != nil {
				slog.Warn("add the machine Morche runs on", "error", err)
			}
			if done {
				return
			}
			time.Sleep(30 * time.Second)
		}
	}()
}

// ensure adds it unless it was added before (and maybe deleted since).
func (h *morcheHostHandler) ensure(ctx context.Context) (bool, error) {
	q := h.s.q
	set, err := q.GetSettings(ctx)
	if err != nil {
		return false, err
	}
	if set.MorcheHostAddedAt != nil {
		return true, nil
	}
	if _, err := q.GetMorcheHost(ctx); err == nil {
		return true, q.MarkMorcheHostAdded(ctx)
	} else if !isNotFound(err) {
		return false, err
	}
	ws, err := q.FirstWorkspace(ctx)
	if isNotFound(err) {
		return false, nil // wait for first-run setup
	}
	if err != nil {
		return false, err
	}
	s, err := h.add(ctx, ws.ID)
	if err != nil {
		return false, err
	}
	slog.Info("added the machine Morche runs on", "server", s.ID, "host", s.Host)
	return true, q.MarkMorcheHostAdded(ctx)
}

// add saves the server with a fresh key of its own.
func (h *morcheHostHandler) add(ctx context.Context, ws uuid.UUID) (sqlc.Server, error) {
	key, pub, err := newSSHKey("morche")
	if err != nil {
		return sqlc.Server{}, err
	}
	params := sqlc.CreateMorcheHostParams{
		WorkspaceID:    ws,
		Host:           h.cfg.ManageHostAddress,
		Port:           h.cfg.ManageHostPort,
		Username:       h.cfg.ManageHostUser,
		PrivateKeyEnc:  h.s.box.Seal(string(key)),
		PassphraseEnc:  h.s.box.Seal(""),
		Description:    morcheHostDescription,
		SetupPublicKey: pub,
		StatusMessage:  needsLoginMessage,
	}
	for i := 1; i <= 20; i++ {
		params.Name = morcheHostName
		if i > 1 {
			params.Name = fmt.Sprintf("%s %d", morcheHostName, i)
		}
		s, err := h.s.q.CreateMorcheHost(ctx, params)
		if isUniqueViolation(err) {
			if _, err := h.s.q.GetMorcheHost(ctx); err == nil {
				return sqlc.Server{}, huma.Error409Conflict("The server Morche runs on is already added.")
			}
			continue // the name is taken
		}
		return s, err
	}
	return sqlc.Server{}, errors.New("no free name for the server Morche runs on")
}

// ---- API ----

type MorcheHostState struct {
	ServerID *string `json:"server_id" format:"uuid" nullable:"true" doc:"The server, when it is added"`
	Enabled  bool    `json:"enabled" doc:"MANAGE_HOST is set: the backend adds it by itself"`
	Address  string  `json:"address" doc:"Where the backend reaches the machine it runs on" example:"host.docker.internal"`
	Port     int32   `json:"port" example:"22"`
	Username string  `json:"username" doc:"The login it starts with" example:"root"`
	// Outside a container the address above (host.docker.internal) means
	// nothing, so the panel only offers to add it when one of these is true.
	InContainer bool `json:"in_container" doc:"The backend runs in a container"`
}

type MorcheHostOutput struct{ Body MorcheHostState }

type AddMorcheHostBody struct {
	WorkspaceID string `json:"workspace_id" format:"uuid"`
}

type ServerSignInBody struct {
	Username   string `json:"username" minLength:"1" maxLength:"64" example:"ubuntu"`
	AuthMethod string `json:"auth_method" enum:"password,private_key"`
	Password   string `json:"password,omitempty" maxLength:"1024"`
	PrivateKey string `json:"private_key,omitempty" maxLength:"16384"`
	Passphrase string `json:"passphrase,omitempty" maxLength:"1024"`
	// What to keep once it signed in.
	KeepLogin bool `json:"keep_login,omitempty" doc:"Store this login as given, instead of putting Morche's own key on the server and forgetting it"`
	AsRoot    bool `json:"as_root,omitempty" doc:"Put Morche's key on root (through sudo) and work as root from then on"`
}

func registerMorcheHost(api huma.API, h *morcheHostHandler) {
	tags := []string{"Servers"}

	huma.Register(api, huma.Operation{
		OperationID: "get-morche-host",
		Method:      http.MethodGet,
		Path:        "/morche-host",
		Summary:     "The machine Morche runs on",
		Description: "Whether it is added as a server, and where the backend reaches it.",
		Tags:        tags,
	}, h.get)

	huma.Register(api, huma.Operation{
		OperationID:   "add-morche-host",
		Method:        http.MethodPost,
		Path:          "/morche-host",
		Summary:       "Add the machine Morche runs on",
		Description:   "Adds it as a server waiting for a sign-in, with a key Morche made for it. System admins only.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, h.addNow)

	huma.Register(api, huma.Operation{
		OperationID: "sign-in-server",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/sign-in",
		Summary:     "Sign in to a server once",
		Description: "Signs in with the given login. Unless keep_login is set and the server has a key Morche made for it, that key is put in the user's (or with as_root, root's) authorized_keys, tried, and stored in place of the login.",
		Tags:        tags,
	}, h.signIn)
}

func (h *morcheHostHandler) state(ctx context.Context) (MorcheHostState, error) {
	out := MorcheHostState{
		Enabled: h.cfg.ManageHost, Address: h.cfg.ManageHostAddress,
		Port: h.cfg.ManageHostPort, Username: h.cfg.ManageHostUser,
		InContainer: selfContainer() != "",
	}
	s, err := h.s.q.GetMorcheHost(ctx)
	switch {
	case err == nil:
		id := s.ID.String()
		out.ServerID = &id
	case !isNotFound(err):
		return out, internalError(err)
	}
	return out, nil
}

func (h *morcheHostHandler) get(ctx context.Context, _ *struct{}) (*MorcheHostOutput, error) {
	st, err := h.state(ctx)
	if err != nil {
		return nil, err
	}
	// Only someone who can see that server learns which one it is.
	if st.ServerID != nil {
		if id, err := uuid.Parse(*st.ServerID); err == nil {
			if s, err := h.s.q.GetServer(ctx, id); err == nil &&
				principalOf(ctx).Access.ServerLevel(s.WorkspaceID, s.ID) == auth.None {
				st.ServerID = nil
			}
		}
	}
	return &MorcheHostOutput{Body: st}, nil
}

func (h *morcheHostHandler) addNow(ctx context.Context, in *struct{ Body AddMorcheHostBody }) (*ServerOutput, error) {
	ws, err := uuid.Parse(in.Body.WorkspaceID)
	if err != nil {
		return nil, fieldError("body.workspace_id", "Not a workspace", in.Body.WorkspaceID)
	}
	if _, err := h.s.q.GetWorkspace(ctx, ws); isNotFound(err) {
		return nil, fieldError("body.workspace_id", "Workspace not found", in.Body.WorkspaceID)
	} else if err != nil {
		return nil, internalError(err)
	}
	s, err := h.add(ctx, ws)
	if err != nil {
		var se huma.StatusError
		if errors.As(err, &se) {
			return nil, err
		}
		return nil, internalError(err)
	}
	_ = h.s.q.MarkMorcheHostAdded(ctx)
	return &ServerOutput{Body: toServer(s)}, nil
}

// signIn signs in to a server with a login given once.
func (h *morcheHostHandler) signIn(ctx context.Context, in *struct {
	ServerIDPath
	Body ServerSignInBody
}) (*ServerOutput, error) {
	s, err := h.s.get(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	b := in.Body
	b.Username = strings.TrimSpace(b.Username)
	if !usernameRe.MatchString(b.Username) {
		return nil, fieldError("body.username", "Usernames can't contain spaces, ':' or '@'", b.Username)
	}
	if b.PrivateKey != "" {
		b.PrivateKey = strings.TrimSpace(b.PrivateKey) + "\n"
	}
	secretField := "body.password"
	t := sshprobe.Target{Host: s.Host, Port: int(s.Port), User: b.Username, KnownHostKey: s.HostKey}
	switch b.AuthMethod {
	case "password":
		if b.Password == "" {
			return nil, fieldError("body.password", "Enter the password", nil)
		}
		t.Password = b.Password
	default:
		secretField = "body.private_key"
		if b.PrivateKey == "" {
			return nil, fieldError("body.private_key", "Paste the private key", nil)
		}
		if _, err := sshprobe.ParseSigner(b.PrivateKey, b.Passphrase); err != nil {
			return nil, fieldError("body.private_key", "Private key: "+err.Error(), nil)
		}
		t.PrivateKey, t.Passphrase = b.PrivateKey, b.Passphrase
	}

	client, seen, err := sshprobe.Dial(ctx, t)
	if err != nil {
		return nil, signInError(err, b, secretField)
	}
	defer client.Close()

	ownKey := s.SetupPublicKey != "" && len(s.PrivateKeyEnc) > 0 && !b.KeepLogin
	var params sqlc.SetServerLoginParams
	if ownKey {
		user := b.Username
		if b.AsRoot {
			user = "root"
		}
		if err := h.putKey(ctx, s, client, b, user); err != nil {
			return nil, err
		}
		if err := h.tryOwnKey(ctx, s, user); err != nil {
			return nil, err
		}
		params = sqlc.SetServerLoginParams{
			Username: user, AuthMethod: "private_key",
			PrivateKeyEnc: s.PrivateKeyEnc, PassphraseEnc: s.PassphraseEnc,
		}
	} else {
		sec, err := h.s.resolveSecrets(Connection{
			Username: b.Username, AuthMethod: b.AuthMethod,
			Password: b.Password, PrivateKey: b.PrivateKey, Passphrase: b.Passphrase,
		}, nil)
		if err != nil {
			return nil, err
		}
		params = sqlc.SetServerLoginParams{
			Username: b.Username, AuthMethod: b.AuthMethod,
			PasswordEnc: sec.password, PrivateKeyEnc: sec.privateKey, PassphraseEnc: sec.passphrase,
		}
	}
	params.ID, params.HostKey = s.ID, seen.HostKey
	saved, err := h.s.q.SetServerLogin(ctx, params)
	if err != nil {
		return nil, internalError(err)
	}
	h.s.pool.Drop(s.ID.String())
	checked, err := h.s.check(ctx, saved)
	if err != nil {
		checked = saved
	}
	return &ServerOutput{Body: toServer(checked)}, nil
}

func signInError(err error, b ServerSignInBody, secretField string) error {
	var de *sshprobe.DialError
	if !errors.As(err, &de) {
		return huma.Error422UnprocessableEntity(err.Error())
	}
	switch de.Status {
	case sshprobe.StatusAuthFailed:
		msg := "That login didn't work: " + de.Message
		if b.Username == "root" && b.AuthMethod == "password" {
			msg = "That login didn't work. Most servers don't let root sign in " +
				"with a password: use your own user (one that can use sudo)."
		}
		return fieldError(secretField, msg, nil)
	case sshprobe.StatusHostKeyMismatch:
		return huma.Error409Conflict("The server's host key changed since it was trusted. " +
			"Check the server first, then trust the new key.")
	default:
		return huma.Error422UnprocessableEntity(de.Message)
	}
}

// keyScript adds key to the authorized_keys of the user in home (a shell
// word like ~ or ~root), once, keeping the file's last line whole.
func keyScript(home, key string) string {
	k := terminal.ShellQuote(key)
	return "cd " + home + ` && umask 077 && mkdir -p .ssh && touch .ssh/authorized_keys && ` +
		`{ grep -qxF ` + k + ` .ssh/authorized_keys || { ` +
		`[ -s .ssh/authorized_keys ] && [ "$(tail -c1 .ssh/authorized_keys)" ] && echo >> .ssh/authorized_keys; ` +
		`printf '%s\n' ` + k + ` >> .ssh/authorized_keys; }; }`
}

// putKey puts the server's own key on user's authorized_keys over client
// (signed in as b.Username): directly when it's the same user, else via sudo.
func (h *morcheHostHandler) putKey(ctx context.Context, s sqlc.Server, client *ssh.Client, b ServerSignInBody, user string) error {
	cmd := keyScript("~", s.SetupPublicKey)
	stdin := ""
	asRoot := false
	if user != b.Username {
		asRoot = true
		script := terminal.ShellQuote(keyScript("~"+user, s.SetupPublicKey))
		if b.AuthMethod == "password" {
			cmd = "sudo -S -p '' sh -c " + script
			stdin = b.Password + "\n"
		} else {
			cmd = "sudo -n sh -c " + script
		}
	}

	var end func(error)
	if sink := h.s.pool.Log; sink != nil {
		if hd := sink.Begin(ctx, cmdlog.Command{
			ServerID: s.ID.String(), Origin: cmdlog.Of(ctx),
			Text: "Add Morche's key to " + user + "'s authorized_keys", AsRoot: asRoot, Started: time.Now(),
		}); hd != nil {
			end = func(err error) {
				r := cmdlog.Result{}
				if err != nil {
					r.Code, r.Error = 1, err.Error()
				}
				hd.End(r)
			}
		}
	}

	sess, err := client.NewSession()
	if err == nil {
		defer sess.Close()
		if stdin != "" {
			sess.Stdin = strings.NewReader(stdin)
		}
		var out []byte
		out, err = sess.CombinedOutput(cmd)
		if err != nil {
			err = fmt.Errorf("%s", strings.TrimSpace(cmdlog.Redact(string(out), b.Password)))
		}
	}
	if end != nil {
		end(err)
	}
	if err == nil {
		return nil
	}
	if asRoot {
		return fieldError("body.as_root", "Couldn't put Morche's key on root with sudo ("+err.Error()+
			"). Turn off Work as root, or use a user that can use sudo.", nil)
	}
	return huma.Error422UnprocessableEntity("Signed in, but couldn't put Morche's key on the server: " + err.Error())
}

// tryOwnKey signs in with the server's own key as user.
func (h *morcheHostHandler) tryOwnKey(ctx context.Context, s sqlc.Server, user string) error {
	key, err := h.s.box.Open(s.PrivateKeyEnc)
	if err != nil {
		return internalError(err)
	}
	client, _, err := sshprobe.Dial(ctx, sshprobe.Target{
		Host: s.Host, Port: int(s.Port), User: user, PrivateKey: key, KnownHostKey: s.HostKey,
	})
	if err != nil {
		msg := "Morche's key is on the server, but signing in with it as " + user + " didn't work"
		var de *sshprobe.DialError
		if errors.As(err, &de) {
			msg += ": " + de.Message
		}
		if user == "root" {
			msg += ". The SSH server may not let root sign in (PermitRootLogin)."
		}
		return huma.Error422UnprocessableEntity(msg + " Turn on Keep this login to store it as given instead.")
	}
	client.Close()
	return nil
}
