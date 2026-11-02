// Package auth holds the rules of who may do what, free of HTTP: access
// levels, password hashing and session tokens.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"

	"github.com/morcheh/backend/internal/database/sqlc"
)

// Level is how much someone can do on a server or storage. Each level includes
// the ones below it.
type Level int

const (
	None Level = iota
	Viewer
	Operator
	Engineer
	Owner
)

// ParseLevel reads a stored level; anything unknown is None.
func ParseLevel(s string) Level {
	switch s {
	case "viewer":
		return Viewer
	case "operator":
		return Operator
	case "engineer":
		return Engineer
	case "owner":
		return Owner
	}
	return None
}

func (l Level) String() string {
	switch l {
	case Viewer:
		return "viewer"
	case Operator:
		return "operator"
	case Engineer:
		return "engineer"
	case Owner:
		return "owner"
	}
	return "none"
}

// WorkspaceGrant is what someone has on a whole workspace.
type WorkspaceGrant struct {
	Level Level
	// CanCreate lets them add servers and storages to it.
	CanCreate bool
}

// Access is everything one person can reach. Direct and group grants are
// already combined: the highest level wins.
type Access struct {
	Admin      bool
	Workspaces map[uuid.UUID]WorkspaceGrant
	Servers    map[uuid.UUID]Level
	Storages   map[uuid.UUID]Level
}

// NewAccess combines a person's grants (their own and their groups').
func NewAccess(admin bool, grants []sqlc.AccessGrant) *Access {
	a := &Access{
		Admin:      admin,
		Workspaces: map[uuid.UUID]WorkspaceGrant{},
		Servers:    map[uuid.UUID]Level{},
		Storages:   map[uuid.UUID]Level{},
	}
	for _, g := range grants {
		l := ParseLevel(g.Level)
		switch {
		case g.WorkspaceID != nil:
			w := a.Workspaces[*g.WorkspaceID]
			w.Level = max(w.Level, l)
			w.CanCreate = w.CanCreate || g.CanCreate
			a.Workspaces[*g.WorkspaceID] = w
		case g.ServerID != nil:
			a.Servers[*g.ServerID] = max(a.Servers[*g.ServerID], l)
		case g.StorageID != nil:
			a.Storages[*g.StorageID] = max(a.Storages[*g.StorageID], l)
		}
	}
	return a
}

// WorkspaceLevel is the level on a workspace as a whole. A single server in it
// doesn't count.
func (a *Access) WorkspaceLevel(workspace uuid.UUID) Level {
	if a.Admin {
		return Owner
	}
	return a.Workspaces[workspace].Level
}

// ServerLevel is the level on a server in the given workspace.
func (a *Access) ServerLevel(workspace, server uuid.UUID) Level {
	if a.Admin {
		return Owner
	}
	return max(a.Workspaces[workspace].Level, a.Servers[server])
}

// StorageLevel is the level on a storage in the given workspace.
func (a *Access) StorageLevel(workspace, storage uuid.UUID) Level {
	if a.Admin {
		return Owner
	}
	return max(a.Workspaces[workspace].Level, a.Storages[storage])
}

// CanCreateIn says whether they may add servers and storages to a workspace.
func (a *Access) CanCreateIn(workspace uuid.UUID) bool {
	return a.Admin || a.Workspaces[workspace].CanCreate
}

// CanCreateAnywhere says whether they may add servers or storages at all.
func (a *Access) CanCreateAnywhere() bool {
	if a.Admin {
		return true
	}
	for _, w := range a.Workspaces {
		if w.CanCreate {
			return true
		}
	}
	return false
}

// Highest is the best level they have on anything, used for actions that
// aren't about one resource.
func (a *Access) Highest() Level {
	if a.Admin {
		return Owner
	}
	best := None
	for _, w := range a.Workspaces {
		best = max(best, w.Level)
	}
	for _, l := range a.Servers {
		best = max(best, l)
	}
	for _, l := range a.Storages {
		best = max(best, l)
	}
	return best
}

// ---- Passwords ----

const (
	PasswordMin = 12
	PasswordMax = 128

	argonTime    = 2
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// Each hash takes 64 MiB, so a burst of logins can't exhaust memory.
var hashing = make(chan struct{}, 4)

// dummyHash is verified when the username doesn't exist, so that answer takes
// as long as a wrong password.
var dummyHash, _ = HashPassword("morcheh-no-such-user")

// HashPassword returns an Argon2id hash in PHC string format.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hashing <- struct{}{}
	defer func() { <-hashing }()
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword compares in constant time. A malformed hash never matches.
func VerifyPassword(hash, password string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || t == 0 || p == 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false
	}
	hashing <- struct{}{}
	defer func() { <-hashing }()
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// BurnPassword spends the time a real check would.
func BurnPassword(password string) {
	VerifyPassword(dummyHash, password)
}

// UsernameRule says what ValidUsername accepts.
const UsernameRule = "Use 3–32 letters, digits, dots, dashes or underscores, starting with a letter or digit."

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{2,31}$`)

// ValidUsername reports whether a new username is acceptable.
func ValidUsername(name string) bool { return usernamePattern.MatchString(name) }

// CheckPassword returns why a new password isn't acceptable, or nil.
func CheckPassword(password, username string) error {
	n := len([]rune(password))
	switch {
	case n < PasswordMin:
		return fmt.Errorf("use at least %d characters", PasswordMin)
	case n > PasswordMax:
		return fmt.Errorf("use at most %d characters", PasswordMax)
	case strings.EqualFold(password, username):
		return errors.New("the password can't be the username")
	}
	return nil
}

// ---- Session tokens ----

// NewToken returns a random session token and the hash to store. Only the
// browser ever holds the token itself.
func NewToken() (token string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token), nil
}

// HashToken is what a token is stored and looked up as.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}
