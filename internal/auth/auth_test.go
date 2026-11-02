package auth

import (
	"testing"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
)

func TestPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(h, "correct horse battery") {
		t.Fatal("right password rejected")
	}
	if VerifyPassword(h, "wrong password here") {
		t.Fatal("wrong password accepted")
	}
	for _, bad := range []string{"", "plain", "$argon2id$v=19$bad$bad$bad"} {
		if VerifyPassword(bad, "x") {
			t.Fatalf("malformed hash %q matched", bad)
		}
	}
}

func TestCheckPassword(t *testing.T) {
	if CheckPassword("short", "ali") == nil {
		t.Fatal("short password allowed")
	}
	if CheckPassword("longusername1", "LongUsername1") == nil {
		t.Fatal("password equal to the username allowed")
	}
	if err := CheckPassword("a good long password", "ali"); err != nil {
		t.Fatal(err)
	}
}

func TestTokenHash(t *testing.T) {
	a, ha, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := NewToken()
	if a == b {
		t.Fatal("tokens repeat")
	}
	if string(HashToken(a)) != string(ha) {
		t.Fatal("hash doesn't match the token")
	}
}

func TestAccessCombines(t *testing.T) {
	ws, other, srv, st := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	a := NewAccess(false, []sqlc.AccessGrant{
		{WorkspaceID: &ws, Level: "viewer"},
		{WorkspaceID: &ws, Level: "operator", CanCreate: true}, // from a group
		{ServerID: &srv, Level: "engineer"},
		{ServerID: &srv, Level: "viewer"},
		{StorageID: &st, Level: "owner"},
	})
	if got := a.WorkspaceLevel(ws); got != Operator {
		t.Fatalf("workspace level = %v", got)
	}
	if got := a.ServerLevel(ws, uuid.New()); got != Operator {
		t.Fatalf("server through workspace = %v", got)
	}
	if got := a.ServerLevel(other, srv); got != Engineer {
		t.Fatalf("direct server grant = %v", got)
	}
	if got := a.ServerLevel(other, uuid.New()); got != None {
		t.Fatalf("no grant = %v", got)
	}
	if got := a.StorageLevel(other, st); got != Owner {
		t.Fatalf("direct storage grant = %v", got)
	}
	if !a.CanCreateIn(ws) || a.CanCreateIn(other) {
		t.Fatal("can_create should stay on its workspace")
	}
	if a.WorkspaceLevel(other) != None {
		t.Fatal("a server grant must not count as the whole workspace")
	}
}

func TestAdminHasEverything(t *testing.T) {
	a := NewAccess(true, nil)
	if a.ServerLevel(uuid.New(), uuid.New()) != Owner || !a.CanCreateIn(uuid.New()) || a.Highest() != Owner {
		t.Fatal("admin should have owner level everywhere")
	}
}
