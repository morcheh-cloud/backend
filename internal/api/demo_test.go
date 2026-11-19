package api

import (
	"testing"

	"github.com/morche/backend/internal/config"
	"github.com/morche/backend/internal/database/sqlc"
)

// A renamed operation would silently reopen in the demo.
func TestDemoRefusedOperationsExist(t *testing.T) {
	for op := range demoRefused {
		if _, ok := policies[op]; !ok {
			t.Errorf("demoRefused lists %q, which has no policy", op)
		}
	}
}

func TestDemoRefuses(t *testing.T) {
	member := &principal{User: sqlc.User{Role: "member"}}
	admin := &principal{User: sqlc.User{Role: "admin"}}
	off := &authz{cfg: &config.Config{}}
	on := &authz{cfg: &config.Config{DemoMode: true}}
	if off.demoRefuses("change-password", member) {
		t.Error("refused outside the demo")
	}
	if !on.demoRefuses("change-password", member) || !on.demoRefuses("auth-register", nil) {
		t.Error("not refused in the demo")
	}
	if on.demoRefuses("change-password", admin) {
		t.Error("refused for an admin")
	}
	if on.demoRefuses("list-servers", member) {
		t.Error("refused an ordinary operation")
	}
}
