package main

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
)

func account(name, role string) sqlc.User {
	return sqlc.User{ID: uuid.New(), Username: name, Role: role, Status: "active"}
}

func TestPickAdmin(t *testing.T) {
	one := []sqlc.User{account("root-admin", "admin"), account("sam", "member")}
	two := append([]sqlc.User{account("second", "admin")}, one...)
	tests := []struct {
		name    string
		users   []sqlc.User
		user    string
		want    string
		wantErr string
	}{
		{name: "no accounts", wantErr: "no accounts yet"},
		{name: "only admin", users: one, want: "root-admin"},
		{name: "several need a name", users: two, wantErr: "several admins"},
		{name: "named", users: two, user: "second", want: "second"},
		{name: "any case", users: two, user: "ROOT-ADMIN", want: "root-admin"},
		{name: "member refused", users: one, user: "sam", wantErr: "isn't an admin"},
		{name: "unknown", users: one, user: "nobody", wantErr: "no account called"},
		{name: "no admin at all", users: []sqlc.User{account("sam", "member")}, wantErr: "no account is an admin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pickAdmin(tt.users, tt.user)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Username != tt.want {
				t.Fatalf("got %s, want %s", got.Username, tt.want)
			}
		})
	}
}

func TestCheckRename(t *testing.T) {
	target, other := account("old-name", "admin"), account("taken", "member")
	users := []sqlc.User{target, other}
	for name, ok := range map[string]bool{
		"new.name": true,
		"OLD-NAME": true, // only its own case changes
		"TAKEN":    false,
		"ab":       false,
		"-dash":    false,
	} {
		if err := checkRename(users, target, name); (err == nil) != ok {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestReadPasswordLine(t *testing.T) {
	for in, want := range map[string]string{
		"  spaces kept  \n": "  spaces kept  ",
		"crlf\r\nignored\n": "crlf",
		"no newline":        "no newline",
		"":                  "",
	} {
		got, err := readPasswordLine(strings.NewReader(in))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}
