package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
)

func TestNormalizeAddress(t *testing.T) {
	ok := map[string]string{
		"portainer.acme.ir":        "https://portainer.acme.ir",
		"localhost:9000":           "https://localhost:9000",
		"10.0.0.5:9000/ui":         "https://10.0.0.5:9000/ui",
		"  http://grafana.local/ ": "http://grafana.local/",
		"HTTPS://minio.acme.ir":    "https://minio.acme.ir",
	}
	for in, want := range ok {
		got, err := normalizeAddress(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
		} else if got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
	bad := []string{
		"", "   ", "javascript:alert(1)", "data:text/html,x", "mailto:a@b.c",
		"ftp://host", "file:///etc/passwd", "https://", "http://user:pass@host",
		"user:pass@host", "https://exa mple.com",
	}
	for _, in := range bad {
		if got, err := normalizeAddress(in); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}

func testAccounts(app uuid.UUID) []sqlc.AppAccount {
	return []sqlc.AppAccount{
		{ID: uuid.New(), AppID: app, Label: "admin", Username: "root", PasswordEnc: []byte("sealed-secret-bytes")},
		{ID: uuid.New(), AppID: app, Label: "readonly", Username: "guest"},
	}
}

func TestToAppHidesAccountsFromViewer(t *testing.T) {
	row := sqlc.App{ID: uuid.New(), WorkspaceID: uuid.New(), Name: "Portainer", LogoKind: "auto"}
	got := toApp(row, testAccounts(row.ID), nil, auth.Viewer)
	if len(got.Accounts) != 0 {
		t.Fatalf("viewer got %d accounts", len(got.Accounts))
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "root") {
		t.Fatalf("viewer JSON leaks a username: %s", b)
	}
	if got := toApp(row, testAccounts(row.ID), nil, auth.Operator); len(got.Accounts) != 2 {
		t.Fatalf("operator got %d accounts", len(got.Accounts))
	}
}

func TestToAppNeverSerializesPassword(t *testing.T) {
	row := sqlc.App{ID: uuid.New(), WorkspaceID: uuid.New(), Name: "MinIO", LogoKind: "auto"}
	b, err := json.Marshal(toApp(row, testAccounts(row.ID), nil, auth.Owner))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, leak := range []string{"sealed-secret-bytes", "password_enc", "c2VhbGVk"} {
		if strings.Contains(s, leak) {
			t.Fatalf("JSON contains %q: %s", leak, s)
		}
	}
	for _, want := range []string{`"username":"root"`, `"has_password":true`, `"has_password":false`} {
		if !strings.Contains(s, want) {
			t.Fatalf("JSON lacks %s: %s", want, s)
		}
	}
}

func TestToAppLogoURL(t *testing.T) {
	id := uuid.New()
	up := time.Unix(1_700_000_000, 0)
	fav := time.Unix(1_600_000_000, 0)
	upload := logoStamp{Source: "upload", UpdatedAt: up}
	favicon := logoStamp{Source: "favicon", UpdatedAt: fav}
	url := func(at time.Time) string { return fmt.Sprintf("/apps/%s/logo?v=%d", id, at.Unix()) }

	cases := []struct {
		name  string
		kind  string
		logos []logoStamp
		want  string
	}{
		{"upload", "upload", []logoStamp{favicon, upload}, url(up)},
		{"auto favicon", "auto", []logoStamp{favicon, upload}, url(fav)},
		{"auto without favicon", "auto", nil, ""},
		{"icon", "icon", []logoStamp{favicon, upload}, ""},
		{"upload missing", "upload", []logoStamp{favicon}, ""},
	}
	for _, c := range cases {
		got := toApp(sqlc.App{ID: id, LogoKind: c.kind}, nil, c.logos, auth.Viewer).LogoURL
		switch {
		case c.want == "" && got != nil:
			t.Errorf("%s: logo = %q, want none", c.name, *got)
		case c.want != "" && (got == nil || *got != c.want):
			t.Errorf("%s: logo = %v, want %q", c.name, got, c.want)
		}
	}
}

func TestCategoriesFor(t *testing.T) {
	ws, other := uuid.New(), uuid.New()
	c1, c2, empty := uuid.New(), uuid.New(), uuid.New()
	cats := []sqlc.AppCategory{{ID: c1, WorkspaceID: ws}, {ID: c2, WorkspaceID: ws}, {ID: empty, WorkspaceID: ws}}
	a1, a2, loose := uuid.New(), uuid.New(), uuid.New()
	apps := []sqlc.App{
		{ID: a1, WorkspaceID: ws, CategoryID: &c1},
		{ID: a2, WorkspaceID: ws, CategoryID: &c2},
		{ID: loose, WorkspaceID: ws},
	}
	ids := func(list []sqlc.AppCategory) []uuid.UUID {
		out := []uuid.UUID{}
		for _, c := range list {
			out = append(out, c.ID)
		}
		return out
	}
	cases := []struct {
		name   string
		grants []sqlc.AccessGrant
		want   []uuid.UUID
	}{
		{"workspace viewer", []sqlc.AccessGrant{{WorkspaceID: &ws, Level: "viewer"}}, []uuid.UUID{c1, c2, empty}},
		{"can create", []sqlc.AccessGrant{{WorkspaceID: &other, Level: "viewer"}, {WorkspaceID: &ws, Level: "none", CanCreate: true}}, []uuid.UUID{c1, c2, empty}},
		{"engineer on one app", []sqlc.AccessGrant{{AppID: &loose, Level: "engineer"}}, []uuid.UUID{c1, c2, empty}},
		{"viewer on one app", []sqlc.AccessGrant{{AppID: &a1, Level: "viewer"}}, []uuid.UUID{c1}},
		{"operator on a loose app", []sqlc.AccessGrant{{AppID: &loose, Level: "operator"}}, []uuid.UUID{}},
	}
	for _, c := range cases {
		got := ids(categoriesFor(auth.NewAccess(false, c.grants), ws, cats, apps))
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
