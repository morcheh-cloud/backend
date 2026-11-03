package api

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/database/sqlc"
)

// appColors are the palette keys a service or category can take. The panel
// owns the actual colors.
var appColors = []string{"slate", "red", "orange", "amber", "green", "teal", "blue", "indigo", "violet", "pink"}

// App is a web service on the Services page as one person sees it.
type App struct {
	ID          string       `json:"id" format:"uuid"`
	WorkspaceID string       `json:"workspace_id" format:"uuid"`
	CategoryID  *string      `json:"category_id,omitempty" format:"uuid"`
	Name        string       `json:"name"`
	Address     string       `json:"address"`
	Note        string       `json:"note"`
	Color       string       `json:"color"`
	Critical    bool         `json:"critical"`
	Position    int32        `json:"position"`
	LogoKind    string       `json:"logo_kind" enum:"auto,upload,icon"`
	LogoIcon    string       `json:"logo_icon"`
	LogoURL     *string      `json:"logo_url,omitempty" doc:"Where to load the logo from; missing = draw the first letter or the icon."`
	Accounts    []AppAccount `json:"accounts" doc:"Empty below Operator."`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// AppAccount is one sign-in for a service. The password never leaves the
// backend here: it is read with the reveal endpoint, which is logged.
type AppAccount struct {
	ID          string `json:"id" format:"uuid"`
	Label       string `json:"label"`
	Username    string `json:"username"`
	HasPassword bool   `json:"has_password"`
}

// logoStamp says which stored logos a service has and when each changed, so
// the logo URL changes with it and caches can keep it forever.
type logoStamp struct {
	Source    string
	UpdatedAt time.Time
}

var schemePrefix = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:`)

// normalizeAddress turns what someone typed into an http(s) URL, adding
// https:// when there is no scheme. Anything else (javascript:, file:, an
// embedded user and password…) is refused.
func normalizeAddress(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("Enter the service's address.")
	}
	if !strings.Contains(s, "://") {
		// "localhost:9000" is a host and port; "mailto:x" is a scheme.
		if m := schemePrefix.FindString(s); m != "" && !startsWithDigit(s[len(m):]) {
			return "", fmt.Errorf("Use an http:// or https:// address.")
		}
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("This isn't a valid address.")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("Use an http:// or https:// address.")
	}
	if u.User != nil {
		return "", fmt.Errorf("Don't put a username or password in the address; add them as an account.")
	}
	if u.Host == "" || u.Hostname() == "" {
		return "", fmt.Errorf("The address needs a host name.")
	}
	return u.String(), nil
}

func startsWithDigit(s string) bool {
	return s != "" && s[0] >= '0' && s[0] <= '9'
}

// toApp shapes a service for someone at the given level: below Operator they
// get no accounts at all, not even usernames.
func toApp(row sqlc.App, accounts []sqlc.AppAccount, logos []logoStamp, level auth.Level) App {
	a := App{
		ID: row.ID.String(), WorkspaceID: row.WorkspaceID.String(), CategoryID: optionalIDString(row.CategoryID),
		Name: row.Name, Address: row.Address, Note: row.Note, Color: row.Color,
		Critical: row.Critical, Position: row.Position,
		LogoKind: row.LogoKind, LogoIcon: row.LogoIcon,
		Accounts:  []AppAccount{},
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
	want := map[string]string{"upload": "upload", "auto": "favicon"}[row.LogoKind]
	for _, l := range logos {
		if want != "" && l.Source == want {
			u := fmt.Sprintf("/apps/%s/logo?v=%d", row.ID, l.UpdatedAt.Unix())
			a.LogoURL = &u
		}
	}
	if level >= auth.Operator {
		for _, acc := range accounts {
			a.Accounts = append(a.Accounts, AppAccount{
				ID: acc.ID.String(), Label: acc.Label, Username: acc.Username,
				HasPassword: acc.PasswordEnc != nil,
			})
		}
	}
	return a
}

// categoriesFor picks the categories of a workspace someone gets. Whoever can
// place a service (the whole workspace, adding here, or Engineer on one of its
// services) gets them all, empty ones too; someone who only reaches a few
// services gets the categories those sit in.
func categoriesFor(acc *auth.Access, ws uuid.UUID, cats []sqlc.AppCategory, apps []sqlc.App) []sqlc.AppCategory {
	all := acc.WorkspaceLevel(ws) > auth.None || acc.CanCreateIn(ws)
	used := map[uuid.UUID]bool{}
	for _, a := range apps {
		if a.WorkspaceID != ws {
			continue
		}
		l := acc.AppLevel(ws, a.ID)
		if l >= auth.Engineer {
			all = true
		}
		if l > auth.None && a.CategoryID != nil {
			used[*a.CategoryID] = true
		}
	}
	out := make([]sqlc.AppCategory, 0, len(cats))
	for _, c := range cats {
		if all || used[c.ID] {
			out = append(out, c)
		}
	}
	return out
}
