package api

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morche/backend/internal/sshpool"
	"github.com/morche/backend/internal/sysconf"
	"github.com/morche/backend/internal/terminal"
)

const hostsPath = "/etc/hosts"

type HostsOverview struct {
	Revision string              `json:"revision" doc:"Send it back with a change; it moves when the file changes"`
	Hostname string              `json:"hostname" doc:"This machine's own name"`
	Entries  []sysconf.HostEntry `json:"entries"`
	Problems []string            `json:"problems" doc:"Names on two addresses, bad addresses or names"`
	Writable bool                `json:"writable" doc:"Morche has root or sudo here"`
}

type HostsBody struct {
	Revision string              `json:"revision"`
	Entries  []sysconf.HostEntry `json:"entries" maxItems:"5000"`
}

type HostsUpdateInput struct {
	ID   string `path:"id" format:"uuid"`
	Body HostsBody
}

type ResolveNameBody struct {
	Name   string `json:"name" maxLength:"253" example:"db.internal"`
	Server string `json:"server,omitempty" required:"false" doc:"Ask this DNS server instead of the server's own lookup (DNS tab's test)"`
}

type ResolveNameInput struct {
	ID   string `path:"id" format:"uuid"`
	Body ResolveNameBody
}

type ResolveNameResult struct {
	OK      bool     `json:"ok"`
	Answers []string `json:"answers" doc:"The addresses it got"`
	Source  string   `json:"source" enum:"hosts,dns,none" doc:"hosts = /etc/hosts answered it"`
	TookMS  int64    `json:"took_ms"`
	Error   string   `json:"error"`
}

func hostsEntryLabel(e sysconf.HostEntry) string {
	return strings.TrimSpace(e.Address + " " + strings.Join(e.Names, " "))
}

// hostsSummary says what a change does in a few words.
func hostsSummary(old, fresh []sysconf.HostEntry) string {
	byLine := map[int]sysconf.HostEntry{}
	for _, e := range old {
		byLine[e.Line] = e
	}
	var added, removed, changed []sysconf.HostEntry
	seen := map[int]bool{}
	for _, e := range fresh {
		o, ok := byLine[e.Line]
		if e.Line == 0 || !ok || seen[e.Line] {
			added = append(added, e)
			continue
		}
		seen[e.Line] = true
		if o.Address != e.Address || !slices.Equal(o.Names, e.Names) || o.Comment != e.Comment || o.Enabled != e.Enabled {
			changed = append(changed, e)
		}
	}
	for _, o := range old {
		if !seen[o.Line] {
			removed = append(removed, o)
		}
	}
	switch n := len(added) + len(removed) + len(changed); {
	case n == 0:
		return "No change to /etc/hosts"
	case n > 1:
		return fmt.Sprintf("Change %d entries in /etc/hosts", n)
	case len(added) == 1:
		return "Add " + hostsEntryLabel(added[0])
	case len(removed) == 1:
		return "Remove " + hostsEntryLabel(removed[0])
	}
	return "Change " + hostsEntryLabel(changed[0])
}

func checkHostEntries(entries []sysconf.HostEntry) error {
	for i, e := range entries {
		loc := fmt.Sprintf("body.entries[%d]", i)
		if !sysconf.ValidIP(e.Address) {
			return fieldError(loc+".address", "Not an IP address", e.Address)
		}
		if len(e.Names) == 0 || len(e.Names) > 20 {
			return fieldError(loc+".names", "Give 1 to 20 names", e.Names)
		}
		for j, n := range e.Names {
			if !sysconf.ValidHostname(n) {
				return fieldError(fmt.Sprintf("%s.names[%d]", loc, j), "Use letters, digits, dots and hyphens", n)
			}
		}
		if len(e.Comment) > 200 || strings.ContainsAny(e.Comment, "\n\r\x00") {
			return fieldError(loc+".comment", "Keep the note on one line, at most 200 characters", e.Comment)
		}
	}
	return nil
}

// parseGetent answers the addresses of `getent ahosts`, once each.
func parseGetent(out string) []string {
	var addrs []string
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) > 0 && sysconf.ValidIP(f[0]) && !slices.Contains(addrs, f[0]) {
			addrs = append(addrs, f[0])
		}
	}
	return addrs
}

func (h *serverHandler) hostsOverview(ctx context.Context, id string) (*HostsOverview, error) {
	out := &HostsOverview{}
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.rootShell(ctx, id, c)
		if err != nil {
			return err
		}
		files, rev, err := readConfigFiles(ctx, sh, hostsPath)
		if err != nil {
			return err
		}
		text, _ := fileText(files, hostsPath)
		name, _ := sh.run(ctx, "hostname")
		out.Revision = rev
		out.Hostname = strings.TrimSpace(name)
		out.Entries = sysconf.ParseHosts(text)
		if out.Entries == nil {
			out.Entries = []sysconf.HostEntry{}
		}
		out.Problems = sysconf.HostsProblems(out.Entries)
		if out.Problems == nil {
			out.Problems = []string{}
		}
		out.Writable = sh.priv != privUser
		return nil
	})
	return out, toProblem(err)
}

func (h *serverHandler) resolveName(ctx context.Context, id string, b ResolveNameBody) (*ResolveNameResult, error) {
	if !sysconf.ValidHostname(b.Name) {
		return nil, fieldError("body.name", "Not a host name", b.Name)
	}
	if b.Server != "" && !sysconf.ValidIP(b.Server) {
		return nil, fieldError("body.server", "Not an IP address", b.Server)
	}
	res := &ResolveNameResult{Answers: []string{}, Source: "none"}
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.rootShell(ctx, id, c)
		if err != nil {
			return err
		}
		name := terminal.ShellQuote(b.Name)
		script := "timeout 8 getent ahosts " + name
		if b.Server != "" {
			srv := terminal.ShellQuote(b.Server)
			script = "if command -v dig >/dev/null 2>&1; then dig +short +time=3 +tries=1 @" + srv + " " + name + " A " + name + " AAAA | grep -v '\\.$'; " +
				"elif command -v nslookup >/dev/null 2>&1; then nslookup -timeout=3 " + name + " " + srv + " | awk '/^Address/ && NR>2 {print $2}'; " +
				"else echo 'MORCHE-NOTOOL'; fi"
		}
		start := time.Now()
		r, err := sh.exec(ctx, script, 15*time.Second, 16<<10)
		if err != nil {
			return err
		}
		res.TookMS = time.Since(start).Milliseconds()
		if strings.Contains(string(r.output), "MORCHE-NOTOOL") {
			res.Error = "Asking a chosen DNS server needs dig or nslookup on the server (package dnsutils or bind-utils)"
			return nil
		}
		res.Answers = parseGetent(string(r.output))
		if res.Answers == nil {
			res.Answers = []string{}
		}
		res.OK = len(res.Answers) > 0
		if !res.OK {
			res.Error = "No address found for " + b.Name
			return nil
		}
		res.Source = "dns"
		if b.Server == "" {
			files, _, _ := readConfigFiles(ctx, sh, hostsPath)
			text, _ := fileText(files, hostsPath)
			for _, e := range sysconf.ParseHosts(text) {
				if e.Enabled && slices.ContainsFunc(e.Names, func(n string) bool { return strings.EqualFold(n, b.Name) }) {
					res.Source = "hosts"
				}
			}
		}
		return nil
	})
	return res, toProblem(err)
}

func registerConfigHosts(api huma.API, h *serverHandler) {
	tags := []string{"Server config"}

	huma.Register(api, huma.Operation{
		OperationID: "get-server-hosts",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/hosts",
		Summary:     "The server's /etc/hosts",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body HostsOverview }, error) {
		o, err := h.hostsOverview(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body HostsOverview }{*o}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-server-hosts",
		Method:      http.MethodPut,
		Path:        "/servers/{id}/hosts",
		Summary:     "Save /etc/hosts",
		Description: "Every entry, as the list should be. Lines that didn't change, comments and blank lines stay as they were. 409 when the file changed since `revision`.",
		Tags:        tags,
	}, func(ctx context.Context, in *HostsUpdateInput) (*struct{ Body HostsOverview }, error) {
		if err := checkHostEntries(in.Body.Entries); err != nil {
			return nil, err
		}
		_, err := h.configChange(ctx, in.ID, in.Body.Revision, func(sh *rootShell) (configPlan, error) {
			files, _, err := readConfigFiles(ctx, sh, hostsPath)
			if err != nil {
				return configPlan{}, err
			}
			text, _ := fileText(files, hostsPath)
			return configPlan{
				Area: "hosts", Summary: hostsSummary(sysconf.ParseHosts(text), in.Body.Entries),
				Read:   []string{hostsPath},
				Writes: []configWrite{{Path: hostsPath, Text: sysconf.PrintHosts(text, in.Body.Entries)}},
			}, nil
		})
		if err != nil {
			return nil, err
		}
		o, err := h.hostsOverview(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &struct{ Body HostsOverview }{*o}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "resolve-server-name",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/resolve",
		Summary:     "Look a name up from the server",
		Description: "What the server gets for a name, the way its programs would (/etc/hosts first, then DNS), or from one DNS server.",
		Tags:        tags,
	}, func(ctx context.Context, in *ResolveNameInput) (*struct{ Body ResolveNameResult }, error) {
		r, err := h.resolveName(ctx, in.ID, in.Body)
		if err != nil {
			return nil, err
		}
		return &struct{ Body ResolveNameResult }{*r}, nil
	})

	configRestorers["hosts"] = func(context.Context, *serverHandler, string, *rootShell, []ConfigChangeFile) (configPlan, error) {
		return configPlan{Read: []string{hostsPath}}, nil
	}
}
