// Command morche is the command-line client for a Morche panel's API, over a
// personal API token (Account › API tokens in the panel).
//
//	morche login                      # asks for the panel's API address and a token
//	morche servers list -q web
//	morche run deploy.sh --on web-1,web-2 --wait
//	morche api GET /servers
//
// The address and token come from MORCHE_URL / MORCHE_TOKEN, else from
// ~/.config/morche/config.json (written by login, mode 0600).
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"
)

const usage = `morche: the Morche panel from the command line.

Usage:
  morche login [--url URL]           sign in with an API token (asks for both)
  morche logout                      forget the saved token
  morche whoami                      who the token belongs to
  morche servers list [-q TEXT]      servers you can reach
  morche servers check <name|id>     check a server's connection now
  morche jobs list                   background tasks
  morche jobs watch <id>             follow a task until it ends
  morche run <script> --on <servers> [--wait]
                                     run a saved script (name or id) on servers
  morche cronjobs list               the workspace's cron jobs
  morche cronjobs run <name|id>      run a cron job now
  morche automations list            the workspace's automations
  morche automations run <name|id>   run an automation now
  morche api <METHOD> <path> [-d JSON|@file|@-]
                                     any API call, the answer printed as is

Global flags (before or after the command):
  --json              print lists as JSON
  --workspace NAME    the workspace (name or id) for workspace lists and runs
  --url URL           the API address (else MORCHE_URL or the saved one)

Environment: MORCHE_URL, MORCHE_TOKEN, MORCHE_WORKSPACE.
`

type config struct {
	URL       string `json:"url"`
	Token     string `json:"token"`
	Workspace string `json:"workspace,omitempty"`
}

type cli struct {
	cfg       config
	jsonOut   bool
	workspace string
	http      *http.Client
	out       io.Writer
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "morche:", err)
		os.Exit(1)
	}
}

func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "morche", "config.json"), nil
}

func loadConfig() config {
	var c config
	if p, err := configPath(); err == nil {
		if raw, err := os.ReadFile(p); err == nil {
			_ = json.Unmarshal(raw, &c)
		}
	}
	if v := os.Getenv("MORCHE_URL"); v != "" {
		c.URL = v
	}
	if v := os.Getenv("MORCHE_TOKEN"); v != "" {
		c.Token = v
	}
	if v := os.Getenv("MORCHE_WORKSPACE"); v != "" {
		c.Workspace = v
	}
	return c
}

func saveConfig(c config) error {
	p, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(p, append(raw, '\n'), 0o600)
}

// splitGlobal takes the global flags out wherever they are.
func splitGlobal(args []string, c *cli) ([]string, error) {
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "--") {
			rest = append(rest, a)
			continue
		}
		take := func() (string, error) {
			if hasVal {
				return val, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("--%s needs a value", name)
			}
			i++
			return args[i], nil
		}
		switch name {
		case "json":
			c.jsonOut = true
		case "workspace":
			v, err := take()
			if err != nil {
				return nil, err
			}
			c.workspace = v
		case "url":
			v, err := take()
			if err != nil {
				return nil, err
			}
			c.cfg.URL = v
		default:
			rest = append(rest, a)
		}
	}
	return rest, nil
}

func run(args []string) error {
	c := &cli{cfg: loadConfig(), http: &http.Client{Timeout: 2 * time.Minute}, out: os.Stdout}
	args, err := splitGlobal(args, c)
	if err != nil {
		return err
	}
	if c.workspace == "" {
		c.workspace = c.cfg.Workspace
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(usage)
		return nil
	}
	cmd, rest := args[0], args[1:]
	sub := ""
	if len(rest) > 0 {
		sub = rest[0]
	}
	switch cmd {
	case "login":
		return c.login()
	case "logout":
		c.cfg.Token = ""
		return saveConfig(c.cfg)
	case "whoami":
		return c.whoami()
	case "api":
		return c.api(rest)
	case "run":
		return c.runScript(rest)
	case "servers":
		switch sub {
		case "list", "":
			return c.listServers(rest[min(1, len(rest)):])
		case "check":
			return c.checkServer(rest[1:])
		}
	case "jobs":
		switch sub {
		case "list", "":
			return c.listJobs()
		case "watch":
			if len(rest) < 2 {
				return errors.New("usage: morche jobs watch <id>")
			}
			return c.watchJob(rest[1])
		}
	case "cronjobs":
		switch sub {
		case "list", "":
			return c.listWorkspaceThings("schedules", "Cron jobs")
		case "run":
			return c.runThing("schedules", rest[1:])
		}
	case "automations":
		switch sub {
		case "list", "":
			return c.listWorkspaceThings("automations", "Automations")
		case "run":
			return c.runThing("automations", rest[1:])
		}
	}
	return fmt.Errorf("unknown command %q (morche help)", strings.TrimSpace(cmd+" "+sub))
}

// ---- HTTP ----

type apiError struct {
	Status int
	Detail string
}

func (e *apiError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("the panel answered %d %s", e.Status, http.StatusText(e.Status))
	}
	return fmt.Sprintf("%s (%d)", e.Detail, e.Status)
}

// do sends a request and answers the body; a non-2xx answer is an apiError.
func (c *cli) do(method, path string, body []byte, workspace string) ([]byte, int, error) {
	if c.cfg.URL == "" {
		return nil, 0, errors.New("no panel address: run morche login, or set MORCHE_URL")
	}
	if c.cfg.Token == "" {
		return nil, 0, errors.New("not signed in: run morche login, or set MORCHE_TOKEN")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, strings.TrimRight(c.cfg.URL, "/")+path, r)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "morche-cli/1")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if workspace != "" {
		req.Header.Set("X-Workspace-Id", workspace)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var p struct {
			Detail string `json:"detail"`
			Errors []struct {
				Message  string `json:"message"`
				Location string `json:"location"`
			} `json:"errors"`
		}
		_ = json.Unmarshal(raw, &p)
		d := p.Detail
		for _, e := range p.Errors {
			d += "; " + strings.TrimPrefix(e.Location+": ", ": ") + e.Message
		}
		return raw, resp.StatusCode, &apiError{Status: resp.StatusCode, Detail: d}
	}
	return raw, resp.StatusCode, nil
}

func (c *cli) getJSON(path, workspace string, v any) error {
	raw, _, err := c.do(http.MethodGet, path, nil, workspace)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func (c *cli) postJSON(path, workspace string, body, v any) error {
	b, _ := json.Marshal(body)
	raw, _, err := c.do(http.MethodPost, path, b, workspace)
	if err != nil {
		return err
	}
	if v == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, v)
}

func (c *cli) printJSON(v any) error {
	enc := json.NewEncoder(c.out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (c *cli) table(header string, rows [][]string) {
	w := tabwriter.NewWriter(c.out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, header)
	for _, r := range rows {
		fmt.Fprintln(w, strings.Join(r, "\t"))
	}
	w.Flush()
}

// ---- Commands ----

type me struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	FullName string `json:"full_name"`
	Role     string `json:"role"`
}

func (c *cli) login() error {
	in := bufio.NewReader(os.Stdin)
	if c.cfg.URL == "" || !isTTY() {
		def := c.cfg.URL
		fmt.Fprintf(os.Stderr, "API address%s: ", bracket(def))
		line, _ := in.ReadString('\n')
		if line = strings.TrimSpace(line); line != "" {
			c.cfg.URL = line
		} else if def == "" {
			return errors.New("the API address is needed (e.g. https://panel.example.com/api)")
		}
	}
	c.cfg.URL = strings.TrimRight(c.cfg.URL, "/")
	fmt.Fprint(os.Stderr, "API token (morche_…): ")
	var token string
	if isTTY() {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		token = string(b)
	} else {
		line, _ := in.ReadString('\n')
		token = line
	}
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, "morche_") {
		return errors.New("that isn't a Morche API token (they start with morche_)")
	}
	c.cfg.Token = token
	var u me
	if err := c.getJSON("/auth/me", "", &u); err != nil {
		return fmt.Errorf("the token didn't work: %w", err)
	}
	if err := saveConfig(c.cfg); err != nil {
		return err
	}
	p, _ := configPath()
	fmt.Fprintf(os.Stderr, "Signed in as %s. Saved in %s\n", cmpOr(u.FullName, u.Username), p)
	return nil
}

func isTTY() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

func bracket(s string) string {
	if s == "" {
		return ""
	}
	return " [" + s + "]"
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (c *cli) whoami() error {
	var u me
	if err := c.getJSON("/auth/me", "", &u); err != nil {
		return err
	}
	if c.jsonOut {
		return c.printJSON(u)
	}
	fmt.Fprintf(c.out, "%s (%s, %s) on %s\n", cmpOr(u.FullName, u.Username), u.Username, u.Role, c.cfg.URL)
	return nil
}

func (c *cli) api(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: morche api <METHOD> <path> [-d JSON|@file|@-]")
	}
	method, path := strings.ToUpper(args[0]), args[1]
	var body []byte
	for i := 2; i < len(args); i++ {
		if args[i] != "-d" && args[i] != "--data" {
			return fmt.Errorf("unknown flag %s", args[i])
		}
		if i+1 >= len(args) {
			return errors.New("-d needs a value")
		}
		i++
		d := args[i]
		var err error
		switch {
		case d == "@-":
			body, err = io.ReadAll(os.Stdin)
		case strings.HasPrefix(d, "@"):
			body, err = os.ReadFile(d[1:])
		default:
			body = []byte(d)
		}
		if err != nil {
			return err
		}
		if !json.Valid(body) {
			return errors.New("the body isn't valid JSON")
		}
	}
	ws, err := c.workspaceID(false)
	if err != nil {
		return err
	}
	raw, _, err := c.do(method, path, body, ws)
	if len(raw) > 0 {
		var pretty bytes.Buffer
		if json.Indent(&pretty, raw, "", "  ") == nil {
			raw = append(pretty.Bytes(), '\n')
		}
		_, _ = c.out.Write(raw)
	}
	return err
}

type workspace struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// workspaceID resolves --workspace (a name or id). need: there must be one,
// so the only workspace is picked when none was named.
func (c *cli) workspaceID(need bool) (string, error) {
	if c.workspace == "" && !need {
		return "", nil
	}
	var list struct {
		Items []workspace `json:"items"`
	}
	if err := c.getJSON("/workspaces", "", &list); err != nil {
		return "", err
	}
	if c.workspace == "" {
		if len(list.Items) == 1 {
			return list.Items[0].ID, nil
		}
		names := make([]string, len(list.Items))
		for i, w := range list.Items {
			names[i] = w.Name
		}
		return "", fmt.Errorf("pick a workspace with --workspace (%s)", strings.Join(names, ", "))
	}
	for _, w := range list.Items {
		if w.ID == c.workspace || strings.EqualFold(w.Name, c.workspace) {
			return w.ID, nil
		}
	}
	return "", fmt.Errorf("no workspace %q", c.workspace)
}

type server struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	Name        string `json:"name"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Status      string `json:"status"`
}

func (c *cli) listServers(args []string) error {
	fs := flag.NewFlagSet("servers list", flag.ContinueOnError)
	q := fs.String("q", "", "search names, hosts, tags")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ws, err := c.workspaceID(false)
	if err != nil {
		return err
	}
	v := url.Values{"limit": {"200"}}
	if *q != "" {
		v.Set("q", *q)
	}
	var list struct {
		Items []json.RawMessage `json:"items"`
		Total int               `json:"total"`
	}
	if err := c.getJSON("/servers?"+v.Encode(), ws, &list); err != nil {
		return err
	}
	if c.jsonOut {
		return c.printJSON(list.Items)
	}
	rows := [][]string{}
	for _, raw := range list.Items {
		var s server
		_ = json.Unmarshal(raw, &s)
		rows = append(rows, []string{s.Name, fmt.Sprintf("%s:%d", s.Host, s.Port), s.Status, s.ID})
	}
	c.table("NAME\tADDRESS\tSTATUS\tID", rows)
	if list.Total > len(list.Items) {
		fmt.Fprintf(c.out, "(%d of %d; narrow it with -q)\n", len(list.Items), list.Total)
	}
	return nil
}

// findServer resolves a server name or id.
func (c *cli) findServer(nameOrID string) (server, error) {
	var s server
	if looksLikeID(nameOrID) {
		if err := c.getJSON("/servers/"+nameOrID, "", &s); err == nil {
			return s, nil
		}
	}
	var list struct {
		Items []server `json:"items"`
	}
	if err := c.getJSON("/servers?"+url.Values{"q": {nameOrID}, "limit": {"200"}}.Encode(), "", &list); err != nil {
		return s, err
	}
	var found []server
	for _, x := range list.Items {
		if strings.EqualFold(x.Name, nameOrID) {
			found = append(found, x)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return s, fmt.Errorf("no server named %q", nameOrID)
	}
	return s, fmt.Errorf("%d servers are named %q: use the id", len(found), nameOrID)
}

func looksLikeID(s string) bool { return len(s) == 36 && strings.Count(s, "-") == 4 }

func (c *cli) checkServer(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: morche servers check <name|id>")
	}
	s, err := c.findServer(args[0])
	if err != nil {
		return err
	}
	var out json.RawMessage
	if err := c.postJSON("/servers/"+s.ID+"/check", "", nil, &out); err != nil {
		return err
	}
	if c.jsonOut {
		return c.printJSON(out)
	}
	var r server
	_ = json.Unmarshal(out, &r)
	fmt.Fprintf(c.out, "%s: %s\n", r.Name, r.Status)
	return nil
}

type job struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Title    string `json:"title"`
	State    string `json:"state"`
	Error    string `json:"error"`
	Log      string `json:"log"`
	Progress struct {
		Phase   string `json:"phase"`
		Current string `json:"current"`
		Done    int64  `json:"done"`
		Total   int64  `json:"total"`
	} `json:"progress"`
	CreatedAt time.Time `json:"created_at"`
}

func (c *cli) listJobs() error {
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := c.getJSON("/jobs?limit=50", "", &list); err != nil {
		return err
	}
	if c.jsonOut {
		return c.printJSON(list.Items)
	}
	rows := [][]string{}
	for _, raw := range list.Items {
		var j job
		_ = json.Unmarshal(raw, &j)
		rows = append(rows, []string{j.State, j.Title, j.CreatedAt.Local().Format("Jan 2 15:04"), j.ID})
	}
	c.table("STATE\tTITLE\tSTARTED\tID", rows)
	return nil
}

func finished(state string) bool {
	return state != "queued" && state != "running" && state != ""
}

// watchJob polls a job until it ends, printing its new log lines.
func (c *cli) watchJob(id string) error {
	printed := 0
	last := ""
	for {
		var j job
		if err := c.getJSON("/jobs/"+id, "", &j); err != nil {
			return err
		}
		if !c.jsonOut {
			if len(j.Log) >= printed {
				fmt.Fprint(c.out, j.Log[printed:])
			} else { // the log's head was cut: print what's new
				fmt.Fprint(c.out, j.Log)
			}
			printed = len(j.Log)
			status := j.State
			if j.Progress.Phase != "" {
				status += ": " + j.Progress.Phase
			}
			if status != last && !finished(j.State) {
				fmt.Fprintf(os.Stderr, "· %s\n", status)
				last = status
			}
		}
		if finished(j.State) {
			if c.jsonOut {
				_ = c.printJSON(j)
			} else {
				fmt.Fprintf(os.Stderr, "%s %s\n", j.Title, j.State)
			}
			if j.State != "succeeded" {
				return fmt.Errorf("%s%s", j.State, prefixed(": ", j.Error))
			}
			return nil
		}
		time.Sleep(2 * time.Second)
	}
}

func prefixed(p, s string) string {
	if s == "" {
		return ""
	}
	return p + s
}

type named struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// find resolves a name or id among a workspace's things of a kind
// (scripts, schedules, automations: GET /workspaces/{id}/<kind>).
func (c *cli) find(kind, nameOrID string) (named, string, error) {
	ws, err := c.workspaceID(true)
	if err != nil {
		return named{}, "", err
	}
	var list struct {
		Items []named `json:"items"`
	}
	if err := c.getJSON("/workspaces/"+ws+"/"+kind, ws, &list); err != nil {
		return named{}, ws, err
	}
	var found []named
	for _, x := range list.Items {
		if x.ID == nameOrID || strings.EqualFold(x.Name, nameOrID) {
			found = append(found, x)
		}
	}
	switch len(found) {
	case 1:
		return found[0], ws, nil
	case 0:
		return named{}, ws, fmt.Errorf("nothing named %q in %s", nameOrID, kind)
	}
	return named{}, ws, fmt.Errorf("%d %s are named %q: use the id", len(found), kind, nameOrID)
}

func (c *cli) listWorkspaceThings(kind, title string) error {
	ws, err := c.workspaceID(true)
	if err != nil {
		return err
	}
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := c.getJSON("/workspaces/"+ws+"/"+kind, ws, &list); err != nil {
		return err
	}
	if c.jsonOut {
		return c.printJSON(list.Items)
	}
	rows := [][]string{}
	for _, raw := range list.Items {
		var x struct {
			named
			Enabled   *bool      `json:"enabled"`
			Action    string     `json:"action"`
			NextRunAt *time.Time `json:"next_run_at"`
		}
		_ = json.Unmarshal(raw, &x)
		state := ""
		if x.Enabled != nil {
			state = map[bool]string{true: "on", false: "off"}[*x.Enabled]
		}
		next := ""
		if x.NextRunAt != nil {
			next = x.NextRunAt.Local().Format("Jan 2 15:04")
		}
		rows = append(rows, []string{x.Name, x.Action, state, next, x.ID})
	}
	fmt.Fprintln(c.out, title+":")
	c.table("NAME\tACTION\tSTATE\tNEXT RUN\tID", rows)
	return nil
}

// runThing runs a cron job or automation now: POST /<kind>/{id}/run.
func (c *cli) runThing(kind string, args []string) error {
	wait := false
	var rest []string
	for _, a := range args {
		if a == "--wait" || a == "-w" {
			wait = true
		} else {
			rest = append(rest, a)
		}
	}
	if len(rest) != 1 {
		cmd := map[string]string{"schedules": "cronjobs", "automations": "automations"}[kind]
		return fmt.Errorf("usage: morche %s run <name|id> [--wait]", cmd)
	}
	x, ws, err := c.find(kind, rest[0])
	if err != nil {
		return err
	}
	var out struct {
		Run json.RawMessage `json:"run"`
		Job *job            `json:"job"`
	}
	if err := c.postJSON("/"+kind+"/"+x.ID+"/run", ws, map[string]any{}, &out); err != nil {
		return err
	}
	if c.jsonOut && !wait {
		return c.printJSON(out)
	}
	if out.Job == nil {
		fmt.Fprintf(c.out, "Started %s.\n", x.Name)
		return nil
	}
	fmt.Fprintf(c.out, "Started %s (job %s).\n", x.Name, out.Job.ID)
	if wait {
		return c.watchJob(out.Job.ID)
	}
	return nil
}

func (c *cli) runScript(args []string) error {
	var name, on string
	wait := false
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--wait" || a == "-w":
			wait = true
		case a == "--on":
			if i+1 >= len(args) {
				return errors.New("--on needs servers")
			}
			i++
			on = args[i]
		case strings.HasPrefix(a, "--on="):
			on = strings.TrimPrefix(a, "--on=")
		case name == "":
			name = a
		default:
			return fmt.Errorf("unexpected %q", a)
		}
	}
	if name == "" || on == "" {
		return errors.New("usage: morche run <script> --on <server>[,<server>…] [--wait]")
	}
	script, ws, err := c.find("scripts", name)
	if err != nil {
		return err
	}
	var ids []string
	for _, s := range strings.Split(on, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		srv, err := c.findServer(s)
		if err != nil {
			return err
		}
		ids = append(ids, srv.ID)
	}
	var out struct {
		Run struct {
			ID string `json:"id"`
		} `json:"run"`
		Job job `json:"job"`
	}
	if err := c.postJSON("/script-runs", ws, map[string]any{"script_id": script.ID, "server_ids": ids}, &out); err != nil {
		return err
	}
	if !wait {
		if c.jsonOut {
			return c.printJSON(out)
		}
		fmt.Fprintf(c.out, "Started %s on %d server(s): run %s, job %s\n", script.Name, len(ids), out.Run.ID, out.Job.ID)
		return nil
	}
	jobErr := c.watchJobQuiet(out.Job.ID)
	var detail struct {
		State   string `json:"state"`
		Targets []struct {
			ServerName string `json:"server_name"`
			State      string `json:"state"`
			ExitCode   *int   `json:"exit_code"`
			Error      string `json:"error"`
			Output     string `json:"output"`
		} `json:"targets"`
	}
	if err := c.getJSON("/script-runs/"+out.Run.ID, ws, &detail); err != nil {
		return err
	}
	if c.jsonOut {
		return c.printJSON(detail)
	}
	for _, t := range detail.Targets {
		code := ""
		if t.ExitCode != nil {
			code = fmt.Sprintf(", exit %d", *t.ExitCode)
		}
		fmt.Fprintf(c.out, "==> %s (%s%s)\n", t.ServerName, t.State, code)
		if t.Error != "" {
			fmt.Fprintln(c.out, t.Error)
		}
		fmt.Fprint(c.out, t.Output)
		if t.Output != "" && !strings.HasSuffix(t.Output, "\n") {
			fmt.Fprintln(c.out)
		}
	}
	return jobErr
}

// watchJobQuiet waits for a job without printing its log.
func (c *cli) watchJobQuiet(id string) error {
	for {
		var j job
		if err := c.getJSON("/jobs/"+id, "", &j); err != nil {
			return err
		}
		if finished(j.State) {
			if j.State != "succeeded" {
				return fmt.Errorf("%s%s", j.State, prefixed(": ", j.Error))
			}
			return nil
		}
		time.Sleep(2 * time.Second)
	}
}
