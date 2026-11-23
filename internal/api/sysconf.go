package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/sshpool"
	"github.com/morche/backend/internal/terminal"
)

// Config files on a server (hosts, DNS, clock, network, package sources)
// share one way of being changed: read with a revision, snapshot, write,
// check, apply, and a history row that can be taken back. Changes that can
// cut SSH off (the network) wait 90 seconds for Keep it and undo themselves
// otherwise, the same way the firewall does.

const (
	configDir      = "/run/morche-config"
	configWindow   = 90
	configTimeout  = 3 * time.Minute
	configKeepText = 256 << 10

	cfgExitPrepare = 69
	cfgExitCheck   = 70
	cfgExitApply   = 71
	cfgExitPending = 72
)

var configAreas = []string{"hosts", "dns", "clock", "network", "repos"}

// ---- Types ----

type ConfigChange struct {
	ID        string    `json:"id" format:"uuid"`
	Area      string    `json:"area" enum:"hosts,dns,clock,network,repos"`
	Summary   string    `json:"summary" example:"Add 10.0.0.5 db.internal"`
	User      string    `json:"user" doc:"Who made it"`
	Status    string    `json:"status" enum:"applied,pending,undone" doc:"pending = waiting for Keep it; undone = taken back by the timer or Undo now"`
	Files     []string  `json:"files" doc:"The files it changed"`
	CreatedAt time.Time `json:"created_at"`
}

type ConfigChanges struct {
	Items []ConfigChange `json:"items" doc:"Newest first; each area keeps its last 50"`
}

type ConfigChangeFile struct {
	Path    string `json:"path"`
	Before  string `json:"before"`
	After   string `json:"after"`
	Existed bool   `json:"existed" doc:"The file was there before the change"`
	Exists  bool   `json:"exists" doc:"The file was there after the change"`
	Cut     bool   `json:"cut" doc:"Too big to keep (over 256 KiB), or it holds secrets (shown as <hidden>): it can't be put back"`
}

type ConfigChangeDetail struct {
	Change ConfigChange       `json:"change"`
	Files  []ConfigChangeFile `json:"files"`
}

type ConfigPending struct {
	Summary   string    `json:"summary"`
	ExpiresAt time.Time `json:"expires_at" doc:"When the server undoes it by itself"`
}

type ConfigChangesInput struct {
	ID   string `path:"id" format:"uuid"`
	Area string `query:"area" required:"false" enum:"hosts,dns,clock,network,repos"`
}

type ConfigChangeInput struct {
	ID     string `path:"id" format:"uuid"`
	Change string `path:"change" format:"uuid"`
}

type ConfigAreaInput struct {
	ID   string `path:"id" format:"uuid"`
	Area string `path:"area" enum:"hosts,dns,clock,network,repos"`
}

// ---- Reading ----

type configFile struct {
	Path   string
	Text   string
	Exists bool
}

func fileText(files []configFile, p string) (string, bool) {
	for _, f := range files {
		if f.Path == p {
			return f.Text, f.Exists
		}
	}
	return "", false
}

// readConfigFiles reads paths in one round trip. The revision covers every path
// (missing ones too), so adding a file counts as a change.
func readConfigFiles(ctx context.Context, sh *rootShell, paths ...string) ([]configFile, string, error) {
	if len(paths) == 0 {
		return nil, revisionOf(nil), nil
	}
	script := `for p in ` + quoteAll(paths) + `; do
if [ -f "$p" ] && [ -r "$p" ]; then printf '\036MORCHE 1 %s\n' "$p"; cat "$p"; else printf '\036MORCHE 0 %s\n' "$p"; fi
done`
	out, err := sh.hiding(true).run(ctx, script)
	if err != nil {
		return nil, "", err
	}
	var files []configFile
	for _, chunk := range strings.Split(out, "\x1eMORCHE ")[1:] {
		head, body, _ := strings.Cut(chunk, "\n")
		flag, p, _ := strings.Cut(head, " ")
		files = append(files, configFile{Path: p, Text: body, Exists: flag == "1"})
	}
	return files, revisionOf(files), nil
}

func revisionOf(files []configFile) string {
	h := sha256.New()
	for _, f := range files {
		fmt.Fprintf(h, "%s\x00%t\x00%d\x00%s", f.Path, f.Exists, len(f.Text), f.Text)
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}

// listFiles answers the regular files matching shell globs, sorted.
func listFiles(ctx context.Context, sh *rootShell, globs ...string) ([]string, error) {
	out, err := sh.run(ctx, `for f in `+strings.Join(globs, " ")+`; do [ -f "$f" ] && printf '%s\n' "$f"; done; true`)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l != "" {
			files = append(files, l)
		}
	}
	slices.Sort(files)
	return slices.Compact(files), nil
}

func (h *serverHandler) configRoot(ctx context.Context, id string, c *sshpool.Conn) (*rootShell, error) {
	sh, err := h.rootShell(ctx, id, c)
	if err != nil {
		return nil, err
	}
	if sh.priv == privUser {
		return nil, huma.Error403Forbidden("Changing this needs root or sudo on this server")
	}
	return sh, nil
}

// configPending says what is waiting for Keep it in an area, if anything.
func configPending(ctx context.Context, sh *rootShell, area string) *ConfigPending {
	d := configDir + "/" + area
	out, err := sh.run(ctx, `d=`+d+`; [ -f "$d/armed" ] || exit 0; cat "$d/expires"; echo; cat "$d/summary"`)
	if err != nil || strings.TrimSpace(out) == "" {
		return nil
	}
	exp, summary, _ := strings.Cut(out, "\n")
	sec, err := strconv.ParseInt(strings.TrimSpace(exp), 10, 64)
	if err != nil || time.Unix(sec, 0).Before(time.Now().Add(-5*time.Second)) {
		return nil
	}
	return &ConfigPending{Summary: strings.TrimSpace(summary), ExpiresAt: time.Unix(sec, 0)}
}

// ---- Writing ----

type configWrite struct {
	Path   string
	Text   string
	Remove bool
	Mode   string // default 0644
}

type configPlan struct {
	Area    string
	Summary string
	// Read is compared against the revision, snapshotted and recorded.
	Read []string
	// Keep is snapshotted too (folders a tool writes into).
	Keep   []string
	Writes []configWrite
	// Check runs after writing; Apply after Check. Undo runs after the
	// files are put back when Apply fails or the change is undone.
	Check, Apply, Undo string
	Risky              bool
}

var configLocks sync.Map

func configLock(id, area string) *sync.Mutex {
	l, _ := configLocks.LoadOrStore(id+"/"+area, &sync.Mutex{})
	return l.(*sync.Mutex)
}

// configChange runs a plan. expect is the revision the person saw ("" =
// don't check). It answers the history row's id.
func (h *serverHandler) configChange(ctx context.Context, id, expect string, build func(sh *rootShell) (configPlan, error)) (uuid.UUID, error) {
	var p configPlan
	var before []configFile
	var sh *rootShell
	var lock *sync.Mutex
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		var err error
		if sh, err = h.configRoot(ctx, id, c); err != nil {
			return err
		}
		if p, err = build(sh); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return uuid.Nil, toProblem(err)
	}
	lock = configLock(id, p.Area)
	lock.Lock()
	defer lock.Unlock()

	// Once it starts, it must not stop half way.
	ctx = context.WithoutCancel(ctx)
	c, err := h.conn(ctx, id)
	if err != nil {
		return uuid.Nil, toProblem(err)
	}
	var change uuid.UUID
	err = hold(c, func() error {
		sh, err := h.configRoot(ctx, id, c)
		if err != nil {
			return err
		}
		var rev string
		if before, rev, err = readConfigFiles(ctx, sh, p.Read...); err != nil {
			return err
		}
		if expect != "" && rev != expect {
			return huma.Error409Conflict("This changed on the server since you opened it. Load it again to see the new version.")
		}
		token := make([]byte, 16)
		if _, err := rand.Read(token); err != nil {
			return internalError(err)
		}
		script := configScript(p, hex.EncodeToString(token))
		// The files' contents stay out of the command log.
		var payloads []string
		for _, w := range p.Writes {
			if !w.Remove && w.Text != "" {
				payloads = append(payloads, base64.StdEncoding.EncodeToString([]byte(w.Text)))
			}
		}
		res, err := sh.hiding(false, payloads...).exec(ctx, script, configTimeout, 64<<10)
		lost := huma.Error502BadGateway(fmt.Sprintf("The connection dropped during the change. If it cut Morche off, the server undoes it within %d seconds.", configWindow))
		switch {
		case err != nil || res.timedOut:
			if p.Risky {
				return lost
			}
			if err != nil {
				return err
			}
			return huma.Error504GatewayTimeout("The server took too long")
		case res.code == cfgExitPending:
			return huma.Error409Conflict("Keep or undo the last change first")
		case res.code == cfgExitPrepare:
			return huma.Error422UnprocessableEntity(configMessage(res.output, "Couldn't save a copy of the current files, so nothing was changed"))
		case res.code == cfgExitCheck:
			return huma.Error422UnprocessableEntity("The server refused it, so nothing was changed: " + configMessage(res.output, "the check failed"))
		case res.code == cfgExitApply:
			return huma.Error422UnprocessableEntity("Applying it failed, so it was put back: " + configMessage(res.output, "the command failed"))
		case res.code != 0:
			return huma.Error422UnprocessableEntity(fmt.Sprintf("The change failed (exit %d): %s", res.code, configMessage(res.output, "")))
		}
		if p.Risky && !h.reachable(ctx, id) {
			_, _ = sh.run(ctx, configUndoScript(p.Area))
			return huma.Error422UnprocessableEntity("That change would have cut Morche off from this server, so it was undone.")
		}
		after, _, err := readConfigFiles(ctx, sh, p.Read...)
		if err != nil {
			after = nil
		}
		status := "applied"
		if p.Risky {
			status = "pending"
		}
		change = h.recordConfigChange(ctx, id, p, status, before, after)
		return nil
	})
	return change, toProblem(err)
}

func configMessage(out []byte, fallback string) string {
	ls := strings.Split(strings.TrimSpace(stripANSI(string(out))), "\n")
	if len(ls) > 6 {
		ls = ls[len(ls)-6:]
	}
	msg := strings.TrimSpace(strings.Join(ls, " "))
	if msg == "" {
		return fallback
	}
	return truncate(msg, 600)
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && !(s[i] >= 'A' && s[i] <= 'Z' || s[i] >= 'a' && s[i] <= 'z') {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func rel(p string) string { return strings.TrimPrefix(path.Clean(p), "/") }

// configScript snapshots, writes, checks and applies. The snapshot holds
// every path that exists; putting it back moves the current ones aside
// first, so files the change added go too.
func configScript(p configPlan, token string) string {
	d := configDir + "/" + p.Area
	all := append(append([]string{}, p.Read...), p.Keep...)
	var rels []string
	for _, a := range all {
		rels = append(rels, rel(a))
	}
	var rb strings.Builder
	rb.WriteString("d=" + d + "\nrm -f \"$d/armed\"\ncd /\n")
	rb.WriteString("for p in " + quoteAll(rels) + "; do [ -e \"/$p\" ] && mv \"/$p\" \"/$p.morche-undo\"; done\n")
	rb.WriteString("if tar -C / -xf \"$d/snap.tar\" 2>/dev/null || [ ! -s \"$d/list\" ]; then\n")
	rb.WriteString("  for p in " + quoteAll(rels) + "; do rm -rf \"/$p.morche-undo\"; done\nelse\n")
	rb.WriteString("  for p in " + quoteAll(rels) + "; do [ -e \"/$p.morche-undo\" ] && { rm -rf \"/$p\"; mv \"/$p.morche-undo\" \"/$p\"; }; done\nfi\n")
	if p.Undo != "" {
		rb.WriteString("( " + p.Undo + " ) >/dev/null 2>&1\n")
	}
	rb.WriteString("rm -f \"$d/summary\" \"$d/expires\"\n")

	var b strings.Builder
	b.WriteString(`d=` + d + `
umask 077
mkdir -p "$d" || { echo "Could not write to $d"; exit ` + strconv.Itoa(cfgExitPrepare) + `; }
if [ -f "$d/armed" ] && [ "$(cat "$d/expires" 2>/dev/null || echo 0)" -gt "$(date +%s)" ]; then exit ` + strconv.Itoa(cfgExitPending) + `; fi
rm -f "$d/armed" "$d/list"
for p in ` + quoteAll(rels) + `; do [ -e "/$p" ] && printf '%s\n' "$p" >> "$d/list"; done
touch "$d/list"
if [ -s "$d/list" ]; then tar -C / -cf "$d/snap.tar" -T "$d/list" 2>/dev/null || { echo "Could not save a copy of the current files"; exit ` + strconv.Itoa(cfgExitPrepare) + `; }; else rm -f "$d/snap.tar"; fi
cat > "$d/rollback.sh" <<'MORCHE_ROLLBACK'
` + rb.String() + `MORCHE_ROLLBACK
back() { sh "$d/rollback.sh" >/dev/null 2>&1; }
umask 022
`)
	for _, w := range p.Writes {
		q := terminal.ShellQuote(w.Path)
		if w.Remove {
			b.WriteString("rm -f " + q + " || { back; exit " + strconv.Itoa(cfgExitApply) + "; }\n")
			continue
		}
		mode := w.Mode
		if mode == "" {
			mode = "0644"
		}
		tmp := terminal.ShellQuote(w.Path + ".morche-new")
		b.WriteString("mkdir -p " + terminal.ShellQuote(path.Dir(w.Path)) + " && printf '%s' " +
			terminal.ShellQuote(base64.StdEncoding.EncodeToString([]byte(w.Text))) + " | base64 -d > " + tmp +
			" && chmod " + mode + " " + tmp + " && mv -f " + tmp + " " + q +
			" || { rm -f " + tmp + "; echo \"Could not write " + w.Path + "\"; back; exit " + strconv.Itoa(cfgExitApply) + "; }\n")
	}
	if p.Check != "" {
		b.WriteString("if ! o=$( ( " + p.Check + " ) 2>&1 ); then printf '%s\\n' \"$o\"; back; exit " + strconv.Itoa(cfgExitCheck) + "; fi\n")
	}
	if p.Risky {
		timer := "sleep " + strconv.Itoa(configWindow) + `; [ "$(cat ` + d + `/armed 2>/dev/null)" = ` + token + ` ] && sh ` + d + `/rollback.sh`
		b.WriteString("printf '%s' " + terminal.ShellQuote(p.Summary) + " > \"$d/summary\"\n")
		b.WriteString("echo $(( $(date +%s) + " + strconv.Itoa(configWindow) + " )) > \"$d/expires\"\n")
		b.WriteString("printf '%s' " + token + " > \"$d/armed\"\n")
		b.WriteString("setsid nohup sh -c " + terminal.ShellQuote(timer) + " >/dev/null 2>&1 </dev/null &\n")
	}
	if p.Apply != "" {
		b.WriteString("if ! o=$( ( " + p.Apply + " ) 2>&1 ); then printf '%s\\n' \"$o\"; back; exit " + strconv.Itoa(cfgExitApply) + "; fi\n")
	}
	if !p.Risky {
		b.WriteString(`rm -f "$d/snap.tar" "$d/rollback.sh" "$d/list"` + "\n")
	}
	return b.String()
}

func configKeepScript(area string) string {
	return `d=` + configDir + `/` + area + `
[ -f "$d/armed" ] || exit 3
rm -f "$d/armed" "$d/summary" "$d/expires" "$d/snap.tar" "$d/rollback.sh" "$d/list"
`
}

func configUndoScript(area string) string {
	return `d=` + configDir + `/` + area + `
[ -f "$d/armed" ] || exit 3
sh "$d/rollback.sh"
`
}

var secretLine = regexp.MustCompile(`(?im)^(\s*(?:psk|password|wep-key\d|private-key-password|secret|pin)[^=\n]*=).*$`)

// keptFile is what the history keeps of a file: nothing when it is too big,
// and secrets (Wi-Fi keys, 802.1x passwords) hidden, which also means it
// can't be put back.
func keptFile(text string) (string, bool) {
	if len(text) > configKeepText {
		return "", true
	}
	if secretLine.MatchString(text) {
		return secretLine.ReplaceAllString(text, "${1}<hidden>"), true
	}
	return text, false
}

func (h *serverHandler) recordConfigChange(ctx context.Context, id string, p configPlan, status string, before, after []configFile) uuid.UUID {
	var files []ConfigChangeFile
	for _, b := range before {
		a, exists := fileText(after, b.Path)
		if after == nil {
			a, exists = b.Text, b.Exists
		}
		if a == b.Text && exists == b.Exists {
			continue
		}
		bt, cut1 := keptFile(b.Text)
		at, cut2 := keptFile(a)
		files = append(files, ConfigChangeFile{Path: b.Path, Before: bt, After: at, Existed: b.Exists, Exists: exists, Cut: cut1 || cut2})
	}
	data, _ := json.Marshal(files)
	actor := actorOf(ctx)
	sid := uuid.MustParse(id)
	row, err := h.q.AddConfigChange(ctx, sqlc.AddConfigChangeParams{
		ServerID: sid, UserID: actor.id, UserName: actor.name, Area: p.Area,
		Summary: truncate(p.Summary, 300), Status: status, Files: data,
	})
	if err != nil {
		slog.Warn("save a config change", "server", id, "error", err)
		return uuid.Nil
	}
	_ = h.q.PruneConfigChanges(ctx, sqlc.PruneConfigChangesParams{ServerID: sid, Area: p.Area})
	return row
}

func (h *serverHandler) settleConfig(ctx context.Context, id, area, status string) {
	_ = h.q.SettleConfigChanges(ctx, sqlc.SettleConfigChangesParams{ServerID: uuid.MustParse(id), Area: area, Status: status})
}

// ---- Taking a change back ----

// configRestorers give each area's Check/Apply/Undo for putting files back.
var configRestorers = map[string]func(ctx context.Context, h *serverHandler, id string, sh *rootShell, files []ConfigChangeFile) (configPlan, error){}

func changeOf(id uuid.UUID, user, area, summary, status string, files []byte, at time.Time) ConfigChange {
	var fs []ConfigChangeFile
	_ = json.Unmarshal(files, &fs)
	paths := make([]string, 0, len(fs))
	for _, f := range fs {
		paths = append(paths, f.Path)
	}
	return ConfigChange{ID: id.String(), Area: area, Summary: summary, User: user, Status: status, Files: paths, CreatedAt: at}
}

func registerConfigHistory(api huma.API, h *serverHandler) {
	tags := []string{"Server config"}

	huma.Register(api, huma.Operation{
		OperationID: "list-config-changes",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/config-changes",
		Summary:     "Config changes made through Morche",
		Description: "Changes to hosts, DNS, clock, network and package sources, newest first.",
		Tags:        tags,
	}, func(ctx context.Context, in *ConfigChangesInput) (*struct{ Body ConfigChanges }, error) {
		var area *string
		if in.Area != "" {
			area = &in.Area
		}
		rows, err := h.q.ListConfigChanges(ctx, sqlc.ListConfigChangesParams{ServerID: uuid.MustParse(in.ID), Area: area})
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct{ Body ConfigChanges }{ConfigChanges{Items: []ConfigChange{}}}
		for _, r := range rows {
			out.Body.Items = append(out.Body.Items, changeOf(r.ID, r.UserName, r.Area, r.Summary, r.Status, r.Files, r.CreatedAt))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-config-change",
		Method:      http.MethodGet,
		Path:        "/servers/{id}/config-changes/{change}",
		Summary:     "One config change with the files before and after",
		Tags:        tags,
	}, func(ctx context.Context, in *ConfigChangeInput) (*struct{ Body ConfigChangeDetail }, error) {
		r, err := h.configChangeRow(ctx, in.ID, in.Change)
		if err != nil {
			return nil, err
		}
		out := &struct{ Body ConfigChangeDetail }{}
		out.Body.Change = changeOf(r.ID, r.UserName, r.Area, r.Summary, r.Status, r.Files, r.CreatedAt)
		_ = json.Unmarshal(r.Files, &out.Body.Files)
		if out.Body.Files == nil {
			out.Body.Files = []ConfigChangeFile{}
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "restore-config-change",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/config-changes/{change}/restore",
		Summary:     "Put the files back as they were before a change",
		Description: "Writes the files back through the same checks as any change. A network change waits for Keep it like any other.",
		Tags:        tags,
	}, func(ctx context.Context, in *ConfigChangeInput) (*struct{ Body ConfigChange }, error) {
		r, err := h.configChangeRow(ctx, in.ID, in.Change)
		if err != nil {
			return nil, err
		}
		var files []ConfigChangeFile
		_ = json.Unmarshal(r.Files, &files)
		if len(files) == 0 {
			return nil, huma.Error422UnprocessableEntity("This change has no files to put back")
		}
		if slices.ContainsFunc(files, func(f ConfigChangeFile) bool { return f.Cut }) {
			return nil, huma.Error422UnprocessableEntity("A file of this change was too big to keep or holds secrets, so it can't be put back")
		}
		restore := configRestorers[r.Area]
		id, err := h.configChange(ctx, in.ID, "", func(sh *rootShell) (configPlan, error) {
			p, err := restore(ctx, h, in.ID, sh, files)
			if err != nil {
				return p, err
			}
			p.Area = r.Area
			p.Summary = "Go back: " + r.Summary
			for _, f := range files {
				if !slices.Contains(p.Read, f.Path) {
					p.Read = append(p.Read, f.Path)
				}
				p.Writes = append(p.Writes, configWrite{Path: f.Path, Text: f.Before, Remove: !f.Existed})
			}
			return p, nil
		})
		if err != nil {
			return nil, err
		}
		row, err := h.configChangeRow(ctx, in.ID, id.String())
		if err != nil {
			return nil, err
		}
		return &struct{ Body ConfigChange }{changeOf(row.ID, row.UserName, row.Area, row.Summary, row.Status, row.Files, row.CreatedAt)}, nil
	})

	for _, op := range []struct{ id, verb, summary string }{
		{"keep-config-change", "keep", "Keep the change that's waiting"},
		{"undo-config-change", "undo", "Undo the change that's waiting"},
	} {
		huma.Register(api, huma.Operation{
			OperationID: op.id,
			Method:      http.MethodPost,
			Path:        "/servers/{id}/config/{area}/" + op.verb,
			Summary:     op.summary,
			Tags:        tags,
		}, func(ctx context.Context, in *ConfigAreaInput) (*struct{}, error) {
			lock := configLock(in.ID, in.Area)
			lock.Lock()
			defer lock.Unlock()
			script, status := configKeepScript(in.Area), "applied"
			if op.verb == "undo" {
				script, status = configUndoScript(in.Area), "undone"
			}
			err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
				sh, err := h.configRoot(ctx, in.ID, c)
				if err != nil {
					return err
				}
				res, err := sh.exec(ctx, script, configTimeout, 4<<10)
				if err != nil {
					return err
				}
				if res.code == 3 {
					h.settleConfig(ctx, in.ID, in.Area, "undone")
					return huma.Error409Conflict("Nothing is waiting: time ran out and the server undid the change")
				}
				h.settleConfig(ctx, in.ID, in.Area, status)
				return nil
			})
			return &struct{}{}, toProblem(err)
		})
	}
}

func (h *serverHandler) configChangeRow(ctx context.Context, server, change string) (sqlc.ServerConfigChange, error) {
	sid, err := uuid.Parse(server)
	if err != nil {
		return sqlc.ServerConfigChange{}, huma.Error404NotFound("No such change")
	}
	cid, err := uuid.Parse(change)
	if err != nil {
		return sqlc.ServerConfigChange{}, huma.Error404NotFound("No such change")
	}
	r, err := h.q.GetConfigChange(ctx, sqlc.GetConfigChangeParams{ID: cid, ServerID: sid})
	if err != nil {
		return r, huma.Error404NotFound("No such change")
	}
	return r, nil
}
