package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/terminal"
)

// ---- Docker daemon config (daemon.json) ----
//
// The engine's own settings file, read and written over SSH as root. The
// file in use is the one dockerd was started with (--config-file), else
// /etc/docker/daemon.json. A save is checked with `dockerd --validate` when
// the engine has it, keeps the old copy beside it (.morcheh-bak), and can be
// applied by a reload (SIGHUP: only some keys) or a restart, which puts the
// old file back when Docker doesn't come up with the new one.

const daemonMaxBytes = 1 << 20

// When a reload last applied the file, per server: a reload doesn't change
// the process' start time, so `pending` would stay true without it.
var daemonReloads sync.Map // server id → time.Time

type DockerDaemonConfig struct {
	Supported  bool       `json:"supported" doc:"A Docker engine (dockerd) is installed or running; Podman has no daemon.json"`
	Note       string     `json:"note,omitempty" doc:"Why it isn't supported, or something to know"`
	Path       string     `json:"path" doc:"The file dockerd reads"`
	Exists     bool       `json:"exists"`
	Content    string     `json:"content"`
	Revision   string     `json:"revision" doc:"sha256 of the content, empty when there is no file; send it back with a save"`
	Previous   string     `json:"previous" doc:"The copy kept by the last save (.morcheh-bak), empty when none"`
	Writable   bool       `json:"writable" doc:"Morche can write it: root or sudo"`
	Running    bool       `json:"running"`
	Manager    string     `json:"manager" enum:"systemd,snap,openrc,sysv,none" doc:"What restarts Docker; none = Morche can't restart it (it is PID 1 in a container, or unknown)"`
	CanReload  bool       `json:"can_reload"`
	CanRestart bool       `json:"can_restart"`
	Validates  bool       `json:"validates" doc:"dockerd --validate is available, so a save is checked first"`
	Rootless   bool       `json:"rootless"`
	Flags      []string   `json:"flags" doc:"dockerd's command line; a setting given both here and in the file stops Docker from starting"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	ModifiedAt *time.Time `json:"modified_at,omitempty"`
	Pending    bool       `json:"pending" doc:"The file changed after Docker started (or was last reloaded)"`
}

type DockerDaemonSaveBody struct {
	Content  string `json:"content" maxLength:"1048576" doc:"A JSON object; empty removes the file (Docker's defaults)"`
	Revision string `json:"revision" doc:"From the read; 409 when the file changed since"`
	Force    bool   `json:"force,omitempty" doc:"Overwrite even when the file changed since it was read"`
	Apply    string `json:"apply" enum:"none,reload,restart" default:"none"`
}

type DockerDaemonApplyBody struct {
	Apply string `json:"apply" enum:"reload,restart"`
}

type DockerDaemonResult struct {
	Config  DockerDaemonConfig `json:"config"`
	Applied string             `json:"applied" enum:"none,reload,restart"`
	Output  string             `json:"output,omitempty" doc:"What the restart printed, when it says anything"`
}

// daemonDetect finds dockerd, its config file and what restarts it.
const daemonDetect = `pid=$( (pgrep -xo dockerd || pidof -s dockerd) 2>/dev/null | head -n1)
cfg=
if [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ]; then
  cfg=$(tr '\0' '\n' < "/proc/$pid/cmdline" | awk 'p{print;exit} /^--config-file=/{sub(/^--config-file=/,"");print;exit} $0=="--config-file"{p=1}')
fi
[ -n "$cfg" ] || cfg=/etc/docker/daemon.json
if [ "$pid" = 1 ]; then mgr=none
else case "$cfg" in
  /var/snap/*|/snap/*) mgr=snap ;;
  *) if [ -d /run/systemd/system ] && systemctl cat docker.service >/dev/null 2>&1; then mgr=systemd
     elif command -v rc-service >/dev/null 2>&1 && [ -e /etc/init.d/docker ]; then mgr=openrc
     elif command -v service >/dev/null 2>&1 && [ -e /etc/init.d/docker ]; then mgr=sysv
     else mgr=none; fi ;;
esac; fi
`

const daemonReadScript = daemonDetect + `echo "pid=$pid"
echo "path=$cfg"
echo "mgr=$mgr"
if [ -n "$pid" ]; then
  st=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null)
  bt=$(awk '/^btime/{print $2}' /proc/stat 2>/dev/null)
  hz=$(getconf CLK_TCK 2>/dev/null || echo 100)
  [ -n "$st" ] && [ -n "$bt" ] && echo "started=$((bt + st / hz))"
  echo "uid=$(awk '/^Uid:/{print $2}' "/proc/$pid/status" 2>/dev/null)"
  echo "args=$(base64 < "/proc/$pid/cmdline" 2>/dev/null | tr -d '\n')"
fi
command -v dockerd >/dev/null 2>&1 && echo dockerd=1
command -v dockerd >/dev/null 2>&1 && dockerd --help 2>&1 | grep -q -- '--validate' && echo validate=1
command -v podman >/dev/null 2>&1 && echo podman=1
if [ -f "$cfg" ]; then
  echo "mtime=$(stat -c %Y "$cfg")"
  echo "file=$(head -c 1048577 "$cfg" | base64 | tr -d '\n')"
fi
[ -f "$cfg.morcheh-bak" ] && echo "prev=$(head -c 1048577 "$cfg.morcheh-bak" | base64 | tr -d '\n')"
exit 0
`

// daemonApply is shell for applying the file: $apply = reload|restart.
// Exit 6 = reload failed, 4 = Docker didn't come back.
const daemonApplyFuncs = `restart_docker() {
  case $mgr in
    systemd) systemctl restart docker ;;
    snap) snap restart docker ;;
    openrc) rc-service docker restart ;;
    sysv) service docker restart ;;
    *) echo "Morche can't restart Docker on this server."; return 1 ;;
  esac
}
docker_up() {
  i=0
  while [ $i -lt 60 ]; do
    if command -v docker >/dev/null 2>&1; then
      docker info >/dev/null 2>&1 && return 0
    else
      pgrep -x dockerd >/dev/null 2>&1 && sleep 3 && return 0
    fi
    i=$((i + 1)); sleep 1
  done
  return 1
}
docker_logs() {
  if [ "$mgr" = systemd ] && command -v journalctl >/dev/null 2>&1; then
    journalctl -u docker -n 20 --no-pager -o cat --since "-3min" 2>/dev/null
  fi
}
reload_docker() {
  [ -n "$pid" ] || { echo "Docker isn't running."; return 1; }
  kill -HUP "$pid" || return 1
  sleep 1
  kill -0 "$pid" 2>/dev/null || { echo "Docker stopped after the reload."; return 1; }
}
`

func daemonRevision(content []byte, exists bool) string {
	if !exists {
		return ""
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func (h *serverHandler) readDaemonConfig(ctx context.Context, id string, sh *rootShell) (DockerDaemonConfig, error) {
	out, err := sh.hiding(true).run(ctx, daemonReadScript)
	if err != nil {
		return DockerDaemonConfig{}, err
	}
	d := DockerDaemonConfig{Flags: []string{}, Writable: sh.priv != privUser, Manager: "none"}
	var hasDockerd, podman bool
	var started int64
	for line := range strings.SplitSeq(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "pid":
			d.Running = v != ""
		case "path":
			d.Path = v
		case "mgr":
			d.Manager = v
		case "started":
			started, _ = strconv.ParseInt(v, 10, 64)
		case "uid":
			d.Rootless = v != "" && v != "0"
		case "args":
			raw, _ := base64.StdEncoding.DecodeString(v)
			for a := range strings.SplitSeq(strings.TrimRight(string(raw), "\x00"), "\x00") {
				if a != "" {
					d.Flags = append(d.Flags, a)
				}
			}
		case "dockerd":
			hasDockerd = true
		case "validate":
			d.Validates = true
		case "podman":
			podman = true
		case "mtime":
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				t := time.Unix(n, 0).UTC()
				d.ModifiedAt = &t
			}
		case "file":
			b, err := base64.StdEncoding.DecodeString(v)
			if err == nil {
				d.Exists = true
				d.Content = string(b)
			}
		case "prev":
			if b, err := base64.StdEncoding.DecodeString(v); err == nil {
				d.Previous = string(b)
			}
		}
	}
	d.Supported = hasDockerd || d.Running
	switch {
	case !d.Supported && podman:
		d.Note = "This server runs Podman, which has no daemon.json: its settings live in containers.conf."
	case !d.Supported:
		d.Note = "Docker isn't installed on this server."
	case d.Rootless:
		d.Note = "Docker runs rootless here; its settings are in that user's ~/.config/docker/daemon.json, which Morche doesn't edit yet."
		d.Supported = false
	case len(d.Content) > daemonMaxBytes:
		d.Note = "The file is larger than 1 MB, so Morche doesn't open it."
		d.Supported = false
		d.Content = ""
	case !d.Writable:
		d.Note = "The login user isn't root and has no sudo, so the file can only be read."
	}
	d.Revision = daemonRevision([]byte(d.Content), d.Exists)
	d.CanReload = d.Writable && d.Running
	d.CanRestart = d.Writable && d.Manager != "none"
	if started > 0 {
		t := time.Unix(started, 0).UTC()
		d.StartedAt = &t
		since := t
		if r, ok := daemonReloads.Load(id); ok && r.(time.Time).After(since) {
			since = r.(time.Time)
		}
		d.Pending = d.ModifiedAt != nil && d.ModifiedAt.After(since)
	}
	return d, nil
}

// checkDaemonJSON says what's wrong with content as a daemon.json, or "".
func checkDaemonJSON(content string) string {
	if strings.TrimSpace(content) == "" {
		return ""
	}
	dec := json.NewDecoder(strings.NewReader(content))
	var v any
	if err := dec.Decode(&v); err != nil {
		return "This isn't valid JSON: " + err.Error()
	}
	if _, ok := v.(map[string]any); !ok {
		return "daemon.json must be a JSON object: { … }"
	}
	if dec.More() {
		return "There is more after the closing }"
	}
	return ""
}

// daemonFlagKeys maps dockerd flags to their daemon.json keys where the
// names differ; the rest share the name.
var daemonFlagKeys = map[string]string{
	"H": "hosts", "host": "hosts",
	"insecure-registry":    "insecure-registries",
	"registry-mirror":      "registry-mirrors",
	"log-opt":              "log-opts",
	"label":                "labels",
	"storage-opt":          "storage-opts",
	"exec-opt":             "exec-opts",
	"default-ulimit":       "default-ulimits",
	"add-runtime":          "runtimes",
	"authorization-plugin": "authorization-plugins",
	"dns-opt":              "dns-opts",
	"default-address-pool": "default-address-pools",
	"D":                    "debug", "l": "log-level", "G": "group", "b": "bridge", "p": "pidfile",
}

// daemonFlagClashes lists the keys set both on dockerd's command line and in
// content: dockerd refuses to start with such a file.
func daemonFlagClashes(flags []string, content string) []string {
	var cfg map[string]any
	if json.Unmarshal([]byte(content), &cfg) != nil || len(cfg) == 0 {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for i, arg := range flags {
		if i == 0 || !strings.HasPrefix(arg, "-") || arg == "-" || arg == "--" {
			continue
		}
		name, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		key := name
		if k, ok := daemonFlagKeys[name]; ok {
			key = k
		}
		if _, ok := cfg[key]; ok && !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	return out
}

func tailText(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = "…" + s[len(s)-n:]
	}
	return s
}

func registerDockerDaemon(api huma.API, h *serverHandler) {
	tags := []string{"Containers"}
	base := "/servers/{id}/docker/daemon"

	huma.Register(api, huma.Operation{
		OperationID: "get-docker-daemon-config",
		Method:      http.MethodGet,
		Path:        base,
		Summary:     "Docker's daemon.json",
		Description: "The engine's settings file, where it is, whether Morche can write it, and how a change can be applied.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*struct{ Body DockerDaemonConfig }, error) {
		out := &struct{ Body DockerDaemonConfig }{}
		err := h.withShell(ctx, in.ID, func(_ *sshpool.Conn, sh *rootShell) error {
			d, err := h.readDaemonConfig(ctx, in.ID, sh)
			out.Body = d
			return err
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "save-docker-daemon-config",
		Method:      http.MethodPut,
		Path:        base,
		Summary:     "Save Docker's daemon.json",
		Description: "Checks the JSON (and `dockerd --validate` when there is one), keeps the old file as daemon.json.morcheh-bak, writes the new one and optionally reloads or restarts Docker. A restart that doesn't bring Docker back puts the old file back and restarts again (422 with Docker's log). 409 when the file changed since it was read.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body DockerDaemonSaveBody
	}) (*struct{ Body DockerDaemonResult }, error) {
		if msg := checkDaemonJSON(in.Body.Content); msg != "" {
			return nil, fieldError("body.content", msg, nil)
		}
		apply := in.Body.Apply
		if apply == "" {
			apply = "none"
		}
		out := &struct{ Body DockerDaemonResult }{}
		err := h.withShell(ctx, in.ID, func(_ *sshpool.Conn, sh *rootShell) error {
			cur, err := h.readDaemonConfig(ctx, in.ID, sh)
			if err != nil {
				return err
			}
			switch {
			case !cur.Supported:
				return huma.Error422UnprocessableEntity(cur.Note)
			case !cur.Writable:
				return huma.Error403Forbidden(cur.Note)
			case apply == "restart" && !cur.CanRestart:
				return huma.Error422UnprocessableEntity("Morche can't restart Docker on this server; save without restarting and restart it yourself.")
			case apply == "reload" && !cur.CanReload:
				return huma.Error422UnprocessableEntity("Docker isn't running, so there is nothing to reload.")
			}
			if keys := daemonFlagClashes(cur.Flags, in.Body.Content); len(keys) > 0 {
				return fieldError("body.content", "Docker wouldn't start: "+strings.Join(keys, ", ")+" is also set as a flag on its command line. Remove it from the file, or from the command line.", nil)
			}
			content := in.Body.Content
			if strings.TrimSpace(content) != "" && !strings.HasSuffix(content, "\n") {
				content += "\n"
			}
			if strings.TrimSpace(content) == "" {
				content = ""
			}

			var b strings.Builder
			b.WriteString(daemonDetect)
			b.WriteString(daemonApplyFuncs)
			b.WriteString("expected=" + terminal.ShellQuote(in.Body.Revision) + "\n")
			if in.Body.Force {
				b.WriteString("force=1\n")
			} else {
				b.WriteString("force=0\n")
			}
			b.WriteString(`cur=; had=0
if [ -f "$cfg" ]; then had=1; cur=$(sha256sum < "$cfg" | cut -c1-64); fi
[ "$force" = 1 ] || [ "$cur" = "$expected" ] || { echo "The file changed since it was read."; exit 9; }
d=$(dirname "$cfg"); mkdir -p "$d" || exit 5
new=$(mktemp "$d/.morcheh-daemon.XXXXXX") || exit 5
trap 'rm -f "$new"' EXIT
`)
			b.WriteString("printf '%s' " + terminal.ShellQuote(base64.StdEncoding.EncodeToString([]byte(content))) + " | base64 -d > \"$new\" || exit 5\n")
			b.WriteString(`if [ -s "$new" ] && command -v dockerd >/dev/null 2>&1 && dockerd --help 2>&1 | grep -q -- '--validate'; then
  out=$(dockerd --validate --config-file "$new" 2>&1) || { printf '%s\n' "$out"; exit 2; }
fi
[ "$had" = 1 ] && cp -p "$cfg" "$cfg.morcheh-bak"
if [ -s "$new" ]; then chmod 644 "$new" && mv -f "$new" "$cfg" || exit 5
else rm -f "$cfg"; fi
`)
			b.WriteString("apply=" + apply + "\n")
			b.WriteString(`case $apply in
  reload) reload_docker || exit 6 ;;
  restart)
    if restart_docker 2>&1 && docker_up; then exit 0; fi
    echo "==> Docker didn't start with the new file; putting the old one back."
    docker_logs
    if [ "$had" = 1 ]; then cp -p "$cfg.morcheh-bak" "$cfg"; else rm -f "$cfg"; fi
    [ "$mgr" = systemd ] && systemctl reset-failed docker >/dev/null 2>&1
    if restart_docker >/dev/null 2>&1 && docker_up; then exit 3; fi
    exit 4 ;;
esac
exit 0
`)
			res, err := sh.exec(ctx, b.String(), 4*time.Minute, 64<<10)
			if err != nil {
				return err
			}
			if apply == "restart" {
				h.docker.drop(in.ID)
			}
			text := tailText(string(bytes.ToValidUTF8(res.output, nil)), 3000)
			switch {
			case res.timedOut:
				return huma.Error504GatewayTimeout("Docker took too long to come back. Check it on the server.")
			case res.code == 9:
				return huma.Error409Conflict("Someone changed daemon.json after you opened it. Load theirs, or overwrite it.")
			case res.code == 2:
				return fieldError("body.content", "Docker refused this config: "+text, nil)
			case res.code == 5:
				return huma.Error422UnprocessableEntity("Couldn't write the file: " + text)
			case res.code == 6:
				return huma.Error422UnprocessableEntity("Saved, but the reload failed: " + text)
			case res.code == 3:
				return huma.Error422UnprocessableEntity("Docker didn't start with this config, so the old file is back and Docker is running again.\n\n" + text)
			case res.code == 4:
				return huma.Error422UnprocessableEntity("Docker didn't start, even with the old file put back. Check it on the server now.\n\n" + text)
			case res.code != 0:
				return huma.Error422UnprocessableEntity("Saving failed: " + text)
			}
			if apply == "reload" {
				daemonReloads.Store(in.ID, time.Now())
			}
			d, err := h.readDaemonConfig(ctx, in.ID, sh)
			out.Body = DockerDaemonResult{Config: d, Applied: apply, Output: text}
			return err
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "apply-docker-daemon-config",
		Method:      http.MethodPost,
		Path:        base + "/apply",
		Summary:     "Reload or restart Docker",
		Description: "Applies the saved daemon.json: `reload` sends dockerd SIGHUP (only some settings take effect), `restart` restarts the service and waits for it (422 with Docker's log when it doesn't come back).",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body DockerDaemonApplyBody
	}) (*struct{ Body DockerDaemonResult }, error) {
		out := &struct{ Body DockerDaemonResult }{}
		err := h.withShell(ctx, in.ID, func(_ *sshpool.Conn, sh *rootShell) error {
			cur, err := h.readDaemonConfig(ctx, in.ID, sh)
			if err != nil {
				return err
			}
			switch {
			case !cur.Supported:
				return huma.Error422UnprocessableEntity(cur.Note)
			case !cur.Writable:
				return huma.Error403Forbidden(cur.Note)
			case in.Body.Apply == "restart" && !cur.CanRestart:
				return huma.Error422UnprocessableEntity("Morche can't restart Docker on this server.")
			case in.Body.Apply == "reload" && !cur.CanReload:
				return huma.Error422UnprocessableEntity("Docker isn't running, so there is nothing to reload.")
			}
			script := daemonDetect + daemonApplyFuncs + "apply=" + in.Body.Apply + "\n" + `case $apply in
  reload) reload_docker || exit 6 ;;
  restart) if restart_docker 2>&1 && docker_up; then exit 0; fi; docker_logs; exit 4 ;;
esac
exit 0
`
			res, err := sh.exec(ctx, script, 3*time.Minute, 64<<10)
			if err != nil {
				return err
			}
			if in.Body.Apply == "restart" {
				h.docker.drop(in.ID)
			}
			text := tailText(string(bytes.ToValidUTF8(res.output, nil)), 3000)
			switch {
			case res.timedOut:
				return huma.Error504GatewayTimeout("Docker took too long to come back. Check it on the server.")
			case res.code == 6:
				return huma.Error422UnprocessableEntity("The reload failed: " + text)
			case res.code != 0:
				return huma.Error422UnprocessableEntity("Docker didn't come back after the restart. Check it on the server.\n\n" + text)
			}
			if in.Body.Apply == "reload" {
				daemonReloads.Store(in.ID, time.Now())
			}
			d, err := h.readDaemonConfig(ctx, in.ID, sh)
			out.Body = DockerDaemonResult{Config: d, Applied: in.Body.Apply, Output: text}
			return err
		})
		return out, err
	})
}
