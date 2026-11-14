package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/firewall"
	"github.com/morcheh/backend/internal/sshpool"
)

// Who may reach a container's published ports. Docker's ports skip ufw and
// firewalld, so these limits live in their own chain under DOCKER-USER (see
// firewall/docker.go), with their own files and boot service. They don't
// depend on which firewall is in charge, or on whether there is one.

const (
	ctDir     = "/etc/morcheh"
	ctList    = ctDir + "/docker-limits.json"
	ctBin     = "/usr/local/sbin/morcheh-docker-limits"
	ctService = "morcheh-docker-limits"
	ctUnit    = "/etc/systemd/system/" + ctService + ".service"
)

type ContainerAccess struct {
	Access     string                    `json:"access" enum:"root,sudo,user"`
	Init       string                    `json:"init" enum:"systemd,openrc,none"`
	Docker     bool                      `json:"docker" doc:"Docker is installed"`
	Running    bool                      `json:"running" doc:"Docker answers"`
	Supported  bool                      `json:"supported" doc:"Limits can be set here"`
	Problem    string                    `json:"problem,omitempty" doc:"Why limits can't be set, or why Docker didn't answer"`
	Loaded     bool                      `json:"loaded" doc:"The saved limits are in force right now"`
	Persistent bool                      `json:"persistent" doc:"They're loaded again after a restart"`
	IPv6       bool                      `json:"ipv6" doc:"IPv6 traffic is limited too"`
	Revision   string                    `json:"revision" doc:"Send it back with a change"`
	Limits     []firewall.ContainerLimit `json:"limits"`
	Published  []firewall.PublishedPort  `json:"published" doc:"Ports running containers publish on this server"`
	SSHPort    int                       `json:"ssh_port"`
	MorchehIP  string                    `json:"morcheh_ip" doc:"The address this server sees Morche's connection from"`
	YourIP     string                    `json:"your_ip" doc:"The address of the person asking, when it isn't a loopback one"`
}

type ContainerAccessOutput struct{ Body ContainerAccess }

type ContainerLimitBody struct {
	Protocol string   `json:"protocol" enum:"tcp,udp"`
	Port     string   `json:"port" maxLength:"11" doc:"The port on the server, or a range like 8000-8010" example:"3030"`
	Allow    []string `json:"allow" maxItems:"200" doc:"Addresses or networks let in; empty = nobody from outside this server" example:"[\"203.0.113.7\"]"`
	Comment  string   `json:"comment,omitempty" maxLength:"120"`
}

type ContainerAccessBody struct {
	Limits   []ContainerLimitBody `json:"limits" maxItems:"200" doc:"The whole list: what's left out is removed"`
	Revision string               `json:"revision" maxLength:"64" doc:"From the overview; a different one means it changed meanwhile (409)"`
}

func registerFirewallContainers(api huma.API, h *serverHandler, base string) {
	tags := []string{"Firewall"}

	huma.Register(api, huma.Operation{
		OperationID: "get-container-access",
		Method:      http.MethodGet,
		Path:        base + "/containers",
		Summary:     "Who may reach containers' published ports",
		Description: "Docker publishes ports past ufw and firewalld. These limits are kept in a chain of Morche's own under DOCKER-USER.",
		Tags:        tags,
	}, func(ctx context.Context, in *ServerIDPath) (*ContainerAccessOutput, error) {
		out := &ContainerAccessOutput{}
		err := h.withConn(ctx, in.ID, func(c *sshpool.Conn) error {
			sh, err := h.rootShell(ctx, in.ID, c)
			if err != nil {
				return err
			}
			a, err := collectContainerAccess(ctx, sh)
			if err == nil {
				out.Body = *a
			}
			return err
		})
		return out, toProblem(err)
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-container-access",
		Method:      http.MethodPut,
		Path:        base + "/containers",
		Summary:     "Set who may reach containers' published ports",
		Description: "Replaces the whole list and loads it at once; an empty list takes Morche's chain and its boot service away. " +
			"Sending the same list again loads it again. 409 when the list changed meanwhile.",
		Tags: tags,
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body ContainerAccessBody
	}) (*ContainerAccessOutput, error) {
		return h.setContainerAccess(ctx, in.ID, in.Body)
	})
}

var ctCollectScript = fwEnv + `m=` + fwMarker + `
echo "$m host"
` + hostScript + `
echo "$m limits"; cat ` + ctList + ` 2>/dev/null; echo
echo "$m daemon"; cat /etc/docker/daemon.json 2>/dev/null; echo
if command -v docker >/dev/null 2>&1; then
  echo "$m docker"
  if out=$(timeout 15 docker ps --format '{{.Names}}	{{.Ports}}' 2>&1); then
    echo "$m ps"; printf '%s\n' "$out"
  else
    echo "$m ps-error"; printf '%s\n' "$out" | tail -n 2
  fi
fi
for t in iptables ip6tables; do
  command -v "$t" >/dev/null 2>&1 || continue
  echo "$m $t"; "$t" -w -S DOCKER-USER 2>/dev/null
  echo "$m $t-chain"; "$t" -w -S ` + firewall.ContainerChain + ` 2>/dev/null
done
echo "$m boot"
` + enabledScript(ctService) + `exit 0
`

func collectContainerAccess(ctx context.Context, sh *rootShell) (*ContainerAccess, error) {
	raw, err := sh.run(ctx, ctCollectScript)
	if err != nil {
		return nil, err
	}
	conn, err := run(ctx, sh.c, `echo "$SSH_CONNECTION"`)
	if err != nil {
		return nil, err
	}
	a := parseContainerAccess(splitFwSections(raw), sh.priv.access(), conn)
	if ip := clientOf(ctx).ip; ip != "" {
		if addr, err := netip.ParseAddr(ip); err == nil && !addr.IsLoopback() {
			a.YourIP = addr.Unmap().String()
		}
	}
	return a, nil
}

func parseContainerAccess(s map[string]string, access, conn string) *ContainerAccess {
	host := parseHost(s["host"])
	a := &ContainerAccess{
		Access: access, Init: host.init,
		Limits:    firewall.ParseContainerLimits(s["limits"]),
		Published: []firewall.PublishedPort{},
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(s["limits"])))
	a.Revision = hex.EncodeToString(sum[:8])
	if f := strings.Fields(conn); len(f) == 4 {
		a.MorchehIP = f[0]
		a.SSHPort, _ = strconv.Atoi(f[3])
	}
	_, a.Docker = s["docker"]
	if ps, ok := s["ps"]; ok {
		a.Running = true
		a.Published = firewall.ParseDockerPorts(ps)
	}
	for i, p := range a.Published {
		for _, l := range a.Limits {
			if l.Covers(p.Protocol, p.Port) {
				a.Published[i].Limit = l.ID
				break
			}
		}
	}
	a.Persistent = strings.Contains(s["boot"], "enabled")
	_, v4 := s["iptables"]
	_, a.IPv6 = s["ip6tables"]

	var daemon struct {
		Iptables        *bool  `json:"iptables"`
		FirewallBackend string `json:"firewall-backend"`
	}
	_ = json.Unmarshal([]byte(strings.TrimSpace(s["daemon"])), &daemon)

	switch {
	case access == "user":
		a.Problem = "Limiting who reaches containers needs root: log in as root, or allow sudo for this user."
	case !a.Docker:
		a.Problem = "Docker isn't installed on this server."
	case daemon.Iptables != nil && !*daemon.Iptables:
		a.Problem = `Docker's own firewall rules are off here ("iptables": false), so its published ports go through the server's firewall like any other port: limit them on the Rules tab.`
	case daemon.FirewallBackend == "nftables":
		a.Problem = "Docker uses its nftables firewall backend here, which has no DOCKER-USER chain. Limit who reaches a port by publishing it on 127.0.0.1 and putting a reverse proxy in front."
	case !v4:
		a.Problem = "iptables isn't installed on this server."
	case a.Running && !strings.Contains(s["iptables"], "-N DOCKER-USER"):
		a.Problem = "Docker didn't make its DOCKER-USER chain here, so limits can't be added in front of its rules."
	default:
		a.Supported = true
	}
	if !a.Running && a.Docker && a.Problem == "" {
		if msg := strings.TrimSpace(s["ps-error"]); msg != "" {
			a.Problem = "Docker didn't answer: " + truncate(msg, 200)
		}
	}

	hooked := func(t string) bool {
		return strings.Contains(s[t], "-A DOCKER-USER -j "+firewall.ContainerChain)
	}
	a.Loaded = len(a.Limits) == 0 ||
		hooked("iptables") && firewall.ContainerLoaded(a.Limits, false, s["iptables-chain"]) &&
			(!a.IPv6 || hooked("ip6tables") && firewall.ContainerLoaded(a.Limits, true, s["ip6tables-chain"]))
	return a
}

// ctLoadScript is installed on the server: the boot service runs it, and so
// does every change.
const ctLoadScript = `#!/bin/sh
# Managed by Morcheh: who may reach ports Docker publishes. Edit them from
# Morche (Firewall > Containers); changes made here are overwritten.
export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"
d=` + ctDir + `
c=` + firewall.ContainerChain + `
drop() {
  command -v "$1" >/dev/null 2>&1 || return 0
  while "$1" -w -D DOCKER-USER -j "$c" 2>/dev/null; do :; done
  "$1" -w -F "$c" 2>/dev/null; "$1" -w -X "$c" 2>/dev/null; return 0
}
load() {
  command -v "$1" >/dev/null 2>&1 || return 0
  if [ ! -s "$2" ]; then drop "$1"; return 0; fi
  "$1" -w -N DOCKER-USER 2>/dev/null
  "$1-restore" -w -n < "$2" 2>/dev/null || "$1-restore" -n < "$2" || return 1
  "$1" -w -C DOCKER-USER -j "$c" 2>/dev/null || "$1" -w -I DOCKER-USER 1 -j "$c"
}
case "${1:-start}" in
  stop) drop iptables; drop ip6tables ;;
  *) load iptables "$d/docker-limits.v4" && load ip6tables "$d/docker-limits.v6" ;;
esac
`

const ctUnitFile = `[Unit]
Description=Morcheh: who may reach ports Docker publishes
After=docker.service
PartOf=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=` + ctBin + ` start
ExecStop=` + ctBin + ` stop

[Install]
WantedBy=docker.service
`

func writeFileLine(path, content string) string {
	return "printf '%s' " + base64.StdEncoding.EncodeToString([]byte(content)) + " | base64 -d > " + path + ".new && mv -f " + path + ".new " + path
}

// ctApplyScript writes the list and loads it. If loading fails, the files
// that were there go back and are loaded again.
func ctApplyScript(limits []firewall.ContainerLimit, init string) (string, error) {
	data, err := json.MarshalIndent(limits, "", "  ")
	if err != nil {
		return "", err
	}
	files := []string{"docker-limits.json", "docker-limits.v4", "docker-limits.v6"}
	var b strings.Builder
	b.WriteString(fwEnv)
	b.WriteString("fail() { echo \"ERROR: $*\"; exit " + strconv.Itoa(fwExitPrepare) + "; }\n")
	b.WriteString("command -v iptables >/dev/null 2>&1 || fail \"iptables isn't installed\"\n")
	b.WriteString("command -v base64 >/dev/null 2>&1 || fail \"base64 isn't installed\"\n")
	b.WriteString("mkdir -p " + ctDir + " || fail \"Could not create " + ctDir + "\"\n")
	b.WriteString("cd " + ctDir + " || exit " + strconv.Itoa(fwExitPrepare) + "\n")
	for _, f := range files {
		b.WriteString("if [ -f " + f + " ]; then cp -p " + f + " " + f + ".prev; else rm -f " + f + ".prev; fi\n")
	}
	b.WriteString(writeFileLine(ctBin, ctLoadScript) + " && chmod 755 " + ctBin + " || fail \"Could not write " + ctBin + "\"\n")

	systemd := init == "systemd"
	if len(limits) == 0 {
		if systemd {
			b.WriteString("systemctl disable " + ctService + " >/dev/null 2>&1; systemctl stop " + ctService + " >/dev/null 2>&1\n")
			b.WriteString("rm -f " + ctUnit + "; systemctl daemon-reload >/dev/null 2>&1\n")
		}
		b.WriteString(ctBin + " stop\n")
		b.WriteString("rm -f " + strings.Join(files, " ") + " " + strings.Join(files, ".prev ") + ".prev " + ctBin + "\n")
		b.WriteString("exit 0\n")
		return b.String(), nil
	}

	b.WriteString(writeFileLine(ctDir+"/docker-limits.json", string(data)+"\n") + " || fail \"Could not write the list\"\n")
	b.WriteString(writeFileLine(ctDir+"/docker-limits.v4", firewall.ContainerRestore(limits, false)) + " || fail \"Could not write the rules\"\n")
	b.WriteString(writeFileLine(ctDir+"/docker-limits.v6", firewall.ContainerRestore(limits, true)) + " || fail \"Could not write the rules\"\n")
	b.WriteString(`if ! out=$(` + ctBin + ` start 2>&1); then
  for f in ` + strings.Join(files, " ") + `; do if [ -f "$f.prev" ]; then mv -f "$f.prev" "$f"; else rm -f "$f"; fi; done
  ` + ctBin + ` start >/dev/null 2>&1
  echo "ERROR: The rules didn't load: $(printf '%s' "$out" | tail -n 2 | tr '\n' ' ')"
  exit ` + strconv.Itoa(fwExitRefused) + `
fi
rm -f ` + strings.Join(files, ".prev ") + `.prev
`)
	if systemd {
		b.WriteString(writeFileLine(ctUnit, ctUnitFile) + " || fail \"Could not write " + ctUnit + "\"\n")
		b.WriteString("systemctl daemon-reload && systemctl enable " + ctService + " >/dev/null 2>&1\n")
		// Started so that restarting Docker takes it along (PartOf); the
		// rules are already loaded, so starting it again changes nothing.
		b.WriteString("systemctl is-active -q " + ctService + " || systemctl start " + ctService + " >/dev/null 2>&1\n")
	}
	b.WriteString("exit 0\n")
	return b.String(), nil
}

func (h *serverHandler) setContainerAccess(ctx context.Context, id string, body ContainerAccessBody) (*ContainerAccessOutput, error) {
	limits := make([]firewall.ContainerLimit, len(body.Limits))
	for i, in := range body.Limits {
		l := firewall.ContainerLimit{Protocol: in.Protocol, Port: in.Port, Allow: in.Allow, Comment: in.Comment}
		if err := l.Normalize(); err != nil {
			if fe, ok := err.(*firewall.FieldError); ok {
				return nil, fieldError(fmt.Sprintf("body.limits[%d].%s", i, fe.Field), fe.Message, nil)
			}
			return nil, err
		}
		for j := range i {
			if limits[j].Overlaps(l) {
				return nil, fieldError(fmt.Sprintf("body.limits[%d].port", i),
					fmt.Sprintf("%s/%s is already in another limit (%s)", l.Port, l.Protocol, limits[j].Port), l.Port)
			}
		}
		limits[i] = l
	}

	lock := fwLock(id)
	lock.Lock()
	defer lock.Unlock()

	out := &ContainerAccessOutput{}
	err := h.withConn(ctx, id, func(c *sshpool.Conn) error {
		sh, err := h.fwRoot(ctx, id, c)
		if err != nil {
			return err
		}
		cur, err := collectContainerAccess(ctx, sh)
		if err != nil {
			return err
		}
		if !cur.Supported && len(limits) > 0 {
			return huma.Error422UnprocessableEntity(cur.Problem)
		}
		if body.Revision != cur.Revision {
			return huma.Error409Conflict("The limits were changed meanwhile. Look at them again before saving.")
		}
		for i, l := range limits {
			// Only matters when SSH itself reaches this server through a
			// published container port.
			if cur.SSHPort != 0 && cur.MorchehIP != "" && l.Covers("tcp", cur.SSHPort) && !l.Lets(cur.MorchehIP) &&
				publishes(cur.Published, "tcp", cur.SSHPort) {
				return fieldError(fmt.Sprintf("body.limits[%d].allow", i),
					"Morche reaches this server on that port: add "+cur.MorchehIP+" or it would be cut off", cur.MorchehIP)
			}
		}
		script, err := ctApplyScript(limits, cur.Init)
		if err != nil {
			return internalError(err)
		}
		res, err := sh.exec(context.WithoutCancel(ctx), script, fwCmdTimeout, 64<<10)
		switch {
		case err != nil:
			return err
		case res.timedOut:
			return huma.Error504GatewayTimeout("The server took too long to load the rules")
		case res.code == fwExitPrepare, res.code == fwExitRefused:
			return huma.Error422UnprocessableEntity(toolMessage(res.output))
		case res.code != 0:
			return huma.Error422UnprocessableEntity(fmt.Sprintf("The change failed (exit %d): %s", res.code, toolMessage(res.output)))
		}
		fresh, err := collectContainerAccess(ctx, sh)
		if err == nil {
			out.Body = *fresh
		}
		return err
	})
	return out, toProblem(err)
}

func publishes(list []firewall.PublishedPort, protocol string, port int) bool {
	for _, p := range list {
		if p.Protocol == protocol && p.Port == port && p.Public {
			return true
		}
	}
	return false
}
