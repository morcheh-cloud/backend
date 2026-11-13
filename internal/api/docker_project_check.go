package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/terminal"
)

// ---- API shapes ----

type DockerProjectCheckBody struct {
	Name    string `json:"name,omitempty" maxLength:"63" doc:"The project's name, when chosen: checked against the server's projects"`
	Compose string `json:"compose" minLength:"1" maxLength:"500000"`
	Env     string `json:"env,omitempty" maxLength:"200000"`
}

type DockerCheckService struct {
	Name  string `json:"name"`
	Image string `json:"image,omitempty"`
	// Built from a Dockerfile rather than pulled.
	Build bool `json:"build"`
}

type DockerCheckPort struct {
	Service   string `json:"service"`
	Published string `json:"published" doc:"Host port, or a range like 8000-8010"`
	Target    string `json:"target"`
	Protocol  string `json:"protocol"`
	HostIP    string `json:"host_ip,omitempty"`
	InUse     bool   `json:"in_use" doc:"Something on the server already listens on it"`
	Duplicate bool   `json:"duplicate" doc:"Another service in this file publishes it too"`
}

type DockerProjectCheck struct {
	// Compose accepted the files.
	OK          bool                 `json:"ok"`
	Problem     string               `json:"problem,omitempty" doc:"What compose said when it refused the files"`
	NameProblem string               `json:"name_problem,omitempty"`
	Config      string               `json:"config,omitempty" doc:"The files as compose reads them (variables filled in)"`
	Format      string               `json:"format,omitempty" enum:"json,yaml"`
	Compose     string               `json:"compose_command,omitempty" doc:"docker compose, docker-compose or podman-compose"`
	Services    []DockerCheckService `json:"services"`
	Ports       []DockerCheckPort    `json:"ports"`
	PortsRead   bool                 `json:"ports_read" doc:"The server's listening ports could be read (ss)"`
}

// ---- Handler ----

func registerDockerProjectCheck(api huma.API, h *serverHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "check-docker-project",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/docker/projects/check",
		Summary:     "Check a new project's files",
		Description: "Runs `docker compose config` on the server over a temporary copy of the files (removed after), and compares the published ports with what already listens there. Nothing is saved or started.",
		Tags:        []string{"Containers"},
	}, func(ctx context.Context, in *struct {
		ServerIDPath
		Body DockerProjectCheckBody
	}) (*struct{ Body DockerProjectCheck }, error) {
		b := in.Body
		if err := checkComposeText(b.Compose); err != nil {
			return nil, err
		}
		out := DockerProjectCheck{Services: []DockerCheckService{}, Ports: []DockerCheckPort{}}
		name := b.Name
		ps, root, err := h.dockerProjects(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if name != "" {
			if !projectNameRe.MatchString(name) {
				out.NameProblem = "Use lowercase letters, digits, - and _ (starting with a letter or digit)"
			}
			for _, p := range ps {
				if p.Name == name {
					out.NameProblem = "This server already has a project called " + name
				}
			}
		} else {
			name = "new-project"
		}
		dir := path.Join(root, name)
		b64c := base64.StdEncoding.EncodeToString([]byte(b.Compose))
		b64e := base64.StdEncoding.EncodeToString([]byte(b.Env))
		q := terminal.ShellQuote

		var s strings.Builder
		s.WriteString("set -e\nT=$(mktemp -d)\ntrap 'rm -rf \"$T\"' EXIT\ncd \"$T\"\numask 077\n")
		s.WriteString("printf '%s' " + q(b64c) + " | base64 -d > compose.yaml\n")
		if b.Env != "" {
			s.WriteString("printf '%s' " + q(b64e) + " | base64 -d > .env\n")
		}
		s.WriteString("taken=n\nfor f in " + strings.Join(composeFileNames, " ") + "; do [ -e " + q(dir) + `/"$f" ] && taken=y; done` + "\necho \"taken=$taken\"\n")
		s.WriteString(composeDetect)
		s.WriteString(`echo "cmd=$C"
set +e
fmt=yaml
if [ "$C" = "docker compose" ]; then fmt=json; out=$($C -p ` + q(name) + ` --project-directory "$T" -f compose.yaml config --format json 2>&1); code=$?
else out=$($C -p ` + q(name) + ` --project-directory "$T" -f compose.yaml config 2>&1); code=$?; fi
echo "code=$code"
echo "fmt=$fmt"
printf '%s' "$out" | sed "s#$T#"` + q(dir) + `"#g" | base64 | tr -d '\n'; echo
if command -v ss >/dev/null 2>&1; then echo ports=y; ss -ltnuH 2>/dev/null | awk '{print $1, $5}' | base64 | tr -d '\n'; echo; else echo ports=n; echo; fi
`)
		var res string
		err = h.withShell(ctx, in.ID, func(_ *sshpool.Conn, sh *rootShell) error {
			var err error
			res, err = sh.hiding(true, b64c, b64e).run(ctx, s.String())
			return err
		})
		if err != nil {
			return nil, shellFailure(err, "")
		}

		vals := map[string]string{}
		var blobs []string
		for _, line := range strings.Split(strings.TrimRight(res, "\n"), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok && (k == "taken" || k == "cmd" || k == "code" || k == "fmt" || k == "ports") {
				vals[k] = v
				continue
			}
			blobs = append(blobs, line)
		}
		decode := func(i int) string {
			if i >= len(blobs) {
				return ""
			}
			d, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(blobs[i]))
			return string(d)
		}
		if out.NameProblem == "" && vals["taken"] == "y" && b.Name != "" {
			out.NameProblem = dir + " already holds a compose file"
		}
		out.Compose = vals["cmd"]
		text := decode(0)
		if vals["code"] != "0" {
			out.Problem = lastLines(text, 8)
			return &struct{ Body DockerProjectCheck }{out}, nil
		}
		out.OK = true
		out.Config, out.Format = text, vals["fmt"]
		if out.Format == "json" {
			out.Services, out.Ports = readComposeJSON(text)
		}
		if vals["ports"] == "y" {
			out.PortsRead = true
			listening := listeningPorts(decode(1))
			seen := map[string]int{}
			for i := range out.Ports {
				p := &out.Ports[i]
				for _, n := range portRange(p.Published) {
					if listening[p.Protocol+"/"+strconv.Itoa(n)] {
						p.InUse = true
					}
					seen[p.Protocol+"/"+strconv.Itoa(n)]++
				}
			}
			for i := range out.Ports {
				p := &out.Ports[i]
				for _, n := range portRange(p.Published) {
					if seen[p.Protocol+"/"+strconv.Itoa(n)] > 1 {
						p.Duplicate = true
					}
				}
			}
		}
		return &struct{ Body DockerProjectCheck }{out}, nil
	})
}

// readComposeJSON takes the services and their published ports out of
// `compose config --format json`.
func readComposeJSON(text string) ([]DockerCheckService, []DockerCheckPort) {
	var doc struct {
		Services map[string]struct {
			Image string          `json:"image"`
			Build json.RawMessage `json:"build"`
			Ports []struct {
				Target    json.Number `json:"target"`
				Published json.Number `json:"published"`
				Protocol  string      `json:"protocol"`
				HostIP    string      `json:"host_ip"`
			} `json:"ports"`
		} `json:"services"`
	}
	services := []DockerCheckService{}
	ports := []DockerCheckPort{}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		// Older compose prints published as a string ("8080"): try again loosely.
		var loose struct {
			Services map[string]struct {
				Image string           `json:"image"`
				Build json.RawMessage  `json:"build"`
				Ports []map[string]any `json:"ports"`
			} `json:"services"`
		}
		if json.Unmarshal([]byte(text), &loose) != nil {
			return services, ports
		}
		for name, s := range loose.Services {
			services = append(services, DockerCheckService{Name: name, Image: s.Image, Build: len(s.Build) > 0})
			for _, p := range s.Ports {
				pub := anyText(p["published"])
				if pub == "" {
					continue
				}
				proto := anyText(p["protocol"])
				if proto == "" {
					proto = "tcp"
				}
				ports = append(ports, DockerCheckPort{Service: name, Published: pub, Target: anyText(p["target"]), Protocol: proto, HostIP: anyText(p["host_ip"])})
			}
		}
		sortCheck(services, ports)
		return services, ports
	}
	for name, s := range doc.Services {
		services = append(services, DockerCheckService{Name: name, Image: s.Image, Build: len(s.Build) > 0})
		for _, p := range s.Ports {
			if p.Published == "" {
				continue
			}
			proto := p.Protocol
			if proto == "" {
				proto = "tcp"
			}
			ports = append(ports, DockerCheckPort{Service: name, Published: p.Published.String(), Target: p.Target.String(), Protocol: proto, HostIP: p.HostIP})
		}
	}
	sortCheck(services, ports)
	return services, ports
}

func anyText(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return ""
}

func sortCheck(services []DockerCheckService, ports []DockerCheckPort) {
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Service != ports[j].Service {
			return ports[i].Service < ports[j].Service
		}
		return ports[i].Published < ports[j].Published
	})
}

// listeningPorts reads `ss -ltnuH | awk '{print $1, $5}'`: "tcp 0.0.0.0:22".
func listeningPorts(text string) map[string]bool {
	m := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		proto, addr, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		i := strings.LastIndex(addr, ":")
		if i < 0 {
			continue
		}
		if _, err := strconv.Atoi(addr[i+1:]); err == nil {
			m[proto+"/"+addr[i+1:]] = true
		}
	}
	return m
}

// portRange expands "8080" or "8000-8010" (at most 1000 ports).
func portRange(s string) []int {
	lo, hi, found := strings.Cut(s, "-")
	a, err := strconv.Atoi(lo)
	if err != nil {
		return nil
	}
	b := a
	if found {
		if b, err = strconv.Atoi(hi); err != nil || b < a || b-a > 1000 {
			return []int{a}
		}
	}
	out := make([]int, 0, b-a+1)
	for n := a; n <= b; n++ {
		out = append(out, n)
	}
	return out
}
