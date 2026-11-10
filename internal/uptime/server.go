package uptime

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/morcheh/backend/internal/dbmon"
)

// ---- databases ----

func checkDatabase(ctx context.Context, c MonitorConfig, s MonitorSecrets, env Env) CheckResult {
	d := env.Dial
	if d == nil {
		d = Dialer(dbmon.DirectDialer(env.AllowInternal))
	}
	port := c.Port
	if port == 0 {
		port = dbmon.DefaultPort(c.Engine)
	}
	tlsMode := c.TLSMode
	switch tlsMode {
	case "disable", "require", "verify":
	default:
		tlsMode = "disable"
	}
	start := time.Now()
	conn, err := dbmon.Open(ctx, dbmon.Config{
		Engine:   c.Engine,
		Host:     strings.Trim(strings.TrimSpace(c.Host), "[]"),
		Port:     port,
		Username: c.Username,
		Password: s.Password,
		Database: c.Database,
		TLS:      tlsMode,
		Dial:     dbmon.Dialer(d),
		Tunneled: env.Tunneled,
		Timeout:  env.Timeout,
	})
	r := CheckResult{}
	r.took(start)
	if err != nil {
		status, msg := dbmon.Classify(err)
		r.Status = Down
		r.Code = status
		switch status {
		case dbmon.StatusAuthFailed:
			r.Message = "Sign-in was refused: " + clip(msg, 300)
		case dbmon.StatusTLSError:
			r.Message = "TLS failed: " + clip(msg, 300)
		default:
			r.Message = clip(errText(err), 300)
		}
		return r
	}
	_ = conn.Close()
	r.Status = Up
	r.Message = "Connected and signed in"
	if c.Username == "" {
		r.Message = "Connected"
	}
	return r
}

// ---- on a server ----

func needRunner(env Env) *CheckResult {
	if env.Run == nil {
		r := down("This check runs on a server; pick one")
		return &r
	}
	return nil
}

func sudo(c MonitorConfig, argv []string) []string {
	if c.Sudo {
		return append([]string{"sudo", "-n", "--"}, argv...)
	}
	return argv
}

func runFailed(err error) CheckResult {
	return down("Couldn't run the check on the server: %s", errText(err))
}

func checkDocker(ctx context.Context, c MonitorConfig, env Env) CheckResult {
	if r := needRunner(env); r != nil {
		return *r
	}
	start := time.Now()
	argv := sudo(c, []string{"docker", "inspect", "--type", "container", "--format",
		"{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.State.ExitCode}}|{{.RestartCount}}|{{.State.StartedAt}}",
		c.Container})
	out, code, err := env.Run(ctx, argv)
	if err != nil {
		return runFailed(err)
	}
	r := CheckResult{}
	r.took(start)
	out = strings.TrimSpace(out)
	if code != 0 {
		r.Status = Down
		r.Code = strconv.Itoa(code)
		low := strings.ToLower(out)
		switch {
		case strings.Contains(low, "no such"):
			r.Message = "There's no container " + c.Container
		case strings.Contains(low, "permission denied"):
			r.Message = "Docker refused the login user; turn on sudo or add it to the docker group"
		case strings.Contains(low, "not found") && strings.Contains(low, "docker"):
			r.Message = "Docker isn't installed on the server"
		case strings.Contains(low, "a password is required"):
			r.Message = "sudo needs a password; the login user needs passwordless sudo"
		default:
			r.Message = clip(out, 300)
		}
		return r
	}
	parts := strings.Split(out, "|")
	for len(parts) < 5 {
		parts = append(parts, "")
	}
	state, health, exit, restarts := parts[0], parts[1], parts[2], parts[3]
	r.Code = state
	if health != "" {
		r.Code = state + "/" + health
	}
	switch {
	case state != "running":
		r.Status = Down
		r.Message = "The container is " + state
		if state == "exited" {
			r.Message += " (exit code " + exit + ")"
		}
	case health == "unhealthy":
		r.Status = Down
		r.Message = "Running but unhealthy"
	case health == "starting":
		r.Status = Degraded
		r.Message = "Running, health check still starting"
	case state == "restarting":
		r.Status = Degraded
		r.Message = "Restarting"
	default:
		r.Status = Up
		r.Message = "Running"
		if health == "healthy" {
			r.Message = "Running and healthy"
		}
	}
	if n, _ := strconv.Atoi(restarts); n > 0 {
		r.Message += fmt.Sprintf(", restarted %d times", n)
	}
	return r
}

func checkSystemd(ctx context.Context, c MonitorConfig, env Env) CheckResult {
	if r := needRunner(env); r != nil {
		return *r
	}
	start := time.Now()
	out, code, err := env.Run(ctx, []string{"systemctl", "show", "--no-pager",
		"--property=LoadState,ActiveState,SubState,Result,NRestarts", "--", c.Unit})
	if err != nil {
		return runFailed(err)
	}
	r := CheckResult{}
	r.took(start)
	if code != 0 {
		r.Status = Down
		r.Code = strconv.Itoa(code)
		r.Message = "systemctl failed: " + clip(out, 300)
		if strings.Contains(out, "not found") {
			r.Message = "systemd isn't on the server"
		}
		return r
	}
	p := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			p[k] = v
		}
	}
	if p["LoadState"] == "not-found" {
		r.Status = Down
		r.Code = "not-found"
		r.Message = "There's no unit " + c.Unit
		return r
	}
	active, sub := p["ActiveState"], p["SubState"]
	r.Code = active + "/" + sub
	switch active {
	case "active", "reloading":
		r.Status = Up
		r.Message = "Active (" + sub + ")"
	case "activating":
		r.Status = Degraded
		r.Message = "Starting (" + sub + ")"
	default:
		r.Status = Down
		r.Message = "The unit is " + active
		if res := p["Result"]; res != "" && res != "success" {
			r.Message += " (" + res + ")"
		}
	}
	if n, _ := strconv.Atoi(p["NRestarts"]); n > 0 {
		r.Message += fmt.Sprintf(", restarted %d times", n)
	}
	return r
}

// checkCommand runs a shell command, read the Nagios way: exit 0 up, 1
// degraded, anything else down; the first line of output is the message.
func checkCommand(ctx context.Context, c MonitorConfig, env Env) CheckResult {
	if r := needRunner(env); r != nil {
		return *r
	}
	start := time.Now()
	out, code, err := env.Run(ctx, sudo(c, []string{"sh", "-c", c.Script}))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return down("Timed out")
		}
		return runFailed(err)
	}
	r := CheckResult{Code: strconv.Itoa(code), Detail: clip(out, 4000)}
	r.took(start)
	first := strings.TrimSpace(out)
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	first = clip(first, 300)
	switch code {
	case 0:
		r.Status = Up
		if first == "" {
			first = "Exit 0"
		}
	case 1:
		r.Status = Degraded
		if first == "" {
			first = "Exit 1 (warning)"
		}
	default:
		r.Status = Down
		if first == "" {
			first = fmt.Sprintf("Exit %d", code)
		}
	}
	r.Message = first
	return r
}
