// Package ansible runs ansible-playbook on the Morcheh host against servers
// Morcheh manages. Each run gets a private temporary folder holding the
// playbook, an inventory built from the chosen servers (with their
// credentials), a known_hosts file of the keys Morcheh already trusts and a
// callback plugin that reports plays, tasks and results as JSON lines. When
// bubblewrap is available the process runs in a sandbox that sees only the
// system's programs and that folder, so a playbook's local tasks (lookups,
// delegate_to: localhost) can't read Morcheh's own files or processes.
package ansible

import (
	"bufio"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed callback/morcheh.py
var callbackPlugin []byte

// Sandbox modes.
const (
	SandboxAuto  = "auto"  // bubblewrap when it works, else none
	SandboxBwrap = "bwrap" // bubblewrap or refuse to run
	SandboxOff   = "off"
)

// Config says where ansible-playbook is and how to run it.
type Config struct {
	Playbook string // ansible-playbook (a name on PATH or a path)
	Sandbox  string // auto, bwrap or off
	Timeout  time.Duration
}

// Status is what the Morcheh host offers.
type Status struct {
	Installed bool
	Version   string // ansible-core version
	Path      string
	// Sandbox is "bwrap" or "" (none).
	Sandbox string
	// Problem says why runs can't start (not installed, sandbox required but
	// missing).
	Problem string
}

var versionRe = regexp.MustCompile(`\[core ([^\]]+)\]`)

// Detect looks for ansible-playbook and the sandbox.
func Detect(ctx context.Context, c Config) Status {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var st Status
	path, err := exec.LookPath(c.Playbook)
	if err != nil {
		st.Problem = "ansible-playbook isn't installed on the Morcheh server (install ansible-core, or set ANSIBLE_PLAYBOOK)"
		return st
	}
	// The real file: the sandbox binds the folders it lives in.
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	out, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil {
		st.Problem = "ansible-playbook doesn't start: " + err.Error()
		return st
	}
	st.Installed, st.Path = true, path
	if m := versionRe.FindSubmatch(out); m != nil {
		st.Version = string(m[1])
	} else {
		st.Version = strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	}
	if c.Sandbox != SandboxOff {
		if err := tryBwrap(ctx, path); err == nil {
			st.Sandbox = "bwrap"
		} else if c.Sandbox == SandboxBwrap {
			st.Problem = "The sandbox (bubblewrap) doesn't work here: " + err.Error()
		}
	}
	return st
}

// Hook receives what a run produces as it comes. Calls are not concurrent.
// Both are already masked (see Filter).
type Hook struct {
	Output func(text string)
	Event  func(RunEvent)
}

// Spec is one run.
type Spec struct {
	Playbook  string // YAML
	Hosts     []Host
	Check     bool
	Diff      bool
	Verbosity int
	Tags      []string
	SkipTags  []string
	Limit     string
	Forks     int
	ExtraVars string // YAML
}

// Run runs a playbook and waits for it. It returns ansible-playbook's exit
// code (0 = every host fine, 2 = a host failed, 4 = unreachable, …); err is
// for when it couldn't run at all or ctx ended.
func Run(ctx context.Context, c Config, st Status, s Spec, hook Hook) (int, error) {
	if !st.Installed || st.Problem != "" {
		return -1, errors.New(st.Problem)
	}
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	dir, err := os.MkdirTemp("", "morcheh-ansible-")
	if err != nil {
		return -1, err
	}
	defer os.RemoveAll(dir)
	if err := prepare(dir, s); err != nil {
		return -1, err
	}

	args := []string{"-i", filepath.Join(dir, "inventory.json")}
	if s.Check {
		args = append(args, "--check")
	}
	if s.Diff {
		args = append(args, "--diff")
	}
	if s.Verbosity > 0 {
		args = append(args, "-"+strings.Repeat("v", min(s.Verbosity, 4)))
	}
	if len(s.Tags) > 0 {
		args = append(args, "--tags", strings.Join(s.Tags, ","))
	}
	if len(s.SkipTags) > 0 {
		args = append(args, "--skip-tags", strings.Join(s.SkipTags, ","))
	}
	if s.Limit != "" {
		args = append(args, "--limit", s.Limit)
	}
	if s.Forks > 0 {
		args = append(args, "--forks", strconv.Itoa(s.Forks))
	}
	if strings.TrimSpace(s.ExtraVars) != "" {
		args = append(args, "--extra-vars", "@"+filepath.Join(dir, "vars.yml"))
	}
	args = append(args, filepath.Join(dir, "playbook.yml"))

	env := environ(dir, st.Path)
	var cmd *exec.Cmd
	if st.Sandbox == "bwrap" {
		bw, err := bwrapArgs(dir, st.Path)
		if err != nil {
			return -1, err
		}
		cmd = exec.CommandContext(ctx, "bwrap", append(append(bw, envArgs(env)...), append([]string{st.Path}, args...)...)...)
		cmd.Env = []string{}
	} else {
		cmd = exec.CommandContext(ctx, st.Path, args...)
		cmd.Env = env
	}
	cmd.Dir = dir
	// Its own process group, so canceling stops ssh and the rest too.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 10 * time.Second

	outR, outW, err := os.Pipe()
	if err != nil {
		return -1, err
	}
	evR, evW, err := os.Pipe()
	if err != nil {
		outR.Close()
		outW.Close()
		return -1, err
	}
	cmd.Stdout, cmd.Stderr = outW, outW
	cmd.ExtraFiles = []*os.File{evW} // fd 3
	startErr := cmd.Start()
	outW.Close()
	evW.Close()
	if startErr != nil {
		outR.Close()
		evR.Close()
		return -1, startErr
	}

	// Both readers feed the hook through one lock.
	filter := NewFilter(s.Hosts)
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer outR.Close()
		buf := make([]byte, 32<<10)
		for {
			n, err := outR.Read(buf)
			if n > 0 && hook.Output != nil {
				mu.Lock()
				if text := filter.Write(buf[:n]); text != "" {
					hook.Output(text)
				}
				mu.Unlock()
			}
			if err != nil {
				if hook.Output != nil {
					mu.Lock()
					if text := filter.Flush(); text != "" {
						hook.Output(text)
					}
					mu.Unlock()
				}
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer evR.Close()
		sc := bufio.NewScanner(evR)
		sc.Buffer(make([]byte, 64<<10), 16<<20)
		for sc.Scan() {
			if hook.Event == nil {
				continue
			}
			mu.Lock()
			ev, err := filter.Event(sc.Bytes())
			if err != nil {
				mu.Unlock()
				continue
			}
			hook.Event(ev)
			mu.Unlock()
		}
		_, _ = io.Copy(io.Discard, evR)
	}()
	wg.Wait()
	err = cmd.Wait()

	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return -1, fmt.Errorf("stopped after %s (ANSIBLE_RUN_TIMEOUT)", c.Timeout)
		}
		return -1, ctx.Err()
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}

// prepare writes the run's files into dir.
func prepare(dir string, s Spec) error {
	for _, d := range []string{"home", "plugins", "cp", "tmp"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			return err
		}
	}
	files := map[string][]byte{
		"playbook.yml":       []byte(s.Playbook),
		"plugins/morcheh.py": callbackPlugin,
		"ansible.cfg":        []byte(config(dir)),
	}
	if strings.TrimSpace(s.ExtraVars) != "" {
		files["vars.yml"] = []byte(s.ExtraVars)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return err
		}
	}
	return writeInventory(dir, s.Hosts)
}

// config is the run's ansible.cfg: only the hosts Morcheh trusts, with the
// keys it already knows, and nothing from the Morcheh host's own ssh setup.
func config(dir string) string {
	known := filepath.Join(dir, "known_hosts")
	return `[defaults]
host_key_checking = True
retry_files_enabled = False
interpreter_python = auto_silent
callback_plugins = ` + filepath.Join(dir, "plugins") + `
callbacks_enabled = morcheh
local_tmp = ` + filepath.Join(dir, "tmp") + `
nocows = True
force_color = True

[ssh_connection]
ssh_args = -F /dev/null -o UserKnownHostsFile=` + known + ` -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o CheckHostIP=no -o ControlMaster=auto -o ControlPersist=60s -o ServerAliveInterval=15
control_path_dir = ` + filepath.Join(dir, "cp") + `
pipelining = True
`
}

// environ is the whole environment ansible-playbook gets: nothing of
// Morcheh's own (its database URL, secrets key).
func environ(dir, playbook string) []string {
	path := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	path = filepath.Dir(playbook) + ":" + path
	return []string{
		"PATH=" + path,
		"HOME=" + filepath.Join(dir, "home"),
		"TMPDIR=" + filepath.Join(dir, "tmp"),
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"TERM=xterm-256color",
		"ANSIBLE_CONFIG=" + filepath.Join(dir, "ansible.cfg"),
		"ANSIBLE_FORCE_COLOR=1",
		"PYTHONUNBUFFERED=1",
		"PYTHONDONTWRITEBYTECODE=1",
		"MORCHEH_EVENTS_FD=3",
	}
}

// CleanStale removes the folders of runs that never got to clean up after
// themselves (Morcheh was killed): they hold decrypted credentials.
func CleanStale(olderThan time.Duration) {
	dirs, _ := filepath.Glob(filepath.Join(os.TempDir(), "morcheh-ansible-*"))
	for _, d := range dirs {
		if fi, err := os.Stat(d); err == nil && time.Since(fi.ModTime()) > olderThan {
			_ = os.RemoveAll(d)
		}
	}
}
