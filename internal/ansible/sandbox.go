package ansible

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// bwrapArgs builds bubblewrap's arguments: the system's programs and /etc
// read-only, ansible's own install read-only, the run's folder writable, and
// nothing else of the host (no home folders, no other processes). The network
// is shared: ansible has to reach the servers.
func bwrapArgs(dir, playbook string) ([]string, error) {
	args := []string{
		"--unshare-all", "--share-net", "--die-with-parent",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/etc", "/etc",
	}
	// /bin, /lib… are links into /usr on most systems, folders on some.
	for _, p := range []string{"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"} {
		fi, err := os.Lstat(p)
		switch {
		case err != nil:
		case fi.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return nil, err
			}
			args = append(args, "--symlink", target, p)
		case fi.IsDir():
			args = append(args, "--ro-bind", p, p)
		}
	}
	// /etc/resolv.conf often points into /run (systemd-resolved).
	if target, err := filepath.EvalSymlinks("/etc/resolv.conf"); err == nil && !strings.HasPrefix(target, "/etc/") {
		args = append(args, "--ro-bind", filepath.Dir(target), filepath.Dir(target))
	}
	roots, err := installRoots(playbook)
	if err != nil {
		return nil, err
	}
	for _, r := range roots {
		args = append(args, "--ro-bind", r, r)
	}
	args = append(args,
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--tmpfs", "/var/tmp",
		"--bind", dir, dir,
		"--chdir", dir,
		"--clearenv",
	)
	return args, nil
}

// installRoots are the folders ansible-playbook and its Python live in,
// outside /usr (a virtualenv, a pipx or uv tool, a Python built elsewhere).
func installRoots(playbook string) ([]string, error) {
	var roots []string
	add := func(exe string) {
		real, err := filepath.EvalSymlinks(exe)
		if err != nil {
			return
		}
		for _, p := range []string{exe, real} {
			// …/prefix/bin/program → …/prefix
			root := filepath.Dir(filepath.Dir(p))
			if root == "/" || root == "/usr" || strings.HasPrefix(root, "/usr/") {
				continue
			}
			covered := false
			for _, r := range roots {
				if root == r || strings.HasPrefix(root, r+"/") {
					covered = true
				}
			}
			if !covered {
				roots = append(roots, root)
			}
		}
	}
	add(playbook)
	f, err := os.Open(playbook)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	line, _ := bufio.NewReader(f).ReadString('\n')
	if interp, ok := strings.CutPrefix(strings.TrimSpace(line), "#!"); ok {
		fields := strings.Fields(interp)
		if len(fields) > 0 {
			exe := fields[0]
			if filepath.Base(exe) == "env" && len(fields) > 1 {
				exe, _ = exec.LookPath(fields[1])
			}
			if exe != "" {
				add(exe)
			}
		}
	}
	return roots, nil
}

// envArgs passes the environment through bubblewrap's --setenv.
func envArgs(env []string) []string {
	var out []string
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		out = append(out, "--setenv", k, v)
	}
	return out
}

// tryBwrap starts ansible-playbook --version in the sandbox it would run in.
func tryBwrap(ctx context.Context, playbook string) error {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return errors.New("bwrap isn't installed (install bubblewrap)")
	}
	dir, err := os.MkdirTemp("", "morcheh-ansible-check-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	_ = os.MkdirAll(filepath.Join(dir, "home"), 0o700)
	_ = os.MkdirAll(filepath.Join(dir, "tmp"), 0o700)
	args, err := bwrapArgs(dir, playbook)
	if err != nil {
		return err
	}
	args = append(args, envArgs(environ(dir, playbook))...)
	args = append(args, playbook, "--version")
	cmd := exec.CommandContext(ctx, bwrap, args...)
	cmd.Env = []string{}
	if out, err := cmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		if msg == "" {
			return err
		}
		return errors.New(msg)
	}
	return nil
}
