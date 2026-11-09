package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/dbmon"
	"github.com/morcheh/backend/internal/jobs"
)

// LocalRunnerName is how the machine Morcheh runs on is shown as a runner.
const LocalRunnerName = "This Morcheh server"

// localRunner is the value of runner_server_id that asks for this machine
// explicitly (an empty one means the plan's choice on a restore).
const localRunner = "local"

// runsLocally says whether a script runs on Morcheh's own machine: a direct
// database's backup without a server chosen to run it.
func (s dumpScript) runsLocally() bool { return s.server == uuid.Nil }

// runLocal runs the script on this machine, its stdout going to out. Same
// contract as runDump: the script goes in on stdin (never a command line),
// data follows it for a restore.
func (h *backupHandler) runLocal(ctx context.Context, t *jobs.Task, s dumpScript, out io.Writer) (dumpMarks, error) {
	if s.container != "" {
		return dumpMarks{}, errors.New("A database inside a container is backed up on its own server.")
	}
	shell := "sh -s"
	if s.data != nil {
		shell = feedCommand(len(s.script))
	}
	var stdin io.Reader = strings.NewReader(s.script)
	if s.data != nil {
		stdin = io.MultiReader(stdin, s.data)
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", shell)
	cmd.Env = localEnv()
	cmd.Dir = os.TempDir()
	// Its own process group, so canceling stops the dump tool too.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = scriptGrace
	var stderr tailWriter
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, out, &stderr
	if out == nil {
		cmd.Stdout = &stderr
	}
	err := cmd.Run()
	if ctx.Err() != nil {
		return dumpMarks{}, ctx.Err()
	}
	marks, text := readMarks(string(stderr.b))
	text = scrub(text, s.secrets...)
	var exit *exec.ExitError
	switch {
	case err == nil:
		if text != "" {
			t.Logf("%s", text)
		}
		return marks, nil
	case marks.broken:
		return marks, errChainBroken
	case errors.As(err, &exit):
		if text != "" {
			return marks, errors.New(text)
		}
		if st, ok := exit.Sys().(syscall.WaitStatus); ok && st.Signaled() {
			return marks, errors.New("It was killed by signal " + st.Signal().String() + ".")
		}
		return marks, fmt.Errorf("It stopped with code %d.", exit.ExitCode())
	}
	return marks, err
}

// localEnv is what a local script sees: enough to find the tools, nothing of
// Morcheh's own settings (its database URL, the secrets key).
func localEnv() []string {
	env := []string{"LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	for _, k := range []string{"PATH", "HOME", "TMPDIR", "TZ", "USER"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// LocalTools says which client tools this machine lacks for an engine, so
// the plan form can say so before the first run.
type LocalTools struct {
	Supported bool     `json:"supported" doc:"Whether this kind of database can be backed up from the Morcheh server at all"`
	Missing   []string `json:"missing" doc:"Tools a backup or restore needs that aren't installed here"`
	Note      string   `json:"note" doc:"Why not, when it can't"`
}

// localTools checks the tools a backup and a restore of this engine use.
// Each entry is a set of alternatives.
func localTools(d sqlc.Database) LocalTools {
	if d.Mode != "direct" {
		return LocalTools{Missing: []string{}, Note: "It's reached through a server, so its backups run there."}
	}
	var need [][]string
	switch d.Engine {
	case dbmon.Postgres:
		need = [][]string{{"pg_dump"}, {"pg_dumpall"}, {"pg_restore"}, {"psql"}}
	case dbmon.MySQL:
		need = [][]string{{"mariadb-dump", "mysqldump"}, {"mariadb", "mysql"}, {"mariadb-binlog", "mysqlbinlog"}}
	case dbmon.Mongo:
		need = [][]string{{"mongodump"}, {"mongorestore"}}
	case dbmon.Redis:
		need = [][]string{{"redis-cli", "valkey-cli"}}
	case dbmon.MSSQL:
		return LocalTools{Missing: []string{}, Note: "SQL Server writes its backups on its own disk, so they run on its own machine."}
	}
	out := LocalTools{Supported: true, Missing: []string{}}
	for _, alt := range need {
		found := false
		for _, name := range alt {
			if _, err := exec.LookPath(name); err == nil {
				found = true
				break
			}
		}
		if !found {
			out.Missing = append(out.Missing, alt[0])
		}
	}
	return out
}
