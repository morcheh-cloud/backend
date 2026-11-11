package terminal

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/morcheh/backend/internal/sshpool"
)

// Shell integration: so the command log can list what is typed into a
// terminal, bash and zsh are started with small hooks that report each
// command line, where it ran and how it ended, as private escape sequences
// (OSC 7766) in the output. Morcheh takes them out of the output before
// anyone sees or records it. Nothing reads keystrokes, so a password typed
// at a sudo prompt is never seen. Other shells start as before and their
// commands aren't captured.
//
// The hooks live in ~/.cache/morcheh/shell on the server (not /tmp, where
// another user could plant a file first) and are written again when they
// change (hooksVersion).

// Commands receives what the shell hooks report.
type Commands interface {
	// Ready: the hooks run in shell (bash, zsh) as uid.
	Ready(shell string, uid int)
	// Started: a command line starts, in cwd.
	Started(cmd, cwd string, at time.Time)
	// Output: the shell printed this (between Started and Finished it is
	// the command's output).
	Output(data []byte)
	// Finished: the command line ended with code.
	Finished(code int, at time.Time)
	// Closed: the shell itself ended (code -1 when unknown).
	Closed(code int, at time.Time)
}

const (
	hooksVersion = "1"
	hooksDir     = ".cache/morcheh/shell"
	oscPrefix    = "\x1b]7766;"
	// An unfinished sequence longer than this is not ours: let it through.
	oscMax = 256 << 10
)

// InstallHooks writes the shell hooks to the login user's home. An error
// means the shell starts without them.
func InstallHooks(ctx context.Context, conn *sshpool.Conn) error {
	sess, err := conn.Session(ctx)
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Quiet = true
	sess.Stdin = strings.NewReader(installScript)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { sess.Close() })
	defer stop()
	out, err := sess.CombinedOutput("sh -s")
	if err != nil {
		return errors.New("shell hooks: " + strings.TrimSpace(string(out)) + " " + err.Error())
	}
	return nil
}

// startCommand starts the shell through the hooks, in cwd when set.
func startCommand(cwd, nonce string) string {
	return `exec /bin/sh "$HOME/` + hooksDir + `/start" ` + ShellQuote(cwd) + " " + nonce
}

func newNonce() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// The start script picks the hooks for the login shell.
const startScript = `d="$HOME/.cache/morcheh/shell"
[ -n "$1" ] && cd -- "$1" 2>/dev/null
command -v base64 >/dev/null 2>&1 || exec "${SHELL:-/bin/sh}" -l
export MORCHEH_NONCE="$2"
case "${SHELL##*/}" in
bash) exec "$SHELL" --rcfile "$d/bashrc" -i ;;
zsh)
	export MORCHEH_USER_ZDOTDIR="${ZDOTDIR-}"
	export ZDOTDIR="$d/zsh"
	exec "$SHELL" -l ;;
esac
unset MORCHEH_NONCE
exec "${SHELL:-/bin/sh}" -l
`

// bash isn't started as a login shell (it would skip --rcfile), so the rc
// reads the login files itself, then adds the hooks last so they win.
const bashRC = `__m_nonce=$MORCHEH_NONCE; unset MORCHEH_NONCE
[ -f /etc/profile ] && . /etc/profile
for __m_f in "$HOME/.bash_profile" "$HOME/.bash_login" "$HOME/.profile"; do
	if [ -f "$__m_f" ]; then . "$__m_f"; break; fi
done
unset __m_f
HISTCONTROL=; unset HISTIGNORE
__m_b() { printf '%s' "$1" | base64 | tr -d '\n'; }
__m_pre() {
	local n c
	c=$(HISTTIMEFORMAT= builtin history 1)
	c=${c#"${c%%[! ]*}"}; n=${c%%[!0-9]*}
	c=${c#"$n"}; c=${c#\*}; c=${c#"${c%%[! ]*}"}
	printf '\033]7766;%s;s;%s;%s;%s\007' "$__m_nonce" "$n" "$(__m_b "$PWD")" "$(__m_b "$c")"
}
__m_post() { local e=$?; printf '\033]7766;%s;e;%s\007' "$__m_nonce" "$e"; return $e; }
PROMPT_COMMAND="__m_post${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
PS0="${PS0-}"'$(__m_pre)'
printf '\033]7766;%s;r;bash;%s\007' "$__m_nonce" "$(id -u)"
`

// zsh reads its files from ZDOTDIR: ours read the user's own, then the
// last one puts ZDOTDIR back and adds the hooks.
const zshEnv = `__m_dir=$ZDOTDIR
ZDOTDIR=${MORCHEH_USER_ZDOTDIR:-$HOME}
[[ -f $ZDOTDIR/.zshenv ]] && source $ZDOTDIR/.zshenv
ZDOTDIR=$__m_dir
`

const zshProfile = `ZDOTDIR=${MORCHEH_USER_ZDOTDIR:-$HOME}
[[ -f $ZDOTDIR/.zprofile ]] && source $ZDOTDIR/.zprofile
ZDOTDIR=$__m_dir
`

const zshRC = `__m_nonce=$MORCHEH_NONCE; unset MORCHEH_NONCE
ZDOTDIR=${MORCHEH_USER_ZDOTDIR:-$HOME}; unset MORCHEH_USER_ZDOTDIR __m_dir
[[ -f $ZDOTDIR/.zshrc ]] && source $ZDOTDIR/.zshrc
__m_b() { printf '%s' "$1" | base64 | tr -d '\n' }
__m_pre() { printf '\033]7766;%s;s;;%s;%s\007' "$__m_nonce" "$(__m_b "$PWD")" "$(__m_b "$1")" }
__m_post() { local e=$?; printf '\033]7766;%s;e;%s\007' "$__m_nonce" "$e"; return $e }
autoload -Uz add-zsh-hook
add-zsh-hook preexec __m_pre
precmd_functions=(__m_post ${precmd_functions[@]})
printf '\033]7766;%s;r;zsh;%s\007' "$__m_nonce" "$(id -u)"
`

// zsh reads .zlogin after .zshrc from the user's ZDOTDIR by then, so ours
// needs none.

var installScript = func() string {
	var b strings.Builder
	b.WriteString("set -e\numask 077\nd=\"$HOME/" + hooksDir + "\"\n")
	b.WriteString(`[ "$(cat "$d/version" 2>/dev/null)" = ` + hooksVersion + ` ] && [ -f "$d/start" ] && exit 0` + "\n")
	b.WriteString("mkdir -p \"$d/zsh\"\n")
	files := []struct{ name, body string }{
		{"start", startScript}, {"bashrc", bashRC},
		{"zsh/.zshenv", zshEnv}, {"zsh/.zprofile", zshProfile}, {"zsh/.zshrc", zshRC},
		{"version", hooksVersion + "\n"},
	}
	for _, f := range files {
		b.WriteString("cat > \"$d/" + f.name + ".tmp\" <<'MORCHEH_EOF'\n" + f.body + "MORCHEH_EOF\n")
		b.WriteString("mv -f \"$d/" + f.name + ".tmp\" \"$d/" + f.name + "\"\n")
	}
	return b.String()
}()

// ---- Reading the hooks' reports out of the output ----

// oscFilter takes OSC 7766 sequences out of a shell's output. Ones carrying
// the session's nonce become events; any other (a program printing a fake
// one) is dropped without effect.
type oscFilter struct {
	nonce string
	// Bytes held back: maybe the start of a sequence split across reads.
	pending []byte
	// The last command line's history number (bash), so one isn't counted twice.
	lastHist string
}

type hookEvent struct {
	kind  byte // 'r' ready, 's' start, 'e' end
	shell string
	uid   int
	cmd   string
	cwd   string
	code  int
	// Where it was in the output feed returned: what came before it.
	at int
}

// feed returns data without the sequences, and what they reported.
func (f *oscFilter) feed(data []byte) ([]byte, []hookEvent) {
	if len(f.pending) > 0 {
		data = append(f.pending, data...)
		f.pending = nil
	}
	if !bytes.Contains(data, []byte{0x1b}) {
		return data, nil
	}
	var out []byte
	var events []hookEvent
	for {
		i := bytes.Index(data, []byte(oscPrefix))
		if i < 0 {
			// Hold back a tail that could be the start of the prefix.
			keep := partialPrefix(data)
			out = append(out, data[:len(data)-keep]...)
			if keep > 0 {
				f.pending = bytes.Clone(data[len(data)-keep:])
			}
			return out, events
		}
		out = append(out, data[:i]...)
		rest := data[i+len(oscPrefix):]
		end, size := oscEnd(rest)
		if end < 0 {
			if len(rest) > oscMax {
				out = append(out, data[i:]...)
				return out, events
			}
			f.pending = bytes.Clone(data[i:])
			return out, events
		}
		if ev, ok := f.parse(string(rest[:end])); ok {
			ev.at = len(out)
			events = append(events, ev)
		}
		data = rest[end+size:]
	}
}

// partialPrefix is how many bytes at the end of data start oscPrefix.
func partialPrefix(data []byte) int {
	for n := min(len(oscPrefix)-1, len(data)); n > 0; n-- {
		if bytes.HasSuffix(data, []byte(oscPrefix[:n])) {
			return n
		}
	}
	return 0
}

// oscEnd finds the sequence's terminator: BEL, or ESC \.
func oscEnd(b []byte) (int, int) {
	for i, c := range b {
		switch {
		case c == 0x07:
			return i, 1
		case c == 0x1b && i+1 < len(b) && b[i+1] == '\\':
			return i, 2
		}
	}
	return -1, 0
}

func (f *oscFilter) parse(body string) (hookEvent, bool) {
	parts := strings.Split(body, ";")
	if len(parts) < 2 || parts[0] != f.nonce || len(parts[1]) != 1 {
		return hookEvent{}, false
	}
	ev := hookEvent{kind: parts[1][0]}
	switch ev.kind {
	case 'r':
		if len(parts) < 4 {
			return ev, false
		}
		ev.shell = parts[2]
		ev.uid, _ = strconv.Atoi(parts[3])
	case 's':
		if len(parts) < 5 {
			return ev, false
		}
		hist := parts[2]
		cwd, _ := base64.StdEncoding.DecodeString(parts[3])
		cmd, _ := base64.StdEncoding.DecodeString(parts[4])
		ev.cwd, ev.cmd = string(cwd), strings.TrimSpace(string(cmd))
		// bash shows the same history entry again when the line wasn't
		// added to the history (only spaces, history turned off…).
		if hist != "" && hist == f.lastHist {
			return ev, false
		}
		f.lastHist = hist
		if ev.cmd == "" {
			return ev, false
		}
	case 'e':
		if len(parts) < 3 {
			return ev, false
		}
		code, err := strconv.Atoi(parts[2])
		if err != nil {
			return ev, false
		}
		ev.code = code
	default:
		return ev, false
	}
	return ev, true
}
