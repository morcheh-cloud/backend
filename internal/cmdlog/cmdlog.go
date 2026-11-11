// Package cmdlog describes the command log: every command Morcheh runs on a
// server over SSH, and every command typed into one of its terminals. The
// SSH pool reports commands to a Sink; who and what they are for travels in
// the context as an Origin.
package cmdlog

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Kind is why a command ran.
type Kind string

const (
	// Typed into a terminal opened from the panel.
	Terminal Kind = "terminal"
	// Part of something a person changed in the panel (a non-GET request).
	Change Kind = "change"
	// Run to show a person something (a GET request): lists, details, logs.
	Read Kind = "read"
	// A background task (copy, install, backup…) someone started.
	Job Kind = "job"
	// A scheduled task (cron job) running on its own.
	Schedule Kind = "schedule"
	// Morcheh's own upkeep: live stats, checks, scans, monitors.
	Automatic Kind = "automatic"
)

// Kinds lists every kind, in the order the panel shows them.
var Kinds = []Kind{Terminal, Change, Read, Job, Schedule, Automatic}

// Origin is who a command runs for and what for.
type Origin struct {
	Kind Kind
	// What it was for, in the panel's words: "Install packages", "Shell 2".
	Source string
	// The person; nil for Morcheh itself.
	UserID *uuid.UUID
	// Where the person was (their IP address), when known.
	ClientIP string
	// The job or terminal it belongs to, for links.
	Ref string
}

type originKey struct{}

// With returns ctx carrying o.
func With(ctx context.Context, o Origin) context.Context {
	return context.WithValue(ctx, originKey{}, o)
}

// Of returns the origin in ctx; without one a command is Morcheh's own.
func Of(ctx context.Context) Origin {
	if o, ok := ctx.Value(originKey{}).(Origin); ok {
		return o
	}
	return Origin{Kind: Automatic, Source: "Background"}
}

// Background marks ctx as Morcheh's own upkeep with a name for it.
func Background(ctx context.Context, source string) context.Context {
	return With(ctx, Origin{Kind: Automatic, Source: source})
}

// Command is one command starting on a server.
type Command struct {
	ServerID string
	Origin   Origin
	// What ran: the command line, or the script it was given.
	Text string
	// Where it ran, for terminal commands.
	Cwd    string
	AsRoot bool
	// A terminal command line or an opened shell.
	Shell   bool
	Started time.Time
	// The terminal recording it falls in, and where (ms from its start).
	RecordingID *uuid.UUID
	RecordingMs int64
}

// Result is how a command ended. Code is -1 when there was no exit status
// (the connection dropped, Morcheh stopped it).
type Result struct {
	Code  int
	Error string
	// What it printed; nil when nothing was captured.
	Output *Output
}

// Handle is a logged command; End it once.
type Handle interface {
	End(Result)
}

// Sink receives commands. Begin may return nil when the command isn't kept.
type Sink interface {
	Begin(ctx context.Context, c Command) Handle
}

// Redacted is what a secret is replaced with.
const Redacted = "••••••"

// Redact replaces each secret (at least 4 characters) in text.
func Redact(text string, secrets ...string) string {
	for _, s := range secrets {
		if len(s) >= 4 {
			text = strings.ReplaceAll(text, s, Redacted)
		}
	}
	return text
}
