package cmdlog

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"
)

// What a command printed is kept up to OutputHead bytes from its start and
// OutputTail from its end; the middle of a longer output is left out.
const (
	OutputHead = 16 << 10
	OutputTail = 48 << 10
)

// Output is what a command printed, as far as it was kept.
type Output struct {
	// UTF-8 text (terminal output keeps its escape sequences); a marker line
	// stands where the middle was left out.
	Text string
	// Bytes printed in all.
	Size int64
	// The middle was left out.
	Truncated bool
	// Why nothing was kept although it printed something.
	Note string
}

// OutputBuffer collects a command's output (stdout and stderr together),
// keeping its start and its end. Safe from several goroutines.
type OutputBuffer struct {
	mu     sync.Mutex
	head   []byte
	tail   []byte
	size   int64
	binary bool
	screen bool
}

// Ways a program switches to the terminal's other screen (vim, top, less).
var altScreen = [][]byte{[]byte("\x1b[?1049h"), []byte("\x1b[?1047h"), []byte("\x1b[?47h")}

func (b *OutputBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.size += int64(len(p))
	if b.binary || b.screen {
		return len(p), nil
	}
	if bytes.IndexByte(p, 0) >= 0 {
		b.binary, b.head, b.tail = true, nil, nil
		return len(p), nil
	}
	for _, seq := range altScreen {
		if bytes.Contains(p, seq) {
			b.screen, b.head, b.tail = true, nil, nil
			return len(p), nil
		}
	}
	rest := p
	if room := OutputHead - len(b.head); room > 0 {
		n := min(room, len(rest))
		b.head = append(b.head, rest[:n]...)
		rest = rest[n:]
	}
	if len(rest) > 0 {
		b.tail = append(b.tail, rest...)
		// Trim in steps, not on every write.
		if len(b.tail) > 2*OutputTail {
			b.tail = append([]byte(nil), b.tail[len(b.tail)-OutputTail:]...)
		}
	}
	return len(p), nil
}

// Result is the kept output, with secrets replaced; nil when nothing was
// printed.
func (b *OutputBuffer) Result(secrets ...string) *Output {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.size == 0 {
		return nil
	}
	out := &Output{Size: b.size}
	switch {
	case b.binary:
		out.Note = "It printed binary data, which isn't kept"
		return out
	case b.screen:
		out.Note = "A full-screen program (like vim or top): its screen isn't kept"
		return out
	}
	tail := b.tail
	if len(tail) > OutputTail {
		tail = tail[len(tail)-OutputTail:]
	}
	kept := int64(len(b.head) + len(tail))
	var text string
	if kept < b.size {
		out.Truncated = true
		// Start the tail on a whole character and line where it can.
		for len(tail) > 0 && !utf8.RuneStart(tail[0]) {
			tail = tail[1:]
		}
		if i := bytes.IndexByte(tail, '\n'); i >= 0 && i < 1024 {
			tail = tail[i+1:]
		}
		text = string(b.head) + fmt.Sprintf("\n\n··· %s left out ···\n\n", sizeText(b.size-kept)) + string(tail)
	} else {
		text = string(b.head) + string(tail)
	}
	text = strings.ToValidUTF8(text, "�")
	out.Text = Redact(text, secrets...)
	return out
}

func sizeText(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d bytes", n)
}
