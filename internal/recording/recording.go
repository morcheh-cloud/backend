// Package recording writes a terminal session's output as an asciicast v2
// file (https://docs.asciinema.org/manual/asciicast/v2/), gzipped in memory.
// Only what the server printed is kept, never what was typed: a password
// typed at a prompt isn't echoed, so it never reaches the recording.
package recording

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"
)

// MaxSize is the most output (before compression) one recording keeps.
const MaxSize = 50 << 20

// Cast is one recording in progress. Safe for concurrent use.
type Cast struct {
	mu        sync.Mutex
	start     time.Time
	last      time.Duration
	buf       bytes.Buffer
	gz        *gzip.Writer
	size      int64
	truncated bool
	closed    bool
	dirty     bool
	// The start of a UTF-8 character cut off at the end of the last chunk.
	pending []byte
}

// Snapshot is a recording as it stands.
type Snapshot struct {
	Data      []byte
	Size      int64
	Duration  time.Duration
	Truncated bool
}

type header struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Title     string            `json:"title,omitempty"`
	Env       map[string]string `json:"env"`
}

func New(cols, rows int, title string, start time.Time) *Cast {
	c := &Cast{start: start}
	c.gz, _ = gzip.NewWriterLevel(&c.buf, gzip.BestSpeed)
	line, _ := json.Marshal(header{
		Version: 2, Width: cols, Height: rows, Timestamp: start.Unix(), Title: title,
		Env: map[string]string{"TERM": "xterm-256color"},
	})
	c.write(append(line, '\n'))
	c.dirty = true
	return c
}

func (c *Cast) write(p []byte) {
	_, _ = c.gz.Write(p)
}

func (c *Cast) event(kind string, data string) {
	t := time.Since(c.start)
	if t < c.last {
		t = c.last
	}
	c.last = t
	s, _ := json.Marshal(data)
	line := make([]byte, 0, len(s)+24)
	line = append(line, '[')
	line = strconv.AppendFloat(line, t.Seconds(), 'f', 6, 64)
	line = append(line, `, "`...)
	line = append(line, kind...)
	line = append(line, `", `...)
	line = append(line, s...)
	line = append(line, "]\n"...)
	c.write(line)
	c.dirty = true
}

// Output records what the server printed.
func (c *Cast) Output(p []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.truncated || len(p) == 0 {
		return
	}
	if c.size+int64(len(p)) > MaxSize {
		c.truncated = true
		c.event("m", "Recording stopped: it reached its size limit.")
		return
	}
	c.size += int64(len(p))
	data := append(c.pending, p...)
	c.pending = nil
	// A character cut in two by the read waits for its other half, so the
	// JSON string stays valid UTF-8.
	for i := len(data) - 1; i >= 0 && i >= len(data)-utf8.UTFMax; i-- {
		if utf8.RuneStart(data[i]) {
			if !utf8.FullRune(data[i:]) {
				c.pending = bytes.Clone(data[i:])
				data = data[:i]
			}
			break
		}
	}
	if len(data) > 0 {
		c.event("o", string(data))
	}
}

// Resize records the terminal's new size.
func (c *Cast) Resize(cols, rows int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.event("r", strconv.Itoa(cols)+"x"+strconv.Itoa(rows))
}

// Changed reports (and clears) whether anything was recorded since the last
// call.
func (c *Cast) Changed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	d := c.dirty
	c.dirty = false
	return d
}

// Snapshot returns the recording so far: a gzip stream without its end until
// Close, which Read tolerates.
func (c *Cast) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		_ = c.gz.Flush()
	}
	return Snapshot{Data: bytes.Clone(c.buf.Bytes()), Size: c.size, Duration: c.last, Truncated: c.truncated}
}

// Close ends the recording; the duration runs to now.
func (c *Cast) Close() Snapshot {
	c.mu.Lock()
	if !c.closed {
		if len(c.pending) > 0 {
			c.event("o", string(c.pending))
			c.pending = nil
		}
		if t := time.Since(c.start); t > c.last {
			c.last = t
		}
		_ = c.gz.Close()
		c.closed = true
	}
	c.mu.Unlock()
	return c.Snapshot()
}

// Read unpacks a stored recording. One saved before its shell ended has no
// gzip trailer; everything up to there is still returned.
func Read(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(r)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		err = nil
	}
	return out, err
}
