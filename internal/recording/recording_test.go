package recording

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func lines(t *testing.T, data []byte) []string {
	t.Helper()
	out, err := Read(data)
	if err != nil {
		t.Fatal(err)
	}
	var ls []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		ls = append(ls, sc.Text())
	}
	return ls
}

func TestCast(t *testing.T) {
	c := New(80, 24, "Shell 1", time.Now())
	c.Output([]byte("hello \xd8"))
	c.Output([]byte("\xb3\r\n"))
	c.Resize(100, 30)

	// A snapshot taken mid-session is readable.
	live := lines(t, c.Snapshot().Data)
	if len(live) != 4 {
		t.Fatalf("live lines = %d: %q", len(live), live)
	}
	var h header
	if err := json.Unmarshal([]byte(live[0]), &h); err != nil || h.Version != 2 || h.Width != 80 {
		t.Fatalf("header = %+v, %v", h, err)
	}
	var ev []any
	if err := json.Unmarshal([]byte(live[2]), &ev); err != nil {
		t.Fatal(err)
	}
	// The split "س" is rejoined in the second event.
	if ev[1] != "o" || ev[2] != "س\r\n" {
		t.Fatalf("event = %v", ev)
	}
	if !strings.Contains(live[3], `"r", "100x30"`) {
		t.Fatalf("resize = %s", live[3])
	}

	s := c.Close()
	if s.Size != int64(len("hello \xd8\xb3\r\n")) || s.Truncated {
		t.Fatalf("snapshot = %+v", s)
	}
	if len(lines(t, s.Data)) != 4 {
		t.Fatal("closed recording lost lines")
	}
	c.Output([]byte("after"))
	if len(lines(t, c.Snapshot().Data)) != 4 {
		t.Fatal("output after Close was recorded")
	}
}

func TestCastLimit(t *testing.T) {
	c := New(80, 24, "", time.Now())
	c.Output(bytes.Repeat([]byte("x"), MaxSize-1))
	c.Output([]byte("yy"))
	s := c.Close()
	if !s.Truncated || s.Size != MaxSize-1 {
		t.Fatalf("size = %d, truncated = %v", s.Size, s.Truncated)
	}
}
