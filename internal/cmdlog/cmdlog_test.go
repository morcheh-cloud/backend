package cmdlog

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	got := Redact("mysql -psecret1 -h db; echo secret1", "secret1", "ab", "")
	if got != "mysql -p"+Redacted+" -h db; echo "+Redacted {
		t.Fatalf("got %q", got)
	}
}

func TestOutputBuffer(t *testing.T) {
	var b OutputBuffer
	if b.Result() != nil {
		t.Fatal("empty output should be nil")
	}
	b.Write([]byte("hello secret1\n"))
	o := b.Result("secret1")
	if o.Text != "hello "+Redacted+"\n" || o.Size != 14 || o.Truncated {
		t.Fatalf("got %+v", o)
	}

	var big OutputBuffer
	line := []byte(strings.Repeat("x", 99) + "\n")
	for range 2000 {
		big.Write(line)
	}
	o = big.Result()
	if !o.Truncated || o.Size != 200000 || !strings.Contains(o.Text, "left out") {
		t.Fatalf("got truncated=%v size=%d", o.Truncated, o.Size)
	}
	if len(o.Text) > OutputHead+OutputTail+100 {
		t.Fatalf("kept %d bytes", len(o.Text))
	}

	var bin OutputBuffer
	bin.Write([]byte("abc\x00def"))
	if o := bin.Result(); o.Text != "" || o.Note == "" {
		t.Fatalf("binary: %+v", o)
	}
	var screen OutputBuffer
	screen.Write([]byte("\x1b[?1049hvim"))
	if o := screen.Result(); o.Text != "" || o.Note == "" {
		t.Fatalf("screen: %+v", o)
	}
}
