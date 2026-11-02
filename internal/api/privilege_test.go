package api

import (
	"slices"
	"testing"
)

func TestLineWriter(t *testing.T) {
	var got []string
	w := &lineWriter{fn: func(l string) { got = append(got, l) }}
	for _, chunk := range []string{"Fetching", " a\nProgress 10%\rProgress 20%\r\n", "\n  \n", "last"} {
		if _, err := w.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	if want := []string{"Fetching a", "Progress 10%", "Progress 20%"}; !slices.Equal(got, want) {
		t.Fatalf("lines = %q, want %q", got, want)
	}
	w.flush()
	if got[len(got)-1] != "last" {
		t.Errorf("flush didn't give the last line: %q", got)
	}
}

func TestLineWriterBoundsALongLine(t *testing.T) {
	var got int
	w := &lineWriter{fn: func(string) { got++ }}
	_, _ = w.Write(make([]byte, 0))
	long := make([]byte, maxLine+1)
	for i := range long {
		long[i] = 'x'
	}
	_, _ = w.Write(long)
	if got != 1 || len(w.buf) != 0 {
		t.Errorf("got %d lines, %d bytes kept", got, len(w.buf))
	}
}
