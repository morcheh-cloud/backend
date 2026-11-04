package ansible

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// Filter cleans what a run prints before it is stored or shown: passwords
// Morcheh put in the inventory come out as ****, so someone who may read a
// run's log doesn't get a login they couldn't see otherwise (a playbook that
// prints hostvars, a high verbosity), and the text is always valid UTF-8
// without NUL, which PostgreSQL refuses. Chunks can split a password or a
// character: the part that might continue in the next chunk waits for it.
//
// This guards against accidents. Whoever runs a playbook can get at the
// credentials anyway, which is why running one needs Owner.
type Filter struct {
	secrets [][]byte
	held    []byte
}

const masked = "****"

// NewFilter masks the hosts' passwords and passphrases.
func NewFilter(hosts []Host) *Filter {
	f := &Filter{}
	seen := map[string]bool{}
	for _, h := range hosts {
		for _, s := range []string{h.Password, h.Passphrase, strings.TrimSpace(h.PrivateKey)} {
			// Too short to tell apart from ordinary output.
			if len(s) < 4 || seen[s] {
				continue
			}
			seen[s] = true
			f.secrets = append(f.secrets, []byte(s))
			// As it reads inside a JSON string.
			if j, err := json.Marshal(s); err == nil {
				if e := j[1 : len(j)-1]; !bytes.Equal(e, []byte(s)) {
					f.secrets = append(f.secrets, e)
				}
			}
		}
	}
	return f
}

// Line masks a complete piece of text.
func (f *Filter) Line(b []byte) []byte {
	for _, s := range f.secrets {
		b = bytes.ReplaceAll(b, s, []byte(masked))
	}
	return b
}

// Event reads a callback line with the passwords masked. It masks the decoded
// values, never the JSON itself: a password that happens to read "status" must
// not break the line.
func (f *Filter) Event(line []byte) (RunEvent, error) {
	if len(f.secrets) == 0 {
		return ParseEvent(line)
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return RunEvent{}, err
	}
	out, err := json.Marshal(f.maskValue(v))
	if err != nil {
		return RunEvent{}, err
	}
	return ParseEvent(out)
}

func (f *Filter) maskValue(v any) any {
	switch x := v.(type) {
	case string:
		return string(f.Line([]byte(x)))
	case []any:
		for i := range x {
			x[i] = f.maskValue(x[i])
		}
	case map[string]any:
		for k := range x {
			x[k] = f.maskValue(x[k])
		}
	}
	return v
}

// Write takes the next chunk and returns the text that is safe to show now.
func (f *Filter) Write(chunk []byte) string {
	b := f.Line(append(f.held, chunk...))
	keep := max(f.secretPrefix(b), partialRune(b))
	f.held = bytes.Clone(b[len(b)-keep:])
	return clean(b[:len(b)-keep])
}

// Flush returns what was held back, at the end of the output.
func (f *Filter) Flush() string {
	b := f.Line(f.held)
	f.held = nil
	return clean(b)
}

// secretPrefix is how many bytes at the end of b could be a password's start.
func (f *Filter) secretPrefix(b []byte) int {
	best := 0
	for _, s := range f.secrets {
		for n := min(len(s)-1, len(b)); n > best; n-- {
			if bytes.HasSuffix(b, s[:n]) {
				best = n
				break
			}
		}
	}
	return best
}

// partialRune is how many bytes at the end of b start an unfinished character.
func partialRune(b []byte) int {
	for n := 1; n <= min(3, len(b)); n++ {
		c := b[len(b)-n]
		if utf8.RuneStart(c) {
			if c >= utf8.RuneSelf && !utf8.FullRune(b[len(b)-n:]) {
				return n
			}
			return 0
		}
	}
	return 0
}

func clean(b []byte) string {
	return strings.ReplaceAll(strings.ToValidUTF8(string(b), "�"), "\x00", "")
}

// Output keeps what a run printed within a cap: its start and its end, with a
// note where the middle was dropped. Failures tend to be at the end, so a
// simple cut-off would lose what matters.
type Output struct {
	head, tail strings.Builder
	total      int64
	cut        bool
}

const (
	outputHead = 1 << 20
	outputTail = 3 << 20
)

// Add appends text. It returns how many bytes came before it, so a client
// following along can tell whether it missed any.
func (o *Output) Add(s string) int64 {
	offset := o.total
	o.total += int64(len(s))
	if room := outputHead - o.head.Len(); room > 0 && !o.cut {
		if len(s) <= room {
			o.head.WriteString(s)
			return offset
		}
		o.head.WriteString(strings.ToValidUTF8(s[:room], ""))
		s = s[room:]
		o.cut = true
	}
	o.cut = true
	o.tail.WriteString(s)
	if o.tail.Len() > 2*outputTail {
		t := o.tail.String()
		t = strings.ToValidUTF8(t[len(t)-outputTail:], "")
		o.tail.Reset()
		o.tail.WriteString(t)
	}
	return offset
}

// Total is every byte printed so far, kept or not.
func (o *Output) Total() int64 { return o.total }

// Truncated says part of the output was dropped.
func (o *Output) Truncated() bool {
	return o.cut && o.total > int64(o.head.Len()+o.tail.Len()) || o.tail.Len() > outputTail
}

// String is the kept output.
func (o *Output) String() string {
	t := o.tail.String()
	if len(t) > outputTail {
		t = strings.ToValidUTF8(t[len(t)-outputTail:], "")
	}
	if !o.Truncated() {
		return o.head.String() + t
	}
	return o.head.String() + "\n\n… (the middle of the output was too long and was dropped) …\n\n" + t
}
