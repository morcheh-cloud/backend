package nginx

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/morcheh/backend/internal/proxy"
)

// accessReadMax is the most a read ever keeps, whatever LogRead.Cap says.
const accessReadMax = 256 << 20

// AccessScript prints a header (@@mark inode size, and @@reset/@@capped
// when they apply), then @@data gz|plain and the lines: gzipped and in
// base64 when the server has both, so a big read crosses SSH small.
func (Driver) AccessScript(hostID string, r proxy.LogRead) string {
	if !hostIDRe.MatchString(hostID) {
		return "echo @@morcheh-nolog\n"
	}
	return logScript(AccessLog(hostID), r)
}

// WAFLogScript reads a host's firewall log (one JSON record a line) the way
// AccessScript reads its access log; ParseAccessOutput reads the output and
// ParseWAFLines its lines.
func (Driver) WAFLogScript(hostID string, r proxy.LogRead) string {
	if !hostIDRe.MatchString(hostID) {
		return "echo @@morcheh-nolog\n"
	}
	return logScript(WAFLog(hostID), r)
}

func logScript(f string, r proxy.LogRead) string {
	limit := r.Cap
	if limit <= 0 || limit > accessReadMax {
		limit = accessReadMax
	}
	var b strings.Builder
	fmt.Fprintf(&b, "f=%s\n", f)
	b.WriteString(`if [ ! -f "$f" ]; then echo @@morcheh-nolog; exit 0; fi
set -- $(stat -c '%i %s' "$f")
ino=$1 size=$2
echo "@@mark $ino $size"
`)
	if r.Mark != nil {
		inode := r.Mark.Inode
		if !hostIDRe.MatchString(inode) {
			inode = "-"
		}
		fmt.Fprintf(&b, `o=%d
if [ "$ino" != "%s" ] || [ "$size" -lt "$o" ]; then o=0; echo @@reset; fi
if [ $((size - o)) -gt %d ]; then o=$((size - %d)); echo @@capped; fi
emit() { if [ "$size" -gt "$o" ]; then tail -c +$((o + 1)) "$f" | head -c $((size - o)); fi; }
`, max(r.Mark.Size, 0), inode, limit, limit)
	} else {
		// Rotated files (name.1, name.2.gz, name-20261108.gz…) written to
		// since Since, oldest first; the live file only up to the size
		// printed above, so following on from the mark repeats nothing.
		since := r.Since.Unix()
		if r.Since.IsZero() {
			since = 0
		}
		fmt.Fprintf(&b, `emit() {
  for x in "$f"*; do [ -f "$x" ] && stat -c '%%Y %%n' "$x"; done | sort -k1,1n -k2,2r | while read -r t n; do
    [ "$t" -ge %d ] || [ "$n" = "$f" ] || continue
    case "$n" in
      "$f") head -c "$size" "$f" ;;
      *.gz) gzip -dc "$n" 2>/dev/null ;;
      *.bz2|*.xz|*.zst|*.lz4) ;;
      *) cat "$n" ;;
    esac
  done
}
`, since)
	}
	pipe := "emit"
	if r.Grep != "" {
		pipe += " | { grep -i -F -e " + shellQuote(r.Grep) + " || true; }"
	}
	// One byte over the cap says older lines were cut.
	pipe += fmt.Sprintf(" | tail -c %d", limit+1)
	b.WriteString(`if command -v gzip >/dev/null 2>&1 && command -v base64 >/dev/null 2>&1; then
  echo "@@data gz"
  ` + pipe + ` | gzip -1 -c | base64
else
  echo "@@data plain"
  ` + pipe + `
fi
exit 0
`)
	// The cap travels in the header so the parser can tell a cut read.
	return fmt.Sprintf("echo '@@cap %d'\n", limit) + b.String()
}

// ParseAccessOutput reads AccessScript's output.
func (Driver) ParseAccessOutput(out string) (proxy.LogChunk, error) {
	var c proxy.LogChunk
	var limit int64
	rest := out
	for rest != "" {
		line, after, _ := strings.Cut(rest, "\n")
		f := strings.Fields(line)
		if len(f) == 0 {
			rest = after
			continue
		}
		switch f[0] {
		case "@@morcheh-nolog":
			c.Missing = true
			return c, nil
		case "@@cap":
			if len(f) == 2 {
				limit, _ = strconv.ParseInt(f[1], 10, 64)
			}
		case "@@mark":
			if len(f) == 3 {
				c.Mark.Inode = f[1]
				c.Mark.Size, _ = strconv.ParseInt(f[2], 10, 64)
			}
		case "@@reset":
			c.Reset = true
		case "@@capped":
			c.Capped = true
		case "@@data":
			data := after
			if len(f) == 2 && f[1] == "gz" {
				raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(data), ""))
				if err != nil {
					return c, fmt.Errorf("reading the log: %w", err)
				}
				if len(raw) == 0 {
					data = ""
				} else {
					zr, err := gzip.NewReader(bytes.NewReader(raw))
					if err != nil {
						return c, fmt.Errorf("reading the log: %w", err)
					}
					text, err := io.ReadAll(zr)
					if err != nil {
						return c, fmt.Errorf("reading the log: %w", err)
					}
					data = string(text)
				}
			}
			// Over the cap: the first line is cut, and older ones are gone.
			if limit > 0 && int64(len(data)) > limit {
				c.Capped = true
				if i := strings.IndexByte(data, '\n'); i >= 0 {
					data = data[i+1:]
				}
			}
			for l := range strings.SplitSeq(data, "\n") {
				if l = strings.TrimRight(l, "\r"); l != "" {
					c.Lines = append(c.Lines, l)
				}
			}
			return c, nil
		}
		rest = after
	}
	return c, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ParseAccess reads one line of the morcheh_access format, nginx's combined
// one (older lines) or the stream one.
//
//	1.2.3.4 - - [08/Nov/2026:10:15:32 +0330] "GET /a?b=1 HTTP/2.0" 200 512 "-" "curl/8" "example.com" 0.012 "0.010" "-" "200" "10.0.0.2:80" 431 "f3…"
func (Driver) ParseAccess(line string) (proxy.AccessEntry, bool) {
	e := proxy.AccessEntry{Duration: -1, Upstream: -1, RequestLength: -1}
	tok := accessTokens(line)
	if len(tok) < 9 {
		return e, false
	}
	e.IP = tok[0].v
	if tok[2].v != "-" {
		e.User = tok[2].v
	}
	if !tok[3].bracket {
		return e, false
	}
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", tok[3].v)
	if err != nil {
		return e, false
	}
	e.Time = t.UTC()
	req := tok[4].v
	if m, rest, ok := strings.Cut(req, " "); ok {
		e.Method = m
		if i := strings.LastIndexByte(rest, ' '); i >= 0 && strings.HasPrefix(rest[i+1:], "HTTP/") {
			e.Path, e.Protocol = rest[:i], rest[i+1:]
		} else {
			e.Path = rest
		}
	} else if req != "-" {
		// A stream: "TCP" / "UDP".
		e.Protocol = req
	}
	e.Status, err = strconv.Atoi(tok[5].v)
	if err != nil {
		return e, false
	}
	e.Bytes, _ = strconv.ParseInt(tok[6].v, 10, 64)
	if v := tok[7].v; v != "-" {
		e.Referer = v
	}
	if v := tok[8].v; v != "-" {
		e.Agent = v
	}
	if len(tok) >= 17 {
		e.Detailed = true
		if v := tok[9].v; v != "-" {
			e.Domain = strings.ToLower(v)
		}
		e.Duration = seconds(tok[10].v)
		e.Upstream = upstreamSeconds(tok[11].v)
		if v := tok[12].v; v != "-" {
			e.Cache = v
		}
		if v := tok[13].v; v != "-" {
			e.UpstreamStatus = v
		}
		if v := tok[14].v; v != "-" {
			e.UpstreamAddr = v
		}
		if n, err := strconv.ParseInt(tok[15].v, 10, 64); err == nil {
			e.RequestLength = n
		}
		if v := tok[16].v; v != "-" {
			e.RequestID = v
		}
	}
	return e, true
}

func seconds(v string) float64 {
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 {
		return -1
	}
	return f
}

// upstreamSeconds adds up "0.010, 0.020" (tried more than one) and
// "0.010 : 0.020" (an internal redirect).
func upstreamSeconds(v string) float64 {
	if v == "-" || v == "" {
		return -1
	}
	total, any := 0.0, false
	for p := range strings.FieldsFuncSeq(v, func(r rune) bool { return r == ',' || r == ':' || r == ' ' }) {
		if f := seconds(p); f >= 0 {
			total += f
			any = true
		}
	}
	if !any {
		return -1
	}
	return total
}

type accessToken struct {
	v       string
	bracket bool
}

// accessTokens splits a log line on spaces, keeping "quoted" and [bracketed]
// parts whole. nginx writes a quote inside a value as \x22, so a quote
// always ends one.
func accessTokens(line string) []accessToken {
	var out []accessToken
	i := 0
	for i < len(line) {
		switch line[i] {
		case ' ':
			i++
		case '"':
			j := strings.IndexByte(line[i+1:], '"')
			if j < 0 {
				out = append(out, accessToken{v: line[i+1:]})
				return out
			}
			out = append(out, accessToken{v: unescape(line[i+1 : i+1+j])})
			i += j + 2
		case '[':
			j := strings.IndexByte(line[i+1:], ']')
			if j < 0 {
				return out
			}
			out = append(out, accessToken{v: line[i+1 : i+1+j], bracket: true})
			i += j + 2
		default:
			j := strings.IndexByte(line[i:], ' ')
			if j < 0 {
				out = append(out, accessToken{v: line[i:]})
				return out
			}
			out = append(out, accessToken{v: line[i : i+j]})
			i += j
		}
	}
	return out
}

// unescape turns nginx's \xHH back into the byte.
func unescape(s string) string {
	if !strings.Contains(s, `\x`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if n, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
