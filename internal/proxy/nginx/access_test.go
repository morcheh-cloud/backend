package nginx

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/morcheh/backend/internal/proxy"
)

func TestParseAccess(t *testing.T) {
	var d Driver
	e, ok := d.ParseAccess(`1.2.3.4 - bob [08/Nov/2026:10:15:32 +0330] "GET /a?b=\x22x\x22 HTTP/2.0" 404 512 "https://r.example/" "curl/8 (x)" "Example.com" 0.012 "0.004, 0.006" "MISS" "502, 200" "10.0.0.2:80" 431 "abc"`)
	if !ok {
		t.Fatal("not parsed")
	}
	want := time.Date(2026, 11, 8, 6, 45, 32, 0, time.UTC)
	if !e.Time.Equal(want) || e.IP != "1.2.3.4" || e.User != "bob" || e.Method != "GET" ||
		e.Path != `/a?b="x"` || e.Protocol != "HTTP/2.0" || e.Status != 404 || e.Bytes != 512 ||
		e.Referer != "https://r.example/" || e.Agent != "curl/8 (x)" || e.Domain != "example.com" ||
		e.Duration != 0.012 || e.Cache != "MISS" || e.UpstreamStatus != "502, 200" ||
		e.UpstreamAddr != "10.0.0.2:80" || e.RequestLength != 431 || e.RequestID != "abc" || !e.Detailed {
		t.Fatalf("got %+v", e)
	}
	if e.Upstream < 0.0099 || e.Upstream > 0.0101 {
		t.Fatalf("upstream %v", e.Upstream)
	}

	e, ok = d.ParseAccess(`5.6.7.8 - - [08/Nov/2026:10:15:32 +0000] "POST /x HTTP/1.1" 200 0 "-" "-"`)
	if !ok || e.Detailed || e.Duration != -1 || e.Agent != "" || e.Method != "POST" {
		t.Fatalf("combined: %+v %v", e, ok)
	}
	if _, ok := d.ParseAccess("garbage"); ok {
		t.Fatal("garbage parsed")
	}
}

func TestParseAccessOutput(t *testing.T) {
	var d Driver
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte("cut line\nline one\nline two\n"))
	zw.Close()
	out := "@@cap 20\n@@mark 123 999\n@@data gz\n" + base64.StdEncoding.EncodeToString(buf.Bytes()) + "\n"
	c, err := d.ParseAccessOutput(out)
	if err != nil {
		t.Fatal(err)
	}
	if c.Mark != (proxy.LogMark{Inode: "123", Size: 999}) || !c.Capped ||
		strings.Join(c.Lines, "|") != "line one|line two" {
		t.Fatalf("got %+v", c)
	}
	c, _ = d.ParseAccessOutput("@@cap 100\n@@mark 1 2\n@@reset\n@@data plain\na\nb\n")
	if !c.Reset || c.Capped || len(c.Lines) != 2 {
		t.Fatalf("plain: %+v", c)
	}
	c, _ = d.ParseAccessOutput("@@cap 100\n@@morcheh-nolog\n")
	if !c.Missing {
		t.Fatal("missing")
	}
}

func TestAccessScript(t *testing.T) {
	var d Driver
	s := d.AccessScript("h1", proxy.LogRead{Mark: &proxy.LogMark{Inode: "42", Size: 10}, Grep: "it's", Cap: 1000})
	for _, want := range []string{"@@cap 1000", "o=10", `"42"`, `'it'\''s'`, "tail -c 1001"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in\n%s", want, s)
		}
	}
	if s := d.AccessScript("../x", proxy.LogRead{}); !strings.Contains(s, "nolog") {
		t.Fatal("bad id accepted")
	}
}
