package dbbackup

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"
)

func TestClickHouseScripts(t *testing.T) {
	const secret = "s3cr'et$(x)<&>"
	for _, tls := range []string{"", "require", "verify"} {
		tg := Target{Engine: "clickhouse", Host: "db.example", Username: "u", Password: secret, Name: "shop", TLS: tls, CACert: "-----PEM-----"}
		spec, err := Build(tg)
		if err != nil {
			t.Fatal(err)
		}
		if spec.Format != ClickHouseTar || !spec.Pack || spec.Ext != "ch.tar.gz" || spec.Workers != 1 {
			t.Fatalf("%+v", spec)
		}
		restore, err := BuildRestore(tg, RestoreOptions{Format: ClickHouseTar, Source: "shop", First: true, Last: true})
		if err != nil {
			t.Fatal(err)
		}
		for _, script := range []string{spec.Script, restore} {
			for line := range strings.SplitSeq(script, "\n") {
				if !strings.Contains(line, "s3cr") {
					continue
				}
				if !strings.HasPrefix(line, "printf ") {
					t.Errorf("tls %q: secret on a command line: %q", tls, line)
				}
				// XML-escaped inside the shell word.
				if !strings.Contains(line, `s3cr&apos;et$(x)&lt;&amp;&gt;`) {
					t.Errorf("tls %q: secret not escaped: %q", tls, line)
				}
			}
			if !strings.Contains(script, "</dev/null") {
				t.Error("a tool would swallow the rest of the script from stdin")
			}
		}
		switch tls {
		case "require":
			if !strings.Contains(spec.Script, "AcceptCertificateHandler") {
				t.Error("require must accept any certificate")
			}
		case "verify":
			if !strings.Contains(spec.Script, "<caConfig>") || !strings.Contains(spec.Script, "strict") {
				t.Error("verify must check against the CA")
			}
		default:
			if strings.Contains(spec.Script, "<secure>") {
				t.Error("no TLS asked for")
			}
		}
	}
	// Next to the server a TLS port is still TLS, without checking the name.
	spec, _ := Build(Target{Engine: "clickhouse", Name: "shop", Local: true, TLS: "verify"})
	if !strings.Contains(spec.Script, "AcceptCertificateHandler") {
		t.Error("local + TLS should still connect securely")
	}
	if inc := Incremental("clickhouse"); inc.Supported {
		t.Error("no incrementals")
	}
}

func TestClickHouseRestoreRules(t *testing.T) {
	if why := Restorable(ClickHouseTar, ""); why == "" {
		t.Error("a dump of everything needs a database picked")
	}
	if why := RestoreInto(ClickHouseTar, "a", "b", false); why != "" {
		t.Error(why)
	}
	s, err := BuildRestore(Target{Engine: "clickhouse", Name: "new`db"}, RestoreOptions{Format: ClickHouseTar, Source: "shop"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "CREATE DATABASE `new\\`db`") || !strings.Contains(s, "CH_SOURCE=73686F70") {
		t.Error(s)
	}
	// A new database is only dropped again when the load fails, after it's made.
	if i := strings.Index(s, "DROP DATABASE"); i < 0 || i < strings.Index(s, "CREATE DATABASE") {
		t.Error("a failed new restore must drop what it made, and nothing before")
	}
}

func TestChIdent(t *testing.T) {
	for in, want := range map[string]string{
		"shop": "`shop`", "a`b": "`a\\`b`", `a\b`: "`a\\\\b`", "a\tb\nc": "`a\\tb\\nc`",
	} {
		if got := chIdent(in); got != want {
			t.Errorf("%q: %s, want %s", in, got, want)
		}
	}
}

// chTar builds a dump like the script's.
func chTar(t *testing.T, toc string, members map[string]string, order []string) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	put := func(name, data string) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(data))
	}
	put(chToc, toc)
	for _, m := range order {
		put(m, members[m])
	}
	tw.Close()
	return b.Bytes()
}

func TestClickHouseSniffAndVerify(t *testing.T) {
	toc := chTocHeader + "\n" +
		"0001.sql\tdatabase\t73686F70\t-\t`shop`\t-\tAtomic\n" +
		"0002.sql\ttable\t73686F70\t6576656E7473\t`shop`\t`events`\tMergeTree\n" +
		"0003.native\tdata\t73686F70\t6576656E7473\t`shop`\t`events`\tMergeTree\n" +
		"0004.sql\tdatabase\t6C6F6773\t-\t`logs`\t-\tAtomic\n"
	members := map[string]string{"0001.sql": "CREATE DATABASE shop", "0002.sql": "CREATE TABLE events (x Int8) ENGINE = Log", "0003.native": "\x01\x01", "0004.sql": "CREATE DATABASE logs"}
	order := []string{"0001.sql", "0002.sql", "0003.native", "0004.sql"}
	file := chTar(t, toc, members, order)
	packed := func(data []byte, method string) []byte {
		var z bytes.Buffer
		w, _ := Pack(&z, method, LevelFast)
		w.Write(data)
		w.Close()
		return z.Bytes()
	}

	for _, method := range []string{Gzip, Zstd} {
		f := packed(file, method)
		s, err := Sniff(bytes.NewReader(f), "postgres")
		if err != nil {
			t.Fatal(err)
		}
		if s.Format != ClickHouseTar || s.Engine != "clickhouse" || s.Pack != method || strings.Join(s.Databases, ",") != "logs,shop" {
			t.Fatalf("%+v", s)
		}
		if why := s.ForEngine("postgres"); !strings.Contains(why, "ClickHouse") {
			t.Error(why)
		}
		if _, err := Verify(ClickHouseTar, bytes.NewReader(f)); err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		fc, err := CheckFile(bytes.NewReader(f), "clickhouse")
		if err != nil || fc.Problem != "" {
			t.Fatalf("%+v %v", fc, err)
		}
	}

	// A member missing at the end, members out of order, a file cut short.
	for name, bad := range map[string][]byte{
		"missing":   chTar(t, toc, members, order[:3]),
		"reordered": chTar(t, toc, members, []string{"0001.sql", "0003.native", "0002.sql", "0004.sql"}),
		"cut":       file[:len(file)-2048],
		"not ours":  chTar(t, "something else\n", members, order),
	} {
		if _, err := Verify(ClickHouseTar, bytes.NewReader(packed(bad, Gzip))); err == nil {
			t.Errorf("%s: verified", name)
		}
		if name == "cut" {
			continue
		}
		fc, err := CheckFile(bytes.NewReader(packed(bad, Gzip)), "clickhouse")
		if err != nil || fc.Problem == "" {
			t.Errorf("%s: %+v %v", name, fc, err)
		}
	}
}
