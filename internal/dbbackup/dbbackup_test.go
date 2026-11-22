package dbbackup

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func TestScriptsKeepSecretsOffCommandLines(t *testing.T) {
	const secret = "s3cr'et$(x)"
	for _, engine := range []string{"postgres", "mysql", "mongodb", "redis", "mssql"} {
		spec, err := Build(Target{
			Engine: engine, Host: "db.example", Username: "u", Password: secret,
			Name: "shop", TLS: "require", Local: engine == "mssql", ID: "abc",
		})
		if err != nil {
			t.Fatalf("%s: %v", engine, err)
		}
		for line := range strings.SplitSeq(spec.Script, "\n") {
			if !strings.Contains(line, "s3cr") {
				continue
			}
			// Only shell builtins may carry it: nothing shows up in ps.
			if !strings.HasPrefix(line, "export ") && !strings.HasPrefix(line, "printf ") {
				t.Errorf("%s: secret on a command line: %q", engine, line)
			}
			if !strings.Contains(line, `s3cr'\''et$(x)`) {
				t.Errorf("%s: secret not quoted: %q", engine, line)
			}
		}
	}
}

func TestToolsDontReadTheScript(t *testing.T) {
	for _, engine := range []string{"postgres", "mysql", "mongodb", "redis", "mssql"} {
		spec, err := Build(Target{Engine: engine, Username: "u", Name: "shop", Local: true, ID: "abc"})
		if err != nil {
			t.Fatalf("%s: %v", engine, err)
		}
		if !strings.Contains(spec.Script, "</dev/null") {
			t.Errorf("%s: a tool would swallow the rest of the script from stdin", engine)
		}
	}
}

func TestMSSQLRules(t *testing.T) {
	if _, err := Build(Target{Engine: "mssql", Name: "shop"}); err == nil {
		t.Error("a far-away SQL Server must be refused")
	}
	if _, err := Build(Target{Engine: "mssql", Local: true, ID: "abc"}); err == nil {
		t.Error("SQL Server needs a database name")
	}
	spec, err := Build(Target{Engine: "mssql", Name: "a]b", Local: true, ID: "abc", Username: "sa"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(spec.Script, "[a]]b]") {
		t.Errorf("name not escaped: %s", spec.Script)
	}
}

func TestCheckName(t *testing.T) {
	for _, bad := range []string{"-x", " x", "a\nb", strings.Repeat("a", 129)} {
		if CheckName(bad) == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
	for _, good := range []string{"", "shop", "my db", "a-b_c.d"} {
		if err := CheckName(good); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
}

func zipped(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func TestVerify(t *testing.T) {
	good := zipped("-- MySQL dump\nCREATE TABLE x;\n-- Dump completed on 2026-11-07\n")
	res, err := Verify(MySQLSQL, bytes.NewReader(good))
	if err != nil {
		t.Fatal(err)
	}
	if res.Bytes != int64(len(good)) || len(res.SHA256) != 64 {
		t.Errorf("result %+v", res)
	}
	cases := []struct {
		name, format string
		data         []byte
	}{
		{"cut gzip", MySQLSQL, good[:len(good)-6]},
		{"no last line", MySQLSQL, zipped("CREATE TABLE x;\n")},
		{"not gzip", RedisRDB, []byte("REDIS0012")},
		{"wrong content", RedisRDB, zipped("hello")},
		{"wrong pg", PgCustom, []byte("hello")},
		{"empty pg", PgCustom, nil},
		{"wrong mongo", MongoArchive, zipped("hello")},
		{"wrong bak", MSSQLBak, zipped("hello")},
	}
	for _, c := range cases {
		if _, err := Verify(c.format, bytes.NewReader(c.data)); err == nil {
			t.Errorf("%s: should fail", c.name)
		}
	}
	if _, err := Verify(PgCustom, strings.NewReader("PGDMP123")); err != nil {
		t.Error(err)
	}
}

func TestTempDir(t *testing.T) {
	for dir, ok := range map[string]bool{"": true, "/var/tmp": true, "/mnt/big disk": true, "tmp": false, "/a\nb": false} {
		if err := CheckTempDir(dir); (err == nil) != ok {
			t.Errorf("%q: %v", dir, err)
		}
	}
	spec, err := Build(Target{Engine: "postgres", Username: "u", Name: "shop", Local: true, Workers: 4, TempDir: "/mnt/big disk/it's"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(spec.Script, `parent='/mnt/big disk/it'\''s'`) || !strings.Contains(spec.Script, `mktemp -d "$parent/morche-backup.XXXXXX"`) {
		t.Errorf("the folder isn't used, quoted:\n%s", spec.Script)
	}
	s, err := BuildRestore(Target{Engine: "postgres", Username: "u", Name: "shop", Local: true}, RestoreOptions{Format: PgDir, Workers: 2, TempDir: "/srv/tmp"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, `mktemp -d "$parent/morche-restore.XXXXXX"`) {
		t.Errorf("the restore doesn't use the folder:\n%s", s)
	}
}
