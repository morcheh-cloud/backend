package dbquery

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/morche/backend/internal/dbmon"
)

// Split cuts a script into statements on semicolons outside strings,
// quoted names and comments (SQL Server: also on lines that are just GO).
// Empty statements are dropped.
func Split(engine, script string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		if s := strings.TrimSpace(b.String()); s != "" && !onlyComments(engine, s) {
			out = append(out, s)
		}
		b.Reset()
	}
	rs := []rune(script)
	n := len(rs)
	lineStart := true
	for i := 0; i < n; i++ {
		c := rs[i]
		if engine == dbmon.MSSQL && lineStart {
			// A batch separator: GO alone on its line.
			j := i
			for j < n && (rs[j] == ' ' || rs[j] == '\t') {
				j++
			}
			if j+2 <= n && strings.EqualFold(string(rs[j:j+2]), "go") {
				k := j + 2
				for k < n && (rs[k] == ' ' || rs[k] == '\t') {
					k++
				}
				if k == n || rs[k] == '\n' || rs[k] == '\r' {
					flush()
					i = k
					lineStart = true
					continue
				}
			}
		}
		lineStart = c == '\n'
		switch {
		case c == ';':
			flush()
			continue
		case c == '-' && i+1 < n && rs[i+1] == '-', c == '#' && mysqlLexer(engine):
			j := i
			for j < n && rs[j] != '\n' {
				j++
			}
			b.WriteString(string(rs[i:j]))
			i = j - 1
			continue
		case c == '/' && i+1 < n && rs[i+1] == '*':
			j := i + 2
			depth := 1
			for j < n && depth > 0 {
				if rs[j] == '*' && j+1 < n && rs[j+1] == '/' {
					depth--
					j += 2
					continue
				}
				if (engine == dbmon.Postgres || engine == dbmon.ClickHouse) && rs[j] == '/' && j+1 < n && rs[j+1] == '*' {
					depth++
					j += 2
					continue
				}
				j++
			}
			b.WriteString(string(rs[i:min(j, n)]))
			i = min(j, n) - 1
			continue
		case c == '\'' || c == '"' || (c == '`' && mysqlLexer(engine)):
			j := skipQuoted(rs, i, c, mysqlLexer(engine))
			b.WriteString(string(rs[i:j]))
			i = j - 1
			continue
		case c == '[' && engine == dbmon.MSSQL:
			j := skipQuoted(rs, i, ']', false)
			b.WriteString(string(rs[i:j]))
			i = j - 1
			continue
		case c == '$' && engine == dbmon.Postgres:
			if tag, ok := dollarTag(rs, i); ok {
				j := dollarEnd(rs, i, tag)
				b.WriteString(string(rs[i:j]))
				i = j - 1
				continue
			}
		}
		b.WriteRune(c)
	}
	flush()
	return out
}

// skipQuoted returns the index after the closing quote (doubled quotes stay
// inside; MySQL also skips backslash escapes in strings).
func skipQuoted(rs []rune, i int, close rune, backslash bool) int {
	n := len(rs)
	j := i + 1
	for j < n {
		if backslash && rs[j] == '\\' && close != '`' {
			j += 2
			continue
		}
		if rs[j] == close {
			if j+1 < n && rs[j+1] == close {
				j += 2
				continue
			}
			return j + 1
		}
		j++
	}
	return n
}

// indexRunes finds sub in rs from start; -1 when absent.
func indexRunes(rs []rune, start int, sub []rune) int {
	for i := start; i+len(sub) <= len(rs); i++ {
		match := true
		for k := range sub {
			if rs[i+k] != sub[k] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// dollarEnd is the index after a $tag$…$tag$ string that starts at i.
func dollarEnd(rs []rune, i int, tag []rune) int {
	j := indexRunes(rs, i+len(tag), tag)
	if j < 0 {
		return len(rs)
	}
	return j + len(tag)
}

func dollarTag(rs []rune, i int) ([]rune, bool) {
	j := i + 1
	for j < len(rs) && (rs[j] == '_' || unicode.IsLetter(rs[j]) || (j > i+1 && unicode.IsDigit(rs[j]))) {
		j++
	}
	if j < len(rs) && rs[j] == '$' {
		return rs[i : j+1], true
	}
	return nil, false
}

// mysqlLexer: backtick names, # comments and backslash escapes in strings
// (MySQL and ClickHouse).
func mysqlLexer(engine string) bool { return engine == dbmon.MySQL || engine == dbmon.ClickHouse }

func onlyComments(engine, s string) bool { return len(words(engine, s)) == 0 }

// words lists a statement's bare words, upper-cased, in order: no strings,
// quoted names or comments.
func words(engine, s string) []string {
	var out []string
	rs := []rune(s)
	n := len(rs)
	for i := 0; i < n; i++ {
		c := rs[i]
		switch {
		case c == '-' && i+1 < n && rs[i+1] == '-', c == '#' && mysqlLexer(engine):
			for i < n && rs[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && rs[i+1] == '*':
			j := indexRunes(rs, i+2, []rune("*/"))
			if j < 0 {
				return out
			}
			i = j + 1
		case c == '\'' || c == '"' || (c == '`' && mysqlLexer(engine)):
			i = skipQuoted(rs, i, c, mysqlLexer(engine)) - 1
		case c == '[' && engine == dbmon.MSSQL:
			i = skipQuoted(rs, i, ']', false) - 1
		case c == '$' && engine == dbmon.Postgres:
			if tag, ok := dollarTag(rs, i); ok {
				i = dollarEnd(rs, i, tag) - 1
			}
		case unicode.IsLetter(c) || c == '_':
			j := i
			for j < n && (unicode.IsLetter(rs[j]) || unicode.IsDigit(rs[j]) || rs[j] == '_' || rs[j] == '$') {
				j++
			}
			out = append(out, strings.ToUpper(string(rs[i:j])))
			i = j - 1
		}
	}
	return out
}

// readFirst are the words a read-only statement may start with.
var readFirst = map[string]bool{
	"SELECT": true, "WITH": true, "SHOW": true, "DESCRIBE": true, "DESC": true,
	"EXPLAIN": true, "VALUES": true, "TABLE": true,
}

// mssqlWrites can change something even inside a rolled-back transaction,
// or make no sense in a read: refused anywhere in a read-only statement.
var mssqlWrites = map[string]bool{
	"INSERT": true, "UPDATE": true, "DELETE": true, "MERGE": true, "DROP": true,
	"CREATE": true, "ALTER": true, "TRUNCATE": true, "EXEC": true, "EXECUTE": true,
	"GRANT": true, "REVOKE": true, "DENY": true, "BACKUP": true, "RESTORE": true,
	"SHUTDOWN": true, "KILL": true, "DBCC": true, "BULK": true, "OPENROWSET": true,
	"OPENQUERY": true, "OPENDATASOURCE": true, "RECONFIGURE": true, "USE": true,
	"INTO": true, "WAITFOR": true, "SET": true, "DECLARE": true, "COMMIT": true,
	"ROLLBACK": true, "SAVE": true, "BEGIN": true,
}

// checkRead refuses a statement that isn't plain reading. The engines' own
// read-only transactions (Postgres, MySQL) or a rollback (SQL Server) stop
// writes too; this catches what those don't (DDL commits on MySQL, SELECT
// INTO OUTFILE, batches).
func checkRead(engine, stmt string) error {
	ws := words(engine, stmt)
	if len(ws) == 0 {
		return nil
	}
	if engine == dbmon.ClickHouse {
		return checkReadClickHouse(stmt, ws)
	}
	if !readFirst[ws[0]] {
		return refused("%s changes something or isn't a read. Turn on Allow changes to run it.", ws[0])
	}
	for i, w := range ws {
		switch engine {
		case dbmon.MySQL:
			if w == "INTO" && i+1 < len(ws) && (ws[i+1] == "OUTFILE" || ws[i+1] == "DUMPFILE") {
				return refused("SELECT … INTO %s writes a file on the database's machine. Turn on Allow changes to run it.", ws[i+1])
			}
			if w == "INTO" && i > 0 {
				return refused("SELECT … INTO sets variables or writes a file. Turn on Allow changes to run it.")
			}
		case dbmon.MSSQL:
			if mssqlWrites[w] {
				return refused("%s isn't allowed in a read-only query. Turn on Allow changes to run it.", w)
			}
		}
	}
	return nil
}

// chReadFirst are the words a read-only ClickHouse statement may start with.
var chReadFirst = map[string]bool{
	"SELECT": true, "WITH": true, "SHOW": true, "DESCRIBE": true, "DESC": true,
	"EXPLAIN": true, "EXISTS": true,
}

// chOutside are table functions that reach past the database (files on its
// machine, other servers, URLs, programs). readonly = 2 still lets them run.
var chOutside = regexp.MustCompile(`(?i)\b(?:FROM|JOIN|,)\s*(url|urlCluster|s3|s3Cluster|gcs|oss|cosn|azureBlobStorage|azureBlobStorageCluster|hdfs|hdfsCluster|remote|remoteSecure|cluster|clusterAllReplicas|mysql|postgresql|mongodb|redis|sqlite|odbc|jdbc|executable|file|fileCluster|deltaLake|deltaLakeCluster|iceberg|icebergS3|icebergAzure|icebergHDFS|icebergLocal|hudi|paimon|arrowFlight|ytsaurus)\s*\(`)

// checkReadClickHouse: reads run with readonly = 2 too, which refuses every
// write on the server; this gives the reason up front and stops what readonly
// lets through.
func checkReadClickHouse(stmt string, ws []string) error {
	if !chReadFirst[ws[0]] {
		return refused("%s changes something or isn't a read. Turn on Allow changes to run it.", ws[0])
	}
	for i, w := range ws {
		if w == "INTO" && i+1 < len(ws) && ws[i+1] == "OUTFILE" {
			return refused("SELECT … INTO OUTFILE writes a file. Turn on Allow changes to run it.")
		}
	}
	if m := chOutside.FindStringSubmatch(bare(dbmon.ClickHouse, stmt)); m != nil {
		return refused("%s() reaches outside the database (files, other servers or addresses). Turn on Allow changes to run it.", m[1])
	}
	return nil
}

// bare is the statement with strings, quoted names and comments blanked out,
// so a pattern only sees what the server parses as code.
func bare(engine, s string) string {
	rs := []rune(s)
	n := len(rs)
	out := make([]rune, 0, n)
	blank := func(from, to int) {
		for range rs[from:min(to, n)] {
			out = append(out, ' ')
		}
	}
	for i := 0; i < n; i++ {
		c := rs[i]
		switch {
		case c == '-' && i+1 < n && rs[i+1] == '-', c == '#' && mysqlLexer(engine):
			j := i
			for j < n && rs[j] != '\n' {
				j++
			}
			blank(i, j)
			i = j - 1
		case c == '/' && i+1 < n && rs[i+1] == '*':
			j := indexRunes(rs, i+2, []rune("*/"))
			if j < 0 {
				j = n
			} else {
				j += 2
			}
			blank(i, j)
			i = j - 1
		case c == '\'' || c == '"' || (c == '`' && mysqlLexer(engine)):
			j := skipQuoted(rs, i, c, mysqlLexer(engine))
			// A quoted name stays a name: keep a placeholder word.
			if c != '\'' {
				out = append(out, 'x')
				blank(i+1, j)
			} else {
				out = append(out, '0')
				blank(i+1, j)
			}
			i = j - 1
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

// Risks lists what in a change script drops or empties data, or touches who
// may do what: such scripts need the database's name typed to run.
func Risks(engine, script string) []string {
	var out []string
	add := func(s string) {
		for _, o := range out {
			if o == s {
				return
			}
		}
		out = append(out, s)
	}
	switch engine {
	case dbmon.Redis:
		for _, line := range redisLines(script) {
			if len(line) == 0 {
				continue
			}
			switch c := strings.ToUpper(line[0]); c {
			case "FLUSHALL", "FLUSHDB", "SHUTDOWN", "DEBUG", "SWAPDB", "REPLICAOF", "SLAVEOF", "MIGRATE", "MODULE", "ACL", "FAILOVER":
				add(c + " affects the whole server or database")
			case "CONFIG":
				if len(line) > 1 && !strings.EqualFold(line[1], "GET") {
					add("CONFIG " + strings.ToUpper(line[1]) + " changes the server's settings")
				}
			case "DEL", "UNLINK":
				if len(line) > 11 {
					add(c + " removes many keys")
				}
			}
		}
		return out
	case dbmon.Mongo:
		return mongoRisks(script)
	}
	for _, st := range Split(engine, script) {
		ws := words(engine, st)
		if len(ws) == 0 {
			continue
		}
		has := func(w string) bool {
			for _, x := range ws {
				if x == w {
					return true
				}
			}
			return false
		}
		line := strings.Join(strings.Fields(st), " ")
		if len([]rune(line)) > 80 {
			line = string([]rune(line)[:80]) + "…"
		}
		switch ws[0] {
		case "DETACH":
			if engine == dbmon.ClickHouse {
				add(line)
			}
		case "DROP", "TRUNCATE":
			add(line)
		case "ALTER":
			if has("DROP") {
				add(line)
			}
		case "DELETE", "UPDATE":
			if !has("WHERE") {
				add(line + " (no WHERE: every row)")
			}
		case "GRANT", "REVOKE", "DENY":
			add(line)
		}
	}
	return out
}

// short is a statement cut to one readable line.
func short(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) > 200 {
		return string([]rune(s)[:200]) + "…"
	}
	return s
}
