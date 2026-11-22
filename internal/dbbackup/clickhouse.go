package dbbackup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/morche/backend/internal/dbmon"
)

// ClickHouseTar is a ClickHouse dump made with clickhouse-client: a tar whose
// first member, clickhouse.toc, lists the rest in the order they're loaded:
//
//	NNNN.sql     a CREATE statement, its own database's name taken out (so it
//	             goes into any database)
//	NNNN.native  a table's rows, SELECT * … FORMAT Native
//
// Order: each database's CREATE (for people; a restore makes its own), the
// tables that keep rows, their rows, then everything else (views,
// materialized views, dictionaries, Distributed, Buffer, Kafka… tables) in
// creation order, and last the rows of materialized views that keep them
// themselves (no TO table). Views come after the rows, so a materialized view
// doesn't count them again. A table is written to a temporary folder, then
// sent, so the dump needs room for its biggest table; Morche compresses the
// whole stream.
const ClickHouseTar = "ch_tar"

// chToc is the tar's first member.
const chToc = "clickhouse.toc"

// chTocHeader starts the table of contents; the number is its version.
const chTocHeader = "# morche clickhouse 1"

// chSystem are ClickHouse's own databases.
var chSystem = []string{"system", "INFORMATION_SCHEMA", "information_schema"}

// chQuoteSQL is the SQL that quotes column c as an identifier, with no tab
// or newline left in it (so it fits on one line of the table of contents).
func chQuoteSQL(c string) string {
	return `concat('` + "`" + `', replaceAll(replaceAll(replaceAll(replaceAll(replaceAll(` + c +
		`, '\\', '\\\\'), '` + "`" + `', '\\` + "`" + `'), '\n', '\\n'), '\t', '\\t'), '\r', '\\r'), '` + "`" + `')`
}

// chIdent quotes an identifier the same way.
func chIdent(name string) string {
	r := strings.NewReplacer(`\`, `\\`, "`", "\\`", "\n", `\n`, "\t", `\t`, "\r", `\r`)
	return "`" + r.Replace(name) + "`"
}

func chHex(s string) string { return strings.ToUpper(hex.EncodeToString([]byte(s))) }

// chTocSQL lists what a dump holds, one line per member (before numbering):
// kind, database and name in hex (to find them again), quoted (to write
// them in SQL), and the engine.
func chTocSQL(name string) string {
	dbs := "SELECT name FROM system.databases WHERE engine IN ('Atomic', 'Ordinary', 'Replicated', 'Lazy', 'Memory') AND name NOT IN ('" + strings.Join(chSystem, "', '") + "')"
	if name != "" {
		dbs += " AND name = unhex('" + chHex(name) + "')"
	}
	stored := "NOT is_temporary AND has_own_data AND engine NOT IN ('Set', 'KeeperMap') AND NOT startsWith(name, '.inner')"
	from := " FROM system.tables WHERE database IN (" + dbs + ") AND "
	cols := "database, name, engine, metadata_modification_time"
	return "SELECT kind, hex(db), if(t = '', '-', hex(t)), " + chQuoteSQL("db") + ", if(t = '', '-', " + chQuoteSQL("t") + "), engine FROM (" +
		"SELECT 1 AS phase, 'database' AS kind, name AS db, '' AS t, engine, toDateTime(0) AS at FROM system.databases WHERE name IN (" + dbs + ")" +
		" UNION ALL SELECT 2, 'table', " + cols + from + stored +
		" UNION ALL SELECT 3, 'data', " + cols + from + stored +
		" UNION ALL SELECT 4, 'object', " + cols + from + "NOT is_temporary AND NOT startsWith(name, '.inner') AND NOT (" + stored + ")" +
		" UNION ALL SELECT 5, 'mvdata', " + cols + from + "engine = 'MaterializedView' AND ((database, concat('.inner_id.', toString(uuid))) IN (SELECT database, name FROM system.tables) OR (database, concat('.inner.', name)) IN (SELECT database, name FROM system.tables))" +
		") ORDER BY phase, at, db, t FORMAT TSVRaw"
}

// chDDLSQL is one table's CREATE with references to its own database taken
// out, so it goes into whatever database the restore runs in (ClickHouse adds
// the current one back to a view's tables, and a dictionary's CLICKHOUSE
// source without DB reads its own database). A string in a view that reads
// "<database>." is changed too.
func chDDLSQL() string {
	lit := `concat('\'', replaceAll(replaceAll(database, '\\', '\\\\'), '\'', '\\\''), '\'')`
	return `SELECT if(engine = 'Dictionary', replaceRegexpAll(q, concat('\\sDB\\s+', regexpQuoteMeta(` + lit + `)), ''), q) FROM (` +
		`SELECT engine, database, replaceRegexpAll(create_table_query, concat('(^|[^\\w.` + "`" + `])(', regexpQuoteMeta(database), '|', regexpQuoteMeta(` +
		chQuoteSQL("database") + `), ')\\.'), '\\1') AS q FROM system.tables WHERE database = unhex({d:String}) AND name = unhex({t:String})) FORMAT RawBLOB`
}

// chPrelude finds the client and writes its private config: address, login,
// TLS. $dir must exist (the config lives there). It defines ch.
func chPrelude(b *strings.Builder, t Target) {
	b.WriteString(`if command -v clickhouse-client >/dev/null 2>&1; then CH_TOOL=clickhouse-client
elif command -v clickhouse >/dev/null 2>&1; then CH_TOOL="clickhouse client"
else ` + missing("clickhouse-client") + `
fi
command -v tar >/dev/null 2>&1 || { ` + missing("tar") + `; }
`)
	conf := "<config><host>" + xmlText(t.Host) + "</host><port>" + strconv.Itoa(t.Port) + "</port>"
	if t.Username != "" {
		conf += "<user>" + xmlText(t.Username) + "</user>"
	}
	if t.Password != "" {
		conf += "<password>" + xmlText(t.Password) + "</password>"
	}
	tls := t.TLS
	if t.Local && tls == dbmon.TLSVerify {
		// Next to the server its name isn't the certificate's, but a TLS port
		// only speaks TLS.
		tls = dbmon.TLSRequire
	}
	b.WriteString("conf=\"$dir/client.xml\"\n")
	switch tls {
	case dbmon.TLSRequire:
		conf += "<secure>true</secure><openSSL><client><verificationMode>none</verificationMode><invalidCertificateHandler><name>AcceptCertificateHandler</name></invalidCertificateHandler></client></openSSL>"
	case dbmon.TLSVerify:
		conf += "<secure>true</secure><openSSL><client><verificationMode>strict</verificationMode><loadDefaultCAFile>true</loadDefaultCAFile>"
		if verifiesCA(t) {
			b.WriteString("printf '%s' " + quote(conf+"<caConfig>") + " > \"$conf\"\nprintf '%s' \"$ca\" >> \"$conf\"\n")
			conf = "</caConfig>"
		}
		conf += "<invalidCertificateHandler><name>RejectCertificateHandler</name></invalidCertificateHandler></client></openSSL>"
	}
	conf += "</config>"
	if verifiesCA(t) && tls == dbmon.TLSVerify {
		b.WriteString("printf '%s\\n' " + quote(conf) + " >> \"$conf\"\n")
	} else {
		b.WriteString("printf '%s\\n' " + quote(conf) + " > \"$conf\"\n")
	}
	b.WriteString("export CH_TOOL conf dir\n")
	b.WriteString("# shellcheck disable=SC2086\nch() { $CH_TOOL --config-file=\"$conf\" \"$@\" </dev/null; }\n")
}

func xmlText(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func clickhouse(t Target) Spec {
	var b strings.Builder
	b.WriteString("umask 077\n")
	if verifiesCA(t) {
		caFile(&b, t.CACert)
	}
	tempFolder(&b, t.TempDir, "backup")
	chPrelude(&b, t)
	fmt.Fprintf(&b, `ch -q %s > "$dir/list" || exit 1
`, quote(chTocSQL(t.Name)))
	if t.Name != "" {
		fmt.Fprintf(&b, `[ -s "$dir/list" ] || { echo %s >&2; exit 1; }
`, quote("ClickHouse has no database called "+t.Name+" that keeps its own tables."))
	}
	// Members are numbered here, so the table of contents goes out first.
	fmt.Fprintf(&b, `{ echo %s; awk -F'\t' '{ n++; printf "%%04d.%%s\t%%s\n", n, ($1 == "data" || $1 == "mvdata") ? "native" : "sql", $0 }' "$dir/list"; } > "$dir/%s" || exit 1
# A tar member, without the end of the archive tar adds after it.
emit() {
  size=$(wc -c < "$dir/$1") || exit 1
  # The rest is read away, so tar never meets a closed pipe.
  tar -cf - -C "$dir" "$1" | { head -c $((512 + (size + 511) / 512 * 512)) || exit 1; cat >/dev/null; } || exit 1
}
emit %s
ddl=%s
while IFS='	' read -r m kind dbh nh dbq nq engine; do
  case $m in '#'*) continue ;; esac
  case $kind in
    database) ch -q "SHOW CREATE DATABASE $dbq FORMAT RawBLOB" > "$dir/$m" ;;
    table|object) ch --param_d="$dbh" --param_t="$nh" -q "$ddl" > "$dir/$m" && [ -s "$dir/$m" ] ;;
    data|mvdata) ch -q "SELECT * FROM $dbq.$nq FORMAT Native" > "$dir/$m" ;;
    *) false ;;
  esac || { echo "Couldn't dump $dbq.$nq ($engine)." >&2; exit 1; }
  emit "$m"
  rm -f "$dir/$m"
done < "$dir/%s"
head -c 1024 /dev/zero
`, quote(chTocHeader), chToc, chToc, quote(chDDLSQL()), chToc)
	return Spec{Script: b.String(), Ext: "ch.tar.gz", Format: ClickHouseTar, Pack: true}
}

// chHandler loads one member of the tar, which comes on stdin with its name
// in TAR_FILENAME (GNU tar's --to-command, or the fallback loop). Members of
// other databases than CH_SOURCE are skipped; views and the like wait in
// $dir until the rows are in ("flush"), then are made in as many passes as
// their dependencies need.
const chHandler = `# shellcheck disable=SC2086
ch() { $CH_TOOL --config-file="$conf" "$@"; }
name() { awk -F'\t' -v m="$1" '$1 == m { print $6 }' "$dir/toc"; }
flush() {
  [ ! -e "$dir/flushed" ] || return 0
  : > "$dir/flushed"
  [ -s "$dir/deferred" ] || return 0
  left=$(cat "$dir/deferred")
  while [ -n "$left" ]; do
    next= made=
    for m in $left; do
      if ch -d "$CH_DB" -n < "$dir/d.$m" 2> "$dir/err.$m"; then made=1; else next="$next $m"; fi
    done
    if [ -z "$made" ]; then
      for m in $next; do echo "Couldn't create $(name "$m"): $(cat "$dir/err.$m")" >&2; done
      return 1
    fi
    left=$next
  done
}
fail() { echo "$1" >&2; : > "$dir/failed"; cat >/dev/null; exit 0; }
if [ "${1:-}" = flush ]; then flush; exit; fi
m=${TAR_FILENAME#./}
if [ -e "$dir/failed" ]; then cat >/dev/null; exit 0; fi
if [ "$m" = clickhouse.toc ]; then cat > "$dir/toc"; exit 0; fi
case $m in
  [0-9]*.sql|[0-9]*.native) ;;
  *) fail "The file holds $m, which a ClickHouse backup doesn't." ;;
esac
case $m in *[!0-9a-z.]*) fail "The file holds $m, which a ClickHouse backup doesn't." ;; esac
[ -s "$dir/toc" ] || fail "The file doesn't start with its table of contents (clickhouse.toc), so it isn't a ClickHouse backup Morche made."
line=$(awk -F'\t' -v m="$m" '$1 == m' "$dir/toc")
[ -n "$line" ] || fail "The file holds $m, which its table of contents doesn't list."
IFS='	' read -r _ kind dbh _ _ nq _ <<EOF
$line
EOF
if [ "$dbh" != "$CH_SOURCE" ]; then cat >/dev/null; exit 0; fi
: > "$dir/seen"
case $kind in
  table) ch -d "$CH_DB" -n || fail "Couldn't create the table $nq." ;;
  data|mvdata)
    if [ "$kind" = mvdata ]; then flush || fail "Couldn't create the views and dictionaries."; fi
    if [ "${TAR_SIZE:-1}" = 0 ]; then cat >/dev/null; exit 0; fi
    ch -d "$CH_DB" --max_partitions_per_insert_block=0 --insert_deduplicate=0 -q "INSERT INTO $nq FORMAT Native" || fail "Couldn't load the rows of $nq." ;;
  object) { cat > "$dir/d.$m" && echo "$m" >> "$dir/deferred"; } || fail "Couldn't keep $nq for later." ;;
  *) cat >/dev/null ;;
esac
`

// clickhouseRestore drops and makes the target again (replace) or makes it
// (new; dropped again when the load fails), then loads the source database's
// members into it.
func clickhouseRestore(t Target, o RestoreOptions) string {
	var b strings.Builder
	b.WriteString("umask 077\n")
	if verifiesCA(t) {
		caFile(&b, t.CACert)
	}
	tempFolder(&b, o.TempDir, "restore")
	chPrelude(&b, t)
	ident := chIdent(t.Name)
	fmt.Fprintf(&b, "CH_DB=%s CH_SOURCE=%s\nexport CH_DB CH_SOURCE\n", quote(t.Name), chHex(o.Source))
	b.WriteString("printf '%s' " + quote(chHandler) + " > \"$dir/h\" || exit 1\n")
	undo := ""
	if o.Replace {
		b.WriteString("ch -q " + quote("DROP DATABASE IF EXISTS "+ident+" SYNC") + " || exit 1\n")
	} else {
		undo = "ch -q " + quote("DROP DATABASE IF EXISTS "+ident+" SYNC") + " >&2; "
	}
	b.WriteString("ch -q " + quote("CREATE DATABASE "+ident) + " || exit 1\n")
	fmt.Fprintf(&b, `code=
if tar --help 2>/dev/null | grep -q -e --to-command; then
  # Each member goes straight into the database: nothing is unpacked.
  tar -xf - --to-command='sh "$dir/h"' || code=$?
else
  mkdir "$dir/x" && tar -xf - -C "$dir/x" || code=$?
  if [ -z "$code" ]; then
    if [ -f "$dir/x/%[1]s" ]; then
      TAR_FILENAME=%[1]s sh "$dir/h" < "$dir/x/%[1]s"
      while IFS='	' read -r m _; do
        case $m in '#'*|*[!0-9a-z.]*) continue ;; esac
        [ -f "$dir/x/$m" ] || { echo "The file is missing $m, which its table of contents lists." >&2; code=1; break; }
        TAR_FILENAME=$m TAR_SIZE=$(wc -c < "$dir/x/$m") sh "$dir/h" < "$dir/x/$m"
        rm -f "$dir/x/$m"
      done < "$dir/toc"
    else
      echo "The file doesn't start with its table of contents (%[1]s), so it isn't a ClickHouse backup Morche made." >&2; code=1
    fi
  fi
fi
[ ! -e "$dir/failed" ] || code=1
if [ -z "$code" ] && [ ! -e "$dir/seen" ]; then
  echo %[2]s >&2; code=1
fi
[ -n "$code" ] || sh "$dir/h" flush || code=1
if [ -n "$code" ]; then
  %[3]sexit 1
fi
`, chToc, quote("The file holds no database called "+o.Source+"."), undo)
	return b.String()
}

// ChEntry is one line of a ClickHouse dump's table of contents.
type ChEntry struct {
	Member, Kind, Database, Table, Engine string
}

// parseChToc reads clickhouse.toc.
func parseChToc(data []byte) ([]ChEntry, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var out []ChEntry
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first {
			if line != chTocHeader {
				return nil, errors.New("its table of contents isn't one Morche wrote")
			}
			first = false
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 7 || !chMember.MatchString(f[0]) {
			return nil, errors.New("its table of contents has a line Morche can't read")
		}
		db, err := hex.DecodeString(f[2])
		if err != nil {
			return nil, errors.New("its table of contents has a line Morche can't read")
		}
		e := ChEntry{Member: f[0], Kind: f[1], Database: string(db), Engine: f[6]}
		if f[3] != "-" {
			tb, err := hex.DecodeString(f[3])
			if err != nil {
				return nil, errors.New("its table of contents has a line Morche can't read")
			}
			e.Table = string(tb)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if first {
		return nil, errors.New("its table of contents is empty")
	}
	return out, nil
}

var chMember = regexp.MustCompile(`^[0-9]+\.(sql|native)$`)

// chDatabases are the databases a table of contents names, sorted.
func chDatabases(toc []ChEntry) []string {
	var out []string
	for _, e := range toc {
		if !slices.Contains(out, e.Database) {
			out = append(out, e.Database)
		}
	}
	slices.Sort(out)
	return out
}

// tarIsChDump says a tar's first member is a ClickHouse dump's table of contents.
func tarIsChDump(head []byte) bool {
	h, err := tar.NewReader(bytes.NewReader(head)).Next()
	return err == nil && strings.TrimPrefix(h.Name, "./") == chToc
}

// chTocIn reads the table of contents from the start of a dump.
func chTocIn(head []byte) ([]ChEntry, error) {
	tr := tar.NewReader(bytes.NewReader(head))
	if _, err := tr.Next(); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(tr)
	if err != nil {
		return nil, errors.New("its table of contents is cut short")
	}
	return parseChToc(data)
}

// checkChTar reads a whole ClickHouse dump: the table of contents first, then
// every member it lists, in its order, each complete. bad is a verdict on the
// file; err is a failing read, which says nothing about it.
func checkChTar(r io.Reader) (toc []ChEntry, bad, err error) {
	tr := tar.NewReader(r)
	short := func(err error) bool {
		return errors.Is(err, tar.ErrHeader) || errors.Is(err, io.ErrUnexpectedEOF) || isDamaged(err)
	}
	h, err := tr.Next()
	if err != nil {
		if errors.Is(err, io.EOF) || short(err) {
			return nil, errors.New("the archive is empty or damaged"), nil
		}
		return nil, nil, err
	}
	if strings.TrimPrefix(h.Name, "./") != chToc {
		return nil, errors.New("it doesn't start with its table of contents (" + chToc + ")"), nil
	}
	data, err := io.ReadAll(tr)
	if err != nil {
		if short(err) {
			return nil, errors.New("the archive is cut short"), nil
		}
		return nil, nil, err
	}
	toc, verdict := parseChToc(data)
	if verdict != nil {
		return nil, verdict, nil
	}
	for i, e := range toc {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return toc, fmt.Errorf("the archive is cut short: it ends after %d of %d parts", i, len(toc)), nil
		}
		if err != nil {
			if short(err) {
				return toc, errors.New("the archive is cut short or damaged"), nil
			}
			return toc, nil, err
		}
		if name := strings.TrimPrefix(h.Name, "./"); name != e.Member {
			return toc, fmt.Errorf("it holds %s where its table of contents says %s", name, e.Member), nil
		}
		if _, err := io.Copy(io.Discard, tr); err != nil {
			if short(err) {
				return toc, errors.New("the archive is cut short"), nil
			}
			return toc, nil, err
		}
	}
	if h, err := tr.Next(); err == nil {
		return toc, fmt.Errorf("it holds %s, which its table of contents doesn't list", h.Name), nil
	}
	return toc, nil, nil
}
