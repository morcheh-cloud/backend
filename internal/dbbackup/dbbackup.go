// Package dbbackup writes the shell scripts that dump a database and checks
// the files they produce. It runs nothing: the API feeds a script to `sh -s`
// over SSH (on the server, or inside the database's container) and stores
// what it prints on stdout.
//
// Scripts arrive on stdin and take passwords from the environment or a
// private temp file, so no secret ever shows on a command line or in `ps`.
package dbbackup

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/morcheh/backend/internal/dbmon"
)

// File formats. Stored with a backup, they decide the restore steps and how
// the file is checked.
const (
	PgCustom     = "pg_custom"    // pg_dump -Fc: compressed already
	PgAll        = "pg_all"       // pg_dumpall, gzipped by Morcheh
	MySQLSQL     = "mysql_sql"    // mysqldump --databases, gzipped by Morcheh
	MySQLDB      = "mysql_db"     // mysqldump of one database, gzipped by Morcheh
	MySQLBinlog  = "mysql_binlog" // mysqlbinlog's text, gzipped by Morcheh
	MongoArchive = "mongo_arch"   // mongodump --archive --gzip
	RedisRDB     = "redis_rdb"    // RDB snapshot, gzipped by Morcheh
	MSSQLBak     = "mssql_bak"    // BACKUP DATABASE, gzipped by Morcheh
	MSSQLDiff    = "mssql_diff"   // BACKUP DATABASE ... WITH DIFFERENTIAL, gzipped by Morcheh
	mssqlDataDir = "/var/opt/mssql/data"
)

// Lines an incremental's script leaves on stderr for the API: where the next
// one continues from, and that the chain can't be continued.
const (
	PositionMark = "MORCHEH_POSITION="
	BrokenMark   = "MORCHEH_CHAIN_BROKEN"
)

// Gzipped says Morcheh compressed the file itself, so it's the one to undo that
// on the way back.
func Gzipped(format string) bool {
	switch format {
	case PgAll, MySQLSQL, MySQLDB, MySQLBinlog, RedisRDB, MSSQLBak, MSSQLDiff:
		return true
	}
	return false
}

// IncrementalSupport says whether an engine can back up only what changed.
type IncrementalSupport struct {
	Supported bool
	// Why not, or what it asks of the database.
	Note string
}

// Incremental tells what an engine offers. PostgreSQL's incremental backup is
// physical and of the whole server, and bringing it back means stopping the
// server; MongoDB's oplog needs a replica set and isn't per database.
func Incremental(engine string) IncrementalSupport {
	switch engine {
	case dbmon.MySQL:
		return IncrementalSupport{true, "Saves the binary log since the last backup. Binary logging must be on, and the login needs RELOAD, REPLICATION CLIENT and REPLICATION SLAVE."}
	case dbmon.MSSQL:
		return IncrementalSupport{true, "Uses SQL Server's differential backup: everything changed since the last full one."}
	case dbmon.Postgres:
		return IncrementalSupport{false, "PostgreSQL's incremental backups cover the whole server and need it stopped to bring back, so only full backups are offered."}
	case dbmon.Mongo:
		return IncrementalSupport{false, "MongoDB only has this through the oplog of a replica set, not per database."}
	case dbmon.Redis:
		return IncrementalSupport{false, "Redis only makes whole snapshots."}
	}
	return IncrementalSupport{false, "This engine doesn't have one."}
}

// Target is what to dump and how to reach it from where the script runs.
type Target struct {
	Engine   string
	Host     string
	Port     int
	Username string
	Password string
	// The database the login belongs to (Mongo's auth source).
	AuthDatabase string
	// One database's name; empty = the whole instance.
	Name   string
	TLS    string
	CACert string
	// Runs next to the database (same machine or inside its container).
	Local bool
	// Unique per run: names SQL Server's temporary file.
	ID string
	// A full backup that incrementals will build on.
	Chain bool
	// Only what changed since Position.
	Incremental bool
	// Where the chain stands: binary log file:offset, or SQL Server's base.
	Position string
}

// Spec is a script and what comes out of it.
type Spec struct {
	Script string
	// File extension, without the dot.
	Ext    string
	Format string
	// Morcheh should gzip the output while storing it.
	Gzip bool
	// The chain's position is in the file's first lines (see PositionIn).
	HeadPosition bool
}

var idPattern = regexp.MustCompile(`^[0-9a-zA-Z-]+$`)

// CheckName refuses what can't be a database name, or could be taken for an
// option by a dump tool.
func CheckName(name string) error {
	if name != strings.TrimSpace(name) {
		return errors.New("Remove the spaces around the name.")
	}
	if len(name) > 128 {
		return errors.New("Use 128 characters or fewer.")
	}
	if strings.HasPrefix(name, "-") {
		return errors.New("A name can't start with a dash.")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return errors.New("The name has a character that can't be used.")
		}
	}
	return nil
}

// Build writes the script for a target.
func Build(t Target) (Spec, error) {
	if err := CheckName(t.Name); err != nil {
		return Spec{}, err
	}
	if t.Port == 0 {
		t.Port = dbmon.DefaultPort(t.Engine)
	}
	if t.Host == "" {
		t.Host = "127.0.0.1"
	}
	switch t.Engine {
	case dbmon.Postgres:
		return postgres(t), nil
	case dbmon.MySQL:
		return mysql(t), nil
	case dbmon.Mongo:
		return mongo(t), nil
	case dbmon.Redis:
		return redis(t), nil
	case dbmon.MSSQL:
		return mssql(t)
	}
	return Spec{}, fmt.Errorf("backups don't support %s", t.Engine)
}

// Quote makes a string one shell word.
func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// missing ends the script when no tool of the list exists; the wording ends
// up on the backup's row.
func missing(tool string) string {
	return "echo " + quote(tool+" isn't installed where the backup runs.") + " >&2; exit 127"
}

// caFile writes the CA certificate to a private file; $ca holds its path.
func caFile(b *strings.Builder, pem string) {
	b.WriteString("ca=$(mktemp) || exit 1\ntrap 'rm -f \"$ca\"' EXIT\n")
	b.WriteString("printf '%s\\n' " + quote(pem) + " > \"$ca\"\n")
}

func verifiesCA(t Target) bool { return t.TLS == dbmon.TLSVerify && t.CACert != "" }

func pgSSLMode(t Target) string {
	if t.Local {
		return "prefer"
	}
	switch t.TLS {
	case dbmon.TLSRequire:
		return "require"
	case dbmon.TLSVerify:
		return "verify-full"
	}
	return "disable"
}

func postgres(t Target) Spec {
	var b strings.Builder
	b.WriteString("umask 077\n")
	if verifiesCA(t) {
		caFile(&b, t.CACert)
		b.WriteString("export PGSSLROOTCERT=\"$ca\"\n")
	}
	env := []string{
		"PGHOST=" + quote(t.Host), "PGPORT=" + strconv.Itoa(t.Port),
		"PGUSER=" + quote(t.Username), "PGSSLMODE=" + pgSSLMode(t), "PGCONNECT_TIMEOUT=20",
	}
	if t.Password != "" {
		env = append(env, "PGPASSWORD="+quote(t.Password))
	}
	if t.Name != "" {
		// The environment, not -d: a name is never read as a connection string.
		env = append(env, "PGDATABASE="+quote(t.Name))
	}
	b.WriteString("export " + strings.Join(env, " ") + "\n")
	if t.Name == "" {
		b.WriteString("command -v pg_dumpall >/dev/null 2>&1 || { " + missing("pg_dumpall") + "; }\n")
		b.WriteString("pg_dumpall --no-password </dev/null\n")
		return Spec{Script: b.String(), Ext: "sql.gz", Format: PgAll, Gzip: true}
	}
	b.WriteString("command -v pg_dump >/dev/null 2>&1 || { " + missing("pg_dump") + "; }\n")
	b.WriteString("pg_dump -Fc --no-password </dev/null\n")
	return Spec{Script: b.String(), Ext: "dump", Format: PgCustom}
}

// mysqlFlags are the TLS flags, by client family.
func mysqlFlags(t Target) (mariadb, oracle string) {
	switch {
	case t.Local || t.TLS == dbmon.TLSDisable || t.TLS == "":
		return "--skip-ssl", "--ssl-mode=DISABLED"
	case t.TLS == dbmon.TLSRequire:
		return "--ssl --skip-ssl-verify-server-cert", "--ssl-mode=REQUIRED"
	}
	mariadb, oracle = "--ssl --ssl-verify-server-cert", "--ssl-mode=VERIFY_IDENTITY"
	if verifiesCA(t) {
		mariadb += ` --ssl-ca="$ca"`
		oracle += ` --ssl-ca="$ca"`
	}
	return mariadb, oracle
}

// mysqlTool defines the shell function name to run the first tool found. The
// two families' tools share all flags but the TLS ones.
func mysqlTool(b *strings.Builder, t Target, name, maria, oracle string) {
	fmt.Fprintf(b, `if command -v %[1]s >/dev/null 2>&1; then
  %[3]s_tool=%[1]s; %[3]s_family=mariadb
elif command -v %[2]s >/dev/null 2>&1; then
  %[3]s_tool=%[2]s
  case "$(%[2]s --version 2>/dev/null)" in
    *[Mm]aria*) %[3]s_family=mariadb ;;
    *) %[3]s_family=mysql ;;
  esac
else
  %[4]s
fi
`, maria, oracle, name, missing(oracle))
	m, o := mysqlFlags(t)
	fmt.Fprintf(b, "if [ \"$%[1]s_family\" = mariadb ]; then\n  %[1]s() { \"$%[1]s_tool\" %[2]s \"$@\"; }\nelse\n  %[1]s() { \"$%[1]s_tool\" %[3]s \"$@\"; }\nfi\n", name, m, o)
}

func mysqlPrelude(b *strings.Builder, t Target) {
	b.WriteString("umask 077\n")
	if verifiesCA(t) {
		caFile(b, t.CACert)
	}
	if t.Password != "" {
		b.WriteString("export MYSQL_PWD=" + quote(t.Password) + "\n")
	}
}

func mysqlLogin(t Target) string {
	return fmt.Sprintf("--host=%s --port=%d --user=%s", quote(t.Host), t.Port, quote(t.Username))
}

func mysql(t Target) Spec {
	if t.Incremental {
		return mysqlBinlog(t)
	}
	var b strings.Builder
	mysqlPrelude(&b, t)
	mysqlTool(&b, t, "dump", "mariadb-dump", "mysqldump")
	// One database's file holds no USE, so it can go into another name.
	what, format := "--all-databases", MySQLSQL
	if t.Name != "" {
		what, format = "-- "+quote(t.Name), MySQLDB
	}
	position := ""
	if t.Chain {
		// A comment at the top of the file says where the binary log stood.
		b.WriteString(`case "$(dump --help 2>/dev/null)" in
  *--source-data*) position=--source-data=2 ;;
  *) position=--master-data=2 ;;
esac
`)
		position = "$position "
	}
	fmt.Fprintf(&b, "dump %s --single-transaction --quick --routines --triggers --events --hex-blob --no-tablespaces %s%s </dev/null\n",
		mysqlLogin(t), position, what)
	return Spec{Script: b.String(), Ext: "sql.gz", Format: format, Gzip: true, HeadPosition: t.Chain}
}

var headPosition = regexp.MustCompile(`(?:MASTER|SOURCE)_LOG_FILE='([^']+)',\s*(?:MASTER|SOURCE)_LOG_POS=(\d+)`)

// PositionIn finds where the binary log stood in the top of a dump.
func PositionIn(head []byte) string {
	m := headPosition.FindSubmatch(head)
	if m == nil {
		return ""
	}
	return string(m[1]) + ":" + string(m[2])
}

// mysqlBinlog prints the binary log since Position, for one database, after
// closing the current file so the next run has a clean start.
func mysqlBinlog(t Target) Spec {
	file, offset, _ := strings.Cut(t.Position, ":")
	var b strings.Builder
	mysqlPrelude(&b, t)
	mysqlTool(&b, t, "client", "mariadb", "mysql")
	mysqlTool(&b, t, "logs", "mariadb-binlog", "mysqlbinlog")
	login := mysqlLogin(t)
	fmt.Fprintf(&b, `client %[1]s --batch --skip-column-names -e 'FLUSH BINARY LOGS' </dev/null >&2 || exit 1
list=$(client %[1]s --batch --skip-column-names -e 'SHOW BINARY LOGS' </dev/null | awk '{print $1}') || exit 1
start=%[2]s
newest=$(printf '%%s\n' "$list" | tail -n 1)
files=$(printf '%%s\n' "$list" | awk -v s="$start" '$0 == s {on = 1} on')
[ -n "$files" ] || { echo %[3]s >&2; exit 3; }
files=$(printf '%%s\n' "$files" | sed '$d')
case "$(logs --help 2>/dev/null)" in
  *--skip-gtids*) gtids=--skip-gtids ;;
  *) gtids= ;;
esac
# shellcheck disable=SC2086
[ -z "$files" ] || logs %[1]s --read-from-remote-server --start-position=%[4]s --database=%[5]s $gtids $files </dev/null || exit 1
echo %[6]s"$newest":4 >&2
`, login, quote(file), BrokenMark, quote(offset), quote(t.Name), PositionMark)
	return Spec{Script: b.String(), Ext: "binlog.sql.gz", Format: MySQLBinlog, Gzip: true}
}

// mongoAccess writes the login's private files and gives the shared flags.
func mongoAccess(b *strings.Builder, t Target) []string {
	b.WriteString("conf=$(mktemp) || exit 1\n")
	if verifiesCA(t) {
		b.WriteString("ca=$(mktemp) || exit 1\ntrap 'rm -f \"$conf\" \"$ca\"' EXIT\n")
		b.WriteString("printf '%s\\n' " + quote(t.CACert) + " > \"$ca\"\n")
	} else {
		b.WriteString("trap 'rm -f \"$conf\"' EXIT\n")
	}
	if t.Password != "" {
		// YAML reads a JSON string as it is.
		pw, _ := json.Marshal(t.Password)
		b.WriteString("printf '%s\\n' " + quote("password: "+string(pw)) + " > \"$conf\"\n")
	}
	args := []string{`--config="$conf"`, "--host=" + quote(t.Host), "--port=" + strconv.Itoa(t.Port)}
	if t.Username != "" {
		source := t.AuthDatabase
		if source == "" {
			source = "admin"
		}
		args = append(args, "--username="+quote(t.Username), "--authenticationDatabase="+quote(source))
	}
	if !t.Local {
		switch t.TLS {
		case dbmon.TLSRequire:
			args = append(args, "--ssl", "--sslAllowInvalidCertificates")
		case dbmon.TLSVerify:
			args = append(args, "--ssl")
			if verifiesCA(t) {
				args = append(args, `--sslCAFile="$ca"`)
			}
		}
	}
	return args
}

func mongo(t Target) Spec {
	var b strings.Builder
	b.WriteString("umask 077\ncommand -v mongodump >/dev/null 2>&1 || { " + missing("mongodump") + "; }\n")
	args := append([]string{"mongodump", "--quiet", "--archive", "--gzip"}, mongoAccess(&b, t)...)
	if t.Name != "" {
		args = append(args, "--db="+quote(t.Name))
	}
	b.WriteString(strings.Join(args, " ") + " </dev/null\n")
	return Spec{Script: b.String(), Ext: "archive.gz", Format: MongoArchive}
}

func redis(t Target) Spec {
	var b strings.Builder
	b.WriteString("umask 077\n")
	if t.Password != "" {
		b.WriteString("export REDISCLI_AUTH=" + quote(t.Password) + "\n")
	}
	b.WriteString(`if command -v redis-cli >/dev/null 2>&1; then tool=redis-cli
elif command -v valkey-cli >/dev/null 2>&1; then tool=valkey-cli
else ` + missing("redis-cli") + `
fi
`)
	args := []string{`"$tool"`, "-h", quote(t.Host), "-p", strconv.Itoa(t.Port)}
	if t.Username != "" {
		args = append(args, "--user", quote(t.Username))
	}
	var clean []string
	if !t.Local {
		switch t.TLS {
		case dbmon.TLSRequire:
			args = append(args, "--tls", "--insecure")
		case dbmon.TLSVerify:
			args = append(args, "--tls")
			if verifiesCA(t) {
				caFile(&b, t.CACert)
				args = append(args, `--cacert "$ca"`)
				clean = append(clean, `"$ca"`)
			}
		}
	}
	// Before 7.0 redis-cli insists on a real file: it fsyncs what it writes.
	cmd := strings.Join(args, " ")
	files := strings.Join(append(clean, `"$f"`), " ")
	b.WriteString(`major=$("$tool" --version 2>/dev/null | sed 's/[^0-9]*\([0-9]*\).*/\1/')
if [ "${major:-0}" -ge 7 ]; then
  ` + cmd + ` --rdb - </dev/null
else
  f=$(mktemp) || exit 1
  trap 'rm -f ` + files + `' EXIT
  ` + cmd + ` --rdb "$f" </dev/null >&2 || exit $?
  cat "$f"
fi
`)
	return Spec{Script: b.String(), Ext: "rdb.gz", Format: RedisRDB, Gzip: true}
}

// mssqlPrelude finds sqlcmd and defines `run`, which takes sqlcmd's flags.
func mssqlPrelude(b *strings.Builder, t Target) {
	b.WriteString("umask 077\n")
	if t.Password != "" {
		b.WriteString("export SQLCMDPASSWORD=" + quote(t.Password) + "\n")
	}
	b.WriteString(`tool=$(command -v sqlcmd 2>/dev/null)
for p in /opt/mssql-tools18/bin/sqlcmd /opt/mssql-tools/bin/sqlcmd; do
  [ -n "$tool" ] || { [ -x "$p" ] && tool=$p; }
done
[ -n "$tool" ] || { ` + missing("sqlcmd") + `; }
`)
	// -x: a name with $( in it isn't a sqlcmd variable.
	fmt.Fprintf(b, "run() { \"$tool\" -C -b -x -S %s -U %s \"$@\" </dev/null; }\n",
		quote(fmt.Sprintf("tcp:%s,%d", t.Host, t.Port)), quote(t.Username))
}

func mssqlName(name string) string { return "[" + strings.ReplaceAll(name, "]", "]]") + "]" }

func mssqlText(s string) string { return "N'" + strings.ReplaceAll(s, "'", "''") + "'" }

func mssqlSQL(sql string) string { return quote(sql) }

func mssql(t Target) (Spec, error) {
	if t.Name == "" {
		return Spec{}, errors.New("SQL Server backups are one database at a time.")
	}
	if !t.Local {
		return Spec{}, errors.New("SQL Server writes its backup on its own disk, so Morcheh has to reach the machine or container it runs on.")
	}
	if !idPattern.MatchString(t.ID) {
		return Spec{}, errors.New("a backup needs an id")
	}
	var b strings.Builder
	mssqlPrelude(&b, t)
	file := mssqlDataDir + "/morcheh-" + t.ID + ".bak"
	b.WriteString("f=" + quote(file) + "\ntrap 'rm -f \"$f\"' EXIT\n")
	base := "SET NOCOUNT ON; SELECT differential_base_guid FROM sys.master_files WHERE database_id = DB_ID(" + mssqlText(t.Name) + ") AND file_id = 1"
	readBase := "base=$(run -h-1 -W -Q " + mssqlSQL(base) + " | tr -d '[:space:]') || exit 1\n"
	with, format, ext := "COPY_ONLY, CHECKSUM", MSSQLBak, "bak.gz"
	switch {
	case t.Incremental:
		// Any other full backup since moves the base: a differential taken now
		// wouldn't fit the file the chain starts with.
		b.WriteString(readBase)
		fmt.Fprintf(&b, "[ \"$base\" = %s ] || { echo %s >&2; exit 3; }\n", quote(t.Position), BrokenMark)
		with, format, ext = "DIFFERENTIAL, CHECKSUM", MSSQLDiff, "diff.bak.gz"
	case t.Chain:
		// Unlike COPY_ONLY, this one starts a new base.
		with = "CHECKSUM"
	}
	sql := "BACKUP DATABASE " + mssqlName(t.Name) + " TO DISK=" + mssqlText(file) + " WITH " + with
	b.WriteString("run -Q " + mssqlSQL(sql) + " >&2 || exit 1\n")
	if t.Chain && !t.Incremental {
		b.WriteString(readBase)
	}
	b.WriteString("cat \"$f\" || exit 1\n")
	if t.Chain || t.Incremental {
		b.WriteString("echo " + PositionMark + "\"$base\" >&2\n")
	}
	return Spec{Script: b.String(), Ext: ext, Format: format, Gzip: true}, nil
}

// Restore explains how to bring a backup back by hand: for what the panel
// can't do, or when it has to happen somewhere Morcheh doesn't reach.
func Restore(format, target, file string) string {
	q := quote(file)
	name := target
	if name == "" {
		name = "<database>"
	}
	switch format {
	case PgCustom:
		return "# Into an empty database (add --clean --if-exists to replace one):\npg_restore --no-owner -d " + quote(name) + " " + q
	case PgAll:
		return "# Recreates every database and role:\ngunzip -c " + q + " | psql -d postgres"
	case MySQLSQL:
		return "# The file recreates its databases:\ngunzip -c " + q + " | mysql -u root -p"
	case MySQLDB:
		return "# Into an existing database:\ngunzip -c " + q + " | mysql -u root -p " + quote(name)
	case MySQLBinlog:
		return "# After the full backup and the incrementals before this one, in order:\ngunzip -c " + q + " | mysql -u root -p"
	case MongoArchive:
		return "# Add --drop to replace what's there:\nmongorestore --gzip --archive=" + q
	case RedisRDB:
		return "# Stop Redis, then put the snapshot in its data folder:\ngunzip -c " + q + " > /var/lib/redis/dump.rdb\n# Turn appendonly off for this start, or Redis ignores the file. Start Redis."
	case MSSQLBak:
		return "# Unpack it where SQL Server can read it, then:\ngunzip " + q + "\nsqlcmd -C -Q \"RESTORE DATABASE " + mssqlName(name) + " FROM DISK=N'/var/opt/mssql/data/" + strings.TrimSuffix(file, ".gz") + "' WITH REPLACE\""
	case MSSQLDiff:
		return "# Restore its full backup WITH NORECOVERY first, then:\ngunzip " + q + "\nsqlcmd -C -Q \"RESTORE DATABASE " + mssqlName(name) + " FROM DISK=N'/var/opt/mssql/data/" + strings.TrimSuffix(file, ".gz") + "' WITH RECOVERY\""
	}
	return ""
}
