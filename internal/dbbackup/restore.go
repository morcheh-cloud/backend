package dbbackup

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/morche/backend/internal/dbmon"
)

// A restore script reads the backup on stdin, plain (Morche undoes its own
// compression), so it needs nothing on the server beyond the database's client tools.
// It must keep its other commands off stdin.

// Why restores lock out: a table in use shouldn't hang a restore forever.
const restoreLockMillis = 60_000

// Restorable says why a file can't be restored from the panel; empty = it can.
func Restorable(format, target string) string {
	switch format {
	case PgCustom, PgDir, PgSQL, MySQLDB, MySQLBinlog, MSSQLBak, MSSQLDiff:
		return ""
	case MongoArchive, MySQLSQL, ClickHouseTar:
		if target != "" {
			return ""
		}
		return "This file holds every database at once, so it has to be restored by hand."
	case PgAll:
		return "This file holds every database and role at once, so it has to be restored by hand."
	case RedisRDB:
		return "Redis has to be stopped and its data file replaced, so this is done on the server."
	}
	return "Morche doesn't know how to restore this file."
}

// RestoreInto says why a backup of source can't go into a database called dest.
func RestoreInto(format, source, dest string, chained bool) string {
	if source == dest {
		return ""
	}
	switch {
	case format == MySQLSQL:
		return "This file names its database, so it can only go back to " + source + "."
	case chained && (format == MySQLDB || format == MySQLBinlog):
		return "The binary log names its database, so an incremental can only go back to " + source + "."
	}
	return ""
}

// RestoreOptions is one file of a restore.
type RestoreOptions struct {
	Format string
	// The database the file was taken from.
	Source string
	// The target exists, and what the file holds overwrites it.
	Replace bool
	// The chain's first and last files. A single file is both.
	First, Last bool
	// A Mongo archive whose collections aren't compressed (mongodump
	// without --gzip; Morche's own always are).
	MongoPlain bool
	// A MySQL file that names its database goes into a new one: make it
	// first (a file from elsewhere may not), drop it if the load fails.
	CreateNamed bool
	// Parallel jobs for a pg_dir file; 0 or 1 = one, in a single transaction.
	Workers int
	// Where a pg_dir file is unpacked first (a ClickHouse dump, when the
	// runner's tar can't stream it into the database); empty = the system's temporary
	// folder.
	TempDir string
}

// BuildRestore writes the script that loads one file into t.Name.
func BuildRestore(t Target, o RestoreOptions) (string, error) {
	if t.Name == "" {
		return "", errors.New("Name the database to restore into.")
	}
	if err := CheckName(t.Name); err != nil {
		return "", err
	}
	if t.Port == 0 {
		t.Port = dbmon.DefaultPort(t.Engine)
	}
	if t.Host == "" {
		t.Host = "127.0.0.1"
	}
	if why := Restorable(o.Format, o.Source); why != "" {
		return "", errors.New(why)
	}
	switch o.Format {
	case PgCustom, PgDir:
		return pgRestore(t, o), nil
	case PgSQL:
		return pgSQLRestore(t, o)
	case MySQLDB, MySQLSQL, MySQLBinlog:
		return mysqlRestore(t, o), nil
	case MongoArchive:
		return mongoRestore(t, o), nil
	case MSSQLBak, MSSQLDiff:
		return mssqlRestore(t, o)
	case ClickHouseTar:
		return clickhouseRestore(t, o), nil
	}
	return "", fmt.Errorf("can't restore %s", o.Format)
}

// connInfo is one value of a libpq connection string.
func connInfo(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return "'" + strings.ReplaceAll(s, "'", `\'`) + "'"
}

// pgPrelude writes the connection environment of a restore and returns a
// command that runs sql in the maintenance database.
func pgPrelude(b *strings.Builder, t Target) func(sql string) string {
	b.WriteString("umask 077\n")
	sslmode := pgSSLMode(t)
	if verifiesCA(t) {
		caFile(b, t.CACert)
		b.WriteString("export PGSSLROOTCERT=\"$ca\"\n")
	}
	env := []string{
		"PGHOST=" + quote(t.Host), "PGPORT=" + strconv.Itoa(t.Port), "PGUSER=" + quote(t.Username),
		"PGSSLMODE=" + sslmode, "PGCONNECT_TIMEOUT=20",
		"PGOPTIONS=" + quote(fmt.Sprintf("-c lock_timeout=%d", restoreLockMillis)),
	}
	if t.Password != "" {
		env = append(env, "PGPASSWORD="+quote(t.Password))
	}
	b.WriteString("export " + strings.Join(env, " ") + "\n")
	maintenance := t.AuthDatabase
	if maintenance == "" {
		maintenance = "postgres"
	}
	return func(sql string) string {
		return "psql -X -q -v ON_ERROR_STOP=1 --no-password -d " + quote("dbname="+connInfo(maintenance)) + " -c " + quote(sql) + " </dev/null"
	}
}

func pgIdent(name string) string { return `"` + strings.ReplaceAll(name, `"`, `""`) + `"` }

func pgRestore(t Target, o RestoreOptions) string {
	var b strings.Builder
	admin := pgPrelude(&b, t)
	b.WriteString("command -v pg_restore >/dev/null 2>&1 || { " + missing("pg_restore") + "; }\n")
	ident := pgIdent(t.Name)
	args := "pg_restore --no-owner --no-privileges --exit-on-error --no-password -d " + quote("dbname="+connInfo(t.Name))
	workers := max(1, min(o.Workers, MaxWorkers))
	if o.Format == PgDir {
		// The tar comes on stdin; pg_restore reads the folder it unpacks to.
		b.WriteString("command -v tar >/dev/null 2>&1 || { " + missing("tar") + "; }\n")
		tempFolder(&b, o.TempDir, "restore")
		b.WriteString(`tar -xf - -C "$dir" || {
  code=$?
  free=$(df -Pk "$dir" 2>/dev/null | awk 'NR == 2 {print $4}')
  [ "${free:-1048576}" -ge 65536 ] || echo "The temporary folder $(dirname "$dir") ran out of space: a parallel backup is unpacked there first. Pick a temporary folder on a bigger disk." >&2
  exit $code
}
`)
	}
	if workers > 1 && o.Format == PgDir {
		// Parallel jobs can't share one transaction.
		args += " -j " + strconv.Itoa(workers)
	} else {
		args += " --single-transaction"
	}
	if o.Format == PgDir {
		args += ` "$dir"`
	}
	// A custom archive is read from stdin; the folder's already unpacked.
	stdin := ""
	if o.Format == PgDir {
		stdin = " </dev/null"
	}
	if o.Replace {
		b.WriteString(args + " --clean --if-exists" + stdin + "\n")
		return b.String()
	}
	b.WriteString("command -v psql >/dev/null 2>&1 || { " + missing("psql") + "; }\n")
	b.WriteString(admin("CREATE DATABASE "+ident) + " || exit 1\n")
	// A failed restore into a new database leaves nothing behind.
	b.WriteString(args + stdin + " || { code=$?; " + admin("DROP DATABASE "+ident) + " >&2; exit $code; }\n")
	return b.String()
}

func mysqlRestore(t Target, o RestoreOptions) string {
	var b strings.Builder
	mysqlPrelude(&b, t)
	mysqlTool(&b, t, "client", "mariadb", "mysql")
	// A file is only data: --binary-mode already turns off the client's own
	// commands (\! system, source…) for piped input; sandbox mode, where the
	// client has it, refuses them outright (MariaDB 10.5.25+, MySQL 8.0.40+).
	b.WriteString(`case "$("$client_tool" --help 2>/dev/null)" in
  *--sandbox*) safe=--sandbox ;;
  *--system-command*) safe=--system-command=OFF ;;
  *) safe= ;;
esac
`)
	login := mysqlLogin(t)
	ident := "`" + strings.ReplaceAll(t.Name, "`", "``") + "`"
	if o.Format == MySQLBinlog || o.Format == MySQLSQL {
		// These files say which database they're for.
		load := "client $safe " + login + " --binary-mode"
		if o.CreateNamed && !o.Replace {
			b.WriteString("client " + login + " -e " + quote("CREATE DATABASE "+ident) + " </dev/null || exit 1\n")
			load += " || { s=$?; client " + login + " -e " + quote("DROP DATABASE IF EXISTS "+ident) + " </dev/null; exit $s; }"
		}
		b.WriteString(load + "\n")
		return b.String()
	}
	load := "client $safe " + login + " --binary-mode -D " + quote(t.Name)
	switch {
	case o.First && o.Replace:
		// The database becomes what the file holds: tables the file doesn't
		// have go too.
		b.WriteString("client " + login + " -e " + quote("DROP DATABASE IF EXISTS "+ident+"; CREATE DATABASE "+ident) + " </dev/null || exit 1\n")
	case o.First:
		// A new database that didn't load leaves nothing behind.
		b.WriteString("client " + login + " -e " + quote("CREATE DATABASE "+ident) + " </dev/null || exit 1\n")
		load += " || { s=$?; client " + login + " -e " + quote("DROP DATABASE IF EXISTS "+ident) + " </dev/null; exit $s; }"
	}
	b.WriteString(load + "\n")
	return b.String()
}

func mongoRestore(t Target, o RestoreOptions) string {
	var b strings.Builder
	b.WriteString("umask 077\ncommand -v mongorestore >/dev/null 2>&1 || { " + missing("mongorestore") + "; }\n")
	args := []string{"mongorestore", "--quiet", "--archive", "--gzip", "--stopOnError"}
	if o.MongoPlain {
		args = slices.Delete(args, 3, 4)
	}
	args = append(args, mongoAccess(&b, t)...)
	if o.Replace {
		args = append(args, "--drop")
	}
	args = append(args, "--nsInclude="+quote(o.Source+".*"))
	if o.Source != t.Name {
		args = append(args, "--nsFrom="+quote(o.Source+".*"), "--nsTo="+quote(t.Name+".*"))
	}
	b.WriteString(strings.Join(args, " ") + "\n")
	return b.String()
}

func mssqlRestore(t Target, o RestoreOptions) (string, error) {
	if !t.Local {
		return "", errors.New("SQL Server reads a backup from its own disk, so Morche has to reach the machine or container it runs on.")
	}
	if !idPattern.MatchString(t.ID) {
		return "", errors.New("a restore needs an id")
	}
	var b strings.Builder
	mssqlPrelude(&b, t)
	file := mssqlDataDir + "/morche-" + t.ID + ".bak"
	b.WriteString("f=" + quote(file) + "\ntrap 'rm -f \"$f\"' EXIT\n")
	// The file has to be readable by SQL Server's own user; root wrote it here.
	b.WriteString("cat > \"$f\" || exit 1\nchown mssql \"$f\" 2>/dev/null || chmod 644 \"$f\"\n")
	name, text := mssqlName(t.Name), mssqlText(t.Name)
	source := "FROM DISK=" + mssqlText(file)
	recovery := "NORECOVERY"
	if o.Last {
		recovery = "RECOVERY"
	}
	if !o.First {
		// Only the differential is left to load. Failing here leaves the database
		// waiting for it, so it's brought up as the full backup left it.
		sql := "RESTORE DATABASE " + name + " " + source + " WITH CHECKSUM, " + recovery
		b.WriteString("run -Q " + mssqlSQL(sql) + " >&2 || { code=$?; run -Q " + mssqlSQL("RESTORE DATABASE "+name+" WITH RECOVERY") + " >&2; exit $code; }\n")
		return b.String(), nil
	}
	if !o.Replace {
		check := "IF DB_ID(" + text + ") IS NOT NULL RAISERROR('A database with that name exists already.', 16, 1)"
		b.WriteString("run -Q " + mssqlSQL(check) + " >&2 || exit 1\n")
	}
	if o.Source != t.Name {
		// Another name needs files of its own, or they'd clash with the original's.
		list := "SET NOCOUNT ON; RESTORE FILELISTONLY " + source
		fmt.Fprintf(&b, `move=$(run -h-1 -W -s '|' -Q %s | awk -F'|' -v dir=%s -v id=%s 'NF > 2 && $1 != "" {
  n++; ext = ($3 == "L") ? ".ldf" : ".mdf"; gsub(/\047/, "\047\047", $1)
  printf ", MOVE N\047%%s\047 TO N\047%%s/morche-%%s-%%d%%s\047", $1, dir, id, n, ext
}') || exit 1
[ -n "$move" ] || { echo 'The backup lists no files.' >&2; exit 1; }
`, mssqlSQL(list), quote(mssqlDataDir), quote(t.ID))
	} else {
		b.WriteString("move=\n")
	}
	if o.Replace {
		sql := "IF DB_ID(" + text + ") IS NOT NULL ALTER DATABASE " + name + " SET SINGLE_USER WITH ROLLBACK IMMEDIATE"
		b.WriteString("run -Q " + mssqlSQL(sql) + " >&2 || exit 1\n")
	}
	head := "RESTORE DATABASE " + name + " " + source + " WITH REPLACE, CHECKSUM, " + recovery
	fmt.Fprintf(&b, "run -Q %s\"$move\" >&2", mssqlSQL(head))
	if o.Replace {
		b.WriteString(" || { code=$?; run -Q " + mssqlSQL("IF DB_ID("+text+") IS NOT NULL ALTER DATABASE "+name+" SET MULTI_USER") + " >&2; exit $code; }\n")
	} else {
		b.WriteString(" || exit 1\n")
	}
	return b.String(), nil
}

// PgSQLCheck is what pgSQLRestore's psql prints when it can't run the file
// safely (no restricted mode before 17.6 / 16.10 / 15.14 / 14.19 / 13.22).
const PgSQLCheck = "psql on the machine that runs the restore is too old to load a plain SQL file safely: it needs PostgreSQL 17.6, 16.10, 15.14, 14.19 or 13.22 or later."

// pgSQLRestore loads a plain pg_dump file (read through PlainSQL) with psql,
// in one transaction. It goes into a new database first; replacing swaps it
// in by name only once it has loaded, so a failure leaves the old one as is.
func pgSQLRestore(t Target, o RestoreOptions) (string, error) {
	if !idPattern.MatchString(t.ID) || len(strings.ReplaceAll(t.ID, "-", "")) < 8 {
		return "", errors.New("a restore needs an id")
	}
	var b strings.Builder
	admin := pgPrelude(&b, t)
	b.WriteString("command -v psql >/dev/null 2>&1 || { " + missing("psql") + "; }\n")
	// The file is read in restricted mode (no \! and the like): psql has to
	// know it, or it would ignore the line and run whatever the file says.
	b.WriteString(`out=$(printf '\\restrict morche\n\\unrestrict morche\n' | psql -X -q -v ON_ERROR_STOP=1 --no-password -d ` +
		quote("dbname="+connInfo(cmp.Or(t.AuthDatabase, "postgres"))) + ` -f - 2>&1) || {
  case "$out" in
    *"invalid command"*) echo ` + quote(PgSQLCheck) + ` >&2 ;;
    *) printf '%s\n' "$out" >&2 ;;
  esac
  exit 1
}
`)
	short := strings.ReplaceAll(t.ID, "-", "")[:8]
	into := t.Name
	if o.Replace {
		into = "morche_restore_" + short
	}
	load := "psql -X -q -v ON_ERROR_STOP=1 --single-transaction --no-password -d " + quote("dbname="+connInfo(into)) + " -f -"
	b.WriteString(admin("CREATE DATABASE "+pgIdent(into)) + " || exit 1\n")
	b.WriteString(load + " || { s=$?; " + admin("DROP DATABASE IF EXISTS "+pgIdent(into)) + " >&2; exit $s; }\n")
	if !o.Replace {
		return b.String(), nil
	}
	old := "morche_old_" + short
	literal := "'" + strings.ReplaceAll(t.Name, "'", "''") + "'"
	kick := admin("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = " + literal + " AND pid <> pg_backend_pid()")
	// Sessions in the old one are ended; one that comes straight back can
	// keep the rename from going through, so it's tried a few times.
	b.WriteString(`n=0
until { ` + kick + ` >/dev/null; ` + admin("ALTER DATABASE "+pgIdent(t.Name)+" RENAME TO "+pgIdent(old)) + `; }; do
  n=$((n+1))
  if [ "$n" -ge 5 ]; then
    echo "The database is still in use, so it couldn't be swapped for the restored copy." >&2
    ` + admin("DROP DATABASE IF EXISTS "+pgIdent(into)) + ` >&2
    exit 1
  fi
  sleep 2
done
`)
	b.WriteString(admin("ALTER DATABASE "+pgIdent(into)+" RENAME TO "+pgIdent(t.Name)) + ` || {
  ` + admin("ALTER DATABASE "+pgIdent(old)+" RENAME TO "+pgIdent(t.Name)) + ` >&2
  ` + admin("DROP DATABASE IF EXISTS "+pgIdent(into)) + ` >&2
  exit 1
}
`)
	b.WriteString(admin("DROP DATABASE "+pgIdent(old)+" WITH (FORCE)") + " 2>/dev/null || " + admin("DROP DATABASE "+pgIdent(old)) +
		" || echo " + quote("The old copy was kept as "+old+": drop it once nobody uses it.") + " >&2\n")
	return b.String(), nil
}
