package dbbackup

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/morcheh/backend/internal/dbmon"
)

// A restore script reads the backup on stdin, plain (Morcheh undoes its own
// gzip), so it needs nothing on the server beyond the database's client tools.
// It must keep its other commands off stdin.

// Why restores lock out: a table in use shouldn't hang a restore forever.
const restoreLockMillis = 60_000

// Restorable says why a file can't be restored from the panel; empty = it can.
func Restorable(format, target string) string {
	switch format {
	case PgCustom, MySQLDB, MySQLBinlog, MSSQLBak, MSSQLDiff:
		return ""
	case MongoArchive, MySQLSQL:
		if target != "" {
			return ""
		}
		return "This file holds every database at once, so it has to be restored by hand."
	case PgAll:
		return "This file holds every database and role at once, so it has to be restored by hand."
	case RedisRDB:
		return "Redis has to be stopped and its data file replaced, so this is done on the server."
	}
	return "Morcheh doesn't know how to restore this file."
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
	case PgCustom:
		return pgRestore(t, o), nil
	case MySQLDB, MySQLSQL, MySQLBinlog:
		return mysqlRestore(t, o), nil
	case MongoArchive:
		return mongoRestore(t, o), nil
	case MSSQLBak, MSSQLDiff:
		return mssqlRestore(t, o)
	}
	return "", fmt.Errorf("can't restore %s", o.Format)
}

// connInfo is one value of a libpq connection string.
func connInfo(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return "'" + strings.ReplaceAll(s, "'", `\'`) + "'"
}

func pgRestore(t Target, o RestoreOptions) string {
	var b strings.Builder
	b.WriteString("umask 077\n")
	sslmode := pgSSLMode(t)
	if verifiesCA(t) {
		caFile(&b, t.CACert)
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
	b.WriteString("command -v pg_restore >/dev/null 2>&1 || { " + missing("pg_restore") + "; }\n")
	ident := `"` + strings.ReplaceAll(t.Name, `"`, `""`) + `"`
	maintenance := t.AuthDatabase
	if maintenance == "" {
		maintenance = "postgres"
	}
	admin := func(sql string) string {
		return "psql -X -q -v ON_ERROR_STOP=1 --no-password -d " + quote("dbname="+connInfo(maintenance)) + " -c " + quote(sql) + " </dev/null"
	}
	args := "pg_restore --no-owner --no-privileges --single-transaction --exit-on-error --no-password -d " + quote("dbname="+connInfo(t.Name))
	if o.Replace {
		b.WriteString(args + " --clean --if-exists\n")
		return b.String()
	}
	b.WriteString("command -v psql >/dev/null 2>&1 || { " + missing("psql") + "; }\n")
	b.WriteString(admin("CREATE DATABASE "+ident) + " || exit 1\n")
	// A failed restore into a new database leaves nothing behind.
	b.WriteString(args + " || { code=$?; " + admin("DROP DATABASE "+ident) + " >&2; exit $code; }\n")
	return b.String()
}

func mysqlRestore(t Target, o RestoreOptions) string {
	var b strings.Builder
	mysqlPrelude(&b, t)
	mysqlTool(&b, t, "client", "mariadb", "mysql")
	login := mysqlLogin(t)
	ident := "`" + strings.ReplaceAll(t.Name, "`", "``") + "`"
	if o.Format == MySQLBinlog || o.Format == MySQLSQL {
		// These files say which database they're for.
		b.WriteString("client " + login + " --binary-mode\n")
		return b.String()
	}
	load := "client " + login + " --binary-mode -D " + quote(t.Name)
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
	args := append([]string{"mongorestore", "--quiet", "--archive", "--gzip", "--stopOnError"}, mongoAccess(&b, t)...)
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
		return "", errors.New("SQL Server reads a backup from its own disk, so Morcheh has to reach the machine or container it runs on.")
	}
	if !idPattern.MatchString(t.ID) {
		return "", errors.New("a restore needs an id")
	}
	var b strings.Builder
	mssqlPrelude(&b, t)
	file := mssqlDataDir + "/morcheh-" + t.ID + ".bak"
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
  printf ", MOVE N\047%%s\047 TO N\047%%s/morcheh-%%s-%%d%%s\047", $1, dir, id, n, ext
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
