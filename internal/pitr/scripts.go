package pitr

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Every script runs as root and talks to PostgreSQL as the postgres user
// over its local socket (peer login), so no password is involved.

// prelude checks there's a PostgreSQL on this machine on port, and defines:
// asPG (run as postgres), $sock (its socket folder) and sql (one query, one
// value per line).
func prelude(b *strings.Builder, port int) {
	fmt.Fprintf(b, `set -u
port=%d
id postgres >/dev/null 2>&1 || { echo "There's no postgres user on this server. Continuous backup needs PostgreSQL installed on the server itself (not in a container)." >&2; exit 1; }
asPG() {
  if command -v runuser >/dev/null 2>&1; then runuser -u postgres -- "$@"; else sudo -n -u postgres -- "$@"; fi
}
sock=""
for h in /var/run/postgresql /run/postgresql /tmp; do
  [ -S "$h/.s.PGSQL.$port" ] && { sock=$h; break; }
done
[ -n "$sock" ] || { echo "No PostgreSQL listens on port $port on this server (no socket in /var/run/postgresql or /tmp)." >&2; exit 1; }
sql() { asPG psql -X -At -v ON_ERROR_STOP=1 -h "$sock" -p "$port" -d postgres -c "$1"; }
`, port)
}

// storedPrelude is prelude for restores: PostgreSQL may be down (that's
// often why it's being restored), so the socket folder comes from what
// detection stored and $up says whether it answers now.
func storedPrelude(b *strings.Builder, c PitrCluster) {
	fmt.Fprintf(b, `set -u
port=%d
sock=%s
id postgres >/dev/null 2>&1 || { echo "There's no postgres user on this server." >&2; exit 1; }
asPG() {
  if command -v runuser >/dev/null 2>&1; then runuser -u postgres -- "$@"; else sudo -n -u postgres -- "$@"; fi
}
sql() { asPG psql -X -At -v ON_ERROR_STOP=1 -h "$sock" -p "$port" -d postgres -c "$1"; }
up=""
[ -S "$sock/.s.PGSQL.$port" ] && sql 'select 1' >/dev/null 2>&1 && up=1
`, c.Port, q(cmpOr(c.Socket, "/var/run/postgresql")))
}

// clusterVars sets the shell variables the restart, restore and teardown
// scripts use, from what Detect found.
func clusterVars(b *strings.Builder, c PitrCluster) {
	fmt.Fprintf(b, "data=%s\nbindir=%s\nunit=%s\npgc=%s\nconf=%s\nhba=%s\nident=%s\n",
		q(c.DataDir), q(c.BinDir), q(c.Service), q(c.PgCluster), q(c.ConfigFile), q(c.HbaFile), q(c.IdentFile))
	// pgctl stop|start|restart, by whatever runs this PostgreSQL: its
	// systemd unit, Debian's pg_ctlcluster, or pg_ctl itself.
	b.WriteString(`pgctl() {
  if [ -n "$unit" ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl "$1" "$unit"
  elif [ -n "$pgc" ] && command -v pg_ctlcluster >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    if [ "$1" = start ]; then pg_ctlcluster $pgc start; else pg_ctlcluster $pgc "$1" -m fast; fi
  elif [ "$1" = start ]; then
    asPG "$bindir/pg_ctl" -D "$data" -w -t 600 -l "$data/morche-start.log" start
  else
    asPG "$bindir/pg_ctl" -D "$data" -w -t 600 -m fast "$1"
  fi
}
# stopped: PostgreSQL's postmaster for $data is gone.
stopped() {
  [ -f "$data/postmaster.pid" ] || return 0
  pid=$(head -n 1 "$data/postmaster.pid" 2>/dev/null)
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && return 1
  return 0
}
# stopIt: stop it however it runs; already stopped is fine.
stopIt() {
  pgctl stop >&2 || true
  i=0
  until stopped; do
    i=$((i + 1)); [ $i -lt 120 ] || { echo "PostgreSQL didn't stop." >&2; return 1; }
    sleep 1
  done
}
# waitUp port: until it takes connections and has left recovery.
waitUp() {
  i=0
  until asPG psql -X -At -h "$sock" -p "$1" -d postgres -c 'select 1' >/dev/null 2>&1; do
    i=$((i + 1)); [ $i -lt 600 ] || { echo "PostgreSQL didn't come back within 10 minutes." >&2; return 1; }
    sleep 1
  done
  while :; do
    r=$(asPG psql -X -At -h "$sock" -p "$1" -d postgres -c 'select pg_is_in_recovery()' 2>/dev/null) || { echo "PostgreSQL stopped while replaying the WAL." >&2; return 1; }
    [ "$r" = t ] || return 0
    sleep 5
  done
}
`)
}

// DetectScript reads what Morche needs to know about the PostgreSQL on port.
func DetectScript(port int) string {
	var b strings.Builder
	prelude(&b, port)
	b.WriteString(`m() { printf 'MORCHE_%s=%s\n' "$1" "$2"; }
m version "$(sql 'show server_version_num')"
data=$(sql 'show data_directory'); m data_directory "$data"
m config_file "$(sql 'show config_file')"
m hba_file "$(sql 'show hba_file')"
m ident_file "$(sql 'show ident_file')"
m archive_mode "$(sql 'show archive_mode')"
m archive_command "$(sql 'show archive_command')"
m archive_timeout "$(sql "select setting from pg_settings where name = 'archive_timeout'")"
m wal_level "$(sql 'show wal_level')"
m size "$(sql 'select sum(pg_database_size(datname))::bigint from pg_database')"
m in_recovery "$(sql 'select pg_is_in_recovery()')"
m socket "$sock"
pid=$(head -n 1 "$data/postmaster.pid" 2>/dev/null)
m pid "$pid"
# Its programs' folder: from the running process (exe needs ptrace rights,
# cmdline doesn't), else where the packages put them.
exe=""
if [ -n "$pid" ]; then
  exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
  [ -n "$exe" ] || exe=$(tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | head -n 1)
fi
case "$exe" in /*) bindir=$(dirname "$exe") ;; *) bindir="" ;; esac
if [ -z "$bindir" ] || [ ! -x "$bindir/pg_ctl" ]; then
  major=$(( $(sql 'show server_version_num') / 10000 ))
  for d in "/usr/lib/postgresql/$major/bin" "/usr/pgsql-$major/bin" /usr/local/pgsql/bin "$(dirname "$(command -v pg_ctl 2>/dev/null || echo /x/x)")"; do
    [ -x "$d/pg_ctl" ] && { bindir=$d; break; }
  done
fi
m bindir "$bindir"
if [ -n "$pid" ] && [ -d /run/systemd/system ]; then
  m service "$(sed -n 's#.*/\([^/]*\.service\).*#\1#p' "/proc/$pid/cgroup" 2>/dev/null | tail -n 1)"
fi
if command -v pg_lsclusters >/dev/null 2>&1; then
  m pg_cluster "$(pg_lsclusters --no-header 2>/dev/null | awk -v p="$port" '$3 == p {print $1 " " $2; exit}')"
fi
m free "$(df -Pk "$(dirname "$data")" 2>/dev/null | awk 'NR == 2 {print $4 * 1024}')"
if command -v pgbackrest >/dev/null 2>&1; then m pgbackrest "$(pgbackrest version 2>/dev/null | awk '{print $2}')"; fi
for p in apt-get dnf yum zypper; do command -v $p >/dev/null 2>&1 && { m package "$p"; break; }; done
`)
	return b.String()
}

// Cluster is what DetectScript found.
type PitrCluster struct {
	Version        int    `json:"version"` // major
	DataDir        string `json:"data_dir"`
	ConfigFile     string `json:"config_file"`
	HbaFile        string `json:"hba_file"`
	IdentFile      string `json:"ident_file"`
	Port           int    `json:"port"`
	Socket         string `json:"socket"`
	BinDir         string `json:"bin_dir"`
	ArchiveMode    string `json:"archive_mode"`
	ArchiveCommand string `json:"archive_command"`
	ArchiveTimeout int    `json:"archive_timeout"`
	WalLevel       string `json:"wal_level"`
	InRecovery     bool   `json:"in_recovery"`
	SizeBytes      int64  `json:"size_bytes"`
	FreeBytes      int64  `json:"free_bytes"`
	// pgBackRest's version when installed.
	PgBackRest string `json:"pgbackrest"`
	// apt-get, dnf, yum or zypper.
	Package string `json:"package"`
	// The systemd unit PostgreSQL runs under, or Debian's "17 main".
	Service   string `json:"service"`
	PgCluster string `json:"pg_cluster"`
}

// ParseDetect reads DetectScript's output.
func ParseDetect(out string, port int) (PitrCluster, error) {
	c := PitrCluster{Port: port}
	v := marks(out)
	num, _ := strconv.Atoi(v["version"])
	c.Version = num / 10000
	c.DataDir, c.ConfigFile, c.HbaFile, c.IdentFile = v["data_directory"], v["config_file"], v["hba_file"], v["ident_file"]
	c.Socket, c.BinDir, c.ArchiveMode, c.ArchiveCommand, c.WalLevel = v["socket"], v["bindir"], v["archive_mode"], v["archive_command"], v["wal_level"]
	c.ArchiveTimeout, _ = strconv.Atoi(v["archive_timeout"])
	c.InRecovery = v["in_recovery"] == "t"
	c.SizeBytes, _ = strconv.ParseInt(v["size"], 10, 64)
	c.FreeBytes, _ = strconv.ParseInt(v["free"], 10, 64)
	c.PgBackRest, c.Package, c.Service, c.PgCluster = v["pgbackrest"], v["package"], v["service"], v["pg_cluster"]
	switch {
	case c.Version == 0 || c.DataDir == "":
		return c, fmt.Errorf("Couldn't read PostgreSQL's settings on the server.")
	case c.Version < 12:
		return c, fmt.Errorf("PostgreSQL %d is too old: continuous backup needs 12 or newer.", c.Version)
	case !strings.HasPrefix(c.BinDir, "/"):
		return c, fmt.Errorf("Couldn't find PostgreSQL's programs (pg_ctl) on the server.")
	}
	return c, nil
}

// Ours says archive_command is Morche's, empty, or what RemoveScript left.
func (c PitrCluster) Ours() bool {
	switch c.ArchiveCommand {
	case "", "(disabled)", ArchiveCommand, removedCommand:
		return true
	}
	return false
}

// removedCommand is the no-op RemoveScript leaves in archive_command.
const removedCommand = "/bin/true"

// NeedsRestart says archive settings only take effect after a restart.
func (c PitrCluster) NeedsRestart() bool {
	return c.ArchiveMode == "off" || c.WalLevel == "minimal"
}

// SetupScript installs pgBackRest when missing, writes Morche's config,
// creates the stanza and points archive_command at it. It prints
// MORCHE_RESTART=1 when archive_mode or wal_level still need a restart,
// MORCHE_READY=1 when pgbackrest check passed. Run again, it rewrites the
// config (new storage or settings) and leaves the rest as it is.
func SetupScript(c PitrCluster, s Settings, replace bool) string {
	var b strings.Builder
	prelude(&b, c.Port)
	if !replace && !c.Ours() {
		fmt.Fprintf(&b, "echo %s >&2; exit 1\n",
			q("archive_command is already set to something else ("+c.ArchiveCommand+"). Morche won't replace it unless you ask it to."))
	}
	b.WriteString(`if ! command -v pgbackrest >/dev/null 2>&1; then
  echo "Installing pgBackRest" >&2
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q pgbackrest >&2 || { apt-get update -q >&2 && DEBIAN_FRONTEND=noninteractive apt-get install -y -q pgbackrest >&2; }
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q pgbackrest >&2
  elif command -v yum >/dev/null 2>&1; then yum install -y -q pgbackrest >&2
  elif command -v zypper >/dev/null 2>&1; then zypper -n -q install pgbackrest >&2
  fi
  command -v pgbackrest >/dev/null 2>&1 || { echo "pgBackRest couldn't be installed. Install it by hand (PostgreSQL's own package repository has it) and try again." >&2; exit 1; }
fi
ver=$(pgbackrest version | awk '{print $2}')
echo "MORCHE_pgbackrest=$ver"
newer() { [ "$(printf '%s\n%s\n' "$1" "$ver" | sort -V | head -n 1)" = "$1" ]; }
install -d -m 755 /etc/pgbackrest
install -d -o postgres -g postgres -m 750 /var/log/pgbackrest /var/spool/pgbackrest
umask 027
cat > /etc/pgbackrest/morche.conf.new <<'MORCHE_CONF_EOF'
`)
	b.WriteString(s.Config(c))
	b.WriteString("MORCHE_CONF_EOF\n")
	// Block incremental came in 2.46, SFTP repositories in 2.46 too.
	b.WriteString(`newer 2.46 || sed -i '/^repo1-block=/d' /etc/pgbackrest/morche.conf.new
`)
	if s.Repo.Type == "sftp" {
		port := s.Repo.Port
		if port == 0 {
			port = 22
		}
		b.WriteString(`newer 2.48 || { rm -f /etc/pgbackrest/morche.conf.new; echo "pgBackRest $ver can't use SFTP this way (it needs 2.48 or newer). Update it, or use an S3 storage." >&2; exit 1; }
command -v ssh-keyscan >/dev/null 2>&1 || { rm -f /etc/pgbackrest/morche.conf.new; echo "ssh-keyscan isn't installed (openssh-client): it's needed to check the SFTP server's key." >&2; exit 1; }
`)
		fmt.Fprintf(&b, `scan=$(ssh-keyscan -T 10 -p %d -t rsa,ecdsa,ed25519 %s 2>/dev/null)
printf '%%s\n' "$scan" | awk '{print $2 " " $3}' | grep -qxF %s || { rm -f /etc/pgbackrest/morche.conf.new; echo "The SFTP server's key, as this server sees it, isn't the one Morche trusts: check the storage's address, or check the storage again in Morche if its key changed." >&2; exit 1; }
printf '%%s\n' "$scan" > %s.new && chmod 644 %s.new && mv -f %s.new %s
`, port, q(s.Repo.Host), q(s.Repo.HostKey), SFTPKnownHosts, SFTPKnownHosts, SFTPKnownHosts, SFTPKnownHosts)
		b.WriteString(`cat > ` + SFTPKeyPath + ".new <<'MORCHE_KEY_EOF'\n" + strings.TrimRight(s.Repo.PrivateKey, "\n") + "\nMORCHE_KEY_EOF\n" +
			`chown root:postgres ` + SFTPKeyPath + `.new && chmod 640 ` + SFTPKeyPath + `.new && mv -f ` + SFTPKeyPath + `.new ` + SFTPKeyPath + "\n")
	} else {
		b.WriteString("rm -f " + SFTPKeyPath + "\n")
	}
	b.WriteString(`chown root:postgres /etc/pgbackrest/morche.conf.new && chmod 640 /etc/pgbackrest/morche.conf.new
mv -f /etc/pgbackrest/morche.conf.new ` + ConfigPath + `
echo "Creating the stanza" >&2
asPG ` + pgbackrest + ` --log-level-console=warn stanza-create >&2 || exit 1
`)
	fmt.Fprintf(&b, `sql %s >/dev/null || exit 1
`, q("ALTER SYSTEM SET archive_command = "+sqlString(ArchiveCommand)))
	b.WriteString(`sql "ALTER SYSTEM SET archive_mode = 'on'" >/dev/null || exit 1
`)
	fmt.Fprintf(&b, "sql %s >/dev/null || exit 1\n", q(fmt.Sprintf("ALTER SYSTEM SET archive_timeout = %d", s.ArchiveTimeout)))
	b.WriteString(`[ "$(sql 'show wal_level')" != minimal ] || sql "ALTER SYSTEM SET wal_level = 'replica'" >/dev/null || exit 1
sql 'select pg_reload_conf()' >/dev/null
if [ "$(sql 'show archive_mode')" = off ] || [ "$(sql 'show wal_level')" = minimal ]; then
  echo MORCHE_RESTART=1
  exit 0
fi
echo "Checking that WAL reaches the storage" >&2
asPG ` + pgbackrest + ` --log-level-console=warn check >&2 || exit 1
echo MORCHE_READY=1
`)
	return b.String()
}

// RestartScript restarts PostgreSQL so archive_mode takes effect, then
// checks archiving works.
func RestartScript(c PitrCluster) string {
	var b strings.Builder
	prelude(&b, c.Port)
	clusterVars(&b, c)
	b.WriteString(`echo "Restarting PostgreSQL" >&2
pgctl restart >&2 || exit 1
waitUp "$port" || exit 1
[ "$(sql 'show archive_mode')" != off ] || { echo "PostgreSQL restarted, but archive_mode is still off: another setting overrides it (check postgresql.conf and the command line)." >&2; exit 1; }
echo "Checking that WAL reaches the storage" >&2
asPG ` + pgbackrest + ` --log-level-console=warn check >&2 || exit 1
echo MORCHE_READY=1
`)
	return b.String()
}

// CheckScript makes PostgreSQL switch WAL files and waits until that one is
// in the repository.
func CheckScript(c PitrCluster) string {
	var b strings.Builder
	prelude(&b, c.Port)
	b.WriteString("asPG " + pgbackrest + " --log-level-console=warn check >&2 || exit 1\necho MORCHE_READY=1\n")
	return b.String()
}

// Backup types.
const (
	Full = "full"
	Diff = "diff"
	Incr = "incr"
)

// BackupScript takes a backup of the given type; pgBackRest then expires
// what retention no longer keeps. Its progress lines go to stderr.
func BackupScript(c PitrCluster, kind string) string {
	var b strings.Builder
	prelude(&b, c.Port)
	fmt.Fprintf(&b, "asPG %s --type=%s --log-level-console=info backup >&2 || exit 1\n", pgbackrest, kind)
	return b.String()
}

// InfoScript prints the repository's state and PostgreSQL's archiver.
func InfoScript(c PitrCluster) string {
	var b strings.Builder
	prelude(&b, c.Port)
	// Taken whole first: in a pipe its failure would be lost (sh has no
	// pipefail), and its own message is what the page should show.
	// pgBackRest writes its errors to stdout.
	b.WriteString(`info=$(asPG ` + pgbackrest + ` --output=json info 2>&1) || { printf '%s\n' "$info" >&2; exit 1; }
printf 'MORCHE_info=%s\n' "$(printf '%s' "$info" | tr -d '\n')"
printf 'MORCHE_archiver='; sql 'select row_to_json(a) from pg_stat_archiver a'
printf 'MORCHE_now='; sql "select to_char(now() at time zone 'utc', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')"
`)
	return b.String()
}

// TargetTime is how a recovery target is written for pgBackRest
// ("YYYY-MM-DD HH:MM:SS.mmm+00", milliseconds at most); empty for a zero
// time, which means as far as the WAL goes.
func TargetTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04:05.000") + "+00"
}

// targetVar sets $t to the target time (empty = the newest point), and
// defines pgRestore OPTIONS…: pgbackrest restore to $t, or to the newest
// point when its first argument is "latest".
func targetVar(b *strings.Builder, at time.Time) {
	fmt.Fprintf(b, `t=%s
pgRestore() {
  if [ "$1" = latest ] || [ -z "$t" ]; then
    shift; asPG `+pgbackrest+` "$@" --log-level-console=info restore >&2
  else
    shift; asPG `+pgbackrest+` "$@" --type=time "--target=$t" --target-action=promote --log-level-console=info restore >&2
  fi
}
`, q(TargetTime(at)))
}

// RestoreNewScript restores into a new folder beside the data directory and
// starts it on port, on its own (archive_mode off, so it never writes to the
// repository), using the server's own config files. need is how much room
// the folder will take. It prints MORCHE_RESTORED=<folder> once the copy
// has left recovery.
func RestoreNewScript(c PitrCluster, at time.Time, stamp string, port int, need int64) string {
	var b strings.Builder
	storedPrelude(&b, c)
	clusterVars(&b, c)
	replayFunc(&b)
	targetVar(&b, at)
	fmt.Fprintf(&b, `dir="$(dirname "$data")/%s%s"
rport=%d
need=%d
free=$(df -Pk "$(dirname "$data")" | awk 'NR == 2 {print $4 * 1024}')
[ "${free:-0}" -gt "$need" ] || { echo "There isn't room for the copy next to the data folder: $((free / 1073741824)) GiB free, about $((need / 1073741824)) GiB needed." >&2; exit 1; }
ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$rport\$" && { echo "Port $rport is taken on the server. Try again." >&2; exit 1; }
[ ! -e "$dir" ] || { echo "$dir already exists." >&2; exit 1; }
if [ -n "$up" ]; then
  echo "Archiving the current WAL first" >&2
  asPG %s --log-level-console=warn check >&2 || echo "WAL couldn't be archived just now: the copy can only reach what's already in the storage." >&2
else
  echo "PostgreSQL isn't running: the copy reaches what's already in the storage." >&2
fi
opts="-c port=$rport -c listen_addresses=localhost -c external_pid_file= -c cluster_name=morche-restore -c shared_buffers=256MB%s"
# restoreTo time|latest: a fresh folder, then the replay.
restoreTo() {
  rm -rf -- "$dir"
  install -d -o postgres -g postgres -m 700 "$dir"
  echo "Restoring into $dir" >&2
  pgRestore "$1" --pg1-path="$dir" --archive-mode=off --no-delta || { rm -rf -- "$dir"; exit 1; }
  echo "Starting it on port $rport and replaying the WAL" >&2
  replay "$dir" "$rport" "$opts"
}
restoreTo time
case $? in
0) ;;
2) echo "Nothing changed between that time and the newest WAL in the storage, so the copy is restored to the newest point: it's the same data." >&2
   restoreTo latest || { rm -rf -- "$dir"; exit 1; } ;;
*) rm -rf -- "$dir"; exit 1 ;;
esac
echo "MORCHE_RESTORED=$dir"
`, RestorePrefix, stamp, port, need, pgbackrest, statsDir(c))
	return b.String()
}

// statsDir keeps a copy's statistics files apart from the server's on
// PostgreSQL 14 and older (Debian points stats_temp_directory at a shared
// folder in /var/run/postgresql).
func statsDir(c PitrCluster) string {
	if c.Version > 0 && c.Version <= 14 {
		return ` -c stats_temp_directory=$dir/pg_stat_tmp`
	}
	return ""
}

// replayFunc defines replay DIR PORT OPTIONS: start a restored data folder
// with the server's own config files and wait until it has left recovery.
// It returns 2 when the WAL holds no change after the target time (so
// PostgreSQL can't tell where to stop), 1 on any other failure.
func replayFunc(b *strings.Builder) {
	b.WriteString(`replay() {
  # shellcheck disable=SC2086
  if asPG "$bindir/pg_ctl" -D "$1" -l "$1/morche-restore.log" -w -t 86400 \
    -o "-c config_file=$conf -c data_directory=$1 -c hba_file=$hba -c ident_file=$ident -c unix_socket_directories=$sock $3" start >&2 \
    && waitUp "$2"; then
    return 0
  fi
  if grep -q "recovery ended before configured recovery target was reached" "$1/morche-restore.log" 2>/dev/null; then
    return 2
  fi
  tail -n 20 "$1/morche-restore.log" >&2
  return 1
}
`)
}

// TeardownScript stops a copy RestoreNewScript started and removes its
// folder. It refuses any folder that isn't named like one.
func TeardownScript(c PitrCluster, dir string) string {
	var b strings.Builder
	b.WriteString("set -u\n")
	clusterVars(&b, c)
	fmt.Fprintf(&b, `dir=%s
case "$(basename "$dir")" in %s*) ;; *) echo "$dir isn't a restored copy." >&2; exit 1 ;; esac
asPG() {
  if command -v runuser >/dev/null 2>&1; then runuser -u postgres -- "$@"; else sudo -n -u postgres -- "$@"; fi
}
if [ -f "$dir/postmaster.pid" ]; then
  asPG "$bindir/pg_ctl" -D "$dir" -m fast -w -t 120 stop >&2 || asPG "$bindir/pg_ctl" -D "$dir" -m immediate stop >&2 || true
fi
rm -rf -- "$dir"
echo MORCHE_GONE=1
`, q(dir), RestorePrefix)
	return b.String()
}

// ReplaceScript brings the whole cluster back to a point in time: archives
// the current WAL first (so where it is now stays reachable), stops
// PostgreSQL, restores over the data directory (only changed files),
// replays it with pg_ctl (so a failure can be read from its own log), then
// hands it back to whatever normally runs it.
func ReplaceScript(c PitrCluster, at time.Time) string {
	var b strings.Builder
	storedPrelude(&b, c)
	clusterVars(&b, c)
	replayFunc(&b)
	targetVar(&b, at)
	// Running but unable to archive: what it holds now would be lost for
	// good, so it stops there. Down: there's nothing more to archive.
	fmt.Fprintf(&b, `if [ -n "$up" ]; then
  echo "Archiving the current WAL first" >&2
  asPG %s --log-level-console=warn check >&2 || { echo "PostgreSQL runs but its current WAL couldn't be archived, so the newest changes would be lost: nothing was changed. Fix archiving first, or stop PostgreSQL to restore anyway." >&2; exit 1; }
else
  echo "PostgreSQL isn't running: restoring from what's in the storage." >&2
fi
echo "Stopping PostgreSQL" >&2
stopIt || exit 1
broken() {
  echo "The restore failed and PostgreSQL is stopped. Its data folder may be half restored: run the restore again (to the newest point if need be), or restore to a new copy." >&2
  exit 1
}
restoreOver() {
  echo "Restoring over $data" >&2
  pgRestore "$1" --delta || broken
  echo "Replaying the WAL" >&2
  replay "$data" "$port" "-c external_pid_file="
}
restoreOver time
case $? in
0) ;;
2) echo "Nothing changed between that time and the newest WAL, so it's restored to the newest point: it's the same data." >&2
   restoreOver latest || broken ;;
*) broken ;;
esac
asPG "$bindir/pg_ctl" -D "$data" -m fast -w -t 600 stop >&2 || broken
echo "Starting PostgreSQL" >&2
pgctl start >&2 || exit 1
waitUp "$port" || exit 1
echo MORCHE_READY=1
`, pgbackrest)
	return b.String()
}

// RemoveScript stops archiving into Morche's repository: archive_command
// becomes a no-op so WAL keeps being recycled, and archive_mode goes back
// to its default at the next restart. With purge, the stanza and every
// backup in the repository are deleted too. Morche's config is removed.
func RemoveScript(c PitrCluster, purge bool) string {
	var b strings.Builder
	prelude(&b, c.Port)
	b.WriteString(`sql "ALTER SYSTEM SET archive_command = '` + removedCommand + `'" >/dev/null || exit 1
sql 'ALTER SYSTEM RESET archive_mode' >/dev/null || exit 1
sql 'ALTER SYSTEM RESET archive_timeout' >/dev/null || exit 1
sql 'select pg_reload_conf()' >/dev/null
`)
	if purge {
		b.WriteString(`if [ -f ` + ConfigPath + ` ]; then
  echo "Deleting the backups from the storage" >&2
  asPG ` + pgbackrest + ` stop >&2 || true
  asPG ` + pgbackrest + ` --force stanza-delete >&2 || exit 1
fi
`)
	}
	b.WriteString("rm -f " + ConfigPath + " " + SFTPKeyPath + " " + SFTPKnownHosts + "\necho MORCHE_REMOVED=1\n")
	return b.String()
}

// marks reads a script's MORCHE_key=value lines.
func marks(out string) map[string]string {
	v := map[string]string{}
	for line := range strings.SplitSeq(out, "\n") {
		k, val, ok := strings.Cut(strings.TrimRight(line, "\r"), "=")
		if ok && strings.HasPrefix(k, mark) {
			v[strings.TrimPrefix(k, mark)] = val
		}
	}
	return v
}

// Marks is marks for the API.
func Marks(out string) map[string]string { return marks(out) }
