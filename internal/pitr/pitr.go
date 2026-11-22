// Package pitr writes the scripts behind PostgreSQL continuous backup
// (point-in-time recovery) with pgBackRest, and reads what they print. Like
// dbbackup it never runs anything itself: the API feeds each script to
// `sh -s` as root on the database's server (over SSH) and parses its output.
//
// Morche keeps to its own files: one config (ConfigPath) and one stanza
// (Stanza), so a pgBackRest someone set up by hand is left alone. Postgres
// itself runs archive-push for every WAL file, so the repository's
// credentials have to live on the server, readable by the postgres user.
package pitr

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

const (
	// Stanza is the name Morche's pgBackRest stanza goes by.
	Stanza = "morche"
	// ConfigPath is Morche's own pgBackRest config on the server.
	ConfigPath = "/etc/pgbackrest/morche.conf"
	// SFTPKeyPath holds the private key of an SFTP repository, and
	// SFTPKnownHosts its host's keys.
	SFTPKeyPath    = "/etc/pgbackrest/morche-sftp.key"
	SFTPKnownHosts = "/etc/pgbackrest/morche-known-hosts"
	// RestorePrefix starts the name of every folder a restore to a new
	// instance makes; teardown only ever removes folders named so.
	RestorePrefix = "morche-restore-"

	// Lines a script prints on stdout for Morche.
	mark = "MORCHE_"
)

// pgbackrest is the command line every script runs pgBackRest with.
var pgbackrest = "pgbackrest --config=" + ConfigPath + " --stanza=" + Stanza

// ArchiveCommand is what archive_command is set to.
var ArchiveCommand = pgbackrest + " archive-push %p"

// Repo is where the backups and the WAL go: an S3 bucket (over HTTPS:
// pgBackRest has no plain-http S3) or an SFTP server (key login only).
type Repo struct {
	Type string // "s3" or "sftp"
	// The folder inside the bucket, or on the SFTP server.
	Path string

	// S3
	Endpoint  string // host name, no scheme
	Port      int    // 0 = 443
	Bucket    string
	Region    string
	Key       string
	Secret    string
	PathStyle bool
	VerifyTLS bool

	// SFTP
	Host       string
	User       string
	PrivateKey string
	Passphrase string
	// The host key Morche trusts, as "type base64". pgBackRest's libssh2 may
	// pick another of the host's keys, so setup scans them all from the
	// database's server and keeps them only if this one is among them.
	HostKey string
}

// Settings are what a person picks for a database.
type Settings struct {
	Repo Repo
	// Full backups kept; older ones and the WAL they need are expired.
	RetentionFull int
	// zstd level, 1..19.
	CompressLevel int
	// Parallel processes for backup, restore and async archiving.
	ProcessMax int
	// Seconds after which a WAL file is archived even if it isn't full:
	// the most a quiet database can lose. 0 = only when full.
	ArchiveTimeout int
	// Repository encryption passphrase; empty = not encrypted.
	CipherPass string
}

// Check refuses settings pgBackRest would choke on, or that can't be
// written into its config safely.
func (s Settings) Check() error {
	r := s.Repo
	switch r.Type {
	case "s3":
		if r.Endpoint == "" || r.Bucket == "" {
			return errors.New("The storage needs an endpoint and a bucket.")
		}
		if r.Key == "" || r.Secret == "" {
			return errors.New("The storage needs an access key and a secret key.")
		}
	case "sftp":
		if r.Host == "" || r.User == "" {
			return errors.New("The storage needs a host and a user.")
		}
		if r.PrivateKey == "" {
			return errors.New("pgBackRest signs in to SFTP with a key only: give the storage a private key.")
		}
		if len(strings.Fields(r.HostKey)) != 2 {
			return errors.New("Morche doesn't know the SFTP server's host key yet: check the storage once to trust it.")
		}
	default:
		return fmt.Errorf("pgBackRest can't use a %s storage: use S3 (HTTPS) or SFTP.", r.Type)
	}
	if !strings.HasPrefix(r.Path, "/") {
		return errors.New("The folder must be a full path.")
	}
	for _, v := range []string{r.Path, r.Endpoint, r.Bucket, r.Region, r.Key, r.Secret, r.Host, r.User, r.Passphrase, r.HostKey, s.CipherPass} {
		if strings.ContainsFunc(v, unicode.IsControl) {
			return errors.New("A setting has a character pgBackRest's config can't hold.")
		}
	}
	if s.RetentionFull < 1 || s.CompressLevel < 1 || s.CompressLevel > 19 || s.ProcessMax < 1 || s.ProcessMax > 32 || s.ArchiveTimeout < 0 {
		return errors.New("A setting is out of range.")
	}
	return nil
}

// Config is the text of ConfigPath.
func (s Settings) Config(c PitrCluster) string {
	var b strings.Builder
	line := func(k, v string) { b.WriteString(k + "=" + v + "\n") }
	r := s.Repo
	b.WriteString("# Written by Morche. Edits are overwritten when the settings are saved.\n[global]\n")
	line("repo1-type", r.Type)
	line("repo1-path", r.Path)
	switch r.Type {
	case "s3":
		line("repo1-s3-endpoint", r.Endpoint)
		line("repo1-s3-bucket", r.Bucket)
		line("repo1-s3-region", cmpOr(r.Region, "us-east-1"))
		line("repo1-s3-key", r.Key)
		line("repo1-s3-key-secret", r.Secret)
		if r.PathStyle {
			line("repo1-s3-uri-style", "path")
		}
		if r.Port > 0 && r.Port != 443 {
			line("repo1-storage-port", strconv.Itoa(r.Port))
		}
		if !r.VerifyTLS {
			line("repo1-storage-verify-tls", "n")
		}
	case "sftp":
		line("repo1-sftp-host", r.Host)
		if r.Port > 0 && r.Port != 22 {
			line("repo1-sftp-host-port", strconv.Itoa(r.Port))
		}
		line("repo1-sftp-host-user", r.User)
		line("repo1-sftp-private-key-file", SFTPKeyPath)
		if r.Passphrase != "" {
			line("repo1-sftp-private-key-passphrase", r.Passphrase)
		}
		// Required even though strict checking doesn't use it.
		line("repo1-sftp-host-key-hash-type", "sha1")
		line("repo1-sftp-host-key-check-type", "strict")
		line("repo1-sftp-known-host", SFTPKnownHosts)
	}
	if s.CipherPass != "" {
		line("repo1-cipher-type", "aes-256-cbc")
		line("repo1-cipher-pass", s.CipherPass)
	}
	line("repo1-retention-full-type", "count")
	line("repo1-retention-full", strconv.Itoa(s.RetentionFull))
	// Small files go in bundles; changed blocks only (needs bundling).
	line("repo1-bundle", "y")
	line("repo1-block", "y")
	line("compress-type", "zst")
	line("compress-level", strconv.Itoa(s.CompressLevel))
	line("process-max", strconv.Itoa(s.ProcessMax))
	line("archive-async", "y")
	line("spool-path", "/var/spool/pgbackrest")
	line("lock-path", "/tmp/pgbackrest-morche")
	line("log-path", "/var/log/pgbackrest")
	line("log-level-console", "info")
	line("log-level-file", "detail")
	line("start-fast", "y")
	line("delta", "y")
	b.WriteString("\n[" + Stanza + "]\n")
	line("pg1-path", c.DataDir)
	line("pg1-port", strconv.Itoa(c.Port))
	if c.Socket != "" {
		line("pg1-socket-path", c.Socket)
	}
	return b.String()
}

// q quotes for sh.
func q(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// sqlString quotes a SQL string literal.
func sqlString(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
