package dbbackup

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/morche/backend/internal/dbmon"
)

// PgSQL is a plain-text pg_dump. Morche never writes one, but a file brought
// from elsewhere often is.
const PgSQL = "pg_sql"

// sniffHead is how much of a file (unpacked) is read to tell what it is.
const sniffHead = 1 << 20

// Sniffed is what a backup file Morche didn't take turns out to be.
type Sniffed struct {
	// One of the formats; empty = not one Morche knows.
	Format string
	// The engine it's for.
	Engine string
	// In words, for people.
	Label string
	// The file is gzip around what it holds.
	Gzip bool
	// gzip or zstd around what it holds; empty = neither.
	Pack string
	// The databases it names, when it does (MySQL's USE, Mongo's archive).
	Databases []string
	// A Mongo archive whose collections are compressed (mongodump --gzip).
	MongoGzip bool
	// Why it can't be restored from the panel; empty = it can.
	Problem string
}

// engineNames are the engines in words.
var engineNames = map[string]string{
	dbmon.Postgres: "PostgreSQL", dbmon.MySQL: "MySQL / MariaDB", dbmon.MSSQL: "SQL Server",
	dbmon.Redis: "Redis", dbmon.Mongo: "MongoDB", dbmon.ClickHouse: "ClickHouse",
	dbmon.Elastic: "Elasticsearch", dbmon.Meili: "Meilisearch",
}

// Sniff reads the start of a backup file to tell what it is. engine is the
// database it would go into: a plain SQL file says little about itself, so
// it's read as that engine's.
func Sniff(r io.Reader, engine string) (Sniffed, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	method, data, err := unpack(br)
	if err != nil {
		return Sniffed{}, err
	}
	defer data.Close()
	head, err := io.ReadAll(io.LimitReader(data, sniffHead))
	if err != nil {
		if method != "" && isDamaged(err) {
			return Sniffed{Gzip: method == Gzip, Pack: method, Label: method + " file", Problem: "The compressed data is damaged."}, nil
		}
		return Sniffed{}, err
	}
	s := sniff(head, engine)
	s.Gzip, s.Pack = method == Gzip, method
	return s, nil
}

// unpack undoes gzip or zstd when the stream starts with it.
func unpack(br *bufio.Reader) (string, io.ReadCloser, error) {
	method, err := packOf(br)
	if err != nil {
		return "", nil, err
	}
	if method == "" {
		return "", io.NopCloser(br), nil
	}
	zr, err := Unpack(br, method)
	if err != nil {
		return method, nil, fmt.Errorf("the file looks like %s but isn't: %w", method, err)
	}
	return method, zr, nil
}

var (
	mongoMagic = []byte{0x6d, 0xe2, 0x99, 0x81}
	useLine    = regexp.MustCompile("(?i)^USE\\s+`((?:[^`]|``)+)`")
)

func sniff(head []byte, engine string) Sniffed {
	has := func(p string) bool { return bytes.HasPrefix(head, []byte(p)) }
	switch {
	case len(head) == 0:
		return Sniffed{Label: "Empty file", Problem: "The file is empty."}
	case has("PGDMP"):
		return Sniffed{Format: PgCustom, Engine: dbmon.Postgres, Label: "PostgreSQL archive (pg_dump -Fc)"}
	case isTar(head) && tarHasToc(head):
		return Sniffed{Format: PgDir, Engine: dbmon.Postgres, Label: "PostgreSQL parallel archive (pg_dump -Fd, tar)"}
	case isTar(head) && tarIsChDump(head):
		return sniffClickHouse(head)
	case bytes.HasPrefix(head, mongoMagic):
		return sniffMongo(head)
	case has("TAPE"):
		return Sniffed{Format: MSSQLBak, Engine: dbmon.MSSQL, Label: "SQL Server backup (.bak)"}
	case has("REDIS"):
		return Sniffed{Format: RedisRDB, Engine: dbmon.Redis, Label: "Redis snapshot (RDB)",
			Problem: Restorable(RedisRDB, "")}
	case !isText(head):
		return Sniffed{Label: "Unknown file", Problem: "This isn't a backup Morche knows: not a SQL dump, a pg_dump archive, a mongodump archive, a SQL Server backup or a ClickHouse dump Morche made."}
	}
	if n := sniffNative(head); n.Format != "" {
		return n
	}
	text := string(head)
	switch {
	case strings.Contains(text, "PostgreSQL database cluster dump"):
		return Sniffed{Format: PgAll, Engine: dbmon.Postgres, Label: "PostgreSQL cluster dump (pg_dumpall)",
			Problem: Restorable(PgAll, "")}
	case strings.Contains(text, "PostgreSQL database dump"):
		return pgPlain(head)
	case strings.Contains(text, "-- MySQL dump"), strings.Contains(text, "-- MariaDB dump"):
		return mysqlPlain(head)
	}
	// A dump without the usual header: read it as the target's.
	switch engine {
	case dbmon.Postgres:
		return pgPlain(head)
	case dbmon.MySQL:
		return mysqlPlain(head)
	}
	return Sniffed{Label: "SQL file", Problem: "Only PostgreSQL and MySQL / MariaDB load SQL files."}
}

// isText says the head reads as text: no NUL, mostly valid UTF-8 (a dump
// can hold other encodings in its data).
func isText(head []byte) bool {
	if bytes.IndexByte(head, 0) >= 0 {
		return false
	}
	sample := head[:min(len(head), 4096)]
	bad := 0
	for len(sample) > 0 {
		r, n := utf8.DecodeRune(sample)
		if r == utf8.RuneError && n == 1 && len(sample) > 3 {
			bad++
		}
		sample = sample[n:]
	}
	return bad < 32
}

// sniffClickHouse reads a ClickHouse dump's table of contents: the
// databases in it.
func sniffClickHouse(head []byte) Sniffed {
	s := Sniffed{Format: ClickHouseTar, Engine: dbmon.ClickHouse, Label: "ClickHouse dump (Morche, tar)"}
	toc, err := chTocIn(head)
	if err != nil {
		s.Problem = "The dump can't be read: " + err.Error() + "."
		return s
	}
	s.Databases = chDatabases(toc)
	if len(s.Databases) == 0 {
		s.Problem = "The dump holds no databases."
	}
	return s
}

func pgPlain(head []byte) Sniffed {
	s := Sniffed{Format: PgSQL, Engine: dbmon.Postgres, Label: "PostgreSQL SQL dump"}
	sc := newLineScan()
	sc.write(head)
	if sc.connects {
		s.Problem = pgCreateProblem
	}
	return s
}

func mysqlPlain(head []byte) Sniffed {
	s := Sniffed{Format: MySQLDB, Engine: dbmon.MySQL, Label: "MySQL / MariaDB SQL dump"}
	sc := newLineScan()
	sc.write(head)
	s.Databases = sc.uses
	mysqlKind(&s)
	return s
}

// mysqlKind decides between one database's dump and one that names it.
func mysqlKind(s *Sniffed) {
	switch len(s.Databases) {
	case 0:
		s.Format = MySQLDB
	case 1:
		s.Format = MySQLSQL
	default:
		s.Format = MySQLSQL
		s.Problem = fmt.Sprintf("This file holds %d databases (%s), so it has to be restored by hand.",
			len(s.Databases), strings.Join(s.Databases, ", "))
	}
}

const pgCreateProblem = "This dump creates and connects to its own database (pg_dump --create), so it has to be restored by hand, or dumped again without --create."

// sniffMongo reads a mongodump archive's prelude: the databases in it, and
// whether the collections are compressed.
func sniffMongo(head []byte) Sniffed {
	s := Sniffed{Format: MongoArchive, Engine: dbmon.Mongo, Label: "MongoDB archive (mongodump --archive)", MongoGzip: true}
	rest := head[len(mongoMagic):]
	next := func() (bson.Raw, bool) {
		if len(rest) < 5 {
			return nil, false
		}
		n := int(binary.LittleEndian.Uint32(rest))
		if n < 5 || n > len(rest) {
			return nil, false
		}
		doc := bson.Raw(rest[:n])
		rest = rest[n:]
		return doc, true
	}
	terminator := func() bool {
		if len(rest) >= 4 && binary.LittleEndian.Uint32(rest) == 0xffffffff {
			rest = rest[4:]
			return true
		}
		return false
	}
	// The header, then one document per collection, then a terminator.
	if _, ok := next(); !ok {
		return s
	}
	for !terminator() {
		doc, ok := next()
		if !ok {
			break
		}
		if db, ok := doc.Lookup("db").StringValueOK(); ok && db != "" && !slices.Contains(s.Databases, db) {
			s.Databases = append(s.Databases, db)
		}
	}
	slices.Sort(s.Databases)
	// Then a collection's header and its data: gzip, or plain documents.
	for range 64 {
		if _, ok := next(); !ok {
			return s
		}
		if terminator() {
			continue
		}
		if len(rest) >= 2 {
			s.MongoGzip = rest[0] == 0x1f && rest[1] == 0x8b
		}
		return s
	}
	return s
}

// lineScan looks at the start of every SQL line, skipping COPY data.
type lineScan struct {
	atStart, inCopy bool
	line            []byte
	// Every database a USE line names, in order of first use.
	uses []string
	// pg_dump --create: \connect or CREATE DATABASE.
	connects bool
}

func newLineScan() *lineScan { return &lineScan{atStart: true} }

// keepLine is how much of a line's start is looked at.
const keepLine = 512

func (l *lineScan) Write(p []byte) (int, error) {
	l.write(p)
	return len(p), nil
}

func (l *lineScan) write(p []byte) {
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		part := p
		if i >= 0 {
			part = p[:i]
		}
		if l.atStart {
			l.line = l.line[:0]
			l.atStart = false
		}
		if room := keepLine - len(l.line); room > 0 {
			l.line = append(l.line, part[:min(room, len(part))]...)
		}
		if i < 0 {
			return
		}
		l.end()
		l.atStart = true
		p = p[i+1:]
	}
}

// end handles one whole line (at least its start).
func (l *lineScan) end() {
	line := bytes.TrimRight(l.line, "\r")
	if l.inCopy {
		if string(line) == `\.` {
			l.inCopy = false
		}
		return
	}
	switch {
	case bytes.HasPrefix(line, []byte("COPY ")) && bytes.HasSuffix(line, []byte("FROM stdin;")):
		l.inCopy = true
	case bytes.HasPrefix(line, []byte(`\connect `)), bytes.HasPrefix(line, []byte(`\c `)),
		bytes.HasPrefix(bytes.ToUpper(line[:min(len(line), 16)]), []byte("CREATE DATABASE ")):
		l.connects = true
	}
	if m := useLine.FindSubmatch(line); m != nil {
		name := strings.ReplaceAll(string(m[1]), "``", "`")
		if !slices.Contains(l.uses, name) {
			l.uses = append(l.uses, name)
		}
	}
}

// FileCheck is a whole external file read through.
type FileCheck struct {
	Sniffed
	Bytes  int64
	SHA256 string
}

// CheckFile reads a whole file Morche didn't take: what it is, that gzip
// holds to the end, and that a dump reaches its last line. Problem says why
// it can't be restored.
func CheckFile(r io.Reader, engine string) (FileCheck, error) {
	sum := sha256.New()
	var size keeper
	raw := io.TeeReader(r, io.MultiWriter(sum, &size))
	br := bufio.NewReaderSize(raw, 64<<10)
	method, data, err := unpack(br)
	if err != nil {
		return FileCheck{}, err
	}
	defer data.Close()
	finish := func(out FileCheck) (FileCheck, error) {
		// What the decompressor didn't read still counts.
		if _, err := io.Copy(io.Discard, br); err != nil {
			return FileCheck{}, err
		}
		out.Bytes, out.SHA256 = size.total, hex.EncodeToString(sum.Sum(nil))
		return out, nil
	}
	damaged := func(err error) (FileCheck, error) {
		if method != "" && isDamaged(err) {
			return finish(FileCheck{Sniffed: Sniffed{Gzip: method == Gzip, Pack: method, Problem: "The compressed data is damaged: " + err.Error()}})
		}
		return FileCheck{}, err
	}
	head, err := io.ReadAll(io.LimitReader(data, sniffHead))
	if err != nil {
		return damaged(err)
	}
	out := FileCheck{Sniffed: sniff(head, engine)}
	out.Gzip, out.Pack = method == Gzip, method
	if out.Format == ClickHouseTar {
		_, verdict, err := checkChTar(io.MultiReader(bytes.NewReader(head), data))
		if err != nil {
			return damaged(err)
		}
		if verdict != nil && out.Problem == "" {
			out.Problem = "The archive is damaged: " + verdict.Error() + "."
		}
		return finish(out)
	}
	if out.Format == PgDir {
		verdict, err := checkPgDir(io.MultiReader(bytes.NewReader(head), data))
		if err != nil {
			return damaged(err)
		}
		if verdict != nil {
			out.Problem = "The archive is damaged: " + verdict.Error() + "."
		}
		return finish(out)
	}
	var tail keeper
	tail.Write(head)
	lines := newLineScan()
	text := out.Format == PgSQL || out.Format == MySQLDB || out.Format == MySQLSQL
	if text {
		lines.write(head)
	}
	var sink io.Writer = &tail
	if text {
		sink = io.MultiWriter(&tail, lines)
	}
	if _, err := io.Copy(sink, data); err != nil {
		return damaged(err)
	}
	if out.Problem != "" {
		return finish(out)
	}
	ends := func(s string) bool { return bytes.Contains(tail.tail, []byte(s)) }
	if NativeFormat(out.Format) && !nativeEnds(tail.tail) {
		out.Problem = "The file doesn't reach its last line, so it was cut short."
	}
	headText := string(head[:min(len(head), 4096)])
	switch out.Format {
	case PgSQL:
		switch {
		case lines.connects:
			out.Problem = pgCreateProblem
		case strings.Contains(headText, "PostgreSQL database dump") && !ends("PostgreSQL database dump complete"):
			out.Problem = "The dump doesn't reach its last line, so it was cut short."
		}
	case MySQLDB, MySQLSQL:
		out.Databases = lines.uses
		mysqlKind(&out.Sniffed)
		dumped := strings.Contains(headText, "-- MySQL dump") || strings.Contains(headText, "-- MariaDB dump")
		if out.Problem == "" && dumped && !ends("Dump completed") {
			out.Problem = "The dump doesn't reach its last line, so it was cut short."
		}
	}
	return finish(out)
}

// ForEngine says why a file can't go into a database of engine.
func (s Sniffed) ForEngine(engine string) string {
	if s.Problem != "" {
		return s.Problem
	}
	if s.Engine != engine {
		return fmt.Sprintf("This is a %s backup, but the database is %s.", engineNames[s.Engine], engineNames[engine])
	}
	return ""
}

// PlainSQL turns a pg_dump text file into what psql may run: in restricted
// mode under a key only Morche knows, so the file can't use psql's own
// commands (\! runs a shell command). The dump's own \restrict lines go, and
// so do owners and grants (like pg_restore --no-owner --no-privileges: the
// roles rarely exist here) and settings an older server doesn't know.
func PlainSQL(r io.Reader, key string) io.Reader {
	return io.MultiReader(strings.NewReader(`\restrict `+key+"\n"), &pgFilter{br: bufio.NewReaderSize(r, 64<<10), atStart: true})
}

type pgFilter struct {
	br                        *bufio.Reader
	pending                   []byte
	atStart, inCopy, skipping bool
	err                       error
}

func (f *pgFilter) Read(p []byte) (int, error) {
	for len(f.pending) == 0 {
		if f.err != nil {
			return 0, f.err
		}
		chunk, err := f.br.ReadSlice('\n')
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			f.err = err
		}
		if len(chunk) == 0 {
			continue
		}
		if f.atStart {
			line := bytes.TrimRight(chunk, "\r\n")
			switch {
			case f.inCopy:
				f.skipping = false
				if string(line) == `\.` {
					f.inCopy = false
				}
			case dropLine(line):
				f.skipping = true
			default:
				f.skipping = false
				if bytes.HasPrefix(line, []byte("COPY ")) && bytes.HasSuffix(line, []byte("FROM stdin;")) {
					f.inCopy = true
				}
			}
		}
		f.atStart = chunk[len(chunk)-1] == '\n'
		if !f.skipping {
			// ReadSlice's buffer is reused: copy it out.
			f.pending = append(f.pending[:0], chunk...)
		}
	}
	n := copy(p, f.pending)
	f.pending = f.pending[n:]
	return n, nil
}

// dropLine says a pg_dump line (outside COPY data) is left out.
func dropLine(line []byte) bool {
	has := func(p string) bool { return bytes.HasPrefix(line, []byte(p)) }
	statement := bytes.HasSuffix(line, []byte(";"))
	switch {
	case has(`\restrict `), has(`\unrestrict `):
		return true
	case has("ALTER ") && statement && bytes.Contains(line, []byte(" OWNER TO ")):
		return true
	case (has("GRANT ") || has("REVOKE ") || has("ALTER DEFAULT PRIVILEGES ")) && statement:
		return true
	case string(line) == "SET transaction_timeout = 0;":
		return true
	}
	return false
}
