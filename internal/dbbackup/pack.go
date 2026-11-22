package dbbackup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/morche/backend/internal/dbmon"
)

// Compression methods a plan picks from.
const (
	Gzip = "gzip"
	Zstd = "zstd"
)

// Compression levels, in words: what each means per method is below.
const (
	LevelFast     = "fast"
	LevelBalanced = "balanced"
	LevelSmall    = "small"
)

// MaxWorkers is the most parallel jobs a dump or restore may use.
const MaxWorkers = 16

// CompressionMark is the line a script leaves on stderr when it compressed
// otherwise than asked (an older pg_dump without zstd).
const CompressionMark = "MORCHE_COMPRESSION="

// CheckCompression refuses a method or level Morche doesn't know.
func CheckCompression(method, level string) error {
	switch method {
	case Gzip, Zstd:
	default:
		return errors.New("Pick gzip or zstd.")
	}
	switch level {
	case LevelFast, LevelBalanced, LevelSmall:
	default:
		return errors.New("Pick fast, balanced or small.")
	}
	return nil
}

// gzipLevel is the level for gzip, here and in pg_dump.
func gzipLevel(level string) int {
	switch level {
	case LevelFast:
		return 1
	case LevelSmall:
		return 9
	}
	return 6
}

// zstdLevel is pg_dump's zstd level (1..22; 3 is zstd's own default).
func zstdLevel(level string) int {
	switch level {
	case LevelFast:
		return 1
	case LevelSmall:
		return 15
	}
	return 4
}

// Compression says how a file was compressed, as stored on a backup:
// "method:level".
func Compression(method, level string) string { return method + ":" + level }

// Method is the method of a stored compression; older backups have none and
// were gzip.
func Method(compression string) string {
	m, _, _ := strings.Cut(compression, ":")
	if m == Zstd {
		return Zstd
	}
	return Gzip
}

// Packed says what Morche itself compressed a stored file with, so it's the
// one to undo it on the way back; empty = the dump tool did (or nothing).
func Packed(format, compression string) string {
	switch format {
	case PgCustom, PgDir:
		return ""
	case MongoArchive:
		// mongodump's own --gzip, unless Morche used zstd instead.
		if Method(compression) == Zstd {
			return Zstd
		}
		return ""
	}
	return Method(compression)
}

// Pack wraps w in the method's compressor. Close it to finish the stream.
func Pack(w io.Writer, method, level string) (io.WriteCloser, error) {
	if method == Zstd {
		speed := zstd.SpeedDefault
		switch level {
		case LevelFast:
			speed = zstd.SpeedFastest
		case LevelSmall:
			speed = zstd.SpeedBetterCompression
		}
		return zstd.NewWriter(w, zstd.WithEncoderLevel(speed))
	}
	return gzip.NewWriterLevel(w, gzipLevel(level))
}

// Unpack undoes method on r. Close the result when done.
func Unpack(r io.Reader, method string) (io.ReadCloser, error) {
	switch method {
	case Zstd:
		zr, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(0))
		if err != nil {
			return nil, fmt.Errorf("The file isn't zstd: %w", err)
		}
		return zr.IOReadCloser(), nil
	case Gzip:
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("The file isn't gzip: %w", err)
		}
		zr.Multistream(true)
		return zr, nil
	}
	return io.NopCloser(r), nil
}

var zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

// packOf tells gzip or zstd by the stream's first bytes.
func packOf(br *bufio.Reader) (string, error) {
	magic, err := br.Peek(4)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		return Gzip, nil
	case bytes.Equal(magic, zstdMagic):
		return Zstd, nil
	}
	return "", nil
}

// isDamaged says a read error comes from the compressed data, not from where
// it's read.
func isDamaged(err error) bool {
	for _, e := range []error{
		gzip.ErrChecksum, gzip.ErrHeader, io.ErrUnexpectedEOF,
		zstd.ErrCRCMismatch, zstd.ErrMagicMismatch, zstd.ErrReservedBlockType,
		zstd.ErrBlockTooSmall, zstd.ErrCompressedSizeTooBig, zstd.ErrFrameSizeMismatch,
		zstd.ErrWindowSizeExceeded, zstd.ErrWindowSizeTooSmall, zstd.ErrUnknownDictionary,
		zstd.ErrDecoderSizeExceeded,
	} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// PgDir's tar holds pg_dump's directory: toc.dat first, then the data files.
const tocName = "toc.dat"

// checkPgDir reads a whole pg_dir tar: every member complete, the table of
// contents there and a pg_dump one. bad is a verdict on the file; err is a
// failing read, which says nothing about it.
func checkPgDir(r io.Reader) (bad, err error) {
	tr := tar.NewReader(r)
	toc := false
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if errors.Is(err, tar.ErrHeader) || errors.Is(err, io.ErrUnexpectedEOF) {
				return errors.New("the archive is cut short or damaged"), nil
			}
			return nil, err
		}
		if strings.TrimPrefix(h.Name, "./") == tocName {
			head := make([]byte, 5)
			if _, err := io.ReadFull(tr, head); err != nil || string(head) != "PGDMP" {
				return errors.New("its table of contents isn't a pg_dump one"), nil
			}
			toc = true
		}
		if _, err := io.Copy(io.Discard, tr); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return errors.New("the archive is cut short"), nil
			}
			return nil, err
		}
	}
	if !toc {
		return errors.New("it has no pg_dump table of contents (toc.dat)"), nil
	}
	return nil, nil
}

// isTar says head starts with a tar header.
func isTar(head []byte) bool {
	return len(head) >= 262 && bytes.Equal(head[257:262], []byte("ustar"))
}

// tarHasToc says a tar's first member is pg_dump's table of contents.
func tarHasToc(head []byte) bool {
	h, err := tar.NewReader(bytes.NewReader(head)).Next()
	return err == nil && strings.TrimPrefix(h.Name, "./") == tocName
}

// Parallel says whether an engine's dumps can use several jobs at once.
func Parallel(engine string) IncrementalSupport {
	switch engine {
	case dbmon.Postgres:
		return IncrementalSupport{true, "pg_dump dumps several tables at once (its directory format) and restores the same way. The dump is written to a temporary folder where it runs first, so that needs room for it; each job holds a connection of its own, and a parallel restore isn't one transaction."}
	case dbmon.Mongo:
		return IncrementalSupport{true, "mongodump reads this many collections at once (it does 4 by its own default)."}
	case dbmon.MySQL:
		return IncrementalSupport{false, "mysqldump reads one table at a time."}
	case dbmon.Redis:
		return IncrementalSupport{false, "Redis makes one snapshot."}
	case dbmon.MSSQL:
		return IncrementalSupport{false, "SQL Server's backup runs on its own."}
	case dbmon.ClickHouse:
		return IncrementalSupport{false, "ClickHouse already reads each table with many threads; the dump takes the tables one at a time."}
	}
	return IncrementalSupport{false, "This engine doesn't have one."}
}

// CompressionNote says how an engine's files are compressed.
func CompressionNote(engine string) string {
	switch engine {
	case dbmon.Postgres:
		return "pg_dump compresses its archive itself. zstd needs pg_dump 16 or newer built with it; older ones use gzip, and the backup says so."
	case dbmon.Mongo:
		return "gzip is mongodump's own and has no levels; zstd is done by Morche."
	case dbmon.ClickHouse:
		return "Morche compresses the file while it's uploaded. Each table is written to a temporary folder before it's sent, so that needs room for the biggest table."
	}
	return "Morche compresses the file while it's uploaded."
}
