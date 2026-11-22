package dbbackup

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Result is what reading a stored file back found.
type Result struct {
	Bytes  int64
	SHA256 string
}

// keeper holds a stream's first and last bytes.
type keeper struct {
	head, tail []byte
	total      int64
}

const keep = 512

func (k *keeper) Write(p []byte) (int, error) {
	k.total += int64(len(p))
	if room := keep - len(k.head); room > 0 {
		k.head = append(k.head, p[:min(room, len(p))]...)
	}
	k.tail = append(k.tail, p[max(0, len(p)-keep):]...)
	if len(k.tail) > keep {
		k.tail = k.tail[len(k.tail)-keep:]
	}
	return len(p), nil
}

// Verify reads a whole backup file: its checksum, that its compression holds
// to the end, and that the content is the kind and complete as far as the
// format can tell. It's no restore, but it catches a file cut short or
// corrupted.
func Verify(format string, r io.Reader) (Result, error) {
	sum := sha256.New()
	var size keeper
	raw := io.TeeReader(r, io.MultiWriter(sum, &size))
	var out keeper
	var bad error

	switch format {
	case PgCustom:
		if _, err := io.Copy(&out, raw); err != nil {
			return Result{}, err
		}
	case PgDir:
		verdict, err := checkPgDir(io.TeeReader(raw, &out))
		if err != nil {
			return Result{}, err
		}
		bad = verdict
	default:
		// gzip or zstd, told by the file itself.
		br := bufio.NewReaderSize(raw, 64<<10)
		method, err := packOf(br)
		if err != nil {
			return Result{}, err
		}
		if method == "" {
			bad = errors.New("the file isn't gzip or zstd")
			break
		}
		zr, err := Unpack(br, method)
		if err != nil {
			bad = err
			break
		}
		if format == ClickHouseTar {
			// The tar is read member by member.
			var verdict error
			_, verdict, err = checkChTar(io.TeeReader(zr, &out))
			if err == nil && verdict == nil {
				_, err = io.Copy(&out, zr)
			}
			bad = verdict
		} else {
			_, err = io.Copy(&out, zr)
		}
		zr.Close()
		if err != nil {
			// A failing read of the storage isn't a verdict on the file.
			if !isDamaged(err) {
				return Result{}, err
			}
			bad = fmt.Errorf("the compressed data is damaged: %w", err)
		}
		// What the decompressor didn't read still counts for the checksum.
		if _, err := io.Copy(io.Discard, br); err != nil {
			return Result{}, err
		}
	}
	if _, err := io.Copy(io.Discard, raw); err != nil {
		return Result{}, err
	}
	res := Result{Bytes: size.total, SHA256: hex.EncodeToString(sum.Sum(nil))}
	if bad != nil {
		return res, bad
	}
	return res, check(format, &out)
}

func check(format string, k *keeper) error {
	has := func(prefix string) bool { return bytes.HasPrefix(k.head, []byte(prefix)) }
	ends := func(s string) bool { return bytes.Contains(k.tail, []byte(s)) }
	if k.total == 0 && format != MySQLBinlog {
		return errors.New("the file is empty")
	}
	switch format {
	case PgCustom:
		if !has("PGDMP") {
			return errors.New("it isn't a pg_dump archive")
		}
	case PgDir:
		// checkPgDir read it all.
	case PgAll:
		if !ends("cluster dump complete") {
			return errors.New("the dump doesn't reach its last line, so it was cut short")
		}
	case MySQLSQL, MySQLDB:
		if !ends("Dump completed") {
			return errors.New("the dump doesn't reach its last line, so it was cut short")
		}
	case MongoArchive:
		if !bytes.HasPrefix(k.head, []byte{0x6d, 0xe2, 0x99, 0x81}) {
			return errors.New("it isn't a mongodump archive")
		}
	case RedisRDB:
		if !has("REDIS") {
			return errors.New("it isn't a Redis snapshot")
		}
	case MySQLBinlog:
		// The server may have had nothing new: an empty file is a good one.
	case ClickHouseTar:
		// checkChTar read it all.
	case MSSQLBak, MSSQLDiff:
		if !has("TAPE") {
			return errors.New("it isn't a SQL Server backup")
		}
	}
	return nil
}
