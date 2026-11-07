package dbbackup

import (
	"bytes"
	"compress/gzip"
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

// Verify reads a whole backup file: its checksum, that gzip holds to the
// end, and that the content is the kind and complete as far as the format
// can tell. It's no restore, but it catches a file cut short or corrupted.
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
	default:
		zr, err := gzip.NewReader(raw)
		if err != nil {
			bad = errors.New("the file isn't gzip")
			break
		}
		if _, err := io.Copy(&out, zr); err != nil {
			// A failing read of the storage isn't a verdict on the file.
			if errors.Is(err, gzip.ErrChecksum) || errors.Is(err, gzip.ErrHeader) || errors.Is(err, io.ErrUnexpectedEOF) {
				bad = fmt.Errorf("the compressed data is damaged: %w", err)
			} else {
				return Result{}, err
			}
		}
	}
	// What gzip didn't read still counts for the checksum.
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
	case MSSQLBak, MSSQLDiff:
		if !has("TAPE") {
			return errors.New("it isn't a SQL Server backup")
		}
	}
	return nil
}
