package dbquery

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// text turns a driver value into what the panel shows; nil stays nil.
func text(v any, typ string) *string {
	var s string
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		s = x
	case []byte:
		up := strings.ToUpper(typ)
		switch {
		case up == "UNIQUEIDENTIFIER" && len(x) == 16:
			// SQL Server sends the first three groups little-endian.
			b := []byte{x[3], x[2], x[1], x[0], x[5], x[4], x[7], x[6]}
			b = append(b, x[8:]...)
			h := hex.EncodeToString(b)
			s = strings.ToUpper(h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:])
		case utf8.Valid(x):
			s = string(x)
		default:
			n := min(len(x), maxCell/2)
			s = `\x` + hex.EncodeToString(x[:n])
			if n < len(x) {
				s += "…"
			}
		}
	case time.Time:
		switch strings.ToUpper(typ) {
		case "DATE":
			s = x.Format("2006-01-02")
		case "TIME":
			s = x.Format("15:04:05.999999")
		default:
			up := strings.ToUpper(typ)
			if strings.Contains(up, "TZ") || strings.Contains(up, "OFFSET") {
				s = x.Format("2006-01-02 15:04:05.999999Z07:00")
			} else {
				s = x.Format("2006-01-02 15:04:05.999999")
			}
		}
	case bool:
		s = strconv.FormatBool(x)
	case int64:
		s = strconv.FormatInt(x, 10)
	case int32:
		s = strconv.FormatInt(int64(x), 10)
	case int:
		s = strconv.Itoa(x)
	case int8:
		s = strconv.FormatInt(int64(x), 10)
	case int16:
		s = strconv.FormatInt(int64(x), 10)
	case uint8:
		s = strconv.FormatUint(uint64(x), 10)
	case uint16:
		s = strconv.FormatUint(uint64(x), 10)
	case uint32:
		s = strconv.FormatUint(uint64(x), 10)
	case uint64:
		s = strconv.FormatUint(x, 10)
	case big.Int:
		s = x.String()
	case float64:
		s = strconv.FormatFloat(x, 'g', -1, 64)
	case float32:
		s = strconv.FormatFloat(float64(x), 'g', -1, 32)
	case *big.Int:
		s = x.String()
	case fmt.Stringer:
		s = x.String()
	default:
		// ClickHouse's driver hands Nullable values over as pointers.
		if rv := reflect.ValueOf(x); rv.Kind() == reflect.Pointer {
			if rv.IsNil() {
				return nil
			}
			if _, ok := x.(json.Marshaler); !ok {
				return text(rv.Elem().Interface(), typ)
			}
		}
		b, err := json.Marshal(x)
		if err != nil {
			s = fmt.Sprint(x)
		} else {
			s = string(b)
		}
	}
	return clip(s)
}

func clip(s string) *string {
	if len(s) > maxCell {
		cut := maxCell
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return &s
}

func ptr[T any](v T) *T { return &v }
