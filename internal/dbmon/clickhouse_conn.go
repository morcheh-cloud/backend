package dbmon

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"net"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

// clickhouseOptions reaches ClickHouse over its native protocol (port 9000,
// 9440 with TLS), through cfg's dialer. The driver only wraps TLS around its
// own dialer, so it's done here.
func clickhouseOptions(cfg Config, database, app string) (*clickhouse.Options, error) {
	tc, err := cfg.tlsConfig()
	if err != nil {
		return nil, err
	}
	dial := cfg.dialer()
	return &clickhouse.Options{
		Protocol: clickhouse.Native,
		Addr:     []string{cfg.addr()},
		Auth: clickhouse.Auth{
			Database: cmp(database, cmp(cfg.Database, "default")),
			Username: cmp(cfg.Username, "default"),
			Password: cfg.Password,
		},
		DialContext: func(ctx context.Context, addr string) (net.Conn, error) {
			c, err := dial(ctx, "tcp", addr)
			if err != nil || tc == nil {
				return c, err
			}
			t := tls.Client(c, tc)
			hctx, cancel := context.WithTimeout(ctx, cfg.timeout())
			defer cancel()
			if err := t.HandshakeContext(hctx); err != nil {
				c.Close()
				return nil, err
			}
			return t, nil
		},
		DialTimeout:      cfg.timeout(),
		ReadTimeout:      5 * time.Minute,
		MaxOpenConns:     3,
		MaxIdleConns:     3,
		ConnMaxLifetime:  time.Hour,
		ClientInfo:       clickhouse.ClientInfo{Products: []struct{ Name, Version string }{{Name: app, Version: "1"}}},
		ConnOpenStrategy: clickhouse.ConnOpenInOrder,
	}, nil
}

// openClickHouseDB is a database/sql handle (not pinged).
func openClickHouseDB(cfg Config, database, app string) (*sql.DB, error) {
	o, err := clickhouseOptions(cfg, database, app)
	if err != nil {
		return nil, err
	}
	return clickhouse.OpenDB(o), nil
}

// OpenClickHouse opens and pings a database/sql handle on one ClickHouse
// database, for the data explorer and syncs. The caller closes it.
func OpenClickHouse(ctx context.Context, cfg Config, database, app string) (*sql.DB, error) {
	db, err := openClickHouseDB(cfg, database, app)
	if err != nil {
		return nil, err
	}
	pctx, cancel := context.WithTimeout(ctx, cfg.timeout())
	defer cancel()
	if err := db.PingContext(pctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// ClickHouse error codes worth telling apart.
const (
	chAuthFailed    = 516 // AUTHENTICATION_FAILED
	chUnknownUser   = 192 // UNKNOWN_USER
	chWrongPassword = 193 // WRONG_PASSWORD
	chRequiredPass  = 194 // REQUIRED_PASSWORD
	chUnknownDB     = 81  // UNKNOWN_DATABASE
	chAccessDenied  = 497 // ACCESS_DENIED
)

func engineAuthErrorClickHouse(err error) bool {
	var ex *clickhouse.Exception
	if !errors.As(err, &ex) {
		return false
	}
	switch ex.Code {
	case chAuthFailed, chUnknownUser, chWrongPassword, chRequiredPass:
		return true
	}
	return false
}

// ClickHouseCode is the server's error code, 0 when err isn't one.
func ClickHouseCode(err error) int32 {
	var ex *clickhouse.Exception
	if errors.As(err, &ex) {
		return ex.Code
	}
	return 0
}
