package dbmon

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// OpenSQL opens a database/sql handle on one database of a Postgres or
// MySQL/MariaDB connection, reached the same way monitoring reaches it, for
// work that moves rows (database syncs). No statement timeout: copying a big
// table takes as long as it takes. The caller closes it.
func OpenSQL(ctx context.Context, cfg Config, database, app string) (*sql.DB, error) {
	tc, err := cfg.tlsConfig()
	if err != nil {
		return nil, err
	}
	dial := cfg.dialer()
	var db *sql.DB
	switch cfg.Engine {
	case Postgres:
		cc, err := pgx.ParseConfig("")
		if err != nil {
			return nil, err
		}
		cc.Host = cfg.Host
		cc.Port = uint16(cfg.Port)
		cc.User = cfg.Username
		cc.Password = cfg.Password
		cc.Database = cmp(database, cmp(cfg.Database, "postgres"))
		cc.ConnectTimeout = cfg.timeout()
		cc.Fallbacks = nil
		cc.TLSConfig = tc
		// Same text on both ends of a sync, whatever the server's defaults.
		cc.RuntimeParams = map[string]string{
			"application_name": app,
			"TimeZone":         "UTC",
			"DateStyle":        "ISO, YMD",
			"IntervalStyle":    "postgres",
			"bytea_output":     "hex",
		}
		cc.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dial(ctx, network, addr)
		}
		if cfg.Tunneled {
			cc.LookupFunc = func(_ context.Context, host string) ([]string, error) {
				return []string{host}, nil
			}
		}
		db = stdlib.OpenDB(*cc)
	case MySQL:
		mc := mysql.NewConfig()
		mc.User = cfg.Username
		mc.Passwd = cfg.Password
		mc.Net = "tcp"
		mc.Addr = cfg.addr()
		mc.DBName = database
		mc.Timeout = cfg.timeout()
		mc.ParseTime = false
		mc.ClientFoundRows = true
		mc.MultiStatements = false
		mc.ConnectionAttributes = "program_name:" + app
		mc.TLS = tc
		mc.InterpolateParams = true // text protocol: every value comes back as text
		mc.Collation = "utf8mb4_general_ci"
		mc.Params = map[string]string{"time_zone": "'+00:00'"}
		mc.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dial(ctx, network, addr)
		}
		conn, err := mysql.NewConnector(mc)
		if err != nil {
			return nil, err
		}
		db = sql.OpenDB(conn)
	default:
		return nil, fmt.Errorf("%s can't be synced row by row", cfg.Engine)
	}
	db.SetMaxOpenConns(3)
	db.SetMaxIdleConns(3)
	db.SetConnMaxIdleTime(5 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
