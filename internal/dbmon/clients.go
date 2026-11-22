package dbmon

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

// OpenMongo connects a MongoDB client the way monitoring does, for work that
// reads documents (the data explorer). The caller disconnects it.
func OpenMongo(ctx context.Context, cfg Config, app string) (*mongo.Client, error) {
	tc, err := cfg.tlsConfig()
	if err != nil {
		return nil, err
	}
	opts := options.Client().
		SetHosts([]string{cfg.addr()}).
		SetDirect(true).
		SetAppName(app).
		SetDialer(dialFunc(cfg.dialer())).
		SetConnectTimeout(cfg.timeout()).
		SetServerSelectionTimeout(cfg.timeout()).
		SetMaxPoolSize(3).
		SetRetryReads(false).
		SetRetryWrites(false).
		SetReadPreference(readpref.PrimaryPreferred())
	if cfg.Username != "" {
		opts.SetAuth(options.Credential{
			Username: cfg.Username, Password: cfg.Password,
			AuthSource: cmp(cfg.Database, "admin"),
		})
	}
	if tc != nil {
		opts.SetTLSConfig(tc)
	}
	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, nil); err != nil {
		client.Disconnect(context.Background())
		return nil, err
	}
	return client, nil
}

// OpenRedis connects to one numbered Redis database the way monitoring does.
// No read timeout of its own: the caller's context bounds each command.
func OpenRedis(ctx context.Context, cfg Config, db int, app string) (*redis.Client, error) {
	tc, err := cfg.tlsConfig()
	if err != nil {
		return nil, err
	}
	dial := cfg.dialer()
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil || tc == nil {
			return c, err
		}
		tl := tls.Client(c, tc)
		if err := tl.HandshakeContext(ctx); err != nil {
			c.Close()
			return nil, err
		}
		return tl, nil
	}
	rdb := redis.NewClient(&redis.Options{
		Addr:                  cfg.addr(),
		Username:              cfg.Username,
		Password:              cfg.Password,
		DB:                    db,
		ClientName:            app,
		Protocol:              2,
		DisableIdentity:       true,
		Dialer:                dialer,
		DialTimeout:           cfg.timeout(),
		ReadTimeout:           -1,
		WriteTimeout:          cfg.timeout(),
		ContextTimeoutEnabled: true,
		PoolSize:              3,
		MaxRetries:            -1,
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		rdb.Close()
		return nil, err
	}
	return rdb, nil
}
