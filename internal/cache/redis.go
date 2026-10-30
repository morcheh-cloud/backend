package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrMiss is returned by Get when the key does not exist.
var ErrMiss = errors.New("cache miss")

// Cache is a JSON cache on top of Redis. Client exposes the raw client for
// anything beyond get/set (counters, locks, pub/sub).
type Cache struct {
	Client *redis.Client
}

// Connect opens a Redis client from a redis:// URL and verifies it with a ping.
func Connect(ctx context.Context, url string) (*Cache, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	client := redis.NewClient(opts)

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}
	return &Cache{Client: client}, nil
}

func (c *Cache) Close() error { return c.Client.Close() }

func (c *Cache) Ping(ctx context.Context) error { return c.Client.Ping(ctx).Err() }

// Get decodes the JSON value stored at key into dst; returns ErrMiss if absent.
func (c *Cache) Get(ctx context.Context, key string, dst any) error {
	b, err := c.Client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrMiss
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

// Set stores v as JSON at key. ttl <= 0 means no expiry.
func (c *Cache) Set(ctx context.Context, key string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.Client.Set(ctx, key, b, ttl).Err()
}

func (c *Cache) Delete(ctx context.Context, keys ...string) error {
	return c.Client.Del(ctx, keys...).Err()
}

// Remember returns the cached value at key, or calls load, caches its result
// for ttl and returns it.
func Remember[T any](ctx context.Context, c *Cache, key string, ttl time.Duration, load func(context.Context) (T, error)) (T, error) {
	var v T
	if err := c.Get(ctx, key, &v); err == nil {
		return v, nil
	} else if !errors.Is(err, ErrMiss) {
		return v, err
	}
	v, err := load(ctx)
	if err != nil {
		return v, err
	}
	return v, c.Set(ctx, key, v, ttl)
}
