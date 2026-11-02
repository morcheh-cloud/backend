package config

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

type Config struct {
	Env         string   `env:"APP_ENV" envDefault:"development"`
	HTTPAddr    string   `env:"HTTP_ADDR" envDefault:":8080"`
	DatabaseURL string   `env:"DATABASE_URL,required"`
	RedisURL    string   `env:"REDIS_URL,required"`
	CORSOrigins []string `env:"CORS_ALLOWED_ORIGINS" envSeparator:"," envDefault:"http://localhost:3200"`
	// Base64 of 32 random bytes (`openssl rand -base64 32`); seals stored SSH
	// credentials. Changing it makes existing credentials unreadable.
	SecretsKey string `env:"SECRETS_KEY,required,notEmpty"`
	// A web terminal nobody is attached to is closed after this long.
	TerminalDetachedTimeout time.Duration `env:"TERMINAL_DETACHED_TIMEOUT" envDefault:"15m"`
	// If set, the first-run form asks for it, so a stranger who reaches a fresh
	// install can't become its admin.
	SetupToken string `env:"SETUP_TOKEN"`
	// Believe X-Forwarded-For / X-Real-IP. Only behind a proxy that sets them:
	// otherwise anyone can fake their address and dodge the login limits.
	TrustProxy bool `env:"TRUST_PROXY"`
	// Send the session cookie over plain HTTP outside development.
	CookieInsecure bool `env:"COOKIE_INSECURE"`
}

// Development reports whether this is a local dev setup.
func (c *Config) Development() bool { return c.Env == "development" }

// Load reads configuration from the environment, using a .env file if present.
func Load() (*Config, error) {
	_ = godotenv.Load()

	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	// With credentials, a wildcard origin would let any site act as the user.
	if !cfg.Development() && slices.Contains(cfg.CORSOrigins, "*") {
		return nil, errors.New("CORS_ALLOWED_ORIGINS can't be * outside development")
	}
	return &cfg, nil
}
