package config

import (
	"fmt"
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
}

// Load reads configuration from the environment, using a .env file if present.
func Load() (*Config, error) {
	_ = godotenv.Load()

	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}
