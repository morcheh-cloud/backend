package config

import (
	"fmt"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

type Config struct {
	Env         string   `env:"APP_ENV" envDefault:"development"`
	HTTPAddr    string   `env:"HTTP_ADDR" envDefault:":8080"`
	DatabaseURL string   `env:"DATABASE_URL,required"`
	RedisURL    string   `env:"REDIS_URL,required"`
	CORSOrigins []string `env:"CORS_ALLOWED_ORIGINS" envSeparator:"," envDefault:"http://localhost:3200"`
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
