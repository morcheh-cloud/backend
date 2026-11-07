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
	// Every server's connection is re-checked this often in the background,
	// so a status doesn't stay "online" after the server went away. 0 = off.
	ServerCheckInterval time.Duration `env:"SERVER_CHECK_INTERVAL" envDefault:"15s"`
	// Same for storages. Slower than servers: each check signs in to the
	// remote service (an S3 request, an FTP/SFTP login). 0 = off.
	StorageCheckInterval time.Duration `env:"STORAGE_CHECK_INTERVAL" envDefault:"30s"`
	// Each online storage is walked this often to measure how much it holds
	// (Storage › Insights). Big buckets take a while and cost list requests
	// on paid S3. 0 = only when someone presses Measure.
	StorageScanInterval time.Duration `env:"STORAGE_SCAN_INTERVAL" envDefault:"24h"`
	// Storage check history (uptime and latency charts) is kept this long.
	StorageHistory time.Duration `env:"STORAGE_HISTORY" envDefault:"744h"`
	// Each online Linux server's CPU, memory, disk and network are read this
	// often for Servers › Insights (about a second of work on the server).
	// 0 = off.
	ServerSampleInterval time.Duration `env:"SERVER_SAMPLE_INTERVAL" envDefault:"5m"`
	// Server check history and resource samples are kept this long.
	ServerHistory time.Duration `env:"SERVER_HISTORY" envDefault:"744h"`
	// Same for DNS servers. 0 = off.
	DNSCheckInterval time.Duration `env:"DNS_CHECK_INTERVAL" envDefault:"30s"`
	// How often Morcheh looks for cron jobs that are due. 0 = they never run
	// on time (Run now still works).
	ScheduleTick time.Duration `env:"SCHEDULE_TICK" envDefault:"15s"`
	// If set, the first-run form asks for it, so a stranger who reaches a fresh
	// install can't become its admin.
	SetupToken string `env:"SETUP_TOKEN"`
	// ansible-playbook to run playbooks with: a name on PATH or a path.
	AnsiblePlaybook string `env:"ANSIBLE_PLAYBOOK" envDefault:"ansible-playbook"`
	// auto: run playbooks in a bubblewrap sandbox when it works; without one
	// only system admins can run them. bwrap: refuse to run without it. off:
	// never use it.
	AnsibleSandbox string `env:"ANSIBLE_SANDBOX" envDefault:"auto"`
	// A playbook still running after this long is stopped.
	AnsibleRunTimeout time.Duration `env:"ANSIBLE_RUN_TIMEOUT" envDefault:"2h"`
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
	if !slices.Contains([]string{"auto", "bwrap", "off"}, cfg.AnsibleSandbox) {
		return nil, errors.New("ANSIBLE_SANDBOX must be auto, bwrap or off")
	}
	return &cfg, nil
}
