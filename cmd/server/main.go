package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/morcheh/backend/internal/api"
	"github.com/morcheh/backend/internal/cache"
	"github.com/morcheh/backend/internal/config"
	"github.com/morcheh/backend/internal/database"
	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/secrets"
)

func main() {
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	box, err := secrets.New(cfg.SecretsKey)
	if err != nil {
		return err
	}

	db, err := database.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	rdb, err := cache.Connect(ctx, cfg.RedisURL)
	if err != nil {
		return err
	}
	defer rdb.Close()

	queries := sqlc.New(db)
	if n, err := queries.CountUsers(ctx); err == nil && n == 0 && !cfg.Development() && cfg.SetupToken == "" {
		slog.Warn("no users yet and no SETUP_TOKEN: whoever reaches this server first becomes its admin")
	}

	runner := jobs.New(queries)
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           api.NewRouter(cfg, db, rdb, box, runner),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := runner.Start(ctx); err != nil {
		return err
	}

	ln, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return err
	}
	base := baseURL(ln.Addr())
	slog.Info("http server listening", "addr", cfg.HTTPAddr, "env", cfg.Env)
	slog.Info("swagger ui", "url", base+"/docs", "spec", base+"/openapi.json")

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	slog.Info("shutting down")
	// Running jobs stop and are marked interrupted; queued ones wait for the
	// next start.
	jobsCtx, cancelJobs := context.WithTimeout(context.Background(), 5*time.Second)
	runner.Close(jobsCtx)
	cancelJobs()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// baseURL turns a listener address into a browsable URL; wildcard hosts
// (":8080", "0.0.0.0", "::") become localhost.
func baseURL(addr net.Addr) string {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return "http://" + addr.String()
	}
	host := "localhost"
	if !tcp.IP.IsUnspecified() {
		host = tcp.IP.String()
	}
	return "http://" + net.JoinHostPort(host, fmt.Sprint(tcp.Port))
}
