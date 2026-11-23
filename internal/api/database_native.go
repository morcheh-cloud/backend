package api

import (
	"context"
	"io"

	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/dbbackup"
)

// nativeRun is a backup or restore Morche does itself over the database's
// HTTP API (Elasticsearch, Meilisearch) instead of a script on a runner. It
// reaches the database the way monitoring does, through its server's tunnel
// when it has one.
type nativeRun func(ctx context.Context, in io.Reader, out io.Writer) error

// nativeFor is d's export (o nil) or load of t, or nil when d's engine takes a
// script.
func (h *backupHandler) nativeFor(d sqlc.Database, t dbbackup.Target, o *dbbackup.RestoreOptions) nativeRun {
	if !dbbackup.NativeEngine(d.Engine) {
		return nil
	}
	return func(ctx context.Context, in io.Reader, out io.Writer) error {
		cfg, ssh, err := h.db.config(ctx, d)
		if ssh != nil {
			defer ssh.Release()
		}
		if err != nil {
			return err
		}
		if o == nil {
			return dbbackup.Dump(ctx, cfg, t, out)
		}
		return dbbackup.Load(ctx, cfg, t, *o, in)
	}
}
