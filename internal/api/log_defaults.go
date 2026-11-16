package api

import (
	"context"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/morche/backend/internal/database/sqlc"
)

// defaultLogFolder is where files go on a storage unless a policy says.
const defaultLogFolder = "/morche-archives"

// defaultPolicy is what every kind of logs starts with, and what Reset to
// default puts back: on, archived to Morche's own disk once rows pass the
// kind's suggested days, every night at 03:00 on Morche's clock.
func (d logDataset) defaultPolicy() LogPolicyBody {
	period := "month"
	if d.Days < 90 {
		period = "week"
	}
	return LogPolicyBody{
		Enabled: true, Mode: "archive", AfterDays: d.Days, Period: period,
		KeepLocal: true, StorageIDs: []string{}, Folder: defaultLogFolder,
		Cron: "0 3 * * *", Timezone: localZoneName(),
	}
}

// localZoneName is the name of Morche's own time zone (TZ, else what
// /etc/localtime points at), or UTC when it has none.
var localZoneName = sync.OnceValue(func() string {
	ok := func(name string) bool {
		if name == "" || name == "Local" {
			return false
		}
		_, err := time.LoadLocation(name)
		return err == nil
	}
	if tz := strings.TrimPrefix(os.Getenv("TZ"), ":"); ok(tz) {
		return tz
	}
	if link, err := os.Readlink("/etc/localtime"); err == nil {
		if _, name, found := strings.Cut(link, "zoneinfo/"); found && ok(name) {
			return name
		}
	}
	return "UTC"
})

// isDefaultPolicy says whether a saved policy is still its kind's default.
func isDefaultPolicy(p *LogPolicy, d LogPolicyBody) bool {
	return p != nil && p.Enabled == d.Enabled && p.Mode == d.Mode &&
		p.AfterDays == d.AfterDays && p.MaxMB == d.MaxMB && p.Period == d.Period &&
		p.KeepLocal == d.KeepLocal && slices.Equal(p.StorageIDs, d.StorageIDs) &&
		p.Folder == d.Folder && p.KeepDays == d.KeepDays && p.Cron == d.Cron &&
		p.Timezone == d.Timezone
}

// seedLogPolicies gives every kind of logs without a policy its default
// one. A policy an admin changed or turned off stays as it is; a kind added
// later gets its default on the next start.
func seedLogPolicies(ctx context.Context, q *sqlc.Queries) {
	for _, d := range logDatasets {
		b := d.defaultPolicy()
		err := q.SeedLogArchivePolicy(ctx, sqlc.SeedLogArchivePolicyParams{
			Dataset: d.Key, Enabled: b.Enabled, Mode: b.Mode, AfterDays: int32(b.AfterDays),
			MaxMb: int32(b.MaxMB), Period: b.Period, KeepLocal: b.KeepLocal,
			StorageIds: []uuid.UUID{}, Folder: b.Folder, KeepDays: int32(b.KeepDays),
			Cron: b.Cron, Timezone: b.Timezone, NextRunAt: nextRun(b.Cron, b.Timezone, time.Now()),
		})
		if err != nil {
			slog.Warn("seed log retention policy", "dataset", d.Key, "error", err)
		}
	}
}
