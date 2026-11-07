package api

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/jobs"
	"github.com/morcheh/backend/internal/storage"
)

// keepSet is which of a plan's good backups (newest first) its retention
// keeps. Each database of the plan is counted on its own, its newest backup is
// always kept, and so is everything a kept incremental builds on.
func keepSet(rows []sqlc.DatabaseBackup, p sqlc.DatabaseBackupPlan, loc *time.Location, now time.Time) map[uuid.UUID]bool {
	keep := map[uuid.UUID]bool{}
	groups := map[string][]sqlc.DatabaseBackup{}
	var order []string
	for _, b := range rows {
		if _, ok := groups[b.Target]; !ok {
			order = append(order, b.Target)
		}
		groups[b.Target] = append(groups[b.Target], b)
	}
	for _, target := range order {
		group := groups[target]
		keep[group[0].ID] = true
		switch p.Retention {
		case "forever":
			for _, b := range group {
				keep[b.ID] = true
			}
		case "gfs":
			// The newest backup of each of the last N days, weeks and months
			// that have one. A backup that's both counts once.
			tiers := []struct {
				n   int32
				key func(time.Time) [2]int
			}{
				{p.GfsDaily, func(t time.Time) [2]int { return [2]int{t.Year(), t.YearDay()} }},
				{p.GfsWeekly, func(t time.Time) [2]int { y, w := t.ISOWeek(); return [2]int{y, w} }},
				{p.GfsMonthly, func(t time.Time) [2]int { return [2]int{t.Year(), int(t.Month())} }},
			}
			for _, tier := range tiers {
				seen := map[[2]int]bool{}
				for _, b := range group {
					if int32(len(seen)) >= tier.n {
						break
					}
					k := tier.key(b.CreatedAt.In(loc))
					if !seen[k] {
						seen[k] = true
						keep[b.ID] = true
					}
				}
			}
		default:
			cutoff := now.Add(-time.Duration(p.KeepDays) * 24 * time.Hour)
			for _, b := range group {
				if b.CreatedAt.After(cutoff) {
					keep[b.ID] = true
				}
			}
		}
	}
	// An incremental is useless without what it builds on.
	byID := make(map[uuid.UUID]sqlc.DatabaseBackup, len(rows))
	for _, b := range rows {
		byID[b.ID] = b
	}
	for id := range keep {
		for b, ok := byID[id]; ok && b.ParentID != nil; b, ok = byID[*b.ParentID] {
			keep[*b.ParentID] = true
		}
	}
	return keep
}

// prune applies the plan's retention, then forgets old runs that left no
// backup. It only deletes files its own runs wrote; a file it can't delete stays
// on the list for next time. Backups taken before a restore have no plan, so
// they're never pruned.
func (h *backupHandler) prune(ctx context.Context, t *jobs.Task, p sqlc.DatabaseBackupPlan) {
	if p.Retention != "forever" {
		rows, err := h.q.ListPlanBackups(ctx, &p.ID)
		if err != nil {
			slog.Warn("list a plan's backups", "plan", p.ID, "error", err)
		}
		keep := keepSet(rows, p, scheduleLoc(p.Timezone), time.Now())
		for _, b := range rows {
			if keep[b.ID] {
				continue
			}
			if err := h.deleteWithDependents(ctx, b, t); err != nil {
				t.Logf("Couldn't delete %s: %s", b.Path, problemText(err))
				continue
			}
			t.Logf("Deleted %s (past what the plan keeps)", b.Path)
		}
	}
	if err := h.q.PruneBackupRecords(ctx, sqlc.PruneBackupRecordsParams{PlanID: &p.ID, Keep: backupFailedRows}); err != nil {
		slog.Warn("prune backup records", "plan", p.ID, "error", err)
	}
}

// deleteWithDependents deletes a backup, and first every incremental built on
// it, files and all. A row stays while any of its files does.
func (h *backupHandler) deleteWithDependents(ctx context.Context, b sqlc.DatabaseBackup, t *jobs.Task) error {
	deps, err := h.q.BackupDependents(ctx, &b.ID)
	if err != nil {
		return err
	}
	for _, id := range deps {
		d, err := h.q.GetBackup(ctx, id)
		if isNotFound(err) {
			continue
		}
		if err != nil {
			return err
		}
		if err := h.removeBackup(ctx, d); err != nil {
			return err
		}
		if t != nil {
			t.Logf("Deleted %s (it built on %s)", d.Path, b.Path)
		}
	}
	return h.removeBackup(ctx, b)
}

// removeBackup deletes every stored copy of one backup, then its row. A
// file already gone, or a storage removed from Morcheh, is fine.
func (h *backupHandler) removeBackup(ctx context.Context, b sqlc.DatabaseBackup) error {
	stored, err := h.storedCopies(ctx, b.ID)
	if err != nil {
		return err
	}
	var first error
	for _, c := range stored {
		if b.Path == "" {
			break
		}
		if _, err := h.q.GetStorage(ctx, *c.StorageID); isNotFound(err) {
			continue
		}
		err := h.st.withFS(ctx, c.StorageID.String(), func(_ sqlc.Storage, f storage.FS) error {
			if err := f.Remove(ctx, b.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			return nil
		})
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		// So a later try, or a restore, doesn't count on it.
		if err := h.q.SetBackupCopy(ctx, sqlc.SetBackupCopyParams{
			State: "failed", Error: "Deleted from the storage.", BackupID: b.ID, StorageID: c.StorageID,
		}); err != nil {
			slog.Warn("record a deleted backup copy", "backup", b.ID, "error", err)
		}
	}
	if first != nil {
		return first
	}
	_, err = h.q.DeleteBackup(ctx, b.ID)
	return err
}
