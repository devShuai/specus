package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/config"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/store"
)

// runArchive periodically aggregates old connection records into monthly stats and deletes the
// archived detail rows. Mirrors Java's ConnectionArchiveService fixed-delay behavior.
func runArchive(ctx context.Context, db *store.DB, logger *slog.Logger, options config.ConnectionRecordConfig) {
	if options.DetailRetentionDays <= 0 {
		logger.Info("connection archive disabled", "detailRetentionDays", options.DetailRetentionDays)
		return
	}
	interval := time.Duration(options.ArchiveIntervalMs) * time.Millisecond
	if interval <= 0 {
		interval = time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		archiveCtx, cancel := context.WithTimeout(ctx, time.Minute)
		cutoff, ok := connectionArchiveCutoff(time.Now(), options.DetailRetentionDays)
		if !ok {
			cancel()
			continue
		}
		archived, err := db.ArchiveOldConnections(archiveCtx, cutoff)
		cancel()
		if err != nil {
			logger.Error("connection archive failed", "err", err)
			continue
		}
		if archived > 0 {
			logger.Info("archived old connections", "count", archived)
		}
	}
}

func connectionArchiveCutoff(now time.Time, retentionDays int) (time.Time, bool) {
	if retentionDays <= 0 {
		return time.Time{}, false
	}
	day := now.UTC().AddDate(0, 0, -retentionDays)
	return time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC), true
}
