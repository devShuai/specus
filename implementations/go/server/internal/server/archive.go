package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/store"
)

const (
	archiveInterval = time.Hour
	archiveAge      = 60 * 24 * time.Hour
)

// runArchive periodically aggregates connection records older than 60 days into monthly stats
// and deletes them. Mirrors the C# ConnectionArchiveService (BackgroundService + fixed delay).
func runArchive(ctx context.Context, db *store.DB, logger *slog.Logger) {
	ticker := time.NewTicker(archiveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		archiveCtx, cancel := context.WithTimeout(ctx, time.Minute)
		archived, err := db.ArchiveOldConnections(archiveCtx, time.Now().Add(-archiveAge))
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
