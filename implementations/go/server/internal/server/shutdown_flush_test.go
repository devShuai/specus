package server

import (
	"context"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// Traffic counters live in memory between periodic flushes, so closing the database before a final
// flush loses everything accumulated since the last tick. A SIGTERM must not cost data. The
// detail-record queue drain is covered in the store package, where the queue is reachable.
func TestCloseFlushesBufferedTrafficBeforeClosingTheDatabase(t *testing.T) {
	app, _ := startTestApp(t)
	databasePath := app.cfg.ConnectionString

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	account, err := app.DB().FindClientByName(ctx, DemoClientName)
	if err != nil || account == nil {
		t.Fatalf("find demo client: %v", err)
	}

	// Buffer both kinds of write without letting the periodic flush run.
	app.traffic.RecordUpload(account.ClientName, 4096)
	app.traffic.RecordDownload(account.ClientName, 2048)

	if err := app.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen the same database file: whatever survived is what a restart would see.
	reopened, err := store.Open("sqlite", databasePath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })

	verifyCtx, verifyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer verifyCancel()
	usage, err := reopened.ListTraffic(verifyCtx, &account.ID, 10)
	if err != nil {
		t.Fatalf("list traffic: %v", err)
	}
	var upload, download int64
	for _, row := range usage {
		upload += row.UploadBytes
		download += row.DownloadBytes
	}
	if upload != 4096 || download != 2048 {
		t.Fatalf("persisted traffic = %d/%d, want 4096/2048", upload, download)
	}

}
