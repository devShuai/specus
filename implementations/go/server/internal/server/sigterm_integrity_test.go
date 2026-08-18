package server

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// newSignalShutdownApp builds an app the test owns end to end. startTestApp registers its own
// cancel and Close cleanups, which is the opposite of what a shutdown test needs: here the test has
// to decide exactly when the context is cancelled and when Close runs.
func newSignalShutdownApp(t *testing.T) (*App, context.CancelFunc, <-chan error, string) {
	t.Helper()
	cfg := config.Default()
	cfg.Env = "test"
	cfg.Auth.Password = "admin"
	cfg.Netty.Port = 0
	cfg.ManagementAddr = "127.0.0.1:0"
	cfg.ConnectionString = filepath.Join(t.TempDir(), "sigterm.db")
	// A long flush interval guarantees the periodic flush never fires, so anything on disk at the
	// end got there through the shutdown path and not by luck of timing.
	cfg.Traffic.CaptureFlushIntervalMs = 600_000

	app, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for app.ControlPort() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if app.ControlPort() == 0 {
		cancel()
		_ = app.Close()
		t.Fatal("control channel never bound")
	}
	return app, cancel, done, cfg.ConnectionString
}

// This is the shape of a real SIGTERM: main's signal.NotifyContext cancels the context Run is
// serving on, Run unwinds, and the deferred Close follows. Traffic buffered since the last periodic
// flush has to survive that sequence — an operator restarting the service must not pay for it in
// lost accounting.
func TestSignalShapedShutdownPersistsTrafficBufferedSinceTheLastFlush(t *testing.T) {
	app, cancel, done, databasePath := newSignalShutdownApp(t)

	lookupCtx, lookupCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer lookupCancel()
	account, err := app.DB().FindClientByName(lookupCtx, DemoClientName)
	if err != nil || account == nil {
		t.Fatalf("find demo client: %v", err)
	}

	app.traffic.RecordUpload(account.ClientName, 8192)
	app.traffic.RecordDownload(account.ClientName, 1024)

	// SIGTERM: cancel, wait for Run to unwind, then Close as main's defer does.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
	if err := app.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen the file: this is exactly what the next start would see.
	reopened := reopenStoreAfterShutdown(t, databasePath)

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
	if upload != 8192 || download != 1024 {
		t.Fatalf("persisted traffic = %d/%d, want 8192/1024", upload, download)
	}
}

// reopenStoreAfterShutdown opens the database file a restart would inherit. Goroutines unwinding
// from the cancelled context can still be handing their SQLite connections back for a moment after
// Close returns, so a brief SQLITE_BUSY is retried rather than failed on.
func reopenStoreAfterShutdown(t *testing.T, databasePath string) *store.DB {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		reopened, err := store.Open("sqlite", databasePath)
		if err == nil {
			t.Cleanup(func() { _ = reopened.Close() })
			return reopened
		}
		if time.Now().After(deadline) {
			t.Fatalf("reopen store: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Shutting down twice, or shutting down without ever having served traffic, must stay clean: the
// signal path runs on a process that may already be tearing down.
func TestShutdownIsIdempotentAndSafeWithNothingBuffered(t *testing.T) {
	app, cancel, done, _ := newSignalShutdownApp(t)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
	// A second cancel is what a repeated SIGTERM looks like.
	cancel()

	if err := app.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	// The database is gone now, so a second Close must report the closed database rather than
	// panicking or hanging.
	closed := make(chan error, 1)
	go func() { closed <- app.Close() }()
	select {
	case <-closed:
	case <-time.After(15 * time.Second):
		t.Fatal("a second Close hung")
	}
}
