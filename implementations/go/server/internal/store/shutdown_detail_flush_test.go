package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// Detail records are queued in memory and written by the periodic flush, so a shutdown that closes
// the database without draining the queue loses every record captured since the last tick.
func TestFlushTrafficDetailsDrainsTheQueuedRecords(t *testing.T) {
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "detail-flush.db"))
	if err != nil {
		t.Fatalf("open temp db: %v", err)
	}
	defer db.Close()
	db.ConfigureTrafficDetailQueue(100, 100)

	ctx := context.Background()
	now := time.Now().UTC()
	// Persisting a detail record resolves the owning client, so the account must exist first.
	if _, err := db.InsertClientIfAbsent(ctx, ClientAccount{
		ID:                           2001,
		TenantID:                     "default",
		OwnerUsername:                "admin",
		ClientName:                   "Demo client",
		PasswordHash:                 "hash",
		Enabled:                      true,
		ConnectionRateLimitPerMinute: 30,
		CreatedAt:                    now,
		UpdatedAt:                    now,
	}); err != nil {
		t.Fatalf("insert client: %v", err)
	}
	db.enqueueHTTPExchange(HTTPExchangeRecord{
		ClientName:   "Demo client",
		Route:        "shutdown-flush",
		Method:       "GET",
		RelativePath: "/shutdown-flush",
		StatusCode:   200,
		StartedAt:    time.Now(),
	})
	db.enqueueTCPFrame(TCPFrameRecord{
		ClientName: "Demo client",
		ListenPort: 10022,
		ChannelID:  "channel-1",
		Direction:  "UPLOAD",
		Payload:    []byte("frame"),
	})

	if err := db.FlushTrafficDetails(ctx); err != nil {
		t.Fatalf("flush traffic details: %v", err)
	}

	exchanges, _, err := db.ListHTTPExchanges(ctx, HTTPExchangeFilter{Page: 0, Size: 10})
	if err != nil {
		t.Fatalf("list http exchanges: %v", err)
	}
	found := false
	for _, item := range exchanges {
		if item.RelativePath == "/shutdown-flush" {
			found = true
		}
	}
	if !found {
		t.Fatal("a queued HTTP detail record must be persisted by the final flush")
	}

	frames, _, err := db.ListTCPFrames(ctx, TCPFrameFilter{Page: 0, Size: 10})
	if err != nil {
		t.Fatalf("list tcp frames: %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("a queued TCP detail record must be persisted by the final flush")
	}
}
