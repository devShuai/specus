package store

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestConnectionRecordSnapshotPreservesPersistedFieldsAndNulls(t *testing.T) {
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "connection-record.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	// Stored timestamps use the shared canonical seven-fractional-digit format.
	stamp := time.Date(2026, 10, 17, 11, 0, 0, 123456700, time.UTC)
	clientID, channel, remote := int64(123), "original-channel", "127.0.0.1:12345"
	for _, original := range []ConnectionRecord{
		{TenantID: "tenant-a", ClientID: &clientID, ClientName: "original-client", ChannelID: &channel, RemoteAddress: &remote, ConnectedAt: stamp, Success: true},
		{TenantID: "default", ClientName: "unknown-client", ConnectedAt: stamp, Success: false},
	} {
		id, err := db.InsertConnectionRecord(ctx, original)
		if err != nil {
			t.Fatal(err)
		}
		original.ID = id
		actual, err := db.GetConnectionRecord(ctx, id)
		if err != nil || !reflect.DeepEqual(actual, &original) {
			t.Fatalf("snapshot mismatch: actual=%+v original=%+v error=%v", actual, original, err)
		}
		when, reason := stamp.Add(time.Second), ReasonClientClosed
		if err := db.MarkDisconnect(ctx, id, reason, when); err != nil {
			t.Fatal(err)
		}
		if err := db.MarkDisconnect(ctx, id, ReasonUnknown, when.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		original.DisconnectedAt, original.DisconnectReason = &when, &reason
		actual, err = db.GetConnectionRecord(ctx, id)
		if err != nil || !reflect.DeepEqual(actual, &original) {
			t.Fatalf("disconnect snapshot changed original fields or first close: actual=%+v original=%+v error=%v", actual, original, err)
		}
	}
	if actual, err := db.GetConnectionRecord(ctx, -1); err != nil || actual != nil {
		t.Fatalf("missing snapshot should not invent a record: %+v %v", actual, err)
	}
}
