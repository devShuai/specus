package server

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func TestConnectionEventPublicationUsesPersistedPrecisionAndIdentity(t *testing.T) {
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "event-snapshot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	stamp := time.Date(2026, 10, 17, 11, 0, 0, 123456789, time.FixedZone("fixture-offset", 8*3600))
	clientID, channelID, remote := int64(123), "persisted-channel", "127.0.0.1:23456"
	id, err := db.InsertConnectionRecord(ctx, store.ConnectionRecord{
		TenantID: "tenant-a", ClientID: &clientID, ClientName: "persisted-client", ChannelID: &channelID,
		RemoteAddress: &remote, ConnectedAt: stamp, Success: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	var events []store.ConnectionRecord
	d := &Dispatcher{db: db, logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		onConnectionEvent: func(kind string, record store.ConnectionRecord) {
			kinds = append(kinds, kind)
			events = append(events, record)
		}}
	d.publishConnectionRecord(ctx, "created", id, channelID)
	when, reason := stamp.Add(time.Second), store.ReasonClientClosed
	if err := db.MarkDisconnect(ctx, id, reason, when); err != nil {
		t.Fatal(err)
	}
	d.publishConnectionRecord(ctx, "updated", id, channelID)
	d.publishConnectionRecord(ctx, "updated", -1, channelID)
	if !reflect.DeepEqual(kinds, []string{"created", "updated"}) {
		t.Fatalf("missing audit row emitted a phantom event: %v", kinds)
	}
	for _, event := range events {
		if event.ClientID == nil || *event.ClientID != clientID || event.RemoteAddress == nil || *event.RemoteAddress != remote ||
			event.ChannelID == nil || *event.ChannelID != channelID || event.TenantID != "tenant-a" || event.ClientName != "persisted-client" ||
			!event.Success || !event.ConnectedAt.Equal(stamp.UTC().Truncate(100*time.Nanosecond)) {
			t.Fatalf("event did not retain canonical persisted snapshot: %+v", event)
		}
	}
	if events[0].DisconnectedAt != nil || events[0].DisconnectReason != nil || events[1].DisconnectedAt == nil ||
		!events[1].DisconnectedAt.Equal(when.UTC().Truncate(100*time.Nanosecond)) || events[1].DisconnectReason == nil || *events[1].DisconnectReason != reason {
		t.Fatalf("event did not reflect its persisted lifecycle state: %+v", events)
	}
}
