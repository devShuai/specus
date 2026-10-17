package peermesh

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func TestServerOwnedCatalogRevisionsSurviveHugeReportsAndSessionCleanup(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	registry := session.NewRegistry()
	service := New(config.PeerMeshConfig{Enabled: true, CIDR: "100.96.0.0/11", SessionTTLSeconds: 3600}, db, registry, nil)
	publisher := insertPeerClient(t, db, 7301, "tenant-revision", "alice", "revision-publisher")
	recipient := insertPeerClient(t, db, 7302, "tenant-revision", "alice", "revision-consumer")
	insertPeerDevice(t, db, publisher, "100.96.0.31", "publisher-key")
	insertPeerDevice(t, db, recipient, "100.96.0.32", "consumer-key")
	now := time.Now().UTC()
	const sid int64 = 7381
	if err := db.InsertClientSession(ctx, store.ClientSession{ID: sid, TenantID: publisher.TenantID, ClientID: publisher.ID, ClientName: publisher.ClientName, TokenHash: "revision-fixture", Status: "NETTY_ONLINE", MachineFingerprint: "revision", OSUser: "revision", PeerServiceDiscoveryVersion: 2, HTTPLoginAt: now, NettyConnectedAt: &now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	recipientSession := &recordingSession{name: recipient.ClientName}
	registry.Replace(recipientSession)
	admin := AccessContext{Username: "admin", TenantID: publisher.TenantID, Admin: true}
	if _, err := service.SetSharing(ctx, admin, true); err != nil {
		t.Fatal(err)
	}
	name, app, host := "revision-service", "http", "127.0.0.1"
	targetPort, publishedPort, enabled := 8080, 18080, true
	definition, err := service.CreateSharedService(ctx, admin, ServiceMutation{ClientID: &publisher.ID, Name: &name, Application: &app, TargetHost: &host, TargetPort: &targetPort, PublishedPort: &publishedPort})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.UpdateSharedService(ctx, admin, definition.ID, ServiceMutation{Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	recipientSession.packets = nil
	var wire []string
	capture := func(expected int64, count int) {
		t.Helper()
		found := 0
		for _, packet := range recipientSession.packets {
			response, ok := packet.(protocol.MessageResponse)
			if !ok {
				t.Fatalf("unexpected packet %T", packet)
			}
			var message ControlMessage
			if err := json.Unmarshal([]byte(response.Message), &message); err != nil {
				t.Fatal(err)
			}
			if message.Type != TypeServiceCatalog {
				continue
			}
			found++
			if message.Revision == nil || *message.Revision != expected || len(message.Services) != count {
				t.Fatalf("catalog=%s expected revision=%d services=%d", response.Message, expected, count)
			}
			wire = append(wire, response.Message)
		}
		if found != 1 {
			t.Fatalf("catalog count=%d", found)
		}
		recipientSession.packets = nil
	}
	report := func(revision int64) {
		t.Helper()
		if err := service.handleServiceReport(ctx, publisher, ControlMessage{Type: TypeServiceReport, Enabled: boolPtr(true), Revision: &revision, Services: []AdvertisedService{{ServiceID: definition.ServiceID}}}, sid); err != nil {
			t.Fatal(err)
		}
	}
	report(math.MaxInt64 - 1)
	capture(1, 1)
	report(math.MaxInt64)
	capture(2, 1)
	report(math.MaxInt64)
	report(math.MaxInt64 - 1)
	if len(recipientSession.packets) != 0 {
		t.Fatal("duplicate reports emitted catalog data")
	}
	if _, err := service.SetSharing(ctx, admin, false); err != nil {
		t.Fatal(err)
	}
	capture(3, 0)
	if err := db.MarkClientSessionDisconnected(ctx, sid, "DISCONNECTED", time.Now()); err != nil {
		t.Fatal(err)
	}
	service.OnClientDisconnected(ctx, publisher.ClientName, sid)
	capture(4, 0)
	key := catalogKey{publisher.TenantID, publisher.ID, sid}
	if len(service.catalogRevisions) != 0 || len(service.reportRevisions) != 0 {
		t.Fatal("session cleanup leaked bounded revision slots")
	}
	if err := db.MarkClientSessionOnline(ctx, sid, "NETTY_ONLINE", "new-control", "127.0.0.1", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetSharing(ctx, admin, true); err != nil {
		t.Fatal(err)
	}
	recipientSession.packets = nil
	report(1)
	capture(5, 1)
	service.catalogMu.Lock()
	service.catalogSequence = math.MaxInt64
	service.catalogMu.Unlock()
	revision, accepted := service.acceptReportRevision(key, 2)
	if accepted || revision != 0 || service.catalogRevisions[key] != 5 || service.reportRevisions[key] != 1 {
		t.Fatal("exhausted server clock wrapped or changed accepted state")
	}
	if directory := os.Getenv("SPECUS_TEST_CATALOG_REVISION_WIRE_DIR"); directory != "" {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "go.jsonl"), []byte(strings.Join(wire, "\n")+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
