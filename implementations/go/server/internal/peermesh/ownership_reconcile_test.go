package peermesh

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/ownership"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

type ownershipRecordingSession struct {
	recordingSession
	failType string
	closes   int
}

func (s *ownershipRecordingSession) Send(packet protocol.Packet) error {
	if response, ok := packet.(protocol.MessageResponse); ok {
		var message ControlMessage
		if err := json.Unmarshal([]byte(response.Message), &message); err != nil {
			return err
		}
		if s.failType != "" && message.Type == s.failType {
			return errors.New("ownership injected send failure")
		}
	}
	return s.recordingSession.Send(packet)
}
func (s *ownershipRecordingSession) Close(string) { s.closes++ }

func (s *ownershipRecordingSession) SendContext(ctx context.Context, packet protocol.Packet) error {
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("missing bounded delivery deadline")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.Send(packet)
}

func transferOwnershipFixture(t *testing.T, f closeCommitFixture, targetID int64, auditID int64) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := f.db.InsertManagementUser(ctx, store.ManagementUser{Username: "bob", TenantID: "tenant-a", Role: store.ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	actor := store.ManagementWriteActor{Username: "admin", TenantID: "tenant-a", Admin: true, BuiltIn: true}
	snapshot, err := f.db.LoadOwnerTransferSnapshot(ctx, "tenant-a", store.OwnerScopeSingle, targetID)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := store.PreviewOwnerTransfer(actor, store.OwnerScopeSingle, targetID, snapshot)
	if err != nil || preview.Revision == nil {
		t.Fatalf("real preview: %+v %v", preview, err)
	}
	request := store.OwnerTransferWrite{Actor: actor, Scope: store.OwnerScopeSingle, PathID: targetID, AuditID: auditID, Body: map[string]any{"scope": store.OwnerScopeSingle, "targetUsername": "bob", "expectedRevision": *preview.Revision}}
	request.BuiltInTarget.Username = "admin"
	request.BuiltInTarget.TenantID = "tenant-a"
	request.BuiltInTarget.Enabled = true
	if out, err := f.db.TransferClientOwnership(ctx, request); err != nil || out.AuditID == nil || !out.Response.AccessRetained {
		t.Fatalf("real transfer: %+v %v", out, err)
	}
}

func TestOwnerNotificationsActualPeerCleanupRetriesAcrossNodes(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "implicit-denied", true: "explicit-preserved"}[explicit], func(t *testing.T) {
			ctx := context.Background()
			f := newCloseCommitFixture(t, 2)
			other := newPeerMeshTestService(f.db)
			for _, id := range f.ids {
				other.cacheRelayAuthorization(*getPeerSession(t, f.db, id), time.Now())
			}
			bound := &ownershipRecordingSession{recordingSession: recordingSession{name: f.source.ClientName}}
			f.service.sessions.Replace(bound)
			missing := insertPeerClient(t, f.db, 3001, "tenant-a", "alice", "no-peer-device")
			missingBound := &ownershipRecordingSession{recordingSession: recordingSession{name: missing.ClientName}}
			f.service.sessions.Replace(missingBound)
			first := getPeerSession(t, f.db, f.ids[0])
			before, err := f.db.FindPeerMeshDeviceByClientID(ctx, "tenant-a", first.TargetClientID)
			if err != nil {
				t.Fatal(err)
			}
			if explicit {
				now := time.Now()
				if err := f.db.InsertPeerMeshACL(ctx, store.PeerMeshACL{ID: 912001, TenantID: "tenant-a", OwnerUsername: "admin", SourceClientID: f.source.ID, SourceClientName: f.source.ClientName, TargetClientID: first.TargetClientID, TargetClientName: first.TargetClientName, Allowed: true, Direction: "OUTBOUND", CreatedAt: now, UpdatedAt: now}); err != nil {
					t.Fatal(err)
				}
			}
			n, err := ownership.New(f.db, f.service, nil)
			if err != nil {
				t.Fatal(err)
			}
			n2, err := ownership.New(f.db, other, nil)
			if err != nil {
				t.Fatal(err)
			}
			transferOwnershipFixture(t, f, first.TargetClientID, 951001)
			count := func() int {
				var count int
				if err := f.raw.QueryRow(`SELECT COUNT(*) FROM client_owner_transfer_receipt WHERE event_id=951001`).Scan(&count); err != nil {
					t.Fatal(err)
				}
				return count
			}
			if !explicit {
				if _, err := f.raw.Exec(`CREATE TRIGGER reject_ownership_close BEFORE UPDATE ON peer_mesh_session WHEN NEW.status='CLOSED' BEGIN SELECT RAISE(ABORT,'ownership close fault'); END`); err != nil {
					t.Fatal(err)
				}
				if err := n.Drain(ctx); err == nil || count() != 0 {
					t.Fatal("SQL cleanup error acknowledged")
				}
				if _, ok := f.service.getCachedSessionToken(first.ID); !ok {
					t.Fatal("failed SQL close evicted token")
				}
				f.service.relayMu.Lock()
				_, cached := f.service.relayAuthorizations[first.ID]
				pending := f.service.pendingRelayBytes[first.ID]
				f.service.relayMu.Unlock()
				if cached || pending != 19 {
					t.Fatal("failed SQL cleanup retained auth or lost counters")
				}
				if _, err := f.raw.Exec(`DROP TRIGGER reject_ownership_close`); err != nil {
					t.Fatal(err)
				}
				bound.failType = TypeClose
				if err := n.Drain(ctx); err == nil || count() != 0 || getPeerSession(t, f.db, first.ID).Status != StatusClosed {
					t.Fatal("failed close delivery acknowledged or SQL uncommitted")
				}
				bound.failType = ""
			}
			if err := n.Drain(ctx); err != nil || count() != 1 {
				t.Fatalf("retry did not acknowledge successful current effects: %v receipts=%d", err, count())
			}
			if err := n2.Drain(ctx); err != nil || count() != 2 {
				t.Fatalf("other node did not independently reconcile: %v receipts=%d", err, count())
			}
			row := getPeerSession(t, f.db, first.ID)
			if (row.Status == StatusClosed) == explicit {
				t.Fatalf("current explicit ACL/default owner policy wrong: %+v", row)
			}
			if !explicit {
				other.relayMu.Lock()
				_, cached := other.relayAuthorizations[first.ID]
				other.relayMu.Unlock()
				if cached {
					t.Fatal("remote node kept stale active cache after SQL was already CLOSED")
				}
			}
			if getPeerSession(t, f.db, f.ids[1]).Status != StatusActive {
				t.Fatal("unrelated valid grant closed")
			}
			after, err := f.db.FindPeerMeshDeviceByClientID(ctx, "tenant-a", first.TargetClientID)
			if err != nil || after.VirtualIP != before.VirtualIP || after.PublicKey == nil || *after.PublicKey != *before.PublicKey || after.Enabled != before.Enabled {
				t.Fatal("reconciliation changed device address/key/switch")
			}
			if row, err := f.db.FindPeerMeshDeviceByClientID(ctx, "tenant-a", missing.ID); err != nil || row != nil {
				t.Fatal("reconciliation provisioned missing Peer device")
			}
			if bound.closes != 0 || missingBound.closes != 0 {
				t.Fatal("management-only transfer disconnected client access")
			}
		})
	}
}

func TestOwnerReconciliationEmptyCredentialGroupHasNoTenantWideEffects(t *testing.T) {
	f := newCloseCommitFixture(t, 1)
	if err := f.service.ReconcileOwnership(context.Background(), "tenant-a", nil); err != nil {
		t.Fatal(err)
	}
	assertCloseNotCommitted(t, f)
}

func TestOwnerReconciliationServiceACLUsesConsumerToPublisherDirection(t *testing.T) {
	for _, reverseOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "consumer-outbound", true: "publisher-outbound-only"}[reverseOnly], func(t *testing.T) {
			ctx := context.Background()
			db := openPeerMeshTestDB(t)
			s := newPeerMeshTestService(db)
			now := time.Now().UTC()
			if err := db.UpsertPeerMeshServiceSharing(ctx, store.PeerMeshServiceSharing{TenantID: "tenant-a", Enabled: true, UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}
			publisher := insertPeerClient(t, db, 6101, "tenant-a", "alice", "ownership-publisher")
			consumer := insertPeerClient(t, db, 6102, "tenant-a", "bob", "ownership-consumer")
			insertPeerDevice(t, db, publisher, "100.96.0.61", "publisher-key")
			insertPeerDevice(t, db, consumer, "100.96.0.62", "consumer-key")
			from, to := consumer, publisher
			if reverseOnly {
				from, to = publisher, consumer
			}
			if err := db.InsertPeerMeshACL(ctx, store.PeerMeshACL{ID: 6201, TenantID: "tenant-a", OwnerUsername: "admin", SourceClientID: from.ID, SourceClientName: from.ClientName, TargetClientID: to.ID, TargetClientName: to.ClientName, Allowed: true, Direction: "OUTBOUND", CreatedAt: now, UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}
			definition := store.PeerMeshSharedService{ID: 6301, TenantID: "tenant-a", ClientID: publisher.ID, ClientName: publisher.ClientName, ServiceID: "ownership-svc", Name: "web", Transport: "tcp", Application: "http", TargetHost: "127.0.0.1", TargetPort: 8080, PublishedPort: 18080, Path: "/", Enabled: true, Visibility: "ACL", AllowedClientIDs: "[]", CreatedAt: now, UpdatedAt: now}
			if err := db.InsertPeerMeshSharedService(ctx, definition); err != nil {
				t.Fatal(err)
			}
			local, err := s.localServicesForChecked(ctx, publisher, 2)
			if err != nil || len(local) != 1 {
				t.Fatalf("local config: %+v %v", local, err)
			}
			expected := []string{}
			if !reverseOnly {
				expected = []string{"100.96.0.62"}
			}
			if !reflect.DeepEqual(local[0].AllowedPeerVirtualIPs, expected) {
				t.Fatalf("source whitelist used reverse ACL: got=%+v want=%+v", local[0].AllowedPeerVirtualIPs, expected)
			}
			bound := &ownershipRecordingSession{recordingSession: recordingSession{name: consumer.ClientName}}
			s.sessions.Replace(bound)
			key := catalogKey{"tenant-a", publisher.ID, 6401}
			if err := db.InsertClientSession(ctx, store.ClientSession{ID: 6401, TenantID: "tenant-a", ClientID: publisher.ID, ClientName: publisher.ClientName, TokenHash: "ownership-session", Status: "NETTY_ONLINE", HTTPLoginAt: now, NettyConnectedAt: &now, ExpiresAt: now.Add(time.Hour), PeerServiceDiscoveryVersion: 2}); err != nil {
				t.Fatal(err)
			}
			s.catalogs[key] = catalogSnapshot{revision: 1, expiresAt: now.Add(time.Hour), services: []AdvertisedService{{ServiceID: definition.ServiceID, Name: "web", Transport: "tcp", Application: "http", PublishedPort: 18080}}}
			clients, err := db.ListClients(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.pushOwnershipCatalogs(ctx, "tenant-a", clients); err != nil {
				t.Fatal(err)
			}
			messages := bound.peerMessages(t)
			if len(messages) != 1 || (len(messages[0].Services) == 1) == reverseOnly {
				t.Fatalf("catalog did not follow consumer ACL: %+v", messages)
			}
			bound.packets = nil
			s.fanoutCatalogMode(ctx, publisher, key.publisherSessionID, 2, s.catalogs[key].services, now.Add(time.Hour), true)
			messages = bound.peerMessages(t)
			if len(messages) != 1 || (len(messages[0].Services) == 1) == reverseOnly {
				t.Fatal("ordinary catalog fanout differs from reconciliation direction")
			}
			bound.packets = nil
			s.pushCurrentCatalogs(ctx, consumer)
			messages = bound.peerMessages(t)
			if len(messages) != 1 || (len(messages[0].Services) == 1) == reverseOnly {
				t.Fatal("login catalog differs from reconciliation direction")
			}
			bound.packets = nil
			if err := db.UpsertPeerMeshServiceSharing(ctx, store.PeerMeshServiceSharing{TenantID: "tenant-a", Enabled: false, UpdatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			if err := s.pushOwnershipCatalogs(ctx, "tenant-a", clients); err != nil {
				t.Fatal(err)
			}
			messages = bound.peerMessages(t)
			if len(messages) != 1 || len(messages[0].Services) != 0 {
				t.Fatal("delayed ownership callback reannounced disabled sharing")
			}
			bound.packets = nil
			if err := db.UpsertPeerMeshServiceSharing(ctx, store.PeerMeshServiceSharing{TenantID: "tenant-a", Enabled: true, UpdatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			if err := db.MarkClientSessionDisconnected(ctx, 6401, "DISCONNECTED", time.Now()); err != nil {
				t.Fatal(err)
			}
			if err := s.pushOwnershipCatalogs(ctx, "tenant-a", clients); err != nil {
				t.Fatal(err)
			}
			messages = bound.peerMessages(t)
			if len(messages) != 1 || len(messages[0].Services) != 0 {
				t.Fatal("delayed ownership callback reannounced offline publisher")
			}
		})
	}
}

func TestOwnerReconciliationUnsupportedTransportIsNotAcknowledged(t *testing.T) {
	f := newCloseCommitFixture(t, 1)
	bound := &recordingSession{name: f.source.ClientName}
	f.service.sessions.Replace(bound)
	if err := f.service.ReconcileOwnership(context.Background(), "tenant-a", []int64{f.source.ID}); err == nil {
		t.Fatal("unbounded delivery adapter treated as successful")
	}
	if len(bound.packets) != 0 {
		t.Fatal("unsupported adapter used unbounded Send fallback")
	}
}
