package peermesh

import (
	"context"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func TestDeletedPublisherWithdrawsCatalogAndRevokesCachedRelayGrant(t *testing.T) {
	ctx := context.Background()
	s, registry, consumer, publisher, consumerSession, _ := newLogoutFixture(t)
	now := time.Now().UTC()
	foreign := insertPeerClient(t, s.db, 1203, "tenant-b", "alice", "other-tenant-client")
	foreignSession := &recordingSession{name: foreign.ClientName}
	registry.Replace(foreignSession)
	insertEgressCapableSession(t, s.db, consumer, 901)
	item := store.PeerMeshSession{ID: 701, TenantID: publisher.TenantID,
		SourceClientID: publisher.ID, SourceClientName: publisher.ClientName,
		TargetClientID: consumer.ID, TargetClientName: consumer.ClientName,
		PathType: PathRelay, Status: StatusActive, StartedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := s.db.InsertPeerMeshSession(ctx, item); err != nil {
		t.Fatal(err)
	}
	s.cacheRelayAuthorization(item, now)
	s.cacheSessionToken(item.ID, "cached-secret")
	s.addPendingRelayBytes(item.ID, 10)
	key := catalogKey{publisher.TenantID, publisher.ID, 801}
	foreignKey := catalogKey{foreign.TenantID, publisher.ID, 802}
	s.catalogs[key] = catalogSnapshot{revision: 3, expiresAt: now.Add(time.Minute), services: []AdvertisedService{{ServiceID: "service-1"}}, mdns: []MdnsCandidate{{Name: "printer"}}}
	s.catalogRevisions[key] = 3
	s.reportRevisions[key] = 3
	s.serviceReportRates[key.publisherSessionID] = []time.Time{now}
	s.catalogs[foreignKey] = catalogSnapshot{revision: 4, expiresAt: now.Add(time.Minute)}
	s.catalogRevisions[foreignKey] = 4
	s.reportRevisions[foreignKey] = 4
	_, closed, err := s.db.DeleteClientAuditedWithPeerSessions(ctx, publisher.ID, "admin", now.Unix(), func(store.HTTPRouteMapping) string { return "private" })
	if err != nil {
		t.Fatal(err)
	}
	// The database is already committed. Cache eviction must use the identity snapshot.
	if _, err := s.db.GetClient(ctx, publisher.ID); err != store.ErrNotFound {
		t.Fatalf("account still present: %v", err)
	}
	s.OnClientDeleted(ctx, publisher, closed)
	assertHasCloseMessage(t, consumerSession.peerMessages(t), item.ID)
	var catalog, roster, egress *ControlMessage
	for _, message := range consumerSession.peerMessages(t) {
		message := message
		switch message.Type {
		case TypeServiceCatalog:
			if message.PublisherClientID == publisher.ID {
				catalog = &message
			}
		case TypeRoster:
			roster = &message
		case ControlTypeEgressCatalog:
			egress = &message
		}
	}
	if catalog == nil || catalog.PublisherSessionID == nil || *catalog.PublisherSessionID != 801 ||
		catalog.Revision == nil || *catalog.Revision <= 3 || len(catalog.Services) != 0 {
		t.Fatalf("publisher catalogue was not withdrawn: %+v", catalog)
	}
	if roster == nil {
		t.Fatal("survivor received no roster")
	}
	for _, peer := range roster.Peers {
		if peer.ClientID == publisher.ID {
			t.Fatalf("deleted device remains in roster: %+v", roster.Peers)
		}
	}
	if egress == nil || len(egress.Egresses) != 0 {
		t.Fatalf("egress catalogue not refreshed: %+v", egress)
	}
	if _, found := s.relayAuthorizations[item.ID]; found {
		t.Fatal("relay authorization retained")
	}
	if _, found := s.getCachedSessionToken(item.ID); found {
		t.Fatal("session token retained")
	}
	if _, found := s.pendingRelayBytes[item.ID]; found {
		t.Fatal("pending relay state retained")
	}
	if len(s.catalogs) != 1 || len(s.catalogRevisions) != 1 || len(s.reportRevisions) != 1 || len(s.serviceReportRates) != 0 {
		t.Fatal("publisher state retained or foreign state removed")
	}
	if len(foreignSession.packets) != 0 {
		t.Fatal("deletion notified another tenant")
	}
}

func TestDeletedLastServiceRecipientPushesDisabledDefinitionToPublisher(t *testing.T) {
	ctx := context.Background()
	s, _, consumer, publisher, _, publisherSession := newLogoutFixture(t)
	now := time.Now().UTC()
	if err := s.db.InsertPeerMeshSharedService(ctx, store.PeerMeshSharedService{ID: 702,
		TenantID: publisher.TenantID, ClientID: publisher.ID, ClientName: publisher.ClientName,
		ServiceID: "service-2", Name: "test", Transport: "tcp", Application: "tcp", TargetHost: "127.0.0.1",
		TargetPort: 80, PublishedPort: 18080, Enabled: true, Visibility: "ACL", AllowedClientIDs: "1201", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	_, closed, err := s.db.DeleteClientAuditedWithPeerSessions(ctx, consumer.ID, "admin", now.Unix(), func(store.HTTPRouteMapping) string { return "private" })
	if err != nil {
		t.Fatal(err)
	}
	s.OnClientDeleted(ctx, consumer, closed)
	var config *LoginConfig
	for _, message := range publisherSession.peerMessages(t) {
		if message.Type == TypeConfig {
			config = message.PeerMesh
		}
	}
	if config == nil {
		t.Fatal("publisher did not receive updated config")
	}
	for _, service := range config.LocalServices {
		if service.ServiceID == "service-2" && service.Enabled {
			t.Fatal("publisher retained enabled service after last recipient deletion")
		}
	}
}
