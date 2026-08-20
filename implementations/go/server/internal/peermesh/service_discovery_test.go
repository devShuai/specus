package peermesh

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func TestValidateServiceReportEnvelopeRejectsClientControlledRoutingAndIdentity(t *testing.T) {
	valid := protocol.MessageRequest{Message: `{"type":"service-report","enabled":true,"revision":1,"services":[]}`}
	if err := validateServiceReportEnvelope(valid); err != nil {
		t.Fatalf("valid envelope: %v", err)
	}
	targeted := valid
	targeted.ToClientName = "peer-b"
	if err := validateServiceReportEnvelope(targeted); err == nil {
		t.Fatal("targeted service-report was accepted")
	}
	for _, field := range []string{
		"sourceClientId", "sourceClientName", "sourceVirtualIp", "sourcePublicKey", "sourceKeyEpoch",
		"targetClientId", "targetClientName", "targetVirtualIp", "targetPublicKey",
		"sessionId", "token", "publisherClientId", "publisherClientName", "publisherSessionId",
	} {
		request := valid
		request.Message = fmt.Sprintf(`{"type":"service-report","enabled":true,"revision":1,"services":[],%q:null}`, field)
		if err := validateServiceReportEnvelope(request); err == nil {
			t.Errorf("field %s was accepted", field)
		}
	}
}

func TestServiceReportWithdrawalKeepsRevisionTombstoneAndServerTTL(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	registry := session.NewRegistry()
	service := New(config.PeerMeshConfig{Enabled: true, CIDR: "100.96.0.0/11", SessionTTLSeconds: 3600}, db, registry, nil)
	publisher := insertPeerClient(t, db, 3020, "tenant-a", "alice", "alice-laptop")
	recipient := insertPeerClient(t, db, 3021, "tenant-a", "alice", "alice-nas")
	insertPeerDevice(t, db, publisher, "100.96.0.20", "publisher-key")
	insertPeerDevice(t, db, recipient, "100.96.0.21", "recipient-key")
	now := time.Now().UTC()
	if err := db.InsertClientSession(ctx, store.ClientSession{
		ID: sessionIDForTest, TenantID: publisher.TenantID, ClientID: publisher.ID,
		ClientName: publisher.ClientName, TokenHash: "peer-service-test", Status: "NETTY_ONLINE",
		MachineFingerprint: "machine", OSUser: "user", PeerServiceDiscoveryVersion: 2,
		HTTPLoginAt: now, NettyConnectedAt: &now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	recipientSession := &recordingSession{name: recipient.ClientName}
	registry.Replace(recipientSession)
	if _, err := service.SetSharing(ctx, AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true}, true); err != nil {
		t.Fatal(err)
	}
	name, app, host := "web", "http", "127.0.0.1"
	targetPort, publishedPort, enabled := 8080, 18080, true
	created, err := service.CreateSharedService(ctx, AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true}, ServiceMutation{
		ClientID: &publisher.ID, Name: &name, Application: &app, TargetHost: &host,
		TargetPort: &targetPort, PublishedPort: &publishedPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UpdateSharedService(ctx, AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true}, created.ID, ServiceMutation{Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	sessionID := int64(sessionIDForTest)
	revision2 := int64(2)
	report := ControlMessage{Type: TypeServiceReport, Enabled: boolPtr(true), Revision: &revision2,
		Services: []AdvertisedService{{ServiceID: created.ServiceID}}}
	if err := service.handleServiceReport(ctx, publisher, report, sessionID); err != nil {
		t.Fatal(err)
	}
	recipientSession.packets = nil
	service.PushOnLogin(ctx, recipient)
	loginMessages := recipientSession.peerMessages(t)
	foundCurrentCatalog := false
	for _, message := range loginMessages {
		if message.Type == TypeServiceCatalog && message.PublisherClientID == publisher.ID &&
			message.PublisherSessionID != nil && *message.PublisherSessionID == sessionID &&
			message.Revision != nil && *message.Revision == revision2 && len(message.Services) == 1 {
			foundCurrentCatalog = true
			break
		}
	}
	if !foundCurrentCatalog {
		t.Fatalf("login did not receive current service catalog: %#v", loginMessages)
	}
	service.catalogMu.Lock()
	snapshot := service.catalogs[catalogKey{publisher.TenantID, publisher.ID, sessionID}]
	service.catalogMu.Unlock()
	if snapshot.expiresAt.After(time.Now().Add(5*time.Minute + time.Second)) {
		t.Fatalf("server accepted client-controlled TTL: %s", snapshot.expiresAt)
	}
	revision3 := int64(3)
	report.Revision = &revision3
	report.Enabled = boolPtr(false)
	if err := service.handleServiceReport(ctx, publisher, report, sessionID); err != nil {
		t.Fatal(err)
	}
	report.Revision = &revision2
	report.Enabled = boolPtr(true)
	if err := service.handleServiceReport(ctx, publisher, report, sessionID); err != nil {
		t.Fatal(err)
	}
	service.catalogMu.Lock()
	_, revived := service.catalogs[catalogKey{publisher.TenantID, publisher.ID, sessionID}]
	service.catalogMu.Unlock()
	if revived {
		t.Fatal("stale report revived withdrawn catalog")
	}
	service.OnClientDisconnected(ctx, publisher.ClientName, sessionID)
	service.catalogMu.Lock()
	_, revisionTracked := service.catalogRevisions[catalogKey{publisher.TenantID, publisher.ID, sessionID}]
	_, rateTracked := service.serviceReportRates[sessionID]
	service.catalogMu.Unlock()
	if revisionTracked || rateTracked {
		t.Fatal("disconnect retained bounded service-report state")
	}
}

const sessionIDForTest = 99

func boolPtr(value bool) *bool { return &value }

func TestSharingDefaultsOffAndRejectsPublicTarget(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	service := New(config.PeerMeshConfig{Enabled: true, CIDR: "100.96.0.0/11", SessionTTLSeconds: 3600}, db, session.NewRegistry(), nil)
	access := AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true}

	status, err := service.SharingStatus(ctx, access)
	if err != nil {
		t.Fatal(err)
	}
	if status.ConfiguredEnabled || status.EffectiveEnabled || status.EnabledServiceCount != 0 {
		t.Fatalf("sharing should default off: %+v", status)
	}

	user := AccessContext{Username: "alice", TenantID: "tenant-a", Admin: false}
	if _, err := service.SetSharing(ctx, user, true); err == nil {
		t.Fatal("expected forbidden")
	}

	disabled := New(config.PeerMeshConfig{Enabled: false, CIDR: "100.96.0.0/11"}, db, session.NewRegistry(), nil)
	if _, err := disabled.SetSharing(ctx, access, true); err == nil {
		t.Fatal("expected deployment disabled error")
	}

	account := insertPeerClient(t, db, 3001, "tenant-a", "alice", "alice-laptop")
	host := "evil.example"
	name := "web"
	app := "http"
	port := 80
	published := 8080
	_, err = service.CreateSharedService(ctx, access, ServiceMutation{
		ClientID: &account.ID, Name: &name, Application: &app, TargetHost: &host, TargetPort: &port, PublishedPort: &published,
	})
	if err == nil {
		t.Fatal("expected public target host rejection")
	}

	local := "127.0.0.1"
	view, err := service.CreateSharedService(ctx, access, ServiceMutation{
		ClientID: &account.ID, Name: &name, Application: &app, TargetHost: &local, TargetPort: &port, PublishedPort: &published,
	})
	if err != nil {
		t.Fatal(err)
	}
	if view.Enabled {
		t.Fatal("new services must default disabled")
	}
	if view.TargetHost == nil || *view.TargetHost != "127.0.0.1" {
		t.Fatalf("admin view should include targetHost: %+v", view)
	}
}

func TestLoginConfigIncludesOwnerLocalServices(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	service := New(config.PeerMeshConfig{Enabled: true, CIDR: "100.96.0.0/11", SessionTTLSeconds: 3600}, db, session.NewRegistry(), nil)
	access := AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true}
	account := insertPeerClient(t, db, 3002, "tenant-a", "alice", "alice-laptop")
	local := "127.0.0.1"
	name := "ssh"
	app := "ssh"
	port := 22
	published := 2222
	if _, err := service.CreateSharedService(ctx, access, ServiceMutation{
		ClientID: &account.ID, Name: &name, Application: &app, TargetHost: &local, TargetPort: &port, PublishedPort: &published,
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := service.BuildLoginConfig(ctx, account, "", "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.LocalServices) != 1 {
		t.Fatalf("localServices = %#v", cfg.LocalServices)
	}
	if cfg.LocalServices[0].TargetHost != "127.0.0.1" || cfg.LocalServices[0].TargetPort != 22 {
		t.Fatalf("owner config must include target: %+v", cfg.LocalServices[0])
	}
	legacy, err := service.BuildLoginConfig(ctx, account, "", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(legacy.LocalServices) != 0 {
		t.Fatalf("v1 client must not receive services without data-plane ACL: %#v", legacy.LocalServices)
	}
}

func TestLoginConfigIncludesOnlyAuthorizedPeerVirtualIPs(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	service := New(config.PeerMeshConfig{Enabled: true, CIDR: "100.96.0.0/11", SessionTTLSeconds: 3600}, db, session.NewRegistry(), nil)
	access := AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true}
	publisher := insertPeerClient(t, db, 3010, "tenant-a", "alice", "alice-laptop")
	allowed := insertPeerClient(t, db, 3011, "tenant-a", "alice", "alice-nas")
	denied := insertPeerClient(t, db, 3012, "tenant-a", "bob", "bob-pc")
	insertPeerDevice(t, db, publisher, "100.96.0.10", "publisher-key")
	insertPeerDevice(t, db, allowed, "100.96.0.11", "allowed-key")
	insertPeerDevice(t, db, denied, "100.96.0.12", "denied-key")
	name, app, host, visibility := "web", "http", "127.0.0.1", "OWNER"
	targetPort, publishedPort, enabled := 8080, 18080, true
	created, err := service.CreateSharedService(ctx, access, ServiceMutation{
		ClientID: &publisher.ID, Name: &name, Application: &app, TargetHost: &host,
		TargetPort: &targetPort, PublishedPort: &publishedPort, Visibility: &visibility,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UpdateSharedService(ctx, access, created.ID, ServiceMutation{Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	cfg, err := service.BuildLoginConfig(ctx, publisher, "", "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.LocalServices) != 1 || len(cfg.LocalServices[0].AllowedPeerVirtualIPs) != 1 || cfg.LocalServices[0].AllowedPeerVirtualIPs[0] != "100.96.0.11" {
		t.Fatalf("allowedPeerVirtualIps = %#v", cfg.LocalServices)
	}
}

func TestUdpAndAclAndMdnsDefaults(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	service := New(config.PeerMeshConfig{Enabled: true, CIDR: "100.96.0.0/11", SessionTTLSeconds: 3600}, db, session.NewRegistry(), nil)
	access := AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true}
	account := insertPeerClient(t, db, 3003, "tenant-a", "alice", "alice-laptop")
	name := "dns"
	app := "udp"
	tcp := "tcp"
	host := "127.0.0.1"
	port := 53
	if _, err := service.CreateSharedService(ctx, access, ServiceMutation{
		ClientID: &account.ID, Name: &name, Transport: &tcp, Application: &app, TargetHost: &host, TargetPort: &port, PublishedPort: &port,
	}); err == nil {
		t.Fatal("udp application must reject tcp transport")
	}
	udp := "udp"
	view, err := service.CreateSharedService(ctx, access, ServiceMutation{
		ClientID: &account.ID, Name: &name, Transport: &udp, Application: &app, TargetHost: &host, TargetPort: &port, PublishedPort: &port,
	})
	if err != nil {
		t.Fatal(err)
	}
	if view.Transport != "udp" {
		t.Fatalf("transport=%s", view.Transport)
	}
	status, err := service.SharingStatus(ctx, access)
	if err != nil {
		t.Fatal(err)
	}
	if status.MdnsImportEnabled {
		t.Fatal("mdns import must default off")
	}
	allowed := []int64{9}
	visibility := "ACL"
	if _, err := service.UpdateSharedService(ctx, access, view.ID, ServiceMutation{Visibility: &visibility, AllowedClientIDs: allowed}); err != nil {
		t.Fatal(err)
	}
	items, err := service.ListSharedServices(ctx, access)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || len(items[0].AllowedClientIDs) != 1 || items[0].AllowedClientIDs[0] != 9 {
		t.Fatalf("allowedClientIds=%v", items)
	}
}

func TestRequireTargetHostAcceptsLoopbackOnly(t *testing.T) {
	if _, err := requireTargetHost("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := requireTargetHost("http://127.0.0.1"); err == nil {
		t.Fatal("url should be rejected")
	}
	if _, err := requirePath("javascript:alert(1)", "http"); err == nil {
		t.Fatal("script path should be rejected")
	}
}
