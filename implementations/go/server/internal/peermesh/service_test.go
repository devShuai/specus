package peermesh

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/config"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/protocol"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/session"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/store"
)

func TestHandleSignalCandidatesCreatesGrantAndForwardsJavaShape(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	registry := session.NewRegistry()
	service := New(config.PeerMeshConfig{
		Enabled:           true,
		CIDR:              "100.96.0.0/11",
		PublicAddress:     "203.0.113.10",
		StunTurnPort:      3478,
		SessionTTLSeconds: 3600,
	}, db, registry, nil)

	source := insertPeerClient(t, db, 1001, "tenant-a", "alice", "alice-laptop")
	target := insertPeerClient(t, db, 1002, "tenant-a", "alice", "alice-nas")
	insertPeerDevice(t, db, source, "100.96.0.10", "source-key")
	insertPeerDevice(t, db, target, "100.96.0.11", "target-key")

	sourceSession := &recordingSession{name: source.ClientName}
	targetSession := &recordingSession{name: target.ClientName}
	registry.Replace(sourceSession)
	registry.Replace(targetSession)

	body, err := json.Marshal(ControlMessage{
		Type: TypeCandidates,
		Candidates: []Candidate{{
			Type:      "host",
			Transport: "udp",
			Address:   "192.168.1.10",
			Port:      53000,
		}},
	})
	if err != nil {
		t.Fatalf("marshal signal: %v", err)
	}
	err = service.HandleSignal(ctx, protocol.MessageRequest{
		ToClientName: target.ClientName,
		MessageType:  protocol.MessageTypePeerControl,
		Message:      string(body),
	}, source.ClientName)
	if err != nil {
		t.Fatalf("handle candidates signal: %v", err)
	}

	grant := decodeOnlyPeerMessage(t, sourceSession)
	if grant.Type != TypeSessionGrant {
		t.Fatalf("source message type = %q, want %q: %+v", grant.Type, TypeSessionGrant, grant)
	}
	if grant.SessionID == nil || grant.Token == "" || grant.ExpiresAt == "" ||
		grant.PathType != PathDirect || grant.Status != StatusNegotiating {
		t.Fatalf("session grant missing Java-shaped session fields: %+v", grant)
	}
	if grant.SourceClientID != source.ID || grant.SourceClientName != source.ClientName ||
		grant.SourceVirtualIP != "100.96.0.10" || grant.SourcePublicKey == nil || *grant.SourcePublicKey != "source-key" {
		t.Fatalf("session grant source identity mismatch: %+v", grant)
	}
	if grant.TargetClientID != target.ID || grant.TargetClientName != target.ClientName ||
		grant.TargetVirtualIP != "100.96.0.11" || grant.TargetPublicKey == nil || *grant.TargetPublicKey != "target-key" {
		t.Fatalf("session grant target identity mismatch: %+v", grant)
	}

	forwarded := decodeOnlyPeerMessage(t, targetSession)
	if forwarded.Type != TypeCandidates {
		t.Fatalf("target message type = %q, want %q: %+v", forwarded.Type, TypeCandidates, forwarded)
	}
	if forwarded.SessionID == nil || grant.SessionID == nil || *forwarded.SessionID != *grant.SessionID ||
		forwarded.Token != grant.Token || forwarded.ExpiresAt != grant.ExpiresAt {
		t.Fatalf("forwarded signal did not reuse grant fields: grant=%+v forwarded=%+v", grant, forwarded)
	}
	if forwarded.SourceClientID != source.ID || forwarded.SourceVirtualIP != "100.96.0.10" ||
		forwarded.TargetClientID != target.ID || forwarded.TargetVirtualIP != "100.96.0.11" {
		t.Fatalf("forwarded signal identity mismatch: %+v", forwarded)
	}

	sessions, err := db.ListPeerMeshSessions(ctx, "tenant-a", 10)
	if err != nil {
		t.Fatalf("list peer sessions: %v", err)
	}
	if len(sessions) != 1 || sessions[0].ID != *grant.SessionID ||
		sessions[0].SourceClientID != source.ID || sessions[0].TargetClientID != target.ID ||
		sessions[0].PathType != PathDirect || sessions[0].Status != StatusNegotiating {
		t.Fatalf("persisted session mismatch: %+v", sessions)
	}
}

func TestPushOnLoginRefreshesRosterForTenantPeers(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	registry := session.NewRegistry()
	service := New(config.PeerMeshConfig{
		Enabled:           true,
		CIDR:              "100.96.0.0/11",
		PublicAddress:     "203.0.113.10",
		StunTurnPort:      3478,
		SessionTTLSeconds: 3600,
	}, db, registry, nil)

	source := insertPeerClient(t, db, 1101, "tenant-a", "alice", "alice-laptop")
	target := insertPeerClient(t, db, 1102, "tenant-a", "alice", "alice-nas")
	insertPeerDevice(t, db, source, "100.96.0.10", "source-key")
	insertPeerDevice(t, db, target, "100.96.0.11", "target-key")

	sourceSession := &recordingSession{name: source.ClientName}
	targetSession := &recordingSession{name: target.ClientName}
	registry.Replace(sourceSession)
	registry.Replace(targetSession)

	service.PushOnLogin(ctx, source)

	sourceMessages := sourceSession.peerMessages(t)
	var configMessage *ControlMessage
	var sourceRoster *ControlMessage
	for i := range sourceMessages {
		switch sourceMessages[i].Type {
		case TypeConfig:
			configMessage = &sourceMessages[i]
		case TypeRoster:
			sourceRoster = &sourceMessages[i]
		}
	}
	if configMessage == nil {
		t.Fatalf("source did not receive peer config: %+v", sourceMessages)
	}
	if configMessage.TargetClientID != source.ID || configMessage.TargetClientName != source.ClientName {
		t.Fatalf("peer config target fields mismatch: %+v", configMessage)
	}
	if sourceRoster == nil || !rosterContains(sourceRoster.Peers, target.ID, target.ClientName, true) {
		t.Fatalf("source roster missing online target: %+v", sourceRoster)
	}

	targetMessages := targetSession.peerMessages(t)
	var targetRoster *ControlMessage
	for i := range targetMessages {
		if targetMessages[i].Type == TypeRoster {
			targetRoster = &targetMessages[i]
			break
		}
	}
	if targetRoster == nil || !rosterContains(targetRoster.Peers, source.ID, source.ClientName, true) {
		t.Fatalf("target roster missing online source: %+v", targetMessages)
	}
}

func TestRuntimeConfigUsesIndependentStandaloneStunEndpoint(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	service := New(config.PeerMeshConfig{
		Enabled:               true,
		CIDR:                  "100.96.0.0/11",
		PublicAddress:         "turn.example.com",
		StunTurnPort:          3478,
		StandaloneStunAddress: "stun.example.com",
		StandaloneStunPort:    5349,
		SessionTTLSeconds:     3600,
	}, db, session.NewRegistry(), nil)
	account := insertPeerClient(t, db, 1151, "tenant-a", "alice", "alice-tablet")
	insertPeerDevice(t, db, account, "100.96.0.18", "public-key")

	runtimeConfig, err := service.BuildRuntimeConfig(ctx, account)
	if err != nil {
		t.Fatalf("build runtime config: %v", err)
	}
	if runtimeConfig.StunHost != "stun.example.com" || runtimeConfig.StunPort != 5349 {
		t.Fatalf("runtime STUN endpoint = %s:%d, want stun.example.com:5349",
			runtimeConfig.StunHost, runtimeConfig.StunPort)
	}
	if runtimeConfig.TurnHost != "turn.example.com" || runtimeConfig.TurnPort != 3478 {
		t.Fatalf("runtime TURN endpoint = %s:%d, want turn.example.com:3478",
			runtimeConfig.TurnHost, runtimeConfig.TurnPort)
	}

	publicConfig := service.PublicStunConfig("ignored.example.com")
	if publicConfig.SelfHostedStunServer != "stun:stun.example.com:5349" {
		t.Fatalf("public self-hosted STUN = %q", publicConfig.SelfHostedStunServer)
	}
	if publicConfig.StunTurnPort != 3478 {
		t.Fatalf("legacy stunTurnPort = %d, want TURN port 3478", publicConfig.StunTurnPort)
	}
}

func TestPublicStunConfigSupportsIndependentDeploymentAndLegacyFallback(t *testing.T) {
	standalone := New(config.PeerMeshConfig{
		Enabled:               false,
		PublicAddress:         "turn.example.com",
		StunTurnPort:          4444,
		StandaloneStunAddress: "stun.example.com",
		StandaloneStunPort:    5349,
	}, nil, nil, nil).PublicStunConfig("ignored.example.com")
	if standalone.PeerMeshEnabled {
		t.Fatal("standalone STUN config unexpectedly enabled peer mesh")
	}
	if standalone.SelfHostedStunServer != "stun:stun.example.com:5349" ||
		len(standalone.StunServers) != 1 || standalone.StunServers[0] != standalone.SelfHostedStunServer {
		t.Fatalf("standalone STUN was not published while peer mesh was disabled: %+v", standalone)
	}
	if standalone.StunTurnPort != 4444 {
		t.Fatalf("standalone response changed legacy TURN port: %+v", standalone)
	}

	legacy := New(config.PeerMeshConfig{
		Enabled:            true,
		PublicAddress:      "relay.example.com",
		StunTurnPort:       4444,
		StandaloneStunPort: 5349,
	}, nil, nil, nil).PublicStunConfig("ignored.example.com")
	if legacy.SelfHostedStunServer != "stun:relay.example.com:4444" {
		t.Fatalf("legacy endpoint did not retain stunTurnPort: %+v", legacy)
	}

	partial := New(config.PeerMeshConfig{
		Enabled:               true,
		PublicAddress:         "relay.example.com",
		StunTurnPort:          4444,
		StandaloneStunAddress: "stun.example.com",
		StandaloneStunPort:    0,
	}, nil, nil, nil).PublicStunConfig("ignored.example.com")
	if partial.SelfHostedStunServer != "stun:relay.example.com:4444" {
		t.Fatalf("incomplete standalone endpoint did not fall back as a unit: %+v", partial)
	}
}

func TestDeviceReportPersistsNatBehaviorFields(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	service := newPeerMeshTestService(db)
	account := insertPeerClient(t, db, 1171, "tenant-a", "alice", "alice-phone")
	insertPeerDevice(t, db, account, "100.96.0.19", "public-key")
	natType := "PORT_RESTRICTED_NAT"
	mapping := "ENDPOINT_INDEPENDENT"
	filtering := "ADDRESS_AND_PORT_DEPENDENT"
	discovery := "RFC5780"
	endpoint := "198.51.100.20:52000"

	view, err := service.ReportDevice(ctx, account, ControlMessage{
		NatType:              &natType,
		NatMappingBehavior:   &mapping,
		NatFilteringBehavior: &filtering,
		NatBehaviorDiscovery: &discovery,
		LastEndpoint:         &endpoint,
	})
	if err != nil {
		t.Fatalf("report device: %v", err)
	}
	if view.NatMappingBehavior == nil || *view.NatMappingBehavior != mapping ||
		view.NatFilteringBehavior == nil || *view.NatFilteringBehavior != filtering ||
		view.NatBehaviorDiscovery == nil || *view.NatBehaviorDiscovery != discovery {
		t.Fatalf("reported device view lost NAT behavior fields: %+v", view)
	}

	stored, err := db.FindPeerMeshDeviceByClientID(ctx, account.TenantID, account.ID)
	if err != nil || stored == nil {
		t.Fatalf("reload reported device: device=%+v err=%v", stored, err)
	}
	if stored.NatMappingBehavior == nil || *stored.NatMappingBehavior != mapping ||
		stored.NatFilteringBehavior == nil || *stored.NatFilteringBehavior != filtering ||
		stored.NatBehaviorDiscovery == nil || *stored.NatBehaviorDiscovery != discovery {
		t.Fatalf("stored device lost NAT behavior fields: %+v", stored)
	}

	devices, err := service.ListDevices(ctx, AccessContext{
		Username: account.OwnerUsername,
		TenantID: account.TenantID,
	})
	if err != nil || len(devices) != 1 {
		t.Fatalf("list devices: devices=%+v err=%v", devices, err)
	}
	if devices[0].NatMappingBehavior == nil || *devices[0].NatMappingBehavior != mapping ||
		devices[0].NatFilteringBehavior == nil || *devices[0].NatFilteringBehavior != filtering ||
		devices[0].NatBehaviorDiscovery == nil || *devices[0].NatBehaviorDiscovery != discovery {
		t.Fatalf("management device view lost NAT behavior fields: %+v", devices[0])
	}
}

func TestCanPeerMatchesJavaCaseSensitiveIdentityAndDirectionalACLs(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	service := newPeerMeshTestService(db)

	source := insertPeerClient(t, db, 1201, "tenant-a", "Alice", "alice-laptop")
	target := insertPeerClient(t, db, 1202, "tenant-a", "alice", "alice-nas")
	insertPeerDevice(t, db, source, "100.96.0.12", "source-key")
	insertPeerDevice(t, db, target, "100.96.0.13", "target-key")

	if allowed, err := service.CanPeer(ctx, source, target); err != nil || allowed {
		t.Fatalf("case-distinct owners bypassed ACL: allowed=%v err=%v", allowed, err)
	}
	caseDistinctTenant := target
	caseDistinctTenant.TenantID = "TENANT-A"
	if allowed, err := service.CanPeer(ctx, source, caseDistinctTenant); err != nil || allowed {
		t.Fatalf("case-distinct tenants were treated as equal: allowed=%v err=%v", allowed, err)
	}

	access := AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true}
	direction := "inbound"
	view, err := service.CreateACL(ctx, access, ACLMutation{
		SourceClientID: &source.ID, TargetClientID: &target.ID, Direction: &direction,
	})
	if err != nil {
		t.Fatalf("create inbound ACL: %v", err)
	}
	if view.Direction != "INBOUND" || !view.Allowed {
		t.Fatalf("management ACL view lost direction/default allowed: %+v", view)
	}
	if allowed, _ := service.CanPeer(ctx, source, target); allowed {
		t.Fatal("INBOUND ACL allowed source -> target")
	}
	if allowed, err := service.CanPeer(ctx, target, source); err != nil || !allowed {
		t.Fatalf("INBOUND ACL did not allow target -> source: allowed=%v err=%v", allowed, err)
	}

	direction = "OUTBOUND"
	view, err = service.CreateACL(ctx, access, ACLMutation{
		SourceClientID: &source.ID, TargetClientID: &target.ID, Direction: &direction,
	})
	if err != nil || view.Direction != "OUTBOUND" {
		t.Fatalf("update outbound ACL: view=%+v err=%v", view, err)
	}
	if allowed, err := service.CanPeer(ctx, source, target); err != nil || !allowed {
		t.Fatalf("OUTBOUND ACL did not allow source -> target: allowed=%v err=%v", allowed, err)
	}
	if allowed, _ := service.CanPeer(ctx, target, source); allowed {
		t.Fatal("OUTBOUND ACL allowed target -> source")
	}

	direction = "both"
	view, err = service.CreateACL(ctx, access, ACLMutation{
		SourceClientID: &source.ID, TargetClientID: &target.ID, Direction: &direction,
	})
	if err != nil || view.Direction != "BOTH" {
		t.Fatalf("update bidirectional ACL: view=%+v err=%v", view, err)
	}
	for _, pair := range [][2]store.ClientAccount{{source, target}, {target, source}} {
		if allowed, err := service.CanPeer(ctx, pair[0], pair[1]); err != nil || !allowed {
			t.Fatalf("BOTH ACL denied %s -> %s: allowed=%v err=%v", pair[0].ClientName, pair[1].ClientName, allowed, err)
		}
	}

	invalid := " inbound "
	if _, err := service.CreateACL(ctx, access, ACLMutation{
		SourceClientID: &source.ID, TargetClientID: &target.ID, Direction: &invalid,
	}); err == nil {
		t.Fatal("direction with Java-invalid surrounding whitespace was accepted")
	}
	allowedFlag := false
	view, err = service.CreateACL(ctx, access, ACLMutation{
		SourceClientID: &source.ID, TargetClientID: &target.ID, Allowed: &allowedFlag,
	})
	if err != nil || view.Direction != "BOTH" || view.Allowed {
		t.Fatalf("omitted direction did not preserve existing value: view=%+v err=%v", view, err)
	}
	for _, pair := range [][2]store.ClientAccount{{source, target}, {target, source}} {
		if allowed, _ := service.CanPeer(ctx, pair[0], pair[1]); allowed {
			t.Fatalf("disabled BOTH ACL still allowed %s -> %s", pair[0].ClientName, pair[1].ClientName)
		}
	}
}

func TestManagementAccessAndVisibilityRejectMixedCaseTenantAndOwner(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	service := newPeerMeshTestService(db)

	source := insertPeerClient(t, db, 1251, "tenant-a", "Alice", "alice-laptop")
	target := insertPeerClient(t, db, 1252, "tenant-a", "Alice", "alice-nas")
	caseTenant := insertPeerClient(t, db, 1253, "TENANT-A", "Alice", "case-tenant-host")
	lowerOwnerSource := insertPeerClient(t, db, 1254, "tenant-a", "alice", "lower-owner-host")
	insertPeerDevice(t, db, source, "100.96.0.14", "source-key")
	insertPeerDevice(t, db, target, "100.96.0.15", "target-key")
	insertPeerDevice(t, db, caseTenant, "100.96.0.16", "case-tenant-key")
	insertPeerSession(t, db, 9251, source, target, StatusActive, time.Now().UTC().Add(time.Hour))
	now := time.Now().UTC()
	acl := store.PeerMeshACL{
		ID: 8251, TenantID: source.TenantID, OwnerUsername: source.OwnerUsername,
		SourceClientID: source.ID, SourceClientName: source.ClientName,
		TargetClientID: target.ID, TargetClientName: target.ClientName,
		Allowed: true, Direction: "OUTBOUND", CreatedAt: now, UpdatedAt: now,
	}
	if err := db.InsertPeerMeshACL(ctx, acl); err != nil {
		t.Fatalf("insert peer ACL: %v", err)
	}

	ownerCaseMismatch := AccessContext{Username: "alice", TenantID: "tenant-a"}
	if _, err := service.findClient(ctx, ownerCaseMismatch, source.ID, false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("mixed-case owner accessed client: %v", err)
	}
	if _, err := service.findAccessibleDevice(ctx, ownerCaseMismatch, source.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("mixed-case owner accessed device: %v", err)
	}
	ids, err := service.visibleClientIDs(ctx, ownerCaseMismatch)
	if err != nil || len(ids) != 1 || ids[0] != lowerOwnerSource.ID {
		t.Fatalf("mixed-case owner visible client ids = %v, err=%v", ids, err)
	}
	if _, err := service.CreateACL(ctx, ownerCaseMismatch, ACLMutation{
		SourceClientID: &lowerOwnerSource.ID, TargetClientID: &target.ID,
	}); err == nil {
		t.Fatal("mixed-case target owner created ACL")
	}
	if err := service.DeleteACL(ctx, ownerCaseMismatch, acl.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("mixed-case owner deleted ACL: %v", err)
	}

	tenantCaseMismatch := AccessContext{Username: "Alice", TenantID: "TENANT-A", Admin: true}
	if _, err := service.findTenantClient(ctx, tenantCaseMismatch.TenantID, source.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("mixed-case tenant accessed client: %v", err)
	}
	if _, err := service.findAccessibleSession(ctx, tenantCaseMismatch, 9251); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("mixed-case tenant accessed session: %v", err)
	}
	if err := service.DeleteACL(ctx, tenantCaseMismatch, acl.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("mixed-case tenant deleted ACL: %v", err)
	}
	reporter := source
	reporter.TenantID = "TENANT-A"
	sessionID := int64(9251)
	if _, err := service.findReportableSession(ctx, reporter, &sessionID); err == nil {
		t.Fatal("mixed-case tenant reported traffic for session")
	}

	refreshTargets := service.rosterRefreshTargets(ctx, reporter)
	if len(refreshTargets) != 1 || refreshTargets[0].ID != caseTenant.ID {
		t.Fatalf("mixed-case tenant roster leaked other tenant casing: %+v", refreshTargets)
	}
}

func TestRefreshDeviceDisableClosesOpenSessionsAndNotifiesBothPeers(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	registry := session.NewRegistry()
	service := New(config.PeerMeshConfig{
		Enabled:           true,
		CIDR:              "100.96.0.0/11",
		PublicAddress:     "203.0.113.10",
		StunTurnPort:      3478,
		SessionTTLSeconds: 3600,
	}, db, registry, nil)

	source := insertPeerClient(t, db, 2001, "tenant-a", "alice", "alice-laptop")
	target := insertPeerClient(t, db, 2002, "tenant-a", "alice", "alice-nas")
	insertPeerDevice(t, db, source, "100.96.0.20", "source-key")
	insertPeerDevice(t, db, target, "100.96.0.21", "target-key")

	sourceSession := &recordingSession{name: source.ClientName}
	targetSession := &recordingSession{name: target.ClientName}
	registry.Replace(sourceSession)
	registry.Replace(targetSession)

	now := time.Now().UTC()
	if err := db.InsertPeerMeshSession(ctx, store.PeerMeshSession{
		ID:               9001,
		TenantID:         "tenant-a",
		SourceClientID:   source.ID,
		SourceClientName: source.ClientName,
		TargetClientID:   target.ID,
		TargetClientName: target.ClientName,
		PathType:         PathDirect,
		Status:           StatusActive,
		StartedAt:        now.Add(-time.Minute),
		UpdatedAt:        now.Add(-time.Minute),
		ExpiresAt:        now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("insert peer session: %v", err)
	}

	closed, err := service.RefreshDevice(ctx, AccessContext{Username: "alice", TenantID: "tenant-a"}, source.ID, false)
	if err != nil {
		t.Fatalf("refresh disabled device: %v", err)
	}
	if len(closed) != 1 || closed[0].ID != 9001 || closed[0].Status != StatusClosed || closed[0].ClosedAt == nil {
		t.Fatalf("closed sessions mismatch: %+v", closed)
	}

	sourceMessages := sourceSession.peerMessages(t)
	targetMessages := targetSession.peerMessages(t)
	assertHasCloseMessage(t, sourceMessages, 9001)
	assertHasCloseMessage(t, targetMessages, 9001)
	assertHasMessageType(t, sourceMessages, TypeConfig)
	assertHasMessageType(t, targetMessages, TypeRoster)
}

func TestPathStatsAggregatesDirectRatioReportedSessionsAndNatTypes(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	service := newPeerMeshTestService(db)

	source := insertPeerClient(t, db, 2501, "tenant-a", "alice", "alice-laptop")
	target := insertPeerClient(t, db, 2502, "tenant-a", "alice", "alice-nas")
	insertPeerDevice(t, db, source, "100.96.0.30", "source-key")
	insertPeerDevice(t, db, target, "100.96.0.31", "target-key")
	sourceDevice, err := db.FindPeerMeshDeviceByClientID(ctx, "tenant-a", source.ID)
	if err != nil {
		t.Fatalf("find source peer device: %v", err)
	}
	natType := "PORT_RESTRICTED_NAT"
	mapping := "ENDPOINT_INDEPENDENT"
	filtering := "ADDRESS_AND_PORT_DEPENDENT"
	discovery := "RFC5780"
	sourceDevice.NatType = &natType
	sourceDevice.NatMappingBehavior = &mapping
	sourceDevice.NatFilteringBehavior = &filtering
	sourceDevice.NatBehaviorDiscovery = &discovery
	if err := db.UpdatePeerMeshDevice(ctx, *sourceDevice); err != nil {
		t.Fatalf("update source peer device: %v", err)
	}

	now := time.Now().UTC()
	rttDirect := int64(10)
	rttRelay := int64(30)
	for _, item := range []store.PeerMeshSession{
		{
			ID:               9201,
			TenantID:         "tenant-a",
			SourceClientID:   source.ID,
			SourceClientName: source.ClientName,
			TargetClientID:   target.ID,
			TargetClientName: target.ClientName,
			PathType:         PathDirect,
			Status:           StatusActive,
			RTTMillis:        &rttDirect,
			DirectBytes:      100,
			RelayBytes:       5,
			StartedAt:        now.Add(-2 * time.Minute),
			UpdatedAt:        now.Add(-2 * time.Minute),
			ExpiresAt:        now.Add(time.Hour),
		},
		{
			ID:               9202,
			TenantID:         "tenant-a",
			SourceClientID:   target.ID,
			SourceClientName: target.ClientName,
			TargetClientID:   source.ID,
			TargetClientName: source.ClientName,
			PathType:         PathRelay,
			Status:           StatusActive,
			RTTMillis:        &rttRelay,
			DirectBytes:      0,
			RelayBytes:       200,
			StartedAt:        now.Add(-2 * time.Minute),
			UpdatedAt:        now.Add(-2 * time.Minute),
			ExpiresAt:        now.Add(time.Hour),
		},
		{
			ID:               9203,
			TenantID:         "tenant-a",
			SourceClientID:   source.ID,
			SourceClientName: source.ClientName,
			TargetClientID:   target.ID,
			TargetClientName: target.ClientName,
			PathType:         PathDirect,
			Status:           StatusNegotiating,
			StartedAt:        now.Add(-2 * time.Minute),
			UpdatedAt:        now.Add(-2 * time.Minute),
			ExpiresAt:        now.Add(time.Hour),
		},
	} {
		if err := db.InsertPeerMeshSession(ctx, item); err != nil {
			t.Fatalf("insert peer session %d: %v", item.ID, err)
		}
	}

	stats, err := service.PathStats(ctx, AccessContext{Username: "alice", TenantID: "tenant-a", Admin: true})
	if err != nil {
		t.Fatalf("path stats: %v", err)
	}
	if stats.TotalSessions != 3 || stats.ReportedSessions != 2 ||
		stats.ActiveSessions != 2 || stats.ActiveDirectSessions != 1 || stats.ActiveRelaySessions != 1 {
		t.Fatalf("stats counters mismatch: %+v", stats)
	}
	if stats.ActiveDirectRatio == nil || *stats.ActiveDirectRatio != 0.5 {
		t.Fatalf("active direct ratio = %v, want 0.5", stats.ActiveDirectRatio)
	}
	directActive := findPathTypeStat(stats.PathTypes, PathDirect, StatusActive)
	if directActive == nil || directActive.Sessions != 1 || directActive.ReportedSessions != 1 ||
		directActive.AvgRttMillis == nil || *directActive.AvgRttMillis != 10 ||
		directActive.DirectBytes != 100 || directActive.RelayBytes != 5 {
		t.Fatalf("direct active aggregate mismatch: %+v", directActive)
	}
	directNegotiating := findPathTypeStat(stats.PathTypes, PathDirect, StatusNegotiating)
	if directNegotiating == nil || directNegotiating.ReportedSessions != 0 {
		t.Fatalf("direct negotiating aggregate mismatch: %+v", directNegotiating)
	}
	if findNatTypeStat(stats.NatTypes, "PORT_RESTRICTED_NAT") != 1 ||
		findNatTypeStat(stats.NatTypes, "UNKNOWN") != 1 {
		t.Fatalf("nat type aggregate mismatch: %+v", stats.NatTypes)
	}
	if stats.NatBehaviorDevices != 1 || stats.NatBehaviorClassifiedDevices != 1 ||
		stats.NatBehaviorSuccessRatio == nil || *stats.NatBehaviorSuccessRatio != 1 {
		t.Fatalf("nat behavior success mismatch: %+v", stats)
	}
	if findNatBehaviorStat(stats.NatMappingBehaviors, mapping) != 1 ||
		findNatBehaviorStat(stats.NatFilteringBehaviors, filtering) != 1 ||
		findNatBehaviorStat(stats.NatBehaviorDiscoveries, discovery) != 1 {
		t.Fatalf("nat behavior aggregates mismatch: %+v", stats)
	}
}

func TestAuthorizeRelayFrameRequiresActiveMatchingSessionAndAccountsBytes(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	service := newPeerMeshTestService(db)

	source := insertPeerClient(t, db, 3001, "tenant-a", "alice", "alice-laptop")
	target := insertPeerClient(t, db, 3002, "tenant-a", "alice", "alice-nas")
	insertPeerSession(t, db, 9101, source, target, StatusActive, time.Now().UTC().Add(time.Hour))

	allowed := service.AuthorizeRelayFrame(ctx, DataFrameHeader{
		SessionID:    9101,
		FromClientID: source.ID,
		ToClientID:   target.ID,
		Sequence:     7,
	}, 512)
	if !allowed {
		t.Fatalf("AuthorizeRelayFrame active matching session = false, want true")
	}
	allowed = service.AuthorizeRelayFrame(ctx, DataFrameHeader{
		SessionID:    9101,
		FromClientID: target.ID,
		ToClientID:   source.ID,
		Sequence:     8,
	}, 256)
	if !allowed {
		t.Fatalf("AuthorizeRelayFrame cached reverse session = false, want true")
	}
	if err := service.FlushRelayTraffic(ctx); err != nil {
		t.Fatalf("flush relay traffic: %v", err)
	}

	stored := getPeerSession(t, db, 9101)
	if stored.RelayBytes != 768 || stored.DirectBytes != 0 || stored.LastTrafficAt == nil {
		t.Fatalf("relay accounting mismatch: %+v", stored)
	}
	if stored.Status != StatusActive || stored.ClosedAt != nil {
		t.Fatalf("active relay authorization changed session lifecycle: %+v", stored)
	}
}

func TestAuthorizeRelayFrameRejectsWrongPeerPair(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	service := newPeerMeshTestService(db)

	source := insertPeerClient(t, db, 3101, "tenant-a", "alice", "alice-laptop")
	target := insertPeerClient(t, db, 3102, "tenant-a", "alice", "alice-nas")
	insertPeerSession(t, db, 9102, source, target, StatusActive, time.Now().UTC().Add(time.Hour))

	allowed := service.AuthorizeRelayFrame(ctx, DataFrameHeader{
		SessionID:    9102,
		FromClientID: source.ID,
		ToClientID:   9999,
		Sequence:     7,
	}, 512)
	if allowed {
		t.Fatalf("AuthorizeRelayFrame wrong peer pair = true, want false")
	}

	stored := getPeerSession(t, db, 9102)
	if stored.RelayBytes != 0 || stored.LastTrafficAt != nil || stored.Status != StatusActive {
		t.Fatalf("wrong peer pair should not mutate traffic/lifecycle: %+v", stored)
	}
}

func TestAuthorizeRelayFrameRejectsExpiredSessionAndClosesIt(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	service := newPeerMeshTestService(db)

	source := insertPeerClient(t, db, 3201, "tenant-a", "alice", "alice-laptop")
	target := insertPeerClient(t, db, 3202, "tenant-a", "alice", "alice-nas")
	insertPeerSession(t, db, 9103, source, target, StatusActive, time.Now().UTC().Add(-time.Second))

	allowed := service.AuthorizeRelayFrame(ctx, DataFrameHeader{
		SessionID:    9103,
		FromClientID: source.ID,
		ToClientID:   target.ID,
		Sequence:     7,
	}, 512)
	if allowed {
		t.Fatalf("AuthorizeRelayFrame expired session = true, want false")
	}

	stored := getPeerSession(t, db, 9103)
	if stored.Status != StatusClosed || stored.ClosedAt == nil {
		t.Fatalf("expired session was not closed: %+v", stored)
	}
	if stored.RelayBytes != 0 || stored.LastTrafficAt != nil {
		t.Fatalf("expired session should not account relay traffic: %+v", stored)
	}
}

func TestAuthorizeRelayFrameRejectsNegotiatingSession(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	service := newPeerMeshTestService(db)

	source := insertPeerClient(t, db, 3301, "tenant-a", "alice", "alice-laptop")
	target := insertPeerClient(t, db, 3302, "tenant-a", "alice", "alice-nas")
	insertPeerSession(t, db, 9104, source, target, StatusNegotiating, time.Now().UTC().Add(time.Hour))

	allowed := service.AuthorizeRelayFrame(ctx, DataFrameHeader{
		SessionID:    9104,
		FromClientID: source.ID,
		ToClientID:   target.ID,
		Sequence:     7,
	}, 512)
	if allowed {
		t.Fatalf("AuthorizeRelayFrame negotiating session = true, want false")
	}

	stored := getPeerSession(t, db, 9104)
	if stored.RelayBytes != 0 || stored.LastTrafficAt != nil || stored.Status != StatusNegotiating {
		t.Fatalf("negotiating session should not mutate traffic/lifecycle: %+v", stored)
	}
}

func TestEffectivePathTypeUsesBusinessTrafficDominance(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	service := newPeerMeshTestService(db)

	source := insertPeerClient(t, db, 3401, "tenant-a", "alice", "alice-laptop")
	target := insertPeerClient(t, db, 3402, "tenant-a", "alice", "alice-nas")
	insertPeerSession(t, db, 9401, source, target, StatusActive, time.Now().UTC().Add(time.Hour))

	sessionID := int64(9401)
	if _, err := service.ReportTraffic(ctx, source, ControlMessage{
		SessionID:   &sessionID,
		DirectBytes: 20_000,
		RelayBytes:  5_800_000,
	}); err != nil {
		t.Fatalf("report traffic: %v", err)
	}
	rtt := int64(7)
	view, err := service.ReportPath(ctx, source, ControlMessage{
		SessionID: &sessionID,
		PathType:  PathDirect,
		Status:    StatusActive,
		RTTMillis: &rtt,
	})
	if err != nil {
		t.Fatalf("report path: %v", err)
	}
	if view.PathType != PathRelay {
		t.Fatalf("session view pathType = %q, want %q: %+v", view.PathType, PathRelay, view)
	}

	stored := getPeerSession(t, db, sessionID)
	if stored.PathType != PathRelay {
		t.Fatalf("stored pathType = %q, want %q: %+v", stored.PathType, PathRelay, stored)
	}

	stats, err := service.PathStats(ctx, AccessContext{Username: "alice", TenantID: "tenant-a", Admin: true})
	if err != nil {
		t.Fatalf("path stats: %v", err)
	}
	if stats.ActiveDirectSessions != 0 || stats.ActiveRelaySessions != 1 {
		t.Fatalf("active path counters mismatch: %+v", stats)
	}
	if stats.ActiveDirectRatio == nil || *stats.ActiveDirectRatio != 0 {
		t.Fatalf("active direct ratio = %v, want 0", stats.ActiveDirectRatio)
	}
	relayActive := findPathTypeStat(stats.PathTypes, PathRelay, StatusActive)
	if relayActive == nil || relayActive.Sessions != 1 || relayActive.ReportedSessions != 1 ||
		relayActive.DirectBytes != 20_000 || relayActive.RelayBytes != 5_800_000 {
		t.Fatalf("relay active aggregate mismatch: %+v", relayActive)
	}
	if directActive := findPathTypeStat(stats.PathTypes, PathDirect, StatusActive); directActive != nil {
		t.Fatalf("unexpected direct active aggregate: %+v", directActive)
	}
}

func openPeerMeshTestDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "peer-mesh.db"))
	if err != nil {
		t.Fatalf("open temp db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newPeerMeshTestService(db *store.DB) *Service {
	return New(config.PeerMeshConfig{
		Enabled:           true,
		CIDR:              "100.96.0.0/11",
		PublicAddress:     "203.0.113.10",
		StunTurnPort:      3478,
		SessionTTLSeconds: 3600,
	}, db, session.NewRegistry(), nil)
}

func insertPeerClient(t *testing.T, db *store.DB, id int64, tenantID, owner, name string) store.ClientAccount {
	t.Helper()
	now := time.Now().UTC()
	account := store.ClientAccount{
		ID:                           id,
		TenantID:                     tenantID,
		OwnerUsername:                owner,
		ClientName:                   name,
		PasswordHash:                 "unused",
		Enabled:                      true,
		ConnectionRateLimitPerMinute: 60,
		CreatedAt:                    now,
		UpdatedAt:                    now,
	}
	if err := db.InsertClient(context.Background(), account); err != nil {
		t.Fatalf("insert client %s: %v", name, err)
	}
	return account
}

func insertPeerDevice(t *testing.T, db *store.DB, account store.ClientAccount, virtualIP, publicKey string) {
	t.Helper()
	now := time.Now().UTC()
	if err := db.InsertPeerMeshDevice(context.Background(), store.PeerMeshDevice{
		ID:            account.ID + 10000,
		TenantID:      account.TenantID,
		OwnerUsername: account.OwnerUsername,
		ClientID:      account.ID,
		ClientName:    account.ClientName,
		VirtualIP:     virtualIP,
		CIDR:          "100.96.0.0/11",
		PublicKey:     &publicKey,
		Enabled:       true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}); err != nil {
		t.Fatalf("insert peer device %s: %v", account.ClientName, err)
	}
}

func insertPeerSession(t *testing.T, db *store.DB, id int64, source, target store.ClientAccount, status string, expiresAt time.Time) {
	t.Helper()
	now := time.Now().UTC().Add(-time.Minute)
	if err := db.InsertPeerMeshSession(context.Background(), store.PeerMeshSession{
		ID:               id,
		TenantID:         source.TenantID,
		SourceClientID:   source.ID,
		SourceClientName: source.ClientName,
		TargetClientID:   target.ID,
		TargetClientName: target.ClientName,
		PathType:         PathDirect,
		Status:           status,
		StartedAt:        now,
		UpdatedAt:        now,
		ExpiresAt:        expiresAt,
	}); err != nil {
		t.Fatalf("insert peer session %d: %v", id, err)
	}
}

func getPeerSession(t *testing.T, db *store.DB, id int64) *store.PeerMeshSession {
	t.Helper()
	item, err := db.GetPeerMeshSession(context.Background(), id)
	if err != nil {
		t.Fatalf("get peer session %d: %v", id, err)
	}
	if item == nil {
		t.Fatalf("peer session %d not found", id)
	}
	return item
}

func decodeOnlyPeerMessage(t *testing.T, session *recordingSession) ControlMessage {
	t.Helper()
	messages := session.peerMessages(t)
	if len(messages) != 1 {
		t.Fatalf("%s messages len = %d, want 1: %+v", session.name, len(messages), messages)
	}
	return messages[0]
}

func assertHasCloseMessage(t *testing.T, messages []ControlMessage, sessionID int64) {
	t.Helper()
	for _, message := range messages {
		if message.Type == TypeClose && message.SessionID != nil && *message.SessionID == sessionID &&
			message.Status == StatusClosed && message.Reason == "admin-force-close" {
			return
		}
	}
	t.Fatalf("missing close message for session %d in %+v", sessionID, messages)
}

func assertHasMessageType(t *testing.T, messages []ControlMessage, messageType string) {
	t.Helper()
	for _, message := range messages {
		if message.Type == messageType {
			return
		}
	}
	t.Fatalf("missing message type %q in %+v", messageType, messages)
}

func rosterContains(items []RosterItem, clientID int64, clientName string, online bool) bool {
	for _, item := range items {
		if item.ClientID == clientID && item.ClientName == clientName && item.Online == online {
			return true
		}
	}
	return false
}

func findPathTypeStat(items []PathTypeStat, pathType, status string) *PathTypeStat {
	for i := range items {
		if items[i].PathType == pathType && items[i].Status == status {
			return &items[i]
		}
	}
	return nil
}

func findNatTypeStat(items []NatTypeStat, natType string) int64 {
	for _, item := range items {
		if item.NatType == natType {
			return item.Devices
		}
	}
	return 0
}

func findNatBehaviorStat(items []NatBehaviorStat, behavior string) int64 {
	for _, item := range items {
		if item.Behavior == behavior {
			return item.Devices
		}
	}
	return 0
}

type recordingSession struct {
	name    string
	packets []protocol.Packet
}

func (s *recordingSession) ClientName() string { return s.name }

func (s *recordingSession) LoginTimeMs() int64 { return time.Now().UnixMilli() }

func (s *recordingSession) Send(packet protocol.Packet) error {
	s.packets = append(s.packets, packet)
	return nil
}

func (s *recordingSession) Close(string) {}

func (s *recordingSession) peerMessages(t *testing.T) []ControlMessage {
	t.Helper()
	var messages []ControlMessage
	for _, packet := range s.packets {
		response, ok := packet.(protocol.MessageResponse)
		if !ok {
			t.Fatalf("%s got non-message packet: %#v", s.name, packet)
		}
		if response.MessageType != protocol.MessageTypePeerControl {
			t.Fatalf("%s message type = %d, want peer control", s.name, response.MessageType)
		}
		var message ControlMessage
		if err := json.Unmarshal([]byte(response.Message), &message); err != nil {
			t.Fatalf("decode peer message for %s: %v", s.name, err)
		}
		messages = append(messages, message)
	}
	return messages
}
