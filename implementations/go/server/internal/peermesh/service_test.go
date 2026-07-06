package peermesh

import (
	"context"
	"encoding/json"
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
	sourceDevice.NatType = &natType
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
