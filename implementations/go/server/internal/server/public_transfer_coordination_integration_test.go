package server

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
)

func TestPublicTransferCoordinationAcrossRedisInstances(t *testing.T) {
	redisURI := os.Getenv("SPECUS_TEST_REDIS_URI")
	if redisURI == "" {
		t.Skip("SPECUS_TEST_REDIS_URI is not configured")
	}
	cfg := config.PublicTransferConfig{
		ClusterEnabled: true, RedisURI: redisURI,
		RedisKeyPrefix:       "specus:test:" + randomDiscoveryLeaseID(),
		PresenceLeaseSeconds: 30, PresenceRefreshIntervalMs: 10_000,
		RedisCommandTimeoutMs: 2_000,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	first, err := newPublicTransferCoordination(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := newPublicTransferCoordination(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	alpha := clusterTestParticipant("lease-a", "peer-a", "Device Alpha", "room", "key",
		"2026-07-22T00:00:00Z")
	beta := clusterTestParticipant("lease-b", "peer-b", "Device Beta", "room", "key",
		"2026-07-22T00:00:01Z")
	if registration, err := first.register(ctx, alpha, 2); err != nil || registration.err != "" {
		t.Fatalf("register alpha: result=%+v err=%v", registration, err)
	}
	if registration, err := second.register(ctx, beta, 2); err != nil || registration.err != "" {
		t.Fatalf("register beta: result=%+v err=%v", registration, err)
	}
	roster, err := first.roster(ctx, alpha)
	if err != nil || len(roster.participants) != 2 || roster.revision < 2 {
		t.Fatalf("shared roster: result=%+v err=%v", roster, err)
	}
	duplicateName := clusterTestParticipant("lease-c", "peer-c", "device alpha", "other", "key",
		"2026-07-22T00:00:02Z")
	if registration, err := second.register(ctx, duplicateName, 2); err != nil ||
		registration.err != "client name is already in use" {
		t.Fatalf("global name check: result=%+v err=%v", registration, err)
	}
	full := clusterTestParticipant("lease-d", "peer-d", "Device Delta", "room", "key",
		"2026-07-22T00:00:03Z")
	if registration, err := second.register(ctx, full, 2); err != nil || registration.err != "room is full" {
		t.Fatalf("room limit: result=%+v err=%v", registration, err)
	}
	if allowed, err := first.allowRate(ctx, "integration", "same-source", 1, time.Minute); err != nil || !allowed {
		t.Fatalf("first shared rate: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := second.allowRate(ctx, "integration", "same-source", 1, time.Minute); err != nil || allowed {
		t.Fatalf("second shared rate: allowed=%v err=%v", allowed, err)
	}
	delivered := make(chan struct{}, 1)
	second.setListener(func(event publicTransferClusterEvent) {
		if event.kind == clusterEventKindText && event.groupID == alpha.groupID() &&
			string(event.payload) == "cross-instance" {
			delivered <- struct{}{}
		}
	})
	if err := first.publishText(ctx, alpha.groupID(), "peer-b", alpha.LeaseID, false,
		[]byte("cross-instance")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-delivered:
	case <-ctx.Done():
		t.Fatal("cross-instance event was not delivered")
	}
	managementDelivered := make(chan struct{}, 1)
	managementPayload := []byte(`{"tenantId":"default","type":"created"}`)
	second.addListener(func(event publicTransferClusterEvent) {
		if event.kind == clusterEventKindManagement && event.groupID == managementGroupID("default") &&
			string(event.payload) == string(managementPayload) {
			managementDelivered <- struct{}{}
		}
	})
	if err := first.publishManagement(ctx, "default", managementPayload); err != nil {
		t.Fatal(err)
	}
	select {
	case <-managementDelivered:
	case <-ctx.Done():
		t.Fatal("cross-instance management event was not delivered")
	}
	if revision, err := first.unregister(ctx, alpha); err != nil || revision == 0 {
		t.Fatalf("unregister alpha: revision=%d err=%v", revision, err)
	}
	if revision, err := second.unregister(ctx, beta); err != nil || revision == 0 {
		t.Fatalf("unregister beta: revision=%d err=%v", revision, err)
	}
}

func clusterTestParticipant(leaseID, peerID, displayName, roomID, roomKey,
	connectedAt string) clusterParticipant {
	return clusterTestParticipantOn("203.0.113.1", leaseID, peerID, displayName, roomID, roomKey, connectedAt)
}

func clusterTestParticipantOn(publicAddress, leaseID, peerID, displayName, roomID, roomKey,
	connectedAt string) clusterParticipant {
	return clusterParticipant{LeaseID: leaseID, PeerID: peerID, DisplayName: displayName,
		RoomID: roomID, PublicAddress: publicAddress, RoomKey: roomKey, RoomRole: "EDITOR",
		SharedRoom: true, ConnectedAt: connectedAt}
}

func TestPublicTransferCoordinationMergesNetRoster(t *testing.T) {
	redisURI := os.Getenv("SPECUS_TEST_REDIS_URI")
	if redisURI == "" {
		t.Skip("SPECUS_TEST_REDIS_URI is not configured")
	}
	cfg := config.PublicTransferConfig{
		ClusterEnabled: true, RedisURI: redisURI,
		RedisKeyPrefix:       "specus:test:" + randomDiscoveryLeaseID(),
		PresenceLeaseSeconds: 30, PresenceRefreshIntervalMs: 10_000,
		RedisCommandTimeoutMs: 2_000,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	coordination, err := newPublicTransferCoordination(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer coordination.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const ipX, ipY = "203.0.113.31", "198.51.100.31"
	alpha := clusterTestParticipantOn(ipX, "lease-a", "peer-a", "Alpha", "room", "key-one",
		"2026-07-22T00:00:00Z")
	beta := clusterTestParticipantOn(ipY, "lease-b", "peer-b", "Beta", "room", "key-one",
		"2026-07-22T00:00:01Z")
	gamma := clusterTestParticipantOn(ipX, "lease-g", "peer-g", "Gamma", "room", "key-two",
		"2026-07-22T00:00:02Z")
	for _, participant := range []clusterParticipant{alpha, beta, gamma} {
		if registration, err := coordination.register(ctx, participant, 8); err != nil || registration.err != "" {
			t.Fatalf("register %s: result=%+v err=%v", participant.PeerID, registration, err)
		}
	}

	// alpha's merged view carries both the remote roommate (via the shared group) and
	// the same-net stranger from the other token room.
	roster, err := coordination.roster(ctx, alpha)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(roster.participants); got != 3 {
		t.Fatalf("merged net roster size = %d, want 3: %+v", got, roster.participants)
	}
	// beta's view sees its own group across nets, but not the other token room.
	betaRoster, err := coordination.roster(ctx, beta)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(betaRoster.participants); got != 2 {
		t.Fatalf("remote net roster size = %d, want 2: %+v", got, betaRoster.participants)
	}
	// Re-reading without changes must not regress the summed revision.
	again, err := coordination.roster(ctx, alpha)
	if err != nil || again.revision < roster.revision {
		t.Fatalf("roster revision regressed: first=%+v second=%+v err=%v", roster, again, err)
	}

	// Duplicate peer IDs are rejected across groups within the net and across nets
	// within the group, but stay allowed on a foreign net.
	sameNet := clusterTestParticipantOn(ipX, "lease-x", "peer-a", "X-ray", "room", "key-two",
		"2026-07-22T00:00:03Z")
	if registration, err := coordination.register(ctx, sameNet, 8); err != nil ||
		registration.err != duplicateDiscoveryPeerError {
		t.Fatalf("same-net duplicate: result=%+v err=%v", registration, err)
	}
	sameGroup := clusterTestParticipantOn(ipY, "lease-y", "peer-a", "Yankee", "room", "key-one",
		"2026-07-22T00:00:04Z")
	if registration, err := coordination.register(ctx, sameGroup, 8); err != nil ||
		registration.err != duplicateDiscoveryPeerError {
		t.Fatalf("same-group duplicate: result=%+v err=%v", registration, err)
	}
	foreign := clusterTestParticipantOn("192.0.2.31", "lease-z", "peer-a", "Zulu", "room", "key-two",
		"2026-07-22T00:00:05Z")
	if registration, err := coordination.register(ctx, foreign, 8); err != nil || registration.err != "" {
		t.Fatalf("foreign-net peer id must be allowed: result=%+v err=%v", registration, err)
	}

	// Directed routing resolves targets inside the source's merged visibility domain and
	// publishes exactly once to the resolved target's group.
	received := make(chan string, 4)
	coordination.setListener(func(event publicTransferClusterEvent) {
		if event.kind == clusterEventKindText && strings.HasPrefix(string(event.payload), "signal-") {
			received <- event.groupID
		}
	})
	target, err := coordination.findPeer(ctx, alpha, "peer-b")
	if err != nil || target == nil || target.groupID() != beta.groupID() {
		t.Fatalf("findPeer remote roommate: target=%+v err=%v", target, err)
	}
	if err := coordination.publishText(ctx, target.groupID(), "peer-b", alpha.LeaseID, false,
		[]byte("signal-roommate")); err != nil {
		t.Fatal(err)
	}
	netTarget, err := coordination.findPeer(ctx, alpha, "peer-g")
	if err != nil || netTarget == nil || netTarget.groupID() != gamma.groupID() {
		t.Fatalf("findPeer net stranger: target=%+v err=%v", netTarget, err)
	}
	if err := coordination.publishText(ctx, netTarget.groupID(), "peer-g", alpha.LeaseID, false,
		[]byte("signal-stranger")); err != nil {
		t.Fatal(err)
	}
	// gamma cannot see beta at all: different token room and different net. The hub
	// falls back to publishing at the source's group for such unresolved targets
	// (hidden peers never register presence), so assert the fallback route here.
	if invisible, err := coordination.findPeer(ctx, gamma, "peer-b"); err != nil || invisible != nil {
		t.Fatalf("invisible cross-net peer must not resolve: target=%+v err=%v", invisible, err)
	}
	if err := coordination.publishText(ctx, gamma.groupID(), "peer-b", gamma.LeaseID, false,
		[]byte("signal-fallback")); err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]int)
	for i := 0; i < 3; i++ {
		select {
		case group := <-received:
			seen[group]++
		case <-ctx.Done():
			t.Fatalf("directed publish delivered %v, want both target groups plus the fallback group", seen)
		}
	}
	if seen[beta.groupID()] != 1 || seen[gamma.groupID()] != 2 {
		t.Fatalf("each resolved target group gets one copy, the fallback reuses the source group: %v", seen)
	}

	for _, participant := range []clusterParticipant{alpha, beta, gamma, foreign} {
		if _, err := coordination.unregister(ctx, participant); err != nil {
			t.Fatalf("unregister %s: %v", participant.PeerID, err)
		}
	}
}
