package server

import (
	"context"
	"io"
	"log/slog"
	"os"
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
	roster, err := first.roster(ctx, alpha.groupID())
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
	return clusterParticipant{LeaseID: leaseID, PeerID: peerID, DisplayName: displayName,
		RoomID: roomID, PublicAddress: "203.0.113.1", RoomKey: roomKey, RoomRole: "EDITOR",
		SharedRoom: true, ConnectedAt: connectedAt}
}
