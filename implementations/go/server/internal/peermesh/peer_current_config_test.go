package peermesh

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func TestPeerConfigUsesCurrentParentAfterTransfer(t *testing.T) {
	for _, mode := range []string{"login", "runtime"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			db := openPeerMeshTestDB(t)
			service := newPeerMeshTestService(db)
			publisher := insertPeerClient(t, db, 3010, "tenant-a", "alice", "config-publisher")
			oldPeer := insertPeerClient(t, db, 3011, "tenant-a", "alice", "config-old-peer")
			newPeer := insertPeerClient(t, db, 3012, "tenant-a", "bob", "config-new-peer")
			insertPeerDevice(t, db, publisher, "100.96.0.10", "publisher-key")
			insertPeerDevice(t, db, oldPeer, "100.96.0.11", "old-key")
			insertPeerDevice(t, db, newPeer, "100.96.0.12", "new-key")
			now := time.Now()
			if err := db.InsertClientSession(ctx, store.ClientSession{
				ID: 91001, TenantID: publisher.TenantID, ClientID: publisher.ID,
				ClientName: publisher.ClientName, TokenHash: "config-test", Status: "NETTY_ONLINE",
				MachineFingerprint: "machine", OSUser: "user", PeerServiceDiscoveryVersion: 2,
				HTTPLoginAt: now, NettyConnectedAt: &now, ExpiresAt: now.Add(time.Hour),
			}); err != nil {
				t.Fatal(err)
			}
			access := AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true, BuiltIn: true}
			if _, err := service.SetSharing(ctx, access, true); err != nil {
				t.Fatal(err)
			}
			name, application, host, visibility := "web", "http", "127.0.0.1", "OWNER"
			targetPort, publishedPort, enabled := 8080, 18080, true
			created, err := service.CreateSharedService(ctx, access, ServiceMutation{
				ClientID: &publisher.ID, Name: &name, Application: &application, TargetHost: &host,
				TargetPort: &targetPort, PublishedPort: &publishedPort, Visibility: &visibility,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.UpdateSharedService(ctx, access, created.ID, ServiceMutation{Enabled: &enabled}); err != nil {
				t.Fatal(err)
			}
			build := func() (LoginConfig, error) {
				if mode == "login" {
					return service.BuildLoginConfig(ctx, publisher, "", "", 2)
				}
				return service.BuildRuntimeConfig(ctx, publisher)
			}
			before, err := build()
			if err != nil || len(before.LocalServices) != 1 || len(before.LocalServices[0].AllowedPeerVirtualIPs) != 1 || before.LocalServices[0].AllowedPeerVirtualIPs[0] != "100.96.0.11" {
				t.Fatalf("initial config: %+v / %v", before, err)
			}
			transferPeerFixtureClient(t, db, publisher.ID, "bob")
			// Keep the original caller object: a login/runtime callback can outlive an owner transfer.
			after, err := build()
			if err != nil || len(after.LocalServices) != 1 || len(after.LocalServices[0].AllowedPeerVirtualIPs) != 1 || after.LocalServices[0].AllowedPeerVirtualIPs[0] != "100.96.0.12" {
				t.Fatalf("cached owner selected data-plane whitelist: %+v / %v", after, err)
			}
			actor := store.ManagementWriteActor{Username: "admin", TenantID: "tenant-a", Admin: true, BuiltIn: true}
			off := false
			if _, err := db.PatchManagedClient(ctx, actor, publisher.ID, store.ManagementClientPatch{Enabled: &off}, now, now.Unix()); err != nil {
				t.Fatal(err)
			}
			disabled, err := build()
			if err != nil || disabled.Enabled || disabled.ServiceSharing.EffectiveEnabled {
				t.Fatalf("disabled parent emitted enabled config: %+v / %v", disabled, err)
			}
			rename := "renamed-config-publisher"
			if _, err := db.PatchManagedClient(ctx, actor, publisher.ID, store.ManagementClientPatch{ClientName: &rename}, now, now.Unix()); err != nil {
				t.Fatal(err)
			}
			if _, err := build(); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("stale alias rebound runtime config: %v", err)
			}
		})
	}
}
