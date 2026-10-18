package peermesh

import (
	"context"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func transferPeerFixtureClient(t *testing.T, db *store.DB, clientID int64, owner string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	user, err := db.FindManagementUserByLogin(ctx, "tenant-a", owner)
	if err != nil {
		t.Fatal(err)
	}
	if user == nil {
		if _, err := db.InsertManagementUser(ctx, store.ManagementUser{Username: owner, TenantID: "tenant-a", Role: store.ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	actor := store.ManagementWriteActor{Username: "admin", TenantID: "tenant-a", Admin: true, BuiltIn: true}
	snapshot, err := db.LoadOwnerTransferSnapshot(ctx, "tenant-a", store.OwnerScopeSingle, clientID)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := store.PreviewOwnerTransfer(actor, store.OwnerScopeSingle, clientID, snapshot)
	if err != nil || preview.Revision == nil {
		t.Fatalf("preview: %+v / %v", preview, err)
	}
	request := store.OwnerTransferWrite{Actor: actor, Scope: store.OwnerScopeSingle, PathID: clientID, AuditID: 800001, Body: map[string]any{"scope": store.OwnerScopeSingle, "targetUsername": owner, "expectedRevision": *preview.Revision}}
	request.BuiltInTarget.Username = "admin"
	request.BuiltInTarget.TenantID = "tenant-a"
	request.BuiltInTarget.Enabled = true
	if out, err := db.TransferClientOwnership(ctx, request); err != nil || !out.Response.Changed {
		t.Fatalf("actual fixture transfer: %+v / %v", out, err)
	}
}

func TestPeerGrantUsesCurrentParentsRatherThanCachedOwner(t *testing.T) {
	for _, scenario := range []string{"lost-implicit", "gained-implicit", "explicit-kept", "reuse-lost", "disabled-parent", "renamed-parent", "deleted-parent"} {
		t.Run(scenario, func(t *testing.T) {
			db := openPeerMeshTestDB(t)
			service := newPeerMeshTestService(db)
			ctx := context.Background()
			source := insertPeerClient(t, db, 1001, "tenant-a", "alice", "current-source")
			targetOwner := "alice"
			if scenario == "gained-implicit" {
				targetOwner = "bob"
			}
			target := insertPeerClient(t, db, 1002, "tenant-a", targetOwner, "current-target")
			insertPeerDevice(t, db, source, "100.96.0.10", "source-key")
			insertPeerDevice(t, db, target, "100.96.0.11", "target-key")
			now := time.Now()
			beforeCount := 0
			if scenario == "explicit-kept" {
				if err := db.InsertPeerMeshACL(ctx, store.PeerMeshACL{ID: 9001, TenantID: "tenant-a", OwnerUsername: "alice", SourceClientID: source.ID, SourceClientName: source.ClientName, TargetClientID: target.ID, TargetClientName: target.ClientName, Allowed: true, Direction: "OUTBOUND", CreatedAt: now, UpdatedAt: now}); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "reuse-lost" {
				if _, err := service.CreateSession(ctx, source, target, PathDirect); err != nil {
					t.Fatal(err)
				}
				beforeCount = 1
			}
			actor := store.ManagementWriteActor{Username: "admin", TenantID: "tenant-a", Admin: true, BuiltIn: true}
			switch scenario {
			case "lost-implicit", "explicit-kept", "reuse-lost":
				transferPeerFixtureClient(t, db, target.ID, "bob")
			case "gained-implicit":
				transferPeerFixtureClient(t, db, target.ID, "alice")
			case "disabled-parent":
				off := false
				if _, err := db.PatchManagedClient(ctx, actor, source.ID, store.ManagementClientPatch{Enabled: &off}, now, now.Unix()); err != nil {
					t.Fatal(err)
				}
			case "renamed-parent":
				name := "renamed-source"
				if _, err := db.PatchManagedClient(ctx, actor, source.ID, store.ManagementClientPatch{ClientName: &name}, now, now.Unix()); err != nil {
					t.Fatal(err)
				}
			case "deleted-parent":
				if _, err := db.DeleteManagedClient(ctx, actor, source.ID, now, now.Unix(), func(store.HTTPRouteMapping) string { return "private" }); err != nil {
					t.Fatal(err)
				}
			}
			grant, err := service.CreateSession(ctx, source, target, PathDirect)
			allowed := scenario == "gained-implicit" || scenario == "explicit-kept"
			if allowed {
				if err != nil || grant.session.ID == 0 || grant.token == "" {
					t.Fatalf("current valid permission rejected: scenario=%s err=%v", scenario, err)
				}
			} else if err == nil {
				t.Fatalf("stale parent authorized new/reused grant: scenario=%s session=%d", scenario, grant.session.ID)
			}
			if !allowed {
				rows, err := db.ListPeerMeshSessions(ctx, "tenant-a", 20)
				if err != nil || len(rows) != beforeCount {
					t.Fatalf("denied admission persisted a session: count=%d want=%d err=%v", len(rows), beforeCount, err)
				}
			}
		})
	}
}

func TestPeerRosterUsesCurrentOwnerAfterTransfer(t *testing.T) {
	db := openPeerMeshTestDB(t)
	service := newPeerMeshTestService(db)
	ctx := context.Background()
	source := insertPeerClient(t, db, 1001, "tenant-a", "alice", "roster-source")
	target := insertPeerClient(t, db, 1002, "tenant-a", "bob", "roster-target")
	unrelated := insertPeerClient(t, db, 1003, "tenant-a", "alice", "roster-unrelated")
	insertPeerDevice(t, db, source, "100.96.0.10", "source-key")
	insertPeerDevice(t, db, target, "100.96.0.11", "target-key")
	insertPeerDevice(t, db, unrelated, "100.96.0.12", "unrelated-key")
	transferPeerFixtureClient(t, db, source.ID, "bob")
	roster, err := service.AllowedRoster(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[int64]bool{}
	for _, peer := range roster {
		ids[peer.ClientID] = true
	}
	if !ids[target.ID] || ids[unrelated.ID] {
		t.Fatalf("cached pre-transfer owner selected roster: currentPeer=%v unrelatedOldOwnerPeer=%v", ids[target.ID], ids[unrelated.ID])
	}
}

func TestDelayedPeerDisableRefreshDoesNotCloseReenabledGrant(t *testing.T) {
	db := openPeerMeshTestDB(t)
	service := newPeerMeshTestService(db)
	ctx := context.Background()
	source := insertPeerClient(t, db, 1001, "tenant-a", "alice", "refresh-source")
	target := insertPeerClient(t, db, 1002, "tenant-a", "alice", "refresh-target")
	insertPeerDevice(t, db, source, "100.96.0.10", "source-key")
	insertPeerDevice(t, db, target, "100.96.0.11", "target-key")
	actor := store.ManagementWriteActor{Username: "admin", TenantID: "tenant-a", Admin: true, BuiltIn: true}
	for _, value := range []bool{false, true} {
		value := value
		if _, err := db.SetPeerMeshDeviceEnabled(ctx, actor, source.ID, &value, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	grant, err := service.CreateSession(ctx, source, target, PathDirect)
	if err != nil {
		t.Fatal(err)
	}
	// An old post-commit callback arrives after re-enable and a genuinely new valid grant.
	closed, err := service.RefreshDevice(ctx, AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true, BuiltIn: true}, source.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	current, err := db.GetPeerMeshSession(ctx, grant.session.ID)
	if err != nil || current.Status == StatusClosed || len(closed) != 0 {
		t.Fatalf("stale disable callback closed a fresh valid grant: status=%s closures=%d err=%v", current.Status, len(closed), err)
	}
}
