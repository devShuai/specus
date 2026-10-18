package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestDeleteClientCleansPeerReferencesWithoutWideningGrants(t *testing.T) {
	for _, audited := range []bool{false, true} {
		t.Run(fmt.Sprintf("audited=%t", audited), func(t *testing.T) {
			db, now := peerDeletionFixture(t)
			ctx := context.Background()
			if audited {
				_, closed, err := db.DeleteClientAuditedWithPeerSessions(ctx, 1001, "admin", now.Unix(), func(HTTPRouteMapping) string { return "private" })
				if err != nil {
					t.Fatal(err)
				}
				if len(closed) != 1 || closed[0].ID != 40 || closed[0].Status != "CLOSED" || !closed[0].ClosedAt.Equal(now) {
					t.Fatalf("committed session snapshot = %+v", closed)
				}
			} else if err := db.DeleteClient(ctx, 1001); err != nil {
				t.Fatal(err)
			}
			for _, check := range []struct {
				table, predicate string
				count            int
			}{
				{"specus_client_account", "id = 1001", 0},
				{"peer_mesh_device", "tenant_id = 'tenant-a' AND client_id = 1001", 0},
				{"peer_mesh_acl", "tenant_id = 'tenant-a' AND (source_client_id = 1001 OR target_client_id = 1001)", 0},
				{"peer_mesh_egress_policy", "tenant_id = 'tenant-a' AND egress_client_id = 1001", 0},
				{"peer_mesh_shared_service", "tenant_id = 'tenant-a' AND client_id = 1001", 0},
				{"management_workbench_item", "object_id = 10", 0},
				{"peer_mesh_device", "tenant_id = 'tenant-b' AND client_id = 1001", 1},
				{"peer_mesh_acl", "tenant_id = 'tenant-b' AND source_client_id = 1001", 1},
			} {
				var count int
				if err := db.sql.QueryRow(`SELECT COUNT(*) FROM ` + check.table + ` WHERE ` + check.predicate).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != check.count {
					t.Errorf("%s %s: got %d want %d", check.table, check.predicate, count, check.count)
				}
			}
			for _, check := range []struct {
				id      int64
				allowed string
				enabled bool
			}{
				{11, "1003", true}, {12, "", false}, {13, "", true}, {14, "", true}, {15, "1001", true},
			} {
				tenant := "tenant-a"
				if check.id == 15 {
					tenant = "tenant-b"
				}
				row, err := db.GetPeerMeshSharedService(ctx, tenant, check.id)
				if err != nil || row == nil {
					t.Fatalf("service %d: %v", check.id, err)
				}
				if row.AllowedClientIDs != check.allowed || row.Enabled != check.enabled {
					t.Errorf("service %d allowed=%q enabled=%t", check.id, row.AllowedClientIDs, row.Enabled)
				}
			}
			for _, check := range []struct {
				id              int64
				tenant, allowed string
			}{
				{21, "tenant-a", "1003"}, {22, "tenant-a", ""}, {23, "tenant-b", "1001"},
			} {
				row, err := db.GetPeerMeshEgressPolicy(ctx, check.tenant, check.id)
				if err != nil || row == nil || row.AllowedConsumerClientIDs != check.allowed {
					t.Fatalf("policy %d: %+v err=%v", check.id, row, err)
				}
			}
			open, err := db.GetPeerMeshSession(ctx, 40)
			if err != nil || open.Status != "CLOSED" || open.ClosedAt == nil || open.DirectBytes != 7 || open.RelayBytes != 9 {
				t.Fatalf("session history lost: %+v err=%v", open, err)
			}
			historical, err := db.GetPeerMeshSession(ctx, 41)
			if err != nil || historical.ClosedAt == nil || !historical.ClosedAt.Equal(now.Add(-time.Hour)) {
				t.Fatalf("historical close changed: %+v err=%v", historical, err)
			}
			foreign, err := db.GetPeerMeshSession(ctx, 42)
			if err != nil || foreign.Status != "CONNECTED" || foreign.ClosedAt != nil {
				t.Fatalf("other tenant session changed: %+v err=%v", foreign, err)
			}
		})
	}
}

func TestDeleteClientRollsBackPeerCleanupWhenAccountDeleteFails(t *testing.T) {
	for _, audited := range []bool{false, true} {
		t.Run(fmt.Sprintf("audited=%t", audited), func(t *testing.T) {
			db, now := peerDeletionFixture(t)
			_, err := db.sql.Exec(`CREATE TRIGGER reject_client_delete BEFORE DELETE ON specus_client_account
				WHEN OLD.id = 1001 BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END`)
			if err != nil {
				t.Fatal(err)
			}
			if audited {
				_, closed, err := db.DeleteClientAuditedWithPeerSessions(context.Background(), 1001, "admin", now.Unix(), func(HTTPRouteMapping) string { return "private" })
				if err == nil || closed != nil {
					t.Fatalf("failed transaction exposed sessions: %v %+v", err, closed)
				}
			} else if err := db.DeleteClient(context.Background(), 1001); err == nil {
				t.Fatal("delete succeeded")
			}
			for _, table := range []string{"peer_mesh_device", "peer_mesh_acl", "peer_mesh_shared_service", "peer_mesh_egress_policy", "management_workbench_item"} {
				var count int
				if err := db.sql.QueryRow(`SELECT COUNT(*) FROM ` + table + ` WHERE tenant_id = 'tenant-a'`).Scan(&count); err != nil {
					t.Fatal(err)
				}
				want := map[string]int{"peer_mesh_device": 1, "peer_mesh_acl": 2, "peer_mesh_shared_service": 5, "peer_mesh_egress_policy": 3, "management_workbench_item": 1}[table]
				if count != want {
					t.Errorf("rollback %s count=%d want=%d", table, count, want)
				}
			}
			row, err := db.GetPeerMeshSharedService(context.Background(), "tenant-a", 12)
			if err != nil || !row.Enabled || row.AllowedClientIDs != "1001" {
				t.Fatalf("allowlist rollback: %+v %v", row, err)
			}
			item, err := db.GetPeerMeshSession(context.Background(), 40)
			if err != nil || item.Status != "CONNECTED" || item.ClosedAt != nil {
				t.Fatalf("session rollback: %+v %v", item, err)
			}
		})
	}
}

func peerDeletionFixture(t *testing.T) (*DB, time.Time) {
	t.Helper()
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "peer-delete.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []int64{1001, 1002, 1003} {
		must(db.InsertClient(ctx, ClientAccount{ID: id, TenantID: "tenant-a", OwnerUsername: "alice", ClientName: fmt.Sprintf("client-%d", id), PasswordHash: "hash", Enabled: true, CreatedAt: now, UpdatedAt: now}))
	}
	for index, tenant := range []string{"tenant-a", "tenant-b"} {
		must(db.InsertPeerMeshDevice(ctx, PeerMeshDevice{ID: int64(index + 1), TenantID: tenant, OwnerUsername: "alice", ClientID: 1001, ClientName: "client-1001", VirtualIP: "100.96.0.2", CIDR: "100.96.0.0/11", Enabled: true, CreatedAt: now, UpdatedAt: now}))
	}
	for index, pair := range [][2]int64{{1001, 1002}, {1002, 1001}, {1001, 1002}} {
		tenant := "tenant-a"
		if index == 2 {
			tenant = "tenant-b"
		}
		must(db.InsertPeerMeshACL(ctx, PeerMeshACL{ID: int64(index + 30), TenantID: tenant, OwnerUsername: "alice", SourceClientID: pair[0], SourceClientName: "source", TargetClientID: pair[1], TargetClientName: "target", Allowed: true, Direction: "BOTH", CreatedAt: now, UpdatedAt: now}))
	}
	for index, allowed := range []string{"", "1001,1003,1001", "1001", "", "1001", "1001"} {
		tenant, visibility, clientID := "tenant-a", "ACL", int64(1002)
		if index == 0 {
			clientID = 1001
		}
		if index == 4 {
			visibility = "OWNER"
		}
		if index == 5 {
			tenant = "tenant-b"
		}
		must(db.InsertPeerMeshSharedService(ctx, PeerMeshSharedService{ID: int64(index + 10), TenantID: tenant, ClientID: clientID, ClientName: "publisher", ServiceID: fmt.Sprintf("service-%d", index), Name: "test", Transport: "tcp", Application: "tcp", TargetHost: "127.0.0.1", TargetPort: 80, PublishedPort: 18080 + index, Enabled: true, Visibility: visibility, AllowedClientIDs: allowed, CreatedAt: now, UpdatedAt: now}))
	}
	for index, allowed := range []string{"", "1001,1003", "1001", "1001"} {
		tenant, clientID := "tenant-a", int64(1002+index)
		if index == 0 {
			clientID = 1001
		}
		if index == 3 {
			tenant = "tenant-b"
		}
		must(db.InsertPeerMeshEgressPolicy(ctx, PeerMeshEgressPolicy{ID: int64(index + 20), TenantID: tenant, OwnerUsername: "alice", EgressClientID: clientID, EgressClientName: "egress", Enabled: true, Scope: "ACL", AllowedConsumerClientIDs: allowed, DestinationRules: "[]", CreatedAt: now, UpdatedAt: now}))
	}
	for index := range 3 {
		item := PeerMeshSession{ID: int64(index + 40), TenantID: "tenant-a", SourceClientID: 1001, SourceClientName: "client-1001", TargetClientID: 1002, TargetClientName: "client-1002", PathType: "DIRECT", Status: "CONNECTED", StartedAt: now.Add(-time.Hour), UpdatedAt: now, ExpiresAt: now.Add(time.Hour), DirectBytes: 7, RelayBytes: 9}
		if index == 1 {
			old := now.Add(-time.Hour)
			item.Status = "CLOSED"
			item.ClosedAt = &old
		}
		if index == 2 {
			item.TenantID = "tenant-b"
		}
		must(db.InsertPeerMeshSession(ctx, item))
	}
	_, err = db.sql.Exec(`INSERT INTO management_workbench_item (tenant_id, username, list, kind, object_id, at_ms)
		VALUES ('tenant-a', 'alice', 'favorite', ?, 10, 1)`, WorkbenchKindPeerService)
	must(err)
	return db, now
}
