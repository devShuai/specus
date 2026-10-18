package store

import (
	"context"
	"testing"
	"time"
)

func TestManagedRenameLeavesForeignReferencesUntouched(t *testing.T) {
	db := provisionTestDB(t)
	ctx := context.Background()
	_, root := managedResourceFixture(t, db)
	now := time.Now()
	if err := db.InsertPeerMeshDevice(ctx, PeerMeshDevice{ID: 900001, TenantID: "foreign", OwnerUsername: "foreign-owner", ClientID: 1001, ClientName: "foreign-peer-keep", VirtualIP: "100.97.1.1", CIDR: "100.96.0.0/11", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertIdentity(ctx, ClientIdentity{ID: 900002, TenantID: "foreign", CredentialID: 501, ClientID: 1001, ClientName: "foreign-identity-keep", MachineFingerprint: "foreign-machine", OSUser: "fixture", FirstSeenAt: now, LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec(`INSERT INTO peer_mesh_acl(id,tenant_id,owner_username,source_client_id,source_client_name,target_client_id,target_client_name,allowed,created_at,updated_at) VALUES(900003,'foreign','foreign-owner',1001,'foreign-acl-keep',9001,'other-foreign-client',1,?,?)`, formatTime(now), formatTime(now)); err != nil {
		t.Fatal(err)
	}
	name := "renamed-current-client"
	if _, err := db.PatchManagedClient(ctx, root, 1001, ManagementClientPatch{ClientName: &name}, now, now.Unix()); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		table, column, expected string
		id                      int64
	}{
		{"peer_mesh_device", "client_name", "foreign-peer-keep", 900001},
		{"specus_client_identity", "client_name", "foreign-identity-keep", 900002},
		{"peer_mesh_acl", "source_client_name", "foreign-acl-keep", 900003},
	} {
		var actual string
		if err := db.sql.QueryRow(`SELECT `+row.column+` FROM `+row.table+` WHERE id=?`, row.id).Scan(&actual); err != nil || actual != row.expected {
			t.Errorf("rename crossed tenant on %s: got=%q want=%q err=%v", row.table, actual, row.expected, err)
		}
	}
	var actual string
	if err := db.sql.QueryRow(`SELECT client_name FROM peer_mesh_device WHERE id=21001`).Scan(&actual); err != nil || actual != name {
		t.Fatalf("own reference not renamed: %q / %v", actual, err)
	}
}
